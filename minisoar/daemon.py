from __future__ import annotations

"""MiniSOAR alert daemon core loop.

This module implements the Redis alert consumer daemon. It pops alert payloads
from Redis, parses and enriches the event context, indexes it in Elasticsearch,
evaluates the risk using ML/rules, and triggers automatic mitigations or Telegram broadcasts.
"""

import datetime
import json
import logging
import os
import time
from pathlib import Path

from .config import load_env, norm_provider
from .database import (
    es_index,
    extract_top_paths,
    make_event_id,
    parse_ts_epoch,
    redis_client,
    sig_hash,
)
from .mitigation.core import (
    trigger_auto_block,
    trigger_auto_unblock,
    trigger_commit,
    is_ip_blocked,
    register_block_state,
    extend_block_state,
    get_expired_blocks,
    remove_block_state,
)
from .ml.inference import load_model_artifact, predict_block
from .utils import (
    abuseipdb_lookup,
    build_message,
    enrich_ip,
    enrich_multi_ip,
    get_perimeter_info,
    inject_perimeter_line,
    is_ip_whitelisted,
    load_cidr_list_from_env_and_file,
    log_unmapped_site_once_per_day,
    log_user_action,
    provider_badge,
    resolve_log_path,
    send_telegram,
)

logger = logging.getLogger(__name__)


def main() -> None:
    # 1. Load Configurations and Env
    load_env()
    logging.basicConfig(level=logging.INFO)

    # 2. Extract Config Variables
    redis_key = os.environ.get("REDIS_KEY", "logstash_alert_queue")
    redis_host = os.environ.get("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))

    telegram_bot = os.environ.get("TELEGRAM_BOT", "")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    telegram_proc_chat_id = os.environ.get("TELEGRAM_PROCESS_CHAT_ID", "") or telegram_chat_id

    es_hosts = os.environ.get("ES_HOSTS", "")
    es_index_prefix = os.environ.get("ES_EVENTS_INDEX_PREFIX", "minisoar-events")

    de_disable_buttons = os.environ.get("DE_DISABLE_BUTTONS", "0")
    minisoar_blocking_mode = os.environ.get("MINISOAR_BLOCKING_MODE", "MANUAL").upper()
    minisoar_event_window = int(os.environ.get("MINISOAR_EVENT_WINDOW", "60"))
    minisoar_commit_interval = int(os.environ.get("MINISOAR_COMMIT_INTERVAL", "3600"))
    minisoar_block_duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))

    # Resolve paths
    bypass_file_path = resolve_log_path("BYPASS_FILE", "/etc/logstash/minisoar-bypass.txt", "minisoar-bypass.txt")
    whitelist_file_path = resolve_log_path("WHITELIST_FILE", "minisoar-whitelist.txt", "minisoar-whitelist.txt")
    perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
    unmapped_log_path = resolve_log_path("UNMAPPED_LOG_PATH", "/var/log/minisoar-unmapped-sites.log", "minisoar-unmapped-sites.log")
    unmapped_log_ttl = int(os.environ.get("UNMAPPED_LOG_TTL_SEC", "86400"))
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

    # Load bypass and whitelist networks
    bypass_nets = load_cidr_list_from_env_and_file("BYPASS_IPS", bypass_file_path)
    whitelist_nets = load_cidr_list_from_env_and_file("WHITELIST_IPS", whitelist_file_path)

    # Helper function for checking bypass
    def is_ip_bypassed(ip_addr: str) -> bool:
        from .utils import ip_in_nets
        return ip_in_nets(ip_addr, bypass_nets)

    # 3. Load ML model artifact
    model_artifact = load_model_artifact()

    # 4. Redis Client Setup
    r = redis_client()

    # Commit Batching State
    last_commit_times = {"paloalto": time.time(), "akamai": time.time()}
    pending_commits = {"paloalto": False, "akamai": False}

    # Startup Diagnostics
    print("=" * 60)
    print("⚡ MiniSOAR Alert Daemon — Startup Diagnostics")
    print("=" * 60)
    print(f"• OS Platform      : {os.name} ({'Windows' if os.name == 'nt' else 'Linux/WSL'})")
    print(f"• Redis Target     : {redis_host}:{redis_port} (Key: {redis_key})")
    print(f"• Commit Interval  : {minisoar_commit_interval}s")
    print(f"• Block Duration   : {minisoar_block_duration}s")
    print(f"• Bypass File Path : {bypass_file_path}")
    print(f"• Bypass Nets      : {bypass_nets}")
    print(f"• Whitelist File   : {whitelist_file_path}")
    print(f"• Whitelist Nets   : {len(whitelist_nets)} networks loaded")
    print(f"• Perimeter Map    : {perimeter_map_path}")
    print(f"• Unmapped Log Path: {unmapped_log_path}")

    bot_status = "SET" if telegram_bot else "NOT SET"
    bot_masked = f"{telegram_bot[:6]}...{telegram_bot[-6:]}" if len(telegram_bot) > 12 else telegram_bot
    chat_status = "SET" if telegram_chat_id else "NOT SET"
    proc_chat_status = "SET" if os.environ.get("TELEGRAM_PROCESS_CHAT_ID") else "NOT SET (FALLBACK)"

    print(f"• Telegram Bot Token: {bot_masked} ({bot_status})")
    print(f"• Telegram Chat ID  : {telegram_chat_id} ({chat_status})")
    print(f"• Telegram Proc Chat: {telegram_proc_chat_id} ({proc_chat_status})")
    print("=" * 60)

    try:
        while True:
            try:
                # Check for expired temporary blocks
                expired_blocks = get_expired_blocks(r)
                for exp_ip, exp_prov in expired_blocks:
                    if remove_block_state(r, exp_ip, exp_prov):
                        logger.info("[TEMP-BLOCK] Block expired for %s on %s. Triggering unblock...", exp_ip, exp_prov)
                        unblk_ok, unblk_msg = trigger_auto_unblock(exp_ip, exp_prov, commit=False)
                        if unblk_ok:
                            p_norm = norm_provider(exp_prov)
                            if p_norm in pending_commits:
                                pending_commits[p_norm] = True
                            
                            unblk_notify_msg = f"ℹ️ *System Action: AUTO-UNBLOCKED*\n• IP: `{exp_ip}`\n• Provider: `{exp_prov.upper()}`\n• Status: Expiration of temporary block duration ({minisoar_block_duration}s) reached with no further activity."
                            send_telegram(unblk_notify_msg, show_buttons=False, chat_id=telegram_proc_chat_id)
                            log_user_action(
                                "AUTO_UNBLOCK",
                                {"username": "system"},
                                ip=exp_ip,
                                target=exp_prov,
                                note=f"Block duration expired ({minisoar_block_duration}s of inactivity)",
                                logfile=logfile,
                            )
                        else:
                            logger.error("[TEMP-BLOCK] Failed to auto-unblock %s on %s: %s", exp_ip, exp_prov, unblk_msg)

                # Check for scheduled commits
                current_time = time.time()
                for p_name in ["paloalto", "akamai"]:
                    if pending_commits[p_name]:
                        elapsed = current_time - last_commit_times[p_name]
                        if elapsed >= minisoar_commit_interval:
                            logger.info(
                                "Scheduled commit/activation triggered for %s (elapsed: %.1fs, interval: %ds)",
                                p_name,
                                elapsed,
                                minisoar_commit_interval,
                            )
                            success, commit_msg = trigger_commit(p_name)
                            if success:
                                pending_commits[p_name] = False
                                last_commit_times[p_name] = current_time
                                logger.info("Scheduled commit/activation for %s completed: %s", p_name, commit_msg)
                            else:
                                logger.error("Scheduled commit/activation for %s failed: %s", p_name, commit_msg)

                item = r.blpop(redis_key, timeout=10)
                if not item:
                    continue

                _, value = item
                try:
                    event = json.loads(value)
                except Exception as e:
                    logger.error("JSON parse error: %s", e)
                    continue

                # Add last_seen normalization
                if "last_seen" not in event and "@timestamp" in event:
                    event["last_seen"] = event["@timestamp"]

                ip = (event.get("alert") or {}).get("src_ip") or event.get("src_ip") or event.get("ip") or ""
                website = (event.get("alert") or {}).get("server_name") or event.get("server_name") or event.get("servername") or ""

                providers, mapped, _ = get_perimeter_info(website, perimeter_map_path)
                if not mapped:
                    log_unmapped_site_once_per_day(website, event, unmapped_log_path, unmapped_log_ttl)

                whitelisted = bool(ip and is_ip_whitelisted(ip, whitelist_nets))
                bypassed = bool(ip and is_ip_bypassed(ip))

                # Handle bypass for single IP alerts
                if bypassed:
                    logger.info("[DROP/BYPASS] single IP %s — alert dropped.", ip)
                    continue

                msg = build_message(event)
                perimeter = provider_badge(providers, mapped)
                msg = inject_perimeter_line(msg, perimeter)

                alert_type = (event.get("alert") or {}).get("type")
                tags = event.get("tags") or (event.get("alert") or {}).get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                tags = set(tags)

                # Process event IDs and Elasticsearch indexing
                ts_epoch = parse_ts_epoch(event)
                if ts_epoch:
                    detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
                    asset_id = (event.get("alert") or {}).get("server_name") or event.get("server_name") or "(unknown)"
                    src_ip = (event.get("alert") or {}).get("src_ip") or event.get("src_ip") or event.get("ip") or "(unknown)"
                    top_paths = extract_top_paths(event)
                    event_id = make_event_id(detector_type, asset_id, src_ip, ts_epoch, minisoar_event_window, top_paths)

                    # Enrich payload dictionaries
                    event["event_id"] = event_id
                    event["detector_type"] = detector_type
                    event["severity"] = (event.get("alert") or {}).get("severity") or (event.get("alert") or {}).get("severity_hint")

                    asset = event.setdefault("asset", {})
                    asset["id"] = asset_id

                    src = event.setdefault("src", {})
                    src["ip"] = src_ip

                    perimeter_node = event.setdefault("perimeter", {})
                    perimeter_node["vendor"] = norm_provider(providers[0] if providers else "none")

                    metrics = event.setdefault("metrics", {})
                    metrics["hit_count"] = (event.get("alert") or {}).get("count") or event.get("count")
                    metrics["window_seconds"] = minisoar_event_window

                    samples = event.setdefault("samples", {})
                    samples["paths_top"] = top_paths

                    signature = event.setdefault("signature", {})
                    signature["top_paths_hash"] = sig_hash(top_paths)

                    dt_obj = datetime.datetime.fromtimestamp(ts_epoch, tz=datetime.timezone.utc)
                    index_name = f"{es_index_prefix}-{dt_obj.strftime('%Y.%m.%d')}"
                    es_doc = {
                        "@timestamp": dt_obj.isoformat(),
                        "event_id": event_id,
                        "detector_type": detector_type,
                        "severity": event.get("severity"),
                        "asset": {"id": asset_id},
                        "src": {"ip": src_ip},
                        "perimeter": {"vendor": norm_provider(providers[0] if providers else "none")},
                        "metrics": {"hit_count": event.get("metrics", {}).get("hit_count"), "window_seconds": minisoar_event_window},
                        "samples": {"paths_top": top_paths},
                        "signature": {"top_paths_hash": event.get("signature", {}).get("top_paths_hash")},
                        "alert": event.get("alert") or {},
                        "event": event,
                    }
                    es_index(index_name, event_id, es_doc)
                else:
                    event_id = ""

                # Distributed error bypass check
                ip_list = (event.get("alert") or {}).get("ip_list") or event.get("ip_list")
                from .utils import _normalize_ip_list
                norm_ips = _normalize_ip_list(ip_list)

                if alert_type == "alert_distributed_error" or "alert_distributed_error" in tags:
                    ips = [ent.get("ip") for ent in (norm_ips or []) if ent.get("ip")]
                    if ips and all(is_ip_bypassed(x) for x in ips):
                        logger.info("[DROP/BYPASS] distributed all IP bypassed: %s", ips)
                        continue
                    send_telegram(msg, show_buttons=False, event_id=event_id)
                    continue

                # Single-IP alerts evaluation (ML model vs heuristic)
                if alert_type in {
                    "alert_random_url",
                    "alert_url_major",
                    "alert_url_minor",
                    "alert_gambling_slot",
                    "alert_webshell_name",
                    "alert_webshell_heur",
                    "alert_url_probe",
                    "alert_webshell_immediate",
                    "alert_sqli_attack",
                    "alert_xss_attack",
                    "alert_lfi_attempt",
                    "alert_rce_heur",
                } or {
                    "alert_random_url",
                    "alert_url_major",
                    "alert_url_minor",
                    "alert_gambling_slot",
                    "alert_webshell_name",
                    "alert_webshell_heur",
                    "alert_url_probe",
                    "alert_webshell_immediate",
                    "alert_sqli_attack",
                    "alert_xss_attack",
                    "alert_lfi_attempt",
                    "alert_rce_heur",
                } & tags:
                    _, rep_str = abuseipdb_lookup(ip) if ip and ip != "(unknown)" else (ip, "")
                    ml_provider = providers[0] if providers else "none"
                    pred_label, pred_prob = predict_block(event, ip, ml_provider, whitelisted, rep_str, model_artifact)

                    if minisoar_blocking_mode == "AUTO":
                        if pred_label == 1:
                            extended_any = False
                            blocked_any = False
                            block_targets = providers if (mapped and providers) else ["imperva"]
                            for p in block_targets:
                                p_norm = norm_provider(p)
                                if is_ip_blocked(r, ip, p_norm):
                                    extend_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                    extended_any = True
                                    log_user_action(
                                        "BLOCK_EXTEND",
                                        {"username": "system"},
                                        ip=ip,
                                        target=p,
                                        note=f"ML prediction {pred_prob:.2%} - Block extended +{minisoar_block_duration}s",
                                        logfile=logfile,
                                    )
                                else:
                                    success, blk_msg = trigger_auto_block(ip, p, commit=False)
                                    if success:
                                        register_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                        blocked_any = True
                                        if p_norm in pending_commits:
                                            pending_commits[p_norm] = True
                                    log_user_action(
                                        "AUTO_BLOCK",
                                        {"username": "system"},
                                        ip=ip,
                                        target=p,
                                        note=f"ML prediction {pred_prob:.2%} (Commit deferred)",
                                        logfile=logfile,
                                    )
                            if extended_any and not blocked_any:
                                msg = f"🤖 *AI Action: BLOCK EXTENDED* (Confidence: {pred_prob:.0%} - IP already blocked, extended +{minisoar_block_duration}s)\n" + msg
                            else:
                                needs_commit = any(norm_provider(t) in {"paloalto", "akamai"} for t in block_targets)
                                if needs_commit:
                                    msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} - Commit pending, temporary block {minisoar_block_duration}s)\n" + msg
                                else:
                                    msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} - Temporary block {minisoar_block_duration}s)\n" + msg
                            send_telegram(msg, ip=ip, show_buttons=False, providers=block_targets, website=website, event_id=event_id, chat_id=telegram_proc_chat_id)
                            continue
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg
                    elif minisoar_blocking_mode == "SEMI":
                        if pred_label == 1:
                            if pred_prob > 0.70:
                                extended_any = False
                                blocked_any = False
                                block_targets = providers if (mapped and providers) else ["imperva"]
                                for p in block_targets:
                                    p_norm = norm_provider(p)
                                    if is_ip_blocked(r, ip, p_norm):
                                        extend_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                        extended_any = True
                                        log_user_action(
                                            "SEMI_BLOCK_EXTEND",
                                            {"username": "system"},
                                            ip=ip,
                                            target=p,
                                            note=f"ML prediction {pred_prob:.2%} (>70%) - Block extended +{minisoar_block_duration}s",
                                            logfile=logfile,
                                        )
                                    else:
                                        success, blk_msg = trigger_auto_block(ip, p, commit=False)
                                        if success:
                                            register_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                            blocked_any = True
                                            if p_norm in pending_commits:
                                                pending_commits[p_norm] = True
                                        log_user_action(
                                            "SEMI_AUTO_BLOCK",
                                            {"username": "system"},
                                            ip=ip,
                                            target=p,
                                            note=f"ML prediction {pred_prob:.2%} (>70%, Commit deferred)",
                                            logfile=logfile,
                                        )
                                if extended_any and not blocked_any:
                                    msg = f"🤖 *AI Action: BLOCK EXTENDED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - IP already blocked, extended +{minisoar_block_duration}s)\n" + msg
                                else:
                                    needs_commit = any(norm_provider(t) in {"paloalto", "akamai"} for t in block_targets)
                                    if needs_commit:
                                        msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - Commit pending, temporary block {minisoar_block_duration}s)\n" + msg
                                    else:
                                        msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - Temporary block {minisoar_block_duration}s)\n" + msg
                                send_telegram(msg, ip=ip, show_buttons=False, providers=block_targets, website=website, event_id=event_id, chat_id=telegram_proc_chat_id)
                                continue
                            else:
                                msg = f"🤖 *AI Recommendation: BLOCK* (Confidence: {pred_prob:.0%})\n" + msg
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg

                    show_btn = (de_disable_buttons != "1" and not whitelisted)
                    if whitelisted:
                        logger.info("[WL] %s whitelisted — sending alert without action buttons.", ip)
                    send_telegram(msg, ip=ip, show_buttons=show_btn, providers=providers, website=website, event_id=event_id)
                else:
                    show_btn = (de_disable_buttons != "1" and not whitelisted)
                    send_telegram(msg, ip=ip if ip else None, show_buttons=show_btn, providers=providers, website=website, event_id=event_id)

            except Exception as e:
                logger.error("Redis loop error: %s", e)
                time.sleep(5)

    except KeyboardInterrupt:
        print("\n[INFO] Daemon alert dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")


if __name__ == "__main__":
    main()
