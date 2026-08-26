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
from .correlation import CorrelationEngine
from .database import (
    es_index,
    extract_top_paths,
    make_event_id,
    parse_ts_epoch,
    redis_client,
    sig_hash,
    store_label,
)
from .ecs_normalizer import normalize_to_ecs
from .edr import check_all_edr_connectivity
from .mitigation.core import (
    check_perimeter_connectivity,
    extend_block_state,
    get_expired_blocks,
    is_ip_blocked,
    register_block_state,
    remove_block_state,
    trigger_auto_block,
    trigger_auto_unblock,
    trigger_commit,
)
from .ml.inference import load_model_artifact, predict_block
from .playbook import ExecutionContext, PlaybookEngine
from .utils import (
    abuseipdb_lookup,
    build_message,
    extract_reputation_score,
    get_perimeter_info,
    inject_edr_line,
    inject_perimeter_line,
    is_ip_whitelisted,
    load_cidr_list_from_env_and_file,
    log_unmapped_site_once_per_day,
    log_user_action,
    notify_action_log,
    provider_badge,
    resolve_log_path,
    send_telegram,
    valid_ip,
)

logger = logging.getLogger(__name__)


def sync_edr_ioc_if_malicious(
    r,
    ip: str,
    rep_score: int,
    is_permanent: bool,
    pred_label: int,
    event_id: str,
    detector_type: str,
    logfile: str | None = None,
) -> bool:
    """Auto-registers confirmed high-threat / C2 / malicious IPs to EDR IoC repositories (Kaspersky KSC & Trend Micro Vision One)."""
    if not ip or ip == "(unknown)" or not valid_ip(ip):
        return False

    # Kriteria: Reputasi ancaman intelijen tinggi (>= 50%), permanent block, ML prediction block, atau serangan webshell/RCE
    is_malicious = (
        is_permanent
        or rep_score >= 50
        or pred_label == 1
        or detector_type in {
            "alert_webshell_immediate",
            "alert_webshell_name",
            "alert_webshell_heur",
            "alert_rce_heur",
            "alert_c2_communication",
            "alert_ransomware_activity",
        }
    )
    if not is_malicious:
        return False

    cache_key = f"minisoar:edr_ioc_synced:{ip}"
    if r and r.exists(cache_key):
        return False

    try:
        from .edr.core import add_edr_ioc

        ok, msg = add_edr_ioc(
            ioc_type="ip",
            ioc_value=ip,
            provider="all",
            comment=f"ThreatIntel Rep:{rep_score}% - Event:{event_id or detector_type}",
        )
        if ok:
            if r:
                r.setex(cache_key, 86400, "1")
            log_user_action(
                "EDR_IOC_AUTO_SYNC",
                {"username": "threat_intel"},
                ip=ip,
                target="EDR-ALL",
                note=f"Auto IoC synced to Kaspersky & TrendMicro: {msg}",
                logfile=logfile,
            )
            notify_action_log(
                f"🛡️ *EDR IOC AUTO-SYNC*\n"
                f"• IP: `{ip}`\n"
                f"• Target EDR: `Kaspersky KSC & Trend Micro Vision One`\n"
                f"• Note: `ThreatIntel Rep: {rep_score}% - Event: {detector_type}`\n"
                f"• Status: `✅ Active / Blocked on EDR Repositories`"
            )
            logger.info("[EDR-IOC] Auto-registered IP %s to EDR Suspicious Objects: %s", ip, msg)
            return True
    except Exception as e:
        logger.debug("[EDR-IOC] Auto IoC registration skipped/failed: %s", e)
    return False


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
    
    # Scheduling logic: Minimum 1 hour, triggers strictly at XX:00
    minisoar_commit_interval = max(3600, minisoar_commit_interval)
    interval_hours = max(1, minisoar_commit_interval // 3600)
    now_dt = datetime.datetime.now()
    next_commit_dt = now_dt.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=interval_hours)
    next_commit_ts = next_commit_dt.timestamp()

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
    print(f"• Process Chat ID   : {telegram_proc_chat_id} ({proc_chat_status})")
    print(f"• Elasticsearch     : {es_hosts or 'Default'}")
    # 5. Playbook & Correlation Engines Setup
    playbooks_dir = Path(__file__).parent / "playbooks"
    playbook_engine = PlaybookEngine(playbooks_dir=playbooks_dir)
    correlation_engine = CorrelationEngine(redis_conn=r, default_window=minisoar_event_window)

    print(f"• Playbook Engine  : {len(playbook_engine.playbooks)} playbooks loaded ({playbooks_dir})")
    print(f"• Correlation Mode : Active (Window: {minisoar_event_window}s)")
    print(f"• Blocking Mode    : {minisoar_blocking_mode}")
    print("=" * 60)

    # Perimeter connectivity check — verify every configured provider is reachable
    # before entering the main loop, so misconfiguration surfaces at startup instead
    # of silently failing on the first real auto-block attempt.
    print("• Perimeter Connectivity Check:")
    perimeter_results = check_perimeter_connectivity()
    for res in perimeter_results:
        provider = res["provider"].upper()
        if not res["configured"]:
            print(f"   - {provider:<10}: SKIPPED (not configured)")
            continue
        if res["ok"]:
            print(f"   - {provider:<10}: OK (reachable)")
            logger.info("Perimeter check OK: %s", res["provider"])
        else:
            print(f"   - {provider:<10}: FAILED - {res['error']}")
            logger.error(
                "Perimeter check FAILED: provider=%s error=%s hint=%s",
                res["provider"], res["error"], res["hint"],
            )
            if res.get("traceback"):
                logger.error("Traceback for %s:\n%s", res["provider"], res["traceback"])

    # EDR connectivity check — verify Kaspersky KSC and TrendMicro Vision One
    print("• EDR Connectivity Check (Kaspersky & TrendMicro):")
    edr_results = check_all_edr_connectivity()
    for res in edr_results:
        provider = res["provider"].upper()
        if not res["configured"]:
            print(f"   - {provider:<10}: SKIPPED (not configured)")
            continue
        if res["ok"]:
            print(f"   - {provider:<10}: OK (reachable)")
            logger.info("EDR check OK: %s", res["provider"])
        else:
            print(f"   - {provider:<10}: FAILED - {res['error']}")
            logger.error("EDR check FAILED: provider=%s error=%s hint=%s", res["provider"], res["error"], res["hint"])
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
                            send_telegram(unblk_notify_msg, show_buttons=False)
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
                if current_time >= next_commit_ts:
                    for p_name in ["paloalto", "akamai"]:
                        if pending_commits[p_name]:
                            logger.info(
                                "Scheduled commit/activation triggered for %s at hour boundary",
                                p_name,
                            )
                            success, commit_msg = trigger_commit(p_name)
                            if success:
                                pending_commits[p_name] = False
                                last_commit_times[p_name] = current_time
                                logger.info("Scheduled commit/activation for %s completed: %s", p_name, commit_msg)
                            else:
                                logger.error("Scheduled commit/activation for %s failed: %s", p_name, commit_msg)
                    
                    # Update to next hour boundary
                    now_dt = datetime.datetime.now()
                    next_commit_dt = now_dt.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=interval_hours)
                    next_commit_ts = next_commit_dt.timestamp()

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

                    if isinstance(event.get("samples"), dict):
                        event["samples"]["paths_top"] = top_paths
                    else:
                        raw_samples = event.get("samples")
                        event["samples"] = {"paths_top": top_paths}
                        if raw_samples is not None:
                            event["samples"]["raw"] = raw_samples

                    signature = event.setdefault("signature", {})
                    signature["top_paths_hash"] = sig_hash(top_paths)

                    dt_obj = datetime.datetime.fromtimestamp(ts_epoch, tz=datetime.timezone.utc)
                    index_name = f"{es_index_prefix}-{dt_obj.strftime('%Y.%m.%d')}"
                    
                    # Normalisasi ECS-like
                    es_doc = normalize_to_ecs(
                        raw_event=event,
                        event_id=event_id,
                        providers=providers,
                        minisoar_event_window=minisoar_event_window,
                        ts_epoch=ts_epoch
                    )
                    
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

                    rep_score = extract_reputation_score(rep_str)
                    is_permanent = rep_score >= 50

                    # Correlation aggregation & Campaign detection
                    _corr_data = correlation_engine.aggregate_event(
                        ip=ip,
                        website=website,
                        detector_type=alert_type or "generic",
                        top_paths=top_paths if ts_epoch else [],
                        hits=int((event.get("alert") or {}).get("count") or event.get("count") or 1),
                        window_seconds=minisoar_event_window,
                    )
                    campaign_data = correlation_engine.detect_campaign(
                        website=website,
                        detector_type=alert_type or "generic",
                        src_ip=ip,
                    )
                    if campaign_data.get("is_campaign"):
                        event["campaign"] = campaign_data
                        msg = f"🚨 *DISTRIBUTED CAMPAIGN ({campaign_data['attacker_count']} IPs targeting {website or 'asset'})*\n" + msg

                    # 2026-08-21 - Otomasi Sinkronisasi IP Terkonfirmasi Ancaman/C2 ke EDR IoC (Kaspersky KSC & Trend Micro)
                    if not whitelisted and not bypassed:
                        is_edr_synced = sync_edr_ioc_if_malicious(
                            r=r,
                            ip=ip,
                            rep_score=rep_score,
                            is_permanent=is_permanent,
                            pred_label=pred_label,
                            event_id=event_id,
                            detector_type=alert_type or "generic",
                            logfile=logfile,
                        )
                        if is_edr_synced or (r and r.exists(f"minisoar:edr_ioc_synced:{ip}")):
                            msg = inject_edr_line(msg, "🛡️ Kaspersky & Trend Micro (Synced)")

                    if minisoar_blocking_mode == "PLAYBOOK":
                        ctx = ExecutionContext(
                            event=event,
                            ip=ip,
                            website=website,
                            providers=providers,
                            mapped=mapped,
                            whitelisted=whitelisted,
                            bypassed=bypassed,
                            ml_prob=pred_prob,
                            ml_label=pred_label,
                            reputation_score=rep_score,
                            rep_str=rep_str,
                            event_id=event_id,
                            redis_conn=r,
                            pending_commits=pending_commits,
                            logfile=logfile,
                            minisoar_block_duration=minisoar_block_duration,
                        )
                        ok_pb, pb_id = playbook_engine.execute(ctx)
                        if ok_pb:
                            continue

                    if minisoar_blocking_mode == "AUTO":
                        if whitelisted:
                            msg = "🤖 *AI Action: ALLOW (Whitelisted)*\n" + msg
                        elif pred_label == 1:
                            extended_any = False
                            blocked_any = False
                            failed_providers = []
                            block_targets = providers if (mapped and providers and providers != ["none"]) else ["imperva"]
                            for p in block_targets:
                                p_norm = norm_provider(p)
                                if is_ip_blocked(r, ip, p_norm):
                                    if not is_permanent:
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
                                        remove_block_state(r, ip, p_norm)
                                        extended_any = True
                                        log_user_action(
                                            "BLOCK_PERMANENT",
                                            {"username": "system"},
                                            ip=ip,
                                            target=p,
                                            note=f"Reputation {rep_score}% - Upgraded to Permanent Block",
                                            logfile=logfile,
                                        )
                                else:
                                    success, blk_msg = trigger_auto_block(ip, p, commit=False)
                                    if success:
                                        if not is_permanent:
                                            register_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                        blocked_any = True
                                        if p_norm in pending_commits:
                                            pending_commits[p_norm] = True
                                        act_type = "AUTO_BLOCK_PERMANENT" if is_permanent else "AUTO_BLOCK"
                                        act_note = "Permanent" if is_permanent else f"Temporary {minisoar_block_duration}s"
                                        log_user_action(
                                            act_type,
                                            {"username": "system"},
                                            ip=ip,
                                            target=p,
                                            note=f"ML prediction {pred_prob:.2%} ({act_note})",
                                            logfile=logfile,
                                        )
                                    else:
                                        logger.error("Failed to auto-block %s on %s: %s", ip, p, blk_msg)
                                        failed_providers.append((p_norm, blk_msg))
                            if blocked_any or extended_any:
                                store_label(event_id, "block", "system", "auto_block", ip=ip)
                            if failed_providers:
                                fail_lines = "\n".join(f"• `{fp}`: {fm}" for fp, fm in failed_providers)
                                notify_action_log(
                                    f"⚠️ *AUTO-BLOCK FAILED*\n"
                                    f"• IP: `{ip}`\n"
                                    f"• Website: `{website or '-'}`\n"
                                    f"• Mode: `AUTO`\n"
                                    f"• Failed provider(s):\n{fail_lines}"
                                )
                            if extended_any and not blocked_any:
                                if is_permanent:
                                    msg = f"🤖 *AI Action: PERMANENT BLOCK* (Confidence: {pred_prob:.0%} - Rep: {rep_score}%)\n" + msg
                                else:
                                    msg = f"🤖 *AI Action: BLOCK EXTENDED* (Confidence: {pred_prob:.0%} - IP already blocked, extended +{minisoar_block_duration}s)\n" + msg
                            elif blocked_any:
                                needs_commit = any(norm_provider(t) in {"paloalto", "akamai"} for t in block_targets)
                                if is_permanent:
                                    status_str = "Commit pending, permanent block" if needs_commit else "Permanent block"
                                else:
                                    status_str = f"Commit pending, temporary block {minisoar_block_duration}s" if needs_commit else f"Temporary block {minisoar_block_duration}s"
                                msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} - Rep: {rep_score}% - {status_str})\n" + msg
                            else:
                                msg = f"❌ *AI Action: AUTO-BLOCK FAILED* (Confidence: {pred_prob:.0%} - Rep: {rep_score}% - all providers failed, see Action Log)\n" + msg
                            send_telegram(msg, ip=ip, show_buttons=False, providers=block_targets, website=website, event_id=event_id)
                            continue
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg
                    elif minisoar_blocking_mode == "SEMI":
                        if whitelisted:
                            msg = "🤖 *AI Recommendation: ALLOW (Whitelisted)*\n" + msg
                        elif pred_label == 1:
                            if pred_prob > 0.70:
                                extended_any = False
                                blocked_any = False
                                failed_providers = []
                                block_targets = providers if (mapped and providers and providers != ["none"]) else ["imperva"]
                                for p in block_targets:
                                    p_norm = norm_provider(p)
                                    if is_ip_blocked(r, ip, p_norm):
                                        if not is_permanent:
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
                                            remove_block_state(r, ip, p_norm)
                                            extended_any = True
                                            log_user_action(
                                                "SEMI_BLOCK_PERMANENT",
                                                {"username": "system"},
                                                ip=ip,
                                                target=p,
                                                note=f"Reputation {rep_score}% - Upgraded to Permanent Block (>70% confidence)",
                                                logfile=logfile,
                                            )
                                    else:
                                        success, blk_msg = trigger_auto_block(ip, p, commit=False)
                                        if success:
                                            if not is_permanent:
                                                register_block_state(r, ip, p_norm, duration=minisoar_block_duration)
                                            blocked_any = True
                                            if p_norm in pending_commits:
                                                pending_commits[p_norm] = True
                                            act_type = "SEMI_AUTO_BLOCK_PERMANENT" if is_permanent else "SEMI_AUTO_BLOCK"
                                            act_note = "Permanent" if is_permanent else f"Temporary {minisoar_block_duration}s"
                                            log_user_action(
                                                act_type,
                                                {"username": "system"},
                                                ip=ip,
                                                target=p,
                                                note=f"ML prediction {pred_prob:.2%} (>70%) ({act_note})",
                                                logfile=logfile,
                                            )
                                        else:
                                            logger.error("Failed to semi-auto-block %s on %s: %s", ip, p, blk_msg)
                                            failed_providers.append((p_norm, blk_msg))
                                if blocked_any or extended_any:
                                    store_label(event_id, "block", "system", "semi_auto_block", ip=ip)
                                if failed_providers:
                                    fail_lines = "\n".join(f"• `{fp}`: {fm}" for fp, fm in failed_providers)
                                    notify_action_log(
                                        f"⚠️ *AUTO-BLOCK FAILED*\n"
                                        f"• IP: `{ip}`\n"
                                        f"• Website: `{website or '-'}`\n"
                                        f"• Mode: `SEMI`\n"
                                        f"• Failed provider(s):\n{fail_lines}"
                                    )
                                if extended_any and not blocked_any:
                                    if is_permanent:
                                        msg = f"🤖 *AI Action: PERMANENT BLOCK* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - Rep: {rep_score}%)\n" + msg
                                    else:
                                        msg = f"🤖 *AI Action: BLOCK EXTENDED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - IP already blocked, extended +{minisoar_block_duration}s)\n" + msg
                                elif blocked_any:
                                    needs_commit = any(norm_provider(t) in {"paloalto", "akamai"} for t in block_targets)
                                    if is_permanent:
                                        status_str = "Commit pending, permanent block" if needs_commit else "Permanent block"
                                    else:
                                        status_str = f"Commit pending, temporary block {minisoar_block_duration}s" if needs_commit else f"Temporary block {minisoar_block_duration}s"
                                    msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - Rep: {rep_score}% - {status_str})\n" + msg
                                else:
                                    msg = f"❌ *AI Action: AUTO-BLOCK FAILED* (Confidence: {pred_prob:.0%} > 70% in SEMI Mode - Rep: {rep_score}% - all providers failed, see Action Log)\n" + msg
                                send_telegram(msg, ip=ip, show_buttons=False, providers=block_targets, website=website, event_id=event_id)
                                continue
                            else:
                                msg = f"🤖 *AI Recommendation: BLOCK* (Confidence: {pred_prob:.0%})\n" + msg
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg

                    show_btn = (de_disable_buttons != "1" and not whitelisted)
                    if whitelisted:
                        logger.info("[WL] %s whitelisted — sending alert without action buttons.", ip)
                    send_telegram(msg, ip=ip, show_buttons=show_btn, providers=providers if (mapped and providers and providers != ["none"]) else ["imperva"], website=website, event_id=event_id)
                else:
                    show_btn = (de_disable_buttons != "1" and not whitelisted)
                    send_telegram(msg, ip=ip if ip else None, show_buttons=show_btn, providers=providers if (mapped and providers and providers != ["none"]) else ["imperva"], website=website, event_id=event_id)

            except Exception as e:
                logger.error("Redis loop error: %s", e)
                time.sleep(5)

    except KeyboardInterrupt:
        print("\n[INFO] Daemon alert dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")


if __name__ == "__main__":
    main()
