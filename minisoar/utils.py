from __future__ import annotations

"""Shared utilities.

This module consolidates helper functions that were duplicated across
09-tele-soar.py, 14_redis_telegram_alert.py, and perimeter_mitigation.py.
"""

import concurrent.futures
import datetime
import ipaddress
import json
import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

from .config import norm_provider, telegram_config

logger = logging.getLogger(__name__)

ISO_FRACTION_RE = re.compile(
    r"^(?P<ymdhms>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
LOCAL_TZ = datetime.timezone(datetime.timedelta(hours=7), name="WIB")


# -----------------
# Path Resolution
# -----------------

def resolve_log_path(env_key: str, default_linux_path: str, default_win_filename: str) -> str:
    val = os.getenv(env_key)
    if val:
        return val

    base = Path.cwd()
    if os.name == "nt":
        return str(base / default_win_filename)

    try:
        parent = os.path.dirname(default_linux_path)
        if parent and os.path.exists(parent):
            return default_linux_path
    except Exception:
        pass

    return str(base / default_win_filename)


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_iso8601_relaxed(s: str) -> datetime.datetime:
    s = s.strip()
    m = ISO_FRACTION_RE.match(s)
    if not m:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    ymdhms = m.group("ymdhms")
    frac = m.group("frac") or ""
    tz = m.group("tz") or "+00:00"
    if frac:
        frac = "." + (frac[1:7])
    if tz == "Z":
        tz = "+00:00"
    return datetime.datetime.fromisoformat(ymdhms + frac + tz)


def extract_reputation_score(rep_str: str) -> int:
    if not rep_str:
        return 0
    match = re.search(r"(\d+)/100", rep_str)
    if match:
        return int(match.group(1))
    return 0


# -----------------
# Networking / Whitelist / Bypass
# -----------------



def load_cidr_list_from_env_and_file(env_key: str, file_path: str) -> List[str]:
    nets = []
    raw = os.environ.get(env_key, "").strip()
    if raw:
        for part in raw.split(","):
            s = part.strip()
            if s:
                nets.append(s)
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    nets.append(line)
    except Exception as e:
        logger.warning("[BYPASS] warning: gagal baca file %s: %s", file_path, e)

    seen = set()
    out = []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def ip_in_nets(ip: str, nets: List[str]) -> bool:
    try:
        ip_addr = ipaddress.ip_address(ip)
        for net in nets:
            if "/" in net:
                if ip_addr in ipaddress.ip_network(net, strict=False):
                    return True
            else:
                if ip_addr == ipaddress.ip_address(net):
                    return True
        return False
    except Exception:
        return False


def is_ip_whitelisted(ip: str, nets: List[str]) -> bool:
    return ip_in_nets(ip, nets)


# -----------------
# Threat Intelligence
# -----------------

def abuseipdb_lookup(ip: str) -> tuple[str, str]:
    token_cfg = os.environ.get("ABUSEIPDB_API_KEY", "")
    cache_ttl = int(os.environ.get("ABUSEIPDB_CACHE_TTL", str(6 * 3600)))
    lookup_timeout = int(os.environ.get("LOOKUP_TIMEOUT", "4"))

    # We must access Redis. Since utils shouldn't hold strict global state,
    # we get a transient connection.
    from .database import redis_client
    r = redis_client()

    cache_key = f"reputation:abuseipdb:{ip}"
    cached = r.get(cache_key)
    if cached:
        return ip, cached

    if not token_cfg:
        return ip, "ℹ️ Skip Reputation (no key)"

    try:
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=60",
            headers={"Key": token_cfg, "Accept": "application/json"},
            timeout=lookup_timeout,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            total_reports = data.get("totalReports", 0)
            if score >= 80:
                rep = f"🛑 Malicious ({score}/100, {total_reports} rep)"
            elif score >= 30:
                rep = f"⚠️ Suspicious ({score}/100, {total_reports} rep)"
            else:
                rep = f"✅ Clean ({score}/100)"
            r.setex(cache_key, cache_ttl, rep)
            return ip, rep
    except Exception as e:
        logger.error("AbuseIPDB error: %s", e)

    r.setex(cache_key, 3600, "❓ Unreachable")
    return ip, "❓ Unreachable"


def ipapi_lookup(ip: str) -> tuple[str, str]:
    cache_ttl = int(os.environ.get("IPAPI_CACHE_TTL", str(12 * 3600)))
    lookup_timeout = int(os.environ.get("LOOKUP_TIMEOUT", "4"))

    from .database import redis_client
    r = redis_client()

    cache_key = f"reputation:geo:{ip}"
    cached = r.get(cache_key)
    if cached:
        return ip, cached

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org", timeout=lookup_timeout)
        if resp.status_code == 200:
            data = resp.json()
            geo = f"{data.get('countryCode','--')}/{data.get('country','--')} ({data.get('isp','-')})"
            r.setex(cache_key, cache_ttl, geo)
            return ip, geo
    except Exception as e:
        logger.error("ip-api error: %s", e)

    r.setex(cache_key, 3600, "??")
    return ip, "??"


def enrich_ip(ip: str) -> tuple[str, str]:
    _, rep = abuseipdb_lookup(ip)
    _, geo = ipapi_lookup(ip)
    return rep, geo


def enrich_multi_ip(ip_list: list[str]) -> dict[str, dict[str, str]]:
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futs1 = {executor.submit(abuseipdb_lookup, ip): ip for ip in ip_list}
        futs2 = {executor.submit(ipapi_lookup, ip): ip for ip in ip_list}
        for fut in concurrent.futures.as_completed(futs1):
            ip, rep = fut.result()
            results.setdefault(ip, {})["rep"] = rep
        for fut in concurrent.futures.as_completed(futs2):
            ip, geo = fut.result()
            results.setdefault(ip, {})["geo"] = geo
    return results


# -----------------
# Perimeter Mapping Helper
# -----------------

def get_perimeter_info(server_name: str, perimeter_map_path: str) -> tuple[list[str], bool, str | None]:
    host = (server_name or "").strip().lower()
    if not host:
        return ["none"], False, None

    try:
        with open(perimeter_map_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("[PERIMETER] gagal load %s: %s", perimeter_map_path, e)
        cfg = {}

    sites = cfg.get("sites") or {}
    if not isinstance(sites, dict):
        return ["none"], False, None

    match_key = None
    if host in sites:
        match_key = host
    else:
        for key in sites.keys():
            if key.startswith("*.") and host.endswith(key[1:]):
                match_key = key
                break

    if match_key:
        meta = sites.get(match_key)
        prov_raw = meta.get("provider") if isinstance(meta, dict) else meta
        if isinstance(prov_raw, list):
            providers = [norm_provider(p) for p in prov_raw]
        else:
            providers = [norm_provider(prov_raw)]
        return providers, True, match_key

    return ["none"], False, None


def provider_badge(providers: list[str], mapped: bool) -> str:
    if not mapped or not providers or providers == ["none"]:
        return "⚪ UNKNOWN (unmapped)"
        
    badges = []
    for p in providers:
        p = norm_provider(p)
        if p == "akamai":
            badges.append("🟢 Akamai")
        elif p == "imperva":
            badges.append("🔵 Imperva")
        elif p == "paloalto":
            badges.append("🟠 Palo Alto")
        else:
            badges.append(f"⚪ External ({p})")
            
    return " | ".join(badges)


def log_unmapped_site_once_per_day(server_name: str, event: Dict[str, Any], unmapped_log_path: str, unmapped_log_ttl: int) -> None:
    host = (server_name or "").strip().lower()
    if not host or host == "(unknown)":
        return

    from .database import redis_client
    r = redis_client()

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    rkey = f"minisoar:unmapped_site_logged:{today}:{host}"

    try:
        if r.get(rkey):
            return
        r.setex(rkey, unmapped_log_ttl, "1")
    except Exception as e:
        logger.warning("[WARN] redis rate-limit for unmapped log failed: %s", e)

    a = event.get("alert") or {}
    payload = {
        "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "website": host,
        "src_ip": a.get("src_ip") or event.get("src_ip") or event.get("ip"),
        "type": a.get("type") or (a.get("tags") or ""),
        "severity": a.get("severity") or a.get("severity_hint") or (event.get("minisoar", {}) or {}).get("severity"),
        "sample_url": a.get("url") or event.get("url_original"),
    }

    try:
        os.makedirs(os.path.dirname(unmapped_log_path), exist_ok=True)
        with open(unmapped_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("[WARN] cannot write unmapped log to %s: %s", unmapped_log_path, e)


# -----------------
# Message Formatters
# -----------------

def _fmt_last_seen(event: dict) -> Optional[str]:
    # find timestamp field
    for k in ("last_seen", "last_ts", "lastSeen", "event_ts", "end_ts", "@timestamp", "timestamp", "ts"):
        v = event.get(k)
        if v is not None:
            ts = v
            break
    else:
        ts = (event.get("alert") or {}).get("ts")

    if ts is None:
        return None

    try:
        if isinstance(ts, (int, float)):
            sec = float(ts)
            if sec > 1e12:
                sec = sec / 1000.0
            dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
        elif isinstance(ts, dict):
            dt = None
            for k in ("epoch_millis", "millis", "ms"):
                if k in ts:
                    dt = datetime.datetime.fromtimestamp(float(ts[k]) / 1000.0, tz=datetime.timezone.utc)
                    break
            if dt is None and "epoch" in ts:
                dt = datetime.datetime.fromtimestamp(float(ts["epoch"]), tz=datetime.timezone.utc)
            if dt is None:
                raw = json.dumps(ts, ensure_ascii=False)
                m = ISO_RE.search(raw)
                if m:
                    dt = parse_iso8601_relaxed(m.group(0))
            if dt is None:
                return None
        else:
            dt = parse_iso8601_relaxed(str(ts))
        return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return None


def _humanize_ago(delta_seconds: int) -> str:
    s = abs(int(delta_seconds))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"


def _bullet_last_seen(event) -> str:
    s = _fmt_last_seen(event)
    if not s:
        return ""
    try:
        raw = event.get("last_seen") or event.get("@timestamp") or event.get("timestamp") or (event.get("alert") or {}).get("ts")
        dt = parse_iso8601_relaxed(str(raw)) if raw else None
        if dt is not None:
            ago = (datetime.datetime.now(LOCAL_TZ) - dt.astimezone(LOCAL_TZ)).total_seconds()
            return f"• *Last Seen:* {s} ({_humanize_ago(int(ago))} ago)\n"
    except Exception:
        pass
    return f"• *Last Seen:* {s}\n"


def _gx(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _normalize_ip_list(ip_list: Any) -> List[Dict[str, Any]]:
    if not ip_list:
        return []
    if isinstance(ip_list, list) and all(isinstance(x, dict) and "ip" in x for x in ip_list):
        return ip_list
    if isinstance(ip_list, list) and all(isinstance(x, str) for x in ip_list):
        c = Counter(ip_list)
        return [{"ip": ip, "count": cnt} for ip, cnt in c.items()]
    return []


def inject_perimeter_line(msg: str, perimeter: str) -> str:
    if not msg:
        return msg
    if "*Perimeter:*" in msg or "Perimeter:" in msg:
        return msg

    per_line = f"• *Perimeter:* `{perimeter}`"
    lines = msg.splitlines()

    for i, line in enumerate(lines):
        if "*Website:*" in line:
            lines.insert(i + 1, per_line)
            return "\n".join(lines)

    return msg + "\n" + per_line


def build_message(event: Dict[str, Any]) -> str:
    a = event.get("alert") or {}

    tags = event.get("tags") or a.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    tags = set(tags)

    alert_type = a.get("type")
    severity = a.get("severity") or a.get("severity_hint") or (event.get("minisoar", {}) or {}).get("severity")
    server_name = a.get("server_name") or event.get("server_name") or event.get("servername") or "(unknown)"
    ip = a.get("src_ip") or event.get("src_ip") or event.get("ip") or "(unknown)"
    method = a.get("method") or _gx(event, "http", "request", "method") or event.get("http_method") or event.get("method")
    url = a.get("url") or event.get("url_original") or ""
    status = a.get("status") or event.get("http_status") or ""
    count = a.get("count") or event.get("count") or ""
    ip_list = a.get("ip_list") or event.get("ip_list") or []
    top_urls = a.get("top_urls") or event.get("top_urls") or []
    samples = a.get("samples") or event.get("samples") or []

    if alert_type == "alert_webshell_immediate" or "alert_webshell_immediate" in tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        return (
            "🧨 *WebShell Immediate*\n"
            f"• *Severity:* `high`\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Source IP:* `{ip}`\n"
            f"• *Reputation:* {rep}\n"
            f"• *Location:* {geo}\n"
            f"• *Method / Status:* `{method or '-'} {status}`\n"
            f"• *URL:* `{url}`\n"
            f"{_bullet_last_seen(event)}"
        )

    if alert_type in {"alert_url_major", "alert_url_minor"} or {"alert_url_major", "alert_url_minor"} & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        if alert_type == "alert_url_major" or "alert_url_major" in tags:
            head = "🚨 *[MAJOR] Burst Access from 1 IP to 1 URL*"
        else:
            head = "🪪 *WebShell Burst (Minor)*" if "webshell_burst" in tags else "⚠️ *[MINOR] Burst Access Detected*"
        sample_lines = ""
        if isinstance(samples, list) and samples:
            rows = []
            for s in samples[:5]:
                mm = str(s.get("method") or "-").replace("`", "'")
                uu = str(s.get("url") or "-").replace("`", "'")
                ss = str(s.get("status") or "-").replace("`", "'")
                rows.append(f"  - `{mm}` | `{uu}` | `{ss}`")
            if rows:
                sample_lines = "\n• *Samples (top 5):*\n" + "\n".join(rows)
        return (
            head + "\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Source IP:* `{ip}`\n"
            f"• *Reputation:* {rep}\n"
            f"• *Location:* {geo}\n"
            f"• *Hit:* `{count}`x\n"
            f"{_bullet_last_seen(event)}" + sample_lines
        )

    if alert_type == "alert_distributed_error" or "alert_distributed_error" in tags:
        norm = _normalize_ip_list(ip_list)
        top5 = sorted(norm, key=lambda x: x.get("count", 0), reverse=True)[:5]
        ip_addr_top5 = [i["ip"] for i in top5]
        repgeo = enrich_multi_ip(ip_addr_top5) if ip_addr_top5 else {}
        title_plain = a.get("title_plain") or "[DISTRIBUTED ERROR]"
        emoji = a.get("emoji") or "🌐"
        ip_lines = []
        for i, ent in enumerate(top5):
            ipi = ent["ip"]
            cnt = ent.get("count", 0)
            rep = repgeo.get(ipi, {}).get("rep", "-")
            geo = repgeo.get(ipi, {}).get("geo", "-")
            ip_lines.append(f"{i+1}. `{ipi}` ({cnt}x)\n    — {rep} | {geo}")
        url_lines = []
        if isinstance(top_urls, list) and top_urls:
            for i, item in enumerate(top_urls[:5], 1):
                if isinstance(item, dict):
                    u = item.get("url")
                    c = item.get("count")
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    u, c = item[0], item[1]
                else:
                    u, c = str(item), None
                if u:
                    url_lines.append(f"{i}. `{u}`{f' ({c}x)' if c is not None else ''}")
        return (
            f"{emoji} *{title_plain}* {emoji}\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Status Code:* `{status}`\n"
            f"• *Requests:* `{count}`\n"
            f"• *Unique IP:* `{len(norm)}`\n"
            f"{_bullet_last_seen(event)}"
            f"• *Top 5 IP:*\n" + ("\n".join(ip_lines) if ip_lines else "-") + (
                "\n• *Top 5 URLs:*\n" + ("\n".join(url_lines) if url_lines else "-") if top_urls else ""
            )
        )

    if alert_type in {"alert_webshell_name", "alert_webshell_heur"} or {"alert_webshell_name", "alert_webshell_heur"} & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        inds = a.get("indicators") or (event.get("minisoar") or {}).get("webshell_indicators") or []
        ind_line = f"• *Indicators:* `{', '.join(inds)}`\n" if inds else ""
        sev = severity or ("high" if (alert_type == "alert_webshell_name" or "alert_webshell_name" in tags) else "medium")
        title = "WebShell Name Match" if (alert_type == "alert_webshell_name" or "alert_webshell_name" in tags) else "WebShell Heuristic"
        emoji = "🪟" if title.startswith("WebShell Name") else "🕸️"
        return (
            f"{emoji} *{title}* {emoji}\n"
            f"• *Severity:* `{sev}`\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Source IP:* `{ip}`\n"
            f"• *Reputation:* {rep}\n"
            f"• *Location:* {geo}\n"
            f"• *Method / Status:* `{method or '-'} {status}`\n"
            f"• *URL:* `{url}`\n"
            f"{ind_line}"
            f"{_bullet_last_seen(event)}"
        )

    exploit_types = {"alert_url_probe", "alert_sqli_attack", "alert_xss_attack", "alert_lfi_attempt", "alert_rce_heur"}
    if alert_type in ({"alert_gambling_slot"} | exploit_types) or ({"alert_gambling_slot"} | exploit_types) & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        if alert_type == "alert_gambling_slot" or "alert_gambling_slot" in tags:
            title_plain = "Gambling/Slot Pattern"
        elif "sqli" in alert_type: title_plain = "SQLi Attack"
        elif "xss" in alert_type: title_plain = "XSS Attack"
        elif "lfi" in alert_type: title_plain = "LFI Attempt"
        elif "rce" in alert_type: title_plain = "RCE Heuristic"
        else: title_plain = "Exploit/Probe URL"
            
        emoji = "🎰" if "gambling" in title_plain.lower() else "💣" if "rce" in alert_type else "🛠️"
        sev = severity or ("critical" if "rce" in alert_type else "high" if "Gambling" in title_plain or "lfi" in alert_type or "sqli" in alert_type else "medium")
        return (
            f"{emoji} *{title_plain} {emoji}*\n"
            f"• *Severity:* `{sev}`\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Source IP:* `{ip}`\n"
            f"• *Reputation:* {rep}\n"
            f"• *Location:* {geo}\n"
            f"• *Method / Status:* `{method or '-'} {status}`\n"
            f"• *URL:* `{url}`\n"
            f"{_bullet_last_seen(event)}"
        )

    return f"🔔 Anomali terdeteksi:\n```json\n{json.dumps(event, indent=2, ensure_ascii=False)}\n```"


# -----------------
# Telegram Sender
# -----------------

def _build_callback_data(action: str, ip: str, event_id: str) -> str:
    if not event_id:
        return f"{action}:{ip}"
    payload = f"{ip}|{event_id}"
    full = f"{action}:{payload}"
    if len(full) <= 64:
        return full
    return f"{action}:{ip}"


def send_telegram(
    msg: str,
    ip: str | None = None,
    show_buttons: bool = True,
    providers: list[str] | None = None,
    website: str = "",
    event_id: str = "",
    chat_id: str | None = None,
) -> None:
    cfg = telegram_config()
    target_chat = chat_id or cfg.chat_id
    if not target_chat or not cfg.token:
        logger.warning("[WARN] TELEGRAM_BOT / TARGET_CHAT_ID not set — skipping send.")
        return

    url = f"https://api.telegram.org/bot{cfg.token}/sendMessage"
    data = {
        "chat_id": target_chat,
        "text": msg,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    if show_buttons and ip and ip != "(unknown)":
        buttons = []
        if providers:
            for p in providers:
                p = norm_provider(p)
                if p == "akamai":
                    txt = f"🚫 Block di Akamai {ip}"
                    cb = _build_callback_data("blockonakamai", ip, event_id)
                    if website: txt += f" ({website})"
                    buttons.append([{"text": txt, "callback_data": cb}])
                elif p == "imperva":
                    txt = f"🚫 Block di Imperva {ip}"
                    cb = _build_callback_data("blockonimperva", ip, event_id)
                    if website: txt += f" ({website})"
                    buttons.append([{"text": txt, "callback_data": cb}])
                elif p == "paloalto":
                    txt = f"🛡️ Block di Palo Alto {ip}"
                    cb = _build_callback_data("blockonpalo", ip, event_id)
                    if website: txt += f" ({website})"
                    buttons.append([{"text": txt, "callback_data": cb}])
        
        if buttons:
            ignore_cb = _build_callback_data("ignore", ip, event_id)
            buttons.append([{"text": "🙈 Ignore", "callback_data": ignore_cb}])
            data["reply_markup"] = {"inline_keyboard": buttons}

    try:
        resp = requests.post(url, json=data, timeout=10)
        if resp.status_code >= 400:
            logger.error("Telegram error: %s - %s", resp.status_code, resp.text)
        else:
            logger.info("Alert sent (buttons: %s)", "ON" if "reply_markup" in data else "OFF")
    except Exception as e:
        logger.error("Failed to send alert: %s", e)


def log_user_action(
    action: str,
    user: Any,
    ip: str | None = None,
    target: str | None = None,
    source: str | None = None,
    chat_id: str | int | None = None,
    note: str | None = None,
    logfile: str | None = None
) -> None:
    if not logfile:
        return
    try:
        if hasattr(user, "username"):
            username = getattr(user, "username") or getattr(user, "full_name", str(user))
        elif isinstance(user, dict):
            username = user.get("username", str(user))
        else:
            username = str(user)
            
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "timestamp": ts,
            "action": action,
            "user": username,
            "ip": ip,
            "target": target,
            "source": source,
            "chat_id": chat_id,
            "note": note
        }
        
        log_dir = os.path.dirname(logfile)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        logger.warning("Failed to write log_user_action to %s: %s", logfile, e)
