#!/usr/bin/env python3
# 09_redis_telegram_alert.py — dengan BYPASS mode
# - Whitelist: kirim notif TANPA tombol
# - Bypass: drop notif (tidak terkirim)
# - Distributed Error: selalu tanpa tombol; jika semua IP bypass ⇒ drop
# Basis: versi terintegrasi sebelumnya

import os
from dotenv import load_dotenv
from pathlib import Path

# Load env variables (prioritise system env, fallback to local .env)
load_dotenv("/root/tele-soar/.env", override=False)
load_dotenv(Path(__file__).resolve().parent / ".env", override=False)

# Force load from local .env if critical variables are empty/missing in environment
if not os.environ.get("TELEGRAM_BOT") or not os.environ.get("TELEGRAM_CHAT_ID"):
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

import redis, requests, json, time, concurrent.futures, ipaddress, re, yaml, hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, List
from collections import Counter

# ==== MACHINE LEARNING & PERIMETER INTEGRATION ====
import joblib
import pandas as pd
from perimeter_mitigation import trigger_auto_block, log_user_action

MINISOAR_BLOCKING_MODE = os.environ.get("MINISOAR_BLOCKING_MODE", "MANUAL").upper()

model_path = Path(__file__).resolve().parent / "baseline_model.joblib"
model_artifact = None
if model_path.exists():
    try:
        model_artifact = joblib.load(model_path)
        print(f"[ML] Successfully loaded baseline_model.joblib trained on {model_artifact.get('trained_date')}")
    except Exception as e:
        print(f"[ML] Failed to load baseline_model.joblib: {e}")
else:
    print("[ML] baseline_model.joblib not found. Fallback heuristic will be used.")

def extract_reputation_score(rep_str: str) -> int:
    if not rep_str:
        return 0
    match = re.search(r"(\d+)/100", rep_str)
    if match:
        return int(match.group(1))
    return 0

def predict_block(event: dict, ip: str, provider: str, whitelisted: bool, rep_str: str) -> tuple[int, float]:
    """
    Predict whether to block the IP using the loaded ML model.
    Returns: (predicted_label, probability_score)
    """
    rep_score = extract_reputation_score(rep_str)
    
    if not model_artifact:
        detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
        if detector_type == "alert_webshell_immediate" or rep_score >= 80:
            return 1, 0.95
        return 0, 0.05

    model = model_artifact["model"]
    feature_columns = model_artifact["feature_columns"]
    severity_map = model_artifact.get("severity_map", {"low": 0, "medium": 1, "high": 2})

    hit_count = int((event.get("alert") or {}).get("count") or event.get("count") or 1)
    is_whitelisted = 1 if whitelisted else 0
    severity = (event.get("alert") or {}).get("severity") or (event.get("alert") or {}).get("severity_hint") or "medium"
    severity_encoded = severity_map.get(str(severity).lower(), 1)

    detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
    perimeter_vendor = _norm_provider(provider)

    row = {}
    for col in feature_columns:
        if col == "reputation_score":
            row[col] = rep_score
        elif col == "hit_count":
            row[col] = hit_count
        elif col == "is_whitelisted":
            row[col] = is_whitelisted
        elif col == "severity_encoded":
            row[col] = severity_encoded
        elif col.startswith("detector_type_"):
            row[col] = 1 if col == f"detector_type_{detector_type}" else 0
        elif col.startswith("perimeter_vendor_"):
            row[col] = 1 if col == f"perimeter_vendor_{perimeter_vendor}" else 0
        else:
            row[col] = 0

    try:
        df_input = pd.DataFrame([row], columns=feature_columns)
        pred = int(model.predict(df_input)[0])
        prob = float(model.predict_proba(df_input)[0][1])
        return pred, prob
    except Exception as e:
        print(f"[ML] Inference error: {e}. Falling back to rule-based logic.")
        if detector_type == "alert_webshell_immediate" or rep_score >= 80:
            return 1, 0.95
        return 0, 0.05

# ==== KONFIGURASI ====
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_KEY  = os.environ.get("REDIS_KEY", "logstash_alert_queue")

TELEGRAM_BOT     = os.environ.get("TELEGRAM_BOT", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_PROCESS_CHAT_ID = os.environ.get("TELEGRAM_PROCESS_CHAT_ID", "") or TELEGRAM_CHAT_ID

ABUSEIPDB_API_KEY   = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_CACHE_TTL = int(os.environ.get("ABUSEIPDB_CACHE_TTL", str(6 * 3600)))
IPAPI_CACHE_TTL     = int(os.environ.get("IPAPI_CACHE_TTL", str(12 * 3600)))
LOOKUP_TIMEOUT      = int(os.environ.get("LOOKUP_TIMEOUT", "4"))
DE_DISABLE_BUTTONS  = os.environ.get("DE_DISABLE_BUTTONS", "0")

ES_HOSTS = os.environ.get("ES_HOSTS", "")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")
ES_VERIFY = os.environ.get("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
ES_EVENTS_INDEX_PREFIX = os.environ.get("ES_EVENTS_INDEX_PREFIX", "minisoar-events")
ES_TIMEOUT = int(os.environ.get("ES_TIMEOUT", "6"))

LOCAL_TZ = timezone(timedelta(hours=7), name="WIB")
_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
ISO_FRACTION_RE = re.compile(
    r"^(?P<ymdhms>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)

# ==== PATH RESOLUTION SYSTEM (Cross-platform support) ====
def resolve_path(env_key: str, default_linux_path: str, default_win_filename: str) -> str:
    # 1. Check env override
    val = os.environ.get(env_key)
    if val:
        return val
    # 2. Windows fallback to script directory
    script_dir = Path(__file__).resolve().parent
    if os.name == "nt":
        return str(script_dir / default_win_filename)
    # 3. Linux/WSL check if parent folder is accessible
    try:
        parent = os.path.dirname(default_linux_path)
        if parent and os.path.exists(parent):
            return default_linux_path
    except Exception:
        pass
    return str(script_dir / default_win_filename)

BYPASS_FILE_PATH = resolve_path("BYPASS_FILE", "/etc/logstash/minisoar-bypass.txt", "minisoar-bypass.txt")
PERIMETER_MAP_PATH = resolve_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "minisoar-perimeter.yml")
UNMAPPED_LOG_PATH = resolve_path("UNMAPPED_LOG_PATH", "/var/log/minisoar-unmapped-sites.log", "minisoar-unmapped-sites.log")
UNMAPPED_LOG_TTL_SEC = int(os.environ.get("UNMAPPED_LOG_TTL_SEC", "86400"))  # 1 hari

# ==== WHITELIST (tetap: notif tanpa tombol) ====
WHITELIST = [
    "103.8.77.26", "172.30.100.0/22", "103.8.76.0/24", "103.8.77.0/24", "36.91.84.230/29",
    "182.23.23.206/29", "103.164.13.182/29", "202.89.116.0/24", "202.89.117.0/24",
    "172.30.0.0/24","172.30.11.0/24","172.30.12.0/24","172.30.96.0/24","172.30.32.0/24",
    "172.30.200.0/24","172.30.112.0/24", "103.119.138.1", "10.0.0.0/8"
]

def _load_cidr_list_from_env_and_file(env_key: str, file_path: str) -> List[str]:
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
        print(f"[BYPASS] warning: gagal baca file {file_path}: {e}")
    # dedup sambil pertahankan urutan
    seen = set(); out = []
    for n in nets:
        if n not in seen:
            seen.add(n); out.append(n)
    return out

# ==== BYPASS MODE (notif di-drop) ====
_BYPASS_NETS = _load_cidr_list_from_env_and_file("BYPASS_IPS", BYPASS_FILE_PATH)

def _ip_in_nets(ip: str, nets: List[str]) -> bool:
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

def is_ip_whitelisted(ip: str) -> bool:
    return _ip_in_nets(ip, WHITELIST)

def is_ip_bypassed(ip: str) -> bool:
    return _ip_in_nets(ip, _BYPASS_NETS)

# ==== PERIMETER MAP (website -> security perimeter) ====

_PERIMETER_MTIME = None
_PERIMETER_CFG: Dict[str, Any] = {}

def _load_perimeter_cfg() -> Dict[str, Any]:
    global _PERIMETER_MTIME, _PERIMETER_CFG
    try:
        m = os.path.getmtime(PERIMETER_MAP_PATH)
        if _PERIMETER_CFG and _PERIMETER_MTIME == m:
            return _PERIMETER_CFG
        with open(PERIMETER_MAP_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        if not isinstance(cfg, dict):
            cfg = {}
        _PERIMETER_CFG = cfg
        _PERIMETER_MTIME = m
    except Exception as e: 
        # File tidak ada / invalid -> fallback kosong (no buttons)
        print(f"[PERIMETER] gagal load {PERIMETER_MAP_PATH}: {e}")
        _PERIMETER_CFG = {}
    return _PERIMETER_CFG

def _norm_provider(p: Any) -> str:
    s = (p or "").strip().lower()
    # normalisasi alias penamaan
    if s in {"palo", "paloalto", "palo-alto", "palo_alto", "pan", "panos"}:
        return "paloalto"
    if s in {"akamai", "ak"}:
        return "akamai"
    if s in {"imperva", "imp"}:
        return "imperva"
    if s in {"none", "external", "eksternal", "outside", "off"}:
        return "none"
    return s or "none"

def provider_label(provider: str) -> str:
    p = _norm_provider(provider)
    if p == "akamai":
        return "Akamai"
    if p == "imperva":
        return "Imperva"
    if p == "paloalto":
        return "Palo Alto"
    return "external/none"

def get_perimeter_provider(server_name: str) -> str:
    host = (server_name or "").strip().lower()
    if not host:
        return "none"

    cfg = _load_perimeter_cfg()
    sites = cfg.get("sites") or {}
    if not isinstance(sites, dict):
        return "none"

    meta = sites.get(host)
    if isinstance(meta, dict):
        return _norm_provider(meta.get("provider"))
    if meta is not None:
        return _norm_provider(meta)

    return "none"


def provider_badge(provider: str, mapped: bool) -> str:
    p = _norm_provider(provider)
    if p == "akamai":
        return "🟢 Akamai"
    if p == "imperva":
        return "🔵 Imperva"
    if p == "paloalto":
        return "🟠 Palo Alto"
    if mapped:
        return "⚪ External/None"
    return "⚪ UNKNOWN (unmapped)"

def get_perimeter_info(server_name: str):
    host = (server_name or "").strip().lower()
    if not host:
        return ("none", False, None)

    cfg = _load_perimeter_cfg()
    sites = cfg.get("sites") or {}
    if not isinstance(sites, dict):
        return ("none", False, None)

    if host in sites:
        meta = sites.get(host)
        if isinstance(meta, dict):
            return (_norm_provider(meta.get("provider")), True, host)
        return (_norm_provider(meta), True, host)

    return ("none", False, None)

def _safe_append_line(path: str, line: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[WARN] cannot write unmapped log to {path}: {e}")

def log_unmapped_site_once_per_day(server_name: str, event: Dict[str, Any]):
    """Log website yang belum termapping (unmapped) ke file, max 1x/hari per website."""
    host = (server_name or "").strip().lower()
    if not host or host == "(unknown)":
        return

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rkey = f"minisoar:unmapped_site_logged:{today}:{host}"

    try:
        if r.get(rkey):
            return
        r.setex(rkey, UNMAPPED_LOG_TTL_SEC, "1")
    except Exception as e:
        print(f"[WARN] redis rate-limit for unmapped log failed: {e}")

    a = event.get("alert") or {}
    payload = {
        "ts_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "website": host,
        "src_ip": a.get("src_ip") or event.get("src_ip") or event.get("ip"),
        "type": a.get("type") or (a.get("tags") or ""),
        "severity": a.get("severity") or a.get("severity_hint") or (event.get("minisoar", {}) or {}).get("severity"),
        "sample_url": a.get("url") or event.get("url_original"),
    }
    _safe_append_line(UNMAPPED_LOG_PATH, json.dumps(payload, ensure_ascii=False))

def inject_perimeter_line(msg: str, perimeter: str) -> str:
    """Tambahkan bullet Perimeter ke message Telegram (tanpa duplikasi)."""
    if not msg:
        return msg
    if "*Perimeter:*" in msg or "Perimeter:" in msg:
        return msg

    per_line = f"• *Perimeter:* `{perimeter}`"
    lines = msg.splitlines()

    # Sisipkan setelah baris Website jika ada
    for i, line in enumerate(lines):
        if "*Website:*" in line:
            lines.insert(i + 1, per_line)
            return "\n".join(lines)

    # fallback: append di akhir
    return msg + "\n" + per_line


# ==== REDIS ====
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# ==== LOOKUP REPUTATION / GEO ====
def abuseipdb_lookup(ip):
    cache_key = f"reputation:abuseipdb:{ip}"
    cached = r.get(cache_key)
    if cached: return ip, cached
    if not ABUSEIPDB_API_KEY:
        return ip, "ℹ️ Skip Reputation (no key)"
    try:
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=60",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=LOOKUP_TIMEOUT
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
            r.setex(cache_key, ABUSEIPDB_CACHE_TTL, rep)
            return ip, rep
    except Exception as e:
        print("AbuseIPDB error:", e)
    r.setex(cache_key, 3600, "❓ Unreachable")
    return ip, "❓ Unreachable"

def ipapi_lookup(ip):
    cache_key = f"reputation:geo:{ip}"
    cached = r.get(cache_key)
    if cached: return ip, cached
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org",
            timeout=LOOKUP_TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            geo = f"{data.get('countryCode','--')}/{data.get('country','--')} ({data.get('isp','-')})"
            r.setex(cache_key, IPAPI_CACHE_TTL, geo)
            return ip, geo
    except Exception as e:
        print("ip-api error:", e)
    r.setex(cache_key, 3600, "??")
    return ip, "??"

def enrich_ip(ip):
    _, rep = abuseipdb_lookup(ip)
    _, geo = ipapi_lookup(ip)
    return rep, geo

def enrich_multi_ip(ip_list):
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

# ==== UTIL (ts parsing, dsb.) ====
def _parse_iso8601_relaxed(s: str) -> datetime:
    s = s.strip()
    m = ISO_FRACTION_RE.match(s)
    if not m:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    ymdhms = m.group("ymdhms")
    frac = m.group("frac") or ""
    tz = m.group("tz") or "+00:00"
    if frac:
        frac = "." + (frac[1:7])
    if tz == "Z":
        tz = "+00:00"
    return datetime.fromisoformat(ymdhms + frac + tz)

def _pick_ts_field(event: dict):
    for k in ("last_seen","last_ts","lastSeen","event_ts","end_ts","[alert][ts]","@timestamp","timestamp","ts"):
        v = event.get(k)
        if v is not None:
            return v
    alert = event.get("alert") or {}
    return alert.get("ts")

def _parse_ts_epoch(event: dict) -> Optional[int]:
    ts = _pick_ts_field(event)
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            sec = float(ts)
            if sec > 1e12:
                sec = sec / 1000.0
            return int(sec)
        if isinstance(ts, dict):
            for k in ("epoch_millis", "millis", "ms"):
                if k in ts:
                    return int(float(ts[k]) / 1000.0)
            if "epoch" in ts:
                return int(float(ts["epoch"]))
        dt = _parse_iso8601_relaxed(str(ts))
        return int(dt.timestamp())
    except Exception:
        return None

def _extract_top_paths(event: Dict[str, Any]) -> List[str]:
    a = event.get("alert") or {}
    samples = a.get("samples") or event.get("samples") or []
    top_urls = a.get("top_urls") or event.get("top_urls") or []
    url_list = a.get("url_list") or event.get("url_list") or []

    out = []
    if isinstance(samples, list):
        for s in samples:
            if isinstance(s, dict):
                u = s.get("url") or s.get("path") or s.get("request_path") or s.get("url_path")
                if u:
                    out.append(str(u))
            elif isinstance(s, str):
                out.append(s)
    if not out and isinstance(top_urls, list):
        for item in top_urls:
            if isinstance(item, dict):
                u = item.get("url")
                if u:
                    out.append(str(u))
            elif isinstance(item, str):
                out.append(item)
    if not out and isinstance(url_list, list):
        for u in url_list:
            if isinstance(u, str):
                out.append(u)
    return [u.strip() for u in out if u][:5]

def _sig_hash(parts: List[str]) -> str:
    base = "|".join([p.lower().strip() for p in parts if p])
    if not base:
        return "na"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]

def make_event_id(detector_type: str, asset_id: str, src_ip: str, ts_epoch: int, window_seconds: int, top_paths: List[str]) -> str:
    bucket = int(ts_epoch // window_seconds) * window_seconds
    sig = _sig_hash(top_paths)
    return f"{detector_type}|{asset_id}|{src_ip}|{bucket}|{sig}"

def _es_host() -> str:
    if not ES_HOSTS:
        return ""
    hosts = [h.strip() for h in ES_HOSTS.split(",") if h.strip()]
    return hosts[0] if hosts else ""

def _es_index(index_name: str, doc_id: str, payload: Dict[str, Any]):
    host = _es_host()
    if not host:
        return
    url = f"{host.rstrip('/')}/{index_name}/_doc/{doc_id}"
    auth = (ES_USER, ES_PASS) if ES_USER or ES_PASS else None
    try:
        resp = requests.put(url, json=payload, auth=auth, verify=ES_VERIFY, timeout=ES_TIMEOUT)
        if resp.status_code >= 400:
            print("ES index error:", resp.status_code, resp.text[:200])
    except Exception as e:
        print("ES index exception:", e)

def _fmt_last_seen(event: dict) -> Optional[str]:
    ts = _pick_ts_field(event)
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            sec = float(ts)
            if sec > 1e12: sec = sec / 1000.0
            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        elif isinstance(ts, dict):
            dt = None
            for k in ("epoch_millis","millis","ms"):
                if k in ts:
                    dt = datetime.fromtimestamp(float(ts[k])/1000.0, tz=timezone.utc); break
            if dt is None and "epoch" in ts:
                dt = datetime.fromtimestamp(float(ts["epoch"]), tz=timezone.utc)
            if dt is None:
                raw = json.dumps(ts, ensure_ascii=False)
                m = _ISO_RE.search(raw)
                if m: dt = _parse_iso8601_relaxed(m.group(0))
            if dt is None: return None
        else:
            dt = _parse_iso8601_relaxed(str(ts))
        return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return None

def _humanize_ago(delta_seconds: int) -> str:
    s = abs(int(delta_seconds))
    if s < 60: return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60: return f"{m}m {s}s"
    h, m = divmod(m, 60)
    if h < 24: return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"

def _bullet_last_seen(event) -> str:
    s = _fmt_last_seen(event)
    if not s: return ""
    try:
        raw = event.get("last_seen") or event.get("@timestamp") or event.get("timestamp") or (event.get("alert") or {}).get("ts")
        dt = _parse_iso8601_relaxed(str(raw)) if raw else None
        if dt is not None:
            ago = (datetime.now(LOCAL_TZ) - dt.astimezone(LOCAL_TZ)).total_seconds()
            return f"• *Last Seen:* {s} ({_humanize_ago(int(ago))} ago)\n"
    except Exception:
        pass
    return f"• *Last Seen:* {s}\n"

def _gx(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict): return default
        cur = cur.get(k)
        if cur is None: return default
    return cur

def _normalize_ip_list(ip_list: Any) -> List[Dict[str, Any]]:
    if not ip_list: return []
    if isinstance(ip_list, list) and all(isinstance(x, dict) and "ip" in x for x in ip_list):
        return ip_list
    if isinstance(ip_list, list) and all(isinstance(x, str) for x in ip_list):
        c = Counter(ip_list)
        return [{"ip": ip, "count": cnt} for ip, cnt in c.items()]
    return []

# ==== BUILD MESSAGE (tidak diubah) ====
def build_message(event: Dict[str, Any]) -> str:
    a = event.get("alert") or {}

    tags = event.get("tags") or a.get("tags") or []
    if isinstance(tags, str): tags = [tags]
    tags = set(tags)

    alert_type  = a.get("type")
    severity    = a.get("severity") or a.get("severity_hint") or (event.get("minisoar", {}) or {}).get("severity")
    server_name = a.get("server_name") or event.get("server_name") or event.get("servername") or "(unknown)"
    ip          = a.get("src_ip")     or event.get("src_ip") or event.get("ip") or "(unknown)"
    method      = a.get("method") or _gx(event, "http", "request", "method") or event.get("http_method") or event.get("method")
    url         = a.get("url")        or event.get("url_original") or ""
    status      = a.get("status")     or event.get("http_status") or ""
    count       = a.get("count")      or event.get("count") or ""
    url_list    = a.get("url_list")   or event.get("url_list") or []
    url_count   = a.get("url_count")  or event.get("urlcount") or len(url_list)
    ip_list     = a.get("ip_list")    or event.get("ip_list") or []
    top_urls    = a.get("top_urls")   or event.get("top_urls") or []
    samples     = a.get("samples")    or event.get("samples") or []

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

    if alert_type in {"alert_url_major","alert_url_minor"} or {"alert_url_major","alert_url_minor"} & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        if alert_type == "alert_url_major" or "alert_url_major" in tags:
            head = "🚨 *[MAJOR] Burst Access from 1 IP to 1 URL*"
        else:
            head = "🪪 *WebShell Burst (Minor)*" if "webshell_burst" in tags else "⚠️ *[MINOR] Burst Access Detected*"
        sample_lines = ""
        if isinstance(samples, list) and samples:
            rows = []
            for s in samples[:5]:
                # Bungkus nilai dinamis dengan backticks agar aman untuk Telegram Markdown.
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
            f"{_bullet_last_seen(event)}"
            + sample_lines
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
            ipi = ent["ip"]; cnt = ent.get("count", 0)
            rep = repgeo.get(ipi, {}).get("rep", "-"); geo = repgeo.get(ipi, {}).get("geo", "-")
            ip_lines.append(f"{i+1}. `{ipi}` ({cnt}x)\n    — {rep} | {geo}")
        url_lines = []
        if isinstance(top_urls, list) and top_urls:
            for i, item in enumerate(top_urls[:5], 1):
                if isinstance(item, dict):
                    u = item.get("url"); c = item.get("count")
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    u, c = item[0], item[1]
                else:
                    u, c = str(item), None
                if u: url_lines.append(f"{i}. `{u}`{f' ({c}x)' if c is not None else ''}")
        return (
            f"{emoji} *{title_plain}* {emoji}\n"
            f"• *Website:* `{server_name}`\n"
            f"• *Status Code:* `{status}`\n"
            f"• *Requests:* `{count}`\n"
            f"• *Unique IP:* `{len(norm)}`\n"
            f"{_bullet_last_seen(event)}"
            f"• *Top 5 IP:*\n" + ("\n".join(ip_lines) if ip_lines else "-") +
            ("\n• *Top 5 URLs:*\n" + ("\n".join(url_lines) if url_lines else "-") if top_urls else "")
        )

    if alert_type in {"alert_webshell_name","alert_webshell_heur"} or {"alert_webshell_name","alert_webshell_heur"} & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        inds = a.get("indicators") or (event.get("minisoar") or {}).get("webshell_indicators") or []
        ind_line = f"• *Indicators:* `{', '.join(inds)}`\n" if inds else ""
        sev = severity or ("high" if (alert_type=="alert_webshell_name" or "alert_webshell_name" in tags) else "medium")
        title = "WebShell Name Match" if (alert_type=="alert_webshell_name" or "alert_webshell_name" in tags) else "WebShell Heuristic"
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

    if alert_type in {"alert_gambling_slot","alert_url_probe"} or {"alert_gambling_slot","alert_url_probe"} & tags:
        rep, geo = enrich_ip(ip) if ip != "(unknown)" else ("-", "-")
        title_plain = "Gambling/Slot Pattern" if (alert_type=="alert_gambling_slot" or "alert_gambling_slot" in tags) else "Exploit/Probe URL"
        emoji = "🎰" if "gambling" in title_plain.lower() else "🛠️"
        sev = severity or ("high" if "Gambling" in title_plain else "medium")
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

# ==== TELEGRAM SENDER ====
def _build_callback_data(action: str, ip: str, event_id: str) -> str:
    if not event_id:
        return f"{action}:{ip}"
    payload = f"{ip}|{event_id}"
    full = f"{action}:{payload}"
    # Telegram callback_data limit is 64 bytes; keep it safe for ASCII payloads.
    if len(full) <= 64:
        return full
    return f"{action}:{ip}"


def send_telegram(msg, ip=None, ip_list=None, show_buttons=True, provider: str = "none", website: str = "", event_id: str = ""):
    """Kirim alert ke Telegram.

    - Sesuai rencana baru: hanya 1 tombol action, tergantung perimeter provider (akamai/imperva/paloalto).
    - Jika provider 'none' / tidak ada mapping / hosting eksternal -> tidak tampilkan tombol.
    """
    if not TELEGRAM_BOT or not TELEGRAM_CHAT_ID:
        print("[WARN] TELEGRAM_BOT / TELEGRAM_CHAT_ID not set — skipping send.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage"

    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }

    if show_buttons and ip and ip != "(unknown)":
        p = _norm_provider(provider)
        # hanya 1 tombol sesuai perimeter; jika none -> tanpa tombol
        if p in {"akamai", "imperva", "paloalto"}:
            # callback_data menjaga kompatibilitas dengan handler lama (blockonakamai / blockonimperva / blockonpalo)
            if p == "akamai":
                txt = f"🚫 Block di Akamai {ip}"
                cb = _build_callback_data("blockonakamai", ip, event_id)
            elif p == "imperva":
                txt = f"🚫 Block di Imperva {ip}"
                cb = _build_callback_data("blockonimperva", ip, event_id)
            else:
                txt = f"🛡️ Block di Palo Alto {ip}"
                cb = _build_callback_data("blockonpalo", ip, event_id)

            # Opsional: tambahkan nama website di label tombol (biar operator yakin)
            if website:
                txt = txt + f" ({website})"

            ignore_cb = _build_callback_data("ignore", ip, event_id)
            data["reply_markup"] = {"inline_keyboard": [[{"text": txt, "callback_data": cb}, {"text": "🙈 Ignore", "callback_data": ignore_cb}]]}

    try:
        resp = requests.post(url, json=data, timeout=10)
        if resp.status_code >= 400:
            print("Telegram error:", resp.status_code, resp.text)
        else:
            print("Alert sent (buttons:", "ON" if "reply_markup" in data else "OFF", ")")
    except Exception as e:
        print("Failed to send alert:", e)

# ==== MAIN LOOP ====
if __name__ == "__main__":
    try:
        # Startup Diagnostics
        print("=" * 60)
        print("⚡ MiniSOAR Alert Daemon — Startup Diagnostics")
        print("=" * 60)
        print(f"• OS Platform      : {os.name} ({'Windows' if os.name == 'nt' else 'Linux/WSL'})")
        print(f"• Redis Target     : {REDIS_HOST}:{REDIS_PORT} (Key: {REDIS_KEY})")
        print(f"• Bypass File Path : {BYPASS_FILE_PATH}")
        print(f"• Bypass Nets      : {_BYPASS_NETS}")
        print(f"• Perimeter Map    : {PERIMETER_MAP_PATH}")
        print(f"• Unmapped Log Path: {UNMAPPED_LOG_PATH}")
        
        bot_status = "SET" if TELEGRAM_BOT else "NOT SET"
        bot_masked = f"{TELEGRAM_BOT[:6]}...{TELEGRAM_BOT[-6:]}" if len(TELEGRAM_BOT) > 12 else TELEGRAM_BOT
        chat_status = "SET" if TELEGRAM_CHAT_ID else "NOT SET"
        proc_chat_status = "SET" if os.environ.get("TELEGRAM_PROCESS_CHAT_ID") else "NOT SET (FALLBACK)"
        
        print(f"• Telegram Bot Token: {bot_masked} ({bot_status})")
        print(f"• Telegram Chat ID  : {TELEGRAM_CHAT_ID} ({chat_status})")
        print(f"• Telegram Proc Chat: {TELEGRAM_PROCESS_CHAT_ID} ({proc_chat_status})")
        print("=" * 60)
        while True:
            try:
                item = r.blpop(REDIS_KEY, timeout=10)
                if not item:
                    continue
                _key, value = item
                try:
                    event = json.loads(value)
                except Exception as e:
                    print("JSON parse error:", e); continue

                if "last_seen" not in event and "@timestamp" in event:
                    event["last_seen"] = event["@timestamp"]

                ip = (event.get("alert") or {}).get("src_ip") or event.get("src_ip") or event.get("ip")
                website = (event.get('alert') or {}).get('server_name') or event.get('server_name') or event.get('servername') or ''
                provider, mapped, matched_key = get_perimeter_info(website)
                if not mapped:
                    log_unmapped_site_once_per_day(website, event)

                whitelisted = bool(ip and is_ip_whitelisted(ip))
                bypassed    = bool(ip and is_ip_bypassed(ip))

                # === BYPASS (single-IP events) : drop
                # (Untuk distributed, penanganan ada di cabang khusus di bawah)
                if bypassed:
                    print(f"[DROP/BYPASS] single IP {ip} — alert dropped.")
                    continue

                msg = build_message(event)
                perimeter = provider_badge(provider, mapped)
                msg = inject_perimeter_line(msg, perimeter)
                alert_type = (event.get("alert") or {}).get("type")
                tags = event.get("tags") or (event.get("alert") or {}).get("tags") or []
                if isinstance(tags, str): tags = [tags]
                tags = set(tags)

                ts_epoch = _parse_ts_epoch(event)
                if ts_epoch:
                    detector_type = (event.get("alert") or {}).get("type") or "alert_generic"
                    asset_id = (event.get("alert") or {}).get("server_name") or event.get("server_name") or "(unknown)"
                    src_ip = (event.get("alert") or {}).get("src_ip") or event.get("src_ip") or event.get("ip") or "(unknown)"
                    window_seconds = int(os.environ.get("MINISOAR_EVENT_WINDOW", "60"))
                    top_paths = _extract_top_paths(event)
                    event_id = make_event_id(detector_type, asset_id, src_ip, ts_epoch, window_seconds, top_paths)
                    event["event_id"] = event_id
                    event["detector_type"] = detector_type
                    event["severity"] = (event.get("alert") or {}).get("severity") or (event.get("alert") or {}).get("severity_hint")
                    asset = event.get("asset")
                    if not isinstance(asset, dict):
                        asset = {}
                        event["asset"] = asset
                    asset["id"] = asset_id

                    src = event.get("src")
                    if not isinstance(src, dict):
                        src = {}
                        event["src"] = src
                    src["ip"] = src_ip

                    perimeter = event.get("perimeter")
                    if not isinstance(perimeter, dict):
                        perimeter = {}
                        event["perimeter"] = perimeter
                    perimeter["vendor"] = _norm_provider(provider)

                    metrics = event.get("metrics")
                    if not isinstance(metrics, dict):
                        metrics = {}
                        event["metrics"] = metrics
                    metrics["hit_count"] = (event.get("alert") or {}).get("count") or event.get("count")
                    metrics["window_seconds"] = window_seconds

                    samples = event.get("samples")
                    if not isinstance(samples, dict):
                        samples = {}
                        event["samples"] = samples
                    samples["paths_top"] = top_paths

                    signature = event.get("signature")
                    if not isinstance(signature, dict):
                        signature = {}
                        event["signature"] = signature
                    signature["top_paths_hash"] = _sig_hash(top_paths)

                    dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
                    index_name = f"{ES_EVENTS_INDEX_PREFIX}-{dt.strftime('%Y.%m.%d')}"
                    es_doc = {
                        "@timestamp": dt.isoformat(),
                        "event_id": event_id,
                        "detector_type": detector_type,
                        "severity": event.get("severity"),
                        "asset": {"id": asset_id},
                        "src": {"ip": src_ip},
                        "perimeter": {"vendor": _norm_provider(provider)},
                        "metrics": {"hit_count": event.get("metrics", {}).get("hit_count"), "window_seconds": window_seconds},
                        "samples": {"paths_top": top_paths},
                        "signature": {"top_paths_hash": event.get("signature", {}).get("top_paths_hash")},
                        "alert": event.get("alert") or {},
                        "event": event,
                    }
                    _es_index(index_name, event_id, es_doc)
                else:
                    event_id = ""

                ip_list = (event.get("alert") or {}).get("ip_list") or event.get("ip_list")
                norm = _normalize_ip_list(ip_list)

                # === Distributed error: ALWAYS no buttons
                if alert_type == "alert_distributed_error" or "alert_distributed_error" in tags:
                    # Jika semua IP di event bypass ⇒ drop
                    ips = [ent.get("ip") for ent in (norm or []) if ent.get("ip")]
                    if ips and all(is_ip_bypassed(x) for x in ips):
                        print(f"[DROP/BYPASS] distributed all IP bypassed: {ips}")
                        continue
                    send_telegram(msg, show_buttons=False, event_id=event_id)
                    continue

                # === Single-IP style alerts: tombol ON kecuali whitelist / global disable
                if alert_type in {
                    "alert_random_url","alert_url_major","alert_url_minor","alert_gambling_slot",
                    "alert_webshell_name","alert_webshell_heur","alert_url_probe","alert_webshell_immediate"
                } or {"alert_random_url","alert_url_major","alert_url_minor","alert_gambling_slot",
                      "alert_webshell_name","alert_webshell_heur","alert_url_probe","alert_webshell_immediate"} & tags:
                    # 2026-05-26 - Pass real reputation string to predict_block
                    _, rep_str = abuseipdb_lookup(ip) if ip and ip != "(unknown)" else (ip, "")
                    pred_label, pred_prob = predict_block(event, ip, provider, whitelisted, rep_str)
                    mode = MINISOAR_BLOCKING_MODE
                    if mode == "AUTO":
                        if pred_label == 1:
                            # Auto-block the IP
                            success, blk_msg = trigger_auto_block(ip, provider)
                            # Log AI action
                            log_user_action("AUTO_BLOCK", {"username": "system"}, ip=ip, target=provider, note=f"ML prediction {pred_prob:.2%}")
                            # Prepend badge to message
                            msg = f"🤖 *AI Action: AUTO-BLOCKED* (Confidence: {pred_prob:.0%})\n" + msg
                            send_telegram(msg, ip=ip, show_buttons=False, provider=provider, website=website, event_id=event_id)
                            continue
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg
                    elif mode == "SEMI":
                        if pred_label == 1:
                            msg = f"🤖 *AI Recommendation: BLOCK* (Confidence: {pred_prob:.0%})\n" + msg
                        else:
                            msg = f"🤖 *AI Recommendation: ALLOW* (Confidence: {pred_prob:.0%})\n" + msg
                    # If whitelisted: send without buttons
                    show_btn = (DE_DISABLE_BUTTONS != "1" and not whitelisted)
                    if whitelisted:
                        print(f"[WL] {ip} whitelisted — sending alert without action buttons.")
                    send_telegram(msg, ip=ip, show_buttons=show_btn, provider=provider, website=website, event_id=event_id)
                else:
                    # Fallback
                    show_btn = (DE_DISABLE_BUTTONS != "1" and not whitelisted)
                    send_telegram(msg, ip=ip if ip else None, show_buttons=show_btn, provider=provider, website=website, event_id=event_id)

            except Exception as e:
                print("Redis loop error:", e)
                time.sleep(5)
    except KeyboardInterrupt:
        print("\n[INFO] Daemon alert dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")
