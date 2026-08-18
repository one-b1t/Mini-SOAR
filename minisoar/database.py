from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
from typing import Any

import redis
import requests

from .utils import parse_iso8601_relaxed

logger = logging.getLogger(__name__)


# -----------------
# Redis
# -----------------

def redis_client() -> redis.StrictRedis:
    host = os.getenv("REDIS_HOST", "127.0.0.1")
    port = int(os.getenv("REDIS_PORT", "6379"))
    return redis.StrictRedis(host=host, port=port, decode_responses=True)


# -----------------
# Elasticsearch
# -----------------

def es_host() -> str:
    hosts = os.getenv("ES_HOSTS", "")
    if not hosts:
        return ""
    all_hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    return all_hosts[0] if all_hosts else ""


def es_verify_value():
    ca_bundle = os.getenv("ES_CA_BUNDLE", "").strip()
    es_verify = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
    return ca_bundle or es_verify


def es_index(index_name: str, doc_id: str, payload: dict[str, Any]) -> None:
    host = es_host()
    if not host:
        return
    url = f"{host.rstrip('/')}/{index_name}/_doc/{doc_id}"
    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if es_user or es_pass else None

    try:
        resp = requests.put(url, json=payload, auth=auth, verify=es_verify_value(), timeout=es_timeout)
        if resp.status_code >= 400:
            logger.warning("ES index error %s: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("ES index exception: %s", e)


def es_find_latest_event_id_by_ip(ip: str, approx_dt: datetime.datetime | None = None, window_minutes: int = 30) -> str | None:
    host = es_host()
    if not host or not ip:
        return None

    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if es_user or es_pass else None

    url = f"{host.rstrip('/')}/minisoar-events-*/_search"

    must = []
    if approx_dt:
        try:
            if getattr(approx_dt, "tzinfo", None) is not None:
                approx_dt = approx_dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        except (ValueError, TypeError) as e:
            logger.debug("Failed to normalize approx_dt timezone: %s", e)
        start = (approx_dt - datetime.timedelta(minutes=window_minutes)).replace(microsecond=0).isoformat() + "Z"
        end = (approx_dt + datetime.timedelta(minutes=window_minutes)).replace(microsecond=0).isoformat() + "Z"
        must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

    should = [
        {"term": {"src.ip.keyword": ip}},
        {"term": {"src.ip": ip}},
        {"term": {"alert.src_ip.keyword": ip}},
        {"term": {"alert.src_ip": ip}},
        {"term": {"event.src.ip.keyword": ip}},
        {"term": {"event.src.ip": ip}},
        {"term": {"event.alert.src_ip.keyword": ip}},
        {"term": {"event.alert.src_ip": ip}},
    ]

    query = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["event_id", "event.event_id", "rule.id", "alert.src_ip", "src.ip", "@timestamp"],
        "query": {"bool": {"must": must, "should": should, "minimum_should_match": 1}},
    }

    try:
        resp = requests.get(url, json=query, auth=auth, verify=es_verify_value(), timeout=es_timeout)
        if resp.status_code >= 400:
            logger.warning("ES event lookup error %s: %s", resp.status_code, resp.text[:200])
            return None
        data = resp.json()
        hits = (data.get("hits") or {}).get("hits") or []
        if not hits:
            return None
        src = hits[0].get("_source") or {}
        return src.get("event_id") or (src.get("event") or {}).get("event_id") or (src.get("rule") or {}).get("id")
    except Exception as e:
        logger.warning("ES event lookup exception: %s", e)
        return None


def store_label(
    event_id: str,
    label: str,
    user,
    reason_code: str,
    *,
    ip: str | None = None,
    telegram_message_id: str | None = None,
    chat_id: str | int | None = None,
):
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    ts = now_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    labels_prefix = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
    index_name = f"{labels_prefix}-{now_utc.strftime('%Y.%m.%d')}"

    if hasattr(user, "id"):
        user_id = user.id
        username = getattr(user, "username", None) or getattr(user, "full_name", None)
    elif isinstance(user, dict):
        user_id = user.get("id")
        username = user.get("username")
    else:
        user_id = "system"
        username = str(user)

    doc = {
        "@timestamp": ts,
        "event_id": event_id,
        "label": label,
        "actor": {"username": username, "id": user_id},
        "reason_code": reason_code,
    }
    if ip:
        doc["src"] = {"ip": ip}
    if telegram_message_id is not None or chat_id is not None:
        doc["telegram"] = {}
        if telegram_message_id is not None:
            doc["telegram"]["message_id"] = str(telegram_message_id)
        if chat_id is not None:
            doc["telegram"]["chat_id"] = str(chat_id)

    base = event_id or ip or "na"
    doc_id = f"{base}:{label}:{user_id}:{telegram_message_id or 'na'}"
    es_index(index_name, doc_id, doc)


# -----------------
# Event ID helpers
# -----------------

def extract_top_paths(event: dict[str, Any]) -> list[str]:
    a = event.get("alert") or {}
    samples = a.get("samples") or event.get("samples") or []
    top_urls = a.get("top_urls") or event.get("top_urls") or []
    url_list = a.get("url_list") or event.get("url_list") or []

    out: list[str] = []
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


def sig_hash(parts: list[str]) -> str:
    base = "|".join([p.lower().strip() for p in parts if p])
    if not base:
        return "na"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:12]



def make_event_id(detector_type: str, asset_id: str, src_ip: str, ts_epoch: int, window_seconds: int, top_paths: list[str]) -> str:
    bucket = int(ts_epoch // window_seconds) * window_seconds
    sig = sig_hash(top_paths)
    return f"{detector_type}|{asset_id}|{src_ip}|{bucket}|{sig}"


def parse_ts_epoch(event: dict) -> int | None:
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
            return int(sec)
        if isinstance(ts, dict):
            for k in ("epoch_millis", "millis", "ms"):
                if k in ts:
                    return int(float(ts[k]) / 1000.0)
            if "epoch" in ts:
                return int(float(ts["epoch"]))
            raw = json.dumps(ts, ensure_ascii=False)
            # best-effort ISO extraction
            for token in raw.split():
                if "T" in token and len(token) >= 19:
                    try:
                        dt = parse_iso8601_relaxed(token.strip('" ,'))
                        return int(dt.timestamp())
                    except (ValueError, TypeError):
                        logger.debug("Failed parsing token timestamp: %s", token)
            return None

        dt = parse_iso8601_relaxed(str(ts))
        return int(dt.timestamp())
    except Exception:
        return None


def es_get_event_website_by_id(event_id: str) -> str | None:
    host = es_host()
    if not host or not event_id:
        return None

    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if es_user or es_pass else None

    url = f"{host.rstrip('/')}/minisoar-events-*/_search"
    query = {
        "size": 1,
        "query": {
            "ids": {
                "values": [event_id]
            }
        },
        "_source": ["host.name", "host.hostname", "log.source", "alert.server_name", "server_name", "event.host.name", "event.host.hostname", "event.log.source", "event.alert.server_name", "event.server_name"]
    }

    try:
        resp = requests.get(url, json=query, auth=auth, verify=es_verify_value(), timeout=es_timeout)
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            if hits:
                src = hits[0].get("_source", {})
                website = (
                    src.get("server_name")
                    or src.get("alert", {}).get("server_name")
                    or src.get("host", {}).get("name")
                    or src.get("host", {}).get("hostname")
                    or src.get("log", {}).get("source")
                )
                if not website and "event" in src:
                    ev = src["event"]
                    website = (
                        ev.get("server_name")
                        or ev.get("alert", {}).get("server_name")
                        or ev.get("host", {}).get("name")
                        or ev.get("host", {}).get("hostname")
                        or ev.get("log", {}).get("source")
                    )
                return website
    except Exception as e:
        logger.warning("Gagal mengambil website event %s dari ES: %s", event_id, e)
    return None


def es_get_latest_event_website_by_ip(ip: str) -> str | None:
    host = es_host()
    if not host or not ip:
        return None

    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if es_user or es_pass else None

    url = f"{host.rstrip('/')}/minisoar-events-*/_search"

    should = [
        {"term": {"src.ip.keyword": ip}},
        {"term": {"src.ip": ip}},
        {"term": {"alert.src_ip.keyword": ip}},
        {"term": {"alert.src_ip": ip}},
        {"term": {"event.src.ip.keyword": ip}},
        {"term": {"event.src.ip": ip}},
        {"term": {"event.alert.src_ip.keyword": ip}},
        {"term": {"event.alert.src_ip": ip}},
    ]

    query = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["host.name", "host.hostname", "log.source", "alert.server_name", "server_name", "event.host.name", "event.host.hostname", "event.log.source", "event.alert.server_name", "event.server_name"],
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
    }

    try:
        resp = requests.get(url, json=query, auth=auth, verify=es_verify_value(), timeout=es_timeout)
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            if hits:
                src = hits[0].get("_source", {})
                website = (
                    src.get("server_name")
                    or src.get("alert", {}).get("server_name")
                    or src.get("host", {}).get("name")
                    or src.get("host", {}).get("hostname")
                    or src.get("log", {}).get("source")
                )
                if not website and "event" in src:
                    ev = src["event"]
                    website = (
                        ev.get("server_name")
                        or ev.get("alert", {}).get("server_name")
                        or ev.get("host", {}).get("name")
                        or ev.get("host", {}).get("hostname")
                        or ev.get("log", {}).get("source")
                    )
                return website
    except Exception as e:
        logger.warning("Gagal mengambil website terbaru IP %s dari ES: %s", ip, e)
    return None


def es_count_hits_by_ip(ip: str) -> tuple[int, str | None]:
    """Query total incident count and latest attack description for an IP in Elasticsearch."""
    host = es_host()
    if not host or not ip:
        return 0, None

    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if es_user or es_pass else None

    url = f"{host.rstrip('/')}/minisoar-events-*/_search"
    should = [
        {"term": {"src.ip.keyword": ip}},
        {"term": {"src.ip": ip}},
        {"term": {"alert.src_ip.keyword": ip}},
        {"term": {"alert.src_ip": ip}},
        {"term": {"event.src.ip.keyword": ip}},
        {"term": {"event.src.ip": ip}},
    ]
    query = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
    }

    try:
        resp = requests.get(url, json=query, auth=auth, verify=es_verify_value(), timeout=es_timeout)
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            hits = data.get("hits", {}).get("hits", [])
            latest_action = None
            if hits:
                src = hits[0].get("_source", {})
                latest_action = src.get("alert", {}).get("signature") or src.get("rule", {}).get("name") or src.get("event", {}).get("action")
            return total, latest_action
    except Exception as e:
        logger.warning("Gagal menanyakan hit count IP %s dari ES: %s", ip, e)
    return 0, None


def get_system_health() -> dict[str, Any]:
    """Collect real-time health diagnostic metrics across Redis, Elasticsearch, and AI Copilot."""
    health: dict[str, Any] = {
        "redis": {"status": "OFFLINE", "queue_len": 0},
        "elasticsearch": {"status": "OFFLINE", "indices": 0},
        "ai": {"provider": "none", "model": "none"},
    }

    # 1. Redis
    try:
        r = redis_client()
        if r.ping():
            q_len = r.llen("logstash_alert_queue")
            health["redis"] = {"status": "OK", "queue_len": q_len}
    except Exception as e:
        health["redis"] = {"status": "ERROR", "error": str(e), "queue_len": 0}

    # 2. Elasticsearch
    host = es_host()
    if host:
        try:
            es_user = os.getenv("ES_USER", "")
            es_pass = os.getenv("ES_PASS", "")
            auth = (es_user, es_pass) if es_user or es_pass else None
            resp = requests.get(f"{host.rstrip('/')}/_cluster/health", auth=auth, verify=es_verify_value(), timeout=4)
            if resp.status_code == 200:
                cluster_status = resp.json().get("status", "unknown").upper()
                health["elasticsearch"] = {"status": cluster_status, "host": host}
        except Exception as e:
            health["elasticsearch"] = {"status": "ERROR", "error": str(e)}

    # 3. AI Copilot
    try:
        from .ai import copilot
        info = copilot.get_auth_info()
        health["ai"] = {"provider": info.get("provider", "none"), "model": info.get("model", "none")}
    except Exception:
        pass

    return health

