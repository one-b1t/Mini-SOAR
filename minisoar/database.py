from __future__ import annotations

import datetime
import logging
import os
from typing import Any

import redis
import requests

logger = logging.getLogger(__name__)


def redis_client() -> redis.StrictRedis:
    host = os.getenv("REDIS_HOST", "127.0.0.1")
    port = int(os.getenv("REDIS_PORT", "6379"))
    return redis.StrictRedis(host=host, port=port, decode_responses=True)


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


def store_label(event_id: str, label: str, user, reason_code: str, *, ip: str = None, telegram_message_id: str = None, chat_id: str = None):
    ts = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    labels_prefix = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
    index_name = f"{labels_prefix}-{datetime.datetime.utcnow().strftime('%Y.%m.%d')}"

    if hasattr(user, "id"):
        user_id = getattr(user, "id")
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
        "actor": {
            "username": username,
            "id": user_id,
        },
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
