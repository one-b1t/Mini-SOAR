import datetime
import json
import logging
from typing import Any, Dict, List

from .config import norm_provider

logger = logging.getLogger(__name__)

def remove_empty(d: Any) -> Any:
    if isinstance(d, dict):
        cleaned = {k: remove_empty(v) for k, v in d.items() if v is not None}
        return {k: v for k, v in cleaned.items() if v != {} and v != []}
    if isinstance(d, list):
        cleaned = [remove_empty(v) for v in d if v is not None]
        return [v for v in cleaned if v != {} and v != []]
    return d

def normalize_to_ecs(
    raw_event: dict,
    event_id: str,
    providers: list,
    minisoar_event_window: int,
    ts_epoch: int
) -> dict:
    alert = raw_event.get("alert") or {}
    tags = raw_event.get("tags") or alert.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
        
    alert_type = alert.get("type") or "unknown"
    severity_raw = alert.get("severity") or alert.get("severity_hint") or raw_event.get("severity")
    
    # Priority & Severity logic
    severity = 0
    if isinstance(severity_raw, int) or (isinstance(severity_raw, str) and severity_raw.isdigit()):
        severity = int(severity_raw)
    elif isinstance(severity_raw, str):
        s_low = severity_raw.lower()
        if s_low == "critical": severity = 95
        elif s_low == "high": severity = 75
        elif s_low == "medium": severity = 50
        elif s_low == "low": severity = 25
        
    priority = "P5"
    if severity >= 90: priority = "P1"
    elif severity >= 70: priority = "P2"
    elif severity >= 40: priority = "P3"
    elif severity >= 20: priority = "P4"
    
    # Category mapping based on alert_type
    category = []
    type_list = ["indicator"]
    kind = "alert"
    action = "detected"
    
    if alert_type.startswith("alert_webshell"):
        category = ["malware", "web"]
    elif "sqli" in alert_type or "xss" in alert_type or "lfi" in alert_type or "rce" in alert_type:
        category = ["intrusion_detection", "web"]
    elif alert_type.startswith("alert_url"):
        category = ["network", "web"]
        type_list = ["access"]
    else:
        category = ["host"]
        type_list = ["info"]
        
    # Timestamps
    dt_obj = datetime.datetime.fromtimestamp(ts_epoch, tz=datetime.timezone.utc)
    timestamp_str = dt_obj.isoformat()
    
    raw_log_str = json.dumps(raw_event, ensure_ascii=False)
    
    src_ip = alert.get("src_ip") or raw_event.get("src_ip") or raw_event.get("ip")
    server_name = alert.get("server_name") or raw_event.get("server_name") or raw_event.get("servername")
    method = alert.get("method") or raw_event.get("http_method") or raw_event.get("method")
    status = alert.get("status") or raw_event.get("http_status")
    if isinstance(status, str) and status.isdigit():
        status = int(status)
    url_orig = alert.get("url") or raw_event.get("url_original")
    
    # Observer
    vendor = norm_provider(providers[0]) if providers else "unknown"
    
    # Dedup key
    # Format: "<event.action>|<source.ip>|<destination.ip>|<destination.port>|<user.name>|<rule.name>|<file.hash.sha256>"
    action_key = action or "unknown"
    sip_key = src_ip or "unknown"
    dip_key = "unknown"
    dport_key = "unknown"
    user_key = "unknown"
    rule_key = alert_type or "unknown"
    hash_key = "unknown"
    dedup_key = f"{action_key}|{sip_key}|{dip_key}|{dport_key}|{user_key}|{rule_key}|{hash_key}"
    
    # Related arrays
    related_ips = set()
    if src_ip: related_ips.add(src_ip)
    related_hosts = set()
    if server_name: related_hosts.add(server_name)
    
    doc = {
        "@timestamp": timestamp_str,
        "message": f"MiniSOAR Alert: {alert_type}",
        "raw_log": raw_log_str,
        "event": {
            "kind": kind,
            "category": category,
            "type": type_list,
            "action": action,
            "outcome": "unknown",
            "severity": severity,
            "risk_score": severity,
            "original": raw_log_str,
            "original_time": None,
            "dataset": "mini_soar.normalized",
            "module": "mini_soar",
            "timezone": None
        },
        "log": {
            "level": "warning" if severity >= 40 else "info",
            "logger": "minisoar",
            "source": server_name
        },
        "observer": {
            "name": "minisoar",
            "type": "siem",
            "vendor": vendor,
        },
        "host": {
            "name": server_name,
            "hostname": server_name,
        },
        "source": {
            "ip": src_ip,
        },
        "http": {
            "request": {
                "method": str(method).lower() if method else None
            },
            "response": {
                "status_code": status
            }
        },
        "url": {
            "original": url_orig
        },
        "rule": {
            "name": alert_type,
            "id": event_id
        },
        "related": {
            "ip": list(related_ips),
            "hosts": list(related_hosts),
            "user": [],
            "hash": []
        },
        "labels": {
            "normalization_status": "success",
            "parser": "python-ecs",
            "parser_version": "mini-soar-elastic-v1",
            "timezone_missing": False,
            "dedup_key": dedup_key,
            "recommended_action": "investigate" if severity >= 70 else "monitor",
            "recommended_priority": priority
        },
        "tags": ["mini-soar", "normalized"] + list(tags)
    }
    
    # Allow related to be empty lists instead of removing them entirely
    
    # Remove nulls/empty according to omission rule, but keep required fields
    cleaned = remove_empty(doc)
    
    # Ensure mandatory fields are present
    mandatory = ["@timestamp", "message", "raw_log", "event", "labels", "tags"]
    for m in mandatory:
        if m not in cleaned:
            cleaned[m] = doc.get(m)
            
    # Keep related arrays if missing
    if "related" not in cleaned:
        cleaned["related"] = doc["related"]
    else:
        for rm in ["ip", "hosts", "user", "hash"]:
            if rm not in cleaned["related"]:
                cleaned["related"][rm] = doc["related"][rm]
            
    # Also ensure event has mandatory fields
    event_mand = ["kind", "category", "type", "action", "outcome", "severity"]
    if "event" not in cleaned:
        cleaned["event"] = {}
    for em in event_mand:
        if em not in cleaned["event"]:
            cleaned["event"][em] = doc["event"].get(em)
            
    return cleaned
