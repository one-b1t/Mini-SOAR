from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests
import urllib3
import xmltodict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def build_object_name(ip: str) -> str:
    return f"{ip}minisoar"


def palo_api_request(pa_host: str, params: dict) -> dict:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Palo Alto API request: params=%s", params)
        action = params.get("action")
        if action == "commit":
            return {
                "response": {
                    "@status": "success",
                    "result": {"job": "1234", "msg": "Commit job started"},
                }
            }
        if params.get("type") == "log":
            now = time.strftime("%Y/%m/%d %H:%M:%S")
            return {
                "response": {
                    "@status": "success",
                    "result": {
                        "@count": "1",
                        "log": {
                            "entry": {
                                "time_generated": now,
                                "src": "203.0.113.10",
                                "dst": "198.51.100.20",
                                "app": "ssl",
                                "action": "alert",
                                "threatid": params.get("query", "40001"),
                                "severity": "critical",
                                "category": "info-leak",
                                "serial": "MOCK0000001",
                                "sessionid": "12345",
                                "repeat": "1",
                            }
                        },
                    },
                }
            }
        return {"response": {"@status": "success", "result": "Mocked configuration command successful"}}

    try:
        url = f"{pa_host}/api/"
        r = requests.get(url, params=params, verify=False, timeout=10)
        r.raise_for_status()
        return xmltodict.parse(r.text)
    except Exception as e:
        return {"error": str(e)}


def add_address_object(pa_host: str, pa_api_key: str, *, ip: str, vsys: str) -> dict:
    name = build_object_name(ip)
    params = {
        "type": "config",
        "action": "set",
        "key": pa_api_key,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address",
        "element": f"<entry name='{name}'><ip-netmask>{ip}</ip-netmask></entry>",
    }
    return palo_api_request(pa_host, params)


def add_to_group(pa_host: str, pa_api_key: str, *, ip: str, vsys: str, group: str) -> dict:
    name = build_object_name(ip)
    params = {
        "type": "config",
        "action": "set",
        "key": pa_api_key,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address-group/entry[@name='{group}']/static",
        "element": f"<member>{name}</member>",
    }
    return palo_api_request(pa_host, params)


def remove_from_group(pa_host: str, pa_api_key: str, *, ip: str, vsys: str, group: str) -> dict:
    name = build_object_name(ip)
    params = {
        "type": "config",
        "action": "delete",
        "key": pa_api_key,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address-group/entry[@name='{group}']/static/member[text()='{name}']",
    }
    return palo_api_request(pa_host, params)


def delete_address_object(pa_host: str, pa_api_key: str, *, ip: str, vsys: str) -> dict:
    name = build_object_name(ip)
    params = {
        "type": "config",
        "action": "delete",
        "key": pa_api_key,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address/entry[@name='{name}']",
    }
    return palo_api_request(pa_host, params)


def partial_commit(pa_host: str, pa_api_key: str, *, admin: str) -> dict:
    params = {
        "type": "commit",
        "key": pa_api_key,
        "cmd": f"<commit><partial><admin><member>{admin}</member></admin></partial></commit>",
    }
    return palo_api_request(pa_host, params)


def query_threat_log(
    pa_host: str,
    pa_api_key: str,
    *,
    threat_id: str | None = None,
    session_id: str | None = None,
    src_ip: str | None = None,
    nlogs: int = 50,
) -> dict:
    """Query PAN-OS threat logs via the XML API (type=log, log-type=threat).

    Pass exactly one filter: threat_id, session_id, or src_ip. The returned
    dict mirrors the XML structure from xmltodict:
    {"response": {"@status": ..., "result": {"log": {"entry": {...}}}}}
    """
    if threat_id:
        field = f"( eq ( threatid {threat_id.strip()} ) )"
    elif session_id:
        field = f"( eq ( sessionid {session_id.strip()} ) )"
    elif src_ip:
        field = f"( eq ( src {src_ip.strip()} ) )"
    else:
        return {"error": "No filter given (threat_id, session_id, or src_ip)"}

    params = {
        "type": "log",
        "log-type": "threat",
        "query": field,
        "nlogs": nlogs,
        "key": pa_api_key,
    }
    return palo_api_request(pa_host, params)


def parse_threat_logs(resp: dict) -> tuple[list[dict], str | None]:
    """Flatten a PAN-OS threat-log response into a list of entry dicts.

    Returns (entries, error). Entries are normalized: keys are stripped of
    their '@' prefix (XML attributes become like "@count") and 'time_generated'
    is a local time string as returned by the firewall.
    """
    if "error" in resp:
        return [], resp["error"]

    try:
        status = resp["response"]["@status"]
        if status != "success":
            return [], resp["response"].get("msg", "Unknown error")
        result = resp["response"].get("result") or {}
        count = int(result.get("@count") or 0)
        log_node = result.get("log") or {}
        entry_node = log_node.get("entry") or []
        if isinstance(entry_node, dict):
            entries = [entry_node]
        else:
            entries = entry_node or []
        return entries[:count] if count else entries, None
    except Exception as e:
        return [], f"Invalid response format: {e}"


def response_message(resp: dict, action_desc: str) -> str:
    if "error" in resp:
        return f"{action_desc}: ERROR - {resp['error']}"
    try:
        status = resp["response"]["@status"]
        if status == "success":
            return f"{action_desc}: SUCCESS"
        msg = resp["response"].get("msg", "Unknown error")
        return f"{action_desc}: FAILED - {msg}"
    except Exception:
        return f"{action_desc}: ERROR - Invalid response format"
