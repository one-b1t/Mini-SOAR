from __future__ import annotations

import logging
import os
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
