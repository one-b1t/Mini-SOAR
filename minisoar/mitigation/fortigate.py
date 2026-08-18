from __future__ import annotations

"""Fortinet FortiGate Firewall REST API Integration."""

import logging
import os
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _get_base_url() -> str:
    return os.getenv("FORTIGATE_HOST", "").rstrip("/")


def _get_headers() -> dict[str, str]:
    token = os.getenv("FORTIGATE_API_TOKEN", "")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _get_verify_ssl() -> bool:
    return os.getenv("FORTIGATE_VERIFY_SSL", "0").lower() in {"1", "true", "yes"}


def is_configured() -> bool:
    return bool(os.getenv("FORTIGATE_HOST") and os.getenv("FORTIGATE_API_TOKEN"))


def check_connectivity() -> dict[str, Any]:
    """Tests connectivity to FortiGate FortiOS REST API."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return {"provider": "fortigate", "ok": True, "configured": True, "error": None, "hint": None}

    if not is_configured():
        return {
            "provider": "fortigate",
            "ok": False,
            "configured": False,
            "error": "FORTIGATE_HOST or FORTIGATE_API_TOKEN not configured",
            "hint": "Set FORTIGATE_HOST and FORTIGATE_API_TOKEN in .env",
        }

    url = f"{_get_base_url()}/api/v2/monitor/system/status"
    try:
        resp = requests.get(url, headers=_get_headers(), verify=_get_verify_ssl(), timeout=10)
        if resp.status_code == 200:
            return {"provider": "fortigate", "ok": True, "configured": True, "error": None, "hint": None}
        return {
            "provider": "fortigate",
            "ok": False,
            "configured": True,
            "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
            "hint": "Check FortiGate API token permissions and VDOM settings",
        }
    except Exception as e:
        return {
            "provider": "fortigate",
            "ok": False,
            "configured": True,
            "error": str(e),
            "hint": "Check network connectivity and HTTPS port to FortiGate host",
        }


def block_ip(
    ip: str,
    *,
    group_name: str | None = None,
    comment: str = "MiniSOAR automated block",
) -> tuple[bool, str]:
    """Creates a firewall address object and assigns it to the blacklist address group."""
    addr_group = group_name or os.getenv("FORTIGATE_BLOCK_GROUP", "MiniSOAR_Blacklist")
    addr_name = f"ADDR_{ip.replace('.', '_')}"

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] FortiGate block IP: %s (Group=%s)", ip, addr_group)
        return True, f"SUCCESS: IP {ip} added to FortiGate group {addr_group} (Mock)"

    if not is_configured():
        return False, "FortiGate is not configured."

    base = _get_base_url()
    headers = _get_headers()
    verify = _get_verify_ssl()

    # 1. Create Address Object
    addr_url = f"{base}/api/v2/cmdb/firewall/address"
    addr_payload = {
        "name": addr_name,
        "type": "ipmask",
        "subnet": f"{ip} 255.255.255.255",
        "comment": comment,
    }

    try:
        resp = requests.post(addr_url, headers=headers, json=addr_payload, verify=verify, timeout=15)
        if resp.status_code not in {200, 424, 500} and resp.status_code >= 400:
            return False, f"Failed to create FortiGate address {addr_name}: HTTP {resp.status_code} {resp.text[:200]}"

        # 2. Add to Address Group
        grp_url = f"{base}/api/v2/cmdb/firewall/addrgrp/{addr_group}/member"
        grp_payload = {"name": addr_name}
        grp_resp = requests.post(grp_url, headers=headers, json=grp_payload, verify=verify, timeout=15)
        if grp_resp.status_code in {200, 201}:
            return True, f"SUCCESS: IP {ip} added to FortiGate address group {addr_group}"
        return False, f"Failed to assign address to group {addr_group}: {grp_resp.text[:300]}"
    except Exception as e:
        return False, f"FortiGate request failed: {e}"


def unblock_ip(
    ip: str,
    *,
    group_name: str | None = None,
) -> tuple[bool, str]:
    """Removes an IP address object from FortiGate address group and deletes object."""
    addr_group = group_name or os.getenv("FORTIGATE_BLOCK_GROUP", "MiniSOAR_Blacklist")
    addr_name = f"ADDR_{ip.replace('.', '_')}"

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] FortiGate unblock IP: %s (Group=%s)", ip, addr_group)
        return True, f"SUCCESS: IP {ip} removed from FortiGate group {addr_group} (Mock)"

    if not is_configured():
        return False, "FortiGate is not configured."

    base = _get_base_url()
    headers = _get_headers()
    verify = _get_verify_ssl()

    try:
        # 1. Remove from group
        grp_url = f"{base}/api/v2/cmdb/firewall/addrgrp/{addr_group}/member/{addr_name}"
        requests.delete(grp_url, headers=headers, verify=verify, timeout=15)

        # 2. Delete address object
        addr_url = f"{base}/api/v2/cmdb/firewall/address/{addr_name}"
        del_resp = requests.delete(addr_url, headers=headers, verify=verify, timeout=15)
        if del_resp.status_code in {200, 404}:
            return True, f"SUCCESS: IP {ip} removed from FortiGate"
        return False, f"Failed to delete FortiGate address {addr_name}: {del_resp.text[:300]}"
    except Exception as e:
        return False, f"FortiGate unblock error: {e}"
