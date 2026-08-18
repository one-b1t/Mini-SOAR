from __future__ import annotations

"""Cloudflare WAF / Edge Firewall Integration."""

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)


def _get_headers() -> dict[str, str]:
    token = os.getenv("CLOUDFLARE_API_TOKEN", "")
    auth_key = os.getenv("CLOUDFLARE_API_KEY", "")
    email = os.getenv("CLOUDFLARE_EMAIL", "")

    if token:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    if auth_key and email:
        return {
            "X-Auth-Email": email,
            "X-Auth-Key": auth_key,
            "Content-Type": "application/json",
        }
    return {"Content-Type": "application/json"}


def _get_zone_id() -> str:
    return os.getenv("CLOUDFLARE_ZONE_ID", "")


def is_configured() -> bool:
    return bool((os.getenv("CLOUDFLARE_API_TOKEN") or os.getenv("CLOUDFLARE_API_KEY")) and os.getenv("CLOUDFLARE_ZONE_ID"))


def check_connectivity() -> dict[str, Any]:
    """Tests connectivity to Cloudflare API and verifies Zone token validity."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return {"provider": "cloudflare", "ok": True, "configured": True, "error": None, "hint": None}

    if not is_configured():
        return {
            "provider": "cloudflare",
            "ok": False,
            "configured": False,
            "error": "CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID not configured",
            "hint": "Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in .env",
        }

    zone_id = _get_zone_id()
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    try:
        resp = requests.get(url, headers=_get_headers(), timeout=10)
        if resp.status_code == 200 and resp.json().get("success"):
            return {"provider": "cloudflare", "ok": True, "configured": True, "error": None, "hint": None}
        return {
            "provider": "cloudflare",
            "ok": False,
            "configured": True,
            "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
            "hint": "Check Cloudflare API Token permissions and Zone ID",
        }
    except Exception as e:
        return {
            "provider": "cloudflare",
            "ok": False,
            "configured": True,
            "error": str(e),
            "hint": "Check internet connectivity and DNS resolution to api.cloudflare.com",
        }


def block_ip(
    ip: str,
    *,
    mode: str = "block",
    notes: str = "MiniSOAR automated threat block",
) -> tuple[bool, str]:
    """Blocks an IP address using Cloudflare IP Access Rules."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Cloudflare IP Access Rule added: block %s", ip)
        return True, f"SUCCESS: IP {ip} blocked on Cloudflare (Mock)"

    if not is_configured():
        return False, "Cloudflare is not configured."

    zone_id = _get_zone_id()
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    payload = {
        "mode": mode,  # block, challenge, whitelist, js_challenge
        "configuration": {
            "target": "ip",
            "value": ip,
        },
        "notes": notes,
    }

    try:
        resp = requests.post(url, headers=_get_headers(), json=payload, timeout=15)
        data = resp.json() if resp.text else {}
        if resp.status_code in {200, 201} and data.get("success"):
            rule_id = (data.get("result") or {}).get("id", "created")
            return True, f"SUCCESS: IP {ip} blocked on Cloudflare (Rule ID: {rule_id})"
        errors = "; ".join([e.get("message", "") for e in data.get("errors", [])])
        return False, f"Cloudflare block failed: {errors or resp.text[:300]}"
    except Exception as e:
        return False, f"Cloudflare request failed: {e}"


def unblock_ip(ip: str) -> tuple[bool, str]:
    """Unblocks an IP address by finding and deleting its Cloudflare IP Access Rule."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Cloudflare IP Access Rule removed: unblock %s", ip)
        return True, f"SUCCESS: IP {ip} unblocked on Cloudflare (Mock)"

    if not is_configured():
        return False, "Cloudflare is not configured."

    zone_id = _get_zone_id()
    search_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    try:
        # 1. Find the rule ID
        resp = requests.get(search_url, headers=_get_headers(), params={"configuration.value": ip}, timeout=15)
        data = resp.json() if resp.text else {}
        results = data.get("result", [])
        if not results:
            return True, f"IP {ip} not found in Cloudflare access rules (already unblocked)"

        rule_id = results[0].get("id")
        # 2. Delete rule
        del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules/{rule_id}"
        del_resp = requests.delete(del_url, headers=_get_headers(), timeout=15)
        del_data = del_resp.json() if del_resp.text else {}
        if del_resp.status_code == 200 and del_data.get("success"):
            return True, f"SUCCESS: IP {ip} unblocked on Cloudflare"
        return False, f"Failed to delete Cloudflare rule {rule_id}: {del_resp.text[:300]}"
    except Exception as e:
        return False, f"Cloudflare unblock error: {e}"
