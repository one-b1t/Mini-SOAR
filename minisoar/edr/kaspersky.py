from __future__ import annotations

"""Kaspersky Security Center (KSC) 15.1 OpenAPI EDR integration.

Reference: https://support.kaspersky.com/ksc/15.1/211453
"""

import base64
import logging
import os
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _get_base_url() -> str:
    url = os.getenv("KSC_SERVER_URL", "https://127.0.0.1:13299/api/v1.0").rstrip("/")
    return url


def _get_verify_ssl() -> bool:
    return os.getenv("KSC_VERIFY_SSL", "no").lower() in {"1", "true", "yes"}


def is_configured() -> bool:
    return bool(os.getenv("KSC_SERVER_URL") and os.getenv("KSC_USERNAME") and os.getenv("KSC_PASSWORD"))


def login() -> tuple[str | None, str | None]:
    """Authenticates to KSC 15.1 OpenAPI via Session.StartSession and retrieves a session token."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return "mock-ksc-session-token-9988", None

    if not is_configured():
        return None, "KSC credentials (KSC_SERVER_URL, KSC_USERNAME, KSC_PASSWORD) not configured."

    base_url = _get_base_url()
    username = os.getenv("KSC_USERNAME", "")
    password = os.getenv("KSC_PASSWORD", "")

    # KSC 15.1 OpenAPI uses base64 encoded user:pass in Authorization header
    auth_str = f"{username}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"KSCBasic {auth_b64}",
        "Content-Type": "application/json",
    }

    endpoints = [
        f"{base_url}/Session.StartSession",
        f"{base_url}/login",
    ]

    last_err = ""
    for url in endpoints:
        try:
            resp = requests.post(url, headers=headers, json={}, verify=_get_verify_ssl(), timeout=10)
            if resp.status_code == 200:
                data = resp.json() if resp.text else {}
                token = data.get("accessor") or data.get("session_token") or resp.headers.get("X-KSC-Session") or resp.headers.get("Kaspersky-Session-Token")
                if not token:
                    token = resp.cookies.get("KSC-Session-Token", "ksc-authenticated-session")
                return token, None
            last_err = f"HTTP {resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            last_err = f"Connection to KSC failed ({url}): {e}"

    return None, last_err


def _get_auth_headers(token: str) -> dict[str, str]:
    """Builds headers required by KSC 15.1 OpenAPI for session-authenticated endpoints."""
    return {
        "X-KSC-Session": token,
        "Kaspersky-Session-Token": token,
        "Authorization": f"KSCSession {token}",
        "Content-Type": "application/json",
    }


def check_connectivity() -> dict[str, Any]:
    """Tests connectivity and credentials for Kaspersky Security Center (KSC) 15.1."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return {"provider": "kaspersky", "version": "15.1 OpenAPI", "ok": True, "configured": True, "error": None, "hint": None}

    if not is_configured():
        return {
            "provider": "kaspersky",
            "ok": False,
            "configured": False,
            "error": "KSC_SERVER_URL, KSC_USERNAME, or KSC_PASSWORD not configured",
            "hint": "Set KSC credentials in .env",
        }

    token, err = login()
    if token:
        return {"provider": "kaspersky", "version": "15.1 OpenAPI", "ok": True, "configured": True, "error": None, "hint": None}
    return {
        "provider": "kaspersky",
        "ok": False,
        "configured": True,
        "error": err,
        "hint": "Check KSC OpenAPI port (default 13299), username, and password",
    }


def find_host_by_ip(ip: str) -> tuple[list[dict[str, Any]], str | None]:
    """Searches for managed hosts by IP address in Kaspersky Security Center 15.1."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mock_host = {
            "hostId": "ksc-host-10928",
            "hostName": f"SRV-KL-{ip.replace('.', '-')}",
            "ipAddress": ip,
            "osName": "Microsoft Windows Server 2019",
            "networkIsolated": False,
            "kesVersion": "12.2.0.452",
        }
        return [mock_host], None

    token, err = login()
    if not token:
        return [], f"KSC login failed: {err}"

    url = f"{_get_base_url()}/HostGroup.FindHosts"
    headers = _get_auth_headers(token)
    payload = {
        "wstrFilter": f"(KLHST_WKS_IP_LONG = \"{ip}\")",
        "vecFieldsToReturn": [
            "KLHST_WKS_HOSTNAME",
            "KLHST_WKS_IP_LONG",
            "KLHST_WKS_OS_NAME",
            "KLHST_WKS_STATUS",
            "KLHST_WKS_ISOLATED",
            "KLHST_WKS_ID",
        ],
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=_get_verify_ssl(), timeout=15)
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}: {resp.text[:300]}"
        data = resp.json()
        items = data.get("PxgRetVal") or data.get("items") or []
        normalized = []
        for it in items:
            normalized.append({
                "hostId": it.get("KLHST_WKS_ID") or it.get("hostId") or it.get("KLHST_WKS_HOSTNAME"),
                "hostName": it.get("KLHST_WKS_HOSTNAME") or it.get("hostName"),
                "osName": it.get("KLHST_WKS_OS_NAME") or it.get("osName"),
                "networkIsolated": bool(it.get("KLHST_WKS_ISOLATED")),
            })
        return normalized if normalized else items, None
    except Exception as e:
        return [], f"Query failed: {e}"


def isolate_host(
    host_id: str | None = None,
    *,
    ip: str | None = None,
    reason: str = "MiniSOAR automated incident containment",
) -> tuple[bool, str, dict[str, Any]]:
    """Enforces network isolation / quarantine on a managed host in Kaspersky KSC 15.1."""
    target_id = host_id
    if not target_id and ip:
        hosts, err = find_host_by_ip(ip)
        if hosts:
            target_id = hosts[0].get("hostId") or hosts[0].get("hostName") or hosts[0].get("KLHST_WKS_HOSTNAME")
        elif err:
            return False, f"Could not find host for IP {ip}: {err}", {}

    if not target_id:
        return False, "Missing target host ID or IP", {}

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Kaspersky KSC isolate host: %s (ip=%s)", target_id, ip)
        return True, f"SUCCESS: Host {target_id} network isolated successfully on Kaspersky KSC", {"hostId": target_id, "status": "isolated"}

    token, err = login()
    if not token:
        return False, f"KSC login failed: {err}", {}

    url = f"{_get_base_url()}/HostGroup.SetHostNetworkIsolation"
    headers = _get_auth_headers(token)
    payload = {
        "strHostName": target_id,
        "bIsolate": True,
        "strReason": reason,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=_get_verify_ssl(), timeout=20)
        if resp.status_code == 200:
            return True, f"SUCCESS: Host {target_id} isolated on Kaspersky KSC", resp.json() if resp.text else {}
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", {}
    except Exception as e:
        return False, f"Request failed: {e}", {}


def restore_host(
    host_id: str | None = None,
    *,
    ip: str | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Restores network connectivity for an isolated host in Kaspersky KSC 15.1."""
    target_id = host_id
    if not target_id and ip:
        hosts, err = find_host_by_ip(ip)
        if hosts:
            target_id = hosts[0].get("hostId") or hosts[0].get("hostName") or hosts[0].get("KLHST_WKS_HOSTNAME")
        elif err:
            return False, f"Could not find host for IP {ip}: {err}", {}

    if not target_id:
        return False, "Missing target host ID or IP", {}

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Kaspersky KSC restore host: %s (ip=%s)", target_id, ip)
        return True, f"SUCCESS: Host {target_id} network connectivity restored on Kaspersky KSC", {"hostId": target_id, "status": "normal"}

    token, err = login()
    if not token:
        return False, f"KSC login failed: {err}", {}

    url = f"{_get_base_url()}/HostGroup.SetHostNetworkIsolation"
    headers = _get_auth_headers(token)
    payload = {
        "strHostName": target_id,
        "bIsolate": False,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=_get_verify_ssl(), timeout=20)
        if resp.status_code == 200:
            return True, f"SUCCESS: Host {target_id} restored on Kaspersky KSC", resp.json() if resp.text else {}
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", {}
    except Exception as e:
        return False, f"Request failed: {e}", {}


def add_ioc(
    ioc_type: str,
    ioc_value: str,
    *,
    comment: str = "MiniSOAR automated IoC feed",
) -> tuple[bool, str]:
    """Registers an IoC (hash, IP, URL) to Kaspersky Security Center 15.1 IoC repository."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Kaspersky KSC add IoC: %s=%s", ioc_type, ioc_value)
        return True, f"SUCCESS: Registered IoC {ioc_type}={ioc_value} on Kaspersky KSC"

    token, err = login()
    if not token:
        return False, f"KSC login failed: {err}"

    url = f"{_get_base_url()}/IoCRepository.AddObject"
    headers = _get_auth_headers(token)
    payload = {
        "type": ioc_type,
        "value": ioc_value,
        "comment": comment,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=_get_verify_ssl(), timeout=15)
        if resp.status_code in {200, 201}:
            return True, f"SUCCESS: IoC {ioc_value} added to Kaspersky KSC"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        return False, f"Request failed: {e}"
