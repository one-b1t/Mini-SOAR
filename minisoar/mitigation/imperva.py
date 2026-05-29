from __future__ import annotations

import os
import logging
from typing import Any, Optional

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def login_via_api(base_url: str, username: str, password: str) -> Optional[dict]:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return {"mock-session": "1"}

    login_url = f"{base_url}/SecureSphere/api/v1/auth/session"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = requests.post(
            login_url,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            verify=False,
            timeout=10,
        )
        if response.status_code == 200:
            session_id = response.json().get("session-id")
            if session_id:
                cookies = {}
                for item in session_id.split(";"):
                    if "=" in item:
                        key, value = item.strip().split("=", 1)
                        cookies[key] = value
                return cookies
    except Exception as e:
        logger.error("Imperva login API connection failed: %s", e)
    return None


def imperva_api_request(
    base_url: str,
    method: str,
    path: str,
    cookies: dict,
    *,
    params: dict | None = None,
    json: Any = None,
    timeout: int = 20,
) -> requests.Response:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Imperva API request: %s %s", method, path)
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b'{"status": "success", "message": "mocked response"}'
        return mock_resp

    url = f"{base_url}{path}"
    headers = {"Accept": "application/json"}
    if json is not None:
        headers["Content-Type"] = "application/json"

    return requests.request(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        params=params,
        json=json,
        verify=False,
        timeout=timeout,
    )


def ip_blocklist_api(base_url: str, group_name: str, api_cookies: dict, ip_address: str, *, action: str = "add") -> tuple[bool, str]:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Imperva Blocklist API: action=%s, IP=%s", action, ip_address)
        return True, f"✅ [MOCK] IP {ip_address} berhasil di{'blokir' if action == 'add' else 'unblokir'} di Imperva On-prem."

    api_url = f"{base_url}/SecureSphere/api/v1/conf/ipGroups/{group_name}/data"
    payload = {
        "entries": [
            {
                "operation": action,
                "type": "single",
                "ipAddressFrom": ip_address,
            }
        ]
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        response = requests.put(
            api_url,
            json=payload,
            headers=headers,
            cookies=api_cookies,
            verify=False,
            timeout=15,
        )
        if response.status_code == 200:
            return True, f"✅ IP {ip_address} berhasil di{'blokir' if action == 'add' else 'unblokir'} di Imperva On-prem."
        return False, f"❌ Gagal {'blokir' if action == 'add' else 'unblokir'} IP {ip_address} ({response.status_code}): {response.text}"
    except Exception as e:
        return False, f"❌ Connection error during Imperva blocklist update: {e}"


def get_blocked_ip_list(base_url: str, group_name: str, api_cookies: dict) -> list[str] | None:
    api_url = f"{base_url}/SecureSphere/api/v1/conf/ipGroups/{group_name}/data"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = requests.get(api_url, headers=headers, cookies=api_cookies, verify=False, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return [
                entry["ipAddressFrom"]
                for entry in data.get("entries", [])
                if entry.get("type") == "single"
            ]
    except Exception as e:
        logger.error("Failed to fetch blocked IP list from Imperva: %s", e)
    return None


def get_violation_by_event_number(
    base_url: str,
    cookies: dict,
    *,
    event_number: str,
    days: int = 7,
    limit: int = 50,
) -> tuple[dict | None, str | None]:
    path = "/SecureSphere/api/v1/monitor/violations/"
    event_number_str = str(event_number).strip()

    params = {"lastFewDays": days, "eventNumber": event_number_str, "limit": int(limit)}

    try:
        resp = imperva_api_request(base_url, "GET", path, cookies, params=params)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text}"
        data = resp.json()
    except Exception as e:
        return None, f"Request failed: {e}"

    if isinstance(data, dict):
        violations = data.get("violations") or []
    elif isinstance(data, list):
        violations = data
    else:
        violations = []

    if not violations:
        return None, "Violation not found"

    for v in violations:
        if isinstance(v, dict) and str(v.get("eventNumber", "")).strip() == event_number_str:
            return v, None

    return None, "Violation not found"
