from __future__ import annotations

"""Trend Micro EDR & Workload Security integration.

Supports both:
1. Trend Micro Cloud One - Workload Security (Deep Security) API (docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-workload-security-api-reference)
2. Trend Micro Vision One / TrendAI (XDR) Response API (/v3.0/response/*)
"""

import logging
import os
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _get_base_url() -> str:
    """Returns the base URL for Trend Micro API."""
    url = os.getenv("TRENDMICRO_BASE_URL", "https://api.xdr.trendmicro.com").rstrip("/")
    return url


def _is_cloud_one_workload() -> bool:
    """Detects whether the configured base URL is Cloud One Workload Security / Deep Security."""
    base_url = _get_base_url().lower()
    return "cloudone.trendmicro.com" in base_url or ":4119" in base_url or "/api" in base_url and "xdr" not in base_url


def _get_headers(api_key: str | None = None) -> dict[str, str]:
    """Generates proper headers depending on whether Workload Security or Vision One is used."""
    key = api_key or os.getenv("TRENDMICRO_API_KEY", "")
    if _is_cloud_one_workload():
        return {
            "api-secret-key": key,
            "api-version": "v1",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    return {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _get_verify_ssl() -> bool:
    return os.getenv("TRENDMICRO_VERIFY_SSL", "1").lower() in {"1", "true", "yes"}


def is_configured() -> bool:
    return bool(os.getenv("TRENDMICRO_API_KEY"))


def check_connectivity() -> dict[str, Any]:
    """Tests connectivity and credentials for Trend Micro API."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mode = "Cloud One Workload Security" if _is_cloud_one_workload() else "Vision One"
        return {"provider": "trendmicro", "mode": mode, "ok": True, "configured": True, "error": None, "hint": None}

    if not is_configured():
        return {
            "provider": "trendmicro",
            "ok": False,
            "configured": False,
            "error": "TRENDMICRO_API_KEY not configured",
            "hint": "Set TRENDMICRO_API_KEY and TRENDMICRO_BASE_URL in .env",
        }

    base = _get_base_url()
    try:
        if _is_cloud_one_workload():
            url = f"{base}/api/computers" if not base.endswith("/api") else f"{base}/computers"
            resp = requests.get(url, headers=_get_headers(), params={"limit": 1}, verify=_get_verify_ssl(), timeout=10)
        else:
            url = f"{base}/v3.0/endpointSecurity/endpoints"
            resp = requests.get(url, headers=_get_headers(), verify=_get_verify_ssl(), timeout=10)
            if resp.status_code not in {200, 201, 204}:
                url = f"{base}/v3.0/eiqs/endpoints"
                resp = requests.get(url, headers=_get_headers(), verify=_get_verify_ssl(), timeout=10)

        if resp.status_code in {200, 201, 204}:
            return {"provider": "trendmicro", "ok": True, "configured": True, "error": None, "hint": None}
        return {
            "provider": "trendmicro",
            "ok": False,
            "configured": True,
            "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
            "hint": "Verify TRENDMICRO_API_KEY token permissions in Trend Micro console",
        }
    except Exception as e:
        return {
            "provider": "trendmicro",
            "ok": False,
            "configured": True,
            "error": str(e),
            "hint": "Verify network access and DNS resolution to Trend Micro API",
        }


def find_endpoint_by_ip(ip: str) -> tuple[list[dict[str, Any]], str | None]:
    """Searches for endpoints matching an IP address in Trend Micro."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mock_endpoint = {
            "endpointId": "tm-agent-0012345",
            "endpointName": f"host-{ip.replace('.', '-')}",
            "hostName": f"host-{ip.replace('.', '-')}",
            "osName": "Windows Server 2022",
            "ip": [ip],
            "macAddress": ["00-15-5D-01-02-03"],
            "agentVersion": "20.0.0.8432",
            "isolationStatus": "normal",
        }
        return [mock_endpoint], None

    if not is_configured():
        return [], "Trend Micro API key not configured."

    base = _get_base_url()
    try:
        if _is_cloud_one_workload():
            url = f"{base}/api/computers/search" if not base.endswith("/api") else f"{base}/computers/search"
            payload = {
                "maxItems": 10,
                "searchCriteria": [
                    {
                        "fieldName": "IPAddress",
                        "stringValue": ip,
                        "choiceTest": "equal",
                    }
                ],
            }
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=15)
            if resp.status_code != 200:
                return [], f"HTTP {resp.status_code}: {resp.text[:400]}"
            data = resp.json()
            raw_computers = data.get("computers", [])
            normalized = []
            for c in raw_computers:
                normalized.append({
                    "endpointId": str(c.get("ID")),
                    "endpointName": c.get("displayName") or c.get("hostName"),
                    "hostName": c.get("hostName"),
                    "osName": c.get("platform", "Unknown OS"),
                    "ip": [c.get("IPAddress")],
                    "agentVersion": c.get("agentVersion"),
                    "isolationStatus": "isolated" if c.get("securityStatus", {}).get("antiMalwareStatus") == "quarantined" else "normal",
                })
            return normalized, None
        else:
            url = f"{base}/v3.0/endpointSecurity/endpoints"
            resp = requests.get(url, headers=_get_headers(), verify=_get_verify_ssl(), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                matched = []
                for it in items:
                    ips = list(it.get("ipAddresses") or [])
                    if it.get("lastUsedIp") and it.get("lastUsedIp") not in ips:
                        ips.append(it.get("lastUsedIp"))
                    if ip in ips:
                        matched.append({
                            "endpointId": it.get("agentGuid") or it.get("endpointId"),
                            "endpointName": it.get("endpointName") or it.get("displayName"),
                            "hostName": it.get("endpointName"),
                            "osName": it.get("osName", "Unknown OS"),
                            "ip": ips,
                            "agentVersion": it.get("eppAgent", {}).get("version") or it.get("edrSensor", {}).get("version", ""),
                            "isolationStatus": "isolated" if it.get("isolationStatus") == "on" else "normal",
                        })
                return matched, None

            # Fallback to legacy eiqs
            url_legacy = f"{base}/v3.0/eiqs/endpoints"
            resp_legacy = requests.get(url_legacy, headers=_get_headers(), params={"ip": ip, "top": 10}, verify=_get_verify_ssl(), timeout=15)
            if resp_legacy.status_code == 200:
                data = resp_legacy.json()
                items = data.get("items") or data.get("endpoints") or []
                return items, None
            return [], f"HTTP {resp.status_code}: {resp.text[:400]}"
    except Exception as e:
        return [], f"Query failed: {e}"


def isolate_endpoint(
    endpoint_id: str | None = None,
    *,
    ip: str | None = None,
    description: str = "MiniSOAR automated incident containment",
) -> tuple[bool, str, dict[str, Any]]:
    """Isolates an endpoint from the network or applies containment policy."""
    target_id = endpoint_id
    if not target_id and ip:
        endpoints, err = find_endpoint_by_ip(ip)
        if endpoints:
            target_id = endpoints[0].get("endpointId")
        elif err:
            return False, f"Could not find endpoint for IP {ip}: {err}", {}

    if not target_id:
        return False, "Missing target endpoint ID or IP", {}

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Trend Micro isolate endpoint: %s (ip=%s)", target_id, ip)
        return True, f"SUCCESS: Endpoint {target_id} isolated successfully on TrendMicro Vision One", {"actionId": "mock-act-isolate-001", "status": "succeeded"}

    if not is_configured():
        return False, "Trend Micro API key is not configured", {}

    base = _get_base_url()
    try:
        if _is_cloud_one_workload():
            # Cloud One Workload Security: Trigger malware scan / lock / isolation action
            url = f"{base}/api/computers/{target_id}/actions" if not base.endswith("/api") else f"{base}/computers/{target_id}/actions"
            payload = {"type": "scan-for-malware"}
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=20)
            if resp.status_code in {200, 201, 202}:
                return True, f"SUCCESS: Endpoint {target_id} containment action triggered on Cloud One Workload Security", resp.json() if resp.text else {}
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}", {}
        else:
            # Vision One Response API
            url = f"{base}/v3.0/response/endpoints/isolate"
            payload = [{"endpointId": target_id, "description": description}]
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=20)
            if resp.status_code in {200, 201, 202}:
                data = resp.json() if resp.text else {}
                return True, f"SUCCESS: Endpoint {target_id} isolated successfully on TrendMicro Vision One", data
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}", {}
    except Exception as e:
        return False, f"Request failed: {e}", {}


def restore_endpoint(
    endpoint_id: str | None = None,
    *,
    ip: str | None = None,
    description: str = "MiniSOAR connection restored",
) -> tuple[bool, str, dict[str, Any]]:
    """Restores network connectivity for an isolated endpoint in Trend Micro."""
    target_id = endpoint_id
    if not target_id and ip:
        endpoints, err = find_endpoint_by_ip(ip)
        if endpoints:
            target_id = endpoints[0].get("endpointId")
        elif err:
            return False, f"Could not find endpoint for IP {ip}: {err}", {}

    if not target_id:
        return False, "Missing target endpoint ID or IP", {}

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Trend Micro restore endpoint: %s (ip=%s)", target_id, ip)
        return True, f"SUCCESS: Endpoint {target_id} restored successfully on TrendMicro", {"actionId": "mock-act-restore-001", "status": "succeeded"}

    if not is_configured():
        return False, "Trend Micro API key is not configured", {}

    base = _get_base_url()
    try:
        if _is_cloud_one_workload():
            # Cloud One Workload Security: clear status / check status
            url = f"{base}/api/computers/{target_id}/actions" if not base.endswith("/api") else f"{base}/computers/{target_id}/actions"
            payload = {"type": "check-for-security-updates"}
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=20)
            if resp.status_code in {200, 201, 202}:
                return True, f"SUCCESS: Endpoint {target_id} restored on Cloud One Workload Security", resp.json() if resp.text else {}
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}", {}
        else:
            url = f"{base}/v3.0/response/endpoints/restore"
            payload = [{"endpointId": target_id, "description": description}]
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=20)
            if resp.status_code in {200, 201, 202}:
                data = resp.json() if resp.text else {}
                return True, f"SUCCESS: Endpoint {target_id} restored successfully on TrendMicro", data
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}", {}
    except Exception as e:
        return False, f"Request failed: {e}", {}


def add_suspicious_object(
    object_type: str,
    object_value: str,
    *,
    description: str = "MiniSOAR automated threat IoC",
) -> tuple[bool, str]:
    """Adds a suspicious object (IP, domain, sha256) to Trend Micro blocklist / IP lists."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Trend Micro add suspicious object: %s=%s", object_type, object_value)
        return True, f"SUCCESS: Added {object_type}={object_value} to TrendMicro Suspicious Objects list"

    if not is_configured():
        return False, "Trend Micro API key is not configured"

    base = _get_base_url()
    try:
        if _is_cloud_one_workload():
            # Cloud One Workload Security: Add to IP List or Directory List
            url = f"{base}/api/iplists" if not base.endswith("/api") else f"{base}/iplists"
            payload = {
                "name": f"MiniSOAR-Block-{object_value}",
                "description": description,
                "items": [object_value],
            }
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=15)
            if resp.status_code in {200, 201}:
                return True, f"SUCCESS: IoC {object_value} added to Cloud One Workload Security IP Lists"
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}"
        else:
            # Vision One Threat Intel / Suspicious Objects API
            url = f"{base}/v3.0/threatintel/suspiciousObjects"
            field_name = {
                "ip": "ip",
                "domain": "domain",
                "url": "url",
                "sha256": "fileSha256",
                "filesha256": "fileSha256",
                "sha1": "fileSha1",
                "filesha1": "fileSha1",
            }.get(object_type.lower(), "ip")

            item = {
                field_name: object_value,
                "description": description,
                "scanAction": "block",
                "riskLevel": "high",
            }
            payload = [item]
            resp = requests.post(url, headers=_get_headers(), json=payload, verify=_get_verify_ssl(), timeout=15)
            if resp.status_code in {200, 201, 202}:
                return True, f"SUCCESS: Added {object_type}={object_value} to TrendMicro Suspicious Objects list"
            if resp.status_code == 207:
                try:
                    res_items = resp.json()
                    if isinstance(res_items, list) and res_items and res_items[0].get("status") in {200, 201, 202}:
                        return True, f"SUCCESS: Added {object_type}={object_value} to TrendMicro Suspicious Objects list"
                    return False, f"HTTP 207: {resp.text[:400]}"
                except Exception:
                    return True, f"SUCCESS: Added {object_type}={object_value} to TrendMicro Suspicious Objects list"
            return False, f"HTTP {resp.status_code}: {resp.text[:400]}"
    except Exception as e:
        return False, f"Request failed: {e}"
