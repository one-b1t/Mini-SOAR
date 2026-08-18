from __future__ import annotations

"""3rd-Party Ticketing Connectors for MiniSOAR (Optional & Modular).

Supports external 3rd-party ticketing platforms:
1. TheHive 4/5 (Security Incident Response & Case Management)
2. Atlassian Jira Service Management / Jira Software
3. ServiceNow IT Service Management (Table API)
4. Generic Webhook (Zendesk, Freshservice, PagerDuty, Teams, Slack, SIEM)

TICKETING IS 100% OPTIONAL:
- If TICKETING_PROVIDER is 'none' or not configured, MiniSOAR will not create or mandate external tickets.
- If configured, MiniSOAR automatically pushes security incidents to your designated 3rd-party platform.
"""

import logging
import os
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def get_ticketing_provider() -> str:
    """Returns the configured 3rd-party ticketing provider (none, thehive, jira, servicenow, webhook)."""
    return os.getenv("TICKETING_PROVIDER", "none").lower().strip()


def is_ticketing_enabled() -> bool:
    """Checks whether 3rd-party ticketing integration is enabled and configured."""
    provider = get_ticketing_provider()
    if provider in {"none", "disabled", "off", ""}:
        return False
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return True
    if provider == "thehive":
        return is_thehive_configured()
    if provider == "jira":
        return is_jira_configured()
    if provider in {"servicenow", "snow"}:
        return is_servicenow_configured()
    if provider == "webhook":
        return bool(os.getenv("INCIDENT_WEBHOOK_URL"))
    return False


# ---------------------------------------------------------
# 1. TheHive Connector (API v4 / v5)
# ---------------------------------------------------------
def is_thehive_configured() -> bool:
    return bool(os.getenv("THEHIVE_URL") and os.getenv("THEHIVE_API_KEY"))


def create_thehive_case(
    title: str,
    description: str,
    severity: int = 2,  # 1: Low, 2: Medium, 3: High, 4: Critical
    tags: list[str] | None = None,
    observables: list[dict[str, str]] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Creates an incident case in 3rd-party TheHive instance."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mock_case_id = f"TH-CASE-MOCK-{abs(hash(title)) % 100000}"
        logger.info("[MOCK] Created TheHive Case: %s (%s)", mock_case_id, title)
        return True, f"SUCCESS: TheHive case created with ID {mock_case_id}", {"caseId": mock_case_id, "ticket_id": mock_case_id, "provider": "thehive"}

    if not is_thehive_configured():
        return False, "TheHive is not configured (THEHIVE_URL, THEHIVE_API_KEY).", {}

    base_url = os.getenv("THEHIVE_URL", "").rstrip("/")
    api_key = os.getenv("THEHIVE_API_KEY", "")
    verify_ssl = os.getenv("THEHIVE_VERIFY_SSL", "0").lower() in {"1", "true", "yes"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "title": title,
        "description": description,
        "severity": severity,
        "tags": tags or ["MiniSOAR", "Automated"],
        "flag": False,
        "tlp": 2,  # Amber
    }

    try:
        url = f"{base_url}/api/v1/case" if "/v1" not in base_url else f"{base_url}/case"
        resp = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=15)
        if resp.status_code in {200, 201}:
            data = resp.json()
            case_id = data.get("id") or data.get("_id") or data.get("number")
            if observables and case_id:
                for obs in observables:
                    add_thehive_observable(case_id, obs.get("type", "ip"), obs.get("value", ""))
            return True, f"SUCCESS: TheHive case created with ID {case_id}", {"ticket_id": case_id, "data": data, "provider": "thehive"}
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", {}
    except Exception as e:
        return False, f"TheHive connection failed: {e}", {}


def add_thehive_observable(case_id: str, data_type: str, data_value: str, message: str = "MiniSOAR IoC") -> tuple[bool, str]:
    """Attaches an observable (IP, hash, domain) to an existing TheHive case."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return True, f"SUCCESS: Added observable {data_type}={data_value} to TheHive case {case_id}"

    if not is_thehive_configured():
        return False, "TheHive is not configured."

    base_url = os.getenv("THEHIVE_URL", "").rstrip("/")
    api_key = os.getenv("THEHIVE_API_KEY", "")
    verify_ssl = os.getenv("THEHIVE_VERIFY_SSL", "0").lower() in {"1", "true", "yes"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    url = f"{base_url}/api/v1/case/{case_id}/observable"
    payload = {
        "dataType": data_type,
        "data": data_value,
        "message": message,
        "tlp": 2,
        "ioc": True,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=10)
        if resp.status_code in {200, 201}:
            return True, f"SUCCESS: Added observable {data_value}"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        return False, f"Failed to add observable: {e}"


# ---------------------------------------------------------
# 2. Jira Service Management Connector
# ---------------------------------------------------------
def is_jira_configured() -> bool:
    return bool(os.getenv("JIRA_URL") and os.getenv("JIRA_API_TOKEN") and os.getenv("JIRA_PROJECT_KEY"))


def create_jira_issue(
    summary: str,
    description: str,
    issue_type: str = "Incident",
    priority: str = "Medium",
    labels: list[str] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Creates an incident ticket in 3rd-party Atlassian Jira."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mock_key = f"{os.getenv('JIRA_PROJECT_KEY', 'SEC')}-{abs(hash(summary)) % 10000}"
        logger.info("[MOCK] Created Jira Issue: %s (%s)", mock_key, summary)
        return True, f"SUCCESS: Jira issue created with Key {mock_key}", {"key": mock_key, "ticket_id": mock_key, "provider": "jira"}

    if not is_jira_configured():
        return False, "Jira is not configured (JIRA_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY).", {}

    base_url = os.getenv("JIRA_URL", "").rstrip("/")
    email = os.getenv("JIRA_USER_EMAIL", "")
    token = os.getenv("JIRA_API_TOKEN", "")
    project_key = os.getenv("JIRA_PROJECT_KEY", "SEC")

    headers = {"Content-Type": "application/json"}
    auth = (email, token) if email else None

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "labels": labels or ["MiniSOAR", "SecurityIncident"],
        }
    }

    try:
        url = f"{base_url}/rest/api/2/issue"
        resp = requests.post(url, headers=headers, json=payload, auth=auth, timeout=15)
        if resp.status_code in {200, 201}:
            data = resp.json()
            key = data.get("key", "Unknown")
            return True, f"SUCCESS: Jira issue created with Key {key}", {"ticket_id": key, "data": data, "provider": "jira"}
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", {}
    except Exception as e:
        return False, f"Jira connection failed: {e}", {}


# ---------------------------------------------------------
# 3. ServiceNow ITSM Connector (Table API)
# ---------------------------------------------------------
def is_servicenow_configured() -> bool:
    return bool(os.getenv("SERVICENOW_URL") and os.getenv("SERVICENOW_USER") and os.getenv("SERVICENOW_PASSWORD"))


def create_servicenow_incident(
    short_description: str,
    description: str,
    urgency: str = "2",  # 1: High, 2: Medium, 3: Low
    impact: str = "2",
) -> tuple[bool, str, dict[str, Any]]:
    """Creates an incident record in 3rd-party ServiceNow."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        mock_num = f"INC{abs(hash(short_description)) % 10000000:07d}"
        logger.info("[MOCK] Created ServiceNow Incident: %s", mock_num)
        return True, f"SUCCESS: ServiceNow incident created with Number {mock_num}", {"number": mock_num, "ticket_id": mock_num, "provider": "servicenow"}

    if not is_servicenow_configured():
        return False, "ServiceNow is not configured (SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD).", {}

    base_url = os.getenv("SERVICENOW_URL", "").rstrip("/")
    user = os.getenv("SERVICENOW_USER", "")
    password = os.getenv("SERVICENOW_PASSWORD", "")

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {
        "short_description": short_description,
        "description": description,
        "urgency": urgency,
        "impact": impact,
        "caller_id": "MiniSOAR",
        "category": "Security",
    }

    try:
        url = f"{base_url}/api/now/table/incident"
        resp = requests.post(url, headers=headers, json=payload, auth=(user, password), timeout=15)
        if resp.status_code in {200, 201}:
            data = resp.json().get("result", {})
            inc_num = data.get("number", "INC-UNKNOWN")
            return True, f"SUCCESS: ServiceNow incident created with Number {inc_num}", {"ticket_id": inc_num, "data": data, "provider": "servicenow"}
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}", {}
    except Exception as e:
        return False, f"ServiceNow connection failed: {e}", {}


# ---------------------------------------------------------
# 4. Generic Webhook / SIEM / ITSM Connector
# ---------------------------------------------------------
def send_generic_webhook(payload: dict[str, Any], webhook_url: str | None = None) -> tuple[bool, str]:
    """Dispatches an incident payload to a generic external webhook or SIEM/SOAR endpoint."""
    url = webhook_url or os.getenv("INCIDENT_WEBHOOK_URL")
    if not url:
        return False, "INCIDENT_WEBHOOK_URL is not configured."

    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info("[MOCK] Dispatched generic webhook to %s", url)
        return True, "SUCCESS: Webhook payload dispatched (Mock)"

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code in {200, 201, 202, 204}:
            return True, f"SUCCESS: Webhook accepted (HTTP {resp.status_code})"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        return False, f"Webhook dispatch failed: {e}"


# ---------------------------------------------------------
# Unified 3rd-Party Ticketing Dispatcher (Optional)
# ---------------------------------------------------------
def dispatch_external_ticket(
    title: str,
    description: str,
    severity: str = "medium",
    attacker_ip: str | None = None,
    target_asset: str | None = None,
    tags: list[str] | None = None,
    observables: list[dict[str, str]] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Dispatches incident to configured 3rd-party ticketing platform if enabled.

    If TICKETING_PROVIDER is 'none' or unconfigured, it gracefully skips without error.
    """
    if not is_ticketing_enabled():
        return False, "3rd-party ticketing is disabled or not configured (optional).", {}

    provider = get_ticketing_provider()
    logger.info("Dispatching incident to 3rd-party ticketing provider: %s", provider)

    if provider == "thehive":
        sev_int = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity.lower(), 2)
        obs = observables or []
        if attacker_ip and not any(o.get("value") == attacker_ip for o in obs):
            obs.append({"type": "ip", "value": attacker_ip})
        return create_thehive_case(title, description, severity=sev_int, tags=tags, observables=obs)

    if provider == "jira":
        prio = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}.get(severity.lower(), "Medium")
        return create_jira_issue(title, description, priority=prio, labels=tags)

    if provider in {"servicenow", "snow"}:
        urg = {"critical": "1", "high": "1", "medium": "2", "low": "3"}.get(severity.lower(), "2")
        return create_servicenow_incident(title, description, urgency=urg)

    if provider == "webhook":
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "attacker_ip": attacker_ip,
            "target_asset": target_asset,
            "tags": tags or [],
        }
        ok, msg = send_generic_webhook(payload)
        return ok, msg, {"provider": "webhook"}

    return False, f"Unknown ticketing provider: {provider}", {}
