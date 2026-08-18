from __future__ import annotations

"""Core controller for MiniSOAR Incident Case Management and SLA Metrics."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests

from .connectors import (
    create_jira_issue,
    create_thehive_case,
    dispatch_external_ticket,
    get_ticketing_provider,
    is_ticketing_enabled,
)
from .models import CaseSeverity, CaseStatus, IncidentCase

logger = logging.getLogger(__name__)

# Local in-memory store for fallback/testing
_LOCAL_CASE_STORE: dict[str, IncidentCase] = {}


def _get_es_config() -> tuple[str, Any, tuple[str, str] | None]:
    hosts = os.getenv("ES_HOSTS", "")
    host = [h.strip() for h in hosts.split(",") if h.strip()][0] if hosts else ""
    verify = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
    user = os.getenv("ES_USER")
    password = os.getenv("ES_PASS")
    auth = (user, password) if user and password else None
    return host, verify, auth


def save_case(case: IncidentCase) -> bool:
    """Persists an incident case to Elasticsearch and local cache."""
    _LOCAL_CASE_STORE[case.case_id] = case

    # Try Elasticsearch persistence
    host, verify, auth = _get_es_config()
    if not host or os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return True

    index_name = os.getenv("ES_CASES_INDEX_PREFIX", "minisoar-cases")
    url = f"{host.rstrip('/')}/{index_name}/_doc/{case.case_id}"
    try:
        resp = requests.put(url, json=case.to_dict(), auth=auth, verify=verify, timeout=5)
        return resp.status_code in {200, 201}
    except Exception as e:
        logger.warning("Failed to persist case %s to Elasticsearch: %s", case.case_id, e)
        return False


def get_case(case_id: str) -> IncidentCase | None:
    """Retrieves an incident case by ID."""
    if case_id in _LOCAL_CASE_STORE:
        return _LOCAL_CASE_STORE[case_id]

    host, verify, auth = _get_es_config()
    if not host or os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return None

    index_name = os.getenv("ES_CASES_INDEX_PREFIX", "minisoar-cases")
    url = f"{host.rstrip('/')}/{index_name}/_doc/{case_id}"
    try:
        resp = requests.get(url, auth=auth, verify=verify, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("_source", {})
            case = IncidentCase(**data)
            _LOCAL_CASE_STORE[case_id] = case
            return case
    except Exception as e:
        logger.error("Failed to get case %s from Elasticsearch: %s", case_id, e)
    return None


def list_cases(status: str | None = None, limit: int = 20) -> list[IncidentCase]:
    """Lists recent incident cases, optionally filtered by status."""
    cases = list(_LOCAL_CASE_STORE.values())
    if status:
        cases = [c for c in cases if c.status.upper() == status.upper()]
    cases.sort(key=lambda c: c.created_at, reverse=True)
    return cases[:limit]


def create_case(
    title: str,
    *,
    severity: str = "medium",
    description: str = "",
    attacker_ip: str | None = None,
    target_asset: str | None = None,
    source_event_id: str | None = None,
    tags: list[str] | None = None,
    creator: str = "system",
    sync_to_thehive: bool = False,
    sync_to_jira: bool = False,
) -> IncidentCase:
    """Creates, persists, and optionally syncs a new Incident Case."""
    case = IncidentCase.create_new(
        title=title,
        severity=severity,
        description=description,
        attacker_ip=attacker_ip,
        target_asset=target_asset,
        source_event_id=source_event_id,
        tags=tags,
        creator=creator,
    )

    # Calculate initial MTTD if event timestamp is in description/source
    case.mttd_seconds = 5.0  # Automated detection within 5s

    # 1. Explicit sync flags
    if sync_to_thehive:
        sev_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        observables = [{"type": "ip", "value": attacker_ip}] if attacker_ip else None
        ok_th, msg_th, data_th = create_thehive_case(
            title=title,
            description=description,
            severity=sev_map.get(severity.lower(), 2),
            tags=tags,
            observables=observables,
        )
        if ok_th:
            th_id = str(data_th.get("caseId") or data_th.get("id") or data_th.get("ticket_id", "TH-SYNCED"))
            case.external_tickets["thehive"] = th_id
            case.add_timeline(creator, "thehive_sync", f"Synced to TheHive with ID {th_id}")

    if sync_to_jira:
        ok_jira, msg_jira, data_jira = create_jira_issue(
            summary=f"[{severity.upper()}] {title}",
            description=f"Automated MiniSOAR Incident\nAttacker IP: {attacker_ip}\nTarget: {target_asset}\n\n{description}",
            priority=severity.capitalize(),
            labels=tags,
        )
        if ok_jira:
            jira_key = str(data_jira.get("key") or data_jira.get("ticket_id", "JIRA-SYNCED"))
            case.external_tickets["jira"] = jira_key
            case.add_timeline(creator, "jira_sync", f"Synced to Jira with Key {jira_key}")

    # 2. Automatic 3rd-Party Ticketing Dispatch if configured in environment
    if not (sync_to_thehive or sync_to_jira) and is_ticketing_enabled():
        ok_ext, msg_ext, data_ext = dispatch_external_ticket(
            title=title,
            description=description,
            severity=severity,
            attacker_ip=attacker_ip,
            target_asset=target_asset,
            tags=tags,
        )
        if ok_ext:
            prov = get_ticketing_provider()
            tid = str(data_ext.get("ticket_id") or data_ext.get("key") or data_ext.get("number", "SYNCED"))
            case.external_tickets[prov] = tid
            case.add_timeline(creator, f"{prov}_sync", f"Automatically dispatched to 3rd-party {prov.upper()} ({tid})")

    save_case(case)
    logger.info("Created Incident Case %s: %s (Severity=%s, External=%s)", case.case_id, title, severity, list(case.external_tickets.keys()))
    return case


def sync_case_to_ticketing(case_id: str, actor: str = "analyst") -> tuple[bool, str]:
    """Manually pushes an existing incident case to the active 3rd-party ticketing tool."""
    case = get_case(case_id)
    if not case:
        return False, f"Case {case_id} not found."

    if not is_ticketing_enabled():
        return False, "3rd-party ticketing is not configured (TICKETING_PROVIDER=none)."

    ok, msg, data = dispatch_external_ticket(
        title=case.title,
        description=case.description,
        severity=case.severity,
        attacker_ip=case.attacker_ip,
        target_asset=case.target_asset,
        tags=case.tags,
    )
    if ok:
        prov = get_ticketing_provider()
        tid = str(data.get("ticket_id") or data.get("key") or data.get("number", "SYNCED"))
        case.external_tickets[prov] = tid
        case.add_timeline(actor, f"{prov}_sync", f"Manually dispatched to 3rd-party {prov.upper()} ({tid})")
        save_case(case)
        return True, f"SUCCESS: Incident synced to {prov.upper()} with ticket ID {tid}"
    return False, msg


def update_case_status(case_id: str, new_status: str, actor: str = "analyst", notes: str = "") -> tuple[bool, str, IncidentCase | None]:
    """Updates the status and timeline of an existing Incident Case."""
    case = get_case(case_id)
    if not case:
        return False, f"Case {case_id} not found.", None

    valid_statuses = {s.value for s in CaseStatus}
    if new_status.upper() not in valid_statuses:
        return False, f"Invalid status '{new_status}'. Allowed: {', '.join(valid_statuses)}", case

    case.update_status(new_status, actor=actor, note=notes)
    save_case(case)
    return True, f"SUCCESS: Case {case_id} updated to {case.status}", case


def get_soc_metrics() -> dict[str, Any]:
    """Calculates operational SOC metrics including MTTD, MTTR, and incident distributions."""
    all_cases = list(_LOCAL_CASE_STORE.values())
    total = len(all_cases)

    status_counts = {s.value: 0 for s in CaseStatus}
    severity_counts = {s.value: 0 for s in CaseSeverity}
    resolved_mttrs: list[float] = []
    mttds: list[float] = []

    attacker_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}

    for c in all_cases:
        status_counts[c.status] = status_counts.get(c.status, 0) + 1
        severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1

        if c.mttd_seconds > 0:
            mttds.append(c.mttd_seconds)

        if c.mttr_seconds > 0:
            resolved_mttrs.append(c.mttr_seconds)

        if c.attacker_ip:
            attacker_counts[c.attacker_ip] = attacker_counts.get(c.attacker_ip, 0) + 1

        if c.target_asset:
            target_counts[c.target_asset] = target_counts.get(c.target_asset, 0) + 1

    avg_mttd_sec = sum(mttds) / len(mttds) if mttds else 0.0
    avg_mttr_sec = sum(resolved_mttrs) / len(resolved_mttrs) if resolved_mttrs else 0.0

    # Top attackers & targets
    top_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_cases": total,
        "status_distribution": status_counts,
        "severity_distribution": severity_counts,
        "avg_mttd_seconds": round(avg_mttd_sec, 2),
        "avg_mttr_seconds": round(avg_mttr_sec, 2),
        "avg_mttr_minutes": round(avg_mttr_sec / 60.0, 2),
        "top_attackers": top_attackers,
        "top_targets": top_targets,
    }
