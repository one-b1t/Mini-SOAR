from __future__ import annotations

"""Unified EDR Controller for Kaspersky KSC and TrendMicro Vision One."""

import logging
from typing import Any

from . import kaspersky, trendmicro

logger = logging.getLogger(__name__)


def norm_edr_provider(provider: str | None) -> str:
    s = (provider or "").strip().lower()
    if s in {"ksc", "kaspersky", "kl"}:
        return "kaspersky"
    if s in {"trendmicro", "trend", "tm", "visionone", "v1"}:
        return "trendmicro"
    if s in {"all", "both", "*"}:
        return "all"
    return s or "all"


def check_all_edr_connectivity() -> list[dict[str, Any]]:
    """Runs diagnostics across all configured EDR providers."""
    results = [
        kaspersky.check_connectivity(),
        trendmicro.check_connectivity(),
    ]
    return results


def isolate_endpoint(
    target: str,
    *,
    provider: str = "all",
    reason: str = "MiniSOAR automated containment",
) -> tuple[bool, str, dict[str, Any]]:
    """Triggers endpoint isolation across designated EDR providers (Kaspersky, TrendMicro, or all).

    target can be an IP address or an endpoint host ID.
    """
    p_norm = norm_edr_provider(provider)
    providers_to_run = ["kaspersky", "trendmicro"] if p_norm == "all" else [p_norm]

    overall_success = False
    messages: list[str] = []
    details: dict[str, Any] = {}

    for p in providers_to_run:
        if p == "trendmicro":
            ok, msg, dt = trendmicro.isolate_endpoint(endpoint_id=target if not _is_ip(target) else None, ip=target if _is_ip(target) else None, description=reason)
            details["trendmicro"] = {"success": ok, "message": msg, "data": dt}
            messages.append(f"TrendMicro: {msg}")
            if ok:
                overall_success = True
        elif p == "kaspersky":
            ok, msg, dt = kaspersky.isolate_host(host_id=target if not _is_ip(target) else None, ip=target if _is_ip(target) else None, reason=reason)
            details["kaspersky"] = {"success": ok, "message": msg, "data": dt}
            messages.append(f"Kaspersky: {msg}")
            if ok:
                overall_success = True

    combined_msg = " | ".join(messages)
    return overall_success, combined_msg, details


def restore_endpoint(
    target: str,
    *,
    provider: str = "all",
) -> tuple[bool, str, dict[str, Any]]:
    """Restores network connectivity for an isolated endpoint across EDR providers."""
    p_norm = norm_edr_provider(provider)
    providers_to_run = ["kaspersky", "trendmicro"] if p_norm == "all" else [p_norm]

    overall_success = False
    messages: list[str] = []
    details: dict[str, Any] = {}

    for p in providers_to_run:
        if p == "trendmicro":
            ok, msg, dt = trendmicro.restore_endpoint(endpoint_id=target if not _is_ip(target) else None, ip=target if _is_ip(target) else None)
            details["trendmicro"] = {"success": ok, "message": msg, "data": dt}
            messages.append(f"TrendMicro: {msg}")
            if ok:
                overall_success = True
        elif p == "kaspersky":
            ok, msg, dt = kaspersky.restore_host(host_id=target if not _is_ip(target) else None, ip=target if _is_ip(target) else None)
            details["kaspersky"] = {"success": ok, "message": msg, "data": dt}
            messages.append(f"Kaspersky: {msg}")
            if ok:
                overall_success = True

    combined_msg = " | ".join(messages)
    return overall_success, combined_msg, details


def add_edr_ioc(
    ioc_type: str,
    ioc_value: str,
    *,
    provider: str = "all",
    comment: str = "MiniSOAR automated IoC feed",
) -> tuple[bool, str]:
    """Adds suspicious object / IoC to EDR server blocklists."""
    p_norm = norm_edr_provider(provider)
    providers_to_run = ["kaspersky", "trendmicro"] if p_norm == "all" else [p_norm]

    overall_success = False
    messages: list[str] = []

    for p in providers_to_run:
        if p == "trendmicro":
            ok, msg = trendmicro.add_suspicious_object(ioc_type, ioc_value, description=comment)
            messages.append(f"TrendMicro: {msg}")
            if ok:
                overall_success = True
        elif p == "kaspersky":
            ok, msg = kaspersky.add_ioc(ioc_type, ioc_value, comment=comment)
            messages.append(f"Kaspersky: {msg}")
            if ok:
                overall_success = True

    return overall_success, " | ".join(messages)


def query_endpoint(ip: str, *, provider: str = "all") -> dict[str, Any]:
    """Queries endpoint inventory across EDR platforms."""
    p_norm = norm_edr_provider(provider)
    results: dict[str, Any] = {"ip": ip, "kaspersky": [], "trendmicro": [], "errors": []}

    if p_norm in {"all", "trendmicro"}:
        tm_hosts, tm_err = trendmicro.find_endpoint_by_ip(ip)
        if tm_err:
            results["errors"].append(f"TrendMicro: {tm_err}")
        else:
            results["trendmicro"] = tm_hosts

    if p_norm in {"all", "kaspersky"}:
        kl_hosts, kl_err = kaspersky.find_host_by_ip(ip)
        if kl_err:
            results["errors"].append(f"Kaspersky: {kl_err}")
        else:
            results["kaspersky"] = kl_hosts

    return results


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False
