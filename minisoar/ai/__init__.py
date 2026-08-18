from __future__ import annotations

"""MiniSOAR AI SOC Copilot Package."""

from .copilot import (
    analyze_payload,
    analyze_payload_json,
    ask_copilot,
    call_llm,
    call_llm_json,
    generate_rca,
    generate_rca_json,
    get_auth_info,
    is_configured,
    recommend_mitigation,
    resolve_auth_credential,
    set_active_model,
    set_active_provider,
)

__all__ = [
    "analyze_payload",
    "analyze_payload_json",
    "ask_copilot",
    "call_llm",
    "call_llm_json",
    "generate_rca",
    "generate_rca_json",
    "get_auth_info",
    "is_configured",
    "recommend_mitigation",
    "resolve_auth_credential",
    "set_active_model",
    "set_active_provider",
]

