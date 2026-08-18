from __future__ import annotations

"""MiniSOAR AI SOC Copilot Package."""

from .copilot import (
    analyze_payload,
    ask_copilot,
    call_llm,
    generate_rca,
    get_auth_info,
    is_configured,
    recommend_mitigation,
    resolve_auth_credential,
    set_active_model,
    set_active_provider,
)

__all__ = [
    "analyze_payload",
    "ask_copilot",
    "call_llm",
    "generate_rca",
    "get_auth_info",
    "is_configured",
    "recommend_mitigation",
    "resolve_auth_credential",
    "set_active_model",
    "set_active_provider",
]

