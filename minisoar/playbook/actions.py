from __future__ import annotations

"""Action handlers registry for MiniSOAR Playbook Engine."""

import logging
from typing import Any, Callable

from ..config import norm_provider
from ..database import store_label
from ..mitigation.core import (
    extend_block_state,
    is_ip_blocked,
    register_block_state,
    remove_block_state,
    trigger_auto_block,
    trigger_auto_unblock,
)
from ..utils import (
    build_message,
    inject_perimeter_line,
    log_user_action,
    provider_badge,
    send_telegram,
)
from .models import ExecutionContext

logger = logging.getLogger(__name__)

ActionHandler = Callable[[ExecutionContext, dict[str, Any]], tuple[bool, Any]]

_ACTION_REGISTRY: dict[str, ActionHandler] = {}


def register_action(name: str):
    """Decorator to register a playbook action handler."""
    def decorator(fn: ActionHandler):
        _ACTION_REGISTRY[name] = fn
        return fn
    return decorator


@register_action("mitigation.auto_block")
def action_auto_block(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to automatically block the attacker IP on designated perimeter providers."""
    ip = ctx.ip
    if not ip or ip in {"(unknown)", "127.0.0.1"}:
        return False, "Invalid or missing IP address for auto_block"

    if ctx.whitelisted:
        logger.info("[PLAYBOOK] IP %s is whitelisted. Skipping auto_block.", ip)
        return True, "Skipped (whitelisted)"

    duration = int(params.get("duration") or ctx.minisoar_block_duration)
    commit = bool(params.get("commit", False))
    target_param = params.get("targets")

    if target_param:
        if isinstance(target_param, str):
            target_providers = [target_param]
        else:
            target_providers = list(target_param)
    else:
        target_providers = ctx.providers if (ctx.mapped and ctx.providers and ctx.providers != ["none"]) else ["imperva"]

    r = ctx.redis_conn
    is_permanent = bool(params.get("permanent", False) or ctx.reputation_score >= 50)
    blocked_any = False
    extended_any = False
    failed_providers = []

    for p in target_providers:
        p_norm = norm_provider(p)
        if r and is_ip_blocked(r, ip, p_norm):
            if not is_permanent:
                extend_block_state(r, ip, p_norm, duration=duration)
                extended_any = True
                log_user_action(
                    "BLOCK_EXTEND",
                    {"username": "playbook"},
                    ip=ip,
                    target=p,
                    note=f"Playbook block extended +{duration}s",
                    logfile=ctx.logfile,
                )
            else:
                remove_block_state(r, ip, p_norm)
                extended_any = True
                log_user_action(
                    "BLOCK_PERMANENT",
                    {"username": "playbook"},
                    ip=ip,
                    target=p,
                    note=f"Playbook upgraded to permanent block (Reputation: {ctx.reputation_score}%)",
                    logfile=ctx.logfile,
                )
        else:
            success, blk_msg = trigger_auto_block(ip, p, commit=commit)
            if success:
                if r and not is_permanent:
                    register_block_state(r, ip, p_norm, duration=duration)
                blocked_any = True
                if not commit and p_norm in ctx.pending_commits:
                    ctx.pending_commits[p_norm] = True
                act_type = "AUTO_BLOCK_PERMANENT" if is_permanent else "AUTO_BLOCK"
                act_note = "Permanent" if is_permanent else f"Temporary {duration}s"
                log_user_action(
                    act_type,
                    {"username": "playbook"},
                    ip=ip,
                    target=p,
                    note=f"Playbook auto-block ({act_note})",
                    logfile=ctx.logfile,
                )
            else:
                failed_providers.append(f"{p.upper()}: {blk_msg}")
                logger.error("[PLAYBOOK] Auto-block failed for %s on %s: %s", ip, p, blk_msg)

    result_data = {
        "blocked_any": blocked_any,
        "extended_any": extended_any,
        "is_permanent": is_permanent,
        "duration": duration,
        "targets": target_providers,
        "failed_providers": failed_providers,
    }
    return (blocked_any or extended_any or not failed_providers), result_data


@register_action("mitigation.auto_unblock")
def action_auto_unblock(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to unblock an IP from designated perimeters."""
    ip = ctx.ip
    if not ip:
        return False, "Missing IP"

    target_param = params.get("targets")
    target_providers = [target_param] if isinstance(target_param, str) else (target_param or ctx.providers)
    commit = bool(params.get("commit", True))

    r = ctx.redis_conn
    unblocked_any = False
    for p in target_providers:
        p_norm = norm_provider(p)
        ok, msg = trigger_auto_unblock(ip, p, commit=commit)
        if ok:
            if r:
                remove_block_state(r, ip, p_norm)
            unblocked_any = True
            log_user_action("UNBLOCK", {"username": "playbook"}, ip=ip, target=p, note="Playbook unblock", logfile=ctx.logfile)
    return unblocked_any, {"unblocked_any": unblocked_any}


@register_action("notification.telegram")
def action_send_telegram(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to broadcast an alert message to Telegram."""
    custom_header = params.get("header")
    show_buttons = params.get("show_buttons", True)
    if ctx.whitelisted:
        show_buttons = False

    msg = build_message(ctx.event)
    badge = provider_badge(ctx.providers, ctx.mapped)
    msg = inject_perimeter_line(msg, badge)

    if custom_header:
        msg = f"{custom_header}\n" + msg
    elif ctx.whitelisted:
        msg = "🤖 *Playbook Action: ALLOW (Whitelisted)*\n" + msg
    elif ctx.results.get("mitigation.auto_block", {}).get("blocked_any"):
        auto_blk_res = ctx.results["mitigation.auto_block"]
        dur = auto_blk_res.get("duration", 600)
        is_perm = auto_blk_res.get("is_permanent", False)
        status_text = "Permanent" if is_perm else f"Temporary {dur}s"
        msg = f"🤖 *Playbook Action: AUTO-BLOCKED ({status_text})*\n" + msg
    elif ctx.results.get("mitigation.auto_block", {}).get("extended_any"):
        msg = "🤖 *Playbook Action: BLOCK EXTENDED*\n" + msg

    target_providers = ctx.providers if (ctx.mapped and ctx.providers and ctx.providers != ["none"]) else ["imperva"]
    send_telegram(
        msg,
        ip=ctx.ip,
        show_buttons=show_buttons,
        providers=target_providers,
        website=ctx.website,
        event_id=ctx.event_id,
    )
    return True, {"message_sent": True}


@register_action("database.store_label")
def action_store_label(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to store decision label in Elasticsearch for ML dataset training."""
    if not ctx.event_id:
        return False, "Missing event_id"

    decision = params.get("decision", "block" if ctx.ml_label == 1 else "ignore")
    actor_name = params.get("actor", "playbook_engine")
    actor = {"username": actor_name, "id": 0}

    store_label(
        event_id=ctx.event_id,
        decision=decision,
        user=actor,
        source="playbook",
        ip=ctx.ip,
        tags=list(ctx.event.get("tags") or []),
    )
    return True, {"label_stored": True, "decision": decision}


@register_action("context.set_variable")
def action_set_variable(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to set custom variable in context for downstream steps."""
    for k, v in params.items():
        ctx.custom_vars[k] = v
    return True, ctx.custom_vars


@register_action("edr.isolate_endpoint")
def action_edr_isolate(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to isolate an endpoint host via EDR (Kaspersky KSC / TrendMicro Vision One)."""
    from ..edr.core import isolate_endpoint

    target = params.get("target") or ctx.ip
    provider = params.get("provider", "all")
    reason = params.get("reason", f"MiniSOAR automated playbook isolation for {ctx.event_id}")

    ok, msg, details = isolate_endpoint(target=target, provider=provider, reason=reason)
    log_user_action(
        "EDR_ISOLATE",
        {"username": "playbook"},
        ip=target,
        target=f"EDR-{provider.upper()}",
        note=f"Playbook EDR Isolation: {msg}",
        logfile=ctx.logfile,
    )
    return ok, {"message": msg, "details": details}


@register_action("edr.restore_endpoint")
def action_edr_restore(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to restore network connectivity for an isolated endpoint via EDR."""
    from ..edr.core import restore_endpoint

    target = params.get("target") or ctx.ip
    provider = params.get("provider", "all")

    ok, msg, details = restore_endpoint(target=target, provider=provider)
    log_user_action(
        "EDR_RESTORE",
        {"username": "playbook"},
        ip=target,
        target=f"EDR-{provider.upper()}",
        note=f"Playbook EDR Restore: {msg}",
        logfile=ctx.logfile,
    )
    return ok, {"message": msg, "details": details}


@register_action("edr.add_ioc")
def action_edr_add_ioc(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to push IoC indicators (IP, hash, URL) to EDR servers."""
    from ..edr.core import add_edr_ioc

    ioc_type = params.get("type", "ip")
    ioc_value = params.get("value") or ctx.ip
    provider = params.get("provider", "all")
    comment = params.get("comment", f"MiniSOAR Playbook IoC for event {ctx.event_id}")

    ok, msg = add_edr_ioc(ioc_type=ioc_type, ioc_value=ioc_value, provider=provider, comment=comment)
    return ok, {"message": msg}


# ---------------------------------------------
# Tier 3: Case Management Actions
# ---------------------------------------------
@register_action("case.create_case")
def action_create_case(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to initialize an incident case from playbook execution."""
    from ..cases.core import create_case

    title = params.get("title") or f"Incident: {ctx.event.get('alert', {}).get('type', 'Threat Alert')} on {ctx.website}"
    severity = params.get("severity") or ctx.event.get("alert", {}).get("severity", "medium")
    sync_th = bool(params.get("sync_thehive", False))
    sync_jira = bool(params.get("sync_jira", False))

    case = create_case(
        title=title,
        severity=severity,
        description=f"Auto-generated by playbook for Event ID {ctx.event_id}",
        attacker_ip=ctx.ip,
        target_asset=ctx.website,
        source_event_id=ctx.event_id,
        tags=params.get("tags") or ["playbook", "automated"],
        creator="playbook",
        sync_to_thehive=sync_th,
        sync_to_jira=sync_jira,
    )
    return True, {"case_id": case.case_id, "status": case.status}


@register_action("case.update_case")
def action_update_case(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to update status or timeline of an existing incident case."""
    from ..cases.core import update_case_status

    case_id = params.get("case_id")
    status = params.get("status", "CONTAINED")
    notes = params.get("notes", "Updated by automated playbook")
    if not case_id:
        return False, "Missing case_id parameter"

    ok, msg, case = update_case_status(case_id, status, actor="playbook", notes=notes)
    return ok, {"message": msg, "case_id": case_id}


# ---------------------------------------------
# Tier 4: Extended Perimeters (Cloudflare & FortiGate)
# ---------------------------------------------
@register_action("mitigation.cloudflare_block")
def action_cloudflare_block(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to block an attacker IP directly on Cloudflare WAF."""
    from ..mitigation.cloudflare import block_ip

    ip = params.get("ip") or ctx.ip
    if not ip:
        return False, "Missing target IP"
    ok, msg = block_ip(ip, notes=params.get("notes", f"Playbook event {ctx.event_id}"))
    return ok, {"message": msg, "provider": "cloudflare"}


@register_action("mitigation.fortigate_block")
def action_fortigate_block(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to block an attacker IP directly on Fortinet FortiGate."""
    from ..mitigation.fortigate import block_ip

    ip = params.get("ip") or ctx.ip
    if not ip:
        return False, "Missing target IP"
    ok, msg = block_ip(ip, comment=params.get("comment", f"Playbook event {ctx.event_id}"))
    return ok, {"message": msg, "provider": "fortigate"}


# ---------------------------------------------
# Tier 5: AI SOC Copilot Actions
# ---------------------------------------------
@register_action("ai.copilot_analyze")
def action_copilot_analyze(ctx: ExecutionContext, params: dict[str, Any]) -> tuple[bool, Any]:
    """Action to run AI Copilot payload analysis or RCA on the incident."""
    from ..ai.copilot import analyze_payload

    payload = params.get("payload") or ctx.event.get("http", {}).get("request", {}).get("body", {}).get("content", "") or str(ctx.event)
    analysis = analyze_payload(str(payload))
    return True, {"analysis": analysis}


def get_action_handler(name: str) -> ActionHandler | None:
    return _ACTION_REGISTRY.get(name)

