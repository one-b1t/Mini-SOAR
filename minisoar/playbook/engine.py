from __future__ import annotations

"""Playbook Engine orchestrator and YAML loader."""

import logging
from pathlib import Path
from typing import Any

import yaml

from .actions import get_action_handler
from .conditions import evaluate_conditions
from .models import ExecutionContext, Playbook, PlaybookStep, TriggerCriteria

logger = logging.getLogger(__name__)


def parse_playbook_dict(data: dict[str, Any]) -> Playbook:
    """Parses a dictionary (loaded from YAML) into a Playbook instance."""
    p_id = str(data.get("id") or "unnamed_playbook")
    p_name = str(data.get("name") or p_id)
    description = str(data.get("description") or "")
    enabled = bool(data.get("enabled", True))
    priority = int(data.get("priority", 100))

    trigger_data = data.get("trigger") or {}
    trigger = TriggerCriteria(
        alert_types=list(trigger_data.get("alert_types") or []),
        tags=list(trigger_data.get("tags") or []),
        severity=list(trigger_data.get("severity") or []),
        min_ml_prob=float(trigger_data["min_ml_prob"]) if "min_ml_prob" in trigger_data else None,
        min_reputation_score=int(trigger_data["min_reputation_score"]) if "min_reputation_score" in trigger_data else None,
    )

    conditions = [str(c) for c in (data.get("conditions") or [])]

    steps_raw = data.get("steps") or []
    steps: list[PlaybookStep] = []
    for s_idx, s in enumerate(steps_raw):
        s_id = str(s.get("id") or f"step_{s_idx+1}")
        s_name = str(s.get("name") or s_id)
        action = str(s.get("action") or "")
        params = dict(s.get("params") or {})
        s_conditions = [str(c) for c in (s.get("conditions") or [])]
        on_failure = str(s.get("on_failure") or "continue").lower()
        steps.append(PlaybookStep(
            id=s_id,
            name=s_name,
            action=action,
            params=params,
            conditions=s_conditions,
            on_failure=on_failure,
        ))

    return Playbook(
        id=p_id,
        name=p_name,
        description=description,
        enabled=enabled,
        priority=priority,
        trigger=trigger,
        conditions=conditions,
        steps=steps,
    )


def load_playbooks_from_dir(directory: Path | str) -> list[Playbook]:
    """Loads and sorts all YAML playbooks from a given directory."""
    path = Path(directory)
    if not path.is_dir():
        logger.warning("Playbooks directory not found: %s", path)
        return []

    playbooks: list[Playbook] = []
    for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    pb = parse_playbook_dict(data)
                    if pb.enabled:
                        playbooks.append(pb)
                        logger.debug("Loaded playbook: %s (id=%s, priority=%d)", pb.name, pb.id, pb.priority)
        except Exception as e:
            logger.error("Failed to parse playbook file %s: %s", file, e)

    # Sort playbooks by priority (lowest integer value executed first)
    playbooks.sort(key=lambda x: x.priority)
    return playbooks


class PlaybookEngine:
    """Core engine to match and execute declarative playbooks."""

    def __init__(self, playbooks_dir: Path | str | None = None, playbooks: list[Playbook] | None = None):
        if playbooks is not None:
            self.playbooks = sorted([p for p in playbooks if p.enabled], key=lambda x: x.priority)
        elif playbooks_dir:
            self.playbooks = load_playbooks_from_dir(playbooks_dir)
        else:
            self.playbooks = []

    def select_playbook(self, ctx: ExecutionContext) -> Playbook | None:
        """Finds the first matching playbook for the given execution context."""
        alert_type = (ctx.event.get("alert") or {}).get("type") or ctx.event.get("detector_type") or ""
        event_tags = set(ctx.event.get("tags") or (ctx.event.get("alert") or {}).get("tags") or [])
        severity = (ctx.event.get("alert") or {}).get("severity") or ctx.event.get("severity")

        eval_scope = ctx.get_eval_dict()

        for pb in self.playbooks:
            if not pb.trigger.matches(alert_type, event_tags, severity, ctx.ml_prob, ctx.reputation_score):
                continue

            if pb.conditions and not evaluate_conditions(pb.conditions, eval_scope):
                continue

            return pb

        return None

    def execute(self, ctx: ExecutionContext) -> tuple[bool, str | None]:
        """Selects and executes a playbook against the given execution context.

        Returns (success: bool, executed_playbook_id: str | None).
        """
        pb = self.select_playbook(ctx)
        if not pb:
            logger.debug("[PLAYBOOK] No matching playbook found for event %s", ctx.event_id)
            return False, None

        logger.info("[PLAYBOOK] Executing Playbook '%s' (id=%s) for event %s", pb.name, pb.id, ctx.event_id)
        eval_scope = ctx.get_eval_dict()

        for step in pb.steps:
            if step.conditions:
                eval_scope = ctx.get_eval_dict()
                if not evaluate_conditions(step.conditions, eval_scope):
                    logger.debug("[PLAYBOOK] Step '%s' skipped due to condition mismatch", step.name)
                    continue

            handler = get_action_handler(step.action)
            if not handler:
                logger.error("[PLAYBOOK] Unknown action handler: %s in step %s", step.action, step.name)
                if step.on_failure == "stop":
                    return False, pb.id
                continue

            try:
                ok, res = handler(ctx, step.params)
                ctx.executed_steps.append(step.id)
                ctx.results[step.action] = res
                ctx.results[step.id] = res

                if not ok:
                    logger.warning("[PLAYBOOK] Step '%s' (%s) reported failure: %s", step.name, step.action, res)
                    if step.on_failure == "stop":
                        return False, pb.id
            except Exception as e:
                logger.exception("[PLAYBOOK] Exception executing step '%s': %s", step.name, e)
                if step.on_failure == "stop":
                    return False, pb.id

        return True, pb.id
