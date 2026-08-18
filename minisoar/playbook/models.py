from __future__ import annotations

"""Data models for MiniSOAR Declarative Playbook Engine."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TriggerCriteria:
    alert_types: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    min_ml_prob: float | None = None
    min_reputation_score: int | None = None

    def matches(self, alert_type: str, event_tags: set[str], severity: str | None, ml_prob: float, rep_score: int) -> bool:
        if self.alert_types:
            type_match = alert_type in self.alert_types or any(t in event_tags for t in self.alert_types)
            if not type_match:
                return False

        if self.tags and not (set(self.tags) & event_tags):
            return False

        if self.severity:
            norm_sev = (severity or "low").lower()
            if not any(s.lower() == norm_sev for s in self.severity):
                return False

        if self.min_ml_prob is not None and ml_prob < self.min_ml_prob:
            return False

        if self.min_reputation_score is not None and rep_score < self.min_reputation_score:
            return False

        return True


@dataclass
class PlaybookStep:
    id: str
    name: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    conditions: list[str] = field(default_factory=list)
    on_failure: str = "continue"  # "continue" or "stop"


@dataclass
class Playbook:
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100  # Lower number = higher priority
    trigger: TriggerCriteria = field(default_factory=TriggerCriteria)
    conditions: list[str] = field(default_factory=list)
    steps: list[PlaybookStep] = field(default_factory=list)


@dataclass
class ExecutionContext:
    event: dict[str, Any]
    ip: str
    website: str
    providers: list[str]
    mapped: bool
    whitelisted: bool
    bypassed: bool
    ml_prob: float
    ml_label: int
    reputation_score: int
    rep_str: str
    event_id: str
    redis_conn: Any = None
    pending_commits: dict[str, bool] = field(default_factory=dict)
    logfile: str = "tele-soar-actions.log"
    minisoar_block_duration: int = 600
    custom_vars: dict[str, Any] = field(default_factory=dict)
    executed_steps: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)

    def get_eval_dict(self) -> dict[str, Any]:
        """Provides a safe dictionary for evaluating playbook conditions."""
        return {
            "event": self.event,
            "ip": self.ip,
            "website": self.website,
            "providers": self.providers,
            "mapped": self.mapped,
            "whitelisted": self.whitelisted,
            "bypassed": self.bypassed,
            "ml_prob": self.ml_prob,
            "ml_label": self.ml_label,
            "reputation_score": self.reputation_score,
            "rep_str": self.rep_str,
            "event_id": self.event_id,
            "severity": (self.event.get("alert") or {}).get("severity") or self.event.get("severity") or "low",
            "alert_type": (self.event.get("alert") or {}).get("type") or self.event.get("detector_type") or "",
            "tags": list(self.event.get("tags") or []),
            "custom": self.custom_vars,
            "results": self.results,
        }
