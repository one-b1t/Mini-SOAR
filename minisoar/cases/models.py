from __future__ import annotations

"""Data models for MiniSOAR Incident Case Management."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class CaseStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


class CaseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimelineEntry:
    timestamp: str
    actor: str
    action: str
    note: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentCase:
    case_id: str
    title: str
    severity: str
    status: str
    description: str = ""
    assigned_to: str = "unassigned"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed_at: str | None = None
    source_event_id: str | None = None
    attacker_ip: str | None = None
    target_asset: str | None = None
    tags: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    mitigation_actions: list[dict[str, Any]] = field(default_factory=list)
    resolution_notes: str = ""
    external_tickets: dict[str, str] = field(default_factory=dict)  # {"thehive": "123", "jira": "SEC-402"}
    mttd_seconds: float = 0.0  # Mean Time to Detect / Acknowledge
    mttr_seconds: float = 0.0  # Mean Time to Resolve / Contain

    @classmethod
    def create_new(
        cls,
        title: str,
        *,
        severity: str = "medium",
        description: str = "",
        attacker_ip: str | None = None,
        target_asset: str | None = None,
        source_event_id: str | None = None,
        tags: list[str] | None = None,
        creator: str = "system",
    ) -> IncidentCase:
        cid = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        initial_entry = TimelineEntry(
            timestamp=now_str,
            actor=creator,
            action="case_created",
            note=f"Case initialized with severity={severity}",
        )
        return cls(
            case_id=cid,
            title=title,
            severity=severity.lower(),
            status=CaseStatus.NEW.value,
            description=description,
            created_at=now_str,
            updated_at=now_str,
            source_event_id=source_event_id,
            attacker_ip=attacker_ip,
            target_asset=target_asset,
            tags=tags or [],
            timeline=[initial_entry.to_dict()],
        )

    def add_timeline(self, actor: str, action: str, note: str, data: dict[str, Any] | None = None) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        self.updated_at = now_str
        entry = TimelineEntry(
            timestamp=now_str,
            actor=actor,
            action=action,
            note=note,
            data=data or {},
        )
        self.timeline.append(entry.to_dict())

    def update_status(self, new_status: str, actor: str, note: str = "") -> None:
        old_status = self.status
        self.status = new_status.upper()
        now = datetime.now(timezone.utc)
        self.updated_at = now.isoformat()

        # Calculate MTTR if closing or resolving
        if self.status in {CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value, CaseStatus.FALSE_POSITIVE.value}:
            if not self.closed_at:
                self.closed_at = now.isoformat()
                try:
                    created_dt = datetime.fromisoformat(self.created_at)
                    self.mttr_seconds = max(0.0, (now - created_dt).total_seconds())
                except Exception:
                    pass

        self.add_timeline(actor, "status_change", f"Status changed from {old_status} to {self.status}. {note}".strip())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
