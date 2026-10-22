"""
Investigation case management for threat intelligence operations.
Groups related alerts into cases, tracks lifecycle, and generates timelines.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .models import AlertTriage, IOC, PlaybookAction, Severity


class CaseState(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    PENDING_CLOSURE = "pending_closure"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

    @property
    def is_terminal(self) -> bool:
        return self in (CaseState.RESOLVED, CaseState.CLOSED, CaseState.FALSE_POSITIVE)


class CasePriority(str, Enum):
    CRITICAL = "P1"
    HIGH = "P2"
    MEDIUM = "P3"
    LOW = "P4"

    @classmethod
    def from_severity(cls, severity: Severity) -> "CasePriority":
        mapping = {
            Severity.CRITICAL: cls.CRITICAL,
            Severity.HIGH: cls.HIGH,
            Severity.MEDIUM: cls.MEDIUM,
            Severity.LOW: cls.LOW,
            Severity.INFO: cls.LOW,
        }
        return mapping[severity]


@dataclass
class TimelineEvent:
    """A single event in a case investigation timeline."""

    timestamp: datetime
    event_type: str
    description: str
    actor: str = "system"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "actor": self.actor,
            "metadata": self.metadata,
        }


@dataclass
class Evidence:
    """A piece of evidence attached to a case."""

    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: str = ""  # "ioc", "pcap", "log", "screenshot", "artifact"
    description: str = ""
    source: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    added_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "source": self.source,
            "data": self.data,
            "tags": list(self.tags),
            "added_at": self.added_at.isoformat(),
            "added_by": self.added_by,
        }


@dataclass
class InvestigationCase:
    """A grouped investigation case containing related alerts."""

    title: str
    description: str = ""
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: CaseState = CaseState.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    severity: Severity = Severity.MEDIUM
    assigned_to: Optional[str] = None
    tags: Set[str] = field(default_factory=set)

    alerts: List[AlertTriage] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    recommended_actions: List[PlaybookAction] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    analyst_notes: str = ""
    resolution_summary: str = ""
    timeline: List[TimelineEvent] = field(default_factory=list)

    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self._add_timeline_event("case_created", f"Case '{self.title}' created")

    # ------------------------------------------------------------------ #
    # State transitions
    # ------------------------------------------------------------------ #

    def start_investigation(self, analyst: str = "system") -> None:
        if self.state != CaseState.OPEN:
            raise ValueError(f"Cannot start investigation from state {self.state}")
        self.state = CaseState.INVESTIGATING
        self.assigned_to = self.assigned_to or analyst
        self._add_timeline_event("investigation_started", "Investigation started", actor=analyst)
        self._touch()

    def request_closure(self, analyst: str = "system") -> None:
        if self.state not in (CaseState.OPEN, CaseState.INVESTIGATING):
            raise ValueError(f"Cannot request closure from state {self.state}")
        self.state = CaseState.PENDING_CLOSURE
        self._add_timeline_event("closure_requested", "Closure requested", actor=analyst)
        self._touch()

    def resolve(self, summary: str, analyst: str = "system") -> None:
        if self.state.is_terminal:
            raise ValueError(f"Case already in terminal state {self.state}")
        self.state = CaseState.RESOLVED
        self.resolution_summary = summary
        self.resolved_at = datetime.now(timezone.utc)
        self._add_timeline_event(
            "case_resolved", f"Case resolved: {summary[:120]}", actor=analyst
        )
        self._touch()

    def close(self, analyst: str = "system") -> None:
        if self.state not in (CaseState.RESOLVED, CaseState.PENDING_CLOSURE):
            raise ValueError(f"Cannot close from state {self.state}")
        self.state = CaseState.CLOSED
        self.closed_at = datetime.now(timezone.utc)
        self._add_timeline_event("case_closed", "Case closed", actor=analyst)
        self._touch()

    def mark_false_positive(self, reason: str, analyst: str = "system") -> None:
        if self.state.is_terminal:
            raise ValueError(f"Case already in terminal state {self.state}")
        self.state = CaseState.FALSE_POSITIVE
        self.resolution_summary = f"False positive: {reason}"
        self.resolved_at = datetime.now(timezone.utc)
        self._add_timeline_event(
            "false_positive", f"Marked false positive: {reason[:120]}", actor=analyst
        )
        self._touch()

    # ------------------------------------------------------------------ #
    # Alert and evidence management
    # ------------------------------------------------------------------ #

    def add_alert(self, alert: AlertTriage, analyst: str = "system") -> None:
        if any(a.alert_id == alert.alert_id for a in self.alerts):
            return
        self.alerts.append(alert)
        self._recalculate_severity()
        self._merge_recommended_actions(alert.recommended_actions)
        self._merge_mitre(alert.mitre_techniques)
        for ioc in alert.matched_iocs:
            self.add_ioc(ioc)
        self._add_timeline_event(
            "alert_added",
            f"Alert '{alert.title}' (severity={alert.severity.value}) added to case",
            actor=analyst,
            metadata={"alert_id": alert.alert_id},
        )
        self._touch()

    def remove_alert(self, alert_id: str, analyst: str = "system") -> bool:
        before = len(self.alerts)
        self.alerts = [a for a in self.alerts if a.alert_id != alert_id]
        if len(self.alerts) < before:
            self._recalculate_severity()
            self._add_timeline_event(
                "alert_removed", f"Alert {alert_id} removed from case", actor=analyst
            )
            self._touch()
            return True
        return False

    def add_ioc(self, ioc: IOC) -> None:
        if any(i.fingerprint == ioc.fingerprint for i in self.iocs):
            return
        self.iocs.append(ioc)
        self._touch()

    def add_evidence(
        self,
        evidence_type: str,
        description: str,
        source: str,
        data: Optional[Dict[str, Any]] = None,
        tags: Optional[Set[str]] = None,
        analyst: str = "system",
    ) -> Evidence:
        ev = Evidence(
            evidence_type=evidence_type,
            description=description,
            source=source,
            data=data or {},
            tags=tags or set(),
            added_by=analyst,
        )
        self.evidence.append(ev)
        self._add_timeline_event(
            "evidence_added",
            f"Evidence added: {description[:80]}",
            actor=analyst,
            metadata={"evidence_id": ev.evidence_id, "type": evidence_type},
        )
        self._touch()
        return ev

    def add_note(self, note: str, analyst: str = "system") -> None:
        ts = datetime.now(timezone.utc).isoformat()
        entry = f"[{ts}] ({analyst}): {note}"
        self.analyst_notes = (self.analyst_notes + "\n" + entry).strip()
        self._add_timeline_event("note_added", f"Note added by {analyst}", actor=analyst)
        self._touch()

    # ------------------------------------------------------------------ #
    # Computed properties
    # ------------------------------------------------------------------ #

    @property
    def risk_score(self) -> float:
        """Composite risk 0-100 derived from alert risk scores."""
        if not self.alerts:
            return 0.0
        scores = [a.risk_score for a in self.alerts]
        # Use 70% max + 30% average to reflect worst-case while penalizing breadth
        return min(100.0, 0.7 * max(scores) + 0.3 * (sum(scores) / len(scores)))

    @property
    def age_hours(self) -> float:
        end = self.resolved_at or datetime.now(timezone.utc)
        return (end - self.created_at).total_seconds() / 3600.0

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def ioc_count(self) -> int:
        return len(self.iocs)

    @property
    def unique_ioc_types(self) -> Set[str]:
        return {ioc.ioc_type.value for ioc in self.iocs}

    @property
    def top_mitre_techniques(self) -> List[str]:
        return self.mitre_techniques[:10]

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "state": self.state.value,
            "priority": self.priority.value,
            "severity": self.severity.value,
            "assigned_to": self.assigned_to,
            "tags": list(self.tags),
            "risk_score": round(self.risk_score, 2),
            "age_hours": round(self.age_hours, 2),
            "alert_count": self.alert_count,
            "ioc_count": self.ioc_count,
            "unique_ioc_types": list(self.unique_ioc_types),
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": [a.value for a in self.recommended_actions],
            "analyst_notes": self.analyst_notes,
            "resolution_summary": self.resolution_summary,
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": [t.to_dict() for t in self.timeline],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _recalculate_severity(self) -> None:
        if not self.alerts:
            return
        severities = [a.severity for a in self.alerts]
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if s in severities:
                self.severity = s
                self.priority = CasePriority.from_severity(s)
                return

    def _merge_recommended_actions(self, actions: List[PlaybookAction]) -> None:
        for action in actions:
            if action not in self.recommended_actions:
                self.recommended_actions.append(action)

    def _merge_mitre(self, techniques: List[str]) -> None:
        for t in techniques:
            if t not in self.mitre_techniques:
                self.mitre_techniques.append(t)

    def _add_timeline_event(
        self,
        event_type: str,
        description: str,
        actor: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.timeline.append(
            TimelineEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                description=description,
                actor=actor,
                metadata=metadata or {},
            )
        )

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)


class CaseManager:
    """
    Manages a collection of investigation cases.

    Provides case creation, alert-to-case routing, bulk queries, and
    automatic case grouping by shared IOC fingerprints.
    """

    def __init__(self) -> None:
        self._cases: Dict[str, InvestigationCase] = {}

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #

    def create_case(
        self,
        title: str,
        description: str = "",
        tags: Optional[Set[str]] = None,
        analyst: str = "system",
    ) -> InvestigationCase:
        case = InvestigationCase(title=title, description=description, tags=tags or set())
        self._cases[case.case_id] = case
        return case

    def get_case(self, case_id: str) -> Optional[InvestigationCase]:
        return self._cases.get(case_id)

    def delete_case(self, case_id: str) -> bool:
        if case_id in self._cases:
            del self._cases[case_id]
            return True
        return False

    def all_cases(self) -> List[InvestigationCase]:
        return list(self._cases.values())

    # ------------------------------------------------------------------ #
    # Routing: add an alert to an appropriate case
    # ------------------------------------------------------------------ #

    def route_alert(
        self,
        alert: AlertTriage,
        create_if_missing: bool = True,
        analyst: str = "system",
    ) -> Optional[InvestigationCase]:
        """
        Route an alert to a matching open case or create a new one.

        Matching strategy (in order):
        1. Open/investigating case that shares at least one IOC fingerprint.
        2. Open/investigating case whose title keyword overlaps with the alert title.
        3. Create a new case if `create_if_missing` is True.
        """
        candidate = self._find_ioc_match(alert) or self._find_title_match(alert)
        if candidate:
            candidate.add_alert(alert, analyst=analyst)
            return candidate
        if create_if_missing:
            case = self.create_case(
                title=f"Investigation: {alert.title}",
                description=f"Auto-created from alert {alert.alert_id}",
                tags={"auto-created"},
                analyst=analyst,
            )
            case.add_alert(alert, analyst=analyst)
            return case
        return None

    def _find_ioc_match(self, alert: AlertTriage) -> Optional[InvestigationCase]:
        alert_fps = {ioc.fingerprint for ioc in alert.matched_iocs}
        if not alert_fps:
            return None
        for case in self._cases.values():
            if case.state.is_terminal:
                continue
            case_fps = {ioc.fingerprint for ioc in case.iocs}
            if alert_fps & case_fps:
                return case
        return None

    def _find_title_match(self, alert: AlertTriage) -> Optional[InvestigationCase]:
        alert_words = set(alert.title.lower().split())
        stop_words = {"the", "a", "an", "in", "on", "at", "of", "for", "to", "and", "or"}
        alert_words -= stop_words
        if not alert_words:
            return None
        best_case: Optional[InvestigationCase] = None
        best_overlap = 0
        for case in self._cases.values():
            if case.state.is_terminal:
                continue
            case_words = set(case.title.lower().split()) - stop_words
            overlap = len(alert_words & case_words)
            if overlap > best_overlap:
                best_overlap = overlap
                best_case = case
        return best_case if best_overlap >= 2 else None

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def open_cases(self) -> List[InvestigationCase]:
        return [c for c in self._cases.values() if not c.state.is_terminal]

    def cases_by_state(self, state: CaseState) -> List[InvestigationCase]:
        return [c for c in self._cases.values() if c.state == state]

    def cases_by_severity(self, severity: Severity) -> List[InvestigationCase]:
        return [c for c in self._cases.values() if c.severity == severity]

    def cases_by_tag(self, tag: str) -> List[InvestigationCase]:
        return [c for c in self._cases.values() if tag in c.tags]

    def cases_with_ioc(self, ioc_fingerprint: str) -> List[InvestigationCase]:
        return [
            c for c in self._cases.values()
            if any(i.fingerprint == ioc_fingerprint for i in c.iocs)
        ]

    def high_risk_cases(self, threshold: float = 70.0) -> List[InvestigationCase]:
        """Return open cases with risk score at or above threshold, sorted descending."""
        candidates = [c for c in self.open_cases() if c.risk_score >= threshold]
        return sorted(candidates, key=lambda c: c.risk_score, reverse=True)

    def stale_cases(self, max_age_hours: float = 72.0) -> List[InvestigationCase]:
        """Return open cases that have not been updated recently."""
        now = datetime.now(timezone.utc)
        result = []
        for case in self.open_cases():
            idle = (now - case.updated_at).total_seconds() / 3600.0
            if idle >= max_age_hours:
                result.append(case)
        return sorted(result, key=lambda c: c.updated_at)

    # ------------------------------------------------------------------ #
    # Bulk operations
    # ------------------------------------------------------------------ #

    def merge_cases(
        self,
        primary_id: str,
        secondary_id: str,
        analyst: str = "system",
    ) -> InvestigationCase:
        """
        Merge secondary into primary case, transferring all alerts and evidence.
        Secondary is closed after merge.
        """
        primary = self._cases.get(primary_id)
        secondary = self._cases.get(secondary_id)
        if primary is None or secondary is None:
            raise ValueError("Both case IDs must exist")
        if primary_id == secondary_id:
            raise ValueError("Cannot merge a case with itself")
        for alert in secondary.alerts:
            primary.add_alert(alert, analyst=analyst)
        for ev in secondary.evidence:
            primary.evidence.append(ev)
        for note_line in secondary.analyst_notes.splitlines():
            if note_line.strip():
                primary.analyst_notes = (primary.analyst_notes + "\n" + note_line).strip()
        primary._add_timeline_event(
            "cases_merged",
            f"Merged case {secondary_id} ('{secondary.title}') into this case",
            actor=analyst,
            metadata={"merged_case_id": secondary_id},
        )
        secondary.close(analyst=analyst)
        primary._touch()
        return primary

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #

    def summary_report(self) -> Dict[str, Any]:
        """High-level statistics across all managed cases."""
        cases = list(self._cases.values())
        by_state: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for c in cases:
            by_state[c.state.value] = by_state.get(c.state.value, 0) + 1
            by_severity[c.severity.value] = by_severity.get(c.severity.value, 0) + 1

        open_c = self.open_cases()
        risk_scores = [c.risk_score for c in open_c] if open_c else [0.0]

        return {
            "total_cases": len(cases),
            "by_state": by_state,
            "by_severity": by_severity,
            "open_count": len(open_c),
            "high_risk_open": len(self.high_risk_cases()),
            "avg_open_risk_score": round(sum(risk_scores) / len(risk_scores), 2),
            "total_alerts_tracked": sum(c.alert_count for c in cases),
            "total_iocs_tracked": sum(c.ioc_count for c in cases),
        }
