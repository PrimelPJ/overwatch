"""
Alert suppression rules engine.

Evaluates incoming alerts against a set of suppression rules to silence
known-noisy or false-positive alert patterns.  Rules support exact match,
regex, wildcard glob, and threshold/time-window suppression.
"""

from __future__ import annotations

import fnmatch
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

from overwatch.models import AlertTriage, RawAlert, Severity

logger = logging.getLogger(__name__)


class MatchType(str, Enum):
    EXACT = "exact"
    REGEX = "regex"
    GLOB = "glob"
    CONTAINS = "contains"
    STARTSWITH = "startswith"


class SuppressionScope(str, Enum):
    """What field on the alert the condition inspects."""
    TITLE = "title"
    SOURCE = "source"
    SEVERITY = "severity"
    DESCRIPTION = "description"
    TAG = "tag"
    IOC_VALUE = "ioc_value"
    RAW_FIELD = "raw_field"  # arbitrary key inside raw_data


class SuppressionAction(str, Enum):
    DROP = "drop"          # discard alert entirely
    SILENCE = "silence"    # mark as suppressed but keep in log
    DOWNGRADE = "downgrade"  # lower severity by one level


@dataclass
class SuppressionCondition:
    """Single field-level condition within a suppression rule."""
    scope: SuppressionScope
    match_type: MatchType
    value: str                       # pattern/value to match against
    raw_field_key: Optional[str] = None  # required when scope=RAW_FIELD

    # compiled regex cache
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.match_type == MatchType.REGEX:
            self._compiled = re.compile(self.value, re.IGNORECASE)

    def evaluate(self, alert: "AlertCandidate") -> bool:
        target = self._extract_target(alert)
        if target is None:
            return False
        return self._match(target)

    def _extract_target(self, alert: "AlertCandidate") -> Optional[str]:
        if self.scope == SuppressionScope.TITLE:
            return alert.title
        if self.scope == SuppressionScope.SOURCE:
            return alert.source
        if self.scope == SuppressionScope.SEVERITY:
            return alert.severity.value
        if self.scope == SuppressionScope.DESCRIPTION:
            return alert.description
        if self.scope == SuppressionScope.TAG:
            # match against any tag
            for tag in alert.tags:
                if self._match(tag):
                    return tag
            return None
        if self.scope == SuppressionScope.IOC_VALUE:
            for ioc_val in alert.ioc_values:
                if self._match(ioc_val):
                    return ioc_val
            return None
        if self.scope == SuppressionScope.RAW_FIELD:
            val = alert.raw_data.get(self.raw_field_key or "")
            return str(val) if val is not None else None
        return None

    def _match(self, text: str) -> bool:
        if self.match_type == MatchType.EXACT:
            return text.lower() == self.value.lower()
        if self.match_type == MatchType.CONTAINS:
            return self.value.lower() in text.lower()
        if self.match_type == MatchType.STARTSWITH:
            return text.lower().startswith(self.value.lower())
        if self.match_type == MatchType.GLOB:
            return fnmatch.fnmatchcase(text.lower(), self.value.lower())
        if self.match_type == MatchType.REGEX and self._compiled:
            return bool(self._compiled.search(text))
        return False


@dataclass
class ThresholdConfig:
    """
    Suppress after *count* matching alerts within *window_seconds*.
    Until the threshold is hit the alert passes through normally.
    """
    count: int           # number of hits that triggers suppression
    window_seconds: int  # rolling time-window length
    group_by: Optional[str] = None  # raw_data key to group counts by


@dataclass
class SuppressionRule:
    """A named suppression rule composed of one-or-more conditions."""

    name: str
    conditions: List[SuppressionCondition]
    action: SuppressionAction = SuppressionAction.DROP
    # ALL conditions must match (AND).  Set to False for OR semantics.
    require_all: bool = True
    threshold: Optional[ThresholdConfig] = None
    # Optional absolute expiry for the rule itself
    expires_at: Optional[datetime] = None
    enabled: bool = True
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Counters
    match_count: int = 0
    suppressed_count: int = 0

    def is_active(self) -> bool:
        if not self.enabled:
            return False
        if self.expires_at and datetime.now(timezone.utc) >= self.expires_at:
            return False
        return True

    def conditions_match(self, alert: "AlertCandidate") -> bool:
        if not self.conditions:
            return False
        results = [c.evaluate(alert) for c in self.conditions]
        if self.require_all:
            return all(results)
        return any(results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "action": self.action.value,
            "require_all": self.require_all,
            "description": self.description,
            "match_count": self.match_count,
            "suppressed_count": self.suppressed_count,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AlertCandidate:
    """Thin projection of an alert for condition evaluation."""
    alert_id: str
    title: str
    description: str
    source: str
    severity: Severity
    tags: List[str] = field(default_factory=list)
    ioc_values: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_raw_alert(cls, alert: Any) -> "AlertCandidate":
        """Build candidate from a RawAlert or AlertTriage instance."""
        tags: List[str] = []
        ioc_values: List[str] = []
        if hasattr(alert, "matched_iocs"):
            ioc_values = [ioc.value for ioc in alert.matched_iocs]
            tags = list(alert.mitre_techniques)
        observables = getattr(alert, "observables", [])
        for obs in observables:
            if isinstance(obs, dict) and "value" in obs:
                ioc_values.append(obs["value"])
        return cls(
            alert_id=getattr(alert, "alert_id", str(uuid.uuid4())),
            title=getattr(alert, "title", ""),
            description=getattr(alert, "description", ""),
            source=getattr(alert, "source", ""),
            severity=getattr(alert, "severity", Severity.MEDIUM),
            tags=tags,
            ioc_values=ioc_values,
            raw_data=getattr(alert, "raw_data", {}),
        )


@dataclass
class SuppressionVerdict:
    suppressed: bool
    rule_id: Optional[str]
    rule_name: Optional[str]
    action: Optional[SuppressionAction]
    reason: str = ""

    @classmethod
    def allow(cls) -> "SuppressionVerdict":
        return cls(suppressed=False, rule_id=None, rule_name=None, action=None)

    @classmethod
    def suppress(cls, rule: SuppressionRule, reason: str = "") -> "SuppressionVerdict":
        return cls(
            suppressed=True,
            rule_id=rule.id,
            rule_name=rule.name,
            action=rule.action,
            reason=reason or f"Matched suppression rule: {rule.name}",
        )


class SuppressionEngine:
    """
    Evaluates alerts against a registry of suppression rules.

    Rules are evaluated in priority order (insertion order).  The first
    matching active rule wins.  Threshold rules maintain per-group sliding
    windows of alert timestamps to implement rate-based suppression.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, SuppressionRule] = {}  # id -> rule
        self._rule_order: List[str] = []              # ordered rule ids
        # threshold state: rule_id -> group_key -> deque of timestamps
        self._threshold_windows: Dict[str, Dict[str, Deque[float]]] = defaultdict(
            lambda: defaultdict(deque)
        )

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: SuppressionRule) -> str:
        """Register a rule.  Returns the rule id."""
        self._rules[rule.id] = rule
        self._rule_order.append(rule.id)
        logger.info("Registered suppression rule: %s (%s)", rule.name, rule.id)
        return rule.id

    def remove_rule(self, rule_id: str) -> bool:
        if rule_id not in self._rules:
            return False
        del self._rules[rule_id]
        self._rule_order.remove(rule_id)
        self._threshold_windows.pop(rule_id, None)
        logger.info("Removed suppression rule: %s", rule_id)
        return True

    def enable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False

    def get_rule(self, rule_id: str) -> Optional[SuppressionRule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[SuppressionRule]:
        return [self._rules[rid] for rid in self._rule_order]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, alert: Any) -> SuppressionVerdict:
        """
        Evaluate *alert* (RawAlert, AlertTriage, or AlertCandidate) against
        all active suppression rules.  Returns a SuppressionVerdict.
        """
        if isinstance(alert, AlertCandidate):
            candidate = alert
        else:
            candidate = AlertCandidate.from_raw_alert(alert)

        for rule_id in self._rule_order:
            rule = self._rules[rule_id]
            if not rule.is_active():
                continue
            if not rule.conditions_match(candidate):
                continue

            rule.match_count += 1

            if rule.threshold is not None:
                if not self._threshold_exceeded(rule, candidate):
                    # Conditions match but count threshold not yet reached
                    logger.debug(
                        "Rule %s matched alert %s but threshold not exceeded",
                        rule.name, candidate.alert_id,
                    )
                    continue

            rule.suppressed_count += 1
            verdict = SuppressionVerdict.suppress(rule)
            logger.info(
                "Alert %s suppressed by rule %s (action=%s)",
                candidate.alert_id, rule.name, rule.action.value,
            )
            return verdict

        return SuppressionVerdict.allow()

    def _threshold_exceeded(self, rule: SuppressionRule, candidate: AlertCandidate) -> bool:
        """Record this hit and return True if the threshold is now exceeded."""
        cfg = rule.threshold
        assert cfg is not None

        # Determine the grouping key
        group_key = "_default_"
        if cfg.group_by:
            group_key = str(candidate.raw_data.get(cfg.group_by, "_default_"))

        window = self._threshold_windows[rule.id][group_key]
        now = time.time()
        cutoff = now - cfg.window_seconds

        # Evict stale entries
        while window and window[0] <= cutoff:
            window.popleft()

        window.append(now)

        return len(window) >= cfg.count

    # ------------------------------------------------------------------
    # Bulk / pipeline helpers
    # ------------------------------------------------------------------

    def filter_alerts(
        self,
        alerts: List[Any],
    ) -> Tuple[List[Any], List[Tuple[Any, SuppressionVerdict]]]:
        """
        Partition *alerts* into (allowed, suppressed).

        Returns:
            allowed   – list of alerts that passed all rules
            suppressed – list of (alert, verdict) tuples
        """
        allowed: List[Any] = []
        suppressed: List[Tuple[Any, SuppressionVerdict]] = []
        for alert in alerts:
            verdict = self.evaluate(alert)
            if verdict.suppressed:
                suppressed.append((alert, verdict))
            else:
                allowed.append(alert)
        return allowed, suppressed

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        total_rules = len(self._rules)
        active_rules = sum(1 for r in self._rules.values() if r.is_active())
        total_matches = sum(r.match_count for r in self._rules.values())
        total_suppressed = sum(r.suppressed_count for r in self._rules.values())
        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "disabled_rules": total_rules - active_rules,
            "total_condition_matches": total_matches,
            "total_suppressed": total_suppressed,
            "rules": [r.to_dict() for r in self.list_rules()],
        }
