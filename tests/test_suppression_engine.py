"""
Tests for the alert suppression rules engine.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from overwatch.models import Severity
from overwatch.suppression_engine import (
    AlertCandidate,
    MatchType,
    SuppressionAction,
    SuppressionCondition,
    SuppressionEngine,
    SuppressionRule,
    SuppressionScope,
    SuppressionVerdict,
    ThresholdConfig,
)


def _make_candidate(
    title: str = "Test Alert",
    source: str = "ids",
    severity: Severity = Severity.MEDIUM,
    description: str = "",
    tags: list | None = None,
    ioc_values: list | None = None,
    raw_data: dict | None = None,
) -> AlertCandidate:
    return AlertCandidate(
        alert_id="test-001",
        title=title,
        description=description,
        source=source,
        severity=severity,
        tags=tags or [],
        ioc_values=ioc_values or [],
        raw_data=raw_data or {},
    )


def _exact_title_rule(
    value: str,
    action: SuppressionAction = SuppressionAction.DROP,
) -> SuppressionRule:
    return SuppressionRule(
        name="exact-title",
        conditions=[
            SuppressionCondition(
                scope=SuppressionScope.TITLE,
                match_type=MatchType.EXACT,
                value=value,
            )
        ],
        action=action,
    )


class TestSuppressionCondition:
    def test_exact_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.TITLE,
            match_type=MatchType.EXACT,
            value="Heartbeat Alert",
        )
        assert cond.evaluate(_make_candidate(title="Heartbeat Alert"))
        assert cond.evaluate(_make_candidate(title="heartbeat alert"))  # case-insensitive
        assert not cond.evaluate(_make_candidate(title="Not Heartbeat Alert"))

    def test_regex_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.TITLE,
            match_type=MatchType.REGEX,
            value=r"port scan (from|detected)",
        )
        assert cond.evaluate(_make_candidate(title="port scan from 10.0.0.1"))
        assert cond.evaluate(_make_candidate(title="Port Scan Detected"))
        assert not cond.evaluate(_make_candidate(title="brute force attack"))

    def test_glob_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.SOURCE,
            match_type=MatchType.GLOB,
            value="test-sensor-*",
        )
        assert cond.evaluate(_make_candidate(source="test-sensor-01"))
        assert cond.evaluate(_make_candidate(source="test-sensor-99"))
        assert not cond.evaluate(_make_candidate(source="prod-sensor-01"))

    def test_contains_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.DESCRIPTION,
            match_type=MatchType.CONTAINS,
            value="scheduled scan",
        )
        assert cond.evaluate(_make_candidate(description="automated scheduled scan job"))
        assert not cond.evaluate(_make_candidate(description="unscheduled activity"))

    def test_startswith_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.TITLE,
            match_type=MatchType.STARTSWITH,
            value="[INFO]",
        )
        assert cond.evaluate(_make_candidate(title="[INFO] service restarted"))
        assert not cond.evaluate(_make_candidate(title="[WARN] high memory"))

    def test_tag_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.TAG,
            match_type=MatchType.EXACT,
            value="maintenance",
        )
        assert cond.evaluate(_make_candidate(tags=["maintenance", "scheduled"]))
        assert not cond.evaluate(_make_candidate(tags=["production", "critical"]))

    def test_ioc_value_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.IOC_VALUE,
            match_type=MatchType.EXACT,
            value="192.168.1.1",
        )
        assert cond.evaluate(_make_candidate(ioc_values=["192.168.1.1", "10.0.0.1"]))
        assert not cond.evaluate(_make_candidate(ioc_values=["10.0.0.1"]))

    def test_raw_field_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.RAW_FIELD,
            match_type=MatchType.EXACT,
            value="scanner",
            raw_field_key="agent_type",
        )
        assert cond.evaluate(_make_candidate(raw_data={"agent_type": "scanner"}))
        assert not cond.evaluate(_make_candidate(raw_data={"agent_type": "endpoint"}))

    def test_severity_match(self):
        cond = SuppressionCondition(
            scope=SuppressionScope.SEVERITY,
            match_type=MatchType.EXACT,
            value="info",
        )
        assert cond.evaluate(_make_candidate(severity=Severity.INFO))
        assert not cond.evaluate(_make_candidate(severity=Severity.HIGH))


class TestSuppressionRule:
    def test_and_conditions_both_must_match(self):
        rule = SuppressionRule(
            name="and-rule",
            require_all=True,
            conditions=[
                SuppressionCondition(
                    scope=SuppressionScope.SOURCE,
                    match_type=MatchType.EXACT,
                    value="dev-ids",
                ),
                SuppressionCondition(
                    scope=SuppressionScope.SEVERITY,
                    match_type=MatchType.EXACT,
                    value="info",
                ),
            ],
        )
        assert rule.conditions_match(
            _make_candidate(source="dev-ids", severity=Severity.INFO)
        )
        assert not rule.conditions_match(
            _make_candidate(source="dev-ids", severity=Severity.HIGH)
        )
        assert not rule.conditions_match(
            _make_candidate(source="prod-ids", severity=Severity.INFO)
        )

    def test_or_conditions_any_match(self):
        rule = SuppressionRule(
            name="or-rule",
            require_all=False,
            conditions=[
                SuppressionCondition(
                    scope=SuppressionScope.TITLE,
                    match_type=MatchType.CONTAINS,
                    value="heartbeat",
                ),
                SuppressionCondition(
                    scope=SuppressionScope.TITLE,
                    match_type=MatchType.CONTAINS,
                    value="keepalive",
                ),
            ],
        )
        assert rule.conditions_match(_make_candidate(title="heartbeat check"))
        assert rule.conditions_match(_make_candidate(title="tcp keepalive timeout"))
        assert not rule.conditions_match(_make_candidate(title="brute force"))

    def test_expiry(self):
        rule = SuppressionRule(
            name="expired-rule",
            conditions=[],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert not rule.is_active()

    def test_disabled_rule(self):
        rule = SuppressionRule(
            name="disabled",
            conditions=[
                SuppressionCondition(
                    scope=SuppressionScope.TITLE,
                    match_type=MatchType.EXACT,
                    value="noisy alert",
                )
            ],
            enabled=False,
        )
        assert not rule.is_active()


class TestSuppressionEngine:
    def test_no_rules_passes_all(self):
        engine = SuppressionEngine()
        verdict = engine.evaluate(_make_candidate(title="any alert"))
        assert not verdict.suppressed

    def test_exact_match_drops_alert(self):
        engine = SuppressionEngine()
        engine.add_rule(_exact_title_rule("heartbeat check"))
        verdict = engine.evaluate(_make_candidate(title="heartbeat check"))
        assert verdict.suppressed
        assert verdict.action == SuppressionAction.DROP

    def test_non_matching_alert_passes(self):
        engine = SuppressionEngine()
        engine.add_rule(_exact_title_rule("heartbeat check"))
        verdict = engine.evaluate(_make_candidate(title="brute force login"))
        assert not verdict.suppressed

    def test_first_matching_rule_wins(self):
        engine = SuppressionEngine()
        engine.add_rule(
            SuppressionRule(
                name="rule-a",
                conditions=[
                    SuppressionCondition(
                        scope=SuppressionScope.TITLE,
                        match_type=MatchType.CONTAINS,
                        value="scan",
                    )
                ],
                action=SuppressionAction.DROP,
            )
        )
        engine.add_rule(
            SuppressionRule(
                name="rule-b",
                conditions=[
                    SuppressionCondition(
                        scope=SuppressionScope.TITLE,
                        match_type=MatchType.CONTAINS,
                        value="scan",
                    )
                ],
                action=SuppressionAction.SILENCE,
            )
        )
        verdict = engine.evaluate(_make_candidate(title="port scan from 10.0.0.1"))
        assert verdict.suppressed
        assert verdict.rule_name == "rule-a"  # first match wins
        assert verdict.action == SuppressionAction.DROP

    def test_remove_rule(self):
        engine = SuppressionEngine()
        rid = engine.add_rule(_exact_title_rule("noise"))
        engine.remove_rule(rid)
        verdict = engine.evaluate(_make_candidate(title="noise"))
        assert not verdict.suppressed

    def test_disable_rule(self):
        engine = SuppressionEngine()
        rid = engine.add_rule(_exact_title_rule("noise"))
        engine.disable_rule(rid)
        verdict = engine.evaluate(_make_candidate(title="noise"))
        assert not verdict.suppressed

    def test_filter_alerts_partitions(self):
        engine = SuppressionEngine()
        engine.add_rule(_exact_title_rule("heartbeat"))
        alerts = [
            _make_candidate(title="heartbeat"),
            _make_candidate(title="real alert"),
            _make_candidate(title="heartbeat"),
            _make_candidate(title="another real alert"),
        ]
        allowed, suppressed = engine.filter_alerts(alerts)
        assert len(allowed) == 2
        assert len(suppressed) == 2

    def test_threshold_not_triggered_below_count(self):
        engine = SuppressionEngine()
        engine.add_rule(
            SuppressionRule(
                name="rate-limit",
                conditions=[
                    SuppressionCondition(
                        scope=SuppressionScope.SOURCE,
                        match_type=MatchType.EXACT,
                        value="noisy-sensor",
                    )
                ],
                threshold=ThresholdConfig(count=3, window_seconds=60),
            )
        )
        # First two hits: conditions match but threshold not yet exceeded
        v1 = engine.evaluate(_make_candidate(source="noisy-sensor"))
        v2 = engine.evaluate(_make_candidate(source="noisy-sensor"))
        assert not v1.suppressed
        assert not v2.suppressed

    def test_threshold_triggers_at_count(self):
        engine = SuppressionEngine()
        engine.add_rule(
            SuppressionRule(
                name="rate-limit",
                conditions=[
                    SuppressionCondition(
                        scope=SuppressionScope.SOURCE,
                        match_type=MatchType.EXACT,
                        value="noisy-sensor",
                    )
                ],
                threshold=ThresholdConfig(count=3, window_seconds=60),
            )
        )
        # Third hit triggers suppression
        for _ in range(2):
            engine.evaluate(_make_candidate(source="noisy-sensor"))
        v3 = engine.evaluate(_make_candidate(source="noisy-sensor"))
        assert v3.suppressed

    def test_threshold_group_by_isolates_sources(self):
        engine = SuppressionEngine()
        engine.add_rule(
            SuppressionRule(
                name="per-host-limit",
                conditions=[
                    SuppressionCondition(
                        scope=SuppressionScope.TITLE,
                        match_type=MatchType.CONTAINS,
                        value="login",
                    )
                ],
                threshold=ThresholdConfig(
                    count=2,
                    window_seconds=60,
                    group_by="src_ip",
                ),
            )
        )
        host_a = _make_candidate(title="failed login", raw_data={"src_ip": "1.2.3.4"})
        host_b = _make_candidate(title="failed login", raw_data={"src_ip": "9.9.9.9"})

        # host_a hits threshold
        engine.evaluate(host_a)
        va2 = engine.evaluate(host_a)
        # host_b not yet at threshold
        vb1 = engine.evaluate(host_b)

        assert va2.suppressed
        assert not vb1.suppressed

    def test_stats_counters(self):
        engine = SuppressionEngine()
        engine.add_rule(_exact_title_rule("noise"))
        engine.evaluate(_make_candidate(title="noise"))
        engine.evaluate(_make_candidate(title="noise"))
        engine.evaluate(_make_candidate(title="real"))
        stats = engine.stats()
        assert stats["total_rules"] == 1
        assert stats["total_condition_matches"] == 2
        assert stats["total_suppressed"] == 2
