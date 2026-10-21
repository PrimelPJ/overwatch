"""
Tests for the threat hunting module.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from overwatch.models import IOC, IOCType, Severity, TLPLevel
from overwatch.threat_hunt import (
    HuntHypothesis,
    HuntQuery,
    HuntSession,
    HuntStatus,
    HypothesisOutcome,
    IOCCluster,
    TemporalPattern,
    ThreatHunter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ioc(
    value: str = "1.2.3.4",
    ioc_type: IOCType = IOCType.IPV4,
    severity: Severity = Severity.HIGH,
    confidence: int = 80,
    tags: set | None = None,
    mitre_techniques: list | None = None,
    source: str = "test-feed",
    first_seen: datetime | None = None,
) -> IOC:
    ioc = IOC(
        ioc_type=ioc_type,
        value=value,
        source=source,
        severity=severity,
        confidence=confidence,
        tags=tags or set(),
        mitre_techniques=mitre_techniques or [],
    )
    if first_seen:
        ioc.first_seen = first_seen  # type: ignore[attr-defined]
    return ioc


# ---------------------------------------------------------------------------
# HuntQuery.matches
# ---------------------------------------------------------------------------

class TestHuntQuery:
    def test_type_filter(self):
        ioc = _make_ioc(ioc_type=IOCType.IPV4)
        q_match = HuntQuery(ioc_types=[IOCType.IPV4])
        q_miss = HuntQuery(ioc_types=[IOCType.DOMAIN])
        assert q_match.matches(ioc)
        assert not q_miss.matches(ioc)

    def test_severity_filter(self):
        ioc = _make_ioc(severity=Severity.HIGH)
        assert HuntQuery(severities=[Severity.HIGH, Severity.CRITICAL]).matches(ioc)
        assert not HuntQuery(severities=[Severity.LOW]).matches(ioc)

    def test_tags_or_filter(self):
        ioc = _make_ioc(tags={"apt29", "phishing"})
        assert HuntQuery(tags={"apt29"}).matches(ioc)
        assert HuntQuery(tags={"phishing", "cobalt"}).matches(ioc)  # any match
        assert not HuntQuery(tags={"emotet"}).matches(ioc)

    def test_tags_all_filter(self):
        ioc = _make_ioc(tags={"apt29", "phishing"})
        assert HuntQuery(tags_all={"apt29", "phishing"}).matches(ioc)
        assert not HuntQuery(tags_all={"apt29", "cobalt"}).matches(ioc)

    def test_confidence_range(self):
        ioc = _make_ioc(confidence=70)
        assert HuntQuery(confidence_min=50, confidence_max=90).matches(ioc)
        assert not HuntQuery(confidence_min=80).matches(ioc)

    def test_value_contains(self):
        ioc = _make_ioc(value="evil.example.com", ioc_type=IOCType.DOMAIN)
        assert HuntQuery(value_contains="evil").matches(ioc)
        assert HuntQuery(value_contains="EVIL").matches(ioc)  # case-insensitive
        assert not HuntQuery(value_contains="benign").matches(ioc)

    def test_mitre_techniques_filter(self):
        ioc = _make_ioc(mitre_techniques=["T1071", "T1566"])
        assert HuntQuery(mitre_techniques=["T1071"]).matches(ioc)
        assert not HuntQuery(mitre_techniques=["T1003"]).matches(ioc)


# ---------------------------------------------------------------------------
# ThreatHunter.execute_hunt
# ---------------------------------------------------------------------------

class TestThreatHunterExecuteHunt:
    def setup_method(self):
        self.iocs = [
            _make_ioc("1.1.1.1", IOCType.IPV4, Severity.HIGH, 90, {"apt29"}, ["T1071"]),
            _make_ioc("2.2.2.2", IOCType.IPV4, Severity.MEDIUM, 60, {"phishing"}, ["T1566"]),
            _make_ioc("evil.com", IOCType.DOMAIN, Severity.CRITICAL, 95, {"apt29", "c2"}, ["T1071"]),
            _make_ioc("benign.com", IOCType.DOMAIN, Severity.LOW, 20, set(), []),
            _make_ioc("ab" * 32, IOCType.FILE_HASH_MD5, Severity.HIGH, 85, {"ransomware"}, ["T1486"]),
        ]
        self.hunter = ThreatHunter(self.iocs)

    def test_no_filter_returns_all(self):
        results = self.hunter.execute_hunt(HuntQuery())
        assert len(results) == 5

    def test_type_filter(self):
        results = self.hunter.execute_hunt(HuntQuery(ioc_types=[IOCType.IPV4]))
        assert len(results) == 2
        assert all(r.ioc_type == IOCType.IPV4 for r in results)

    def test_severity_filter(self):
        results = self.hunter.execute_hunt(
            HuntQuery(severities=[Severity.CRITICAL, Severity.HIGH])
        )
        assert len(results) == 3

    def test_tag_filter(self):
        results = self.hunter.execute_hunt(HuntQuery(tags={"apt29"}))
        assert len(results) == 2

    def test_confidence_filter(self):
        results = self.hunter.execute_hunt(HuntQuery(confidence_min=80))
        assert len(results) == 3

    def test_limit_respected(self):
        results = self.hunter.execute_hunt(HuntQuery(limit=2))
        assert len(results) == 2

    def test_value_search(self):
        results = self.hunter.search_by_value_pattern("evil")
        assert len(results) == 1
        assert results[0].value == "evil.com"


# ---------------------------------------------------------------------------
# ThreatHunter.find_related
# ---------------------------------------------------------------------------

class TestFindRelated:
    def test_finds_by_shared_tags(self):
        ioc_a = _make_ioc("1.1.1.1", tags={"apt29", "c2"})
        ioc_b = _make_ioc("evil.com", IOCType.DOMAIN, tags={"apt29"})
        ioc_c = _make_ioc("benign.com", IOCType.DOMAIN, tags={"phishing"})
        hunter = ThreatHunter([ioc_a, ioc_b, ioc_c])
        related = hunter.find_related(ioc_a)
        assert ioc_b in related
        assert ioc_c not in related

    def test_finds_by_shared_technique(self):
        ioc_a = _make_ioc("1.1.1.1", mitre_techniques=["T1071"])
        ioc_b = _make_ioc("2.2.2.2", mitre_techniques=["T1071", "T1566"])
        ioc_c = _make_ioc("3.3.3.3", mitre_techniques=["T1003"])
        hunter = ThreatHunter([ioc_a, ioc_b, ioc_c])
        related = hunter.find_related(ioc_a)
        assert ioc_b in related
        assert ioc_c not in related


# ---------------------------------------------------------------------------
# ThreatHunter.cluster_by_campaign
# ---------------------------------------------------------------------------

class TestClusterByCampaign:
    def test_groups_by_shared_tag(self):
        ioc_a = _make_ioc("1.1.1.1", tags={"apt29"})
        ioc_b = _make_ioc("2.2.2.2", tags={"apt29"})
        ioc_c = _make_ioc("3.3.3.3", tags={"emotet"})
        ioc_d = _make_ioc("4.4.4.4", tags={"emotet"})
        hunter = ThreatHunter([ioc_a, ioc_b, ioc_c, ioc_d])
        clusters = hunter.cluster_by_campaign([ioc_a, ioc_b, ioc_c, ioc_d])
        assert len(clusters) == 2
        sizes = sorted([c.size for c in clusters])
        assert sizes == [2, 2]

    def test_single_ioc_not_clustered(self):
        ioc_a = _make_ioc("1.1.1.1", tags={"unique-tag"})
        ioc_b = _make_ioc("2.2.2.2", tags={"other-tag"})
        hunter = ThreatHunter([ioc_a, ioc_b])
        clusters = hunter.cluster_by_campaign([ioc_a, ioc_b])
        assert clusters == []

    def test_cohesion_perfect_when_same_tags(self):
        ioc_a = _make_ioc("1.1.1.1", tags={"apt29", "c2"})
        ioc_b = _make_ioc("2.2.2.2", tags={"apt29", "c2"})
        hunter = ThreatHunter([ioc_a, ioc_b])
        clusters = hunter.cluster_by_campaign([ioc_a, ioc_b])
        assert len(clusters) == 1
        assert clusters[0].cohesion_score == 1.0


# ---------------------------------------------------------------------------
# ThreatHunter.analyze_temporal_patterns
# ---------------------------------------------------------------------------

class TestTemporalPatternAnalysis:
    def _iocs_with_timestamps(self, timestamps: list) -> list:
        iocs = []
        for ts in timestamps:
            ioc = _make_ioc()
            ioc.first_seen = ts  # type: ignore[attr-defined]
            iocs.append(ioc)
        return iocs

    def test_empty_iocs_returns_unknown(self):
        hunter = ThreatHunter([])
        pattern = hunter.analyze_temporal_patterns([])
        assert pattern.pattern_type == "unknown"

    def test_steady_pattern_detection(self):
        now = datetime.now(timezone.utc)
        # One IOC per day for 10 days — very steady
        timestamps = [now - timedelta(days=i) for i in range(10)]
        iocs = self._iocs_with_timestamps(timestamps)
        hunter = ThreatHunter(iocs)
        pattern = hunter.analyze_temporal_patterns(iocs)
        # Should be steady or sporadic given perfect distribution
        assert pattern.pattern_type in ("steady", "sporadic", "burst", "escalating")
        assert pattern.peak_count >= 1

    def test_start_end_time_correct(self):
        now = datetime.now(timezone.utc)
        older = now - timedelta(days=5)
        ioc_old = _make_ioc()
        ioc_new = _make_ioc()
        ioc_old.first_seen = older  # type: ignore[attr-defined]
        ioc_new.first_seen = now   # type: ignore[attr-defined]
        hunter = ThreatHunter([ioc_old, ioc_new])
        pattern = hunter.analyze_temporal_patterns([ioc_old, ioc_new])
        assert pattern.start_time == older
        assert pattern.end_time == now


# ---------------------------------------------------------------------------
# HuntSession lifecycle
# ---------------------------------------------------------------------------

class TestHuntSession:
    def test_create_and_finalize(self):
        hunter = ThreatHunter([])
        session = hunter.create_session("APT29 Hunt", analyst="alice")
        assert session.status == HuntStatus.OPEN
        assert session.name == "APT29 Hunt"
        summary = session.finalize(notes="Nothing found.")
        assert session.status == HuntStatus.COMPLETED
        assert summary["findings_count"] == 0

    def test_run_hypothesis_records_findings(self):
        ioc_a = _make_ioc("1.1.1.1", tags={"apt29"})
        ioc_b = _make_ioc("2.2.2.2", tags={"emotet"})
        hunter = ThreatHunter([ioc_a, ioc_b])
        session = hunter.create_session("Test Hunt")
        hypothesis = HuntHypothesis(
            title="Look for APT29 IPs",
            hunt_query=HuntQuery(tags={"apt29"}),
        )
        findings = hunter.run_hypothesis(session, hypothesis)
        assert len(findings) == 1
        assert findings[0].value == "1.1.1.1"
        assert len(session.findings) == 1
        assert session.status == HuntStatus.IN_PROGRESS

    def test_hypothesis_resolution(self):
        h = HuntHypothesis(title="Test")
        h.resolve(HypothesisOutcome.CONFIRMED, "Evidence found in log files")
        assert h.outcome == HypothesisOutcome.CONFIRMED
        assert h.resolved_at is not None

    def test_duplicate_findings_not_recorded(self):
        ioc = _make_ioc("1.1.1.1", tags={"apt29"})
        hunter = ThreatHunter([ioc])
        session = hunter.create_session("Dupe Test")
        session.record_finding(ioc)
        session.record_finding(ioc)  # duplicate
        assert len(session.findings) == 1
