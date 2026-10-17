"""
Tests for core IOC and alert models.
"""

import time
from datetime import datetime, timezone

import pytest

from overwatch.models import (
    IOC,
    AlertTriage,
    IOCType,
    PlaybookAction,
    Severity,
    TLPLevel,
)


def make_ioc(**kwargs):
    defaults = dict(
        ioc_type=IOCType.IPV4,
        value="1.2.3.4",
        source="test",
        severity=Severity.HIGH,
        confidence=80,
    )
    defaults.update(kwargs)
    return IOC(**defaults)


class TestIOC:
    def test_fingerprint_is_deterministic(self):
        ioc1 = make_ioc(value="1.2.3.4")
        ioc2 = make_ioc(value="1.2.3.4")
        assert ioc1.fingerprint == ioc2.fingerprint

    def test_fingerprint_case_insensitive(self):
        ioc1 = make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="ABCDEF123456" * 5 + "ABCD")
        ioc2 = make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="abcdef123456" * 5 + "abcd")
        assert ioc1.fingerprint == ioc2.fingerprint

    def test_fingerprint_differs_by_type(self):
        ioc1 = make_ioc(ioc_type=IOCType.IPV4, value="1.2.3.4")
        ioc2 = make_ioc(ioc_type=IOCType.DOMAIN, value="1.2.3.4")
        assert ioc1.fingerprint != ioc2.fingerprint

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            make_ioc(confidence=101)
        with pytest.raises(ValueError):
            make_ioc(confidence=-1)

    def test_adjusted_confidence_no_history(self):
        ioc = make_ioc(confidence=70)
        assert ioc.adjusted_confidence == 70

    def test_adjusted_confidence_with_false_positives(self):
        ioc = make_ioc(confidence=100)
        ioc.hit_count = 5
        ioc.false_positive_count = 5
        assert ioc.adjusted_confidence == 50.0

    def test_risk_score_range(self):
        for sev in Severity:
            ioc = make_ioc(severity=sev, confidence=50)
            assert 0 <= ioc.risk_score <= 100

    def test_record_hit_increments_count(self):
        ioc = make_ioc()
        assert ioc.hit_count == 0
        ioc.record_hit()
        assert ioc.hit_count == 1
        assert ioc.last_seen is not None

    def test_record_false_positive(self):
        ioc = make_ioc()
        ioc.record_false_positive()
        assert ioc.false_positive_count == 1

    def test_extend_ttl(self):
        ioc = make_ioc(ttl_seconds=100)
        ioc.extend_ttl(200)
        assert ioc.ttl_seconds == 300

    def test_not_expired_by_default(self):
        ioc = make_ioc(ttl_seconds=3600)
        assert not ioc.is_expired

    def test_stix_serialization_ipv4(self):
        ioc = make_ioc(ioc_type=IOCType.IPV4, value="192.168.1.1")
        stix = ioc.to_stix()
        assert stix["type"] == "indicator"
        assert stix["spec_version"] == "2.1"
        assert "ipv4-addr:value = '192.168.1.1'" in stix["pattern"]

    def test_stix_serialization_sha256(self):
        sha = "a" * 64
        ioc = make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value=sha)
        stix = ioc.to_stix()
        assert "SHA-256" in stix["pattern"]
        assert sha in stix["pattern"]

    def test_stix_includes_tags(self):
        ioc = make_ioc(tags={"ransomware", "apt29"})
        stix = ioc.to_stix()
        assert "ransomware" in stix["labels"]
        assert "apt29" in stix["labels"]

    def test_stix_mitre_techniques(self):
        ioc = make_ioc(mitre_techniques=["T1059.001"])
        stix = ioc.to_stix()
        phases = stix["kill_chain_phases"]
        assert any(p["phase_name"] == "T1059.001" for p in phases)


class TestSeverity:
    def test_scores_are_ordered(self):
        assert Severity.CRITICAL.score > Severity.HIGH.score
        assert Severity.HIGH.score > Severity.MEDIUM.score
        assert Severity.MEDIUM.score > Severity.LOW.score
        assert Severity.LOW.score > Severity.INFO.score


class TestAlertTriage:
    def test_risk_score_no_iocs(self):
        alert = AlertTriage(
            alert_id="a1",
            title="Test",
            description="desc",
            severity=Severity.HIGH,
            source="siem",
        )
        assert alert.risk_score == Severity.HIGH.score * 20.0

    def test_risk_score_with_iocs(self):
        ioc = make_ioc(severity=Severity.CRITICAL, confidence=100)
        alert = AlertTriage(
            alert_id="a2",
            title="Test",
            description="desc",
            severity=Severity.HIGH,
            source="siem",
            matched_iocs=[ioc],
        )
        assert alert.risk_score > 0

    def test_resolve(self):
        alert = AlertTriage(
            alert_id="a3",
            title="Test",
            description="desc",
            severity=Severity.LOW,
            source="siem",
        )
        assert not alert.is_resolved
        alert.resolve(notes="Closed as expected")
        assert alert.is_resolved
        assert alert.resolved_at is not None
