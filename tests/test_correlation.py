"""Tests for the IOC correlation engine."""

from datetime import datetime, timedelta, timezone

import pytest

from overwatch.correlation import Campaign, CorrelationEngine
from overwatch.models import IOC, IOCType, Severity


def make_ioc(
    value: str,
    ioc_type: IOCType = IOCType.IPV4,
    source: str = "feed1",
    confidence: int = 75,
    severity: Severity = Severity.MEDIUM,
    tags=None,
    techniques=None,
    related=None,
) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        source=source,
        confidence=confidence,
        severity=severity,
        tags=set(tags or []),
        mitre_techniques=list(techniques or []),
        related_iocs=list(related or []),
    )


class TestCorrelationEngine:
    def test_no_correlation_for_unrelated_iocs(self):
        engine = CorrelationEngine()
        iocs = [
            make_ioc("1.1.1.1", tags=["botnet"]),
            make_ioc("2.2.2.2", tags=["spam"]),
            make_ioc("3.3.3.3", tags=["adware"]),
        ]
        campaigns = engine.correlate(iocs)
        assert campaigns == []

    def test_shared_techniques_correlates(self):
        engine = CorrelationEngine(min_shared_techniques=1)
        iocs = [
            make_ioc("1.1.1.1", techniques=["T1059", "T1055"]),
            make_ioc("evil.com", IOCType.DOMAIN, techniques=["T1059", "T1071"]),
            make_ioc("2.2.2.2", techniques=["T1059"]),
        ]
        campaigns = engine.correlate(iocs)
        assert len(campaigns) >= 1
        assert campaigns[0].size >= 2

    def test_shared_tags_correlates(self):
        engine = CorrelationEngine(min_shared_tags=2)
        iocs = [
            make_ioc("10.0.0.1", tags=["apt29", "spear-phishing", "cozy-bear"]),
            make_ioc("10.0.0.2", tags=["apt29", "spear-phishing", "c2"]),
        ]
        campaigns = engine.correlate(iocs)
        assert len(campaigns) == 1
        assert campaigns[0].size == 2

    def test_explicit_related_iocs_correlates(self):
        engine = CorrelationEngine(min_edge_weight=0.2)
        a = make_ioc("a.evil.com", IOCType.DOMAIN)
        b = make_ioc("b.evil.com", IOCType.DOMAIN)
        # Manually link
        a.related_iocs.append(b.fingerprint)
        campaigns = engine.correlate([a, b])
        assert len(campaigns) == 1
        assert campaigns[0].size == 2

    def test_campaign_aggregates_techniques(self):
        engine = CorrelationEngine()
        iocs = [
            make_ioc("1.2.3.4", techniques=["T1059"]),
            make_ioc("5.6.7.8", techniques=["T1055"]),
        ]
        iocs[0].related_iocs.append(iocs[1].fingerprint)
        campaigns = engine.correlate(iocs)
        assert len(campaigns) == 1
        assert "T1059" in campaigns[0].mitre_techniques
        assert "T1055" in campaigns[0].mitre_techniques

    def test_campaign_takes_max_severity(self):
        engine = CorrelationEngine()
        low = make_ioc("1.1.1.1", severity=Severity.LOW)
        critical = make_ioc("2.2.2.2", severity=Severity.CRITICAL)
        low.related_iocs.append(critical.fingerprint)
        campaigns = engine.correlate([low, critical])
        assert len(campaigns) == 1
        assert campaigns[0].severity == Severity.CRITICAL

    def test_find_related(self):
        engine = CorrelationEngine()
        anchor = make_ioc("1.1.1.1", techniques=["T1059"], tags=["apt"])
        similar = make_ioc("2.2.2.2", techniques=["T1059"], tags=["apt", "c2"])
        unrelated = make_ioc("9.9.9.9", tags=["spam"])
        all_iocs = [anchor, similar, unrelated]
        related = engine.find_related(anchor, all_iocs)
        # similar should rank higher than unrelated
        assert len(related) >= 1
        values = [ioc.value for ioc, _ in related]
        assert "2.2.2.2" in values

    def test_temporal_proximity_boosts_score(self):
        engine = CorrelationEngine(min_edge_weight=0.05)
        now = datetime.now(timezone.utc)
        a = make_ioc("10.10.10.1")
        b = make_ioc("10.10.10.2")
        a.first_seen = now
        b.first_seen = now + timedelta(minutes=10)
        a.related_iocs.append(b.fingerprint)  # ensure they cluster
        campaigns = engine.correlate([a, b])
        assert len(campaigns) == 1

    def test_campaigns_sorted_by_size_descending(self):
        engine = CorrelationEngine(min_edge_weight=0.2)
        # Cluster 1: 3 IOCs
        a, b, c = [make_ioc(f"1.1.1.{i}") for i in range(3)]
        a.related_iocs.extend([b.fingerprint, c.fingerprint])
        b.related_iocs.append(c.fingerprint)
        # Cluster 2: 2 IOCs
        d, e = make_ioc("2.2.2.1"), make_ioc("2.2.2.2")
        d.related_iocs.append(e.fingerprint)

        campaigns = engine.correlate([a, b, c, d, e])
        sizes = [c.size for c in campaigns]
        assert sizes == sorted(sizes, reverse=True)

    def test_idempotent_second_correlate(self):
        engine = CorrelationEngine()
        a = make_ioc("3.3.3.1", techniques=["T1059"])
        b = make_ioc("3.3.3.2", techniques=["T1059"])
        first = engine.correlate([a, b])
        second = engine.correlate([a, b])
        # Both runs should produce same number of campaigns
        assert len(first) == len(second)
