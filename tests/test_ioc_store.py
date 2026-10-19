"""Tests for IOCStore."""

import time
from datetime import datetime, timezone

import pytest

from overwatch.ioc_store import IOCStore
from overwatch.models import IOC, IOCType, Severity, TLPLevel


def make_ioc(
    value: str = "1.2.3.4",
    ioc_type: IOCType = IOCType.IPV4,
    source: str = "test",
    confidence: int = 80,
    severity: Severity = Severity.MEDIUM,
    tags=None,
    ttl: int = 3600,
) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        source=source,
        confidence=confidence,
        severity=severity,
        tags=set(tags or []),
        ttl_seconds=ttl,
    )


class TestIOCStoreBasics:
    def test_add_and_get(self):
        store = IOCStore()
        ioc = make_ioc("10.0.0.1")
        assert store.add(ioc) is True
        retrieved = store.get(ioc.fingerprint)
        assert retrieved is not None
        assert retrieved.value == "10.0.0.1"

    def test_add_duplicate_returns_false(self):
        store = IOCStore()
        ioc1 = make_ioc("10.0.0.1", confidence=50)
        ioc2 = make_ioc("10.0.0.1", confidence=90)
        assert store.add(ioc1) is True
        assert store.add(ioc2) is False
        # Confidence should be upgraded to the higher value
        retrieved = store.get(ioc1.fingerprint)
        assert retrieved.confidence == 90

    def test_lookup_by_type_value(self):
        store = IOCStore()
        ioc = make_ioc("evil.example.com", IOCType.DOMAIN)
        store.add(ioc)
        found = store.lookup(IOCType.DOMAIN, "evil.example.com")
        assert found is not None
        assert found.value == "evil.example.com"

    def test_get_by_id(self):
        store = IOCStore()
        ioc = make_ioc("5.5.5.5")
        store.add(ioc)
        found = store.get_by_id(ioc.id)
        assert found is not None
        assert found.fingerprint == ioc.fingerprint

    def test_remove(self):
        store = IOCStore()
        ioc = make_ioc("9.9.9.9")
        store.add(ioc)
        assert store.remove(ioc.fingerprint) is True
        assert store.get(ioc.fingerprint) is None
        assert store.size() == 0

    def test_size(self):
        store = IOCStore()
        for i in range(5):
            store.add(make_ioc(f"10.0.0.{i}"))
        assert store.size() == 5


class TestIOCStoreQuery:
    def setup_method(self):
        self.store = IOCStore()
        self.store.add(make_ioc("1.1.1.1", IOCType.IPV4, severity=Severity.HIGH, tags=["apt"]))
        self.store.add(make_ioc("2.2.2.2", IOCType.IPV4, severity=Severity.LOW, tags=["spam"]))
        self.store.add(make_ioc("evil.com", IOCType.DOMAIN, tags=["apt"]))
        self.store.add(make_ioc("bad.com", IOCType.DOMAIN, tags=["ransomware"]))

    def test_query_by_type(self):
        ips = self.store.query_by_type(IOCType.IPV4)
        assert len(ips) == 2

    def test_query_by_type_min_confidence(self):
        results = self.store.query_by_type(IOCType.IPV4, min_confidence=90)
        assert len(results) == 0

    def test_query_by_tag(self):
        apt = self.store.query_by_tag("apt")
        assert len(apt) == 2

    def test_query_by_severity(self):
        high = self.store.query_by_severity(Severity.HIGH)
        assert len(high) == 1
        assert high[0].value == "1.1.1.1"

    def test_query_by_source(self):
        results = self.store.query_by_source("test")
        assert len(results) == 4


class TestIOCStoreExpiry:
    def test_expired_ioc_not_returned(self):
        store = IOCStore()
        ioc = make_ioc("192.168.1.1", ttl=0)
        store.add(ioc)
        # TTL=0 means immediately expired
        assert store.get(ioc.fingerprint) is None

    def test_gc_removes_expired(self):
        store = IOCStore()
        store.add(make_ioc("192.168.1.1", ttl=0))
        store.add(make_ioc("192.168.1.2", ttl=3600))
        removed = store.gc()
        assert removed == 1
        assert store.size() == 1


class TestIOCStoreMerge:
    def test_merge_upgrades_severity(self):
        store = IOCStore()
        low = make_ioc("3.3.3.3", severity=Severity.LOW)
        store.add(low)
        high = make_ioc("3.3.3.3", severity=Severity.HIGH)
        store.add(high)
        merged = store.get(low.fingerprint)
        assert merged.severity == Severity.HIGH

    def test_merge_combines_tags(self):
        store = IOCStore()
        ioc_a = make_ioc("4.4.4.4", tags=["botnet"])
        store.add(ioc_a)
        ioc_b = make_ioc("4.4.4.4", tags=["c2"])
        store.add(ioc_b)
        merged = store.get(ioc_a.fingerprint)
        assert "botnet" in merged.tags
        assert "c2" in merged.tags


class TestIOCStoreEviction:
    def test_evicts_lowest_risk_when_full(self):
        store = IOCStore(max_size=3)
        low = make_ioc("1.0.0.1", severity=Severity.INFO, confidence=10)
        med = make_ioc("1.0.0.2", severity=Severity.MEDIUM, confidence=50)
        high = make_ioc("1.0.0.3", severity=Severity.HIGH, confidence=90)
        store.add(low)
        store.add(med)
        store.add(high)
        # Adding one more should evict the lowest-risk entry
        new = make_ioc("1.0.0.4", severity=Severity.CRITICAL, confidence=100)
        store.add(new)
        assert store.size() == 3
        assert store.get(low.fingerprint) is None


class TestIOCStoreConfidenceDecay:
    def test_decay_lowers_stale_confidence(self):
        store = IOCStore()
        ioc = make_ioc("5.5.5.1", confidence=100)
        # Backdate last_seen by 3 days
        from datetime import timedelta
        ioc.last_seen = datetime.now(timezone.utc) - timedelta(days=3)
        store.add(ioc)
        updated = store.apply_confidence_decay(decay_factor=0.5)
        assert updated == 1
        retrieved = store.get(ioc.fingerprint)
        assert retrieved.confidence < 100
