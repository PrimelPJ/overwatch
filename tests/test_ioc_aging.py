"""Tests for the IOC aging and confidence decay engine."""

import math
from datetime import datetime, timedelta, timezone

import pytest

from overwatch.ioc_aging import (
    AgingPolicy,
    DecayFunction,
    IOCAgingEngine,
    DEFAULT_POLICIES,
)
from overwatch.models import IOC, IOCType, Severity


def make_ioc(
    ioc_type: IOCType = IOCType.IPV4,
    value: str = "192.0.2.1",
    confidence: int = 80,
    severity: Severity = Severity.HIGH,
    days_old: float = 0.0,
    hit_count: int = 0,
    fp_count: int = 0,
    ttl_seconds: int = 86400 * 7,
) -> IOC:
    created = datetime.now(timezone.utc) - timedelta(days=days_old)
    ioc = IOC(
        ioc_type=ioc_type,
        value=value,
        source="test_feed",
        severity=severity,
        confidence=confidence,
        ttl_seconds=ttl_seconds,
    )
    ioc.created_at = created
    ioc.updated_at = created
    ioc.first_seen = created
    ioc.hit_count = hit_count
    ioc.false_positive_count = fp_count
    return ioc


class TestConfidenceDecay:
    def test_fresh_ioc_near_original_confidence(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(ioc_type=IOCType.IPV4, days_old=0.0, confidence=80)
        conf = engine.compute_current_confidence(ioc)
        assert abs(conf - 80) < 5.0  # within 5 points of original

    def test_ip_decays_faster_than_hash(self):
        engine = IOCAgingEngine()
        ip_ioc = make_ioc(ioc_type=IOCType.IPV4, days_old=7.0, confidence=80)
        hash_ioc = make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="abc123" * 10, days_old=7.0, confidence=80)
        ip_conf = engine.compute_current_confidence(ip_ioc)
        hash_conf = engine.compute_current_confidence(hash_ioc)
        assert ip_conf < hash_conf, "IP confidence should decay faster than hash"

    def test_high_severity_decays_slower(self):
        engine = IOCAgingEngine()
        high = make_ioc(severity=Severity.CRITICAL, days_old=5.0, confidence=80)
        low = make_ioc(severity=Severity.LOW, days_old=5.0, confidence=80)
        high_conf = engine.compute_current_confidence(high)
        low_conf = engine.compute_current_confidence(low)
        assert high_conf >= low_conf

    def test_hit_boosts_confidence(self):
        engine = IOCAgingEngine()
        # IOC observed 2 days ago but hit just now
        ioc = make_ioc(days_old=2.0, hit_count=5, confidence=70)
        ioc.last_seen = datetime.now(timezone.utc)
        aged = engine.compute_current_confidence(ioc)
        plain = engine.compute_current_confidence(make_ioc(days_old=2.0, confidence=70))
        assert aged > plain, "Hits should boost confidence"

    def test_false_positives_lower_confidence(self):
        engine = IOCAgingEngine()
        ioc_clean = make_ioc(confidence=80, hit_count=10, fp_count=0)
        ioc_fp = make_ioc(confidence=80, hit_count=10, fp_count=5)
        clean_conf = engine.compute_current_confidence(ioc_clean)
        fp_conf = engine.compute_current_confidence(ioc_fp)
        assert fp_conf < clean_conf

    def test_confidence_never_exceeds_original(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(confidence=60, hit_count=100)
        ioc.last_seen = datetime.now(timezone.utc)
        conf = engine.compute_current_confidence(ioc)
        assert conf <= 60.0

    def test_confidence_never_negative(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(days_old=365.0, confidence=50)
        conf = engine.compute_current_confidence(ioc)
        assert conf >= 0.0

    def test_source_reliability_multiplier(self):
        engine = IOCAgingEngine()
        engine.set_source_reliability("test_feed", 0.5)
        ioc = make_ioc(confidence=80)
        conf = engine.compute_current_confidence(ioc)
        # Confidence should be at most 50% of original (reliability=0.5)
        assert conf <= 80.0 * 0.5 + 0.1


class TestAgingResult:
    def test_age_ioc_returns_result(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(days_old=3.0, confidence=80)
        result = engine.age_ioc(ioc)
        assert result.ioc_fingerprint == ioc.fingerprint
        assert result.original_confidence == 80
        assert 0.0 <= result.new_confidence <= 80.0
        assert result.days_old == pytest.approx(3.0, abs=0.1)

    def test_expired_ioc_should_archive(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(ttl_seconds=86400, days_old=2.0)  # TTL=1 day, aged 2 days
        result = engine.age_ioc(ioc)
        assert result.should_archive is True

    def test_fresh_ioc_should_not_archive(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(ttl_seconds=86400 * 30, days_old=0.1, confidence=90)
        result = engine.age_ioc(ioc)
        assert result.should_archive is False

    def test_low_confidence_should_archive(self):
        engine = IOCAgingEngine()
        # Manually set very low confidence
        ioc = make_ioc(days_old=60.0, confidence=5)
        result = engine.age_ioc(ioc)
        assert result.should_archive is True


class TestAgingCollection:
    def test_age_collection_returns_all_results(self):
        engine = IOCAgingEngine()
        iocs = [make_ioc(value=f"192.0.2.{i}", days_old=float(i)) for i in range(5)]
        results, active = engine.age_collection(iocs)
        assert len(results) == 5

    def test_prune_removes_archived_iocs(self):
        engine = IOCAgingEngine()
        fresh = make_ioc(value="192.0.2.1", ttl_seconds=86400 * 30, days_old=0.0)
        expired = make_ioc(value="192.0.2.2", ttl_seconds=3600, days_old=2.0)
        _, active = engine.age_collection([fresh, expired], prune=True)
        active_values = [i.value for i in active]
        assert "192.0.2.1" in active_values
        assert "192.0.2.2" not in active_values

    def test_bulk_prune_returns_pruned_fingerprints(self):
        engine = IOCAgingEngine()
        expired = make_ioc(value="10.0.0.1", ttl_seconds=1, days_old=1.0)
        fresh = make_ioc(value="192.0.2.50", ttl_seconds=86400 * 30, days_old=0.0)
        active, pruned = engine.bulk_prune([expired, fresh])
        assert expired.fingerprint in pruned
        assert fresh.fingerprint not in pruned


class TestTTLExtension:
    def test_hit_extends_ttl(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(ttl_seconds=86400)
        original_ttl = ioc.ttl_seconds
        new_ttl = engine.apply_hit_extension(ioc)
        assert new_ttl > original_ttl

    def test_ttl_capped_at_max(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(ioc_type=IOCType.IPV4)
        policy = DEFAULT_POLICIES[IOCType.IPV4]
        ioc.ttl_seconds = policy.max_ttl - 1
        new_ttl = engine.apply_hit_extension(ioc)
        assert new_ttl <= policy.max_ttl


class TestForecast:
    def test_forecast_returns_list(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(confidence=80)
        forecast = engine.get_confidence_forecast(ioc, days_ahead=7, interval_days=1)
        assert len(forecast) == 8  # days 0..7

    def test_forecast_monotonically_decreasing_for_fresh_ioc(self):
        engine = IOCAgingEngine()
        ioc = make_ioc(confidence=80)
        forecast = engine.get_confidence_forecast(ioc, days_ahead=30, interval_days=5)
        confidences = [c for _, c in forecast]
        for i in range(len(confidences) - 1):
            assert confidences[i] >= confidences[i + 1] - 0.01  # allow tiny float error


class TestCustomPolicy:
    def test_set_custom_policy(self):
        engine = IOCAgingEngine()
        policy = AgingPolicy(
            ioc_type=IOCType.DOMAIN,
            base_ttl=86400 * 100,
            daily_decay_rate=0.1,
            archival_threshold=5,
            decay_function=DecayFunction.LINEAR,
        )
        engine.set_policy(IOCType.DOMAIN, policy)
        ioc = make_ioc(ioc_type=IOCType.DOMAIN, value="evil.com", days_old=10.0, confidence=80)
        conf = engine.compute_current_confidence(ioc)
        # Linear decay: 80 - 0.1*10 = 79
        assert abs(conf - (80 - 0.1 * 10 * (1.0 / policy.severity_multipliers["high"]))) < 5
