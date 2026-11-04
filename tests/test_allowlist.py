"""Tests for the IOC allowlist and false-positive suppression engine."""

from __future__ import annotations

import json
from datetime import timedelta, timezone, datetime

import pytest

from overwatch.allowlist import (
    AllowlistEngine,
    AllowlistEntry,
    AllowlistReason,
    build_default_allowlist,
)
from overwatch.models import IOC, IOCType, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _ip_ioc(value: str) -> IOC:
    return IOC(ioc_type=IOCType.IPV4, value=value, source="test", severity=Severity.MEDIUM)


def _domain_ioc(value: str) -> IOC:
    return IOC(ioc_type=IOCType.DOMAIN, value=value, source="test", severity=Severity.MEDIUM)


def _hash_ioc(value: str) -> IOC:
    return IOC(ioc_type=IOCType.FILE_HASH_SHA256, value=value, source="test", severity=Severity.HIGH)


# ---------------------------------------------------------------------------
# Exact-match tests
# ---------------------------------------------------------------------------

class TestExactMatch:
    def test_ip_exact_match(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
            reason=AllowlistReason.KNOWN_GOOD,
        ))
        matched, entry = engine.is_allowlisted(_ip_ioc("1.2.3.4"))
        assert matched
        assert entry is not None

    def test_ip_no_match(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
        ))
        matched, _ = engine.is_allowlisted(_ip_ioc("1.2.3.5"))
        assert not matched

    def test_domain_case_insensitive(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.DOMAIN, pattern="Evil.example.com", match_type="exact",
        ))
        matched, _ = engine.is_allowlisted(_domain_ioc("evil.example.com"))
        assert matched

    def test_hash_case_sensitive(self):
        engine = AllowlistEngine()
        sha = "a" * 64
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.FILE_HASH_SHA256, pattern=sha, match_type="exact",
        ))
        matched_lower, _ = engine.is_allowlisted(_hash_ioc(sha))
        matched_upper, _ = engine.is_allowlisted(_hash_ioc(sha.upper()))
        assert matched_lower
        assert not matched_upper

    def test_type_filter_prevents_cross_match(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.DOMAIN, pattern="1.2.3.4", match_type="exact",
        ))
        # Same value but wrong type (IPV4 vs DOMAIN entry)
        matched, _ = engine.is_allowlisted(_ip_ioc("1.2.3.4"))
        assert not matched


# ---------------------------------------------------------------------------
# CIDR tests
# ---------------------------------------------------------------------------

class TestCIDRMatch:
    def test_ipv4_in_range(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="192.168.1.0/24", match_type="cidr",
        ))
        assert engine.is_allowlisted(_ip_ioc("192.168.1.100"))[0]
        assert not engine.is_allowlisted(_ip_ioc("192.168.2.1"))[0]

    def test_rfc1918_range(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="10.0.0.0/8", match_type="cidr",
        ))
        for ip in ["10.0.0.1", "10.255.255.254"]:
            assert engine.is_allowlisted(_ip_ioc(ip))[0]
        assert not engine.is_allowlisted(_ip_ioc("11.0.0.1"))[0]

    def test_invalid_cidr_raises(self):
        engine = AllowlistEngine()
        with pytest.raises(ValueError, match="Invalid CIDR"):
            engine.add_entry(AllowlistEntry(
                ioc_type=IOCType.IPV4, pattern="not_a_cidr", match_type="cidr",
            ))

    def test_non_ip_value_does_not_crash(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=None, pattern="10.0.0.0/8", match_type="cidr",
        ))
        # domain IOC shouldn't crash on CIDR check
        ioc = IOC(ioc_type=IOCType.DOMAIN, value="example.com", source="test", severity=Severity.LOW)
        matched, _ = engine.is_allowlisted(ioc)
        assert not matched


# ---------------------------------------------------------------------------
# Wildcard tests
# ---------------------------------------------------------------------------

class TestWildcardMatch:
    def test_subdomain_wildcard(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.DOMAIN, pattern="*.corp.internal", match_type="wildcard",
        ))
        assert engine.is_allowlisted(_domain_ioc("mail.corp.internal"))[0]
        assert engine.is_allowlisted(_domain_ioc("api.corp.internal"))[0]
        assert not engine.is_allowlisted(_domain_ioc("corp.internal"))[0]  # no subdomain

    def test_wildcard_case_insensitive(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.DOMAIN, pattern="*.Microsoft.COM", match_type="wildcard",
        ))
        assert engine.is_allowlisted(_domain_ioc("update.microsoft.com"))[0]

    def test_add_domain_patterns_helper(self):
        engine = AllowlistEngine()
        ids = engine.add_domain_patterns(["*.safe.example.com", "exact.example.com"])
        # Each pattern applied to DOMAIN + URL = 4 entries
        assert len(ids) == 4
        assert engine.is_allowlisted(_domain_ioc("sub.safe.example.com"))[0]
        assert engine.is_allowlisted(_domain_ioc("exact.example.com"))[0]


# ---------------------------------------------------------------------------
# Regex tests
# ---------------------------------------------------------------------------

class TestRegexMatch:
    def test_regex_match(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.DOMAIN, pattern=r"^internal-\d+\.corp\.com$", match_type="regex",
        ))
        assert engine.is_allowlisted(_domain_ioc("internal-42.corp.com"))[0]
        assert not engine.is_allowlisted(_domain_ioc("external.corp.com"))[0]

    def test_invalid_regex_raises(self):
        engine = AllowlistEngine()
        with pytest.raises(ValueError, match="Invalid regex"):
            engine.add_entry(AllowlistEntry(
                ioc_type=IOCType.DOMAIN, pattern="[invalid", match_type="regex",
            ))


# ---------------------------------------------------------------------------
# Expiry tests
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_entry_not_matched(self):
        engine = AllowlistEngine()
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
            expires_at=past,
        ))
        matched, _ = engine.is_allowlisted(_ip_ioc("1.2.3.4"))
        assert not matched

    def test_future_expiry_still_matches(self):
        engine = AllowlistEngine()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
            expires_at=future,
        ))
        matched, _ = engine.is_allowlisted(_ip_ioc("1.2.3.4"))
        assert matched


# ---------------------------------------------------------------------------
# filter_iocs tests
# ---------------------------------------------------------------------------

class TestFilterIocs:
    def test_partitions_correctly(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
        ))
        iocs = [_ip_ioc("1.2.3.4"), _ip_ioc("5.6.7.8"), _domain_ioc("evil.com")]
        clean, suppressed = engine.filter_iocs(iocs)
        assert len(clean) == 2
        assert len(suppressed) == 1
        assert suppressed[0][0].value == "1.2.3.4"


# ---------------------------------------------------------------------------
# False-positive reporting
# ---------------------------------------------------------------------------

class TestFalsePositive:
    def test_confidence_decremented(self):
        engine = AllowlistEngine()
        ioc = _ip_ioc("1.2.3.4")
        ioc.confidence = 70
        engine.report_false_positive(ioc, confidence_penalty=25)
        assert ioc.confidence == 45
        assert ioc.false_positive_count == 1

    def test_confidence_clamps_at_zero(self):
        engine = AllowlistEngine()
        ioc = _ip_ioc("1.2.3.4")
        ioc.confidence = 10
        engine.report_false_positive(ioc, confidence_penalty=50)
        assert ioc.confidence == 0

    def test_auto_add_creates_entry(self):
        engine = AllowlistEngine()
        ioc = _ip_ioc("9.9.9.9")
        entry_id = engine.report_false_positive(ioc, auto_add=True)
        assert entry_id is not None
        assert engine.is_allowlisted(ioc)[0]


# ---------------------------------------------------------------------------
# Hit count tracking
# ---------------------------------------------------------------------------

def test_hit_count_increments():
    engine = AllowlistEngine()
    eid = engine.add_entry(AllowlistEntry(
        ioc_type=IOCType.IPV4, pattern="5.5.5.5", match_type="exact",
    ))
    for _ in range(3):
        engine.is_allowlisted(_ip_ioc("5.5.5.5"))
    assert engine.get_entry(eid).hit_count == 3


# ---------------------------------------------------------------------------
# JSON import / export
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_roundtrip(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4, pattern="10.0.0.0/8", match_type="cidr",
            reason=AllowlistReason.INTERNAL_INFRA, comment="RFC-1918",
        ))
        json_str = engine.to_json()
        engine2 = AllowlistEngine()
        count = engine2.load_json(json_str)
        assert count == 1
        assert engine2.is_allowlisted(_ip_ioc("10.1.2.3"))[0]

    def test_replace_flag(self):
        engine = AllowlistEngine()
        engine.add_entry(AllowlistEntry(ioc_type=IOCType.IPV4, pattern="1.1.1.1", match_type="exact"))
        engine.add_entry(AllowlistEntry(ioc_type=IOCType.IPV4, pattern="2.2.2.2", match_type="exact"))
        json_str = json.dumps([{
            "entry_id": "aaa", "ioc_type": "ipv4-addr", "pattern": "3.3.3.3",
            "match_type": "exact", "reason": "known_good", "comment": "",
            "created_by": "", "created_at": "2024-01-01T00:00:00+00:00",
            "expires_at": None, "hit_count": 0,
        }])
        engine.load_json(json_str, replace=True)
        assert len(engine.list_entries()) == 1
        assert engine.list_entries()[0].pattern == "3.3.3.3"


# ---------------------------------------------------------------------------
# Default allowlist
# ---------------------------------------------------------------------------

def test_default_allowlist_rfc1918():
    engine = build_default_allowlist()
    assert engine.is_allowlisted(_ip_ioc("10.0.0.1"))[0]
    assert engine.is_allowlisted(_ip_ioc("192.168.100.50"))[0]
    assert engine.is_allowlisted(_ip_ioc("172.16.0.1"))[0]
    assert not engine.is_allowlisted(_ip_ioc("8.8.8.8"))[0]


def test_default_allowlist_domains():
    engine = build_default_allowlist()
    assert engine.is_allowlisted(_domain_ioc("update.microsoft.com"))[0]
    assert not engine.is_allowlisted(_domain_ioc("evil-microsoft.hax.ru"))[0]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_stats():
    engine = AllowlistEngine()
    engine.add_entry(AllowlistEntry(ioc_type=IOCType.IPV4, pattern="10.0.0.0/8", match_type="cidr"))
    engine.is_allowlisted(_ip_ioc("10.1.2.3"))
    s = engine.stats()
    assert s["total_entries"] == 1
    assert s["total_suppressed"] == 1
    assert s["by_match_type"]["cidr"] == 1


# ---------------------------------------------------------------------------
# Entry removal
# ---------------------------------------------------------------------------

def test_remove_entry():
    engine = AllowlistEngine()
    eid = engine.add_entry(AllowlistEntry(
        ioc_type=IOCType.IPV4, pattern="1.2.3.4", match_type="exact",
    ))
    assert engine.remove_entry(eid)
    matched, _ = engine.is_allowlisted(_ip_ioc("1.2.3.4"))
    assert not matched
    assert not engine.remove_entry("nonexistent")
