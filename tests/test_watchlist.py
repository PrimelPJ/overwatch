"""Tests for the watchlist and whitelist manager."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from overwatch.watchlist import (
    EntryType,
    ListEntry,
    ListType,
    LookupResult,
    WatchlistManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mgr() -> WatchlistManager:
    return WatchlistManager()


def _future_ts(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _past_ts(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


# ---------------------------------------------------------------------------
# Basic add / lookup
# ---------------------------------------------------------------------------

class TestBasicAddLookup:
    def test_add_exact_whitelist_and_lookup(self):
        mgr = _mgr()
        mgr.add("malware.example.com", ListType.WHITELIST, reason="test")
        result = mgr.lookup("malware.example.com")
        assert result.matched
        assert result.is_whitelisted

    def test_add_exact_watchlist_and_lookup(self):
        mgr = _mgr()
        mgr.add("evil.c2.net", ListType.WATCHLIST, reason="Known C2")
        result = mgr.lookup("evil.c2.net")
        assert result.matched
        assert result.is_watchlisted

    def test_lookup_missing_returns_no_match(self):
        mgr = _mgr()
        result = mgr.lookup("nothere.example.com")
        assert not result.matched
        assert result.list_type is None

    def test_lookup_is_case_insensitive(self):
        mgr = _mgr()
        mgr.add("Evil.Domain.COM", ListType.WATCHLIST)
        assert mgr.lookup("evil.domain.com").matched
        assert mgr.lookup("EVIL.DOMAIN.COM").matched

    def test_entry_reason_preserved(self):
        mgr = _mgr()
        mgr.add("1.2.3.4", ListType.WHITELIST, reason="internal probe")
        result = mgr.lookup("1.2.3.4")
        assert result.entry is not None
        assert result.entry.reason == "internal probe"

    def test_add_duplicate_replaces_entry(self):
        mgr = _mgr()
        mgr.add("host.example.com", ListType.WHITELIST, reason="first")
        mgr.add("host.example.com", ListType.WATCHLIST, reason="second")
        result = mgr.lookup("host.example.com")
        assert result.is_watchlisted
        assert result.entry.reason == "second"


# ---------------------------------------------------------------------------
# CIDR range matching
# ---------------------------------------------------------------------------

class TestCIDRMatching:
    def test_ip_inside_whitelisted_cidr(self):
        mgr = _mgr()
        mgr.add("10.0.0.0/8", ListType.WHITELIST, entry_type=EntryType.CIDR,
                reason="Private range")
        assert mgr.is_whitelisted("10.1.2.3")
        assert mgr.is_whitelisted("10.255.0.1")

    def test_ip_outside_cidr_not_matched(self):
        mgr = _mgr()
        mgr.add("10.0.0.0/8", ListType.WHITELIST, entry_type=EntryType.CIDR)
        assert not mgr.is_whitelisted("192.168.1.1")

    def test_ipv6_cidr_match(self):
        mgr = _mgr()
        mgr.add("::1/128", ListType.WHITELIST, entry_type=EntryType.CIDR,
                reason="IPv6 loopback")
        assert mgr.is_whitelisted("::1")
        assert not mgr.is_whitelisted("::2")

    def test_watchlist_cidr_ip_match(self):
        mgr = _mgr()
        mgr.add("203.0.113.0/24", ListType.WATCHLIST, entry_type=EntryType.CIDR,
                reason="Known threat actor")
        assert mgr.is_watchlisted("203.0.113.55")

    def test_cidr_whitelist_takes_precedence_over_watchlist(self):
        mgr = _mgr()
        mgr.add("172.16.0.0/12", ListType.WATCHLIST, entry_type=EntryType.CIDR)
        mgr.add("172.16.0.0/12", ListType.WHITELIST, entry_type=EntryType.CIDR)
        result = mgr.lookup("172.16.5.5")
        assert result.is_whitelisted

    def test_invalid_cidr_raises(self):
        mgr = _mgr()
        with pytest.raises(ValueError):
            mgr.add("not-a-cidr", ListType.WHITELIST, entry_type=EntryType.CIDR)


# ---------------------------------------------------------------------------
# Glob matching
# ---------------------------------------------------------------------------

class TestGlobMatching:
    def test_wildcard_subdomain_match(self):
        mgr = _mgr()
        mgr.add("*.internal.corp", ListType.WHITELIST, entry_type=EntryType.GLOB,
                reason="Internal infrastructure")
        assert mgr.is_whitelisted("api.internal.corp")
        assert mgr.is_whitelisted("db01.internal.corp")
        assert not mgr.is_whitelisted("evil.external.corp")

    def test_exact_glob_pattern(self):
        mgr = _mgr()
        mgr.add("malware-*.evil.net", ListType.WATCHLIST, entry_type=EntryType.GLOB)
        assert mgr.is_watchlisted("malware-v2.evil.net")
        assert mgr.is_watchlisted("malware-test.evil.net")
        assert not mgr.is_watchlisted("goodware.evil.net")

    def test_glob_case_insensitive(self):
        mgr = _mgr()
        mgr.add("*.TRUSTED.ORG", ListType.WHITELIST, entry_type=EntryType.GLOB)
        assert mgr.is_whitelisted("host.trusted.org")


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_entry_not_matched(self):
        mgr = _mgr()
        mgr.add("stale.evil.com", ListType.WATCHLIST, expires_at=_past_ts())
        result = mgr.lookup("stale.evil.com")
        assert not result.matched

    def test_valid_ttl_entry_matched(self):
        mgr = _mgr()
        mgr.add("fresh.evil.com", ListType.WATCHLIST, expires_at=_future_ts())
        result = mgr.lookup("fresh.evil.com")
        assert result.matched

    def test_none_expiry_never_expires(self):
        mgr = _mgr()
        mgr.add("permanent.corp", ListType.WHITELIST, expires_at=None)
        assert mgr.is_whitelisted("permanent.corp")

    def test_purge_expired_removes_entries(self):
        mgr = _mgr()
        mgr.add("old1.example.com", ListType.WATCHLIST, expires_at=_past_ts())
        mgr.add("old2.example.com", ListType.WATCHLIST, expires_at=_past_ts())
        mgr.add("active.example.com", ListType.WATCHLIST)
        removed = mgr.purge_expired()
        assert removed == 2
        assert not mgr.lookup("old1.example.com").matched
        assert mgr.lookup("active.example.com").matched

    def test_entry_is_expired_property(self):
        e = ListEntry(
            value="x.com",
            list_type=ListType.WATCHLIST,
            expires_at=_past_ts(),
        )
        assert e.is_expired

    def test_entry_not_expired_property(self):
        e = ListEntry(
            value="x.com",
            list_type=ListType.WATCHLIST,
            expires_at=_future_ts(),
        )
        assert not e.is_expired


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------

class TestRemove:
    def test_remove_exact_entry(self):
        mgr = _mgr()
        mgr.add("badguy.com", ListType.WATCHLIST)
        assert mgr.remove("badguy.com")
        assert not mgr.lookup("badguy.com").matched

    def test_remove_cidr_entry(self):
        mgr = _mgr()
        mgr.add("192.168.0.0/16", ListType.WHITELIST, entry_type=EntryType.CIDR)
        assert mgr.remove("192.168.0.0/16")
        assert not mgr.is_whitelisted("192.168.1.1")

    def test_remove_returns_false_if_not_found(self):
        mgr = _mgr()
        assert not mgr.remove("nonexistent.example.com")


# ---------------------------------------------------------------------------
# Bulk add
# ---------------------------------------------------------------------------

class TestBulkAdd:
    def test_bulk_add_all_entries_present(self):
        mgr = _mgr()
        domains = ["a.evil.com", "b.evil.com", "c.evil.com"]
        count = mgr.add_bulk(domains, ListType.WATCHLIST, reason="bulk import")
        assert count == 3
        for d in domains:
            assert mgr.is_watchlisted(d)

    def test_bulk_add_skips_empty_strings(self):
        mgr = _mgr()
        count = mgr.add_bulk(["", "  ", "valid.com"], ListType.WHITELIST)
        assert count == 1


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_to_dict_and_from_dict_roundtrip(self):
        mgr = _mgr()
        mgr.add("test.example.com", ListType.WATCHLIST, reason="roundtrip test")
        mgr.add("10.0.0.0/8", ListType.WHITELIST, entry_type=EntryType.CIDR)
        mgr.add("*.safe.corp", ListType.WHITELIST, entry_type=EntryType.GLOB)

        data = mgr.to_dict()
        restored = WatchlistManager.from_dict(data)

        assert restored.is_watchlisted("test.example.com")
        assert restored.is_whitelisted("10.1.2.3")
        assert restored.is_whitelisted("host.safe.corp")

    def test_save_and_load_json_file(self):
        mgr = _mgr()
        mgr.add("evil.domain", ListType.WATCHLIST, reason="persist test")
        mgr.add("192.168.0.0/16", ListType.WHITELIST, entry_type=EntryType.CIDR)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            mgr.save(path)
            loaded = WatchlistManager.load(path)
            assert loaded.is_watchlisted("evil.domain")
            assert loaded.is_whitelisted("192.168.10.5")
        finally:
            os.unlink(path)

    def test_from_dict_skips_malformed_entries(self, caplog):
        data = {
            "entries": [
                {"value": "good.com", "list_type": "watchlist", "entry_type": "exact"},
                {"not_value": "bad entry"},  # missing required field
            ]
        }
        mgr = WatchlistManager.from_dict(data)
        assert mgr.is_watchlisted("good.com")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_counts_correct(self):
        mgr = _mgr()
        mgr.add("a.com", ListType.WHITELIST)
        mgr.add("b.com", ListType.WATCHLIST)
        mgr.add("10.0.0.0/8", ListType.WHITELIST, entry_type=EntryType.CIDR)
        mgr.add("*.evil.net", ListType.WATCHLIST, entry_type=EntryType.GLOB)

        s = mgr.stats()
        assert s["total"] == 4
        assert s["whitelist"] == 2
        assert s["watchlist"] == 2
        assert s["exact"] == 2
        assert s["cidr"] == 1
        assert s["glob"] == 1

    def test_entries_filter_by_list_type(self):
        mgr = _mgr()
        mgr.add("a.com", ListType.WHITELIST)
        mgr.add("b.com", ListType.WATCHLIST)
        mgr.add("c.com", ListType.WATCHLIST)

        wl_entries = mgr.entries(list_type=ListType.WATCHLIST)
        assert len(wl_entries) == 2
        assert all(e.list_type == ListType.WATCHLIST for e in wl_entries)


# ---------------------------------------------------------------------------
# LookupResult properties
# ---------------------------------------------------------------------------

class TestLookupResult:
    def test_no_match_result_properties(self):
        result = LookupResult(matched=False)
        assert not result.is_whitelisted
        assert not result.is_watchlisted

    def test_whitelist_result_properties(self):
        result = LookupResult(
            matched=True,
            list_type=ListType.WHITELIST,
            entry=ListEntry(value="x", list_type=ListType.WHITELIST),
        )
        assert result.is_whitelisted
        assert not result.is_watchlisted

    def test_watchlist_result_properties(self):
        result = LookupResult(
            matched=True,
            list_type=ListType.WATCHLIST,
            entry=ListEntry(value="x", list_type=ListType.WATCHLIST),
        )
        assert result.is_watchlisted
        assert not result.is_whitelisted
