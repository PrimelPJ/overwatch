"""
Watchlist and whitelist manager for threat indicators.

Provides fast O(1) lookup for:
  - Whitelist: trusted/benign indicators to suppress from alerting
  - Watchlist: high-priority indicators that should trigger elevated alerts

Supports:
  - Exact value matching for hashes, IPs, domains, URLs, emails
  - CIDR range matching for IPv4/IPv6 addresses
  - Glob-style wildcard matching for domains (e.g. *.internal.corp)
  - TTL-based automatic expiry for time-bounded entries
  - JSON serialization / deserialization for persistence
  - Thread-safe reads via RLock
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ListType(str, Enum):
    WHITELIST = "whitelist"
    WATCHLIST = "watchlist"


class EntryType(str, Enum):
    EXACT = "exact"          # exact string / hash match
    CIDR = "cidr"            # IP network range
    GLOB = "glob"            # fnmatch-style wildcard


@dataclass
class ListEntry:
    value: str                          # the indicator or pattern
    list_type: ListType
    entry_type: EntryType = EntryType.EXACT
    reason: str = ""
    added_by: str = ""
    added_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None    # ISO-8601 or None (no expiry)
    tags: List[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            # Ensure timezone-aware comparison
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) >= exp
        except ValueError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "list_type": self.list_type.value,
            "entry_type": self.entry_type.value,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at,
            "expires_at": self.expires_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ListEntry":
        return cls(
            value=data["value"],
            list_type=ListType(data["list_type"]),
            entry_type=EntryType(data.get("entry_type", "exact")),
            reason=data.get("reason", ""),
            added_by=data.get("added_by", ""),
            added_at=data.get("added_at", datetime.now(timezone.utc).isoformat()),
            expires_at=data.get("expires_at"),
            tags=data.get("tags", []),
        )


@dataclass
class LookupResult:
    matched: bool
    list_type: Optional[ListType] = None
    entry: Optional[ListEntry] = None

    @property
    def is_whitelisted(self) -> bool:
        return self.matched and self.list_type == ListType.WHITELIST

    @property
    def is_watchlisted(self) -> bool:
        return self.matched and self.list_type == ListType.WATCHLIST


class WatchlistManager:
    """
    Central manager for whitelist and watchlist entries.

    All mutations are protected by an RLock so the manager can be shared
    across threads (e.g. in an async SOAR pipeline with a thread pool).

    Usage::

        mgr = WatchlistManager()
        mgr.add("192.168.1.0/24", ListType.WHITELIST, entry_type=EntryType.CIDR,
                reason="Internal LAN", added_by="admin")
        mgr.add("malware.example.com", ListType.WATCHLIST,
                reason="Known C2", added_by="threat-intel")

        result = mgr.lookup("192.168.1.50")
        assert result.is_whitelisted
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # exact lookups: lower(value) -> ListEntry
        self._exact: Dict[str, ListEntry] = {}
        # CIDR entries keyed by network string
        self._cidr_entries: List[ListEntry] = []
        self._cidr_nets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        # Glob entries
        self._glob_entries: List[ListEntry] = []

    # ── Public API ─────────────────────────────────────────────────────────

    def add(
        self,
        value: str,
        list_type: ListType,
        entry_type: EntryType = EntryType.EXACT,
        reason: str = "",
        added_by: str = "",
        expires_at: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ListEntry:
        """Add an entry. Replaces any existing entry with the same value."""
        entry = ListEntry(
            value=value,
            list_type=list_type,
            entry_type=entry_type,
            reason=reason,
            added_by=added_by,
            expires_at=expires_at,
            tags=tags or [],
        )
        with self._lock:
            self._store(entry)
        return entry

    def add_entry(self, entry: ListEntry) -> None:
        """Add a pre-built ListEntry (used during deserialization)."""
        with self._lock:
            self._store(entry)

    def remove(self, value: str) -> bool:
        """Remove entry by exact value string. Returns True if found."""
        key = value.lower()
        with self._lock:
            if key in self._exact:
                del self._exact[key]
                return True
            # Remove from CIDR list
            for i, e in enumerate(self._cidr_entries):
                if e.value.lower() == key:
                    self._cidr_entries.pop(i)
                    self._cidr_nets.pop(i)
                    return True
            # Remove from glob list
            for i, e in enumerate(self._glob_entries):
                if e.value.lower() == key:
                    self._glob_entries.pop(i)
                    return True
        return False

    def lookup(self, indicator: str) -> LookupResult:
        """
        Look up an indicator against both lists.

        Returns the FIRST non-expired match. Whitelist entries take
        precedence over watchlist entries when both match.
        """
        with self._lock:
            self._evict_expired()
            key = indicator.lower()

            # 1. Exact match
            if key in self._exact:
                e = self._exact[key]
                return LookupResult(matched=True, list_type=e.list_type, entry=e)

            # 2. CIDR match
            cidr_result = self._lookup_cidr(indicator)
            if cidr_result is not None:
                return LookupResult(
                    matched=True,
                    list_type=cidr_result.list_type,
                    entry=cidr_result,
                )

            # 3. Glob match
            glob_result = self._lookup_glob(indicator)
            if glob_result is not None:
                return LookupResult(
                    matched=True,
                    list_type=glob_result.list_type,
                    entry=glob_result,
                )

            return LookupResult(matched=False)

    def is_whitelisted(self, indicator: str) -> bool:
        return self.lookup(indicator).is_whitelisted

    def is_watchlisted(self, indicator: str) -> bool:
        return self.lookup(indicator).is_watchlisted

    def purge_expired(self) -> int:
        """Remove all expired entries and return the count removed."""
        with self._lock:
            before = self._total_count()
            self._evict_expired(force_all=True)
            return before - self._total_count()

    def entries(
        self,
        list_type: Optional[ListType] = None,
        include_expired: bool = False,
    ) -> List[ListEntry]:
        """Return all entries, optionally filtered by list type."""
        with self._lock:
            all_entries: List[ListEntry] = (
                list(self._exact.values())
                + list(self._cidr_entries)
                + list(self._glob_entries)
            )
        results = []
        for e in all_entries:
            if not include_expired and e.is_expired:
                continue
            if list_type is not None and e.list_type != list_type:
                continue
            results.append(e)
        return results

    # ── Bulk operations ────────────────────────────────────────────────────

    def add_bulk(
        self,
        values: Iterable[str],
        list_type: ListType,
        entry_type: EntryType = EntryType.EXACT,
        reason: str = "",
        added_by: str = "",
        expires_at: Optional[str] = None,
    ) -> int:
        """Add many values at once. Returns count added."""
        count = 0
        for value in values:
            v = value.strip()
            if v:
                self.add(v, list_type, entry_type=entry_type,
                         reason=reason, added_by=added_by, expires_at=expires_at)
                count += 1
        return count

    # ── Persistence ────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "entries": [
                e.to_dict()
                for e in self.entries(include_expired=True)
            ]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WatchlistManager":
        mgr = cls()
        for raw in data.get("entries", []):
            try:
                entry = ListEntry.from_dict(raw)
                mgr.add_entry(entry)
            except (KeyError, ValueError) as exc:
                logger.warning("Skipping malformed watchlist entry: %s", exc)
        return mgr

    def save(self, path: str | Path) -> None:
        """Persist to a JSON file (atomic write via temp file)."""
        path = Path(path)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        os.replace(tmp, path)
        logger.debug("Watchlist saved to %s (%d entries)", path, self._total_count())

    @classmethod
    def load(cls, path: str | Path) -> "WatchlistManager":
        """Load from a JSON file created by save()."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls.from_dict(data)

    # ── Statistics ─────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            whitelist_count = sum(
                1 for e in self._all_entries() if e.list_type == ListType.WHITELIST
            )
            watchlist_count = sum(
                1 for e in self._all_entries() if e.list_type == ListType.WATCHLIST
            )
            expired_count = sum(1 for e in self._all_entries() if e.is_expired)
            return {
                "total": self._total_count(),
                "whitelist": whitelist_count,
                "watchlist": watchlist_count,
                "expired": expired_count,
                "exact": len(self._exact),
                "cidr": len(self._cidr_entries),
                "glob": len(self._glob_entries),
            }

    # ── Private helpers ────────────────────────────────────────────────────

    def _store(self, entry: ListEntry) -> None:
        if entry.entry_type == EntryType.CIDR:
            try:
                net = ipaddress.ip_network(entry.value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR: {entry.value!r}: {exc}") from exc
            # Replace existing
            key = entry.value.lower()
            for i, e in enumerate(self._cidr_entries):
                if e.value.lower() == key:
                    self._cidr_entries[i] = entry
                    self._cidr_nets[i] = net
                    return
            self._cidr_entries.append(entry)
            self._cidr_nets.append(net)
        elif entry.entry_type == EntryType.GLOB:
            key = entry.value.lower()
            for i, e in enumerate(self._glob_entries):
                if e.value.lower() == key:
                    self._glob_entries[i] = entry
                    return
            self._glob_entries.append(entry)
        else:
            self._exact[entry.value.lower()] = entry

    def _lookup_cidr(
        self, indicator: str
    ) -> Optional[ListEntry]:
        try:
            addr = ipaddress.ip_address(indicator)
        except ValueError:
            return None

        # Prefer whitelist over watchlist in case of overlap
        whitelist_match: Optional[ListEntry] = None
        watchlist_match: Optional[ListEntry] = None

        for entry, net in zip(self._cidr_entries, self._cidr_nets):
            if entry.is_expired:
                continue
            try:
                if addr in net:
                    if entry.list_type == ListType.WHITELIST:
                        whitelist_match = entry
                    else:
                        watchlist_match = entry
            except TypeError:
                continue

        return whitelist_match or watchlist_match

    def _lookup_glob(
        self, indicator: str
    ) -> Optional[ListEntry]:
        key = indicator.lower()
        whitelist_match: Optional[ListEntry] = None
        watchlist_match: Optional[ListEntry] = None

        for entry in self._glob_entries:
            if entry.is_expired:
                continue
            if fnmatch.fnmatch(key, entry.value.lower()):
                if entry.list_type == ListType.WHITELIST:
                    whitelist_match = entry
                else:
                    watchlist_match = entry

        return whitelist_match or watchlist_match

    def _evict_expired(self, force_all: bool = False) -> None:
        """Remove expired entries from internal stores."""
        self._exact = {
            k: v for k, v in self._exact.items() if not v.is_expired
        }
        to_remove = [
            i for i, e in enumerate(self._cidr_entries) if e.is_expired
        ]
        for i in reversed(to_remove):
            self._cidr_entries.pop(i)
            self._cidr_nets.pop(i)

        self._glob_entries = [e for e in self._glob_entries if not e.is_expired]

    def _all_entries(self) -> Iterator[ListEntry]:
        yield from self._exact.values()
        yield from self._cidr_entries
        yield from self._glob_entries

    def _total_count(self) -> int:
        return len(self._exact) + len(self._cidr_entries) + len(self._glob_entries)
