"""
IOC allowlist and false-positive suppression engine.

Supports:
- CIDR range matching for IPv4/IPv6 addresses
- Wildcard glob patterns for domains, URLs, and user-agents
- Exact-match suppression for file hashes, emails, and registry keys
- Confidence-weighted false-positive tracking that decays IOC confidence scores
- Persistent allow-entries with reason codes and expiry timestamps
- Thread-safe bulk import/export in STIX-compatible JSON format
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

from overwatch.models import IOC, IOCType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowlist entry model
# ---------------------------------------------------------------------------

class AllowlistReason(str, Enum):
    KNOWN_GOOD = "known_good"
    INTERNAL_INFRA = "internal_infrastructure"
    THIRD_PARTY_SVC = "third_party_service"
    SCANNER = "security_scanner"
    FALSE_POSITIVE_CONFIRMED = "false_positive_confirmed"
    TEMP_EXCEPTION = "temporary_exception"
    CUSTOM = "custom"


@dataclass
class AllowlistEntry:
    """
    A single allow-list rule.

    ``pattern`` is interpreted based on ``match_type``:
    - ``exact``:   literal string equality (case-insensitive for domains/URLs)
    - ``cidr``:    IPv4 or IPv6 CIDR block, e.g. ``10.0.0.0/8``
    - ``wildcard``: shell-style glob, e.g. ``*.internal.corp``
    - ``regex``:  full Python regular expression
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ioc_type: Optional[IOCType] = None   # None = matches any type
    pattern: str = ""
    match_type: str = "exact"            # exact | cidr | wildcard | regex
    reason: AllowlistReason = AllowlistReason.KNOWN_GOOD
    comment: str = ""
    created_by: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    hit_count: int = 0

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["ioc_type"] = self.ioc_type.value if self.ioc_type else None
        d["reason"] = self.reason.value
        d["created_at"] = self.created_at.isoformat()
        d["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "AllowlistEntry":
        d = dict(d)
        if d.get("ioc_type"):
            d["ioc_type"] = IOCType(d["ioc_type"])
        if d.get("reason"):
            d["reason"] = AllowlistReason(d["reason"])
        if d.get("created_at"):
            d["created_at"] = datetime.fromisoformat(d["created_at"])
        if d.get("expires_at"):
            d["expires_at"] = datetime.fromisoformat(d["expires_at"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Match helpers
# ---------------------------------------------------------------------------

def _match_cidr(value: str, cidr: str) -> bool:
    """Return True if *value* is an IP address contained in *cidr*."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(value)
        return addr in network
    except ValueError:
        return False


def _match_wildcard(value: str, pattern: str) -> bool:
    """Case-insensitive shell-style wildcard match."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _match_regex(value: str, pattern: str) -> bool:
    try:
        return bool(re.search(pattern, value, re.IGNORECASE))
    except re.error:
        logger.warning("Invalid regex in allowlist: %s", pattern)
        return False


# ---------------------------------------------------------------------------
# Allowlist engine
# ---------------------------------------------------------------------------

class AllowlistEngine:
    """
    Thread-safe IOC allowlist with CIDR, wildcard, regex, and exact-match support.

    Typical usage::

        engine = AllowlistEngine()

        # Add a CIDR exception for RFC-1918 space
        engine.add_entry(AllowlistEntry(
            ioc_type=IOCType.IPV4,
            pattern="10.0.0.0/8",
            match_type="cidr",
            reason=AllowlistReason.INTERNAL_INFRA,
            comment="RFC-1918 private range",
        ))

        # Check an IOC
        if engine.is_allowlisted(ioc):
            ...  # suppress / skip

        # Bulk load from JSON export
        engine.load_json(json_string)
    """

    def __init__(self) -> None:
        self._entries: Dict[str, AllowlistEntry] = {}
        self._compiled_regex: Dict[str, re.Pattern] = {}
        self._compiled_cidr: Dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        self._lock = threading.RLock()

        # Metrics
        self._total_suppressed: int = 0
        self._fp_reported: int = 0

    # ------------------------------------------------------------------
    # Entry management
    # ------------------------------------------------------------------

    def add_entry(self, entry: AllowlistEntry) -> str:
        """Add an allow-list entry. Returns the entry_id."""
        with self._lock:
            if entry.match_type == "cidr":
                try:
                    self._compiled_cidr[entry.entry_id] = ipaddress.ip_network(
                        entry.pattern, strict=False
                    )
                except ValueError as exc:
                    raise ValueError(f"Invalid CIDR pattern '{entry.pattern}': {exc}") from exc

            elif entry.match_type == "regex":
                try:
                    self._compiled_regex[entry.entry_id] = re.compile(
                        entry.pattern, re.IGNORECASE
                    )
                except re.error as exc:
                    raise ValueError(f"Invalid regex pattern '{entry.pattern}': {exc}") from exc

            self._entries[entry.entry_id] = entry
            logger.debug("Allowlist entry %s added (%s / %s)",
                         entry.entry_id, entry.match_type, entry.pattern)
        return entry.entry_id

    def remove_entry(self, entry_id: str) -> bool:
        """Remove an entry by ID. Returns True if removed, False if not found."""
        with self._lock:
            if entry_id not in self._entries:
                return False
            self._entries.pop(entry_id)
            self._compiled_cidr.pop(entry_id, None)
            self._compiled_regex.pop(entry_id, None)
            return True

    def get_entry(self, entry_id: str) -> Optional[AllowlistEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    def list_entries(
        self,
        ioc_type: Optional[IOCType] = None,
        include_expired: bool = False,
    ) -> List[AllowlistEntry]:
        with self._lock:
            entries = list(self._entries.values())
        if not include_expired:
            entries = [e for e in entries if not e.is_expired()]
        if ioc_type is not None:
            entries = [e for e in entries if e.ioc_type is None or e.ioc_type == ioc_type]
        return entries

    # ------------------------------------------------------------------
    # Core matching
    # ------------------------------------------------------------------

    def is_allowlisted(self, ioc: IOC) -> Tuple[bool, Optional[AllowlistEntry]]:
        """
        Check whether *ioc* is covered by any allowlist rule.

        Returns ``(True, entry)`` on match, ``(False, None)`` otherwise.
        Expired entries are automatically ignored and their hit_count is not incremented.
        """
        with self._lock:
            for entry in self._entries.values():
                if entry.is_expired():
                    continue
                if entry.ioc_type is not None and entry.ioc_type != ioc.ioc_type:
                    continue
                if self._entry_matches(entry, ioc.value):
                    entry.hit_count += 1
                    self._total_suppressed += 1
                    logger.debug("IOC %s suppressed by allowlist entry %s",
                                 ioc.value, entry.entry_id)
                    return True, entry
        return False, None

    def filter_iocs(self, iocs: Iterable[IOC]) -> Tuple[List[IOC], List[Tuple[IOC, AllowlistEntry]]]:
        """
        Partition *iocs* into (clean, suppressed) lists.

        Returns:
            clean:      IOCs that did not match any allow rule.
            suppressed: ``(ioc, matching_entry)`` tuples for suppressed indicators.
        """
        clean: List[IOC] = []
        suppressed: List[Tuple[IOC, AllowlistEntry]] = []
        for ioc in iocs:
            matched, entry = self.is_allowlisted(ioc)
            if matched:
                suppressed.append((ioc, entry))
            else:
                clean.append(ioc)
        return clean, suppressed

    # ------------------------------------------------------------------
    # False-positive feedback
    # ------------------------------------------------------------------

    def report_false_positive(
        self,
        ioc: IOC,
        confidence_penalty: int = 20,
        auto_add: bool = False,
        comment: str = "",
    ) -> Optional[str]:
        """
        Mark *ioc* as a confirmed false positive.

        Increments ``ioc.false_positive_count`` and decrements confidence
        by *confidence_penalty* (clamped to 0).

        If *auto_add* is True, automatically adds an exact-match allowlist entry
        for this IOC and returns its entry_id; otherwise returns None.
        """
        ioc.false_positive_count += 1
        ioc.confidence = max(0, ioc.confidence - confidence_penalty)
        self._fp_reported += 1

        logger.info("False positive reported for %s (confidence now %d)",
                    ioc.value, ioc.confidence)

        if auto_add:
            entry = AllowlistEntry(
                ioc_type=ioc.ioc_type,
                pattern=ioc.value,
                match_type="exact",
                reason=AllowlistReason.FALSE_POSITIVE_CONFIRMED,
                comment=comment or f"Auto-added from FP report (fp_count={ioc.false_positive_count})",
            )
            return self.add_entry(entry)
        return None

    # ------------------------------------------------------------------
    # Bulk import / export
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize all entries to a JSON string."""
        with self._lock:
            return json.dumps(
                [e.to_dict() for e in self._entries.values()],
                indent=indent,
                default=str,
            )

    def load_json(self, json_str: str, replace: bool = False) -> int:
        """
        Load allowlist entries from a JSON string.

        :param json_str: JSON array of serialized :class:`AllowlistEntry` dicts.
        :param replace:  If True, clear existing entries first.
        :returns: Number of entries loaded.
        """
        data = json.loads(json_str)
        if not isinstance(data, list):
            raise ValueError("Expected a JSON array of allowlist entries")

        loaded = 0
        with self._lock:
            if replace:
                self._entries.clear()
                self._compiled_cidr.clear()
                self._compiled_regex.clear()

            for item in data:
                try:
                    entry = AllowlistEntry.from_dict(item)
                    self.add_entry(entry)
                    loaded += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Skipping invalid allowlist entry: %s — %s", item, exc)

        return loaded

    # ------------------------------------------------------------------
    # Convenience bulk-add helpers
    # ------------------------------------------------------------------

    def add_cidr_ranges(
        self,
        cidrs: List[str],
        reason: AllowlistReason = AllowlistReason.INTERNAL_INFRA,
        comment: str = "",
        expires_in: Optional[timedelta] = None,
    ) -> List[str]:
        """Add multiple CIDR ranges at once; returns list of entry_ids."""
        entry_ids = []
        expires_at = (datetime.now(timezone.utc) + expires_in) if expires_in else None
        for cidr in cidrs:
            entry = AllowlistEntry(
                ioc_type=IOCType.IPV4,
                pattern=cidr,
                match_type="cidr",
                reason=reason,
                comment=comment,
                expires_at=expires_at,
            )
            try:
                entry_ids.append(self.add_entry(entry))
            except ValueError:
                # Try IPv6
                entry.ioc_type = IOCType.IPV6
                try:
                    entry_ids.append(self.add_entry(entry))
                except ValueError:
                    logger.warning("Invalid CIDR: %s", cidr)
        return entry_ids

    def add_domain_patterns(
        self,
        patterns: List[str],
        reason: AllowlistReason = AllowlistReason.KNOWN_GOOD,
        comment: str = "",
        expires_in: Optional[timedelta] = None,
    ) -> List[str]:
        """
        Add domain/URL allowlist patterns. Patterns containing '*' are treated as
        wildcard globs; plain strings are exact-matched.
        """
        entry_ids = []
        expires_at = (datetime.now(timezone.utc) + expires_in) if expires_in else None
        for pat in patterns:
            match_type = "wildcard" if "*" in pat or "?" in pat else "exact"
            # Apply to both DOMAIN and URL types
            for ioc_type in (IOCType.DOMAIN, IOCType.URL):
                entry = AllowlistEntry(
                    ioc_type=ioc_type,
                    pattern=pat,
                    match_type=match_type,
                    reason=reason,
                    comment=comment,
                    expires_at=expires_at,
                )
                entry_ids.append(self.add_entry(entry))
        return entry_ids

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def stats(self) -> Dict:
        with self._lock:
            active = sum(1 for e in self._entries.values() if not e.is_expired())
            expired = len(self._entries) - active
            by_type: Dict[str, int] = {}
            for e in self._entries.values():
                key = e.ioc_type.value if e.ioc_type else "any"
                by_type[key] = by_type.get(key, 0) + 1
            by_match: Dict[str, int] = {}
            for e in self._entries.values():
                by_match[e.match_type] = by_match.get(e.match_type, 0) + 1
        return {
            "total_entries": len(self._entries),
            "active_entries": active,
            "expired_entries": expired,
            "total_suppressed": self._total_suppressed,
            "false_positives_reported": self._fp_reported,
            "by_ioc_type": by_type,
            "by_match_type": by_match,
        }

    # ------------------------------------------------------------------
    # Private matching dispatch
    # ------------------------------------------------------------------

    def _entry_matches(self, entry: AllowlistEntry, value: str) -> bool:
        mt = entry.match_type
        if mt == "exact":
            # Case-insensitive for network indicators; case-sensitive for hashes
            if entry.ioc_type in (
                IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256
            ):
                return value == entry.pattern
            return value.lower() == entry.pattern.lower()

        if mt == "cidr":
            network = self._compiled_cidr.get(entry.entry_id)
            if network is None:
                return False
            try:
                return ipaddress.ip_address(value) in network
            except ValueError:
                return False

        if mt == "wildcard":
            return _match_wildcard(value, entry.pattern)

        if mt == "regex":
            compiled = self._compiled_regex.get(entry.entry_id)
            if compiled is None:
                return False
            return bool(compiled.search(value))

        logger.warning("Unknown match_type '%s' in entry %s", mt, entry.entry_id)
        return False


# ---------------------------------------------------------------------------
# Default allowlist: well-known benign infrastructure
# ---------------------------------------------------------------------------

_RFC1918_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                   "169.254.0.0/16", "::1/128", "fc00::/7"]

_BENIGN_DOMAINS = [
    "*.microsoft.com", "*.windows.com", "*.windowsupdate.com",
    "*.google.com", "*.googleapis.com", "*.gstatic.com",
    "*.amazon.com", "*.amazonaws.com",
    "*.apple.com", "*.icloud.com",
    "*.akamai.net", "*.akamaiedge.net",
    "*.cloudflare.com", "*.cloudfront.net",
]


def build_default_allowlist() -> AllowlistEngine:
    """
    Return a pre-populated :class:`AllowlistEngine` with RFC-1918 ranges and
    commonly benign CDN/cloud domains whitelisted.

    This is a starting point — always review and tune for your environment.
    """
    engine = AllowlistEngine()

    # RFC-1918 and loopback ranges
    for cidr in _RFC1918_RANGES:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ioc_type = IOCType.IPV6 if ":" in cidr else IOCType.IPV4
            entry = AllowlistEntry(
                ioc_type=ioc_type,
                pattern=cidr,
                match_type="cidr",
                reason=AllowlistReason.INTERNAL_INFRA,
                comment=f"Standard non-routable / loopback range ({cidr})",
            )
            engine.add_entry(entry)
        except ValueError:
            pass

    # Benign CDN domains
    for pat in _BENIGN_DOMAINS:
        for ioc_type in (IOCType.DOMAIN, IOCType.URL):
            engine.add_entry(AllowlistEntry(
                ioc_type=ioc_type,
                pattern=pat,
                match_type="wildcard",
                reason=AllowlistReason.THIRD_PARTY_SVC,
                comment="Common CDN/cloud provider domain (review before using in production)",
            ))

    return engine
