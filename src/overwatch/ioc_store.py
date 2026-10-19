"""
In-memory IOC store with TTL management, indexing, and confidence aging.
Provides fast lookups by type, value, fingerprint, and tag.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Set

from overwatch.models import IOC, IOCType, Severity, TLPLevel

logger = logging.getLogger(__name__)


class IOCStore:
    """
    Thread-safe in-memory store for IOCs with automatic TTL expiry,
    deduplication by fingerprint, and multi-index lookups.
    """

    def __init__(self, max_size: int = 100_000, gc_interval: int = 300) -> None:
        self._store: Dict[str, IOC] = {}           # fingerprint -> IOC
        self._by_id: Dict[str, str] = {}            # ioc_id -> fingerprint
        self._by_type: Dict[IOCType, Set[str]] = defaultdict(set)
        self._by_source: Dict[str, Set[str]] = defaultdict(set)
        self._by_tag: Dict[str, Set[str]] = defaultdict(set)
        self._by_severity: Dict[Severity, Set[str]] = defaultdict(set)

        self._lock = threading.RLock()
        self.max_size = max_size
        self._gc_interval = gc_interval
        self._last_gc: float = time.monotonic()

        self.stats = {
            "total_added": 0,
            "total_updated": 0,
            "total_expired": 0,
            "total_evicted": 0,
        }

    def add(self, ioc: IOC) -> bool:
        """
        Add or update an IOC. Returns True if new, False if updated existing.
        When fingerprint matches, merges hit counts and refreshes metadata.
        """
        self._maybe_gc()
        fp = ioc.fingerprint

        with self._lock:
            if fp in self._store:
                self._merge(self._store[fp], ioc)
                self.stats["total_updated"] += 1
                return False

            if len(self._store) >= self.max_size:
                self._evict_one()

            self._store[fp] = ioc
            self._by_id[ioc.id] = fp
            self._by_type[ioc.ioc_type].add(fp)
            self._by_source[ioc.source].add(fp)
            self._by_severity[ioc.severity].add(fp)
            for tag in ioc.tags:
                self._by_tag[tag].add(fp)

            self.stats["total_added"] += 1
            return True

    def get(self, fingerprint: str) -> Optional[IOC]:
        with self._lock:
            ioc = self._store.get(fingerprint)
            if ioc and ioc.is_expired:
                self._remove(fingerprint)
                return None
            return ioc

    def get_by_id(self, ioc_id: str) -> Optional[IOC]:
        with self._lock:
            fp = self._by_id.get(ioc_id)
            return self.get(fp) if fp else None

    def lookup(self, ioc_type: IOCType, value: str) -> Optional[IOC]:
        """Look up an IOC by type+value (computes fingerprint)."""
        import hashlib
        fp = hashlib.sha256(f"{ioc_type.value}:{value.lower()}".encode()).hexdigest()
        return self.get(fp)

    def query_by_type(self, ioc_type: IOCType, min_confidence: int = 0) -> List[IOC]:
        with self._lock:
            fps = set(self._by_type.get(ioc_type, set()))
        results = []
        for fp in fps:
            ioc = self.get(fp)
            if ioc and ioc.confidence >= min_confidence:
                results.append(ioc)
        return sorted(results, key=lambda x: x.risk_score, reverse=True)

    def query_by_tag(self, tag: str) -> List[IOC]:
        with self._lock:
            fps = set(self._by_tag.get(tag, set()))
        return [ioc for fp in fps if (ioc := self.get(fp)) is not None]

    def query_by_severity(self, severity: Severity, min_confidence: int = 0) -> List[IOC]:
        with self._lock:
            fps = set(self._by_severity.get(severity, set()))
        return [
            ioc for fp in fps
            if (ioc := self.get(fp)) is not None and ioc.confidence >= min_confidence
        ]

    def query_by_source(self, source: str) -> List[IOC]:
        with self._lock:
            fps = set(self._by_source.get(source, set()))
        return [ioc for fp in fps if (ioc := self.get(fp)) is not None]

    def iter_all(self, include_expired: bool = False) -> Iterator[IOC]:
        with self._lock:
            fps = list(self._store.keys())
        for fp in fps:
            ioc = self._store.get(fp)
            if ioc is None:
                continue
            if not include_expired and ioc.is_expired:
                continue
            yield ioc

    def remove(self, fingerprint: str) -> bool:
        with self._lock:
            if fingerprint not in self._store:
                return False
            self._remove(fingerprint)
            return True

    def apply_confidence_decay(self, decay_factor: float = 0.95) -> int:
        """
        Apply time-based confidence decay to all IOCs.
        IOCs that haven't been seen recently lose confidence.
        Returns count of IOCs updated.
        """
        updated = 0
        now = datetime.now(timezone.utc)
        with self._lock:
            for ioc in self._store.values():
                if ioc.last_seen is None:
                    continue
                days_stale = (now - ioc.last_seen).total_seconds() / 86400
                if days_stale > 1:
                    new_conf = max(1, int(ioc.confidence * (decay_factor ** days_stale)))
                    if new_conf != ioc.confidence:
                        ioc.confidence = new_conf
                        ioc.updated_at = now
                        updated += 1
        return updated

    def gc(self) -> int:
        """Remove all expired IOCs. Returns count removed."""
        removed = 0
        with self._lock:
            expired = [fp for fp, ioc in self._store.items() if ioc.is_expired]
            for fp in expired:
                self._remove(fp)
                removed += 1
        self.stats["total_expired"] += removed
        self._last_gc = time.monotonic()
        logger.debug("GC removed %d expired IOCs", removed)
        return removed

    def size(self) -> int:
        with self._lock:
            return len(self._store)

    def summary(self) -> Dict:
        with self._lock:
            by_type = {t.value: len(fps) for t, fps in self._by_type.items() if fps}
            by_sev = {s.value: len(fps) for s, fps in self._by_severity.items() if fps}
        return {
            "total": self.size(),
            "by_type": by_type,
            "by_severity": by_sev,
            "stats": dict(self.stats),
        }

    # ------------------------------------------------------------------
    # Internal helpers

    def _remove(self, fp: str) -> None:
        ioc = self._store.pop(fp, None)
        if not ioc:
            return
        self._by_id.pop(ioc.id, None)
        self._by_type[ioc.ioc_type].discard(fp)
        self._by_source[ioc.source].discard(fp)
        self._by_severity[ioc.severity].discard(fp)
        for tag in ioc.tags:
            self._by_tag[tag].discard(fp)

    def _merge(self, existing: IOC, incoming: IOC) -> None:
        """Merge incoming IOC data into existing record."""
        existing.hit_count += incoming.hit_count
        existing.tags.update(incoming.tags)
        existing.mitre_techniques = list(
            set(existing.mitre_techniques) | set(incoming.mitre_techniques)
        )
        existing.related_iocs = list(
            set(existing.related_iocs) | set(incoming.related_iocs)
        )
        # Upgrade severity if incoming is higher
        if incoming.severity.score > existing.severity.score:
            existing.severity = incoming.severity
        # Take max confidence
        if incoming.confidence > existing.confidence:
            existing.confidence = incoming.confidence
        existing.updated_at = datetime.now(timezone.utc)
        if incoming.last_seen:
            existing.last_seen = incoming.last_seen

    def _evict_one(self) -> None:
        """Evict the IOC with lowest risk score when store is full."""
        if not self._store:
            return
        worst = min(self._store.items(), key=lambda kv: kv[1].risk_score)
        self._remove(worst[0])
        self.stats["total_evicted"] += 1

    def _maybe_gc(self) -> None:
        if time.monotonic() - self._last_gc > self._gc_interval:
            self.gc()
