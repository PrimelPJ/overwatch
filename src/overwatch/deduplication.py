"""
Alert deduplication and triage engine.
Detects duplicate alerts and correlates them with IOCs for prioritized triage.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from overwatch.models import AlertTriage, IOC, IOCType, Severity

logger = logging.getLogger(__name__)


@dataclass
class DedupWindow:
    """Sliding time window for deduplication."""
    window_seconds: int = 3600
    max_events: int = 1000

    def is_within_window(self, ts1: datetime, ts2: datetime) -> bool:
        delta = abs((ts1 - ts2).total_seconds())
        return delta <= self.window_seconds


@dataclass
class TriageDecision:
    alert_id: str
    verdict: str  # "new" | "duplicate" | "correlated" | "false_positive"
    priority: int  # 1 (critical) to 5 (info)
    duplicate_of: Optional[str] = None
    correlated_alerts: List[str] = field(default_factory=list)
    matched_iocs: List[IOC] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    suppressed: bool = False
    notes: str = ""


class AlertDeduplicator:
    """
    Deduplicates and triages security alerts using multiple matching strategies:

    1. Exact match: identical alert fingerprint
    2. Near-duplicate: same source + target within time window
    3. IOC correlation: same IOC matched in multiple alerts
    4. Semantic similarity: same title pattern with different parameters
    """

    # Patterns that normalize variable parts for semantic comparison
    _NORMALIZE_PATTERNS = [
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
        (re.compile(r"\b[0-9a-fA-F]{32,64}\b"), "<HASH>"),
        (re.compile(r"\bhttps?://[^\s]+"), "<URL>"),
        (re.compile(r"\b\d{4,}\b"), "<NUM>"),
        (re.compile(r"\b[0-9a-fA-F-]{36}\b"), "<UUID>"),
    ]

    def __init__(
        self,
        dedup_window: Optional[DedupWindow] = None,
        ioc_store: Optional[Dict[str, IOC]] = None,
    ) -> None:
        self._window = dedup_window or DedupWindow()
        self._ioc_store: Dict[str, IOC] = ioc_store or {}
        self._seen_fingerprints: Dict[str, AlertTriage] = {}
        self._seen_semantic: Dict[str, List[AlertTriage]] = defaultdict(list)
        self._ioc_alert_index: Dict[str, List[str]] = defaultdict(list)  # IOC fp -> alert ids
        self._alert_index: Dict[str, AlertTriage] = {}
        self._false_positive_patterns: Set[str] = set()

    def update_ioc_store(self, ioc_store: Dict[str, IOC]) -> None:
        self._ioc_store = ioc_store

    def add_false_positive_pattern(self, pattern: str) -> None:
        """Add a normalized title pattern that should be auto-suppressed."""
        self._false_positive_patterns.add(pattern)

    def process_alert(self, alert: AlertTriage) -> TriageDecision:
        """Process an incoming alert and return a triage decision."""
        fingerprint = self._compute_alert_fingerprint(alert)
        semantic_key = self._compute_semantic_key(alert)

        # Check false positive patterns
        if semantic_key in self._false_positive_patterns:
            alert.is_false_positive = True
            return TriageDecision(
                alert_id=alert.alert_id,
                verdict="false_positive",
                priority=5,
                suppressed=True,
                notes="Matched false positive pattern",
            )

        # Check exact duplicates
        if fingerprint in self._seen_fingerprints:
            existing = self._seen_fingerprints[fingerprint]
            if self._window.is_within_window(alert.created_at, existing.created_at):
                alert.is_duplicate = True
                alert.duplicate_of = existing.alert_id
                return TriageDecision(
                    alert_id=alert.alert_id,
                    verdict="duplicate",
                    priority=5,
                    duplicate_of=existing.alert_id,
                    suppressed=True,
                    notes=f"Exact duplicate of {existing.alert_id}",
                )

        # Check near-duplicate (same semantic key within window)
        near_dups = self._find_near_duplicates(semantic_key, alert)
        if near_dups:
            primary = near_dups[0]
            alert.is_duplicate = True
            alert.duplicate_of = primary.alert_id
            return TriageDecision(
                alert_id=alert.alert_id,
                verdict="duplicate",
                priority=max(1, alert.severity.score),
                duplicate_of=primary.alert_id,
                suppressed=True,
                notes=f"Near-duplicate of {primary.alert_id} ({len(near_dups)} similar alerts)",
            )

        # Match IOCs and correlate
        matched_iocs = self._match_iocs(alert)
        alert.matched_iocs = matched_iocs
        correlated = self._find_correlated_alerts(matched_iocs, alert.alert_id)

        priority = self._compute_priority(alert, matched_iocs)
        recommended = self._recommend_actions(alert, matched_iocs)

        # Index this alert
        self._seen_fingerprints[fingerprint] = alert
        self._seen_semantic[semantic_key].append(alert)
        self._alert_index[alert.alert_id] = alert
        for ioc in matched_iocs:
            self._ioc_alert_index[ioc.fingerprint].append(alert.alert_id)

        verdict = "correlated" if correlated else "new"
        return TriageDecision(
            alert_id=alert.alert_id,
            verdict=verdict,
            priority=priority,
            correlated_alerts=[a.alert_id for a in correlated],
            matched_iocs=matched_iocs,
            recommended_actions=recommended,
            notes=self._build_triage_notes(alert, matched_iocs, correlated),
        )

    def get_alert_cluster(self, alert_id: str) -> List[AlertTriage]:
        """Get all alerts correlated with the given alert."""
        alert = self._alert_index.get(alert_id)
        if not alert:
            return []

        cluster_ids: Set[str] = {alert_id}
        for ioc in alert.matched_iocs:
            for corr_id in self._ioc_alert_index.get(ioc.fingerprint, []):
                cluster_ids.add(corr_id)

        return [
            self._alert_index[aid]
            for aid in cluster_ids
            if aid in self._alert_index
        ]

    def get_dedup_stats(self) -> Dict[str, int]:
        return {
            "total_processed": len(self._alert_index),
            "unique_fingerprints": len(self._seen_fingerprints),
            "semantic_groups": len(self._seen_semantic),
            "ioc_correlations": sum(len(v) for v in self._ioc_alert_index.values()),
        }

    def _compute_alert_fingerprint(self, alert: AlertTriage) -> str:
        """Exact deduplication fingerprint."""
        key = f"{alert.source}:{alert.title}:{alert.severity.value}"
        if alert.matched_iocs:
            ioc_fp = ":".join(sorted(i.fingerprint for i in alert.matched_iocs))
            key += f":{ioc_fp}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _compute_semantic_key(self, alert: AlertTriage) -> str:
        """Normalized alert title for near-duplicate detection."""
        title = alert.title.lower()
        for pattern, replacement in self._NORMALIZE_PATTERNS:
            title = pattern.sub(replacement, title)
        return hashlib.sha256(f"{alert.source}:{title}".encode()).hexdigest()[:16]

    def _find_near_duplicates(
        self, semantic_key: str, alert: AlertTriage
    ) -> List[AlertTriage]:
        candidates = self._seen_semantic.get(semantic_key, [])
        return [
            a for a in candidates
            if self._window.is_within_window(alert.created_at, a.created_at)
        ]

    def _match_iocs(self, alert: AlertTriage) -> List[IOC]:
        """Extract IOC values from alert data and match against IOC store."""
        if not self._ioc_store:
            return []

        text_to_scan = f"{alert.title} {alert.description}"
        for v in alert.raw_data.values():
            if isinstance(v, str):
                text_to_scan += f" {v}"

        candidates = self._extract_observables_from_text(text_to_scan)
        matched = []
        for ioc_type, value in candidates:
            # Compute fingerprint and look up
            fp = hashlib.sha256(f"{ioc_type.value}:{value.lower()}".encode()).hexdigest()
            if fp in self._ioc_store:
                ioc = self._ioc_store[fp]
                if not ioc.is_expired:
                    ioc.record_hit()
                    matched.append(ioc)

        return matched

    def _extract_observables_from_text(
        self, text: str
    ) -> List[Tuple[IOCType, str]]:
        """Extract potential IOC values from free text."""
        results = []
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_re = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")
        url_re = re.compile(r"https?://[^\s\",]+")
        sha256_re = re.compile(r"\b[0-9a-fA-F]{64}\b")
        sha1_re = re.compile(r"\b[0-9a-fA-F]{40}\b")
        md5_re = re.compile(r"\b[0-9a-fA-F]{32}\b")

        for m in url_re.finditer(text):
            results.append((IOCType.URL, m.group()))
        for m in sha256_re.finditer(text):
            results.append((IOCType.FILE_HASH_SHA256, m.group()))
        for m in sha1_re.finditer(text):
            results.append((IOCType.FILE_HASH_SHA1, m.group()))
        for m in md5_re.finditer(text):
            results.append((IOCType.FILE_HASH_MD5, m.group()))
        for m in ip_re.finditer(text):
            results.append((IOCType.IPV4, m.group()))
        for m in domain_re.finditer(text):
            val = m.group()
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
                results.append((IOCType.DOMAIN, val))

        return results

    def _find_correlated_alerts(
        self, matched_iocs: List[IOC], exclude_alert_id: str
    ) -> List[AlertTriage]:
        """Find other alerts that match the same IOCs."""
        correlated_ids: Set[str] = set()
        for ioc in matched_iocs:
            for aid in self._ioc_alert_index.get(ioc.fingerprint, []):
                if aid != exclude_alert_id:
                    correlated_ids.add(aid)
        return [self._alert_index[aid] for aid in correlated_ids if aid in self._alert_index]

    def _compute_priority(self, alert: AlertTriage, matched_iocs: List[IOC]) -> int:
        """Compute triage priority 1 (highest) to 5 (lowest)."""
        base = 6 - alert.severity.score

        if matched_iocs:
            max_ioc_risk = max(ioc.risk_score for ioc in matched_iocs)
            if max_ioc_risk > 80:
                base = min(base, 1)
            elif max_ioc_risk > 60:
                base = min(base, 2)

        return max(1, min(5, base))

    def _recommend_actions(
        self, alert: AlertTriage, matched_iocs: List[IOC]
    ) -> List[str]:
        """Recommend response actions based on alert and IOC context."""
        actions = []
        if alert.severity in (Severity.CRITICAL, Severity.HIGH):
            actions.append("notify_soc")
            actions.append("create_ticket")

        ioc_types = {ioc.ioc_type for ioc in matched_iocs}
        if IOCType.IPV4 in ioc_types or IOCType.IPV6 in ioc_types:
            actions.append("block_ip")
        if IOCType.DOMAIN in ioc_types or IOCType.URL in ioc_types:
            actions.append("block_domain")
        if any(t in ioc_types for t in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256)):
            actions.append("quarantine_host")

        if alert.severity == Severity.CRITICAL:
            actions.append("isolate_endpoint")

        return list(dict.fromkeys(actions))  # deduplicate preserving order

    def _build_triage_notes(
        self,
        alert: AlertTriage,
        matched_iocs: List[IOC],
        correlated: List[AlertTriage],
    ) -> str:
        parts = []
        if matched_iocs:
            parts.append(f"Matched {len(matched_iocs)} IOC(s)")
            high_risk = [ioc for ioc in matched_iocs if ioc.risk_score > 70]
            if high_risk:
                parts.append(f"{len(high_risk)} high-risk indicator(s)")
        if correlated:
            parts.append(f"Correlated with {len(correlated)} existing alert(s)")
        return "; ".join(parts) if parts else "New unmatched alert"
