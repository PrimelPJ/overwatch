"""
Threat hunting module for proactive IOC investigation and campaign discovery.
Provides a query DSL, hypothesis tracking, temporal pattern analysis,
and hunt session management for structured threat hunting operations.
"""

from __future__ import annotations

import math
import statistics
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from overwatch.models import IOC, IOCType, Severity, TLPLevel


class HuntStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class HypothesisOutcome(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    PENDING = "pending"


@dataclass
class HuntQuery:
    """Structured query for filtering IOCs from the hunt store."""

    ioc_types: Optional[List[IOCType]] = None
    severities: Optional[List[Severity]] = None
    tags: Optional[Set[str]] = None          # OR match: any tag matches
    tags_all: Optional[Set[str]] = None      # AND match: all tags must be present
    sources: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    confidence_min: int = 0
    confidence_max: int = 100
    first_seen_after: Optional[datetime] = None
    first_seen_before: Optional[datetime] = None
    last_seen_after: Optional[datetime] = None
    value_contains: Optional[str] = None
    hit_count_min: int = 0
    limit: int = 1000

    def matches(self, ioc: IOC) -> bool:
        if self.ioc_types and ioc.ioc_type not in self.ioc_types:
            return False
        if self.severities and ioc.severity not in self.severities:
            return False
        if self.tags and not (ioc.tags & self.tags):
            return False
        if self.tags_all and not self.tags_all.issubset(ioc.tags):
            return False
        if self.sources and ioc.source not in self.sources:
            return False
        if self.mitre_techniques:
            if not any(t in ioc.mitre_techniques for t in self.mitre_techniques):
                return False
        if not (self.confidence_min <= ioc.confidence <= self.confidence_max):
            return False
        if self.value_contains and self.value_contains.lower() not in ioc.value.lower():
            return False
        if self.hit_count_min and ioc.hit_count < self.hit_count_min:
            return False
        first_seen = getattr(ioc, "first_seen", None)
        if first_seen:
            if self.first_seen_after and first_seen < self.first_seen_after:
                return False
            if self.first_seen_before and first_seen > self.first_seen_before:
                return False
        last_seen = getattr(ioc, "last_seen", None)
        if last_seen and self.last_seen_after:
            if last_seen < self.last_seen_after:
                return False
        return True


@dataclass
class TemporalPattern:
    """Temporal activity pattern detected in a set of IOCs."""

    pattern_type: str          # burst | steady | sporadic | escalating
    start_time: datetime
    end_time: datetime
    peak_count: int
    average_count: float
    std_dev: float
    hourly_histogram: Dict[int, int]   # hour-of-day -> count
    daily_histogram: Dict[str, int]    # YYYY-MM-DD -> count
    burst_windows: List[Tuple[datetime, datetime, int]]  # (start, end, count)
    description: str = ""


@dataclass
class HuntHypothesis:
    """A structured hypothesis for a threat hunt operation."""

    hypothesis_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    hunt_query: Optional[HuntQuery] = None
    expected_ioc_types: List[IOCType] = field(default_factory=list)
    outcome: HypothesisOutcome = HypothesisOutcome.PENDING
    evidence_ioc_ids: List[str] = field(default_factory=list)
    analyst_notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None

    def resolve(self, outcome: HypothesisOutcome, notes: str = "") -> None:
        self.outcome = outcome
        self.analyst_notes = notes
        self.resolved_at = datetime.now(timezone.utc)


@dataclass
class IOCCluster:
    """A cluster of related IOCs grouped by tag/technique overlap."""

    cluster_id: str
    iocs: List[IOC]
    shared_tags: Set[str]
    shared_techniques: List[str]
    dominant_severity: Severity
    source_diversity: int
    cohesion_score: float  # 0.0-1.0: how tightly related the IOCs are

    @property
    def size(self) -> int:
        return len(self.iocs)

    @property
    def ioc_types(self) -> Set[IOCType]:
        return {ioc.ioc_type for ioc in self.iocs}


@dataclass
class HuntSession:
    """A complete threat hunt session grouping hypotheses and findings."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    analyst: str = ""
    status: HuntStatus = HuntStatus.OPEN
    hypotheses: List[HuntHypothesis] = field(default_factory=list)
    findings: List[IOC] = field(default_factory=list)
    clusters: List[IOCCluster] = field(default_factory=list)
    temporal_patterns: List[TemporalPattern] = field(default_factory=list)
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_hypothesis(self, hypothesis: HuntHypothesis) -> None:
        self.hypotheses.append(hypothesis)

    def record_finding(self, ioc: IOC) -> None:
        if not any(f.ioc_id == ioc.ioc_id for f in self.findings):
            self.findings.append(ioc)

    def finalize(self, notes: str = "") -> Dict[str, Any]:
        self.status = HuntStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.notes = notes
        confirmed = sum(
            1 for h in self.hypotheses
            if h.outcome == HypothesisOutcome.CONFIRMED
        )
        return {
            "session_id": self.session_id,
            "name": self.name,
            "duration_seconds": (
                (self.completed_at - self.created_at).total_seconds()
            ),
            "hypotheses_total": len(self.hypotheses),
            "hypotheses_confirmed": confirmed,
            "findings_count": len(self.findings),
            "clusters_found": len(self.clusters),
            "temporal_patterns": len(self.temporal_patterns),
            "status": self.status.value,
        }


class ThreatHunter:
    """
    Core threat hunting engine.

    Accepts a list of IOC objects (sourced from IOCStore or any iterable)
    and provides query, clustering, and temporal analysis capabilities.
    """

    def __init__(self, iocs: List[IOC]) -> None:
        self._iocs = list(iocs)
        self._index_by_type: Dict[IOCType, List[IOC]] = defaultdict(list)
        self._index_by_source: Dict[str, List[IOC]] = defaultdict(list)
        self._index_by_tag: Dict[str, List[IOC]] = defaultdict(list)
        self._build_indexes()

    def _build_indexes(self) -> None:
        for ioc in self._iocs:
            self._index_by_type[ioc.ioc_type].append(ioc)
            self._index_by_source[ioc.source].append(ioc)
            for tag in ioc.tags:
                self._index_by_tag[tag].append(ioc)

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def execute_hunt(self, query: HuntQuery) -> List[IOC]:
        """Return all IOCs matching the given HuntQuery."""
        candidates: List[IOC] = []

        # Use type index for fast pre-filtering when possible
        if query.ioc_types:
            for t in query.ioc_types:
                candidates.extend(self._index_by_type.get(t, []))
            candidates = list({id(c): c for c in candidates}.values())
        else:
            candidates = list(self._iocs)

        results = [ioc for ioc in candidates if query.matches(ioc)]
        return results[: query.limit]

    def search_by_value_pattern(self, pattern: str, ioc_types: Optional[List[IOCType]] = None) -> List[IOC]:
        """Case-insensitive substring search across IOC values."""
        query = HuntQuery(value_contains=pattern, ioc_types=ioc_types)
        return self.execute_hunt(query)

    def find_related(self, ioc: IOC, max_results: int = 50) -> List[IOC]:
        """
        Find IOCs related to the given indicator by shared tags,
        MITRE techniques, or source.
        """
        related: Dict[str, Tuple[IOC, int]] = {}  # ioc_id -> (ioc, score)

        def _score(candidate: IOC) -> int:
            score = 0
            shared_tags = ioc.tags & candidate.tags
            score += len(shared_tags) * 3
            shared_techniques = set(ioc.mitre_techniques) & set(candidate.mitre_techniques)
            score += len(shared_techniques) * 5
            if candidate.source == ioc.source:
                score += 2
            return score

        for tag in ioc.tags:
            for candidate in self._index_by_tag.get(tag, []):
                if candidate.ioc_id != ioc.ioc_id:
                    s = _score(candidate)
                    if s > 0:
                        cid = candidate.ioc_id
                        if cid not in related or related[cid][1] < s:
                            related[cid] = (candidate, s)

        sorted_related = sorted(related.values(), key=lambda x: x[1], reverse=True)
        return [ioc for ioc, _ in sorted_related[:max_results]]

    # ------------------------------------------------------------------
    # Temporal pattern analysis
    # ------------------------------------------------------------------

    def analyze_temporal_patterns(
        self,
        iocs: List[IOC],
        burst_threshold_multiplier: float = 2.5,
        window_hours: int = 6,
    ) -> TemporalPattern:
        """
        Analyse the temporal distribution of IOC observations.

        Detects burst windows where activity exceeds the mean by
        `burst_threshold_multiplier` standard deviations.
        """
        timestamped: List[datetime] = []
        for ioc in iocs:
            ts = getattr(ioc, "first_seen", None) or getattr(ioc, "created_at", None)
            if ts and isinstance(ts, datetime):
                timestamped.append(ts)

        if not timestamped:
            now = datetime.now(timezone.utc)
            return TemporalPattern(
                pattern_type="unknown",
                start_time=now,
                end_time=now,
                peak_count=0,
                average_count=0.0,
                std_dev=0.0,
                hourly_histogram={},
                daily_histogram={},
                burst_windows=[],
                description="No timestamped IOCs available for analysis.",
            )

        timestamped.sort()
        start_time = timestamped[0]
        end_time = timestamped[-1]

        # Build daily histogram
        daily_hist: Dict[str, int] = Counter()
        hourly_hist: Dict[int, int] = Counter()
        for ts in timestamped:
            daily_hist[ts.strftime("%Y-%m-%d")] += 1
            hourly_hist[ts.hour] += 1

        daily_counts = list(daily_hist.values())
        mean_daily = statistics.mean(daily_counts) if daily_counts else 0.0
        std_daily = statistics.stdev(daily_counts) if len(daily_counts) > 1 else 0.0
        peak_count = max(daily_counts) if daily_counts else 0

        # Detect burst windows using sliding window
        burst_windows: List[Tuple[datetime, datetime, int]] = []
        window_delta = timedelta(hours=window_hours)
        if len(timestamped) >= 3:
            threshold = mean_daily + burst_threshold_multiplier * std_daily
            i = 0
            while i < len(timestamped):
                window_end = timestamped[i] + window_delta
                window_iocs = [
                    t for t in timestamped[i:]
                    if t <= window_end
                ]
                window_count = len(window_iocs)
                # Approximate daily rate for this window
                daily_rate = window_count * (24 / window_hours)
                if daily_rate > threshold and window_count > 2:
                    burst_windows.append((timestamped[i], window_end, window_count))
                    i += window_count  # skip ahead past burst
                else:
                    i += 1

        # Classify pattern type
        if not burst_windows:
            if std_daily < mean_daily * 0.3:
                pattern_type = "steady"
            else:
                pattern_type = "sporadic"
        else:
            # Check if the most recent days are the busiest (escalating)
            if daily_counts and len(daily_counts) >= 3:
                recent_mean = statistics.mean(daily_counts[-3:])
                early_mean = statistics.mean(daily_counts[:3])
                pattern_type = "escalating" if recent_mean > early_mean * 1.5 else "burst"
            else:
                pattern_type = "burst"

        duration_desc = (
            f"{(end_time - start_time).days}d span"
            if end_time > start_time
            else "single point"
        )
        description = (
            f"{pattern_type.capitalize()} activity over {duration_desc}. "
            f"Peak: {peak_count}/day, avg: {mean_daily:.1f}/day, "
            f"{len(burst_windows)} burst window(s) detected."
        )

        return TemporalPattern(
            pattern_type=pattern_type,
            start_time=start_time,
            end_time=end_time,
            peak_count=peak_count,
            average_count=mean_daily,
            std_dev=std_daily,
            hourly_histogram=dict(hourly_hist),
            daily_histogram=dict(daily_hist),
            burst_windows=burst_windows,
            description=description,
        )

    # ------------------------------------------------------------------
    # Clustering
    # ------------------------------------------------------------------

    def cluster_by_campaign(
        self,
        iocs: List[IOC],
        min_shared_tags: int = 1,
        min_cluster_size: int = 2,
    ) -> List[IOCCluster]:
        """
        Group IOCs into clusters based on shared tag and MITRE technique overlap.

        Uses a greedy single-pass union-find approach.
        """
        if not iocs:
            return []

        # Build adjacency: two IOCs are linked if they share >= min_shared_tags tags
        # or any MITRE technique
        parent: Dict[str, str] = {ioc.ioc_id: ioc.ioc_id for ioc in iocs}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        ioc_map = {ioc.ioc_id: ioc for ioc in iocs}

        # Compare pairwise — O(n^2) but acceptable for hunt-sized sets (<10k)
        ioc_list = list(iocs)
        for i in range(len(ioc_list)):
            for j in range(i + 1, len(ioc_list)):
                a, b = ioc_list[i], ioc_list[j]
                shared_tags = a.tags & b.tags
                shared_techniques = set(a.mitre_techniques) & set(b.mitre_techniques)
                if len(shared_tags) >= min_shared_tags or shared_techniques:
                    union(a.ioc_id, b.ioc_id)

        # Collect clusters
        groups: Dict[str, List[IOC]] = defaultdict(list)
        for ioc in iocs:
            groups[find(ioc.ioc_id)].append(ioc)

        clusters: List[IOCCluster] = []
        for cluster_root, members in groups.items():
            if len(members) < min_cluster_size:
                continue

            all_tags: List[Set[str]] = [ioc.tags for ioc in members]
            shared_tags = all_tags[0].copy()
            for tag_set in all_tags[1:]:
                shared_tags &= tag_set

            technique_counter: Counter = Counter()
            for ioc in members:
                for t in ioc.mitre_techniques:
                    technique_counter[t] += 1
            shared_techniques = [
                t for t, cnt in technique_counter.items()
                if cnt >= max(2, len(members) // 2)
            ]

            severity_counter: Counter = Counter(ioc.severity for ioc in members)
            dominant_severity = severity_counter.most_common(1)[0][0]

            sources = {ioc.source for ioc in members}

            # Cohesion: ratio of shared tags to total unique tags across cluster
            all_unique_tags: Set[str] = set()
            for ioc in members:
                all_unique_tags |= ioc.tags
            cohesion = len(shared_tags) / max(len(all_unique_tags), 1)

            clusters.append(IOCCluster(
                cluster_id=cluster_root[:8],
                iocs=members,
                shared_tags=shared_tags,
                shared_techniques=shared_techniques,
                dominant_severity=dominant_severity,
                source_diversity=len(sources),
                cohesion_score=round(cohesion, 4),
            ))

        return sorted(clusters, key=lambda c: c.size, reverse=True)

    # ------------------------------------------------------------------
    # Hunt session management
    # ------------------------------------------------------------------

    def create_session(self, name: str, analyst: str = "") -> HuntSession:
        return HuntSession(name=name, analyst=analyst)

    def run_hypothesis(
        self,
        session: HuntSession,
        hypothesis: HuntHypothesis,
    ) -> List[IOC]:
        """
        Execute a hypothesis's embedded query against the IOC corpus,
        record findings in the session, and return matching IOCs.
        """
        session.add_hypothesis(hypothesis)
        session.status = HuntStatus.IN_PROGRESS
        if hypothesis.hunt_query is None:
            return []
        findings = self.execute_hunt(hypothesis.hunt_query)
        hypothesis.evidence_ioc_ids = [ioc.ioc_id for ioc in findings]
        for ioc in findings:
            session.record_finding(ioc)
        return findings

    def enrich_session(
        self,
        session: HuntSession,
        cluster_min_size: int = 2,
    ) -> None:
        """
        Run clustering and temporal analysis on a session's findings
        and attach results to the session object.
        """
        if not session.findings:
            return
        session.clusters = self.cluster_by_campaign(
            session.findings, min_cluster_size=cluster_min_size
        )
        session.temporal_patterns = [
            self.analyze_temporal_patterns(session.findings)
        ]
