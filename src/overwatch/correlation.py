"""
IOC correlation engine.
Clusters related indicators into campaigns, detects attack patterns,
and scores relationships between observables.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from overwatch.models import IOC, IOCType, Severity, ThreatActor

logger = logging.getLogger(__name__)


# Relationships that carry positive correlation weight
RELATED_TYPES: Dict[IOCType, Set[IOCType]] = {
    IOCType.IPV4: {IOCType.DOMAIN, IOCType.URL, IOCType.NETWORK_TRAFFIC},
    IOCType.IPV6: {IOCType.DOMAIN, IOCType.URL, IOCType.NETWORK_TRAFFIC},
    IOCType.DOMAIN: {IOCType.IPV4, IOCType.IPV6, IOCType.URL, IOCType.EMAIL},
    IOCType.URL: {IOCType.DOMAIN, IOCType.IPV4, IOCType.FILE_HASH_SHA256},
    IOCType.FILE_HASH_MD5: {IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256},
    IOCType.FILE_HASH_SHA1: {IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA256},
    IOCType.FILE_HASH_SHA256: {IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1},
    IOCType.EMAIL: {IOCType.DOMAIN, IOCType.IPV4},
}


@dataclass
class CorrelationEdge:
    """Directed edge between two IOCs with relationship weight."""
    source_fp: str
    target_fp: str
    weight: float               # 0.0–1.0
    relationship: str           # "shares_infrastructure", "same_campaign", etc.
    evidence: List[str] = field(default_factory=list)


@dataclass
class Campaign:
    """
    A correlated cluster of IOCs attributed to a single threat campaign.
    """
    campaign_id: str
    name: str
    ioc_fingerprints: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    confidence: float = 0.0         # 0.0–1.0
    severity: Severity = Severity.MEDIUM
    actor: Optional[ThreatActor] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def size(self) -> int:
        return len(self.ioc_fingerprints)

    def merge(self, other: "Campaign") -> None:
        """Absorb another campaign cluster into this one."""
        self.ioc_fingerprints |= other.ioc_fingerprints
        self.mitre_techniques |= other.mitre_techniques
        self.tags |= other.tags
        # Take higher confidence and severity
        self.confidence = max(self.confidence, other.confidence)
        if other.severity.score > self.severity.score:
            self.severity = other.severity
        # Extend time window
        for ts in (other.first_seen, other.last_seen):
            if ts is None:
                continue
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts


class CorrelationEngine:
    """
    Correlates IOCs using:
    - Shared MITRE techniques
    - Overlapping tags
    - Shared infrastructure (IP/domain co-occurrence)
    - Explicit related_iocs links
    - Temporal proximity
    """

    def __init__(
        self,
        min_shared_tags: int = 2,
        min_shared_techniques: int = 1,
        min_edge_weight: float = 0.3,
    ) -> None:
        self._edges: List[CorrelationEdge] = []
        self._campaigns: Dict[str, Campaign] = {}
        # Union-Find for cluster management
        self._parent: Dict[str, str] = {}

        self.min_shared_tags = min_shared_tags
        self.min_shared_techniques = min_shared_techniques
        self.min_edge_weight = min_edge_weight

    # ------------------------------------------------------------------
    # Public API

    def correlate(self, iocs: List[IOC]) -> List[Campaign]:
        """
        Run full correlation pass over a list of IOCs.
        Returns discovered campaigns sorted by size descending.
        """
        self._edges.clear()
        self._parent.clear()

        # Initialize union-find
        for ioc in iocs:
            self._parent[ioc.fingerprint] = ioc.fingerprint

        # Build correlation edges
        for i, a in enumerate(iocs):
            for b in iocs[i + 1:]:
                edge = self._score_pair(a, b)
                if edge and edge.weight >= self.min_edge_weight:
                    self._edges.append(edge)
                    self._union(a.fingerprint, b.fingerprint)

        # Build campaigns from connected components
        clusters: Dict[str, Set[str]] = defaultdict(set)
        for ioc in iocs:
            root = self._find(ioc.fingerprint)
            clusters[root].add(ioc.fingerprint)

        # Map IOCs for quick access
        ioc_map = {ioc.fingerprint: ioc for ioc in iocs}

        campaigns = []
        for root, fps in clusters.items():
            if len(fps) < 2:
                continue
            campaign = self._build_campaign(root, fps, ioc_map)
            self._campaigns[campaign.campaign_id] = campaign
            campaigns.append(campaign)

        return sorted(campaigns, key=lambda c: c.size, reverse=True)

    def find_related(self, ioc: IOC, all_iocs: List[IOC], top_k: int = 10) -> List[Tuple[IOC, float]]:
        """Return top-k IOCs most strongly correlated with the given IOC."""
        scored: List[Tuple[IOC, float]] = []
        for candidate in all_iocs:
            if candidate.fingerprint == ioc.fingerprint:
                continue
            edge = self._score_pair(ioc, candidate)
            if edge and edge.weight > 0:
                scored.append((candidate, edge.weight))
        return sorted(scored, key=lambda x: x[1], reverse=True)[:top_k]

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)

    def all_campaigns(self) -> List[Campaign]:
        return list(self._campaigns.values())

    # ------------------------------------------------------------------
    # Scoring

    def _score_pair(self, a: IOC, b: IOC) -> Optional[CorrelationEdge]:
        weight = 0.0
        evidence: List[str] = []

        # Explicit related_iocs links (strongest signal)
        if b.fingerprint in a.related_iocs or a.fingerprint in b.related_iocs:
            weight += 0.6
            evidence.append("explicit_link")

        # Shared MITRE techniques
        shared_techs = set(a.mitre_techniques) & set(b.mitre_techniques)
        if shared_techs:
            tech_score = min(0.4, len(shared_techs) * 0.15)
            weight += tech_score
            evidence.append(f"shared_techniques:{','.join(sorted(shared_techs))}")

        # Shared tags
        shared_tags = a.tags & b.tags
        if len(shared_tags) >= self.min_shared_tags:
            tag_score = min(0.3, len(shared_tags) * 0.08)
            weight += tag_score
            evidence.append(f"shared_tags:{','.join(sorted(shared_tags))}")

        # Complementary type relationship (e.g., IP resolves domain)
        related = RELATED_TYPES.get(a.ioc_type, set())
        if b.ioc_type in related:
            weight += 0.15
            evidence.append(f"infrastructure:{a.ioc_type.value}->{b.ioc_type.value}")

        # Same source feed
        if a.source == b.source:
            weight += 0.1
            evidence.append(f"same_source:{a.source}")

        # Temporal proximity (both seen within 1 hour of each other)
        if a.first_seen and b.first_seen:
            delta = abs((a.first_seen - b.first_seen).total_seconds())
            if delta < 3600:
                proximity_score = 0.1 * (1 - delta / 3600)
                weight += proximity_score
                evidence.append("temporal_proximity")

        if weight == 0:
            return None

        return CorrelationEdge(
            source_fp=a.fingerprint,
            target_fp=b.fingerprint,
            weight=min(1.0, weight),
            relationship=self._classify_relationship(evidence),
            evidence=evidence,
        )

    @staticmethod
    def _classify_relationship(evidence: List[str]) -> str:
        if any("explicit_link" in e for e in evidence):
            return "known_association"
        if any("infrastructure" in e for e in evidence):
            return "shares_infrastructure"
        if any("shared_techniques" in e for e in evidence):
            return "same_ttp"
        if any("temporal" in e for e in evidence):
            return "temporal_cluster"
        return "correlated"

    def _build_campaign(
        self, root: str, fps: Set[str], ioc_map: Dict[str, IOC]
    ) -> Campaign:
        campaign_id = hashlib.sha256(
            "|".join(sorted(fps)).encode()
        ).hexdigest()[:16]

        iocs_in_cluster = [ioc_map[fp] for fp in fps if fp in ioc_map]
        all_techniques: Set[str] = set()
        all_tags: Set[str] = set()
        timestamps = []
        max_severity = Severity.LOW
        total_confidence = 0.0

        for ioc in iocs_in_cluster:
            all_techniques.update(ioc.mitre_techniques)
            all_tags.update(ioc.tags)
            if ioc.first_seen:
                timestamps.append(ioc.first_seen)
            if ioc.last_seen:
                timestamps.append(ioc.last_seen)
            if ioc.severity.score > max_severity.score:
                max_severity = ioc.severity
            total_confidence += ioc.adjusted_confidence

        avg_confidence = (total_confidence / len(iocs_in_cluster)) / 100.0 if iocs_in_cluster else 0.0

        # Boost confidence with cluster size
        size_boost = min(0.2, len(fps) * 0.02)

        return Campaign(
            campaign_id=campaign_id,
            name=f"Campaign-{campaign_id[:8].upper()}",
            ioc_fingerprints=fps,
            mitre_techniques=all_techniques,
            tags=all_tags,
            confidence=min(1.0, avg_confidence + size_boost),
            severity=max_severity,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    # ------------------------------------------------------------------
    # Union-Find

    def _find(self, x: str) -> str:
        while self._parent.get(x, x) != x:
            # Path compression
            parent = self._parent.get(x, x)
            self._parent[x] = self._parent.get(parent, parent)
            x = self._parent[x]
        return x

    def _union(self, x: str, y: str) -> None:
        rx, ry = self._find(x), self._find(y)
        if rx != ry:
            self._parent[ry] = rx
