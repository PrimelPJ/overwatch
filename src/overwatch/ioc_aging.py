"""
IOC lifecycle management: aging, confidence decay, TTL enforcement, and archival.
Handles time-based degradation of indicator reliability and automated expiry.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from overwatch.models import IOC, IOCType, Severity

logger = logging.getLogger(__name__)


class DecayFunction(str, Enum):
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    STEP = "step"
    LOGARITHMIC = "logarithmic"


@dataclass
class AgingPolicy:
    """
    Per-IOC-type policy controlling confidence decay and TTL.
    """
    ioc_type: Optional[IOCType] = None  # None = applies to all types

    # Base TTL in seconds
    base_ttl: int = 86400 * 7  # 7 days

    # Confidence decay per day (absolute points 0-100)
    daily_decay_rate: float = 5.0

    # Minimum confidence before archival
    archival_threshold: int = 10

    # Extend TTL by this many seconds on each observed hit
    hit_ttl_extension: int = 3600 * 6  # 6 hours per hit

    # Cap on TTL extensions (prevents unbounded extension)
    max_ttl: int = 86400 * 30  # 30 days

    # Decay function type
    decay_function: DecayFunction = DecayFunction.EXPONENTIAL

    # IOC types that get longer default TTLs (infrastructure vs ephemeral)
    # e.g., file hashes decay slower than IPs
    severity_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.75,
        "info": 0.5,
    })


# Default policies per IOC type
DEFAULT_POLICIES: Dict[IOCType, AgingPolicy] = {
    IOCType.IPV4: AgingPolicy(
        ioc_type=IOCType.IPV4,
        base_ttl=86400 * 3,          # IPs rotate - 3 days
        daily_decay_rate=10.0,
        archival_threshold=15,
        hit_ttl_extension=3600 * 2,
        max_ttl=86400 * 14,
        decay_function=DecayFunction.EXPONENTIAL,
    ),
    IOCType.IPV6: AgingPolicy(
        ioc_type=IOCType.IPV6,
        base_ttl=86400 * 3,
        daily_decay_rate=10.0,
        archival_threshold=15,
        hit_ttl_extension=3600 * 2,
        max_ttl=86400 * 14,
        decay_function=DecayFunction.EXPONENTIAL,
    ),
    IOCType.DOMAIN: AgingPolicy(
        ioc_type=IOCType.DOMAIN,
        base_ttl=86400 * 14,         # Domains persist longer
        daily_decay_rate=3.0,
        archival_threshold=10,
        hit_ttl_extension=3600 * 12,
        max_ttl=86400 * 60,
        decay_function=DecayFunction.LOGARITHMIC,
    ),
    IOCType.URL: AgingPolicy(
        ioc_type=IOCType.URL,
        base_ttl=86400 * 7,
        daily_decay_rate=7.0,
        archival_threshold=10,
        hit_ttl_extension=3600 * 4,
        max_ttl=86400 * 21,
        decay_function=DecayFunction.EXPONENTIAL,
    ),
    IOCType.FILE_HASH_MD5: AgingPolicy(
        ioc_type=IOCType.FILE_HASH_MD5,
        base_ttl=86400 * 90,         # File hashes don't rotate
        daily_decay_rate=0.5,
        archival_threshold=5,
        hit_ttl_extension=86400,
        max_ttl=86400 * 365,
        decay_function=DecayFunction.LINEAR,
    ),
    IOCType.FILE_HASH_SHA256: AgingPolicy(
        ioc_type=IOCType.FILE_HASH_SHA256,
        base_ttl=86400 * 90,
        daily_decay_rate=0.3,
        archival_threshold=5,
        hit_ttl_extension=86400,
        max_ttl=86400 * 365,
        decay_function=DecayFunction.LINEAR,
    ),
    IOCType.CVE: AgingPolicy(
        ioc_type=IOCType.CVE,
        base_ttl=86400 * 180,        # CVEs are persistent
        daily_decay_rate=0.1,
        archival_threshold=2,
        hit_ttl_extension=86400 * 7,
        max_ttl=86400 * 730,
        decay_function=DecayFunction.STEP,
    ),
}

_FALLBACK_POLICY = AgingPolicy()


@dataclass
class AgingResult:
    ioc_fingerprint: str
    original_confidence: int
    new_confidence: float
    confidence_delta: float
    days_old: float
    should_archive: bool
    ttl_remaining_seconds: float
    applied_policy: str


class IOCAgingEngine:
    """
    Applies time-based confidence decay and TTL management to IOC indicators.

    Confidence decay models:
    - Linear: constant points/day reduction
    - Exponential: percentage-based decay (half-life style)
    - Logarithmic: fast initial decay that slows over time
    - Step: discrete confidence tiers based on age brackets

    Additional modifiers:
    - Hit count: each new observation extends TTL and boosts confidence
    - False positive feedback: accelerates decay and lowers floor
    - Source reliability: multiplier based on feed reputation
    """

    def __init__(self) -> None:
        self._policies: Dict[IOCType, AgingPolicy] = dict(DEFAULT_POLICIES)
        self._global_policy = _FALLBACK_POLICY
        self._source_reliability: Dict[str, float] = {}  # source -> 0.0-1.0
        self._archived: List[str] = []  # fingerprints

    def set_policy(self, ioc_type: IOCType, policy: AgingPolicy) -> None:
        self._policies[ioc_type] = policy

    def set_global_policy(self, policy: AgingPolicy) -> None:
        self._global_policy = policy

    def set_source_reliability(self, source: str, reliability: float) -> None:
        if not 0.0 <= reliability <= 1.0:
            raise ValueError(f"Reliability must be 0.0-1.0, got {reliability}")
        self._source_reliability[source] = reliability

    def _get_policy(self, ioc: IOC) -> AgingPolicy:
        return self._policies.get(ioc.ioc_type, self._global_policy)

    def _compute_decay(
        self,
        days_old: float,
        original_confidence: int,
        policy: AgingPolicy,
        severity: Severity,
    ) -> float:
        """Apply the policy's decay function to compute current confidence."""
        sev_mult = policy.severity_multipliers.get(severity.value, 1.0)
        # Slower decay for higher severity indicators
        effective_decay = policy.daily_decay_rate / sev_mult

        if policy.decay_function == DecayFunction.LINEAR:
            decayed = original_confidence - (effective_decay * days_old)

        elif policy.decay_function == DecayFunction.EXPONENTIAL:
            # Half-life: confidence halves every (0.693/rate)*days
            half_life = math.log(2) / (effective_decay / 100.0)
            decayed = original_confidence * (0.5 ** (days_old / half_life))

        elif policy.decay_function == DecayFunction.LOGARITHMIC:
            # Fast early decay, slower later: c - rate*ln(1+days)
            decayed = original_confidence - (effective_decay * math.log1p(days_old))

        elif policy.decay_function == DecayFunction.STEP:
            # Tiered decay: weekly steps
            weeks = int(days_old / 7)
            step_decay = effective_decay * 2.0  # larger per step
            decayed = original_confidence - (step_decay * weeks)

        else:
            decayed = original_confidence

        return max(0.0, min(float(original_confidence), decayed))

    def compute_current_confidence(self, ioc: IOC, as_of: Optional[datetime] = None) -> float:
        """Compute the time-adjusted confidence for an IOC."""
        now = as_of or datetime.now(timezone.utc)
        policy = self._get_policy(ioc)

        created = ioc.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days_old = max(0.0, (now - created).total_seconds() / 86400.0)

        base_conf = self._compute_decay(
            days_old=days_old,
            original_confidence=ioc.confidence,
            policy=policy,
            severity=ioc.severity,
        )

        # Hits bump confidence back up, capped at original
        if ioc.hit_count > 0 and ioc.last_seen:
            last_seen = ioc.last_seen
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            days_since_last_hit = max(0.0, (now - last_seen).total_seconds() / 86400.0)
            # Recency bonus decays quickly
            recency_bonus = min(15.0, ioc.hit_count * 3.0) * math.exp(-days_since_last_hit * 0.5)
            base_conf = min(float(ioc.confidence), base_conf + recency_bonus)

        # False positive penalty
        total_observations = ioc.hit_count + ioc.false_positive_count
        if total_observations > 0:
            fp_rate = ioc.false_positive_count / total_observations
            base_conf *= (1.0 - fp_rate * 0.8)

        # Source reliability multiplier (default 1.0 = no penalty when source unknown)
        reliability = self._source_reliability.get(ioc.source, 1.0)
        base_conf *= reliability

        return max(0.0, min(100.0, base_conf))

    def age_ioc(self, ioc: IOC, as_of: Optional[datetime] = None) -> AgingResult:
        """Apply aging to a single IOC and return the result."""
        now = as_of or datetime.now(timezone.utc)
        policy = self._get_policy(ioc)

        created = ioc.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days_old = (now - created).total_seconds() / 86400.0

        new_confidence = self.compute_current_confidence(ioc, as_of=now)
        confidence_delta = new_confidence - ioc.confidence

        # Compute TTL
        effective_ttl = min(ioc.ttl_seconds, policy.max_ttl)
        age_seconds = (now - created).total_seconds()
        ttl_remaining = max(0.0, effective_ttl - age_seconds)

        # Check if this IOC should be archived
        is_expired = ttl_remaining <= 0
        below_threshold = new_confidence < policy.archival_threshold
        should_archive = is_expired or below_threshold

        if should_archive and ioc.fingerprint not in self._archived:
            self._archived.append(ioc.fingerprint)
            logger.info(
                "IOC %s (%s) marked for archival: expired=%s, confidence=%.1f",
                ioc.value, ioc.ioc_type.value, is_expired, new_confidence
            )

        return AgingResult(
            ioc_fingerprint=ioc.fingerprint,
            original_confidence=ioc.confidence,
            new_confidence=new_confidence,
            confidence_delta=confidence_delta,
            days_old=days_old,
            should_archive=should_archive,
            ttl_remaining_seconds=ttl_remaining,
            applied_policy=policy.ioc_type.value if policy.ioc_type else "global",
        )

    def age_collection(
        self,
        iocs: List[IOC],
        as_of: Optional[datetime] = None,
        prune: bool = False,
    ) -> Tuple[List[AgingResult], List[IOC]]:
        """
        Age an entire collection of IOCs.

        Returns:
            (results, active_iocs) where active_iocs excludes archived ones if prune=True
        """
        now = as_of or datetime.now(timezone.utc)
        results = []
        active = []

        for ioc in iocs:
            result = self.age_ioc(ioc, as_of=now)
            results.append(result)
            if not (prune and result.should_archive):
                active.append(ioc)

        archived_count = sum(1 for r in results if r.should_archive)
        if archived_count:
            logger.info("Aged %d IOCs: %d marked for archival", len(iocs), archived_count)

        return results, active

    def apply_hit_extension(self, ioc: IOC) -> int:
        """Record a new observation hit and extend the IOC's TTL."""
        policy = self._get_policy(ioc)
        new_ttl = min(ioc.ttl_seconds + policy.hit_ttl_extension, policy.max_ttl)
        ioc.ttl_seconds = new_ttl
        ioc.record_hit()
        return new_ttl

    def bulk_prune(
        self,
        iocs: List[IOC],
        as_of: Optional[datetime] = None,
    ) -> Tuple[List[IOC], List[str]]:
        """
        Remove expired and low-confidence IOCs.
        Returns (surviving_iocs, pruned_fingerprints).
        """
        _, active = self.age_collection(iocs, as_of=as_of, prune=True)
        pruned = [
            ioc.fingerprint for ioc in iocs
            if ioc.fingerprint not in {a.fingerprint for a in active}
        ]
        return active, pruned

    def get_confidence_forecast(
        self,
        ioc: IOC,
        days_ahead: int = 30,
        interval_days: int = 1,
    ) -> List[Tuple[datetime, float]]:
        """Compute confidence trajectory over the next N days."""
        now = datetime.now(timezone.utc)
        forecast = []
        for d in range(0, days_ahead + 1, interval_days):
            future = now + timedelta(days=d)
            conf = self.compute_current_confidence(ioc, as_of=future)
            forecast.append((future, conf))
        return forecast

    @property
    def archived_fingerprints(self) -> List[str]:
        return list(self._archived)

    def clear_archived(self) -> int:
        count = len(self._archived)
        self._archived.clear()
        return count
