"""
IOC reputation aggregator: cross-feed confidence weighting and Bayesian consensus scoring.

Aggregates IOC reputation signals from multiple threat intelligence feeds,
weights by historical feed reliability via Beta distribution Bayesian updates,
and produces consensus confidence scores when multiple feeds report the same IOC.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

from overwatch.models import IOC, IOCType, Severity

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


@dataclass
class FeedReliabilityRecord:
    """
    Tracks a feed's historical accuracy using a Beta distribution.

    Alpha = number of confirmed true positives (+ prior).
    Beta  = number of confirmed false positives (+ prior).

    The mean of Beta(alpha, beta) gives the expected precision of the feed.
    """
    feed_name: str
    alpha: float = 3.0   # optimistic prior: start with some trust
    beta: float = 1.0
    total_verified: int = 0
    true_positives: int = 0
    false_positives: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def reliability_score(self) -> float:
        """Expected precision: mean of Beta(alpha, beta) scaled to 0-100."""
        return (self.alpha / (self.alpha + self.beta)) * 100.0

    @property
    def uncertainty(self) -> float:
        """
        Variance of the Beta distribution, normalized.
        High variance = low trust = feed hasn't been verified enough.
        """
        ab = self.alpha + self.beta
        variance = (self.alpha * self.beta) / (ab * ab * (ab + 1))
        return math.sqrt(variance)

    def update_true_positive(self) -> None:
        """IOC from this feed was confirmed malicious."""
        self.alpha += 1.0
        self.true_positives += 1
        self.total_verified += 1
        self.updated_at = datetime.now(timezone.utc)

    def update_false_positive(self) -> None:
        """IOC from this feed was confirmed benign."""
        self.beta += 1.0
        self.false_positives += 1
        self.total_verified += 1
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "feed_name": self.feed_name,
            "alpha": self.alpha,
            "beta": self.beta,
            "reliability_score": round(self.reliability_score, 2),
            "uncertainty": round(self.uncertainty, 4),
            "total_verified": self.total_verified,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class ReputationVote:
    """
    One feed's reputation assessment for a given IOC.
    """
    feed_name: str
    ioc_fingerprint: str
    verdict: Verdict
    raw_confidence: int     # 0-100, as reported by the feed
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def age_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.timestamp).total_seconds()


@dataclass
class ConsensusScore:
    """
    Multi-feed consensus result for a single IOC.
    """
    ioc_fingerprint: str
    ioc_value: str
    ioc_type: IOCType

    # Weighted consensus values
    consensus_confidence: float       # 0-100
    consensus_verdict: Verdict
    feed_weighted_score: float        # weighted average across feeds

    # Aggregated metadata
    contributing_feeds: List[str] = field(default_factory=list)
    dissenting_feeds: List[str] = field(default_factory=list)
    vote_count: int = 0
    malicious_votes: int = 0
    benign_votes: int = 0
    unknown_votes: int = 0

    # Aggregated tags from all feeds
    all_tags: List[str] = field(default_factory=list)

    # Confidence in the consensus itself (how much feeds agree)
    consensus_strength: float = 0.0   # 0.0 = total disagreement, 1.0 = unanimous

    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_high_confidence(self) -> bool:
        return self.consensus_confidence >= 70 and self.consensus_strength >= 0.6

    @property
    def has_disagreement(self) -> bool:
        return len(self.dissenting_feeds) > 0

    def to_dict(self) -> dict:
        return {
            "ioc_fingerprint": self.ioc_fingerprint,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type.value,
            "consensus_confidence": round(self.consensus_confidence, 2),
            "consensus_verdict": self.consensus_verdict.value,
            "feed_weighted_score": round(self.feed_weighted_score, 2),
            "contributing_feeds": self.contributing_feeds,
            "dissenting_feeds": self.dissenting_feeds,
            "vote_count": self.vote_count,
            "malicious_votes": self.malicious_votes,
            "benign_votes": self.benign_votes,
            "unknown_votes": self.unknown_votes,
            "all_tags": self.all_tags,
            "consensus_strength": round(self.consensus_strength, 4),
            "is_high_confidence": self.is_high_confidence,
            "has_disagreement": self.has_disagreement,
            "computed_at": self.computed_at.isoformat(),
        }


class ReputationAggregator:
    """
    Aggregates IOC reputation from multiple threat intelligence feeds.

    Algorithm:
    1. Each feed is assigned a reliability score based on its Beta distribution,
       derived from historical true/false positive feedback.
    2. When computing consensus for an IOC, each feed's vote is weighted by:
         weight = reliability_score * recency_factor
       where recency_factor decays exponentially with vote age (half-life = 24h).
    3. Weighted votes are summed; the final confidence is a weighted average of
       raw_confidence values, scaled by verdicts (malicious=positive, benign=negative).
    4. Consensus strength is measured by the fraction of total weight that agrees
       with the majority verdict.
    5. Disagreement is flagged when a minority of feeds (by weight) votes opposite.
    """

    # Vote age half-life in seconds (24 hours)
    RECENCY_HALF_LIFE: float = 86400.0

    # Weight floor: even unverified feeds get some minimum weight
    MIN_FEED_WEIGHT: float = 0.1

    def __init__(self) -> None:
        # feed_name -> FeedReliabilityRecord
        self._feed_records: Dict[str, FeedReliabilityRecord] = {}
        # ioc_fingerprint -> list of ReputationVote
        self._vote_store: Dict[str, List[ReputationVote]] = {}
        # ioc_fingerprint -> cached ConsensusScore (invalidated on new vote)
        self._consensus_cache: Dict[str, ConsensusScore] = {}

    def register_feed(
        self,
        feed_name: str,
        initial_reliability: float = 75.0,
    ) -> FeedReliabilityRecord:
        """
        Register a new feed with an optional initial reliability estimate.

        initial_reliability is converted to Beta distribution params via
        method of moments: mean = initial_reliability / 100, variance is
        set assuming moderate uncertainty (equivalent to ~4 prior observations).
        """
        if feed_name in self._feed_records:
            return self._feed_records[feed_name]

        mean = max(0.01, min(0.99, initial_reliability / 100.0))
        total_prior = 4.0
        alpha = mean * total_prior
        beta = (1.0 - mean) * total_prior

        record = FeedReliabilityRecord(
            feed_name=feed_name,
            alpha=alpha,
            beta=beta,
        )
        self._feed_records[feed_name] = record
        logger.info(
            "Registered feed %s with initial reliability %.1f%% (alpha=%.2f, beta=%.2f)",
            feed_name,
            initial_reliability,
            alpha,
            beta,
        )
        return record

    def submit_vote(self, vote: ReputationVote) -> None:
        """
        Accept a reputation vote from a feed for an IOC.
        Auto-registers the feed if not known.
        """
        if vote.feed_name not in self._feed_records:
            self.register_feed(vote.feed_name)

        if vote.ioc_fingerprint not in self._vote_store:
            self._vote_store[vote.ioc_fingerprint] = []

        # Replace previous vote from same feed (one vote per feed per IOC)
        existing = self._vote_store[vote.ioc_fingerprint]
        self._vote_store[vote.ioc_fingerprint] = [
            v for v in existing if v.feed_name != vote.feed_name
        ]
        self._vote_store[vote.ioc_fingerprint].append(vote)

        # Invalidate cached consensus
        self._consensus_cache.pop(vote.ioc_fingerprint, None)

        logger.debug(
            "Vote submitted: feed=%s ioc=%s verdict=%s confidence=%d",
            vote.feed_name,
            vote.ioc_fingerprint[:16],
            vote.verdict.value,
            vote.raw_confidence,
        )

    def submit_votes_for_ioc(self, ioc: IOC, verdict: Verdict = Verdict.MALICIOUS) -> None:
        """
        Convenience: submit a vote sourced from the IOC's own source field.
        """
        vote = ReputationVote(
            feed_name=ioc.source,
            ioc_fingerprint=ioc.fingerprint,
            verdict=verdict,
            raw_confidence=ioc.confidence,
            severity=ioc.severity,
            tags=list(ioc.tags),
        )
        self.submit_vote(vote)

    def record_feedback(self, feed_name: str, confirmed_tp: bool) -> None:
        """
        Update feed reliability after a verdict is confirmed by an analyst.

        confirmed_tp=True  -> IOC was a true positive (feed was correct)
        confirmed_tp=False -> IOC was a false positive (feed was wrong)
        """
        if feed_name not in self._feed_records:
            self.register_feed(feed_name)

        record = self._feed_records[feed_name]
        if confirmed_tp:
            record.update_true_positive()
            logger.info("Feed %s TP confirmed, reliability now %.1f%%",
                        feed_name, record.reliability_score)
        else:
            record.update_false_positive()
            logger.info("Feed %s FP confirmed, reliability now %.1f%%",
                        feed_name, record.reliability_score)

        # Invalidate all consensus scores involving this feed
        affected = [
            fp for fp, votes in self._vote_store.items()
            if any(v.feed_name == feed_name for v in votes)
        ]
        for fp in affected:
            self._consensus_cache.pop(fp, None)

    def _feed_weight(self, feed_name: str, vote_age_seconds: float) -> float:
        """Compute effective weight for a feed's vote, accounting for recency."""
        record = self._feed_records.get(feed_name)
        if record is None:
            base_reliability = 50.0
        else:
            base_reliability = record.reliability_score

        # Normalize to 0-1
        reliability_weight = max(self.MIN_FEED_WEIGHT, base_reliability / 100.0)

        # Exponential recency decay: weight halves every RECENCY_HALF_LIFE seconds
        recency_factor = math.exp(-math.log(2) * vote_age_seconds / self.RECENCY_HALF_LIFE)

        return reliability_weight * recency_factor

    def compute_consensus(
        self,
        ioc_fingerprint: str,
        ioc: Optional[IOC] = None,
    ) -> Optional[ConsensusScore]:
        """
        Compute weighted consensus score for an IOC from all submitted votes.

        Returns None if no votes exist for this fingerprint.
        Returns cached result if votes haven't changed.
        """
        if ioc_fingerprint in self._consensus_cache:
            return self._consensus_cache[ioc_fingerprint]

        votes = self._vote_store.get(ioc_fingerprint, [])
        if not votes:
            return None

        ioc_value = ioc.value if ioc else ioc_fingerprint[:16] + "..."
        ioc_type = ioc.ioc_type if ioc else IOCType.IPV4

        # --- Weighted voting ---
        total_weight = 0.0
        malicious_weight = 0.0
        benign_weight = 0.0
        unknown_weight = 0.0
        weighted_confidence_sum = 0.0

        malicious_votes = 0
        benign_votes = 0
        unknown_votes = 0
        all_tags: List[str] = []

        vote_weights: List[Tuple[ReputationVote, float]] = []

        for vote in votes:
            weight = self._feed_weight(vote.feed_name, vote.age_seconds)
            vote_weights.append((vote, weight))
            total_weight += weight

            if vote.verdict == Verdict.MALICIOUS or vote.verdict == Verdict.SUSPICIOUS:
                malicious_weight += weight
                malicious_votes += 1
                # Scale confidence positively
                weighted_confidence_sum += vote.raw_confidence * weight
            elif vote.verdict == Verdict.BENIGN:
                benign_weight += weight
                benign_votes += 1
                # Scale confidence negatively (benign reduces overall threat score)
                weighted_confidence_sum -= vote.raw_confidence * weight * 0.5
            else:
                unknown_weight += weight
                unknown_votes += 1
                weighted_confidence_sum += vote.raw_confidence * weight * 0.3

            all_tags.extend(vote.tags)

        if total_weight == 0.0:
            return None

        # --- Consensus verdict ---
        if malicious_weight > benign_weight and malicious_weight > unknown_weight:
            consensus_verdict = Verdict.MALICIOUS
            majority_weight = malicious_weight
        elif benign_weight > malicious_weight:
            consensus_verdict = Verdict.BENIGN
            majority_weight = benign_weight
        else:
            consensus_verdict = Verdict.UNKNOWN
            majority_weight = unknown_weight

        # --- Consensus confidence (0-100) ---
        raw_score = weighted_confidence_sum / total_weight
        consensus_confidence = max(0.0, min(100.0, raw_score))

        # --- Consensus strength: fraction of total weight behind the majority ---
        consensus_strength = majority_weight / total_weight if total_weight > 0 else 0.0

        # --- Feed weighted score (pure malicious signal, 0-100) ---
        feed_weighted_score = (malicious_weight / total_weight) * 100.0

        # --- Dissent detection ---
        contributing_feeds: List[str] = []
        dissenting_feeds: List[str] = []

        for vote, weight in vote_weights:
            contributing_feeds.append(vote.feed_name)
            if consensus_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                if vote.verdict == Verdict.BENIGN:
                    dissenting_feeds.append(vote.feed_name)
            elif consensus_verdict == Verdict.BENIGN:
                if vote.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                    dissenting_feeds.append(vote.feed_name)

        score = ConsensusScore(
            ioc_fingerprint=ioc_fingerprint,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            consensus_confidence=consensus_confidence,
            consensus_verdict=consensus_verdict,
            feed_weighted_score=feed_weighted_score,
            contributing_feeds=contributing_feeds,
            dissenting_feeds=dissenting_feeds,
            vote_count=len(votes),
            malicious_votes=malicious_votes,
            benign_votes=benign_votes,
            unknown_votes=unknown_votes,
            all_tags=list(set(all_tags)),
            consensus_strength=consensus_strength,
        )

        self._consensus_cache[ioc_fingerprint] = score
        return score

    def apply_consensus_to_ioc(self, ioc: IOC) -> Tuple[IOC, Optional[ConsensusScore]]:
        """
        Update an IOC's confidence field with the aggregated consensus score.

        Returns the modified IOC and the ConsensusScore used.
        """
        consensus = self.compute_consensus(ioc.fingerprint, ioc=ioc)
        if consensus is None:
            return ioc, None

        old_confidence = ioc.confidence
        ioc.confidence = int(round(consensus.consensus_confidence))
        ioc.tags.update(consensus.all_tags)
        ioc.updated_at = datetime.now(timezone.utc)

        if consensus.has_disagreement:
            ioc.metadata["reputation_disagreement"] = consensus.dissenting_feeds
        ioc.metadata["reputation_consensus_strength"] = round(consensus.consensus_strength, 4)
        ioc.metadata["reputation_feed_weighted_score"] = round(consensus.feed_weighted_score, 2)
        ioc.metadata["reputation_vote_count"] = consensus.vote_count

        logger.info(
            "IOC %s confidence updated %d -> %d (consensus=%.1f%%, strength=%.2f, verdict=%s)",
            ioc.value,
            old_confidence,
            ioc.confidence,
            consensus.consensus_confidence,
            consensus.consensus_strength,
            consensus.consensus_verdict.value,
        )
        return ioc, consensus

    def bulk_apply_consensus(self, iocs: List[IOC]) -> Dict[str, ConsensusScore]:
        """
        Apply consensus scores to a list of IOCs.
        Returns a mapping of fingerprint -> ConsensusScore for IOCs that had votes.
        """
        results: Dict[str, ConsensusScore] = {}
        for ioc in iocs:
            _, consensus = self.apply_consensus_to_ioc(ioc)
            if consensus is not None:
                results[ioc.fingerprint] = consensus
        return results

    def get_feed_reliability(self, feed_name: str) -> Optional[FeedReliabilityRecord]:
        return self._feed_records.get(feed_name)

    def get_all_feed_records(self) -> Dict[str, FeedReliabilityRecord]:
        return dict(self._feed_records)

    def get_votes_for_ioc(self, ioc_fingerprint: str) -> List[ReputationVote]:
        return list(self._vote_store.get(ioc_fingerprint, []))

    def feeds_by_reliability(self) -> List[FeedReliabilityRecord]:
        """Return all feed records sorted by reliability score (desc)."""
        return sorted(
            self._feed_records.values(),
            key=lambda r: r.reliability_score,
            reverse=True,
        )

    def high_disagreement_iocs(self, min_vote_count: int = 2) -> List[ConsensusScore]:
        """
        Return IOCs where feeds disagree significantly.
        Useful for prioritizing manual analyst review.
        """
        results = []
        for fp in self._vote_store:
            if fp in self._consensus_cache:
                score = self._consensus_cache[fp]
            else:
                score = self.compute_consensus(fp)
            if score and score.has_disagreement and score.vote_count >= min_vote_count:
                results.append(score)
        return sorted(results, key=lambda s: s.consensus_strength)

    def stats(self) -> dict:
        """Return aggregator-level statistics."""
        total_votes = sum(len(v) for v in self._vote_store.values())
        return {
            "registered_feeds": len(self._feed_records),
            "total_iocs_tracked": len(self._vote_store),
            "total_votes": total_votes,
            "cached_consensus_scores": len(self._consensus_cache),
            "feeds": {
                name: record.to_dict()
                for name, record in self._feed_records.items()
            },
        }
