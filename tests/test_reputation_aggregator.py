"""Tests for IOC reputation aggregator."""

from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

import pytest

from overwatch.models import IOC, IOCType, Severity
from overwatch.reputation_aggregator import (
    ConsensusScore,
    FeedReliabilityRecord,
    ReputationAggregator,
    ReputationVote,
    Verdict,
)


def make_ioc(value: str = "1.2.3.4", source: str = "test-feed", confidence: int = 70) -> IOC:
    return IOC(
        ioc_type=IOCType.IPV4,
        value=value,
        source=source,
        confidence=confidence,
        severity=Severity.HIGH,
    )


def make_vote(
    feed: str,
    ioc: IOC,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: int = 80,
) -> ReputationVote:
    return ReputationVote(
        feed_name=feed,
        ioc_fingerprint=ioc.fingerprint,
        verdict=verdict,
        raw_confidence=confidence,
    )


class TestFeedReliabilityRecord:
    def test_initial_reliability(self):
        r = FeedReliabilityRecord(feed_name="feed-a", alpha=3.0, beta=1.0)
        assert abs(r.reliability_score - 75.0) < 0.1

    def test_update_tp_increases_reliability(self):
        r = FeedReliabilityRecord(feed_name="feed-a", alpha=2.0, beta=2.0)
        before = r.reliability_score
        r.update_true_positive()
        assert r.reliability_score > before
        assert r.true_positives == 1
        assert r.total_verified == 1

    def test_update_fp_decreases_reliability(self):
        r = FeedReliabilityRecord(feed_name="feed-a", alpha=3.0, beta=1.0)
        before = r.reliability_score
        r.update_false_positive()
        assert r.reliability_score < before
        assert r.false_positives == 1

    def test_uncertainty_decreases_with_evidence(self):
        r = FeedReliabilityRecord(feed_name="feed-a", alpha=2.0, beta=2.0)
        u_before = r.uncertainty
        for _ in range(10):
            r.update_true_positive()
        assert r.uncertainty < u_before

    def test_to_dict_fields(self):
        r = FeedReliabilityRecord(feed_name="feed-x", alpha=3.0, beta=1.0)
        d = r.to_dict()
        assert "feed_name" in d
        assert "reliability_score" in d
        assert "alpha" in d


class TestReputationAggregator:
    def test_register_feed_default(self):
        agg = ReputationAggregator()
        rec = agg.register_feed("feed-a")
        assert rec.feed_name == "feed-a"
        assert abs(rec.reliability_score - 75.0) < 1.0

    def test_register_feed_idempotent(self):
        agg = ReputationAggregator()
        r1 = agg.register_feed("feed-a")
        r2 = agg.register_feed("feed-a")
        assert r1 is r2

    def test_submit_vote_auto_registers_feed(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        vote = make_vote("new-feed", ioc)
        agg.submit_vote(vote)
        assert "new-feed" in agg.get_all_feed_records()

    def test_submit_vote_replaces_existing(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        v1 = make_vote("feed-a", ioc, Verdict.MALICIOUS, 80)
        v2 = make_vote("feed-a", ioc, Verdict.BENIGN, 90)
        agg.submit_vote(v1)
        agg.submit_vote(v2)
        votes = agg.get_votes_for_ioc(ioc.fingerprint)
        assert len(votes) == 1
        assert votes[0].verdict == Verdict.BENIGN

    def test_consensus_none_when_no_votes(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        assert agg.compute_consensus(ioc.fingerprint) is None

    def test_consensus_single_malicious_vote(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        agg.submit_votes_for_ioc(ioc, Verdict.MALICIOUS)
        score = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score is not None
        assert score.consensus_verdict == Verdict.MALICIOUS
        assert score.vote_count == 1
        assert score.malicious_votes == 1
        assert score.consensus_confidence > 0

    def test_consensus_majority_wins(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        for feed in ["feed-a", "feed-b", "feed-c"]:
            agg.register_feed(feed, initial_reliability=80.0)
            agg.submit_vote(make_vote(feed, ioc, Verdict.MALICIOUS, 85))
        agg.register_feed("feed-d", initial_reliability=80.0)
        agg.submit_vote(make_vote("feed-d", ioc, Verdict.BENIGN, 60))

        score = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score is not None
        assert score.consensus_verdict == Verdict.MALICIOUS
        assert "feed-d" in score.dissenting_feeds
        assert score.has_disagreement

    def test_consensus_strength_unanimous(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        for feed in ["f1", "f2", "f3"]:
            agg.register_feed(feed, initial_reliability=75.0)
            agg.submit_vote(make_vote(feed, ioc, Verdict.MALICIOUS, 80))

        score = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score is not None
        # Unanimous -> strength should be 1.0
        assert abs(score.consensus_strength - 1.0) < 1e-9

    def test_apply_consensus_updates_ioc_confidence(self):
        agg = ReputationAggregator()
        ioc = make_ioc(confidence=50)
        agg.register_feed("ext-feed", initial_reliability=80.0)
        # Submit a vote with higher confidence than the IOC's own value
        vote = ReputationVote(
            feed_name="ext-feed",
            ioc_fingerprint=ioc.fingerprint,
            verdict=Verdict.MALICIOUS,
            raw_confidence=90,
        )
        agg.submit_vote(vote)

        updated_ioc, consensus = agg.apply_consensus_to_ioc(ioc)
        assert consensus is not None
        assert updated_ioc.confidence != 50  # 90 != 50
        assert "reputation_vote_count" in updated_ioc.metadata

    def test_apply_consensus_returns_none_for_untracked(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        updated_ioc, consensus = agg.apply_consensus_to_ioc(ioc)
        assert consensus is None

    def test_record_feedback_updates_feed_reliability(self):
        agg = ReputationAggregator()
        agg.register_feed("feed-x", initial_reliability=50.0)
        before = agg.get_feed_reliability("feed-x").reliability_score

        # Five confirmed TPs should push reliability up significantly
        for _ in range(5):
            agg.record_feedback("feed-x", confirmed_tp=True)

        after = agg.get_feed_reliability("feed-x").reliability_score
        assert after > before

    def test_record_feedback_invalidates_cache(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        agg.register_feed("feed-a", initial_reliability=80.0)
        agg.submit_vote(make_vote("feed-a", ioc))

        score1 = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score1 is not None

        # Force a cache invalidation by marking FP
        agg.record_feedback("feed-a", confirmed_tp=False)

        # Should recompute (cache was cleared)
        score2 = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score2 is not None
        assert score2.consensus_confidence <= score1.consensus_confidence

    def test_bulk_apply_consensus(self):
        agg = ReputationAggregator()
        iocs = [make_ioc(f"10.0.0.{i}", f"feed-{i}") for i in range(5)]
        for ioc in iocs:
            agg.register_feed(ioc.source, initial_reliability=75.0)
            agg.submit_votes_for_ioc(ioc, Verdict.MALICIOUS)

        results = agg.bulk_apply_consensus(iocs)
        assert len(results) == 5

    def test_high_disagreement_iocs(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        agg.register_feed("f1", 80.0)
        agg.register_feed("f2", 80.0)
        agg.submit_vote(make_vote("f1", ioc, Verdict.MALICIOUS, 90))
        agg.submit_vote(make_vote("f2", ioc, Verdict.BENIGN, 80))

        disagreements = agg.high_disagreement_iocs(min_vote_count=2)
        assert len(disagreements) == 1
        assert disagreements[0].ioc_fingerprint == ioc.fingerprint

    def test_feeds_by_reliability_ordered(self):
        agg = ReputationAggregator()
        agg.register_feed("low-rel", initial_reliability=20.0)
        agg.register_feed("high-rel", initial_reliability=90.0)
        agg.register_feed("mid-rel", initial_reliability=60.0)

        ranked = agg.feeds_by_reliability()
        scores = [r.reliability_score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_stats_structure(self):
        agg = ReputationAggregator()
        ioc = make_ioc(source="feed-a")
        agg.register_feed("feed-a")
        agg.submit_votes_for_ioc(ioc, Verdict.MALICIOUS)

        s = agg.stats()
        assert s["registered_feeds"] == 1  # feed-a registered once
        assert s["total_iocs_tracked"] == 1
        assert s["total_votes"] == 1

    def test_tags_aggregated_across_feeds(self):
        agg = ReputationAggregator()
        ioc = make_ioc()
        v1 = ReputationVote(
            feed_name="f1",
            ioc_fingerprint=ioc.fingerprint,
            verdict=Verdict.MALICIOUS,
            raw_confidence=80,
            tags=["botnet", "c2"],
        )
        v2 = ReputationVote(
            feed_name="f2",
            ioc_fingerprint=ioc.fingerprint,
            verdict=Verdict.MALICIOUS,
            raw_confidence=75,
            tags=["ransomware", "c2"],
        )
        agg.submit_vote(v1)
        agg.submit_vote(v2)

        score = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score is not None
        assert "botnet" in score.all_tags
        assert "ransomware" in score.all_tags
        assert score.all_tags.count("c2") == 1  # deduped

    def test_high_reliability_feed_dominates_low(self):
        """A high-reliability feed's vote should outweigh a low-reliability one."""
        agg = ReputationAggregator()
        ioc = make_ioc()

        # High reliability feed says MALICIOUS at 90 confidence
        agg.register_feed("trusted", initial_reliability=95.0)
        # Pump up trust with TPs
        for _ in range(20):
            agg.record_feedback("trusted", confirmed_tp=True)
        agg.submit_vote(make_vote("trusted", ioc, Verdict.MALICIOUS, 90))

        # Very low reliability feed says BENIGN at 60 confidence
        agg.register_feed("untrusted", initial_reliability=5.0)
        for _ in range(20):
            agg.record_feedback("untrusted", confirmed_tp=False)
        agg.submit_vote(make_vote("untrusted", ioc, Verdict.BENIGN, 60))

        score = agg.compute_consensus(ioc.fingerprint, ioc=ioc)
        assert score is not None
        assert score.consensus_verdict == Verdict.MALICIOUS
