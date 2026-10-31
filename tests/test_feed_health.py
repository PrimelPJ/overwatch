"""Tests for the feed health monitor."""

import time
from unittest.mock import MagicMock

import pytest

from overwatch.feed_health import (
    FeedHealthMonitor,
    FeedSLA,
    FeedStatus,
    IngestionTimer,
)


@pytest.fixture
def monitor():
    return FeedHealthMonitor(window_size=20)


def test_unknown_status_before_any_records(monitor):
    monitor.register_feed("test_feed")
    stats = monitor.get_health("test_feed")
    assert stats.status == FeedStatus.UNKNOWN
    assert stats.window_records == 0


def test_healthy_after_successful_ingestions(monitor):
    monitor.register_feed("feed_a")
    for _ in range(5):
        monitor.record_ingestion("feed_a", success=True, ioc_count=100, fetch_duration_ms=500)
    stats = monitor.get_health("feed_a")
    assert stats.status == FeedStatus.HEALTHY
    assert stats.success_rate_pct == 100.0
    assert stats.total_iocs_ingested == 500


def test_degraded_on_low_success_rate(monitor):
    monitor.register_feed("feed_b")
    for i in range(10):
        monitor.record_ingestion(
            "feed_b", success=(i < 5), ioc_count=50 if i < 5 else 0, fetch_duration_ms=200
        )
    stats = monitor.get_health("feed_b")
    assert stats.success_rate_pct == 50.0
    assert stats.status in (FeedStatus.DEGRADED, FeedStatus.FAILING)


def test_failing_after_five_consecutive_failures(monitor):
    monitor.register_feed("feed_c")
    monitor.record_ingestion("feed_c", success=True, ioc_count=100, fetch_duration_ms=100)
    for _ in range(5):
        monitor.record_ingestion("feed_c", success=False, ioc_count=0, fetch_duration_ms=100, error_message="timeout")
    stats = monitor.get_health("feed_c")
    assert stats.status == FeedStatus.FAILING
    assert stats.consecutive_failures == 5


def test_sla_latency_violation(monitor):
    sla = FeedSLA(max_fetch_latency_ms=1000.0)
    monitor.register_feed("slow_feed", sla=sla)
    for _ in range(5):
        monitor.record_ingestion("slow_feed", success=True, ioc_count=50, fetch_duration_ms=5000.0)
    stats = monitor.get_health("slow_feed")
    assert any("avg_latency" in v for v in stats.sla_violations)
    assert stats.status == FeedStatus.DEGRADED


def test_sla_success_rate_violation(monitor):
    sla = FeedSLA(min_success_rate_pct=95.0)
    monitor.register_feed("flaky_feed", sla=sla)
    for i in range(20):
        monitor.record_ingestion(
            "flaky_feed", success=(i % 10 != 0), ioc_count=100 if i % 10 != 0 else 0, fetch_duration_ms=300
        )
    stats = monitor.get_health("flaky_feed")
    assert any("success_rate" in v for v in stats.sla_violations)


def test_alert_callback_triggered_on_degradation(monitor):
    callback = MagicMock()
    monitor.add_alert_callback(callback)
    monitor.register_feed("alert_feed")
    monitor.record_ingestion("alert_feed", success=True, ioc_count=100, fetch_duration_ms=200)
    for _ in range(5):
        monitor.record_ingestion("alert_feed", success=False, ioc_count=0, fetch_duration_ms=100, error_message="err")
    assert callback.called
    call_args = callback.call_args
    assert call_args[0][0] == "alert_feed"


def test_parse_error_rate_tracked(monitor):
    monitor.register_feed("feed_d")
    for _ in range(5):
        monitor.record_ingestion("feed_d", success=True, ioc_count=90, parse_errors=10, fetch_duration_ms=300)
    stats = monitor.get_health("feed_d")
    assert stats.parse_error_rate_pct == pytest.approx(10.0, abs=0.1)


def test_p95_latency_computed(monitor):
    monitor.register_feed("latency_feed")
    latencies = [100.0] * 19 + [5000.0]
    for lat in latencies:
        monitor.record_ingestion("latency_feed", success=True, ioc_count=50, fetch_duration_ms=lat)
    stats = monitor.get_health("latency_feed")
    assert stats.p95_fetch_latency_ms >= 5000.0


def test_dashboard_summary_structure(monitor):
    monitor.register_feed("d1")
    monitor.register_feed("d2")
    monitor.record_ingestion("d1", success=True, ioc_count=100, fetch_duration_ms=200)
    summary = monitor.get_dashboard_summary()
    assert summary["total_feeds"] == 2
    assert "status_breakdown" in summary
    assert "feeds" in summary
    assert any(f["feed_name"] == "d1" for f in summary["feeds"])


def test_ingestion_timer_records_success():
    monitor = FeedHealthMonitor()
    monitor.register_feed("timed_feed")
    with IngestionTimer(monitor, "timed_feed") as t:
        t.ioc_count = 150
    stats = monitor.get_health("timed_feed")
    assert stats.success_rate_pct == 100.0
    assert stats.total_iocs_ingested == 150


def test_ingestion_timer_records_failure_on_exception():
    monitor = FeedHealthMonitor()
    monitor.register_feed("ex_feed")
    try:
        with IngestionTimer(monitor, "ex_feed"):
            raise ValueError("network error")
    except ValueError:
        pass
    stats = monitor.get_health("ex_feed")
    assert stats.success_rate_pct == 0.0
    assert stats.consecutive_failures == 1


def test_auto_register_on_record(monitor):
    monitor.record_ingestion("auto_feed", success=True, ioc_count=10, fetch_duration_ms=100)
    assert "auto_feed" in monitor._records


def test_stale_status_detected(monitor):
    sla = FeedSLA(max_staleness_seconds=1)
    monitor.register_feed("stale_feed", sla=sla)
    monitor.record_ingestion("stale_feed", success=True, ioc_count=50, fetch_duration_ms=200)
    time.sleep(1.1)
    stats = monitor.get_health("stale_feed")
    assert stats.status == FeedStatus.STALE
