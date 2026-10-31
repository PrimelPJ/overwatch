"""
Feed health monitor with SLA tracking, latency metrics, and anomaly detection.

Tracks per-feed ingestion statistics: success rate, IOC volume, parse errors,
staleness, and SLA compliance. Raises alerts when feeds degrade.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class FeedStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STALE = "stale"
    FAILING = "failing"
    UNKNOWN = "unknown"


@dataclass
class IngestionRecord:
    """Single ingestion attempt outcome."""

    timestamp: float
    success: bool
    ioc_count: int
    parse_errors: int
    fetch_duration_ms: float
    parse_duration_ms: float
    http_status: Optional[int] = None
    error_message: Optional[str] = None

    @property
    def total_duration_ms(self) -> float:
        return self.fetch_duration_ms + self.parse_duration_ms


@dataclass
class FeedSLA:
    """SLA thresholds for a feed."""

    max_staleness_seconds: int = 3600
    min_success_rate_pct: float = 90.0
    max_fetch_latency_ms: float = 30_000.0
    max_parse_error_rate_pct: float = 5.0
    min_ioc_volume_per_run: int = 0


@dataclass
class FeedHealthStats:
    """Aggregated health statistics computed over a rolling window."""

    feed_name: str
    status: FeedStatus
    last_success_at: Optional[float]
    last_failure_at: Optional[float]
    success_rate_pct: float
    avg_fetch_latency_ms: float
    p95_fetch_latency_ms: float
    avg_ioc_count: float
    total_iocs_ingested: int
    parse_error_rate_pct: float
    consecutive_failures: int
    sla_violations: List[str]
    window_records: int
    computed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "feed_name": self.feed_name,
            "status": self.status.value,
            "last_success_at": (
                datetime.fromtimestamp(self.last_success_at, tz=timezone.utc).isoformat()
                if self.last_success_at
                else None
            ),
            "last_failure_at": (
                datetime.fromtimestamp(self.last_failure_at, tz=timezone.utc).isoformat()
                if self.last_failure_at
                else None
            ),
            "success_rate_pct": round(self.success_rate_pct, 2),
            "avg_fetch_latency_ms": round(self.avg_fetch_latency_ms, 1),
            "p95_fetch_latency_ms": round(self.p95_fetch_latency_ms, 1),
            "avg_ioc_count": round(self.avg_ioc_count, 1),
            "total_iocs_ingested": self.total_iocs_ingested,
            "parse_error_rate_pct": round(self.parse_error_rate_pct, 2),
            "consecutive_failures": self.consecutive_failures,
            "sla_violations": self.sla_violations,
            "window_records": self.window_records,
            "computed_at": datetime.fromtimestamp(self.computed_at, tz=timezone.utc).isoformat(),
        }


class FeedHealthMonitor:
    """
    Monitors ingestion health for multiple threat feeds.

    Maintains a rolling window of IngestionRecords per feed, computes
    success rates, latency percentiles, and SLA violations, and exposes
    callbacks for alerting when a feed degrades.
    """

    def __init__(
        self,
        window_size: int = 50,
        staleness_check_interval: int = 60,
    ) -> None:
        self._window_size = window_size
        self._staleness_check_interval = staleness_check_interval
        self._records: Dict[str, Deque[IngestionRecord]] = {}
        self._slas: Dict[str, FeedSLA] = {}
        self._alert_callbacks: List[Callable[[str, FeedHealthStats], None]] = []
        self._previous_status: Dict[str, FeedStatus] = {}
        self._monitor_task: Optional[asyncio.Task] = None

    def register_feed(self, feed_name: str, sla: Optional[FeedSLA] = None) -> None:
        """Register a feed for monitoring with optional SLA configuration."""
        if feed_name not in self._records:
            self._records[feed_name] = deque(maxlen=self._window_size)
        self._slas[feed_name] = sla or FeedSLA()

    def record_ingestion(
        self,
        feed_name: str,
        success: bool,
        ioc_count: int,
        fetch_duration_ms: float,
        parse_duration_ms: float = 0.0,
        parse_errors: int = 0,
        http_status: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Record the outcome of a single ingestion attempt."""
        if feed_name not in self._records:
            self.register_feed(feed_name)

        record = IngestionRecord(
            timestamp=time.time(),
            success=success,
            ioc_count=ioc_count,
            parse_errors=parse_errors,
            fetch_duration_ms=fetch_duration_ms,
            parse_duration_ms=parse_duration_ms,
            http_status=http_status,
            error_message=error_message,
        )
        self._records[feed_name].append(record)
        self._check_status_change(feed_name)

    def _compute_stats(self, feed_name: str) -> FeedHealthStats:
        records = list(self._records.get(feed_name, []))
        sla = self._slas.get(feed_name, FeedSLA())

        if not records:
            return FeedHealthStats(
                feed_name=feed_name,
                status=FeedStatus.UNKNOWN,
                last_success_at=None,
                last_failure_at=None,
                success_rate_pct=0.0,
                avg_fetch_latency_ms=0.0,
                p95_fetch_latency_ms=0.0,
                avg_ioc_count=0.0,
                total_iocs_ingested=0,
                parse_error_rate_pct=0.0,
                consecutive_failures=0,
                sla_violations=[],
                window_records=0,
            )

        successes = [r for r in records if r.success]
        failures = [r for r in records if not r.success]

        last_success_at = max((r.timestamp for r in successes), default=None)
        last_failure_at = max((r.timestamp for r in failures), default=None)

        success_rate = len(successes) / len(records) * 100 if records else 0.0

        latencies = [r.fetch_duration_ms for r in records]
        avg_latency = statistics.mean(latencies) if latencies else 0.0
        sorted_latencies = sorted(latencies)
        p95_idx = min(len(sorted_latencies) - 1, int(len(sorted_latencies) * 0.95))
        p95_latency = sorted_latencies[p95_idx] if sorted_latencies else 0.0

        total_iocs = sum(r.ioc_count for r in records)
        avg_iocs = total_iocs / len(records) if records else 0.0

        total_parse_errors = sum(r.parse_errors for r in records)
        total_ioc_attempts = sum(r.ioc_count + r.parse_errors for r in records)
        parse_error_rate = (
            total_parse_errors / total_ioc_attempts * 100 if total_ioc_attempts > 0 else 0.0
        )

        consecutive_failures = 0
        for r in reversed(records):
            if not r.success:
                consecutive_failures += 1
            else:
                break

        sla_violations = self._compute_sla_violations(
            feed_name, sla, success_rate, avg_latency,
            parse_error_rate, last_success_at, avg_iocs,
        )

        status = self._determine_status(
            consecutive_failures, success_rate, sla_violations, last_success_at, sla
        )

        return FeedHealthStats(
            feed_name=feed_name,
            status=status,
            last_success_at=last_success_at,
            last_failure_at=last_failure_at,
            success_rate_pct=success_rate,
            avg_fetch_latency_ms=avg_latency,
            p95_fetch_latency_ms=p95_latency,
            avg_ioc_count=avg_iocs,
            total_iocs_ingested=total_iocs,
            parse_error_rate_pct=parse_error_rate,
            consecutive_failures=consecutive_failures,
            sla_violations=sla_violations,
            window_records=len(records),
        )

    def _compute_sla_violations(
        self,
        feed_name: str,
        sla: FeedSLA,
        success_rate: float,
        avg_latency_ms: float,
        parse_error_rate: float,
        last_success_at: Optional[float],
        avg_iocs: float,
    ) -> List[str]:
        violations = []
        now = time.time()

        if success_rate < sla.min_success_rate_pct:
            violations.append(
                f"success_rate {success_rate:.1f}% < SLA {sla.min_success_rate_pct}%"
            )

        if avg_latency_ms > sla.max_fetch_latency_ms:
            violations.append(
                f"avg_latency {avg_latency_ms:.0f}ms > SLA {sla.max_fetch_latency_ms:.0f}ms"
            )

        if parse_error_rate > sla.max_parse_error_rate_pct:
            violations.append(
                f"parse_error_rate {parse_error_rate:.1f}% > SLA {sla.max_parse_error_rate_pct}%"
            )

        if last_success_at is not None:
            staleness = now - last_success_at
            if staleness > sla.max_staleness_seconds:
                violations.append(
                    f"stale {staleness:.0f}s > SLA {sla.max_staleness_seconds}s"
                )
        elif sla.max_staleness_seconds > 0:
            violations.append("never successfully ingested")

        if sla.min_ioc_volume_per_run > 0 and avg_iocs < sla.min_ioc_volume_per_run:
            violations.append(
                f"avg_ioc_volume {avg_iocs:.1f} < SLA {sla.min_ioc_volume_per_run}"
            )

        return violations

    def _determine_status(
        self,
        consecutive_failures: int,
        success_rate: float,
        sla_violations: List[str],
        last_success_at: Optional[float],
        sla: FeedSLA,
    ) -> FeedStatus:
        if consecutive_failures >= 5:
            return FeedStatus.FAILING

        if last_success_at is not None:
            staleness = time.time() - last_success_at
            if staleness > sla.max_staleness_seconds:
                return FeedStatus.STALE

        if sla_violations or success_rate < 70.0:
            return FeedStatus.DEGRADED

        return FeedStatus.HEALTHY

    def _check_status_change(self, feed_name: str) -> None:
        stats = self._compute_stats(feed_name)
        prev = self._previous_status.get(feed_name)
        if prev != stats.status:
            self._previous_status[feed_name] = stats.status
            if stats.status in (FeedStatus.DEGRADED, FeedStatus.FAILING, FeedStatus.STALE):
                self._fire_alert(feed_name, stats)

    def _fire_alert(self, feed_name: str, stats: FeedHealthStats) -> None:
        for callback in self._alert_callbacks:
            try:
                callback(feed_name, stats)
            except Exception:
                logger.exception("Alert callback raised exception for feed %s", feed_name)

    def add_alert_callback(self, callback: Callable[[str, FeedHealthStats], None]) -> None:
        """Register a callback invoked when a feed's status becomes degraded/failing/stale."""
        self._alert_callbacks.append(callback)

    def get_health(self, feed_name: str) -> FeedHealthStats:
        """Return current health statistics for a feed."""
        return self._compute_stats(feed_name)

    def get_all_health(self) -> Dict[str, FeedHealthStats]:
        """Return health statistics for all registered feeds."""
        return {name: self._compute_stats(name) for name in self._records}

    def get_dashboard_summary(self) -> Dict:
        """Return a high-level dashboard dict suitable for API responses."""
        all_stats = self.get_all_health()
        status_counts: Dict[str, int] = {}
        for s in all_stats.values():
            status_counts[s.status.value] = status_counts.get(s.status.value, 0) + 1

        feeds_summary = [s.to_dict() for s in all_stats.values()]
        feeds_summary.sort(key=lambda x: x["feed_name"])

        return {
            "total_feeds": len(all_stats),
            "status_breakdown": status_counts,
            "feeds": feeds_summary,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def start_staleness_monitor(self) -> None:
        """Background task that periodically checks all feeds for staleness."""
        self._monitor_task = asyncio.current_task()
        while True:
            await asyncio.sleep(self._staleness_check_interval)
            for feed_name in list(self._records.keys()):
                self._check_status_change(feed_name)

    def stop_staleness_monitor(self) -> None:
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()


class IngestionTimer:
    """Context manager that times an ingestion attempt and records it."""

    def __init__(
        self,
        monitor: FeedHealthMonitor,
        feed_name: str,
        min_ioc_volume: int = 0,
    ) -> None:
        self._monitor = monitor
        self._feed_name = feed_name
        self._min_ioc_volume = min_ioc_volume
        self._start: float = 0.0
        self._fetch_end: float = 0.0
        self.ioc_count: int = 0
        self.parse_errors: int = 0
        self.http_status: Optional[int] = None
        self.error: Optional[str] = None

    def mark_fetch_done(self, http_status: Optional[int] = None) -> None:
        """Call after the HTTP fetch completes, before parsing."""
        self._fetch_end = time.time()
        self.http_status = http_status

    def __enter__(self) -> "IngestionTimer":
        self._start = time.time()
        self._fetch_end = self._start
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        end = time.time()
        fetch_ms = (self._fetch_end - self._start) * 1000
        parse_ms = (end - self._fetch_end) * 1000

        success = exc_type is None and (
            self._min_ioc_volume == 0 or self.ioc_count >= self._min_ioc_volume
        )

        self._monitor.record_ingestion(
            feed_name=self._feed_name,
            success=success,
            ioc_count=self.ioc_count,
            fetch_duration_ms=fetch_ms,
            parse_duration_ms=parse_ms,
            parse_errors=self.parse_errors,
            http_status=self.http_status,
            error_message=str(exc_val) if exc_val else self.error,
        )
        return False
