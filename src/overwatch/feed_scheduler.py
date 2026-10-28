"""
Autonomous threat intelligence feed scheduler.
Polls configured threat feeds on configurable intervals, manages per-feed
state (ETag / Last-Modified caching), implements exponential backoff on
errors, enforces per-feed rate limits, and emits feed health metrics.
Integrates with FeedIngestionEngine for automatic IOC updates.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from overwatch.feed_ingestion import FeedIngestionEngine, FeedSource, IngestionStats

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FeedHealth(str, Enum):
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"    # last fetch had errors but is still retrying
    FAILING   = "failing"     # exceeded max consecutive failures
    DISABLED  = "disabled"    # manually or automatically disabled
    PENDING   = "pending"     # never polled yet


class FetchStatus(str, Enum):
    SUCCESS       = "success"
    NOT_MODIFIED  = "not_modified"  # HTTP 304 - content unchanged
    ERROR         = "error"
    SKIPPED       = "skipped"       # rate-limited or disabled


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FeedScheduleConfig:
    """Per-feed scheduling parameters."""
    source: FeedSource
    poll_interval: int = 3600          # seconds between polls
    min_interval: int = 300            # hard floor (5 min)
    max_backoff: int = 7200            # max backoff on errors (2 h)
    max_consecutive_failures: int = 5  # disable after this many in a row
    timeout: int = 60                  # HTTP request timeout
    follow_redirects: bool = True
    verify_tls: bool = True
    extra_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class FeedPollRecord:
    """Persistent state for a single feed across polls."""
    feed_name: str
    last_poll_at: Optional[float] = None     # unix timestamp
    last_success_at: Optional[float] = None
    next_poll_at: float = 0.0
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    consecutive_failures: int = 0
    total_polls: int = 0
    total_successes: int = 0
    total_iocs_ingested: int = 0
    health: FeedHealth = FeedHealth.PENDING
    last_error: Optional[str] = None
    # Rolling 10-poll latency history (ms)
    latency_history: List[float] = field(default_factory=list)

    @property
    def avg_latency_ms(self) -> float:
        if not self.latency_history:
            return 0.0
        return sum(self.latency_history) / len(self.latency_history)

    @property
    def success_rate(self) -> float:
        if self.total_polls == 0:
            return 0.0
        return self.total_successes / self.total_polls

    def record_latency(self, ms: float) -> None:
        self.latency_history.append(ms)
        if len(self.latency_history) > 10:
            self.latency_history.pop(0)

    def is_due(self) -> bool:
        return time.time() >= self.next_poll_at

    def schedule_next(self, interval: int) -> None:
        self.next_poll_at = time.time() + max(interval, 60)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feed_name": self.feed_name,
            "health": self.health.value,
            "last_poll": (
                datetime.fromtimestamp(self.last_poll_at, tz=timezone.utc).isoformat()
                if self.last_poll_at else None
            ),
            "last_success": (
                datetime.fromtimestamp(self.last_success_at, tz=timezone.utc).isoformat()
                if self.last_success_at else None
            ),
            "next_poll": (
                datetime.fromtimestamp(self.next_poll_at, tz=timezone.utc).isoformat()
                if self.next_poll_at else None
            ),
            "consecutive_failures": self.consecutive_failures,
            "total_polls": self.total_polls,
            "total_successes": self.total_successes,
            "success_rate": round(self.success_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "total_iocs_ingested": self.total_iocs_ingested,
            "last_error": self.last_error,
        }


@dataclass
class FetchResult:
    feed_name: str
    status: FetchStatus
    http_status: int = 0
    content: bytes = b""
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    latency_ms: float = 0.0
    error: Optional[str] = None
    ingestion_stats: Optional[IngestionStats] = None


@dataclass
class SchedulerMetrics:
    """Aggregate scheduler health metrics."""
    total_feeds: int = 0
    healthy_feeds: int = 0
    degraded_feeds: int = 0
    failing_feeds: int = 0
    disabled_feeds: int = 0
    polls_per_hour: float = 0.0
    total_iocs_this_session: int = 0
    scheduler_uptime_seconds: float = 0.0
    last_updated: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_feeds": self.total_feeds,
            "healthy": self.healthy_feeds,
            "degraded": self.degraded_feeds,
            "failing": self.failing_feeds,
            "disabled": self.disabled_feeds,
            "polls_per_hour": round(self.polls_per_hour, 2),
            "total_iocs_this_session": self.total_iocs_this_session,
            "uptime_seconds": round(self.scheduler_uptime_seconds, 1),
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
        }


# ---------------------------------------------------------------------------
# HTTP fetcher (async)
# ---------------------------------------------------------------------------

class FeedFetcher:
    """
    Async HTTP fetcher with ETag / Last-Modified cache validation,
    configurable timeout, and TLS control.
    """

    def __init__(self, session: Optional[Any] = None) -> None:
        self._session = session  # injected aiohttp.ClientSession or None

    async def fetch(
        self,
        url: str,
        *,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
        timeout: int = 60,
        verify_tls: bool = True,
        headers: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> FetchResult:
        start = time.perf_counter()
        feed_name = urlparse(url).netloc

        req_headers: Dict[str, str] = {
            "User-Agent": "Overwatch-ThreatIntel/1.0",
            "Accept": "application/json, text/plain, application/stix+json",
        }
        if headers:
            req_headers.update(headers)
        if api_key:
            req_headers["X-OTX-API-KEY"] = api_key
            req_headers["Authorization"] = f"Bearer {api_key}"
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified

        if not HAS_AIOHTTP:
            return FetchResult(
                feed_name=feed_name,
                status=FetchStatus.ERROR,
                error="aiohttp not installed",
            )

        try:
            connector = aiohttp.TCPConnector(ssl=verify_tls)
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout_obj
            ) as session:
                async with session.get(url, headers=req_headers) as response:
                    latency_ms = (time.perf_counter() - start) * 1000

                    if response.status == 304:
                        return FetchResult(
                            feed_name=feed_name,
                            status=FetchStatus.NOT_MODIFIED,
                            http_status=304,
                            latency_ms=latency_ms,
                        )

                    if response.status >= 400:
                        return FetchResult(
                            feed_name=feed_name,
                            status=FetchStatus.ERROR,
                            http_status=response.status,
                            latency_ms=latency_ms,
                            error=f"HTTP {response.status}",
                        )

                    content = await response.read()
                    return FetchResult(
                        feed_name=feed_name,
                        status=FetchStatus.SUCCESS,
                        http_status=response.status,
                        content=content,
                        etag=response.headers.get("ETag"),
                        last_modified=response.headers.get("Last-Modified"),
                        latency_ms=latency_ms,
                    )

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start) * 1000
            return FetchResult(
                feed_name=feed_name,
                status=FetchStatus.ERROR,
                latency_ms=latency_ms,
                error=f"Timeout after {timeout}s",
            )
        except Exception as exc:  # noqa: BLE001
            latency_ms = (time.perf_counter() - start) * 1000
            return FetchResult(
                feed_name=feed_name,
                status=FetchStatus.ERROR,
                latency_ms=latency_ms,
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class FeedScheduler:
    """
    Autonomous scheduler that polls threat intelligence feeds on configurable
    intervals and feeds raw data into the FeedIngestionEngine.

    Features:
    - Per-feed poll state (ETag/Last-Modified caching for bandwidth savings)
    - Exponential backoff on errors (doubles up to max_backoff)
    - Automatic feed disabling after max_consecutive_failures
    - Jitter on startup to prevent thundering-herd
    - Poll callbacks for external event hooks
    - Aggregate health metrics

    Usage::

        engine = FeedIngestionEngine()
        scheduler = FeedScheduler(engine)
        scheduler.add_feed(FeedScheduleConfig(source=my_source))
        asyncio.run(scheduler.run_forever())
    """

    def __init__(
        self,
        ingestion_engine: FeedIngestionEngine,
        poll_callback: Optional[Callable[[FetchResult], None]] = None,
        jitter_max: int = 60,
    ) -> None:
        self._engine = ingestion_engine
        self._poll_callback = poll_callback
        self._jitter_max = jitter_max
        self._configs: Dict[str, FeedScheduleConfig] = {}
        self._records: Dict[str, FeedPollRecord] = {}
        self._fetcher = FeedFetcher()
        self._running = False
        self._start_time: Optional[float] = None
        self._lock = asyncio.Lock()
        self._session_iocs = 0

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_feed(self, config: FeedScheduleConfig) -> None:
        name = config.source.name
        self._configs[name] = config
        if name not in self._records:
            self._records[name] = FeedPollRecord(feed_name=name)
            # Stagger initial polls with jitter
            import random
            self._records[name].next_poll_at = time.time() + random.uniform(0, self._jitter_max)
        logger.info("Registered feed for scheduling: %s (interval=%ds)", name, config.poll_interval)

    def remove_feed(self, name: str) -> None:
        self._configs.pop(name, None)
        self._records.pop(name, None)
        logger.info("Removed feed from scheduler: %s", name)

    def enable_feed(self, name: str) -> None:
        if name in self._records:
            self._records[name].health = FeedHealth.HEALTHY
            self._records[name].consecutive_failures = 0
            self._records[name].next_poll_at = time.time()
            logger.info("Feed re-enabled: %s", name)

    def disable_feed(self, name: str) -> None:
        if name in self._records:
            self._records[name].health = FeedHealth.DISABLED
            logger.info("Feed disabled: %s", name)

    # ------------------------------------------------------------------
    # Main scheduler loop
    # ------------------------------------------------------------------

    async def run_forever(self, tick_interval: float = 30.0) -> None:
        """Run the scheduler indefinitely, checking for due polls every tick."""
        self._running = True
        self._start_time = time.time()
        logger.info("Feed scheduler started (%d feeds registered)", len(self._configs))

        try:
            while self._running:
                await self._tick()
                await asyncio.sleep(tick_interval)
        except asyncio.CancelledError:
            logger.info("Feed scheduler cancelled")
            self._running = False

    async def run_once(self) -> List[FetchResult]:
        """Execute one scheduling tick synchronously and return all results."""
        return await self._tick()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Single tick
    # ------------------------------------------------------------------

    async def _tick(self) -> List[FetchResult]:
        due = [
            name for name, rec in self._records.items()
            if rec.is_due() and rec.health != FeedHealth.DISABLED
        ]

        if not due:
            return []

        tasks = [self._poll_feed(name) for name in due]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)

    # ------------------------------------------------------------------
    # Per-feed poll
    # ------------------------------------------------------------------

    async def _poll_feed(self, name: str) -> FetchResult:
        config = self._configs[name]
        record = self._records[name]
        source = config.source

        record.total_polls += 1
        record.last_poll_at = time.time()

        if not source.url:
            result = FetchResult(
                feed_name=name,
                status=FetchStatus.SKIPPED,
                error="No URL configured",
            )
            self._update_record_on_skip(record, config)
            return result

        logger.debug("Polling feed: %s (%s)", name, source.url)

        result = await self._fetcher.fetch(
            source.url,
            etag=record.etag,
            last_modified=record.last_modified,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            headers=config.extra_headers,
            api_key=source.api_key,
        )
        result.feed_name = name

        record.record_latency(result.latency_ms)

        if result.status == FetchStatus.NOT_MODIFIED:
            self._update_record_on_success(record, config, iocs=0)
            logger.debug("Feed %s: not modified (304), skipping ingestion", name)

        elif result.status == FetchStatus.SUCCESS:
            # Update cache headers for next request
            if result.etag:
                record.etag = result.etag
            if result.last_modified:
                record.last_modified = result.last_modified

            # Ingest the fetched data
            stats = self._ingest_content(name, result.content)
            result.ingestion_stats = stats
            iocs = stats.new_iocs + stats.updated_iocs if stats else 0
            self._session_iocs += iocs
            self._update_record_on_success(record, config, iocs=iocs)

            logger.info(
                "Feed %s: fetched %d bytes, ingested %d new IOCs in %.0fms",
                name, len(result.content), iocs, result.latency_ms,
            )

        else:
            # Error path
            self._update_record_on_error(record, config, result.error or "unknown")
            logger.warning(
                "Feed %s: poll failed (%s), consecutive_failures=%d, next in %ds",
                name, result.error, record.consecutive_failures,
                max(0, int(record.next_poll_at - time.time())),
            )

        # Fire callback
        if self._poll_callback:
            try:
                self._poll_callback(result)
            except Exception:  # noqa: BLE001
                pass

        return result

    # ------------------------------------------------------------------
    # Ingestion bridge
    # ------------------------------------------------------------------

    def _ingest_content(self, feed_name: str, content: bytes) -> Optional[IngestionStats]:
        if not content:
            return None
        try:
            text = content.decode("utf-8", errors="replace")
            return self._engine.ingest(feed_name, text)
        except Exception as exc:  # noqa: BLE001
            logger.error("Ingestion error for feed %s: %s", feed_name, exc)
            return None

    # ------------------------------------------------------------------
    # Record update helpers
    # ------------------------------------------------------------------

    def _update_record_on_success(
        self, record: FeedPollRecord, config: FeedScheduleConfig, iocs: int
    ) -> None:
        record.consecutive_failures = 0
        record.last_success_at = time.time()
        record.total_successes += 1
        record.total_iocs_ingested += iocs
        record.last_error = None
        record.health = FeedHealth.HEALTHY
        record.schedule_next(config.poll_interval)

    def _update_record_on_error(
        self, record: FeedPollRecord, config: FeedScheduleConfig, error: str
    ) -> None:
        record.consecutive_failures += 1
        record.last_error = error
        record.health = FeedHealth.DEGRADED

        if record.consecutive_failures >= config.max_consecutive_failures:
            record.health = FeedHealth.FAILING
            logger.error(
                "Feed %s reached max consecutive failures (%d), marking as FAILING",
                record.feed_name, config.max_consecutive_failures,
            )

        # Exponential backoff: interval * 2^(failures-1), capped at max_backoff
        backoff = min(
            config.poll_interval * (2 ** (record.consecutive_failures - 1)),
            config.max_backoff,
        )
        record.schedule_next(int(backoff))

    def _update_record_on_skip(
        self, record: FeedPollRecord, config: FeedScheduleConfig
    ) -> None:
        record.schedule_next(config.poll_interval)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> SchedulerMetrics:
        m = SchedulerMetrics(
            total_feeds=len(self._configs),
            total_iocs_this_session=self._session_iocs,
            last_updated=datetime.now(timezone.utc),
        )
        if self._start_time:
            m.scheduler_uptime_seconds = time.time() - self._start_time

        for rec in self._records.values():
            if rec.health == FeedHealth.HEALTHY:
                m.healthy_feeds += 1
            elif rec.health == FeedHealth.DEGRADED:
                m.degraded_feeds += 1
            elif rec.health == FeedHealth.FAILING:
                m.failing_feeds += 1
            elif rec.health == FeedHealth.DISABLED:
                m.disabled_feeds += 1

        # Approximate polls per hour from records
        if self._start_time and time.time() > self._start_time:
            elapsed_hours = (time.time() - self._start_time) / 3600.0
            total_polls = sum(r.total_polls for r in self._records.values())
            m.polls_per_hour = total_polls / elapsed_hours if elapsed_hours > 0 else 0.0

        return m

    def get_feed_status(self) -> List[Dict[str, Any]]:
        """Return current status for all registered feeds."""
        return [rec.to_dict() for rec in self._records.values()]

    def get_feed_record(self, name: str) -> Optional[FeedPollRecord]:
        return self._records.get(name)

    # ------------------------------------------------------------------
    # Prometheus-compatible metrics export
    # ------------------------------------------------------------------

    def prometheus_metrics(self) -> str:
        """
        Emit metrics in Prometheus text format.
        Suitable for scraping by a Prometheus exporter or push gateway.
        """
        lines = [
            "# HELP overwatch_feed_health Feed health status (1=healthy, 0=unhealthy)",
            "# TYPE overwatch_feed_health gauge",
        ]
        for name, rec in self._records.items():
            healthy = 1 if rec.health == FeedHealth.HEALTHY else 0
            lines.append(f'overwatch_feed_health{{feed="{name}"}} {healthy}')

        lines += [
            "",
            "# HELP overwatch_feed_consecutive_failures Number of consecutive failures",
            "# TYPE overwatch_feed_consecutive_failures gauge",
        ]
        for name, rec in self._records.items():
            lines.append(
                f'overwatch_feed_consecutive_failures{{feed="{name}"}} {rec.consecutive_failures}'
            )

        lines += [
            "",
            "# HELP overwatch_feed_total_polls Total polls since scheduler start",
            "# TYPE overwatch_feed_total_polls counter",
        ]
        for name, rec in self._records.items():
            lines.append(f'overwatch_feed_total_polls{{feed="{name}"}} {rec.total_polls}')

        lines += [
            "",
            "# HELP overwatch_feed_iocs_ingested Total IOCs ingested from this feed",
            "# TYPE overwatch_feed_iocs_ingested counter",
        ]
        for name, rec in self._records.items():
            lines.append(
                f'overwatch_feed_iocs_ingested{{feed="{name}"}} {rec.total_iocs_ingested}'
            )

        lines += [
            "",
            "# HELP overwatch_feed_avg_latency_ms Average poll latency in ms (last 10)",
            "# TYPE overwatch_feed_avg_latency_ms gauge",
        ]
        for name, rec in self._records.items():
            lines.append(
                f'overwatch_feed_avg_latency_ms{{feed="{name}"}} {rec.avg_latency_ms:.1f}'
            )

        lines += [
            "",
            "# HELP overwatch_scheduler_total_iocs Total IOCs ingested this session",
            "# TYPE overwatch_scheduler_total_iocs counter",
            f"overwatch_scheduler_total_iocs {self._session_iocs}",
        ]

        if self._start_time:
            uptime = time.time() - self._start_time
            lines += [
                "",
                "# HELP overwatch_scheduler_uptime_seconds Scheduler uptime in seconds",
                "# TYPE overwatch_scheduler_uptime_seconds counter",
                f"overwatch_scheduler_uptime_seconds {uptime:.1f}",
            ]

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Preconfigured common feeds
# ---------------------------------------------------------------------------

def build_default_schedule_configs(
    abuse_ch_enabled: bool = True,
    otx_api_key: Optional[str] = None,
) -> List[FeedScheduleConfig]:
    """
    Return a list of FeedScheduleConfigs for well-known public threat feeds.
    Pass otx_api_key to enable AlienVault OTX polling.
    """
    from overwatch.feed_ingestion import FeedFormat

    configs: List[FeedScheduleConfig] = []

    if abuse_ch_enabled:
        # URLhaus feed (updated every 5 min)
        configs.append(FeedScheduleConfig(
            source=FeedSource(
                name="abuse_ch_urlhaus",
                format=FeedFormat.ABUSECH_URLHAUS,
                url="https://urlhaus.abuse.ch/downloads/json/",
                poll_interval=600,
                default_confidence=85,
                tags=["abuse.ch", "urlhaus", "malware_urls"],
            ),
            poll_interval=600,
            min_interval=300,
        ))

        # MalwareBazaar (updated every 5 min)
        configs.append(FeedScheduleConfig(
            source=FeedSource(
                name="abuse_ch_malwarebazaar",
                format=FeedFormat.ABUSECH_MALWAREBAZAAR,
                url="https://mb-api.abuse.ch/api/v1/",
                poll_interval=600,
                default_confidence=90,
                tags=["abuse.ch", "malwarebazaar", "malware_hashes"],
            ),
            poll_interval=600,
            min_interval=300,
        ))

        # Feodo Tracker (updated hourly)
        configs.append(FeedScheduleConfig(
            source=FeedSource(
                name="abuse_ch_feodo",
                format=FeedFormat.ABUSECH_FEODO,
                url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                poll_interval=3600,
                default_confidence=90,
                tags=["abuse.ch", "feodo", "botnet_c2"],
            ),
            poll_interval=3600,
            min_interval=1800,
        ))

    if otx_api_key:
        configs.append(FeedScheduleConfig(
            source=FeedSource(
                name="otx_subscribed_pulses",
                format=FeedFormat.OTX_PULSE,
                url="https://otx.alienvault.com/api/v1/pulses/subscribed",
                api_key=otx_api_key,
                poll_interval=1800,
                default_confidence=75,
                tags=["otx", "alienvault"],
            ),
            poll_interval=1800,
            min_interval=600,
            extra_headers={"X-OTX-API-KEY": otx_api_key},
        ))

    return configs
