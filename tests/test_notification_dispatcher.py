"""
Tests for notification_dispatcher module.
"""

from __future__ import annotations

import json
import time
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from overwatch.models import IOC, IOCType, Severity, TLPLevel
from overwatch.notification_dispatcher import (
    ChannelConfig,
    ChannelType,
    NotificationDispatcher,
    NotificationEvent,
    NotificationResult,
    _RateLimiter,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ioc(
    value: str = "192.168.1.99",
    ioc_type: IOCType = IOCType.IPV4,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.85,
    tags: Optional[List[str]] = None,
) -> IOC:
    return IOC(
        value=value,
        ioc_type=ioc_type,
        severity=severity,
        confidence=confidence,
        source="test_feed",
        tags=set(tags or []),
    )


def _make_channel(
    channel_id: str = "test-slack",
    channel_type: ChannelType = ChannelType.SLACK,
    min_severity: Severity = Severity.LOW,
    rate_limit: int = 0,
) -> ChannelConfig:
    return ChannelConfig(
        channel_id=channel_id,
        channel_type=channel_type,
        webhook_url="https://hooks.example.com/test",
        min_severity=min_severity,
        rate_limit_per_minute=rate_limit,
    )


@pytest.fixture
def dispatcher() -> NotificationDispatcher:
    return NotificationDispatcher(dedup_window=60)


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_unlimited_always_allows(self) -> None:
        limiter = _RateLimiter(0)
        for _ in range(1000):
            assert limiter.allow()

    def test_rate_limited_blocks_after_burst(self) -> None:
        # 1 token/minute = 1 immediate call allowed
        limiter = _RateLimiter(1)
        assert limiter.allow()       # first token
        assert not limiter.allow()   # bucket empty

    def test_tokens_refill_over_time(self) -> None:
        limiter = _RateLimiter(60)   # 1 token/second
        # drain completely
        for _ in range(60):
            limiter.allow()
        # artificially advance last refill time by 2 seconds
        limiter._last_refill -= 2.0
        assert limiter.allow()
        assert limiter.allow()


# ---------------------------------------------------------------------------
# Channel management
# ---------------------------------------------------------------------------


class TestChannelManagement:
    def test_add_channel(self, dispatcher: NotificationDispatcher) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        assert "test-slack" in dispatcher.channel_ids

    def test_remove_channel(self, dispatcher: NotificationDispatcher) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        dispatcher.remove_channel("test-slack")
        assert "test-slack" not in dispatcher.channel_ids

    def test_remove_nonexistent_is_noop(self, dispatcher: NotificationDispatcher) -> None:
        dispatcher.remove_channel("ghost")  # must not raise

    def test_disabled_channel_not_dispatched(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        ch.enabled = False
        dispatcher.add_channel(ch)
        ioc = _make_ioc()
        with patch.object(dispatcher, "_send") as mock_send:
            dispatcher.notify_ioc(ioc)
            mock_send.assert_not_called()


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------


class TestSeverityFilter:
    def test_severity_below_threshold_skipped(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel(min_severity=Severity.CRITICAL)
        dispatcher.add_channel(ch)
        ioc = _make_ioc(severity=Severity.LOW)
        with patch.object(dispatcher, "_send") as mock_send:
            results = dispatcher.notify_ioc(ioc)
        assert results == []
        mock_send.assert_not_called()

    def test_severity_at_threshold_dispatched(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel(min_severity=Severity.HIGH)
        dispatcher.add_channel(ch)
        ioc = _make_ioc(severity=Severity.HIGH)
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert len(results) == 1
        assert results[0].success

    def test_severity_above_threshold_dispatched(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel(min_severity=Severity.MEDIUM)
        dispatcher.add_channel(ch)
        ioc = _make_ioc(severity=Severity.CRITICAL)
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Event subscription filtering
# ---------------------------------------------------------------------------


class TestEventFilter:
    def test_subscribed_event_dispatched(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        ch.subscribed_events = [NotificationEvent.IOC_DETECTED]
        dispatcher.add_channel(ch)
        ioc = _make_ioc(confidence=0.5)  # not high-confidence, so IOC_DETECTED
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert len(results) == 1

    def test_unsubscribed_event_skipped(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        ch.subscribed_events = [NotificationEvent.PLAYBOOK_COMPLETED]
        dispatcher.add_channel(ch)
        ioc = _make_ioc(confidence=0.5)
        with patch.object(dispatcher, "_send") as mock_send:
            results = dispatcher.notify_ioc(ioc)
        assert results == []
        mock_send.assert_not_called()

    def test_empty_subscriptions_receives_all(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        ch.subscribed_events = []
        dispatcher.add_channel(ch)
        ioc = _make_ioc()
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_duplicate_suppressed(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        ioc = _make_ioc()
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)) as mock_send:
            r1 = dispatcher.notify_ioc(ioc)
            r2 = dispatcher.notify_ioc(ioc)
        # First send goes through, second is deduped
        assert mock_send.call_count == 1
        assert not r1[0].deduped
        assert r2[0].deduped

    def test_different_iocs_not_deduped(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        ioc1 = _make_ioc("10.0.0.1")
        ioc2 = _make_ioc("10.0.0.2")
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)) as mock_send:
            dispatcher.notify_ioc(ioc1)
            dispatcher.notify_ioc(ioc2)
        assert mock_send.call_count == 2

    def test_expired_dedup_allows_resend(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        dispatcher_short = NotificationDispatcher(dedup_window=1)
        ch = _make_channel()
        dispatcher_short.add_channel(ch)
        ioc = _make_ioc()
        with patch.object(dispatcher_short, "_send", return_value=(True, 200, None)) as mock_send:
            dispatcher_short.notify_ioc(ioc)
        # Artificially expire the cache entry
        for k in list(dispatcher_short._dedup_cache):
            dispatcher_short._dedup_cache[k] -= 10
        with patch.object(dispatcher_short, "_send", return_value=(True, 200, None)) as mock_send2:
            dispatcher_short.notify_ioc(ioc)
        assert mock_send2.call_count == 1


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_rate_limited_channel_returns_rate_limited_result(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel(rate_limit=1)  # 1 per minute = 1 token
        dispatcher.add_channel(ch)
        ioc1 = _make_ioc("10.0.0.1")
        ioc2 = _make_ioc("10.0.0.2")
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            r1 = dispatcher.notify_ioc(ioc1)
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)) as mock_send2:
            r2 = dispatcher.notify_ioc(ioc2)
        assert not r1[0].rate_limited
        assert r2[0].rate_limited
        mock_send2.assert_not_called()


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


class TestPayloadBuilders:
    def test_slack_payload_structure(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        payload = dispatcher._build_slack_payload(
            title="Test Alert",
            summary="Something happened",
            severity=Severity.HIGH,
            fields={"Key": "Value"},
        )
        assert "attachments" in payload
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#FF4500"  # HIGH color
        assert any(
            b.get("type") == "header" for b in attachment["blocks"]
        )

    def test_teams_payload_structure(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        payload = dispatcher._build_teams_payload(
            title="Test Alert",
            summary="Summary",
            severity=Severity.CRITICAL,
            fields={"A": "B"},
        )
        assert payload["@type"] == "MessageCard"
        assert payload["sections"][0]["facts"] == [{"name": "A", "value": "B"}]

    def test_pagerduty_payload_structure(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        payload = dispatcher._build_pagerduty_payload(
            routing_key="abc123",
            title="Critical IOC",
            summary="Details here",
            severity=Severity.CRITICAL,
            fields={"IOC": "1.2.3.4"},
        )
        assert payload["routing_key"] == "abc123"
        assert payload["event_action"] == "trigger"
        assert payload["payload"]["severity"] == "critical"

    def test_generic_payload_contains_event_field(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        payload = dispatcher._build_generic_payload(
            event=NotificationEvent.FEED_DOWN,
            title="Feed Down",
            summary="xyz feed unavailable",
            severity=Severity.HIGH,
            fields={"Feed": "xyz"},
        )
        assert payload["event"] == "feed_down"
        assert payload["source"] == "overwatch"

    def test_high_confidence_ioc_uses_high_confidence_event(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        ioc = _make_ioc(confidence=0.95)
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert results[0].event == NotificationEvent.HIGH_CONFIDENCE_MATCH

    def test_notify_feed_down_dispatches(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel(min_severity=Severity.HIGH)
        dispatcher.add_channel(ch)
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_feed_down("abuse_ch", "connection refused")
        assert len(results) == 1
        assert results[0].event == NotificationEvent.FEED_DOWN


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------


class TestHttpTransport:
    def test_send_returns_ok_on_200(self, dispatcher: NotificationDispatcher) -> None:
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status = 200
        with patch("urllib.request.urlopen", return_value=mock_response):
            ok, status, err = dispatcher._send(
                url="https://hooks.example.com/test",
                payload={"text": "hello"},
            )
        assert ok
        assert status == 200
        assert err is None

    def test_send_returns_error_on_http_error(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                url="https://x", code=403, msg="Forbidden", hdrs=None, fp=None
            ),
        ):
            ok, status, err = dispatcher._send(
                url="https://hooks.example.com/test",
                payload={},
            )
        assert not ok
        assert status == 403

    def test_send_returns_error_on_connection_error(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        with patch(
            "urllib.request.urlopen",
            side_effect=ConnectionRefusedError("refused"),
        ):
            ok, status, err = dispatcher._send(
                url="https://hooks.example.com/test",
                payload={},
            )
        assert not ok
        assert status is None
        assert err is not None

    def test_result_records_duration_ms(
        self, dispatcher: NotificationDispatcher
    ) -> None:
        ch = _make_channel()
        dispatcher.add_channel(ch)
        ioc = _make_ioc()
        with patch.object(dispatcher, "_send", return_value=(True, 200, None)):
            results = dispatcher.notify_ioc(ioc)
        assert results[0].duration_ms >= 0.0
