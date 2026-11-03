"""
SOC notification dispatcher for Overwatch alerts.

Routes IOC-triggered alerts and playbook execution results to external
communication channels: Slack, Microsoft Teams, PagerDuty Events API v2,
and generic JSON webhooks. Supports per-channel rate limiting, payload
deduplication, and configurable severity thresholds.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from overwatch.models import IOC, AlertTriage, Severity
from overwatch.playbook import PlaybookExecution, PlaybookStatus

logger = logging.getLogger(__name__)


class ChannelType(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC_WEBHOOK = "generic_webhook"


class NotificationEvent(str, Enum):
    IOC_DETECTED = "ioc_detected"
    ALERT_ESCALATED = "alert_escalated"
    PLAYBOOK_COMPLETED = "playbook_completed"
    PLAYBOOK_FAILED = "playbook_failed"
    FEED_DOWN = "feed_down"
    HIGH_CONFIDENCE_MATCH = "high_confidence_match"


# Severity -> PagerDuty severity mapping
_PD_SEVERITY: Dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}

# Severity -> Slack colour mapping
_SLACK_COLOR: Dict[Severity, str] = {
    Severity.CRITICAL: "#B22222",
    Severity.HIGH: "#FF4500",
    Severity.MEDIUM: "#FFA500",
    Severity.LOW: "#FFD700",
    Severity.INFO: "#1E90FF",
}


@dataclass
class ChannelConfig:
    """Configuration for a single notification channel."""

    channel_id: str
    channel_type: ChannelType
    webhook_url: str
    # Minimum severity that triggers a notification on this channel
    min_severity: Severity = Severity.MEDIUM
    # Events that this channel subscribes to (empty = all)
    subscribed_events: List[NotificationEvent] = field(default_factory=list)
    # Max notifications per minute (0 = unlimited)
    rate_limit_per_minute: int = 30
    enabled: bool = True
    # Extra headers (e.g. Authorization for PagerDuty)
    extra_headers: Dict[str, str] = field(default_factory=dict)
    # PagerDuty routing key (only for PAGERDUTY channels)
    routing_key: str = ""


@dataclass
class NotificationResult:
    channel_id: str
    event: NotificationEvent
    success: bool
    http_status: Optional[int] = None
    error: Optional[str] = None
    deduped: bool = False
    rate_limited: bool = False
    duration_ms: float = 0.0


class _RateLimiter:
    """Token-bucket rate limiter per channel."""

    def __init__(self, rate_per_minute: int) -> None:
        self._rate = rate_per_minute
        self._tokens: float = float(rate_per_minute)
        self._last_refill: float = time.monotonic()

    def allow(self) -> bool:
        if self._rate == 0:
            return True
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._rate),
            self._tokens + elapsed * (self._rate / 60.0),
        )
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class NotificationDispatcher:
    """
    Routes alerts and playbook results to configured external channels.

    Usage::

        dispatcher = NotificationDispatcher()
        dispatcher.add_channel(ChannelConfig(
            channel_id="slack-soc",
            channel_type=ChannelType.SLACK,
            webhook_url="https://hooks.slack.com/services/...",
            min_severity=Severity.HIGH,
        ))
        dispatcher.notify_ioc(ioc)
    """

    # Dedup window in seconds — identical payload fingerprints within this
    # window are suppressed.
    DEDUP_WINDOW_SECONDS: int = 300

    def __init__(self, dedup_window: int = DEDUP_WINDOW_SECONDS) -> None:
        self._channels: Dict[str, ChannelConfig] = {}
        self._rate_limiters: Dict[str, _RateLimiter] = {}
        self._dedup_cache: Dict[str, float] = {}  # fingerprint -> timestamp
        self._dedup_window = dedup_window

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------

    def add_channel(self, config: ChannelConfig) -> None:
        self._channels[config.channel_id] = config
        self._rate_limiters[config.channel_id] = _RateLimiter(
            config.rate_limit_per_minute
        )
        logger.info(
            "Registered channel %s (%s) min_severity=%s",
            config.channel_id,
            config.channel_type,
            config.min_severity,
        )

    def remove_channel(self, channel_id: str) -> None:
        self._channels.pop(channel_id, None)
        self._rate_limiters.pop(channel_id, None)

    @property
    def channel_ids(self) -> List[str]:
        return list(self._channels.keys())

    # ------------------------------------------------------------------
    # Public dispatch helpers
    # ------------------------------------------------------------------

    def notify_ioc(self, ioc: IOC) -> List[NotificationResult]:
        """Dispatch an IOC-detected notification to all eligible channels."""
        event = (
            NotificationEvent.HIGH_CONFIDENCE_MATCH
            if ioc.confidence >= 0.9
            else NotificationEvent.IOC_DETECTED
        )
        fields = {
            "IOC": ioc.value,
            "Type": ioc.ioc_type.value,
            "Confidence": f"{ioc.confidence:.0%}",
            "Tags": ", ".join(sorted(ioc.tags)) if ioc.tags else "—",
            "Source": ioc.source,
        }
        title = f"[{ioc.severity.value.upper()}] IOC Detected: {ioc.value}"
        return self._dispatch_all(
            event=event,
            severity=ioc.severity,
            title=title,
            summary=f"{ioc.ioc_type.value} {ioc.value} matched with {ioc.confidence:.0%} confidence",
            fields=fields,
        )

    def notify_alert(self, alert: AlertTriage) -> List[NotificationResult]:
        """Dispatch an alert-escalated notification."""
        fields = {
            "Alert ID": alert.alert_id,
            "Rule": alert.rule_name,
            "Status": alert.status.value,
            "IOC Matches": str(len(alert.matched_iocs)),
        }
        title = f"[{alert.severity.value.upper()}] Alert Escalated: {alert.rule_name}"
        return self._dispatch_all(
            event=NotificationEvent.ALERT_ESCALATED,
            severity=alert.severity,
            title=title,
            summary=f"Alert '{alert.rule_name}' escalated with {len(alert.matched_iocs)} IOC matches",
            fields=fields,
        )

    def notify_playbook(
        self, execution: PlaybookExecution
    ) -> List[NotificationResult]:
        """Dispatch a playbook completion or failure notification."""
        event = (
            NotificationEvent.PLAYBOOK_FAILED
            if execution.status == PlaybookStatus.FAILED
            else NotificationEvent.PLAYBOOK_COMPLETED
        )
        severity = (
            Severity.HIGH
            if execution.status == PlaybookStatus.FAILED
            else Severity.INFO
        )
        fields: Dict[str, str] = {
            "Playbook": execution.playbook_name,
            "Status": execution.status.value,
            "Steps": str(len(execution.steps)),
            "Succeeded": str(execution.success_count),
            "Failed": str(execution.failure_count),
        }
        if execution.duration_ms is not None:
            fields["Duration"] = f"{execution.duration_ms:.0f} ms"
        if execution.error:
            fields["Error"] = execution.error[:200]
        title = f"Playbook '{execution.playbook_name}' {execution.status.value}"
        return self._dispatch_all(
            event=event,
            severity=severity,
            title=title,
            summary=f"Playbook {execution.playbook_name}: {execution.success_count}/{len(execution.steps)} steps succeeded",
            fields=fields,
        )

    def notify_feed_down(self, feed_name: str, reason: str) -> List[NotificationResult]:
        """Dispatch a feed-down notification."""
        fields = {"Feed": feed_name, "Reason": reason}
        return self._dispatch_all(
            event=NotificationEvent.FEED_DOWN,
            severity=Severity.HIGH,
            title=f"Feed Down: {feed_name}",
            summary=f"Threat feed '{feed_name}' is unavailable: {reason}",
            fields=fields,
        )

    # ------------------------------------------------------------------
    # Core dispatch logic
    # ------------------------------------------------------------------

    def _dispatch_all(
        self,
        event: NotificationEvent,
        severity: Severity,
        title: str,
        summary: str,
        fields: Dict[str, str],
    ) -> List[NotificationResult]:
        results: List[NotificationResult] = []
        for channel in self._channels.values():
            if not channel.enabled:
                continue
            if not self._severity_passes(severity, channel.min_severity):
                continue
            if channel.subscribed_events and event not in channel.subscribed_events:
                continue
            result = self._dispatch_one(
                channel=channel,
                event=event,
                severity=severity,
                title=title,
                summary=summary,
                fields=fields,
            )
            results.append(result)
        return results

    def _dispatch_one(
        self,
        channel: ChannelConfig,
        event: NotificationEvent,
        severity: Severity,
        title: str,
        summary: str,
        fields: Dict[str, str],
    ) -> NotificationResult:
        # Rate-limit check
        limiter = self._rate_limiters[channel.channel_id]
        if not limiter.allow():
            logger.debug("Rate-limited channel %s", channel.channel_id)
            return NotificationResult(
                channel_id=channel.channel_id,
                event=event,
                success=False,
                rate_limited=True,
            )

        # Deduplication check
        fingerprint = self._make_fingerprint(channel.channel_id, event, title, fields)
        if self._is_duplicate(fingerprint):
            logger.debug("Deduped notification for channel %s", channel.channel_id)
            return NotificationResult(
                channel_id=channel.channel_id,
                event=event,
                success=True,
                deduped=True,
            )

        # Build payload
        try:
            if channel.channel_type == ChannelType.SLACK:
                payload = self._build_slack_payload(title, summary, severity, fields)
            elif channel.channel_type == ChannelType.TEAMS:
                payload = self._build_teams_payload(title, summary, severity, fields)
            elif channel.channel_type == ChannelType.PAGERDUTY:
                payload = self._build_pagerduty_payload(
                    channel.routing_key, title, summary, severity, fields
                )
            else:
                payload = self._build_generic_payload(
                    event, title, summary, severity, fields
                )
        except Exception as exc:  # pragma: no cover
            return NotificationResult(
                channel_id=channel.channel_id,
                event=event,
                success=False,
                error=f"payload build error: {exc}",
            )

        # Send
        start = time.monotonic()
        ok, status_code, err = self._send(
            url=channel.webhook_url,
            payload=payload,
            extra_headers=channel.extra_headers,
        )
        duration_ms = (time.monotonic() - start) * 1000

        if ok:
            self._record_fingerprint(fingerprint)

        result = NotificationResult(
            channel_id=channel.channel_id,
            event=event,
            success=ok,
            http_status=status_code,
            error=err,
            duration_ms=duration_ms,
        )
        if not ok:
            logger.warning(
                "Notification to channel %s failed (HTTP %s): %s",
                channel.channel_id,
                status_code,
                err,
            )
        return result

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    def _build_slack_payload(
        self,
        title: str,
        summary: str,
        severity: Severity,
        fields: Dict[str, str],
    ) -> Dict[str, Any]:
        color = _SLACK_COLOR.get(severity, "#808080")
        field_blocks = [
            {"type": "mrkdwn", "text": f"*{k}*\n{v}"}
            for k, v in fields.items()
        ]
        # Slack Block Kit: header + attachment for colour bar
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": title, "emoji": True},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
        ]
        if field_blocks:
            # Spread into 2-column section fields (max 10)
            blocks.append(
                {"type": "section", "fields": field_blocks[:10]}
            )
        blocks.append({"type": "divider"})
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                    "fallback": summary,
                }
            ]
        }

    def _build_teams_payload(
        self,
        title: str,
        summary: str,
        severity: Severity,
        fields: Dict[str, str],
    ) -> Dict[str, Any]:
        """Microsoft Teams Incoming Webhook (Adaptive Card v1.4 via messageCard)."""
        facts = [
            {"name": k, "value": v}
            for k, v in fields.items()
        ]
        theme_color = _SLACK_COLOR.get(severity, "#808080").lstrip("#")
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "summary": summary,
            "sections": [
                {
                    "activityTitle": title,
                    "activityText": summary,
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

    def _build_pagerduty_payload(
        self,
        routing_key: str,
        title: str,
        summary: str,
        severity: Severity,
        fields: Dict[str, str],
    ) -> Dict[str, Any]:
        """PagerDuty Events API v2 trigger payload."""
        pd_severity = _PD_SEVERITY.get(severity, "warning")
        return {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": pd_severity,
                "source": "overwatch",
                "custom_details": {**fields, "description": summary},
            },
            "client": "Overwatch SOAR",
        }

    def _build_generic_payload(
        self,
        event: NotificationEvent,
        title: str,
        summary: str,
        severity: Severity,
        fields: Dict[str, str],
    ) -> Dict[str, Any]:
        return {
            "source": "overwatch",
            "event": event.value,
            "severity": severity.value,
            "title": title,
            "summary": summary,
            "fields": fields,
            "timestamp": time.time(),
        }

    # ------------------------------------------------------------------
    # HTTP transport
    # ------------------------------------------------------------------

    def _send(
        self,
        url: str,
        payload: Dict[str, Any],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """POST JSON payload to the webhook URL.  Returns (ok, status, error)."""
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Overwatch-NotificationDispatcher/1.0",
        }
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                ok = 200 <= status < 300
                return ok, status, None
        except urllib.error.HTTPError as exc:
            return False, exc.code, str(exc.reason)
        except Exception as exc:
            return False, None, str(exc)

    # ------------------------------------------------------------------
    # Deduplication helpers
    # ------------------------------------------------------------------

    def _make_fingerprint(
        self,
        channel_id: str,
        event: NotificationEvent,
        title: str,
        fields: Dict[str, str],
    ) -> str:
        raw = json.dumps(
            {"channel": channel_id, "event": event.value, "title": title, "fields": fields},
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _is_duplicate(self, fingerprint: str) -> bool:
        now = time.time()
        ts = self._dedup_cache.get(fingerprint)
        return ts is not None and (now - ts) < self._dedup_window

    def _record_fingerprint(self, fingerprint: str) -> None:
        self._dedup_cache[fingerprint] = time.time()
        # Prune stale entries to bound memory usage
        now = time.time()
        stale = [
            k for k, ts in self._dedup_cache.items()
            if (now - ts) > self._dedup_window
        ]
        for k in stale:
            del self._dedup_cache[k]

    @staticmethod
    def _severity_passes(event_severity: Severity, min_severity: Severity) -> bool:
        return event_severity.score >= min_severity.score
