"""
Alert processing pipeline.
Orchestrates ingestion -> IOC matching -> enrichment -> deduplication -> triage -> playbook dispatch.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from overwatch.deduplication import AlertDeduplicator
from overwatch.enrichment import EnrichmentPipeline
from overwatch.ioc_store import IOCStore
from overwatch.models import AlertTriage, IOC, IOCType, PlaybookAction, Severity

logger = logging.getLogger(__name__)


class PipelineStage(str, Enum):
    IOC_MATCH = "ioc_match"
    ENRICHMENT = "enrichment"
    DEDUPLICATION = "deduplication"
    SEVERITY_SCORE = "severity_score"
    PLAYBOOK_DISPATCH = "playbook_dispatch"


@dataclass
class RawAlert:
    """Incoming alert before pipeline processing."""
    alert_id: str
    title: str
    description: str
    source: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.MEDIUM
    # Extracted observables before full IOC lookup
    observables: List[Dict[str, str]] = field(default_factory=list)
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PipelineResult:
    raw_alert: RawAlert
    triage: Optional[AlertTriage] = None
    stages_completed: List[str] = field(default_factory=list)
    stage_timings_ms: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    @property
    def success(self) -> bool:
        return self.triage is not None and not self.skipped

    @property
    def total_ms(self) -> float:
        return sum(self.stage_timings_ms.values())


class AlertPipeline:
    """
    Sequential alert processing pipeline with per-stage timing.

    Each stage is a callable (sync or async) that receives and mutates
    a PipelineResult. Stages can short-circuit by setting result.skipped.
    """

    def __init__(
        self,
        ioc_store: IOCStore,
        enrichment_pipeline: Optional[EnrichmentPipeline] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
        max_ioc_matches: int = 20,
    ) -> None:
        self.ioc_store = ioc_store
        self.enrichment = enrichment_pipeline or EnrichmentPipeline()
        self.dedup = deduplicator or AlertDeduplicator()
        self.max_ioc_matches = max_ioc_matches

        self._processed = 0
        self._duplicates = 0
        self._errors = 0

    def process(self, raw: RawAlert) -> PipelineResult:
        """Synchronous pipeline execution."""
        result = PipelineResult(raw_alert=raw)

        stages = [
            (PipelineStage.IOC_MATCH, self._stage_ioc_match),
            (PipelineStage.ENRICHMENT, self._stage_enrichment),
            (PipelineStage.DEDUPLICATION, self._stage_deduplication),
            (PipelineStage.SEVERITY_SCORE, self._stage_severity_score),
            (PipelineStage.PLAYBOOK_DISPATCH, self._stage_playbook_dispatch),
        ]

        # Build initial AlertTriage object
        result.triage = AlertTriage(
            alert_id=raw.alert_id,
            title=raw.title,
            description=raw.description,
            severity=raw.severity,
            source=raw.source,
            raw_data=raw.raw_data,
        )

        for stage_name, stage_fn in stages:
            if result.skipped:
                break
            t0 = time.monotonic()
            try:
                stage_fn(result)
                result.stages_completed.append(stage_name.value)
            except Exception as exc:
                result.errors.append(f"{stage_name.value}: {exc}")
                self._errors += 1
                logger.warning("Pipeline stage %s failed for alert %s: %s",
                               stage_name.value, raw.alert_id, exc)
            finally:
                elapsed = (time.monotonic() - t0) * 1000
                result.stage_timings_ms[stage_name.value] = elapsed

        self._processed += 1
        if result.skipped:
            self._duplicates += 1

        return result

    async def process_async(self, raw: RawAlert) -> PipelineResult:
        """Async wrapper — runs the sync pipeline in executor to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.process, raw)

    async def process_batch(
        self, raws: List[RawAlert], concurrency: int = 8
    ) -> List[PipelineResult]:
        """Process a batch of alerts with bounded concurrency."""
        sem = asyncio.Semaphore(concurrency)

        async def _guarded(raw: RawAlert) -> PipelineResult:
            async with sem:
                return await self.process_async(raw)

        return await asyncio.gather(*[_guarded(r) for r in raws])

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "processed": self._processed,
            "duplicates": self._duplicates,
            "errors": self._errors,
        }

    # ------------------------------------------------------------------
    # Pipeline stages

    def _stage_ioc_match(self, result: PipelineResult) -> None:
        """Match observables in the raw alert against the IOC store."""
        assert result.triage is not None
        matched: List[IOC] = []

        for obs in result.raw_alert.observables:
            obs_type_str = obs.get("type", "")
            obs_value = obs.get("value", "")
            if not obs_value:
                continue

            try:
                ioc_type = IOCType(obs_type_str)
            except ValueError:
                continue

            ioc = self.ioc_store.lookup(ioc_type, obs_value)
            if ioc:
                ioc.record_hit()
                matched.append(ioc)
                if len(matched) >= self.max_ioc_matches:
                    break

        result.triage.matched_iocs = matched

        # Aggregate MITRE techniques from matched IOCs
        techs: set = set()
        for ioc in matched:
            techs.update(ioc.mitre_techniques)
        result.triage.mitre_techniques = list(techs)

    def _stage_enrichment(self, result: PipelineResult) -> None:
        """Run enrichment pipeline over matched IOCs."""
        assert result.triage is not None
        enriched = []
        for ioc in result.triage.matched_iocs:
            enriched_ioc = self.enrichment.enrich(ioc)
            enriched.append(enriched_ioc)
            self.ioc_store.add(enriched_ioc)
        result.triage.matched_iocs = enriched

    def _stage_deduplication(self, result: PipelineResult) -> None:
        """Check for duplicate alerts."""
        assert result.triage is not None
        dup_id = self.dedup.find_duplicate(result.triage)
        if dup_id:
            result.triage.is_duplicate = True
            result.triage.duplicate_of = dup_id
            result.skipped = True
            result.skip_reason = f"duplicate of {dup_id}"
        else:
            self.dedup.register(result.triage)

    def _stage_severity_score(self, result: PipelineResult) -> None:
        """Recalculate severity based on matched IOC risk scores."""
        assert result.triage is not None
        if not result.triage.matched_iocs:
            return

        max_ioc_severity = max(
            (ioc.severity for ioc in result.triage.matched_iocs),
            key=lambda s: s.score,
            default=None,
        )
        if max_ioc_severity and max_ioc_severity.score > result.triage.severity.score:
            result.triage.severity = max_ioc_severity
            logger.debug(
                "Alert %s severity escalated to %s",
                result.triage.alert_id,
                max_ioc_severity.value,
            )

    def _stage_playbook_dispatch(self, result: PipelineResult) -> None:
        """Determine recommended playbook actions based on matched IOCs and severity."""
        assert result.triage is not None
        actions: List[PlaybookAction] = []

        severity = result.triage.severity
        matched_types = {ioc.ioc_type for ioc in result.triage.matched_iocs}

        # Always enrich
        actions.append(PlaybookAction.ENRICH_ALERT)

        if IOCType.IPV4 in matched_types or IOCType.IPV6 in matched_types:
            actions.append(PlaybookAction.BLOCK_IP)

        if IOCType.DOMAIN in matched_types or IOCType.URL in matched_types:
            actions.append(PlaybookAction.BLOCK_DOMAIN)

        if severity in (Severity.HIGH, Severity.CRITICAL):
            actions.append(PlaybookAction.NOTIFY_SOC)
            actions.append(PlaybookAction.CREATE_TICKET)

        if severity == Severity.CRITICAL:
            actions.append(PlaybookAction.QUARANTINE_HOST)
            actions.append(PlaybookAction.COLLECT_FORENSICS)

        if IOCType.FILE_HASH_SHA256 in matched_types or IOCType.FILE_HASH_MD5 in matched_types:
            actions.append(PlaybookAction.COLLECT_FORENSICS)

        if IOCType.EMAIL in matched_types:
            actions.append(PlaybookAction.RESET_CREDENTIALS)

        # Deduplicate while preserving order
        seen: set = set()
        result.triage.recommended_actions = [
            a for a in actions if not (a in seen or seen.add(a))
        ]


def build_pipeline(ioc_store: IOCStore) -> AlertPipeline:
    """Convenience factory with default components."""
    return AlertPipeline(
        ioc_store=ioc_store,
        enrichment_pipeline=EnrichmentPipeline(),
        deduplicator=AlertDeduplicator(),
    )
