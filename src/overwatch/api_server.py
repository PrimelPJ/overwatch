"""
REST API server for the Overwatch threat intelligence platform.

Exposes endpoints for IOC queries, indicator submission, playbook execution,
alert triage management, and enrichment operations. Designed for SIEM and
external tool integration via HTTP/JSON.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, HTTPException, Query, Request, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

from overwatch.models import (
    IOC,
    IOCType,
    Severity,
    TLPLevel,
    AlertTriage,
    AlertStatus,
)
from overwatch.ioc_store import IOCStore
from overwatch.enrichment import EnrichmentPipeline, EnrichmentSource
from overwatch.playbook import PlaybookExecutor, PlaybookResult
from overwatch.correlation import CorrelationEngine, CorrelationResult
from overwatch.deduplication import DeduplicationEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class IOCSubmitRequest(BaseModel):
    value: str = Field(..., description="Indicator value (IP, domain, hash, URL, etc.)")
    ioc_type: str = Field(..., description="IOC type key from IOCType enum")
    source: str = Field(default="api", description="Feed or submitter name")
    severity: str = Field(default="medium", description="Severity: low/medium/high/critical")
    tlp: str = Field(default="amber", description="TLP level: white/green/amber/red")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)
    ttl_hours: int = Field(default=720, ge=1, le=8760, description="TTL in hours (1–8760)")
    description: str = Field(default="")

    @validator("ioc_type")
    def validate_ioc_type(cls, v: str) -> str:
        valid = {t.value for t in IOCType}
        if v not in valid:
            raise ValueError(f"ioc_type must be one of: {sorted(valid)}")
        return v

    @validator("severity")
    def validate_severity(cls, v: str) -> str:
        valid = {s.value for s in Severity}
        if v not in valid:
            raise ValueError(f"severity must be one of: {sorted(valid)}")
        return v

    @validator("tlp")
    def validate_tlp(cls, v: str) -> str:
        valid = {t.value for t in TLPLevel}
        if v not in valid:
            raise ValueError(f"tlp must be one of: {sorted(valid)}")
        return v


class BulkSubmitRequest(BaseModel):
    indicators: List[IOCSubmitRequest] = Field(..., max_items=500)


class PlaybookRunRequest(BaseModel):
    ioc_id: str = Field(..., description="IOC UUID to execute playbook against")
    playbook_name: str = Field(default="auto", description="Playbook name or 'auto' to select by severity")
    dry_run: bool = Field(default=False)


class TriageUpdateRequest(BaseModel):
    alert_id: str
    status: str = Field(..., description="new/investigating/escalated/resolved/false_positive")
    analyst: str = Field(default="api-user")
    notes: str = Field(default="")


class IOCSearchParams(BaseModel):
    value: Optional[str] = None
    ioc_type: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    min_confidence: float = 0.0
    tags: Optional[List[str]] = None
    active_only: bool = True
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class IOCResponse(BaseModel):
    id: str
    value: str
    ioc_type: str
    source: str
    severity: str
    tlp: str
    confidence: float
    tags: List[str]
    first_seen: str
    last_seen: str
    expiry: Optional[str]
    active: bool
    description: str
    hit_count: int


class EnrichResponse(BaseModel):
    ioc_id: str
    value: str
    enrichments: Dict[str, Any]
    sources_queried: List[str]
    duration_ms: float


class CorrelationResponse(BaseModel):
    ioc_id: str
    related_iocs: List[Dict[str, Any]]
    cluster_id: Optional[str]
    threat_actor: Optional[str]
    campaign: Optional[str]
    confidence: float


class PlaybookResponse(BaseModel):
    run_id: str
    ioc_id: str
    playbook_name: str
    status: str
    steps_total: int
    steps_succeeded: int
    steps_failed: int
    actions_taken: List[str]
    duration_ms: float
    dry_run: bool


class StatsResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    by_source: Dict[str, int]
    enrichments_today: int
    playbooks_run_today: int
    uptime_seconds: float


# ---------------------------------------------------------------------------
# In-memory runtime state (replace with Redis/DB for production)
# ---------------------------------------------------------------------------

class _RuntimeState:
    def __init__(self) -> None:
        self.ioc_store: IOCStore = IOCStore()
        self.enrichment: EnrichmentPipeline = EnrichmentPipeline()
        self.dedup: DeduplicationEngine = DeduplicationEngine()
        self.correlation: CorrelationEngine = CorrelationEngine()
        self.playbook_executor: PlaybookExecutor = PlaybookExecutor()
        self.start_time: float = time.monotonic()
        self.enrichments_today: int = 0
        self.playbooks_today: int = 0

    def uptime(self) -> float:
        return time.monotonic() - self.start_time


_state: Optional[_RuntimeState] = None


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _ioc_to_response(ioc: IOC) -> IOCResponse:
    return IOCResponse(
        id=str(ioc.id),
        value=ioc.value,
        ioc_type=ioc.ioc_type.value,
        source=ioc.source,
        severity=ioc.severity.value,
        tlp=ioc.tlp.value,
        confidence=ioc.confidence,
        tags=list(ioc.tags),
        first_seen=ioc.first_seen.isoformat(),
        last_seen=ioc.last_seen.isoformat(),
        expiry=ioc.expiry.isoformat() if ioc.expiry else None,
        active=ioc.active,
        description=ioc.description,
        hit_count=ioc.hit_count,
    )


def _request_to_ioc(req: IOCSubmitRequest) -> IOC:
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=req.ttl_hours)
    ioc = IOC(
        value=req.value,
        ioc_type=IOCType(req.ioc_type),
        source=req.source,
        severity=Severity(req.severity),
        tlp=TLPLevel(req.tlp),
        confidence=req.confidence,
        tags=set(req.tags),
        first_seen=now,
        last_seen=now,
        expiry=expiry,
        description=req.description,
    )
    return ioc


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> "FastAPI":
    if not HAS_FASTAPI:
        raise RuntimeError("fastapi is required. Install with: pip install fastapi uvicorn")

    global _state

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[type-arg]
        global _state
        _state = _RuntimeState()
        logger.info("Overwatch API server started")
        yield
        logger.info("Overwatch API server shutting down")

    app = FastAPI(
        title="Overwatch Threat Intelligence API",
        description="REST API for IOC management, enrichment, correlation, and automated response",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # Health / status
    # -----------------------------------------------------------------------

    @app.get("/health", tags=["system"])
    async def health_check() -> Dict[str, Any]:
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/stats", response_model=StatsResponse, tags=["system"])
    async def get_stats() -> StatsResponse:
        assert _state is not None
        all_iocs = _state.ioc_store.list_all()
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        active_count = 0
        for ioc in all_iocs:
            by_type[ioc.ioc_type.value] = by_type.get(ioc.ioc_type.value, 0) + 1
            by_severity[ioc.severity.value] = by_severity.get(ioc.severity.value, 0) + 1
            by_source[ioc.source] = by_source.get(ioc.source, 0) + 1
            if ioc.active:
                active_count += 1
        return StatsResponse(
            total_iocs=len(all_iocs),
            active_iocs=active_count,
            by_type=by_type,
            by_severity=by_severity,
            by_source=by_source,
            enrichments_today=_state.enrichments_today,
            playbooks_run_today=_state.playbooks_today,
            uptime_seconds=_state.uptime(),
        )

    # -----------------------------------------------------------------------
    # IOC endpoints
    # -----------------------------------------------------------------------

    @app.post("/iocs", response_model=IOCResponse, status_code=status.HTTP_201_CREATED, tags=["iocs"])
    async def submit_ioc(req: IOCSubmitRequest) -> IOCResponse:
        assert _state is not None
        ioc = _request_to_ioc(req)
        # Deduplication check
        existing = _state.ioc_store.get_by_value(ioc.value, ioc.ioc_type)
        if existing:
            # Update last_seen and merge tags
            existing.last_seen = datetime.now(timezone.utc)
            existing.tags |= ioc.tags
            if ioc.confidence > existing.confidence:
                existing.confidence = ioc.confidence
            _state.ioc_store.update(existing)
            return _ioc_to_response(existing)
        _state.ioc_store.store(ioc)
        return _ioc_to_response(ioc)

    @app.post("/iocs/bulk", tags=["iocs"])
    async def bulk_submit(req: BulkSubmitRequest) -> Dict[str, Any]:
        assert _state is not None
        created = 0
        updated = 0
        errors: List[Dict[str, str]] = []
        for idx, item in enumerate(req.indicators):
            try:
                ioc = _request_to_ioc(item)
                existing = _state.ioc_store.get_by_value(ioc.value, ioc.ioc_type)
                if existing:
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.tags |= ioc.tags
                    _state.ioc_store.update(existing)
                    updated += 1
                else:
                    _state.ioc_store.store(ioc)
                    created += 1
            except Exception as exc:
                errors.append({"index": str(idx), "value": item.value, "error": str(exc)})
        return {
            "created": created,
            "updated": updated,
            "errors": errors,
            "total": len(req.indicators),
        }

    @app.get("/iocs/{ioc_id}", response_model=IOCResponse, tags=["iocs"])
    async def get_ioc(ioc_id: str) -> IOCResponse:
        assert _state is not None
        try:
            uid = uuid.UUID(ioc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IOC ID format")
        ioc = _state.ioc_store.get_by_id(uid)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")
        return _ioc_to_response(ioc)

    @app.delete("/iocs/{ioc_id}", tags=["iocs"])
    async def expire_ioc(ioc_id: str) -> Dict[str, str]:
        assert _state is not None
        try:
            uid = uuid.UUID(ioc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IOC ID format")
        ioc = _state.ioc_store.get_by_id(uid)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")
        ioc.active = False
        _state.ioc_store.update(ioc)
        return {"status": "expired", "id": ioc_id}

    @app.post("/iocs/search", response_model=List[IOCResponse], tags=["iocs"])
    async def search_iocs(params: IOCSearchParams) -> List[IOCResponse]:
        assert _state is not None
        results = _state.ioc_store.search(
            value=params.value,
            ioc_type=IOCType(params.ioc_type) if params.ioc_type else None,
            source=params.source,
            severity=Severity(params.severity) if params.severity else None,
            min_confidence=params.min_confidence,
            tags=set(params.tags) if params.tags else None,
            active_only=params.active_only,
            limit=params.limit,
            offset=params.offset,
        )
        return [_ioc_to_response(ioc) for ioc in results]

    @app.get("/iocs/lookup/{value}", response_model=List[IOCResponse], tags=["iocs"])
    async def lookup_ioc(value: str, active_only: bool = Query(default=True)) -> List[IOCResponse]:
        assert _state is not None
        hits = _state.ioc_store.lookup(value, active_only=active_only)
        if not hits:
            raise HTTPException(status_code=404, detail=f"No IOCs found for value: {value}")
        for ioc in hits:
            ioc.hit_count += 1
            _state.ioc_store.update(ioc)
        return [_ioc_to_response(ioc) for ioc in hits]

    # -----------------------------------------------------------------------
    # Enrichment endpoints
    # -----------------------------------------------------------------------

    @app.post("/iocs/{ioc_id}/enrich", response_model=EnrichResponse, tags=["enrichment"])
    async def enrich_ioc(ioc_id: str, sources: Optional[List[str]] = None) -> EnrichResponse:
        assert _state is not None
        try:
            uid = uuid.UUID(ioc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IOC ID format")
        ioc = _state.ioc_store.get_by_id(uid)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")

        t0 = time.monotonic()
        enrichment_sources = None
        if sources:
            try:
                enrichment_sources = [EnrichmentSource(s) for s in sources]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        enrichments = await _state.enrichment.enrich_async(ioc, sources=enrichment_sources)
        duration_ms = (time.monotonic() - t0) * 1000
        _state.enrichments_today += 1

        return EnrichResponse(
            ioc_id=ioc_id,
            value=ioc.value,
            enrichments=enrichments,
            sources_queried=sources or [s.value for s in EnrichmentSource],
            duration_ms=round(duration_ms, 2),
        )

    # -----------------------------------------------------------------------
    # Correlation endpoint
    # -----------------------------------------------------------------------

    @app.get("/iocs/{ioc_id}/correlate", response_model=CorrelationResponse, tags=["correlation"])
    async def correlate_ioc(ioc_id: str, max_depth: int = Query(default=2, ge=1, le=5)) -> CorrelationResponse:
        assert _state is not None
        try:
            uid = uuid.UUID(ioc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IOC ID format")
        ioc = _state.ioc_store.get_by_id(uid)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")

        all_iocs = _state.ioc_store.list_all()
        result: CorrelationResult = _state.correlation.correlate(ioc, all_iocs, max_depth=max_depth)

        related = [
            {
                "id": str(r.id),
                "value": r.value,
                "ioc_type": r.ioc_type.value,
                "severity": r.severity.value,
                "confidence": r.confidence,
            }
            for r in result.related_iocs
        ]

        return CorrelationResponse(
            ioc_id=ioc_id,
            related_iocs=related,
            cluster_id=result.cluster_id,
            threat_actor=result.threat_actor,
            campaign=result.campaign,
            confidence=result.confidence,
        )

    # -----------------------------------------------------------------------
    # Playbook endpoint
    # -----------------------------------------------------------------------

    @app.post("/playbooks/run", response_model=PlaybookResponse, tags=["playbooks"])
    async def run_playbook(req: PlaybookRunRequest) -> PlaybookResponse:
        assert _state is not None
        try:
            uid = uuid.UUID(req.ioc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IOC ID format")
        ioc = _state.ioc_store.get_by_id(uid)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC {req.ioc_id} not found")

        t0 = time.monotonic()
        run_id = str(uuid.uuid4())

        result: PlaybookResult = _state.playbook_executor.run(
            ioc=ioc,
            playbook_name=req.playbook_name,
            dry_run=req.dry_run,
        )
        duration_ms = (time.monotonic() - t0) * 1000
        _state.playbooks_today += 1

        return PlaybookResponse(
            run_id=run_id,
            ioc_id=req.ioc_id,
            playbook_name=result.playbook_name,
            status=result.status.value,
            steps_total=result.steps_total,
            steps_succeeded=result.steps_succeeded,
            steps_failed=result.steps_failed,
            actions_taken=result.actions_taken,
            duration_ms=round(duration_ms, 2),
            dry_run=req.dry_run,
        )

    # -----------------------------------------------------------------------
    # Alert triage endpoints
    # -----------------------------------------------------------------------

    @app.get("/alerts", tags=["alerts"])
    async def list_alerts(
        status_filter: Optional[str] = Query(default=None, alias="status"),
        limit: int = Query(default=50, ge=1, le=500),
    ) -> List[Dict[str, Any]]:
        assert _state is not None
        alerts = _state.ioc_store.list_alerts(
            status=AlertStatus(status_filter) if status_filter else None,
            limit=limit,
        )
        return [
            {
                "alert_id": str(a.alert_id),
                "ioc_id": str(a.ioc_id),
                "status": a.status.value,
                "severity": a.severity.value,
                "analyst": a.analyst,
                "created_at": a.created_at.isoformat(),
                "updated_at": a.updated_at.isoformat(),
                "notes": a.notes,
            }
            for a in alerts
        ]

    @app.put("/alerts/{alert_id}", tags=["alerts"])
    async def update_alert(alert_id: str, req: TriageUpdateRequest) -> Dict[str, Any]:
        assert _state is not None
        try:
            uid = uuid.UUID(alert_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid alert ID")
        try:
            new_status = AlertStatus(req.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")
        alert = _state.ioc_store.get_alert(uid)
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        alert.status = new_status
        alert.analyst = req.analyst
        alert.notes = req.notes
        alert.updated_at = datetime.now(timezone.utc)
        _state.ioc_store.update_alert(alert)
        return {"status": "updated", "alert_id": alert_id, "new_status": req.status}

    # -----------------------------------------------------------------------
    # Export endpoint
    # -----------------------------------------------------------------------

    @app.get("/export/stix", tags=["export"])
    async def export_stix(
        active_only: bool = Query(default=True),
        min_confidence: float = Query(default=0.5, ge=0.0, le=1.0),
        max_items: int = Query(default=1000, ge=1, le=10000),
    ) -> Dict[str, Any]:
        assert _state is not None
        iocs = _state.ioc_store.search(
            active_only=active_only,
            min_confidence=min_confidence,
            limit=max_items,
        )
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []
        for ioc in iocs:
            pattern = _ioc_to_stix_pattern(ioc)
            if not pattern:
                continue
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.id}",
                "name": f"{ioc.ioc_type.value}: {ioc.value}",
                "description": ioc.description or f"IOC from {ioc.source}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen.isoformat(),
                "labels": list(ioc.tags) or ["malicious-activity"],
                "confidence": int(ioc.confidence * 100),
                "created": ioc.first_seen.isoformat(),
                "modified": ioc.last_seen.isoformat(),
            })
        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(objects),
        }

    @app.get("/export/csv", tags=["export"])
    async def export_csv(
        active_only: bool = Query(default=True),
        max_items: int = Query(default=5000, ge=1, le=50000),
    ) -> JSONResponse:
        from fastapi.responses import Response as FastAPIResponse
        assert _state is not None
        iocs = _state.ioc_store.search(active_only=active_only, limit=max_items)
        lines = ["id,value,type,source,severity,confidence,tlp,tags,first_seen,last_seen,active"]
        for ioc in iocs:
            tags_str = "|".join(sorted(ioc.tags))
            lines.append(
                f"{ioc.id},{ioc.value},{ioc.ioc_type.value},{ioc.source},"
                f"{ioc.severity.value},{ioc.confidence:.3f},{ioc.tlp.value},"
                f"{tags_str},{ioc.first_seen.isoformat()},{ioc.last_seen.isoformat()},{ioc.active}"
            )
        csv_content = "\n".join(lines)
        return JSONResponse(
            content={"csv": csv_content, "rows": len(iocs)},
            headers={"X-Row-Count": str(len(iocs))},
        )

    return app


def _ioc_to_stix_pattern(ioc: IOC) -> Optional[str]:
    patterns = {
        IOCType.IPV4: f"[ipv4-addr:value = '{ioc.value}']",
        IOCType.IPV6: f"[ipv6-addr:value = '{ioc.value}']",
        IOCType.DOMAIN: f"[domain-name:value = '{ioc.value}']",
        IOCType.URL: f"[url:value = '{ioc.value}']",
        IOCType.EMAIL: f"[email-addr:value = '{ioc.value}']",
        IOCType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{ioc.value}']",
        IOCType.FILE_HASH_SHA1: f"[file:hashes.'SHA-1' = '{ioc.value}']",
        IOCType.FILE_HASH_SHA256: f"[file:hashes.'SHA-256' = '{ioc.value}']",
        IOCType.CVE: f"[vulnerability:name = '{ioc.value}']",
    }
    return patterns.get(ioc.ioc_type)


# ---------------------------------------------------------------------------
# Entry point for running directly
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("uvicorn is required. Install with: pip install uvicorn")
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    main()
