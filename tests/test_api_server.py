"""
Tests for the Overwatch REST API server.
Uses FastAPI's TestClient for synchronous testing.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from overwatch.models import IOC, IOCType, Severity, TLPLevel, AlertTriage, AlertStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_ioc() -> IOC:
    return IOC(
        value="192.168.1.100",
        ioc_type=IOCType.IPV4,
        source="test-feed",
        severity=Severity.HIGH,
        tlp=TLPLevel.AMBER,
        confidence=0.85,
        tags={"c2", "botnet"},
        description="Known C2 server",
    )


@pytest.fixture
def sample_domain_ioc() -> IOC:
    return IOC(
        value="malware.evil.example.com",
        ioc_type=IOCType.DOMAIN,
        source="test-feed",
        severity=Severity.CRITICAL,
        tlp=TLPLevel.RED,
        confidence=0.95,
        tags={"phishing", "malware"},
    )


@pytest.fixture
def sample_hash_ioc() -> IOC:
    return IOC(
        value="d41d8cd98f00b204e9800998ecf8427e",
        ioc_type=IOCType.FILE_HASH_MD5,
        source="virustotal",
        severity=Severity.MEDIUM,
        tlp=TLPLevel.WHITE,
        confidence=0.7,
        tags={"trojan"},
    )


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------

class TestIOCConversions:
    def test_ioc_to_response_fields(self, sample_ioc: IOC) -> None:
        try:
            from overwatch.api_server import _ioc_to_response
        except ImportError:
            pytest.skip("fastapi not installed")
        resp = _ioc_to_response(sample_ioc)
        assert resp.value == "192.168.1.100"
        assert resp.ioc_type == "ipv4"
        assert resp.severity == "high"
        assert resp.tlp == "amber"
        assert resp.confidence == 0.85
        assert "c2" in resp.tags
        assert resp.active is True

    def test_request_to_ioc_ttl(self) -> None:
        try:
            from overwatch.api_server import _request_to_ioc, IOCSubmitRequest
        except ImportError:
            pytest.skip("fastapi not installed")
        req = IOCSubmitRequest(
            value="10.0.0.1",
            ioc_type="ipv4",
            source="test",
            severity="low",
            tlp="white",
            confidence=0.5,
            tags=["scanner"],
            ttl_hours=48,
        )
        ioc = _request_to_ioc(req)
        assert ioc.value == "10.0.0.1"
        assert ioc.ioc_type == IOCType.IPV4
        assert ioc.severity == Severity.LOW
        # TTL should be ~48 hours from now
        delta = (ioc.expiry - ioc.first_seen).total_seconds()
        assert abs(delta - 48 * 3600) < 5

    def test_invalid_ioc_type_raises(self) -> None:
        try:
            from overwatch.api_server import IOCSubmitRequest
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("fastapi not installed")
        with pytest.raises(ValidationError):
            IOCSubmitRequest(
                value="1.2.3.4",
                ioc_type="invalid_type",
                source="test",
            )

    def test_invalid_severity_raises(self) -> None:
        try:
            from overwatch.api_server import IOCSubmitRequest
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("fastapi not installed")
        with pytest.raises(ValidationError):
            IOCSubmitRequest(
                value="1.2.3.4",
                ioc_type="ipv4",
                source="test",
                severity="ultra",
            )

    def test_confidence_bounds(self) -> None:
        try:
            from overwatch.api_server import IOCSubmitRequest
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("fastapi not installed")
        with pytest.raises(ValidationError):
            IOCSubmitRequest(
                value="1.2.3.4",
                ioc_type="ipv4",
                source="test",
                confidence=1.5,
            )


class TestSTIXPatternGeneration:
    def test_ipv4_pattern(self, sample_ioc: IOC) -> None:
        try:
            from overwatch.api_server import _ioc_to_stix_pattern
        except ImportError:
            pytest.skip("fastapi not installed")
        pattern = _ioc_to_stix_pattern(sample_ioc)
        assert pattern == "[ipv4-addr:value = '192.168.1.100']"

    def test_domain_pattern(self, sample_domain_ioc: IOC) -> None:
        try:
            from overwatch.api_server import _ioc_to_stix_pattern
        except ImportError:
            pytest.skip("fastapi not installed")
        pattern = _ioc_to_stix_pattern(sample_domain_ioc)
        assert pattern == "[domain-name:value = 'malware.evil.example.com']"

    def test_md5_pattern(self, sample_hash_ioc: IOC) -> None:
        try:
            from overwatch.api_server import _ioc_to_stix_pattern
        except ImportError:
            pytest.skip("fastapi not installed")
        pattern = _ioc_to_stix_pattern(sample_hash_ioc)
        assert pattern == "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"

    def test_unknown_type_returns_none(self) -> None:
        try:
            from overwatch.api_server import _ioc_to_stix_pattern
        except ImportError:
            pytest.skip("fastapi not installed")
        ioc = IOC(
            value="AS12345",
            ioc_type=IOCType.ASN,
            source="test",
            severity=Severity.LOW,
            tlp=TLPLevel.WHITE,
        )
        result = _ioc_to_stix_pattern(ioc)
        assert result is None


# ---------------------------------------------------------------------------
# Integration tests using TestClient (skipped if fastapi not installed)
# ---------------------------------------------------------------------------

def _get_test_client():
    try:
        from fastapi.testclient import TestClient
        from overwatch.api_server import create_app
        return TestClient(create_app())
    except ImportError:
        return None


class TestHealthEndpoints:
    def test_health_returns_ok(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "timestamp" in data

    def test_stats_returns_structure(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            resp = client.get("/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert "total_iocs" in data
            assert "active_iocs" in data
            assert "by_type" in data
            assert "uptime_seconds" in data


class TestIOCCRUD:
    def test_submit_and_get_ioc(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            payload = {
                "value": "203.0.113.1",
                "ioc_type": "ipv4",
                "source": "test-api",
                "severity": "high",
                "tlp": "amber",
                "confidence": 0.9,
                "tags": ["c2", "apt"],
                "ttl_hours": 24,
            }
            create_resp = client.post("/iocs", json=payload)
            assert create_resp.status_code == 201
            created = create_resp.json()
            assert created["value"] == "203.0.113.1"
            assert created["ioc_type"] == "ipv4"
            assert created["active"] is True

            ioc_id = created["id"]
            get_resp = client.get(f"/iocs/{ioc_id}")
            assert get_resp.status_code == 200
            fetched = get_resp.json()
            assert fetched["id"] == ioc_id
            assert fetched["confidence"] == 0.9

    def test_get_nonexistent_ioc_returns_404(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            resp = client.get(f"/iocs/{uuid.uuid4()}")
            assert resp.status_code == 404

    def test_invalid_uuid_returns_400(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            resp = client.get("/iocs/not-a-uuid")
            assert resp.status_code == 400

    def test_submit_duplicate_updates_existing(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            payload = {
                "value": "198.51.100.42",
                "ioc_type": "ipv4",
                "source": "feed-a",
                "confidence": 0.6,
                "tags": ["scanner"],
            }
            r1 = client.post("/iocs", json=payload)
            assert r1.status_code == 201
            id1 = r1.json()["id"]
            # Submit same value with higher confidence and extra tag
            payload2 = dict(payload, confidence=0.9, tags=["scanner", "botnet"])
            r2 = client.post("/iocs", json=payload2)
            assert r2.status_code == 201
            id2 = r2.json()["id"]
            # Should be the same IOC (updated, not duplicated)
            assert id1 == id2
            assert r2.json()["confidence"] == 0.9
            assert "botnet" in r2.json()["tags"]

    def test_expire_ioc(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            payload = {"value": "192.0.2.99", "ioc_type": "ipv4", "source": "test"}
            r = client.post("/iocs", json=payload)
            ioc_id = r.json()["id"]
            del_resp = client.delete(f"/iocs/{ioc_id}")
            assert del_resp.status_code == 200
            assert del_resp.json()["status"] == "expired"

    def test_bulk_submit(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            payload = {
                "indicators": [
                    {"value": "10.0.1.1", "ioc_type": "ipv4", "source": "bulk"},
                    {"value": "10.0.1.2", "ioc_type": "ipv4", "source": "bulk"},
                    {"value": "evil.example.com", "ioc_type": "domain", "source": "bulk"},
                ]
            }
            resp = client.post("/iocs/bulk", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["created"] == 3
            assert data["errors"] == []


class TestIOCSearch:
    def test_search_by_type(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            client.post("/iocs", json={"value": "1.2.3.4", "ioc_type": "ipv4", "source": "t"})
            client.post("/iocs", json={"value": "bad.domain.example", "ioc_type": "domain", "source": "t"})
            search_resp = client.post("/iocs/search", json={"ioc_type": "ipv4", "limit": 100})
            assert search_resp.status_code == 200
            results = search_resp.json()
            assert all(r["ioc_type"] == "ipv4" for r in results)

    def test_lookup_existing_value(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            client.post("/iocs", json={"value": "5.6.7.8", "ioc_type": "ipv4", "source": "t"})
            resp = client.get("/iocs/lookup/5.6.7.8")
            assert resp.status_code == 200
            assert len(resp.json()) >= 1

    def test_lookup_missing_value_returns_404(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            resp = client.get("/iocs/lookup/99.99.99.99")
            assert resp.status_code == 404


class TestExportEndpoints:
    def test_stix_export_structure(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            client.post("/iocs", json={"value": "192.0.2.10", "ioc_type": "ipv4", "source": "t", "confidence": 0.8})
            resp = client.get("/export/stix?min_confidence=0.5")
            assert resp.status_code == 200
            data = resp.json()
            assert data["type"] == "bundle"
            assert data["spec_version"] == "2.1"
            assert isinstance(data["objects"], list)
            assert data["count"] >= 1

    def test_csv_export_structure(self) -> None:
        client = _get_test_client()
        if client is None:
            pytest.skip("fastapi not installed")
        with client:
            client.post("/iocs", json={"value": "192.0.2.11", "ioc_type": "ipv4", "source": "t"})
            resp = client.get("/export/csv")
            assert resp.status_code == 200
            data = resp.json()
            assert "csv" in data
            assert "rows" in data
            lines = data["csv"].split("\n")
            assert lines[0].startswith("id,value,type")
