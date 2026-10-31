"""Tests for the TAXII 2.1 server."""

import json
import pytest

from overwatch.ioc_store import IOCStore
from overwatch.models import IOC, IOCType, Severity, TLPLevel
from overwatch.taxii_server import (
    TAXIIServer,
    TAXIIServerConfig,
    TAXII_CONTENT_TYPE,
    STIX_CONTENT_TYPE,
)


@pytest.fixture
def store():
    s = IOCStore()
    s.add(IOC(ioc_type=IOCType.IPV4, value="1.2.3.4", source="test", tlp=TLPLevel.GREEN, confidence=80))
    s.add(IOC(ioc_type=IOCType.DOMAIN, value="evil.example.com", source="test", tlp=TLPLevel.AMBER, confidence=90))
    s.add(IOC(ioc_type=IOCType.FILE_HASH_SHA256, value="a" * 64, source="test", tlp=TLPLevel.RED, confidence=95))
    s.add(IOC(ioc_type=IOCType.URL, value="http://bad.example.com/payload", source="test", tlp=TLPLevel.WHITE, confidence=70))
    return s


@pytest.fixture
def server(store):
    cfg = TAXIIServerConfig(host="localhost", port=8421, api_root_path="threat-intel")
    return TAXIIServer(store, cfg)


def test_discovery_endpoint(server):
    status, ct, body = server.handle_request("GET", "/taxii2/", {})
    assert status == 200
    assert ct == TAXII_CONTENT_TYPE
    assert "title" in body
    assert "api_roots" in body
    assert len(body["api_roots"]) == 1


def test_api_root_endpoint(server):
    status, ct, body = server.handle_request("GET", "/threat-intel/", {})
    assert status == 200
    assert "versions" in body
    assert any("taxii" in v for v in body["versions"])


def test_collections_endpoint_returns_all_four(server):
    status, ct, body = server.handle_request("GET", "/threat-intel/collections/", {})
    assert status == 200
    cols = body["collections"]
    assert len(cols) == 4
    titles = {c["title"].lower() for c in cols}
    assert {"public", "community", "trusted", "internal"} == titles


def test_collection_metadata_by_id(server):
    status, ct, body = server.handle_request("GET", "/threat-intel/collections/", {})
    first_id = body["collections"][0]["id"]
    status2, ct2, col = server.handle_request("GET", f"/threat-intel/collections/{first_id}/", {})
    assert status2 == 200
    assert col["id"] == first_id
    assert "title" in col


def test_unknown_collection_returns_404(server):
    status, ct, body = server.handle_request("GET", "/threat-intel/collections/nonexistent/", {})
    assert status == 404


def test_objects_endpoint_public_only_sees_white(server):
    public_col = server.get_collection_by_name("Public")
    assert public_col is not None
    status, ct, body = server.handle_request(
        "GET", f"/threat-intel/collections/{public_col.id}/objects/", {}
    )
    assert status == 200
    assert ct == STIX_CONTENT_TYPE
    objects = body.get("objects", [])
    for obj in objects:
        marking_refs = obj.get("object_marking_refs", [])
        assert "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed" not in marking_refs  # RED
        assert "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82" not in marking_refs  # AMBER
        assert "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da" not in marking_refs  # GREEN


def test_objects_endpoint_internal_sees_all(server, store):
    internal_col = server.get_collection_by_name("Internal")
    status, ct, body = server.handle_request(
        "GET", f"/threat-intel/collections/{internal_col.id}/objects/", {}
    )
    assert status == 200
    assert len(body.get("objects", [])) == 4


def test_objects_pagination(server):
    internal_col = server.get_collection_by_name("Internal")
    status, ct, body = server.handle_request(
        "GET",
        f"/threat-intel/collections/{internal_col.id}/objects/",
        {"limit": ["2"]},
    )
    assert status == 200
    assert len(body.get("objects", [])) == 2
    assert body.get("more") is True
    assert body.get("next") == "2"


def test_stix_indicator_pattern_format(server):
    internal_col = server.get_collection_by_name("Internal")
    status, ct, body = server.handle_request(
        "GET", f"/threat-intel/collections/{internal_col.id}/objects/", {}
    )
    patterns = {obj["pattern"] for obj in body.get("objects", [])}
    assert any("ipv4-addr:value" in p for p in patterns)
    assert any("domain-name:value" in p for p in patterns)
    assert any("file:hashes.'SHA-256'" in p for p in patterns)


def test_manifest_endpoint(server):
    internal_col = server.get_collection_by_name("Internal")
    status, ct, body = server.handle_request(
        "GET", f"/threat-intel/collections/{internal_col.id}/manifest/", {}
    )
    assert status == 200
    manifest = body.get("objects", [])
    assert len(manifest) == 4
    for entry in manifest:
        assert "id" in entry
        assert "date_added" in entry
        assert "version" in entry


def test_community_collection_includes_green_not_amber(server):
    community_col = server.get_collection_by_name("Community")
    status, ct, body = server.handle_request(
        "GET", f"/threat-intel/collections/{community_col.id}/objects/", {}
    )
    objects = body.get("objects", [])
    markings_seen = {
        m for obj in objects for m in obj.get("object_marking_refs", [])
    }
    GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    assert GREEN in markings_seen
    assert AMBER not in markings_seen


def test_summary_dict(server):
    s = server.summary()
    assert s["collections"] == 4
    assert s["total_iocs"] == 4


def test_unknown_path_returns_404(server):
    status, ct, body = server.handle_request("GET", "/notfound/", {})
    assert status == 404
