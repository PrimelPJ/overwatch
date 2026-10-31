"""
TAXII 2.1 server that serves threat intelligence from the Overwatch IOC store.

Implements the mandatory TAXII 2.1 endpoints per the specification:
  GET /taxii2/                          - discovery
  GET /{api_root}/                      - API root information
  GET /{api_root}/collections/          - list collections
  GET /{api_root}/collections/{id}/     - get collection metadata
  GET /{api_root}/collections/{id}/objects/  - get STIX objects
  POST /{api_root}/collections/{id}/objects/ - add STIX objects
  GET /{api_root}/collections/{id}/manifest/ - get object manifest

Collections are mapped to TLP levels so consumers only receive indicators
they are authorised to see.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from overwatch.ioc_store import IOCStore
from overwatch.models import IOC, IOCType, TLPLevel
from overwatch.stix_exporter import StixExporter

logger = logging.getLogger(__name__)

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
STIX_CONTENT_TYPE = "application/stix+json;version=2.1"

# Standard STIX 2.1 TLP marking definition IDs
_TLP_MARKING_IDS = {
    TLPLevel.WHITE: "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519ae",
    TLPLevel.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    TLPLevel.AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    TLPLevel.RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# Levels each collection includes (cumulative: GREEN includes WHITE+GREEN)
_COLLECTION_TLP_SETS: Dict[str, List[TLPLevel]] = {
    "public": [TLPLevel.WHITE],
    "community": [TLPLevel.WHITE, TLPLevel.GREEN],
    "trusted": [TLPLevel.WHITE, TLPLevel.GREEN, TLPLevel.AMBER],
    "internal": [TLPLevel.WHITE, TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.RED],
}


@dataclass
class TAXIICollection:
    id: str
    title: str
    description: str
    tlp_levels: List[TLPLevel]
    can_read: bool = True
    can_write: bool = False
    media_types: List[str] = field(default_factory=lambda: [STIX_CONTENT_TYPE])

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "media_types": self.media_types,
        }


@dataclass
class TAXIIServerConfig:
    title: str = "Overwatch Threat Intelligence"
    description: str = "TAXII 2.1 endpoint serving Overwatch IOC store"
    contact: str = ""
    api_root_path: str = "threat-intel"
    host: str = "localhost"
    port: int = 8421
    default_page_size: int = 100
    max_page_size: int = 1000


class TAXIIServer:
    """
    TAXII 2.1 server backed by the Overwatch IOC store.

    Collections are pre-defined by TLP level. The server renders IOCs as
    STIX 2.1 indicator objects on the fly via STIXExporter.
    """

    def __init__(
        self,
        ioc_store: IOCStore,
        config: Optional[TAXIIServerConfig] = None,
    ) -> None:
        self._store = ioc_store
        self._cfg = config or TAXIIServerConfig()
        self._exporter = StixExporter()
        self._collections: Dict[str, TAXIICollection] = self._build_collections()
        self._added_objects: Dict[str, List[Dict]] = {}  # collection_id -> raw STIX objects

    def _build_collections(self) -> Dict[str, TAXIICollection]:
        collections = {}
        descs = {
            "public": "TLP:WHITE public threat indicators",
            "community": "TLP:WHITE and TLP:GREEN community-shared indicators",
            "trusted": "TLP:AMBER and below — for trusted partner sharing",
            "internal": "All indicators including TLP:RED — internal use only",
        }
        for name, tlp_levels in _COLLECTION_TLP_SETS.items():
            cid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"overwatch.collection.{name}"))
            collections[cid] = TAXIICollection(
                id=cid,
                title=name.capitalize(),
                description=descs[name],
                tlp_levels=tlp_levels,
            )
        return collections

    def _discovery_response(self) -> Dict:
        api_root_url = f"http://{self._cfg.host}:{self._cfg.port}/{self._cfg.api_root_path}/"
        return {
            "title": self._cfg.title,
            "description": self._cfg.description,
            "contact": self._cfg.contact,
            "default": api_root_url,
            "api_roots": [api_root_url],
        }

    def _api_root_response(self) -> Dict:
        return {
            "title": self._cfg.title,
            "description": self._cfg.description,
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760,
        }

    def _collections_response(self) -> Dict:
        return {"collections": [c.to_dict() for c in self._collections.values()]}

    def _collection_response(self, collection_id: str) -> Optional[Dict]:
        col = self._collections.get(collection_id)
        return col.to_dict() if col else None

    def _iocs_for_collection(self, collection: TAXIICollection) -> List[IOC]:
        """Return all IOCs whose TLP is within the collection's allowed levels."""
        allowed = set(collection.tlp_levels)
        result = []
        for ioc in self._store.iter_all():
            if ioc.tlp in allowed:
                result.append(ioc)
        return result

    def _ioc_to_stix_indicator(self, ioc: IOC) -> Dict:
        """Convert a single IOC to a minimal STIX 2.1 indicator object."""
        pattern = self._make_stix_pattern(ioc)
        if not pattern:
            return {}

        now = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
        indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ioc.fingerprint)}"

        obj: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"{ioc.ioc_type.value}: {ioc.value}",
            "description": f"Source: {ioc.source}. Confidence: {ioc.confidence}.",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": [self._severity_to_indicator_type(ioc.severity.value)],
            "confidence": ioc.confidence,
            "object_marking_refs": [_TLP_MARKING_IDS[ioc.tlp]],
            "labels": list(ioc.tags),
        }
        if ioc.mitre_techniques:
            obj["external_references"] = [
                {"source_name": "mitre-attack", "external_id": t}
                for t in ioc.mitre_techniques
            ]
        return obj

    def _make_stix_pattern(self, ioc: IOC) -> str:
        patterns = {
            IOCType.IPV4: f"[ipv4-addr:value = '{ioc.value}']",
            IOCType.IPV6: f"[ipv6-addr:value = '{ioc.value}']",
            IOCType.DOMAIN: f"[domain-name:value = '{ioc.value}']",
            IOCType.URL: f"[url:value = '{ioc.value}']",
            IOCType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{ioc.value}']",
            IOCType.FILE_HASH_SHA1: f"[file:hashes.'SHA-1' = '{ioc.value}']",
            IOCType.FILE_HASH_SHA256: f"[file:hashes.'SHA-256' = '{ioc.value}']",
            IOCType.EMAIL: f"[email-addr:value = '{ioc.value}']",
            IOCType.CVE: f"[vulnerability:name = '{ioc.value}']",
        }
        return patterns.get(ioc.ioc_type, "")

    def _severity_to_indicator_type(self, severity: str) -> str:
        return {
            "critical": "malicious-activity",
            "high": "malicious-activity",
            "medium": "anomalous-activity",
            "low": "anomalous-activity",
            "info": "benign",
        }.get(severity, "anomalous-activity")

    def _build_stix_bundle(self, objects: List[Dict]) -> Dict:
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [o for o in objects if o],
        }

    def _build_manifest(self, objects: List[Dict]) -> List[Dict]:
        manifest = []
        for obj in objects:
            if not obj:
                continue
            manifest.append({
                "id": obj.get("id", ""),
                "date_added": obj.get("created", ""),
                "version": obj.get("modified", ""),
                "media_type": STIX_CONTENT_TYPE,
            })
        return manifest

    def handle_request(
        self,
        method: str,
        path: str,
        query: Dict[str, List[str]],
        body: Optional[bytes] = None,
        accept_tlp: Optional[TLPLevel] = None,
    ) -> tuple[int, str, Dict]:
        """
        Route a TAXII request and return (status_code, content_type, body_dict).

        This is the pure-logic layer; the HTTP server calls into it.
        """
        api_root = self._cfg.api_root_path
        segments = [s for s in path.strip("/").split("/") if s]

        # GET /taxii2/
        if segments == ["taxii2"]:
            return 200, TAXII_CONTENT_TYPE, self._discovery_response()

        # GET /{api_root}/
        if segments == [api_root]:
            return 200, TAXII_CONTENT_TYPE, self._api_root_response()

        # GET /{api_root}/collections/
        if segments == [api_root, "collections"]:
            return 200, TAXII_CONTENT_TYPE, self._collections_response()

        # /{api_root}/collections/{id}/...
        if len(segments) >= 3 and segments[0] == api_root and segments[1] == "collections":
            col_id = segments[2]
            col = self._collections.get(col_id)
            if col is None:
                return 404, TAXII_CONTENT_TYPE, {"title": "Collection not found", "http_status": 404}

            # GET /{api_root}/collections/{id}/
            if len(segments) == 3:
                return 200, TAXII_CONTENT_TYPE, col.to_dict()

            # GET /{api_root}/collections/{id}/objects/
            if segments[3] == "objects" and method == "GET":
                iocs = self._iocs_for_collection(col)
                stix_objects = [self._ioc_to_stix_indicator(ioc) for ioc in iocs]
                # Also include any directly added objects
                stix_objects.extend(self._added_objects.get(col_id, []))

                page_size = int(query.get("limit", [str(self._cfg.default_page_size)])[0])
                page_size = min(page_size, self._cfg.max_page_size)
                offset = int(query.get("next", ["0"])[0])
                page = stix_objects[offset: offset + page_size]

                bundle = self._build_stix_bundle(page)
                resp = {
                    "type": "bundle",
                    "id": bundle["id"],
                    "spec_version": "2.1",
                    "objects": bundle["objects"],
                    "more": (offset + page_size) < len(stix_objects),
                    "next": str(offset + page_size) if (offset + page_size) < len(stix_objects) else None,
                }
                return 200, STIX_CONTENT_TYPE, resp

            # POST /{api_root}/collections/{id}/objects/
            if segments[3] == "objects" and method == "POST":
                if not col.can_write:
                    return 405, TAXII_CONTENT_TYPE, {"title": "Collection is read-only", "http_status": 405}
                if not body:
                    return 400, TAXII_CONTENT_TYPE, {"title": "Empty request body", "http_status": 400}
                try:
                    bundle = json.loads(body.decode())
                    added = self._ingest_stix_bundle(col_id, bundle)
                    return 200, TAXII_CONTENT_TYPE, {
                        "id": f"status--{uuid.uuid4()}",
                        "status": "complete",
                        "total_count": len(added),
                        "success_count": len(added),
                        "failure_count": 0,
                    }
                except (json.JSONDecodeError, KeyError) as exc:
                    return 400, TAXII_CONTENT_TYPE, {"title": str(exc), "http_status": 400}

            # GET /{api_root}/collections/{id}/manifest/
            if segments[3] == "manifest" and method == "GET":
                iocs = self._iocs_for_collection(col)
                stix_objects = [self._ioc_to_stix_indicator(ioc) for ioc in iocs]
                stix_objects.extend(self._added_objects.get(col_id, []))
                manifest = self._build_manifest(stix_objects)
                return 200, TAXII_CONTENT_TYPE, {"objects": manifest}

        return 404, TAXII_CONTENT_TYPE, {"title": "Not found", "http_status": 404}

    def _ingest_stix_bundle(self, collection_id: str, bundle: Dict) -> List[str]:
        """Accept a STIX bundle into a writable collection's object store."""
        objects = bundle.get("objects", [])
        ids = []
        if collection_id not in self._added_objects:
            self._added_objects[collection_id] = []
        for obj in objects:
            obj_id = obj.get("id", f"unknown--{uuid.uuid4()}")
            self._added_objects[collection_id].append(obj)
            ids.append(obj_id)
        return ids

    def get_collection_by_name(self, name: str) -> Optional[TAXIICollection]:
        for col in self._collections.values():
            if col.title.lower() == name.lower():
                return col
        return None

    def collection_ids(self) -> List[str]:
        return list(self._collections.keys())

    def summary(self) -> Dict:
        return {
            "title": self._cfg.title,
            "api_root": self._cfg.api_root_path,
            "collections": len(self._collections),
            "total_iocs": self._store.size(),
        }


class TAXIIHTTPHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that delegates to TAXIIServer.handle_request."""

    taxii_server: TAXIIServer = None  # set by TAXIIHTTPServer

    def log_message(self, format: str, *args) -> None:
        logger.debug("TAXII %s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, content_type: str, body: Dict) -> None:
        payload = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        status, ct, body = self.taxii_server.handle_request("GET", parsed.path, query)
        self._send_json(status, ct, body)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else None
        status, ct, resp = self.taxii_server.handle_request("POST", parsed.path, query, body)
        self._send_json(status, ct, resp)


class TAXIIHTTPServer(HTTPServer):
    """HTTPServer wired to a TAXIIServer instance."""

    def __init__(self, taxii_server: TAXIIServer, host: str = "localhost", port: int = 8421) -> None:
        self._taxii = taxii_server

        class _Handler(TAXIIHTTPHandler):
            pass

        _Handler.taxii_server = taxii_server
        super().__init__((host, port), _Handler)
        logger.info("TAXII 2.1 server listening on %s:%d", host, port)
