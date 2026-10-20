"""
TAXII 2.x client for consuming threat intelligence from TAXII servers.
Supports TAXII 2.0 and 2.1 endpoints, collection discovery, and incremental polling.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Tuple
from urllib.request import Request

logger = logging.getLogger(__name__)

TAXII_MEDIA_TYPE_20 = "application/vnd.oasis.taxii+json; version=2.0"
TAXII_MEDIA_TYPE_21 = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE_20 = "application/vnd.oasis.stix+json; version=2.0"
STIX_MEDIA_TYPE_21 = "application/stix+json;version=2.1"


class TaxiiVersion(str, Enum):
    V20 = "2.0"
    V21 = "2.1"


@dataclass
class TaxiiCollection:
    id: str
    title: str
    description: str = ""
    can_read: bool = True
    can_write: bool = False
    media_types: List[str] = field(default_factory=list)
    alias: str = ""


@dataclass
class TaxiiPollCursor:
    """Tracks incremental polling state per collection."""
    collection_id: str
    added_after: Optional[str] = None  # ISO8601 timestamp
    last_poll: Optional[float] = None
    total_fetched: int = 0


@dataclass
class TaxiiPollResult:
    collection_id: str
    objects: List[Dict[str, Any]]
    more: bool = False
    next_cursor: Optional[str] = None
    total_count: int = 0
    fetch_duration_ms: float = 0.0
    error: Optional[str] = None


class TaxiiClient:
    """
    TAXII 2.x client with support for:
    - Server discovery and collection enumeration
    - Incremental polling with cursor-based pagination
    - STIX 2.0 and 2.1 bundle retrieval
    - Basic and token authentication
    """

    def __init__(
        self,
        server_url: str,
        version: TaxiiVersion = TaxiiVersion.V21,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
        page_size: int = 100,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.version = version
        self._username = username
        self._password = password
        self._api_key = api_key
        self.timeout = timeout
        self.page_size = page_size
        self._cursors: Dict[str, TaxiiPollCursor] = {}

        if version == TaxiiVersion.V21:
            self._accept = TAXII_MEDIA_TYPE_21
            self._stix_accept = STIX_MEDIA_TYPE_21
        else:
            self._accept = TAXII_MEDIA_TYPE_20
            self._stix_accept = STIX_MEDIA_TYPE_20

    def _build_headers(self, accept: str) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": accept,
            "Content-Type": accept,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username and self._password:
            creds = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        return headers

    def _get(self, path: str, accept: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = f"{self.server_url}{path}"
        if params:
            query = urllib.parse.urlencode(params)
            url = f"{url}?{query}"

        headers = self._build_headers(accept or self._accept)
        req = Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise TaxiiError(f"HTTP {exc.code} from {url}: {body}") from exc
        except urllib.error.URLError as exc:
            raise TaxiiError(f"Connection error to {url}: {exc.reason}") from exc

    def discover(self) -> Dict[str, Any]:
        """Fetch server discovery information."""
        return self._get("/taxii2/")

    def get_api_roots(self) -> List[str]:
        """Return list of API root paths from discovery."""
        info = self.discover()
        roots = info.get("api_roots", [])
        # Normalize to paths relative to server_url
        normalized = []
        for root in roots:
            if root.startswith(self.server_url):
                normalized.append(root[len(self.server_url):])
            elif root.startswith("http"):
                normalized.append(root)
            else:
                normalized.append(root)
        return normalized

    def get_collections(self, api_root: str = "/api/v21/") -> List[TaxiiCollection]:
        """Enumerate available collections in an API root."""
        path = f"{api_root.rstrip('/')}/collections/"
        data = self._get(path)
        collections = []
        for col in data.get("collections", []):
            collections.append(TaxiiCollection(
                id=col.get("id", ""),
                title=col.get("title", ""),
                description=col.get("description", ""),
                can_read=col.get("can_read", True),
                can_write=col.get("can_write", False),
                media_types=col.get("media_types", []),
                alias=col.get("alias", ""),
            ))
        return collections

    def get_objects(
        self,
        api_root: str,
        collection_id: str,
        added_after: Optional[str] = None,
        limit: Optional[int] = None,
        next_param: Optional[str] = None,
        object_types: Optional[List[str]] = None,
    ) -> TaxiiPollResult:
        """
        Fetch STIX objects from a collection with optional time filtering and pagination.
        """
        path = f"{api_root.rstrip('/')}/collections/{collection_id}/objects/"
        params: Dict[str, str] = {}

        if added_after:
            params["added_after"] = added_after
        if limit is not None:
            params["limit"] = str(limit)
        else:
            params["limit"] = str(self.page_size)
        if next_param:
            params["next"] = next_param
        if object_types:
            params["match[type]"] = ",".join(object_types)

        start = time.monotonic()
        try:
            data = self._get(path, accept=self._stix_accept, params=params)
        except TaxiiError as exc:
            return TaxiiPollResult(
                collection_id=collection_id,
                objects=[],
                error=str(exc),
            )

        elapsed_ms = (time.monotonic() - start) * 1000
        objects = data.get("objects", [])
        more = data.get("more", False)
        next_cursor = data.get("next")

        return TaxiiPollResult(
            collection_id=collection_id,
            objects=objects,
            more=more,
            next_cursor=next_cursor,
            total_count=len(objects),
            fetch_duration_ms=elapsed_ms,
        )

    def poll_collection(
        self,
        api_root: str,
        collection_id: str,
        object_types: Optional[List[str]] = None,
        reset_cursor: bool = False,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Incrementally poll a collection, yielding STIX objects one at a time.
        Tracks added_after cursor between calls for incremental updates.
        """
        cursor = self._cursors.get(collection_id)
        if cursor is None or reset_cursor:
            cursor = TaxiiPollCursor(collection_id=collection_id)
            self._cursors[collection_id] = cursor

        next_param: Optional[str] = None
        page = 0
        total = 0

        while True:
            result = self.get_objects(
                api_root=api_root,
                collection_id=collection_id,
                added_after=cursor.added_after,
                next_param=next_param,
                object_types=object_types,
            )

            if result.error:
                logger.error("TAXII poll error for %s: %s", collection_id, result.error)
                break

            for obj in result.objects:
                total += 1
                yield obj

            page += 1
            logger.debug(
                "Page %d: fetched %d objects from collection %s (%.0fms)",
                page, len(result.objects), collection_id, result.fetch_duration_ms
            )

            if not result.more or not result.next_cursor:
                break
            next_param = result.next_cursor

        # Advance cursor to now so next poll fetches only new objects
        cursor.added_after = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.last_poll = time.time()
        cursor.total_fetched += total
        logger.info("Polled %d objects from collection %s", total, collection_id)

    def get_status(self, api_root: str, status_id: str) -> Dict[str, Any]:
        """Check the status of an async TAXII operation."""
        path = f"{api_root.rstrip('/')}/status/{status_id}/"
        return self._get(path)

    def get_collection_manifest(
        self,
        api_root: str,
        collection_id: str,
        added_after: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch object manifest (metadata) without full objects."""
        path = f"{api_root.rstrip('/')}/collections/{collection_id}/manifest/"
        params: Dict[str, str] = {}
        if added_after:
            params["added_after"] = added_after
        data = self._get(path, params=params if params else None)
        return data.get("objects", [])

    def reset_cursor(self, collection_id: str) -> None:
        """Clear the incremental poll cursor for a collection."""
        self._cursors.pop(collection_id, None)

    def get_cursor_state(self, collection_id: str) -> Optional[TaxiiPollCursor]:
        return self._cursors.get(collection_id)


class TaxiiError(Exception):
    """Raised on TAXII protocol or connection errors."""
    pass


class OpenTaxiiAdapter:
    """
    Convenience adapter for well-known public TAXII feeds.
    Wraps TaxiiClient with pre-configured endpoints and collection IDs.
    """

    HAILATAXII = "https://hailataxii.com"
    CISA_AIS = "https://ais2.cisa.dhs.gov/taxii2/"

    # Known collection IDs for major feeds
    COLLECTIONS = {
        "mitre_attack_enterprise": {
            "api_root": "/api/v21/",
            "collection_id": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
            "description": "MITRE ATT&CK Enterprise",
        },
        "mitre_attack_mobile": {
            "api_root": "/api/v21/",
            "collection_id": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
            "description": "MITRE ATT&CK Mobile",
        },
    }

    def __init__(self, server_url: str, **kwargs: Any) -> None:
        self.client = TaxiiClient(server_url, **kwargs)

    def fetch_attack_techniques(self, api_root: str = "/api/v21/") -> Generator[Dict[str, Any], None, None]:
        """Stream MITRE ATT&CK technique objects."""
        for col_info in self.COLLECTIONS.values():
            yield from self.client.poll_collection(
                api_root=col_info["api_root"],
                collection_id=col_info["collection_id"],
                object_types=["attack-pattern"],
            )
