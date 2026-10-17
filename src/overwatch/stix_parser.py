"""
STIX 2.1 bundle parser with full indicator extraction and relationship mapping.
"""

from __future__ import annotations

import json
import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

from overwatch.models import IOC, IOCType, Severity, TLPLevel, ThreatActor

logger = logging.getLogger(__name__)

# STIX pattern extraction regexes
_PATTERN_EXTRACTORS: List[Tuple[IOCType, re.Pattern]] = [
    (IOCType.IPV4, re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")),
    (IOCType.IPV6, re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'")),
    (IOCType.DOMAIN, re.compile(r"domain-name:value\s*=\s*'([^']+)'")),
    (IOCType.URL, re.compile(r"url:value\s*=\s*'([^']+)'")),
    (IOCType.FILE_HASH_MD5, re.compile(r"file:hashes\.MD5\s*=\s*'([^']+)'")),
    (IOCType.FILE_HASH_SHA1, re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'")),
    (IOCType.FILE_HASH_SHA256, re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'")),
    (IOCType.EMAIL, re.compile(r"email-addr:value\s*=\s*'([^']+)'")),
    (IOCType.CVE, re.compile(r"vulnerability:name\s*=\s*'([^']+)'")),
]

_TLP_MARKING_MAP = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519ae": TLPLevel.WHITE,
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": TLPLevel.GREEN,
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": TLPLevel.AMBER,
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": TLPLevel.RED,
}

_SEVERITY_LABEL_MAP = {
    "malicious-activity": Severity.HIGH,
    "compromised": Severity.CRITICAL,
    "anomalous-activity": Severity.MEDIUM,
    "attribution": Severity.MEDIUM,
    "benign": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class STIXParseError(Exception):
    pass


class STIXParser:
    """
    Parses STIX 2.1 bundles and extracts IOCs with full relationship tracking.

    Handles:
    - Indicator objects (pattern-based IOC extraction)
    - Observable objects (direct value extraction)
    - Threat actor attribution
    - Kill chain and MITRE technique mapping
    - TLP markings
    - Object relationships
    """

    def __init__(self, source_name: str = "stix-feed") -> None:
        self.source_name = source_name
        self._object_index: Dict[str, Dict[str, Any]] = {}
        self._relationships: Dict[str, List[str]] = {}

    def parse_bundle(self, bundle_data: str | bytes | Dict[str, Any]) -> List[IOC]:
        """Parse a STIX 2.1 bundle and return extracted IOCs."""
        if isinstance(bundle_data, (str, bytes)):
            try:
                bundle = json.loads(bundle_data)
            except json.JSONDecodeError as e:
                raise STIXParseError(f"Invalid JSON in STIX bundle: {e}") from e
        else:
            bundle = bundle_data

        if bundle.get("type") != "bundle":
            raise STIXParseError(f"Expected STIX bundle, got type={bundle.get('type')!r}")

        objects = bundle.get("objects", [])
        if not objects:
            logger.warning("STIX bundle contains no objects")
            return []

        # Index all objects for relationship resolution
        self._index_objects(objects)
        self._build_relationships(objects)

        iocs: List[IOC] = []
        for obj in objects:
            extracted = self._extract_from_object(obj)
            iocs.extend(extracted)

        logger.info(
            "Parsed STIX bundle: %d objects, %d IOCs extracted",
            len(objects),
            len(iocs),
        )
        return iocs

    def parse_bundle_stream(
        self, bundle_data: str | bytes | Dict[str, Any]
    ) -> Generator[IOC, None, None]:
        """Streaming parser for large STIX bundles."""
        iocs = self.parse_bundle(bundle_data)
        yield from iocs

    def _index_objects(self, objects: List[Dict[str, Any]]) -> None:
        self._object_index = {obj["id"]: obj for obj in objects if "id" in obj}

    def _build_relationships(self, objects: List[Dict[str, Any]]) -> None:
        self._relationships = {}
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src and tgt:
                self._relationships.setdefault(src, []).append(tgt)
                self._relationships.setdefault(tgt, []).append(src)

    def _extract_from_object(self, obj: Dict[str, Any]) -> List[IOC]:
        obj_type = obj.get("type", "")
        handlers = {
            "indicator": self._parse_indicator,
            "ipv4-addr": self._parse_observable_ipv4,
            "ipv6-addr": self._parse_observable_ipv6,
            "domain-name": self._parse_observable_domain,
            "url": self._parse_observable_url,
            "file": self._parse_observable_file,
            "email-addr": self._parse_observable_email,
            "network-traffic": self._parse_network_traffic,
        }
        handler = handlers.get(obj_type)
        if handler:
            try:
                return handler(obj)
            except Exception as e:
                logger.debug("Failed to parse %s object %s: %s", obj_type, obj.get("id"), e)
        return []

    def _parse_indicator(self, obj: Dict[str, Any]) -> List[IOC]:
        """Extract IOCs from STIX indicator objects via pattern matching."""
        pattern = obj.get("pattern", "")
        if not pattern:
            return []

        iocs = []
        for ioc_type, regex in _PATTERN_EXTRACTORS:
            for match in regex.finditer(pattern):
                value = match.group(1).strip()
                if not value:
                    continue
                ioc = self._build_ioc(ioc_type, value, obj)
                iocs.append(ioc)

        return iocs

    def _parse_observable_ipv4(self, obj: Dict[str, Any]) -> List[IOC]:
        value = obj.get("value", "")
        return [self._build_ioc(IOCType.IPV4, value, obj)] if value else []

    def _parse_observable_ipv6(self, obj: Dict[str, Any]) -> List[IOC]:
        value = obj.get("value", "")
        return [self._build_ioc(IOCType.IPV6, value, obj)] if value else []

    def _parse_observable_domain(self, obj: Dict[str, Any]) -> List[IOC]:
        value = obj.get("value", "")
        return [self._build_ioc(IOCType.DOMAIN, value, obj)] if value else []

    def _parse_observable_url(self, obj: Dict[str, Any]) -> List[IOC]:
        value = obj.get("value", "")
        return [self._build_ioc(IOCType.URL, value, obj)] if value else []

    def _parse_observable_file(self, obj: Dict[str, Any]) -> List[IOC]:
        iocs = []
        hashes = obj.get("hashes", {})
        hash_type_map = {
            "MD5": IOCType.FILE_HASH_MD5,
            "SHA-1": IOCType.FILE_HASH_SHA1,
            "SHA-256": IOCType.FILE_HASH_SHA256,
        }
        for hash_name, ioc_type in hash_type_map.items():
            value = hashes.get(hash_name, "")
            if value:
                iocs.append(self._build_ioc(ioc_type, value, obj))
        return iocs

    def _parse_observable_email(self, obj: Dict[str, Any]) -> List[IOC]:
        value = obj.get("value", "")
        return [self._build_ioc(IOCType.EMAIL, value, obj)] if value else []

    def _parse_network_traffic(self, obj: Dict[str, Any]) -> List[IOC]:
        iocs = []
        dst_ref = obj.get("dst_ref")
        if dst_ref and dst_ref in self._object_index:
            dst_obj = self._object_index[dst_ref]
            iocs.extend(self._extract_from_object(dst_obj))
        return iocs

    def _build_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        source_obj: Dict[str, Any],
    ) -> IOC:
        tlp = self._resolve_tlp(source_obj.get("object_marking_refs", []))
        severity = self._resolve_severity(source_obj.get("labels", []))
        confidence = source_obj.get("confidence", 50)
        tags = set(source_obj.get("labels", []))

        mitre_techniques = []
        for phase in source_obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") in ("mitre-attack", "mitre-mobile-attack"):
                mitre_techniques.append(phase.get("phase_name", ""))

        created_raw = source_obj.get("created")
        created_at = self._parse_timestamp(created_raw)

        related = [
            ref for ref in self._relationships.get(source_obj.get("id", ""), [])
            if ref != source_obj.get("id")
        ]

        return IOC(
            ioc_type=ioc_type,
            value=value,
            source=self.source_name,
            severity=severity,
            confidence=confidence,
            tlp=tlp,
            tags=tags,
            mitre_techniques=mitre_techniques,
            related_iocs=related,
            metadata={
                "stix_id": source_obj.get("id"),
                "stix_name": source_obj.get("name", ""),
            },
            created_at=created_at,
        )

    def _resolve_tlp(self, marking_refs: List[str]) -> TLPLevel:
        for ref in marking_refs:
            if ref in _TLP_MARKING_MAP:
                return _TLP_MARKING_MAP[ref]
        return TLPLevel.GREEN

    def _resolve_severity(self, labels: List[str]) -> Severity:
        for label in labels:
            label_lower = label.lower()
            if label_lower in _SEVERITY_LABEL_MAP:
                return _SEVERITY_LABEL_MAP[label_lower]
        return Severity.MEDIUM

    @staticmethod
    def _parse_timestamp(ts: Optional[str]) -> datetime:
        if ts:
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)
