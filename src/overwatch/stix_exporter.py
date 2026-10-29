"""
STIX 2.1 export pipeline for threat intelligence sharing.

Converts internal IOC objects into valid STIX 2.1 bundles with:
  - Proper indicator patterns for each IOC type
  - TLP marking definitions (white/green/amber/red)
  - Identity object representing this platform
  - Malware and campaign relationship objects
  - Filtering by TLP, confidence, severity, IOC type
  - JSON and line-delimited JSON export formats
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set

from overwatch.models import IOC, IOCType, Severity, TLPLevel


# ---------------------------------------------------------------------------
# STIX 2.1 type and vocabulary constants
# ---------------------------------------------------------------------------

STIX_SPEC_VERSION = "2.1"

# Indicator type vocabulary (open-vocab)
INDICATOR_TYPES = {
    Severity.CRITICAL: ["malicious-activity"],
    Severity.HIGH: ["malicious-activity"],
    Severity.MEDIUM: ["malicious-activity", "anomalous-activity"],
    Severity.LOW: ["anomalous-activity"],
    Severity.INFO: ["benign"],
}

# TLP object IDs (fixed per STIX TLP spec)
TLP_OBJECT_IDS: Dict[TLPLevel, str] = {
    TLPLevel.WHITE: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    TLPLevel.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    TLPLevel.AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    TLPLevel.RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# IOC type -> STIX pattern template  (value placeholder: {value})
PATTERN_TEMPLATES: Dict[IOCType, str] = {
    IOCType.IPV4: "[ipv4-addr:value = '{value}']",
    IOCType.IPV6: "[ipv6-addr:value = '{value}']",
    IOCType.DOMAIN: "[domain-name:value = '{value}']",
    IOCType.URL: "[url:value = '{value}']",
    IOCType.FILE_HASH_MD5: "[file:hashes.MD5 = '{value}']",
    IOCType.FILE_HASH_SHA1: "[file:hashes.'SHA-1' = '{value}']",
    IOCType.FILE_HASH_SHA256: "[file:hashes.'SHA-256' = '{value}']",
    IOCType.EMAIL: "[email-addr:value = '{value}']",
    IOCType.MUTEX: "[mutex:name = '{value}']",
    IOCType.REGISTRY_KEY: "[windows-registry-key:key = '{value}']",
    IOCType.USER_AGENT: "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{value}']",
    IOCType.CVE: "[vulnerability:name = '{value}']",
    IOCType.NETWORK_TRAFFIC: "[network-traffic:dst_ref.type = 'ipv4-addr']",  # generic fallback
}


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_stix(dt: Optional[datetime]) -> str:
    if dt is None:
        return _now_stix()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Export filter
# ---------------------------------------------------------------------------

@dataclass
class ExportFilter:
    """Controls which IOCs are included in an export bundle."""

    max_tlp: TLPLevel = TLPLevel.RED
    min_confidence: int = 0
    min_severity: Optional[Severity] = None
    ioc_types: Optional[Set[IOCType]] = None
    tags: Optional[Set[str]] = None          # any tag must match (OR)
    sources: Optional[List[str]] = None
    exclude_expired: bool = True

    _TLP_ORDER = [TLPLevel.WHITE, TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.RED]

    def _tlp_rank(self, tlp: TLPLevel) -> int:
        try:
            return self._TLP_ORDER.index(tlp)
        except ValueError:
            return 0

    def allows(self, ioc: IOC) -> bool:
        if self.exclude_expired and ioc.is_expired:
            return False
        if self._tlp_rank(ioc.tlp) > self._tlp_rank(self.max_tlp):
            return False
        if ioc.confidence < self.min_confidence:
            return False
        if self.min_severity is not None and ioc.severity.score < self.min_severity.score:
            return False
        if self.ioc_types is not None and ioc.ioc_type not in self.ioc_types:
            return False
        if self.tags is not None and not (ioc.tags & self.tags):
            return False
        if self.sources is not None and ioc.source not in self.sources:
            return False
        return True


# ---------------------------------------------------------------------------
# TLP marking definition builder
# ---------------------------------------------------------------------------

def _build_tlp_marking(tlp: TLPLevel) -> Dict[str, Any]:
    """Return a STIX 2.1 TLP marking-definition object."""
    tlp_name = tlp.value  # e.g. "TLP:GREEN"
    return {
        "type": "marking-definition",
        "id": TLP_OBJECT_IDS[tlp],
        "spec_version": STIX_SPEC_VERSION,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": tlp_name.lower().replace("tlp:", "")},
    }


# ---------------------------------------------------------------------------
# Identity builder
# ---------------------------------------------------------------------------

def _build_identity(
    name: str = "Overwatch TI Platform",
    identity_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "type": "identity",
        "id": identity_id or _stix_id("identity"),
        "spec_version": STIX_SPEC_VERSION,
        "created": _now_stix(),
        "modified": _now_stix(),
        "name": name,
        "identity_class": "system",
        "sectors": ["technology"],
        "description": "Overwatch threat intelligence and SOAR platform",
    }


# ---------------------------------------------------------------------------
# IOC -> STIX indicator
# ---------------------------------------------------------------------------

def _build_indicator(ioc: IOC, creator_id: str) -> Optional[Dict[str, Any]]:
    """Convert an IOC to a STIX 2.1 indicator object. Returns None if no pattern available."""
    template = PATTERN_TEMPLATES.get(ioc.ioc_type)
    if template is None:
        return None

    escaped_value = ioc.value.replace("'", "\\'")
    pattern = template.format(value=escaped_value)

    indicator_types = INDICATOR_TYPES.get(ioc.severity, ["malicious-activity"])

    labels = sorted(ioc.tags)
    if ioc.mitre_techniques:
        labels += [f"mitre-attack:{t}" for t in ioc.mitre_techniques[:5]]

    obj: Dict[str, Any] = {
        "type": "indicator",
        "id": f"indicator--{ioc.id}",
        "spec_version": STIX_SPEC_VERSION,
        "created": _dt_stix(ioc.created_at),
        "modified": _dt_stix(ioc.updated_at),
        "name": f"{ioc.ioc_type.value}: {ioc.value[:80]}",
        "description": (
            f"Source: {ioc.source}. Severity: {ioc.severity.value}. "
            f"Confidence: {ioc.confidence}."
        ),
        "indicator_types": indicator_types,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _dt_stix(ioc.first_seen or ioc.created_at),
        "confidence": ioc.confidence,
        "created_by_ref": creator_id,
        "object_marking_refs": [TLP_OBJECT_IDS[ioc.tlp]],
    }

    if ioc.last_seen:
        obj["valid_until"] = _dt_stix(ioc.last_seen)

    if labels:
        obj["labels"] = labels

    if ioc.mitre_techniques:
        obj["external_references"] = [
            {
                "source_name": "mitre-attack",
                "external_id": t,
                "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/",
            }
            for t in ioc.mitre_techniques[:10]
        ]

    return obj


# ---------------------------------------------------------------------------
# Relationship builder
# ---------------------------------------------------------------------------

def _build_relationship(
    rel_type: str,
    source_ref: str,
    target_ref: str,
    creator_id: str,
    description: str = "",
) -> Dict[str, Any]:
    now = _now_stix()
    obj: Dict[str, Any] = {
        "type": "relationship",
        "id": _stix_id("relationship"),
        "spec_version": STIX_SPEC_VERSION,
        "created": now,
        "modified": now,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "created_by_ref": creator_id,
    }
    if description:
        obj["description"] = description
    return obj


# ---------------------------------------------------------------------------
# Bundle statistics
# ---------------------------------------------------------------------------

@dataclass
class BundleStats:
    total_iocs: int = 0
    exported: int = 0
    skipped_expired: int = 0
    skipped_tlp: int = 0
    skipped_confidence: int = 0
    skipped_no_pattern: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_tlp: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main exporter
# ---------------------------------------------------------------------------

class StixExporter:
    """Builds and exports STIX 2.1 bundles from IOC collections."""

    def __init__(
        self,
        identity_name: str = "Overwatch TI Platform",
        identity_id: Optional[str] = None,
    ) -> None:
        self._identity = _build_identity(identity_name, identity_id)
        self._identity_id: str = self._identity["id"]

    @property
    def identity_id(self) -> str:
        return self._identity_id

    def build_bundle(
        self,
        iocs: List[IOC],
        export_filter: Optional[ExportFilter] = None,
        include_relationships: bool = True,
    ) -> tuple[Dict[str, Any], BundleStats]:
        """
        Build a STIX 2.1 bundle from a list of IOCs.

        Returns (bundle_dict, stats).
        """
        ef = export_filter or ExportFilter()
        stats = BundleStats(total_iocs=len(iocs))

        objects: List[Dict[str, Any]] = [self._identity]
        seen_tlp_markings: Set[TLPLevel] = set()

        # Track which indicators were created so we can link relationships
        indicator_ids: List[str] = []

        for ioc in iocs:
            # Apply filter
            if ef.exclude_expired and ioc.is_expired:
                stats.skipped_expired += 1
                continue
            if not ef.allows(ioc):
                # Determine why it was skipped for stats
                tlp_rank = ef._tlp_rank(ioc.tlp)
                max_tlp_rank = ef._tlp_rank(ef.max_tlp)
                if tlp_rank > max_tlp_rank:
                    stats.skipped_tlp += 1
                elif ioc.confidence < ef.min_confidence:
                    stats.skipped_confidence += 1
                continue

            indicator = _build_indicator(ioc, self._identity_id)
            if indicator is None:
                stats.skipped_no_pattern += 1
                continue

            # Collect TLP markings we need
            seen_tlp_markings.add(ioc.tlp)

            objects.append(indicator)
            indicator_ids.append(indicator["id"])
            stats.exported += 1

            type_key = ioc.ioc_type.value
            stats.by_type[type_key] = stats.by_type.get(type_key, 0) + 1
            stats.by_severity[ioc.severity.value] = stats.by_severity.get(ioc.severity.value, 0) + 1
            stats.by_tlp[ioc.tlp.value] = stats.by_tlp.get(ioc.tlp.value, 0) + 1

        # Add TLP marking definitions for all TLP levels referenced
        tlp_markings = [_build_tlp_marking(tlp) for tlp in seen_tlp_markings]
        # Insert after identity
        objects = [objects[0]] + tlp_markings + objects[1:]

        # Build relationships for related IOC pairs
        if include_relationships:
            rel_objects = list(self._build_ioc_relationships(iocs, ef))
            objects.extend(rel_objects)

        bundle: Dict[str, Any] = {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": objects,
        }
        return bundle, stats

    def _build_ioc_relationships(
        self, iocs: List[IOC], ef: ExportFilter
    ) -> Iterator[Dict[str, Any]]:
        """Generate 'related-to' relationship objects for IOCs that reference each other."""
        id_map = {ioc.id: ioc for ioc in iocs if ef.allows(ioc)}

        for ioc in iocs:
            if not ef.allows(ioc):
                continue
            for related_id in ioc.related_iocs:
                if related_id in id_map:
                    yield _build_relationship(
                        rel_type="related-to",
                        source_ref=f"indicator--{ioc.id}",
                        target_ref=f"indicator--{related_id}",
                        creator_id=self._identity_id,
                        description=f"IOC correlation from {ioc.source}",
                    )

    def export_json(
        self,
        iocs: List[IOC],
        export_filter: Optional[ExportFilter] = None,
        indent: int = 2,
    ) -> tuple[str, BundleStats]:
        """Export bundle as a formatted JSON string."""
        bundle, stats = self.build_bundle(iocs, export_filter)
        return json.dumps(bundle, indent=indent, ensure_ascii=False), stats

    def export_ndjson(
        self,
        iocs: List[IOC],
        export_filter: Optional[ExportFilter] = None,
    ) -> tuple[str, BundleStats]:
        """Export each STIX object as a newline-delimited JSON record (STIX enveloped)."""
        bundle, stats = self.build_bundle(iocs, export_filter)
        lines = [json.dumps(obj, ensure_ascii=False) for obj in bundle["objects"]]
        return "\n".join(lines), stats

    def export_to_file(
        self,
        iocs: List[IOC],
        path: str,
        export_filter: Optional[ExportFilter] = None,
        indent: int = 2,
    ) -> BundleStats:
        """Write bundle JSON to a file. Returns export stats."""
        content, stats = self.export_json(iocs, export_filter, indent=indent)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return stats

    def iter_indicator_objects(
        self,
        iocs: List[IOC],
        export_filter: Optional[ExportFilter] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield individual STIX indicator dicts without wrapping in a bundle."""
        ef = export_filter or ExportFilter()
        for ioc in iocs:
            if not ef.allows(ioc):
                continue
            obj = _build_indicator(ioc, self._identity_id)
            if obj is not None:
                yield obj
