"""
Threat feed ingestion engine supporting multiple feed formats:
- abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker)
- OTX-style pulse format
- Plain text IOC lists
- MISP event format
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Tuple

from overwatch.models import IOC, IOCType, Severity, TLPLevel

logger = logging.getLogger(__name__)


class FeedFormat(str, Enum):
    STIX = "stix"
    ABUSECH_URLHAUS = "abusech_urlhaus"
    ABUSECH_MALWAREBAZAAR = "abusech_malwarebazaar"
    ABUSECH_FEODO = "abusech_feodo"
    OTX_PULSE = "otx_pulse"
    MISP_EVENT = "misp_event"
    PLAIN_TEXT = "plain_text"
    CSV = "csv"


@dataclass
class FeedSource:
    name: str
    format: FeedFormat
    url: str = ""
    api_key: Optional[str] = None
    tlp: TLPLevel = TLPLevel.GREEN
    default_severity: Severity = Severity.MEDIUM
    default_confidence: int = 70
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    poll_interval: int = 3600  # seconds
    last_poll: Optional[float] = None

    @property
    def is_due(self) -> bool:
        if self.last_poll is None:
            return True
        return time.time() - self.last_poll >= self.poll_interval


@dataclass
class IngestionStats:
    feed_name: str
    total_parsed: int = 0
    new_iocs: int = 0
    updated_iocs: int = 0
    skipped: int = 0
    errors: int = 0
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class FeedIngestionEngine:
    """
    Multi-format threat intelligence feed ingestion with deduplication tracking.
    """

    def __init__(self) -> None:
        self._sources: Dict[str, FeedSource] = {}
        self._seen_fingerprints: set[str] = set()
        self._ioc_store: Dict[str, IOC] = {}  # fingerprint -> IOC
        self._stats_history: List[IngestionStats] = []

    def register_source(self, source: FeedSource) -> None:
        self._sources[source.name] = source
        logger.info("Registered feed source: %s (%s)", source.name, source.format.value)

    def ingest(self, source_name: str, raw_data: str | bytes) -> IngestionStats:
        """Ingest raw feed data from a registered source."""
        source = self._sources.get(source_name)
        if source is None:
            raise ValueError(f"Unknown feed source: {source_name!r}")

        start = time.monotonic()
        stats = IngestionStats(feed_name=source_name)

        try:
            iocs = list(self._parse_feed(source, raw_data))
            stats.total_parsed = len(iocs)

            for ioc in iocs:
                fp = ioc.fingerprint
                if fp in self._ioc_store:
                    self._merge_ioc(fp, ioc)
                    stats.updated_iocs += 1
                else:
                    self._ioc_store[fp] = ioc
                    self._seen_fingerprints.add(fp)
                    stats.new_iocs += 1

            source.last_poll = time.time()

        except Exception as e:
            logger.exception("Ingestion failed for %s: %s", source_name, e)
            stats.errors += 1

        stats.duration_ms = (time.monotonic() - start) * 1000
        self._stats_history.append(stats)
        logger.info(
            "Ingested %s: %d new, %d updated, %d errors in %.1fms",
            source_name,
            stats.new_iocs,
            stats.updated_iocs,
            stats.errors,
            stats.duration_ms,
        )
        return stats

    def get_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        min_confidence: int = 0,
        severity: Optional[Severity] = None,
        include_expired: bool = False,
    ) -> List[IOC]:
        """Retrieve IOCs with optional filtering."""
        results = []
        for ioc in self._ioc_store.values():
            if not include_expired and ioc.is_expired:
                continue
            if ioc_type is not None and ioc.ioc_type != ioc_type:
                continue
            if ioc.confidence < min_confidence:
                continue
            if severity is not None and ioc.severity != severity:
                continue
            results.append(ioc)
        return sorted(results, key=lambda x: x.risk_score, reverse=True)

    def _parse_feed(
        self, source: FeedSource, raw_data: str | bytes
    ) -> Generator[IOC, None, None]:
        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode("utf-8", errors="replace")

        parsers = {
            FeedFormat.ABUSECH_URLHAUS: self._parse_abusech_urlhaus,
            FeedFormat.ABUSECH_MALWAREBAZAAR: self._parse_abusech_malwarebazaar,
            FeedFormat.ABUSECH_FEODO: self._parse_abusech_feodo,
            FeedFormat.OTX_PULSE: self._parse_otx_pulse,
            FeedFormat.MISP_EVENT: self._parse_misp_event,
            FeedFormat.PLAIN_TEXT: self._parse_plain_text,
            FeedFormat.CSV: self._parse_csv,
        }

        parser = parsers.get(source.format)
        if parser is None:
            raise ValueError(f"Unsupported feed format: {source.format}")

        yield from parser(source, raw_data)

    def _parse_abusech_urlhaus(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse abuse.ch URLhaus CSV feed format.
        Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        """
        reader = csv.DictReader(
            (line for line in data.splitlines() if not line.startswith("#")),
            fieldnames=["id", "dateadded", "url", "url_status", "last_online",
                        "threat", "tags", "urlhaus_link", "reporter"],
        )
        for row in reader:
            url = row.get("url", "").strip('"')
            if not url or not url.startswith("http"):
                continue

            threat = row.get("threat", "").lower()
            severity = Severity.HIGH if "malware" in threat else Severity.MEDIUM
            tags = set(source.tags)
            raw_tags = row.get("tags", "")
            if raw_tags:
                tags.update(t.strip().strip('"') for t in raw_tags.split(",") if t.strip())

            yield IOC(
                ioc_type=IOCType.URL,
                value=url,
                source=source.name,
                severity=severity,
                confidence=source.default_confidence,
                tlp=source.tlp,
                tags=tags,
                metadata={
                    "threat": threat,
                    "status": row.get("url_status", ""),
                    "reporter": row.get("reporter", ""),
                    "urlhaus_link": row.get("urlhaus_link", ""),
                },
            )

    def _parse_abusech_malwarebazaar(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse abuse.ch MalwareBazaar JSON API response.
        """
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as e:
            logger.warning("Invalid MalwareBazaar JSON: %s", e)
            return

        if payload.get("query_status") != "ok":
            logger.warning("MalwareBazaar query_status=%s", payload.get("query_status"))
            return

        for sample in payload.get("data", []):
            sha256 = sample.get("sha256_hash", "").lower()
            if not sha256:
                continue

            tags = set(source.tags)
            signature = sample.get("signature", "")
            file_type = sample.get("file_type", "")
            if signature:
                tags.add(f"malware:{signature.lower()}")
            if file_type:
                tags.add(f"filetype:{file_type.lower()}")

            mitre_techniques = []
            for tag in sample.get("tags", []) or []:
                if tag.startswith("T"):
                    mitre_techniques.append(tag)

            yield IOC(
                ioc_type=IOCType.FILE_HASH_SHA256,
                value=sha256,
                source=source.name,
                severity=Severity.HIGH,
                confidence=90,
                tlp=source.tlp,
                tags=tags,
                mitre_techniques=mitre_techniques,
                metadata={
                    "file_name": sample.get("file_name", ""),
                    "file_size": sample.get("file_size"),
                    "file_type": file_type,
                    "signature": signature,
                    "imphash": sample.get("imphash", ""),
                    "first_seen": sample.get("first_seen", ""),
                    "reporter": sample.get("reporter", ""),
                },
            )

            # Also yield MD5 and SHA1 if available
            for hash_type, ioc_type in [
                ("md5_hash", IOCType.FILE_HASH_MD5),
                ("sha1_hash", IOCType.FILE_HASH_SHA1),
            ]:
                h = sample.get(hash_type, "").lower()
                if h:
                    yield IOC(
                        ioc_type=ioc_type,
                        value=h,
                        source=source.name,
                        severity=Severity.HIGH,
                        confidence=90,
                        tlp=source.tlp,
                        tags=tags,
                        metadata={"file_name": sample.get("file_name", "")},
                    )

    def _parse_abusech_feodo(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse abuse.ch Feodo Tracker botnet C2 IPs (CSV or JSON).
        JSON format: [{"ip_address": ..., "port": ..., "status": ..., "malware": ...}]
        """
        data_stripped = data.strip()
        if data_stripped.startswith("[") or data_stripped.startswith("{"):
            try:
                entries = json.loads(data_stripped)
                if isinstance(entries, dict):
                    entries = entries.get("data", [])
                for entry in entries:
                    ip = entry.get("ip_address", "").strip()
                    if not ip:
                        continue
                    malware = entry.get("malware", "").lower()
                    tags = set(source.tags) | {f"c2:{malware}"} if malware else set(source.tags)
                    yield IOC(
                        ioc_type=IOCType.IPV4,
                        value=ip,
                        source=source.name,
                        severity=Severity.CRITICAL,
                        confidence=95,
                        tlp=source.tlp,
                        tags=tags | {"botnet-c2", "feodo"},
                        metadata={
                            "port": entry.get("port"),
                            "status": entry.get("status", ""),
                            "malware": malware,
                            "country": entry.get("country", ""),
                        },
                    )
                return
            except json.JSONDecodeError:
                pass

        # Fall back to CSV parsing
        reader = csv.DictReader(
            (line for line in data.splitlines() if not line.startswith("#")),
        )
        for row in reader:
            ip = (row.get("ip_address") or row.get("dst_ip") or "").strip()
            if not ip:
                continue
            yield IOC(
                ioc_type=IOCType.IPV4,
                value=ip,
                source=source.name,
                severity=Severity.CRITICAL,
                confidence=95,
                tlp=source.tlp,
                tags=set(source.tags) | {"botnet-c2", "feodo"},
                metadata=dict(row),
            )

    def _parse_otx_pulse(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse AlienVault OTX-style pulse JSON format.
        """
        try:
            pulse = json.loads(data)
        except json.JSONDecodeError as e:
            logger.warning("Invalid OTX pulse JSON: %s", e)
            return

        pulse_tags = set(source.tags)
        for tag in pulse.get("tags", []):
            pulse_tags.add(tag.lower())

        adversary = pulse.get("adversary", "")
        malware_families = [m.get("name", "") for m in pulse.get("malware_families", [])]
        attack_ids = [a.get("id", "") for a in pulse.get("attack_ids", [])]

        # OTX indicator type -> IOCType mapping
        otx_type_map = {
            "IPv4": IOCType.IPV4,
            "IPv6": IOCType.IPV6,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "URL": IOCType.URL,
            "FileHash-MD5": IOCType.FILE_HASH_MD5,
            "FileHash-SHA1": IOCType.FILE_HASH_SHA1,
            "FileHash-SHA256": IOCType.FILE_HASH_SHA256,
            "email": IOCType.EMAIL,
            "CVE": IOCType.CVE,
        }

        for indicator in pulse.get("indicators", []):
            otx_type = indicator.get("type", "")
            ioc_type = otx_type_map.get(otx_type)
            if ioc_type is None:
                continue

            value = indicator.get("indicator", "").strip()
            if not value:
                continue

            indicator_tags = pulse_tags.copy()
            for role in indicator.get("role", "").split(","):
                role = role.strip()
                if role:
                    indicator_tags.add(role)

            yield IOC(
                ioc_type=ioc_type,
                value=value,
                source=source.name,
                severity=source.default_severity,
                confidence=source.default_confidence,
                tlp=source.tlp,
                tags=indicator_tags,
                mitre_techniques=attack_ids,
                metadata={
                    "pulse_id": pulse.get("id", ""),
                    "pulse_name": pulse.get("name", ""),
                    "adversary": adversary,
                    "malware_families": malware_families,
                    "description": indicator.get("description", ""),
                },
            )

    def _parse_misp_event(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse MISP event JSON format.
        """
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as e:
            logger.warning("Invalid MISP JSON: %s", e)
            return

        event = payload.get("Event", payload)
        tags = set(source.tags)
        for tag in event.get("Tag", []):
            name = tag.get("name", "")
            if "tlp" in name.lower():
                continue
            tags.add(name.lower())

        misp_type_map = {
            "ip-src": IOCType.IPV4,
            "ip-dst": IOCType.IPV4,
            "ip-src|port": IOCType.IPV4,
            "ip-dst|port": IOCType.IPV4,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5": IOCType.FILE_HASH_MD5,
            "sha1": IOCType.FILE_HASH_SHA1,
            "sha256": IOCType.FILE_HASH_SHA256,
            "filename|md5": IOCType.FILE_HASH_MD5,
            "filename|sha1": IOCType.FILE_HASH_SHA1,
            "filename|sha256": IOCType.FILE_HASH_SHA256,
            "email-src": IOCType.EMAIL,
            "email-dst": IOCType.EMAIL,
            "vulnerability": IOCType.CVE,
        }

        threat_level = int(event.get("threat_level_id", 3))
        severity_map = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM, 4: Severity.LOW}
        severity = severity_map.get(threat_level, Severity.MEDIUM)

        for attr in event.get("Attribute", []):
            misp_type = attr.get("type", "")
            ioc_type = misp_type_map.get(misp_type)
            if ioc_type is None:
                continue

            value = attr.get("value", "").strip()
            if "|" in value:
                value = value.split("|")[1] if "hash" in misp_type.lower() else value.split("|")[0]
            if not value:
                continue

            yield IOC(
                ioc_type=ioc_type,
                value=value,
                source=source.name,
                severity=severity,
                confidence=source.default_confidence,
                tlp=source.tlp,
                tags=tags,
                metadata={
                    "misp_event_id": event.get("id", ""),
                    "misp_attr_id": attr.get("id", ""),
                    "category": attr.get("category", ""),
                    "comment": attr.get("comment", ""),
                    "to_ids": attr.get("to_ids", False),
                },
            )

    def _parse_plain_text(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse plain text IOC lists (one IOC per line, auto-detect type).
        """
        ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$")
        ipv6_re = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
        domain_re = re.compile(r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$")
        url_re = re.compile(r"^https?://")
        md5_re = re.compile(r"^[0-9a-fA-F]{32}$")
        sha1_re = re.compile(r"^[0-9a-fA-F]{40}$")
        sha256_re = re.compile(r"^[0-9a-fA-F]{64}$")
        email_re = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
        cve_re = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            value = line.split()[0]
            ioc_type: Optional[IOCType] = None

            if cve_re.match(value):
                ioc_type = IOCType.CVE
            elif sha256_re.match(value):
                ioc_type = IOCType.FILE_HASH_SHA256
            elif sha1_re.match(value):
                ioc_type = IOCType.FILE_HASH_SHA1
            elif md5_re.match(value):
                ioc_type = IOCType.FILE_HASH_MD5
            elif url_re.match(value):
                ioc_type = IOCType.URL
            elif ip_re.match(value):
                ioc_type = IOCType.IPV4
            elif ipv6_re.match(value):
                ioc_type = IOCType.IPV6
            elif email_re.match(value):
                ioc_type = IOCType.EMAIL
            elif domain_re.match(value):
                ioc_type = IOCType.DOMAIN

            if ioc_type:
                yield IOC(
                    ioc_type=ioc_type,
                    value=value,
                    source=source.name,
                    severity=source.default_severity,
                    confidence=source.default_confidence,
                    tlp=source.tlp,
                    tags=set(source.tags),
                )

    def _parse_csv(
        self, source: FeedSource, data: str
    ) -> Generator[IOC, None, None]:
        """
        Parse generic CSV feed. Requires 'type' and 'value' columns
        or auto-detects from a single-column format.
        """
        reader = csv.DictReader(
            (line for line in data.splitlines() if not line.startswith("#"))
        )
        if reader.fieldnames and "value" in reader.fieldnames:
            for row in reader:
                value = row.get("value", "").strip()
                type_str = row.get("type", "").lower()
                ioc_type_map = {
                    "ip": IOCType.IPV4,
                    "ipv4": IOCType.IPV4,
                    "ipv6": IOCType.IPV6,
                    "domain": IOCType.DOMAIN,
                    "url": IOCType.URL,
                    "md5": IOCType.FILE_HASH_MD5,
                    "sha1": IOCType.FILE_HASH_SHA1,
                    "sha256": IOCType.FILE_HASH_SHA256,
                    "email": IOCType.EMAIL,
                }
                ioc_type = ioc_type_map.get(type_str)
                if value and ioc_type:
                    severity_str = row.get("severity", "").lower()
                    sev_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    severity = sev_map.get(severity_str, source.default_severity)
                    yield IOC(
                        ioc_type=ioc_type,
                        value=value,
                        source=source.name,
                        severity=severity,
                        confidence=int(row.get("confidence", source.default_confidence)),
                        tlp=source.tlp,
                        tags=set(source.tags),
                        metadata={k: v for k, v in row.items() if k not in ("type", "value")},
                    )
        else:
            # Single column - delegate to plain text parser
            yield from self._parse_plain_text(source, data)

    def _merge_ioc(self, fingerprint: str, new_ioc: IOC) -> None:
        """Merge newer IOC data into existing entry."""
        existing = self._ioc_store[fingerprint]
        existing.hit_count += 1
        existing.last_seen = datetime.now(timezone.utc)
        existing.updated_at = existing.last_seen
        # Update confidence if newer source is more authoritative
        if new_ioc.confidence > existing.confidence:
            existing.confidence = new_ioc.confidence
        existing.tags.update(new_ioc.tags)
        for tech in new_ioc.mitre_techniques:
            if tech not in existing.mitre_techniques:
                existing.mitre_techniques.append(tech)
