"""
Core data models for threat intelligence indicators and alerts.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class IOCType(str, Enum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    FILE_HASH_MD5 = "file:hashes.MD5"
    FILE_HASH_SHA1 = "file:hashes.SHA-1"
    FILE_HASH_SHA256 = "file:hashes.SHA-256"
    EMAIL = "email-addr"
    MUTEX = "mutex"
    REGISTRY_KEY = "windows-registry-key"
    NETWORK_TRAFFIC = "network-traffic"
    USER_AGENT = "user-agent"
    CVE = "vulnerability"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class TLPLevel(str, Enum):
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class PlaybookAction(str, Enum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_HOST = "quarantine_host"
    ENRICH_ALERT = "enrich_alert"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    RESET_CREDENTIALS = "reset_credentials"
    COLLECT_FORENSICS = "collect_forensics"
    PATCH_VULNERABILITY = "patch_vulnerability"


@dataclass
class IOC:
    """Indicator of Compromise with full lifecycle management."""

    ioc_type: IOCType
    value: str
    source: str
    severity: Severity = Severity.MEDIUM
    confidence: int = 50  # 0-100
    tlp: TLPLevel = TLPLevel.GREEN
    tags: Set[str] = field(default_factory=set)
    mitre_techniques: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: int = 86400  # 24 hours default
    hit_count: int = 0
    false_positive_count: int = 0

    # Lifecycle timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Internal identifier
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.confidence < 0 or self.confidence > 100:
            raise ValueError(f"Confidence must be 0-100, got {self.confidence}")
        if self.ttl_seconds < 0:
            raise ValueError("TTL must be non-negative")
        if self.first_seen is None:
            self.first_seen = self.created_at

    @property
    def fingerprint(self) -> str:
        """Canonical hash for deduplication."""
        return hashlib.sha256(
            f"{self.ioc_type.value}:{self.value.lower()}".encode()
        ).hexdigest()

    @property
    def is_expired(self) -> bool:
        age = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return age > self.ttl_seconds

    @property
    def adjusted_confidence(self) -> float:
        """Confidence adjusted for false positive rate."""
        total = self.hit_count + self.false_positive_count
        if total == 0:
            return self.confidence
        fp_rate = self.false_positive_count / total
        return self.confidence * (1.0 - fp_rate)

    @property
    def risk_score(self) -> float:
        """Composite risk score 0-100."""
        return (self.severity.score / 5.0) * self.adjusted_confidence

    def record_hit(self) -> None:
        self.hit_count += 1
        self.last_seen = datetime.now(timezone.utc)
        self.updated_at = self.last_seen

    def record_false_positive(self) -> None:
        self.false_positive_count += 1
        self.updated_at = datetime.now(timezone.utc)

    def extend_ttl(self, additional_seconds: int) -> None:
        self.ttl_seconds += additional_seconds
        self.updated_at = datetime.now(timezone.utc)

    def to_stix(self) -> Dict[str, Any]:
        """Serialize to STIX 2.1 indicator format."""
        pattern = self._build_stix_pattern()
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self.id}",
            "created": self.created_at.isoformat(),
            "modified": self.updated_at.isoformat(),
            "name": f"{self.ioc_type.value}: {self.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self.created_at.isoformat(),
            "confidence": self.confidence,
            "labels": list(self.tags),
            "external_references": [
                {"source_name": self.source}
            ],
            "object_marking_refs": [f"marking-definition--{self.tlp.value}"],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": tech}
                for tech in self.mitre_techniques
            ],
        }

    def _build_stix_pattern(self) -> str:
        mapping = {
            IOCType.IPV4: f"[ipv4-addr:value = '{self.value}']",
            IOCType.IPV6: f"[ipv6-addr:value = '{self.value}']",
            IOCType.DOMAIN: f"[domain-name:value = '{self.value}']",
            IOCType.URL: f"[url:value = '{self.value}']",
            IOCType.FILE_HASH_MD5: f"[file:hashes.MD5 = '{self.value}']",
            IOCType.FILE_HASH_SHA1: f"[file:hashes.'SHA-1' = '{self.value}']",
            IOCType.FILE_HASH_SHA256: f"[file:hashes.'SHA-256' = '{self.value}']",
            IOCType.EMAIL: f"[email-addr:value = '{self.value}']",
            IOCType.CVE: f"[vulnerability:name = '{self.value}']",
        }
        return mapping.get(self.ioc_type, f"[{self.ioc_type.value}:value = '{self.value}']")


@dataclass
class AlertTriage:
    """Triaged alert with enrichment and response actions."""

    alert_id: str
    title: str
    description: str
    severity: Severity
    source: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    matched_iocs: List[IOC] = field(default_factory=list)
    recommended_actions: List[PlaybookAction] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    is_false_positive: bool = False
    analyst_notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None

    @property
    def is_resolved(self) -> bool:
        return self.resolved_at is not None

    @property
    def risk_score(self) -> float:
        if not self.matched_iocs:
            return self.severity.score * 20.0
        avg_ioc_risk = sum(ioc.risk_score for ioc in self.matched_iocs) / len(self.matched_iocs)
        return min(100.0, (self.severity.score * 10.0) + avg_ioc_risk)

    def resolve(self, notes: str = "") -> None:
        self.resolved_at = datetime.now(timezone.utc)
        if notes:
            self.analyst_notes += f"\n[Resolved] {notes}"


@dataclass
class ThreatActor:
    """Threat actor profile aggregated from intelligence sources."""

    name: str
    aliases: List[str] = field(default_factory=list)
    motivation: str = ""
    sophistication: str = ""  # minimal, novice, intermediate, advanced, expert, innovator
    resource_level: str = ""
    goals: List[str] = field(default_factory=list)
    mitre_groups: List[str] = field(default_factory=list)
    associated_iocs: List[str] = field(default_factory=list)  # IOC fingerprints
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tlp: TLPLevel = TLPLevel.AMBER
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
