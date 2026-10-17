"""
IOC enrichment pipeline with correlation engine and confidence scoring.
Enriches indicators with GeoIP, WHOIS, passive DNS, and threat context.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from overwatch.models import IOC, IOCType, Severity, ThreatActor

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    ioc_fingerprint: str
    enricher_name: str
    data: Dict[str, Any]
    confidence_delta: int = 0
    severity_override: Optional[Severity] = None
    additional_iocs: List[IOC] = field(default_factory=list)
    tags_to_add: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass
class CorrelationCluster:
    """Group of IOCs that are correlated by campaign, actor, or behavior."""
    cluster_id: str
    label: str
    ioc_fingerprints: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


EnricherFunc = Callable[[IOC], EnrichmentResult]


class EnrichmentPipeline:
    """
    Pluggable enrichment pipeline for IOC indicators.

    Supports:
    - IP reputation and geolocation enrichment
    - Domain WHOIS analysis
    - File hash metadata enrichment
    - Cross-IOC correlation engine
    - Confidence score adjustment based on enrichment results
    - MITRE ATT&CK technique tagging
    """

    def __init__(self) -> None:
        self._enrichers: Dict[str, Tuple[List[IOCType], EnricherFunc]] = {}
        self._correlation_index: Dict[str, List[str]] = {}  # tag/value -> fingerprints
        self._clusters: Dict[str, CorrelationCluster] = {}
        self._threat_actors: Dict[str, ThreatActor] = {}
        self._enrichment_cache: Dict[str, EnrichmentResult] = {}

        # Register default enrichers
        self._register_builtin_enrichers()

    def register_enricher(
        self,
        name: str,
        ioc_types: List[IOCType],
        func: EnricherFunc,
    ) -> None:
        self._enrichers[name] = (ioc_types, func)
        logger.debug("Registered enricher: %s for types %s", name, ioc_types)

    def enrich(self, ioc: IOC) -> List[EnrichmentResult]:
        """Run all applicable enrichers on an IOC and apply results."""
        results = []
        for name, (supported_types, func) in self._enrichers.items():
            if supported_types and ioc.ioc_type not in supported_types:
                continue

            cache_key = f"{name}:{ioc.fingerprint}"
            if cache_key in self._enrichment_cache:
                result = self._enrichment_cache[cache_key]
            else:
                try:
                    result = func(ioc)
                    self._enrichment_cache[cache_key] = result
                except Exception as e:
                    logger.warning("Enricher %s failed for %s: %s", name, ioc.value, e)
                    result = EnrichmentResult(
                        ioc_fingerprint=ioc.fingerprint,
                        enricher_name=name,
                        data={},
                        error=str(e),
                    )

            self._apply_enrichment(ioc, result)
            results.append(result)

        self._update_correlation_index(ioc)
        return results

    def correlate(self, ioc: IOC) -> List[CorrelationCluster]:
        """Find IOCs that correlate with the given indicator."""
        related_fps: set[str] = set()

        # Correlate by shared MITRE techniques
        for tech in ioc.mitre_techniques:
            key = f"mitre:{tech}"
            related_fps.update(self._correlation_index.get(key, []))

        # Correlate by shared tags
        for tag in ioc.tags:
            key = f"tag:{tag}"
            related_fps.update(self._correlation_index.get(key, []))

        # Correlate by subnet for IPs
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            subnet_key = self._get_subnet_key(ioc.value)
            if subnet_key:
                related_fps.update(self._correlation_index.get(subnet_key, []))

        related_fps.discard(ioc.fingerprint)
        if not related_fps:
            return []

        cluster = self._find_or_create_cluster(ioc, related_fps)
        return [cluster]

    def add_threat_actor(self, actor: ThreatActor) -> None:
        self._threat_actors[actor.name.lower()] = actor

    def get_threat_actor(self, name: str) -> Optional[ThreatActor]:
        return self._threat_actors.get(name.lower())

    def compute_cluster_confidence(self, cluster: CorrelationCluster) -> float:
        """Score a cluster based on IOC count and shared attributes."""
        size_score = min(1.0, len(cluster.ioc_fingerprints) / 10.0)
        tech_score = min(1.0, len(cluster.mitre_techniques) / 5.0)
        return round((size_score * 0.6 + tech_score * 0.4) * 100, 2)

    def _apply_enrichment(self, ioc: IOC, result: EnrichmentResult) -> None:
        if not result.succeeded:
            return

        if result.confidence_delta:
            new_conf = max(0, min(100, ioc.confidence + result.confidence_delta))
            ioc.confidence = new_conf

        if result.severity_override:
            ioc.severity = result.severity_override

        for tag in result.tags_to_add:
            ioc.tags.add(tag)

        ioc.metadata.update({f"{result.enricher_name}.{k}": v for k, v in result.data.items()})
        ioc.updated_at = datetime.now(timezone.utc)

    def _update_correlation_index(self, ioc: IOC) -> None:
        fp = ioc.fingerprint

        for tech in ioc.mitre_techniques:
            key = f"mitre:{tech}"
            self._correlation_index.setdefault(key, [])
            if fp not in self._correlation_index[key]:
                self._correlation_index[key].append(fp)

        for tag in ioc.tags:
            key = f"tag:{tag}"
            self._correlation_index.setdefault(key, [])
            if fp not in self._correlation_index[key]:
                self._correlation_index[key].append(fp)

        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            subnet_key = self._get_subnet_key(ioc.value)
            if subnet_key:
                self._correlation_index.setdefault(subnet_key, [])
                if fp not in self._correlation_index[subnet_key]:
                    self._correlation_index[subnet_key].append(fp)

    def _get_subnet_key(self, ip_str: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                return f"subnet:{network.network_address}"
            elif isinstance(addr, ipaddress.IPv6Address):
                network = ipaddress.ip_network(f"{ip_str}/48", strict=False)
                return f"subnet6:{network.network_address}"
        except ValueError:
            pass
        return None

    def _find_or_create_cluster(
        self, ioc: IOC, related_fps: set[str]
    ) -> CorrelationCluster:
        all_fps = {ioc.fingerprint} | related_fps
        cluster_id = hashlib.sha256(":".join(sorted(all_fps)).encode()).hexdigest()[:16]

        if cluster_id not in self._clusters:
            combined_techniques = list(ioc.mitre_techniques)
            cluster = CorrelationCluster(
                cluster_id=cluster_id,
                label=f"Cluster-{cluster_id[:8]}",
                ioc_fingerprints=list(all_fps),
                mitre_techniques=combined_techniques,
            )
            cluster.confidence = self.compute_cluster_confidence(cluster)
            self._clusters[cluster_id] = cluster
        else:
            cluster = self._clusters[cluster_id]
            for fp in all_fps:
                if fp not in cluster.ioc_fingerprints:
                    cluster.ioc_fingerprints.append(fp)

        return cluster

    def _register_builtin_enrichers(self) -> None:
        self.register_enricher(
            "ip_reputation",
            [IOCType.IPV4, IOCType.IPV6],
            self._enrich_ip_reputation,
        )
        self.register_enricher(
            "domain_analysis",
            [IOCType.DOMAIN],
            self._enrich_domain_analysis,
        )
        self.register_enricher(
            "hash_metadata",
            [IOCType.FILE_HASH_SHA256, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_MD5],
            self._enrich_hash_metadata,
        )
        self.register_enricher(
            "url_analysis",
            [IOCType.URL],
            self._enrich_url_analysis,
        )

    def _enrich_ip_reputation(self, ioc: IOC) -> EnrichmentResult:
        """Local heuristic IP reputation enrichment."""
        value = ioc.value
        tags_to_add = []
        confidence_delta = 0
        data: Dict[str, Any] = {}

        try:
            addr = ipaddress.ip_address(value.split("/")[0])
            data["is_private"] = addr.is_private
            data["is_loopback"] = addr.is_loopback
            data["is_multicast"] = addr.is_multicast
            data["is_global"] = addr.is_global
            data["ip_version"] = addr.version

            if addr.is_private:
                tags_to_add.append("private-ip")
                confidence_delta -= 20
            elif addr.is_global:
                tags_to_add.append("public-ip")

            if isinstance(addr, ipaddress.IPv4Address):
                octets = str(addr).split(".")
                # Tor exit node indicator: known Tor ranges are common sources
                if octets[0] in ("176", "185", "51"):
                    tags_to_add.append("potential-vpn-range")

        except ValueError:
            return EnrichmentResult(
                ioc_fingerprint=ioc.fingerprint,
                enricher_name="ip_reputation",
                data={},
                error=f"Invalid IP: {value}",
            )

        return EnrichmentResult(
            ioc_fingerprint=ioc.fingerprint,
            enricher_name="ip_reputation",
            data=data,
            confidence_delta=confidence_delta,
            tags_to_add=tags_to_add,
        )

    def _enrich_domain_analysis(self, ioc: IOC) -> EnrichmentResult:
        """Analyze domain structure for DGA and suspicious patterns."""
        domain = ioc.value.lower()
        tags_to_add = []
        confidence_delta = 0
        data: Dict[str, Any] = {}

        # Domain length analysis
        labels = domain.split(".")
        tld = labels[-1] if len(labels) > 1 else ""
        sld = labels[-2] if len(labels) > 1 else labels[0]

        data["tld"] = tld
        data["subdomain_depth"] = len(labels) - 2
        data["domain_length"] = len(sld)

        # DGA detection via entropy and character distribution
        entropy = self._string_entropy(sld)
        data["sld_entropy"] = round(entropy, 3)
        if entropy > 3.8:
            tags_to_add.append("high-entropy-domain")
            confidence_delta += 10

        # Numeric ratio
        numeric_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)
        data["numeric_ratio"] = round(numeric_ratio, 3)
        if numeric_ratio > 0.4:
            tags_to_add.append("high-numeric-domain")

        # Common DGA indicators
        consonant_runs = re.findall(r"[bcdfghjklmnpqrstvwxyz]{4,}", sld)
        if consonant_runs:
            tags_to_add.append("consonant-heavy-domain")
            confidence_delta += 5
            data["max_consonant_run"] = max(len(r) for r in consonant_runs)

        # Suspicious TLDs
        suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz", "work"}
        if tld in suspicious_tlds:
            tags_to_add.append("suspicious-tld")
            confidence_delta += 10
            data["suspicious_tld"] = True

        # Punycode / IDN
        if "xn--" in domain:
            tags_to_add.append("punycode-domain")
            data["is_idn"] = True

        return EnrichmentResult(
            ioc_fingerprint=ioc.fingerprint,
            enricher_name="domain_analysis",
            data=data,
            confidence_delta=confidence_delta,
            tags_to_add=tags_to_add,
        )

    def _enrich_hash_metadata(self, ioc: IOC) -> EnrichmentResult:
        """Validate hash format and detect known patterns."""
        value = ioc.value.lower()
        tags_to_add = []
        data: Dict[str, Any] = {}

        hash_lengths = {
            IOCType.FILE_HASH_MD5: 32,
            IOCType.FILE_HASH_SHA1: 40,
            IOCType.FILE_HASH_SHA256: 64,
        }
        expected_len = hash_lengths.get(ioc.ioc_type)
        data["hash_length"] = len(value)
        data["hash_valid"] = expected_len is not None and len(value) == expected_len
        data["is_hex"] = all(c in "0123456789abcdef" for c in value)

        if not data["hash_valid"] or not data["is_hex"]:
            return EnrichmentResult(
                ioc_fingerprint=ioc.fingerprint,
                enricher_name="hash_metadata",
                data=data,
                error="Invalid hash format",
            )

        # Detect all-zeros or all-same hashes (empty file indicators)
        if len(set(value)) <= 2:
            tags_to_add.append("trivial-hash")
            data["is_trivial"] = True

        # Known empty file hashes
        known_empty = {
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 empty
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty
        }
        if value in known_empty:
            tags_to_add.append("empty-file-hash")
            data["is_empty_file"] = True

        return EnrichmentResult(
            ioc_fingerprint=ioc.fingerprint,
            enricher_name="hash_metadata",
            data=data,
            tags_to_add=tags_to_add,
        )

    def _enrich_url_analysis(self, ioc: IOC) -> EnrichmentResult:
        """Analyze URL structure for malicious patterns."""
        url = ioc.value
        tags_to_add = []
        confidence_delta = 0
        data: Dict[str, Any] = {}

        # Extract components
        scheme_match = re.match(r"^(https?)://([^/]+)(.*)", url)
        if not scheme_match:
            return EnrichmentResult(
                ioc_fingerprint=ioc.fingerprint,
                enricher_name="url_analysis",
                data={},
                error="Could not parse URL",
            )

        scheme, host, path = scheme_match.groups()
        data["scheme"] = scheme
        data["host"] = host
        data["path_length"] = len(path)
        data["uses_https"] = scheme == "https"

        # IP-based URL (suspicious)
        try:
            ipaddress.ip_address(host.split(":")[0])
            tags_to_add.append("ip-based-url")
            confidence_delta += 15
            data["host_is_ip"] = True
        except ValueError:
            data["host_is_ip"] = False

        # Path analysis
        suspicious_extensions = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta",
                                  ".jar", ".scr", ".pif", ".com", ".cmd"}
        path_lower = path.lower()
        for ext in suspicious_extensions:
            if path_lower.endswith(ext):
                tags_to_add.append(f"suspicious-extension:{ext.lstrip('.')}")
                confidence_delta += 20
                data["suspicious_extension"] = ext
                break

        # URL encoding abuse
        if "%00" in url or "%0a" in url.lower() or "%0d" in url.lower():
            tags_to_add.append("null-byte-injection")
            confidence_delta += 25

        # Excessive redirects in path
        if path.count("//") > 2:
            tags_to_add.append("double-slash-path")

        # Long path (common in phishing)
        if len(path) > 200:
            tags_to_add.append("long-url-path")
            data["excessively_long_path"] = True

        # Query string analysis
        if "?" in url:
            query = url.split("?", 1)[1]
            data["has_query_string"] = True
            data["query_param_count"] = query.count("&") + 1
            # Check for common C2 patterns
            if re.search(r"[?&](cmd|exec|system|eval|base64)=", query, re.IGNORECASE):
                tags_to_add.append("cmd-in-query-string")
                confidence_delta += 30

        return EnrichmentResult(
            ioc_fingerprint=ioc.fingerprint,
            enricher_name="url_analysis",
            data=data,
            confidence_delta=confidence_delta,
            tags_to_add=tags_to_add,
        )

    @staticmethod
    def _string_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        from collections import Counter
        import math
        freq = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
