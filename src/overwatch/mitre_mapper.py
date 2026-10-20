"""
MITRE ATT&CK technique mapping and enrichment for threat indicators.
Maps IOC context to ATT&CK tactics, techniques, and sub-techniques.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from overwatch.models import IOC, IOCType, Severity


TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str       # e.g. T1059.001
    name: str
    tactic: str             # e.g. execution
    description: str = ""
    platforms: FrozenSet[str] = field(default_factory=frozenset)
    data_sources: FrozenSet[str] = field(default_factory=frozenset)
    detection: str = ""

    @property
    def parent_id(self) -> Optional[str]:
        """For sub-techniques, return the parent technique ID."""
        if "." in self.technique_id:
            return self.technique_id.split(".")[0]
        return None

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique_id

    def matches_keyword(self, keyword: str) -> bool:
        kw = keyword.lower()
        return (
            kw in self.name.lower()
            or kw in self.description.lower()
            or kw in self.tactic.lower()
        )


# Curated subset of ATT&CK techniques mapped to common IOC contexts
ATTACK_TECHNIQUES: Dict[str, AttackTechnique] = {
    "T1059": AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="execution",
        description="Use of command and scripting interpreters to execute arbitrary commands",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Process", "Command"}),
        detection="Monitor for abnormal use of scripting engines",
    ),
    "T1059.001": AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="execution",
        platforms=frozenset({"Windows"}),
        data_sources=frozenset({"Process", "Module", "Script"}),
    ),
    "T1059.003": AttackTechnique(
        technique_id="T1059.003",
        name="Windows Command Shell",
        tactic="execution",
        platforms=frozenset({"Windows"}),
        data_sources=frozenset({"Process"}),
    ),
    "T1071": AttackTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="command-and-control",
        description="C2 communication using standard application layer protocols",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Network Traffic"}),
    ),
    "T1071.001": AttackTechnique(
        technique_id="T1071.001",
        name="Web Protocols",
        tactic="command-and-control",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Network Traffic"}),
    ),
    "T1071.004": AttackTechnique(
        technique_id="T1071.004",
        name="DNS",
        tactic="command-and-control",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Network Traffic"}),
    ),
    "T1078": AttackTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="defense-evasion",
        platforms=frozenset({"Windows", "Linux", "macOS", "SaaS", "Cloud"}),
        data_sources=frozenset({"Authentication", "Logon Session"}),
    ),
    "T1082": AttackTechnique(
        technique_id="T1082",
        name="System Information Discovery",
        tactic="discovery",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Process", "Command"}),
    ),
    "T1105": AttackTechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="command-and-control",
        description="Transfer tools from external system into compromised environment",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Network Traffic", "File"}),
    ),
    "T1110": AttackTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="credential-access",
        platforms=frozenset({"Windows", "Linux", "macOS", "Cloud"}),
        data_sources=frozenset({"Authentication", "User Account"}),
    ),
    "T1486": AttackTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="impact",
        description="Encrypt data to interrupt availability (ransomware)",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"File", "Process"}),
    ),
    "T1566": AttackTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="initial-access",
        platforms=frozenset({"Windows", "Linux", "macOS", "SaaS"}),
        data_sources=frozenset({"Email", "Network Traffic"}),
    ),
    "T1566.001": AttackTechnique(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="initial-access",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Email", "File"}),
    ),
    "T1583": AttackTechnique(
        technique_id="T1583",
        name="Acquire Infrastructure",
        tactic="resource-development",
        platforms=frozenset({"PRE"}),
        data_sources=frozenset({"Domain Name", "Internet Scan"}),
    ),
    "T1190": AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="initial-access",
        platforms=frozenset({"Windows", "Linux", "macOS", "Network"}),
        data_sources=frozenset({"Application Log", "Network Traffic"}),
    ),
    "T1027": AttackTechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="defense-evasion",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"File", "Process"}),
    ),
    "T1055": AttackTechnique(
        technique_id="T1055",
        name="Process Injection",
        tactic="defense-evasion",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Process"}),
    ),
    "T1562": AttackTechnique(
        technique_id="T1562",
        name="Impair Defenses",
        tactic="defense-evasion",
        platforms=frozenset({"Windows", "Linux", "macOS", "Cloud"}),
        data_sources=frozenset({"Process", "Windows Registry", "Firewall"}),
    ),
    "T1041": AttackTechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="exfiltration",
        platforms=frozenset({"Windows", "Linux", "macOS"}),
        data_sources=frozenset({"Network Traffic", "Command"}),
    ),
    "T1133": AttackTechnique(
        technique_id="T1133",
        name="External Remote Services",
        tactic="initial-access",
        platforms=frozenset({"Windows", "Linux"}),
        data_sources=frozenset({"Network Traffic", "Logon Session"}),
    ),
}

# IOC-type-to-technique heuristic mappings
IOC_TYPE_TECHNIQUE_MAP: Dict[IOCType, List[str]] = {
    IOCType.IPV4: ["T1071", "T1071.001", "T1041", "T1583"],
    IOCType.IPV6: ["T1071", "T1041"],
    IOCType.DOMAIN: ["T1071", "T1071.004", "T1583", "T1566"],
    IOCType.URL: ["T1105", "T1071.001", "T1566.001"],
    IOCType.FILE_HASH_MD5: ["T1027", "T1059", "T1486"],
    IOCType.FILE_HASH_SHA1: ["T1027", "T1059"],
    IOCType.FILE_HASH_SHA256: ["T1027", "T1059", "T1055"],
    IOCType.EMAIL: ["T1566", "T1566.001", "T1078"],
    IOCType.CVE: ["T1190", "T1133"],
    IOCType.REGISTRY_KEY: ["T1562", "T1059.001"],
    IOCType.MUTEX: ["T1059", "T1055"],
    IOCType.NETWORK_TRAFFIC: ["T1071", "T1041"],
    IOCType.USER_AGENT: ["T1071.001"],
}

# Tag/keyword to technique mappings
TAG_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "ransomware": ["T1486", "T1059", "T1027"],
    "phishing": ["T1566", "T1566.001"],
    "backdoor": ["T1059.003", "T1071"],
    "c2": ["T1071", "T1041"],
    "downloader": ["T1105"],
    "dropper": ["T1059", "T1027"],
    "keylogger": ["T1056"],
    "bruteforce": ["T1110"],
    "exploit": ["T1190"],
    "powershell": ["T1059.001"],
    "lateral-movement": ["T1078", "T1133"],
    "exfil": ["T1041"],
    "apt": ["T1583", "T1027"],
    "miner": ["T1496"],
    "botnet": ["T1071", "T1083"],
    "infostealer": ["T1041", "T1082"],
}


@dataclass
class TechniqueMapping:
    ioc_fingerprint: str
    ioc_type: IOCType
    ioc_value: str
    techniques: List[AttackTechnique]
    confidence: float  # 0.0-1.0
    mapping_method: str  # "explicit", "ioc_type", "tag", "keyword"
    notes: str = ""


class MITREMapper:
    """
    Maps IOCs and alerts to MITRE ATT&CK techniques using:
    - Explicit technique IDs on the IOC
    - IOC type heuristics
    - Tag-based inference
    - Keyword matching on IOC value and metadata
    """

    def __init__(self) -> None:
        self._techniques = dict(ATTACK_TECHNIQUES)
        self._custom_tag_map: Dict[str, List[str]] = {}
        self._custom_ioc_map: Dict[IOCType, List[str]] = {}

    def add_technique(self, technique: AttackTechnique) -> None:
        self._techniques[technique.technique_id.upper()] = technique

    def register_tag_mapping(self, tag: str, technique_ids: List[str]) -> None:
        self._custom_tag_map[tag.lower()] = technique_ids

    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        return self._techniques.get(technique_id.upper())

    def map_ioc(self, ioc: IOC) -> TechniqueMapping:
        """Infer ATT&CK techniques for a given IOC."""
        technique_ids: Set[str] = set()
        method = "ioc_type"
        confidence = 0.5

        # Highest priority: explicit technique IDs stored on the IOC
        if ioc.mitre_techniques:
            valid_ids = []
            for tid in ioc.mitre_techniques:
                normalized = tid.upper()
                if normalized in self._techniques or TECHNIQUE_PATTERN.match(normalized):
                    valid_ids.append(normalized)
            if valid_ids:
                technique_ids.update(valid_ids)
                method = "explicit"
                confidence = 0.95

        # IOC type heuristic
        type_ids = (
            self._custom_ioc_map.get(ioc.ioc_type)
            or IOC_TYPE_TECHNIQUE_MAP.get(ioc.ioc_type, [])
        )
        technique_ids.update(type_ids)

        # Tag-based inference
        for tag in ioc.tags:
            tag_lower = tag.lower()
            custom = self._custom_tag_map.get(tag_lower, [])
            builtin = TAG_TECHNIQUE_MAP.get(tag_lower, [])
            matched = custom or builtin
            if matched:
                technique_ids.update(matched)
                if method == "ioc_type":
                    method = "tag"
                    confidence = 0.7

        # Keyword scan on value and metadata
        value_lower = ioc.value.lower()
        for kw, t_ids in TAG_TECHNIQUE_MAP.items():
            if kw in value_lower:
                technique_ids.update(t_ids)
                if method == "ioc_type":
                    method = "keyword"
                    confidence = 0.4

        techniques = [
            self._techniques[tid]
            for tid in technique_ids
            if tid in self._techniques
        ]

        return TechniqueMapping(
            ioc_fingerprint=ioc.fingerprint,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.value,
            techniques=techniques,
            confidence=confidence,
            mapping_method=method,
        )

    def map_collection(self, iocs: List[IOC]) -> List[TechniqueMapping]:
        return [self.map_ioc(ioc) for ioc in iocs]

    def get_tactic_coverage(self, iocs: List[IOC]) -> Dict[str, int]:
        """Return count of IOCs mapped to each ATT&CK tactic."""
        tactic_counts: Dict[str, int] = {}
        for mapping in self.map_collection(iocs):
            for technique in mapping.techniques:
                tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
        return dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True))

    def find_techniques_by_tactic(self, tactic: str) -> List[AttackTechnique]:
        return [t for t in self._techniques.values() if t.tactic == tactic.lower()]

    def find_techniques_by_platform(self, platform: str) -> List[AttackTechnique]:
        plat = platform.lower()
        return [
            t for t in self._techniques.values()
            if any(p.lower() == plat for p in t.platforms)
        ]

    def enrich_ioc_with_techniques(self, ioc: IOC) -> IOC:
        """Add inferred technique IDs to an IOC in place."""
        mapping = self.map_ioc(ioc)
        new_ids = [t.technique_id for t in mapping.techniques]
        existing = set(ioc.mitre_techniques)
        for tid in new_ids:
            if tid not in existing:
                ioc.mitre_techniques.append(tid)
        return ioc

    def extract_technique_ids_from_text(self, text: str) -> List[str]:
        """Pull T-number references out of arbitrary text."""
        found = TECHNIQUE_PATTERN.findall(text)
        return [f.upper() for f in found]

    def build_navigator_layer(
        self,
        iocs: List[IOC],
        layer_name: str = "Threat Intelligence",
    ) -> Dict[str, Any]:
        """
        Generate a MITRE ATT&CK Navigator layer JSON from IOC mappings.
        Can be imported directly into https://mitre-attack.github.io/attack-navigator/
        """
        technique_scores: Dict[str, int] = {}
        for mapping in self.map_collection(iocs):
            for technique in mapping.techniques:
                technique_scores[technique.technique_id] = (
                    technique_scores.get(technique.technique_id, 0) + 1
                )

        max_score = max(technique_scores.values(), default=1)
        techniques_list = []
        for tid, score in technique_scores.items():
            techniques_list.append({
                "techniqueID": tid,
                "score": score,
                "color": "",
                "comment": f"Observed in {score} IOC(s)",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False,
            })

        return {
            "name": layer_name,
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Generated from {len(iocs)} threat intelligence indicators",
            "filters": {"platforms": ["Windows", "Linux", "macOS"]},
            "sorting": 3,
            "layout": {"layout": "side", "aggregateFunction": "average"},
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ff6666ff", "#ff0000ff"],
                "minValue": 0,
                "maxValue": max_score,
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
        }
