"""Tests for MITRE ATT&CK technique mapping."""

import pytest

from overwatch.mitre_mapper import (
    AttackTechnique,
    MITREMapper,
    ATTACK_TECHNIQUES,
    IOC_TYPE_TECHNIQUE_MAP,
)
from overwatch.models import IOC, IOCType, Severity


def make_ioc(
    ioc_type: IOCType = IOCType.IPV4,
    value: str = "192.0.2.1",
    tags: list = None,
    mitre: list = None,
) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        source="test",
        tags=set(tags or []),
        mitre_techniques=list(mitre or []),
    )


class TestMITREMapper:
    def test_map_ip_ioc_returns_techniques(self):
        mapper = MITREMapper()
        ioc = make_ioc(ioc_type=IOCType.IPV4)
        mapping = mapper.map_ioc(ioc)
        assert len(mapping.techniques) > 0
        tids = [t.technique_id for t in mapping.techniques]
        assert "T1071" in tids

    def test_explicit_technique_ids_take_priority(self):
        mapper = MITREMapper()
        ioc = make_ioc(mitre=["T1059.001"])
        mapping = mapper.map_ioc(ioc)
        assert mapping.mapping_method == "explicit"
        assert mapping.confidence >= 0.9
        tids = [t.technique_id for t in mapping.techniques]
        assert "T1059.001" in tids

    def test_tag_based_inference(self):
        mapper = MITREMapper()
        ioc = make_ioc(tags=["ransomware"])
        mapping = mapper.map_ioc(ioc)
        tids = [t.technique_id for t in mapping.techniques]
        assert "T1486" in tids
        assert mapping.mapping_method in ("tag", "ioc_type")

    def test_domain_ioc_maps_to_dns_c2(self):
        mapper = MITREMapper()
        ioc = make_ioc(ioc_type=IOCType.DOMAIN, value="evil.c2.com")
        mapping = mapper.map_ioc(ioc)
        tids = [t.technique_id for t in mapping.techniques]
        assert any(tid in tids for tid in ("T1071", "T1071.004"))

    def test_cve_maps_to_exploitation(self):
        mapper = MITREMapper()
        ioc = make_ioc(ioc_type=IOCType.CVE, value="CVE-2021-44228")
        mapping = mapper.map_ioc(ioc)
        tids = [t.technique_id for t in mapping.techniques]
        assert "T1190" in tids

    def test_enrich_ioc_adds_techniques(self):
        mapper = MITREMapper()
        ioc = make_ioc(ioc_type=IOCType.URL, value="http://evil.com/drop.exe")
        original_count = len(ioc.mitre_techniques)
        enriched = mapper.enrich_ioc_with_techniques(ioc)
        assert len(enriched.mitre_techniques) >= original_count

    def test_tactic_coverage(self):
        mapper = MITREMapper()
        iocs = [
            make_ioc(ioc_type=IOCType.IPV4),
            make_ioc(ioc_type=IOCType.DOMAIN),
            make_ioc(ioc_type=IOCType.EMAIL),
            make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="a" * 64),
        ]
        coverage = mapper.get_tactic_coverage(iocs)
        assert "command-and-control" in coverage
        assert all(v > 0 for v in coverage.values())

    def test_get_technique_by_id(self):
        mapper = MITREMapper()
        t = mapper.get_technique("T1059")
        assert t is not None
        assert t.name == "Command and Scripting Interpreter"
        assert t.tactic == "execution"

    def test_get_unknown_technique_returns_none(self):
        mapper = MITREMapper()
        t = mapper.get_technique("T9999")
        assert t is None

    def test_find_by_tactic(self):
        mapper = MITREMapper()
        techniques = mapper.find_techniques_by_tactic("execution")
        assert all(t.tactic == "execution" for t in techniques)
        assert len(techniques) > 0

    def test_find_by_platform(self):
        mapper = MITREMapper()
        techniques = mapper.find_techniques_by_platform("Windows")
        assert all("Windows" in t.platforms for t in techniques)

    def test_extract_technique_ids_from_text(self):
        mapper = MITREMapper()
        text = "Observed use of T1059.001 (PowerShell) and T1486 for ransomware staging."
        ids = mapper.extract_technique_ids_from_text(text)
        assert "T1059.001" in ids
        assert "T1486" in ids

    def test_custom_tag_mapping(self):
        mapper = MITREMapper()
        mapper.register_tag_mapping("custom_malware", ["T1055", "T1059"])
        ioc = make_ioc(tags=["custom_malware"])
        mapping = mapper.map_ioc(ioc)
        tids = [t.technique_id for t in mapping.techniques]
        assert "T1055" in tids


class TestNavigatorLayer:
    def test_build_navigator_layer_structure(self):
        mapper = MITREMapper()
        iocs = [make_ioc(ioc_type=t) for t in [IOCType.IPV4, IOCType.DOMAIN, IOCType.URL]]
        layer = mapper.build_navigator_layer(iocs, layer_name="Test Layer")
        assert layer["name"] == "Test Layer"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert isinstance(layer["techniques"], list)
        assert all("techniqueID" in t for t in layer["techniques"])

    def test_navigator_layer_scores_positive(self):
        mapper = MITREMapper()
        iocs = [make_ioc() for _ in range(5)]
        layer = mapper.build_navigator_layer(iocs)
        scores = [t["score"] for t in layer["techniques"]]
        assert all(s > 0 for s in scores)


class TestAttackTechnique:
    def test_subtechnique_has_parent(self):
        t = ATTACK_TECHNIQUES["T1059.001"]
        assert t.is_subtechnique is True
        assert t.parent_id == "T1059"

    def test_parent_technique_has_no_parent(self):
        t = ATTACK_TECHNIQUES["T1059"]
        assert t.is_subtechnique is False
        assert t.parent_id is None

    def test_keyword_matching(self):
        t = ATTACK_TECHNIQUES["T1486"]
        assert t.matches_keyword("ransomware") or t.matches_keyword("encrypt")
