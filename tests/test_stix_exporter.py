"""
Tests for the STIX 2.1 export pipeline.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import List

import pytest

from overwatch.models import IOC, IOCType, Severity, TLPLevel
from overwatch.stix_exporter import (
    BundleStats,
    ExportFilter,
    StixExporter,
    TLP_OBJECT_IDS,
    _build_indicator,
    _build_tlp_marking,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ioc(**kwargs) -> IOC:
    defaults = dict(
        ioc_type=IOCType.IPV4,
        value="1.2.3.4",
        source="test-feed",
        severity=Severity.HIGH,
        confidence=80,
        tlp=TLPLevel.GREEN,
    )
    defaults.update(kwargs)
    return IOC(**defaults)


def make_ioc_set() -> List[IOC]:
    return [
        make_ioc(ioc_type=IOCType.IPV4, value="10.0.0.1", severity=Severity.HIGH),
        make_ioc(ioc_type=IOCType.DOMAIN, value="evil.example.com", severity=Severity.CRITICAL, tlp=TLPLevel.AMBER),
        make_ioc(ioc_type=IOCType.URL, value="http://malware.example.com/payload", severity=Severity.MEDIUM),
        make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="a" * 64, severity=Severity.HIGH),
        make_ioc(ioc_type=IOCType.EMAIL, value="phisher@bad.com", severity=Severity.LOW),
    ]


# ---------------------------------------------------------------------------
# TLP marking definitions
# ---------------------------------------------------------------------------

class TestTlpMarkings:
    def test_green_marking_has_fixed_id(self):
        obj = _build_tlp_marking(TLPLevel.GREEN)
        assert obj["id"] == TLP_OBJECT_IDS[TLPLevel.GREEN]

    def test_red_marking_has_fixed_id(self):
        obj = _build_tlp_marking(TLPLevel.RED)
        assert obj["id"] == TLP_OBJECT_IDS[TLPLevel.RED]

    def test_marking_type_is_correct(self):
        obj = _build_tlp_marking(TLPLevel.WHITE)
        assert obj["type"] == "marking-definition"
        assert obj["definition_type"] == "tlp"

    def test_marking_contains_tlp_value(self):
        obj = _build_tlp_marking(TLPLevel.AMBER)
        assert obj["definition"]["tlp"] == "amber"

    def test_all_tlp_levels_produce_unique_ids(self):
        ids = {_build_tlp_marking(lvl)["id"] for lvl in TLPLevel}
        assert len(ids) == len(list(TLPLevel))


# ---------------------------------------------------------------------------
# STIX indicator construction
# ---------------------------------------------------------------------------

class TestBuildIndicator:
    def setup_method(self):
        self.creator_id = "identity--test-0000-0000-0000-000000000000"

    def test_ipv4_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.IPV4, value="192.168.1.1")
        obj = _build_indicator(ioc, self.creator_id)
        assert obj is not None
        assert "[ipv4-addr:value = '192.168.1.1']" == obj["pattern"]

    def test_domain_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.DOMAIN, value="example.com")
        obj = _build_indicator(ioc, self.creator_id)
        assert "[domain-name:value = 'example.com']" == obj["pattern"]

    def test_url_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.URL, value="http://x.com/path")
        obj = _build_indicator(ioc, self.creator_id)
        assert "url:value" in obj["pattern"]

    def test_md5_hash_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.FILE_HASH_MD5, value="d41d8cd98f00b204e9800998ecf8427e")
        obj = _build_indicator(ioc, self.creator_id)
        assert "file:hashes.MD5" in obj["pattern"]

    def test_sha256_hash_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.FILE_HASH_SHA256, value="a" * 64)
        obj = _build_indicator(ioc, self.creator_id)
        assert "SHA-256" in obj["pattern"]

    def test_sha1_hash_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.FILE_HASH_SHA1, value="b" * 40)
        obj = _build_indicator(ioc, self.creator_id)
        assert "SHA-1" in obj["pattern"]

    def test_email_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.EMAIL, value="attacker@evil.org")
        obj = _build_indicator(ioc, self.creator_id)
        assert "email-addr:value" in obj["pattern"]

    def test_mutex_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.MUTEX, value="Global\\MalwareMutex")
        obj = _build_indicator(ioc, self.creator_id)
        assert "mutex:name" in obj["pattern"]

    def test_registry_key_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.REGISTRY_KEY, value=r"HKLM\Software\Malware")
        obj = _build_indicator(ioc, self.creator_id)
        assert "windows-registry-key:key" in obj["pattern"]

    def test_indicator_has_required_stix_fields(self):
        ioc = make_ioc()
        obj = _build_indicator(ioc, self.creator_id)
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert "created" in obj
        assert "modified" in obj
        assert "valid_from" in obj
        assert obj["pattern_type"] == "stix"

    def test_indicator_id_contains_ioc_id(self):
        ioc = make_ioc()
        obj = _build_indicator(ioc, self.creator_id)
        assert ioc.id in obj["id"]

    def test_indicator_confidence_set(self):
        ioc = make_ioc(confidence=72)
        obj = _build_indicator(ioc, self.creator_id)
        assert obj["confidence"] == 72

    def test_indicator_tlp_marking_ref(self):
        ioc = make_ioc(tlp=TLPLevel.AMBER)
        obj = _build_indicator(ioc, self.creator_id)
        assert TLP_OBJECT_IDS[TLPLevel.AMBER] in obj["object_marking_refs"]

    def test_indicator_tags_in_labels(self):
        ioc = make_ioc(tags={"apt29", "ransomware"})
        obj = _build_indicator(ioc, self.creator_id)
        assert "apt29" in obj["labels"]
        assert "ransomware" in obj["labels"]

    def test_mitre_techniques_in_labels_and_refs(self):
        ioc = make_ioc(mitre_techniques=["T1566", "T1059.001"])
        obj = _build_indicator(ioc, self.creator_id)
        assert any("T1566" in lbl for lbl in obj.get("labels", []))
        refs = [r["external_id"] for r in obj.get("external_references", [])]
        assert "T1566" in refs

    def test_special_chars_in_value_escaped(self):
        ioc = make_ioc(ioc_type=IOCType.DOMAIN, value="it's-a.test.com")
        obj = _build_indicator(ioc, self.creator_id)
        assert "\\'" in obj["pattern"]

    def test_critical_severity_indicator_type(self):
        ioc = make_ioc(severity=Severity.CRITICAL)
        obj = _build_indicator(ioc, self.creator_id)
        assert "malicious-activity" in obj["indicator_types"]

    def test_info_severity_indicator_type(self):
        ioc = make_ioc(severity=Severity.INFO)
        obj = _build_indicator(ioc, self.creator_id)
        assert "benign" in obj["indicator_types"]

    def test_valid_until_set_when_last_seen(self):
        now = datetime.now(timezone.utc)
        ioc = make_ioc(last_seen=now)
        obj = _build_indicator(ioc, self.creator_id)
        assert "valid_until" in obj

    def test_no_valid_until_when_no_last_seen(self):
        ioc = make_ioc()
        ioc.last_seen = None
        obj = _build_indicator(ioc, self.creator_id)
        assert "valid_until" not in obj


# ---------------------------------------------------------------------------
# Export filter
# ---------------------------------------------------------------------------

class TestExportFilter:
    def test_allows_ioc_within_tlp(self):
        ef = ExportFilter(max_tlp=TLPLevel.GREEN)
        ioc = make_ioc(tlp=TLPLevel.WHITE)
        assert ef.allows(ioc)

    def test_blocks_ioc_above_tlp(self):
        ef = ExportFilter(max_tlp=TLPLevel.GREEN)
        ioc = make_ioc(tlp=TLPLevel.AMBER)
        assert not ef.allows(ioc)

    def test_blocks_red_when_max_amber(self):
        ef = ExportFilter(max_tlp=TLPLevel.AMBER)
        ioc = make_ioc(tlp=TLPLevel.RED)
        assert not ef.allows(ioc)

    def test_allows_amber_when_max_amber(self):
        ef = ExportFilter(max_tlp=TLPLevel.AMBER)
        ioc = make_ioc(tlp=TLPLevel.AMBER)
        assert ef.allows(ioc)

    def test_min_confidence_filter(self):
        ef = ExportFilter(min_confidence=70)
        assert not ef.allows(make_ioc(confidence=60))
        assert ef.allows(make_ioc(confidence=70))
        assert ef.allows(make_ioc(confidence=80))

    def test_min_severity_filter(self):
        ef = ExportFilter(min_severity=Severity.HIGH)
        assert ef.allows(make_ioc(severity=Severity.HIGH))
        assert ef.allows(make_ioc(severity=Severity.CRITICAL))
        assert not ef.allows(make_ioc(severity=Severity.MEDIUM))
        assert not ef.allows(make_ioc(severity=Severity.LOW))

    def test_ioc_type_filter(self):
        ef = ExportFilter(ioc_types={IOCType.IPV4, IOCType.DOMAIN})
        assert ef.allows(make_ioc(ioc_type=IOCType.IPV4))
        assert ef.allows(make_ioc(ioc_type=IOCType.DOMAIN))
        assert not ef.allows(make_ioc(ioc_type=IOCType.URL))

    def test_tag_filter_or_semantics(self):
        ef = ExportFilter(tags={"ransomware", "apt"})
        assert ef.allows(make_ioc(tags={"ransomware"}))
        assert ef.allows(make_ioc(tags={"apt", "other"}))
        assert not ef.allows(make_ioc(tags={"unrelated"}))

    def test_source_filter(self):
        ef = ExportFilter(sources=["feed-a", "feed-b"])
        assert ef.allows(make_ioc(source="feed-a"))
        assert not ef.allows(make_ioc(source="unknown-feed"))

    def test_expired_ioc_excluded_by_default(self):
        ef = ExportFilter(exclude_expired=True)
        ioc = make_ioc(ttl_seconds=0)
        import time; time.sleep(0.01)
        assert not ef.allows(ioc)

    def test_expired_ioc_included_when_flag_off(self):
        ef = ExportFilter(exclude_expired=False)
        ioc = make_ioc(ttl_seconds=0)
        import time; time.sleep(0.01)
        assert ef.allows(ioc)


# ---------------------------------------------------------------------------
# StixExporter
# ---------------------------------------------------------------------------

class TestStixExporter:
    def setup_method(self):
        self.exporter = StixExporter(identity_name="Test Platform")

    def test_bundle_has_required_keys(self):
        bundle, _ = self.exporter.build_bundle([])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle

    def test_bundle_includes_identity(self):
        bundle, _ = self.exporter.build_bundle([])
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types

    def test_identity_name_set(self):
        bundle, _ = self.exporter.build_bundle([])
        identity = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert identity["name"] == "Test Platform"

    def test_single_ioc_exported(self):
        ioc = make_ioc()
        bundle, stats = self.exporter.build_bundle([ioc])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert stats.exported == 1

    def test_tlp_marking_included_for_referenced_tlp(self):
        ioc = make_ioc(tlp=TLPLevel.AMBER)
        bundle, _ = self.exporter.build_bundle([ioc])
        markings = [o for o in bundle["objects"] if o["type"] == "marking-definition"]
        marking_ids = [m["id"] for m in markings]
        assert TLP_OBJECT_IDS[TLPLevel.AMBER] in marking_ids

    def test_no_marking_for_unreferenced_tlp(self):
        ioc = make_ioc(tlp=TLPLevel.GREEN)
        bundle, _ = self.exporter.build_bundle([ioc])
        markings = [o for o in bundle["objects"] if o["type"] == "marking-definition"]
        marking_ids = [m["id"] for m in markings]
        assert TLP_OBJECT_IDS[TLPLevel.RED] not in marking_ids

    def test_multiple_tlp_levels(self):
        iocs = [
            make_ioc(tlp=TLPLevel.WHITE),
            make_ioc(tlp=TLPLevel.GREEN),
            make_ioc(tlp=TLPLevel.AMBER),
        ]
        bundle, _ = self.exporter.build_bundle(iocs)
        markings = [o for o in bundle["objects"] if o["type"] == "marking-definition"]
        assert len(markings) == 3

    def test_filter_applied_in_build_bundle(self):
        iocs = make_ioc_set()
        ef = ExportFilter(max_tlp=TLPLevel.GREEN)  # explicitly block AMBER and above
        bundle, stats = self.exporter.build_bundle(iocs, ef)
        amber_indicators = [
            o for o in bundle["objects"]
            if o["type"] == "indicator" and TLP_OBJECT_IDS[TLPLevel.AMBER] in o.get("object_marking_refs", [])
        ]
        assert len(amber_indicators) == 0
        assert stats.skipped_tlp >= 1

    def test_default_filter_allows_all_tlp_levels(self):
        iocs = [
            make_ioc(tlp=TLPLevel.WHITE),
            make_ioc(ioc_type=IOCType.DOMAIN, value="a.com", tlp=TLPLevel.GREEN),
            make_ioc(ioc_type=IOCType.URL, value="http://b.com", tlp=TLPLevel.AMBER),
            make_ioc(ioc_type=IOCType.EMAIL, value="c@d.com", tlp=TLPLevel.RED),
        ]
        _, stats = self.exporter.build_bundle(iocs)
        assert stats.exported == 4
        assert stats.skipped_tlp == 0

    def test_stats_by_type_populated(self):
        iocs = make_ioc_set()
        _, stats = self.exporter.build_bundle(iocs)
        assert "ipv4-addr" in stats.by_type
        assert "domain-name" in stats.by_type

    def test_stats_by_severity_populated(self):
        iocs = make_ioc_set()
        _, stats = self.exporter.build_bundle(iocs)
        assert len(stats.by_severity) > 0

    def test_stats_total_count(self):
        iocs = make_ioc_set()
        _, stats = self.exporter.build_bundle(iocs)
        assert stats.total_iocs == len(iocs)

    def test_export_json_is_valid_json(self):
        iocs = make_ioc_set()
        json_str, _ = self.exporter.export_json(iocs)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_export_json_indented(self):
        iocs = [make_ioc()]
        json_str, _ = self.exporter.export_json(iocs, indent=4)
        assert "\n    " in json_str

    def test_export_ndjson_produces_one_object_per_line(self):
        iocs = [make_ioc()]
        ndjson, _ = self.exporter.export_ndjson(iocs)
        lines = [l for l in ndjson.splitlines() if l.strip()]
        for line in lines:
            json.loads(line)  # must be valid JSON
        assert len(lines) >= 2  # at least identity + indicator

    def test_export_to_file(self):
        iocs = make_ioc_set()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
            path = fh.name
        try:
            stats = self.exporter.export_to_file(iocs, path)
            assert os.path.exists(path)
            with open(path) as fh:
                bundle = json.load(fh)
            assert bundle["type"] == "bundle"
            assert stats.exported > 0
        finally:
            os.unlink(path)

    def test_iter_indicator_objects(self):
        iocs = make_ioc_set()
        indicators = list(self.exporter.iter_indicator_objects(iocs))
        assert all(obj["type"] == "indicator" for obj in indicators)
        assert len(indicators) == len(iocs)

    def test_iter_indicator_objects_with_filter(self):
        iocs = make_ioc_set()
        ef = ExportFilter(ioc_types={IOCType.IPV4})
        indicators = list(self.exporter.iter_indicator_objects(iocs, ef))
        assert all("ipv4-addr" in obj["pattern"] for obj in indicators)

    def test_relationships_for_related_iocs(self):
        ioc_a = make_ioc(ioc_type=IOCType.IPV4, value="1.1.1.1")
        ioc_b = make_ioc(ioc_type=IOCType.DOMAIN, value="related.com")
        ioc_a.related_iocs = [ioc_b.id]
        bundle, _ = self.exporter.build_bundle([ioc_a, ioc_b], include_relationships=True)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) >= 1
        assert rels[0]["relationship_type"] == "related-to"

    def test_no_relationships_when_disabled(self):
        ioc_a = make_ioc(ioc_type=IOCType.IPV4, value="1.1.1.1")
        ioc_b = make_ioc(ioc_type=IOCType.DOMAIN, value="related.com")
        ioc_a.related_iocs = [ioc_b.id]
        bundle, _ = self.exporter.build_bundle([ioc_a, ioc_b], include_relationships=False)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 0

    def test_custom_identity_id_preserved(self):
        custom_id = "identity--aaaaaaaa-0000-0000-0000-000000000000"
        exporter = StixExporter(identity_id=custom_id)
        assert exporter.identity_id == custom_id

    def test_empty_ioc_list_produces_valid_bundle(self):
        bundle, stats = self.exporter.build_bundle([])
        assert bundle["type"] == "bundle"
        assert stats.exported == 0
        assert stats.total_iocs == 0

    def test_bundle_object_ids_are_unique(self):
        iocs = make_ioc_set()
        bundle, _ = self.exporter.build_bundle(iocs)
        ids = [o["id"] for o in bundle["objects"]]
        non_tlp_ids = [
            oid for oid in ids if not oid.startswith("marking-definition--")
        ]
        assert len(non_tlp_ids) == len(set(non_tlp_ids))

    def test_indicator_created_by_ref_matches_identity(self):
        ioc = make_ioc()
        bundle, _ = self.exporter.build_bundle([ioc])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert indicators[0]["created_by_ref"] == self.exporter.identity_id

    def test_ipv6_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.IPV6, value="::1")
        bundle, _ = self.exporter.build_bundle([ioc])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert "ipv6-addr:value" in indicators[0]["pattern"]

    def test_cve_pattern(self):
        ioc = make_ioc(ioc_type=IOCType.CVE, value="CVE-2024-1234")
        bundle, _ = self.exporter.build_bundle([ioc])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert "vulnerability:name" in indicators[0]["pattern"]
