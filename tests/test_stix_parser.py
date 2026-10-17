"""
Tests for STIX 2.1 bundle parser.
"""

import json
import pytest

from overwatch.models import IOCType, Severity, TLPLevel
from overwatch.stix_parser import STIXParser, STIXParseError


STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test-001",
    "spec_version": "2.1",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--ip-001",
            "created": "2025-01-15T10:00:00Z",
            "modified": "2025-01-15T10:00:00Z",
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2025-01-15T10:00:00Z",
            "confidence": 85,
            "labels": ["malicious-activity"],
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "T1071.001"}
            ],
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--domain-001",
            "created": "2025-01-15T11:00:00Z",
            "modified": "2025-01-15T11:00:00Z",
            "name": "Malicious domain",
            "pattern": "[domain-name:value = 'evil.example.com']",
            "pattern_type": "stix",
            "valid_from": "2025-01-15T11:00:00Z",
            "confidence": 75,
            "labels": ["compromised"],
            "object_marking_refs": [
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
            ],
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--hash-001",
            "created": "2025-01-15T12:00:00Z",
            "modified": "2025-01-15T12:00:00Z",
            "name": "Malware hash",
            "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
            "pattern_type": "stix",
            "valid_from": "2025-01-15T12:00:00Z",
            "confidence": 95,
            "labels": ["malicious-activity"],
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--multi-001",
            "created": "2025-01-15T13:00:00Z",
            "modified": "2025-01-15T13:00:00Z",
            "name": "Multi-type indicator",
            "pattern": "[url:value = 'http://bad.example.com/payload.exe']",
            "pattern_type": "stix",
            "valid_from": "2025-01-15T13:00:00Z",
            "confidence": 70,
            "labels": ["high"],
        },
    ],
}


class TestSTIXParser:
    def setup_method(self):
        self.parser = STIXParser(source_name="test-feed")

    def test_parse_bundle_dict(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        assert len(iocs) == 4

    def test_parse_bundle_json_string(self):
        iocs = self.parser.parse_bundle(json.dumps(STIX_BUNDLE))
        assert len(iocs) == 4

    def test_parse_bundle_bytes(self):
        iocs = self.parser.parse_bundle(json.dumps(STIX_BUNDLE).encode())
        assert len(iocs) == 4

    def test_ipv4_extraction(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        assert len(ip_iocs) == 1
        assert ip_iocs[0].value == "198.51.100.1"

    def test_domain_extraction(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
        assert len(domain_iocs) == 1
        assert domain_iocs[0].value == "evil.example.com"

    def test_sha256_extraction(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        hash_iocs = [i for i in iocs if i.ioc_type == IOCType.FILE_HASH_SHA256]
        assert len(hash_iocs) == 1
        assert hash_iocs[0].value == "a" * 64

    def test_url_extraction(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL]
        assert len(url_iocs) == 1
        assert "bad.example.com" in url_iocs[0].value

    def test_confidence_propagated(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        ip_ioc = next(i for i in iocs if i.ioc_type == IOCType.IPV4)
        assert ip_ioc.confidence == 85

    def test_tlp_green_resolved(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        ip_ioc = next(i for i in iocs if i.ioc_type == IOCType.IPV4)
        assert ip_ioc.tlp == TLPLevel.GREEN

    def test_tlp_amber_resolved(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        domain_ioc = next(i for i in iocs if i.ioc_type == IOCType.DOMAIN)
        assert domain_ioc.tlp == TLPLevel.AMBER

    def test_severity_from_malicious_activity(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        ip_ioc = next(i for i in iocs if i.ioc_type == IOCType.IPV4)
        assert ip_ioc.severity == Severity.HIGH

    def test_severity_from_compromised(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        domain_ioc = next(i for i in iocs if i.ioc_type == IOCType.DOMAIN)
        assert domain_ioc.severity == Severity.CRITICAL

    def test_mitre_techniques_extracted(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        ip_ioc = next(i for i in iocs if i.ioc_type == IOCType.IPV4)
        assert "T1071.001" in ip_ioc.mitre_techniques

    def test_source_name_set(self):
        iocs = self.parser.parse_bundle(STIX_BUNDLE)
        assert all(i.source == "test-feed" for i in iocs)

    def test_invalid_json_raises(self):
        with pytest.raises(STIXParseError):
            self.parser.parse_bundle("{not valid json")

    def test_wrong_type_raises(self):
        with pytest.raises(STIXParseError):
            self.parser.parse_bundle({"type": "indicator"})

    def test_empty_bundle_returns_empty_list(self):
        bundle = {"type": "bundle", "id": "bundle--empty", "objects": []}
        iocs = self.parser.parse_bundle(bundle)
        assert iocs == []

    def test_streaming_parser(self):
        iocs = list(self.parser.parse_bundle_stream(STIX_BUNDLE))
        assert len(iocs) == 4

    def test_file_observable_with_hashes(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--file-test",
            "objects": [
                {
                    "type": "file",
                    "id": "file--001",
                    "hashes": {
                        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
                        "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                }
            ],
        }
        iocs = self.parser.parse_bundle(bundle)
        types = {i.ioc_type for i in iocs}
        assert IOCType.FILE_HASH_MD5 in types
        assert IOCType.FILE_HASH_SHA1 in types
        assert IOCType.FILE_HASH_SHA256 in types
