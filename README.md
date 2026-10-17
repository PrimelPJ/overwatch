# Overwatch

Threat Intelligence & Security Orchestration, Automation and Response (SOAR) platform.

## Overview

Overwatch is a Python-based threat intelligence platform that ingests, enriches, and correlates Indicators of Compromise (IOCs) from multiple feed formats, and automatically executes response playbooks based on configurable rules.

## Features

- **Multi-format Feed Ingestion**: STIX 2.1, abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker), OTX pulse, MISP events, plain text, and CSV
- **STIX 2.1 Parser**: Full indicator object parsing, observable extraction, TLP resolution, kill chain mapping
- **IOC Lifecycle Management**: Confidence scoring, TTL aging, false positive tracking, risk scoring
- **Enrichment Pipeline**: IP reputation, domain DGA detection, hash validation, URL analysis
- **Correlation Engine**: Subnet-based IP clustering, shared MITRE technique correlation, tag-based grouping
- **Automated Playbooks**: Configurable response playbooks with step dependencies, retry logic, and cooldown management
- **Alert Deduplication**: Exact, near-duplicate, and semantic deduplication with IOC correlation

## Architecture

```
Threat Feeds (STIX/TAXII, abuse.ch, OTX, MISP)
         │
         ▼
  FeedIngestionEngine
         │
         ▼
  EnrichmentPipeline ──→ CorrelationEngine
         │
         ▼
  AlertDeduplicator
         │
         ▼
  PlaybookExecutor ──→ Response Actions
```

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|-----------|-----|-------------|
| Command and Scripting Interpreter | T1059 | URL path analysis for script extensions |
| Application Layer Protocol | T1071 | C2 IP/domain tracking |
| Indicator Removal | T1070 | IOC aging and expiry detection |
| Phishing | T1566 | Email IOC enrichment |
| Resource Development | T1583 | Domain DGA and registration analysis |

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start

```python
from overwatch import (
    FeedIngestionEngine, FeedSource, FeedFormat,
    STIXParser, EnrichmentPipeline, PlaybookExecutor,
    PlaybookDefinition, AlertDeduplicator,
    Severity, TLPLevel,
)

# Ingest abuse.ch Feodo Tracker
engine = FeedIngestionEngine()
engine.register_source(FeedSource(
    name="feodo",
    format=FeedFormat.ABUSECH_FEODO,
    tags=["botnet", "c2"],
    default_severity=Severity.CRITICAL,
))

with open("feodo.json") as f:
    stats = engine.ingest("feodo", f.read())

print(f"Ingested {stats.new_iocs} new C2 indicators")

# Enrich indicators
pipeline = EnrichmentPipeline()
for ioc in engine.get_iocs(min_confidence=70):
    results = pipeline.enrich(ioc)
    clusters = pipeline.correlate(ioc)

# Parse STIX bundle
parser = STIXParser(source_name="taxii-feed")
with open("bundle.json") as f:
    iocs = parser.parse_bundle(f.read())
```

## Project Structure

```
overwatch/
├── src/overwatch/
│   ├── models.py          # IOC, AlertTriage, ThreatActor data models
│   ├── stix_parser.py     # STIX 2.1 bundle parser
│   ├── feed_ingestion.py  # Multi-format feed ingestion engine
│   ├── enrichment.py      # IOC enrichment and correlation
│   ├── playbook.py        # Automated response playbook executor
│   └── deduplication.py   # Alert deduplication and triage
└── tests/
    ├── test_models.py
    └── test_stix_parser.py
```

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT License - Copyright (c) 2026 Primel Jayawardana
