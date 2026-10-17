"""
Overwatch - Threat Intelligence & SOAR Platform
"""

from overwatch.models import (
    IOC,
    IOCType,
    Severity,
    TLPLevel,
    AlertTriage,
    PlaybookAction,
)
from overwatch.stix_parser import STIXParser
from overwatch.feed_ingestion import FeedIngestionEngine
from overwatch.enrichment import EnrichmentPipeline
from overwatch.playbook import PlaybookExecutor
from overwatch.deduplication import AlertDeduplicator

__all__ = [
    "IOC",
    "IOCType",
    "Severity",
    "TLPLevel",
    "AlertTriage",
    "PlaybookAction",
    "STIXParser",
    "FeedIngestionEngine",
    "EnrichmentPipeline",
    "PlaybookExecutor",
    "AlertDeduplicator",
]

__version__ = "0.1.0"
