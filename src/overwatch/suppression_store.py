"""
Persistence layer for suppression rules.

Provides save/load for the full SuppressionEngine state so rules survive
process restarts.  Storage is JSON-based and keyed on the rule id.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from overwatch.suppression_engine import (
    MatchType,
    SuppressionAction,
    SuppressionCondition,
    SuppressionEngine,
    SuppressionRule,
    SuppressionScope,
    ThresholdConfig,
)

logger = logging.getLogger(__name__)


class SuppressionStore:
    """
    File-backed store for suppression rules.

    Rules are serialized to a single JSON file.  On load the engine is
    re-populated from disk.  Concurrent writers are not supported — use
    one store per process.
    """

    def __init__(self, path: str = "suppression_rules.json") -> None:
        self._path = Path(path)

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _condition_to_dict(c: SuppressionCondition) -> Dict[str, Any]:
        return {
            "scope": c.scope.value,
            "match_type": c.match_type.value,
            "value": c.value,
            "raw_field_key": c.raw_field_key,
        }

    @staticmethod
    def _condition_from_dict(d: Dict[str, Any]) -> SuppressionCondition:
        return SuppressionCondition(
            scope=SuppressionScope(d["scope"]),
            match_type=MatchType(d["match_type"]),
            value=d["value"],
            raw_field_key=d.get("raw_field_key"),
        )

    @staticmethod
    def _threshold_to_dict(t: Optional[ThresholdConfig]) -> Optional[Dict[str, Any]]:
        if t is None:
            return None
        return {
            "count": t.count,
            "window_seconds": t.window_seconds,
            "group_by": t.group_by,
        }

    @staticmethod
    def _threshold_from_dict(d: Optional[Dict[str, Any]]) -> Optional[ThresholdConfig]:
        if d is None:
            return None
        return ThresholdConfig(
            count=d["count"],
            window_seconds=d["window_seconds"],
            group_by=d.get("group_by"),
        )

    @classmethod
    def _rule_to_dict(cls, rule: SuppressionRule) -> Dict[str, Any]:
        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "enabled": rule.enabled,
            "require_all": rule.require_all,
            "action": rule.action.value,
            "conditions": [cls._condition_to_dict(c) for c in rule.conditions],
            "threshold": cls._threshold_to_dict(rule.threshold),
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            "created_at": rule.created_at.isoformat(),
            "match_count": rule.match_count,
            "suppressed_count": rule.suppressed_count,
        }

    @classmethod
    def _rule_from_dict(cls, d: Dict[str, Any]) -> SuppressionRule:
        expires_at = None
        if d.get("expires_at"):
            expires_at = datetime.fromisoformat(d["expires_at"])
        created_at = datetime.now(timezone.utc)
        if d.get("created_at"):
            created_at = datetime.fromisoformat(d["created_at"])
        rule = SuppressionRule(
            name=d["name"],
            conditions=[cls._condition_from_dict(c) for c in d.get("conditions", [])],
            action=SuppressionAction(d.get("action", "drop")),
            require_all=d.get("require_all", True),
            threshold=cls._threshold_from_dict(d.get("threshold")),
            expires_at=expires_at,
            enabled=d.get("enabled", True),
            description=d.get("description", ""),
            created_at=created_at,
            match_count=d.get("match_count", 0),
            suppressed_count=d.get("suppressed_count", 0),
        )
        rule.id = d["id"]
        return rule

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, engine: SuppressionEngine) -> None:
        """Persist all rules from *engine* to disk."""
        data: List[Dict[str, Any]] = [
            self._rule_to_dict(rule) for rule in engine.list_rules()
        ]
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self._path)
        logger.info("Saved %d suppression rules to %s", len(data), self._path)

    def load(self, engine: SuppressionEngine) -> int:
        """
        Load rules from disk into *engine*.  Rules already present (by id)
        are skipped to allow incremental load.  Returns count of rules loaded.
        """
        if not self._path.exists():
            logger.debug("No suppression rules file at %s", self._path)
            return 0

        raw = self._path.read_text(encoding="utf-8")
        data: List[Dict[str, Any]] = json.loads(raw)
        existing_ids = {r.id for r in engine.list_rules()}
        loaded = 0
        for entry in data:
            if entry["id"] in existing_ids:
                continue
            try:
                rule = self._rule_from_dict(entry)
                engine.add_rule(rule)
                loaded += 1
            except Exception as exc:
                logger.warning("Failed to load rule %s: %s", entry.get("id"), exc)
        logger.info("Loaded %d suppression rules from %s", loaded, self._path)
        return loaded

    def save_rule(self, rule: SuppressionRule) -> None:
        """Upsert a single rule into the on-disk store."""
        data: List[Dict[str, Any]] = []
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
        # Replace or append
        found = False
        for i, entry in enumerate(data):
            if entry["id"] == rule.id:
                data[i] = self._rule_to_dict(rule)
                found = True
                break
        if not found:
            data.append(self._rule_to_dict(rule))
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by id from the on-disk store.  Returns True if found."""
        if not self._path.exists():
            return False
        data: List[Dict[str, Any]] = json.loads(self._path.read_text(encoding="utf-8"))
        before = len(data)
        data = [e for e in data if e["id"] != rule_id]
        if len(data) == before:
            return False
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self._path)
        return True

    def list_rule_dicts(self) -> List[Dict[str, Any]]:
        """Return raw rule dicts from disk without instantiating a full engine."""
        if not self._path.exists():
            return []
        return json.loads(self._path.read_text(encoding="utf-8"))
