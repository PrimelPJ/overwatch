"""
Automated response playbook executor for threat intelligence actions.
Executes configurable response playbooks based on IOC type, severity, and context.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from overwatch.models import IOC, AlertTriage, PlaybookAction, Severity

logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"


@dataclass
class PlaybookStep:
    action: PlaybookAction
    target: str  # IP, domain, host, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[int] = field(default_factory=list)  # step indices
    on_failure: str = "continue"  # continue | abort | retry
    max_retries: int = 0
    timeout_seconds: int = 30


@dataclass
class PlaybookExecution:
    playbook_name: str
    trigger_ioc: Optional[IOC]
    trigger_alert: Optional[AlertTriage]
    steps: List[PlaybookStep]
    status: PlaybookStatus = PlaybookStatus.PENDING
    results: List[Dict[str, Any]] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds() * 1000
        return None

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.get("status") == "success")

    @property
    def failure_count(self) -> int:
        return sum(1 for r in self.results if r.get("status") == "failed")


@dataclass
class PlaybookDefinition:
    name: str
    description: str
    trigger_severity: List[Severity] = field(default_factory=list)
    trigger_tags: List[str] = field(default_factory=list)
    actions: List[PlaybookAction] = field(default_factory=list)
    enabled: bool = True
    auto_execute: bool = False
    cooldown_seconds: int = 300
    _last_execution: Optional[float] = field(default=None, repr=False)

    def is_triggered_by(self, ioc: IOC) -> bool:
        if not self.enabled:
            return False
        if self.trigger_severity and ioc.severity not in self.trigger_severity:
            return False
        if self.trigger_tags and not ioc.tags.intersection(self.trigger_tags):
            return False
        return True

    @property
    def is_on_cooldown(self) -> bool:
        if self._last_execution is None:
            return False
        return time.time() - self._last_execution < self.cooldown_seconds


ActionHandler = Callable[[PlaybookStep, IOC | AlertTriage | None], Dict[str, Any]]


class PlaybookExecutor:
    """
    Executes security response playbooks triggered by IOC matches and alerts.

    Supports:
    - Sequential and parallel step execution
    - Step dependency resolution
    - Retry logic with configurable backoff
    - Action handler registry
    - Execution history and audit trail
    """

    def __init__(self) -> None:
        self._definitions: Dict[str, PlaybookDefinition] = {}
        self._handlers: Dict[PlaybookAction, ActionHandler] = {}
        self._execution_history: List[PlaybookExecution] = []
        self._register_default_handlers()

    def register_definition(self, definition: PlaybookDefinition) -> None:
        self._definitions[definition.name] = definition
        logger.info("Registered playbook: %s", definition.name)

    def register_handler(self, action: PlaybookAction, handler: ActionHandler) -> None:
        self._handlers[action] = handler
        logger.debug("Registered handler for action: %s", action.value)

    def evaluate_ioc(self, ioc: IOC) -> List[PlaybookDefinition]:
        """Return all playbooks triggered by this IOC."""
        triggered = []
        for defn in self._definitions.values():
            if defn.is_triggered_by(ioc) and not defn.is_on_cooldown:
                triggered.append(defn)
        return triggered

    def execute_for_ioc(self, ioc: IOC, playbook_name: str) -> PlaybookExecution:
        """Execute a named playbook triggered by an IOC."""
        defn = self._definitions.get(playbook_name)
        if defn is None:
            raise ValueError(f"Unknown playbook: {playbook_name!r}")

        steps = self._build_steps_for_ioc(defn, ioc)
        execution = PlaybookExecution(
            playbook_name=playbook_name,
            trigger_ioc=ioc,
            trigger_alert=None,
            steps=steps,
        )
        return self._run_execution(execution, ioc)

    def execute_for_alert(self, alert: AlertTriage, playbook_name: str) -> PlaybookExecution:
        """Execute a named playbook triggered by a triaged alert."""
        defn = self._definitions.get(playbook_name)
        if defn is None:
            raise ValueError(f"Unknown playbook: {playbook_name!r}")

        steps = self._build_steps_for_alert(defn, alert)
        execution = PlaybookExecution(
            playbook_name=playbook_name,
            trigger_ioc=None,
            trigger_alert=alert,
            steps=steps,
        )
        return self._run_execution(execution, alert)

    def auto_respond(self, ioc: IOC) -> List[PlaybookExecution]:
        """Auto-execute all triggered playbooks for an IOC."""
        executions = []
        for defn in self.evaluate_ioc(ioc):
            if defn.auto_execute:
                try:
                    ex = self.execute_for_ioc(ioc, defn.name)
                    executions.append(ex)
                except Exception as e:
                    logger.exception("Auto-execute failed for playbook %s: %s", defn.name, e)
        return executions

    def get_execution_history(
        self,
        playbook_name: Optional[str] = None,
        status: Optional[PlaybookStatus] = None,
        limit: int = 100,
    ) -> List[PlaybookExecution]:
        history = self._execution_history
        if playbook_name:
            history = [e for e in history if e.playbook_name == playbook_name]
        if status:
            history = [e for e in history if e.status == status]
        return history[-limit:]

    def _build_steps_for_ioc(
        self, defn: PlaybookDefinition, ioc: IOC
    ) -> List[PlaybookStep]:
        steps = []
        for action in defn.actions:
            step = PlaybookStep(
                action=action,
                target=ioc.value,
                parameters={"ioc_type": ioc.ioc_type.value, "severity": ioc.severity.value},
            )
            steps.append(step)
        return steps

    def _build_steps_for_alert(
        self, defn: PlaybookDefinition, alert: AlertTriage
    ) -> List[PlaybookStep]:
        steps = []
        for action in defn.actions:
            target = ""
            if alert.matched_iocs:
                target = alert.matched_iocs[0].value
            step = PlaybookStep(
                action=action,
                target=target,
                parameters={
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "ioc_count": len(alert.matched_iocs),
                },
            )
            steps.append(step)
        return steps

    def _run_execution(
        self,
        execution: PlaybookExecution,
        context: IOC | AlertTriage,
    ) -> PlaybookExecution:
        execution.status = PlaybookStatus.RUNNING
        execution.started_at = datetime.now(timezone.utc)
        logger.info(
            "Starting playbook %s with %d steps",
            execution.playbook_name,
            len(execution.steps),
        )

        completed_steps: set[int] = set()
        failed_steps: set[int] = set()

        for idx, step in enumerate(execution.steps):
            # Check dependencies
            if any(dep not in completed_steps for dep in step.depends_on):
                result = {
                    "step": idx,
                    "action": step.action.value,
                    "target": step.target,
                    "status": "skipped",
                    "reason": "dependency_not_met",
                }
                execution.results.append(result)
                continue

            result = self._execute_step(step, context, idx)
            execution.results.append(result)

            if result["status"] == "success":
                completed_steps.add(idx)
            else:
                failed_steps.add(idx)
                if step.on_failure == "abort":
                    execution.status = PlaybookStatus.FAILED
                    execution.error = f"Aborted at step {idx}: {result.get('error')}"
                    break

        if execution.status != PlaybookStatus.FAILED:
            if failed_steps:
                execution.status = PlaybookStatus.PARTIAL
            else:
                execution.status = PlaybookStatus.COMPLETED

        execution.completed_at = datetime.now(timezone.utc)

        # Update cooldown
        defn = self._definitions.get(execution.playbook_name)
        if defn:
            defn._last_execution = time.time()

        self._execution_history.append(execution)
        logger.info(
            "Playbook %s finished: %s (%d/%d steps succeeded)",
            execution.playbook_name,
            execution.status.value,
            execution.success_count,
            len(execution.steps),
        )
        return execution

    def _execute_step(
        self,
        step: PlaybookStep,
        context: IOC | AlertTriage,
        idx: int,
    ) -> Dict[str, Any]:
        handler = self._handlers.get(step.action)
        if handler is None:
            return {
                "step": idx,
                "action": step.action.value,
                "target": step.target,
                "status": "skipped",
                "reason": "no_handler_registered",
            }

        for attempt in range(max(1, step.max_retries + 1)):
            try:
                start = time.monotonic()
                result_data = handler(step, context)
                elapsed_ms = (time.monotonic() - start) * 1000

                return {
                    "step": idx,
                    "action": step.action.value,
                    "target": step.target,
                    "status": "success",
                    "data": result_data,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "attempt": attempt + 1,
                }
            except Exception as e:
                logger.warning(
                    "Step %d action=%s attempt=%d failed: %s",
                    idx, step.action.value, attempt + 1, e,
                )
                if attempt < step.max_retries:
                    time.sleep(2 ** attempt)
                else:
                    return {
                        "step": idx,
                        "action": step.action.value,
                        "target": step.target,
                        "status": "failed",
                        "error": str(e),
                        "attempts": attempt + 1,
                    }

        return {"step": idx, "action": step.action.value, "status": "failed"}

    def _register_default_handlers(self) -> None:
        """Register no-op simulation handlers for all playbook actions."""
        def simulate_block_ip(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Blocking IP: %s", step.target)
            return {"blocked_ip": step.target, "firewall_rule_id": f"fw-{hash(step.target) % 99999}"}

        def simulate_block_domain(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Blocking domain: %s", step.target)
            return {"blocked_domain": step.target, "dns_sinkhole": True}

        def simulate_quarantine_host(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Quarantining host: %s", step.target)
            return {"host": step.target, "quarantine_vlan": "ISOLATED", "ticket_id": "INC-AUTO-001"}

        def simulate_enrich_alert(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Enriching alert for: %s", step.target)
            return {"enrichment_status": "completed", "iocs_found": 0}

        def simulate_create_ticket(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            severity = step.parameters.get("severity", "medium")
            logger.info("[SIMULATE] Creating ticket for severity=%s", severity)
            return {"ticket_id": f"INC-{int(time.time()) % 100000}", "severity": severity}

        def simulate_notify_soc(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Notifying SOC about: %s", step.target)
            return {"notification_sent": True, "channel": "soc-alerts"}

        def simulate_isolate_endpoint(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Isolating endpoint: %s", step.target)
            return {"endpoint": step.target, "isolated": True, "agent_id": "EP-" + step.target[:8]}

        def simulate_reset_credentials(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Resetting credentials for: %s", step.target)
            return {"reset_initiated": True, "affected_accounts": 1}

        def simulate_collect_forensics(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Collecting forensics from: %s", step.target)
            return {"collection_id": f"forensics-{int(time.time())}", "artifacts": ["memory.dmp", "prefetch"]}

        def simulate_patch_vuln(step: PlaybookStep, context: Any) -> Dict[str, Any]:
            logger.info("[SIMULATE] Initiating patch for: %s", step.target)
            return {"patch_ticket": f"PATCH-{int(time.time()) % 10000}", "target": step.target}

        handler_map = {
            PlaybookAction.BLOCK_IP: simulate_block_ip,
            PlaybookAction.BLOCK_DOMAIN: simulate_block_domain,
            PlaybookAction.QUARANTINE_HOST: simulate_quarantine_host,
            PlaybookAction.ENRICH_ALERT: simulate_enrich_alert,
            PlaybookAction.CREATE_TICKET: simulate_create_ticket,
            PlaybookAction.NOTIFY_SOC: simulate_notify_soc,
            PlaybookAction.ISOLATE_ENDPOINT: simulate_isolate_endpoint,
            PlaybookAction.RESET_CREDENTIALS: simulate_reset_credentials,
            PlaybookAction.COLLECT_FORENSICS: simulate_collect_forensics,
            PlaybookAction.PATCH_VULNERABILITY: simulate_patch_vuln,
        }
        for action, handler in handler_map.items():
            self.register_handler(action, handler)
