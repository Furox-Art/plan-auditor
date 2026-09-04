"""Integrated supervisor assessment pipeline.

This module wires the previously independent L0-L14 components into one
fail-closed assessment. L10 remains ``scripts.audit_check``; freshness is
proven by deterministic plan/workspace fingerprints written by a full audit,
not by filesystem mtimes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts import audit_check as core

from .adversarial import AdversarialReport, run_adversarial_review
from .agents import MultiAgentRegistry
from .config import Profile, load_config
from .events import EventBus
from .gate import CompletionGate
from .goals import Beliefs, Desires, GoalModel, Intentions
from .lifecycle import States, TaskLifecycle
from .plan_verifier import verify_plan
from .policies import default_engine, load_policy_rules_from_dir
from .requirements import parse_requirements
from .sealing import MonotonicCheck, check_monotonic, load_seal
from .workspace import capture_workspace
from .evidence import verify_anchor_chain


@dataclass
class FreshAuditProof:
    valid: bool
    reason: str
    audited_at: Optional[str] = None
    steps: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "audited_at": self.audited_at,
            "steps": self.steps,
        }


def _load_plan(root: Path) -> Optional[Dict[str, Any]]:
    path = root / ".plan-auditor" / "plan.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _evidence_files(root: Path) -> List[Path]:
    archive = root / ".plan-auditor" / "archive"
    files: List[Path] = []
    if archive.is_dir():
        files.extend(sorted(archive.glob("evidence-*.jsonl")))
    active = root / ".plan-auditor" / "evidence.jsonl"
    if active.exists():
        files.append(active)
    return files


def _read_evidence_records(root: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for path in _evidence_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                records.append(rec)
    return records


def _checks_match(step: Dict[str, Any], record: Dict[str, Any]) -> bool:
    expected = [core.norm_check(check) for check in step.get("verify", []) if isinstance(check, dict)]
    results = record.get("results", [])
    if len(results) != len(expected):
        return False
    actual = [result.get("check") for result in results if isinstance(result, dict)]
    return actual == expected and all(
        result.get("passed") is True for result in results if isinstance(result, dict)
    )


def fresh_full_audit_proof(root: str | Path, plan: Dict[str, Any]) -> FreshAuditProof:
    """Prove the current plan/workspace exactly matches a completed L10 audit.

    ``status=verified`` is never sufficient. A valid proof requires:
    - the active evidence chain to verify,
    - a final ``audit_complete`` marker,
    - exact plan-contract fingerprint equality,
    - exact workspace-content fingerprint equality,
    - matching successful per-step audit records immediately preceding the
      latest completion marker.
    """
    root_path = Path(root).resolve()
    chain_ok, _count, problem = core.verify_chain(str(root_path))
    if not chain_ok:
        return FreshAuditProof(False, f"active evidence chain invalid: {problem}")

    steps = [step for step in plan.get("steps", []) if isinstance(step, dict)]
    if not steps:
        return FreshAuditProof(False, "plan has no steps")

    records = _read_evidence_records(root_path)
    marker_index: Optional[int] = None
    marker: Optional[Dict[str, Any]] = None
    for index in range(len(records) - 1, -1, -1):
        record = records[index]
        if record.get("mode") == "audit_complete" and record.get("plan", "default") == "default":
            marker_index = index
            marker = record
            break
    if marker is None or marker_index is None:
        return FreshAuditProof(False, "no complete full-audit fingerprint evidence")
    if marker.get("status") != "verified":
        return FreshAuditProof(False, "latest full audit did not pass")

    current_plan_fp = core.plan_contract_fingerprint(plan)
    if marker.get("plan_fingerprint") != current_plan_fp:
        return FreshAuditProof(False, "plan contract changed after audit")

    current_workspace_fp = core.workspace_fingerprint(str(root_path))
    if marker.get("workspace_fingerprint") != current_workspace_fp:
        return FreshAuditProof(False, "workspace content changed after audit")

    audit_records = [
        record for record in records[:marker_index]
        if record.get("mode") == "audit" and record.get("plan", "default") == "default"
    ]
    if len(audit_records) < len(steps):
        return FreshAuditProof(False, "full-audit marker lacks complete step evidence")
    candidate = audit_records[-len(steps):]
    expected_ids = [step.get("id") for step in steps]
    if [record.get("step") for record in candidate] != expected_ids:
        return FreshAuditProof(False, "latest audit evidence does not cover current step sequence")
    for step, record in zip(steps, candidate):
        if record.get("status") != "verified" or not _checks_match(step, record):
            return FreshAuditProof(
                False,
                f"audit evidence does not match current checks for step {step.get('id')}",
            )

    return FreshAuditProof(
        True,
        "current plan and workspace match deterministic full-audit fingerprints",
        str(marker.get("ts")),
        len(steps),
    )


def _tail_logs(root: Path, limit: int = 200) -> List[str]:
    lines: List[str] = []
    for path in (
        root / ".plan-auditor" / "evidence.jsonl",
        root / ".plan-auditor" / "watchdog.jsonl",
    ):
        try:
            lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:])
        except OSError:
            pass
    return lines[-limit:]


def _agent_conflicts(registry: MultiAgentRegistry) -> List[Dict[str, str]]:
    active = registry.active_agents()
    conflicts: List[Dict[str, str]] = []
    for index, left in enumerate(active):
        for right in active[index + 1:]:
            for path in sorted(left.owned_files & right.owned_files):
                conflicts.append({"file": path, "owner": left.agent_id, "accessor": right.agent_id})
    return conflicts


def _lifecycle_for(plan_ok: bool, seal_ok: bool, pending: List[int], proof: FreshAuditProof,
                   outcome: str) -> TaskLifecycle:
    lifecycle = TaskLifecycle(task_id="default")
    for state in (
        States.DISCOVERED, States.ANALYZING, States.REQUIREMENTS_READY,
        States.PLAN_PROPOSED, States.PLAN_REVIEW,
    ):
        lifecycle.transition(state, operator="supervisor")
    if not plan_ok:
        lifecycle.transition(States.REVISION_REQUIRED, operator="plan_verifier")
        return lifecycle
    lifecycle.transition(States.PLAN_APPROVED, operator="plan_verifier")
    if not seal_ok:
        return lifecycle
    lifecycle.transition(States.SEALED, operator="sealing")
    lifecycle.transition(States.IMPLEMENTING, operator="workspace")
    if pending:
        return lifecycle
    lifecycle.transition(States.VERIFYING, operator="deterministic_core")
    lifecycle.transition(States.FINAL_AUDIT, operator="deterministic_core")
    if proof.valid and outcome == "PASS":
        lifecycle.transition(States.PASSED, operator="completion_gate")
    elif outcome == "UNKNOWN":
        lifecycle.transition(States.UNKNOWN, operator="completion_gate")
    elif outcome == "FAIL":
        lifecycle.transition(States.FAILED, operator="completion_gate")
    return lifecycle


def evaluate_workspace(workspace: str, profile: str | None = None,
                       mode: str | None = None) -> Dict[str, Any]:
    root = Path(workspace).resolve()
    cfg = load_config(str(root))
    if profile is not None:
        cfg.profile = Profile(profile.lower())
    if mode is not None:
        cfg.mode = mode

    plan = _load_plan(root)
    if plan is None:
        return {
            "outcome": "NO_PLAN",
            "workspace": str(root),
            "profile": cfg.profile.value,
            "mode": cfg.mode,
            "active_layers": cfg.active_layers(),
        }

    schema_errors = core.validate_plan(plan)
    requirements = parse_requirements(str(plan.get("task", "")))
    plan_analysis = verify_plan(plan)
    plan_ok = not schema_errors and plan_analysis.verdict == "PASS"

    workspace_state = capture_workspace(str(root))
    logs = _tail_logs(root)
    event_bus = EventBus()
    events = event_bus.scan_message("\n".join(logs[-50:])) if logs else []

    active_ok, evidence_count, evidence_problem = core.verify_chain(str(root))
    archive_result = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    evidence_valid = active_ok and archive_result.get("anchored") is True

    seal = load_seal(str(root / ".plan-auditor" / "seal.json"))
    seal_check: Optional[MonotonicCheck]
    if cfg.profile == Profile.LIGHT and seal is None:
        seal_check = None
        seal_ok = True
    elif seal is None:
        seal_check = MonotonicCheck(False, ["plan is not sealed"], [])
        seal_ok = False
    elif seal.format_version < 2:
        seal_check = MonotonicCheck(False, ["legacy seal requires explicit reseal"], [])
        seal_ok = False
    else:
        seal_check = check_monotonic(seal.as_plan(), plan)
        seal_ok = seal_check.ok

    proof = fresh_full_audit_proof(root, plan)
    pending = [step.get("id") for step in plan.get("steps", []) if step.get("status") != "verified"]
    pending = [int(value) for value in pending if isinstance(value, int)]

    registry = MultiAgentRegistry(str(root), owner_timeout=cfg.owner_timeout_sec)
    released = registry.release_stale_ownership()
    conflicts = _agent_conflicts(registry)
    registry_ok = registry.verify_registry_chain()

    adversarial = AdversarialReport()
    if cfg.profile == Profile.STRICT:
        adversarial = run_adversarial_review(
            plan,
            evidence_path=str(root / ".plan-auditor" / "evidence.jsonl"),
        )

    engine = default_engine()
    if cfg.profile == Profile.LIGHT:
        engine.rules = [rule for rule in engine.rules if rule.rule_id != "SEAL_INTACT"]
    for directory in (root / cfg.policies_dir, root / ".plan-auditor" / "policies"):
        engine.extend(load_policy_rules_from_dir(str(directory)))

    context: Dict[str, Any] = {
        "plan_steps": plan.get("steps", []),
        "evidence_valid": evidence_valid,
        "evidence_count": evidence_count,
        "evidence_problem": evidence_problem,
        "logs": logs,
        "missing_required_tools": [],
        "seal_ok": seal_ok,
        "agent_conflicts": conflicts,
        "agent_registry_valid": registry_ok,
        "workspace": workspace_state.to_dict(),
    }

    deterministic_passed = plan_ok and proof.valid and evidence_valid
    gate = CompletionGate(engine)
    report = gate.evaluate(
        deterministic_passed=deterministic_passed,
        pending_steps=pending,
        workspace_context=context,
        seal_check=seal_check,
        adversarial_findings=adversarial.findings,
    )

    goals = GoalModel(
        beliefs=Beliefs(
            repository_state=workspace_state.to_dict(),
            requirements=[requirement.__dict__ for requirement in requirements],
            failures=[{"detail": note} for note in report.notes],
            agent_state={"active": len(registry.active_agents()), "conflicts": conflicts},
            tool_availability=workspace_state.available_tools,
        ),
        desires=Desires(user_goals=[str(plan.get("task", ""))]),
        intentions=Intentions(
            verification_steps=[{"step": step_id} for step_id in pending],
            active_strategy="recovery" if report.outcome == "FAIL" else "exhaustive",
        ),
    )
    lifecycle = _lifecycle_for(plan_ok, seal_ok, pending, proof, report.outcome)

    return {
        "outcome": report.outcome,
        "workspace": str(root),
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "active_layers": cfg.active_layers(),
        "schema_errors": schema_errors,
        "requirements": [requirement.__dict__ for requirement in requirements],
        "plan": {
            "verdict": plan_analysis.verdict,
            "rationale": plan_analysis.rationale,
            "weakest_verification": plan_analysis.weakest_verification,
        },
        "workspace_state": workspace_state.to_dict(),
        "events": [repr(event) for event in events],
        "seal": {
            "present": seal is not None,
            "ok": seal_ok,
            "violations": seal_check.violations if seal_check else [],
        },
        "evidence": {
            "active_chain_valid": active_ok,
            "active_records": evidence_count,
            "active_problem": evidence_problem,
            "archive": archive_result,
        },
        "fresh_audit": proof.as_dict(),
        "adversarial": {
            "used_llm": adversarial.used_llm,
            "findings": [
                {
                    "id": finding.check_id,
                    "severity": finding.severity,
                    "description": finding.description,
                    "suggested_check": finding.suggested_check,
                }
                for finding in adversarial.findings
            ],
            "proposed_checks": adversarial.proposed_checks,
        },
        "agents": {
            "active": [agent.to_dict() for agent in registry.active_agents()],
            "released_stale": released,
            "conflicts": conflicts,
            "registry_valid": registry_ok,
        },
        "goals": goals.beliefs.summary(),
        "lifecycle": {
            "state": str(lifecycle.state),
            "retries": lifecycle.retries,
            "rejected_plans": lifecycle.rejected_plans,
        },
        "gate": report.as_dict(),
    }
