"""Integrated supervisor assessment pipeline.

Every active plan (default plus ``.plan-auditor/plans/*.json``) participates in
one fail-closed completion decision. PASS therefore means all active plans have
explicit requirement coverage, a current full-contract seal, a matching fresh
full audit, valid evidence/registry state, and passing policies.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts import audit_check as core
from scripts.plan_graph import (
    PlanGraphError,
    effective_dependencies,
    output_index,
    required_outputs,
    topological_order,
)

from .adversarial import AdversarialReport, run_adversarial_review
from .agents import MultiAgentRegistry
from .config import Profile, load_config
from .contracts import environment_contract
from .events import EventBus
from .gate import CompletionGate
from .goals import Beliefs, Desires, GoalModel, Intentions
from .lifecycle import States, TaskLifecycle
from .plans import PlanRef, all_plan_refs, load_plan_ref, seal_path
from .plan_verifier import verify_plan
from .policies import default_engine, load_policy_rules_from_dir
from .requirements import parse_requirements
from .sealing import (
    MonotonicCheck,
    SealIntegrityError,
    check_environment,
    check_monotonic,
    load_seal,
)
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


def _result_checks_match(expected, results):
    if len(results) != len(expected):
        return False
    actual = [result.get("check") for result in results if isinstance(result, dict)]
    return actual == expected and len(actual) == len(results) and all(
        result.get("passed") is True for result in results if isinstance(result, dict)
    )


def _checks_match(step: Dict[str, Any], record: Dict[str, Any], dependencies: List[int],
                  by_id: Dict[int, Dict[str, Any]]) -> bool:
    expected = [core.norm_check(check) for check in step.get("verify", []) if isinstance(check, dict)]
    if not _result_checks_match(expected, record.get("results", [])):
        return False
    if record.get("dependencies", []) != dependencies:
        return False

    try:
        declared_outputs = output_index(step)
        expected_required = required_outputs(step)
    except PlanGraphError:
        return False

    actual_outputs = record.get("outputs", [])
    if len(actual_outputs) != len(declared_outputs):
        return False
    for (name, contract), actual_output in zip(declared_outputs.items(), actual_outputs):
        if not isinstance(actual_output, dict):
            return False
        if actual_output.get("name") != name or actual_output.get("passed") is not True:
            return False
        output_checks = [core.norm_check(check) for check in contract.get("verify", []) if isinstance(check, dict)]
        if not _result_checks_match(output_checks, actual_output.get("results", [])):
            return False

    actual_required = record.get("required_outputs", [])
    if len(actual_required) != len(expected_required):
        return False
    for expected_ref, actual_ref in zip(expected_required, actual_required):
        if not isinstance(actual_ref, dict):
            return False
        if (
            actual_ref.get("step") != expected_ref["step"]
            or actual_ref.get("name") != expected_ref["name"]
            or actual_ref.get("passed") is not True
        ):
            return False
        try:
            source_contract = output_index(by_id[expected_ref["step"]])[expected_ref["name"]]
        except (KeyError, PlanGraphError):
            return False
        source_checks = [core.norm_check(check) for check in source_contract.get("verify", []) if isinstance(check, dict)]
        if not _result_checks_match(source_checks, actual_ref.get("results", [])):
            return False
    return True


def fresh_full_audit_proof(
    root: str | Path,
    plan: Dict[str, Any],
    plan_name: str = "default",
) -> FreshAuditProof:
    """Prove current graph, checks, outputs, coverage contract and workspace match a full audit."""
    root_path = Path(root).resolve()
    chain_ok, _count, problem = core.verify_chain(str(root_path))
    if not chain_ok:
        return FreshAuditProof(False, f"active evidence chain invalid: {problem}")
    archive = verify_anchor_chain(str(root_path / ".plan-auditor" / "archive"))
    if archive.get("anchored") is not True:
        return FreshAuditProof(False, "archive evidence chain is not anchored")

    try:
        order = topological_order(plan)
        dependencies = effective_dependencies(plan)
    except PlanGraphError as exc:
        return FreshAuditProof(False, f"dependency graph invalid: {exc}")
    by_id = {
        step.get("id"): step
        for step in plan.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("id"), int)
    }
    if not order or len(by_id) != len(order):
        return FreshAuditProof(False, "plan has no valid dependency-graph steps")
    steps = [by_id[sid] for sid in order]

    records = _read_evidence_records(root_path)
    marker_index: Optional[int] = None
    marker: Optional[Dict[str, Any]] = None
    for index in range(len(records) - 1, -1, -1):
        record = records[index]
        if record.get("mode") == "audit_complete" and record.get("plan", "default") == plan_name:
            marker_index = index
            marker = record
            break
    if marker is None or marker_index is None:
        return FreshAuditProof(False, f"no complete full-audit fingerprint evidence for plan {plan_name}")
    if marker.get("status") != "verified":
        return FreshAuditProof(False, "latest full audit did not pass")
    if marker.get("topological_order") != order:
        return FreshAuditProof(False, "full-audit dependency order does not match current plan")
    if marker.get("plan_fingerprint") != core.plan_contract_fingerprint(plan):
        return FreshAuditProof(False, "plan contract changed after audit")
    if marker.get("workspace_fingerprint") != core.workspace_fingerprint(str(root_path)):
        return FreshAuditProof(False, "workspace content/type/mode changed after audit")

    audit_records = [
        record for record in records[:marker_index]
        if record.get("mode") == "audit" and record.get("plan", "default") == plan_name
    ]
    if len(audit_records) < len(steps):
        return FreshAuditProof(False, "full-audit marker lacks complete step evidence")
    candidate = audit_records[-len(steps):]
    if [record.get("step") for record in candidate] != order:
        return FreshAuditProof(False, "latest audit evidence does not cover dependency order")
    for step, record in zip(steps, candidate):
        sid = step.get("id")
        if record.get("status") != "verified" or not _checks_match(
            step, record, dependencies.get(sid, []), by_id
        ):
            return FreshAuditProof(False, f"audit evidence does not match graph/check/output contract for step {sid}")

    return FreshAuditProof(
        True,
        "current dependency graph, requirement/output contracts, checks, and workspace match full audit",
        str(marker.get("ts")),
        len(steps),
    )


def _tail_logs(root: Path, limit: int = 200) -> List[str]:
    lines: List[str] = []
    for path in (root / ".plan-auditor" / "evidence.jsonl", root / ".plan-auditor" / "watchdog.jsonl"):
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
    for state in (States.DISCOVERED, States.ANALYZING, States.REQUIREMENTS_READY,
                  States.PLAN_PROPOSED, States.PLAN_REVIEW):
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


def _required_tools(plan: Dict[str, Any], available: Dict[str, bool]) -> List[str]:
    raw = plan.get("required_tools", [])
    if not isinstance(raw, list):
        return ["<invalid required_tools>"]
    return sorted({str(tool) for tool in raw if not available.get(str(tool), False)})


def _merge_checks(*checks: Optional[MonotonicCheck]) -> Optional[MonotonicCheck]:
    values = [check for check in checks if check is not None]
    if not values:
        return None
    return MonotonicCheck(
        ok=all(check.ok for check in values),
        violations=[item for check in values for item in check.violations],
        improvements=[item for check in values for item in check.improvements],
    )


def _evaluate_plan(
    root: Path,
    ref: PlanRef,
    cfg,
    workspace_state,
    logs: List[str],
    evidence_valid: bool,
    evidence_count: int,
    evidence_problem: str,
    archive_result: Dict[str, Any],
    registry: MultiAgentRegistry,
    registry_ok: bool,
    conflicts: List[Dict[str, str]],
    policy_rules,
    policy_errors: List[str],
) -> Dict[str, Any]:
    try:
        plan = load_plan_ref(ref)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"outcome": "FAIL", "plan_name": ref.name, "error": f"invalid plan: {exc}"}

    schema_errors = core.validate_plan(plan)
    requirements = parse_requirements(str(plan.get("task", "")))
    plan_analysis = verify_plan(plan, require_coverage=True)
    plan_ok = not schema_errors and plan_analysis.verdict == "PASS"
    env = environment_contract(root, cfg)

    seal = None
    seal_problem = ""
    try:
        seal = load_seal(str(seal_path(root, ref.name)))
    except SealIntegrityError as exc:
        seal_problem = str(exc)

    monotonic: Optional[MonotonicCheck] = None
    environment_check: Optional[MonotonicCheck] = None
    if seal is None:
        monotonic = MonotonicCheck(False, [seal_problem or "plan is not sealed"], [])
    elif seal.format_version < 3:
        monotonic = MonotonicCheck(False, ["legacy seal requires explicit reseal to full-contract format v3"], [])
    else:
        monotonic = check_monotonic(seal.as_plan(), plan)
        environment_check = check_environment(seal, env)
    seal_check = _merge_checks(monotonic, environment_check)
    seal_ok = bool(seal_check and seal_check.ok)

    proof = fresh_full_audit_proof(root, plan, ref.key)
    pending = [int(step.get("id")) for step in plan.get("steps", [])
               if isinstance(step, dict) and isinstance(step.get("id"), int)
               and step.get("status") != "verified"]

    adversarial = AdversarialReport()
    if cfg.profile == Profile.STRICT:
        adversarial = run_adversarial_review(
            plan, evidence_path=str(root / ".plan-auditor" / "evidence.jsonl")
        )

    engine = default_engine()
    engine.extend(policy_rules)
    context: Dict[str, Any] = {
        "plan_steps": plan.get("steps", []),
        "evidence_valid": evidence_valid,
        "evidence_count": evidence_count,
        "evidence_problem": evidence_problem,
        "logs": logs,
        "missing_required_tools": _required_tools(plan, workspace_state.available_tools),
        "seal_ok": seal_ok,
        "agent_conflicts": conflicts,
        "agent_registry_valid": registry_ok,
        "workspace": workspace_state.to_dict(),
        "configuration_errors": list(cfg.errors),
        "policy_errors": list(policy_errors),
    }

    deterministic_passed = (
        plan_ok and proof.valid and evidence_valid and seal_ok and cfg.valid and not policy_errors
    )
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
        "plan_name": ref.name,
        "schema_errors": schema_errors,
        "requirements": [requirement.__dict__ for requirement in requirements],
        "coverage": plan_analysis.coverage.as_dict() if plan_analysis.coverage else None,
        "plan": {
            "verdict": plan_analysis.verdict,
            "rationale": plan_analysis.rationale,
            "weakest_verification": plan_analysis.weakest_verification,
            "graph_errors": plan_analysis.graph_errors,
            "coverage_gaps": plan_analysis.coverage_gaps,
            "topological_order": plan_analysis.topological_order,
            "dependencies": plan_analysis.dependencies,
        },
        "seal": {
            "present": seal is not None,
            "ok": seal_ok,
            "format_version": seal.format_version if seal else None,
            "environment": env,
            "violations": seal_check.violations if seal_check else [seal_problem] if seal_problem else [],
        },
        "evidence": {
            "active_chain_valid": evidence_valid,
            "active_records": evidence_count,
            "active_problem": evidence_problem,
            "archive": archive_result,
        },
        "fresh_audit": proof.as_dict(),
        "adversarial": {
            "used_llm": adversarial.used_llm,
            "findings": [
                {"id": finding.check_id, "severity": finding.severity,
                 "description": finding.description, "suggested_check": finding.suggested_check}
                for finding in adversarial.findings
            ],
            "proposed_checks": adversarial.proposed_checks,
        },
        "goals": goals.beliefs.summary(),
        "lifecycle": {
            "state": str(lifecycle.state),
            "retries": lifecycle.retries,
            "rejected_plans": lifecycle.rejected_plans,
        },
        "gate": report.as_dict(),
    }


def evaluate_workspace(workspace: str, profile: str | None = None,
                       mode: str | None = None) -> Dict[str, Any]:
    root = Path(workspace).resolve()
    cfg = load_config(str(root))
    if profile is not None:
        try:
            cfg.profile = Profile(profile.lower())
        except ValueError:
            cfg.errors.append(f"invalid requested profile: {profile!r}")
    if mode is not None:
        if mode not in {"serial", "parallel-warn", "parallel-strict"}:
            cfg.errors.append(f"invalid requested mode: {mode!r}")
        else:
            cfg.mode = mode

    refs = all_plan_refs(root)
    if not refs:
        return {
            "outcome": "NO_PLAN",
            "workspace": str(root),
            "profile": cfg.profile.value,
            "mode": cfg.mode,
            "active_layers": cfg.active_layers(),
            "configuration_errors": cfg.errors,
            "active_plan_count": 0,
            "plans": {},
        }

    workspace_state = capture_workspace(str(root))
    logs = _tail_logs(root)
    event_bus = EventBus()
    events = event_bus.scan_message("\n".join(logs[-50:])) if logs else []

    active_ok, evidence_count, evidence_problem = core.verify_chain(str(root))
    archive_result = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    evidence_valid = active_ok and archive_result.get("anchored") is True

    registry = MultiAgentRegistry(str(root), owner_timeout=cfg.owner_timeout_sec)
    released = registry.release_stale_ownership()
    conflicts = _agent_conflicts(registry)
    registry_ok = registry.verify_registry_chain()

    policy_errors: List[str] = []
    policy_rules = []
    seen_dirs: set[Path] = set()
    for directory in (root / cfg.policies_dir, root / ".plan-auditor" / "policies"):
        resolved = directory.resolve()
        if resolved in seen_dirs:
            continue
        seen_dirs.add(resolved)
        policy_rules.extend(load_policy_rules_from_dir(str(resolved), errors=policy_errors))

    plans: Dict[str, Any] = {}
    for ref in refs:
        plans[ref.key] = _evaluate_plan(
            root, ref, cfg, workspace_state, logs,
            evidence_valid, evidence_count, evidence_problem, archive_result,
            registry, registry_ok, conflicts, policy_rules, policy_errors,
        )

    outcomes = [str(item.get("outcome", "FAIL")) for item in plans.values()]
    if "FAIL" in outcomes:
        outcome = "FAIL"
    elif "UNKNOWN" in outcomes:
        outcome = "UNKNOWN"
    elif outcomes and all(value == "PASS" for value in outcomes):
        outcome = "PASS"
    else:
        outcome = "FAIL"

    result: Dict[str, Any] = {
        "outcome": outcome,
        "workspace": str(root),
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "active_layers": cfg.active_layers(),
        "configuration_errors": cfg.errors,
        "policy_errors": policy_errors,
        "active_plan_count": len(plans),
        "plans": plans,
        "workspace_state": workspace_state.to_dict(),
        "events": [repr(event) for event in events],
        "agents": {
            "active": [agent.to_dict() for agent in registry.active_agents()],
            "released_stale": released,
            "conflicts": conflicts,
            "registry_valid": registry_ok,
        },
        "evidence": {
            "active_chain_valid": active_ok,
            "active_records": evidence_count,
            "active_problem": evidence_problem,
            "archive": archive_result,
        },
    }

    # Backward-compatible single/default-plan projections for existing clients.
    primary = plans.get("default") or (next(iter(plans.values())) if len(plans) == 1 else None)
    if primary:
        for key in ("schema_errors", "requirements", "coverage", "plan", "seal",
                    "fresh_audit", "adversarial", "goals", "lifecycle", "gate"):
            result[key] = primary.get(key)
    return result
