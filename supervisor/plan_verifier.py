"""L5 — deterministic structural and classical symbolic plan verifier."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scripts.plan_graph import (
    PlanGraphError,
    effective_dependencies,
    explicit_graph,
    output_index,
    required_outputs,
    topological_order,
    validate_output_links,
)

from .coverage import CoverageResult, analyze_coverage
from .formal_planning import FormalPlanningResult, analyze_formal_contract


@dataclass
class StepAnalysis:
    step_id: int
    preconditions_met: bool
    expected_effect_advances: bool
    has_behavioral_verification: bool
    dependencies: List[int] = field(default_factory=list)
    required_outputs: List[Dict] = field(default_factory=list)
    declared_outputs: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class PlanAnalysis:
    verdict: str = "PASS"          # PASS | REVISE | REJECT
    step_analyses: List[StepAnalysis] = field(default_factory=list)
    coverage_gaps: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    graph_errors: List[str] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)
    topological_order: List[int] = field(default_factory=list)
    dependencies: Dict[int, List[int]] = field(default_factory=dict)
    coverage: Optional[CoverageResult] = None
    formal_planning: Optional[FormalPlanningResult] = None

    @property
    def weakest_verification(self) -> Optional[str]:
        for step in self.step_analyses:
            if not step.has_behavioral_verification:
                return "step %d lacks behavioral verification" % step.step_id
        return None


_WEAK_VERIFY = {"file_exists", "regex"}


def _check_step(step: Dict, index: int, dependencies: List[int]) -> StepAnalysis:
    verify = step.get("verify", [])
    types = {check.get("type") for check in verify if isinstance(check, dict)}
    has_behavioral = bool(types - _WEAK_VERIFY)
    risks: List[str] = []
    suggestions: List[str] = []

    if not has_behavioral:
        risks.append("step %d uses only weak checks (file_exists/regex)" % step.get("id", index))
        suggestions.append("add a behavioral check (run/pytest/exec) that exercises real behavior")
    if not verify:
        risks.append("step %d has no verification" % step.get("id", index))

    try:
        outputs = sorted(output_index(step))
    except PlanGraphError as exc:
        outputs = []
        risks.append(str(exc))
    try:
        required = required_outputs(step)
    except PlanGraphError as exc:
        required = []
        risks.append(str(exc))

    return StepAnalysis(
        step_id=step.get("id", index),
        preconditions_met=not any("depend" in risk.lower() for risk in risks),
        expected_effect_advances=has_behavioral or bool(outputs),
        has_behavioral_verification=has_behavioral,
        dependencies=list(dependencies),
        required_outputs=required,
        declared_outputs=outputs,
        risks=risks,
        suggestions=suggestions,
    )


def _unbound_explicit_edges(plan: Dict, dependencies: Dict[int, List[int]]) -> List[str]:
    if not explicit_graph(plan):
        return []
    by_id = {
        step.get("id"): step
        for step in plan.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("id"), int)
    }
    errors: List[str] = []
    for child, parents in dependencies.items():
        step = by_id.get(child, {})
        try:
            refs = required_outputs(step)
        except PlanGraphError:
            continue
        linked_sources = {ref["step"] for ref in refs}
        for parent in parents:
            if parent not in linked_sources:
                errors.append(
                    "dependency edge %s -> %s has no requires_outputs link; explicit dependencies must be backed by a concrete upstream output"
                    % (parent, child)
                )
    return errors


def verify_plan(plan: Dict, *, require_coverage: bool = False) -> PlanAnalysis:
    analysis = PlanAnalysis()
    steps = plan.get("steps", [])
    if not isinstance(steps, list) or not steps:
        analysis.verdict = "REJECT"
        analysis.rationale.append("plan has no steps")
        return analysis

    graph_valid = True
    try:
        analysis.dependencies = effective_dependencies(plan)
        analysis.topological_order = topological_order(plan)
    except PlanGraphError as exc:
        graph_valid = False
        analysis.graph_errors.append(str(exc))
        analysis.rationale.append("dependency graph is invalid")
        analysis.dependencies = {
            step.get("id"): []
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("id"), int)
        }

    output_errors = validate_output_links(plan)
    if output_errors:
        graph_valid = False
        analysis.graph_errors.extend(output_errors)
        analysis.rationale.append("output dependency contract is invalid")

    if graph_valid:
        edge_errors = _unbound_explicit_edges(plan, analysis.dependencies)
        if edge_errors:
            graph_valid = False
            analysis.graph_errors.extend(edge_errors)
            analysis.rationale.append("explicit dependency edges lack concrete output bindings")

    weak_steps = 0
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            continue
        sid = step.get("id", index)
        step_deps = analysis.dependencies.get(sid, []) if isinstance(sid, int) else []
        step_analysis = _check_step(step, index, step_deps)
        analysis.step_analyses.append(step_analysis)
        if not step_analysis.has_behavioral_verification:
            weak_steps += 1

    should_check_coverage = require_coverage or "requirements" in plan or any(
        isinstance(step, dict) and "covers" in step for step in steps
    )
    if should_check_coverage:
        analysis.coverage = analyze_coverage(plan)
        analysis.coverage_gaps = list(analysis.coverage.errors)
        if not analysis.coverage.valid:
            analysis.rationale.append("explicit requirement coverage is incomplete or invalid")

    formal = analyze_formal_contract(plan)
    if formal.enabled:
        analysis.formal_planning = formal
        if formal.verdict == "REJECT":
            analysis.contradictions.extend(formal.errors)
            analysis.rationale.append("sealed classical planning contract is unreachable or invalid")
        elif formal.verdict == "UNKNOWN":
            analysis.rationale.append("sealed classical planning search did not reach a conclusive result")
        else:
            analysis.rationale.append(
                "sealed classical planning contract is reachable in dependency-respecting order"
            )

    if not graph_valid:
        analysis.verdict = "REJECT"
    elif formal.enabled and formal.verdict == "REJECT":
        analysis.verdict = "REJECT"
    elif analysis.coverage is not None and not analysis.coverage.valid:
        analysis.verdict = "REJECT" if require_coverage else "REVISE"
    elif formal.enabled and formal.verdict == "UNKNOWN":
        analysis.verdict = "REVISE"
    elif analysis.step_analyses and weak_steps == len(analysis.step_analyses):
        analysis.verdict = "REJECT"
        analysis.rationale.append("no step has behavioral verification")
    elif weak_steps > 0:
        analysis.verdict = "REVISE"
        analysis.rationale.append(
            "%d/%d steps lack behavioral verification" % (weak_steps, len(analysis.step_analyses))
        )
    else:
        analysis.verdict = "PASS"

    return analysis
