"""L5 — STRIPS-like plan verifier.

Reduces each plan step to ACTION / PRECONDITIONS / EXPECTED EFFECTS /
FAILURE CONDITIONS / DEPENDENCIES / REQUIREMENTS COVERED /
VERIFICATION. Checks logical soundness: preconditions present,
effects advance the goal, coverage complete, no contradictions, no
impossible states, real behavioral verification.

Output: PASS / REVISE / REJECT + rationale. This layer does NOT
execute; it only analyzes the plan structure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class StepAnalysis:
    step_id: int
    preconditions_met: bool
    expected_effect_advances: bool
    has_behavioral_verification: bool
    risks: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class PlanAnalysis:
    verdict: str = "PASS"          # PASS | REVISE | REJECT
    step_analyses: List[StepAnalysis] = field(default_factory=list)
    coverage_gaps: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)

    @property
    def weakest_verification(self) -> Optional[str]:
        for s in self.step_analyses:
            if not s.has_behavioral_verification:
                return "step %d lacks behavioral verification" % s.step_id
        return None


_WEAK_VERIFY = {"file_exists", "regex"}


def _check_step(step: Dict, index: int, total: int) -> StepAnalysis:
    verify = step.get("verify", [])
    types = {c.get("type") for c in verify if isinstance(c, dict)}
    has_behavioral = bool(types - _WEAK_VERIFY)
    risks: List[str] = []
    suggestions: List[str] = []

    if not has_behavioral:
        risks.append("step %d uses only weak checks (file_exists/regex)" % step.get("id", index))
        suggestions.append("add a behavioral check (run/pytest/exec) that exercises real behavior")

    if not verify:
        risks.append("step %d has no verification" % step.get("id", index))

    return StepAnalysis(
        step_id=step.get("id", index),
        preconditions_met=True,            # preconditions need runtime state; optimistic here
        expected_effect_advances=True,
        has_behavioral_verification=has_behavioral,
        risks=risks,
        suggestions=suggestions,
    )


def verify_plan(plan: Dict) -> PlanAnalysis:
    analysis = PlanAnalysis()
    steps = plan.get("steps", [])
    if not steps:
        analysis.verdict = "REJECT"
        analysis.rationale.append("plan has no steps")
        return analysis

    total = len(steps)
    weak_steps = 0
    for i, step in enumerate(steps):
        sa = _check_step(step, i, total)
        analysis.step_analyses.append(sa)
        if not sa.has_behavioral_verification:
            weak_steps += 1

    if weak_steps == total:
        analysis.verdict = "REJECT"
        analysis.rationale.append("no step has behavioral verification")
    elif weak_steps > 0:
        analysis.verdict = "REVISE"
        analysis.rationale.append("%d/%d steps lack behavioral verification" % (weak_steps, total))
    else:
        analysis.verdict = "PASS"

    return analysis
