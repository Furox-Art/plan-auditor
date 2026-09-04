"""L13 — Completion Gate.

The ONLY component that emits final PASS / FAIL / UNKNOWN. Aggregates
the deterministic core, policy engine, subsumption priority, sealing, and
(optionally) adversarial findings. Platforms with a blocking hook can
physically block completion; others record a BLOCKED supervisor state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .policies import PolicyEngine, RuleResult
from .priority import PriorityVerdict, resolve_priority
from .sealing import MonotonicCheck


@dataclass
class CompletionReport:
    outcome: str                       # PASS | FAIL | UNKNOWN
    deterministic_passed: bool
    pending_steps: List[int]
    policy_findings: List[RuleResult]
    verdict: PriorityVerdict
    seal_check: Optional[MonotonicCheck]
    adversarial_findings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "outcome": self.outcome,
            "deterministic_passed": self.deterministic_passed,
            "pending_steps": self.pending_steps,
            "policy_findings": [{"rule": r.rule_id, "level": r.level, "detail": r.detail}
                                for r in self.policy_findings],
            "verdict": {
                "outcome": self.verdict.outcome,
                "blocking_level": self.verdict.blocking_level,
                "blocking_detail": self.verdict.blocking_detail,
            },
            "seal_ok": self.seal_check.ok if self.seal_check else True,
            "seal_violations": self.seal_check.violations if self.seal_check else [],
            "adversarial_findings": self.adversarial_findings,
        }


class CompletionGate:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def evaluate(
        self,
        deterministic_passed: bool,
        pending_steps: List[int],
        workspace_context: Dict,
        seal_check: Optional[MonotonicCheck] = None,
        adversarial_findings: Optional[List[str]] = None,
    ) -> CompletionReport:
        findings = self.policy.failures(workspace_context)
        verdict = resolve_priority(findings)

        notes: List[str] = []
        outcome = "PASS"

        if pending_steps:
            outcome = "FAIL"
            notes.append(f"pending steps: {pending_steps}")
        if not deterministic_passed:
            outcome = "FAIL"
            notes.append("deterministic core reported failure")
        if verdict.outcome == "FAIL":
            outcome = "FAIL"
            notes.append(f"policy level {verdict.blocking_level}: {verdict.blocking_detail}")
        elif verdict.outcome == "UNKNOWN" and outcome == "PASS":
            outcome = "UNKNOWN"
            notes.append(f"policy level {verdict.blocking_level}: {verdict.blocking_detail}")
        if seal_check and not seal_check.ok:
            outcome = "FAIL"
            notes.append(f"seal violated: {seal_check.violations}")

        return CompletionReport(
            outcome=outcome,
            deterministic_passed=deterministic_passed,
            pending_steps=pending_steps,
            policy_findings=findings,
            verdict=verdict,
            seal_check=seal_check,
            adversarial_findings=adversarial_findings or [],
            notes=notes,
        )
