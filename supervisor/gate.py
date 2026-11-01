"""L13 — Completion Gate.

The gate is the only component that emits PASS / FAIL / UNKNOWN. It aggregates
fresh deterministic evidence, policy findings, seal integrity, and optional
adversarial review. Semantic review can never create PASS; high-severity
findings force UNKNOWN until converted into deterministic checks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policies import PolicyEngine, RuleResult
from .priority import PriorityVerdict, resolve_priority
from .sealing import MonotonicCheck


@dataclass
class TrafficCheck:
    """The outbound-traffic evidence reduced for the completion gate.

    ``required`` is false only when the sealed plan does not declare a traffic
    contract. Once a plan opts in, any unverifiable, incomplete, silent or
    out-of-scope run makes completion impossible; the gate never treats a
    missing observation as a clean one.
    """

    required: bool
    ok: bool
    outcome: str
    reason: str
    requests: int = 0
    classes: dict[str, int] = field(default_factory=dict)
    violations: list[dict[str, Any]] = field(default_factory=list)
    authenticated: bool = False
    sessions: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "ok": self.ok,
            "outcome": self.outcome,
            "reason": self.reason,
            "requests": self.requests,
            "classes": dict(self.classes),
            "violations": list(self.violations),
            "authenticated": self.authenticated,
            "sessions": list(self.sessions),
        }


@dataclass
class CompletionReport:
    outcome: str
    deterministic_passed: bool
    pending_steps: List[int]
    policy_findings: List[RuleResult]
    verdict: PriorityVerdict
    seal_check: Optional[MonotonicCheck]
    adversarial_findings: List[Dict[str, str]] = field(default_factory=list)
    traffic_check: TrafficCheck | None = None
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "outcome": self.outcome,
            "deterministic_passed": self.deterministic_passed,
            "pending_steps": self.pending_steps,
            "policy_findings": [
                {"rule": r.rule_id, "level": r.level, "detail": r.detail, "evidence": r.evidence}
                for r in self.policy_findings
            ],
            "verdict": {
                "outcome": self.verdict.outcome,
                "blocking_level": self.verdict.blocking_level,
                "blocking_detail": self.verdict.blocking_detail,
            },
            "seal_ok": self.seal_check.ok if self.seal_check else None,
            "seal_violations": self.seal_check.violations if self.seal_check else [],
            "traffic": self.traffic_check.as_dict() if self.traffic_check else None,
            "adversarial_findings": self.adversarial_findings,
            "notes": self.notes,
        }


def _normalize_adversarial(findings: Optional[List[Any]]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for item in findings or []:
        if isinstance(item, dict):
            out.append({
                "severity": str(item.get("severity", "warn")).lower(),
                "description": str(item.get("description", item)),
            })
        else:
            out.append({
                "severity": str(getattr(item, "severity", "warn")).lower(),
                "description": str(getattr(item, "description", item)),
            })
    return out


class CompletionGate:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def evaluate(
        self,
        deterministic_passed: bool,
        pending_steps: List[int],
        workspace_context: Dict,
        seal_check: Optional[MonotonicCheck] = None,
        adversarial_findings: Optional[List[Any]] = None,
        traffic_check: TrafficCheck | None = None,
    ) -> CompletionReport:
        findings = self.policy.failures(workspace_context)
        verdict = resolve_priority(findings)
        adversarial = _normalize_adversarial(adversarial_findings)

        notes: List[str] = []
        outcome = "PASS"

        if pending_steps:
            outcome = "FAIL"
            notes.append(f"pending steps: {pending_steps}")
        if not deterministic_passed:
            outcome = "FAIL"
            notes.append("no fresh deterministic full-audit proof for the current plan")
        if verdict.outcome == "FAIL":
            outcome = "FAIL"
            notes.append(f"policy level {verdict.blocking_level}: {verdict.blocking_detail}")
        elif verdict.outcome == "UNKNOWN" and outcome == "PASS":
            outcome = "UNKNOWN"
            notes.append(f"policy level {verdict.blocking_level}: {verdict.blocking_detail}")
        if seal_check is not None and not seal_check.ok:
            outcome = "FAIL"
            notes.append(f"seal violated: {seal_check.violations}")
        if traffic_check is not None and traffic_check.required and not traffic_check.ok:
            outcome = "FAIL"
            notes.append(f"outbound traffic gate: {traffic_check.reason}")

        # L12 has no authority to turn anything into PASS/FAIL. However a high
        # semantic finding means the system lacks a deterministic check for a
        # material concern, so PASS is withheld until that check is added/run.
        blocking_semantic = [
            f for f in adversarial if f.get("severity") in {"high", "critical"}
        ]
        if blocking_semantic and outcome == "PASS":
            outcome = "UNKNOWN"
            notes.append("adversarial review requires deterministic follow-up checks")

        return CompletionReport(
            outcome=outcome,
            deterministic_passed=deterministic_passed,
            pending_steps=pending_steps,
            policy_findings=findings,
            verdict=verdict,
            seal_check=seal_check,
            adversarial_findings=adversarial,
            traffic_check=traffic_check,
            notes=notes,
        )
