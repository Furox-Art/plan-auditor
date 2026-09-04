"""L3 — MYCIN / expert-system inspired policy engine.

Deterministic IF/THEN rules. Fail-closed. Testable, versionable.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any
import re


@dataclass
class RuleResult:
    rule_id: str
    triggered: bool
    level: int
    detail: str = ""
    evidence: str = ""


# Each rule is a plain callable: (context) -> RuleResult
RuleFn = Callable[[Dict[str, Any]], RuleResult]


@dataclass
class PolicyRule:
    rule_id: str
    level: int
    question: str
    fn: RuleFn


class PolicyEngine:
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = rules or []

    def add(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate(self, context: Dict[str, Any]) -> List[RuleResult]:
        return [r.fn(context) for r in self.rules]

    def failures(self, context: Dict[str, Any]) -> List[RuleResult]:
        return [r for r in self.evaluate(context) if r.triggered]


def _has_pending(state: Dict) -> bool:
    for step in state.get("plan_steps", []):
        if step.get("status") != "verified":
            return True
    return False


def _has_failed_test(state: Dict) -> bool:
    for step in state.get("plan_steps", []):
        for check in step.get("results", []):
            if check.get("passed") is False:
                return True
    return False


def _seal_intact(state: Dict) -> bool:
    return state.get("seal_hash") == state.get("current_hash")


def _secret_in_log(state: Dict) -> Optional[str]:
    patterns = [r"(api[_-]?key|token|password|secret)\s*[:=]\s*\S+"]
    for log in state.get("logs", []):
        for pat in patterns:
            m = re.search(pat, str(log), re.I)
            if m:
                return m.group(0)
    return None


# Default built-in policy rules.
def required_tests_passing(ctx: Dict) -> RuleResult:
    return RuleResult(
        rule_id="REQ_TESTS_PASS",
        level=2,
        triggered=_has_failed_test(ctx),
        detail="A required test failed" if _has_failed_test(ctx) else "",
    )


def no_pending_steps(ctx: Dict) -> RuleResult:
    return RuleResult(
        rule_id="NO_PENDING",
        level=2,
        triggered=_has_pending(ctx),
        detail="Plan has steps not marked verified" if _has_pending(ctx) else "",
    )


def seal_not_violated(ctx: Dict) -> RuleResult:
    intact = _seal_intact(ctx)
    return RuleResult(
        rule_id="SEAL_INTACT",
        level=1,
        triggered=not intact,
        detail="Sealed plan hash mismatch (criteria weakened?)" if not intact else "",
    )


def no_secret_leak(ctx: Dict) -> RuleResult:
    hit = _secret_in_log(ctx)
    return RuleResult(
        rule_id="NO_SECRET_LEAK",
        level=3,
        triggered=hit is not None,
        detail="Possible secret in logs" if hit else "",
        evidence=hit or "",
    )


def evidence_chain_valid(ctx: Dict) -> RuleResult:
    return RuleResult(
        rule_id="EVIDENCE_VALID",
        level=2,
        triggered=not ctx.get("evidence_valid", True),
        detail="Evidence integrity check failed" if not ctx.get("evidence_valid") else "",
    )


def required_tool_present(ctx: Dict) -> RuleResult:
    missing = ctx.get("missing_required_tools", [])
    return RuleResult(
        rule_id="TOOLS_PRESENT",
        level=2,
        triggered=bool(missing),
        detail="Missing required tools: %s" % ", ".join(missing) if missing else "",
    )


DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule("REQ_TESTS_PASS", 2, "Do all required tests pass?", required_tests_passing),
    PolicyRule("NO_PENDING", 2, "Are all plan steps verified?", no_pending_steps),
    PolicyRule("SEAL_INTACT", 1, "Is the sealed plan intact?", seal_not_violated),
    PolicyRule("NO_SECRET_LEAK", 3, "Any secret leaked to logs?", no_secret_leak),
    PolicyRule("EVIDENCE_VALID", 2, "Is the evidence chain valid?", evidence_chain_valid),
    PolicyRule("TOOLS_PRESENT", 2, "Are required tools present?", required_tool_present),
]


def default_engine() -> PolicyEngine:
    return PolicyEngine(list(DEFAULT_RULES))


def load_policy_rules_from_dir(dirpath: str) -> List[PolicyRule]:
    """Placeholder for user-defined policy loading from .toml files."""
    return []
