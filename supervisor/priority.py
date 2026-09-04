"""L7 — Subsumption-inspired priority / safety layer.

Lower safety-critical layers outrank higher AI judgment. A failure at
priority level N cannot be overridden by a PASS from any level > N.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .policies import RuleResult


# Lower number = higher authority.
LEVEL_PROCESS_SAFETY = 0
LEVEL_PLAN_INTEGRITY = 1
LEVEL_DETERMINISTIC_VERIFICATION = 2
LEVEL_SECURITY_POLICY = 3
LEVEL_REQUIREMENT_COVERAGE = 4
LEVEL_AI_SEMANTIC_JUDGMENT = 5


@dataclass
class PriorityVerdict:
    outcome: str          # PASS | FAIL | UNKNOWN
    blocking_level: Optional[int] = None
    blocking_detail: str = ""
    contributing: Optional[List[Tuple[str, int, str]]] = None

    def __post_init__(self):
        if self.contributing is None:
            self.contributing = []


def resolve_priority(findings: List[RuleResult]) -> PriorityVerdict:
    """Given triggered policy findings, resolve the authoritative outcome.

    The lowest (most authoritative) triggered level wins. If anything at
    level <= 2 triggered, it is blocking regardless of higher-level PASS.
    """
    triggered = [f for f in findings if f.triggered]
    if not triggered:
        return PriorityVerdict(outcome="PASS")

    worst = min(triggered, key=lambda f: f.level)
    if worst.level <= LEVEL_SECURITY_POLICY:
        return PriorityVerdict(
            outcome="FAIL",
            blocking_level=worst.level,
            blocking_detail=worst.detail,
            contributing=[(f.rule_id, f.level, f.detail) for f in triggered],
        )
    # Levels 4-5 (requirement coverage, AI judgment): report but allow
    # escalation rather than hard FAIL unless explicitly security.
    return PriorityVerdict(
        outcome="UNKNOWN" if worst.level == LEVEL_REQUIREMENT_COVERAGE else "FAIL",
        blocking_level=worst.level,
        blocking_detail=worst.detail,
        contributing=[(f.rule_id, f.level, f.detail) for f in triggered],
    )
