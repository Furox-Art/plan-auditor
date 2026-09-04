"""L4 — BDI-inspired goal model.

Beliefs / Desires / Intention state container. Drives audit ordering
and tracks progress toward user goals. Does NOT verify by itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class Beliefs:
    repository_state: Dict = field(default_factory=dict)
    requirements: List[Dict] = field(default_factory=list)
    existing_evidence: List[Dict] = field(default_factory=list)
    test_results: List[Dict] = field(default_factory=list)
    environment: Dict = field(default_factory=dict)
    failures: List[Dict] = field(default_factory=list)
    agent_state: Dict = field(default_factory=dict)
    tool_availability: Dict = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "n_requirements": len(self.requirements),
            "n_evidence": len(self.existing_evidence),
            "n_failures": len(self.failures),
            "tools": {k: v for k, v in self.tool_availability.items() if v},
        }


@dataclass
class Desires:
    user_goals: List[str] = field(default_factory=list)
    mandatory_criteria: List[str] = field(default_factory=list)
    security_goals: List[str] = field(default_factory=lambda: [
        "no secret leakage", "no arbitrary code execution", "monotonic verification",
    ])
    required_outcomes: List[str] = field(default_factory=list)


@dataclass
class Intentions:
    verification_steps: List[Dict] = field(default_factory=list)
    active_strategy: str = "exhaustive"   # exhaustive | targeted | recovery
    audit_order: List[str] = field(default_factory=list)


@dataclass
class GoalModel:
    beliefs: Beliefs = field(default_factory=Beliefs)
    desires: Desires = field(default_factory=Desires)
    intentions: Intentions = field(default_factory=Intentions)

    def next_intention(self) -> Dict:
        if self.intentions.verification_steps:
            return self.intentions.verification_steps.pop(0)
        return {"action": "final_audit"}

    def has_open_intentions(self) -> bool:
        return len(self.intentions.verification_steps) > 0
