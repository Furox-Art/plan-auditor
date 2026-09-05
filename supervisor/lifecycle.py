"""L6 — Soar-like task lifecycle / state engine.

Deterministic state machine for the task lifecycle with operators and
guarded transitions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set


class States(str, Enum):
    NEW = "new"
    DISCOVERED = "discovered"
    ANALYZING = "analyzing"
    REQUIREMENTS_READY = "requirements_ready"
    PLAN_PROPOSED = "plan_proposed"
    PLAN_REVIEW = "plan_review"
    REVISION_REQUIRED = "revision_required"
    PLAN_APPROVED = "plan_approved"
    SEALED = "sealed"
    IMPLEMENTING = "implementing"
    VERIFYING = "verifying"
    RETRYING = "retrying"
    ESCALATED = "escalated"
    FINAL_AUDIT = "final_audit"
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    RECOVERY = "recovery"
    CANCELLED = "cancelled"


# Allowed transitions per state.
_TRANSITIONS: Dict[str, Set[str]] = {
    States.NEW: {States.DISCOVERED, States.CANCELLED},
    States.DISCOVERED: {States.ANALYZING, States.CANCELLED},
    States.ANALYZING: {States.REQUIREMENTS_READY, States.FAILED, States.CANCELLED},
    States.REQUIREMENTS_READY: {States.PLAN_PROPOSED, States.FAILED, States.CANCELLED},
    States.PLAN_PROPOSED: {States.PLAN_REVIEW, States.CANCELLED},
    States.PLAN_REVIEW: {States.PLAN_APPROVED, States.REVISION_REQUIRED, States.FAILED, States.CANCELLED},
    States.REVISION_REQUIRED: {States.PLAN_PROPOSED, States.ESCALATED, States.CANCELLED},
    States.PLAN_APPROVED: {States.SEALED, States.CANCELLED},
    States.SEALED: {States.IMPLEMENTING, States.CANCELLED},
    States.IMPLEMENTING: {States.VERIFYING, States.RETRYING, States.FAILED, States.CANCELLED},
    States.VERIFYING: {States.PASSED, States.RETRYING, States.FAILED, States.FINAL_AUDIT, States.CANCELLED},
    States.RETRYING: {States.IMPLEMENTING, States.ESCALATED, States.FAILED, States.CANCELLED},
    States.ESCALATED: {States.FAILED, States.RECOVERY, States.CANCELLED},
    States.FINAL_AUDIT: {States.PASSED, States.FAILED, States.UNKNOWN, States.CANCELLED},
    States.RECOVERY: {States.IMPLEMENTING, States.FAILED, States.CANCELLED},
    States.PASSED: set(),
    States.FAILED: set(),
    States.UNKNOWN: {States.RECOVERY, States.FAILED, States.CANCELLED},
    States.CANCELLED: set(),
}


@dataclass
class TransitionRecord:
    frm: str
    to: str
    operator: str
    note: str = ""


@dataclass
class TaskLifecycle:
    task_id: str
    state: str = States.NEW
    history: List[TransitionRecord] = field(default_factory=list)
    rejected_plans: int = 0
    retries: int = 0
    metadata: Dict = field(default_factory=dict)

    def can_transition(self, to: str) -> bool:
        return to in _TRANSITIONS.get(self.state, set())

    def transition(self, to: str, operator: str = "operator", note: str = "") -> bool:
        if not self.can_transition(to):
            return False
        record = TransitionRecord(frm=self.state, to=to, operator=operator, note=note)
        self.history.append(record)
        self.state = to
        if to == States.RETRYING:
            self.retries += 1
        if to == States.REVISION_REQUIRED:
            self.rejected_plans += 1
        return True

    def terminal(self) -> bool:
        # UNKNOWN is explicitly recoverable (UNKNOWN -> RECOVERY/FAILED/CANCELLED),
        # so it cannot simultaneously be a terminal state.
        return self.state in {States.PASSED, States.FAILED, States.CANCELLED}

    def progress_fraction(self) -> float:
        ordered = [
            States.NEW, States.DISCOVERED, States.ANALYZING,
            States.REQUIREMENTS_READY, States.PLAN_PROPOSED, States.PLAN_REVIEW,
            States.PLAN_APPROVED, States.SEALED, States.IMPLEMENTING,
            States.VERIFYING, States.FINAL_AUDIT, States.PASSED,
        ]
        if self.state in {States.FAILED, States.CANCELLED}:
            return 0.0
        if self.state == States.PASSED:
            return 1.0
        try:
            return ordered.index(self.state) / (len(ordered) - 1)
        except ValueError:
            return 0.5
