"""L8 — Plan sealing + monotonic verification.

Once a plan is approved, it is canonicalized, hashed, and sealed. After
sealing, criteria may only be *tightened* (new checks, stricter
thresholds), never weakened (removed checks, relaxed criteria, disabled
tests).
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def canonical_plan(plan: Dict) -> str:
    """Stable, sorted-JSON serialization for hashing."""
    return json.dumps(plan, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def plan_hash(plan: Dict) -> str:
    return hashlib.sha256(canonical_plan(plan).encode("utf-8")).hexdigest()


@dataclass
class Seal:
    plan_id: str
    sealed_at: str
    plan_hash: str
    criteria_count: int
    steps: List[Dict]

    def to_dict(self) -> Dict:
        return {
            "plan_id": self.plan_id,
            "sealed_at": self.sealed_at,
            "plan_hash": self.plan_hash,
            "criteria_count": self.criteria_count,
            "steps": self.steps,
        }


def seal_plan(plan: Dict, plan_id: str, sealed_at: str) -> Seal:
    criteria_count = sum(len(s.get("verify", [])) for s in plan.get("steps", []))
    return Seal(
        plan_id=plan_id,
        sealed_at=sealed_at,
        plan_hash=plan_hash(plan),
        criteria_count=criteria_count,
        steps=[{"id": s.get("id"), "verify_count": len(s.get("verify", []))}
               for s in plan.get("steps", [])],
    )


@dataclass
class MonotonicCheck:
    ok: bool
    violations: List[str]
    improvements: List[str]


_WEAK_TYPES = {"file_exists", "regex"}


def _weakness_score(checks: list) -> int:
    """Lower score = weaker verification. run/pytest/exec = 2, weak = 0."""
    score = 0
    for c in checks:
        if not isinstance(c, dict):
            continue
        if c.get("type") in ("run", "pytest", "exec"):
            score += 2
    return score


def check_monotonic(before: Dict, after: Dict) -> MonotonicCheck:
    """Return OK iff `after` only tightens / extends `before`."""
    violations: List[str] = []
    improvements: List[str] = []

    before_steps = {s.get("id"): s for s in before.get("steps", [])}
    after_steps = {s.get("id"): s for s in after.get("steps", [])}

    for sid, step in before_steps.items():
        if sid not in after_steps:
            violations.append("step %s removed after seal" % sid)
            continue
        before_checks = [c for c in step.get("verify", []) if isinstance(c, dict)]
        after_checks = [c for c in after_steps[sid].get("verify", []) if isinstance(c, dict)]
        if len(after_checks) < len(before_checks):
            violations.append("step %s: verification count reduced (%d -> %d)" % (
                sid, len(before_checks), len(after_checks)))
        elif len(after_checks) > len(before_checks):
            improvements.append("step %s: verification count increased (%d -> %d)" % (
                sid, len(before_checks), len(after_checks)))
        else:
            before_score = _weakness_score(before_checks)
            after_score = _weakness_score(after_checks)
            if after_score < before_score:
                violations.append("step %s: verification strength reduced" % sid)
            elif after_score > before_score:
                improvements.append("step %s: verification strength increased" % sid)

    for key in ("task", "requirements"):
        if before.get(key) and not after.get(key):
            violations.append("plan field '%s' removed after seal" % key)

    return MonotonicCheck(ok=not violations, violations=violations, improvements=improvements)


def load_seal(path: str) -> Optional[Seal]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return Seal(
        plan_id=data.get("plan_id", ""),
        sealed_at=data.get("sealed_at", ""),
        plan_hash=data.get("plan_hash", ""),
        criteria_count=data.get("criteria_count", 0),
        steps=data.get("steps", []),
    )


def save_seal(seal: Seal, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".tmp"
    Path(tmp).write_text(json.dumps(seal.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp, path)
