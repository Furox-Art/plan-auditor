"""L8 — plan sealing and monotonic verification.

A sealed verification check may never disappear or be edited in place. New
checks may be appended, which gives a simple fail-closed monotonic rule that is
easy to audit and does not rely on subjective notions of "stricter".
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


def canonical_plan(plan: Dict) -> str:
    return json.dumps(plan, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def plan_hash(plan: Dict) -> str:
    return hashlib.sha256(canonical_plan(plan).encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass
class Seal:
    plan_id: str
    sealed_at: str
    plan_hash: str
    criteria_count: int
    steps: List[Dict]
    task: Any = None
    requirements: Any = None
    format_version: int = 2

    def to_dict(self) -> Dict:
        return {
            "format_version": self.format_version,
            "plan_id": self.plan_id,
            "sealed_at": self.sealed_at,
            "plan_hash": self.plan_hash,
            "criteria_count": self.criteria_count,
            "task": copy.deepcopy(self.task),
            "requirements": copy.deepcopy(self.requirements),
            "steps": copy.deepcopy(self.steps),
        }

    def as_plan(self) -> Dict:
        return {
            "task": copy.deepcopy(self.task),
            "requirements": copy.deepcopy(self.requirements),
            "steps": copy.deepcopy(self.steps),
        }


def seal_plan(plan: Dict, plan_id: str, sealed_at: str) -> Seal:
    criteria_count = sum(len(s.get("verify", [])) for s in plan.get("steps", []))
    return Seal(
        plan_id=plan_id,
        sealed_at=sealed_at,
        plan_hash=plan_hash(plan),
        criteria_count=criteria_count,
        task=copy.deepcopy(plan.get("task")),
        requirements=copy.deepcopy(plan.get("requirements")),
        steps=[
            {
                "id": s.get("id"),
                "verify": copy.deepcopy(
                    [c for c in s.get("verify", []) if isinstance(c, dict)]
                ),
            }
            for s in plan.get("steps", [])
        ],
    )


@dataclass
class MonotonicCheck:
    ok: bool
    violations: List[str]
    improvements: List[str]


def check_monotonic(before: Dict, after: Dict) -> MonotonicCheck:
    """Verify that sealed criteria are preserved exactly and only extended."""
    violations: List[str] = []
    improvements: List[str] = []

    before_steps = {s.get("id"): s for s in before.get("steps", []) if isinstance(s, dict)}
    after_steps = {s.get("id"): s for s in after.get("steps", []) if isinstance(s, dict)}

    for sid, step in before_steps.items():
        if sid not in after_steps:
            violations.append(f"step {sid} removed after seal")
            continue

        # Legacy v1 seals stored only verify_count. They cannot prove check identity.
        if "verify" not in step and "verify_count" in step:
            expected = int(step.get("verify_count", 0))
            actual = len(after_steps[sid].get("verify", []))
            if actual < expected:
                violations.append(
                    f"step {sid}: verification count reduced ({expected} -> {actual})"
                )
            else:
                violations.append(
                    f"step {sid}: legacy seal lacks check contents; explicit reseal required"
                )
            continue

        before_checks = [c for c in step.get("verify", []) if isinstance(c, dict)]
        after_checks = [c for c in after_steps[sid].get("verify", []) if isinstance(c, dict)]
        remaining = [_canonical(c) for c in after_checks]

        for check in before_checks:
            encoded = _canonical(check)
            try:
                remaining.remove(encoded)
            except ValueError:
                violations.append(
                    f"step {sid}: verification reduced; sealed check removed or modified: {encoded}"
                )

        if len(after_checks) > len(before_checks):
            improvements.append(
                f"step {sid}: verification count increased "
                f"({len(before_checks)} -> {len(after_checks)})"
            )

    if before.get("task") is not None and before.get("task") != after.get("task"):
        violations.append("plan field 'task' changed after seal")

    before_req = before.get("requirements")
    after_req = after.get("requirements")
    if before_req is not None:
        if isinstance(before_req, list) and isinstance(after_req, list):
            after_encoded = {_canonical(item) for item in after_req}
            for item in before_req:
                if _canonical(item) not in after_encoded:
                    violations.append("a sealed requirement was removed or modified")
                    break
            if len(after_req) > len(before_req):
                improvements.append(
                    f"requirements increased ({len(before_req)} -> {len(after_req)})"
                )
        elif before_req != after_req:
            violations.append("plan field 'requirements' changed after seal")

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
        criteria_count=int(data.get("criteria_count", 0)),
        task=copy.deepcopy(data.get("task")),
        requirements=copy.deepcopy(data.get("requirements")),
        steps=copy.deepcopy(data.get("steps", [])),
        format_version=int(data.get("format_version", 1)),
    )


def save_seal(seal: Seal, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".tmp"
    Path(tmp).write_text(
        json.dumps(seal.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, path)
