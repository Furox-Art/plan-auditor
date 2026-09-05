"""Deterministic requirement-to-step coverage for supervisor PASS decisions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CoverageResult:
    valid: bool
    required_ids: List[str] = field(default_factory=list)
    covered_ids: List[str] = field(default_factory=list)
    missing_ids: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    mapping: Dict[str, List[int]] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "required_ids": self.required_ids,
            "covered_ids": self.covered_ids,
            "missing_ids": self.missing_ids,
            "errors": self.errors,
            "mapping": self.mapping,
        }


def _requirements(plan: Dict[str, Any]) -> tuple[List[Dict[str, Any]], List[str]]:
    raw = plan.get("requirements")
    if not isinstance(raw, list) or not raw:
        return [], [
            "supervisor PASS requires explicit non-empty plan.requirements; "
            "free-form task text alone cannot prove requirement coverage"
        ]
    result: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw, 1):
        if isinstance(item, str):
            item = {"id": f"REQ-{index:03d}", "description": item, "priority": "must"}
        if not isinstance(item, dict):
            errors.append(f"requirement {index} must be an object or string")
            continue
        req_id = item.get("id")
        description = item.get("description")
        priority = str(item.get("priority", "must")).lower()
        if not isinstance(req_id, str) or not req_id.strip():
            errors.append(f"requirement {index} requires a non-empty id")
            continue
        req_id = req_id.strip()
        if req_id in seen:
            errors.append(f"duplicate requirement id: {req_id}")
            continue
        seen.add(req_id)
        if not isinstance(description, str) or not description.strip():
            errors.append(f"requirement {req_id} requires a non-empty description")
        if priority not in {"must", "should", "may"}:
            errors.append(f"requirement {req_id} has invalid priority {priority!r}")
        result.append({"id": req_id, "description": description, "priority": priority})
    return result, errors


def analyze_coverage(plan: Dict[str, Any]) -> CoverageResult:
    requirements, errors = _requirements(plan)
    required_ids = [
        item["id"] for item in requirements if item.get("priority") in {"must", "should"}
    ]
    known = {item["id"] for item in requirements}
    mapping: Dict[str, List[int]] = {req_id: [] for req_id in known}

    for step in plan.get("steps", []):
        if not isinstance(step, dict):
            continue
        sid = step.get("id")
        covers = step.get("covers", [])
        if covers is None:
            covers = []
        if not isinstance(covers, list):
            errors.append(f"step {sid} covers must be a list")
            continue
        seen_step: set[str] = set()
        for req_id in covers:
            if not isinstance(req_id, str) or not req_id.strip():
                errors.append(f"step {sid} covers contains an invalid requirement id")
                continue
            req_id = req_id.strip()
            if req_id in seen_step:
                errors.append(f"step {sid} repeats coverage for {req_id}")
                continue
            seen_step.add(req_id)
            if req_id not in known:
                errors.append(f"step {sid} covers unknown requirement {req_id}")
                continue
            if isinstance(sid, int):
                mapping.setdefault(req_id, []).append(sid)

    covered = sorted(req_id for req_id in required_ids if mapping.get(req_id))
    missing = sorted(req_id for req_id in required_ids if not mapping.get(req_id))
    if missing:
        errors.append("required requirements are not covered by any plan step: " + ", ".join(missing))
    return CoverageResult(
        valid=not errors,
        required_ids=required_ids,
        covered_ids=covered,
        missing_ids=missing,
        errors=errors,
        mapping={key: sorted(value) for key, value in sorted(mapping.items())},
    )
