from __future__ import annotations

import json
from pathlib import Path

from supervisor.request_contract import activation_path, initialize_request, request_path


def activate_for_plan(root: Path, plan: dict) -> None:
    if request_path(root).exists() or activation_path(root).exists():
        return
    requirements = []
    for req in plan.get("requirements", []) if isinstance(plan, dict) else []:
        if not isinstance(req, dict):
            continue
        rid = req.get("id")
        checks = []
        for step in plan.get("steps", []):
            if isinstance(step, dict) and rid in (step.get("covers") or []):
                checks.extend(check for check in step.get("verify", []) if isinstance(check, dict))
        item = dict(req)
        if str(item.get("priority", "must")).lower() in {"must", "should"}:
            item["acceptance_checks"] = checks
        requirements.append(item)
    if not requirements:
        first = next((step for step in plan.get("steps", []) if isinstance(step, dict)), None)
        if first is None:
            raise ValueError("cannot activate request fixture without a plan step")
        checks = [check for check in first.get("verify", []) if isinstance(check, dict)]
        requirements = [{
            "id": "REQ-FIXTURE",
            "description": "exercise fixture behavior",
            "priority": "must",
            "acceptance_checks": checks,
        }]
        plan.setdefault("requirements", []).append({
            "id": "REQ-FIXTURE", "description": "exercise fixture behavior", "priority": "must"
        })
        first.setdefault("covers", []).append("REQ-FIXTURE")
        pg = root / ".plan-auditor"
        if (pg / "plan.json").is_file():
            (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    initialize_request(root, {
        "format_version": 1,
        "task": str(plan.get("task", "fixture request")),
        "requirements": requirements,
    })
