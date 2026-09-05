"""Safe discovery and addressing of active Plan Auditor plans."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class PlanNameError(ValueError):
    pass


@dataclass(frozen=True)
class PlanRef:
    name: str
    path: Path

    @property
    def key(self) -> str:
        return "default" if self.name == "default" else self.name


def validate_plan_name(name: str | None) -> str:
    if name in (None, "", "default"):
        return "default"
    value = str(name)
    if value in {".", ".."} or not PLAN_NAME_RE.fullmatch(value):
        raise PlanNameError(
            "plan name must match [A-Za-z0-9][A-Za-z0-9._-]{0,127} and cannot be '.' or '..'"
        )
    if "/" in value or "\\" in value:
        raise PlanNameError("plan name cannot contain path separators")
    return value


def plan_path(root: str | Path, name: str | None = None) -> Path:
    workspace = Path(root).resolve()
    safe = validate_plan_name(name)
    if safe == "default":
        return workspace / ".plan-auditor" / "plan.json"
    path = workspace / ".plan-auditor" / "plans" / f"{safe}.json"
    resolved = path.resolve()
    plans_root = (workspace / ".plan-auditor" / "plans").resolve()
    try:
        resolved.relative_to(plans_root)
    except ValueError as exc:
        raise PlanNameError("plan path escapes .plan-auditor/plans") from exc
    return resolved


def seal_path(root: str | Path, name: str | None = None) -> Path:
    workspace = Path(root).resolve()
    safe = validate_plan_name(name)
    if safe == "default":
        return workspace / ".plan-auditor" / "seal.json"
    return workspace / ".plan-auditor" / "seals" / f"{safe}.json"


def iter_plan_refs(root: str | Path) -> Iterator[PlanRef]:
    workspace = Path(root).resolve()
    default = plan_path(workspace)
    if default.is_file():
        yield PlanRef("default", default)
    directory = workspace / ".plan-auditor" / "plans"
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.json")):
        try:
            name = validate_plan_name(path.stem)
        except PlanNameError:
            continue
        yield PlanRef(name, path.resolve())


def load_plan_ref(ref: PlanRef) -> dict[str, Any]:
    value = json.loads(ref.path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"plan root must be an object: {ref.path}")
    return value


def all_plan_refs(root: str | Path) -> list[PlanRef]:
    return list(iter_plan_refs(root))
