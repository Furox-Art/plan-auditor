"""Safe discovery and addressing of active Plan Auditor plans."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .control_plane import ControlPlanePathError, confined_workspace_path

PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

#: The plan is the input being verified, so it is untrusted. Without a byte bound
#: a host that passes a plan through to this tool can make it allocate the whole
#: file before a single validation rule runs, which turns a plan-size check into
#: an out-of-memory denial of service instead of a verdict. 2 MiB is far above
#: any plan a real task needs and far below what breaks the process.
MAX_PLAN_BYTES = 2_000_000


class PlanNameError(ValueError):
    pass


def _unique_plan_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError(f"duplicate plan JSON key: {key}")
        values[key] = value
    return values


def _reject_plan_constant(value: str) -> None:
    raise ValueError(f"non-standard plan JSON constant: {value}")


def _finite_plan_float(source: str) -> float:
    number = float(source)
    if not math.isfinite(number):
        raise ValueError("non-finite plan JSON number")
    return number


class PlanSizeError(PlanNameError):
    """Raised when a plan file exceeds the byte bound.

    A ``ValueError`` subclass, matching ``PlanNameError``: call sites already
    treat both as "this plan is unusable input", and the difference is only which
    rule rejected it.
    """


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


def _confined(root: str | Path, relative: str, *, directory: bool = False) -> Path:
    try:
        return confined_workspace_path(root, relative, require_directory=directory)
    except ControlPlanePathError as exc:
        raise PlanNameError(str(exc)) from exc


def plan_path(root: str | Path, name: str | None = None) -> Path:
    safe = validate_plan_name(name)
    if safe == "default":
        return _confined(root, ".plan-auditor/plan.json")
    _confined(root, ".plan-auditor/plans", directory=True)
    return _confined(root, f".plan-auditor/plans/{safe}.json")


def seal_path(root: str | Path, name: str | None = None) -> Path:
    safe = validate_plan_name(name)
    if safe == "default":
        return _confined(root, ".plan-auditor/seal.json")
    _confined(root, ".plan-auditor/seals", directory=True)
    return _confined(root, f".plan-auditor/seals/{safe}.json")


def iter_plan_refs(root: str | Path) -> Iterator[PlanRef]:
    default = plan_path(root)
    if default.exists():
        # ``plan_path`` already rejected symlinked components/leaf.  A directory
        # named plan.json is invalid state rather than an absent plan.
        if not default.is_file():
            raise PlanNameError(f"default plan is not a regular file: {default}")
        yield PlanRef("default", default)

    directory = _confined(root, ".plan-auditor/plans", directory=True)
    if not directory.exists():
        return
    if not directory.is_dir():
        raise PlanNameError(f"named plan directory is not a directory: {directory}")

    for path in sorted(directory.iterdir()):
        if path.suffix.lower() != ".json":
            continue
        if path.is_symlink():
            raise PlanNameError(f"named plan entry is a symlink: {path}")
        try:
            name = validate_plan_name(path.stem)
        except PlanNameError:
            # Unsafe plan-like files are blocking state; silently skipping them
            # could hide an unfinished plan from aggregate completion.
            raise
        safe_path = plan_path(root, name)
        if not safe_path.is_file():
            raise PlanNameError(f"named plan is not a regular file: {safe_path}")
        yield PlanRef(name, safe_path)


def load_plan_ref(ref: PlanRef) -> dict[str, Any]:
    if ref.path.is_symlink() or not ref.path.is_file():
        raise ValueError(f"plan path is not a safe regular file: {ref.path}")
    # Bound the read itself. Checking the size before reading is what keeps a
    # hostile plan from being loaded into memory at all; checking afterwards
    # would only bound the verdict, not the allocation.
    size = ref.path.stat().st_size
    if size > MAX_PLAN_BYTES:
        raise PlanSizeError(
            f"plan {ref.key!r} is {size} bytes, over the {MAX_PLAN_BYTES}-byte "
            "bound; shrink the plan or split it into named plans "
            f"({ref.path})"
        )
    value = json.loads(
        ref.path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_plan_keys,
        parse_float=_finite_plan_float,
        parse_constant=_reject_plan_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"plan root must be an object: {ref.path}")
    return value


def all_plan_refs(root: str | Path) -> list[PlanRef]:
    return list(iter_plan_refs(root))
