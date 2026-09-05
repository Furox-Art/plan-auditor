"""L8 — full plan-contract sealing, scope control, monotonic verification, and HMAC auth."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.plan_graph import PlanGraphError, effective_dependencies

from scripts.integrity import (
    IntegrityKeyError,
    KeyMaterial,
    SEAL_DOMAIN,
    make_auth,
    runtime_key,
    verify_auth,
)

from .control_plane import ControlPlanePathError, confined_workspace_path

SEAL_FORMAT_VERSION = 4


class SealIntegrityError(RuntimeError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _contract_step(step: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": step.get("id"),
        "title": copy.deepcopy(step.get("title")),
        "depends_on": copy.deepcopy(step.get("depends_on")),
        "requires_outputs": copy.deepcopy(step.get("requires_outputs", [])),
        "outputs": copy.deepcopy(step.get("outputs", [])),
        "covers": copy.deepcopy(step.get("covers", [])),
        "verify": copy.deepcopy([c for c in step.get("verify", []) if isinstance(c, dict)]),
    }


def _legacy_v3_contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Reproduce the exact v2.1.0/v3 seal hashing contract.

    v3 stored raw ``depends_on`` values. v4 canonicalizes the effective graph, so
    genuine legacy seals must be self-checked with the historical encoding before
    they can be migrated.
    """
    return {
        "task": copy.deepcopy(plan.get("task")),
        "requirements": copy.deepcopy(plan.get("requirements")),
        "required_tools": copy.deepcopy(plan.get("required_tools", [])),
        "steps": [
            _contract_step(step)
            for step in plan.get("steps", [])
            if isinstance(step, dict)
        ],
    }


def legacy_v3_plan_hash(plan: Dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical(_legacy_v3_contract_plan(plan)).encode("utf-8")
    ).hexdigest()


def contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    try:
        dependencies = effective_dependencies(plan)
    except PlanGraphError:
        dependencies = {}
    steps: List[Dict[str, Any]] = []
    for step in plan.get("steps", []):
        if not isinstance(step, dict):
            continue
        contracted = _contract_step(step)
        sid = step.get("id")
        if isinstance(sid, int) and sid in dependencies:
            contracted["depends_on"] = copy.deepcopy(dependencies[sid])
        steps.append(contracted)
    return {
        "task": copy.deepcopy(plan.get("task")),
        "requirements": copy.deepcopy(plan.get("requirements")),
        "required_tools": copy.deepcopy(plan.get("required_tools", [])),
        "steps": steps,
    }


def canonical_plan(plan: Dict) -> str:
    return _canonical(contract_plan(plan))


def plan_hash(plan: Dict) -> str:
    return hashlib.sha256(canonical_plan(plan).encode("utf-8")).hexdigest()


@dataclass
class Seal:
    plan_id: str
    sealed_at: str
    plan_hash: str
    criteria_count: int
    steps: List[Dict]
    task: Any = None
    requirements: Any = None
    required_tools: Any = None
    environment: Dict[str, Any] | None = None
    format_version: int = SEAL_FORMAT_VERSION
    auth: Optional[Dict[str, str]] = None

    def payload(self) -> Dict[str, Any]:
        return {
            "format_version": self.format_version,
            "plan_id": self.plan_id,
            "sealed_at": self.sealed_at,
            "plan_hash": self.plan_hash,
            "criteria_count": self.criteria_count,
            "task": copy.deepcopy(self.task),
            "requirements": copy.deepcopy(self.requirements),
            "required_tools": copy.deepcopy(self.required_tools),
            "environment": copy.deepcopy(self.environment or {}),
            "steps": copy.deepcopy(self.steps),
        }

    def to_dict(self) -> Dict[str, Any]:
        value = self.payload()
        if self.auth is not None:
            value["auth"] = copy.deepcopy(self.auth)
        return value

    def as_plan(self) -> Dict[str, Any]:
        return {
            "task": copy.deepcopy(self.task),
            "requirements": copy.deepcopy(self.requirements),
            "required_tools": copy.deepcopy(self.required_tools or []),
            "steps": copy.deepcopy(self.steps),
        }


def _criteria_count(plan: Dict[str, Any]) -> int:
    total = 0
    for step in plan.get("steps", []):
        if not isinstance(step, dict):
            continue
        total += len([c for c in step.get("verify", []) if isinstance(c, dict)])
        for output in step.get("outputs", []) or []:
            if isinstance(output, dict):
                total += len([c for c in output.get("verify", []) or [] if isinstance(c, dict)])
    return total


def seal_plan(plan: Dict, plan_id: str, sealed_at: str,
              environment: Optional[Dict[str, Any]] = None) -> Seal:
    contracted = contract_plan(plan)
    return Seal(
        plan_id=plan_id,
        sealed_at=sealed_at,
        plan_hash=hashlib.sha256(_canonical(contracted).encode("utf-8")).hexdigest(),
        criteria_count=_criteria_count(contracted),
        task=copy.deepcopy(contracted.get("task")),
        requirements=copy.deepcopy(contracted.get("requirements")),
        required_tools=copy.deepcopy(contracted.get("required_tools", [])),
        environment=copy.deepcopy(environment or {}),
        steps=copy.deepcopy(contracted.get("steps", [])),
    )


@dataclass
class MonotonicCheck:
    ok: bool
    violations: List[str]
    improvements: List[str]


def _multiset_contains(before: List[Any], after: List[Any]) -> bool:
    remaining = [_canonical(item) for item in after]
    for item in before:
        encoded = _canonical(item)
        try:
            remaining.remove(encoded)
        except ValueError:
            return False
    return True


def _same_multiset(left: List[Any], right: List[Any]) -> bool:
    return len(left) == len(right) and _multiset_contains(left, right)


def _output_map(step: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for item in step.get("outputs", []) or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = item
    return result


def check_monotonic(before: Dict, after: Dict) -> MonotonicCheck:
    """Allow proof strengthening while freezing host-approved execution scope.

    Safe automatic strengthening is limited to extra deterministic verification
    checks, extra dependencies and extra required-output prerequisites. New
    steps, requirements, tools, coverage assignments or declared outputs change
    the execution/request scope and therefore require a new host-approved request
    generation rather than silently becoming the new seal baseline.
    """
    violations: List[str] = []
    improvements: List[str] = []

    before_steps_list = [s for s in before.get("steps", []) if isinstance(s, dict)]
    after_steps_list = [s for s in after.get("steps", []) if isinstance(s, dict)]
    before_ids = [s.get("id") for s in before_steps_list]
    after_ids = [s.get("id") for s in after_steps_list]
    if after_ids != before_ids:
        violations.append(
            "sealed step scope/order/identity changed; adding or removing steps requires a new host-approved request generation"
        )

    before_steps = {s.get("id"): s for s in before_steps_list}
    after_steps = {s.get("id"): s for s in after_steps_list}
    for sid, step in before_steps.items():
        current = after_steps.get(sid)
        if current is None:
            violations.append(f"step {sid} removed after seal")
            continue
        if step.get("title") != current.get("title"):
            violations.append(f"step {sid}: sealed title changed")

        before_checks = [c for c in step.get("verify", []) if isinstance(c, dict)]
        after_checks = [c for c in current.get("verify", []) if isinstance(c, dict)]
        if not _multiset_contains(before_checks, after_checks):
            violations.append(f"step {sid}: sealed verification check removed or modified")
        elif len(after_checks) > len(before_checks):
            improvements.append(f"step {sid}: verification checks increased")

        before_deps = list(step.get("depends_on") or [])
        after_deps = list(current.get("depends_on") or [])
        if not _multiset_contains(before_deps, after_deps):
            violations.append(f"step {sid}: sealed dependency removed or modified")
        elif len(after_deps) > len(before_deps):
            improvements.append(f"step {sid}: dependencies tightened")

        before_required = list(step.get("requires_outputs") or [])
        after_required = list(current.get("requires_outputs") or [])
        if not _multiset_contains(before_required, after_required):
            violations.append(f"step {sid}: sealed required output removed or modified")
        elif len(after_required) > len(before_required):
            improvements.append(f"step {sid}: required outputs increased")

        before_covers = list(step.get("covers") or [])
        after_covers = list(current.get("covers") or [])
        if not _same_multiset(before_covers, after_covers):
            violations.append(
                f"step {sid}: sealed requirement coverage changed; coverage scope requires host approval"
            )

        before_outputs = _output_map(step)
        after_outputs = _output_map(current)
        if set(after_outputs) != set(before_outputs):
            violations.append(
                f"step {sid}: declared output scope changed; adding/removing outputs requires host approval"
            )
        for name, output in before_outputs.items():
            now = after_outputs.get(name)
            if now is None:
                continue
            before_meta = {k: v for k, v in output.items() if k != "verify"}
            after_meta = {k: v for k, v in now.items() if k != "verify"}
            if before_meta != after_meta:
                violations.append(f"step {sid}: sealed output {name!r} metadata changed")
            before_output_checks = [c for c in output.get("verify", []) if isinstance(c, dict)]
            after_output_checks = [c for c in now.get("verify", []) if isinstance(c, dict)]
            if not _multiset_contains(before_output_checks, after_output_checks):
                violations.append(f"step {sid}: sealed output {name!r} verification weakened")
            elif len(after_output_checks) > len(before_output_checks):
                improvements.append(f"step {sid}: output {name!r} verification checks increased")

    if before.get("task") != after.get("task"):
        violations.append("plan field 'task' changed after seal")

    before_req = before.get("requirements")
    after_req = after.get("requirements")
    if isinstance(before_req, list) and isinstance(after_req, list):
        if not _same_multiset(before_req, after_req):
            violations.append(
                "sealed requirement scope changed; adding/removing/modifying requirements requires host approval"
            )
    elif before_req != after_req:
        violations.append("plan field 'requirements' changed after seal")

    before_tools = list(before.get("required_tools") or [])
    after_tools = list(after.get("required_tools") or [])
    if not _same_multiset(before_tools, after_tools):
        violations.append(
            "sealed required-tool scope changed; adding/removing tools requires host approval"
        )

    return MonotonicCheck(ok=not violations, violations=violations, improvements=improvements)


def check_environment(seal: Seal, current: Dict[str, Any]) -> MonotonicCheck:
    expected = seal.environment or {}
    if expected == current:
        return MonotonicCheck(True, [], [])
    return MonotonicCheck(
        False,
        [f"sealed supervisor environment changed: expected {expected!r}, current {current!r}"],
        [],
    )


def _workspace_from_seal(path: Path) -> Path:
    # Locate the lexical .plan-auditor component first; resolving the entire path
    # before doing so would let a symlinked control-plane parent redefine root.
    absolute = path.expanduser().absolute()
    parts = absolute.parts
    try:
        index = len(parts) - 1 - list(reversed(parts)).index(".plan-auditor")
    except ValueError as exc:
        raise SealIntegrityError(f"seal path is not under .plan-auditor: {absolute}") from exc
    workspace = Path(*parts[:index]).resolve()
    try:
        relative = absolute.relative_to(workspace)
        confined_workspace_path(workspace, relative)
    except (ValueError, ControlPlanePathError) as exc:
        raise SealIntegrityError(f"unsafe seal control-plane path: {absolute}: {exc}") from exc
    return workspace


def _parse_seal_data(data: Dict[str, Any]) -> Seal:
    try:
        criteria_count = int(data.get("criteria_count", 0))
        format_version = int(data.get("format_version", 1))
    except (TypeError, ValueError) as exc:
        raise SealIntegrityError(f"invalid seal numeric metadata: {exc}") from exc
    return Seal(
        plan_id=data.get("plan_id", ""),
        sealed_at=data.get("sealed_at", ""),
        plan_hash=data.get("plan_hash", ""),
        criteria_count=criteria_count,
        task=copy.deepcopy(data.get("task")),
        requirements=copy.deepcopy(data.get("requirements")),
        required_tools=copy.deepcopy(data.get("required_tools", [])),
        environment=copy.deepcopy(data.get("environment", {})),
        steps=copy.deepcopy(data.get("steps", [])),
        format_version=format_version,
        auth=copy.deepcopy(data.get("auth")) if isinstance(data.get("auth"), dict) else None,
    )


def _validate_seal_self_consistency(seal: Seal) -> None:
    if seal.format_version == 3:
        expected_hash = legacy_v3_plan_hash(seal.as_plan())
    elif seal.format_version >= 4:
        expected_hash = plan_hash(seal.as_plan())
    else:
        return
    if not isinstance(seal.plan_hash, str) or seal.plan_hash != expected_hash:
        raise SealIntegrityError("plan seal contract hash mismatch")
    expected_count = _criteria_count(seal.as_plan())
    if seal.criteria_count != expected_count:
        raise SealIntegrityError("plan seal criteria_count mismatch")


def load_seal(path: str) -> Optional[Seal]:
    target = Path(path)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        raise SealIntegrityError(f"invalid seal file: {exc}") from exc
    if not isinstance(data, dict):
        raise SealIntegrityError("seal root must be an object")
    seal = _parse_seal_data(data)
    _validate_seal_self_consistency(seal)
    root = _workspace_from_seal(target)
    try:
        key = runtime_key(root)
    except IntegrityKeyError as exc:
        raise SealIntegrityError(str(exc)) from exc
    payload = seal.payload()
    if key is not None:
        if not verify_auth(key, SEAL_DOMAIN, payload, data.get("auth")):
            raise SealIntegrityError("plan seal HMAC authentication failed")
    elif data.get("auth") is not None:
        raise SealIntegrityError("authenticated plan seal requires HMAC key")
    return seal


def _write_seal_payload(payload: Dict[str, Any], path: Path, key: Optional[KeyMaterial]) -> None:
    value = copy.deepcopy(payload)
    if key is not None:
        value["auth"] = make_auth(key, SEAL_DOMAIN, payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists() and tmp.is_symlink():
        raise SealIntegrityError(f"refusing symlinked seal temp path: {tmp}")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def save_seal(seal: Seal, path: str) -> None:
    target = Path(path)
    root = _workspace_from_seal(target)
    _validate_seal_self_consistency(seal)
    try:
        key = runtime_key(root)
    except IntegrityKeyError as exc:
        raise SealIntegrityError(str(exc)) from exc
    _write_seal_payload(seal.payload(), target, key)


def initialize_seal_auth(root: str | Path, key: KeyMaterial) -> None:
    workspace = Path(root).resolve()
    candidates: List[Path] = []
    try:
        default = confined_workspace_path(workspace, ".plan-auditor/seal.json")
        seals = confined_workspace_path(workspace, ".plan-auditor/seals", require_directory=True)
    except ControlPlanePathError as exc:
        raise SealIntegrityError(str(exc)) from exc
    if default.is_file():
        candidates.append(default)
    if seals.is_dir():
        for path in sorted(seals.iterdir()):
            if path.suffix.lower() != ".json":
                continue
            if path.is_symlink() or not path.is_file():
                raise SealIntegrityError(f"unsafe seal entry: {path}")
            candidates.append(path)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SealIntegrityError(f"cannot authenticate invalid seal {path.name}: {exc}") from exc
        if not isinstance(data, dict):
            raise SealIntegrityError(f"cannot authenticate invalid seal {path.name}")
        seal = _parse_seal_data(data)
        _validate_seal_self_consistency(seal)
        payload = {k: v for k, v in data.items() if k != "auth"}
        _write_seal_payload(payload, path, key)
