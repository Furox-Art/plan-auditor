from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _path(rel: str) -> Path:
    return ROOT / rel


def read(rel: str) -> str:
    return _path(rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = _path(rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{rel}: expected exactly one match, found {count}: {old[:80]!r}")
    write(rel, text.replace(old, new, 1))


def replace_between(rel: str, start: str, end: str, replacement: str) -> None:
    text = read(rel)
    i = text.find(start)
    if i < 0:
        raise RuntimeError(f"{rel}: start marker not found: {start!r}")
    j = text.find(end, i)
    if j < 0:
        raise RuntimeError(f"{rel}: end marker not found: {end!r}")
    write(rel, text[:i] + replacement + text[j:])


REQUEST_CONTRACT = r'''"""Host-owned request contract and activation boundary.

The workspace plan is not the authoritative source of user requirements.  A host
must activate a request contract before sealing.  The contract is then compared
against the union of all active plans and their deterministic checks.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scripts import audit_check as core
from scripts.integrity import (
    ACTIVATION_DOMAIN,
    REQUEST_CONTRACT_DOMAIN,
    IntegrityKeyError,
    KeyMaterial,
    load_key,
    make_auth,
    verify_auth,
)

REQUEST_FORMAT_VERSION = 1
ACTIVATION_FORMAT_VERSION = 1
REQUEST_NAME = "request.json"
ACTIVATION_NAME = "activation.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _payload(value: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in value.items() if k != "auth"}


def _sha256(value: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(_payload(value)).encode("utf-8")).hexdigest()


def request_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / REQUEST_NAME


def activation_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / ACTIVATION_NAME


def _atomic_write(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _validate_check_list(req_id: str, checks: Any) -> List[str]:
    if not isinstance(checks, list) or not checks:
        return [f"requirement {req_id} requires non-empty acceptance_checks"]
    synthetic = {
        "task": f"request acceptance {req_id}",
        "created": "1970-01-01T00:00:00Z",
        "steps": [{"id": 1, "title": req_id, "verify": checks}],
    }
    return [f"requirement {req_id}: {item}" for item in core.validate_plan(synthetic)]


def validate_request(value: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(value, dict):
        return ["request contract root must be an object"]
    if value.get("format_version", REQUEST_FORMAT_VERSION) != REQUEST_FORMAT_VERSION:
        errors.append("unsupported request contract format_version")
    if not isinstance(value.get("task"), str) or not value.get("task", "").strip():
        errors.append("request task must be a non-empty string")
    requirements = value.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        errors.append("request requirements must be a non-empty list")
        return errors
    seen: set[str] = set()
    for index, item in enumerate(requirements, 1):
        if not isinstance(item, dict):
            errors.append(f"request requirement {index} must be an object")
            continue
        req_id = item.get("id")
        description = item.get("description")
        priority = str(item.get("priority", "must")).lower()
        if not isinstance(req_id, str) or not req_id.strip():
            errors.append(f"request requirement {index} requires a non-empty id")
            continue
        req_id = req_id.strip()
        if req_id in seen:
            errors.append(f"duplicate request requirement id: {req_id}")
            continue
        seen.add(req_id)
        if not isinstance(description, str) or not description.strip():
            errors.append(f"request requirement {req_id} requires a non-empty description")
        if priority not in {"must", "should", "may"}:
            errors.append(f"request requirement {req_id} has invalid priority {priority!r}")
        if priority in {"must", "should"}:
            errors.extend(_validate_check_list(req_id, item.get("acceptance_checks")))
    return errors


@dataclass
class RequestStatus:
    activated: bool
    valid: bool
    reason: str = ""
    request: Dict[str, Any] | None = None
    request_sha256: str | None = None
    authenticated: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "activated": self.activated,
            "valid": self.valid,
            "reason": self.reason,
            "request_sha256": self.request_sha256,
            "authenticated": self.authenticated,
        }


@dataclass
class RequestAlignment:
    valid: bool
    errors: List[str] = field(default_factory=list)
    mapping: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "errors": self.errors, "mapping": self.mapping}


def _read_object(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} root must be an object")
    return value


def _auth_value(root: Path, key: KeyMaterial | None, domain: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    value = dict(payload)
    if key is not None:
        value["auth"] = make_auth(key, domain, payload)
    return value


def initialize_request(root: str | Path, source: Dict[str, Any]) -> RequestStatus:
    workspace = Path(root).resolve()
    rpath = request_path(workspace)
    apath = activation_path(workspace)
    if rpath.exists() or apath.exists():
        raise ValueError("request contract is already activated and immutable; create a new approval generation instead of overwriting it")
    payload = dict(source)
    payload.pop("auth", None)
    payload.setdefault("format_version", REQUEST_FORMAT_VERSION)
    errors = validate_request(payload)
    if errors:
        raise ValueError("invalid request contract: " + "; ".join(errors))
    try:
        key = load_key(workspace, required=False)
    except IntegrityKeyError as exc:
        raise ValueError(str(exc)) from exc
    request_value = _auth_value(workspace, key, REQUEST_CONTRACT_DOMAIN, payload)
    digest = _sha256(request_value)
    activation_payload = {
        "format_version": ACTIVATION_FORMAT_VERSION,
        "activated": True,
        "generation": 1,
        "request_sha256": digest,
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }
    activation_value = _auth_value(workspace, key, ACTIVATION_DOMAIN, activation_payload)
    _atomic_write(rpath, request_value)
    _atomic_write(apath, activation_value)
    return verify_request_contract(workspace)


def initialize_request_from_file(root: str | Path, source_path: str | Path) -> RequestStatus:
    source = Path(source_path).expanduser().resolve()
    value = _read_object(source)
    return initialize_request(root, value)


def initialize_request_auth(root: str | Path, key: KeyMaterial) -> None:
    workspace = Path(root).resolve()
    rpath = request_path(workspace)
    apath = activation_path(workspace)
    if not rpath.is_file() or not apath.is_file():
        raise ValueError("request contract must be activated before authenticated integrity initialization")
    request_value = _read_object(rpath)
    activation_value = _read_object(apath)
    errors = validate_request(_payload(request_value))
    if errors:
        raise ValueError("cannot authenticate invalid request contract: " + "; ".join(errors))
    digest = _sha256(request_value)
    if activation_value.get("request_sha256") != digest:
        raise ValueError("request activation hash mismatch")
    _atomic_write(rpath, _auth_value(workspace, key, REQUEST_CONTRACT_DOMAIN, _payload(request_value)))
    _atomic_write(apath, _auth_value(workspace, key, ACTIVATION_DOMAIN, _payload(activation_value)))


def verify_request_contract(root: str | Path) -> RequestStatus:
    workspace = Path(root).resolve()
    rpath = request_path(workspace)
    apath = activation_path(workspace)
    if not rpath.exists() and not apath.exists():
        return RequestStatus(False, False, "request contract is not activated")
    if not rpath.is_file() or not apath.is_file():
        return RequestStatus(True, False, "request contract/activation pair is incomplete")
    try:
        request_value = _read_object(rpath)
        activation_value = _read_object(apath)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return RequestStatus(True, False, f"request contract unreadable: {exc}")
    errors = validate_request(_payload(request_value))
    if errors:
        return RequestStatus(True, False, "; ".join(errors))
    digest = _sha256(request_value)
    activation_payload = _payload(activation_value)
    if (
        activation_payload.get("format_version") != ACTIVATION_FORMAT_VERSION
        or activation_payload.get("activated") is not True
        or activation_payload.get("generation") != 1
        or activation_payload.get("request_sha256") != digest
    ):
        return RequestStatus(True, False, "request activation metadata/hash mismatch", _payload(request_value), digest)
    try:
        key = load_key(workspace, required=False)
    except IntegrityKeyError as exc:
        return RequestStatus(True, False, str(exc), _payload(request_value), digest)
    request_auth = request_value.get("auth")
    activation_auth = activation_value.get("auth")
    if key is not None:
        if not verify_auth(key, REQUEST_CONTRACT_DOMAIN, _payload(request_value), request_auth):
            return RequestStatus(True, False, "request contract HMAC authentication failed", _payload(request_value), digest)
        if not verify_auth(key, ACTIVATION_DOMAIN, activation_payload, activation_auth):
            return RequestStatus(True, False, "request activation HMAC authentication failed", _payload(request_value), digest)
        authenticated = True
    else:
        if request_auth is not None or activation_auth is not None:
            return RequestStatus(True, False, "authenticated request contract requires HMAC key", _payload(request_value), digest)
        authenticated = False
    return RequestStatus(True, True, "request contract active", _payload(request_value), digest, authenticated)


def _normalized_check(check: Dict[str, Any]) -> str:
    return _canonical(core.norm_check(check))


def analyze_request_alignment(plans: Dict[str, Dict[str, Any]], request: Dict[str, Any]) -> RequestAlignment:
    errors: List[str] = []
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    requirements = request.get("requirements", []) if isinstance(request, dict) else []
    for req in requirements:
        if not isinstance(req, dict):
            continue
        req_id = str(req.get("id", ""))
        priority = str(req.get("priority", "must")).lower()
        matches: List[tuple[str, Dict[str, Any]]] = []
        for plan_name, plan in plans.items():
            for item in plan.get("requirements", []) if isinstance(plan, dict) else []:
                if isinstance(item, dict) and item.get("id") == req_id:
                    matches.append((plan_name, item))
        if not matches:
            errors.append(f"authoritative request requirement {req_id} is missing from every active plan")
            continue
        exact = [
            (name, item) for name, item in matches
            if item.get("description") == req.get("description")
            and str(item.get("priority", "must")).lower() == priority
        ]
        if not exact:
            errors.append(f"authoritative request requirement {req_id} was modified in plan requirements")
            continue
        covered: List[Dict[str, Any]] = []
        actual_checks: List[str] = []
        for plan_name, _item in exact:
            plan = plans[plan_name]
            for step in plan.get("steps", []):
                if not isinstance(step, dict) or req_id not in (step.get("covers") or []):
                    continue
                covered.append({"plan": plan_name, "step": step.get("id")})
                for check in step.get("verify", []):
                    if isinstance(check, dict):
                        try:
                            actual_checks.append(_normalized_check(check))
                        except Exception:
                            pass
        mapping[req_id] = covered
        if priority in {"must", "should"} and not covered:
            errors.append(f"authoritative request requirement {req_id} is not covered by any active plan step")
            continue
        for check in req.get("acceptance_checks", []) if priority in {"must", "should"} else []:
            try:
                encoded = _normalized_check(check)
            except Exception as exc:
                errors.append(f"requirement {req_id} acceptance check cannot be normalized: {exc}")
                continue
            if encoded not in actual_checks:
                errors.append(
                    f"requirement {req_id} acceptance check is not executed by any covering step: {check!r}"
                )
    return RequestAlignment(not errors, errors, mapping)


def auditor_state_present(root: str | Path) -> bool:
    pg = Path(root).resolve() / ".plan-auditor"
    if not pg.exists():
        return False
    try:
        return any(pg.iterdir())
    except OSError:
        return True
'''

AUDIT_LOCK = r'''"""Workspace-wide final-audit freeze shared by CLI and agent registry."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

LOCK_TIMEOUT = 10.0
LOCK_STALE = 3600.0
LOCK_NAME = "workspace.audit.lock"


def lock_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / LOCK_NAME


def audit_frozen(root: str | Path) -> bool:
    return lock_path(root).exists()


@contextmanager
def audit_freeze(root: str | Path) -> Iterator[None]:
    target = lock_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, json.dumps({"pid": os.getpid(), "ts": time.time()}).encode("utf-8"))
            finally:
                os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - target.stat().st_mtime > LOCK_STALE:
                    target.unlink()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("workspace final-audit lock timeout")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            target.unlink()
        except OSError:
            pass
'''

write("supervisor/request_contract.py", REQUEST_CONTRACT)
write("supervisor/audit_lock.py", AUDIT_LOCK)

replace_once(
    "scripts/integrity.py",
    'MARKER_DOMAIN = "plan-auditor:integrity-marker:v1"\n',
    'MARKER_DOMAIN = "plan-auditor:integrity-marker:v1"\nREQUEST_CONTRACT_DOMAIN = "plan-auditor:request-contract:v1"\nACTIVATION_DOMAIN = "plan-auditor:request-activation:v1"\n',
)

# Multi-step plans are explicit DAGs only; partial/legacy dependency ambiguity is rejected.
new_effective = r'''def effective_dependencies(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> Dict[int, List[int]]:
    """Return the explicit prerequisite graph.

    A one-step plan may omit ``depends_on`` and is treated as a root. Multi-step
    plans must declare ``depends_on`` on every step. This removes the legacy
    sequential/partial-explicit ambiguity that could otherwise weaken a sealed
    dependency graph by changing graph mode.
    """
    steps = _steps(plan_or_steps)
    by_id = step_index(steps)
    if len(steps) > 1:
        missing = [int(step["id"]) for step in steps if "depends_on" not in step]
        if missing:
            raise PlanGraphError(
                "multi-step plans must explicitly declare depends_on on every step; missing: %s"
                % missing
            )
    deps: Dict[int, List[int]] = {}
    for step in steps:
        sid = int(step["id"])
        raw = step.get("depends_on", [])
        if not isinstance(raw, list):
            raise PlanGraphError("step %s depends_on must be a list" % sid)
        if any(not isinstance(dep, int) or dep < 1 for dep in raw):
            raise PlanGraphError("step %s depends_on must contain positive integer ids" % sid)
        if len(raw) != len(set(raw)):
            raise PlanGraphError("step %s has duplicate dependencies" % sid)
        current = list(raw)
        if sid in current:
            raise PlanGraphError("step %s cannot depend on itself" % sid)
        unknown = [dep for dep in current if dep not in by_id]
        if unknown:
            raise PlanGraphError("step %s depends on unknown step(s): %s" % (sid, unknown))
        deps[sid] = current
    return deps


'''
replace_between("scripts/plan_graph.py", "def effective_dependencies(\n", "def topological_order(\n", new_effective)

new_validate_links = r'''def validate_output_links(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> List[str]:
    """Validate required outputs and bind every direct dependency to one."""
    steps = _steps(plan_or_steps)
    try:
        by_id = step_index(steps)
        deps = effective_dependencies(steps)
        closure = transitive_dependencies(steps)
    except PlanGraphError as exc:
        return [str(exc)]

    errors: List[str] = []
    outputs: Dict[int, Dict[str, Mapping[str, Any]]] = {}
    for step in steps:
        sid = int(step["id"])
        try:
            outputs[sid] = output_index(step)
        except PlanGraphError as exc:
            errors.append(str(exc))

    for step in steps:
        sid = int(step["id"])
        try:
            required = required_outputs(step)
        except PlanGraphError as exc:
            errors.append(str(exc))
            continue
        linked_sources = {int(ref["step"]) for ref in required}
        for parent in deps.get(sid, []):
            if parent not in linked_sources:
                errors.append(
                    "dependency edge %s -> %s has no requires_outputs link; every dependency must be backed by a concrete upstream output"
                    % (parent, sid)
                )
        for ref in required:
            source = int(ref["step"])
            name = str(ref["name"])
            if source not in by_id:
                errors.append("step %s requires output from unknown step %s" % (sid, source))
                continue
            if source not in closure.get(sid, set()):
                errors.append(
                    "step %s requires output %s:%s but source is not a dependency"
                    % (sid, source, name)
                )
                continue
            if name not in outputs.get(source, {}):
                errors.append(
                    "step %s requires undeclared output %s:%s" % (sid, source, name)
                )
    return errors


'''
replace_between("scripts/plan_graph.py", "def validate_output_links(\n", "def graph_summary(\n", new_validate_links)

# Seal v4 canonicalizes the effective graph.
replace_once(
    "supervisor/sealing.py",
    "from scripts.integrity import (\n",
    "from scripts.plan_graph import PlanGraphError, effective_dependencies\n\nfrom scripts.integrity import (\n",
)
replace_once("supervisor/sealing.py", "SEAL_FORMAT_VERSION = 3", "SEAL_FORMAT_VERSION = 4")
new_contract_plan = r'''def contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
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


'''
replace_between("supervisor/sealing.py", "def contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:\n", "def canonical_plan(plan: Dict) -> str:\n", new_contract_plan)

# Bind all behavior-changing supervisor configuration and request contract hash.
new_env_contract = r'''def environment_contract(root: str | Path, cfg: Config) -> Dict[str, Any]:
    from .request_contract import verify_request_contract

    request = verify_request_contract(root)
    return {
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "tier": int(cfg.tier),
        "max_attempts": int(cfg.max_attempts),
        "owner_timeout_sec": int(cfg.owner_timeout_sec),
        "heartbeat_sec": int(cfg.heartbeat_sec),
        "rotate_bytes": int(cfg.rotate_bytes),
        "policies_dir": cfg.policies_dir,
        "policies_sha256": policy_fingerprint(root, cfg),
        "request_sha256": request.request_sha256 if request.valid else None,
    }
'''
replace_between("supervisor/contracts.py", "def environment_contract(root: str | Path, cfg: Config) -> Dict[str, Any]:\n", "", new_env_contract)

# The replace_between helper cannot use an empty end marker; restore contracts.py deterministically.
write("supervisor/contracts.py", r'''"""Deterministic supervisor environment contract used by plan seals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from .config import Config


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def policy_fingerprint(root: str | Path, cfg: Config) -> str:
    workspace = Path(root).resolve()
    candidates = [workspace / cfg.policies_dir, workspace / ".plan-auditor" / "policies"]
    entries: list[dict[str, str]] = []
    seen: set[Path] = set()
    for directory in candidates:
        directory = directory.resolve()
        if directory in seen or not directory.is_dir():
            continue
        seen.add(directory)
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix.lower() not in {".json", ".toml"}:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                data = b"<unreadable>"
            try:
                rel = path.resolve().relative_to(workspace).as_posix()
            except ValueError:
                rel = str(path.resolve())
            entries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest()})
    return hashlib.sha256(_canonical(entries)).hexdigest()


def environment_contract(root: str | Path, cfg: Config) -> Dict[str, Any]:
    from .request_contract import verify_request_contract

    request = verify_request_contract(root)
    return {
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "tier": int(cfg.tier),
        "max_attempts": int(cfg.max_attempts),
        "owner_timeout_sec": int(cfg.owner_timeout_sec),
        "heartbeat_sec": int(cfg.heartbeat_sec),
        "rotate_bytes": int(cfg.rotate_bytes),
        "policies_dir": cfg.policies_dir,
        "policies_sha256": policy_fingerprint(root, cfg),
        "request_sha256": request.request_sha256 if request.valid else None,
    }
''')

# Request contract is a hard precondition for any active-plan assessment.
replace_once(
    "supervisor/orchestrator.py",
    "from .requirements import parse_requirements\n",
    "from .requirements import parse_requirements\nfrom .request_contract import (\n    analyze_request_alignment, auditor_state_present, verify_request_contract,\n)\n",
)
old_refs = '''    refs = all_plan_refs(root)\n    if not refs:\n        return {\n            "outcome": "NO_PLAN",\n            "workspace": str(root),\n            "profile": cfg.profile.value,\n            "mode": cfg.mode,\n            "active_layers": cfg.active_layers(),\n            "configuration_errors": cfg.errors,\n            "active_plan_count": 0,\n            "plans": {},\n        }\n\n    workspace_state = capture_workspace(str(root))\n'''
new_refs = '''    request_status = verify_request_contract(root)\n    refs = all_plan_refs(root)\n    if not refs:\n        if request_status.activated or auditor_state_present(root):\n            return {\n                "outcome": "FAIL",\n                "workspace": str(root),\n                "profile": cfg.profile.value,\n                "mode": cfg.mode,\n                "active_layers": cfg.active_layers(),\n                "configuration_errors": cfg.errors,\n                "active_plan_count": 0,\n                "plans": {},\n                "request_contract": request_status.as_dict(),\n                "error": "auditor state/request activation exists but all active plans are missing",\n            }\n        return {\n            "outcome": "NO_PLAN",\n            "workspace": str(root),\n            "profile": cfg.profile.value,\n            "mode": cfg.mode,\n            "active_layers": cfg.active_layers(),\n            "configuration_errors": cfg.errors,\n            "active_plan_count": 0,\n            "plans": {},\n            "request_contract": request_status.as_dict(),\n        }\n\n    if not request_status.valid or not isinstance(request_status.request, dict):\n        return {\n            "outcome": "FAIL",\n            "workspace": str(root),\n            "profile": cfg.profile.value,\n            "mode": cfg.mode,\n            "active_layers": cfg.active_layers(),\n            "configuration_errors": cfg.errors,\n            "active_plan_count": len(refs),\n            "plans": {ref.key: {"outcome": "FAIL", "error": request_status.reason} for ref in refs},\n            "request_contract": request_status.as_dict(),\n        }\n\n    request_plans: Dict[str, Dict[str, Any]] = {}\n    request_load_errors: List[str] = []\n    for ref in refs:\n        try:\n            request_plans[ref.key] = load_plan_ref(ref)\n        except (OSError, json.JSONDecodeError, ValueError) as exc:\n            request_load_errors.append(f"{ref.key}: {exc}")\n    request_alignment = analyze_request_alignment(request_plans, request_status.request)\n    if request_load_errors or not request_alignment.valid:\n        errors = request_load_errors + request_alignment.errors\n        return {\n            "outcome": "FAIL",\n            "workspace": str(root),\n            "profile": cfg.profile.value,\n            "mode": cfg.mode,\n            "active_layers": cfg.active_layers(),\n            "configuration_errors": cfg.errors,\n            "active_plan_count": len(refs),\n            "plans": {ref.key: {"outcome": "FAIL", "request_alignment_errors": errors} for ref in refs},\n            "request_contract": request_status.as_dict(),\n            "request_alignment": request_alignment.as_dict(),\n        }\n\n    workspace_state = capture_workspace(str(root))\n'''
replace_once("supervisor/orchestrator.py", old_refs, new_refs)
replace_once(
    "supervisor/orchestrator.py",
    '        "policy_errors": policy_errors,\n        "active_plan_count": len(plans),\n',
    '        "policy_errors": policy_errors,\n        "request_contract": request_status.as_dict(),\n        "request_alignment": request_alignment.as_dict(),\n        "active_plan_count": len(plans),\n',
)

# CLI request lifecycle and immutable sealing baseline.
parser_insert = '''    integrity_status = integrity_sub.add_parser("status", help="show authenticated integrity status")\n    integrity_status.add_argument("dir", nargs="?", default=".")\n\n'''
parser_new = parser_insert + '''    request = sub.add_parser("request", help="host-owned immutable request contract")\n    request_sub = request.add_subparsers(dest="action", required=True)\n    request_init = request_sub.add_parser("init", help="activate request contract from a host-provided JSON file")\n    request_init.add_argument("dir", nargs="?", default=".")\n    request_init.add_argument("--file", required=True, dest="request_file")\n    request_status_cmd = request_sub.add_parser("status", help="verify request activation and plan alignment")\n    request_status_cmd.add_argument("dir", nargs="?", default=".")\n\n'''
replace_once("supervisor/cli.py", parser_insert, parser_new)

helper_marker = '''def _policy_errors(root: Path, cfg) -> list[str]:\n'''
helper_code = r'''def _request_gate(root: Path):
    from .plans import all_plan_refs, load_plan_ref
    from .request_contract import analyze_request_alignment, verify_request_contract

    status = verify_request_contract(root)
    if not status.valid or not isinstance(status.request, dict):
        return status, None, [status.reason or "request contract invalid"]
    docs: dict[str, Any] = {}
    errors: list[str] = []
    for ref in all_plan_refs(root):
        try:
            docs[ref.key] = load_plan_ref(ref)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{ref.key}: {exc}")
    alignment = analyze_request_alignment(docs, status.request)
    errors.extend(alignment.errors)
    return status, alignment, errors


def cmd_request(args: argparse.Namespace) -> int:
    from .request_contract import initialize_request_from_file, verify_request_contract

    root = _root(args.dir)
    if args.action == "init":
        try:
            result = initialize_request_from_file(root, args.request_file)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _json({"activated": False, "valid": False, "error": str(exc)})
            return 2
        _json(result.as_dict())
        return 0 if result.valid else 2
    status, alignment, errors = _request_gate(root)
    payload = status.as_dict()
    if alignment is not None:
        payload["alignment"] = alignment.as_dict()
    payload["errors"] = errors
    _json(payload)
    return 0 if status.valid and not errors else 2


'''
text = read("supervisor/cli.py")
pos = text.find(helper_marker)
if pos < 0:
    raise RuntimeError("cli policy helper marker missing")
write("supervisor/cli.py", text[:pos] + helper_code + text[pos:])

# Plan verify must have a host request contract and cannot reset an activated baseline.
old_verify_start = '''    root = _root(args.dir)\n    try:\n        refs = _selected_refs(root, args.plan)\n    except (FileNotFoundError, ValueError) as exc:\n        print(f"ERROR: {exc}", file=sys.stderr)\n        return 1\n    cfg = load_config(str(root))\n'''
new_verify_start = '''    root = _root(args.dir)\n    try:\n        refs = _selected_refs(root, args.plan)\n    except (FileNotFoundError, ValueError) as exc:\n        print(f"ERROR: {exc}", file=sys.stderr)\n        return 1\n    request_status, request_alignment, request_errors = _request_gate(root)\n    if request_errors:\n        _json({"outcome": "FAIL", "request_contract": request_status.as_dict(), "request_errors": request_errors})\n        return 2\n    if args.reseal:\n        _json({\n            "outcome": "FAIL",\n            "reason": "automatic --reseal is disabled after request activation; create a new host-approved request generation instead",\n        })\n        return 2\n    cfg = load_config(str(root))\n'''
replace_once("supervisor/cli.py", old_verify_start, new_verify_start)
replace_once("supervisor/cli.py", "if existing and existing.format_version < 3 and not args.reseal:", "if existing and existing.format_version < 4:")
replace_once("supervisor/cli.py", "if existing and not args.reseal:", "if existing:")

# Integrated audit request gate + v4 seal baseline. Workspace freeze is added in stage 2.
old_audit_start = '''    root = _root(args.dir)\n    try:\n        refs = _selected_refs(root, args.plan)\n    except (FileNotFoundError, ValueError) as exc:\n        print(f"ERROR: {exc}", file=sys.stderr)\n        return 1\n    cfg = load_config(str(root))\n'''
new_audit_start = '''    root = _root(args.dir)\n    try:\n        refs = _selected_refs(root, args.plan)\n    except (FileNotFoundError, ValueError) as exc:\n        print(f"ERROR: {exc}", file=sys.stderr)\n        return 1\n    request_status, request_alignment, request_errors = _request_gate(root)\n    if request_errors:\n        _json({"outcome": "FAIL", "request_contract": request_status.as_dict(), "request_errors": request_errors})\n        return 2\n    cfg = load_config(str(root))\n'''
# This exact sequence occurs twice (plan verify and audit); verify replacement already changed first.
text = read("supervisor/cli.py")
if old_audit_start not in text:
    raise RuntimeError("cli audit start marker missing")
write("supervisor/cli.py", text.replace(old_audit_start, new_audit_start, 1))
replace_once("supervisor/cli.py", "if seal.format_version < 3:", "if seal.format_version < 4:")
replace_once(
    "supervisor/cli.py",
    '''    if args.cmd == "integrity":\n        return cmd_integrity(args)\n    if args.cmd == "agents":\n''',
    '''    if args.cmd == "integrity":\n        return cmd_integrity(args)\n    if args.cmd == "request":\n        return cmd_request(args)\n    if args.cmd == "agents":\n''',
)

# Authenticated integrity signs the already-activated request and is idempotent after marker creation.
replace_once(
    "supervisor/integrity.py",
    '''    if marker.exists() and not verify_marker(root, key):\n        raise IntegrityKeyError("existing integrity marker is invalid or uses another key")\n\n    from .agents import initialize_registry_auth\n''',
    '''    if marker.exists():\n        if not verify_marker(root, key):\n            raise IntegrityKeyError("existing integrity marker is invalid or uses another key")\n        current = integrity_status(root)\n        if current.get("authenticated"):\n            return current\n        raise IntegrityKeyError("authenticated integrity is already initialized but current state no longer verifies; refusing to re-sign it")\n\n    from .agents import initialize_registry_auth\n''',
)
replace_once(
    "supervisor/integrity.py",
    '''    from .evidence import initialize_evidence_auth\n    from .sealing import initialize_seal_auth\n\n    initialize_evidence_auth(root, key)\n''',
    '''    from .evidence import initialize_evidence_auth\n    from .request_contract import initialize_request_auth\n    from .sealing import initialize_seal_auth\n\n    initialize_request_auth(root, key)\n    initialize_evidence_auth(root, key)\n''',
)
replace_once(
    "supervisor/integrity.py",
    '''    from .plans import all_plan_refs, seal_path\n    from .sealing import SealIntegrityError, load_seal\n\n    evidence_ok, evidence_count, evidence_problem = core.verify_chain(str(root))\n''',
    '''    from .plans import all_plan_refs, seal_path\n    from .request_contract import verify_request_contract\n    from .sealing import SealIntegrityError, load_seal\n\n    request = verify_request_contract(root)\n    evidence_ok, evidence_count, evidence_problem = core.verify_chain(str(root))\n''',
)
replace_once(
    "supervisor/integrity.py",
    '''    authenticated = (\n        evidence_ok\n        and archive.get("anchored") is True\n        and registry_ok\n        and not seal_errors\n    )\n''',
    '''    authenticated = (\n        request.valid\n        and request.authenticated\n        and evidence_ok\n        and archive.get("anchored") is True\n        and registry_ok\n        and not seal_errors\n    )\n''',
)
replace_once(
    "supervisor/integrity.py",
    '''        "key_source": key.source,\n        "evidence": {\n''',
    '''        "key_source": key.source,\n        "request_contract": request.as_dict(),\n        "evidence": {\n''',
)

# Dogfood plan uses an explicit graph and concrete output binding.
plan = {
    "task": "plan-auditor kendi kodunu kanıtla doğrular (dogfooding)",
    "created": "2026-09-03T19:15:00",
    "requirements": [
        {"id": "REQ-001", "description": "Plan Auditor unit test suite must pass.", "priority": "must"},
        {"id": "REQ-002", "description": "The Fibonacci example regression tests must pass.", "priority": "must"},
    ],
    "required_tools": ["python"],
    "steps": [
        {
            "id": 1,
            "title": "audit_check.py birim test süiti geçer",
            "depends_on": [],
            "covers": ["REQ-001"],
            "verify": [{"type": "pytest", "args": "tests/ -q"}],
            "outputs": [
                {"name": "unit-suite-pass", "verify": [{"type": "pytest", "args": "tests/ -q"}]}
            ],
            "status": "pending",
        },
        {
            "id": 2,
            "title": "örnek fib görevinin testleri geçer",
            "depends_on": [1],
            "requires_outputs": [{"step": 1, "name": "unit-suite-pass"}],
            "covers": ["REQ-002"],
            "verify": [{"type": "pytest", "args": "examples/fib/test_fib.py -q"}],
            "status": "pending",
        },
    ],
}
write(".plan-auditor/plan.json", json.dumps(plan, ensure_ascii=False, indent=2) + "\n")
request_source = {
    "format_version": 1,
    "task": plan["task"],
    "requirements": [
        {
            "id": "REQ-001",
            "description": "Plan Auditor unit test suite must pass.",
            "priority": "must",
            "acceptance_checks": [{"type": "pytest", "args": "tests/ -q"}],
        },
        {
            "id": "REQ-002",
            "description": "The Fibonacci example regression tests must pass.",
            "priority": "must",
            "acceptance_checks": [{"type": "pytest", "args": "examples/fib/test_fib.py -q"}],
        },
    ],
}
write(".plan-auditor/request-source.json", json.dumps(request_source, ensure_ascii=False, indent=2) + "\n")

# CI initializes the host request before sealing/auditing and pins first-party actions.
for rel in (".github/workflows/plan-audit.yml", ".github/workflows/wheel-cli-smoke.yml", ".github/workflows/release.yml"):
    text = read(rel)
    text = text.replace("actions/checkout@v7", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
    text = text.replace("actions/setup-python@v7", "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97")
    write(rel, text)
replace_once(
    ".github/workflows/plan-audit.yml",
    '''      - name: Validate plan schema\n        run: python scripts/audit_check.py validate .\n''',
    '''      - name: Activate host request contract\n        run: plan-auditor request init . --file .plan-auditor/request-source.json\n      - name: Validate plan schema\n        run: python scripts/audit_check.py validate .\n''',
)
replace_once(
    ".github/workflows/plan-audit.yml",
    '''      - name: Prepare sealed and audited workspace\n        run: |\n          plan-auditor plan verify .\n          plan-auditor audit .\n''',
    '''      - name: Prepare sealed and audited workspace\n        run: |\n          plan-auditor request init . --file .plan-auditor/request-source.json\n          plan-auditor plan verify .\n          plan-auditor audit .\n''',
)
replace_once(
    ".github/workflows/release.yml",
    "uses: pypa/gh-action-pypi-publish@release/v1",
    "uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
)
# There are two publish uses; pin the second too if still present.
text = read(".github/workflows/release.yml").replace(
    "uses: pypa/gh-action-pypi-publish@release/v1",
    "uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
)
text = text.replace(
    "uses: softprops/action-gh-release@v3",
    "uses: softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64",
)
write(".github/workflows/release.yml", text)

# New root-regression tests.
write("tests/test_request_contract_hardening.py", r'''from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from supervisor.cli import main as cli_main
from supervisor.orchestrator import evaluate_workspace
from supervisor.request_contract import initialize_request
from supervisor.sealing import check_monotonic, seal_plan


def _request(*requirements):
    return {
        "format_version": 1,
        "task": "authoritative user request",
        "requirements": list(requirements),
    }


def _req(req_id: str, description: str, check=None):
    if check is None:
        check = {"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}
    return {
        "id": req_id,
        "description": description,
        "priority": "must",
        "acceptance_checks": [check],
    }


def _plan(requirements, *, checks=None):
    checks = checks or [{"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}]
    return {
        "task": "implementation",
        "created": "2026-09-05T00:00:00Z",
        "requirements": requirements,
        "steps": [{"id": 1, "title": "behavior", "covers": [item["id"] for item in requirements], "verify": checks}],
    }


def _write(root: Path, plan: dict):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")


def test_authoritative_request_omission_blocks_plan_verify(tmp_path: Path):
    r1 = _req("REQ-1", "first")
    r2 = _req("REQ-2", "second")
    initialize_request(tmp_path, _request(r1, r2))
    _write(tmp_path, _plan([{"id": "REQ-1", "description": "first", "priority": "must"}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 2


def test_covers_label_without_approved_acceptance_check_is_rejected(tmp_path: Path):
    expected = {"type": "run", "argv": [sys.executable, "-c", "print('secure')"]}
    initialize_request(tmp_path, _request(_req("REQ-1", "secure behavior", expected)))
    _write(tmp_path, _plan([
        {"id": "REQ-1", "description": "secure behavior", "priority": "must"}
    ], checks=[{"type": "run", "argv": [sys.executable, "-c", "print('unrelated')"]}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 2


def test_activated_workspace_cannot_become_no_plan(tmp_path: Path):
    initialize_request(tmp_path, _request(_req("REQ-1", "behavior")))
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert report["active_plan_count"] == 0


def test_reseal_is_disabled_after_activation(tmp_path: Path):
    req = _req("REQ-1", "behavior")
    initialize_request(tmp_path, _request(req))
    _write(tmp_path, _plan([{"id": "REQ-1", "description": "behavior", "priority": "must"}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    assert cli_main(["plan", "verify", str(tmp_path), "--reseal"]) == 2


def test_multistep_plan_requires_explicit_dependencies(tmp_path: Path):
    plan = {
        "task": "two steps",
        "created": "2026-09-05T00:00:00Z",
        "steps": [
            {"id": 1, "title": "one", "verify": [{"type": "run", "argv": [sys.executable, "-c", "print(1)"]}]},
            {"id": 2, "title": "two", "verify": [{"type": "run", "argv": [sys.executable, "-c", "print(2)"]}]},
        ],
    }
    from scripts import audit_check as core
    errors = core.validate_plan(plan)
    assert any("depends_on" in item for item in errors)


def test_partial_explicit_graph_cannot_switch_dependency_mode():
    from scripts.plan_graph import PlanGraphError, effective_dependencies
    plan = {
        "steps": [
            {"id": 1, "depends_on": []},
            {"id": 2},
        ]
    }
    try:
        effective_dependencies(plan)
    except PlanGraphError as exc:
        assert "every step" in str(exc)
    else:
        raise AssertionError("partial explicit graph was accepted")
''')

# Update existing tests that assert seal format 3.
text = read("tests/test_cli.py").replace('assert seal["format_version"] == 3', 'assert seal["format_version"] == 4')
write("tests/test_cli.py", text)

# Changelog records the security migration as unreleased.
changelog = read("CHANGELOG.md")
entry = """## Unreleased\n\n- Introduce host-owned immutable request activation and deterministic acceptance-check binding.\n- Reject active-workspace plan deletion as FAIL instead of NO_PLAN.\n- Remove automatic reseal baseline reset; request generations are immutable.\n- Require explicit dependency declarations and concrete output bindings for every multi-step edge.\n- Upgrade seals to format v4 with canonical effective dependency graphs and full runtime-config/request fingerprints.\n- Make authenticated-integrity initialization idempotent and refuse re-signing a broken initialized state.\n- Pin GitHub Actions dependencies to immutable commit SHAs.\n\n"""
if changelog.startswith("## Unreleased"):
    # Preserve existing unreleased section but prepend new bullets after heading.
    changelog = changelog.replace("## Unreleased\n", entry, 1)
else:
    changelog = entry + changelog
write("CHANGELOG.md", changelog)

print("stage1 hardening patch applied")
