"""Host-owned request contract and activation boundary.

The workspace plan is not the authoritative source of user requirements.  A host
must activate a request contract before sealing.  The contract is then compared
against the union of all active plans and their deterministic checks.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts import audit_check as core
from scripts.contract import (
    REQUEST_PLAN_BINDING_FIELD,
    canonical_digest,
    canonical_json,
    payload_without_auth,
    plan_hash,
)
from scripts.integrity import (
    ACTIVATION_DOMAIN,
    REQUEST_CONTRACT_DOMAIN,
    IntegrityKeyError,
    KeyMaterial,
    load_key,
    make_auth,
    verify_auth,
)

from .control_plane import ControlPlanePathError, confined_workspace_path

REQUEST_FORMAT_VERSION = 1
ACTIVATION_FORMAT_VERSION = 1
REQUEST_NAME = "request.json"
ACTIVATION_NAME = "activation.json"


def _canonical(value: Any) -> str:
    return canonical_json(value)


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    return payload_without_auth(value)


def _sha256(value: dict[str, Any]) -> str:
    return canonical_digest(payload_without_auth(value))


def _request_control_path(root: str | Path, name: str) -> Path:
    try:
        return confined_workspace_path(root, f".plan-auditor/{name}")
    except ControlPlanePathError as exc:
        raise ValueError(f"unsafe request control-plane path: {exc}") from exc


def request_path(root: str | Path) -> Path:
    return _request_control_path(root, REQUEST_NAME)


def activation_path(root: str | Path) -> Path:
    return _request_control_path(root, ACTIVATION_NAME)


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    """Persist an immutable control-plane record with a unique fsynced temp."""
    if path.is_symlink():
        raise ValueError(f"refusing to write request metadata through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _validate_check_list(req_id: str, checks: Any) -> list[str]:
    if not isinstance(checks, list) or not checks:
        return [f"requirement {req_id} requires non-empty acceptance_checks"]
    synthetic = {
        "task": f"request acceptance {req_id}",
        "created": "1970-01-01T00:00:00Z",
        "steps": [{"id": 1, "title": req_id, "verify": checks}],
    }
    return [f"requirement {req_id}: {item}" for item in core.validate_plan(synthetic)]


def validate_request(value: Any) -> list[str]:
    errors: list[str] = []
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
    request: dict[str, Any] | None = None
    request_sha256: str | None = None
    authenticated: bool = False

    def as_dict(self) -> dict[str, Any]:
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
    errors: list[str] = field(default_factory=list)
    mapping: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": self.errors, "mapping": self.mapping}


MAX_REQUEST_CONTROL_BYTES = 1024 * 1024


def _unique_control_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate request JSON field: {name}")
        result[name] = value
    return result


def _finite_control_float(raw: str) -> float:
    result = float(raw)
    if not math.isfinite(result):
        raise ValueError("non-finite request JSON number")
    return result


def _reject_control_constant(raw: str) -> None:
    raise ValueError(f"invalid request JSON constant: {raw}")


def _read_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.name} is not a safe regular file")
    with path.open(encoding="utf-8") as source:
        raw = source.read(MAX_REQUEST_CONTROL_BYTES + 1)
    if len(raw) > MAX_REQUEST_CONTROL_BYTES:
        raise ValueError(f"{path.name} exceeds bounded request JSON input size")
    value = json.loads(
        raw,
        object_pairs_hook=_unique_control_fields,
        parse_float=_finite_control_float,
        parse_constant=_reject_control_constant,
    )
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} root must be an object")
    return value


def _auth_value(
    root: Path, key: KeyMaterial | None, domain: str, payload: dict[str, Any]
) -> dict[str, Any]:
    value = dict(payload)
    if key is not None:
        value["auth"] = make_auth(key, domain, payload)
    return value


def _stamp_plan_binding(workspace: Path, payload: dict[str, Any]) -> None:
    """Record which plan contracts this request approves, keyed by plan name.

    Every active plan gets an entry (the default plan plus each
    ``.plan-auditor/plans/<name>.json``), because a workspace may seal and audit
    several plans under one request. Plans that cannot be read are skipped: the
    request stays authoritative and the seal still binds it, so only the reverse
    binding is deferred.
    """
    from .plans import all_plan_refs, load_plan_ref

    bindings: dict[str, str] = {}
    try:
        refs = all_plan_refs(workspace)
    except (OSError, ValueError):
        refs = []
    for ref in refs:
        try:
            bindings[ref.key] = plan_hash(load_plan_ref(ref))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    if bindings:
        payload[REQUEST_PLAN_BINDING_FIELD] = bindings


def initialize_request(root: str | Path, source: dict[str, Any]) -> RequestStatus:
    workspace = Path(root).resolve()
    rpath = request_path(workspace)
    apath = activation_path(workspace)
    if rpath.exists() or apath.exists():
        raise ValueError(
            "request contract is already activated and immutable; create a new approval generation instead of overwriting it"
        )
    payload = dict(source)
    payload.pop("auth", None)
    payload.setdefault("format_version", REQUEST_FORMAT_VERSION)
    errors = validate_request(payload)
    if errors:
        raise ValueError("invalid request contract: " + "; ".join(errors))
    # Bind the request to the exact plan content it approves. The seal binds the
    # request digest, and this field binds the request back to the plan, so the
    # two objects cannot be independently substituted after approval. A workspace
    # with no default plan yet (named-plan-only, or a host activating the request
    # before the plan exists) simply carries no binding until it is re-approved.
    _stamp_plan_binding(workspace, payload)
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
        raise ValueError(
            "request contract must be activated before authenticated integrity initialization"
        )
    request_value = _read_object(rpath)
    activation_value = _read_object(apath)
    errors = validate_request(_payload(request_value))
    if errors:
        raise ValueError("cannot authenticate invalid request contract: " + "; ".join(errors))
    digest = _sha256(request_value)
    if activation_value.get("request_sha256") != digest:
        raise ValueError("request activation hash mismatch")
    _atomic_write(
        rpath, _auth_value(workspace, key, REQUEST_CONTRACT_DOMAIN, _payload(request_value))
    )
    _atomic_write(apath, _auth_value(workspace, key, ACTIVATION_DOMAIN, _payload(activation_value)))


def verify_request_contract(root: str | Path) -> RequestStatus:
    workspace = Path(root).resolve()
    try:
        rpath = request_path(workspace)
        apath = activation_path(workspace)
    except ValueError as exc:
        return RequestStatus(True, False, str(exc))
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
    # An unauthenticated activation must not be extensible with unreviewed
    # fields that bypass the request digest and are invisible to readers.
    activation_keys = {
        "format_version",
        "activated",
        "generation",
        "request_sha256",
        "activated_at",
    }
    if (
        set(activation_payload) != activation_keys
        or activation_payload.get("format_version") != ACTIVATION_FORMAT_VERSION
        or activation_payload.get("activated") is not True
        or activation_payload.get("generation") != 1
        or activation_payload.get("request_sha256") != digest
    ):
        return RequestStatus(
            True,
            False,
            "request activation metadata/hash mismatch",
            _payload(request_value),
            digest,
        )
    try:
        key = load_key(workspace, required=False)
    except IntegrityKeyError as exc:
        return RequestStatus(True, False, str(exc), _payload(request_value), digest)
    request_auth = request_value.get("auth")
    activation_auth = activation_value.get("auth")
    if key is not None:
        if not verify_auth(key, REQUEST_CONTRACT_DOMAIN, _payload(request_value), request_auth):
            return RequestStatus(
                True,
                False,
                "request contract HMAC authentication failed",
                _payload(request_value),
                digest,
            )
        if not verify_auth(key, ACTIVATION_DOMAIN, activation_payload, activation_auth):
            return RequestStatus(
                True,
                False,
                "request activation HMAC authentication failed",
                _payload(request_value),
                digest,
            )
        authenticated = True
    else:
        if request_auth is not None or activation_auth is not None:
            return RequestStatus(
                True,
                False,
                "authenticated request contract requires HMAC key",
                _payload(request_value),
                digest,
            )
        authenticated = False
    return RequestStatus(
        True, True, "request contract active", _payload(request_value), digest, authenticated
    )


def _normalized_check(check: dict[str, Any]) -> str:
    return _canonical(core.norm_check(check))


def analyze_request_alignment(
    plans: dict[str, dict[str, Any]], request: dict[str, Any]
) -> RequestAlignment:
    """Match exact host-approved checks to structurally valid, covering plan steps.

    This is an independent authorization boundary: malformed in-memory payloads
    must return an invalid alignment even when a caller skipped file validation.
    """
    errors: list[str] = []
    mapping: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(plans, dict):
        return RequestAlignment(False, ["active plans must be an object"], mapping)
    if not isinstance(request, dict):
        return RequestAlignment(False, ["authoritative request must be an object"], mapping)
    requirements = request.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        return RequestAlignment(
            False, ["authoritative request requirements must be a non-empty list"], mapping
        )

    for index, req in enumerate(requirements, 1):
        if not isinstance(req, dict):
            errors.append(f"authoritative request requirement {index} must be an object")
            continue
        req_id = req.get("id")
        if not isinstance(req_id, str) or not req_id.strip():
            errors.append(f"authoritative request requirement {index} has no valid id")
            continue
        priority = str(req.get("priority", "must")).lower()
        matches: list[tuple[str, dict[str, Any]]] = []
        for plan_name, plan in plans.items():
            if not isinstance(plan, dict):
                continue
            plan_requirements = plan.get("requirements", [])
            if not isinstance(plan_requirements, list):
                errors.append(f"plan {plan_name} requirements must be a list")
                continue
            for item in plan_requirements:
                if isinstance(item, dict) and item.get("id") == req_id:
                    matches.append((plan_name, item))
        if not matches:
            errors.append(
                f"authoritative request requirement {req_id} is missing from every active plan"
            )
            continue
        exact = [
            (name, item)
            for name, item in matches
            if item.get("description") == req.get("description")
            and str(item.get("priority", "must")).lower() == priority
        ]
        if not exact:
            errors.append(
                f"authoritative request requirement {req_id} was modified in plan requirements"
            )
            continue
        covered: list[dict[str, Any]] = []
        actual_checks: list[str] = []
        for plan_name, _item in exact:
            plan = plans[plan_name]
            steps = plan.get("steps", [])
            if not isinstance(steps, list):
                errors.append(f"plan {plan_name} steps must be a list")
                continue
            for step_index, step in enumerate(steps, 1):
                if not isinstance(step, dict):
                    errors.append(f"plan {plan_name} step {step_index} must be an object")
                    continue
                covers = step.get("covers") or []
                if not isinstance(covers, list):
                    errors.append(f"plan {plan_name} step {step_index} covers must be a list")
                    continue
                if req_id not in covers:
                    continue
                verify = step.get("verify", [])
                if not isinstance(verify, list):
                    errors.append(f"plan {plan_name} step {step_index} verify must be a list")
                    continue
                covered.append({"plan": plan_name, "step": step.get("id")})
                for check in verify:
                    if isinstance(check, dict):
                        try:
                            actual_checks.append(_normalized_check(check))
                        except (ValueError, TypeError, KeyError):
                            # An invalid check has no evidentiary value; matching
                            # the host-approved check below must still fail.
                            continue
        mapping[req_id] = covered
        if priority in {"must", "should"} and not covered:
            errors.append(
                f"authoritative request requirement {req_id} is not covered by any active plan step"
            )
            continue
        checks = req.get("acceptance_checks", []) if priority in {"must", "should"} else []
        if not isinstance(checks, list):
            errors.append(f"requirement {req_id} acceptance_checks must be a list")
            continue
        for check in checks:
            try:
                encoded = _normalized_check(check)
            except (ValueError, TypeError, KeyError) as exc:
                errors.append(f"requirement {req_id} acceptance check cannot be normalized: {exc}")
                continue
            if encoded not in actual_checks:
                errors.append(
                    f"requirement {req_id} acceptance check is not executed by any covering step: {check!r}"
                )
    return RequestAlignment(not errors, errors, mapping)


def auditor_state_present(root: str | Path) -> bool:
    """Return True only for state that proves Plan Auditor was actually activated.

    A lone config/log/cache file must not turn an otherwise unused workspace into
    a failed task.  Conversely, request/seal/evidence/plan/registry state means a
    deleted plan must fail closed instead of degrading to ``NO_PLAN``.
    """
    workspace = Path(root).resolve()
    try:
        pg = confined_workspace_path(workspace, ".plan-auditor")
    except ControlPlanePathError:
        return True
    if not pg.exists():
        return False
    activating_files = (
        REQUEST_NAME,
        ACTIVATION_NAME,
        "plan.json",
        "seal.json",
        "evidence.jsonl",
        "evidence.head.json",
        "integrity.json",
        "supervisor-assessment.json",
        "watchdog.jsonl",
    )
    for name in activating_files:
        path = pg / name
        if path.exists():
            return True
    # Directory-level state carries activation too: deleting the top-level
    # markers must not turn a used workspace back into "never activated" while
    # rotated evidence, per-plan files or snapshots are still on disk.
    for dirname, suffixes in (
        ("plans", (".json",)),
        ("seals", (".json",)),
        ("archive", (".jsonl",)),
        ("snapshots", (".zip",)),
    ):
        directory = pg / dirname
        if directory.exists():
            if directory.is_symlink():
                return True
            try:
                if any(path.suffix.lower() in suffixes for path in directory.iterdir()):
                    return True
            except OSError:
                return True
    registry = pg / "agents" / "registry.jsonl"
    if registry.exists():
        return True
    return False
