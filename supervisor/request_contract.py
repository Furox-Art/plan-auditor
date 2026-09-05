"""Host-owned request contract and activation boundary.

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
