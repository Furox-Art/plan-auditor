"""Initialization and status for external-key authenticated integrity."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from scripts.integrity import (
    IntegrityKeyError,
    load_key,
    marker_path,
    verify_marker,
    write_marker,
)


def initialize_integrity(workspace: str | Path) -> Dict[str, Any]:
    """Authenticate current evidence, registry, and seal state with an external HMAC key."""
    root = Path(workspace).resolve()
    key = load_key(root, required=True)
    assert key is not None
    marker = marker_path(root)
    if marker.exists():
        if not verify_marker(root, key):
            raise IntegrityKeyError("existing integrity marker is invalid or uses another key")
        current = integrity_status(root)
        if current.get("authenticated"):
            return current
        raise IntegrityKeyError("authenticated integrity is already initialized but current state no longer verifies; refusing to re-sign it")

    from .agents import initialize_registry_auth
    from .evidence import initialize_evidence_auth
    from .request_contract import activation_path, initialize_request_auth, request_path
    from .sealing import initialize_seal_auth

    if request_path(root).is_file() or activation_path(root).exists():
        initialize_request_auth(root, key)
    initialize_evidence_auth(root, key)
    initialize_registry_auth(root, key)
    initialize_seal_auth(root, key)
    write_marker(root, key)

    status = integrity_status(root)
    if not status.get("authenticated"):
        raise IntegrityKeyError(
            "integrity initialization did not pass post-write verification: %s"
            % status.get("problem", "unknown")
        )
    return status


def integrity_status(workspace: str | Path) -> Dict[str, Any]:
    root = Path(workspace).resolve()
    marker = marker_path(root)
    try:
        key = load_key(root, required=marker.exists())
    except IntegrityKeyError as exc:
        return {
            "authenticated": False,
            "configured": True,
            "marker_present": marker.exists(),
            "problem": str(exc),
        }

    if key is None:
        return {
            "authenticated": False,
            "configured": False,
            "marker_present": marker.exists(),
            "mode": "unsigned-compatibility",
            "problem": "external HMAC key is not configured",
        }
    if not marker.exists():
        return {
            "authenticated": False,
            "configured": True,
            "marker_present": False,
            "key_id": key.key_id,
            "problem": "integrity not initialized",
        }
    if not verify_marker(root, key):
        return {
            "authenticated": False,
            "configured": True,
            "marker_present": True,
            "key_id": key.key_id,
            "problem": "integrity marker verification failed",
        }

    from scripts import audit_check as core
    from .agents import MultiAgentRegistry
    from .evidence import verify_anchor_chain
    from .plans import all_plan_refs, seal_path
    from .request_contract import verify_request_contract
    from .sealing import SealIntegrityError, load_seal

    request = verify_request_contract(root)
    evidence_ok, evidence_count, evidence_problem = core.verify_chain(str(root))
    archive = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    registry = MultiAgentRegistry(str(root))
    registry_ok = registry.verify_registry_chain()

    seal_errors: list[str] = []
    seal_count = 0
    for ref in all_plan_refs(root):
        try:
            seal = load_seal(str(seal_path(root, ref.name)))
        except SealIntegrityError as exc:
            seal_errors.append(f"{ref.name}: {exc}")
            continue
        if seal is None:
            seal_errors.append(f"{ref.name}: authenticated plan has no seal")
        else:
            seal_count += 1

    request_ok = (not request.activated) or (request.valid and request.authenticated)
    authenticated = (
        request_ok
        and evidence_ok
        and archive.get("anchored") is True
        and registry_ok
        and not seal_errors
    )
    return {
        "authenticated": authenticated,
        "configured": True,
        "marker_present": True,
        "key_id": key.key_id,
        "key_source": key.source,
        "request_contract": request.as_dict(),
        "evidence": {
            "valid": evidence_ok,
            "records": evidence_count,
            "problem": evidence_problem,
        },
        "archive": archive,
        "registry": {
            "valid": registry_ok,
            "problem": registry.registry_problem,
        },
        "seals": {
            "valid": not seal_errors,
            "count": seal_count,
            "errors": seal_errors,
        },
        "problem": "" if authenticated else "authenticated integrity verification failed",
    }
