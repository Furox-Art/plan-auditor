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
    """Authenticate current evidence/registry state with an external HMAC key.

    Initialization is explicit so merely configuring a key can never bless an
    arbitrary unsigned state. Existing hash chains are validated first; only
    then are HMAC tags/checkpoints added. The signed marker is written last.
    """
    root = Path(workspace).resolve()
    key = load_key(root, required=True)
    assert key is not None
    marker = marker_path(root)
    if marker.exists() and not verify_marker(root, key):
        raise IntegrityKeyError("existing integrity marker is invalid or uses another key")

    from .agents import initialize_registry_auth
    from .evidence import initialize_evidence_auth

    initialize_evidence_auth(root, key)
    initialize_registry_auth(root, key)
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

    evidence_ok, evidence_count, evidence_problem = core.verify_chain(str(root))
    archive = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    registry = MultiAgentRegistry(str(root))
    registry_ok = registry.verify_registry_chain()
    authenticated = evidence_ok and archive.get("anchored") is True and registry_ok
    return {
        "authenticated": authenticated,
        "configured": True,
        "marker_present": True,
        "key_id": key.key_id,
        "key_source": key.source,
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
        "problem": "" if authenticated else "authenticated integrity verification failed",
    }
