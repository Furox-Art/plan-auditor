"""HMAC-authenticated persistence for the supervisor's own assessment.

``.plan-auditor/supervisor-assessment.json`` is the file CI reads as a required
status check: the daemon writes its own verdict there so a PASS survives the
process that produced it. Written as plain JSON it had no integrity binding at
all — anything that could create that path could forge a PASS, and the reader
had no way to tell a real verdict from a hand-written one.

This module closes that hole with the machinery the evidence chain already uses:

* the assessment body is signed with the configured external HMAC key
  (``runtime_key`` / ``make_auth`` / ``verify_auth``), over the
  ``plan-auditor:supervisor-assessment:v1`` domain, so a rewritten file fails
  verification instead of passing silently;
* the signed body carries an ``evidence_binding`` block — key id, active record
  count and chain tail, and the archive tail — recomputed on read, so a signed
  verdict is only accepted while it still describes the evidence it was computed
  from;
* in a keyless state the writer **fails closed**: it never persists a
  PASS-shaped assessment. ``UNKNOWN`` is stored instead, with the reason, because
  a file without a signature is exactly the forgeable artefact the gate exists
  to refuse.
"""
from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any

from scripts.integrity import (
    SUPERVISOR_ASSESSMENT_DOMAIN,
    IntegrityKeyError,
    KeyMaterial,
    make_auth,
    runtime_key,
    verify_auth,
)

from .evidence import tail_hash

ASSESSMENT_FILENAME = "supervisor-assessment.json"
ASSESSMENT_FORMAT_VERSION = 1
UNKNOWN_OUTCOME = "UNKNOWN"


def assessment_path(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".plan-auditor" / ASSESSMENT_FILENAME


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON to ``path`` atomically.

    Uses a unique sibling temp file so independent writers cannot collide.
    Windows can transiently reject replacement while a reader has the old
    destination open; that sharing violation is retried rather than falling back
    to a non-atomic in-place write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    deadline = time.monotonic() + 3.0
    try:
        while True:
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _count_records(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except (OSError, UnicodeError):
        return 0


def _last_hash(path: Path) -> str | None:
    value = tail_hash(str(path))
    return value if isinstance(value, str) else None


def evidence_binding(workspace: str | Path, key: KeyMaterial) -> dict[str, Any]:
    """The evidence state an assessment is bound to at the moment it is signed.

    The same chain-tail facts the evidence head checkpoint records, so an
    assessment cannot be replayed against a different evidence log. Any failure
    to read the chain is reported as ``None`` rather than guessed: an unknown
    tail must not look like a known one.
    """
    root = Path(workspace).resolve()
    active = root / ".plan-auditor" / "evidence.jsonl"
    archive_dir = root / ".plan-auditor" / "archive"
    archives = sorted(archive_dir.glob("evidence-*.jsonl")) if archive_dir.is_dir() else []
    return {
        "key_id": key.key_id,
        "active_records": _count_records(active),
        "active_tail": _last_hash(active),
        "archive_tail": _last_hash(archives[-1]) if archives else None,
    }


def sign_assessment(payload: dict[str, Any], key: KeyMaterial,
                    binding: dict[str, Any]) -> dict[str, Any]:
    """Return the stored form of ``payload``: signed, versioned, evidence-bound."""
    body = {name: value for name, value in payload.items() if name not in {"auth", "format_version"}}
    body["format_version"] = ASSESSMENT_FORMAT_VERSION
    body["evidence_binding"] = binding
    body["auth"] = make_auth(key, SUPERVISOR_ASSESSMENT_DOMAIN, body)
    return body


#: The only fields an unsigned, fail-closed document carries. A PASS-shaped
#: assessment must not be storable without a signature, so nothing from the
#: computed payload — least of all its per-plan outcomes — is copied across.
_UNSIGNED_PASSTHROUGH = ("workspace", "profile", "mode", "error")


def _unsigned_form(payload: dict[str, Any], problem: str) -> dict[str, Any]:
    """Fail closed: never a PASS-shaped assessment without a signature.

    The document is built from a fixed whitelist rather than from the computed
    payload, so there is no code path by which a per-plan PASS, a gate verdict or
    any other pass-shaped field survives into a file a reader cannot verify. The
    reason is kept so an operator can see why the verdict was withheld.
    """
    body: dict[str, Any] = {
        "format_version": ASSESSMENT_FORMAT_VERSION,
        "outcome": UNKNOWN_OUTCOME,
    }
    for name in _UNSIGNED_PASSTHROUGH:
        value = payload.get(name)
        if isinstance(value, str) and value:
            body[name] = value
    body["unsigned_reason"] = (
        "assessment is unsigned (fail closed): %s. A plain JSON assessment is "
        "forgeable by anyone who can write this file, so the computed verdict is "
        "withheld. Configure PLAN_AUDITOR_HMAC_KEY or PLAN_AUDITOR_HMAC_KEY_FILE "
        "and run 'plan-auditor integrity init .' to make persisted assessments "
        "verifiable." % (problem or "no external HMAC key is configured")
    )
    return body


def write_assessment(workspace: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Sign and persist the assessment, or fail closed to an unsigned ``UNKNOWN``.

    Returns the document that was written, so a caller can report the outcome it
    actually published rather than the one it computed.
    """
    root = Path(workspace).resolve()
    problem = ""
    key: KeyMaterial | None
    try:
        key = runtime_key(root)
    except IntegrityKeyError as exc:
        key = None
        problem = str(exc)
    if key is None:
        stored = _unsigned_form(payload, problem)
    else:
        stored = sign_assessment(payload, key, evidence_binding(root, key))
    atomic_write_json(assessment_path(root), stored)
    return stored


MAX_ASSESSMENT_BYTES = 1024 * 1024


def _unique_object_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError(f"duplicate assessment JSON field: {name}")
        value[name] = item
    return value


def _finite_assessment_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite assessment JSON number")
    return value


def _reject_nonjson_constant(raw: str) -> None:
    raise ValueError(f"non-standard assessment JSON constant: {raw}")


def _parse_assessment(raw: str) -> Any:
    value = json.loads(
        raw,
        object_pairs_hook=_unique_object_fields,
        parse_float=_finite_assessment_float,
        parse_constant=_reject_nonjson_constant,
    )
    # Python can decode lone UTF-16 surrogate escapes, which are not legal
    # Unicode scalar values in an interoperable UTF-8 JSON document.
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def read_assessment(workspace: str | Path) -> dict[str, Any] | None:
    """The stored document exactly as written, or ``None`` when unreadable.

    Diagnostic read only. It performs no verification, so its result must never
    be used as a verdict; use :func:`read_assessment_verified` for that.
    """
    try:
        with assessment_path(workspace).open("r", encoding="utf-8") as handle:
            raw = handle.read(MAX_ASSESSMENT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_ASSESSMENT_BYTES:
            return None
        value = _parse_assessment(raw)
    except (OSError, ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def read_assessment_verified(workspace: str | Path) -> dict[str, Any]:
    """Read the persisted assessment and prove both its signature and its binding.

    Returns ``{"present", "verified", "reason", "assessment"}``. Any state that
    cannot be proven — a missing or unreadable file, a missing or unusable key,
    an absent or wrong signature, a binding that no longer matches the evidence
    chain — is reported as unverified with an actionable reason and never as a
    verdict. This is the reader CI must use.
    """
    root = Path(workspace).resolve()
    document = read_assessment(root)
    if document is None:
        return _rejection("persisted assessment is missing or not readable JSON", present=False)

    try:
        key = runtime_key(root)
    except IntegrityKeyError as exc:
        return _rejection(f"cannot resolve the HMAC key to verify this assessment: {exc}")
    if key is None:
        return _rejection(
            "no external HMAC key is configured, so this assessment carries no "
            "signature a reader could check; an unsigned assessment is only ever "
            "written in the fail-closed UNKNOWN state"
        )

    auth = document.get("auth")
    body = {name: value for name, value in document.items() if name != "auth"}
    if not verify_auth(key, SUPERVISOR_ASSESSMENT_DOMAIN, body, auth):
        return _rejection(
            "persisted assessment signature is missing or does not match the "
            "configured HMAC key"
        )
    if (
        type(body.get("format_version")) is not int
        or body["format_version"] != ASSESSMENT_FORMAT_VERSION
    ):
        return _rejection("persisted assessment format version is not recognised")
    binding = body.get("evidence_binding")
    if not isinstance(binding, dict):
        return _rejection("persisted assessment is not bound to any evidence chain")
    if binding != evidence_binding(root, key):
        return _rejection(
            "persisted assessment is not bound to the current evidence chain, so "
            "it describes a state that no longer exists"
        )
    return {"present": True, "verified": True, "reason": "", "assessment": body}


def _rejection(reason: str, *, present: bool = True) -> dict[str, Any]:
    return {"present": present, "verified": False, "reason": reason, "assessment": None}


def verified_outcome(workspace: str | Path) -> str:
    """The persisted, proven outcome — or ``UNKNOWN`` when it cannot be proven."""
    result = read_assessment_verified(workspace)
    if not result["verified"]:
        return UNKNOWN_OUTCOME
    assessment = result["assessment"] or {}
    outcome = assessment.get("outcome")
    return outcome if isinstance(outcome, str) and outcome else UNKNOWN_OUTCOME


def assessment_verification(workspace: str | Path) -> dict[str, Any]:
    """Compact verification summary for report surfaces (``status``, ``doctor``).

    Carries the proven outcome and the reason it could not be proven, so a report
    never has to fall back to the unverified document to explain a verdict.
    """
    result = read_assessment_verified(workspace)
    return {
        "present": bool(result["present"]),
        "verified": bool(result["verified"]),
        "outcome": verified_outcome(workspace),
        "reason": result["reason"],
    }
