"""External-key HMAC support for Plan Auditor integrity metadata.

The HMAC key must come from process environment or a key file outside the
workspace. Workspace files never contain the key. A signed marker prevents
silently upgrading an arbitrary unsigned state after a key is configured.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

HMAC_ALG = "hmac-sha256"
INTEGRITY_FORMAT_VERSION = 1
ENV_KEY = "PLAN_AUDITOR_HMAC_KEY"
ENV_KEY_FILE = "PLAN_AUDITOR_HMAC_KEY_FILE"
MARKER_NAME = "integrity.json"
MIN_KEY_BYTES = 32

EVIDENCE_RECORD_DOMAIN = "plan-auditor:evidence-record:v1"
EVIDENCE_HEAD_DOMAIN = "plan-auditor:evidence-head:v1"
REGISTRY_RECORD_DOMAIN = "plan-auditor:registry-record:v1"
REGISTRY_HEAD_DOMAIN = "plan-auditor:registry-head:v1"
SEAL_DOMAIN = "plan-auditor:plan-seal:v1"
MARKER_DOMAIN = "plan-auditor:integrity-marker:v1"


class IntegrityKeyError(RuntimeError):
    """Raised when authenticated integrity is configured incorrectly."""


@dataclass(frozen=True)
class KeyMaterial:
    key: bytes
    source: str
    key_id: str


def canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def marker_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / MARKER_NAME


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([str(root), str(candidate)]) == str(root)
    except ValueError:
        return False


def load_key(root: str | Path, *, required: bool = False) -> Optional[KeyMaterial]:
    """Load HMAC material without ever reading a key from the workspace."""
    workspace = Path(root).resolve()
    direct = os.environ.get(ENV_KEY)
    file_value = os.environ.get(ENV_KEY_FILE)
    if direct and file_value:
        raise IntegrityKeyError(f"set only one of {ENV_KEY} or {ENV_KEY_FILE}")

    source = ""
    raw: Optional[bytes] = None
    if direct is not None:
        raw = direct.encode("utf-8")
        source = "environment"
    elif file_value:
        key_path = Path(file_value).expanduser().resolve()
        if _inside(workspace, key_path):
            raise IntegrityKeyError("HMAC key file must be outside the workspace")
        try:
            raw = key_path.read_bytes().strip()
        except OSError as exc:
            raise IntegrityKeyError(f"cannot read HMAC key file: {exc}") from exc
        source = str(key_path)

    if raw is None:
        if required:
            raise IntegrityKeyError(
                f"authenticated integrity requires {ENV_KEY} or {ENV_KEY_FILE}"
            )
        return None
    if len(raw) < MIN_KEY_BYTES:
        raise IntegrityKeyError(f"HMAC key must contain at least {MIN_KEY_BYTES} bytes")
    return KeyMaterial(
        key=raw,
        source=source,
        key_id=hashlib.sha256(raw).hexdigest()[:16],
    )


def make_auth(key: KeyMaterial, domain: str, payload: Any) -> Dict[str, str]:
    body = domain.encode("utf-8") + b"\0" + canonical(payload).encode("utf-8")
    mac = hmac.new(key.key, body, hashlib.sha256).hexdigest()
    return {"alg": HMAC_ALG, "key_id": key.key_id, "mac": mac}


def verify_auth(key: KeyMaterial, domain: str, payload: Any, auth: Any) -> bool:
    if not isinstance(auth, dict):
        return False
    if auth.get("alg") != HMAC_ALG or auth.get("key_id") != key.key_id:
        return False
    expected = make_auth(key, domain, payload)["mac"]
    actual = auth.get("mac")
    return isinstance(actual, str) and hmac.compare_digest(actual, expected)


def _marker_payload(key: KeyMaterial) -> Dict[str, Any]:
    return {
        "format_version": INTEGRITY_FORMAT_VERSION,
        "key_id": key.key_id,
        "mode": "external-hmac",
    }


def write_marker(root: str | Path, key: KeyMaterial) -> Path:
    path = marker_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _marker_payload(key)
    value = dict(payload)
    value["auth"] = make_auth(key, MARKER_DOMAIN, payload)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(canonical(value) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def verify_marker(root: str | Path, key: KeyMaterial) -> bool:
    path = marker_path(root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(value, dict):
        return False
    auth = value.get("auth")
    payload = {k: v for k, v in value.items() if k != "auth"}
    return payload == _marker_payload(key) and verify_auth(
        key,
        MARKER_DOMAIN,
        payload,
        auth,
    )


def runtime_key(root: str | Path) -> Optional[KeyMaterial]:
    """Resolve runtime integrity mode and reject partial/downgraded setups."""
    path = marker_path(root)
    key = load_key(root, required=path.exists())
    if key is None:
        return None
    if not path.exists():
        raise IntegrityKeyError(
            "HMAC key is configured but integrity is not initialized; "
            "run 'plan-auditor integrity init <dir>'"
        )
    if not verify_marker(root, key):
        raise IntegrityKeyError("integrity marker is missing, invalid, or signed by another key")
    return key
