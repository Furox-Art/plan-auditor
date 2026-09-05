"""L11 — evidence integrity, archive anchoring, and optional external HMAC auth."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scripts.integrity import (
    EVIDENCE_HEAD_DOMAIN,
    EVIDENCE_RECORD_DOMAIN,
    IntegrityKeyError,
    KeyMaterial,
    canonical as auth_canonical,
    make_auth,
    runtime_key,
    verify_auth,
)

EVIDENCE_HEAD = "evidence.head.json"


def _canonical(obj: Dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def _hash_payload(rec: Dict) -> Dict:
    return {k: v for k, v in rec.items() if k not in {"hash", "auth"}}


def _auth_payload(rec: Dict) -> Dict:
    return {k: v for k, v in rec.items() if k != "auth"}


def file_hash(path: str) -> Optional[str]:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def tail_hash(path: str) -> Optional[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            return value.get("hash") if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _record_count(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def verify_jsonl_chain(
    path: str,
    *,
    key: Optional[KeyMaterial] = None,
    require_auth: bool = False,
    ignore_auth: bool = False,
    initial_prev: str = "GENESIS",
) -> Tuple[Optional[bool], int, str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, 0, str(exc)
    records: List[Dict] = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, len(records), f"line {line_no} is not JSON"
        if not isinstance(rec, dict):
            return False, len(records), f"line {line_no} is not an object"
        records.append(rec)
    if not records:
        return True, 0, ""
    if any("prev" not in rec for rec in records):
        return None, len(records), "legacy archive lacks prev chain"

    prev = initial_prev
    for index, rec in enumerate(records, 1):
        if rec.get("prev") != prev:
            return False, index - 1, f"line {index}: prev chain broken"
        actual = rec.get("hash")
        expected = hashlib.sha256(_canonical(_hash_payload(rec)).encode("utf-8")).hexdigest()
        if actual != expected:
            return False, index - 1, f"line {index}: hash mismatch"
        if not ignore_auth:
            auth = rec.get("auth")
            if require_auth:
                if key is None or not verify_auth(key, EVIDENCE_RECORD_DOMAIN, _auth_payload(rec), auth):
                    return False, index - 1, f"line {index}: HMAC authentication failed"
            elif auth is not None and key is None:
                return False, index - 1, f"line {index}: authenticated record requires HMAC key"
            elif auth is not None and key is not None:
                if not verify_auth(key, EVIDENCE_RECORD_DOMAIN, _auth_payload(rec), auth):
                    return False, index - 1, f"line {index}: HMAC authentication failed"
        prev = actual
    return True, len(records), ""


@dataclass
class ArchiveManifest:
    archives: List[Dict]
    auth_problem: str = ""

    def anchored(self) -> bool:
        if self.auth_problem:
            return False
        if any(item.get("chain_valid") is False for item in self.archives):
            return False
        for index, item in enumerate(self.archives):
            if index == 0:
                continue
            previous = self.archives[index - 1]
            if item.get("previous_archive_hash") != previous.get("tail_hash"):
                return False
        return True

    def legacy_count(self) -> int:
        return sum(1 for item in self.archives if item.get("chain_valid") is None)


def _read_stored_link(path: str) -> Optional[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            return value.get("previous_archive_hash") if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _first_prev(path: str) -> Optional[str]:
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                return value.get("prev") if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
    return None


def _workspace_from_archive_dir(archive_dir: str | Path) -> Path:
    archive = Path(archive_dir).resolve()
    if archive.name == "archive" and archive.parent.name == ".plan-auditor":
        return archive.parent.parent
    return archive.parent


def build_archive_manifest(archive_dir: str) -> ArchiveManifest:
    archives: List[Dict] = []
    root = _workspace_from_archive_dir(archive_dir)
    try:
        key = runtime_key(root)
        auth_problem = ""
    except IntegrityKeyError as exc:
        key = None
        auth_problem = str(exc)
    if not os.path.isdir(archive_dir):
        return ArchiveManifest(archives=[], auth_problem=auth_problem)

    files = sorted(name for name in os.listdir(archive_dir) if name.endswith(".jsonl"))
    expected_prev = "GENESIS"
    for index, filename in enumerate(files):
        path = os.path.join(archive_dir, filename)
        first_prev = _first_prev(path)
        initial_prev = expected_prev
        chain_valid, record_count, chain_problem = verify_jsonl_chain(
            path, key=key, require_auth=key is not None, initial_prev=initial_prev
        )
        cross_archive_start = chain_valid is True
        # Backward compatibility for v2.0.x rotations: each archive began at
        # GENESIS and carried the previous archive tail in its final anchor.
        if chain_valid is False and index > 0 and first_prev == "GENESIS":
            legacy_valid, legacy_count, legacy_problem = verify_jsonl_chain(
                path, key=key, require_auth=key is not None, initial_prev="GENESIS"
            )
            if legacy_valid is True:
                chain_valid, record_count, chain_problem = legacy_valid, legacy_count, legacy_problem
                cross_archive_start = False
        item = {
            "file": filename,
            "sha256": file_hash(path),
            "tail_hash": tail_hash(path),
            "previous_archive_hash": _read_stored_link(path),
            "first_prev": first_prev,
            "cross_archive_start": cross_archive_start,
            "chain_valid": chain_valid,
            "record_count": record_count,
            "chain_problem": chain_problem,
            "authenticated": bool(key) and chain_valid is True,
        }
        archives.append(item)
        expected_prev = item.get("tail_hash") or expected_prev
    return ArchiveManifest(archives, auth_problem=auth_problem)


def verify_anchor_chain(archive_dir: str) -> Dict:
    manifest = build_archive_manifest(archive_dir)
    return {
        "anchored": manifest.anchored(),
        "archives": manifest.archives,
        "broken_at": _first_break(manifest),
        "legacy_archives": manifest.legacy_count(),
        "integrity_ok": (
            not manifest.auth_problem
            and all(item.get("chain_valid") is not False for item in manifest.archives)
        ),
        "auth_problem": manifest.auth_problem,
    }


def _first_break(manifest: ArchiveManifest) -> Optional[int]:
    if manifest.auth_problem:
        return 0
    for index, item in enumerate(manifest.archives):
        if item.get("chain_valid") is False:
            return index
        if index == 0:
            continue
        previous = manifest.archives[index - 1]
        if item.get("previous_archive_hash") != previous.get("tail_hash"):
            return index
    return None


def _sign_jsonl(path: Path, key: KeyMaterial, initial_prev: str = "GENESIS") -> None:
    if not path.exists():
        return
    valid, _count, problem = verify_jsonl_chain(
        str(path), key=key, require_auth=False, ignore_auth=True, initial_prev=initial_prev
    )
    if valid is False and initial_prev != "GENESIS" and _first_prev(str(path)) == "GENESIS":
        valid, _count, problem = verify_jsonl_chain(
            str(path), key=key, require_auth=False, ignore_auth=True, initial_prev="GENESIS"
        )
    if valid is False:
        raise IntegrityKeyError(f"cannot authenticate invalid evidence {path.name}: {problem}")
    if valid is None:
        raise IntegrityKeyError(f"cannot authenticate legacy unchained evidence {path.name}")
    output: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        payload = _auth_payload(rec)
        rec["auth"] = make_auth(key, EVIDENCE_RECORD_DOMAIN, payload)
        output.append(_canonical(rec))
    tmp = path.with_name(path.name + ".auth.tmp")
    tmp.write_text("\n".join(output) + ("\n" if output else ""), encoding="utf-8")
    os.replace(tmp, path)


def _evidence_head_payload(root: Path, key: KeyMaterial) -> Dict:
    active = root / ".plan-auditor" / "evidence.jsonl"
    archive_dir = root / ".plan-auditor" / "archive"
    archives = sorted(archive_dir.glob("evidence-*.jsonl")) if archive_dir.is_dir() else []
    return {
        "format_version": 2,
        "key_id": key.key_id,
        "active_count": _record_count(active),
        "active_tail": tail_hash(str(active)) or "GENESIS",
        "archive_tail": tail_hash(str(archives[-1])) if archives else None,
    }


def write_evidence_head(root: str | Path, key: KeyMaterial) -> Path:
    root_path = Path(root).resolve()
    payload = _evidence_head_payload(root_path, key)
    value = dict(payload)
    value["auth"] = make_auth(key, EVIDENCE_HEAD_DOMAIN, payload)
    path = root_path / ".plan-auditor" / EVIDENCE_HEAD
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(auth_canonical(value) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def verify_evidence_head(root: str | Path, key: KeyMaterial) -> Tuple[bool, str]:
    root_path = Path(root).resolve()
    path = root_path / ".plan-auditor" / EVIDENCE_HEAD
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "evidence authenticated head missing or invalid"
    if not isinstance(value, dict):
        return False, "evidence authenticated head is not an object"
    auth = value.get("auth")
    payload = {k: v for k, v in value.items() if k != "auth"}
    if payload != _evidence_head_payload(root_path, key):
        return False, "evidence authenticated head checkpoint mismatch"
    if not verify_auth(key, EVIDENCE_HEAD_DOMAIN, payload, auth):
        return False, "evidence authenticated head HMAC failed"
    return True, ""


def initialize_evidence_auth(root: str | Path, key: KeyMaterial) -> None:
    root_path = Path(root).resolve()
    pg = root_path / ".plan-auditor"
    archive_dir = pg / "archive"
    archives = sorted(archive_dir.glob("evidence-*.jsonl")) if archive_dir.is_dir() else []
    expected_prev = "GENESIS"
    for path in archives:
        _sign_jsonl(path, key, initial_prev=expected_prev)
        expected_prev = tail_hash(str(path)) or expected_prev
    active = pg / "evidence.jsonl"
    if active.exists():
        _sign_jsonl(active, key, initial_prev=expected_prev)
    write_evidence_head(root_path, key)
