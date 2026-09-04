"""L11 — evidence integrity and cross-archive anchoring.

Evidence is tamper-evident, not immutable. New-format archives are validated
internally (record hash chain) and across rotations (previous archive tail).
Legacy archives remain readable but are marked as legacy integrity state.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _canonical(obj: Dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def file_hash(path: str) -> Optional[str]:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def tail_hash(path: str) -> Optional[str]:
    """Return the last evidence record's own hash."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return None
        return rec.get("hash")
    return None


def verify_jsonl_chain(path: str) -> Tuple[Optional[bool], int, str]:
    """Validate one evidence JSONL file.

    Returns ``(True, n, '')`` for new-format valid chains, ``(False, n, reason)``
    for corrupt chains, and ``(None, n, 'legacy')`` when records predate the
    ``prev`` field and therefore cannot prove an internal chain.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, 0, str(exc)

    records: List[Dict] = []
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, len(records), f"line {i} is not JSON"
        if not isinstance(rec, dict):
            return False, len(records), f"line {i} is not an object"
        records.append(rec)

    if not records:
        return True, 0, ""
    if any("prev" not in rec for rec in records):
        return None, len(records), "legacy archive lacks prev chain"

    prev = "GENESIS"
    for i, rec in enumerate(records, 1):
        if rec.get("prev") != prev:
            return False, i - 1, f"line {i}: prev chain broken"
        actual = rec.get("hash")
        unsigned = {k: v for k, v in rec.items() if k != "hash"}
        expected = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
        if actual != expected:
            return False, i - 1, f"line {i}: hash mismatch"
        prev = actual
    return True, len(records), ""


@dataclass
class ArchiveManifest:
    archives: List[Dict]

    def anchored(self) -> bool:
        for arch in self.archives:
            if arch.get("chain_valid") is False:
                return False
        for i, arch in enumerate(self.archives):
            if i == 0:
                continue
            prev = self.archives[i - 1]
            if arch.get("previous_archive_hash") != prev.get("tail_hash"):
                return False
        return True

    def legacy_count(self) -> int:
        return sum(1 for a in self.archives if a.get("chain_valid") is None)


def build_archive_manifest(archive_dir: str) -> ArchiveManifest:
    archives: List[Dict] = []
    if not os.path.isdir(archive_dir):
        return ArchiveManifest(archives=archives)
    files = sorted(f for f in os.listdir(archive_dir) if f.startswith("evidence-") and f.endswith(".jsonl"))
    for fn in files:
        path = os.path.join(archive_dir, fn)
        stored_link = _read_stored_link(path)
        chain_valid, record_count, chain_problem = verify_jsonl_chain(path)
        archives.append({
            "file": fn,
            "sha256": file_hash(path),
            "tail_hash": tail_hash(path),
            "previous_archive_hash": stored_link,
            "chain_valid": chain_valid,
            "record_count": record_count,
            "chain_problem": chain_problem,
        })
    return ArchiveManifest(archives=archives)


def _read_stored_link(path: str) -> Optional[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return None
        return rec.get("previous_archive_hash")
    return None


def verify_anchor_chain(archive_dir: str) -> Dict:
    manifest = build_archive_manifest(archive_dir)
    anchored = manifest.anchored()
    return {
        "anchored": anchored,
        "archives": manifest.archives,
        "broken_at": _first_break(manifest),
        "legacy_archives": manifest.legacy_count(),
        "integrity_ok": all(a.get("chain_valid") is not False for a in manifest.archives),
    }


def _first_break(manifest: ArchiveManifest) -> Optional[int]:
    for i, arch in enumerate(manifest.archives):
        if arch.get("chain_valid") is False:
            return i
        if i == 0:
            continue
        prev = manifest.archives[i - 1]
        if arch.get("previous_archive_hash") != prev.get("tail_hash"):
            return i
    return None
