"""L11 — evidence integrity and cross-archive anchoring.

Evidence is tamper-evident, not immutable. New-format archives are validated
internally and across rotations. Legacy JSONL files remain discoverable for
backward compatibility and are marked as legacy integrity state.
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
            return json.loads(line).get("hash")
        except json.JSONDecodeError:
            return None
    return None


def verify_jsonl_chain(path: str) -> Tuple[Optional[bool], int, str]:
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

    prev = "GENESIS"
    for index, rec in enumerate(records, 1):
        if rec.get("prev") != prev:
            return False, index - 1, f"line {index}: prev chain broken"
        actual = rec.get("hash")
        unsigned = {k: v for k, v in rec.items() if k != "hash"}
        expected = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
        if actual != expected:
            return False, index - 1, f"line {index}: hash mismatch"
        prev = actual
    return True, len(records), ""


@dataclass
class ArchiveManifest:
    archives: List[Dict]

    def anchored(self) -> bool:
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
            return json.loads(line).get("previous_archive_hash")
        except json.JSONDecodeError:
            return None
    return None


def build_archive_manifest(archive_dir: str) -> ArchiveManifest:
    archives: List[Dict] = []
    if not os.path.isdir(archive_dir):
        return ArchiveManifest(archives=[])
    # Keep the original behavior of discovering any JSONL in the supplied
    # directory; production callers pass .plan-auditor/archive.
    files = sorted(name for name in os.listdir(archive_dir) if name.endswith(".jsonl"))
    for filename in files:
        path = os.path.join(archive_dir, filename)
        chain_valid, record_count, chain_problem = verify_jsonl_chain(path)
        archives.append({
            "file": filename,
            "sha256": file_hash(path),
            "tail_hash": tail_hash(path),
            "previous_archive_hash": _read_stored_link(path),
            "chain_valid": chain_valid,
            "record_count": record_count,
            "chain_problem": chain_problem,
        })
    return ArchiveManifest(archives)


def verify_anchor_chain(archive_dir: str) -> Dict:
    manifest = build_archive_manifest(archive_dir)
    return {
        "anchored": manifest.anchored(),
        "archives": manifest.archives,
        "broken_at": _first_break(manifest),
        "legacy_archives": manifest.legacy_count(),
        "integrity_ok": all(item.get("chain_valid") is not False for item in manifest.archives),
    }


def _first_break(manifest: ArchiveManifest) -> Optional[int]:
    for index, item in enumerate(manifest.archives):
        if item.get("chain_valid") is False:
            return index
        if index == 0:
            continue
        previous = manifest.archives[index - 1]
        if item.get("previous_archive_hash") != previous.get("tail_hash"):
            return index
    return None
