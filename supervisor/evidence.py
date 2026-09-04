"""L11 — Evidence hardening.

Extends the existing evidence chain with cross-archive anchoring so
rotation does not break verifiability. Each archive file carries the
hash of the previous archive's tail, forming an anchored chain.
Tamper-evident (best-effort), not cryptographically immutable.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


def file_hash(path: str) -> Optional[str]:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def tail_hash(path: str) -> Optional[str]:
    """Hash of the last evidence record's own hash (chain anchor)."""
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


@dataclass
class ArchiveManifest:
    archives: List[Dict]

    def anchored(self) -> bool:
        for i, arch in enumerate(self.archives):
            if i == 0:
                continue
            prev = self.archives[i - 1]
            if arch.get("previous_archive_hash") != prev.get("tail_hash"):
                return False
        return True


def build_archive_manifest(archive_dir: str) -> ArchiveManifest:
    """Scan `archive_dir` for `evidence-*.jsonl` and read stored anchor links.

    Each archive's final record may store a `previous_archive_hash` linking
    it to the previous archive's tail. The manifest reads these stored links
    (it does not recompute them) so breaks are detectable.
    """
    archives: List[Dict] = []
    if not os.path.isdir(archive_dir):
        return ArchiveManifest(archives=archives)
    files = sorted(f for f in os.listdir(archive_dir) if f.endswith(".jsonl"))
    for fn in files:
        path = os.path.join(archive_dir, fn)
        stored_link = _read_stored_link(path)
        archives.append({
            "file": fn,
            "sha256": file_hash(path),
            "tail_hash": tail_hash(path),
            "previous_archive_hash": stored_link,
        })
    return ArchiveManifest(archives=archives)


def _read_stored_link(path: str) -> Optional[str]:
    """Read the previous_archive_hash stored in the archive's last record."""
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
    return {
        "anchored": manifest.anchored(),
        "archives": manifest.archives,
        "broken_at": _first_break(manifest),
    }


def _first_break(manifest: ArchiveManifest) -> Optional[int]:
    for i, arch in enumerate(manifest.archives):
        if i == 0:
            continue
        prev = manifest.archives[i - 1]
        if arch.get("previous_archive_hash") != prev.get("tail_hash"):
            return i
    return None
