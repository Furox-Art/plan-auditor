"""Deterministic plan/evidence workload sampled by the determinism matrix."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / "scripts"))

    from scripts import audit_check as ac
    from scripts.contract import canonical_digest, canonical_json, plan_hash

    # audit_check predates strict typing; bind the two entry points through a
    # typed callable so this workload does not add no-untyped-call findings to
    # the ratchet baseline.
    append_evidence: Callable[..., Any] = ac.append_evidence
    verify_chain: Callable[..., Any] = ac.verify_chain

    plan = {
        "task": "determinism matrix",
        "requirements": ["r2", "r1"],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "compute",
                "verify": [{"type": "run", "cmd": 'python -c "print(1)"', "expect_exit": 0}],
                "status": "pending",
            }
        ],
    }
    unordered = {key: len(key) for key in {"zeta", "alpha", "mu", "beta"}}

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        hashes = [
            append_evidence(
                base,
                {"mode": "audit", "step": step, "status": "ok", "n": step, "labels": ["b", "a"]},
            )
            for step in (1, 2, 3)
        ]
        ok, count, problem = verify_chain(base)

    payload: dict[str, Any] = {
        "plan_hash": plan_hash(plan),
        "canonical": canonical_json(unordered),
        "digest": canonical_digest(unordered),
        "evidence_hashes": hashes,
        "verify": {"ok": ok, "count": count, "problem": problem},
    }
    if not payload["verify"]["ok"] or payload["verify"]["count"] != 3:
        raise SystemExit("evidence chain did not verify; the workload is vacuous")
    artifact_dir = os.environ.get("DETERMINISM_ARTIFACT_DIR")
    if artifact_dir:
        Path(artifact_dir, "payload.json").write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
    print(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
