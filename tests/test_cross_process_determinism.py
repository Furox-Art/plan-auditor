"""Cross-process determinism: canonical hashes must not depend on hash seed.

The same contract/digest/evidence workload runs in two fresh interpreters
whose only difference is ``PYTHONHASHSEED``. A plan hash or evidence-chain
hash that moved with hash-seed ordering would silently invalidate seals and
audit trails, so the outputs must be byte-identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

CHILD = r'''
import json
import sys
import tempfile
from pathlib import Path

repo_root = Path(sys.argv[1])
sys.path.insert(0, str(repo_root / "scripts"))

import audit_check as ac
from contract import canonical_digest, canonical_json, plan_hash

plan = {
    "task": "cross-process determinism",
    "requirements": ["r2", "r1"],
    "required_tools": ["python"],
    "steps": [
        {
            "id": 1,
            "title": "compute",
            "verify": [{"type": "run", "cmd": "python -c \"print(1)\"", "expect_exit": 0}],
            "status": "pending",
        }
    ],
}
# Deliberately built from a set: the *insertion* order varies with the hash
# seed, while the values and the canonical encoding must not.
unordered = {key: len(key) for key in {"zeta", "alpha", "mu", "beta"}}

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    hashes = [
        ac.append_evidence(
            base,
            {"mode": "audit", "step": step, "status": "ok", "n": step, "labels": ["b", "a"]},
        )
        for step in (1, 2, 3)
    ]
    ok, count, problem = ac.verify_chain(base)

payload = {
    "plan_hash": plan_hash(plan),
    "canonical": canonical_json(unordered),
    "digest": canonical_digest(unordered),
    "evidence_hashes": hashes,
    "verify": {"ok": ok, "count": count, "problem": problem},
}
print(json.dumps(payload, ensure_ascii=False))
'''


@cache
def _run_with_hash_seed(seed: str) -> str:
    env = {
        **os.environ,
        "PYTHONHASHSEED": seed,
        "PYTHONIOENCODING": "utf-8",
    }
    completed = subprocess.run(
        [sys.executable, "-c", CHILD, str(REPO_ROOT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_hashes_are_byte_identical_across_hash_seeds() -> None:
    first = _run_with_hash_seed("0")
    second = _run_with_hash_seed("12345")
    assert first.strip()
    assert first.strip() == second.strip()


def test_workload_verifies_a_real_evidence_chain() -> None:
    payload = json.loads(_run_with_hash_seed("0"))
    assert len(payload["plan_hash"]) == 64
    assert len(payload["digest"]) == 64
    canonical = payload["canonical"]
    assert canonical == json.dumps(
        json.loads(canonical), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    assert payload["digest"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert len(payload["evidence_hashes"]) == 3
    assert all(len(value) == 64 for value in payload["evidence_hashes"])
    assert payload["verify"] == {"ok": True, "count": 3, "problem": ""}
