"""Tests for the platform-agnostic integrated gate hook."""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts import audit_check as core
from supervisor.cli import main as cli_main
from supervisor.integrity import initialize_integrity
from tests.request_fixture import activate_for_plan


@contextlib.contextmanager
def _hmac_key_for(root: Path):
    """Point the runtime at an external HMAC key outside the workspace."""
    key_file = root.parent / "hook-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    previous = os.environ.get("PLAN_AUDITOR_HMAC_KEY_FILE")
    os.environ["PLAN_AUDITOR_HMAC_KEY_FILE"] = str(key_file)
    try:
        yield key_file
    finally:
        if previous is None:
            os.environ.pop("PLAN_AUDITOR_HMAC_KEY_FILE", None)
        else:
            os.environ["PLAN_AUDITOR_HMAC_KEY_FILE"] = previous


def _run_hook(cwd, fmt="text", warn_file=None):
    hook = Path(__file__).resolve().parent.parent / "hooks" / "gate_hook.py"
    cmd = [sys.executable, str(hook), cwd, "--format", fmt]
    if warn_file:
        cmd += ["--warn-file", warn_file]
    return subprocess.run(cmd, capture_output=True, text=True)


def _write_plan(root: Path, status="pending", *, named: str | None = None):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    plan = {
        "task": "hook integration test",
        "created": "2026-09-03T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "Execute hook behavior", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [{
            "id": 1,
            "title": "behavior",
            "covers": ["REQ-001"],
            "status": status,
            "verify": [{"type": "run", "cmd": "python -c \"print('ok')\""}],
        }],
    }
    if named:
        plans = pg / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / f"{named}.json"
    else:
        path = pg / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    activate_for_plan(root, plan)


def _prepare_real_pass(root: Path):
    _write_plan(root)
    # Trust chain in order: the marker must exist before any HMAC-backed seal or
    # evidence record is written, because a configured key without an init
    # marker is a configuration error rather than a silent downgrade.
    initialize_integrity(root)
    assert cli_main(["plan", "verify", str(root)]) == 0
    assert cli_main(["audit", str(root)]) == 0


def test_hook_pass_only_with_authenticated_audit_and_seal():
    # Regression guard: PASS requires HMAC-authenticated evidence, not merely
    # a hash chain. A keyless environment must never be able to pass the
    # completion gate, so the key is configured for the whole flow.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with _hmac_key_for(root):
            _prepare_real_pass(root)
            result = _run_hook(d)
        assert result.returncode == 0
        assert "PASS" in result.stdout


def test_hook_refuses_pass_on_keyless_evidence():
    # The audit finding this pins: without an external HMAC key the whole
    # evidence chain can be rebuilt by anyone with write access, so the gate
    # must not treat it as proof. The failure names the missing key.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _prepare_real_pass(root)
        result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert result.returncode != 0
        assert data["outcome"] != "PASS"
        assert data["report"]["evidence"]["authenticated"] is False
        assert "evidence" in json.dumps(data["report"]["plans"], default=str)


def test_hook_refuses_pass_when_evidence_chain_is_rebuilt():
    # Direct replay of the reported bypass: rewrite every evidence record,
    # recompute the hash chain, leave it perfectly re-verifiable, and drop the
    # HMAC. A tamper-evident-only chain must not complete the gate.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with _hmac_key_for(root):
            _prepare_real_pass(root)
        path = root / ".plan-auditor" / "evidence.jsonl"
        records = []
        previous = "GENESIS"
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            rec["prev"] = previous
            payload = {k: v for k, v in rec.items() if k not in {"hash", "auth"}}
            rec["hash"] = hashlib_sha256(payload)
            rec["auth"] = {"alg": "none"}
            previous = rec["hash"]
            records.append(rec)
        path.write_text(
            "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in records) + "\n",
            encoding="utf-8",
        )
        result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert data["outcome"] != "PASS"
        assert result.returncode != 0


def hashlib_sha256(payload) -> str:
    import hashlib
    return hashlib.sha256(core.canonical(payload).encode("utf-8")).hexdigest()


def test_hook_blocks_verified_label_without_evidence():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="verified")
        result = _run_hook(d)
        assert result.returncode != 0
        assert "BLOCKED" in result.stdout
        assert "Seal" in result.stdout or "Fresh audit" in result.stdout


def test_hook_blocked_when_pending():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending")
        result = _run_hook(d)
        assert result.returncode == 1
        assert "BLOCKED" in result.stdout
        assert "default" in result.stdout


def test_hook_named_plan_is_active_even_without_default():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending", named="backend")
        result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert result.returncode != 0
        assert data["outcome"] == "FAIL"
        assert data["report"]["active_plan_count"] == 1
        assert "backend" in data["report"]["plans"]


def test_hook_no_plan_skips():
    with tempfile.TemporaryDirectory() as d:
        result = _run_hook(d)
        assert result.returncode == 0
        assert "No active plans" in result.stdout


def test_hook_json_format_reports_authenticated_pass():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with _hmac_key_for(root):
            _prepare_real_pass(root)
            result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert data["outcome"] == "PASS"
        assert data["report"]["fresh_audit"]["valid"] is True
        assert data["report"]["evidence"]["authenticated"] is True


def test_hook_warn_file_written():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending")
        warn = os.path.join(d, ".plan-auditor", "warn.json")
        result = _run_hook(d, warn_file=warn)
        assert result.returncode in (1, 3)
        assert os.path.isfile(warn)
        data = json.loads(Path(warn).read_text(encoding="utf-8"))
        assert data["outcome"] in ("FAIL", "UNKNOWN")
