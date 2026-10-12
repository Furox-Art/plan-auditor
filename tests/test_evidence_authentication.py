"""Regression tests for authenticated — not merely tamper-evident — evidence.

These pin the fix for the audit finding that a keyless completion gate could be
passed by rewriting the evidence chain. Without an external HMAC key any actor
with write access to the workspace can recompute every SHA-256 and rebuild a
fully "valid" chain, so the gate must require authentication and report its
absence instead of silently accepting the chain.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts import audit_check as core
from scripts.integrity import UNSIGNED_AUTH
from supervisor.integrity import initialize_integrity


def _workspace_without_key(tmp_path: Path, monkeypatch) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    return workspace


def _key_for(tmp_path: Path, monkeypatch) -> Path:
    key_file = tmp_path / "outside-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    return key_file


def _append_unsigned_record(workspace: Path, status: str = "verified") -> None:
    core.append_evidence(str(workspace), {
        "ts": "2026-10-12T00:00:00+00:00",
        "mode": "run",
        "plan": "default",
        "step": 1,
        "results": [],
        "status": status,
    })


def test_unsigned_records_carry_an_explicit_auth_descriptor(tmp_path: Path, monkeypatch):
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    rec = json.loads(
        (workspace / ".plan-auditor" / "evidence.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert rec["auth"] == UNSIGNED_AUTH


def test_keyless_evidence_chain_is_not_authentication(tmp_path: Path, monkeypatch):
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    authenticated, problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is False
    assert "PLAN_AUDITOR_HMAC_KEY" in problem
    # The chain itself still verifies: tamper-evidence and authentication are
    # separate claims, and only the second gates completion.
    ok, _, chain_problem = core.verify_chain(str(workspace))
    assert ok is True and chain_problem == ""


def test_empty_workspace_has_nothing_to_authenticate(tmp_path: Path, monkeypatch):
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    authenticated, problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is False
    assert "no active evidence" in problem


def test_hmac_backed_chain_is_authentication(tmp_path: Path, monkeypatch):
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    _key_for(tmp_path, monkeypatch)
    result = initialize_integrity(workspace)
    assert result["authenticated"] is True
    authenticated, problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is True and problem == ""


def test_configured_key_without_marker_fails_closed(tmp_path: Path, monkeypatch):
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    _key_for(tmp_path, monkeypatch)  # key configured, integrity never initialised
    authenticated, problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is False
    assert "integrity" in problem.lower()


def test_modified_unsigned_auth_descriptor_is_rejected(tmp_path: Path, monkeypatch):
    """Stripping or inventing an ``auth`` descriptor is not a bypass."""
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    path = workspace / ".plan-auditor" / "evidence.jsonl"
    rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    rec["auth"] = {"alg": "hmac-sha256", "key_id": "fabricated", "mac": "deadbeef"}
    path.write_text(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    ok, _, problem = core.verify_chain(str(workspace))
    assert ok is False
    assert "HMAC key" in problem
    authenticated, auth_problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is False
    assert "unrecognised auth" in auth_problem


def test_misconfigured_key_state_reports_a_usable_problem(tmp_path: Path, monkeypatch):
    """Two env forms at once is a configuration error, never a downgrade."""
    workspace = _workspace_without_key(tmp_path, monkeypatch)
    _append_unsigned_record(workspace)
    # Both env forms set at once is a configuration error, never a downgrade.
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", "k" * 64)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", "/dev/null")
    authenticated, problem = core.evidence_is_authenticated(str(workspace))
    assert authenticated is False
    assert "PLAN_AUDITOR_HMAC_KEY" in problem
