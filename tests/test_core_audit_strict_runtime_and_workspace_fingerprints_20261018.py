"""Direct audit-core tests: runtime policy, evidence canonicalization and content fingerprints."""

from __future__ import annotations

import json
import os

import pytest

from scripts import audit_check as audit


def config_file(root, value):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    path = pg / "supervisor.json"
    path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
    return path


def test_valid_finite_float_is_preserved_without_softening_json_bounds():
    assert audit._finite_json_float("1.2345") == pytest.approx(1.2345)
    with pytest.raises(ValueError, match="non-finite JSON"):
        audit._finite_json_float("1e9999")


@pytest.mark.parametrize(
    "malformed",
    [
        '{"duplicates":1,"duplicates":2}',
        '{"infinity":NaN}',
        '{"infinity":Infinity}',
        '{"value":1e999}',
    ],
)
def test_audit_core_json_never_accepts_nonstandard_or_duplicate_evidence(malformed):
    with pytest.raises(ValueError):
        audit._strict_external_json(malformed)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({}, 3),
        ({"max_attempts": 5}, 5),
        ({"max_attempts": 1}, 1),
    ],
)
def test_verified_runtime_integer_fallback_is_explicit(data, expected):
    assert audit._strict_runtime_int(data, "max_attempts", 3, 1, 100) == expected


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (True, "integer"),
        (3.0, "integer"),
        ("5", "integer"),
        (0, "between"),
        (101, "between"),
    ],
)
def test_runtime_retry_budget_rejects_coercion_and_unbounded_values(value, reason):
    with pytest.raises(ValueError, match=reason):
        audit._strict_runtime_int({"max_attempts": value}, "max_attempts", 3, 1, 100)


@pytest.mark.parametrize(
    ("invalid", "message"),
    [
        ([], "root must be an object"),
        ({"profile": 2}, "profile must"),
        ({"profile": "unknown"}, "profile must"),
        ({"tier": False}, "tier must"),
        ({"tier": 5}, "tier must"),
        ({"mode": "anything"}, "mode must"),
        ({"pg_dir": "../outside"}, "pg_dir must"),
        ({"policies_dir": ""}, "policies_dir must"),
        ({"policies_dir": "../outside"}, "policies_dir must"),
        ({"extra": []}, "extra must be an object"),
        ({"heartbeat_sec": 3601}, "heartbeat_sec must"),
        ({"owner_timeout_sec": 0}, "owner_timeout_sec must"),
        ({"rotate_bytes": 10}, "rotate_bytes must"),
    ],
)
def test_audit_core_validated_config_requires_actual_bounded_structural_state(
    tmp_path, invalid, message
):
    config_file(tmp_path, invalid)
    with pytest.raises(ValueError, match=message):
        audit._validated_runtime_config(str(tmp_path))


def test_no_config_does_not_create_fictitious_supervisor_authority(tmp_path):
    assert audit._validated_runtime_config(str(tmp_path)) == {}
    assert audit._runtime_limits(str(tmp_path)) == (audit.MAX_ATTEMPTS, audit.ROTATE_BYTES)


def test_explicit_runtime_limits_are_read_back_exactly(tmp_path):
    config_file(
        tmp_path,
        {"profile": "strict", "mode": "parallel-strict", "max_attempts": 7, "rotate_bytes": 4096},
    )
    assert audit._runtime_limits(str(tmp_path)) == (7, 4096)


def test_supervisor_config_symlink_is_not_trusted_as_internal_authority(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    outside = tmp_path / "other.json"
    outside.write_text('{"profile":"strict"}')
    (pg / "supervisor.json").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        audit._validated_runtime_config(str(tmp_path))


def test_oversized_supervisor_config_is_rejected_without_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_SUPERVISOR_CONFIG_CHARS", 20)
    config_file(tmp_path, '{"profile":"standard","extra":{"x":123456}}')
    with pytest.raises(ValueError, match="size limit"):
        audit._validated_runtime_config(str(tmp_path))


def test_malformed_utf8_config_is_not_treated_as_empty_or_valid(tmp_path):
    path = config_file(tmp_path, {})
    path.write_bytes(b'{"profile":"\\xff"}')
    with pytest.raises(ValueError, match="invalid supervisor config"):
        audit._validated_runtime_config(str(tmp_path))


@pytest.mark.parametrize("invalid", [".", "..", "../escape", "a/b", "not legal", "x" * 130])
def test_plan_name_never_grants_authorization_to_external_basename(invalid):
    with pytest.raises(ValueError, match="invalid plan name"):
        audit.validate_plan_name(invalid)


def test_immutable_plan_contract_hash_ignores_mutable_runtime_state():
    plan = {
        "task": "real audit",
        "steps": [
            {
                "id": 1,
                "title": "verify",
                "verify": [{"type": "pytest", "args": "tests"}],
                "status": "pending",
                "results": [{"passed": False}],
            },
        ],
    }
    first = audit.plan_contract_fingerprint(plan)
    plan["steps"][0]["status"] = "verified"
    plan["steps"][0]["results"] = [{"passed": True}]
    assert audit.plan_contract_fingerprint(plan) == first
    plan["steps"][0]["verify"][0]["args"] = "tests/changed"
    assert audit.plan_contract_fingerprint(plan) != first


def test_workspace_fingerprint_sees_actual_bytes_but_not_mtime_or_git_metadata(tmp_path):
    actual = tmp_path / "study.txt"
    actual.write_text("data-one")
    fingerprint = audit.workspace_fingerprint(str(tmp_path))
    os.utime(actual, (1500000000, 1500000000))
    assert audit.workspace_fingerprint(str(tmp_path)) == fingerprint
    git = tmp_path / ".git"
    git.mkdir()
    (git / "metadata").write_text("changed-untrusted-metadata")
    assert audit.workspace_fingerprint(str(tmp_path)) == fingerprint
    actual.write_text("data-two")
    assert audit.workspace_fingerprint(str(tmp_path)) != fingerprint


def test_workspace_fingerprint_records_real_directory_and_symlink_transitions(tmp_path):
    external = tmp_path.parent / (tmp_path.name + "-independent")
    original = audit.workspace_fingerprint(str(tmp_path))
    folder = tmp_path / "directory"
    folder.mkdir()
    after_dir = audit.workspace_fingerprint(str(tmp_path))
    assert after_dir != original
    symlink = tmp_path / "link"
    symlink.symlink_to(external, target_is_directory=True)
    after_link = audit.workspace_fingerprint(str(tmp_path))
    assert after_link != after_dir
    symlink.unlink()
    assert audit.workspace_fingerprint(str(tmp_path)) == after_dir


@pytest.mark.skipif(os.name == "nt", reason="Windows does not expose POSIX permission bits through chmod")
def test_workspace_fingerprint_tracks_executable_permission_without_reading_binary_content(
    tmp_path,
):
    file = tmp_path / "script.sh"
    file.write_text("#!/bin/sh\\nexit 0\\n")
    os.chmod(file, 0o600)
    before = audit.workspace_fingerprint(str(tmp_path))
    os.chmod(file, 0o700)
    assert audit.workspace_fingerprint(str(tmp_path)) != before


def test_empty_nonobject_step_cannot_be_used_to_satisfy_immutable_plan_digest():
    plan = {"task": "science", "steps": [123]}
    first = audit.plan_contract_fingerprint(plan)
    assert len(first) == 64
    plan["steps"] = [{"id": 1, "verify": [{"type": "pytest", "args": "tests"}]}]
    assert audit.plan_contract_fingerprint(plan) != first
