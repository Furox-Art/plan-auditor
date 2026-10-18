"""Sealed plan inputs must have a unique, finite UTF-8 JSON interpretation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.audit_check import load_plan
from scripts.contract import PlanTrustError
from scripts.exec_trust import _read_json_object, require_plan_trust
from tests.trusted_workspace import establish_trust


@pytest.mark.parametrize(
    "raw",
    [
        '{"plan_hash":"a","plan_hash":"b"}',
        '{"environment":{"request_sha256":"a","request_sha256":"b"}}',
        '{"field":NaN}',
        '{"field":Infinity}',
        '{"field":1e9999}',
        '{"field":"\\ud800"}',
    ],
)
def test_untrusted_seal_json_must_have_unique_finite_unicode_fields(
    tmp_path: Path, raw: str
) -> None:
    source = tmp_path / "seal.json"
    source.write_text(raw, encoding="utf-8")
    with pytest.raises(PlanTrustError, match="unreadable"):
        _read_json_object(str(source), "plan seal")


def test_benign_nested_object_is_accepted(tmp_path: Path) -> None:
    source = tmp_path / "request.json"
    value = {"environment": {"items": ["Türkçe", 1.25, True]}}
    source.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    assert _read_json_object(str(source), "request contract") == value


def test_duplicated_seal_fields_rejected_before_command_trust(tmp_path: Path) -> None:
    workspace = tmp_path
    config = workspace / ".plan-auditor"
    config.mkdir()
    plan = {
        "task": "safe test", "created": "2026-10-01T00:00:00",
        "requirements": [{"id": "R1", "description": "test", "priority": "must"}],
        "required_tools": ["python"],
        "steps": [{"id": 1, "title": "test", "covers": ["R1"],
                   "verify": [{"type": "run", "cmd": "python -c \"print(1)\"", "expect_exit": 0}],
                   "status": "pending"}],
    }
    (config / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    establish_trust(workspace)
    seal = config / "seal.json"
    original = seal.read_text(encoding="utf-8").rstrip()
    assert original.endswith("}")
    # The appended duplicate deliberately changes how other parsers can
    # interpret the same sealed object. Never authorize such ambiguity.
    altered = original[:-1] + ', "plan_hash": "arbitrary"}'
    seal.write_text(altered, encoding="utf-8")
    with pytest.raises(PlanTrustError, match="duplicate"):
        require_plan_trust(str(workspace), load_plan(str(workspace)))
