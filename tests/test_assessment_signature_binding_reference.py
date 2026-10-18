"""Independent HMAC and evidence-binding checks for persisted PASS assessments."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import supervisor.assessment as assessment
from scripts.integrity import (
    SUPERVISOR_ASSESSMENT_DOMAIN,
    IntegrityKeyError,
    KeyMaterial,
    make_auth,
)

KEY = KeyMaterial(key=b"k" * 32, source="isolated regression fixture", key_id="fixture-key")


@pytest.fixture
def signed_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(assessment, "runtime_key", lambda root: KEY)
    monkeypatch.setattr(assessment, "tail_hash", lambda path: f"tail-{Path(path).name}")
    path = tmp_path / ".plan-auditor"
    (path / "archive").mkdir(parents=True)
    (path / "evidence.jsonl").write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    (path / "archive" / "evidence-20260101.jsonl").write_text('{"a":3}\n', encoding="utf-8")
    return tmp_path


def test_signed_persisted_pass_is_authenticated_and_bound_to_both_logs(
    signed_workspace: Path,
) -> None:
    payload = {"outcome": "PASS", "profile": "strict", "active_plan_count": 2}
    stored = assessment.write_assessment(signed_workspace, payload)
    assert stored["outcome"] == "PASS"
    assert stored["format_version"] == assessment.ASSESSMENT_FORMAT_VERSION
    assert stored["evidence_binding"] == {
        "key_id": KEY.key_id,
        "active_records": 2,
        "active_tail": "tail-evidence.jsonl",
        "archive_tail": "tail-evidence-20260101.jsonl",
    }
    assert assessment.read_assessment(signed_workspace) == stored
    verified = assessment.read_assessment_verified(signed_workspace)
    assert verified["verified"] and verified["present"]
    assert verified["assessment"]["outcome"] == "PASS"
    assert assessment.verified_outcome(signed_workspace) == "PASS"
    summary = assessment.assessment_verification(signed_workspace)
    assert summary["outcome"] == "PASS"
    assert summary["verified"]


def test_adding_evidence_invalidates_previous_authenticated_pass(
    signed_workspace: Path,
) -> None:
    assessment.write_assessment(signed_workspace, {"outcome": "PASS"})
    evidence = signed_workspace / ".plan-auditor" / "evidence.jsonl"
    evidence.write_text(evidence.read_text() + '{"c":3}\n')
    result = assessment.read_assessment_verified(signed_workspace)
    assert result["present"] and not result["verified"]
    assert "current evidence chain" in result["reason"]
    assert assessment.verified_outcome(signed_workspace) == "UNKNOWN"


@pytest.mark.parametrize("tamper", [
    lambda x: x.update(outcome="PASS") if x.get("outcome") != "PASS" else x.update(outcome="FAIL"),
    lambda x: x.pop("auth"),
    lambda x: x.update(auth={"alg": "none"}),
])
def test_tampered_document_never_produces_verifiable_pass(
    signed_workspace: Path, tamper,
) -> None:
    assessment.write_assessment(signed_workspace, {"outcome": "PASS"})
    path = assessment.assessment_path(signed_workspace)
    doc = json.loads(path.read_text())
    tamper(doc)
    path.write_text(json.dumps(doc))
    result = assessment.read_assessment_verified(signed_workspace)
    assert result["verified"] is False
    assert "signature" in result["reason"]


@pytest.mark.parametrize("version", [2, True])
def test_even_signed_unsupported_format_is_rejected(
    signed_workspace: Path, version: object,
) -> None:
    assessment.write_assessment(signed_workspace, {"outcome": "PASS"})
    path = assessment.assessment_path(signed_workspace)
    body = json.loads(path.read_text())
    body["format_version"] = version
    body.pop("auth")
    body["auth"] = make_auth(KEY, SUPERVISOR_ASSESSMENT_DOMAIN, body)
    path.write_text(json.dumps(body))
    assert not assessment.read_assessment_verified(signed_workspace)["verified"]


def test_signed_but_unbound_document_is_rejected(signed_workspace: Path) -> None:
    assessment.write_assessment(signed_workspace, {"outcome": "PASS"})
    path = assessment.assessment_path(signed_workspace)
    doc = json.loads(path.read_text())
    doc.pop("auth")
    doc["evidence_binding"] = "not an object"
    doc["auth"] = make_auth(KEY, SUPERVISOR_ASSESSMENT_DOMAIN, doc)
    path.write_text(json.dumps(doc))
    result = assessment.read_assessment_verified(signed_workspace)
    assert not result["verified"]
    assert "not bound" in result["reason"]


def test_unsigned_assessment_discards_computed_pass_and_per_plan_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(assessment, "runtime_key", lambda root: None)
    result = assessment.write_assessment(
        tmp_path,
        {
            "outcome": "PASS", "workspace": str(tmp_path), "profile": "strict",
            "mode": "auto", "error": "no key", "plans": {"task": {"outcome": "PASS"}},
            "steps": [{"outcome": "PASS"}], "active_plan_count": 1,
        },
    )
    assert result["outcome"] == "UNKNOWN"
    assert "auth" not in result
    assert "plans" not in result and "steps" not in result
    assert "active_plan_count" not in result
    assert result["profile"] == "strict"
    assert assessment.verified_outcome(tmp_path) == "UNKNOWN"


def test_key_misconfiguration_fails_closed_without_persisting_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bad_key(root):
        raise IntegrityKeyError("invalid key length")

    monkeypatch.setattr(assessment, "runtime_key", bad_key)
    doc = assessment.write_assessment(tmp_path, {"outcome": "PASS"})
    assert doc["outcome"] == "UNKNOWN"
    assert "invalid key length" in doc["unsigned_reason"]
    status = assessment.read_assessment_verified(tmp_path)
    assert status["present"] and not status["verified"]
    assert "cannot resolve" in status["reason"]


def test_assessment_missing_or_invalid_file_remains_unknown(tmp_path: Path) -> None:
    result = assessment.read_assessment_verified(tmp_path)
    assert not result["present"] and not result["verified"]
    assert assessment.read_assessment(tmp_path) is None
    assessment.assessment_path(tmp_path).parent.mkdir(parents=True)
    path = assessment.assessment_path(tmp_path)
    for text in ("not valid JSON", "[]", '{"outcome":"PASS",}', ""):
        path.write_text(text)
        assert assessment.read_assessment(tmp_path) is None
    assert assessment.assessment_verification(tmp_path)["outcome"] == "UNKNOWN"


def test_assessment_rejects_ambiguous_duplicate_or_nonfinite_json(tmp_path: Path) -> None:
    path = assessment.assessment_path(tmp_path)
    path.parent.mkdir(parents=True)
    for text in (
        '{"outcome":"FAIL","outcome":"PASS"}',
        '{"outcome":"UNKNOWN","extra":NaN}',
        '{"outcome":"UNKNOWN","extra":1e9999}',
        r'{"outcome":"UNKNOWN","extra":"\ud800"}',
    ):
        path.write_text(text, encoding="utf-8")
        assert assessment.read_assessment(tmp_path) is None


def test_atomic_write_retries_busy_destination_without_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / ".plan-auditor" / "assessment.json"
    path.parent.mkdir()
    path.write_text("previous fully written document")
    original = assessment.os.replace
    seen: list[tuple[str, str]] = []

    def transient(src, dst):
        seen.append((str(src), str(dst)))
        if len(seen) <= 2:
            raise PermissionError("transient Windows sharing violation")
        return original(src, dst)

    monkeypatch.setattr(assessment.os, "replace", transient)
    monkeypatch.setattr(assessment.time, "sleep", lambda delay: None)
    assessment.atomic_write_json(path, {"outcome": "UNKNOWN"})
    assert json.loads(path.read_text())["outcome"] == "UNKNOWN"
    assert len(seen) == 3
    assert not list(path.parent.glob("*.tmp"))


def test_atomic_write_gives_up_without_truncating_previous_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / ".plan-auditor" / "assessment.json"
    path.parent.mkdir()
    path.write_text("old complete file")

    def denied(src, dst):
        raise PermissionError("locked")

    monkeypatch.setattr(assessment.os, "replace", denied)
    clock = iter([0.0, 4.0])
    monkeypatch.setattr(assessment.time, "monotonic", lambda: next(clock))
    with pytest.raises(PermissionError):
        assessment.atomic_write_json(path, {"outcome": "UNKNOWN"})
    assert path.read_text() == "old complete file"
    assert not list(path.parent.glob("*.tmp"))


def test_evidence_binding_handles_absent_and_invalid_log_tails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(assessment, "tail_hash", lambda _: object())
    result = assessment.evidence_binding(tmp_path, KEY)
    assert result["active_records"] == 0
    assert result["active_tail"] is None
    assert result["archive_tail"] is None


def test_verified_outcome_refuses_empty_or_nontext_claims(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    for outcome in ("", True, None, 2):
        monkeypatch.setattr(
            assessment, "read_assessment_verified",
            lambda root: {"verified": True, "assessment": {"outcome": outcome}},
        )
        assert assessment.verified_outcome(tmp_path) == "UNKNOWN"


def test_assessment_ordinary_finite_float_survives_strict_parser(tmp_path: Path) -> None:
    path = assessment.assessment_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"outcome":"UNKNOWN","risk":0.125}', encoding="utf-8")
    assert assessment.read_assessment(tmp_path) == {
        "outcome": "UNKNOWN", "risk": 0.125,
    }


def test_oversized_assessment_is_rejected_before_json_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(assessment, "MAX_ASSESSMENT_BYTES", 64)
    path = assessment.assessment_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "outcome": "PASS",
        "padding": "x" * 100,
    }), encoding="utf-8")
    assert assessment.read_assessment(tmp_path) is None
    assert not assessment.read_assessment_verified(tmp_path)["verified"]
