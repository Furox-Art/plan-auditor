"""One-pass evidence accounting and HMAC authentication remain distinct claims."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import audit_check as ac


def ledger(tmp_path, lines):
    root = tmp_path / ".plan-auditor"
    root.mkdir(exist_ok=True)
    path = root / "evidence.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def record(*, previous="GENESIS", mode="run", status="failed", step=1, plan="default", auth=None):
    row = {"prev": previous, "mode": mode, "status": status, "step": step, "plan": plan}
    row["hash"] = hashlib.sha256(ac.canonical(row).encode()).hexdigest()
    if auth is not None:
        row["auth"] = auth
    return row


def test_missing_empty_malformed_and_nonobject_evidence_tails_are_not_trusted(tmp_path):
    p = tmp_path / "missing.jsonl"
    assert ac._last_record_hash(str(p)) == "GENESIS"
    for payload in ("", "\n\n", "not-json\n", "[]\n", "{}\n"):
        p.write_text(payload, encoding="utf-8")
        assert ac._last_record_hash(str(p)) == "GENESIS"


def test_tail_reader_finds_actual_last_record_after_long_irrelevant_lines(tmp_path):
    path = tmp_path / "evidence.jsonl"
    last = {"hash": "observed-sha"}
    path.write_text(
        json.dumps({"hash": "old", "padding": "x" * 90_000}) + "\n" + json.dumps(last) + "\n\n",
        encoding="utf-8",
    )
    assert ac._last_record_hash(str(path)) == "observed-sha"


def test_archive_rotation_sequence_selects_highest_valid_record_only(tmp_path):
    root = tmp_path / ".plan-auditor" / "archive"
    root.mkdir(parents=True)
    for name in (
        "evidence-seq00000002-20261018.jsonl",
        "evidence-seq00000011-20261018.jsonl",
        "evidence-20261018-seqINVALID.jsonl",
        "unrelated.jsonl",
    ):
        (root / name).touch()
    # The sequence regex is anchored; unrelated archives are ignored.
    assert ac._next_rotation_sequence(str(tmp_path)) == 12


def test_missing_archive_directory_starts_at_sequence_one(tmp_path):
    assert ac._next_rotation_sequence(str(tmp_path)) == 1
    assert ac._archive_paths(str(tmp_path)) == []


def test_nonrecord_archive_names_are_excluded_from_counted_evidence_paths(tmp_path):
    root = tmp_path / ".plan-auditor" / "archive"
    root.mkdir(parents=True)
    (root / "unrelated.jsonl").write_text("{}")
    (root / "evidence-real.jsonl").write_text("{}")
    files = ac._archive_paths(str(tmp_path))
    assert len(files) == 1
    assert files[0].endswith("evidence-real.jsonl")


def test_failed_attempt_counter_only_counts_observed_failed_executions(tmp_path):
    rows = [
        {"mode": "run", "status": "failed", "step": 1, "plan": "paper"},
        {"mode": "run", "status": "failed", "step": 1, "plan": "paper"},
        {"mode": "audit", "status": "failed", "step": 1, "plan": "paper"},
        {"mode": "run", "status": "verified", "step": 1, "plan": "paper"},
        {"mode": "run", "status": "failed", "step": True, "plan": "paper"},
        {"mode": "run", "status": "failed", "step": 1, "plan": 12},
    ]
    ledger(tmp_path, [json.dumps(x) for x in rows])
    assert ac.failed_attempt_counts(str(tmp_path)) == {("paper", 1): 2}
    assert ac.count_failed_attempts(str(tmp_path), 1, plan="paper") == 2
    assert ac.count_failed_attempts(str(tmp_path), 2, plan="paper") == 0
    assert ac.failed_attempt_counts(str(tmp_path), mode="audit") == {("paper", 1): 1}


@pytest.mark.parametrize(
    "row",
    [
        "not valid JSON",
        "[]",
        '{"status":"failed","status":"verified"}',
        '{"step":1e99999}',
    ],
)
def test_malformed_untrusted_evidence_records_are_refused_for_attempt_accounting(tmp_path, row):
    ledger(tmp_path, [row])
    with pytest.raises(ValueError, match="ambiguous or corrupt|invalid evidence record"):
        ac.failed_attempt_counts(str(tmp_path))


def test_empty_evidence_lines_do_not_create_attempts(tmp_path):
    ledger(tmp_path, ["", "   ", json.dumps({"step": 1, "mode": "audit", "status": "verified"})])
    assert ac.failed_attempt_counts(str(tmp_path)) == {}


def test_signed_head_without_configured_key_cannot_be_verified_as_unsigned(monkeypatch, tmp_path):
    ledger(tmp_path, [])
    key_head = tmp_path / ".plan-auditor" / ac.EVIDENCE_HEAD
    key_head.write_text('{"authenticated":true}')
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    valid, count, reason = ac.verify_chain(str(tmp_path))
    assert valid is False
    assert "requires HMAC key" in reason


def test_zero_record_unsigned_chain_is_not_authentication(monkeypatch, tmp_path):
    ledger(tmp_path, [])
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    authenticated, reason = ac.evidence_is_authenticated(str(tmp_path))
    assert authenticated is False
    assert "no records" in reason


def test_no_ledger_does_not_create_authenticated_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    ok, count, reason = ac.verify_chain(str(tmp_path))
    assert ok and count == 0 and reason == ""
    authenticated, explanation = ac.evidence_is_authenticated(str(tmp_path))
    assert authenticated is False
    assert "no active evidence chain" in explanation


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "[]",
        '{"auth":{"alg":"made-up"}}',
        '{"auth":7}',
    ],
)
def test_keyless_authenticity_reader_refuses_corrupt_or_unrecognized_descriptor(
    monkeypatch, tmp_path, raw
):
    ledger(tmp_path, [raw])
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    authenticated, explanation = ac.evidence_is_authenticated(str(tmp_path))
    assert authenticated is False
    assert (
        "not strict JSON" in explanation
        or "not an object" in explanation
        or "unrecognised auth" in explanation
    )


def test_unsigned_ledger_may_have_valid_hash_chain_without_claiming_authenticated_completion(
    monkeypatch, tmp_path
):
    row = record()
    ledger(tmp_path, [json.dumps(row)])
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    ok, count, why = ac.verify_chain(str(tmp_path))
    assert ok and count == 1 and why == ""
    trusted, why = ac.evidence_is_authenticated(str(tmp_path))
    assert not trusted
    assert "unsigned" in why


@pytest.mark.parametrize(
    ("tamper", "expected"),
    [
        ({"prev": "not-genesis"}, "prev chain broken"),
        ({"hash": "f" * 64}, "hash mismatch"),
    ],
)
def test_chain_verifier_rejects_rewritten_records_even_if_json_is_wellformed(
    monkeypatch, tmp_path, tamper, expected
):
    row = record()
    row.update(tamper)
    ledger(tmp_path, [json.dumps(row)])
    monkeypatch.setattr(ac, "runtime_key", lambda *_: None)
    valid, count, problem = ac.verify_chain(str(tmp_path))
    assert not valid and count == 0 and expected in problem
