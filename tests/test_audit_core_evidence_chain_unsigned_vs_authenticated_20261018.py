"""Evidence hash-chain integrity is strictly weaker than externally keyed HMAC trust."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import audit_check as core
from scripts.integrity import IntegrityKeyError


@pytest.fixture
def unsigned(monkeypatch, tmp_path):
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    return tmp_path


def _make_record(previous="GENESIS", **values):
    rec = {
        "mode": "run",
        "status": "failed",
        "plan": "default",
        "step": 1,
        "results": [],
        "prev": previous,
    }
    rec.update(values)
    rec["hash"] = hashlib.sha256(
        core.canonical(core._evidence_hash_payload(rec)).encode("utf-8")
    ).hexdigest()
    rec.setdefault("auth", {"alg": "none"})
    return rec


def _save(root, records):
    folder = root / ".plan-auditor"
    folder.mkdir(exist_ok=True)
    file = folder / "evidence.jsonl"
    file.write_text("".join(json.dumps(r) + "\n" for r in records))
    return file


def test_absent_unsigned_evidence_is_a_trivially_empty_chain_not_completed_authentication(unsigned):
    assert core.verify_chain(str(unsigned)) == (True, 0, "")
    authenticated, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authenticated
    assert "no active evidence chain" in reason


def test_present_unsigned_chain_is_validly_hash_chained_but_not_authenticated(unsigned):
    rec = _make_record()
    _save(unsigned, [rec])
    assert core.verify_chain(str(unsigned)) == (True, 1, "")
    authenticated, reason = core.evidence_is_authenticated(str(unsigned))
    assert authenticated is False
    assert "tamper-evident only" in reason


def test_valid_multi_record_chain_retains_exact_final_hash_and_record_count(unsigned):
    first = _make_record(step=1)
    second = _make_record(previous=first["hash"], step=2)
    file = _save(unsigned, [first, second])
    assert core.verify_chain(str(unsigned)) == (True, 2, "")
    assert core._last_record_hash(str(file)) == second["hash"]


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ({"prev": "another-previous-checksum"}, "prev chain broken"),
        ({"hash": "forged-tamper"}, "hash mismatch"),
        ({"auth": {"alg": "hmac-sha256", "tag": "unsigned-but-forged"}}, "requires an HMAC key"),
        ({"auth": "not-a-valid-auth"}, "requires an HMAC key"),
    ],
)
def test_each_tampered_hash_chain_field_is_refused_without_an_authentication_key(
    unsigned, event, message
):
    first = _make_record()
    first.update(event)
    _save(unsigned, [first])
    valid, count, reason = core.verify_chain(str(unsigned))
    assert not valid and count == 0
    assert message in reason


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("{not-json\n", "is not strict JSON"),
        ("[]\n", "is not a JSON object"),
        ('{"step":2,"step":3}\n', "is not strict JSON"),
        ('{"step":1,"a":1e999999}\n', "is not strict JSON"),
    ],
)
def test_invalid_evidence_json_cannot_be_reinterpreted_as_a_valid_record(unsigned, line, message):
    directory = unsigned / ".plan-auditor"
    directory.mkdir()
    (directory / "evidence.jsonl").write_text(line)
    passed, count, reason = core.verify_chain(str(unsigned))
    assert not passed and count == 0 and message in reason


def test_malformed_record_after_one_good_record_preserves_audited_prefix_count(unsigned):
    first = _make_record()
    file = _save(unsigned, [first])
    with file.open("a") as f:
        f.write("{broken\n")
    valid, count, reason = core.verify_chain(str(unsigned))
    assert not valid and count == 1
    assert "line 2 is not strict JSON" in reason


def test_unsigned_record_with_legacy_absent_auth_remains_unverified_not_rejected_as_tampered(
    unsigned,
):
    rec = _make_record()
    del rec["auth"]
    _save(unsigned, [rec])
    assert core.verify_chain(str(unsigned)) == (True, 1, "")
    authed, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authed and "unsigned" in reason


def test_signed_checkpoint_without_key_is_never_silently_accepted(unsigned):
    pg = unsigned / ".plan-auditor"
    pg.mkdir()
    (pg / "evidence.head.json").write_text('{"format_version":2}')
    passed, count, reason = core.verify_chain(str(unsigned))
    assert not passed and count == 0
    assert "requires HMAC key" in reason


def test_signature_key_resolution_errors_are_exposed_to_callers(monkeypatch, unsigned):
    def invalid(_):
        raise IntegrityKeyError("inaccessible user-supplied key")

    monkeypatch.setattr(core, "runtime_key", invalid)
    assert core.verify_chain(str(unsigned)) == (False, 0, "inaccessible user-supplied key")
    authed, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authed and "inaccessible user-supplied key" in reason


def test_keyless_evidence_head_is_rejected_even_if_every_unsigned_record_hash_matches(unsigned):
    _save(unsigned, [_make_record()])
    (unsigned / ".plan-auditor" / "evidence.head.json").write_text('{"seq":1}')
    valid, count, reason = core.verify_chain(str(unsigned))
    assert not valid and count == 1
    assert "requires HMAC key" in reason


def test_keyless_chain_explains_malformed_record_instead_of_claiming_authentication(unsigned):
    directory = unsigned / ".plan-auditor"
    directory.mkdir()
    (directory / "evidence.jsonl").write_text("{malformed\n")
    authed, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authed and "not strict JSON" in reason


def test_keyless_chain_refuses_unknown_auth_descriptor_instead_of_demoting_it(unsigned):
    rec = _make_record()
    rec["auth"] = {"alg": "unrecognized", "signature": "bogus"}
    _save(unsigned, [rec])
    authed, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authed
    assert "unrecognised auth descriptor" in reason


def test_empty_existing_unsigned_chain_is_explicitly_unverifiable(unsigned):
    _save(unsigned, [])
    authed, reason = core.evidence_is_authenticated(str(unsigned))
    assert not authed
    assert "no records to authenticate" in reason


def test_failed_attempts_are_scoped_by_plan_step_and_mode(unsigned):
    first = _make_record(plan="default", step=1, status="failed", mode="run")
    second = _make_record(previous=first["hash"], plan="other", step=1, status="failed", mode="run")
    third = _make_record(
        previous=second["hash"], plan="default", step=1, status="verified", mode="run"
    )
    fourth = _make_record(
        previous=third["hash"], plan="default", step=1, status="failed", mode="audit"
    )
    _save(unsigned, [first, second, third, fourth])
    assert core.failed_attempt_counts(str(unsigned)) == {("default", 1): 1, ("other", 1): 1}
    assert core.count_failed_attempts(str(unsigned), 1) == 1
    assert core.count_failed_attempts(str(unsigned), 1, plan="other") == 1
    assert core.count_failed_attempts(str(unsigned), 1, mode="audit") == 1


def test_failed_attempts_ignore_nonexistent_step_mapping_without_crashing(unsigned):
    _save(
        unsigned,
        [
            _make_record(step=True),
            _make_record(step="untyped"),
            _make_record(plan=123),
            _make_record(step=2, status="verified"),
        ],
    )
    assert core.failed_attempt_counts(str(unsigned)) == {}


def test_failed_attempts_refuse_duplicate_keys_and_nan_before_counting(unsigned):
    pg = unsigned / ".plan-auditor"
    pg.mkdir()
    (pg / "evidence.jsonl").write_text('{"step":1,"step":2,"status":"failed","mode":"run"}\n')
    with pytest.raises(ValueError, match="ambiguous or corrupt evidence record"):
        core.failed_attempt_counts(str(unsigned))
