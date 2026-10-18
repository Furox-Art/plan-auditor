"""Recorded evidence must survive real streaming hash checks before authentication."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.integrity import IntegrityKeyError, KeyMaterial
from supervisor import evidence as ev


def signing_key():
    return KeyMaterial(key=b"evidence-test-only-secret-key" * 3, source="fixture", key_id="fixture")


def record(prev="GENESIS", **data):
    value = {"prev": prev, "event": "measured", **data}
    value["hash"] = hashlib.sha256(
        ev._canonical(ev._hash_payload(value)).encode("utf-8")
    ).hexdigest()
    return value


def store(path, records):
    path.write_text("".join(json.dumps(item) + "\n" for item in records))
    return str(path)


def test_unreadable_evidence_has_no_fabricated_file_digest(tmp_path):
    assert ev.file_hash(str(tmp_path / "missing.jsonl")) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[1]\n", None),
        ('{"hash":42}\n', None),
        ('{"hash":"a"}\n', "a"),
        ("not-json\n", None),
    ],
)
def test_evidence_tail_rejects_malformed_record_objects(tmp_path, text, expected):
    path = tmp_path / "record.jsonl"
    path.write_text(text)
    assert ev.tail_hash(str(path)) == expected


@pytest.mark.parametrize(
    ("content", "outcome"),
    [
        ("broken-json\n", False),
        ("[1]\n", False),
        ('{"legacy":"unbound"}\n', None),
        ('{"legacy":"unbound"}\n{"prev":"GENESIS","hash":"bad"}\n', None),
    ],
)
def test_unchained_or_unreadable_records_never_claim_verified_evidence(
    tmp_path,
    content,
    outcome,
):
    path = tmp_path / "record.jsonl"
    path.write_text(content)
    valid, _, reason = ev.verify_jsonl_chain(str(path))
    assert valid is outcome
    assert reason


def test_empty_evidence_log_is_not_a_fabricated_provenance_record(tmp_path):
    path = tmp_path / "record.jsonl"
    path.write_text("\n\n")
    assert ev.verify_jsonl_chain(str(path)) == (True, 0, "")


def test_changed_record_hash_is_rejected(tmp_path):
    observed = record()
    observed["event"] = "tampered after measurement"
    path = store(tmp_path / "record.jsonl", [observed])
    valid, n, reason = ev.verify_jsonl_chain(path)
    assert valid is False and n == 0 and "hash mismatch" in reason


def test_previous_anchor_must_match_exact_prior_digest(tmp_path):
    path = store(tmp_path / "record.jsonl", [record(), record("untrusted-parent")])
    valid, n, reason = ev.verify_jsonl_chain(path)
    assert valid is False and n == 1 and "prev chain broken" in reason


def test_authenticated_evidence_requires_a_real_signing_record(tmp_path):
    path = store(tmp_path / "record.jsonl", [record()])
    valid, n, reason = ev.verify_jsonl_chain(path, key=signing_key(), require_auth=True)
    assert valid is False and n == 0 and "HMAC authentication failed" in reason


def test_auth_claim_without_configured_key_is_never_trusted(tmp_path):
    path = store(tmp_path / "record.jsonl", [record(auth={"alg": "hmac", "tag": "wrong"})])
    valid, n, reason = ev.verify_jsonl_chain(path, key=None)
    assert valid is False and n == 0 and "requires HMAC key" in reason


def test_explicitly_unsigned_chain_remains_unauthed_but_hash_verifiable(tmp_path):
    path = store(tmp_path / "record.jsonl", [record(auth={"alg": "none"})])
    assert ev.verify_jsonl_chain(path, key=None) == (True, 1, "")


def test_real_signed_evidence_chain_passes_verification(tmp_path):
    first = record()
    path = tmp_path / "record.jsonl"
    store(path, [first, record(first["hash"])])
    ev._sign_jsonl(path, signing_key())
    assert ev.verify_jsonl_chain(str(path), key=signing_key(), require_auth=True) == (True, 2, "")


def test_legacy_or_invalid_chain_cannot_be_signed_as_valid_evidence(tmp_path):
    path = tmp_path / "record.jsonl"
    path.write_text('{"legacy":"untrusted"}\n')
    with pytest.raises(IntegrityKeyError, match="legacy unchained"):
        ev._sign_jsonl(path, signing_key())
    path.write_text('{"prev":"wrong","hash":"wrong"}\n')
    with pytest.raises(IntegrityKeyError, match="invalid evidence"):
        ev._sign_jsonl(path, signing_key())


def test_absent_evidence_file_is_not_created_during_signing(tmp_path):
    path = tmp_path / "missing.jsonl"
    ev._sign_jsonl(path, signing_key())
    assert not path.exists()


def test_manifest_auth_problem_blocks_anchored_claim():
    manifest = ev.ArchiveManifest([], auth_problem="invalid external key")
    assert manifest.anchored() is False
    assert ev._first_break(manifest) == 0


def test_mismatched_cross_archive_links_cannot_claim_integrity():
    manifest = ev.ArchiveManifest(
        [
            {"chain_valid": True, "tail_hash": "first"},
            {"chain_valid": True, "previous_archive_hash": "different", "tail_hash": "second"},
        ]
    )
    assert not manifest.anchored()


def test_authenticated_head_requires_actual_object_and_matching_key(tmp_path):
    assert ev.verify_evidence_head(tmp_path, signing_key())[0] is False
    head = tmp_path / ".plan-auditor" / ev.EVIDENCE_HEAD
    head.parent.mkdir()
    head.write_text("42")
    assert ev.verify_evidence_head(tmp_path, signing_key())[0] is False
    ev.write_evidence_head(tmp_path, signing_key())
    assert ev.verify_evidence_head(tmp_path, signing_key()) == (True, "")


def test_signed_chain_with_wrong_key_is_explicit_auth_failure(tmp_path):
    path = tmp_path / "record.jsonl"
    store(path, [record()])
    ev._sign_jsonl(path, signing_key())
    bad_key = KeyMaterial(key=b"other-independent-secret" * 3, source="fixture", key_id="other")
    valid, count, reason = ev.verify_jsonl_chain(str(path), key=bad_key, require_auth=True)
    assert valid is False and count == 0 and "HMAC authentication failed" in reason


def test_missing_stream_file_is_not_a_pass_for_evidence_chain(tmp_path):
    verified, count, reason = ev.verify_jsonl_chain(str(tmp_path / "missing.jsonl"))
    assert verified is False and count == 0 and reason


def test_link_reader_ignores_malformed_untrusted_records(tmp_path):
    source = tmp_path / "archive.jsonl"
    for payload in ['["wrong"]\n', '{"previous_archive_hash":123}\n', "not-json\n"]:
        source.write_text(payload)
        assert ev._read_stored_link(str(source)) is None
    source.write_text('{"previous_archive_hash":"measured-tail"}\n')
    assert ev._read_stored_link(str(source)) == "measured-tail"


def test_first_prev_reader_fails_closed_on_missing_or_unreadable_record(tmp_path):
    source = tmp_path / "missing.jsonl"
    assert ev._first_prev(str(source)) is None
    source.write_text("invalid-json\n")
    assert ev._first_prev(str(source)) is None
    source.write_text('{"prev":"GENESIS","hash":"record"}\n')
    assert ev._first_prev(str(source)) == "GENESIS"


def test_archive_manifest_records_invalid_cryptographic_key_without_forging_anchor(
    monkeypatch, tmp_path
):
    def deny(_):
        raise IntegrityKeyError("external HMAC key is unreadable")

    monkeypatch.setattr(ev, "runtime_key", deny)
    arch = tmp_path / ".plan-auditor" / "archive"
    arch.mkdir(parents=True)
    manifest = ev.build_archive_manifest(str(arch))
    assert manifest.auth_problem == "external HMAC key is unreadable"
    assert manifest.anchored() is False
    assert ev._first_break(manifest) == 0


def test_legacy_genesis_rotation_is_classified_separately_from_true_cross_archive_chain(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(ev, "runtime_key", lambda _: None)
    folder = tmp_path / ".plan-auditor" / "archive"
    folder.mkdir(parents=True)
    first = record()
    store(folder / "evidence-001.jsonl", [first])
    second = record(previous_archive_hash=first["hash"])
    store(folder / "evidence-002.jsonl", [second])
    manifest = ev.build_archive_manifest(str(folder))
    assert len(manifest.archives) == 2
    assert manifest.archives[0]["chain_valid"] is True
    assert manifest.archives[1]["chain_valid"] is True
    assert manifest.archives[1]["cross_archive_start"] is False
    assert manifest.anchored()


def test_signing_legacy_rotated_archive_checks_genesis_after_cross_archive_mismatch(tmp_path):
    path = tmp_path / "rotated.jsonl"
    store(path, [record()])
    ev._sign_jsonl(path, signing_key(), initial_prev="previous-archive-tail")
    assert ev.verify_jsonl_chain(str(path), key=signing_key(), require_auth=True) == (True, 1, "")


@pytest.mark.parametrize(
    ("malformed", "expected"),
    [
        ("not-json\n", "is not JSON"),
        ("[42]\n", "is not an object"),
    ],
)
def test_signer_rechecks_untrusted_file_even_if_previous_validation_is_bypassed(
    monkeypatch, tmp_path, malformed, expected
):
    path = tmp_path / "observed.jsonl"
    path.write_text(malformed)
    monkeypatch.setattr(ev, "verify_jsonl_chain", lambda *a, **kw: (True, 1, ""))
    with pytest.raises(IntegrityKeyError, match=expected):
        ev._sign_jsonl(path, signing_key())


def test_auth_head_with_replaced_mac_cannot_be_verified_as_same_key(tmp_path):
    path = ev.write_evidence_head(tmp_path, signing_key())
    payload = json.loads(path.read_text())
    payload["auth"] = {"alg": "hmac-sha256", "mac": "swapped"}
    path.write_text(json.dumps(payload))
    valid, reason = ev.verify_evidence_head(tmp_path, signing_key())
    assert valid is False
    assert "HMAC failed" in reason


def test_initialize_evidence_auth_signs_actual_archive_and_live_chain(tmp_path):
    root = tmp_path
    pg = root / ".plan-auditor"
    archive = pg / "archive"
    archive.mkdir(parents=True)
    first = record()
    store(archive / "evidence-001.jsonl", [first])
    second = record(first["hash"])
    store(pg / "evidence.jsonl", [second])
    ev.initialize_evidence_auth(root, signing_key())
    assert ev.verify_evidence_head(root, signing_key()) == (True, "")
    assert ev.verify_jsonl_chain(
        str(archive / "evidence-001.jsonl"), key=signing_key(), require_auth=True
    ) == (True, 1, "")
    assert ev.verify_jsonl_chain(
        str(pg / "evidence.jsonl"), key=signing_key(), require_auth=True, initial_prev=first["hash"]
    ) == (True, 1, "")


def test_signed_record_with_wrong_key_is_rejected_even_without_explicit_auth_requirement(
    tmp_path,
):
    path = tmp_path / "record.jsonl"
    store(path, [record()])
    ev._sign_jsonl(path, signing_key())
    different = KeyMaterial(key=b"independent-other-key" * 3, source="fixture", key_id="other")
    valid, count, reason = ev.verify_jsonl_chain(str(path), key=different, require_auth=False)
    assert valid is False and count == 0 and "HMAC authentication failed" in reason


def test_missing_first_record_is_explicit_unknown_previous_hash(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    assert ev._first_prev(str(path)) is None


def test_blank_lines_in_valid_evidence_are_ignored_by_signer(tmp_path):
    path = tmp_path / "record.jsonl"
    path.write_text("\n" + json.dumps(record()) + "\n\n")
    ev._sign_jsonl(path, signing_key())
    assert ev.verify_jsonl_chain(str(path), key=signing_key(), require_auth=True) == (True, 1, "")
    assert "\n\n" not in path.read_text()


def test_failed_legacy_rotated_archive_cannot_be_reclassified_as_a_valid_chain(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(ev, "runtime_key", lambda _: None)
    folder = tmp_path / ".plan-auditor" / "archive"
    folder.mkdir(parents=True)
    first = record()
    store(folder / "evidence-001.jsonl", [first])
    damaged = record(previous_archive_hash="not-first")
    damaged["hash"] = "deliberately-corrupted-digest"
    store(folder / "evidence-002.jsonl", [damaged])
    report = ev.build_archive_manifest(str(folder))
    assert len(report.archives) == 2
    assert report.archives[1]["chain_valid"] is False
    assert report.anchored() is False


def test_cleanup_failure_does_not_hide_original_atomic_signing_failure(monkeypatch, tmp_path):
    path = tmp_path / "record.jsonl"
    store(path, [record()])
    original_unlink = Path.unlink

    def cannot_remove(self, *args, **kwargs):
        if self.name.endswith(".auth.tmp"):
            raise OSError("independent temp cleanup failure")
        return original_unlink(self, *args, **kwargs)

    def cannot_replace(*args, **kwargs):
        raise OSError("simulated atomic signing replace refused")

    monkeypatch.setattr(Path, "unlink", cannot_remove)
    monkeypatch.setattr(ev.os, "replace", cannot_replace)
    with pytest.raises(OSError, match="atomic signing replace refused"):
        ev._sign_jsonl(path, signing_key())
    assert ev.verify_jsonl_chain(str(path), require_auth=False) == (True, 1, "")
