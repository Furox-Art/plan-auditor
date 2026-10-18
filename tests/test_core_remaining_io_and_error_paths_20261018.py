"""Deterministic core fail-closed I/O, unsafe input and evidence lock branches."""

from __future__ import annotations

import builtins
import json
import os

import pytest

from scripts import audit_check as ac


@pytest.mark.parametrize("data", [{}, {"steps": None}, {"steps": []}, {"steps": "bad"}])
def test_empty_or_wrong_shape_steps_must_be_invalid(data):
    assert any("non-empty list" in x for x in ac.validate_plan(data))


@pytest.mark.parametrize("entry", [None, False, 2, "not a step"])
def test_plan_step_must_be_an_object(entry):
    errors = ac.validate_plan({"steps": [entry]})
    assert any("step must be an object" in item for item in errors)


def test_output_graph_invalid_must_be_explicit_error():
    step = {
        "id": 1,
        "title": "test",
        "verify": [{"type": "pytest"}],
        "outputs": {"bad": "not array"},
    }
    errors = ac.validate_plan({"task": "test", "steps": [step]})
    assert any("output graph" in e for e in errors)


@pytest.mark.parametrize("value", [None, 0, "", [], {}, False])
def test_empty_or_nonstring_workspace_paths_are_rejected(tmp_path, value):
    with pytest.raises(ValueError, match="non-empty string"):
        ac._safe_path(str(tmp_path), value)


def test_windows_commonpath_drive_mismatch_is_refused(monkeypatch, tmp_path):
    def different_drives(paths):
        raise ValueError("different drives")

    monkeypatch.setattr(ac.os.path, "commonpath", different_drives)
    with pytest.raises(ValueError, match="escapes the workspace"):
        ac._safe_path(str(tmp_path), "abc.txt")


def test_plan_load_rejects_traversal_before_read(tmp_path):
    with pytest.raises((SystemExit, ValueError)):
        ac.load_plan(str(tmp_path), "../escape")


def test_evidence_record_counter_missing_log_is_zero(tmp_path):
    assert ac._record_count(str(tmp_path / "nonexistent")) == 0


def test_evidence_record_counter_permission_error_does_not_claim_records(tmp_path, monkeypatch):
    path = tmp_path / "evidence.jsonl"
    path.write_text("valid-but-unreadable\n")
    real = builtins.open

    def deny(file, *args, **kwargs):
        if os.fspath(file) == str(path):
            raise PermissionError("injected failure")
        return real(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny)
    assert ac._record_count(str(path)) == 0


def test_last_record_hash_missing_path_is_genesis(tmp_path):
    assert ac._last_record_hash(str(tmp_path / "missing.jsonl")) == "GENESIS"


def test_current_archive_tail_falls_back_to_real_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(ac, "_load_evidence_head", lambda root: None)
    monkeypatch.setattr(ac, "_latest_archive_tail", lambda root: "archive-tail")
    assert ac._current_archive_tail(str(tmp_path)) == "archive-tail"
    monkeypatch.setattr(ac, "_latest_archive_tail", lambda root: None)
    assert ac._current_archive_tail(str(tmp_path)) is None


def test_legacy_head_invalid_json_or_scalar_is_refused(tmp_path):
    path = tmp_path / "lock.json"
    path.write_text("{broken", encoding="utf-8")
    assert ac._lock_holder_dead(str(path)) is False
    path.write_text(json.dumps(["not-an-object"]))
    assert ac._lock_holder_dead(str(path)) is False


def test_lock_holder_with_missing_file_is_not_presumed_dead(tmp_path):
    assert ac._lock_holder_dead(str(tmp_path / "missing.lock")) is False


def test_pid_probe_does_not_presume_access_denied_means_dead(monkeypatch):
    def refuse(pid, sig):
        raise PermissionError("cannot inspect")

    monkeypatch.setattr(ac.os, "kill", refuse)
    assert ac._pid_is_alive(345) is True


def test_pid_probe_windows_error_87_is_only_unknown_pid_signal(monkeypatch):
    error = OSError("invalid process")
    error.winerror = 87

    def absent(pid, sig):
        raise error

    monkeypatch.setattr(ac.os, "kill", absent)
    assert ac._pid_is_alive(345) is False


def test_snapshot_entry_kind_for_fifo_is_not_fabricated_file(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.fail("FIFO capability missing from required Linux WSL test environment")
    fifo = tmp_path / "named-pipe"
    os.mkfifo(fifo)
    assert ac._entry_kind(str(fifo)) == "other"


def test_evidence_snapshot_absent_input_is_none(tmp_path):
    assert ac.latest_snapshot(str(tmp_path)) is None
