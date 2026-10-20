"""Regression tests for the deterministic-hardening fix set.

Each test pins one repaired behaviour that previously failed silently:

* The append fast path may lag the committed head checkpoint by at most one
  record (an interrupted append). That exact lag must heal on the next append;
  any other disagreement (deleted or truncated records) must stay visible.
* A stale write lock may only be stolen from a provably dead holder on this
  host; a live writer must never be robbed, and the pre-host lock format must
  fail closed.
* A truncated regex scan must say so, and a successful check must keep its
  output tail instead of discarding it.
* Rotation and snapshot names carry a monotonic sequence number, so archive
  order survives a wall-clock rollback.
* The formal planner's state bound reports UNKNOWN (exit 3) rather than
  REJECT, and out-of-range bounds are rejected before any search.
* The stop-gate adapter maps PASS/NO_PLAN to 0, everything else to 2, and
  crashes to a fail-closed 2.
* Activation state includes the head checkpoint, assessment, watchdog and
  rotated/snapshot directories, so a deleted plan fails instead of degrading
  to NO_PLAN.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from scripts import audit_check as core
from scripts import stop_gate
from supervisor import formal_planning
from supervisor.agents import Agent, MultiAgentRegistry
from supervisor.evidence import verify_anchor_chain
from supervisor.formal_planning import (
    analyze_formal_contract,
    make_formal_check,
    verify_workspace,
)
from supervisor.integrity import initialize_integrity
import supervisor.orchestrator as orchestrator
from supervisor.request_contract import auditor_state_present

# --------------------------------------------------------------------------
# Interrupted append: heal the one-record lag, never paper over anything else.
# --------------------------------------------------------------------------


def _workspace_with_external_key(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key_file = tmp_path / "outside-hardening.key"
    key_file.write_bytes(b"plan-auditor-hardening-key-material-" * 2)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    return workspace, key_file


def _seed_and_authenticate(workspace: Path, key_file: Path, monkeypatch, records: int = 4) -> str:
    base = str(workspace)
    for index in range(records):
        core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok", "n": index})
    registry = MultiAgentRegistry(base)
    registry.register(Agent("a1", "t1", "p1"))
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    result = initialize_integrity(workspace)
    assert result["authenticated"] is True
    return base


def _active_records(base: str) -> list[dict]:
    text = Path(core.evidence_path(base)).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_interrupted_append_is_healed_by_the_next_append(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_with_external_key(tmp_path, monkeypatch)
    base = _seed_and_authenticate(workspace, key_file, monkeypatch)
    head_path = workspace / ".plan-auditor" / "evidence.head.json"
    committed_head = head_path.read_bytes()
    tail = core._last_record_hash(core.evidence_path(base))

    # Record 5 is fsynced to the log but the checkpoint replace never runs:
    # exactly the crash window the heal path exists for.
    core._write_evidence_record(
        core.evidence_path(base), {"mode": "audit", "step": 1, "status": "ok", "n": 99}, prev=tail
    )
    head_path.write_bytes(committed_head)

    ok, _count, problem = core.verify_chain(base)
    assert ok is False, "a stale checkpoint must not verify"
    assert "mismatch" in problem

    core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok", "n": 100})

    ok, count, problem = core.verify_chain(base)
    assert ok is True, problem
    assert count == 6
    records = _active_records(base)
    assert records[4]["prev"] == tail, "the interrupted record must stay in the chain"
    assert records[5]["prev"] == records[4]["hash"], "the next append must continue from the real tail"
    head = json.loads(head_path.read_text(encoding="utf-8"))
    assert head["active_count"] == 6, "the repaired checkpoint must count every record"
    assert head["active_tail"] == records[5]["hash"]


def test_back_truncation_is_not_papered_over(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_with_external_key(tmp_path, monkeypatch)
    base = _seed_and_authenticate(workspace, key_file, monkeypatch)
    core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok", "n": 50})

    log = Path(core.evidence_path(base))
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    ok, _count, _problem = core.verify_chain(base)
    assert ok is False, "head ahead of a shortened log must not verify"

    core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok", "n": 51})

    ok, _count, problem = core.verify_chain(base)
    assert ok is False, "a removed record must keep the chain broken"
    assert "prev chain broken" in problem


# --------------------------------------------------------------------------
# Write-lock liveness: stale is not dead.
# --------------------------------------------------------------------------


def _lock_path(base: str) -> Path:
    return Path(base) / ".plan-auditor" / "evidence.write.lock"


def _stale_lock(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    old = time.time() - 3600
    os.utime(path, (old, old))


def test_stale_lock_with_a_live_holder_is_never_stolen(tmp_path: Path, monkeypatch):
    base = str(tmp_path)
    lock = _lock_path(base)
    _stale_lock(lock, {"pid": os.getpid(), "host": socket.gethostname(), "ts": 0})
    monkeypatch.setattr(core, "EVIDENCE_LOCK_TIMEOUT", 0.3)

    with pytest.raises(RuntimeError, match="lock timeout"):
        core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok"})
    assert lock.exists(), "a live holder's lock must survive a failed acquisition"


def test_stale_lock_from_a_dead_holder_is_stolen(tmp_path: Path, monkeypatch):
    base = str(tmp_path)
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    if os.name == "nt":
        # subprocess keeps the child's Win32 process handle open until the
        # Popen object is finalized, and the kernel keeps the terminated
        # process object, and its PID, reachable while that handle exists.
        # Closing it is what makes the PID genuinely gone.
        dead._handle.Close()
    if core._pid_is_alive(dead.pid):
        pytest.skip("the finished child's PID was recycled before the probe")
    lock = _lock_path(base)
    _stale_lock(lock, {"pid": dead.pid, "host": socket.gethostname(), "ts": 0})

    core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok"})
    assert not lock.exists(), "a stolen lock must be released after the write"
    assert len(_active_records(base)) == 1


def test_lock_without_a_host_fails_closed(tmp_path: Path, monkeypatch):
    base = str(tmp_path)
    lock = _lock_path(base)
    _stale_lock(lock, {"pid": 424242, "ts": 0})
    monkeypatch.setattr(core, "EVIDENCE_LOCK_TIMEOUT", 0.3)

    with pytest.raises(RuntimeError, match="lock timeout"):
        core.append_evidence(base, {"mode": "audit", "step": 1, "status": "ok"})
    assert lock.exists(), "a lock that cannot be proven dead must not be removed"


@pytest.mark.parametrize("value", [0, -3, "123", True, None, 1.5])
def test_pid_probe_rejects_non_pids(value):
    assert core._pid_is_alive(value) is False


def test_pid_probe_accepts_the_live_process():
    assert core._pid_is_alive(os.getpid()) is True


# --------------------------------------------------------------------------
# Bounded scans: truncation is stated, successes keep their tail.
# --------------------------------------------------------------------------


def test_regex_scan_truncation_is_reported(tmp_path: Path):
    base = str(tmp_path)
    (tmp_path / "artifact.txt").write_text("x" * 4096 + "\nNEEDLE\n", encoding="utf-8")

    ok, detail, tail = core.run_check(
        {"type": "regex", "path": "artifact.txt", "pattern": "NEEDLE"}, base
    )
    assert ok is True and tail == ""
    assert detail == "pattern matched"

    ok, detail, _tail = core.run_check(
        {"type": "regex", "path": "artifact.txt", "pattern": "NEEDLE", "max_bytes": 1024}, base
    )
    assert ok is False
    assert "truncated at 1024 bytes" in detail

    ok, detail, _tail = core.run_check(
        {"type": "regex", "path": "artifact.txt", "pattern": "NEEDLE", "max_bytes": 10}, base
    )
    assert ok is False
    assert "max_bytes must be an int between" in detail


def test_successful_checks_keep_their_output_tail(tmp_path: Path):
    base = str(tmp_path)
    ok, results = core._run_check_list(
        [{"type": "run", "argv": [sys.executable, "-c", "print('hello-archived')"]}], base
    )
    assert ok is True
    assert "hello-archived" in results[0]["output_tail"], (
        "a passing check's output must be archived, not discarded"
    )


# --------------------------------------------------------------------------
# Sequence-numbered rotation and snapshots survive a clock rollback.
# --------------------------------------------------------------------------


def _install_frozen_clock(monkeypatch) -> dict:
    state = {"now": datetime.datetime(2026, 9, 5, 12, 0, 0, 111111, tzinfo=datetime.timezone.utc)}

    class _FrozenDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            value = state["now"]
            return value if tz is None else value.astimezone(tz)

    monkeypatch.setattr(
        core,
        "datetime",
        types.SimpleNamespace(datetime=_FrozenDatetime, timezone=datetime.timezone),
    )
    return state


def test_rotation_names_stay_ordered_across_a_clock_rollback(tmp_path: Path, monkeypatch):
    base = str(tmp_path)
    (tmp_path / ".plan-auditor").mkdir()
    (tmp_path / ".plan-auditor" / "supervisor.json").write_text(
        json.dumps({"rotate_bytes": 1024}), encoding="utf-8"
    )
    clock = _install_frozen_clock(monkeypatch)
    payload = {"mode": "audit", "step": 1, "status": "ok", "pad": "p" * 1200}

    core.append_evidence(base, dict(payload))
    core.append_evidence(base, dict(payload))
    clock["now"] = datetime.datetime(2025, 1, 1, 0, 0, 0, 222222, tzinfo=datetime.timezone.utc)
    core.append_evidence(base, dict(payload))

    archive_dir = tmp_path / ".plan-auditor" / "archive"
    names = sorted(name for name in os.listdir(archive_dir) if name.endswith(".jsonl"))
    assert names == [
        "evidence-seq00000001-20260905T120000111111.jsonl",
        "evidence-seq00000002-20250101T000000222222.jsonl",
    ], "the sequence, not the stamp, must decide archive order"
    manifest = verify_anchor_chain(str(archive_dir))
    assert manifest["anchored"] is True, manifest
    ok, _count, problem = core.verify_chain(base)
    assert ok is True, problem


def test_snapshot_names_stay_ordered_across_a_clock_rollback(tmp_path: Path, monkeypatch):
    base = str(tmp_path)
    (tmp_path / "artifact.txt").write_text("content", encoding="utf-8")
    clock = _install_frozen_clock(monkeypatch)

    core.make_snapshot(base, {})
    clock["now"] = datetime.datetime(2025, 1, 1, 0, 0, 0, 222222, tzinfo=datetime.timezone.utc)
    second = core.make_snapshot(base, {})

    names = sorted(os.listdir(core.snapshots_dir(base)))
    assert names == [
        "snapshot-seq00000001-20260905T120000111111.zip",
        "snapshot-seq00000002-20250101T000000222222.zip",
    ], "the sequence, not the stamp, must decide snapshot order"
    assert core.latest_snapshot(base) == second, (
        "latest must follow the sequence after a clock rollback"
    )


def test_rotation_sequence_ignores_legacy_stamp_names(tmp_path: Path):
    archive = tmp_path / ".plan-auditor" / "archive"
    archive.mkdir(parents=True)
    (archive / "evidence-20260101T000000000000.jsonl").write_text("", encoding="utf-8")
    assert core._next_rotation_sequence(str(tmp_path)) == 1
    (archive / "evidence-seq00000007-20260102T000000000000.jsonl").write_text("", encoding="utf-8")
    assert core._next_rotation_sequence(str(tmp_path)) == 8


# --------------------------------------------------------------------------
# Formal planner: the state bound is UNKNOWN, not REJECT.
# --------------------------------------------------------------------------


def _formal_plan(contract: dict) -> dict:
    formal = make_formal_check(contract)
    return {
        "task": "build then verify an artifact",
        "created": "2026-09-05T00:00:00Z",
        "requirements": [
            {"id": "REQ-1", "description": "build artifact", "priority": "must"},
            {"id": "REQ-2", "description": "verify artifact", "priority": "must"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "verify": [formal],
                "outputs": [
                    {
                        "name": "artifact",
                        "verify": [{"type": "file_exists", "path": "artifact.txt"}],
                    }
                ],
            },
            {
                "id": 2,
                "title": "verify",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "artifact"}],
                "covers": ["REQ-2"],
                "verify": [{"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}],
                "outputs": [],
            },
        ],
    }


def _delete_effect_contract() -> dict:
    return {
        "version": 1,
        "initial_facts": ["workspace-ready"],
        "goal_facts": [
            "artifact-verified",
            "requirement-satisfied:REQ-1",
            "requirement-satisfied:REQ-2",
        ],
        "actions": [
            {
                "step": 1,
                "preconditions": ["workspace-ready"],
                "add_effects": ["artifact-built", "requirement-satisfied:REQ-1"],
                "del_effects": ["workspace-ready"],
            },
            {
                "step": 2,
                "preconditions": ["artifact-built"],
                "add_effects": ["artifact-verified", "requirement-satisfied:REQ-2"],
                "del_effects": [],
            },
        ],
    }


def test_exceeded_search_bound_reports_unknown_not_reject():
    plan = _formal_plan(_delete_effect_contract())
    result = analyze_formal_contract(plan, max_states=1)
    assert result.enabled is True
    assert result.monotonic is False
    assert result.verdict == "UNKNOWN"
    assert "exceeded" in result.reason
    assert analyze_formal_contract(plan).verdict == "PASS"


def test_workspace_verify_maps_unknown_to_exit_code_three(tmp_path: Path):
    control = tmp_path / ".plan-auditor"
    control.mkdir()
    (control / "plan.json").write_text(
        json.dumps(_formal_plan(_delete_effect_contract())), encoding="utf-8"
    )

    ok, payload = verify_workspace(tmp_path)
    assert ok is True and payload["outcome"] == "PASS"

    ok, payload = verify_workspace(tmp_path, max_states=1)
    assert ok is False and payload["outcome"] == "UNKNOWN"

    args = argparse.Namespace(
        dir=str(tmp_path),
        contract_sha=None,
        fast_downward=None,
        require_fast_downward=False,
        max_states=1,
    )
    assert formal_planning._cmd_verify(args) == 3

    ok, payload = verify_workspace(tmp_path, max_states=0)
    assert ok is False and payload["outcome"] == "FAIL"
    assert "--max-states" in payload["error"]
    args.max_states = 0
    assert formal_planning._cmd_verify(args) == 2


# --------------------------------------------------------------------------
# Stop-gate adapter: PASS/NO_PLAN pass, everything else blocks, crashes fail.
# --------------------------------------------------------------------------


def _run_stop_gate(monkeypatch, capsys, workspace: Path | None = None) -> tuple[int, str]:
    if workspace is not None:
        monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(workspace))
    else:
        monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    rc = stop_gate.main()
    return rc, capsys.readouterr().err


def test_stop_gate_allows_an_unactivated_workspace(tmp_path: Path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    rc, err = _run_stop_gate(monkeypatch, capsys, workspace=empty)
    assert rc == 0
    assert "PLAN-AUDITOR" not in err


def test_stop_gate_reads_the_workspace_from_stdin(tmp_path: Path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(empty)})))
    assert stop_gate.main() == 0


def test_stop_gate_blocks_a_failing_workspace(tmp_path: Path, monkeypatch, capsys):
    workspace = tmp_path / "ws"
    (workspace / ".plan-auditor").mkdir(parents=True)
    plan = {
        "task": "blocked completion",
        "created": "2026-09-05T00:00:00+00:00",
        "requirements": [{"id": "REQ-1", "description": "r", "priority": "must"}],
        "steps": [
            {
                "id": 1,
                "title": "s",
                "covers": ["REQ-1"],
                "verify": [{"type": "file_exists", "path": "done.txt"}],
                "outputs": [],
            }
        ],
    }
    (workspace / ".plan-auditor" / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

    rc, err = _run_stop_gate(monkeypatch, capsys, workspace=workspace)
    assert rc == 2
    assert "completion blocked" in err
    assert "Run: plan-auditor" in err


def test_stop_gate_fails_closed_when_the_gate_crashes(tmp_path: Path, monkeypatch, capsys):
    def _boom(_base):
        raise RuntimeError("gate exploded")

    monkeypatch.setattr(orchestrator, "evaluate_workspace", _boom)
    rc, err = _run_stop_gate(monkeypatch, capsys, workspace=tmp_path)
    assert rc == 2
    assert "failed closed" in err
    assert "gate exploded" in err


# --------------------------------------------------------------------------
# Activation state: head/assessment/watchdog markers and rotated state count.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "marker", ["evidence.head.json", "supervisor-assessment.json", "watchdog.jsonl"]
)
def test_new_activation_markers_are_recognized(tmp_path: Path, marker: str):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / marker).write_text("{}", encoding="utf-8")
    assert auditor_state_present(tmp_path) is True


@pytest.mark.parametrize(
    ("dirname", "filename"),
    [
        ("plans", "p1.json"),
        ("seals", "s1.json"),
        ("archive", "evidence-seq00000001-20260101T000000000000.jsonl"),
        ("snapshots", "restore.zip"),
    ],
)
def test_directory_state_activates_the_auditor(tmp_path: Path, dirname: str, filename: str):
    target = tmp_path / ".plan-auditor" / dirname / filename
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    assert auditor_state_present(tmp_path) is True


def test_unrelated_state_directories_do_not_activate(tmp_path: Path):
    pg = tmp_path / ".plan-auditor"
    (pg / "plans").mkdir(parents=True)
    (pg / "plans" / "notes.txt").write_text("x", encoding="utf-8")
    assert auditor_state_present(tmp_path) is False


def test_activation_without_plans_fails_instead_of_degrading(tmp_path: Path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "watchdog.jsonl").write_text("", encoding="utf-8")
    report = orchestrator.evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert "missing" in str(report.get("error", ""))


# --------------------------------------------------------------------------
# The bounded tail reader.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("", "GENESIS"),
        ("\n\n   \n", "GENESIS"),
        ("not json\n", "GENESIS"),
        ("[1, 2, 3]\n", "GENESIS"),
        ('{"no_hash": 1}\n', "GENESIS"),
        ('{"hash": "abc"}\n', "abc"),
    ],
)
def test_last_record_hash_reports_genesis_for_unusable_tails(tmp_path: Path, content, expected):
    path = tmp_path / "evidence.jsonl"
    path.write_text(content, encoding="utf-8")
    assert core._last_record_hash(str(path)) == expected


def test_last_record_hash_reads_a_record_wider_than_one_window(tmp_path: Path):
    path = tmp_path / "evidence.jsonl"
    record = {"hash": "f" * 64, "pad": "p" * 150_000}
    path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    assert core._last_record_hash(str(path)) == "f" * 64


def test_last_record_hash_of_a_missing_file_is_genesis(tmp_path: Path):
    assert core._last_record_hash(str(tmp_path / "absent.jsonl")) == "GENESIS"
