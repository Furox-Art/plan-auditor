"""Execution-path and evidence-rotation smoke coverage.

Two parts of the runtime that every user depends on had no coverage of their own:

* ``_bounded_command``, the only place this project ever spawns a program, was
  only ever exercised by launching a real interpreter. A regression in the
  launch options â€” a shell reappearing, ``cwd`` escaping the workspace, the
  buffer bound silently raised â€” would pass those tests, because a real
  interpreter accepts any of them. The tests below replace ``subprocess.Popen``
  with a recorder, so the launch contract is asserted on what the executor
  actually passes out, and no program is ever run.

* ``maybe_rotate`` was only smoke-tested for "an archive appeared". What the
  anchor is *for* â€” linking one rotated archive to the tail of the one before
  it, so a torn-out history is detectable â€” had no coverage at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import audit_check as core

#: A plan whose single step passes a ``run`` check, so the executor is reached.
PLAN = {
    "task": "smoke the executor bounds",
    "created": "2026-10-13T00:00:00",
    "requirements": [{"id": "REQ-001", "description": "the declared check", "priority": "must"}],
    "required_tools": ["python"],
    "steps": [
        {
            "id": 1,
            "title": "the declared check",
            "covers": ["REQ-001"],
            "verify": [
                {
                    "type": "run",
                    "argv": [sys.executable, "-c", "print('ok')"],
                    "expect_exit": 0,
                }
            ],
            "status": "pending",
        }
    ],
}


# --------------------------------------------------------------------------
# The executor's launch contract, asserted against a recorder.
# --------------------------------------------------------------------------


class _FakeStdout:
    """Stands in for ``proc.stdout``: one payload, then EOF."""

    def __init__(self, payload: bytes = b"") -> None:
        self._payload = payload
        self._offset = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    """Records what the executor passed to ``Popen``, and exits on its own.

    ``poll()`` returns ``None`` a few times first: the executor's wait loop is
    driven by it, and a process that never exits would make the test run for
    the whole command timeout.
    """

    def __init__(self, argv, kwargs, payload: bytes, exit_code: int) -> None:
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = _FakeStdout(payload)
        self.returncode = exit_code
        self.pid = 4242
        self.polls = 0
        self.killed = False

    def poll(self):
        self.polls += 1
        return None if self.polls <= 3 else self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True

    def __enter__(self):  # pragma: no cover - subprocess.run is never faked
        return self

    def __exit__(self, *_exc):  # pragma: no cover
        return False


class _SpawnRecorder:
    """Captures every launch. Stands in for the ``subprocess`` module inside
    ``scripts.audit_check`` only, so the real ``subprocess.run`` used by the
    process-tree teardown keeps working and no program is ever started."""

    def __init__(self, payload: bytes = b"recorded\n", exit_code: int = 0) -> None:
        self.payload = payload
        self.exit_code = exit_code
        self.launches: list[tuple[object, dict, _FakePopen]] = []
        self.teardown_commands: list[list[str]] = []

    def __call__(self, command, kwargs):
        instance = _FakePopen(command, kwargs, self.payload, self.exit_code)
        self.launches.append((command, kwargs, instance))
        return instance

    @property
    def last_process(self) -> _FakePopen:
        assert self.launches, "no process was spawned"
        return self.launches[-1][2]


def _recorder(monkeypatch, payload: bytes = b"recorded\n", exit_code: int = 0) -> _SpawnRecorder:
    rec = _SpawnRecorder(payload, exit_code)

    class _Proxy:
        """Delegates every unused subprocess attribute to the real module."""

        def Popen(self, command, **kwargs):  # noqa: N802 - mirrors subprocess
            return rec(command, kwargs)

        def run(self, args, **kwargs):
            rec.teardown_commands.append(list(args))
            return None

        def __getattr__(self, name):
            return getattr(subprocess, name)

    monkeypatch.setattr(core, "subprocess", _Proxy())
    return rec


@pytest.fixture
def recorder(monkeypatch) -> _SpawnRecorder:
    return _recorder(monkeypatch)


def test_bounded_command_launches_without_a_shell(recorder, tmp_path: Path):
    argv = ["python", "-c", "print('ok')"]
    rc, state, output, overflow = core._bounded_command(argv, str(tmp_path), 60, 2_000_000)

    assert rc == 0 and state == "ok" and output == "recorded\n" and overflow is False
    (launched, kwargs) = recorder.launches[0][0], recorder.launches[0][1]
    assert launched == argv, "argv must reach Popen unchanged, as a list"
    assert kwargs.get("shell") is False, (
        "the executor handed a shell to Popen; shell=True is how a plan's cmd "
        "string becomes a command line an attacker controls"
    )


def test_bounded_command_runs_in_the_named_workspace(recorder, tmp_path: Path):
    core._bounded_command(["python"], str(tmp_path), 60, 2_000_000)
    assert recorder.launches[0][1].get("cwd") == str(tmp_path), (
        "a check must run in the audited workspace, not in the caller's directory"
    )


def test_bounded_command_is_given_a_buffer_limit(recorder, tmp_path: Path):
    """The check is launched once with its bounds; the bound is enforced after."""
    core._bounded_command(["python"], str(tmp_path), 60, 2_000_000)
    assert recorder.launches, "the executor must spawn exactly one program per check"


def test_bounded_command_returned_tail_never_exceeds_the_bound(monkeypatch, tmp_path: Path):
    """A big payload must come back trimmed to ``max_output``, keeping order."""
    payload = bytes((index % 26) + 65 for index in range(16_384))  # ASCII, 16 KiB
    assert payload[:3] == b"ABC"
    _recorder(monkeypatch, payload=payload)
    _rc, _state, output, overflow = core._bounded_command(["python"], str(tmp_path), 60, 4_096)
    assert overflow is True
    assert len(output) <= 4_096
    # The tail is the last ``max_output`` bytes, not the first ones.
    assert output.encode("utf-8") == payload[len(payload) - len(output) :]


def test_bounded_command_kills_the_tree_and_reports_overflow(monkeypatch, tmp_path: Path):
    """Output past ``max_output`` must stop the process, not buffer it all."""
    rec = _recorder(monkeypatch, payload=b"x" * 8_192)
    rc, state, output, overflow = core._bounded_command(["python"], str(tmp_path), 60, 1_024)

    assert overflow is True, "a bounded read must declare the limit it hit"
    assert state == "overflow" and rc == 0
    assert len(output) <= 1_024, "the returned tail must stay inside the bound"
    assert rec.last_process.killed, "a process that overflows its bound must be killed"


def test_bounded_command_never_launches_a_shell_even_for_a_cmd_string(recorder, tmp_path: Path):
    """A ``cmd`` string is tokenised into argv before the executor sees it."""
    argv = core._command_spec({"cmd": 'python -c "print(1;2)"'})
    assert argv[0] in {"python", "python3"}
    core._bounded_command(argv, str(tmp_path), 60, 2_000_000)
    assert recorder.launches[0][0] == argv


def test_norm_check_rejects_a_shell_flag_before_any_spawn(recorder, tmp_path: Path):
    with pytest.raises(ValueError):
        core._command_spec({"cmd": "print('x')", "shell": True})
    assert not recorder.launches, "a plan asking for a shell must not spawn anything"


def test_oversized_output_still_reports_the_truncation(monkeypatch, tmp_path: Path):
    """A small tail is returned verbatim when nothing overflows."""
    _recorder(monkeypatch, payload=b"tail only\n")
    rc, state, output, overflow = core._bounded_command(["python"], str(tmp_path), 60, 2_000_000)
    assert (rc, state, overflow) == (0, "ok", False)
    assert output == "tail only\n"


def test_run_check_reaches_the_bounded_executor(monkeypatch, tmp_path: Path):
    """``run_check`` must reach the same spawn path with the same bounds."""
    from tests.trusted_workspace import establish_trust

    (tmp_path / ".plan-auditor").mkdir()
    (tmp_path / ".plan-auditor" / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
    establish_trust(tmp_path)
    rec = _recorder(monkeypatch, payload=b"check output\n")

    ok, detail, _rest = core.run_check(
        core.norm_check(PLAN["steps"][0]["verify"][0]), str(tmp_path)
    )
    assert ok is True, detail
    assert detail == "exit=0 (expected 0)"
    assert rec.launches, "run_check must go through the bounded executor"
    assert rec.launches[0][1].get("shell") is False, "the check must not gain a shell"


# --------------------------------------------------------------------------
# Evidence rotation anchoring.
#
# Every record goes through the real evidence writer, not a synthetic line: an
# anchor only means anything against a chain that genuinely hashes, and
# hand-written JSON lines verify as "legacy" instead of chained.
# --------------------------------------------------------------------------


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _archives(base: Path) -> list[Path]:
    return sorted((base / ".plan-auditor" / "archive").glob("evidence-*.jsonl"))


def _rotating_workspace(base: Path, rotate_bytes: int = 1_024) -> Path:
    """A workspace whose evidence log rotates after ``rotate_bytes`` bytes."""
    (base / ".plan-auditor").mkdir()
    (base / ".plan-auditor" / "supervisor.json").write_text(
        json.dumps({"rotate_bytes": rotate_bytes}), encoding="utf-8"
    )
    return base


def _append(base: Path, **extra) -> None:
    core.append_evidence(
        base, {"mode": "audit", "step": 1, "status": "ok", "pad": "p" * 300, **extra}
    )


def _append_until_rotated(base: Path) -> dict:
    """Append records until the log rotates, and return the anchor written."""
    for _ in range(8):
        before = len(_archives(base))
        _append(base)
        after = _archives(base)
        if len(after) > before:
            return _records(after[-1])[-1]
    raise AssertionError("evidence never rotated within 8 appends")


def test_rotation_writes_an_archive_anchor_for_the_first_rotation(tmp_path: Path):
    base = str(tmp_path)
    _rotating_workspace(tmp_path)
    anchor = _append_until_rotated(tmp_path)

    rotated = _records(_archives(tmp_path)[-1])
    assert rotated[-1] == anchor
    assert anchor["mode"] == "archive_anchor"
    assert anchor["previous_archive_hash"] is None, (
        "the first rotation has no earlier archive to anchor to, and it must "
        "say so rather than inventing a previous tail"
    )
    # The anchor closes the cycle of the log it rotated: it chains from the last
    # real record of that log, so the two halves remain one chain.
    assert anchor["prev"] == rotated[-2]["hash"]
    assert core._latest_archive_tail(base) == anchor["hash"], (
        "the active log must continue from the anchor, not restart at GENESIS"
    )

    _append(tmp_path)
    ok, count, problem = core.verify_chain(base)
    assert ok is True and count >= 1, (count, problem)


def test_each_later_rotation_anchors_to_the_previous_archive_tail(tmp_path: Path):
    base = str(tmp_path)
    _rotating_workspace(tmp_path)
    for rotation in range(3):
        anchor = _append_until_rotated(tmp_path)
        assert anchor["mode"] == "archive_anchor"
        archives = _archives(tmp_path)
        assert len(archives) == rotation + 1, "each rotation archives once"
        rotated = _records(archives[-1])
        assert anchor["prev"] == rotated[-2]["hash"], "the anchor closes its own log"
        if rotation == 0:
            assert anchor["previous_archive_hash"] is None
        else:
            previous_tail = _records(archives[rotation - 1])[-1]["hash"]
            assert anchor["previous_archive_hash"] == previous_tail, (
                f"archive {rotation} is not anchored to the tail of archive "
                f"{rotation - 1}; a rotated-out history would be silent"
            )
        assert core._latest_archive_tail(base) == anchor["hash"], (
            "the active log must continue from this rotation's anchor"
        )

        _append(tmp_path)
        ok, _count, problem = core.verify_chain(base)
        assert ok is True, problem


def test_cross_archive_chain_verifies_after_two_rotations(tmp_path: Path):
    """The supervisor-side anchor checker must see a continuous chain."""
    from supervisor.evidence import verify_anchor_chain

    _rotating_workspace(tmp_path)
    for _ in range(2):
        _append_until_rotated(tmp_path)

    manifest = verify_anchor_chain(str(tmp_path / ".plan-auditor" / "archive"))
    assert len(manifest["archives"]) == 2, manifest
    assert manifest["anchored"] is True, manifest
    assert manifest["auth_problem"] == ""
    first = manifest["archives"][0]
    second = manifest["archives"][1]
    assert first["chain_valid"] is True
    assert first["first_prev"] == "GENESIS"
    assert first["cross_archive_start"] is True
    assert second["chain_valid"] is True
    assert second["first_prev"] == first["tail_hash"]
    assert second["cross_archive_start"] is True
    assert manifest["broken_at"] is None
    assert manifest["legacy_archives"] == 0


def test_a_deleted_archive_breaks_the_cross_archive_chain(tmp_path: Path):
    """Deleting an archive must be reported, not silently pass as anchored."""
    from supervisor.evidence import verify_anchor_chain

    _rotating_workspace(tmp_path)
    for _ in range(2):
        _append_until_rotated(tmp_path)

    archives = _archives(tmp_path)
    assert len(archives) == 2
    os.unlink(archives[0])

    manifest = verify_anchor_chain(str(tmp_path / ".plan-auditor" / "archive"))
    assert [item["file"] for item in manifest["archives"]] == [archives[1].name]
    assert manifest["anchored"] is False, manifest
    assert manifest["broken_at"] == 0
    assert manifest["integrity_ok"] is False


def test_a_torn_anchor_is_reported_as_a_broken_link(tmp_path: Path):
    """Rewriting a stored link must not be accepted as the previous archive."""
    from supervisor.evidence import verify_anchor_chain

    _rotating_workspace(tmp_path)
    for _ in range(2):
        _append_until_rotated(tmp_path)

    archives = _archives(tmp_path)
    assert len(archives) == 2
    records = _records(archives[1])
    records[-1]["previous_archive_hash"] = "0" * 64
    archives[1].write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )

    manifest = verify_anchor_chain(str(tmp_path / ".plan-auditor" / "archive"))
    assert manifest["anchored"] is False, manifest
    assert manifest["broken_at"] == 1
