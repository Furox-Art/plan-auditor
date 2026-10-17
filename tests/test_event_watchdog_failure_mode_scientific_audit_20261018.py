"""Event and file watchers produce only observed signals, with no invented activity."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import events, watchdog


def test_missing_file_event_never_fabricates_an_observation(tmp_path):
    bus = events.EventBus()
    assert bus.scan_file(str(tmp_path / "absent.txt")) == []
    assert bus.history == []


def test_real_file_event_reads_content_and_attaches_exact_source_path(tmp_path):
    source = tmp_path / "checks.txt"
    source.write_text("verify changed", encoding="utf-8")
    bus = events.EventBus()
    reported = bus.scan_file(str(source))
    assert reported
    assert all(e.metadata["path"] == str(source) for e in reported)
    assert events.Trigger.PLAN_INTEGRITY in {e.trigger for e in reported}


def test_unreadable_file_scan_is_not_treated_as_valid_or_completed(monkeypatch, tmp_path):
    file = tmp_path / "checks.txt"
    file.write_text("all tests pass")
    original = Path.read_text

    def denied(self, *args, **kwargs):
        if self == file:
            raise OSError("simulated read refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    bus = events.EventBus()
    assert bus.scan_file(str(file)) == []
    assert not bus.history


def test_duplicate_pattern_signals_do_not_emit_duplicate_identical_events():
    one = events.PatternRule(events.Trigger.FINAL_AUDIT, "message", [events.re.compile("done")])
    two = events.PatternRule(events.Trigger.FINAL_AUDIT, "message", [events.re.compile("done")])
    bus = events.EventBus(rules=[one, two])
    seen = []
    bus.on(events.Trigger.FINAL_AUDIT, lambda event: seen.append(event.span))
    out = bus.scan_message("done")
    assert len(out) == 1
    assert seen == ["done"]


def test_file_watchdog_detects_real_create_modify_delete_transitions(monkeypatch, tmp_path):
    monkeypatch.setattr(watchdog, "_git_changed_files", lambda _: set())
    observer = watchdog.Watchdog(str(tmp_path))
    source = tmp_path / "experiment.txt"
    source.write_text("first")
    first = observer.poll()
    assert "experiment.txt" in first.created
    assert any(e.kind == "fs_create" for e in first.events)

    # Force a different timestamp deterministically, without a sleep.
    old_time = observer._baseline["experiment.txt"]
    source.write_text("changed")
    import os

    os.utime(source, (old_time + 20.0, old_time + 20.0))
    modified = observer.poll()
    assert "experiment.txt" in modified.changed_files
    assert any(e.kind == "fs_modify" for e in modified.events)

    source.unlink()
    removed = observer.poll()
    assert "experiment.txt" in removed.deleted
    assert any(e.kind == "fs_delete" for e in removed.events)


def test_git_only_changes_are_reported_as_changes_not_created_or_deleted(monkeypatch, tmp_path):
    monkeypatch.setattr(watchdog, "_snapshot_files", lambda _: {})
    monkeypatch.setattr(watchdog, "_git_changed_files", lambda _: {"staged.txt"})
    w = watchdog.Watchdog(str(tmp_path))
    got = []
    w.on_event(lambda e: got.append(e))
    result = w.poll()
    assert result.changed_files == {"staged.txt"}
    assert result.created == set()
    assert result.deleted == set()
    assert [e.kind for e in got] == ["git_change"]


def test_watchdog_initializes_observer_with_no_handlers_and_then_registers_handler(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(watchdog, "_git_changed_files", lambda _: set())
    w = watchdog.Watchdog(str(tmp_path))
    handled = []
    w.on_event(lambda e: handled.append(e.path))
    (tmp_path / "new.txt").write_text("new")
    w.poll()
    assert handled == ["new.txt"]


def test_watchdog_has_activity_uses_measured_timestamps_only(monkeypatch, tmp_path):
    w = watchdog.Watchdog(str(tmp_path))
    monkeypatch.setattr(watchdog.time, "time", lambda: 1000.0)
    w._baseline = {"recent": 950.0, "old": 1.0}
    assert w.has_activity(100.0)
    assert not w.has_activity(10.0)


def test_inaccessible_file_metadata_does_not_crash_watchdog(monkeypatch, tmp_path):
    path = tmp_path / "unreadable.txt"
    path.write_text("inspected")
    original = watchdog.os.path.getmtime

    def fail(p):
        if str(p) == str(path):
            raise OSError("simulated race")
        return original(p)

    monkeypatch.setattr(watchdog.os.path, "getmtime", fail)
    assert "unreadable.txt" not in watchdog._snapshot_files(str(tmp_path))


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OSError("git unavailable"), set()),
        (subprocess.TimeoutExpired(["git"], 30), set()),
    ],
)
def test_git_probe_failure_returns_no_observed_changes(monkeypatch, tmp_path, error, expected):
    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(watchdog.subprocess, "run", unavailable)
    assert watchdog._git_name_only(str(tmp_path)) == expected


def test_git_probe_failed_exit_code_cannot_be_misrepresented_as_changed_files(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        watchdog.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="false-confirmed.txt"),
    )
    assert watchdog._git_name_only(str(tmp_path)) == set()


def test_git_probe_reports_actual_lines_and_never_executes_shell(monkeypatch, tmp_path):
    observed = []

    def command(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="first.py\n\n second.py \n")

    monkeypatch.setattr(watchdog.subprocess, "run", command)
    assert watchdog._git_name_only(str(tmp_path), cached=True) == {"first.py", "second.py"}
    assert observed[0][1]["shell"] is False
    assert observed[0][0][:3] == ["git", "diff", "--cached"]


def test_watchdog_dedup_window_does_not_fabricate_new_independent_events():
    bus = events.EventBus()
    event = events.Event(events.Trigger.FINAL_AUDIT, "message", "done", span="done")
    bus.emit(event)
    bus.emit(event)
    assert bus.dedup_window(10) == [event]
