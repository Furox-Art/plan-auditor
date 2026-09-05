"""Root-level regressions for runtime, rollback, concurrency and audit quiescence."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from scripts import audit_check as core
from supervisor.agents import Agent, MultiAgentRegistry, RegistryIntegrityError
from supervisor.audit_session import AuditSessionError, final_audit_session
from supervisor.config import load_config
from supervisor.lifecycle import States, TaskLifecycle
from supervisor.workspace import tool_available


def _plan(check=None):
    return {
        "task": "runtime hardening",
        "created": "2026-09-05T00:00:00+00:00",
        "steps": [{
            "id": 1,
            "title": "behavior",
            "status": "pending",
            "verify": [check or {"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}],
        }],
    }


def test_schema_rejects_ambiguous_and_malformed_runtime_fields():
    plan = _plan({
        "type": "run",
        "cmd": "echo x",
        "argv": ["echo", "x"],
        "timeout": "5",
        "expect_exit": True,
        "max_output_bytes": "4096",
        "output_regex": "(",
    })
    errors = core.validate_plan(plan)
    assert any("tam olarak bir" in item for item in errors)
    assert any("timeout" in item for item in errors)
    assert any("expect_exit" in item for item in errors)
    assert any("max_output_bytes" in item for item in errors)
    assert any("output_regex" in item for item in errors)


def test_pytest_normalization_uses_current_interpreter_and_argv():
    normalized = core.norm_check({"type": "pytest", "args": "tests/ -q"})
    assert normalized["argv"] == [sys.executable, "-m", "pytest", "tests/", "-q"]
    assert "cmd" not in normalized


def _descendant_parent(marker: Path, *, flood: bool) -> str:
    child = (
        "import time; from pathlib import Path; time.sleep(1.0); "
        f"Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    body = [
        "import subprocess, sys, time",
        f"subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
    ]
    if flood:
        body.append("print('X' * 2000000, flush=True)")
    body.append("time.sleep(5)")
    return "; ".join(body)


def test_output_limit_kills_process_tree_before_descendant_escapes(tmp_path: Path):
    marker = tmp_path / "escaped.txt"
    ok, detail, _ = core.run_check({
        "type": "run",
        "argv": [sys.executable, "-c", _descendant_parent(marker, flood=True)],
        "max_output_bytes": 4096,
        "timeout": 10,
    }, str(tmp_path))
    assert not ok
    assert "çıktı limiti" in detail
    time.sleep(1.4)
    assert not marker.exists()


def test_timeout_kills_process_tree_before_descendant_escapes(tmp_path: Path):
    marker = tmp_path / "escaped-timeout.txt"
    ok, detail, _ = core.run_check({
        "type": "run",
        "argv": [sys.executable, "-c", _descendant_parent(marker, flood=False)],
        "timeout": 0.2,
        "max_output_bytes": 4096,
    }, str(tmp_path))
    assert not ok
    assert "zaman aşımı" in detail
    time.sleep(1.4)
    assert not marker.exists()


def test_core_uses_configured_attempt_cap(tmp_path: Path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text(json.dumps({"max_attempts": 1}), encoding="utf-8")
    plan = _plan({"type": "run", "argv": [sys.executable, "-c", "raise SystemExit(1)"]})
    core.append_evidence(str(tmp_path), {
        "ts": "t", "mode": "run", "plan": "default", "step": 1,
        "status": "failed", "results": [],
    })
    assert core.audit_steps(str(tmp_path), plan, ids=[1], mode="run") is False
    assert plan["steps"][0]["status"] == "pending"


def test_core_uses_configured_rotation_limit(tmp_path: Path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text(json.dumps({"rotate_bytes": 1024}), encoding="utf-8")
    core.append_evidence(str(tmp_path), {
        "ts": "t1", "mode": "run", "step": 1, "status": "failed",
        "results": [{"blob": "x" * 1800}],
    })
    core.append_evidence(str(tmp_path), {
        "ts": "t2", "mode": "run", "step": 1, "status": "failed", "results": [],
    })
    archives = list((pg / "archive").glob("evidence-*.jsonl"))
    assert archives
    ok, _count, problem = core.verify_chain(str(tmp_path))
    assert ok, problem


def test_strict_config_rejects_integer_coercion(tmp_path: Path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text(json.dumps({"max_attempts": "3"}), encoding="utf-8")
    cfg = load_config(str(tmp_path))
    assert not cfg.valid
    assert any("max_attempts" in item for item in cfg.errors)


def test_full_snapshot_restores_empty_dirs_type_changes_and_new_paths(tmp_path: Path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "data.txt").write_text("original", encoding="utf-8")
    (tmp_path / "target-a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "target-b.txt").write_text("b", encoding="utf-8")
    link_supported = True
    try:
        os.symlink("target-a.txt", tmp_path / "link.txt")
    except (OSError, NotImplementedError):
        link_supported = False

    snapshot = core.make_snapshot(str(tmp_path), _plan())
    assert snapshot

    (tmp_path / "empty").rmdir()
    (tmp_path / "data.txt").unlink()
    (tmp_path / "data.txt").mkdir()
    (tmp_path / "data.txt" / "introduced.txt").write_text("bad", encoding="utf-8")
    (tmp_path / "new-dir").mkdir()
    (tmp_path / "new-dir" / "new.txt").write_text("new", encoding="utf-8")
    if link_supported:
        (tmp_path / "link.txt").unlink()
        os.symlink("target-b.txt", tmp_path / "link.txt")

    core.restore_snapshot(str(tmp_path), snapshot)
    assert (tmp_path / "empty").is_dir()
    assert (tmp_path / "data.txt").is_file()
    assert (tmp_path / "data.txt").read_text(encoding="utf-8") == "original"
    assert not (tmp_path / "new-dir").exists()
    if link_supported:
        assert (tmp_path / "link.txt").is_symlink()
        assert os.readlink(tmp_path / "link.txt") == "target-a.txt"


@pytest.mark.skipif(os.name == "nt", reason="external symlink creation is privilege-dependent on Windows")
def test_snapshot_rejects_symlink_that_escapes_workspace(tmp_path: Path):
    os.symlink("/tmp", tmp_path / "outside")
    with pytest.raises(ValueError, match="symlink"):
        core.make_snapshot(str(tmp_path), _plan())


def test_parallel_strict_claim_is_atomic(tmp_path: Path):
    first = MultiAgentRegistry(str(tmp_path))
    first.register(Agent("a1", "t", "p"))
    first.register(Agent("a2", "t", "p"))
    barrier = threading.Barrier(2)
    outcomes = []
    errors = []

    def claim(agent_id: str):
        try:
            registry = MultiAgentRegistry(str(tmp_path))
            barrier.wait(timeout=3)
            outcomes.append((agent_id, registry.claim_files(agent_id, {"shared.txt"}, mode="parallel-strict")))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=claim, args=(name,)) for name in ("a1", "a2")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=8)
    assert not errors
    assert len(outcomes) == 2
    assert sum(1 for _name, (ok, _conflicts) in outcomes if ok) == 1
    assert sum(1 for _name, (ok, conflicts) in outcomes if not ok and conflicts) == 1
    assert first.verify_registry_chain()


def test_concurrent_heartbeat_and_ownership_preserve_each_other(tmp_path: Path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("a1", "t", "p"))
    barrier = threading.Barrier(2)
    errors = []

    def heartbeats():
        try:
            other = MultiAgentRegistry(str(tmp_path))
            barrier.wait(timeout=3)
            for _ in range(10):
                other.heartbeat("a1", "working")
        except BaseException as exc:
            errors.append(exc)

    def ownership():
        try:
            other = MultiAgentRegistry(str(tmp_path))
            barrier.wait(timeout=3)
            for _ in range(10):
                other.update_ownership("a1", {"src/a.py"})
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=heartbeats), threading.Thread(target=ownership)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    final = MultiAgentRegistry(str(tmp_path)).active_agents()
    assert len(final) == 1
    assert final[0].current_action == "working"
    assert final[0].owned_files == {"src/a.py"}


def test_final_audit_refuses_live_agents(tmp_path: Path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("a1", "t", "p"))
    with pytest.raises(AuditSessionError, match="active agents"):
        with final_audit_session(tmp_path, registry):
            pass


def test_final_audit_freeze_blocks_new_agent_mutation(tmp_path: Path):
    registry = MultiAgentRegistry(str(tmp_path))
    with final_audit_session(tmp_path, registry):
        other = MultiAgentRegistry(str(tmp_path))
        with pytest.raises(RegistryIntegrityError, match="freeze"):
            other.register(Agent("a1", "t", "p"))


def test_final_audit_detects_workspace_mutation(tmp_path: Path):
    registry = MultiAgentRegistry(str(tmp_path))
    with pytest.raises(AuditSessionError, match="workspace"):
        with final_audit_session(tmp_path, registry):
            (tmp_path / "mutated.txt").write_text("x", encoding="utf-8")


def test_unknown_lifecycle_is_recoverable_not_terminal():
    lifecycle = TaskLifecycle("t", state=States.UNKNOWN)
    assert lifecycle.terminal() is False
    assert lifecycle.can_transition(States.RECOVERY)


def test_arbitrary_required_executable_can_be_resolved():
    assert tool_available(sys.executable)
