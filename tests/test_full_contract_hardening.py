"""Regression tests for the v2.1 full-verification-contract hardening pass."""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from scripts import audit_check as core
from supervisor.agents import Agent, MultiAgentRegistry
from supervisor.cli import main as cli_main
from supervisor.config import load_config
from supervisor.contracts import environment_contract
from supervisor.orchestrator import evaluate_workspace
from supervisor.plans import PlanNameError, plan_path as supervisor_plan_path
from supervisor.policies import load_policy_rules_from_dir
from supervisor.sealing import SealIntegrityError, check_environment, check_monotonic, load_seal, seal_plan
from tests.request_fixture import activate_for_plan


def _plan(task: str = "full hardening test", *, marker: str = "done.txt") -> dict:
    return {
        "task": task,
        "created": "2026-09-05T00:00:00+00:00",
        "requirements": [
            {"id": "REQ-001", "description": "Execute real behavior", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [{
            "id": 1,
            "title": "execute behavior",
            "covers": ["REQ-001"],
            "verify": [{
                "type": "run",
                "argv": [
                    os.sys.executable,
                    "-c",
                    "print('verified')",
                ],
            }],
        }],
    }


def _write_plan(root: Path, plan: dict, name: str | None = None) -> Path:
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    if name:
        directory = pg / "plans"
        directory.mkdir(exist_ok=True)
        path = directory / f"{name}.json"
    else:
        path = pg / "plan.json"
    path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    activate_for_plan(root, plan)
    return path


def test_only_named_plan_is_not_treated_as_no_plan(tmp_path: Path) -> None:
    _write_plan(tmp_path, _plan(marker="named.txt"), "backend")
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert report["active_plan_count"] == 1
    assert set(report["plans"]) == {"backend"}


def test_named_pending_plan_blocks_global_pass(tmp_path: Path) -> None:
    default = _plan(marker="default.txt")
    named = _plan(task="named plan", marker="named.txt")
    _write_plan(tmp_path, default)
    _write_plan(tmp_path, named, "backend")
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    assert core.audit_steps(str(tmp_path), default, mode="audit") is True
    report = evaluate_workspace(str(tmp_path))
    assert report["plans"]["default"]["outcome"] == "PASS"
    assert report["plans"]["backend"]["outcome"] == "FAIL"
    assert report["outcome"] == "FAIL"


def test_full_seal_blocks_dependency_output_and_coverage_weakening() -> None:
    plan = {
        "task": "contract",
        "requirements": [
            {"id": "REQ-1", "description": "upstream", "priority": "must"},
            {"id": "REQ-2", "description": "downstream", "priority": "must"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "upstream",
                "depends_on": [],
                "covers": ["REQ-1"],
                "verify": [{"type": "run", "argv": ["python", "-c", "print(1)"]}],
                "outputs": [{
                    "name": "artifact",
                    "verify": [{"type": "file_exists", "path": "artifact.txt"}],
                }],
            },
            {
                "id": 2,
                "title": "downstream",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "artifact"}],
                "covers": ["REQ-2"],
                "verify": [{"type": "run", "argv": ["python", "-c", "print(2)"]}],
            },
        ],
    }
    seal = seal_plan(plan, "p", "2026-09-05T00:00:00Z")
    weakened = json.loads(json.dumps(plan))
    weakened["steps"][1]["depends_on"] = []
    weakened["steps"][1]["requires_outputs"] = []
    weakened["steps"][1]["covers"] = []
    result = check_monotonic(seal.as_plan(), weakened)
    assert not result.ok
    text = "\n".join(result.violations)
    assert "dependency" in text and "required output" in text and "coverage" in text


def test_sealed_environment_detects_profile_downgrade(tmp_path: Path) -> None:
    cfg = load_config(str(tmp_path))
    env = environment_contract(tmp_path, cfg)
    seal = seal_plan(_plan(), "p", "now", environment=env)
    downgraded = dict(env)
    downgraded["profile"] = "light"
    result = check_environment(seal, downgraded)
    assert not result.ok


def test_profile_change_after_seal_blocks_integrated_gate(tmp_path: Path) -> None:
    plan = _plan()
    _write_plan(tmp_path, plan)
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    (tmp_path / ".plan-auditor" / "supervisor.json").write_text(
        json.dumps({"profile": "light", "mode": "serial", "tier": 1}), encoding="utf-8"
    )
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert any("environment" in value for value in report["seal"]["violations"])


def test_hmac_authenticated_seal_detects_tamper(tmp_path: Path, monkeypatch) -> None:
    plan = _plan()
    _write_plan(tmp_path, plan)
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    monkeypatch.setenv(
        "PLAN_AUDITOR_HMAC_KEY",
        "test-external-seal-hmac-key-material-0123456789abcdef",
    )
    assert cli_main(["integrity", "init", str(tmp_path)]) == 0
    seal_path = tmp_path / ".plan-auditor" / "seal.json"
    value = json.loads(seal_path.read_text(encoding="utf-8"))
    value["criteria_count"] += 1
    seal_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SealIntegrityError):
        load_seal(str(seal_path))


def test_invalid_config_is_reported_and_blocks(tmp_path: Path) -> None:
    _write_plan(tmp_path, _plan())
    (tmp_path / ".plan-auditor" / "supervisor.json").write_text("{broken", encoding="utf-8")
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert report["configuration_errors"]


def test_invalid_policy_is_reported_and_blocks(tmp_path: Path) -> None:
    _write_plan(tmp_path, _plan())
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "broken.json").write_text("{broken", encoding="utf-8")
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert report["policy_errors"]


def test_invalid_policy_regex_is_not_silently_ignored(tmp_path: Path) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "bad.json").write_text(json.dumps({
        "rules": [{
            "id": "BAD_REGEX",
            "kind": "forbid_regex",
            "field": "logs",
            "pattern": "[",
            "level": 3,
        }]
    }), encoding="utf-8")
    errors: list[str] = []
    rules = load_policy_rules_from_dir(str(policies), errors=errors)
    assert rules == []
    assert errors


def test_plan_name_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        core.plan_path(str(tmp_path), "../../escape")
    with pytest.raises(PlanNameError):
        supervisor_plan_path(tmp_path, "../../escape")


def test_retry_count_survives_evidence_rotation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(core, "ROTATE_BYTES", 1)
    for index in range(3):
        core.append_evidence(str(tmp_path), {
            "ts": str(index), "mode": "run", "plan": "default",
            "step": 7, "status": "failed", "results": [],
        })
    assert core.count_failed_attempts(str(tmp_path), 7, plan="default") == 3


def test_active_evidence_cross_links_latest_archive_tail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(core, "ROTATE_BYTES", 1)
    core.append_evidence(str(tmp_path), {
        "ts": "1", "mode": "run", "plan": "default",
        "step": 1, "status": "verified", "results": [],
    })
    core.append_evidence(str(tmp_path), {
        "ts": "2", "mode": "run", "plan": "default",
        "step": 2, "status": "verified", "results": [],
    })
    archives = core._archive_paths(str(tmp_path))
    assert archives
    archive_tail = core._last_record_hash(archives[-1])
    active = Path(core.evidence_path(str(tmp_path)))
    first = json.loads(active.read_text(encoding="utf-8").splitlines()[0])
    assert first["prev"] == archive_tail
    ok, count, problem = core.verify_chain(str(tmp_path))
    assert ok, problem
    assert count == 1


def test_concurrent_evidence_appends_remain_valid(tmp_path: Path) -> None:
    def append(index: int) -> None:
        core.append_evidence(str(tmp_path), {
            "ts": str(index), "mode": "run", "plan": "default",
            "step": index + 1, "status": "verified", "results": [],
        })

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(32)))
    ok, count, problem = core.verify_chain(str(tmp_path))
    assert ok, problem
    assert count == 32


def test_evidence_cli_rejects_active_log_tamper(tmp_path: Path) -> None:
    core.append_evidence(str(tmp_path), {
        "ts": "1", "mode": "run", "plan": "default", "step": 1,
        "status": "verified", "results": [],
    })
    path = Path(core.evidence_path(str(tmp_path)))
    rec = json.loads(path.read_text(encoding="utf-8"))
    rec["status"] = "forged"
    path.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert cli_main(["evidence", "verify", str(tmp_path)]) == 2


def test_full_snapshot_rollback_prunes_introduced_files(tmp_path: Path) -> None:
    original = tmp_path / "original.txt"
    original.write_text("before", encoding="utf-8")
    plan = _plan()
    zpath = core.make_snapshot(str(tmp_path), plan)
    assert zpath
    original.write_text("after", encoding="utf-8")
    introduced = tmp_path / "introduced.txt"
    introduced.write_text("remove me", encoding="utf-8")
    core.restore_snapshot(str(tmp_path), zpath)
    assert original.read_text(encoding="utf-8") == "before"
    assert not introduced.exists()


def test_workspace_fingerprint_detects_executable_bit_change(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows has no POSIX executable bit")
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o644)
    before = core.workspace_fingerprint(str(tmp_path))
    script.chmod(0o755)
    after = core.workspace_fingerprint(str(tmp_path))
    assert after != before


def test_agent_ownership_paths_are_canonicalized_for_conflicts(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("a1", "t", "p", owned_files={"src/../src/shared.py"}))
    conflicts = registry.check_conflicts("a2", {"./src/shared.py"})
    assert len(conflicts) == 1
    assert conflicts[0].file_path == "src/shared.py"


def test_unsafe_agent_id_is_rejected(tmp_path: Path) -> None:
    registry = MultiAgentRegistry(str(tmp_path))
    with pytest.raises(ValueError):
        registry.register(Agent("../escape", "t", "p"))


def test_missing_required_tool_blocks_completion(tmp_path: Path) -> None:
    plan = _plan()
    plan["required_tools"] = ["definitely-not-a-real-plan-auditor-tool"]
    _write_plan(tmp_path, plan)
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    findings = report["gate"]["policy_findings"]
    assert any(item["rule"] == "TOOLS_PRESENT" for item in findings)


def test_command_output_limit_fails_closed(tmp_path: Path) -> None:
    ok, detail, _ = core.run_check({
        "type": "run",
        "argv": [os.sys.executable, "-c", "print('x' * 5000)"],
        "max_output_bytes": 1024,
    }, str(tmp_path))
    assert not ok
    assert "limiti" in detail


def test_internal_workspace_and_watchdog_probes_do_not_use_shell_true() -> None:
    root = Path(__file__).resolve().parents[1]
    for rel in ("supervisor/workspace.py", "supervisor/watchdog.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "shell=True" not in text
