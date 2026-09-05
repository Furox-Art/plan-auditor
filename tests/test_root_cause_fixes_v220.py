from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from supervisor.agents import MultiAgentRegistry, RegistryIntegrityError
from supervisor.config import load_config
from supervisor.contracts import environment_contract
from supervisor.evidence import verify_jsonl_chain
from supervisor.plans import PlanNameError, PlanRef, all_plan_refs
from supervisor.policies import load_policy_rules_from_dir
from supervisor.request_contract import auditor_state_present, initialize_request
from supervisor.seal_migration import migrate_one
from supervisor.sealing import (
    Seal,
    check_monotonic,
    legacy_v3_plan_hash,
    load_seal,
    save_seal,
)


def _symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable on this runner: {exc}")


def _check(path: str = "result.txt") -> dict:
    return {
        "type": "run",
        "argv": ["python", "-c", f"from pathlib import Path; assert Path({path!r}).exists()"],
        "expect_exit": 0,
    }


def _plan() -> dict:
    return {
        "task": "produce verified result",
        "created": "2026-09-05T00:00:00+00:00",
        "requirements": [
            {"id": "REQ-1", "description": "produce result", "priority": "must"}
        ],
        "steps": [
            {
                "id": 1,
                "title": "verify result",
                "covers": ["REQ-1"],
                "verify": [_check()],
                "outputs": [
                    {
                        "name": "result",
                        "verify": [{"type": "file_exists", "path": "result.txt"}],
                    }
                ],
            }
        ],
    }


def _two_step_legacy_plan() -> dict:
    """A genuine v3-era implicit sequential plan with raw depends_on omitted."""
    return {
        "task": "produce verified result",
        "created": "2026-09-05T00:00:00+00:00",
        "requirements": [
            {"id": "REQ-1", "description": "produce result", "priority": "must"},
            {"id": "REQ-2", "description": "consume result", "priority": "must"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "verify result",
                "covers": ["REQ-1"],
                "verify": [_check()],
                "outputs": [
                    {
                        "name": "result",
                        "verify": [{"type": "file_exists", "path": "result.txt"}],
                    }
                ],
            },
            {
                "id": 2,
                "title": "consume result",
                "covers": ["REQ-2"],
                "verify": [
                    {
                        "type": "run",
                        "argv": ["python", "-c", "from pathlib import Path; assert Path('result.txt').exists()"],
                        "expect_exit": 0,
                    }
                ],
            },
        ],
    }


def test_named_plan_parent_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    external = tmp_path / "external-plans"
    (root / ".plan-auditor").mkdir(parents=True)
    external.mkdir()
    (external / "hidden.json").write_text(json.dumps(_plan()), encoding="utf-8")
    _symlink_or_skip(external, root / ".plan-auditor" / "plans", directory=True)

    with pytest.raises(PlanNameError, match="symlink"):
        all_plan_refs(root)


def test_default_plan_leaf_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    external = tmp_path / "external-plan.json"
    (root / ".plan-auditor").mkdir(parents=True)
    external.write_text(json.dumps(_plan()), encoding="utf-8")
    _symlink_or_skip(external, root / ".plan-auditor" / "plan.json")

    with pytest.raises(PlanNameError, match="symlink"):
        all_plan_refs(root)


def test_policy_symlink_is_blocked_before_external_read(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    external = tmp_path / "external-policies"
    (root / ".plan-auditor").mkdir(parents=True)
    external.mkdir()
    (external / "outside.json").write_text(
        json.dumps({"rules": [{"id": "OUT", "kind": "require_truthy", "field": "x"}]}),
        encoding="utf-8",
    )
    _symlink_or_skip(external, root / "policies", directory=True)

    cfg = load_config(str(root))
    assert not cfg.valid
    assert any("policy" in error.lower() and "symlink" in error.lower() for error in cfg.errors)

    errors: list[str] = []
    rules = load_policy_rules_from_dir(str((root / "policies").resolve()), errors=errors)
    assert rules == []
    assert any("unsafe workspace symlink" in error for error in errors)


def test_unrelated_direct_policy_loader_remains_usable_after_workspace_registration(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / ".plan-auditor").mkdir(parents=True)
    assert load_config(str(workspace)).valid

    standalone = tmp_path / "standalone-policies"
    standalone.mkdir()
    (standalone / "rule.toml").write_text(
        """
[[rules]]
id = "STANDALONE"
level = 3
kind = "require_truthy"
field = "workspace"
detail = "workspace missing"
""".strip(),
        encoding="utf-8",
    )
    errors: list[str] = []
    rules = load_policy_rules_from_dir(str(standalone), errors=errors)
    assert errors == []
    assert [rule.rule_id for rule in rules] == ["STANDALONE"]


def test_config_only_workspace_is_not_treated_as_activated(tmp_path: Path) -> None:
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text('{"profile":"standard"}', encoding="utf-8")
    assert auditor_state_present(tmp_path) is False

    (pg / "evidence.jsonl").write_text("", encoding="utf-8")
    assert auditor_state_present(tmp_path) is True


def test_seal_blocks_scope_expansion_but_allows_proof_strengthening() -> None:
    before = _plan()

    stronger = json.loads(json.dumps(before))
    stronger["steps"][0]["verify"].append(
        {"type": "run", "argv": ["python", "-c", "assert 1 + 1 == 2"], "expect_exit": 0}
    )
    result = check_monotonic(before, stronger)
    assert result.ok is True
    assert result.improvements

    expanded = json.loads(json.dumps(before))
    expanded["requirements"].append(
        {"id": "REQ-2", "description": "new unapproved scope", "priority": "must"}
    )
    expanded["steps"].append(
        {
            "id": 2,
            "title": "new scope",
            "covers": ["REQ-2"],
            "verify": [{"type": "run", "argv": ["python", "-c", "assert True"]}],
        }
    )
    result = check_monotonic(before, expanded)
    assert result.ok is False
    assert any("host-approved" in violation or "host approval" in violation for violation in result.violations)


def test_registry_live_writer_is_not_evicted_by_age(tmp_path: Path) -> None:
    registry = MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.REGISTRY_LOCK_TIMEOUT = 0.05
    registry.lock_path.write_text(
        json.dumps({"pid": os.getpid(), "token": "live-owner", "created": time.time() - 9999}),
        encoding="utf-8",
    )

    with pytest.raises(RegistryIntegrityError, match="lock timeout"):
        with registry._write_lock():
            pass
    assert registry.lock_path.exists()
    registry.lock_path.unlink()


def test_registry_dead_owner_lock_can_be_recovered(tmp_path: Path) -> None:
    registry = MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.REGISTRY_LOCK_TIMEOUT = 0.2
    registry.lock_path.write_text(
        json.dumps({"pid": 2_000_000_000, "token": "dead-owner", "created": time.time()}),
        encoding="utf-8",
    )
    with registry._write_lock():
        assert registry.lock_path.exists()
    assert not registry.lock_path.exists()


def test_evidence_chain_verification_does_not_use_read_text(tmp_path: Path, monkeypatch) -> None:
    record = {"mode": "audit", "step": 1, "status": "verified", "prev": "GENESIS"}
    import hashlib
    from supervisor.evidence import _canonical, _hash_payload

    record["hash"] = hashlib.sha256(_canonical(_hash_payload(record)).encode("utf-8")).hexdigest()
    path = tmp_path / "evidence.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    original = Path.read_text

    def guarded(self: Path, *args, **kwargs):
        if self == path:
            raise AssertionError("streaming verifier must not call Path.read_text on JSONL")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    valid, count, problem = verify_jsonl_chain(str(path))
    assert (valid, count, problem) == (True, 1, "")


def test_genuine_v3_raw_dependency_hash_has_safe_v4_migration_path(tmp_path: Path) -> None:
    root = tmp_path
    pg = root / ".plan-auditor"
    pg.mkdir()
    plan = _two_step_legacy_plan()
    (pg / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (root / "result.txt").write_text("ok", encoding="utf-8")

    initialize_request(
        root,
        {
            "format_version": 1,
            "task": "produce verified result",
            "requirements": [
                {
                    "id": "REQ-1",
                    "description": "produce result",
                    "priority": "must",
                    "acceptance_checks": plan["steps"][0]["verify"],
                },
                {
                    "id": "REQ-2",
                    "description": "consume result",
                    "priority": "must",
                    "acceptance_checks": plan["steps"][1]["verify"],
                },
            ],
        },
    )
    cfg = load_config(str(root))
    env = environment_contract(root, cfg)
    legacy_env = dict(env)
    legacy_env.pop("request_sha256", None)

    # Construct the same raw contract shape emitted by released v2.1.0. Both
    # steps intentionally retain depends_on=None rather than v4 effective [1].
    legacy_steps = []
    criteria_count = 0
    for step in plan["steps"]:
        contracted = {
            "id": step.get("id"),
            "title": step.get("title"),
            "depends_on": step.get("depends_on"),
            "requires_outputs": step.get("requires_outputs", []),
            "outputs": step.get("outputs", []),
            "covers": step.get("covers", []),
            "verify": step.get("verify", []),
        }
        legacy_steps.append(contracted)
        criteria_count += len(contracted["verify"])
        for output in contracted["outputs"]:
            criteria_count += len(output.get("verify", []))
    legacy = Seal(
        plan_id="legacy",
        sealed_at="2026-09-05T00:00:00+00:00",
        plan_hash="",
        criteria_count=criteria_count,
        steps=legacy_steps,
        task=plan["task"],
        requirements=plan["requirements"],
        required_tools=[],
        environment=legacy_env,
        format_version=3,
    )
    legacy.plan_hash = legacy_v3_plan_hash(legacy.as_plan())
    save_seal(legacy, str(pg / "seal.json"))

    # Genuine legacy v3 hash must load successfully before migration.
    loaded = load_seal(str(pg / "seal.json"))
    assert loaded is not None and loaded.format_version == 3

    result = migrate_one(root, PlanRef("default", pg / "plan.json"))
    assert result["status"] == "migrated"
    migrated = load_seal(str(pg / "seal.json"))
    assert migrated is not None
    assert migrated.format_version == 4
    assert migrated.environment == env
