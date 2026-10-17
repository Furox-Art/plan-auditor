"""Plan file enumeration and policy hash do not silently ignore invalid blockers."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from supervisor import contracts, gate, plans
from supervisor.config import Config
from supervisor.policies import PolicyEngine


def policy(root, relative="policies"):
    return Config(workspace_root=str(root), policies_dir=relative)


def test_duplicate_configured_policy_dir_is_hashed_once_not_twice(tmp_path):
    p = tmp_path / ".plan-auditor" / "policies"
    p.mkdir(parents=True)
    (p / "deny.json").write_text('{"deny":true}')
    first = contracts.policy_fingerprint(tmp_path, policy(tmp_path, ".plan-auditor/policies"))
    second = contracts.policy_fingerprint(tmp_path, policy(tmp_path, "policies"))
    assert first == second


def test_policy_document_directory_is_not_traversed_as_if_it_were_a_policy_file(tmp_path):
    folder = tmp_path / "policies"
    folder.mkdir()
    initial = contracts.policy_fingerprint(tmp_path, policy(tmp_path))
    (folder / "not-a-file.json").mkdir()
    final = contracts.policy_fingerprint(tmp_path, policy(tmp_path))
    assert initial == final


def test_high_severity_adversarial_review_object_withholds_pass_but_never_promotes_it():
    finding = SimpleNamespace(severity="HIGH", description="unverified theorem proof")
    out = gate.CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=True,
        pending_steps=[],
        workspace_context={},
        adversarial_findings=[finding],
    )
    assert out.outcome == "UNKNOWN"
    assert out.as_dict()["adversarial_findings"][0]["description"] == "unverified theorem proof"


def test_named_plan_key_remains_explicit_to_prevent_wrong_seal_binding(tmp_path):
    path = tmp_path / "experiment.json"
    named = plans.PlanRef("experiment", path)
    assert named.key == "experiment"
    assert plans.PlanRef("default", path).key == "default"


def test_named_plans_directory_refuses_malicious_document_symlink(tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "experiment.json").symlink_to(tmp_path.parent / "outside-plan.json")
    with pytest.raises(plans.PlanNameError, match="symlink"):
        plans.all_plan_refs(tmp_path)


def test_named_plan_json_must_be_regular_file(tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "experiment.json").mkdir()
    with pytest.raises(plans.PlanNameError, match="not a regular file"):
        plans.all_plan_refs(tmp_path)


def test_named_plan_directory_symlink_cannot_redirect_trusted_plan_discovery(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plans").symlink_to(tmp_path.parent / "outside-plan-directory", target_is_directory=True)
    with pytest.raises(plans.PlanNameError, match="symlink"):
        plans.all_plan_refs(tmp_path)


def test_default_plan_loader_refuses_symlink_to_external_file(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    external = tmp_path.parent / "outside-plan"
    (pg / "plan.json").symlink_to(external)
    with pytest.raises(plans.PlanNameError, match="symlink"):
        plans.all_plan_refs(tmp_path)


def test_plan_loader_requires_an_actual_file_not_a_disguised_directory(tmp_path):
    folder = tmp_path / "plan.json"
    folder.mkdir()
    with pytest.raises(ValueError, match="not a safe regular file"):
        plans.load_plan_ref(plans.PlanRef("plan", folder))


def test_unsupported_plan_name_is_reported_instead_of_skipping_invalid_json(tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "bad name.json").write_text('{"steps":[]}')
    with pytest.raises(plans.PlanNameError, match="plan name must match"):
        plans.all_plan_refs(tmp_path)


def test_replay_plan_loader_requires_json_object_not_array(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    source = pg / "plan.json"
    source.write_text(json.dumps(["not-a-structured-plan"]))
    with pytest.raises(ValueError, match="plan root must be an object"):
        plans.load_plan_ref(plans.PlanRef("default", source))


def test_secondary_plan_name_guard_still_refuses_slash_after_pattern_is_weakened(monkeypatch):
    import re

    monkeypatch.setattr(plans, "PLAN_NAME_RE", re.compile(r"^.+$"))
    with pytest.raises(plans.PlanNameError, match="path separators"):
        plans.validate_plan_name("a/b")


def test_named_plan_dir_secondary_type_guard_still_refuses_racy_regular_file(monkeypatch, tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.parent.mkdir()
    folder.write_text("replaced with regular file")
    real = plans._confined

    def injected(root, relative, *, directory=False):
        if relative == ".plan-auditor/plans":
            return folder
        return real(root, relative, directory=directory)

    monkeypatch.setattr(plans, "_confined", injected)
    with pytest.raises(plans.PlanNameError, match="not a directory"):
        plans.all_plan_refs(tmp_path)
