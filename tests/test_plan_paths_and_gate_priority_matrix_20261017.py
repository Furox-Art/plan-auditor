"""Actual confined plan reads and independent gate priority semantics."""

from __future__ import annotations

import pytest

from supervisor import control_plane, gate, plans
from supervisor.policies import PolicyEngine, PolicyRule, RuleResult


@pytest.mark.parametrize("value", ["/tmp/outside", "../escape", "a/../b"])
def test_untrusted_workspace_path_cannot_escape_lexically(tmp_path, value):
    with pytest.raises(control_plane.ControlPlanePathError):
        control_plane.confined_workspace_path(tmp_path, value)


def test_control_plane_requires_existing_workspace(tmp_path):
    with pytest.raises(control_plane.ControlPlanePathError, match="workspace is not a directory"):
        control_plane.confined_workspace_path(tmp_path / "missing", "plan.json")


@pytest.mark.parametrize("mode", ["require_exists", "require_directory", "require_file"])
def test_requested_path_type_is_enforced_before_trust(tmp_path, mode):
    p = tmp_path / "data"
    p.write_text("actual file")
    if mode == "require_directory":
        with pytest.raises(control_plane.ControlPlanePathError, match="not a directory"):
            control_plane.confined_workspace_path(tmp_path, "data", require_directory=True)
    elif mode == "require_file":
        p.unlink()
        p.mkdir()
        with pytest.raises(control_plane.ControlPlanePathError, match="not a file"):
            control_plane.confined_workspace_path(tmp_path, "data", require_file=True)
    else:
        p.unlink()
        with pytest.raises(control_plane.ControlPlanePathError, match="does not exist"):
            control_plane.confined_workspace_path(tmp_path, "data", require_exists=True)


def test_control_plane_refuses_symlink_to_external_workspace(tmp_path):
    outside = tmp_path.parent / "outside-root-control-plane"
    target = tmp_path / "escape"
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(control_plane.ControlPlanePathError, match="symlink"):
        control_plane.confined_workspace_path(tmp_path, "escape/plan.json")


@pytest.mark.parametrize("name", ["..", ".", "../escape", "a/b", "bad name", "X" * 129])
def test_plan_name_contract_blocks_path_forgery_and_unbounded_ids(name):
    with pytest.raises(plans.PlanNameError):
        plans.validate_plan_name(name)


@pytest.mark.parametrize(
    ("name", "expected"),
    [(None, "default"), ("", "default"), ("default", "default"), ("safe-plan_3", "safe-plan_3")],
)
def test_valid_plan_name_is_preserved_or_canonical_default(name, expected):
    assert plans.validate_plan_name(name) == expected


def test_plan_discovery_yields_only_recorded_safe_json(tmp_path):
    root = tmp_path / ".plan-auditor"
    root.mkdir()
    (root / "plan.json").write_text('{"steps":[]}')
    folder = root / "plans"
    folder.mkdir()
    (folder / "verified.json").write_text('{"steps":[]}')
    (folder / "ignored.txt").write_text("not-plan")
    refs = plans.all_plan_refs(tmp_path)
    assert [r.name for r in refs] == ["default", "verified"]
    assert [plans.load_plan_ref(r) for r in refs] == [{"steps": []}, {"steps": []}]


def test_plan_directory_with_plan_json_as_directory_fails_closed(tmp_path):
    p = tmp_path / ".plan-auditor" / "plan.json"
    p.mkdir(parents=True)
    with pytest.raises(plans.PlanNameError, match="not a regular file"):
        plans.all_plan_refs(tmp_path)


def test_plan_loader_refuses_nonobject_even_when_valid_json(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="plan root must be an object"):
        plans.load_plan_ref(plans.PlanRef("default", path))


def test_plan_loader_bounds_size_before_allocating_large_json(tmp_path):
    p = tmp_path / "large.json"
    with p.open("wb") as f:
        f.truncate(plans.MAX_PLAN_BYTES + 1)
    with pytest.raises(plans.PlanSizeError, match="over the"):
        plans.load_plan_ref(plans.PlanRef("oversize", p))


def test_final_gate_without_fresh_deterministic_proof_never_passes():
    out = gate.CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=False, pending_steps=[], workspace_context={}
    )
    assert out.outcome == "FAIL"
    assert any("fresh deterministic" in n for n in out.notes)


def test_final_gate_with_pending_steps_fails_despite_fresh_other_checks():
    out = gate.CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=True, pending_steps=[2], workspace_context={}
    )
    assert out.outcome == "FAIL"
    assert out.as_dict()["pending_steps"] == [2]


@pytest.mark.parametrize(
    ("level", "expected"), [(0, "FAIL"), (2, "FAIL"), (3, "FAIL"), (4, "UNKNOWN"), (5, "FAIL")]
)
def test_policy_priority_cannot_be_weakened_by_later_agent_pass(level, expected):
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="blocking",
                level=level,
                question="is there evidence?",
                fn=lambda ctx: RuleResult("blocking", True, level, "real observation"),
            )
        ]
    )
    out = gate.CompletionGate(policy).evaluate(
        deterministic_passed=True, pending_steps=[], workspace_context={}
    )
    assert out.outcome == expected
    assert out.verdict.blocking_level == level
    assert out.as_dict()["policy_findings"][0]["evidence"] == ""


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("low", "PASS"), ("warn", "PASS"), ("high", "UNKNOWN"), ("critical", "UNKNOWN")],
)
def test_semantic_adversarial_review_can_withhold_pass_not_grant_it(severity, expected):
    out = gate.CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=True,
        pending_steps=[],
        workspace_context={},
        adversarial_findings=[{"severity": severity, "description": "unverified inference"}],
    )
    assert out.outcome == expected


def test_no_semantic_finding_can_upgrade_a_real_failure():
    out = gate.CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=False,
        pending_steps=[3],
        workspace_context={},
        adversarial_findings=[{"severity": "low", "description": "looks safe"}],
    )
    assert out.outcome == "FAIL"
    assert out.pending_steps == [3]
