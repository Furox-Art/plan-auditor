"""Measured path confinement, lifecycle authority and environment policy fingerprints."""

from __future__ import annotations

from pathlib import Path

import pytest

from supervisor import contracts, control_plane, lifecycle
from supervisor.config import Config


def test_control_plane_default_root_is_actual_workspace_internal_directory(tmp_path):
    assert control_plane.ensure_control_plane_root(tmp_path) == tmp_path / ".plan-auditor"


def test_absolute_or_dotdot_metadata_paths_are_never_confined_as_valid(tmp_path):
    with pytest.raises(control_plane.ControlPlanePathError, match="workspace-relative"):
        control_plane.confined_workspace_path(tmp_path, tmp_path / "outside")
    with pytest.raises(control_plane.ControlPlanePathError):
        control_plane.confined_workspace_path(tmp_path, "..")


def test_drive_prefix_does_not_bypass_workspace_relative_check(monkeypatch):
    original = control_plane.os.path.splitdrive
    monkeypatch.setattr(control_plane.os.path, "splitdrive", lambda x: ("X:", "policy"))
    with pytest.raises(control_plane.ControlPlanePathError, match="drive prefix"):
        control_plane._parts("safe")
    monkeypatch.setattr(control_plane.os.path, "splitdrive", original)


def test_unreadable_metadata_component_never_falls_through_path_authorization(
    monkeypatch, tmp_path
):
    original = Path.lstat

    def deny(self, *args, **kwargs):
        if self.name == "blocked":
            raise OSError("unreadable simulated inode")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", deny)
    with pytest.raises(
        control_plane.ControlPlanePathError, match="cannot inspect control-plane path"
    ):
        control_plane.confined_workspace_path(tmp_path, "blocked/plan.json")


def test_resolved_path_outside_workspace_is_rejected_at_second_containment_gate(
    monkeypatch, tmp_path
):
    orig = Path.resolve

    def redirect(self, *a, **kw):
        if self.name == "target":
            return tmp_path.parent / "external-target"
        return orig(self, *a, **kw)

    monkeypatch.setattr(Path, "resolve", redirect)
    with pytest.raises(control_plane.ControlPlanePathError, match="escapes workspace"):
        control_plane.confined_workspace_path(tmp_path, "target")


def test_policy_fingerprint_changes_with_signed_policy_contents(tmp_path):
    cfg = Config(workspace_root=str(tmp_path), policies_dir="policies")
    p = tmp_path / "policies"
    p.mkdir()
    file = p / "rules.json"
    file.write_text('{"deny":"unapproved"}')
    initial = contracts.policy_fingerprint(tmp_path, cfg)
    file.write_text('{"deny":"all"}')
    altered = contracts.policy_fingerprint(tmp_path, cfg)
    assert altered != initial
    assert contracts.policy_fingerprint(tmp_path, cfg) == altered


def test_policy_hash_ignores_unrelated_nonpolicy_files_but_not_policy_toml(tmp_path):
    cfg = Config(workspace_root=str(tmp_path), policies_dir="policies")
    p = tmp_path / "policies"
    p.mkdir()
    baseline = contracts.policy_fingerprint(tmp_path, cfg)
    (p / "ignore.txt").write_text("different")
    assert contracts.policy_fingerprint(tmp_path, cfg) == baseline
    (p / "policy.toml").write_text('[rule]\nlevel="deny"\n')
    assert contracts.policy_fingerprint(tmp_path, cfg) != baseline


def test_policy_hash_never_reads_symlinked_policy_documents(tmp_path):
    p = tmp_path / "policies"
    p.mkdir()
    (p / "rules.json").symlink_to(tmp_path.parent / "outside-policy.json")
    cfg = Config(workspace_root=str(tmp_path), policies_dir="policies")
    with pytest.raises(ValueError, match="policy file is a symlink"):
        contracts.policy_fingerprint(tmp_path, cfg)


def test_policy_hash_rejects_symlinked_policy_directory(tmp_path):
    p = tmp_path / "policies"
    p.symlink_to(tmp_path.parent / "external-policy-directory", target_is_directory=True)
    cfg = Config(workspace_root=str(tmp_path), policies_dir="policies")
    with pytest.raises(ValueError, match="unsafe policy directory"):
        contracts.policy_fingerprint(tmp_path, cfg)


def test_policy_hash_reports_file_read_error_instead_of_substituting_empty_payload(
    monkeypatch, tmp_path
):
    p = tmp_path / "policies"
    p.mkdir()
    bad = p / "rules.json"
    bad.write_text('{"deny":"all"}')
    original = Path.read_bytes

    def fail(self, *args, **kwargs):
        if self == bad:
            raise OSError("simulated inaccessible policy")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", fail)
    cfg = Config(workspace_root=str(tmp_path), policies_dir="policies")
    with pytest.raises(ValueError, match="cannot fingerprint policy file"):
        contracts.policy_fingerprint(tmp_path, cfg)


def test_lifecycle_rejects_disallowed_jump_to_pass_without_evidence():
    machine = lifecycle.TaskLifecycle(task_id="sample")
    assert machine.transition(lifecycle.States.PASSED) is False
    assert machine.state == lifecycle.States.NEW
    assert machine.history == []


def test_lifecycle_new_discovers_but_cannot_skip_required_review():
    machine = lifecycle.TaskLifecycle(task_id="sample")
    assert machine.transition(lifecycle.States.DISCOVERED, operator="scan")
    assert not machine.transition(lifecycle.States.SEALED)
    assert machine.state == lifecycle.States.DISCOVERED
    assert machine.history[0].operator == "scan"


def test_lifecycle_recovery_from_unknown_is_not_terminal_success():
    machine = lifecycle.TaskLifecycle(task_id="sample")
    machine.state = lifecycle.States.UNKNOWN
    assert not machine.terminal()
    assert machine.transition(lifecycle.States.RECOVERY)
    assert machine.state == lifecycle.States.RECOVERY
    assert not machine.terminal()


@pytest.mark.parametrize(
    "state",
    [
        lifecycle.States.FAILED,
        lifecycle.States.CANCELLED,
    ],
)
def test_lifecycle_failed_or_cancelled_progress_never_claimed_completed(state):
    machine = lifecycle.TaskLifecycle(task_id="sample", state=state)
    assert machine.terminal()
    assert machine.progress_fraction() == 0.0


def test_lifecycle_passed_is_only_successful_terminal_stage():
    machine = lifecycle.TaskLifecycle(task_id="sample", state=lifecycle.States.PASSED)
    assert machine.terminal()
    assert machine.progress_fraction() == 1.0


@pytest.mark.parametrize(
    "state",
    [
        lifecycle.States.RECOVERY,
        lifecycle.States.RETRYING,
        lifecycle.States.ESCALATED,
    ],
)
def test_unknown_position_in_linear_progress_schedule_is_not_marked_as_pass(state):
    machine = lifecycle.TaskLifecycle(task_id="sample", state=state)
    assert machine.progress_fraction() == 0.5


def test_lifecycle_attempts_and_rejected_plans_are_tracked_distinctly():
    machine = lifecycle.TaskLifecycle(task_id="sample", state=lifecycle.States.PLAN_REVIEW)
    assert machine.transition(lifecycle.States.REVISION_REQUIRED)
    assert machine.rejected_plans == 1
    machine.state = lifecycle.States.VERIFYING
    assert machine.transition(lifecycle.States.RETRYING)
    assert machine.retries == 1
    assert machine.rejected_plans == 1
