"""Workspace result classification preserves unknown, fail, and plan identities."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import supervisor.orchestrator as orch


@pytest.fixture
def isolated_workspace(monkeypatch, tmp_path):
    refs = [SimpleNamespace(name="one", key="one"), SimpleNamespace(name="two", key="two")]
    status = SimpleNamespace(
        valid=True,
        activated=True,
        request={"task": "isolated"},
        reason="",
        as_dict=lambda: {"valid": True},
    )
    monkeypatch.setattr(orch, "verify_request_contract", lambda _: status)
    monkeypatch.setattr(orch, "all_plan_refs", lambda _: refs)
    monkeypatch.setattr(orch, "load_plan_ref", lambda _: {"task": "isolated", "steps": []})
    monkeypatch.setattr(
        orch, "analyze_request_alignment", lambda a, b: orch.RequestAlignment(True, [], {})
    )
    monkeypatch.setattr(
        orch, "capture_workspace", lambda root: SimpleNamespace(to_dict=lambda: {"cwd": root})
    )
    monkeypatch.setattr(orch, "_tail_logs", lambda root: [])
    monkeypatch.setattr(orch.core, "verify_chain", lambda root: (True, 2, ""))
    monkeypatch.setattr(orch.core, "evidence_is_authenticated", lambda root: (False, "key absent"))
    monkeypatch.setattr(orch, "verify_anchor_chain", lambda path: {"anchored": True})

    class Registry:
        def __init__(self, *args, **kwargs):
            pass

        def release_stale_ownership(self):
            return []

        def active_agents(self):
            return []

        def verify_registry_chain(self):
            return True

    monkeypatch.setattr(orch, "MultiAgentRegistry", Registry)
    monkeypatch.setattr(orch, "load_policy_rules_from_dir", lambda path, errors: [])
    return tmp_path, refs, status


@pytest.mark.parametrize(
    "outcomes,expected",
    [
        (["PASS", "PASS"], "PASS"),
        (["PASS", "UNKNOWN"], "UNKNOWN"),
        (["PASS", "FAIL"], "FAIL"),
        (["UNKNOWN", "FAIL"], "FAIL"),
        (["not-an-outcome", "PASS"], "FAIL"),
    ],
)
def test_multi_plan_result_never_masks_worst_outcome(
    isolated_workspace, monkeypatch, outcomes, expected
):
    root, refs, status = isolated_workspace
    mapping = dict(zip((ref.key for ref in refs), outcomes))
    monkeypatch.setattr(
        orch, "_evaluate_plan", lambda _root, ref, *args: {"outcome": mapping[ref.key]}
    )
    result = orch.evaluate_workspace(str(root))
    assert result["outcome"] == expected
    assert result["active_plan_count"] == len(refs)
    assert result["plans"]["one"]["outcome"] == outcomes[0]
    assert result["plans"]["two"]["outcome"] == outcomes[1]
    assert result["request_contract"]["valid"] is True
    assert result["evidence"]["authenticated"] is False


def test_unknown_or_invalid_requested_profile_and_mode_are_errors(isolated_workspace, monkeypatch):
    root, refs, _ = isolated_workspace
    monkeypatch.setattr(orch, "_evaluate_plan", lambda *args: {"outcome": "FAIL"})
    doc = orch.evaluate_workspace(str(root), profile="not-real", mode="unsafe")
    assert any("invalid requested profile" in err for err in doc["configuration_errors"])
    assert any("invalid requested mode" in err for err in doc["configuration_errors"])
    assert doc["outcome"] == "FAIL"


def test_invalid_request_status_is_reported_as_policy_error(isolated_workspace, monkeypatch):
    root, _, status = isolated_workspace
    status.valid = False
    status.reason = "missing host signature"
    monkeypatch.setattr(orch, "_evaluate_plan", lambda *args: {"outcome": "FAIL"})
    doc = orch.evaluate_workspace(str(root))
    assert any("missing host signature" in x for x in doc["policy_errors"])
    assert doc["request_alignment"]["valid"] is False


def test_corrupt_plan_read_is_recorded_in_request_errors(isolated_workspace, monkeypatch):
    root, _, _ = isolated_workspace

    def invalid_plan(_):
        raise ValueError("malformed plan document")

    monkeypatch.setattr(orch, "load_plan_ref", invalid_plan)
    monkeypatch.setattr(orch, "_evaluate_plan", lambda *args: {"outcome": "FAIL"})
    doc = orch.evaluate_workspace(str(root))
    assert any("malformed plan document" in x for x in doc["policy_errors"])
    assert doc["outcome"] == "FAIL"
