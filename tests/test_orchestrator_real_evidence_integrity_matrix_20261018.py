"""Audit proof cannot be made by partial, reordered, unauthenticated evidence.

This exercises the *installed* wheel; controlled fault injection isolates each
logical refusal and checks the real production predicate and message.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.plan_graph import PlanGraphError
from supervisor import orchestrator as audit


def _plan():
    return {"steps": [{"id": 1, "verify": [], "status": "verified"}]}


def _event(step=1):
    return {
        "plan": "default",
        "mode": "audit",
        "step": step,
        "status": "verified",
        "results": [],
        "dependencies": [],
        "outputs": [],
        "required_outputs": [],
    }


def _marker():
    return {
        "plan": "default",
        "mode": "audit_complete",
        "status": "verified",
        "topological_order": [1],
        "plan_fingerprint": "plan-digest",
        "workspace_fingerprint": "workspace-digest",
        "ts": "2026-10-18T00:00:00Z",
    }


def _prepare(monkeypatch, root: Path, records=None):
    monkeypatch.setattr(audit.core, "verify_chain", lambda _: (True, 2, ""))
    monkeypatch.setattr(audit, "verify_anchor_chain", lambda _: {"anchored": True})
    monkeypatch.setattr(audit.core, "plan_contract_fingerprint", lambda _: "plan-digest")
    monkeypatch.setattr(audit.core, "workspace_fingerprint", lambda _: "workspace-digest")
    monkeypatch.setattr(
        audit,
        "_iter_evidence_records",
        lambda _root: iter(records if records is not None else [_event(), _marker()]),
    )
    return audit.fresh_full_audit_proof(root, _plan())


def test_complete_audited_evidence_requires_exact_checks_and_fingerprints(monkeypatch, tmp_path):
    proof = _prepare(monkeypatch, tmp_path)
    assert proof.valid and proof.steps == 1
    assert proof.audited_at == "2026-10-18T00:00:00Z"
    assert proof.as_dict()["reason"].startswith("current dependency graph")


def test_evidence_chain_validation_rejects_prior_to_plan_parse(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(audit.core, "verify_chain", lambda _: (False, 0, "broken chain"))
    proof = audit.fresh_full_audit_proof(tmp_path, _plan())
    assert not proof.valid and "broken chain" in proof.reason


def test_unanchored_archive_cannot_be_accepted_as_a_valid_full_audit(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(audit, "verify_anchor_chain", lambda _: {"anchored": False})
    proof = audit.fresh_full_audit_proof(tmp_path, _plan())
    assert not proof.valid and "not anchored" in proof.reason


def test_dependency_cycles_never_become_valid_evidence_order(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)

    def reject(_):
        raise PlanGraphError("recorded dependency cycle")

    monkeypatch.setattr(audit, "topological_order", reject)
    proof = audit.fresh_full_audit_proof(tmp_path, _plan())
    assert not proof.valid and "dependency graph invalid" in proof.reason


def test_no_valid_steps_never_results_in_a_trivial_successful_proof(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)
    monkeypatch.setattr(audit, "topological_order", lambda _: [])
    proof = audit.fresh_full_audit_proof(tmp_path, _plan())
    assert not proof.valid and "no valid dependency-graph steps" in proof.reason


@pytest.mark.parametrize(
    ("events", "message"),
    [
        ([], "no complete full-audit"),
        ([_marker()], "lacks complete step evidence"),
        ([_event(step=2), _marker()], "does not cover dependency order"),
        ([_event(), {**_marker(), "status": "rejected"}], "latest full audit did not pass"),
        ([_event(), {**_marker(), "topological_order": [2]}], "order does not match"),
        ([_event(), {**_marker(), "plan_fingerprint": "stale"}], "plan contract changed"),
        (
            [_event(), {**_marker(), "workspace_fingerprint": "stale"}],
            "workspace content/type/mode changed",
        ),
        ([{**_event(), "status": "FAILED"}, _marker()], "audit evidence does not match"),
        ([{**_event(), "dependencies": [9]}, _marker()], "audit evidence does not match"),
        (
            [{**_event(), "results": [{"check": {}, "passed": True}]}, _marker()],
            "audit evidence does not match",
        ),
        (
            [_event(), _marker(), {**_marker(), "status": "rejected"}],
            "latest full audit did not pass",
        ),
    ],
)
def test_each_incomplete_or_stale_audit_record_is_refused(monkeypatch, tmp_path, events, message):
    proof = _prepare(monkeypatch, tmp_path, events)
    assert not proof.valid, proof
    assert message in proof.reason


def test_other_plan_records_never_count_as_default_audit_proof(monkeypatch, tmp_path):
    records = [{**_event(), "plan": "other"}, _marker()]
    proof = _prepare(monkeypatch, tmp_path, records)
    assert not proof.valid and "lacks complete step evidence" in proof.reason


def test_streaming_evidence_skips_blank_malformed_nonobject_records(tmp_path):
    directory = tmp_path / ".plan-auditor"
    directory.mkdir()
    (directory / "evidence.jsonl").write_text(
        '\n{malformed\n["not","dict"]\n{"mode":"audit","step":1}\n',
        encoding="utf-8",
    )
    assert list(audit._iter_evidence_records(tmp_path)) == [{"mode": "audit", "step": 1}]


def test_streaming_evidence_archive_precedes_active_log_in_original_order(tmp_path):
    directory = tmp_path / ".plan-auditor"
    archive = directory / "archive"
    archive.mkdir(parents=True)
    (archive / "evidence-001.jsonl").write_text('{"item":"archived"}\n')
    (directory / "evidence.jsonl").write_text('{"item":"active"}\n')
    assert [x["item"] for x in audit._iter_evidence_records(tmp_path)] == ["archived", "active"]


def test_unreadable_archive_is_not_silently_a_verified_audit(monkeypatch, tmp_path):
    directory = tmp_path / ".plan-auditor" / "archive"
    directory.mkdir(parents=True)
    file = directory / "evidence-001.jsonl"
    file.write_text('{"mode":"audit"}\n')
    orig = Path.open

    def reject(self, *a, **kw):
        if self == file:
            raise OSError("read refused")
        return orig(self, *a, **kw)

    monkeypatch.setattr(Path, "open", reject)
    assert list(audit._iter_evidence_records(tmp_path)) == []


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], True),
        ([{"check": {"type": "pytest"}, "passed": True}], True),
    ],
)
def test_exact_result_identity_requires_positive_pass_flag(records, expected):
    approved = [] if not records else [records[0]["check"]]
    assert audit._result_checks_match(approved, records) is expected


@pytest.mark.parametrize(
    "records",
    [
        [42],
        [{"check": {}, "passed": False}],
        [{"check": {"type": "run"}, "passed": True}],
        [{"check": {}, "passed": None}],
        [{}, {}],
    ],
)
def test_result_list_cannot_be_approved_by_count_alone(records):
    assert not audit._result_checks_match([{"type": "pytest"}], records)


def test_missing_step_output_and_source_contract_is_refused(monkeypatch):
    step = {"id": 1, "verify": []}
    records = {"results": [], "dependencies": [], "outputs": [], "required_outputs": []}
    assert audit._checks_match(step, records, [], {1: step})
    monkeypatch.setattr(audit, "output_index", lambda _: {"artifact": {"verify": []}})
    assert not audit._checks_match(step, records, [], {1: step})
    records["outputs"] = [{"name": "artifact", "passed": True, "results": []}]
    assert audit._checks_match(step, records, [], {1: step})
    records["outputs"] = [{"name": "wrong", "passed": True, "results": []}]
    assert not audit._checks_match(step, records, [], {1: step})
    records["outputs"] = [{"name": "artifact", "passed": True, "results": []}]
    monkeypatch.setattr(audit, "required_outputs", lambda _: [{"step": 9, "name": "source"}])
    assert not audit._checks_match(step, records, [], {1: step})
    records["required_outputs"] = [{"step": 9, "name": "source", "passed": True, "results": []}]
    assert not audit._checks_match(step, records, [], {1: step})  # unknown producing step


def test_required_upstream_output_must_exist_and_have_matching_check_evidence(monkeypatch):
    source = {"id": 1, "verify": []}
    target = {"id": 2, "verify": []}
    monkeypatch.setattr(
        audit, "output_index", lambda s: {"artifact": {"verify": []}} if s["id"] == 1 else {}
    )
    monkeypatch.setattr(
        audit,
        "required_outputs",
        lambda s: [{"step": 1, "name": "artifact"}] if s["id"] == 2 else [],
    )
    event = {
        "results": [],
        "dependencies": [1],
        "outputs": [],
        "required_outputs": [{"step": 1, "name": "artifact", "passed": True, "results": []}],
    }
    assert audit._checks_match(target, event, [1], {1: source, 2: target})
    event["required_outputs"][0]["passed"] = False
    assert not audit._checks_match(target, event, [1], {1: source, 2: target})


def test_schema_output_processing_fault_cannot_be_silenced_as_success(monkeypatch):
    def invalid(_):
        raise PlanGraphError("malformed source contract")

    monkeypatch.setattr(audit, "output_index", invalid)
    assert not audit._checks_match({"verify": []}, {"results": [], "dependencies": []}, [], {})


def test_required_tools_invalid_type_is_an_explicit_unknown_tool():
    assert audit._required_tools({"required_tools": "pip"}, {}) == ["<invalid required_tools>"]


def test_required_tools_missing_or_available_are_measured_only(monkeypatch):
    observed = []

    def availability(tool):
        observed.append(tool)
        return tool == "python"

    monkeypatch.setattr(audit, "tool_available", availability)
    cache = {"preinstalled": True}
    missing = audit._required_tools(
        {"required_tools": ["preinstalled", "python", "not-a-tool", "python"]}, cache
    )
    assert missing == ["not-a-tool"]
    assert cache["python"] is True
    assert cache["not-a-tool"] is False
    assert "preinstalled" not in observed


def test_monotonic_checks_refuse_any_failure_without_erasing_original_violations():
    left = audit.MonotonicCheck(ok=True, violations=[], improvements=["more tests"])
    right = audit.MonotonicCheck(ok=False, violations=["signed state diverged"], improvements=[])
    assert audit._merge_checks() is None
    combined = audit._merge_checks(left, right)
    assert combined.ok is False
    assert combined.violations == ["signed state diverged"]
    assert combined.improvements == ["more tests"]


def test_actual_shared_agent_files_generate_a_conflict_not_a_permission():
    left = SimpleNamespace(agent_id="a", owned_files={"a.py", "shared.py"})
    right = SimpleNamespace(agent_id="b", owned_files={"shared.py"})
    registry = SimpleNamespace(active_agents=lambda: [left, right])
    assert audit._agent_conflicts(registry) == [
        {"file": "shared.py", "owner": "a", "accessor": "b"}
    ]


def test_missing_trace_and_watchdog_logs_do_not_become_negative_evidence(tmp_path):
    assert audit._tail_logs(tmp_path) == []
    d = tmp_path / ".plan-auditor"
    d.mkdir()
    (d / "watchdog.jsonl").write_text("one\ntwo\n")
    assert audit._tail_logs(tmp_path, limit=1) == ["two"]


@pytest.mark.parametrize(
    ("plan_ok", "seal_ok", "pending", "proof", "outcome", "expected"),
    [
        (False, False, [1], False, "FAIL", "revision_required"),
        (True, False, [1], False, "FAIL", "plan_approved"),
        (True, True, [1], False, "FAIL", "implementing"),
        (True, True, [], False, "FAIL", "failed"),
        (True, True, [], False, "UNKNOWN", "unknown"),
        (True, True, [], True, "PASS", "passed"),
    ],
)
def test_lifecycle_state_cannot_skip_unverified_completion(
    plan_ok, seal_ok, pending, proof, outcome, expected
):
    history = audit._lifecycle_for(
        plan_ok, seal_ok, pending, audit.FreshAuditProof(proof, ""), outcome
    )
    assert expected in str(history.state).lower()


def test_latest_marker_snapshot_is_not_changed_by_trailing_incomplete_audit(monkeypatch, tmp_path):
    records = [_event(), _marker(), _event(step=9)]
    proof = _prepare(monkeypatch, tmp_path, records)
    assert proof.valid
    assert proof.steps == 1
