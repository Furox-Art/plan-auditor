"""Source-backed exceptional plan and audit conditions never become PASS."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import supervisor.orchestrator as o
from supervisor.config import Profile, load_config
from supervisor.sealing import SealIntegrityError


def test_unreadable_evidence_file_does_not_supply_audit_records(monkeypatch, tmp_path):
    directory = tmp_path / ".plan-auditor"
    directory.mkdir()
    target = directory / "evidence.jsonl"
    target.write_text('{"status":"verified"}\n', encoding="utf-8")
    real = Path.open

    def block(self, *args, **kwargs):
        if self == target:
            raise PermissionError("file not readable")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", block)
    assert list(o._iter_evidence_records(tmp_path)) == []


def _evaluate(tmp_path, monkeypatch, *, bad_plan=False, bad_seal=False, strict=False):
    cfg = load_config(str(tmp_path))
    if strict:
        cfg.profile = Profile.STRICT
    ref = SimpleNamespace(key="default", name="default", path=tmp_path / "plan.json")
    if bad_plan:
        monkeypatch.setattr(
            o, "load_plan_ref", lambda ref: (_ for _ in ()).throw(ValueError("bad plan JSON"))
        )
    else:
        plan = {"id": "isolated", "task": "audit", "steps": []}
        monkeypatch.setattr(o, "load_plan_ref", lambda ref: plan)
    if bad_seal:
        monkeypatch.setattr(
            o, "load_seal", lambda path: (_ for _ in ()).throw(SealIntegrityError("bad seal"))
        )
    else:
        monkeypatch.setattr(o, "load_seal", lambda path: None)
    monkeypatch.setattr(
        o, "fresh_full_audit_proof", lambda *args: o.FreshAuditProof(False, "no audit")
    )
    registry = SimpleNamespace(active_agents=lambda: [])
    state = SimpleNamespace(to_dict=lambda: {}, available_tools={})
    return o._evaluate_plan(
        tmp_path,
        ref,
        cfg,
        state,
        [],
        False,
        0,
        "no evidence",
        False,
        "no key",
        {"anchored": False},
        registry,
        True,
        [],
        [],
        [],
    )


def test_malformed_plan_loading_does_not_bypass_failure(monkeypatch, tmp_path):
    report = _evaluate(tmp_path, monkeypatch, bad_plan=True)
    assert report == {
        "outcome": "FAIL",
        "plan_name": "default",
        "error": "invalid plan: bad plan JSON",
    }


def test_corrupted_seal_is_explicitly_reported(monkeypatch, tmp_path):
    report = _evaluate(tmp_path, monkeypatch, bad_seal=True)
    assert report["outcome"] != "PASS"
    assert "bad seal" in report["seal"]["violations"]


def test_strict_profile_executes_adversarial_review(monkeypatch, tmp_path):
    called = []

    def review(plan, evidence_path):
        called.append((plan, evidence_path))
        return o.AdversarialReport()

    monkeypatch.setattr(o, "run_adversarial_review", review)
    result = _evaluate(tmp_path, monkeypatch, strict=True)
    assert result["outcome"] != "PASS"
    assert len(called) == 1
    assert called[0][1].endswith("evidence.jsonl")


def test_authenticated_error_already_in_gate_notes_is_not_repeated(monkeypatch, tmp_path):
    problem = "evidence is not authenticated: no key"
    evaluated = []

    class Gate:
        def __init__(self, engine):
            self.engine = engine

        def evaluate(self, **kwargs):
            notes = [problem]
            evaluated.append(notes)
            return SimpleNamespace(outcome="FAIL", notes=notes, as_dict=lambda: {"outcome": "FAIL"})

    monkeypatch.setattr(o, "CompletionGate", Gate)
    report = _evaluate(tmp_path, monkeypatch)
    assert report["outcome"] == "FAIL"
    assert evaluated == [[problem]]


def test_policy_directory_deduplication_in_workspace(monkeypatch, tmp_path):
    refs = [SimpleNamespace(name="one", key="one", path=tmp_path / "one.json")]
    monkeypatch.setattr(o, "all_plan_refs", lambda root: refs)
    status = SimpleNamespace(
        activated=True, valid=True, request={}, as_dict=lambda: {"valid": True}
    )
    monkeypatch.setattr(o, "verify_request_contract", lambda root: status)
    monkeypatch.setattr(o, "load_plan_ref", lambda ref: {"steps": []})
    monkeypatch.setattr(
        o, "analyze_request_alignment", lambda a, b: o.RequestAlignment(True, [], {})
    )
    cfg = load_config(str(tmp_path))
    cfg.policies_dir = ".plan-auditor/policies"
    monkeypatch.setattr(o, "load_config", lambda root: cfg)
    monkeypatch.setattr(
        o, "capture_workspace", lambda root: SimpleNamespace(to_dict=lambda: {}, available_tools={})
    )
    monkeypatch.setattr(o, "_tail_logs", lambda root: [])
    monkeypatch.setattr(o.core, "verify_chain", lambda root: (True, 0, ""))
    monkeypatch.setattr(o.core, "evidence_is_authenticated", lambda root: (False, "unsigned"))
    monkeypatch.setattr(o, "verify_anchor_chain", lambda path: {"anchored": True})

    class Registry:
        def __init__(self, *args, **kwargs):
            pass

        def release_stale_ownership(self):
            return []

        def active_agents(self):
            return []

        def verify_registry_chain(self):
            return True

    monkeypatch.setattr(o, "MultiAgentRegistry", Registry)
    monkeypatch.setattr(o, "_evaluate_plan", lambda *args: {"outcome": "FAIL"})
    seen = []
    monkeypatch.setattr(
        o, "load_policy_rules_from_dir", lambda path, errors: seen.append(path) or []
    )
    report = o.evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert len(seen) == 1
