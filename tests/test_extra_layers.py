"""Tests for L1, L4, L5, L9, L11, L12."""
import sys
import os
import json
import tempfile
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.requirements import parse_requirements, Requirement
from supervisor.goals import GoalModel, Beliefs, Desires
from supervisor.plan_verifier import verify_plan
from supervisor.watchdog import Watchdog, _snapshot_files
from supervisor.evidence import build_archive_manifest, verify_anchor_chain, tail_hash
from supervisor.adversarial import run_adversarial_review, Finding


# --------------------------------------------------------------- L1 requirements

def test_parse_requirements_splits_sentences():
    task = "Build a login form. It must hash passwords."
    reqs = parse_requirements(task)
    assert len(reqs) >= 1
    assert all(isinstance(r, Requirement) for r in reqs)


def test_must_priority_detected():
    reqs = parse_requirements("It must authenticate users.")
    assert any(r.priority == "must" for r in reqs)


def test_ambiguity_flagged():
    reqs = parse_requirements("Maybe handle this somehow, perhaps later.")
    assert any(r.ambiguity in ("medium", "high") for r in reqs)


# --------------------------------------------------------------- L4 goals

def test_goal_model_next_intention():
    model = GoalModel()
    model.intentions.verification_steps = [
        {"action": "check_tests"}, {"action": "check_build"},
    ]
    assert model.has_open_intentions()
    assert model.next_intention()["action"] == "check_tests"
    assert model.next_intention()["action"] == "check_build"
    assert model.next_intention()["action"] == "final_audit"


def test_beliefs_summary():
    b = Beliefs(requirements=[{}, {}], tool_availability={"python": True, "rust": False})
    s = b.summary()
    assert s["n_requirements"] == 2
    assert s["tools"] == {"python": True}


# --------------------------------------------------------------- L5 plan verifier

def test_verify_plan_pass_with_behavioral():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "echo"}]}]}
    a = verify_plan(plan)
    assert a.verdict == "PASS"


def test_verify_plan_reject_when_all_weak():
    plan = {"steps": [{"id": 1, "verify": [{"type": "file_exists", "path": "x.py"}]}]}
    a = verify_plan(plan)
    assert a.verdict == "REJECT"


def test_verify_plan_reject_empty():
    a = verify_plan({"steps": []})
    assert a.verdict == "REJECT"


def test_verify_plan_revise_mixed():
    plan = {"steps": [
        {"id": 1, "verify": [{"type": "run", "cmd": "echo"}]},
        {"id": 2, "verify": [{"type": "file_exists", "path": "x"}]},
    ]}
    a = verify_plan(plan)
    assert a.verdict == "REVISE"


# --------------------------------------------------------------- L9 watchdog

def test_watchdog_detects_created_file(tmp_path):
    wd = Watchdog(str(tmp_path), poll_interval=0.1)
    new_file = tmp_path / "new.py"
    new_file.write_text("x")
    result = wd.poll()
    assert "new.py" in result.created


def test_watchdog_detects_deleted_file(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x")
    wd = Watchdog(str(tmp_path), poll_interval=0.1)
    f.unlink()
    result = wd.poll()
    assert "a.py" in result.deleted


def test_snapshot_excludes_plan_auditor():
    with tempfile.TemporaryDirectory() as d:
        Path(d, ".plan-auditor").mkdir()
        Path(d, ".plan-auditor/secret").write_text("hidden")
        Path(d, "real.py").write_text("x")
        snap = _snapshot_files(d)
        assert "real.py" in snap
        assert not any(".plan-auditor" in k for k in snap)


# --------------------------------------------------------------- L11 evidence

def test_tail_hash_of_chain():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        ev = os.path.join(d, "evidence.jsonl")
        with open(ev, "w") as f:
            for h in ("aaa", "bbb"):
                f.write(json.dumps({"hash": h, "x": 1}) + "\n")
        assert tail_hash(ev) == "bbb"


def test_anchor_manifest_single_archive():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        arch_dir = os.path.join(d, "archive")
        os.makedirs(arch_dir)
        with open(os.path.join(arch_dir, "evidence-1.jsonl"), "w") as f:
            f.write(json.dumps({"hash": "h1"}) + "\n")
        result = verify_anchor_chain(arch_dir)
        assert result["anchored"] is True


def test_anchor_detects_break():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        arch_dir = os.path.join(d, "archive")
        os.makedirs(arch_dir)
        with open(os.path.join(arch_dir, "evidence-1.jsonl"), "w") as f:
            f.write(json.dumps({"hash": "h1"}) + "\n")
        with open(os.path.join(arch_dir, "evidence-2.jsonl"), "w") as f:
            f.write(json.dumps({"hash": "h2", "previous_archive_hash": "WRONG"}) + "\n")
        result = verify_anchor_chain(arch_dir)
        assert result["anchored"] is False
        assert result["broken_at"] == 1


# --------------------------------------------------------------- L12 adversarial

def test_adversarial_detects_hardcoded_pass():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "assert True"}]}]}
    report = run_adversarial_review(plan)
    assert any(f.check_id == "ADV-HARDCODED-PASS" for f in report.findings)


def test_adversarial_no_llm_is_tier1_default():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "assert True"}]}]}
    report = run_adversarial_review(plan)
    assert report.used_llm is False
    assert report.has_critical()
