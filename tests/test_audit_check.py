"""audit_check.py birim test süiti — pytest ile çalışır: python -m pytest tests/ -q"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import audit_check as ac  # noqa: E402


def make_plan(tmp_path, plan):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    return tmp_path


def valid_plan(task="görev", **step_over):
    step = {"id": 1, "title": "t",
            "verify": [{"type": "run", "cmd": "python -c \"print(1)\"", "expect_exit": 0}],
            "status": "pending"}
    step.update(step_over)
    return {"task": task, "created": "2026-09-03T00:00:00", "steps": [step]}


# ----------------------------------------------------------- validate_plan

def test_validate_ok():
    assert ac.validate_plan(valid_plan()) == []


def test_validate_rejects_non_dict():
    assert ac.validate_plan(["x"])


def test_validate_rejects_empty_task():
    assert ac.validate_plan(valid_plan(task=""))


def test_validate_rejects_empty_verify():
    p = valid_plan(verify=[])
    errs = ac.validate_plan(p)
    assert any("verify" in e for e in errs)


def test_validate_rejects_non_behavioral_only():
    p = valid_plan(verify=[{"type": "file_exists", "path": "x.py"},
                           {"type": "regex", "path": "x.py", "pattern": "def"}])
    errs = ac.validate_plan(p)
    assert any("DAVRANIŞSAL" in e for e in errs)


def test_validate_rejects_duplicate_ids():
    plan = valid_plan()
    plan["steps"].append(dict(plan["steps"][0]))
    errs = ac.validate_plan(plan)
    assert any("tekrarlı" in e for e in errs)


def test_validate_rejects_run_without_cmd():
    p = valid_plan(verify=[{"type": "run"}])
    errs = ac.validate_plan(p)
    assert any("cmd" in e for e in errs)


def test_validate_rejects_unknown_type():
    p = valid_plan(verify=[{"type": "mistik"}])
    errs = ac.validate_plan(p)
    assert any("geçersiz kontrol" in e for e in errs)


# -------------------------------------------------------------- norm_check

def test_norm_check_pytest_becomes_run():
    c = ac.norm_check({"type": "pytest", "args": "tests/ -q"})
    assert c["type"] == "run"
    assert c["cmd"] == "python -m pytest tests/ -q"
    assert c["expect_exit"] == 0


def test_norm_check_exec_becomes_run():
    c = ac.norm_check({"type": "exec", "cmd": "checker.exe --strict"})
    assert c["type"] == "run"
    assert c["cmd"] == "checker.exe --strict"
    assert c["expect_exit"] == 0


def test_norm_check_run_passthrough():
    c = {"type": "run", "cmd": "x", "expect_exit": 7}
    assert ac.norm_check(c) == c


# --------------------------------------------------------------- run_check

def test_run_check_file_exists(tmp_path):
    f = tmp_path / "var.py"
    f.write_text("x", encoding="utf-8")
    ok, detail, _ = ac.run_check({"type": "file_exists", "path": "var.py"}, str(tmp_path))
    assert ok
    ok, _, _ = ac.run_check({"type": "file_exists", "path": "yok.py"}, str(tmp_path))
    assert not ok


def test_run_check_regex(tmp_path):
    (tmp_path / "a.py").write_text("def fib(n):\n    return n\n", encoding="utf-8")
    ok, _, _ = ac.run_check({"type": "regex", "path": "a.py", "pattern": r"def\s+fib"}, str(tmp_path))
    assert ok
    ok, _, _ = ac.run_check({"type": "regex", "path": "a.py", "pattern": r"class\s+Fib"}, str(tmp_path))
    assert not ok


def test_run_check_exit_code(tmp_path):
    ok, _, _ = ac.run_check(
        {"type": "run", "cmd": "python -c \"import sys; sys.exit(3)\"", "expect_exit": 3},
        str(tmp_path))
    assert ok
    ok, _, _ = ac.run_check(
        {"type": "run", "cmd": "python -c \"import sys; sys.exit(3)\"", "expect_exit": 0},
        str(tmp_path))
    assert not ok


def test_run_check_output_regex(tmp_path):
    ok, _, _ = ac.run_check(
        {"type": "run", "cmd": "python -c \"print('TOTAL: 42')\"",
         "output_regex": r"TOTAL:\s+\d+"},
        str(tmp_path))
    assert ok
    ok, _, _ = ac.run_check(
        {"type": "run", "cmd": "python -c \"print('hayır')\"",
         "output_regex": r"TOTAL:\s+\d+"},
        str(tmp_path))
    assert not ok


# ----------------------------------------------------------- evidence chain

def test_chain_ok_and_tamper_detected(tmp_path):
    base = str(tmp_path)
    ac.append_evidence(base, {"ts": "t1", "mode": "run", "step": 1,
                              "status": "failed", "results": []})
    ac.append_evidence(base, {"ts": "t2", "mode": "run", "step": 2,
                              "status": "verified", "results": []})
    ok, n, problem = ac.verify_chain(base)
    assert ok and n == 2 and problem == ""

    log = ac.evidence_path(base)
    with open(log, encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["status"] = "verified"  # başarısız kaydı geçmişe çevirme girişimi
    lines[0] = ac.canonical(rec) + "\n"
    with open(log, "w", encoding="utf-8") as f:
        f.writelines(lines)
    ok, _, problem = ac.verify_chain(base)
    assert not ok and "hash" in problem


def test_count_failed_attempts(tmp_path):
    base = str(tmp_path)
    ac.append_evidence(base, {"ts": "t1", "mode": "run", "step": 1,
                              "status": "failed", "results": []})
    ac.append_evidence(base, {"ts": "t2", "mode": "run", "step": 1,
                              "status": "verified", "results": []})
    ac.append_evidence(base, {"ts": "t3", "mode": "run", "step": 1,
                              "status": "failed", "results": []})
    ac.append_evidence(base, {"ts": "t4", "mode": "audit", "step": 1,
                              "status": "failed", "results": []})
    assert ac.count_failed_attempts(base, 1) == 2


# ------------------------------------------------------- end-to-end smoke

def test_audit_steps_verifies_and_records(tmp_path):
    base = str(tmp_path)
    (tmp_path / "fib.py").write_text("def fib(n):\n    return n\n", encoding="utf-8")
    plan = valid_plan(verify=[
        {"type": "file_exists", "path": "fib.py"},
        {"type": "run", "cmd": "python -c \"import sys; sys.exit(0)\"", "expect_exit": 0},
    ])
    ok = ac.audit_steps(base, plan, ids=[1], mode="run")
    assert ok
    assert plan["steps"][0]["status"] == "verified"
    ok, n, problem = ac.verify_chain(base)
    assert ok and n == 1
