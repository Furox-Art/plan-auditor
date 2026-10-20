"""audit_check.py unit test suite — run with: python -m pytest tests/ -q"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import audit_check as ac  # noqa: E402


def make_plan(tmp_path, plan):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    return tmp_path


def valid_plan(task="task", **step_over):
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
    assert any("BEHAVIORAL" in e for e in errs)


def test_validate_rejects_duplicate_ids():
    plan = valid_plan()
    plan["steps"].append(dict(plan["steps"][0]))
    errs = ac.validate_plan(plan)
    assert any("duplicate" in e for e in errs)


def test_validate_rejects_run_without_cmd():
    p = valid_plan(verify=[{"type": "run"}])
    errs = ac.validate_plan(p)
    assert any("cmd" in e for e in errs)


def test_validate_rejects_unknown_type():
    p = valid_plan(verify=[{"type": "mistik"}])
    errs = ac.validate_plan(p)
    assert any("invalid check" in e for e in errs)


# -------------------------------------------------------------- norm_check

def test_norm_check_pytest_becomes_run():
    c = ac.norm_check({"type": "pytest", "args": "tests/ -q"})
    assert c["type"] == "run"
    assert c["argv"] == [sys.executable, "-m", "pytest", "tests/", "-q"]
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
        {"type": "run", "cmd": "python -c \"print('no')\"",
         "output_regex": r"TOTAL:\s+\d+"},
        str(tmp_path))
    assert not ok


def test_run_check_argv_executes_without_shell(tmp_path):
    marker = tmp_path / "marker.txt"
    ok, _, output = ac.run_check(
        {"type": "run", "argv": [sys.executable, "-c", "print('ARGV_OK')"]},
        str(tmp_path),
    )
    assert ok and "ARGV_OK" in output
    assert not marker.exists()


def test_run_check_legacy_cmd_does_not_interpret_shell_metacharacters(tmp_path):
    marker = tmp_path / "marker.txt"
    cmd = sys.executable + ' -c "print(123)" > ' + marker.name
    ok, _, output = ac.run_check({"type": "run", "cmd": cmd}, str(tmp_path))
    assert ok
    assert "123" in output
    assert not marker.exists()


def test_run_check_refuses_shell_execution(tmp_path):
    """Shell execution was removed: `>` redirection must not reach a shell."""
    marker = tmp_path / "marker.txt"
    ok, detail, _ = ac.run_check(
        {"type": "run", "cmd": f"echo shell-ok > {marker.name}", "shell": True},
        str(tmp_path),
    )
    assert ok is False
    assert "was removed" in detail
    assert not marker.exists(), "redirection must never be interpreted"


def test_run_check_without_shell_treats_metacharacters_as_arguments(tmp_path):
    """The same command is safe without shell: `>` is just an argument."""
    marker = tmp_path / "marker.txt"
    ok, detail, _ = ac.run_check(
        {"type": "run", "argv": [sys.executable, "-c", "print('x')"]},
        str(tmp_path),
    )
    assert ok is True, detail
    assert not marker.exists()


def test_validate_accepts_structured_argv_and_rejects_shell_argv_mix():
    plan = valid_plan(verify=[
        {"type": "run", "argv": [sys.executable, "-c", "print(1)"]}
    ])
    assert ac.validate_plan(plan) == []
    plan["steps"][0]["verify"][0]["shell"] = True
    errs = ac.validate_plan(plan)
    assert any("shell" in err and "was removed" in err for err in errs), errs


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
    rec["status"] = "verified"  # attempt to flip a failed record to history
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


# ------------------------------------------------- v1.1: multi-plan / cap

def test_plan_path_named_and_default(tmp_path):
    assert ac.plan_path(str(tmp_path)).endswith("plan.json")
    p = ac.plan_path(str(tmp_path), "yan-gorev")
    assert "plans" in p and p.endswith("yan-gorev.json")


def test_all_plan_paths(tmp_path):
    base = str(tmp_path)
    make_plan(tmp_path, valid_plan())
    ac.save_plan(base, valid_plan(task="ikinci"), "ikinci")
    names = [n for n, _ in ac.all_plan_paths(base)]
    assert names == [None, "ikinci"]


def test_attempt_cap_blocks_fourth_run(tmp_path):
    base = str(tmp_path)
    make_plan(tmp_path, valid_plan())
    for i in range(3):
        ac.append_evidence(base, {"ts": "t%d" % i, "mode": "run", "plan": "default",
                                  "step": 1, "status": "failed", "results": []})
    plan = ac.load_plan(base)
    ok = ac.audit_steps(base, plan, ids=[1], mode="run")  # 4. deneme: reddedilmeli
    assert not ok
    assert plan["steps"][0]["status"] == "pending"  # never executed


def test_attempt_cap_respects_force(tmp_path):
    base = str(tmp_path)
    make_plan(tmp_path, valid_plan(verify=[
        {"type": "file_exists", "path": "fib.py"}]))
    (tmp_path / "fib.py").write_text("x", encoding="utf-8")
    for i in range(3):
        ac.append_evidence(base, {"ts": "t%d" % i, "mode": "run", "plan": "default",
                                  "step": 1, "status": "failed", "results": []})
    plan = ac.load_plan(base)
    ok = ac.audit_steps(base, plan, ids=[1], mode="run", force=True)
    assert ok and plan["steps"][0]["status"] == "verified"


def test_attempts_are_scoped_per_plan(tmp_path):
    base = str(tmp_path)
    make_plan(tmp_path, valid_plan())
    ac.save_plan(base, valid_plan(task="yan is"), "yan")
    for i in range(3):
        ac.append_evidence(base, {"ts": "t%d" % i, "mode": "run", "plan": "yan",
                                  "step": 1, "status": "failed", "results": []})
    # attempt = 1 for the default plan (records of the "other" plan do not count)
    assert ac.count_failed_attempts(base, 1, plan="default") == 0
    assert ac.count_failed_attempts(base, 1, plan="yan") == 3


def test_evidence_rotation(tmp_path):
    base = str(tmp_path)
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    big = '{"x":"' + "a" * (ac.ROTATE_BYTES + 10) + '"}\n'
    (pg / "evidence.jsonl").write_text(big, encoding="utf-8")
    ac.append_evidence(base, {"ts": "t", "mode": "run", "plan": "default",
                              "step": 1, "status": "verified", "results": []})
    archive = pg / "archive"
    assert list(archive.glob("evidence-*.jsonl"))
    ok, n, problem = ac.verify_chain(base)
    assert ok and n == 1  # a fresh chain starts at GENESIS


def test_snapshot_and_rollback_roundtrip(tmp_path):
    base = str(tmp_path)
    (tmp_path / "kod.txt").write_text("v1", encoding="utf-8")
    plan = valid_plan()
    plan["snapshot"] = ["kod.txt"]
    ac.make_snapshot(base, plan)
    (tmp_path / "kod.txt").write_text("bozuldu", encoding="utf-8")
    zpath = ac.latest_snapshot(base)
    assert zpath
    ac.restore_snapshot(base, zpath)
    assert (tmp_path / "kod.txt").read_text(encoding="utf-8") == "v1"
    ok, n, problem = ac.verify_chain(base)
    assert ok and n == 2  # snapshot + rollback records stay in one chain


# ----------------------------------------------- audit observational purity
def test_full_audit_rejects_verifier_workspace_mutation(tmp_path):
    base = str(tmp_path)
    plan = valid_plan(verify=[{
        "type": "run",
        "argv": [sys.executable, "-c", "from pathlib import Path; Path('created-by-verifier.txt').write_text('bad')"],
        "expect_exit": 0,
    }])
    ok = ac.audit_steps(base, plan, mode="audit")
    assert ok is False
    assert plan["steps"][0]["status"] == "failed"
    evidence = [
        json.loads(line)
        for line in (tmp_path / ".plan-auditor" / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    step_record = next(
        rec for rec in evidence if rec.get("mode") == "audit" and rec.get("step") == 1
    )
    assert any(
        result.get("check", {}).get("type") == "audit_purity"
        and result.get("passed") is False
        for result in step_record["results"]
    )



# ------------------------------------------- core audit enforces the HMAC gate
#
# H-1 pin: `plan-auditor audit .` is documented as a standalone entry point
# (README quick start, docs/cli.md). For three releases it printed
# "RESULT: audit PASSED" and exited 0 in a keyless workspace, while the
# supervisor CLI refused. The two entry points must hold one rule: completion
# claims require HMAC-authenticated evidence, not merely a valid hash chain.

def _seal(tmp_path, plan):
    from supervisor.config import load_config
    from supervisor.contracts import environment_contract
    from supervisor.sealing import save_seal, seal_plan
    cfg = load_config(str(tmp_path))
    env = environment_contract(tmp_path, cfg)
    seal = seal_plan(plan, "test", "2026-10-13T00:00:00+00:00", environment=env)
    save_seal(seal, str(tmp_path / ".plan-auditor" / "seal.json"))


def test_cmd_audit_refuses_pass_without_authenticated_evidence(tmp_path, capsys, monkeypatch):
    plan = valid_plan()
    make_plan(tmp_path, plan)
    _seal(tmp_path, plan)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    import argparse
    code = ac.cmd_audit(argparse.Namespace(dir=str(tmp_path), plan=None))
    out = capsys.readouterr().out
    assert code == 2
    assert "not authenticated" in out
    assert "integrity init" in out


def test_cmd_audit_passes_with_authenticated_evidence(tmp_path, capsys, monkeypatch):
    plan = valid_plan()
    make_plan(tmp_path, plan)
    _seal(tmp_path, plan)
    key_file = tmp_path.parent / "audit-check-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    from supervisor.integrity import initialize_integrity
    initialize_integrity(tmp_path)
    import argparse
    code = ac.cmd_audit(argparse.Namespace(dir=str(tmp_path), plan=None))
    out = capsys.readouterr().out
    assert code == 0
    assert "RESULT: audit PASSED" in out

def test_evidence_head_update_is_incremental(tmp_path, monkeypatch):
    """H-4 pin: writing evidence must not re-scan the whole log per record.

    The head checkpoint makes the append path O(1); a regression to full scans
    would show up here as a full count on (almost) every append.
    """
    plan = valid_plan()
    make_plan(tmp_path, plan)
    _seal(tmp_path, plan)
    key_file = tmp_path.parent / "head-inc-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    from supervisor.integrity import initialize_integrity
    initialize_integrity(tmp_path)

    counts = {"n": 0}
    original = ac._record_count

    def counting(path):
        counts["n"] += 1
        return original(path)

    monkeypatch.setattr(ac, "_record_count", counting)
    for index in range(25):
        ac._write_evidence_record(
            ac.evidence_path(str(tmp_path)),
            {
                "ts": f"2026-10-13T00:00:{index:02d}+00:00",
                "mode": "run",
                "plan": "default",
                "step": index + 1,
                "results": [],
                "status": "verified",
            },
        )
    # Only the first append may fall back to a full scan (no checkpoint yet).
    assert counts["n"] <= 1, f"evidence appends performed {counts['n']} full scans"
    ok, count, problem = ac.verify_chain(str(tmp_path))
    assert ok and count == 25 and not problem