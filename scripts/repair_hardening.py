"""One-shot maintenance script used by the hardening branch.

This file is removed before merge. It patches the large deterministic core
without weakening the normal repository review/CI path.
"""
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"repair insertion point missing: {label}")
    return text.replace(old, new, 1)


def patch_core() -> None:
    path = Path("scripts/audit_check.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '        ok_all, results = _run_check_list(step.get("verify", []), base)\n        output_results = []\n',
        '        audit_workspace_before = workspace_fingerprint(base) if mode == "audit" else None\n'
        '        ok_all, results = _run_check_list(step.get("verify", []), base)\n'
        '        output_results = []\n',
        "audit purity pre-fingerprint",
    )
    text = replace_once(
        text,
        '        for output in declared.values():\n'
        '            output_result = _run_output_contract(output, base)\n'
        '            output_results.append(output_result)\n'
        '            ok_all = ok_all and output_result["passed"]\n\n'
        '        step["status"] = "verified" if ok_all else "failed"\n',
        '        for output in declared.values():\n'
        '            output_result = _run_output_contract(output, base)\n'
        '            output_results.append(output_result)\n'
        '            ok_all = ok_all and output_result["passed"]\n\n'
        '        if mode == "audit":\n'
        '            audit_workspace_after = workspace_fingerprint(base)\n'
        '            if audit_workspace_after != audit_workspace_before:\n'
        '                ok_all = False\n'
        '                results.append({\n'
        '                    "check": {"type": "audit_purity"},\n'
        '                    "passed": False,\n'
        '                    "detail": (\n'
        '                        "audit verification mutated workspace content/type/mode; "\n'
        '                        "verification must be observational and implementation must happen before audit"\n'
        '                    ),\n'
        '                    "output_tail": "",\n'
        '                })\n\n'
        '        step["status"] = "verified" if ok_all else "failed"\n',
        "audit purity post-fingerprint",
    )
    path.write_text(text, encoding="utf-8")


def patch_wheel_smoke() -> None:
    path = Path("tests/wheel_cli_smoke.py")
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '"from pathlib import Path; Path(\'wheel-upstream.txt\').write_text(\'upstream-ok\', encoding=\'utf-8\')"',
        '"from pathlib import Path; assert Path(\'wheel-upstream.txt\').read_text(encoding=\'utf-8\') == \'upstream-ok\'"',
    )
    text = text.replace(
        '"from pathlib import Path; assert Path(\'wheel-upstream.txt\').read_text(encoding=\'utf-8\') == \'upstream-ok\'; Path(\'wheel-final.txt\').write_text(\'final-ok\', encoding=\'utf-8\')"',
        '"from pathlib import Path; assert Path(\'wheel-upstream.txt\').read_text(encoding=\'utf-8\') == \'upstream-ok\'; assert Path(\'wheel-final.txt\').read_text(encoding=\'utf-8\') == \'final-ok\'"',
    )
    text = text.replace(
        '"from pathlib import Path; Path(\'wheel-named.txt\').write_text(\'named-ok\', encoding=\'utf-8\')"',
        '"from pathlib import Path; assert Path(\'wheel-named.txt\').read_text(encoding=\'utf-8\') == \'named-ok\'"',
    )
    marker = (
        '    (pg / "plan.json").write_text(json.dumps(default_plan, indent=2), encoding="utf-8")\n'
        '    (pg / "plans" / "named.json").write_text(json.dumps(named_plan, indent=2), encoding="utf-8")\n\n'
    )
    addition = marker + (
        '    # Product state exists before verification. Audit commands are evidence, not implementation.\n'
        '    (workspace / "wheel-upstream.txt").write_text("upstream-ok", encoding="utf-8")\n'
        '    (workspace / "wheel-final.txt").write_text("final-ok", encoding="utf-8")\n'
        '    (workspace / "wheel-named.txt").write_text("named-ok", encoding="utf-8")\n\n'
    )
    text = replace_once(text, marker, addition, "wheel smoke product state")
    path.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    path = Path("tests/test_audit_check.py")
    text = path.read_text(encoding="utf-8")
    if "test_full_audit_rejects_verifier_workspace_mutation" not in text:
        text = text.rstrip() + r'''


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
'''
        path.write_text(text + "\n", encoding="utf-8")


def patch_full_contract_tests() -> None:
    path = Path("tests/test_full_contract_hardening.py")
    text = path.read_text(encoding="utf-8")
    old = '''                    "-c",\n                    f"from pathlib import Path; Path({marker!r}).write_text('ok', encoding='utf-8')",\n'''
    new = '''                    "-c",\n                    "print('verified')",\n'''
    text = replace_once(text, old, new, "full-contract observational fixture")
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    patch_core()
    patch_wheel_smoke()
    patch_tests()
    patch_full_contract_tests()
    print("final hardening repair applied")
