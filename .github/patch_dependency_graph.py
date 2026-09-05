from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def replace_function(text: str, name: str, next_name: str, body: str) -> str:
    start = text.index(f"def {name}(")
    end = text.index(f"\ndef {next_name}(", start)
    return text[:start] + body.rstrip() + "\n\n" + text[end + 1:]


def replace_until(text: str, start_token: str, end_token: str, body: str) -> str:
    start = text.index(start_token)
    end = text.index(end_token, start)
    return text[:start] + body.rstrip() + "\n\n" + text[end:]


# ---------------------------------------------------------------- audit core
path = Path("scripts/audit_check.py")
text = path.read_text(encoding="utf-8")

text = replace_once(
    text,
    '\nPG_DIR = ".plan-auditor"\n',
    '''\ntry:\n    from scripts.plan_graph import (\n        PlanGraphError,\n        effective_dependencies,\n        output_index,\n        required_outputs,\n        topological_order,\n        validate_output_links,\n    )\nexcept ImportError:  # direct ``python scripts/audit_check.py`` execution\n    from plan_graph import (\n        PlanGraphError,\n        effective_dependencies,\n        output_index,\n        required_outputs,\n        topological_order,\n        validate_output_links,\n    )\n\nPG_DIR = ".plan-auditor"\n''',
    "plan graph imports",
)

text = replace_once(
    text,
    '''    contract = {\n        "task": plan.get("task"),\n        "requirements": plan.get("requirements"),\n        "steps": [\n            {\n                "id": step.get("id"),\n                "title": step.get("title"),\n                "verify": step.get("verify", []),\n            }\n            for step in plan.get("steps", [])\n            if isinstance(step, dict)\n        ],\n    }\n''',
    '''    contract = {\n        "contract_version": 2,\n        "task": plan.get("task"),\n        "requirements": plan.get("requirements"),\n        "steps": [\n            {\n                "id": step.get("id"),\n                "title": step.get("title"),\n                "depends_on": step.get("depends_on"),\n                "requires_outputs": step.get("requires_outputs", []),\n                "outputs": step.get("outputs", []),\n                "verify": step.get("verify", []),\n            }\n            for step in plan.get("steps", [])\n            if isinstance(step, dict)\n        ],\n    }\n''',
    "plan fingerprint",
)

validate_body = r'''def validate_plan(data):
    errs = []

    def validate_check(check, sid, label):
        if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
            errs.append("%s: geçersiz kontrol %r" % (label, check))
            return
        kind = check["type"]
        if kind in ("file_exists", "regex") and not check.get("path"):
            errs.append("%s: %s kontrolü 'path' ister" % (label, kind))
        if kind == "regex" and not check.get("pattern"):
            errs.append("%s: regex kontrolü 'pattern' ister" % label)
        if kind in ("run", "exec"):
            cmd = check.get("cmd")
            argv = check.get("argv")
            has_cmd = isinstance(cmd, str) and bool(cmd.strip())
            has_argv = (
                isinstance(argv, list) and bool(argv)
                and all(isinstance(arg, str) and bool(arg) for arg in argv)
            )
            if not (has_cmd or has_argv):
                errs.append(
                    "%s: %s kontrolü boş olmayan 'cmd' string veya 'argv' listesi ister"
                    % (label, kind)
                )
            if "argv" in check and not has_argv:
                errs.append("%s: %s argv boş olmayan string listesi olmalı" % (label, kind))
            if "shell" in check and not isinstance(check.get("shell"), bool):
                errs.append("%s: %s shell boolean olmalı" % (label, kind))
            if check.get("shell") is True and has_argv:
                errs.append("%s: %s shell=true ile argv birlikte kullanılamaz" % (label, kind))

    if not isinstance(data, dict):
        return ["plan kökü bir obje olmalı"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        errs.append("task: boş olmayan string olmalı")
    if not isinstance(data.get("created"), str) or not data["created"].strip():
        errs.append("created: ISO zaman damgası olmalı")
    if "snapshot" in data and not isinstance(data["snapshot"], list):
        errs.append("snapshot: dosya yolu listesi olmalı (opsiyonel)")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("steps: boş olmayan liste olmalı")
        return errs

    seen = set()
    for step in steps:
        if not isinstance(step, dict):
            errs.append("adım obje olmalı: %r" % (step,))
            continue
        sid = step.get("id")
        if not isinstance(sid, int) or sid < 1:
            errs.append("adım id pozitif int olmalı: %r" % (sid,))
        elif sid in seen:
            errs.append("adım id tekrarlı: %s" % sid)
        seen.add(sid)
        if not isinstance(step.get("title"), str) or not step["title"].strip():
            errs.append("adım %s: title boş olamaz" % sid)

        checks = step.get("verify")
        if not isinstance(checks, list) or not checks:
            errs.append("adım %s: verify boş olamaz" % sid)
        else:
            behavioral = [
                check for check in checks
                if isinstance(check, dict) and check.get("type") in ("run", "pytest", "exec")
            ]
            if not behavioral:
                errs.append(
                    "adım %s: en az bir DAVRANIŞSAL kontrol (run/pytest/exec) zorunlu — "
                    "yalnızca file_exists/regex ile adım doğrulanamaz" % sid
                )
            for check in checks:
                validate_check(check, sid, "adım %s" % sid)

        outputs = step.get("outputs", [])
        if outputs is not None and isinstance(outputs, list):
            for output in outputs:
                if not isinstance(output, dict):
                    continue
                name = output.get("name")
                output_checks = output.get("verify", [])
                if isinstance(output_checks, list):
                    for check in output_checks:
                        validate_check(check, sid, "adım %s output %r" % (sid, name))

    try:
        effective_dependencies(data)
        topological_order(data)
    except PlanGraphError as exc:
        errs.append("dependency graph: %s" % exc)
    for problem in validate_output_links(data):
        message = "output graph: %s" % problem
        if message not in errs:
            errs.append(message)
    return errs'''
text = replace_function(text, "validate_plan", "norm_check", validate_body)

text = replace_once(
    text,
    'and rec.get("status") != "verified"\n',
    'and rec.get("status") == "failed"\n',
    "blocked retries",
)

audit_body = r'''def _run_check_list(raw_checks, base):
    results = []
    ok_all = True
    for raw_check in raw_checks:
        check = norm_check(raw_check)
        ok, detail, tail = run_check(check, base)
        ok_all = ok_all and ok
        results.append({
            "check": check,
            "passed": ok,
            "detail": detail,
            "output_tail": tail if not ok else "",
        })
    return ok_all, results


def _run_output_contract(output, base):
    ok, results = _run_check_list(output.get("verify", []), base)
    return {
        "name": output.get("name"),
        "passed": ok,
        "results": results,
    }


def _prerequisite_gate(base, plan, step, passed_this_run, selected, mode):
    deps = effective_dependencies(plan).get(step["id"], [])
    by_id = {item["id"]: item for item in plan["steps"] if isinstance(item, dict)}
    dependency_results = []
    ok = True
    for dep in deps:
        if mode == "audit" or dep in selected:
            dep_ok = passed_this_run.get(dep) is True
            source = "current_pass"
        else:
            dep_ok = by_id[dep].get("status") == "verified"
            source = "persisted_status"
        dependency_results.append({"step": dep, "passed": dep_ok, "source": source})
        ok = ok and dep_ok

    required_results = []
    if ok:
        for ref in required_outputs(step):
            source_step = by_id[ref["step"]]
            contract = output_index(source_step)[ref["name"]]
            output_result = _run_output_contract(contract, base)
            item = {
                "step": ref["step"],
                "name": ref["name"],
                "passed": output_result["passed"],
                "results": output_result["results"],
            }
            required_results.append(item)
            ok = ok and item["passed"]
    return ok, deps, dependency_results, required_results


def audit_steps(base, plan, ids=None, mode="run", name=None, force=False):
    try:
        order = topological_order(plan)
        effective_dependencies(plan)
        output_problems = validate_output_links(plan)
        if output_problems:
            raise PlanGraphError("; ".join(output_problems))
    except PlanGraphError as exc:
        print("[FAIL] dependency graph geçersiz: %s" % exc)
        return False

    by_id = {step["id"]: step for step in plan["steps"] if isinstance(step, dict)}
    if ids is None or mode == "audit":
        selected = set(order)
    else:
        selected = set(ids)
        unknown = sorted(selected - set(by_id))
        if unknown:
            sys.exit("HATA: verilen id'ler planda yok: %s" % unknown)
        if not selected:
            return True
    target = [by_id[sid] for sid in order if sid in selected]
    key = plan_key(name)
    all_ok = True
    passed_this_run = {}

    for step in target:
        sid = step["id"]
        prereq_ok, deps, dependency_results, required_results = _prerequisite_gate(
            base, plan, step, passed_this_run, selected, mode
        )
        if not prereq_ok:
            step["status"] = "blocked"
            passed_this_run[sid] = False
            all_ok = False
            append_evidence(base, {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
                "mode": mode,
                "plan": key,
                "step": sid,
                "dependencies": deps,
                "dependency_results": dependency_results,
                "required_outputs": required_results,
                "outputs": [],
                "results": [],
                "status": "blocked",
                "reason": "prerequisite step or required output is not independently verified",
            })
            print("[BLOK] adım %s: prerequisite/output doğrulaması geçmedi" % sid)
            for dep in dependency_results:
                if not dep["passed"]:
                    print("       - dependency step %s doğrulanmadı" % dep["step"])
            for item in required_results:
                if not item["passed"]:
                    print("       - required output %s:%s doğrulanmadı" % (item["step"], item["name"]))
            continue

        attempt = 1
        if mode == "run":
            attempt = count_failed_attempts(base, sid, plan=key) + 1
            if attempt > MAX_ATTEMPTS and not force:
                print("[ATLADI] adım %s: %s önceki gerçek başarısız deneme — %s sınırı aşıldı." % (
                    sid, step.get("title", ""), MAX_ATTEMPTS,
                ))
                passed_this_run[sid] = False
                all_ok = False
                continue

        ok_all, results = _run_check_list(step.get("verify", []), base)
        output_results = []
        try:
            declared = output_index(step)
        except PlanGraphError as exc:
            declared = {}
            ok_all = False
            results.append({
                "check": {"type": "output_contract"},
                "passed": False,
                "detail": str(exc),
                "output_tail": "",
            })
        for output in declared.values():
            output_result = _run_output_contract(output, base)
            output_results.append(output_result)
            ok_all = ok_all and output_result["passed"]

        step["status"] = "verified" if ok_all else "failed"
        passed_this_run[sid] = ok_all
        all_ok = all_ok and ok_all
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "mode": mode,
            "plan": key,
            "step": sid,
            "dependencies": deps,
            "dependency_results": dependency_results,
            "required_outputs": required_results,
            "outputs": output_results,
            "results": results,
            "status": step["status"],
        }
        if mode == "run":
            rec["attempt"] = attempt
        append_evidence(base, rec)

        mark = "OK " if ok_all else "FAIL"
        label = "adım %s: %s" % (sid, step.get("title", ""))
        if mode == "run":
            label += " (deneme %s/%s)" % (min(attempt, MAX_ATTEMPTS), MAX_ATTEMPTS)
        print("[%s] %s" % (mark, label))
        for result in results:
            print("       - %s | %s" % (
                "geçti" if result["passed"] else "KALDI", result["detail"],
            ))
            if not result["passed"] and result["output_tail"]:
                print("         çıktı: %s" % result["output_tail"][-400:].replace("\n", " | "))
        for output in output_results:
            print("       - output %s | %s" % (
                output["name"], "geçti" if output["passed"] else "KALDI",
            ))

    save_plan(base, plan, name)
    if mode == "audit":
        append_evidence(base, {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "mode": "audit_complete",
            "plan": key,
            "step": 0,
            "results": [],
            "status": "verified" if all_ok else "failed",
            "steps": len(plan.get("steps", [])),
            "topological_order": order,
            "plan_fingerprint": plan_contract_fingerprint(plan),
            "workspace_fingerprint": workspace_fingerprint(base),
        })
    return all_ok'''
text = replace_until(
    text,
    "def audit_steps(",
    "# ---------------------------------------------------------------- commands",
    audit_body,
)
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- orchestrator
path = Path("supervisor/orchestrator.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    'from scripts import audit_check as core\n',
    '''from scripts import audit_check as core\nfrom scripts.plan_graph import (\n    PlanGraphError,\n    effective_dependencies,\n    output_index,\n    required_outputs,\n    topological_order,\n)\n''',
    "orchestrator imports",
)

checks_body = r'''def _result_checks_match(expected, results):
    if len(results) != len(expected):
        return False
    actual = [result.get("check") for result in results if isinstance(result, dict)]
    return actual == expected and len(actual) == len(results) and all(
        result.get("passed") is True for result in results if isinstance(result, dict)
    )


def _checks_match(step: Dict[str, Any], record: Dict[str, Any], dependencies: List[int],
                  by_id: Dict[int, Dict[str, Any]]) -> bool:
    expected = [core.norm_check(check) for check in step.get("verify", []) if isinstance(check, dict)]
    results = record.get("results", [])
    if not _result_checks_match(expected, results):
        return False
    if record.get("dependencies", []) != dependencies:
        return False

    try:
        declared_outputs = output_index(step)
        expected_required = required_outputs(step)
    except PlanGraphError:
        return False

    actual_outputs = record.get("outputs", [])
    if len(actual_outputs) != len(declared_outputs):
        return False
    for (name, contract), actual_output in zip(declared_outputs.items(), actual_outputs):
        if not isinstance(actual_output, dict):
            return False
        if actual_output.get("name") != name or actual_output.get("passed") is not True:
            return False
        output_checks = [
            core.norm_check(check)
            for check in contract.get("verify", [])
            if isinstance(check, dict)
        ]
        if not _result_checks_match(output_checks, actual_output.get("results", [])):
            return False

    actual_required = record.get("required_outputs", [])
    if len(actual_required) != len(expected_required):
        return False
    for expected_ref, actual_ref in zip(expected_required, actual_required):
        if not isinstance(actual_ref, dict):
            return False
        if (
            actual_ref.get("step") != expected_ref["step"]
            or actual_ref.get("name") != expected_ref["name"]
            or actual_ref.get("passed") is not True
        ):
            return False
        try:
            source_contract = output_index(by_id[expected_ref["step"]])[expected_ref["name"]]
        except (KeyError, PlanGraphError):
            return False
        source_checks = [
            core.norm_check(check)
            for check in source_contract.get("verify", [])
            if isinstance(check, dict)
        ]
        if not _result_checks_match(source_checks, actual_ref.get("results", [])):
            return False
    return True'''
text = replace_function(text, "_checks_match", "fresh_full_audit_proof", checks_body)

fresh_body = r'''def fresh_full_audit_proof(root: str | Path, plan: Dict[str, Any]) -> FreshAuditProof:
    """Prove current graph, checks, outputs, and workspace match a full audit."""
    root_path = Path(root).resolve()
    chain_ok, _count, problem = core.verify_chain(str(root_path))
    if not chain_ok:
        return FreshAuditProof(False, f"active evidence chain invalid: {problem}")

    try:
        order = topological_order(plan)
        dependencies = effective_dependencies(plan)
    except PlanGraphError as exc:
        return FreshAuditProof(False, f"dependency graph invalid: {exc}")
    by_id = {
        step.get("id"): step
        for step in plan.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("id"), int)
    }
    if not order or len(by_id) != len(order):
        return FreshAuditProof(False, "plan has no valid dependency-graph steps")
    steps = [by_id[sid] for sid in order]

    records = _read_evidence_records(root_path)
    marker_index: Optional[int] = None
    marker: Optional[Dict[str, Any]] = None
    for index in range(len(records) - 1, -1, -1):
        record = records[index]
        if record.get("mode") == "audit_complete" and record.get("plan", "default") == "default":
            marker_index = index
            marker = record
            break
    if marker is None or marker_index is None:
        return FreshAuditProof(False, "no complete full-audit fingerprint evidence")
    if marker.get("status") != "verified":
        return FreshAuditProof(False, "latest full audit did not pass")
    if marker.get("topological_order") != order:
        return FreshAuditProof(False, "full-audit dependency order does not match current plan")

    current_plan_fp = core.plan_contract_fingerprint(plan)
    if marker.get("plan_fingerprint") != current_plan_fp:
        return FreshAuditProof(False, "plan contract changed after audit")

    current_workspace_fp = core.workspace_fingerprint(str(root_path))
    if marker.get("workspace_fingerprint") != current_workspace_fp:
        return FreshAuditProof(False, "workspace content changed after audit")

    audit_records = [
        record for record in records[:marker_index]
        if record.get("mode") == "audit" and record.get("plan", "default") == "default"
    ]
    if len(audit_records) < len(steps):
        return FreshAuditProof(False, "full-audit marker lacks complete step evidence")
    candidate = audit_records[-len(steps):]
    if [record.get("step") for record in candidate] != order:
        return FreshAuditProof(False, "latest audit evidence does not cover dependency order")
    for step, record in zip(steps, candidate):
        sid = step.get("id")
        if record.get("status") != "verified" or not _checks_match(
            step, record, dependencies.get(sid, []), by_id
        ):
            return FreshAuditProof(
                False,
                f"audit evidence does not match graph/check/output contract for step {sid}",
            )

    return FreshAuditProof(
        True,
        "current dependency graph, output contracts, checks, and workspace match full audit",
        str(marker.get("ts")),
        len(steps),
    )'''
text = replace_function(text, "fresh_full_audit_proof", "_tail_logs", fresh_body)

text = replace_once(
    text,
    '''        "plan": {\n            "verdict": plan_analysis.verdict,\n            "rationale": plan_analysis.rationale,\n            "weakest_verification": plan_analysis.weakest_verification,\n        },\n''',
    '''        "plan": {\n            "verdict": plan_analysis.verdict,\n            "rationale": plan_analysis.rationale,\n            "weakest_verification": plan_analysis.weakest_verification,\n            "graph_errors": plan_analysis.graph_errors,\n            "topological_order": plan_analysis.topological_order,\n            "dependencies": plan_analysis.dependencies,\n        },\n''',
    "orchestrator graph report",
)
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- CLI graph reporting
path = Path("supervisor/cli.py")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    output = {\n        "verdict": analysis.verdict,\n        "rationale": analysis.rationale,\n        "weakest_verification": analysis.weakest_verification,\n        "steps": [{"id": s.step_id, "behavioral": s.has_behavioral_verification, "risks": s.risks}\n                  for s in analysis.step_analyses],\n    }\n''',
    '''    output = {\n        "verdict": analysis.verdict,\n        "rationale": analysis.rationale,\n        "weakest_verification": analysis.weakest_verification,\n        "graph_errors": analysis.graph_errors,\n        "topological_order": analysis.topological_order,\n        "dependencies": analysis.dependencies,\n        "steps": [\n            {\n                "id": s.step_id,\n                "behavioral": s.has_behavioral_verification,\n                "dependencies": s.dependencies,\n                "required_outputs": s.required_outputs,\n                "declared_outputs": s.declared_outputs,\n                "risks": s.risks,\n            }\n            for s in analysis.step_analyses\n        ],\n    }\n''',
    "CLI plan verify graph output",
)
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- changelog
path = Path("CHANGELOG.md")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    "## Unreleased\n\n",
    "## Unreleased\n\n- **Dependency DAG enforcement:** plan steps now have deterministic prerequisite semantics. Legacy plans are sequential by default; explicit `depends_on` graphs reject cycles/self/unknown edges and each explicit edge must bind to a concrete upstream `requires_outputs` contract. Required outputs are rechecked before dependent steps, producer outputs are independently verified, blocked prerequisites do not consume retry budget, and full-audit fingerprints/evidence bind graph order plus output contracts.\n",
    "changelog",
)
path.write_text(text, encoding="utf-8")
