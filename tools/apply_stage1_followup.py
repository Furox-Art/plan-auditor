from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if text.count(old) != 1:
        raise RuntimeError(f"{rel}: expected one replacement for {old[:100]!r}, got {text.count(old)}")
    write(rel, text.replace(old, new, 1))


# Authenticated integrity is independently useful for evidence/registry-only
# workspaces. Request state is authenticated when present, but final supervisor
# PASS still requires an activated request contract.
replace_once(
    "supervisor/integrity.py",
    "    from .request_contract import initialize_request_auth\n",
    "    from .request_contract import activation_path, initialize_request_auth, request_path\n",
)
replace_once(
    "supervisor/integrity.py",
    "    initialize_request_auth(root, key)\n    initialize_evidence_auth(root, key)\n",
    "    if request_path(root).is_file() or activation_path(root).exists():\n        initialize_request_auth(root, key)\n    initialize_evidence_auth(root, key)\n",
)
replace_once(
    "supervisor/integrity.py",
    "    authenticated = (\n        request.valid\n        and request.authenticated\n        and evidence_ok\n",
    "    request_ok = (not request.activated) or (request.valid and request.authenticated)\n    authenticated = (\n        request_ok\n        and evidence_ok\n",
)

# Do not short-circuit the integrated diagnostic report merely because the
# request contract is missing/invalid. It remains a blocking condition, but
# registry/seal/policy details are still calculated and returned.
text = read("supervisor/orchestrator.py")
text = text.replace(
    "    analyze_request_alignment, auditor_state_present, verify_request_contract,\n",
    "    RequestAlignment, analyze_request_alignment, auditor_state_present, verify_request_contract,\n",
    1,
)
start = text.find("    request_status = verify_request_contract(root)\n")
end = text.find("    workspace_state = capture_workspace(str(root))\n", start)
if start < 0 or end < 0:
    raise RuntimeError("orchestrator request preflight block not found")
new_block = '''    request_status = verify_request_contract(root)\n    refs = all_plan_refs(root)\n    if not refs:\n        if request_status.activated or auditor_state_present(root):\n            return {\n                "outcome": "FAIL",\n                "workspace": str(root),\n                "profile": cfg.profile.value,\n                "mode": cfg.mode,\n                "active_layers": cfg.active_layers(),\n                "configuration_errors": cfg.errors,\n                "policy_errors": [],\n                "active_plan_count": 0,\n                "plans": {},\n                "request_contract": request_status.as_dict(),\n                "error": "auditor state/request activation exists but all active plans are missing",\n            }\n        return {\n            "outcome": "NO_PLAN",\n            "workspace": str(root),\n            "profile": cfg.profile.value,\n            "mode": cfg.mode,\n            "active_layers": cfg.active_layers(),\n            "configuration_errors": cfg.errors,\n            "policy_errors": [],\n            "active_plan_count": 0,\n            "plans": {},\n            "request_contract": request_status.as_dict(),\n        }\n\n    request_plans: Dict[str, Dict[str, Any]] = {}\n    request_errors: List[str] = []\n    if request_status.valid and isinstance(request_status.request, dict):\n        for ref in refs:\n            try:\n                request_plans[ref.key] = load_plan_ref(ref)\n            except (OSError, json.JSONDecodeError, ValueError) as exc:\n                request_errors.append(f"{ref.key}: {exc}")\n        request_alignment = analyze_request_alignment(request_plans, request_status.request)\n        request_errors.extend(request_alignment.errors)\n    else:\n        request_errors.append(request_status.reason or "request contract invalid")\n        request_alignment = RequestAlignment(False, list(request_errors), {})\n\n'''
text = text[:start] + new_block + text[end:]
old_policy = "    policy_errors: List[str] = []\n    policy_rules = []\n"
new_policy = "    policy_errors: List[str] = [f\"request contract: {item}\" for item in request_errors]\n    policy_rules = []\n"
if old_policy not in text:
    raise RuntimeError("orchestrator policy block not found")
text = text.replace(old_policy, new_policy, 1)
write("supervisor/orchestrator.py", text)

# Test-only host helper: old regression fixtures now explicitly establish the
# independent request boundary instead of silently deriving it in production.
write("tests/request_fixture.py", '''from __future__ import annotations\n\nimport json\nfrom pathlib import Path\n\nfrom supervisor.request_contract import activation_path, initialize_request, request_path\n\n\ndef activate_for_plan(root: Path, plan: dict) -> None:\n    if request_path(root).exists() or activation_path(root).exists():\n        return\n    requirements = []\n    for req in plan.get("requirements", []) if isinstance(plan, dict) else []:\n        if not isinstance(req, dict):\n            continue\n        rid = req.get("id")\n        checks = []\n        for step in plan.get("steps", []):\n            if isinstance(step, dict) and rid in (step.get("covers") or []):\n                checks.extend(check for check in step.get("verify", []) if isinstance(check, dict))\n        item = dict(req)\n        if str(item.get("priority", "must")).lower() in {"must", "should"}:\n            item["acceptance_checks"] = checks\n        requirements.append(item)\n    if not requirements:\n        first = next((step for step in plan.get("steps", []) if isinstance(step, dict)), None)\n        if first is None:\n            raise ValueError("cannot activate request fixture without a plan step")\n        checks = [check for check in first.get("verify", []) if isinstance(check, dict)]\n        requirements = [{\n            "id": "REQ-FIXTURE",\n            "description": "exercise fixture behavior",\n            "priority": "must",\n            "acceptance_checks": checks,\n        }]\n        plan.setdefault("requirements", []).append({\n            "id": "REQ-FIXTURE", "description": "exercise fixture behavior", "priority": "must"\n        })\n        first.setdefault("covers", []).append("REQ-FIXTURE")\n        pg = root / ".plan-auditor"\n        if (pg / "plan.json").is_file():\n            (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")\n    initialize_request(root, {\n        "format_version": 1,\n        "task": str(plan.get("task", "fixture request")),\n        "requirements": requirements,\n    })\n''')

# CLI test helper activates the independent request after writing the plan.
replace_once(
    "tests/test_cli.py",
    "from supervisor.cli import main\n",
    "from supervisor.cli import main\nfrom tests.request_fixture import activate_for_plan\n",
)
replace_once(
    "tests/test_cli.py",
    "    (pg / \"plan.json\").write_text(json.dumps(plan), encoding=\"utf-8\")\n",
    "    (pg / \"plan.json\").write_text(json.dumps(plan), encoding=\"utf-8\")\n    activate_for_plan(tmp_path, plan)\n",
)
replace_once(
    "tests/test_cli.py",
    "    assert main([\"plan\", \"verify\", str(tmp_path)]) == 1\n",
    "    assert main([\"plan\", \"verify\", str(tmp_path)]) == 2\n",
)

# Hook fixtures also activate a host contract.
replace_once(
    "tests/test_hooks.py",
    "from supervisor.cli import main as cli_main\n",
    "from supervisor.cli import main as cli_main\nfrom tests.request_fixture import activate_for_plan\n",
)
replace_once(
    "tests/test_hooks.py",
    "    path.write_text(json.dumps(plan), encoding=\"utf-8\")\n",
    "    path.write_text(json.dumps(plan), encoding=\"utf-8\")\n    activate_for_plan(root, plan)\n",
)

# Full-contract fixtures activate once; multi-plan tests keep one immutable
# authoritative request while still exercising aggregate plan gating.
replace_once(
    "tests/test_full_contract_hardening.py",
    "from supervisor.sealing import SealIntegrityError, check_environment, check_monotonic, load_seal, seal_plan\n",
    "from supervisor.sealing import SealIntegrityError, check_environment, check_monotonic, load_seal, seal_plan\nfrom tests.request_fixture import activate_for_plan\n",
)
replace_once(
    "tests/test_full_contract_hardening.py",
    "    path.write_text(json.dumps(plan, indent=2), encoding=\"utf-8\")\n    return path\n",
    "    path.write_text(json.dumps(plan, indent=2), encoding=\"utf-8\")\n    activate_for_plan(root, plan)\n    return path\n",
)

# Integration fixtures activate request before integrated gate assertions.
replace_once(
    "tests/test_integration_hardening.py",
    "from supervisor.workspace import capture_workspace\n",
    "from supervisor.workspace import capture_workspace\nfrom tests.request_fixture import activate_for_plan\n",
)
replace_once(
    "tests/test_integration_hardening.py",
    "    (pg / \"plan.json\").write_text(json.dumps(value), encoding=\"utf-8\")\n    return value\n",
    "    (pg / \"plan.json\").write_text(json.dumps(value), encoding=\"utf-8\")\n    activate_for_plan(root, value)\n    return value\n",
)

# Registry-gate test uses a fully specified request-aware plan.
replace_once(
    "tests/test_agent_registry_chain.py",
    "from supervisor.sealing import save_seal, seal_plan\n",
    "from supervisor.sealing import save_seal, seal_plan\nfrom tests.request_fixture import activate_for_plan\n",
)
replace_once(
    "tests/test_agent_registry_chain.py",
    "        \"created\": \"2026-09-05T00:00:00+00:00\",\n        \"steps\": [\n",
    "        \"created\": \"2026-09-05T00:00:00+00:00\",\n        \"requirements\": [{\"id\": \"REQ-1\", \"description\": \"real behavior\", \"priority\": \"must\"}],\n        \"steps\": [\n",
)
replace_once(
    "tests/test_agent_registry_chain.py",
    "                \"title\": \"real behavior\",\n                \"status\": \"pending\",\n",
    "                \"title\": \"real behavior\",\n                \"covers\": [\"REQ-1\"],\n                \"status\": \"pending\",\n",
)
replace_once(
    "tests/test_agent_registry_chain.py",
    "    (pg / \"plan.json\").write_text(json.dumps(plan), encoding=\"utf-8\")\n    seal = seal_plan(plan, \"registry-test\", \"2026-09-05T00:00:00+00:00\")\n",
    "    (pg / \"plan.json\").write_text(json.dumps(plan), encoding=\"utf-8\")\n    activate_for_plan(tmp_path, plan)\n    seal = seal_plan(plan, \"registry-test\", \"2026-09-05T00:00:00+00:00\")\n",
)

# Dependency tests now assert the hardened explicit-DAG rule.
replace_once(
    "tests/test_dependency_graph.py",
    "def test_legacy_plan_gets_sequential_dependencies():\n    plan = _plan([_step(10), _step(20), _step(30)])\n    assert effective_dependencies(plan) == {10: [], 20: [10], 30: [20]}\n    assert topological_order(plan) == [10, 20, 30]\n",
    "def test_multistep_legacy_dependencies_are_rejected():\n    plan = _plan([_step(10), _step(20), _step(30)])\n    with pytest.raises(PlanGraphError, match=\"explicitly declare depends_on\"):\n        effective_dependencies(plan)\n",
)
replace_once(
    "tests/test_dependency_graph.py",
    "def test_run_blocks_step_when_prerequisite_is_not_verified(tmp_path):\n    plan = _plan([_step(1), _step(2)])\n    assert core.audit_steps(str(tmp_path), plan, ids=[2], mode=\"run\") is False\n    assert plan[\"steps\"][1][\"status\"] == \"blocked\"\n",
    "def test_run_blocks_step_when_prerequisite_is_not_verified(tmp_path):\n    plan = _plan([\n        _step(1, depends_on=[], outputs=[{\"name\": \"artifact\", \"verify\": [{\"type\": \"file_exists\", \"path\": \"artifact.txt\"}]}]),\n        _step(2, depends_on=[1], requires_outputs=[{\"step\": 1, \"name\": \"artifact\"}]),\n    ])\n    assert core.audit_steps(str(tmp_path), plan, ids=[2], mode=\"run\") is False\n    assert plan[\"steps\"][1][\"status\"] == \"blocked\"\n",
)

# Mixed plan-verifier test uses a valid explicit dependency/output contract so
# it isolates weak-check classification rather than graph rejection.
replace_once(
    "tests/test_extra_layers.py",
    "    plan = {\"steps\": [\n        {\"id\": 1, \"verify\": [{\"type\": \"run\", \"cmd\": \"echo\"}]},\n        {\"id\": 2, \"verify\": [{\"type\": \"file_exists\", \"path\": \"x\"}]},\n    ]}\n",
    "    plan = {\"steps\": [\n        {\"id\": 1, \"depends_on\": [], \"verify\": [{\"type\": \"run\", \"cmd\": \"echo\"}],\n         \"outputs\": [{\"name\": \"x\", \"verify\": [{\"type\": \"file_exists\", \"path\": \"x\"}]}]},\n        {\"id\": 2, \"depends_on\": [1], \"requires_outputs\": [{\"step\": 1, \"name\": \"x\"}],\n         \"verify\": [{\"type\": \"file_exists\", \"path\": \"x\"}]},\n    ]}\n",
)

print("stage1 follow-up applied")
