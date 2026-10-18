"""Formalizer source-bound compilation and real workspace write refusals."""

from __future__ import annotations

import copy
import json

import pytest

from supervisor import formal_compiler as c


def base():
    return {
        "task": "direct evidence plan",
        "requirements": [{"id": "REQ-1", "description": "verified artifact", "priority": "must"}],
        "steps": [
            {
                "id": 1,
                "title": "produce artifact",
                "covers": ["REQ-1"],
                "depends_on": [],
                "requires_outputs": [],
                "outputs": [{"name": "evidence.json"}],
                "verify": [{"type": "file_exists", "path": "evidence.json"}],
            }
        ],
    }


def save(root, plan):
    pg = root / ".plan-auditor"
    pg.mkdir(parents=True, exist_ok=True)
    path = pg / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_compilation_report_serializes_explicit_failure_without_claiming_pass():
    failed = c.CompilationResult(False, errors=["not authenticated"], plan_name="default")
    assert failed.as_dict()["valid"] is False
    assert failed.as_dict()["errors"] == ["not authenticated"]


def test_missing_workspace_plan_cannot_generate_an_approved_contract(tmp_path):
    r = c.compile_workspace(tmp_path, write=False)
    assert len(r) == 1
    assert not r[0].valid
    assert "no matching active plan found" in r[0].errors


def test_named_plan_filter_returns_an_error_for_absent_plan(tmp_path):
    save(tmp_path, base())
    result = c.compile_workspace(tmp_path, plan_name="not-an-active-plan", write=False)
    assert len(result) == 1
    assert not result[0].valid


def test_real_workspace_compilation_dry_run_makes_no_unapproved_file_changes(tmp_path):
    path = save(tmp_path, base())
    original = path.read_bytes()
    reports = c.compile_workspace(tmp_path, write=False)
    assert len(reports) == 1
    assert reports[0].valid
    assert reports[0].changed
    assert reports[0].contract_sha256
    assert path.read_bytes() == original


def test_real_workspace_compilation_writes_a_source_bound_plan_before_sealing(tmp_path):
    path = save(tmp_path, base())
    reports = c.compile_workspace(tmp_path, write=True)
    assert reports[0].valid and reports[0].changed
    new = json.loads(path.read_text())
    assert c.validate_generated_contract(new, new["steps"][0]["verify"][0]["formal_planning"]) == []
    assert c.verify_workspace(tmp_path)[0] is True


def test_compilation_is_idempotent_after_prior_written_formalization(tmp_path):
    save(tmp_path, base())
    assert c.compile_workspace(tmp_path, write=True)[0].changed
    again = c.compile_workspace(tmp_path, write=True)
    assert again[0].valid and not again[0].changed


def test_existing_seal_blocks_formal_compiler_overwriting_active_plan(tmp_path):
    save(tmp_path, base())
    seals = tmp_path / ".plan-auditor" / "seal.json"
    seals.write_text('{"sealed":"yes"}')
    before = (tmp_path / ".plan-auditor" / "plan.json").read_bytes()
    result = c.compile_workspace(tmp_path, write=True)[0]
    assert not result.valid
    assert "refusing to mutate a sealed plan" in result.errors[0]
    assert (tmp_path / ".plan-auditor" / "plan.json").read_bytes() == before


def test_compiler_source_failure_is_returned_as_an_invalid_result_not_a_traceback(tmp_path):
    source = base()
    source["requirements"] = []
    save(tmp_path, source)
    report = c.compile_workspace(tmp_path, write=False)
    assert not report[0].valid
    assert "non-empty plan.requirements" in report[0].errors[0]


def test_workspace_formal_verify_requires_real_generated_contract(tmp_path):
    save(tmp_path, base())
    ok, result = c.verify_workspace(tmp_path)
    assert not ok
    assert "no generated formal planning contract" in result["error"]


def test_workspace_formal_verify_explicit_digest_requires_64_lowercase_hex(tmp_path):
    ok, result = c.verify_workspace(tmp_path, digest="not-sha")
    assert not ok
    assert "lowercase SHA-256" in result["error"]


def test_workspace_formal_verify_cannot_accept_unrelated_source_digest(tmp_path):
    save(tmp_path, base())
    c.compile_workspace(tmp_path, write=True)
    ok, result = c.verify_workspace(tmp_path, digest="0" * 64)
    assert not ok
    assert "matching" in result["error"]


def test_workspace_formal_verify_rejects_changed_source_without_reapproval(tmp_path):
    path = save(tmp_path, base())
    c.compile_workspace(tmp_path, write=True)
    source = json.loads(path.read_text())
    source["steps"][0]["outputs"][0]["name"] = "changed-evidence"
    path.write_text(json.dumps(source))
    ok, result = c.verify_workspace(tmp_path)
    assert not ok
    assert result["outcome"] == "FAIL"
    assert result["formalizations"][0]["errors"]


def test_generated_model_rejects_invalid_and_multiple_source_markers():
    source = base()
    generated = c.compile_contract(source)
    assert c.validate_generated_contract(source, []) == [
        "generated formal contract must be an object"
    ]
    changed = copy.deepcopy(generated)
    changed["initial_facts"] = "not-a-list"
    assert "initial_facts must be a list" in c.validate_generated_contract(source, changed)[0]
    changed = copy.deepcopy(generated)
    changed["initial_facts"].append("formalization-source:other")
    assert "exactly one" in c.validate_generated_contract(source, changed)[0]


def test_manual_formal_contract_remains_outside_generated_compiler_authority():
    source = base()
    assert c.validate_generated_contract(source, {"initial_facts": []}) == []


def test_recompilation_failure_never_confirms_cached_model():
    source = base()
    generated = c.compile_contract(source)
    source["requirements"] = []
    errors = c.validate_generated_contract(source, generated)
    assert any("cannot deterministically recompile" in item for item in errors)


def test_explicit_missing_anchor_cannot_be_silently_rebound():
    with pytest.raises(ValueError, match="does not exist"):
        c.compile_plan(base(), anchor_step=99)


def test_compiler_rejects_unstructured_malformed_plan_step():
    source = base()
    source["steps"] = [None]
    with pytest.raises(ValueError):
        c.compile_plan(source)


def test_output_names_are_normalized_only_for_valid_explicit_named_outputs():
    source = base()
    source["steps"][0]["outputs"] = [None]
    with pytest.raises(ValueError, match="non-empty name"):
        c.compile_contract(source)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"covers": None}, "not covered by any formalized step"),
        ({"covers": [None]}, "invalid requirement id"),
        ({"id": True}, "positive integer id"),
        ({"outputs": [{"name": 3}]}, "non-empty name"),
    ],
)
def test_invalid_structured_steps_cannot_generate_verified_goals(update, message):
    source = base()
    source["steps"][0].update(update)
    with pytest.raises(ValueError, match=message):
        c.compile_contract(source)


def test_repeated_step_ids_refused_before_formal_contract_generation():
    source = base()
    source["steps"].append(copy.deepcopy(source["steps"][0]))
    with pytest.raises(ValueError, match="duplicate step id"):
        c.compile_contract(source)


def test_compiler_never_writes_through_a_symlinked_output_path(tmp_path):
    outside = tmp_path / "target.json"
    outside.write_text("unchanged")
    link = tmp_path / "plan.json"
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        c._write_json_atomic(link, base())
    assert outside.read_text() == "unchanged"


def test_compiler_never_writes_through_symlinked_temporary_plan_path(tmp_path):
    outside = tmp_path / "target.json"
    outside.write_text("unchanged")
    path = tmp_path / "plan.json"
    (tmp_path / "plan.json.formalize.tmp").symlink_to(outside)
    with pytest.raises(ValueError, match="symlinked temporary"):
        c._write_json_atomic(path, base())
    assert outside.read_text() == "unchanged"


def test_compiler_atomic_writer_produces_exact_json_and_no_temp_artifact(tmp_path):
    path = tmp_path / "out" / "plan.json"
    c._write_json_atomic(path, base())
    assert json.loads(path.read_text()) == base()
    assert not (path.parent / "plan.json.formalize.tmp").exists()


def test_compiler_cli_real_parser_reports_failure_without_any_active_plan(tmp_path, capsys):
    assert c.main(["compile", str(tmp_path), "--dry-run"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "FAIL"
    assert result["written"] is False


def test_compiler_cli_actual_dryrun_then_write_then_verify(tmp_path, capsys):
    path = save(tmp_path, base())
    assert c.main(["compile", str(tmp_path), "--dry-run"]) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["outcome"] == "PASS"
    assert dry["written"] is False
    assert c.main(["compile", str(tmp_path)]) == 0
    updated = json.loads(capsys.readouterr().out)
    assert updated["written"] is True
    assert json.loads(path.read_text())["steps"][0]["verify"][0]["formal_planning"]
    assert c.main(["verify", str(tmp_path)]) == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["outcome"] == "PASS"


def test_compiler_cli_rejects_invalid_digest_with_return_code_two(tmp_path, capsys):
    assert c.main(["verify", str(tmp_path), "--contract-sha", "INVALID"]) == 2
    assert json.loads(capsys.readouterr().out)["outcome"] == "FAIL"


def test_oversized_requirement_id_is_not_accepted_as_bounded_source_goal():
    source = base()
    large = "REQ-" + "x" * 245
    source["requirements"][0]["id"] = large
    source["steps"][0]["covers"] = [large]
    with pytest.raises(ValueError, match="too long"):
        c.compile_contract(source)


def test_oversized_output_name_retains_bounded_source_mapping_without_guessing_data():
    source = base()
    source["steps"][0]["outputs"] = [{"name": "observed-" + "x" * 900}]
    contract = c.compile_contract(source)
    fact = c.output_fact(1, "observed-" + "x" * 900)
    assert fact in contract["goal_facts"]
    assert len(fact) <= c.MAX_FACT_LEN


def test_unstructured_step_is_recorded_in_source_projection_not_laundered_away():
    source = base()
    source["steps"].append("not a real step")
    projection = c._source_projection(source)
    assert projection["steps"][1] == {"invalid_step": "not a real step"}


def test_missing_outputs_are_a_valid_empty_set_but_never_fabricated(tmp_path):
    source = base()
    source["steps"][0]["outputs"] = None
    assert c._step_output_names(source["steps"][0]) == ([], [])


def test_generated_contract_classifier_rejects_nonobject_or_nonarray_initial_state():
    assert not c.is_generated_contract([])
    assert not c.is_generated_contract({"initial_facts": "marker"})


def test_real_manual_user_anchor_is_not_a_generated_anchor():
    source = base()
    assert (
        c.validate_generated_contract(source, {"initial_facts": ["manually verified fact"]}) == []
    )


def test_manual_formal_anchors_cannot_be_overwritten_even_when_no_old_source_digest():
    source = base()
    source["steps"][0]["verify"].insert(
        0,
        {
            "formal_planning": {
                "version": 1,
                "initial_facts": ["reviewed"],
                "goal_facts": ["reviewed"],
                "actions": [],
            }
        },
    )
    with pytest.raises(ValueError, match="manual formal_planning"):
        c.compile_plan(source)


def test_formal_compiler_rejects_duplicate_steps_even_when_legacy_graph_mode_is_in_effect():
    source = base()
    source["steps"].append(copy.deepcopy(source["steps"][0]))
    with pytest.raises(ValueError, match="duplicate step id"):
        c.compile_contract(source)


def test_data_dependency_without_explicit_required_output_is_not_an_action_precondition():
    source = base()
    source["steps"].append(
        {
            "id": 2,
            "depends_on": [1],
            "covers": [],
            "outputs": [],
            "verify": [{"type": "file_exists", "path": "result.json"}],
        }
    )
    with pytest.raises(ValueError, match="has no requires_outputs link"):
        c.compile_contract(source)


def test_duplicate_generated_anchor_is_rejected_before_adding_any_new_approval():
    source = base()
    first, contract, _ = c.compile_plan(source)
    first["steps"][0]["verify"].append({"formal_planning": copy.deepcopy(contract)})
    with pytest.raises(ValueError, match="multiple formal_planning anchors"):
        c.compile_plan(first)


def test_none_verification_field_is_treated_as_an_empty_not_executed_check_list():
    source = base()
    source["steps"][0]["verify"] = None
    revised, _, _ = c.compile_plan(source)
    assert len(revised["steps"][0]["verify"]) == 2


def test_nonlist_verification_checks_refused_when_compiling_generated_anchor():
    source = base()
    source["steps"][0]["verify"] = {"type": "file_exists"}
    with pytest.raises(ValueError, match="verify must be a list"):
        c.compile_plan(source)


def test_compiler_refuses_malformed_steps_before_processing_implicit_graph():
    source = base()
    source["steps"] = None
    with pytest.raises(ValueError, match="plan has no steps"):
        c.compile_plan(source)


def test_invalid_plan_index_during_verification_returns_fail_not_generated_proof(
    monkeypatch, tmp_path
):
    from supervisor import formal_compiler as compiler

    def fail(_root):
        raise ValueError("simulated invalid plan index")

    monkeypatch.setattr(compiler, "all_plan_refs", fail)
    valid, result = compiler.verify_workspace(tmp_path)
    assert not valid
    assert "cannot load active plans" in result["error"]


def test_compiler_scans_manual_anchors_without_attributing_a_generated_proof(tmp_path):
    source = base()
    source["steps"][0]["verify"].append(
        {"formal_planning": {"initial_facts": ["manual"], "goal_facts": ["manual"], "actions": []}}
    )
    save(tmp_path, source)
    ok, report = c.verify_workspace(tmp_path)
    assert not ok
    assert "no generated formal planning contract" in report["error"]


def test_formal_cli_without_subcommand_reports_usage_not_false_success():
    with pytest.raises(SystemExit) as error:
        c.main([])
    assert error.value.code == 2


def test_long_output_facts_are_rejected_at_an_explicit_model_limit(monkeypatch):
    monkeypatch.setattr(c, "MAX_FACT_LEN", 40)
    with pytest.raises(ValueError, match="output fact for step"):
        c.output_fact(1, "measured-" + ("x" * 100))


def test_invalid_step_kind_is_rejected_after_verified_dependency_index(monkeypatch):
    monkeypatch.setattr(c, "effective_dependencies", lambda _: {1: []})
    source = base()
    source["steps"][0] = 123
    with pytest.raises(ValueError, match="step 1 must be an object"):
        c.compile_contract(source)


def test_duplicate_step_ids_cannot_be_accepted_if_an_upstream_parser_were_weakened(monkeypatch):
    monkeypatch.setattr(c, "effective_dependencies", lambda _: {1: []})
    source = base()
    source["steps"].append(copy.deepcopy(source["steps"][0]))
    with pytest.raises(ValueError, match="duplicate step id"):
        c.compile_contract(source)


def test_real_required_output_parse_failure_is_not_silently_converted_to_unbound_fact(monkeypatch):
    from scripts.plan_graph import PlanGraphError

    def fail(*args):
        raise PlanGraphError("unresolved measured dataflow binding")

    monkeypatch.setattr(c, "required_outputs", fail)
    with pytest.raises(ValueError, match="unresolved measured dataflow binding"):
        c.compile_contract(base())


def test_compiler_does_not_reconstruct_implicit_edges_when_dependency_graph_is_invalid(monkeypatch):
    from scripts.plan_graph import PlanGraphError

    def fail(*args):
        raise PlanGraphError("invalid verified graph")

    monkeypatch.setattr(c, "effective_dependencies", fail)
    with pytest.raises(ValueError, match="invalid verified graph"):
        c.compile_plan(base())


def test_optional_may_coverage_does_not_fabricate_required_goal():
    source = base()
    source["requirements"].append(
        {"id": "REQ-MAY", "description": "optional future measurement", "priority": "may"}
    )
    source["steps"][0]["covers"].append("REQ-MAY")
    compiled = c.compile_contract(source)
    assert c.requirement_goal_fact("REQ-MAY") not in compiled["goal_facts"]


def test_real_module_entrypoint_exits_nonzero_when_no_subcommand(monkeypatch):
    import runpy
    import sys
    import warnings

    monkeypatch.setattr(sys, "argv", ["plan-auditor-formalize"])
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", message=".*formal_compiler.*found in sys.modules", category=RuntimeWarning
        )
        with pytest.raises(SystemExit) as exit_:
            runpy.run_module("supervisor.formal_compiler", run_name="__main__")
    assert exit_.value.code == 2
