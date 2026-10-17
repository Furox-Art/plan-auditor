"""Classical plan graph checks reject unbound dependency and output claims."""

from __future__ import annotations

import pytest

from scripts import plan_graph as graph


def first_step(*, output=True):
    step = {"id": 1, "depends_on": [], "verify": [{"type": "pytest"}]}
    if output:
        step["outputs"] = [{"name": "measured.csv", "verify": [{"type": "file_sha256"}]}]
    return step


def next_step(*, dependency=True, name="measured.csv"):
    return {
        "id": 2,
        "depends_on": [1] if dependency else [],
        "requires_outputs": [{"step": 1, "name": name}],
        "verify": [{"type": "pytest"}],
    }


@pytest.mark.parametrize(
    ("dep", "pattern"),
    [
        ([0], "positive integer"),
        ([-1], "positive integer"),
        (["1"], "positive integer"),
        ([2, 2], "duplicate dependencies"),
        ([99], "unknown step"),
    ],
)
def test_untrusted_edges_are_refused_before_dependency_execution(dep, pattern):
    plan = {"steps": [first_step(), {"id": 2, "depends_on": dep}]}
    with pytest.raises(graph.PlanGraphError, match=pattern):
        graph.effective_dependencies(plan)


def test_valid_topological_sort_and_closure_respect_real_dependency_links():
    plan = {"steps": [next_step(), first_step()]}
    assert graph.effective_dependencies(plan) == {2: [1], 1: []}
    assert graph.topological_order(plan) == [1, 2]
    assert graph.transitive_dependencies(plan) == {1: set(), 2: {1}}
    assert graph.validate_output_links(plan) == []


@pytest.mark.parametrize(
    ("invalid", "pattern"),
    [
        ("not-array", "outputs must be a list"),
        ([1], "output must be an object"),
        ([{"name": "", "verify": [{"type": "pytest"}]}], "output name must be"),
        ([{"name": "measured.csv", "verify": []}], "requires non-empty verify"),
        (
            [
                {"name": "measured.csv", "verify": [{"type": "pytest"}]},
                {"name": "measured.csv", "verify": [{"type": "pytest"}]},
            ],
            "duplicate output",
        ),
    ],
)
def test_declared_output_refuses_incomplete_or_duplicate_proof(invalid, pattern):
    step = first_step()
    step["outputs"] = invalid
    with pytest.raises(graph.PlanGraphError, match=pattern):
        graph.output_index(step)


def test_explicit_null_outputs_are_not_an_observed_output():
    assert graph.output_index({"id": 1, "outputs": None}) == {}


@pytest.mark.parametrize(
    ("invalid", "pattern"),
    [
        ("not-array", "requires_outputs must be a list"),
        ([1], "required output must be an object"),
        ([{"step": "1", "name": "x"}], "positive step id"),
        ([{"step": 0, "name": "x"}], "positive step id"),
        ([{"step": 1, "name": ""}], "must be non-empty"),
        ([{"step": 1, "name": "x"}, {"step": 1, "name": "x"}], "repeats required output"),
    ],
)
def test_required_output_refuses_unverified_dependency_data(invalid, pattern):
    step = {"id": 2, "requires_outputs": invalid}
    with pytest.raises(graph.PlanGraphError, match=pattern):
        graph.required_outputs(step)


def test_explicit_null_required_outputs_do_not_create_fabricated_links():
    assert graph.required_outputs({"id": 2, "requires_outputs": None}) == []


def test_invalid_source_output_contract_records_failure_without_exception():
    bad = first_step()
    bad["outputs"] = "pretend verified output"
    problems = graph.validate_output_links({"steps": [bad]})
    assert len(problems) == 1
    assert "outputs must be a list" in problems[0]


def test_invalid_required_output_contract_records_error_not_success():
    problem = next_step()
    problem["requires_outputs"] = "not a valid input list"
    report = graph.validate_output_links({"steps": [first_step(), problem]})
    assert any("requires_outputs must be a list" in err for err in report)


def test_required_output_from_unknown_step_is_a_hard_graph_error():
    second = next_step()
    second["requires_outputs"] = [{"step": 99, "name": "measured.csv"}]
    errors = graph.validate_output_links({"steps": [first_step(), second]})
    assert any("unknown step 99" in err for err in errors)


def test_known_source_that_is_not_a_dependency_cannot_prove_data_provenance():
    second = next_step(dependency=False)
    errors = graph.validate_output_links({"steps": [first_step(), second]})
    assert any("not a dependency" in err for err in errors)


def test_known_parent_with_wrong_output_name_does_not_satisfy_contract():
    report = graph.validate_output_links(
        {"steps": [first_step(), next_step(name="unproduced.csv")]}
    )
    assert any("undeclared output" in err for err in report)


def test_output_index_and_graph_summary_preserve_exact_producer_names():
    plan = {"steps": [first_step(), next_step()]}
    summary = graph.graph_summary(plan)
    assert summary["topological_order"] == [1, 2]
    assert summary["explicit"] is True
    assert summary["dependencies"] == {"1": [], "2": [1]}
    assert summary["outputs"] == {"1": ["measured.csv"]}


def test_nonmapping_steps_are_not_silently_reinterpreted_as_real_producers():
    plan = {"steps": [first_step(), {"id": 2, "depends_on": []}, "not a step"]}
    assert graph.step_index(plan).keys() == {1, 2}
