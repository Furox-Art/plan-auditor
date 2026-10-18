"""Roundtrip STRIPS source and CLI PDDL export using actual local filesystem evidence."""

from __future__ import annotations

import json

import pytest

from supervisor import formal_planning as formal


def contract():
    return {
        "version": 1,
        "initial_facts": ["ready"],
        "goal_facts": ["verified"],
        "actions": [
            {"step": 1, "preconditions": ["ready"], "add_effects": ["verified"], "del_effects": []},
        ],
    }


def setup_workspace(root, raw=None):
    raw = contract() if raw is None else raw
    pg = root / ".plan-auditor"
    pg.mkdir()
    plan = {
        "steps": [
            {
                "id": 1,
                "depends_on": [],
                "verify": [
                    formal.make_formal_check(raw),
                ],
            }
        ]
    }
    (pg / "plan.json").write_text(json.dumps(plan))
    return formal.contract_sha256(raw)


def get_response(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_make_check_returns_exact_canonical_hash_and_bounded_argv(tmp_path, capsys):
    raw = contract()
    file = tmp_path / "contract.json"
    file.write_text(json.dumps(raw))
    assert formal.main(["make-check", str(file)]) == 0
    check = get_response(capsys)
    assert check["formal_planning"] == raw
    assert check["argv"] == [
        formal.FORMAL_EXECUTABLE,
        "verify",
        ".",
        "--contract-sha",
        formal.contract_sha256(raw),
    ]


def test_cli_make_check_allows_explicit_external_backend_without_implicit_execution(
    tmp_path, capsys
):
    file = tmp_path / "contract.json"
    file.write_text(json.dumps(contract()))
    assert (
        formal.main(
            [
                "make-check",
                str(file),
                "--fast-downward",
                "fake-planner-executable",
                "--require-fast-downward",
            ]
        )
        == 0
    )
    check = get_response(capsys)
    assert check["argv"][-3:] == [
        "--fast-downward",
        "fake-planner-executable",
        "--require-fast-downward",
    ]


@pytest.mark.parametrize("invalid", ["[]", '{"version":1,', '"scalar"', "invalid json"])
def test_cli_make_check_rejects_nonobject_or_malformed_contract_json(tmp_path, capsys, invalid):
    file = tmp_path / "bad.json"
    file.write_text(invalid)
    assert formal.main(["make-check", str(file)]) == 2
    out = get_response(capsys)
    assert out["outcome"] == "FAIL"


def test_cli_make_check_missing_file_is_not_replaced_by_default_contract(tmp_path, capsys):
    assert formal.main(["make-check", str(tmp_path / "missing.json")]) == 2
    assert get_response(capsys)["outcome"] == "FAIL"


def test_cli_verify_real_plan_without_external_planner_and_export_replay(tmp_path, capsys):
    sha = setup_workspace(tmp_path)
    assert formal.main(["verify", str(tmp_path), "--contract-sha", sha]) == 0
    verdict = get_response(capsys)
    assert verdict["outcome"] == "PASS"
    assert verdict["contracts"][0]["analysis"]["solution_order"] == [1]

    out_dir = tmp_path / "artifacts"
    assert (
        formal.main(["export-pddl", str(tmp_path), "--contract-sha", sha, "--output", str(out_dir)])
        == 0
    )
    recorded = get_response(capsys)
    assert recorded["outcome"] == "PASS"
    assert recorded["contract_sha256"] == sha
    assert recorded["plan"] == "default"
    assert "(:action step-1" in (out_dir / "domain.pddl").read_text()
    assert "(:goal" in (out_dir / "problem.pddl").read_text()
    mapping = json.loads((out_dir / "facts.json").read_text())
    assert "verified" in mapping


def test_cli_export_unknown_digest_never_writes_untrusted_pddl_artifacts(tmp_path, capsys):
    setup_workspace(tmp_path)
    output = tmp_path / "not-created"
    assert (
        formal.main(
            ["export-pddl", str(tmp_path), "--contract-sha", "a" * 64, "--output", str(output)]
        )
        == 2
    )
    verdict = get_response(capsys)
    assert verdict["outcome"] == "FAIL"
    assert not output.exists()


def test_cli_export_invalid_semantic_fact_contract_refuses_output(tmp_path, capsys):
    raw = contract()
    raw["goal_facts"] = ["unobserved"]
    sha = setup_workspace(tmp_path, raw)
    dest = tmp_path / "not-created"
    assert (
        formal.main(["export-pddl", str(tmp_path), "--contract-sha", sha, "--output", str(dest)])
        == 2
    )
    assert get_response(capsys)["outcome"] == "FAIL"
    assert not dest.exists()


def test_cli_verify_unmatched_contract_fails_with_distinct_code_and_no_fake_proof(tmp_path, capsys):
    setup_workspace(tmp_path)
    assert formal.main(["verify", str(tmp_path), "--contract-sha", "0" * 64]) == 2
    assert get_response(capsys)["outcome"] == "FAIL"


def test_cli_verify_required_missing_fast_downward_never_claims_pass(tmp_path, capsys):
    setup_workspace(tmp_path)
    assert (
        formal.main(
            [
                "verify",
                str(tmp_path),
                "--require-fast-downward",
                "--fast-downward",
                str(tmp_path / "nonexistent-executable"),
            ]
        )
        == 2
    )
    result = get_response(capsys)
    assert result["outcome"] == "FAIL"
    assert result["contracts"][0]["fast_downward"]["status"] == "UNAVAILABLE"


def test_cli_verify_rejects_invalid_max_state_bound_without_unbounded_search(tmp_path, capsys):
    setup_workspace(tmp_path)
    assert formal.main(["verify", str(tmp_path), "--max-states", "0"]) == 2
    result = get_response(capsys)
    assert result["outcome"] == "FAIL"


def test_cli_requires_explicit_subcommand_and_argument_types():
    with pytest.raises(SystemExit) as error:
        formal.main([])
    assert error.value.code == 2
