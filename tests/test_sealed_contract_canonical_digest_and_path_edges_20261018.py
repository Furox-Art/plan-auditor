"""Cryptographic plan addresses use canonical data, never mutable runtime status."""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace

import pytest

from scripts import contract


def template():
    return {
        "task": "verify real work",
        "requirements": ["direct measurement"],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "run fixed measurement",
                "depends_on": [],
                "verify": [
                    {"type": "pytest", "args": ["tests/test_measurement.py"]},
                    "forged nonmapping check",
                ],
            }
        ],
    }


def test_canonical_json_orders_keys_preserves_utf8_and_yields_stable_sha256():
    first = {"b": 1, "α": "scientific", "a": [1, 2]}
    second = {"a": [1, 2], "α": "scientific", "b": 1}
    assert contract.canonical_json(first) == contract.canonical_json(second)
    assert "α" in contract.canonical_json(first)
    expected = hashlib.sha256(contract.canonical_json(first).encode("utf8")).hexdigest()
    assert contract.canonical_digest(first) == expected


def test_auth_envelope_cannot_change_canonical_signed_payload():
    original = {"task": "measured", "auth": {"signature": "untrusted"}, "steps": []}
    unsigned = contract.payload_without_auth(original)
    assert unsigned == {"task": "measured", "steps": []}
    assert original["auth"]["signature"] == "untrusted"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (None, None),
        ("", None),
        ("default", None),
        ("measured-study_v1.3", "measured-study_v1.3"),
    ],
)
def test_named_plan_contract_canonicalizes_default_and_safe_basename(name, expected):
    assert contract.validate_plan_name(name) == expected


@pytest.mark.parametrize(
    "bad",
    [
        ".",
        "..",
        "../outside",
        "a/b",
        "a\\\\b",
        "-not-safe",
        "x" * 129,
    ],
)
def test_plan_name_does_not_accept_traversal_or_unbounded_names(bad):
    with pytest.raises(ValueError, match="invalid plan name"):
        contract.validate_plan_name(bad)


def test_secondary_separator_check_refuses_lax_regex_allowlist(monkeypatch):
    monkeypatch.setattr(contract, "PLAN_NAME_RE", SimpleNamespace(fullmatch=lambda _: True))
    with pytest.raises(ValueError, match="path separator"):
        contract.validate_plan_name("record/other")
    with pytest.raises(ValueError, match="path separator"):
        contract.validate_plan_name("record\\\\other")


def test_runtime_status_changes_do_not_rehash_a_sealed_plan():
    source = template()
    first = contract.plan_hash(source)
    changed = copy.deepcopy(source)
    changed["status"] = "PASS"
    changed["steps"][0]["status"] = "COMPLETE"
    assert contract.plan_hash(changed) == first
    changed["steps"][0]["verify"][0]["args"] = ["tests/test_wrong_thing.py"]
    assert contract.plan_hash(changed) != first


def test_contract_projection_ignores_nonmapping_verification_and_copies_inputs():
    source = template()
    projected = contract.contract_step(source["steps"][0])
    assert len(projected["verify"]) == 1
    assert projected["id"] == 1
    projected["verify"][0]["args"].append("wrong-data")
    assert source["steps"][0]["verify"][0]["args"] == ["tests/test_measurement.py"]


def test_legacy_contract_hash_is_based_on_historical_explicit_graph():
    plan = template()
    legacy = contract.legacy_v3_contract_plan(plan)
    assert legacy["steps"][0]["depends_on"] == []
    assert contract.legacy_v3_plan_hash(plan) == contract.canonical_digest(legacy)


def test_nonobject_plan_steps_are_excluded_not_treated_as_verified_work():
    plan = template()
    plan["steps"].append("pretend work completed")
    original = contract.contract_plan(template())
    assert contract.contract_plan(plan) == original


def test_invalid_dependency_graph_has_no_guessed_implicit_contract_edges():
    plan = template()
    plan["steps"][0]["depends_on"] = [1]
    projected = contract.contract_plan(plan)
    assert projected["steps"][0]["depends_on"] == [1]


def test_default_and_named_seals_get_distinct_constrained_paths(tmp_path):
    assert contract.seal_path(tmp_path).endswith("/.plan-auditor/seal.json")
    assert contract.seal_path(tmp_path, "case").endswith("/.plan-auditor/seals/case.json")


def test_second_path_containment_gate_rejects_unexpected_resolution(monkeypatch, tmp_path):
    monkeypatch.setattr(contract.os.path, "commonpath", lambda _: str(tmp_path / "other"))
    with pytest.raises(ValueError, match="seal path escapes"):
        contract.seal_path(tmp_path, "observed")


def test_named_plan_seal_address_is_repeatable_independent_of_relative_root(tmp_path):
    expected = contract.seal_path(tmp_path, "study")
    relative = tmp_path / "sub" / ".."
    (tmp_path / "sub").mkdir()
    assert contract.seal_path(relative, "study") == expected


def test_documented_direct_script_execution_retains_canonical_plan_graph_contract(
    monkeypatch,
):
    import builtins
    import runpy
    import sys

    from scripts import plan_graph

    existing_import = builtins.__import__

    def simulated_direct_script_import(name, *args, **kwargs):
        if name == "scripts.plan_graph":
            raise ImportError("script directory is importable only as top level")
        return existing_import(name, *args, **kwargs)

    monkeypatch.setitem(sys.modules, "plan_graph", plan_graph)
    monkeypatch.setattr(builtins, "__import__", simulated_direct_script_import)
    executed = runpy.run_path(contract.__file__)
    assert executed["effective_dependencies"] is plan_graph.effective_dependencies
    assert executed["plan_hash"](template()) == contract.plan_hash(template())
