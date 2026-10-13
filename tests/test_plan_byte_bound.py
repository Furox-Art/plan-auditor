"""Regression coverage for the bounded plan read.

The plan is untrusted input — it is what the tool verifies, and its commands must
not run before a seal binds it — so how much of it gets loaded into memory is
part of the trust boundary. Both read paths parsed the plan with no bound, so a
host that passes a plan through to this tool could make it allocate the whole
file before a single validation rule ran, turning a plan-size check into an
out-of-memory denial of service instead of a verdict.

The trusted path (``supervisor.plans.load_plan_ref``) and the direct script path
(``scripts.audit_check.load_plan``) now share one bound, so they accept the same
plans instead of disagreeing about which ones are too big.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.audit_check import MAX_PLAN_BYTES, load_plan
from supervisor.plans import PlanSizeError, iter_plan_refs, load_plan_ref, plan_path


def _tiny_plan() -> dict:
    return {
        "task": "t",
        "created": "2026-10-13T00:00:00Z",
        "requirements": [{"id": "REQ-1", "description": "d"}],
        "steps": [
            {
                "id": 1,
                "title": "s",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
            }
        ],
    }


def _default_ref(root: Path):
    """The ``PlanRef`` the trusted reader needs for this workspace."""
    refs = list(iter_plan_refs(root))
    assert len(refs) == 1, refs
    return refs[0]


def _root(root: Path) -> Path:
    """Ensure ``.plan-auditor`` exists and return the plan path."""
    plan_dir = root / ".plan-auditor"
    plan_dir.mkdir(parents=True, exist_ok=True)
    target = plan_path(root)
    assert target.parent == plan_dir.resolve() or target.parent.resolve() == plan_dir.resolve()
    return target


def _read_trusted(root: Path) -> dict:
    return load_plan_ref(_default_ref(root))


def test_the_trusted_path_accepts_a_plan_inside_the_bound(tmp_path: Path):
    _root(tmp_path).write_text(json.dumps(_tiny_plan()), encoding="utf-8")
    assert _read_trusted(tmp_path)["task"] == "t"


def test_the_direct_script_path_accepts_a_plan_inside_the_bound(tmp_path: Path):
    _root(tmp_path).write_text(json.dumps(_tiny_plan()), encoding="utf-8")
    assert load_plan(str(tmp_path))["task"] == "t"


def test_the_trusted_path_rejects_a_plan_over_the_bound_before_parsing(tmp_path: Path):
    size = MAX_PLAN_BYTES + 1
    # Not valid JSON, so a run either rejects on size or dies on a decode error:
    # only the size bound gives the deterministic, explainable failure.
    _root(tmp_path).write_bytes(b"{" + b"p" * size)
    with pytest.raises(PlanSizeError) as caught:
        _read_trusted(tmp_path)
    message = str(caught.value)
    assert "over the" in message, message
    assert str(MAX_PLAN_BYTES) in message, message
    assert str(_root(tmp_path).stat().st_size) in message, message


def test_the_direct_script_path_rejects_a_plan_over_the_bound(tmp_path: Path):
    _root(tmp_path).write_bytes(b"{" + b"p" * (MAX_PLAN_BYTES + 1))
    with pytest.raises(SystemExit) as caught:
        load_plan(str(tmp_path))
    message = str(caught.value)
    assert "plan cok buyuk" in message, message
    assert str(MAX_PLAN_BYTES) in message, message


def test_a_plan_exactly_at_the_bound_is_accepted(tmp_path: Path):
    """The bound rejects *over*, not *at*, and both paths share the same value."""
    from supervisor.plans import MAX_PLAN_BYTES as trusted_bound

    assert trusted_bound == MAX_PLAN_BYTES > 0
    body = json.dumps(_tiny_plan())
    target = _root(tmp_path)
    target.write_text(body, encoding="utf-8")
    assert target.stat().st_size <= MAX_PLAN_BYTES
    assert _read_trusted(tmp_path)["task"] == "t"


def test_the_two_read_paths_cannot_drift_apart():
    """One constant, imported by both. A second copy would be worth failing on."""
    import supervisor.plans as plans

    assert plans.MAX_PLAN_BYTES is MAX_PLAN_BYTES
    assert plans.PlanSizeError.__name__ == "PlanSizeError"
