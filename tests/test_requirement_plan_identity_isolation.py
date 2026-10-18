"""Requirement verification plans must not enable identity or criteria spoofing."""

from __future__ import annotations

import pytest

from supervisor.requirements import Requirement, requirements_to_verification_plan


@pytest.mark.parametrize(
    "ids",
    [
        ("REQ-001", "REQ-001"),
        ("REQ-001", " REQ-001 "),
    ],
)
def test_repeated_requirement_id_is_rejected(ids: tuple[str, str]) -> None:
    reqs = [Requirement(identifier, f"distinct criterion {i}") for i, identifier in enumerate(ids)]
    with pytest.raises(ValueError, match="duplicate requirement"):
        requirements_to_verification_plan(reqs)


@pytest.mark.parametrize("invalid", ["", "   ", None, 123])
def test_invalid_requirement_identity_is_rejected(invalid: object) -> None:
    with pytest.raises(ValueError, match="requirement id"):
        requirements_to_verification_plan([Requirement(invalid, "criterion")])


def test_non_requirement_entries_are_rejected_explicitly() -> None:
    with pytest.raises(TypeError, match="Requirement"):
        requirements_to_verification_plan([{"id": "REQ-001"}])


def test_verification_plan_does_not_alias_mutable_acceptance_criteria() -> None:
    req = Requirement("REQ-001", "authenticate evidence", acceptance_criteria=["signature valid"])
    plan = requirements_to_verification_plan([req])
    plan[0]["acceptance_criteria"].append("fabricated PASS")
    assert req.acceptance_criteria == ["signature valid"]
    req.acceptance_criteria.append("recheck")
    assert plan[0]["acceptance_criteria"] == ["signature valid", "fabricated PASS"]
