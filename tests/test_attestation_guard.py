"""Regression coverage for CI wiring of the supply-chain attestation guard.

``docs/check_attestation_claims.py`` has existed as a standalone script with a
negative control since it was written, but nothing ran it. A guard that is never
executed cannot fail, so the exact claim it was written to catch — a supply-chain
provenance claim in a document that names no channel, states no definite status,
or presents a registry transport signature as build provenance — was free to be
introduced and stay. These tests pin it into the workflow and into the version
lockstep family, and they fail if either wiring is removed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "docs" / "check_attestation_claims.py"
LOCKSTEP = ROOT / ".github" / "scripts" / "check_version_lockstep.py"
WORKFLOWS = ROOT / ".github" / "workflows"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow_text() -> str:
    return "\n".join(sorted(path.read_text(encoding="utf-8") for path in WORKFLOWS.glob("*.yml")))


def test_the_attestation_guard_is_invoked_by_a_workflow_step() -> None:
    """A guard nothing runs is not a guard."""
    text = _workflow_text()
    assert "docs/check_attestation_claims.py" in text, (
        "no workflow runs docs/check_attestation_claims.py; a documentation drift "
        "in a supply-chain provenance claim is invisible to every other job"
    )


def test_the_guard_runs_both_the_drift_scan_and_the_negative_control() -> None:
    """The scan catches drift; the negative control proves the guard can still
    reject a lie. Running only one of the two is how a guard rots silently."""
    text = _workflow_text()
    assert "check_attestation_claims.py --self-test" in text, (
        "the guard's negative control is not run in CI; a guard that has stopped "
        "rejecting known-false claims would still pass"
    )
    assert "check_attestation_claims.py\n" in text, (
        "the guard's drift scan is not run in CI; only its negative control is"
    )


def test_the_guard_is_not_gated_behind_a_manual_only_trigger() -> None:
    """A step conditioned on a release-only trigger never runs on a pull request."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "check_attestation_claims.py" not in text:
            continue
        triggers = text.split("jobs:", 1)[0]
        assert "workflow_dispatch" not in triggers or "push" in triggers, (
            f"{path.name} only runs on manual dispatch; the guard would never run "
            "on a pull request, which is where drift arrives from"
        )


def test_the_guard_negative_control_rejects_known_false_claims() -> None:
    """Invoke the guard's own negative control, in-process, as CI does."""
    guard = _load("check_attestation_claims", GUARD)
    assert guard.main(["--self-test"]) == 0


def test_the_guard_pin_names_the_current_version_the_docs_claim() -> None:
    """The pin and the documents must agree, which is the guard's core rule."""
    guard = _load("check_attestation_claims", GUARD)
    problems = guard.findings()
    assert not problems, "\n".join(problems)


def test_lockstep_registers_the_guard_pin_as_a_released_version() -> None:
    """The published-version family must exist and pass on a healthy tree."""
    lockstep = _load("check_version_lockstep", LOCKSTEP)
    tree_version = lockstep._runtime_version()
    assert lockstep.published_version_family(tree_version) == 0


def test_lockstep_rejects_a_guard_pin_that_names_no_release() -> None:
    lockstep = _load("check_version_lockstep", LOCKSTEP)
    original = lockstep._attestation_guard_pin
    lockstep._attestation_guard_pin = lambda: "9.9.9"
    try:
        assert lockstep.published_version_family("2.5.0") == 1
    finally:
        lockstep._attestation_guard_pin = original


def test_lockstep_rejects_a_guard_pin_ahead_of_the_shipped_tree() -> None:
    lockstep = _load("check_version_lockstep", LOCKSTEP)
    original = lockstep._attestation_guard_pin
    lockstep._attestation_guard_pin = lambda: "99.0.0"
    try:
        assert lockstep.published_version_family("2.5.0") == 1
    finally:
        lockstep._attestation_guard_pin = original
