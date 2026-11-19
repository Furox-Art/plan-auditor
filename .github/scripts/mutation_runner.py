#!/usr/bin/env python3
"""Mutation-test runner that honours the installed-distribution contract.

The root ``conftest.py`` pins ``supervisor`` and ``scripts`` to the *installed*
wheel before any test loads, so mutating the checkout alone changes nothing the
suite executes. Before every mutant run this runner therefore reinstalls the
(possibly mutated) source tree non-editable, then runs pytest against it.

With no arguments it runs a focused subset covering the core modules listed in
``[tool.mutmut]`` (path confinement, plan grammar, gate priority, registry
ownership). That keeps a sample campaign fast; it is an *under-approximation*
of the full suite, so a survivor only proves the subset missed the mutant, not
that the whole suite would. For a full campaign, widen the targets explicitly::

    mutmut run --runner "python .github/scripts/mutation_runner.py tests/ -x -q"

Exit codes are fail-closed, matching the project's core rule: anything other
than a clean pytest pass (test failure, collection error, or a failed
reinstall) is reported as a failed run, so a mutant that breaks the suite is
killed and never silently counted as a survivor. mutmut treats exit code 1 as
"tests failed" and every other non-zero code as "tests passed", which is why
this runner normalises all failures to 1.
"""

from __future__ import annotations

import subprocess
import sys

FOCUSED_TESTS = [
    "tests/test_plan_paths_and_gate_priority_matrix_20261017.py",
    "tests/test_control_plane_lifecycle_policy_hash_adversarial_20261018.py",
    "tests/test_audit_plan_structural_scientific_contracts_20261018.py",
    "tests/test_cross_platform_absolute_path_rejection_20261119.py",
    "tests/test_agent_registry_freeze_and_path_safety_20261018.py",
]


def main() -> int:
    install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--force-reinstall", "."],
        check=False,
    )
    if install.returncode != 0:
        print(
            "mutation runner: reinstalling the mutated checkout failed; "
            "reporting the run as failed (fail closed)",
            file=sys.stderr,
        )
        return 1
    targets = sys.argv[1:] or [*FOCUSED_TESTS, "-x", "-q"]
    result = subprocess.run([sys.executable, "-m", "pytest", *targets], check=False)
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
