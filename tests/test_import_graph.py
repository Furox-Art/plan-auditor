"""Regression coverage for the package import graph.

``supervisor.formal_compiler`` and ``supervisor.formal_semantics`` imported each
other. Both edges were hidden behind function-level imports, and the one in
``formal_semantics`` was wrapped in ``except (ImportError, ValueError)``, so a
genuine circular-import failure was reported as "could not be independently
recompiled" — a semantic check failure, not an import failure. A broken import
in the verification path is the one failure mode a verification tool must never
misreport, so the cycle is broken instead of tolerated: ``formal_semantics`` is
now a leaf module, the single back-edge from it is resolved inside a function,
and it is injectable so a caller that already holds the compiler passes it in.

These tests fail if the cycle is reintroduced, and fail if the seam that removed
the masking is taken away again.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("supervisor", "scripts")


def _module_import_graph() -> dict[str, set[str]]:
    """Module-scope import edges inside ``supervisor`` and ``scripts``.

    Only ``tree.body`` is inspected: a function-level import is already an
    accepted way to break a cycle, so counting it would make this test fail on
    the very pattern the fix is supposed to allow.
    """
    modules: dict[str, set[str]] = {}
    for package in PACKAGES:
        for path in sorted((ROOT / package).glob("*.py")):
            modules[f"{package}.{path.stem}"] = set()
    known = set(modules)
    for package in PACKAGES:
        for path in sorted((ROOT / package).glob("*.py")):
            name = f"{package}.{path.stem}"
            tree = ast.parse(path.read_text(encoding="utf-8"))
            edges: set[str] = set()
            for node in tree.body:
                targets: list[str] = []
                if isinstance(node, ast.ImportFrom):
                    if node.level == 1:
                        targets.append(f"{package}.{node.module}" if node.module else package)
                    elif node.level == 0 and node.module:
                        parts = node.module.split(".")
                        if len(parts) >= 2 and parts[0] in PACKAGES:
                            targets.append(".".join(parts[:2]))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if len(parts) >= 2 and parts[0] in PACKAGES:
                            targets.append(".".join(parts[:2]))
                edges.update(target for target in targets if target in known)
            modules[name] = edges
    return modules


def _import_in_fresh_interpreter(module: str) -> set[str]:
    """Return the module names loaded by importing ``module`` alone."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, importlib;"
            f"importlib.import_module({module!r});"
            "print('\\n'.join(sorted(m for m in sys.modules if m.startswith(('supervisor.', 'scripts.')))))",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def _all_import_graph() -> dict[str, set[str]]:
    """Every import edge, function-level included.

    Used to keep the remaining lazy cycle honest: a back-edge that is broken at
    import time still couples the two modules at call time, so it has to be a
    documented, injectable one rather than a silently tolerated one.
    """
    modules: dict[str, set[str]] = {}
    for package in PACKAGES:
        for path in sorted((ROOT / package).glob("*.py")):
            modules[f"{package}.{path.stem}"] = set()
    known = set(modules)
    for package in PACKAGES:
        for path in sorted((ROOT / package).glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            edges: set[str] = set()
            for node in ast.walk(tree):
                targets: list[str] = []
                if isinstance(node, ast.ImportFrom):
                    if node.level == 1:
                        targets.append(f"{package}.{node.module}" if node.module else package)
                    elif node.level == 0 and node.module:
                        parts = node.module.split(".")
                        if len(parts) >= 2 and parts[0] in PACKAGES:
                            targets.append(".".join(parts[:2]))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if len(parts) >= 2 and parts[0] in PACKAGES:
                            targets.append(".".join(parts[:2]))
                edges.update(target for target in targets if target in known)
            modules[f"{package}.{path.stem}"] = edges
    return modules


def _cycles(graph: dict[str, set[str]]) -> set[frozenset[str]]:
    """Return the node sets that participate in a cycle in ``graph``."""
    found: set[frozenset[str]] = set()
    seen: set[str] = set()

    def walk(node: str, stack: list[str]) -> None:
        if node in stack:
            found.add(frozenset(stack[stack.index(node) :]))
            return
        if node in seen:
            return
        seen.add(node)
        for target in sorted(graph.get(node, ())):
            walk(target, stack + [node])

    for start in sorted(graph):
        walk(start, [])
    return found


#: The one lazy cycle the design still needs, and why. ``formal_compiler``
#: analyses the semantic layer of a contract it produced, and the semantic layer
#: validates a generated contract by asking the compiler to recompile it. The
#: compiler's dependency is now a module-level import into a leaf module; the
#: back-edge lives in ``resolve_contract_validator`` and is injectable.
KNOWN_LAZY_CYCLE = frozenset({"supervisor.formal_compiler", "supervisor.formal_semantics"})


def test_the_only_lazy_cycle_is_the_documented_one():
    """A new masked cycle must be visible here rather than discovered at runtime."""
    cycles = _cycles(_all_import_graph())
    unexpected = cycles - {KNOWN_LAZY_CYCLE}
    assert not unexpected, (
        "new import cycle(s): "
        + "; ".join(" -> ".join(sorted(group)) for group in unexpected)
        + ". Break them with a function-level import plus an injectable seam, "
        "and never wrap the import in `except ImportError`."
    )


def test_supervisor_and_scripts_have_no_module_level_import_cycle():
    """No module may import another in a way that only works by luck of ordering."""
    cycles = _cycles(_module_import_graph())
    assert not cycles, (
        "module-level import cycle(s) detected: "
        + "; ".join(" -> ".join(sorted(group)) for group in cycles)
        + ". Break them with a function-level import or a shared leaf module."
    )


def test_formal_semantics_does_not_import_the_compiler_at_module_scope():
    """The concrete cycle this fix removed: semantics <- -> compiler."""
    loaded = _import_in_fresh_interpreter("supervisor.formal_semantics")
    assert "supervisor.formal_semantics" in loaded
    assert "supervisor.formal_compiler" not in loaded, (
        "importing supervisor.formal_semantics pulls in supervisor.formal_compiler "
        "at module scope; the two modules form an import cycle again"
    )


def test_formal_compiler_still_gets_the_semantic_analysis():
    """Breaking the cycle must not drop the compiler's semantic check."""
    loaded = _import_in_fresh_interpreter("supervisor.formal_compiler")
    assert "supervisor.formal_semantics" in loaded


def test_resolve_contract_validator_is_the_compiler_check():
    from supervisor.formal_compiler import validate_generated_contract
    from supervisor.formal_semantics import resolve_contract_validator

    assert resolve_contract_validator() is validate_generated_contract


def test_semantic_analysis_accepts_an_injected_contract_validator():
    """The seam: a caller that already holds the compiler injects its check."""
    from supervisor.formal_compiler import compile_plan, validate_generated_contract
    from supervisor.formal_semantics import analyze_formal_semantics

    plan, contract, _anchor = compile_plan(_compilable_plan())
    seen: list[object] = []

    def recording_validator(source, signed):
        seen.append(signed)
        return validate_generated_contract(source, signed)

    result = analyze_formal_semantics(plan, contract_validator=recording_validator)
    assert seen == [plan["steps"][0]["verify"][0]["formal_planning"]]
    assert result.generated is True
    assert result.valid, result.errors
    assert contract["initial_facts"]


def test_injected_validator_failure_is_not_reported_as_a_recompile_problem():
    """The old ``except ImportError`` turned an import breakage into a semantic
    verdict. An injected validator that raises must now propagate."""
    import pytest

    from supervisor.formal_compiler import compile_plan
    from supervisor.formal_semantics import analyze_formal_semantics

    plan, _contract, _anchor = compile_plan(_compilable_plan())

    def broken_validator(source, signed):
        raise ImportError("cannot import the recompilation check")

    with pytest.raises(ImportError):
        analyze_formal_semantics(plan, contract_validator=broken_validator)


def _compilable_plan() -> dict:
    """A plan the deterministic compiler can formalise end to end."""
    return {
        "task": "compile and verify artifact",
        "created": "2026-09-05T00:00:00Z",
        "requirements": [
            {"id": "REQ-1", "description": "build artifact", "priority": "must"},
            {"id": "REQ-2", "description": "verify artifact", "priority": "must"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "verify": [{"type": "run", "argv": [sys.executable, "-c", "print('built')"]}],
                "outputs": [
                    {
                        "name": "artifact",
                        "verify": [{"type": "file_exists", "path": "artifact.txt"}],
                    }
                ],
            },
            {
                "id": 2,
                "title": "verify",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "artifact"}],
                "covers": ["REQ-2"],
                "verify": [{"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}],
                "outputs": [],
            },
        ],
    }
