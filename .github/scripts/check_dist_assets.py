#!/usr/bin/env python3
"""Assert the built wheel and sdist ship the assets the documentation promises.

``README.md`` tells users to copy ``SKILL.md``, ``scripts/``, ``references/``
and ``hooks/`` into their host's skills directory, and ``docs/cli.md`` documents
running ``python hooks/gate_hook.py <workspace>``. A wheel that omits those
files installs a CLI whose documented integration path is broken, and nothing in
the test suite notices because the tests import from the checkout.

``tests/wheel_cli_smoke.py`` verifies the Python runtime files. This check
covers the skill assets and the distribution metadata instead, so the two
concerns cannot drift apart silently.
"""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]

# Runtime Python code the CLI cannot work without.
WHEEL_RUNTIME = {
    "supervisor/cli.py",
    "supervisor/orchestrator.py",
    "supervisor/plan_verifier.py",
    "supervisor/sealing.py",
    "supervisor/request_contract.py",
    "supervisor/__init__.py",
    "scripts/audit_check.py",
    "scripts/integrity.py",
    "scripts/plan_graph.py",
}

# Skill assets the README and docs tell users to copy. Inside the wheel they
# live under SKILL_NAMESPACE (see pyproject force-include).
SKILL_ASSETS = {
    "SKILL.md",
    "references/plan-format.md",
    "hooks/gate_hook.py",
    "hooks/README.md",
    "package.json",
    "index.js",
    "bin/plan-auditor.js",
}
SKILL_NAMESPACE = "plan_auditor_skill"

# Sources that must be present in the sdist so a downstream packager can build
# and re-test without cloning the repository.
SDIST_REQUIRED = {
    "pyproject.toml",
    "README.md",
    "SKILL.md",
    "LICENSE",
    "CHANGELOG.md",
    "mkdocs.yml",
    "index.js",
    "package.json",
}

# Never ship build output or local environments.
FORBIDDEN_SUFFIXES = (".pyc", ".pyo")
FORBIDDEN_PARTS = ("__pycache__", ".venv", "node_modules", ".pytest_cache")


def _fail(problems: list[str]) -> int:
    print("\nDISTRIBUTION ASSET CHECK FAILED")
    for problem in problems:
        print(f"  - {problem}")
    return 1


def _check_wheel(wheel: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        # dist-info prefix varies with the normalised distribution name.
        dist_info = sorted(n for n in names if n.endswith(".dist-info/METADATA"))
        if len(dist_info) != 1:
            problems.append(f"expected exactly one dist-info/METADATA, found {dist_info}")
            wheel_root = ""
        else:
            wheel_root = dist_info[0].split("/", 1)[0]

        payload = {n for n in names if not n.startswith(f"{wheel_root}/")}

        missing = sorted(WHEEL_RUNTIME - payload)
        for item in missing:
            problems.append(f"wheel {wheel.name} is missing runtime file {item}")

        # Skill assets are force-included under plan_auditor_skill/ so they do
        # not collide with other distributions at the site-packages root.
        missing_assets = sorted(
            f"{SKILL_NAMESPACE}/{item}"
            for item in SKILL_ASSETS
            if f"{SKILL_NAMESPACE}/{item}" not in payload
        )
        for item in missing_assets:
            problems.append(f"wheel {wheel.name} is missing skill asset {item}")

        for name in sorted(payload):
            if name.endswith(FORBIDDEN_SUFFIXES) or any(
                part in FORBIDDEN_PARTS for part in Path(name).parts
            ):
                problems.append(f"wheel {wheel.name} ships build artifact {name}")

        entry_points = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
        if len(entry_points) != 1:
            problems.append(f"expected one entry_points.txt, found {entry_points}")
        else:
            text = archive.read(entry_points[0]).decode("utf-8")
            for required in (
                "plan-auditor = supervisor.cli:entrypoint",
                "plan-auditor-migrate-seal = supervisor.seal_migration:main",
                "plan-auditor-formal = supervisor.formal_planning:main",
                "plan-auditor-formalize = supervisor.formal_compiler:main",
            ):
                if required not in text:
                    problems.append(f"wheel entry_points.txt is missing {required!r}")

        metadata = archive.read(dist_info[0]).decode("utf-8") if dist_info else ""
    return problems + _check_metadata(metadata, wheel.name, problems)


def _check_metadata(metadata: str, label: str, problems: list[str]) -> list[str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    expected_version = project["version"]
    if f"Version: {expected_version}" not in metadata:
        problems.append(f"{label} metadata Version is not {expected_version}")
    if "License-Expression: MIT" not in metadata and "License: MIT" not in metadata:
        problems.append(f"{label} metadata does not declare the MIT license")
    if f"Requires-Python: {project['requires-python']}" not in metadata:
        problems.append(f"{label} metadata Requires-Python is not {project['requires-python']}")
    return problems


def _check_sdist(sdist: Path) -> list[str]:
    problems: list[str] = []
    with tarfile.open(sdist) as archive:
        members = archive.getnames()
        # Strip the single leading directory component.
        roots = {name.split("/", 1)[0] for name in members}
        if len(roots) != 1:
            problems.append(f"sdist should have exactly one top-level directory, found {roots}")
            prefix = ""
        else:
            prefix = roots.pop()
        payload = {name[len(prefix) + 1 :] for name in members if name != prefix}

    for item in sorted(SDIST_REQUIRED - payload):
        problems.append(f"sdist {sdist.name} is missing {item}")
    for item in sorted((WHEEL_RUNTIME | SKILL_ASSETS) - payload):
        problems.append(f"sdist {sdist.name} is missing {item}")
    for name in sorted(payload):
        if name.endswith(FORBIDDEN_SUFFIXES) or any(
            part in FORBIDDEN_PARTS for part in Path(name).parts
        ):
            problems.append(f"sdist {sdist.name} ships build artifact {name}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", default="dist")
    args = parser.parse_args()

    dist = Path(args.dist_dir)
    if not dist.is_absolute():
        dist = ROOT / dist
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    if len(sdists) != 1:
        raise SystemExit(f"expected exactly one sdist in {dist}, found {len(sdists)}")

    problems = _check_wheel(wheels[0])
    problems += _check_sdist(sdists[0])

    print("=== distribution asset check ===")
    print(f"wheel: {wheels[0].name}")
    print(f"sdist: {sdists[0].name}")
    print(f"required runtime files: {len(WHEEL_RUNTIME)}")
    print(f"required skill assets:  {len(SKILL_ASSETS)}")
    if problems:
        return _fail(problems)
    print("\nwheel and sdist contain every runtime file and documented skill asset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
