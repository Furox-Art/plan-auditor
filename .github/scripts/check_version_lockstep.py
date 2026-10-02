#!/usr/bin/env python3
"""Fail CI when the shipped version is not identical everywhere.

Version drift is silent and expensive: a wheel built from ``pyproject.toml`` can
carry a different version than ``supervisor.__version__``, than the npm
``package.json``, and than the newest entry in ``CHANGELOG.md``. Users then see
three different numbers for one artifact and ``pip`` cannot reason about which
is authoritative.

This script only reads files. It never rewrites a version, because a silent
rewrite would hide which source of truth drifted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
CHANGELOG_RELEASE = re.compile(r"^##\s+v?(\d+\.\d+\.\d+)\b", re.MULTILINE)


def _pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _package_json_version() -> str:
    data = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    return str(data["version"])


def _runtime_version() -> str:
    text = (ROOT / "supervisor" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise SystemExit(
            "supervisor/__init__.py does not define a literal __version__ assignment; "
            "this check needs a statically readable value."
        )
    return match.group(1)


def _skill_version() -> str:
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    # The field is nested under `metadata:`, so leading whitespace is expected.
    match = re.search(r'^\s*version:\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise SystemExit("SKILL.md has no `version:` field under `metadata:`.")
    return match.group(1)


def _citation_version() -> str:
    text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    match = re.search(r"^version:\s*(\S+)", text, re.MULTILINE)
    if match is None:
        raise SystemExit("CITATION.cff has no `version:` field.")
    return match.group(1)


def _changelog_latest() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    releases = CHANGELOG_RELEASE.findall(text)
    if not releases:
        raise SystemExit("CHANGELOG.md has no `## vX.Y.Z` release heading.")

    def key(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split("."))

    return max(releases, key=key)


def main() -> int:
    sources = {
        "pyproject.toml": _pyproject_version(),
        "supervisor/__init__.py (__version__)": _runtime_version(),
        "package.json": _package_json_version(),
        "SKILL.md": _skill_version(),
        "CITATION.cff": _citation_version(),
        "CHANGELOG.md (newest release)": _changelog_latest(),
    }

    print("=== version lockstep ===")
    for source, value in sources.items():
        print(f"  {source:40s} {value}")

    invalid = sorted({v for v in sources.values() if not SEMVER.match(v)})
    if invalid:
        print(f"\nnot a plain semantic version: {invalid}")
        return 1

    unique = sorted(set(sources.values()))
    if len(unique) != 1:
        print(f"\nVERSION DRIFT: {len(unique)} different versions are shipped: {unique}")
        print(
            "Set every one of these to the same value and add a CHANGELOG entry for it. "
            "This check never rewrites a version for you."
        )
        return 1

    print(f"\nall sources agree on {unique[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
