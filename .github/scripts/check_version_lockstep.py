#!/usr/bin/env python3
"""Fail CI when the shipped version is not identical everywhere.

Version drift is silent and expensive: a wheel built from ``pyproject.toml`` can
carry a different version than ``supervisor.__version__``, than the npm
``package.json``, and than the newest entry in ``CHANGELOG.md``. Users then see
three different numbers for one artifact and ``pip`` cannot reason about which
is authoritative.

Two families are checked, because they are two different facts:

* the **shipped tree** family below, which must be exactly identical, and
* the **published version** family — the release number the documents call
  current on PyPI and npm, held by ``docs/check_attestation_claims.py``. That
  one lags the tree on purpose while a release is in flight, so it is checked
  against the changelog instead of against the tree: it must name a real
  release heading and must never be *newer* than the tree. Registering it in the
  equality family would either force a version to be pushed before it is built
  or push the guard's pin out of agreement with the documents it checks.

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


def _changelog_releases() -> list[str]:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return CHANGELOG_RELEASE.findall(text)


def _attestation_guard_pin() -> str:
    """The release number ``docs/check_attestation_claims.py`` calls current.

    Read as text, not imported: ``docs/`` is not an importable package, and a
    regex on a literal assignment is the same contract this script already uses
    for ``SKILL.md`` and ``CITATION.cff``.
    """
    text = (ROOT / "docs" / "check_attestation_claims.py").read_text(encoding="utf-8")
    match = re.search(r'^CURRENT_VERSION = "([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise SystemExit(
            "docs/check_attestation_claims.py does not define a literal "
            "CURRENT_VERSION assignment; this check needs a statically readable value."
        )
    return match.group(1)


def published_version_family(tree_version: str) -> int:
    """Check the published-version family. Returns a process exit code.

    The guard's pin is the version its rules call current on the registries, so
    the invariants are that it names a real release and that it never claims a
    version ahead of what this tree ships. The documents' *agreement* with the
    pin is the guard's own job, run separately in CI.
    """
    pin = _attestation_guard_pin()
    releases = _changelog_releases()
    print("=== published-version family ===")
    print(f"  {'docs/check_attestation_claims.py (CURRENT_VERSION)':40s} {pin}")
    print(f"  {'shipped tree version':40s} {tree_version}")

    problems: list[str] = []
    if not SEMVER.match(pin):
        problems.append(f"not a plain semantic version: {pin!r}")
    if pin not in releases:
        problems.append(
            f"CURRENT_VERSION is {pin}, which is not a '## vX.Y.Z' release heading "
            "in CHANGELOG.md; the guard must pin a release that actually exists"
        )
    if SEMVER.match(pin) and SEMVER.match(tree_version):

        def key(version: str) -> tuple[int, ...]:
            return tuple(int(part) for part in version.split("."))

        if key(pin) > key(tree_version):
            problems.append(
                f"CURRENT_VERSION is {pin}, newer than the shipped tree version "
                f"{tree_version}; the documents cannot call an unreleased version current"
            )
    if problems:
        print("\nPUBLISHED-VERSION DRIFT: " + "; ".join(problems))
        print(
            "Either release the version, or re-point the guard at the newest published "
            "release and update the documents it checks with it. This check never "
            "rewrites a version for you."
        )
        return 1
    if pin == tree_version:
        print(f"\npin {pin} equals the shipped tree version")
    else:
        print(f"\npin {pin} is a released version at or behind {tree_version}")
    return 0


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
    return published_version_family(unique[0])


if __name__ == "__main__":
    raise SystemExit(main())
