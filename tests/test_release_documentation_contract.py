"""Protect release-facing documentation and runnable contributor commands from drift.

All checks use repository files only: never claim that CI verified public registry state.
The live registry version and attestation must still be measured for each release.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _guard_pin() -> str:
    match = re.search(
        r'^CURRENT_VERSION\s*=\s*"([^"]+)"',
        _text("docs/check_attestation_claims.py"),
        re.MULTILINE,
    )
    assert match, "supply-chain guard needs a literal current release"
    return match.group(1)


def test_current_release_documents_agree_with_registry_guard_pin() -> None:
    version = _guard_pin()
    assert f"**Release status (verified 2026-10-13):** `{version}`" in _text("README.md")
    security = _text("SECURITY.md")
    assert security.count(f"`{version}` is the current verified release") == 2
    assert f"**`{version}` is published on both PyPI and npm**" in _text(
        "docs/release-status.md"
    )


def test_claimed_current_release_has_verifiable_registry_urls() -> None:
    version = _guard_pin()
    documentation = _text("docs/release-status.md")
    assert (
        f"https://pypi.org/integrity/plan-auditor/{version}/"
        f"plan_auditor-{version}-py3-none-any.whl/provenance"
    ) in documentation
    assert (
        f"https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@{version}"
    ) in documentation
    assert "2026-10-13" in documentation
    assert "Historical verified artifact checks (2.4.3" in documentation


def test_every_documented_npm_run_script_actually_exists() -> None:
    scripts = json.loads(_text("package.json"))["scripts"]
    for path in ("CONTRIBUTING.md", "docs/benchmark.md"):
        for name in re.findall(r"\bnpm run (test:[a-z:-]+)", _text(path)):
            assert name in scripts, f"{path} references removed npm script {name}"
    assert "test:tarball" not in scripts
    assert "test:installed" not in scripts


def test_current_release_sources_do_not_call_historical_version_current() -> None:
    for path in ("README.md", "SECURITY.md", "docs/release-status.md"):
        text = _text(path).lower()
        for match in re.finditer(r"2\.4\.3", text):
            local = text[max(0, match.start() - 100):match.end() + 100]
            assert not re.search(
                r"2\.4\.3.{0,32}\b(?:is|as)\s+(?:the\s+)?current\b", local
            ), f"{path}: historical version is still labeled current"
