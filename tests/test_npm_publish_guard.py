"""npm may only publish the content that the version bump released.

npm 2.6.3 is the proof. The version was tagged on 2026-10-21 and PyPI 2.6.3 was
built from that tag, but the npm tarball was published from a later main commit
(30408d8): ``supervisor/sealing.py`` carried the strict seal parsing from #70
and #62, and the README described an npm state that only made sense before the
release. 13 of the 70 packed files differed from the tag, so the two registries
served different bytes as "2.6.3".

npm versions are immutable, so guarding after the upload is worthless. Once the
already-published gate has decided there is something to upload, the publish job
compares every packed file against the commit that introduced the version and
refuses to continue when they differ.
"""
from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "npm-publish.yml"


def test_guard_runs_only_for_unpublished_versions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    gate = text.index("Refuse to publish a version that already exists")
    guard = text.index("Refuse to publish content newer than the version bump")
    assert gate < guard
    assert "if: steps.gate.outputs.skip != 'true'\n" in text[guard:]


def test_guard_is_checked_before_publishing() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    guard = text.index("Refuse to publish content newer than the version bump")
    assert guard < text.index("run: npm publish --access public --provenance")
    assert guard < text.index("run: npm publish --access public\n")


def test_guard_compares_packed_files_against_the_version_bump() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert '"rev-list", "--first-parent", "HEAD"' in text
    assert '"pack", "--dry-run", "--json"' in text
    assert "packed files differ from" in text
    assert "Bump the version and release the new content instead." in text


def test_publish_checkout_keeps_history_for_the_guard() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    checkout = text.index("actions/checkout@", text.index("id-token: write"))
    guard = text.index("Refuse to publish content newer than the version bump")
    assert "fetch-depth: 0" in text[checkout:guard]
