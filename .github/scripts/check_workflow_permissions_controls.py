"""Negative controls for the permission checks in check_workflows.py.

A guard that cannot fail is not a guard. Each control below breaks one workflow
in one specific way, asserts the checker rejects it, then restores the file.

Run:  python .github/scripts/check_workflow_permissions_controls.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / ".github" / "scripts" / "check_workflows.py"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

# (label, find, replace, substring the failure message must contain)
CONTROLS = [
    (
        "release job loses contents: write (the original defect)",
        "  github-release:\n    name: create GitHub release\n    needs: [publish]\n"
        "    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n",
        "  github-release:\n    name: create GitHub release\n    needs: [publish]\n"
        "    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n",
        "creates or updates a tag or release",
    ),
    (
        # Proves the check is not keyed to one job name: any job, any name.
        "a differently-named job gains a release step without permission",
        "  wheel-preflight:\n",
        "  rogue-release:\n"
        "    name: a job nobody audited\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - name: Create GitHub release\n"
        "        uses: softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2\n"
        "  wheel-preflight:\n",
        "job rogue-release",
    ),
    (
        "publish job gains contents: write (widened least privilege)",
        "    permissions:\n      # id-token is what mints the OIDC attestation PyPI trusts.\n"
        "      id-token: write\n      contents: read\n",
        "    permissions:\n      # id-token is what mints the OIDC attestation PyPI trusts.\n"
        "      id-token: write\n      contents: write\n",
        "mints an OIDC attestation but is also granted write scope",
    ),
    (
        "github-release action unpinned to a full SHA",
        "uses: softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2",
        "uses: softprops/action-gh-release@v2",
        "not pinned to a full 40-character commit SHA",
    ),
]


def run_checker() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(CHECKER)],
        capture_output=True,
        encoding="utf-8",
        cwd=ROOT,
    )
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    original = RELEASE.read_text(encoding="utf-8")
    failures = 0

    code, output = run_checker()
    print("=== control 0: unmodified tree must PASS ===")
    if code != 0:
        failures += 1
        print(f"    FAIL exit={code}")
        print(output.strip()[-600:])
    else:
        print("    PASS exit=0")

    for label, find, replace, expected in CONTROLS:
        if original.count(find) != 1:
            failures += 1
            print(f"=== {label} ===")
            print(f"    FAIL control did not match the file ({original.count(find)}x)")
            continue

        mutated = original.replace(find, replace)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", delete=False, encoding="utf-8", newline=""
        ) as handle:
            handle.write(mutated)
            backup = Path(handle.name)

        try:
            RELEASE.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8", newline="")
            code, output = run_checker()
            detected = code != 0 and expected in output
            print(f"=== {label} (must FAIL) ===")
            if detected:
                print(f"    PASS exit={code}, reported: {expected!r}")
            else:
                failures += 1
                print(f"    FAIL exit={code}, expected {expected!r} in the output")
                print(output.strip()[-600:])
        finally:
            RELEASE.write_text(original, encoding="utf-8", newline="")
            backup.unlink(missing_ok=True)

    code, _ = run_checker()
    print("=== restored tree must PASS again ===")
    if code != 0:
        failures += 1
        print(f"    FAIL exit={code}")
    else:
        print("    PASS exit=0")

    print(f"\nworkflow permission controls: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())