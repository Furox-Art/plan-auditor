"""The CLI exit-code contract is one enum, and the docs describe that enum.

The codes were literals scattered through cli.py (48 of them), so a new failure
path could silently re-pick a number and the documented legend would drift out
of sync. These tests pin the contract from both directions: no literal returns
remain in the CLI, and the documented table says exactly what the enum says.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "supervisor" / "cli.py"
DOCS = ROOT / "docs" / "cli.md"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supervisor.exit_codes import ExitCode


def test_cli_uses_enum_not_literal_returns() -> None:
    source = CLI.read_text(encoding="utf-8")
    literals = re.findall(r"^\s*return [0-9]+\s*$", source, re.MULTILINE)
    assert literals == [], f"literal exit codes remain in cli.py: {literals}"
    usage = re.findall(r"return ExitCode\.([A-Z_]+)", source)
    assert usage, "cli.py does not return any ExitCode member"


def test_documented_exit_table_matches_enum() -> None:
    docs = DOCS.read_text(encoding="utf-8")
    table = dict(re.findall(r"\| `([0-9])` \| \*\*(.+?)\*\*", docs))
    assert set(table) == {str(int(member)) for member in ExitCode}, (
        f"docs/cli.md codes {sorted(table)} != enum codes {sorted(int(m) for m in ExitCode)}"
    )
    meaning = {
        ExitCode.VERIFICATION_PASSED: "Proven",
        ExitCode.VERIFICATION_FAILED: "Failed",
        ExitCode.REQUEST_REFUSED: "Blocked",
        ExitCode.UNDETERMINED: "UNKNOWN",
    }
    for member, word in meaning.items():
        assert word.lower() in table[str(int(member))].lower(), (
            f"code {int(member)} documented as {table[str(int(member))]!r}, "
            f"enum reason is {member.reason!r}"
        )


def test_every_code_is_int_and_reachable_by_name() -> None:
    for member in ExitCode:
        assert isinstance(int(member), int)
        assert member.reason, f"{member.name} has no reason text"
        assert ExitCode(member.value) is member
