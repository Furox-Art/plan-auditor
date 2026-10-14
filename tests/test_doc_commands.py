"""Every command named in the docs is a command the CLI actually exposes.

The docs quote verification flows end-to-end. When a subcommand was renamed or
a nested subcommand was documented without its parent, the flow silently became
fiction and readers were instructed to run a command that exits with
"invalid choice". This parses the documented commands (including two-word
nested forms) and the parser's full recursive subcommand tree, and fails on the
gap. URLs like `plan-auditor/blob/main/...` are not commands and are excluded.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOCS = [
    ROOT / "docs" / "benchmark.md",
    ROOT / "docs" / "cli.md",
    ROOT / "README.md",
]

#: Verbs of the dependency-free core (`python scripts/audit_check.py <verb>`).
CORE_VERBS = {"audit", "run", "validate", "verify", "version", "help", "completion"}


def _all_subcommand_names(parser) -> set[str]:
    """Every subcommand name at any nesting level."""
    names: set[str] = set()
    subparsers = getattr(parser, "_subparsers", None)
    if subparsers is None:
        return names
    for action in subparsers._group_actions:
        for name, sub in (action.choices or {}).items():
            names.add(name)
            names |= _all_subcommand_names(sub)
    return names


def _real_subcommands() -> set[str]:
    from supervisor.cli import _build_parser

    return _all_subcommand_names(_build_parser())


def _documented_commands(paths) -> set[str]:
    found = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"plan-auditor ([\w-]+)(?: ([\w-]+))?", text):
            first, second = match.group(1), match.group(2)
            # `plan-auditor/blob/...` is a URL path, not a command line.
            if first.startswith("/") or text[match.start(): match.start()+20].lstrip("plan-auditor ").startswith("/"):
                continue
            found.add(first)
            if second:
                found.add(second)
        for match in re.finditer(r"audit_check\.py ([\w-]+)", text):
            found.add(match.group(1))
    return found


def test_documented_commands_exist() -> None:
    subs = _real_subcommands()
    documented = _documented_commands(DOCS)
    unknown = {c for c in documented if c not in subs and c not in CORE_VERBS}
    assert not unknown, (
        f"docs name commands the CLI does not expose: {sorted(unknown)}; "
        f"real subcommands: {sorted(subs)}"
    )


def test_core_entry_point_documents_the_gate() -> None:
    """benchmark.md must present the authenticated-evidence flow.

    The 2.5.0 gate means a benchmark claim in a keyless workspace is void; the
    document must therefore name the HMAC setup and the key variable.
    """
    text = (ROOT / "docs" / "benchmark.md").read_text(encoding="utf-8")
    assert "integrity init" in text, "benchmark.md omits the HMAC setup step"
    assert "PLAN_AUDITOR_HMAC_KEY" in text, (
        "benchmark.md does not mention the HMAC environment variable"
    )
