"""Installed console-script metadata regression coverage."""
from __future__ import annotations

from importlib import metadata


def test_all_runtime_console_scripts_are_installed():
    entries = {
        entry.name: entry.value
        for entry in metadata.entry_points(group="console_scripts")
        if entry.name.startswith("plan-auditor")
    }
    assert entries["plan-auditor"] == "supervisor.cli:entrypoint"
    assert entries["plan-auditor-migrate-seal"] == "supervisor.seal_migration:main"
    assert entries["plan-auditor-formal"] == "supervisor.formal_planning:main"
    assert entries["plan-auditor-formalize"] == "supervisor.formal_compiler:main"
