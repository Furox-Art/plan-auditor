"""Shared fixture helper that establishes plan trust the documented way.

A plan JSON is untrusted input; the CLI refuses to execute its checks until a
format-v4 seal authorises it and an activated request contract is bound to that
seal. Tests that drive the CLI therefore have to perform the same trust flow a
real user performs::

    plan-auditor request init . --file <request-source.json>
    plan-auditor plan verify .

Keeping this in one place means the fixtures cannot drift back into the
unsealed-execution path the security gate exists to close.
"""
from __future__ import annotations
import json
from pathlib import Path

from tests.request_fixture import activate_for_plan


def load_plan(workspace: Path) -> dict:
    return json.loads((workspace / ".plan-auditor" / "plan.json").read_text(encoding="utf-8"))


def establish_trust(workspace: Path) -> None:
    """Activate a request contract and seal the plan, as a user must."""
    # Imported lazily so merely collecting this module does not pull the runtime
    # packages in before the suite starts measuring them.
    from supervisor.cli import main as cli_main

    plan = load_plan(workspace)
    activate_for_plan(workspace, plan)
    rc = cli_main(["plan", "verify", str(workspace)])
    assert rc == 0, f"plan verify must succeed to establish trust (rc={rc})"