"""Regression coverage for the supervisor's monkey-patch coupling.

``supervisor/__init__.py`` hardens the registry by reassigning methods on
``MultiAgentRegistry``. ``verify_registry_chain`` and the PID-aware ``_write_lock``
simply do not exist without it, so this is one import away from silently
bypassing the registry integrity chain: nothing calls a missing method, the gate
just stops checking.

Those tests passed before this seam existed, because the coupling was invisible.
Now every call site is explicit about its target, the state is queryable, and a
test proves the real classes were patched by the import the way production does
it — in a fresh interpreter with no test-order dependency. If the install is
removed, moved, or pointed at a second registry class, these fail.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The methods whose absence would silently bypass the registry integrity chain.
REQUIRED_AGENT_METHODS = (
    "verify_registry_chain",
    "register",
    "unregister",
    "heartbeat",
    "update_ownership",
    "active_agents",
    "stale_agents",
    "release_stale_ownership",
    "check_conflicts",
    "claim_files",
    "write_lock",
    "is_lock_stale",
)

REQUIRED_LOCK_ATTRIBUTES = ("_write_lock",)


def _state_in_fresh_interpreter() -> dict[str, dict]:
    """Ask a clean interpreter what ``import supervisor`` patched onto."""
    script = "import json, supervisor\nprint(json.dumps(supervisor.supervisor_integrity_state()))\n"
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    payload = proc.stdout.strip().splitlines()[-1]
    import json

    return json.loads(payload)


def test_importing_supervisor_hardens_the_real_runtime_classes() -> None:
    """The import-time install must land on the classes production actually uses."""
    state = _state_in_fresh_interpreter()

    registry = state["agent_registry"]
    assert registry["installed"] is True, registry
    assert registry["target"] == "supervisor.agents.MultiAgentRegistry", registry
    missing = [name for name in REQUIRED_AGENT_METHODS if registry.get(name) is not True]
    assert not missing, (
        "importing supervisor left these hardeners uninstalled on the runtime "
        f"registry class: {missing}; the registry integrity chain would be bypassed"
    )

    lock = state["registry_lock"]
    assert lock["installed"] is True, lock
    assert lock["target"] == "supervisor.agents.MultiAgentRegistry", lock
    missing = [name for name in REQUIRED_LOCK_ATTRIBUTES if lock.get(name) is not True]
    assert not missing, f"the PID-aware write lock was not installed: {missing}"


def test_installing_onto_an_explicit_target_does_not_touch_the_shared_class() -> None:
    """The seam: a caller with its own registry class hardens only that one."""
    from supervisor.agents_hardening import agent_hardening_state, install_agent_hardening
    from supervisor.lock_hardening import install_registry_lock_hardening

    before = agent_hardening_state()

    class StubRegistry:
        """A throwaway target that stands in for the real runtime class."""

        def write_lock(self, agent_id):
            raise AssertionError("stub write_lock should have been replaced")

    try:
        install_agent_hardening(StubRegistry)
        install_registry_lock_hardening(StubRegistry)
    except TypeError:
        # The hardeners are written against the runtime class's attributes; a
        # bare stub is only required to accept the assignments.
        raise AssertionError(
            "the installers no longer accept an explicit target, so a caller "
            "cannot control which class it hardens"
        )

    stub = agent_hardening_state(StubRegistry)
    assert stub["installed"] is True
    assert stub["target"].endswith("StubRegistry"), stub
    for name in REQUIRED_AGENT_METHODS:
        assert stub[name] is True, name
        assert getattr(StubRegistry, name) is not None

    # The shared runtime class must be untouched by a stub install.
    after = agent_hardening_state()
    assert after == before


def test_installing_twice_is_idempotent() -> None:
    """A repeated install must not re-wrap or shadow a hardener."""
    from supervisor.agents_hardening import agent_hardening_state, install_agent_hardening
    from supervisor.lock_hardening import (
        install_registry_lock_hardening,
        registry_lock_hardening_state,
    )

    before = (agent_hardening_state(), registry_lock_hardening_state())
    install_agent_hardening()
    install_registry_lock_hardening()
    after = (agent_hardening_state(), registry_lock_hardening_state())
    assert before == after, "a second install changed the reported hardener state"
    assert after[0]["installed"] is True
    assert after[1]["installed"] is True


def test_the_reported_hardener_names_are_the_real_methods() -> None:
    """``agent_hardening_state`` must not report a name the class does not have."""
    from supervisor import supervisor_integrity_state

    state = supervisor_integrity_state()
    assert set(state) == {"agent_registry", "registry_lock"}
    for name in REQUIRED_AGENT_METHODS:
        assert state["agent_registry"][name] is True, name
