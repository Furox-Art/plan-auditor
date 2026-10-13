"""Plan Auditor — AI Agent Verification Supervisor."""
__version__ = "2.6.1"

# The registry hardeners are monkey-patched onto the runtime classes. That is
# load-bearing: the registry integrity chain and the PID-aware write lock only
# exist because of it, and the install happens as an import-time side effect of
# *this* module so no submodule can be imported unhardened. It is done once,
# here, in one place, and ``supervisor_integrity_state`` names exactly what was
# patched onto which class, so a refactor that skips or duplicates the install
# is visible instead of silently bypassing the registry chain.
from .adversarial import run_adversarial_review
from .agents import Agent, MultiAgentRegistry
from .agents_hardening import agent_hardening_state, install_agent_hardening
from .config import Config, Profile, Tier, load_config
from .evidence import verify_anchor_chain
from .gate import CompletionGate, CompletionReport
from .lifecycle import States, TaskLifecycle
from .lock_hardening import install_registry_lock_hardening, registry_lock_hardening_state
from .orchestrator import evaluate_workspace, fresh_full_audit_proof
from .plan_verifier import verify_plan
from .requirements import Requirement, parse_requirements
from .sealing import Seal, check_monotonic, seal_plan
from .watchdog import Watchdog
from .workspace import WorkspaceState, capture_workspace
from .cli import main

install_agent_hardening()
install_registry_lock_hardening()

def supervisor_integrity_state() -> dict[str, dict[str, object]]:
    """Report every runtime class that was patched, and what it received."""
    return {
        "agent_registry": agent_hardening_state(),
        "registry_lock": registry_lock_hardening_state(),
    }


__all__ = [
    "Config", "Profile", "Tier", "load_config",
    "Requirement", "parse_requirements",
    "WorkspaceState", "capture_workspace", "verify_plan",
    "CompletionGate", "CompletionReport",
    "Agent", "MultiAgentRegistry", "verify_anchor_chain",
    "run_adversarial_review", "States", "TaskLifecycle",
    "Seal", "seal_plan", "check_monotonic", "Watchdog",
    "evaluate_workspace", "fresh_full_audit_proof",
    "supervisor_integrity_state",
    "main", "__version__",
]
