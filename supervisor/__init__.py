"""Plan Auditor — AI Agent Verification Supervisor."""
__version__ = "2.1.0"

from .adversarial import run_adversarial_review
from .agents import Agent, MultiAgentRegistry
from .agents_hardening import install_agent_hardening
from .config import Config, Profile, Tier, load_config
from .evidence import verify_anchor_chain
from .gate import CompletionGate, CompletionReport
from .lifecycle import States, TaskLifecycle
from .orchestrator import evaluate_workspace, fresh_full_audit_proof
from .plan_verifier import verify_plan
from .requirements import Requirement, parse_requirements
from .sealing import Seal, check_monotonic, seal_plan
from .watchdog import Watchdog
from .workspace import WorkspaceState, capture_workspace
from .cli import main

install_agent_hardening()

__all__ = [
    "Config", "Profile", "Tier", "load_config",
    "Requirement", "parse_requirements",
    "WorkspaceState", "capture_workspace", "verify_plan",
    "CompletionGate", "CompletionReport",
    "Agent", "MultiAgentRegistry", "verify_anchor_chain",
    "run_adversarial_review", "States", "TaskLifecycle",
    "Seal", "seal_plan", "check_monotonic", "Watchdog",
    "evaluate_workspace", "fresh_full_audit_proof",
    "main", "__version__",
]
