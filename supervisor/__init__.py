"""Plan Auditor — AI Agent Verification Supervisor."""
__version__ = "2.0.1"

from .requirements import Requirement, parse_requirements
from .workspace import WorkspaceState, capture_workspace
from .plan_verifier import verify_plan
from .gate import CompletionGate, CompletionReport
from .agents import Agent, MultiAgentRegistry
from .evidence import verify_anchor_chain
from .adversarial import run_adversarial_review
from .lifecycle import States, TaskLifecycle
from .sealing import Seal, seal_plan, check_monotonic
from .watchdog import Watchdog
from .orchestrator import evaluate_workspace, fresh_full_audit_proof
from .cli import main

__all__ = [
    "Requirement", "parse_requirements",
    "WorkspaceState", "capture_workspace", "verify_plan",
    "CompletionGate", "CompletionReport",
    "Agent", "MultiAgentRegistry", "verify_anchor_chain",
    "run_adversarial_review", "States", "TaskLifecycle",
    "Seal", "seal_plan", "check_monotonic", "Watchdog",
    "evaluate_workspace", "fresh_full_audit_proof",
    "main", "__version__",
]
