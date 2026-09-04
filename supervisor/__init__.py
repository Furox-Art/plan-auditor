"""Plan Auditor — AI Agent Verification Supervisor (v2.0).

Local-first, multi-layered, independent verification supervisor for
AI coding agents. Supports parallel / concurrent agents.

Public entry points:
    supervisor.events        L0 pattern/event detection
    supervisor.config        Profile/tier configuration
"""
__version__ = "2.0.0"

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
from .cli import main

__all__ = [
    "Profile",
    "Tier",
    "Config",
    "load_config",
    "Event",
    "EventBus",
    "PatternRule",
    "DEFAULT_RULES",
    "Requirement",
    "parse_requirements",
    "WorkspaceState",
    "capture_workspace",
    "verify_plan",
    "CompletionGate",
    "CompletionReport",
    "Agent",
    "MultiAgentRegistry",
    "verify_anchor_chain",
    "run_adversarial_review",
    "States",
    "TaskLifecycle",
    "Seal",
    "seal_plan",
    "check_monotonic",
    "Watchdog",
    "main",
    "__version__",
]

