# Integrations & optional enforcement

plan-auditor is a plain Agent Skill package: a `SKILL.md` plus scripts. It installs by copying the folder — nothing else. This document records the install paths per tool and the *optional* enforcement layer for tools that support blocking hooks.

## Skill package install paths (verified)

| Tool | User-level path | Project-level path | Invocation |
|---|---|---|---|
| Command Code | `~/.commandcode/skills/plan-auditor/` | `.commandcode/skills/plan-auditor/` | `/plan-auditor` (also auto-loads by description) |
| Claude Code | `~/.claude/skills/plan-auditor/` | `.claude/skills/plan-auditor/` | `/plan-auditor` |
| Codex CLI | `~/.codex/skills/plan-auditor/` | `.codex/skills/plan-auditor/` | `$plan-auditor`; auto-loads by description; verify with `/skills` |
| OpenCode | `~/.config/opencode/skills/plan-auditor/` | `.opencode/skills/plan-auditor/` | `/plan-auditor`; auto-loads by description |

Notes:
- `SKILL.md` follows the open [agentskills.io](https://agentskills.io) standard; the same file works in all of the above without modification.
- Codex additionally accepts an optional `openai.yaml` per skill for Codex-specific metadata — not required here.
- After copying, start a **new** session; skills are discovered at startup.

## What each tool can and cannot enforce

| Tool | Can it block turn-end with an incomplete plan? | Mechanism |
|---|---|---|
| Command Code | **Yes** | `Stop` hook (`scripts/stop_gate.py`) — wired in the user's `~/.commandcode/settings.json`; exit 2 retries the turn, capped at 3 by the engine |
| Claude Code | Yes (equivalent `Stop` hook exists) | Port the same settings.json pattern to `.claude/settings.json` |
| Codex CLI | No blocking hook exposed | `notify` hook is notification-only; the skill's own workflow (final `audit` exit 0) is the gate |
| OpenCode | No blocking hook exposed | Plugin hooks can inject context into tool output (`scripts/opencode_plugin.js`, optional) but cannot block turn-end |

## Optional: unskippable gate for Command Code

`~/.commandcode/settings.json`:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"C:\\Users\\<you>\\.commandcode\\skills\\plan-auditor\\scripts\\stop_gate.py\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Behavior: at turn end, if `<project>/.plan-auditor/plan.json` exists and any step is not `verified`, the turn is blocked and the model is told to run the auditor. Projects without an active plan are never touched. Hooks load at session start, so restart after changing settings.

## Optional: OpenCode context-injection plugin

`scripts/opencode_plugin.js` is a non-required OpenCode plugin: after every tool call it runs `audit_check.py status` (10 s cache) and, if the plan is incomplete, appends a reminder to the tool output the model sees. Install by copying to `~/.config/opencode/plugins/plan-auditor.js` and restarting OpenCode. It nudges, it does not block.
