# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)

**A strict plan + independent auditor workflow as an [Agent Skill](https://agentskills.io).**

AI coding agents routinely leave work half-done or claim "done" when it isn't. Root cause: no explicit, machine-checkable plan, and nobody verifying the claims. **plan-auditor** fixes both:

1. **Planner** — turns a task into a plan file where every step has machine-checkable done criteria (commands, exit codes, file existence, regex, pytest).
2. **Independent auditor** — a deterministic Python script that tests the agent's work with real command output. It never trusts the agent's own report.

## The strictness rules

- **No evidence = not done.** A step is `verified` only when the auditor script passes all of its checks.
- **The agent is a judge that can only downgrade.** If the agent suspects a step despite passing checks, it must *add a stricter check and re-run* — it can never relax a failed check into a pass.
- **Unverifiable = failed.**
- **Append-only evidence log** with a SHA-256 hash chain — editing history is detected (`exit 2`).
- **Final audit gate.** The task is finished only when `audit` re-verifies *every* step in fresh shells and exits 0.

## What's in the box

```
SKILL.md                  # agent-facing workflow (the skill)
references/plan-format.md # plan.json schema
scripts/audit_check.py    # the independent auditor (stdlib-only, no deps)
scripts/stop_gate.py      # optional Stop-hook gate for Command Code
tests/                    # unit test suite for the auditor itself
examples/fib/             # worked example: fibonacci task
```

`audit_check.py` uses only the Python standard library — no pip installs. The repo **dogfoods**: its own `.plan-auditor/plan.json` verifies the test suite on every push via the `plan-audit gate` workflow.

## Install

One skill package, every agent: copy the `plan-auditor/` folder into the skills directory of whichever tool you use. No config, no build — the folder is the install.

| Tool | User-level path (every project) | Project-level path | Invoke |
|---|---|---|---|
| **Command Code** | `~/.commandcode/skills/plan-auditor/` | `.commandcode/skills/plan-auditor/` | `/plan-auditor <task>` |
| **Claude Code** | `~/.claude/skills/plan-auditor/` | `.claude/skills/plan-auditor/` | `/plan-auditor <task>` |
| **Codex CLI** | `~/.codex/skills/plan-auditor/` | `.codex/skills/plan-auditor/` | `$plan-auditor <task>` (auto-loads by description, `/skills` to verify) |
| **OpenCode** | `~/.config/opencode/skills/plan-auditor/` | `.opencode/skills/plan-auditor/` | `/plan-auditor <task>` (auto-loads by description) |
| **Cursor** | `~/.cursor/skills/plan-auditor/` (or `.agents/skills/`) | `.cursor/skills/plan-auditor/` | `/plan-auditor` (Cursor also reads `.claude`/`.codex` skill dirs) |
| **Grok Build** | `~/.grok/skills/plan-auditor/` | `.grok/skills/plan-auditor/` | auto-loads by description (also reads Claude/Cursor dirs) |

The same `SKILL.md` works everywhere — it follows the [Agent Skills](https://agentskills.io) standard. See [`docs/integrations.md`](docs/integrations.md) for optional extras (e.g. an unskippable Stop-hook gate for Command Code).

## Usage

Invoke the skill with a task (`/plan-auditor "build the login form"`). The agent then:

1. Writes `<project>/.plan-auditor/plan.json` — steps with concrete `verify` checks.
2. Works the steps one at a time, running the auditor after each:

   ```bash
   python <skill-dir>/scripts/audit_check.py run <project-dir>
   ```

3. Finishes only after a full re-verification:

   ```bash
   python <skill-dir>/scripts/audit_check.py audit <project-dir>
   ```

Extras (v1.1):
- **Hard attempt cap** — a step that failed 3 times is refused on the 4th `run`; the agent must escalate to the user (or pass `--force` explicitly).
- **Multi-plan** — `--plan <name>` runs parallel plans from `.plan-auditor/plans/<name>.json`.
- **Snapshot / rollback** — `snapshot` archives the plan's `snapshot` file list (or `git ls-files`); `rollback` restores the latest snapshot.

### Auditor modes & exit codes

| Mode | What it does | Exit |
|---|---|---|
| `validate <dir>` | validate plan.json schema | 0 / 1 |
| `run <dir> [ids...]` | audit pending (or given) steps, append evidence | 0 if all passed, 1 otherwise |
| `audit <dir>` | re-verify **all** steps in fresh shells (final gate) | 0 / 1 |
| `status <dir>` | print the step table without running anything | 0 / 2 |
| any mode | evidence hash chain broken (tampering) | **2** |

### Check types

| Type | Fields | Meaning |
|---|---|---|
| `run` | `cmd`, `expect_exit` (default 0), `output_regex` (opt) | run in a fresh shell; exit code (and optional output regex) must match |
| `file_exists` | `path` | file must exist |
| `regex` | `path`, `pattern` | file content must match the regex |
| `pytest` | `args` (opt) | `python -m pytest <args>` must exit 0 |

## Why a script and not just "an auditor prompt"?

Because an LLM auditing its own work with prose can hallucinate a pass. The evidence engine here is deterministic code: subprocess exit codes, file system facts, regex matches, pytest results. The LLM's judgment can only *tighten* the gate, never loosen it.

## Example

See [`examples/fib/`](examples/fib/) — a two-step plan (write `fib`, pass pytest) with the full negative/partial/positive test flow.

## License

MIT
