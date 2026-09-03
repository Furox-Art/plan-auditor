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

Copy (or symlink) the skill directory into any Agent-Skills-compatible tool:

```bash
# Command Code (user scope, every project)
cp -r plan-auditor ~/.commandcode/skills/plan-auditor

# Claude Code
cp -r plan-auditor ~/.claude/skills/plan-auditor
```

Or point your agent at the skill and let it follow `SKILL.md`.

## Usage

Invoke the skill with a task (`/plan-auditor "build the login form"`). The agent then:

1. Writes `<project>/.plan-auditor/plan.json` — steps with concrete `verify` checks.
2. Works the steps one at a time, running the auditor after each:

   ```bash
   python ~/.commandcode/skills/plan-auditor/scripts/audit_check.py run <project-dir>
   ```

3. Finishes only after a full re-verification:

   ```bash
   python ~/.commandcode/skills/plan-auditor/scripts/audit_check.py audit <project-dir>
   ```

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
