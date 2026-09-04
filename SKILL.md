---
name: plan-auditor
description: Strict plan + independent auditor workflow — turns a task into machine-verifiable steps, tests every step with real command evidence (never trusting the agent's own "done" claim), and only treats the task as finished when the full audit passes. Use when the user asks to build/implement/fix something non-trivial, says "plan it", "audit it", "don't leave it half-done", "did you actually do it", or invokes /plan-auditor.
argument-hint: "<task description>"
metadata:
  version: "1.1.0"
---

# Plan-Auditor: Strict Plan + Independent Auditor

You play TWO roles in this workflow and never mix them:
- **Planner:** break the task into measurable steps.
- **Auditor:** test every step with evidence — never trust your own narration, memory, or "I did it" claim; trust only command output.

## Strict rules (no exceptions)

1. **No evidence = not done.** A step is `verified` only when the auditor script passes all its checks.
2. **Judge can only downgrade.** Even if checks pass, if you believe the work is actually wrong, do not treat `verified` as valid — add a stricter check and re-run the script. You can never turn a failed check into a pass.
3. **Unverifiable = failed.** A step with no reproducible evidence is `failed`.
4. **Log is append-only.** `evidence.jsonl` and its `hash` chain are never edited by hand; nothing outside the script may write to the log.
5. **Check specification lock.** Once work begins, weakening the `verify` lists inside `plan.json` is forbidden; you may only ADD new/stricter checks.
6. **Full audit gate.** Before saying "done", `audit` mode must exit 0. Never finish without it.

## Files

- Plan: `<project>/.plan-auditor/plan.json` (format: `references/plan-format.md`)
- Evidence: `<project>/.plan-auditor/evidence.jsonl` (written by script, append-only, hash-chained)
- Auditor script: `scripts/audit_check.py` inside this skill directory

Always call the script RELATIVE to the skill directory — the folder containing this `SKILL.md` is `<skill-dizini>`; the full path changes per install:

```
python <skill-dizin>/scripts/audit_check.py <mode> <project-dir> [id id ...]
```

Modes: `validate` (schema check) · `run` (audit pending — or given ids like `run <dir> 1 2` — steps) · `audit` (re-verify ALL steps, final gate) · `status` (table, no execution) · `snapshot` / `rollback` (capture / restore a file snapshot). Directory name comes BEFORE ids.

Extra options: `--plan <name>` (multi-plan: `.plan-auditor/plans/<name>.json`; default `plan.json`) · `run --force` (force past the 3-attempt limit — exceptional case, user asked).

## Workflow

### 1. PLAN
- Take the task, write `<project>/.plan-auditor/plan.json` per the schema in `references/plan-format.md`.
- Every step's `verify` list must be CONCRETE and machine-executable: command + expected exit code, file existence, regex, pytest. NO vague criteria like "works correctly".
- When starting a new task, if an old plan exists: archive it to `.plan-auditor/archive/<date>-<slug>.json` if its work is done; if STILL active, keep the new task in a separate file via `--plan <name>`.
- Run `validate`; fix errors and re-run. Summarize the plan to the user.

### 2. EXECUTE + PROVE AFTER EACH STEP + RECOVERY LOOP
- Do steps in order. The moment a step's work is done, run `run <id>`.
- If not `verified`: the step is not finished. Recovery loop:
  1. Diagnose from the FAILED lines in the evidence output (which check, why it fell).
  2. Fix the root cause (not the symptom — if a test passes trivially, FIX the product, never weaken the test).
  3. Re-run `run <id>` for the same step.
- At most **3 recovery attempts per step**. After 3, if still not `verified`, STOP: report to the user with evidence output and ask how to proceed. Never pass by weakening a check, skipping a step, or saying "good enough".
- Advance to the next step only after the previous is `verified`.

### 3. FULL AUDIT
- After all steps are `verified`, run `audit` (re-tests everything in fresh shells).
- If exit is not 0, continue from the report: which step fell why, fix, re-run audit.

### 4. REPORT
- Report as a table: step, check count, status, evidence summary (quotes from command output).
- Do not say "I did it"; say "audit passed, evidence is: ...".

## Mandatory enforcement (hook)

If the user wired this skill's `scripts/stop_gate.py` into Command Code's `Stop` hook: while an active plan has an unverified step, the turn CANNOT close — the hook exits 2 and sends you back to the audit. This is a non-skippable layer; do not rely on the hook's absence but do not contradict it when present. For polyglot checks use the `exec` type: the user's compiled binary (C++/Rust/Java/jar) enters the plan as `{"type": "exec", "cmd": "..."}`; exit code counts as evidence.

## Example

Task: "write fibonacci in fib.py, with a test."

```json
{
  "task": "fibonacci function and test in fib.py",
  "created": "2026-09-03T12:00:00",
  "steps": [
    {
      "id": 1,
      "title": "write fib function",
      "verify": [
        {"type": "file_exists", "path": "fib.py"},
        {"type": "regex", "path": "fib.py", "pattern": "def\\s+fib\\s*\\("},
        {"type": "run", "cmd": "python -c \"from fib import fib; assert fib(10)==55\"", "expect_exit": 0}
      ],
      "status": "pending"
    },
    {
      "id": 2,
      "title": "write and pass pytest",
      "verify": [
        {"type": "pytest", "args": "test_fib.py -q"}
      ],
      "status": "pending"
    }
  ]
}
```

Then: do the steps → `run` after each → `audit` at the end → report with the table.
