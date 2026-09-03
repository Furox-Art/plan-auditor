# Contributing

## Rules of the game

1. **The auditor never trusts the agent.** Any change that lets an LLM claim upgrade a failed or missing evidence into a pass is rejected by design. The LLM's judgment may only *tighten* (add stricter checks, downgrade `verified`), never loosen.
2. **Evidence is append-only.** The SHA-256 hash chain in `evidence.jsonl` is sacred. PRs that allow editing or reordering past records will be declined.
3. **Unverifiable = failed.** Every step needs at least one behavioral check (`run`, `pytest`, or `exec`). File existence or regex alone can never verify a step.
4. **Stdlib only.** `scripts/audit_check.py` must stay dependency-free (Python standard library) so the skill stays plug-and-play everywhere.

## Dev workflow

```bash
python -m pytest tests/ -q          # unit suite
python scripts/audit_check.py audit .   # self-audit gate (CI runs this too)
```

- New check types: add to `CHECK_TYPES`, handle in `run_check`, document in `references/plan-format.md`, add tests.
- New modes: follow the existing `cmd_*` pattern, keep exit codes (0 pass / 1 fail / 2 tamper).
- This repo dogfoods: keep `.plan-auditor/plan.json` accurate — CI enforces it on every push.
