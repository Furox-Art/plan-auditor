<!--
Thanks for contributing. This project is maintained by one person with no external
contributors yet, so a well-scoped pull request is genuinely welcome.

Before you write code, read the five rules in CONTRIBUTING.md. The hardest one:
a change that lets a language-model judgement upgrade a failed or missing
evidence into a pass will be rejected by design, and the test suite enforces it.
-->

## What this changes

<!-- One paragraph. What is different after this merges, and for whom. -->

Closes #

## Area

- [ ] Deterministic core (`scripts/audit_check.py`) — the only thing that can set `verified`
- [ ] Supervisor layer (`supervisor/`) or CLI
- [ ] Skill definition (`SKILL.md`) or hook (`hooks/`)
- [ ] Packaging or release process (`pyproject.toml`, `package.json`, `.github/workflows/`)
- [ ] Documentation (`README.md`, `docs/`, `CHANGELOG.md`)
- [ ] Governance (`SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`)

## Trust properties

Tick what this change preserves. If none apply, explain in prose why the property
still holds — a pull request that cannot answer this will not be reviewed.

- [ ] It cannot turn a missing or failed check into a pass.
- [ ] It does not let a model judgement weaken a deterministic verdict.
- [ ] It does not allow editing or reordering past `evidence.jsonl` records.
- [ ] `scripts/audit_check.py` remains standard library only.
- [ ] New or unavailable evidence fails closed rather than defaulting to success.
- [ ] Not applicable — no behaviour changed.

## Evidence

This is the part that matters most in this repository. What proves the change is
correct, beyond the test suite?

<!--
Paste the command and its real output. A failing-check demo, a seal-violation
demo, or an exit-code comparison. If the change is documentation-only, say which
test proves the documentation is true — for example that a transcript line is
regenerated from a real run.
-->

```

```

## Checks run

Paste the results, including exit codes.

- [ ] `python -m pytest tests/ -q`
- [ ] `python -m pytest examples/fib/test_fib.py -q`
- [ ] `npm test` (if `index.js`, `package.json` or `bin/` changed)
- [ ] `python -m mkdocs build --strict` (if anything under `docs/` changed)
- [ ] `plan-auditor audit .` — the repository's own plan still passes
- [ ] Not applicable

```

```

## Version bump

- [ ] This change needs a version bump and I have **not** bumped it, because the
      release owner owns `pyproject.toml`, `package.json`, `SKILL.md` and
      `CITATION.cff` together.
- [ ] The changelog entry is under `Unreleased` in `CHANGELOG.md`.

## Review notes

<!--
Anything a reviewer should look at first, anything you deliberately left out,
and anything you are unsure about. Saying "I am not sure this is right" is more
useful here than a confident guess.
-->
