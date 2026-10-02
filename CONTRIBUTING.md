# Contributing

Plan Auditor exists to make "the agent says it is done" a checkable fact. That
makes the rules below unusually strict, and most of them are enforced by tests
rather than by review.

## Rules of the game

1. **The auditor never trusts the agent.** Any change that lets a language-model
   claim upgrade a failed or missing evidence into a pass is rejected by design.
   A model's judgment may only *tighten* — add stricter checks, downgrade
   `verified` — never loosen.
2. **Evidence is append-only.** The SHA-256 chain in `evidence.jsonl` is
   load-bearing. Pull requests that permit editing or reordering past records are
   declined.
3. **Unverifiable means failed.** Every step needs at least one behavioural check
   (`run`, `pytest` or `exec`). File existence or a regex alone can never verify a
   step.
4. **Standard library only at runtime.** `scripts/audit_check.py` must stay
   dependency-free so the skill works plug-and-play anywhere. `pyproject.toml`
   declares `dependencies = []` and that is intentional, not an oversight.
5. **Fail closed.** An unprovable state resolves to `FAIL` or `UNKNOWN`, never to
   success, and never to a default of `0`.

## Set up a development environment

```bash
git clone https://github.com/Furox-Art/plan-auditor.git
cd plan-auditor
python -m pip install -e . pytest pytest-cov
```

Python 3.10 or newer. Contributor-only tools, none of which are runtime
dependencies, are installed on demand and named in the section that needs them.

## Run the test suite

```bash
python -m pytest tests/ -q
```

`pytest` is the only third-party package the suite requires. A handful of tests
skip themselves when an optional interpreter or helper is absent, so a pass count
with skips is normal and the skip count tells you which environment you had.

Other suites worth running before you open a pull request:

| Command | What it proves |
|---|---|
| `python -m pytest tests/ -q` | The whole unit and hardening suite. |
| `python -m pytest examples/fib/test_fib.py -q` | The shipped example still passes. |
| `python -m pytest tests/ -q --cov=supervisor --cov=scripts --cov-branch --cov-report=term-missing` | The same coverage command CI runs, with the per-module table. |
| `npm test` | The Node launcher and `bin` entry point parse, and the bin propagates the child's exit code. Needs Node on `PATH`. |

`node bin/plan-auditor.js run <failing-plan>` must exit non-zero. A launcher that
turns a `FAIL` into `0` is the exact bug class this project exists to prevent, so
`tests/test_npm_launcher.py` checks both entry points and repeats the check
against the packed npm tarball.

### The coverage floor

CI enforces a branch-coverage floor on `supervisor` and `scripts`. The floor, the
measured value at the time it was set, and the reasoning are recorded in a comment
on that step in
[`.github/workflows/plan-audit.yml`](https://github.com/Furox-Art/plan-auditor/blob/main/.github/workflows/plan-audit.yml).
Raise the floor as tests land; never lower it to make a run green. A number typed
into a document instead of the workflow goes stale silently, which is why the
documentation does not repeat it.

### The documentation gate

These tests keep the prose true, so most documentation changes need no
explanation of why they are safe — the suite proves it:

| Test | Enforces |
|---|---|
| `tests/test_readme_quickstart.py` | Parses the JSON files and commands out of the README, runs them through the real CLI in a temporary workspace, and asserts every documented output line was actually emitted. |
| `tests/test_doc_transcripts.py` | Regenerates the failing-run transcripts and requires every documented line to be verbatim, with any omission explicitly scoped. |
| `tests/test_docs_metadata.py` | mkdocs navigation covers every page, relative links resolve, badges reference real workflows, every documented `plan-auditor` command exists in the parser, and the versions, keywords, classifiers and URLs agree across `pyproject.toml`, `package.json`, `SKILL.md` and `CITATION.cff`. It also fails on a hand-copied download, star or user count. |

If you change a transcript, change the command that produced it. If you cannot
reproduce the output, the transcript is wrong, not the tool.

### The self-audit gate

This repository dogfoods the tool on itself. `.plan-auditor/plan.json` and
`.plan-auditor/request-source.json` are tracked, and CI runs:

```bash
plan-auditor request init . --file .plan-auditor/request-source.json
python scripts/audit_check.py validate .
plan-auditor plan verify .
plan-auditor audit .
```

A change that weakens the plan is rejected by the seal, not by a reviewer. If
you add a deliverable, add the requirement and the step, then run the gate
locally before you push.

## The sealing and trust workflow, as implemented

This is what the code actually does, in the order a real task goes through it.

1. **The host owns the requirements.** You write `request-source.json`: the task,
   one requirement per thing you asked for, and deterministic
   `acceptance_checks` for each. Every requirement needs at least one behavioural
   check or `request init` refuses it.
2. **You activate it.** `plan-auditor request init . --file request-source.json`
   digests the file into `.plan-auditor/activation.json`. From here the agent
   cannot restate your requirements. Until this runs, `audit` fails with
   `"request contract is not activated"`.
3. **The plan is written and checked against the contract.** Each step declares
   `covers`, naming the requirements it satisfies, plus a dependency DAG and any
   named `outputs` later steps consume through `requires_outputs`. A requirement
   missing from every step, or a description that drifted from the contract, is a
   schema error.
4. **`plan-auditor plan verify .` seals the contract.** The seal is a hash over
   the requirements, the coverage binding, the dependency graph, the output
   contracts, every check, and the supervisor profile/mode/policy fingerprint.
   After sealing, criteria may be **added or strengthened but never removed or
   weakened**; the core enforces monotonicity. Changing the scope genuinely
   requires a new host-approved request generation. `plan-auditor-migrate-seal`
   exists only for a representation-only migration.
5. **Each step is executed in a fresh subprocess.** `plan-auditor run . <step-id>`
   runs that step's checks and appends a record to `evidence.jsonl`, where every
   record carries the SHA-256 of the previous one. A step becomes `verified` only
   when its behavioural check really passed; three failed attempts exhaust the
   budget and the step is refused until you fix the cause or re-arm deliberately
   with `run . <step-id> --force`. The cap is deliberate — it stops an agent from
   brute-forcing green.
6. **The gate re-derives everything.** `plan-auditor audit .` fingerprints the
   workspace, re-runs every check in new shells while the workspace is frozen, and
   fails if anything changed underneath it. It checks every active plan, so a
   passing default plan cannot hide an unfinished named plan. It is the only
   command whose exit code `0` means complete.
7. **You can re-verify later.** `plan-auditor evidence verify .` revalidates the
   chain, including rotated archives. For a tamper signal that survives a local
   attacker, `plan-auditor integrity init` authenticates evidence, seals and the
   agent registry under an external key; detection is then only as strong as the
   secrecy of that key.
8. **Optional formalisation.** For a non-trivial plan,
   `plan-auditor-formalize compile .` derives a conservative grounded STRIPS
   contract from the structured primitives you already wrote, with no language
   model inventing semantics, and a semantic-recompilation check. Run it *before*
   sealing; it refuses to mutate a sealed plan.

### Layer model

Verification is layered, and a lower layer can never be overridden by a higher
one. L10, the deterministic core, is the only component that can set a step to
`verified`; L13, the gate, is the only one that emits a final
`PASS`/`FAIL`/`UNKNOWN`. The full table, the L0-L14 module map and the subsumption
order are in
[docs/architecture.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Proven. Only `audit` treats this as "complete". |
| `1` | Failed: a step's check did not pass, or a gate requirement was not met. |
| `2` | Blocked or refused: the attempt budget is exhausted, the seal is violated, or a prerequisite step did not hold. |

The npm launcher mirrors these rather than defaulting to `0`, and fails closed
with a non-zero code if Python cannot be started at all.

## Adding a check type

1. Add the name to `CHECK_TYPES` in `scripts/audit_check.py`.
2. Handle it in `run_check`, and make sure it reports a behavioural or
   non-behavioural classification consistent with the other checks.
3. Document it in
   [references/plan-format.md](https://github.com/Furox-Art/plan-auditor/blob/main/references/plan-format.md).
4. Add tests: a passing case, a failing case, and a case proving it cannot be
   satisfied by a file-existence shortcut.
5. Run `python scripts/audit_check.py validate .` and `plan-auditor audit .` so
   the repository's own plan still passes.

## Writing documentation

- Every command you document must exist. `tests/test_docs_metadata.py` parses
  fenced code blocks and checks the subcommand against the real argument parser.
- Every transcript must be copied from a real run, and any elision must say what
  is elided. A `çıktı:` line whose interior depends on your Python version must be
  scoped, not quoted.
- Never add a download count, a star count, a user count or a trust badge. Link to
  the package page instead; the tests reject a copied number.
- Never claim a comparison with another tool. There is no harness in this
  repository, so any such table would be invented.
- Prefer "not measured" over an estimate. If you cannot reproduce a number, say
  it is not measured.

### Building the site locally

There is no published documentation site; `mkdocs.yml` is configured but no GitHub
Pages workflow exists yet. Read the Markdown on GitHub, or build it:

```bash
python -m pip install mkdocs-material
mkdocs serve
```

A strict build is a good pre-submission check even though CI does not run one:

```bash
python -m mkdocs build --strict --site-dir .tmp-site
```

## Releasing

The two registries are triggered differently, and that difference has already
produced two different artifacts under one version number. Read the "The two
published `2.4.1` builds" section of
[CHANGELOG.md](https://github.com/Furox-Art/plan-auditor/blob/main/CHANGELOG.md)
before you publish anything.

1. Bump the version in **all four** places: `pyproject.toml`, `package.json`,
   the `metadata.version` in `SKILL.md`, and `version` in `CITATION.cff`. A test
   fails if they disagree.
2. Build and verify both distributions locally:

   ```bash
   python -m pip install build twine
   python -m build
   python -m twine check dist/*
   npm pack --dry-run
   ```

3. Move the `Unreleased` section of the changelog under the new version heading.
4. PyPI: push a change to `.github/pypi-release-trigger`. The release workflow
   builds, runs the suite, smoke-tests the wheel on Linux, Windows and macOS,
   checks the distributions, and skips publishing if the version already exists —
   so an unchanged version number will silently not publish.
5. npm: the publish workflow triggers on any change to `package.json`,
   `index.js` or `bin/**`. As written it runs no test and no `npm pack` check, so
   confirm `npm test` yourself before pushing such a change.
6. Open the GitHub release for the tag and confirm the tag, the PyPI artifact and
   the npm artifact are the same commit.

## Where things live

| Path | Contents |
|---|---|
| `supervisor/` | The 15 supervision layers behind the CLI. |
| `scripts/audit_check.py` | The deterministic core. The only thing that can set `verified`. Standard library only. |
| `plan-auditor request init . --file <path>` | Activates the host-owned request contract. |
| `plan-auditor plan verify .` | Validates the plan and writes the seal. |
| `plan-auditor run . [step]` | Executes a step's checks and appends hashed evidence. |
| `plan-auditor audit .` | The integrated final gate. Exit `0` or not complete. |
| `plan-auditor evidence verify .` | Revalidates the hash chain, including archives. |
| `plan-auditor integrity init` | Authenticates evidence and seals under an external key. |
| `plan-auditor doctor .` | Machine-readable capability and health report. Run this first when anything misbehaves. |
| `SKILL.md` | The Agent Skill definition loaded by skill hosts. |
| `hooks/gate_hook.py` | The authoritative hook gate for hosts that support blocking hooks. |
| `examples/fib/` | A complete, runnable two-step plan, including a deliberately broken variant. |
| `docs/` | The documentation set. Navigation is defined in `mkdocs.yml`. |

## Conduct and security

Behaviour expectations and the private reporting route are in
[CODE_OF_CONDUCT.md](https://github.com/Furox-Art/plan-auditor/blob/main/CODE_OF_CONDUCT.md).
Do not open a public issue for a suspected vulnerability; use the private advisory
route in
[SECURITY.md](https://github.com/Furox-Art/plan-auditor/blob/main/SECURITY.md).

## Licence

By contributing you agree that your contributions are licensed under the
[MIT licence](https://github.com/Furox-Art/plan-auditor/blob/main/LICENSE) of
this project.
