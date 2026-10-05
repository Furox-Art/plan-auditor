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
python -m pip install . pytest pytest-cov
```

Python 3.10 or newer. Install the distribution **non-editable and re-run that
command after you change source**, because `conftest.py` resolves `supervisor`
and `scripts` from site-packages before any test module loads. That is
deliberate: several test modules used to put the repository root on `sys.path`,
which silently shadowed an installed wheel and let the suite pass against files
that never ship. If the distribution is missing, collection fails loudly rather
than falling back to the checkout.

Contributor-only tools, none of which are runtime dependencies, are named in the
section that needs them.

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
| `python -m pytest tests/ -q --cov --cov-report=term-missing` | The same coverage command CI runs, with the per-module table. |
| `npm test` | The Node launcher and `bin` entry point parse. |
| `npm run test:contract` | The launcher keeps the caller's working directory, propagates exit codes and fails closed. |
| `npm run test:tarball` | The packed tarball has no `__pycache__`, venv, build output or `*.test.js`, and does carry what the launcher needs. |
| `python -m mkdocs build --strict` | The documentation site still builds with no warnings. |

Do not pass `--cov=supervisor --cov=scripts`. `pytest-cov` reads `branch`,
`source_pkgs` and `fail_under` from `[tool.coverage.*]` in `pyproject.toml`, and
naming the source directories measures the checkout rather than the installed
distribution.

`node bin/plan-auditor.js run <failing-plan>` must exit non-zero. A launcher that
turns a `FAIL` into `0` is the exact bug class this project exists to prevent, so
`tests/test_npm_launcher.py` and `bin/launcher_contract.test.js` check both entry
points and the packed tarball. The launcher must also keep *your* working
directory: it previously spawned the CLI with the package directory as its cwd, so
a bare `.` resolved against the installed package and the tool audited the wrong
tree while looking authoritative.

### What CI enforces on every pull request

`main` is protected by a ruleset with no bypass actors, including for admins, so
none of these gates can be skipped by pushing to `main`. The required checks are
listed in
[`.github/branch-protection-required.md`](https://github.com/Furox-Art/plan-auditor/blob/main/.github/branch-protection-required.md).

| Gate | Fails when |
|---|---|
| `audit` | The suite, the schema check, the coverage floor, the real CLI smoke or the self-audit gate regresses. |
| `supervisor-runtime` | The background supervisor does not reach `running` with a `PASS` assessment, or does not stop cleanly. |
| `python-compat` | Any supported Python version breaks the suite or the example. |
| `ruff`, `mypy` | A lint or strict type error count rises above the recorded baseline in `.github/baselines/`. Nothing is suppressed: no rule disabled, no `ignore_errors`, no file excluded, and the baseline writer refuses to record a higher count, so new debt cannot be laundered in. |
| `version-lockstep` | `pyproject.toml`, `package.json`, `SKILL.md` and `CITATION.cff` disagree on the version. |
| `build (wheel + sdist)` | The distributions fail to build, fail `twine check --strict`, or do not contain the assets the README and docs promise. `.github/scripts/check_dist_assets.py` asserts the wheel carries the Agent Skill assets under `plan_auditor_skill/`. |
| `docs (mkdocs --strict)` | The documentation site stops building cleanly. |
| `npm-launcher` | A launcher contract or tarball check fails. |
| `workflow-syntax` | A workflow file is not valid: a job without `runs-on` or `permissions`, a step that is not a mapping, a `steps` that is not a list, a step-level `if` referencing the unavailable `secrets` context, or an action not pinned to a full 40-character SHA. |
| `wheel-cli-smoke` | The wheel, installed into a clean venv on Linux, Windows or macOS, does not drive the real CLI. |

### The coverage floor

`fail_under` lives in `[tool.coverage.report]` in `pyproject.toml`, so the
workflow and a local run cannot disagree about it. The measured value at the time
the floor was set, and the reasoning for where it sits, are recorded in a comment
on the coverage step in
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
  is elided. An `output:` line whose interior depends on your Python version must be
  scoped, not quoted.
- Never add a download count, a star count, a user count or a trust badge. Link to
  the package page instead; the tests reject a copied number.
- Never claim a comparison with another tool. There is no harness in this
  repository, so any such table would be invented.
- Prefer "not measured" over an estimate. If you cannot reproduce a number, say
  it is not measured.

### Building the site locally

There is no published documentation site; `mkdocs.yml` is configured and CI runs
`mkdocs build --strict` as a required check, but publishing needs a GitHub Pages
workflow that does not exist yet. Read the Markdown on GitHub, or build it:

```bash
python -m pip install mkdocs-material
mkdocs serve
```

CI pins `mkdocs==1.6.1` and `mkdocs-material==9.6.14`; pin the same pair if you
want your local strict build to match the required check exactly.

## Releasing

`main` is protected with no bypass actors, so a release cannot be pushed straight
to `main` without the gates. The published `2.4.1` artifacts were built from
different commits, which is the mistake this section exists to prevent; the
record is in the "The two published `2.4.1` builds" section of
[CHANGELOG.md](https://github.com/Furox-Art/plan-auditor/blob/main/CHANGELOG.md).

1. Bump the version in **all four** places: `pyproject.toml`, `package.json`,
   the `metadata.version` in `SKILL.md`, and `version` in `CITATION.cff`. The
   `version-lockstep` check fails if they disagree.
2. Build and verify both distributions locally:

   ```bash
   python -m pip install build twine
   python -m build
   twine check --strict dist/*
   python .github/scripts/check_dist_assets.py
   npm pack --dry-run
   npm run test:tarball
   ```

3. Move the `Unreleased` section of the changelog under the new version heading.
4. PyPI: push a change to `.github/pypi-release-trigger`. The workflow builds,
   runs the suite, smoke-tests the wheel on Linux, Windows and macOS, checks the
   distributions, and **skips publishing if the version already exists on PyPI** —
   so an unchanged version number will silently not publish. Publishing uses OIDC
   trusted publishing only; there is no long-lived token in repository secrets.
   Creating the GitHub release is gated on the same version-existence check, so a
   re-run cannot append a second copy of the notes.
5. npm: the publish workflow triggers on any change to `package.json`,
   `index.js`, `bin/**` or the skill assets. It runs a `verify` job first — the
   launcher tests and the packed-tarball check — and refuses to publish a version
   already on the registry, so a no-op push is not a red or duplicate build.
6. Confirm the tag, the PyPI artifact and the npm artifact are the same commit,
   and that the wheel you published actually contains `plan_auditor_skill/`.

Anyone can reproduce every one of those checks from a clean checkout, which is
the point: nothing in the release path depends on a maintainer remembering a step.

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
| `examples/fib/` | A complete, runnable two-step plan whose second step is a pytest run. |
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
