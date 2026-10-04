# What is measurable here — and what is not

This page replaces a previous version of this file that contained comparative
numbers which were never produced by any harness in this repository. Those
numbers are gone. This page tells you exactly what you can measure yourself, and
how to reproduce it.

## Why there is no comparison table

A useful comparison would need a shared task set, a defined metric, an agreed
definition of a "false completion", and re-runs of every competing tool under the
same conditions. This repository has no such harness, so any table of numbers here
would be invented. Rather than publish numbers we cannot defend, we publish the
checks we *can* run and let you run them too.

If you want to build that harness, [open an issue](https://github.com/Furox-Art/plan-auditor/issues).

## Provenance for every number on this page

Nothing on this page is a hand-copied figure. Each quality claim below is tied to
the exact command that produces it, so you can regenerate it and compare. If a
number ever changes, the command changes too — that is the point.

| Claim | Command that produces it | Tool | Commit this text describes | Where the live value lives |
|---|---|---|---|---|
| Regression suite result | `python -m pytest tests/ -q` | the version of `pytest` in your environment | `main` at the time of reading | the `audit` CI job for that commit |
| Example regression | `python -m pytest examples/fib/test_fib.py -q` | same | same | the same CI run |
| Branch coverage | `python -m pytest tests/ -q --cov --cov-report=term-missing` | `pytest-cov` | same | the `TOTAL` row the command prints, and the `fail_under` value in `[tool.coverage.report]` in `pyproject.toml` |
| Docs build cleanly | `python -m mkdocs build --strict` | `mkdocs-material` | same | the `docs (mkdocs --strict)` required CI check |
| Docs and package metadata are consistent | `python -m pytest tests/test_docs_metadata.py tests/test_readme_quickstart.py tests/test_doc_transcripts.py -q` | `pytest` | same | the same CI run |
| Wheel and sdist carry the skill assets | `python .github/scripts/check_dist_assets.py` | none (standard library) | same | the `build (wheel + sdist)` required CI check |
| npm launcher behaviour and tarball | `npm test`, `npm run test:contract`, `npm run test:tarball` | the version of Node you run them with | same | the `npm-launcher` required CI check |
| Published package contents | `python -m build`, `twine check --strict dist/*`, `npm pack --dry-run` | `build`, `twine`, `npm` | the tag you check out | the `build` and `publish` jobs |

Note that the coverage command no longer names the source directories. `pytest-cov`
reads `branch`, `source_pkgs` and `fail_under` from `[tool.coverage.*]` in
`pyproject.toml`, and `conftest.py` pins the suite to the *installed* distribution,
so `--cov=supervisor --cov=scripts` against the checkout is no longer the command
that measures the shipped code.

Two things are deliberately **not** in that table:

- The coverage figure for any given commit. The command prints it, the floor is
  enforced from `pyproject.toml`, and a number typed into this file would
  silently go stale, so the floor and the run output are the only places it
  appears.
- Any number describing how many people use this. No telemetry is collected, so
  such a figure could not be substantiated. The package pages carry whatever the
  registries report.

Platform note: these commands were last exercised by this project's maintainer on
Windows 11 with CPython 3.12. CI runs the suite on `ubuntu-latest` across the
supported Python versions, `wheel-cli-smoke` exercises the installed CLI on Linux,
Windows and macOS, and the branch coverage is measured against the installed
distribution. Numbers can differ slightly by platform because a handful of tests
are skipped when an optional interpreter or helper is absent; the pass and skip
counts the command prints tell you which run you are looking at.

## What is reproducible: the in-repo example

`examples/fib/` is a complete, runnable plan. It is in the repository and in the
**sdist**, but not in the wheel, so a `pip`-only install will not have it — use a
checkout if you want to run this. (The wheel does ship the Agent Skill assets,
namespaced under `plan_auditor_skill/`; `examples/` is deliberately not among
them.)

```bash
cd examples/fib
python -m pytest test_fib.py -q
```

`examples/fib/.plan-auditor/plan.json` declares two steps, and the second step's
verification *is* the pytest run above:

```json
{
  "id": 2,
  "title": "pytest regression for fib() passes",
  "verify": [
    {"type": "file_exists", "path": "test_fib.py"},
    {"type": "pytest", "args": "test_fib.py -q"}
  ],
  "status": "pending"
}
```

So the property being demonstrated is narrow and checkable: *a step is not
`verified` until its declared command exits `0`.* Run the whole gate yourself:

```bash
cd examples/fib
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run .
plan-auditor audit .
```

```console
$ plan-auditor run .
[OK ] step 1: fib.py defines a correct fib() function (attempt 1/3)
       - passed | fib.py EXISTS
       - passed | pattern matched
       - passed | exit=0 (expected 0)
       - output fib-implementation | passed
[OK ] step 2: pytest regression for fib() passes (attempt 1/3)
       - passed | test_fib.py EXISTS
       - passed | exit=0 (expected 0)
```

Now break the implementation and watch the gate refuse to pass. Replace the body of
`fib.py` with `return 0`:

```console
$ plan-auditor run .
[FAIL] step 1: fib.py defines a correct fib() function (attempt 1/3)
       - passed | fib.py EXISTS
       - passed | pattern matched
       - FAILED | exit=1 (expected 0)
...
       - output fib-implementation | passed
[BLOCKED] step 2: prerequisite/output validation failed
```

**Scoped omission:** the single elided line is the tool's `output:` block, which
carries the captured Python traceback as one physical output line joined with
`" | "`. Its interior frames depend on your Python version — 3.11 and newer add
the offending source line and a caret — so quoting it verbatim would be correct on
some interpreters and wrong on the rest. Every remaining line above is verbatim,
the step fails with `exit=1`, and the invocation exits `1`.

The same run through the published npm bin exits `1` too, because the launcher
propagates the child's code rather than defaulting to success. `bin/plan-auditor.js`
is what `npx plan-auditor` resolves to:

```console
$ node bin/plan-auditor.js run /path/to/examples/fib
[FAIL] step 1: fib.py defines a correct fib() function (attempt 1/3)
       - passed | fib.py EXISTS
       - passed | pattern matched
       - FAILED | exit=1 (expected 0)
...
       - output fib-implementation | passed
[BLOCKED] step 2: prerequisite/output validation failed
$ echo $?
1
```

The same scoped omission applies to the launcher's `output:` line; the launcher exit
code of `1` is reproduced by `tests/test_npm_launcher.py`, which also asserts that
a passing `run` yields `0` and that an unstartable Python fails closed.

Step 2 is not merely "unverified" — it is **blocked**, because its prerequisite
output contract no longer holds. Restoring `fib.py` and re-running returns both
steps to `VERIFIED`, and the evidence log records the failing and the passing
attempts in one hash-chained sequence. `plan-auditor evidence verify .`
re-validates that chain.

The same experiment works without any agent involved: the gate does not care who
wrote the code.

## What is reproducible: the regression suite

This is the number this project is willing to stand behind, because it is produced
by the same command CI runs:

```bash
python -m pytest tests/ -q
python -m pytest examples/fib/test_fib.py -q
python -m pytest tests/ -q --cov --cov-report=term-missing
```

The coverage floor lives in `[tool.coverage.report]` as `fail_under` in
`pyproject.toml`, so the workflow and a local run cannot disagree about it, and
the workflow records the measured value and the reasoning for where the floor
sits. `conftest.py` pins the suite to the installed distribution, so the number
measures the code that would ship rather than the working tree. A regression in
coverage fails CI instead of quietly lowering a claim.

## What is not claimed

| Claim | Status |
|---|---|
| This tool catches unverified completions | Demonstrated above on a runnable example |
| Evidence tampering is detected | Covered by `test_chain_ok_and_tamper_detected` in `tests/test_audit_check.py` and `test_evidence_chain_break_detected` in `tests/test_failure_injection.py` |
| Plan criteria cannot be weakened after sealing | Covered by `tests/test_full_contract_hardening.py` and `tests/test_failure_injection.py` |
| Cross-tool detection rates | **Not measured.** No harness exists |
| Productivity or time saved | **Not measured.** No study exists |
| Adoption by size or organization | **Not claimed.** No telemetry is collected |

## Overhead you can measure yourself

Verification is real work: every behavioral check runs a subprocess, and `audit`
runs them all again in fresh shells. Measure it on your own task:

```bash
time plan-auditor run . 1
time plan-auditor audit .
```

`time` is a POSIX shell builtin, so those two lines apply to a POSIX shell. In
PowerShell use `Measure-Command`, and in `cmd.exe` measure with `%TIME%`.

For a cheap sanity check, `plan-auditor doctor .` reports whether the required
toolchain is present in your environment before you commit to a plan that needs it.

## Reproducing every check in this project

```bash
python -m pytest tests/ -q
python -m pytest examples/fib/test_fib.py -q
python -m build
twine check --strict dist/*
python .github/scripts/check_dist_assets.py
python -m mkdocs build --strict
npm test
npm run test:contract
npm run test:tarball
plan-auditor request init . --file .plan-auditor/request-source.json
plan-auditor plan verify .
plan-auditor audit .
```

`build`, `twine`, `mkdocs-material` and Node are contributor-only tools and are
not declared as runtime dependencies, so install them first:

```bash
python -m pip install build twine mkdocs-material
```

CI pins `mkdocs==1.6.1` and `mkdocs-material==9.6.14` for its strict build, so
pin the same pair locally if you want the check to match exactly. Note that
`python -m mkdocs build --strict` needs the dependency installed for the *same*
interpreter you build with; it is not a runtime dependency of the package.

The documentation and package-metadata checks that keep the README and this site
truthful live in `tests/test_docs_metadata.py` and
`tests/test_readme_quickstart.py`.

## Next steps

- [Quick start](quickstart.md) to run this yourself.
- [CLI reference](cli.md) for every command.
- [Threat model](threat-model.md) for the boundary of every claim above.