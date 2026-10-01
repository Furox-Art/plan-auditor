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

## What is reproducible: the in-repo example

`examples/fib/` is a complete, runnable plan that ships with the package.

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
[OK ] adım 1: fib.py defines a correct fib() function (deneme 1/3)
       - geçti | fib.py VAR
       - geçti | pattern eşleşti
       - geçti | exit=0 (beklenen 0)
       - output fib-implementation | geçti
[OK ] adım 2: pytest regression for fib() passes (deneme 1/3)
       - geçti | test_fib.py VAR
       - geçti | exit=0 (beklenen 0)
```

Now break the implementation and watch the gate refuse to pass. Replace the body of
`fib.py` with `return 0`:

```console
$ plan-auditor run .
[FAIL] adım 1: fib.py defines a correct fib() function (deneme 1/3)
       - geçti | fib.py VAR
       - geçti | pattern eşleşti
       - KALDI | exit=1 (beklenen 0)
...
       - output fib-implementation | geçti
[BLOK] adım 2: prerequisite/output doğrulaması geçmedi
```

**Scoped omission:** the single elided line is the tool's `çıktı:` block, which
carries the captured Python traceback as one physical output line joined with
`" | "`. Its interior frames depend on your Python version — 3.11 and newer add
the offending source line and a caret — so quoting it verbatim would be correct on
some interpreters and wrong on the rest. Every remaining line above is verbatim,
the step fails with `exit=1`, and the invocation exits `1`.

The same run through the npm launcher exits `1` too, because the launcher
propagates the child's code rather than defaulting to success:

```console
$ node index.js run /path/to/examples/fib
[FAIL] adım 1: fib.py defines a correct fib() function (deneme 1/3)
       - geçti | fib.py VAR
       - geçti | pattern eşleşti
       - KALDI | exit=1 (beklenen 0)
...
       - output fib-implementation | geçti
[BLOK] adım 2: prerequisite/output doğrulaması geçmedi
$ echo $?
1
```

The same scoped omission applies to the launcher's `çıktı:` line; the launcher exit
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
python -m pytest tests/ -q --cov=supervisor --cov=scripts --cov-branch --cov-report=term-missing
```

The branch-coverage gate in `.github/workflows/plan-audit.yml` enforces a floor
and the file states the measured value and the reasoning for the floor, so a
regression in coverage fails CI instead of quietly lowering a claim.

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

For a cheap sanity check, `plan-auditor doctor .` reports whether the required
toolchain is present in your environment before you commit to a plan that needs it.

## Reproducing every check in this project

```bash
python -m pytest tests/ -q
python -m pytest examples/fib/test_fib.py -q
python -m build
python -m twine check dist/*
python -m mkdocs build --strict --site-dir .tmp-site
node --check index.js && node --check bin/plan-auditor.js
plan-auditor request init . --file .plan-auditor/request-source.json
plan-auditor plan verify .
plan-auditor audit .
```

The documentation and package-metadata checks that keep the README and this site
truthful live in `tests/test_docs_metadata.py` and
`tests/test_readme_quickstart.py`.

## Next steps

- [Quick start](quickstart.md) to run this yourself.
- [CLI reference](cli.md) for every command.
- [Threat model](threat-model.md) for the boundary of every claim above.