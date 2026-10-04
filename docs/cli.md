# CLI reference

Every command below is a real subcommand of the installed `plan-auditor` console
script. `tests/test_docs_metadata.py` fails the build if any invocation documented
on this site is not in the parser surface.

```console
$ plan-auditor --help
usage: plan-auditor [-h]
                    {supervisor,task,plan,evidence,integrity,request,agents,audit,doctor,run,validate}
                    ...

Plan Auditor - independent AI agent verification supervisor.
```

## Exit codes

One legend for every entry point. The npm launcher mirrors these and fails closed
with a non-zero code if Python cannot be started at all.

| Code | Meaning |
|---|---|
| `0` | **Proven.** Only `plan-auditor audit` treats `0` as "complete"; other commands use `0` to mean "this operation succeeded". |
| `1` | **Failed.** A check did not pass, or a gate requirement was not met. |
| `2` | **Blocked or refused.** Attempt budget exhausted, seal violated, tampered evidence, or a prerequisite step did not hold. |
| `3` | **`UNKNOWN`.** The assessment could not be determined, so completion is withheld. An undetermined outcome is never treated as success. |

The per-command tables below list the subset each command can actually return.

`plan-auditor run` and `plan-auditor validate` are forwarded verbatim to the
dependency-free deterministic core, `scripts/audit_check.py`, so you can call it
directly with no installation at all:

```bash
python scripts/audit_check.py validate .
python scripts/audit_check.py run . 1
python scripts/audit_check.py audit .
```

## Command summary

| Command | Purpose | Typical exit codes |
|---|---|---|
| `plan-auditor request init --file <f> [dir]` | Activate the host-owned request contract | `0` ok, `1` rejected |
| `plan-auditor request status [dir]` | Verify activation and plan alignment | `0` aligned, `1` not |
| `plan-auditor validate [dir]` | Validate plan schema (deterministic core) | `0` valid, `1` invalid |
| `plan-auditor run [dir] [ids...] [--force]` | Execute the checks of one or more steps | `0` verified, `1` failed, `2` tampered evidence |
| `plan-auditor plan verify [dir]` | Validate the plan and seal the full contract | `0` sealed, `1` rejected |
| `plan-auditor plan inspect [dir]` | Show plan structure, coverage, and seal | `0` ok |
| `plan-auditor audit [dir]` | Integrated final gate across every active plan | `0` proven, `1` fail, `2` blocked |
| `plan-auditor doctor [dir]` | Machine-readable health/capability report | `0` healthy, `1`/`2` degraded |
| `plan-auditor evidence verify [dir]` | Re-verify the active and archived evidence chains | `0` valid, `1` broken |
| `plan-auditor integrity init [dir]` | Create the external HMAC integrity material | `0` created, `1` refused |
| `plan-auditor integrity status [dir]` | Report integrity configuration | `0` ok |
| `plan-auditor task list [dir]` | List plans as supervisor tasks | `0` ok |
| `plan-auditor task inspect <id> [dir]` | Inspect one task | `0` ok, `1` unknown task |
| `plan-auditor agents list [dir]` | Show registered agents and file conflicts | `0` ok |
| `plan-auditor agents register <agent> [dir]` | Register an agent in the persistent registry | `0` ok |
| `plan-auditor agents claim <agent> <paths...> [dir]` | Claim workspace file ownership | `0` ok, `1` conflict |
| `plan-auditor agents release <agent> [dir]` | Release an agent's ownership | `0` ok |
| `plan-auditor agents heartbeat <agent> [dir]` | Refresh an agent heartbeat | `0` ok |
| `plan-auditor supervisor start [dir]` | Start the background supervisor daemon | `0` started |
| `plan-auditor supervisor stop [dir]` | Stop the daemon | `0` stopped |
| `plan-auditor supervisor status [dir]` | Report daemon state and assessment | `0` running, `1` not running |

Extra commands from the same distribution:

| Command | Purpose |
|---|---|
| `plan-auditor-formalize compile [dir]` | Compile the structured plan into a grounded STRIPS contract |
| `plan-auditor-formalize verify [dir]` | Recompile from the current plan and compare exactly |
| `plan-auditor-formal verify` / `plan-auditor-formal make-check` | Check a hand-written or generated formal contract |
| `plan-auditor-migrate-seal [dir]` | Representation-only migration of exact full-contract seals |

## The sequence that matters

```bash
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run . 1
plan-auditor audit .
```

- `request init` is host-owned. Run it once, before the agent starts.
- `plan verify` seals the contract. Seal **before** formalizing — the auto-formalizer
  refuses to mutate a sealed plan.
- `run` executes a step's real checks.
- `audit` is the completion gate. `0` is the only acceptable answer.

With external-key HMAC integrity:

```bash
plan-auditor integrity init .
plan-auditor audit .
```

## Reading `doctor` output

```bash
plan-auditor doctor .
```

The report has three top-level objects:

| Key | Meaning |
|---|---|
| `workspace` | Detected repository root, git state, inventory, and available toolchain |
| `supervisor` | Daemon state and last persisted assessment |
| `assessment` | The recomputed integrated assessment, including `assessment.outcome` |
| `integrity` | Whether an external HMAC key is configured and authenticated |
| `deterministic_core` | Absolute path to the deterministic core that was used |

`assessment.outcome` is the field to branch on. It is `PASS`, `FAIL`,
`UNKNOWN`, or `NO_PLAN`. A workspace with no active plan is `NO_PLAN`, which is
healthy — it does not degrade to `FAIL`.

## Deterministic core modes

The core is standard-library only and is what actually sets a step to `verified`.

```bash
python scripts/audit_check.py validate .
python scripts/audit_check.py run . 1
python scripts/audit_check.py audit .
python scripts/audit_check.py status .
python scripts/audit_check.py snapshot .
python scripts/audit_check.py rollback --to .plan-auditor/snapshots/<id>.zip
```

Named plans live in `.plan-auditor/plans/<name>.json` and are selected with
`--plan <name>`:

```bash
python scripts/audit_check.py run . --plan migration
```

## The three-attempt cap

A step may fail at most three times. The fourth attempt is refused. Complete
stdout, verbatim, for a workspace with no `README.md`:

```console
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 1/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 2/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 3/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[ATLADI] adım 1: the sentinel script exits nonzero önceki gerçek başarısız deneme — 3 sınırı aşıldı.
```

Every invocation exits `1`. Nothing above is elided. The check is
`python -c "import sys; sys.exit(3)"` against `expect_exit: 0`, chosen because it
writes no stderr and so renders identically on every Python version and platform.

This is deliberate. It stops an agent from brute-forcing a green result. Fix the
underlying problem; re-arm only deliberately with `plan-auditor run . 1 --force`.

## npm launcher exit codes

There are two Node entry points and both mirror the verifier's code:

| Entry point | Reached by |
|---|---|
| `bin/plan-auditor.js` | `npx plan-auditor`, `npm install -g`, the `bin` field in `package.json` |
| `index.js` | `require('plan-auditor')`, the `main` field, or running it directly |

Both exit `0` on a proven workspace, the child's `1` for a failed step and `2` for
a blocked audit, and `1` if Python cannot be started at all. A failing gate can
never look like a success through either launcher.

```bash
node bin/plan-auditor.js audit .
echo $?

npx plan-auditor audit .
echo $?
```

`tests/test_npm_launcher.py` runs every exit-code assertion against both
entry points, asserts the launcher's code equals the underlying CLI's, and repeats
the failing/passing checks against the packed npm tarball so a fix that only works
in the working tree fails the suite.

## Hooks

`hooks/gate_hook.py` is the single authoritative gate and returns `0` (pass or no
active plan), `1` (blocking fail) or `3` (unknown; completion withheld).

```bash
python hooks/gate_hook.py .
python hooks/gate_hook.py . --format json
python hooks/gate_hook.py . --warn-file .plan-auditor/gate-warning.json
```

See [Integrations](integrations.md) for host hook configuration.