# Security Policy

Plan Auditor decides whether work is really done, so its verdict is worth
attacking. This page says how to report a problem, what gets fixed, and what is
explicitly out of scope.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `>= 2.4.2` on npm | Yes | `2.4.3` is the current release. `2.4.0` shipped a syntax error in the `bin` launcher and `2.4.1` shipped a launcher that resolved a relative workspace path against the installed package directory. Both are defective and cannot be withdrawn, because npm versions are immutable. |
| `2.4.0`, `2.4.1` on npm | No | Defective releases. Do not install them. |
| `>= 2.4.2` on PyPI | Yes | `2.4.3` is the current release, published with a PEP 740 provenance attestation. |
| `2.4.0`, `2.4.1` on PyPI | No | Superseded by `2.4.2`. |
| `<= 2.3.0` | No | No fixes. Reproduce on `main` and open an issue if the problem still reproduces. |

Only the latest `2.4.x` is tested across the Python and operating-system matrix
that CI runs. Older minors are not.

### Verifying an install

Three different mechanisms are in play, and conflating them is how a supply-chain check
ends up proving less than it looks:

| Mechanism | What it proves | Where to read it |
|---|---|---|
| `dist.integrity` / `sha256` digest | The bytes you received are the bytes that were published. Integrity only — says nothing about how they were built. | `npm view <pkg> dist.integrity`, PyPI `digests.sha256` |
| npm `dist.signatures` | The **registry** signed the packument entry, so the metadata was not altered in transit. A transport signature, **not** build provenance. | `npm view <pkg> dist.signatures` |
| Build attestation | A CI run built this artifact from a named workflow, repo and commit, and a transparency log has the statement. | see per channel below |

The two channels differ, so check them differently. Both were measured on `2.4.3`:

- **PyPI — attested.** Publishing goes through OIDC trusted publishing, so every `2.4.3`
  artifact carries a [PEP 740](https://peps.python.org/pep-0740/) provenance attestation
  with predicate type `https://docs.pypi.org/attestations/publish/v1`, bound to the
  artifact's SHA-256. Fetch and check it yourself:

  ```bash
  curl -s https://pypi.org/integrity/plan-auditor/2.4.3/plan_auditor-2.4.3-py3-none-any.whl/provenance
  # statement subject sha256 must equal the digest PyPI serves for the file:
  curl -s https://pypi.org/pypi/plan-auditor/2.4.3/json | python -c "import json,sys;print(json.load(sys.stdin)['urls'][0]['digests']['sha256'])"
  ```

  Note the URL shape: PyPI serves attestations **per file**, so the path ends in
  `/<filename>/provenance`. `https://pypi.org/integrity/plan-auditor/2.4.3/` is not an
  endpoint and returns `404` — that 404 means "no such URL", not "no attestation".

- **npm — not attested.** `2.4.3` was published in token mode, and a registry token cannot
  mint an attestation. The attestations endpoint returns `404`:

  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' \
    https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.3   # -> 404
  ```

  So verify the npm artifact by digest instead, and treat that as integrity only:

  ```bash
  npm view plan-auditor@2.4.3 dist.integrity
  ```

### What would give npm provenance

This is **pending**, and is the only reason npm is weaker than PyPI here. It needs one
thing on npmjs.com and nothing in this repository: a trusted publisher with

| Field | Value |
|---|---|
| Owner | `Furox-Art` |
| Package | `plan-auditor` |
| Workflow filename | `npm-publish.yml` |
| Environment | the one this workflow publishes under |

Once that exists, the OIDC path publishes with `--provenance` and an attestation appears.
Until then the npm package is verifiable by digest only, and this document will say so.

When reporting a problem, say which registry and which verification you used.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting.** It opens a private thread
between you and the maintainer, and nothing becomes public until the advisory is
published.

<https://github.com/Furox-Art/plan-auditor/security/advisories/new>

Please do not open a public issue for a suspected vulnerability. A public issue
also means a public timeline for an unfixed problem.

If private reporting is unavailable to you, open a regular issue that contains
only enough detail to ask for a private channel, and no exploit details.

Include, where you can:

- the version you tested and the registry you installed from,
- the operating system and Python version,
- a minimal `.plan-auditor/plan.json` that reproduces it,
- what an attacker gains, and what they need in order to do it.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 48 hours |
| First assessment, with severity and a fix or a mitigation | 7 days |
| Fix released | Case by case; security fixes are prioritised over feature work |

These are targets, not a contract. If a report is out of scope (see below) you
will get that answer in the first assessment.

There is no PGP key published for this project, so reports are not encrypted in
transit beyond HTTPS to GitHub. If that matters for your report, say so and the
maintainer will arrange an encrypted channel.

## In scope

- A verdict of `PASS` or `verified` for a step whose check did not actually pass.
- Tampering with `evidence.jsonl` or an archive that `plan-auditor evidence verify`
  does not detect.
- A sealed plan whose criteria were weakened, dropped or replaced after approval
  without the documented migration path.
- A request contract that an agent can rewrite, deactivate or bypass.
- Path traversal, symlink substitution or unsafe regular-file handling around
  `.plan-auditor/`, `request init --file`, or the evidence archives.
- The blocking `Stop` hook in `hooks/gate_hook.py` exiting `0` for a failed gate.

## Out of scope

- **Not a sandbox.** In a normal install the agent and the verifier run as the same
  operating-system user, so a same-user hostile process can interfere. This is
  documented rather than hidden; read
  [the threat model](https://github.com/Furox-Art/plan-auditor/blob/main/docs/threat-model.md)
  and
  [the deployment-isolation guide](https://github.com/Furox-Art/plan-auditor/blob/main/docs/deployment-isolation.md)
  before relying on it against a hostile agent.
- **Tamper-evident, not tamper-proof.** Without an external HMAC key the agent can
  read, detection covers accidental edits, not a determined local attacker.
- Correctness of a check the host itself wrote. `plan-auditor` proves that the
  declared command exited with the declared status; it cannot prove the command
  tested the right thing.
- Bugs in a plan author's own `plan.json`.
- Dependency CVEs in unrelated tooling.

## External integrity keys

As of the 2.4.4 source hardening, behavioral-check subprocesses no longer inherit
`PLAN_AUDITOR_HMAC_KEY` or `PLAN_AUDITOR_HMAC_KEY_FILE` from the verifier.
This reduces inadvertent environment-based credential exposure, but **does not
sandbox checks**. Project-controlled checks running as the supervisor's OS user
can still read any external key file that user can read.

Version 2.4.5 adds an **opt-in Linux-only privilege boundary**. A trusted root-run
supervisor can require each behavioral check to execute as a separate, non-root
UID/GID with no supplementary groups; the child cannot read a root-only HMAC key
or protected control state. Unsafe or incomplete configuration refuses execution.
This is not automatic in normal mode and is not a container, seccomp or network
sandbox. Never grant the check user access to the supervisor's key or installed
trusted program. Setup instructions and limitations:
[deployment isolation](docs/deployment-isolation.md).

`plan-auditor integrity init` and `plan-auditor integrity status` manage a
keyed authentication of evidence, seals and the agent registry. Detection is only
as strong as the secrecy of that key; keeping it outside the workspace is the
operator's responsibility. The commands and output are documented in
[docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md).
