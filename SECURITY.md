# Security Policy

Plan Auditor decides whether work is really done, so its verdict is worth
attacking. This page says how to report a problem, what gets fixed, and what is
explicitly out of scope.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `>= 2.4.2` on npm | Yes | The current release. `2.4.0` shipped a syntax error in the `bin` launcher and `2.4.1` shipped a launcher that resolved a relative workspace path against the installed package directory. Both are defective and cannot be withdrawn, because npm versions are immutable. |
| `2.4.0`, `2.4.1` on npm | No | Defective releases. Do not install them. |
| `>= 2.4.2` on PyPI | Yes | The current release, published with a PEP 740 provenance attestation. |
| `2.4.0`, `2.4.1` on PyPI | No | Superseded by `2.4.2`. |
| `<= 2.3.0` | No | No fixes. Reproduce on `main` and open an issue if the problem still reproduces. |

Only the latest `2.4.x` is tested across the Python and operating-system matrix
that CI runs. Older minors are not.

### Verifying an install

The two registries do not offer the same guarantee, so check them differently:

- **PyPI** publishes through OIDC trusted publishing, so every `2.4.2` artifact
  carries a [PEP 740](https://peps.python.org/pep-0740/) provenance
  attestation. Fetch it at
  `https://pypi.org/integrity/plan-auditor/<version>/<file>/provenance` and
  confirm the statement's SHA-256 matches the artifact you downloaded.
- **npm `2.4.2` carries no provenance attestation.** It was published in token
  mode, and a registry token cannot mint one; the `dist.signatures` block in the
  packument is npm's own signature over the packument, not evidence of how the
  tarball was built. Verify it with `npm view plan-auditor@<version>
  dist.integrity` instead, and compare it against the tarball you received.

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

`plan-auditor integrity init` and `plan-auditor integrity status` manage a
keyed authentication of evidence, seals and the agent registry. Detection is only
as strong as the secrecy of that key; keeping it outside the workspace is the
operator's responsibility. The commands and output are documented in
[docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md).
