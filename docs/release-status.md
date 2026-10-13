# Release status

What PyPI and npm each publish, what was defective on npm, and what is and is not
attested on each registry. Everything here was measured against the live registries
rather than against this repository, and it is the page to re-read before trusting a
version number.

Verified on 2026-10-13: **`2.6.0` is published on both PyPI and npm**. Both
registry version pages and the per-file PyPI provenance endpoint were checked.
For newer releases, re-check registry metadata; this is a dated measurement.

If this page and a registry ever disagree, the registry is right and this page is
stale.

## What is published

| Surface | Version | Published | Notes |
|---|---|---|---|
| npm (`2.6.0`) | `2.6.0` | 2026-10-13 | Registry reports `shasum` `4c5138778dd9f75216fa419532a8c207d404f088`, integrity `sha512-TAQgGaOot8eKkVNtq4QIZ1PILeEhMf+vP+6E6VGzUv/sMrvcu+r9i+rrfBv4ks4shX5Svm3u86AomgmXyKR2ig==`, 68 files and 690430 unpacked bytes. These values were read from the registry, **not** claimed to reproduce from a fresh local pack. |
| PyPI | `2.6.0` | 2026-10-13 | Wheel SHA-256 `b8cd5653431f5d29429642df08071984656fc0aaa14f817e8bfe027b06579add`; sdist SHA-256 `0d95cbc01ab720e81bef740ce6f60ad815787ee6f24714c16d145b6e00acc2c9`. The **wheel** PEP 740 provenance endpoint returned `200`; the sdist's attestation was not checked separately during this audit. |

## Historical defective releases: `2.4.0` and `2.4.1`; fixes in `2.4.2`

| Version | Defect |
|---|---|
| `2.4.0` | A JavaScript syntax error in the `bin` launcher: the published entry point could not run at all. |
| `2.4.1` | The launcher passed `cwd: __dirname`, so a relative workspace path resolved against the *installed package directory*. `npx plan-auditor audit .` audited the wrong tree while looking authoritative. An absolute workspace path still worked, which made the failure silent. |
| `2.4.2` | Fixes both, and adds the pre-publish gate that would have caught them. |
| `2.4.3` | Documentation corrections and CI fixes. No change to the verify path. |

npm versions are immutable, so `2.4.0` and `2.4.1` cannot be withdrawn. Pin
`plan-auditor>=2.4.2` if you consume the npm package.


### Historical verified artifact checks (2.4.3, 2026-10-04)

These historical values are retained for comparing old installations, **not** as
current-package values:

- npm shasum: `f220d14e987008d7177c7ac2a19da4da63ee082c`; 63 files; 617609 unpacked bytes.
- PyPI wheel SHA-256: `c4fdfddd9c12001d1fb76c3d48962a0cc3de07427bbcc6422a8bf04ad1b77c47`.
- PyPI sdist SHA-256: `29ae465bfc008687cd6ae5ad01fe49f154276441fedcbc120ed803fc446ce2fb`.
- The `2.4.3` PyPI wheel provenance endpoint returned `200` and the npm
  attestation endpoint `404` when measured for that release.

## Supply chain: three mechanisms, not one

These are routinely blurred together. They are different, and only the third is build
provenance.

| Mechanism | What it proves | What it does **not** prove |
|---|---|---|
| `dist.integrity` (sha512) / `shasum` (sha1) on npm, `digests.sha256` on PyPI | The bytes you received are the bytes that were published. | How they were built, or by whom. |
| npm `dist.signatures` | The **registry** signed the packument entry; the metadata was not altered in transit. A transport signature. | Anything about the build. npm's own key signs every package, attested or not. |
| Build attestation (Sigstore / in-toto) | A named CI workflow, repository and commit produced this artifact, and a transparency log holds the statement. | That the build was correct. |

## Per channel: what is true today

Both rows were re-checked against `2.6.0` on 2026-10-13.

| Channel | Build attestation? | Endpoint | Observed |
|---|---|---|---|
| PyPI | **yes (wheel)** | `https://pypi.org/integrity/plan-auditor/2.6.0/plan_auditor-2.6.0-py3-none-any.whl/provenance` | `200`; endpoint returns an attestation bundle. The published wheel digest is listed above; this check establishes endpoint presence, not independent verification of the bundle's signature/subject. |
| npm | **no** | `https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.6.0` | `404`. Registry version metadata contains transport `dist.signatures`, which are **not** build provenance; the publish job used token mode. |

### The URL shape matters when you re-check this

PyPI serves attestations **per file**. The path ends in `/<filename>/provenance`.

```bash
# 200 -- a real attestation
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/plan-auditor/2.6.0/plan_auditor-2.6.0-py3-none-any.whl/provenance

# 404 -- NOT an endpoint. This means "no such URL", not "no attestation".
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/plan-auditor/2.6.0/
```

Reading the second `404` as "PyPI has no attestation" is exactly the mistake this section
exists to prevent. It is the absence of a collection endpoint, and PyPI does not publish
one.

### Verifying each channel by hand

```bash
# PyPI: attestation, then the digest it must match
curl -s https://pypi.org/integrity/plan-auditor/2.6.0/plan_auditor-2.6.0-py3-none-any.whl/provenance
python -c "import json,urllib.request;d=json.load(urllib.request.urlopen('https://pypi.org/pypi/plan-auditor/2.6.0/json'));print(d['urls'][0]['digests']['sha256'])"

# npm: no attestation; verify by digest, and treat that as integrity only
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.6.0
npm view plan-auditor@2.6.0 dist.integrity
npm view plan-auditor@2.6.0 dist.signatures
```

## What would give npm provenance

**Pending as of the `2.6.0` release.** Its npm CI job published using token mode,
which does not create build provenance. Configuring npm trusted publishing is an
account/registry setting; the workflow already supports an OIDC path, but the
registry-side configuration must be completed and independently verified:

| Field | Value |
|---|---|
| Owner | `Furox-Art` |
| Package | `plan-auditor` |
| Workflow filename | `npm-publish.yml` |
| Environment | the environment the publish job declares |

The workflow already takes the OIDC path with `--provenance` when that record exists, and
fails closed rather than silently downgrading. Until the record is created, npm consumers
get digest verification only, and this page will keep saying so.

## What the artifacts contain

`docs/` and `examples/` are in the repository and the sdist, but not in the wheel.
The wheel ships the Python packages `supervisor` and `scripts`, plus the Agent
Skill assets namespaced under `plan_auditor_skill/`, which is where a `pip` install
finds `SKILL.md`, `hooks/`, `references/` and the Node launcher. See
[Integrations](integrations.md) for the exact path.

## Checking these claims yourself

Every version, hash and endpoint on this page is re-checkable:

```bash
npm view plan-auditor version dist.integrity
python -c "import json,urllib.request;print(json.load(urllib.request.urlopen('https://pypi.org/pypi/plan-auditor/json'))['info']['version'])"
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.6.0
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/integrity/plan-auditor/2.6.0/plan_auditor-2.6.0-py3-none-any.whl/provenance
```