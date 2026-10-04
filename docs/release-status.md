# Release status

What PyPI and npm each publish, what was defective on npm, and what is and is not
attested on each registry. Everything here was measured against the live registries
rather than against this repository, and it is the page to re-read before trusting a
version number.

The short version, kept in the README as well: **`2.4.3` is the current release on
both PyPI and npm**, and the quick start in the README describes the published
packages rather than only a checkout.

If this page and a registry ever disagree, the registry is right and this page is
stale.

## What is published

| Surface | Version | Published | Notes |
|---|---|---|---|
| npm (`latest`) | `2.4.3` | 2026-10-04 | Byte-identical to `npm pack` of the `main` tip (`45fd5ee`): `shasum` `f220d14e987008d7177c7ac2a19da4da63ee082c` and integrity `sha512-XYRobvGvmzBlv/VfLDD96W08XP0OPzeVXs2qMVDFnRzb8kgbWuu3IW1Q3MbEiF2Q67JKyW0ikFgn8zXYSVvBLg==` both reproduce from a clean checkout. 63 files, 617 609 bytes unpacked. |
| PyPI | `2.4.3` | 2026-10-04 | Carries a [PEP 740](https://peps.python.org/pep-0740/) provenance attestation on both files. Wheel SHA-256 `c4fdfddd9c12001d1fb76c3d48962a0cc3de07427bbcc6422a8bf04ad1b77c47`, sdist SHA-256 `29ae465bfc008687cd6ae5ad01fe49f154276441fedcbc120ed803fc446ce2fb`. |

## `2.4.0` and `2.4.1` were defective; `2.4.2` fixed them; `2.4.3` is current

| Version | Defect |
|---|---|
| `2.4.0` | A JavaScript syntax error in the `bin` launcher: the published entry point could not run at all. |
| `2.4.1` | The launcher passed `cwd: __dirname`, so a relative workspace path resolved against the *installed package directory*. `npx plan-auditor audit .` audited the wrong tree while looking authoritative. An absolute workspace path still worked, which made the failure silent. |
| `2.4.2` | Fixes both, and adds the pre-publish gate that would have caught them. |
| `2.4.3` | Documentation corrections and CI fixes. No change to the verify path. |

npm versions are immutable, so `2.4.0` and `2.4.1` cannot be withdrawn. Pin
`plan-auditor>=2.4.2` if you consume the npm package.

## Supply chain: three mechanisms, not one

These are routinely blurred together. They are different, and only the third is build
provenance.

| Mechanism | What it proves | What it does **not** prove |
|---|---|---|
| `dist.integrity` (sha512) / `shasum` (sha1) on npm, `digests.sha256` on PyPI | The bytes you received are the bytes that were published. | How they were built, or by whom. |
| npm `dist.signatures` | The **registry** signed the packument entry; the metadata was not altered in transit. A transport signature. | Anything about the build. npm's own key signs every package, attested or not. |
| Build attestation (Sigstore / in-toto) | A named CI workflow, repository and commit produced this artifact, and a transparency log holds the statement. | That the build was correct. |

## Per channel: what is true today

Both rows were measured against `2.4.3`.

| Channel | Build attestation? | Endpoint | Observed |
|---|---|---|---|
| PyPI | **yes** | `https://pypi.org/integrity/plan-auditor/2.4.3/plan_auditor-2.4.3-py3-none-any.whl/provenance` | `200`. in-toto v1 statement, predicate type `https://docs.pypi.org/attestations/publish/v1`, publisher `kind=GitHub`, `repository=Furox-Art/plan-auditor`, `workflow=release.yml`, `environment=pypi`. Subject `sha256` equals the digest PyPI serves. |
| npm | **no** | `https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.3` | `404`. No `provenance` field and no `dist.attestations` in the packument. `dist.signatures` **is** present, and is the transport signature described above. |

### The URL shape matters when you re-check this

PyPI serves attestations **per file**. The path ends in `/<filename>/provenance`.

```bash
# 200 -- a real attestation
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/plan-auditor/2.4.3/plan_auditor-2.4.3-py3-none-any.whl/provenance

# 404 -- NOT an endpoint. This means "no such URL", not "no attestation".
curl -s -o /dev/null -w '%{http_code}\n' \
  https://pypi.org/integrity/plan-auditor/2.4.3/
```

Reading the second `404` as "PyPI has no attestation" is exactly the mistake this section
exists to prevent. It is the absence of a collection endpoint, and PyPI does not publish
one.

### Verifying each channel by hand

```bash
# PyPI: attestation, then the digest it must match
curl -s https://pypi.org/integrity/plan-auditor/2.4.3/plan_auditor-2.4.3-py3-none-any.whl/provenance
python -c "import json,urllib.request;d=json.load(urllib.request.urlopen('https://pypi.org/pypi/plan-auditor/2.4.3/json'));print(d['urls'][0]['digests']['sha256'])"

# npm: no attestation; verify by digest, and treat that as integrity only
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.3
npm view plan-auditor@2.4.3 dist.integrity
npm view plan-auditor@2.4.3 dist.signatures
```

## What would give npm provenance

**Pending.** npm is weaker here for exactly one reason: this package has no trusted
publisher registered on npmjs.com, so the workflow publishes in token mode, and a registry
token cannot mint an attestation. Nothing in this repository needs to change; one record
on npmjs.com does:

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
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.3
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/integrity/plan-auditor/2.4.3/plan_auditor-2.4.3-py3-none-any.whl/provenance
```