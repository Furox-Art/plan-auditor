# Release status

What is published on each registry, what was defective, and what is and is not
attested. Everything here is checked against the live registries rather than
against this repository, and it is the page to re-read before trusting a version
number.

The short version, kept in the README as well: **`2.4.2` is the current release on
both PyPI and npm**, and the quick start in the README describes the published
packages rather than only a checkout.

## What is published

| Surface | Version | Published | Notes |
|---|---|---|---|
| npm (`latest`) | `2.4.2` | 2026-10-03 | Byte-identical to `npm pack` of the `main` tip: `shasum` `0a284a48fb4fe18cf9de8e45134142b7425f7b47` and integrity `sha512-AMTy8LLGVz5ySoAJN80RhT+I0ku9hat2d2DUbj7pKHNSdmpwiiOLDtH7CDfNGwkU7LDUQ2NE3vMUKlAzwES2NQ==` both reproduce from a clean checkout. |
| PyPI | `2.4.2` | 2026-10-02 | Carries a [PEP 740](https://peps.python.org/pep-0740/) provenance attestation. Its wheel's Python runtime is identical to `main`; the only content difference is the bundled `plan_auditor_skill/package.json` (npm dev-script names and the `engines.node` floor), which is not used at runtime. |

## `2.4.0` and `2.4.1` were defective; `2.4.2` is the fixed release

| Version | Defect |
|---|---|
| `2.4.0` | A JavaScript syntax error in the `bin` launcher: the published entry point could not run at all. |
| `2.4.1` | The launcher passed `cwd: __dirname`, so a relative workspace path resolved against the *installed package directory*. `npx plan-auditor audit .` audited the wrong tree while looking authoritative. An absolute workspace path still worked, which made the failure silent. |
| `2.4.2` | Fixes both, and adds the pre-publish gate that would have caught them. |

npm versions are immutable, so `2.4.0` and `2.4.1` cannot be withdrawn. Pin
`plan-auditor>=2.4.2` if you consume the npm package.

## Supply chain: what is and is not attested

Be precise about this, because the two registries differ:

- **PyPI `2.4.2` has a real provenance attestation.** The endpoint
  `https://pypi.org/integrity/plan-auditor/2.4.2/plan_auditor-2.4.2-py3-none-any.whl/provenance`
  returns a signed in-toto v1 statement with predicate type
  `https://docs.pypi.org/attestations/publish/v1`, bound to the artifact's
  SHA-256. It exists because PyPI publishes through OIDC trusted publishing.
- **npm `2.4.2` has no Sigstore attestation.** There is no `provenance` field in
  the packument and
  `https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.2`
  returns `404`. The `dist.signatures` block that *is* present is npm's own
  ECDSA signature over the packument, not evidence of how the tarball was built.
  This is expected: npm `2.4.2` was published in **token mode** (the workflow log
  records `selected publish mode: token`), and token publishing runs
  `npm publish --access public` without `--provenance` because a registry token
  cannot mint an attestation. Registering a trusted publisher for this package on
  npmjs.com would enable OIDC and change this.

Until that happens, verify npm artifacts by the integrity hash the registry
serves, not by an attestation:

```bash
npm view plan-auditor@2.4.2 dist.integrity
```

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
curl -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.2
```

If this page and a registry ever disagree, the registry is right and this page is
stale.
