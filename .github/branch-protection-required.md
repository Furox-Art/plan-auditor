# Required main-branch protection

Enforcement lives in the repository ruleset **`main-branch-protection`**
(`target: branch`, `enforcement: active`), because branch-administration settings
cannot be represented by a source file. This document records the intended
configuration and how to verify it.

## Why this file exists

`.github/workflows/` was advisory: a maintainer could push straight to `main`,
skip CI, and publish. The file you are reading previously documented that
requirement while nothing enforced it.

## Rules enforced on the default branch

Verified with:

```bash
gh api repos/Furox-Art/plan-auditor/rulesets/24360871
```

- **Require a pull request before merging** (`pull_request`, **0 approving
  reviews**, stale reviews dismissed on push, unresolved threads must be
  resolved).
- **Require branches to be up to date** before merging
  (`strict_required_status_checks_policy: true`).
- **Block force pushes** (`non_fast_forward`).
- **Block branch deletion** (`deletion`).
- **No bypass actors.** `bypass_actors` is empty and the ruleset cannot be
  bypassed, including by repository admins.

### Why zero approving reviews

`required_approving_review_count` is `0`, and `require_last_push_approval` is
`false`. This is a single-maintainer repository: any approval requirement is
unsatisfiable by the only person who can push, so a rule demanding one reviewer
would not add a second pair of eyes — it would only make `main` permanently
unmergeable and train the maintainer to bypass the ruleset, which is the failure
mode the ruleset exists to prevent.

The safety property is preserved by the controls that do work here:

- `dismiss_stale_reviews_on_push` stays on, so any review that does exist cannot
  be carried across new commits.
- `required_review_thread_resolution` stays on, so unresolved review threads
  still block a merge.
- The twelve required status checks run on the exact commit being merged with
  `strict_required_status_checks_policy: true`, so unreviewed code still cannot
  land without passing CI.
- Nothing bypasses the ruleset, admins included.

If this repository ever gains a second maintainer, raise the count back to 1 and
set `require_last_push_approval` — the compensating controls above are what makes
zero safe today, and they are a substitute for review, not an argument against it.

## Required status checks

All checks must pass on the exact commit SHA being merged:

| Check | Workflow |
|---|---|
| `audit` | `plan-audit.yml` |
| `supervisor-runtime` | `plan-audit.yml` |
| `ruff` | `lint.yml` |
| `mypy` | `lint.yml` |
| `version-lockstep` | `lint.yml` |
| `workflow-syntax` | `lint.yml` |
| `build (wheel + sdist)` | `build.yml` |
| `docs (mkdocs --strict)` | `build.yml` |
| `npm-launcher` | `build.yml` |
| `wheel-cli-smoke (ubuntu-latest)` | `wheel-cli-smoke.yml` |
| `wheel-cli-smoke (windows-latest)` | `wheel-cli-smoke.yml` |
| `wheel-cli-smoke (macos-latest)` | `wheel-cli-smoke.yml` |

`python-compat` deliberately is **not** required. It fans out to twelve jobs
(4 interpreters x 3 operating systems); requiring all twelve would make the
merge queue unusably slow while adding no signal beyond what `audit` and
`wheel-cli-smoke` already cover. It still runs on every push and pull request,
so a platform-specific failure is visible on the PR itself.

## Release environment

The `pypi` environment is protected with:

- a 5-minute wait timer,
- a custom deployment branch policy allowing only `main`,
- admin bypass disabled.

Required reviewers are intentionally **not** enabled. This is a
single-maintainer repository, so requiring a reviewer would block every release
until a second person approved it: the safety property would be real, but the
release train would be permanently stuck. The compensating controls are the
`main`-only deployment policy, the version-existence gate in `release.yml`, and
OIDC trusted publishing, which means no long-lived PyPI API token exists in
repository secrets to leak.

Verify with:

```bash
gh api repos/Furox-Art/plan-auditor/environments/pypi
```

## Adding a required check

If a new permanent workflow is added, add its check name to the ruleset or
merges will not be blocked by it:

```bash
gh api -X PUT repos/Furox-Art/plan-auditor/rulesets/24360871 \
  --input ruleset.json
```