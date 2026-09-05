# Required main-branch protection

The `main` branch must be protected with repository-level rules requiring pull requests and successful CI before merge.

Required protections:

- Require a pull request before merging.
- Require all permanent Plan Auditor checks for the exact commit SHA, including:
  - `audit`
  - `supervisor-runtime`
  - `python-compat (3.10)`
  - `python-compat (3.11)`
  - `python-compat (3.12)`
  - `python-compat (3.13)`
  - `wheel-cli-smoke (ubuntu-latest)`
  - `wheel-cli-smoke (windows-latest)`
  - `wheel-cli-smoke (macos-latest)`
- Require branches to be up to date before merging.
- Block force pushes.
- Block branch deletion.
- Do not allow direct pushes that bypass the required checks.

This file documents the repository-level security requirement. Enforcement itself must be configured in GitHub Rulesets/Branch Protection because repository administration settings are not represented by source files.
