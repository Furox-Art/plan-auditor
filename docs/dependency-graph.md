# Dependency graph, output contracts, and requirement coverage

Plan Auditor treats a plan as a deterministic prerequisite graph rather than a
list of prose steps.

## Legacy sequential plans

If **no** step contains `depends_on`, steps retain backward-compatible sequential
semantics: each step depends on the preceding step. A later step cannot pass while
its predecessor is pending/failed.

Supervisor PASS still requires explicit requirements and `covers` links even when
the dependency structure is legacy sequential.

## Explicit DAG plans

Once any step contains `depends_on`, dependency semantics are explicit. Multiple
root steps are allowed; cycles, self-dependencies, duplicate edges, and unknown
step IDs are rejected.

Every explicit dependency edge must be tied to at least one concrete upstream
output via `requires_outputs`. This prevents a dependency that exists only as
metadata.

```json
{
  "id": 1,
  "title": "Build normalized dataset",
  "depends_on": [],
  "covers": ["REQ-001"],
  "verify": [
    {"type": "pytest", "args": "tests/test_dataset.py -q"}
  ],
  "outputs": [
    {
      "name": "normalized-dataset",
      "verify": [
        {"type": "file_exists", "path": "data/normalized.parquet"}
      ]
    }
  ]
}
```

Downstream:

```json
{
  "id": 2,
  "title": "Fit model",
  "depends_on": [1],
  "requires_outputs": [
    {"step": 1, "name": "normalized-dataset"}
  ],
  "covers": ["REQ-002"],
  "verify": [
    {"type": "pytest", "args": "tests/test_model_fit.py -q"}
  ]
}
```

## Runtime enforcement

For a dependent step to pass:

1. Every prerequisite must have passed in the current full audit (or already be
   verified for a targeted incremental run).
2. Every required upstream output contract is re-executed immediately before the
   dependent step.
3. The dependent step's own behavioral verification must pass.
4. Every output declared by the dependent step is independently checked.
5. The current graph/check/output/coverage contract must match the audited plan
   fingerprint.
6. The format-v3 seal must still contain all previously approved dependencies,
   required outputs, output checks, coverage links and step checks.

A blocked prerequisite does **not** consume an implementation retry for the
dependent step. It remains incomplete until prerequisites and required outputs are
independently proven.

## Requirement coverage

Dependencies answer “was the prerequisite actually established?” Requirement
coverage answers “did the plan include everything the user required?”

Every `must`/`should` requirement must appear in at least one step's `covers`
list. Unknown or missing requirement IDs are rejected by Supervisor Mode. Coverage
is part of the seal and plan fingerprint, so it cannot be removed after approval
to make the plan easier to pass.

## Multi-plan aggregation

Each active plan has its own DAG/coverage/seal/fresh-audit proof. Final workspace
PASS is the conjunction of all active default/named plans; no individual plan can
hide another plan's incomplete dependency chain.
