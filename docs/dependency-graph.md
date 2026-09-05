# Dependency graph and output contracts

Plan Auditor treats a plan as a deterministic prerequisite graph, not just a list of prose steps.

## Legacy plans

If **no** step contains `depends_on`, the plan keeps backward-compatible sequential semantics: each step depends on the preceding step. A later step cannot be verified while its predecessor is still pending or failed.

## Explicit DAG plans

Once any step contains `depends_on`, dependencies are explicit. Multiple root steps are allowed, but cycles, self-dependencies, duplicate edges, and unknown step IDs are rejected.

Every explicit dependency edge must be tied to at least one concrete upstream output using `requires_outputs`. This prevents a graph edge from being only descriptive metadata.

```json
{
  "id": 1,
  "title": "Build normalized dataset",
  "depends_on": [],
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

A downstream step binds the edge to that output:

```json
{
  "id": 2,
  "title": "Fit model",
  "depends_on": [1],
  "requires_outputs": [
    {"step": 1, "name": "normalized-dataset"}
  ],
  "verify": [
    {"type": "pytest", "args": "tests/test_model_fit.py -q"}
  ]
}
```

## Runtime enforcement

For a dependent step to pass:

1. Every prerequisite step must have passed in the current full audit, or already be verified when running a targeted incremental step.
2. Every `requires_outputs` contract is re-executed immediately before the dependent step.
3. The dependent step's own behavioral verification must pass.
4. Every output declared by that step is independently checked.
5. The dependency graph, required outputs, output checks, and ordinary verification checks are included in the immutable plan fingerprint and fresh-audit evidence.

A blocked prerequisite does **not** count as a consumed implementation retry for the dependent step. The dependent step remains non-complete until its prerequisite state is independently verified.

## Security/verification intent

The graph is designed to answer: **did the agent actually establish the prerequisites and concrete effects claimed by the plan before proceeding?** It does not trust the agent's narrative or step status alone.
