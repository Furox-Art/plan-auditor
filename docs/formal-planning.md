# Sealed classical planning verification

Plan Auditor adds an **LLM-free classical planning proof** to non-trivial plans. The formal layer checks symbolic reachability, while the deterministic execution auditor separately proves that the concrete work was actually performed.

The normal path is now **automatic deterministic formalization**. Users and agents do not need to invent STRIPS facts by hand for ordinary structured plans.

## Default automatic path

After requirements, coverage, dependencies, outputs, and checks are defined—but before sealing—run:

```bash
plan-auditor-formalize compile .
```

For a named plan:

```bash
plan-auditor-formalize compile . --plan <name>
```

The compiler derives a conservative formal model only from structured Plan Auditor primitives. It deliberately does **not** interpret arbitrary prose or ask another LLM to invent symbolic meaning.

Generated facts are limited to four classes:

```text
formalization-source:<SHA256>
step-completed:<STEP-ID>
output-available:<STEP-ID>:<NAME-SLUG>:<HASH>
requirement-satisfied:<REQ-ID>
```

The source fingerprint covers the task, requirements, step coverage, dependency/output dataflow, declared outputs, and non-generated verification checks. Generated formal checks are excluded from the source projection so the fingerprint is non-circular.

## Two independent generated checks

Automatic formalization installs two behavioral checks into one plan step:

1. `plan-auditor-formal verify ...`
   - verifies the embedded grounded STRIPS contract,
   - enforces the Plan Auditor dependency DAG,
   - checks symbolic preconditions/effects and final goals,
   - can optionally cross-check with Fast Downward.

2. `plan-auditor-formalize verify ...`
   - recomputes the expected generated contract from the current structured plan,
   - recomputes the source fingerprint,
   - requires exact equality with the embedded generated contract,
   - rejects stale, weakened, omitted, or manually edited generated formalizations.

This separation matters. A contract can be internally reachable and still be the wrong contract. The second check proves that a generated contract is exactly the deterministic compilation of the plan source rather than a weaker model proposed by the same AI.

## What the compiler derives

For every plan step, the compiler creates one formal action.

The action receives:

- the current `formalization-source:<SHA256>` marker as a precondition,
- an `output-available:...` precondition for every `requires_outputs` reference,
- a `step-completed:<STEP-ID>` add effect,
- an `output-available:...` add effect for every declared named output,
- a `requirement-satisfied:<REQ-ID>` add effect for every covered `must`/`should` requirement.

The final goal includes:

- every required `requirement-satisfied:<REQ-ID>` fact,
- every generated step-completion fact,
- every generated output-availability fact.

The classical planner independently enforces `depends_on`. The generated output facts additionally bind symbolic reachability to concrete Plan Auditor dataflow.

If an explicit dependency edge is not backed by `requires_outputs`, automatic formalization fails instead of inventing a missing data dependency.

## Requirement binding

For every `must` or `should` requirement `REQ-X`, the canonical formal fact is:

```text
requirement-satisfied:REQ-X
```

The integrated semantic verifier rejects a plan unless:

- the fact is a final goal,
- it is not pre-satisfied in the initial state,
- at least one action produces it,
- every producer is a step whose `covers` contains `REQ-X`,
- every formal action has a symbolic effect.

For automatically generated contracts, an additional stronger condition applies: the **entire contract** must exactly equal deterministic recompilation from the structured plan.

So simply changing the contract and recomputing its SHA is not enough to bypass the verifier.

## Source-fingerprint chain

The trust chain for generated contracts is:

```text
host-owned request + acceptance checks
        -> exact plan requirements
        -> covers / dependencies / outputs / requires_outputs / checks
        -> deterministic source SHA-256
        -> generated STRIPS contract
        -> independent deterministic recompilation/equality check
        -> STRIPS reachability
        -> deterministic execution evidence
        -> sealed aggregate PASS
```

If the structured plan changes after generation, the source SHA changes and the old generated contract becomes invalid. Re-run the compiler before sealing.

The compiler refuses to mutate a plan once its seal file exists.

## Optional Fast Downward cross-check

Automatic generation can include an external Fast Downward requirement:

```bash
plan-auditor-formalize compile . \
  --fast-downward auto \
  --require-fast-downward
```

The generated `plan-auditor-formal` check then includes the external-planner requirement in its sealed argv.

PDDL export remains available:

```bash
plan-auditor-formal export-pddl . \
  --contract-sha <sha256> \
  --output ./pddl-proof
```

The output contains:

- `domain.pddl`
- `problem.pddl`
- `facts.json`

Human fact strings are mapped to generated predicates before being inserted into PDDL syntax.

## Internal planner behavior

The built-in planner is a grounded STRIPS-style planner.

For models with no delete effects, facts only accumulate and Plan Auditor uses a deterministic forward solver. For models with delete effects, it uses bounded state-space search.

Every action can execute at most once. A candidate action is applicable only when:

- all Plan Auditor dependencies are complete, and
- all symbolic preconditions are currently true.

PASS requires all plan steps to execute and all final goals to be true.

Search is fail-closed. Exceeding the configured state bound produces UNKNOWN/REVISE rather than PASS.

## Manual domain-specific models

Manual STRIPS contracts are still supported when a project genuinely needs domain facts that cannot be derived from Plan Auditor's structured plan.

Create a manual anchor with:

```bash
plan-auditor-formal make-check formal-contract.json
```

The automatic compiler will **not overwrite** an existing manual formal contract.

This is intentional. Domain semantics such as physical states, protocol states, scientific assumptions, or business invariants should not be silently guessed from natural-language prose. They should be explicitly modeled and reviewed.

## Relationship to the architecture

```text
Modern AI / coding agent
        |
        v
Host request + acceptance checks
        |
        v
Requirements + coverage + dependency/output DAG
        |
        v
Deterministic auto-formalizer
        |
        +--> source SHA-256 provenance
        +--> requirement goals
        +--> output/dataflow facts
        +--> one action per step
        |
        v
Independent deterministic recompilation check
        |
        v
Grounded STRIPS reachability
        |
        +--> PDDL / Fast Downward (optional)
        |
        v
Soar-like lifecycle / subsumption priority
        |
        v
Deterministic subprocess/filesystem audit
        |
        v
Seal + evidence + aggregate completion gate
        |
        v
PASS / FAIL / UNKNOWN
```

## Trust boundary

Automatic formalization closes a major trust gap: the same AI that wrote the implementation no longer needs to be trusted to invent a structurally convenient STRIPS model for ordinary plans.

It does **not** claim to solve arbitrary natural-language semantic formalization. The compiler only derives facts from explicit requirements, coverage, dependency/output dataflow, and checks. Host-owned request acceptance checks remain authoritative for the meaning of the user's request.

For domain semantics that cannot be derived mechanically, fail closed or use a reviewed manual formal model; do not invent facts merely to obtain a formal PASS.

The default internal planner and compiler are local, CPU-only, and require no model API, GPU, or network connection.
