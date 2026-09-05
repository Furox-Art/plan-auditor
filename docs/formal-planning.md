# Sealed classical planning verification

Plan Auditor can attach an **LLM-free classical planning proof** to a normal
multi-step plan. This extends the existing L5 structural verifier with explicit
symbolic state, preconditions, add effects, delete effects, final goals, and a
separate deterministic requirement-to-goal alignment layer.

The design uses three independent checks:

1. an in-process grounded STRIPS-style planner that is always available and uses
   only Python/CPU,
2. deterministic semantic binding from every `must`/`should` requirement to a
   canonical formal goal produced by a step that covers that requirement, and
3. optional PDDL export + Fast Downward execution for an external classical
   planner cross-check.

The existing deterministic audit remains authoritative for the question
"was the work actually executed?". Formal planning answers the different
question "is there a dependency-respecting symbolic action ordering that can
reach the declared goals?". The requirement-binding layer additionally checks
that those goals are not disconnected from the requirements the plan claims to
satisfy.

## Why the contract lives inside a `run` check

Formal planning data is stored under `formal_planning` inside an ordinary
behavioral `run` verification check. Plan Auditor already seals and fingerprints
the complete verification-check object, so this gives the symbolic model the same
protection as every other verification criterion without introducing a second,
weaker plan contract.

A canonical anchor for two requirements looks like this:

```json
{
  "type": "run",
  "argv": [
    "plan-auditor-formal",
    "verify",
    ".",
    "--contract-sha",
    "<sha256-of-formal_planning>"
  ],
  "formal_planning": {
    "version": 1,
    "initial_facts": ["workspace-ready"],
    "goal_facts": [
      "artifact-verified",
      "requirement-satisfied:REQ-001",
      "requirement-satisfied:REQ-002"
    ],
    "actions": [
      {
        "step": 1,
        "preconditions": ["workspace-ready"],
        "add_effects": [
          "artifact-built",
          "requirement-satisfied:REQ-001"
        ],
        "del_effects": []
      },
      {
        "step": 2,
        "preconditions": ["artifact-built"],
        "add_effects": [
          "artifact-verified",
          "requirement-satisfied:REQ-002"
        ],
        "del_effects": []
      }
    ]
  }
}
```

There must be exactly one formal-planning anchor per plan. The formal action set
must contain exactly one action for every Plan Auditor step. Existing
`depends_on` edges are automatically enforced by the classical planner; they are
not duplicated in the symbolic contract.

## Deterministic requirement-to-goal alignment

For every plan requirement whose priority is `must` or `should`, L5 derives the
canonical fact:

```text
requirement-satisfied:<REQ-ID>
```

The integrated verifier fails closed unless all of the following are true:

- the canonical fact is present in `goal_facts`,
- it is **not** present in `initial_facts`,
- at least one formal action produces it,
- every action that produces it belongs to a Plan Auditor step whose `covers`
  list contains the same requirement ID, and
- every formal action has at least one add or delete effect.

This means a planner cannot obtain formal credibility from a decorative symbolic
model that never represents a required outcome. The host-owned request contract
still remains the authority for the exact requirement text and acceptance
checks; request alignment binds that text to the plan requirement ID, and this
layer binds the same ID to the formal goal.

The composition is therefore:

```text
host-approved requirement + acceptance checks
        -> exact plan requirement / covers
        -> requirement-satisfied:<REQ-ID>
        -> covering STRIPS action effect
        -> reachable final symbolic state
        -> deterministic execution evidence
```

This is a structural semantic alignment check, not natural-language theorem
proving. A deliberately incorrect symbolic interpretation can still require
human/domain review for high-assurance work.

## Create a canonical check

Write the symbolic contract alone to `formal-contract.json`, then run:

```bash
plan-auditor-formal make-check formal-contract.json
```

The command prints a complete `run` check with the correct contract SHA-256. Put
that object in one step's `verify` array before sealing the plan.

To require an independent Fast Downward cross-check during the normal audit:

```bash
plan-auditor-formal make-check formal-contract.json \
  --fast-downward auto \
  --require-fast-downward
```

The external-planner requirement is then part of the sealed `argv`, so removing
it later is a seal violation.

## Internal planner behavior

For models with no delete effects, facts only accumulate. Plan Auditor uses a
deterministic forward algorithm: any currently applicable action can be executed
without invalidating a later action, so reachability is checked efficiently.

When delete effects are present, Plan Auditor performs bounded state-space search
and tracks both:

- the current symbolic fact set, and
- the set of Plan Auditor steps already executed.

Every action can execute at most once. A candidate action is applicable only when
both its existing Plan Auditor dependencies and its symbolic preconditions are
satisfied. Final PASS requires **all plan steps** to have executed and every
`goal_fact` to be true.

The search is fail-closed. If the bounded state space is exhausted without a
solution the contract is REJECTED; if the configured hard state bound is reached
before a conclusion, L5 returns UNKNOWN/REVISE rather than PASS.

## PDDL / Fast Downward

The same embedded contract can be translated to PDDL `:strips`:

```bash
plan-auditor-formal export-pddl . \
  --contract-sha <sha256> \
  --output ./pddl-proof
```

The output contains:

- `domain.pddl`
- `problem.pddl`
- `facts.json` mapping human-readable facts to sanitized PDDL predicates

Human fact strings are never inserted directly into PDDL syntax. They are mapped
to generated predicates such as `f0001`, preventing a fact label from injecting
PDDL syntax.

If Fast Downward is installed, it can be used at verification time:

```bash
plan-auditor-formal verify . \
  --contract-sha <sha256> \
  --fast-downward auto \
  --require-fast-downward
```

`auto` checks `FAST_DOWNWARD`, then `fast-downward.py`, then `fast-downward` on
`PATH`. A Python script is launched with the current Python interpreter. Planner
stdout/stderr is written to a temporary file rather than captured without bound,
and the process tree is terminated on timeout.

The generated PDDL includes `unused-step-N` and `done-step-N` predicates. This
forces each Plan Auditor step to run exactly once and requires every step to be
completed in the PDDL goal, so Fast Downward cannot "solve" the formal goal by
silently skipping unrelated plan steps.

## Relationship to the existing architecture

This feature strengthens, rather than replaces, the existing layers:

```text
Modern AI / coding agent
        |
        v
Host request + acceptance checks
        |
        v
Requirements + dependency/output DAG
        |
        v
L4 BDI-inspired goal state
        |
        v
L5 structural verifier
        |
        +--> requirement-to-formal-goal binding
        |
        +--> sealed STRIPS contract
        |       |
        |       +--> internal classical planner (always available)
        |       +--> PDDL + Fast Downward (optional independent cross-check)
        |
        v
L6 Soar-like lifecycle / L7 subsumption priority
        |
        v
L10 deterministic subprocess/filesystem audit
        |
        v
Seal + evidence + aggregate completion gate
        |
        v
PASS / FAIL / UNKNOWN
```

The classical planner does not inspect model chain-of-thought and does not trust
an AI's narration. It reasons only over explicit symbolic facts and the sealed
plan graph. The semantic-binding layer independently checks that the formal goals
cover every required requirement ID. The deterministic audit then independently
proves the concrete work.

## Trust boundary

Formal planning cannot fully repair an incorrect formalization. The new binding
layer prevents omission/disconnection between approved requirements and formal
goals, but it does not understand arbitrary natural-language meaning. For
high-assurance work, the host-owned request contract and acceptance checks remain
authoritative and the symbolic model may still need domain review.

Fast Downward is an optional external executable and is part of the trusted tool
surface when used. The default internal planner requires no GPU, no model API,
and no network connection.
