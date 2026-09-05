# Deployment isolation for a deliberately malicious agent

Plan Auditor's normal mode assumes the AI agent may be wrong or overconfident but
does not have an OS security boundary from the deterministic supervisor. If the
agent process itself is deliberately malicious, a same-user Python lock/HMAC
setup is not a sufficient root of trust: the process can ignore cooperative lock
files and may be able to read same-user key material.

## Required boundary

For that threat model, run the verifier under a different OS/container identity:

1. **Supervisor identity** owns the external HMAC key and Plan Auditor control
   state. The agent identity must not be able to read the key.
2. **Agent identity** gets only the repository/product write permissions needed
   for implementation. It must not be able to modify the supervisor executable,
   key file, service configuration or host approval source.
3. The supervisor receives read access to product state plus the narrowly scoped
   writes required for `.plan-auditor` evidence/seals/registry.
4. Host request activation is performed by the trusted/user side, not by the
   untrusted agent identity.
5. The final audit runs after cooperating agent processes are quiescent. For a
   hostile agent, the OS/container boundary—not `audit.freeze.lock`—prevents
   concurrent mutation of trusted control state.

## Linux example boundary

A typical layout uses two users, for example `pa-agent` and `pa-supervisor`.
Keep the HMAC key in a file readable only by `pa-supervisor` and start the
supervisor service with:

```text
PLAN_AUDITOR_HMAC_KEY_FILE=/var/lib/plan-auditor/keys/project.key
```

The key file should not be inside the workspace. Use normal filesystem ACLs,
service sandboxing or a container mount policy so `pa-agent` cannot read it.

## Container/VM boundary

For stronger isolation, place the deterministic supervisor in a separate
container/VM. Mount product state read-only for the final audit when practical,
and mount only the Plan Auditor control-state directory writable by the
supervisor. Do not share the HMAC secret with the agent container.

## Windows boundary

Use a distinct Windows account/service identity for the supervisor and ACL the
key file so the agent account cannot read it. The same principle applies: a
process running under the same account is not considered isolated merely because
it is a different PID.

## What this changes

This deployment boundary upgrades the external-HMAC/freeze controls from
workspace tamper detection to a meaningful adversarial boundary. Without it, the
project intentionally makes the narrower claim documented in `threat-model.md`:
it detects buggy/overconfident agent behavior and workspace tampering within the
stated same-user trust assumptions; it is not a kernel sandbox.
