# Deployment isolation for a deliberately malicious agent

Plan Auditor's normal mode assumes the AI agent may be wrong or overconfident but
does not have an OS security boundary from the deterministic supervisor. If the
agent process itself is deliberately malicious, a same-user Python lock/HMAC
setup is not a sufficient root of trust: the process can ignore cooperative lock
files and may be able to read same-user key material.

## Required boundary

For that threat model, run the verifier under a different OS/container identity:

1. **Supervisor identity** owns the external HMAC key and Plan Auditor control
   state. Neither the implementing agent nor the code executing behavioral checks
   may read the key or trusted control state.
2. **Agent identity** gets only the repository/product write permissions needed
   for implementation. It must not be able to modify the supervisor executable,
   key file, service configuration or host approval source.
3. **Check-execution identity/container** runs project-controlled verification code
   with neither the supervisor's OS identity nor any key-file access. The trusted
   supervisor checks the results and authenticates evidence *after* that code
   finishes. Simply running the verifier as another user but letting its child
   checks inherit that user's file permissions is NOT sufficient isolation.
4. The supervisor receives read access to product state plus the narrowly scoped
   writes required for `.plan-auditor` evidence/seals/registry.
5. Host request activation is performed by the trusted/user side, not by the
   untrusted agent identity.
6. The final audit runs after cooperating agent processes are quiescent. For a
   hostile agent, the OS/container boundary—not `audit.freeze.lock`—prevents
   concurrent mutation of trusted control state.

## Linux example boundary

A privileged hostile-agent deployment needs three distinct roles, for example
`pa-agent`, `pa-check`, and `pa-supervisor`. Keep the HMAC key in a file
readable only by `pa-supervisor`; the externally isolated `pa-check` worker
must not be able to open it. Start the supervisor service with:

```text
PLAN_AUDITOR_HMAC_KEY_FILE=/var/lib/plan-auditor/keys/project.key
```

The key file must be outside the workspace and be private to the trusted
supervisor. Since 2.4.5, the stock CLI offers an **opt-in Linux privilege drop**
for each behavioral check (not a container sandbox). The supervisor must run as
root; the untrusted check executes as a dedicated, unprivileged OS user.

A minimal trusted-host layout is:

```bash
# Run once as a trusted administrator. The workspace and all ancestors must
# be root-owned. A writable workspace directory must have the sticky bit.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pa-check
sudo install -d -o root -g root -m 1777 /srv/pa-workspace
sudo install -d -o root -g root -m 0700 /srv/pa-workspace/.plan-auditor
sudo install -d -o root -g root -m 0700 /var/lib/plan-auditor/keys
# Provision a strong, random project.key through a trusted mechanism,
# owned by root, mode 0600. Never commit or print the key.
```

The parent directories of the key file must be root-owned and not writable
by group/other. Place the trusted Plan Auditor installation and Python entry
point **outside the agent-writable workspace**, also owned by root. Configure
a host-owned service or root-run invocation:

```bash
sudo env \
  PLAN_AUDITOR_HMAC_KEY_FILE=/var/lib/plan-auditor/keys/project.key \
  PLAN_AUDITOR_CHECK_ISOLATION=required \
  PLAN_AUDITOR_CHECK_UID="$(id -u pa-check)" \
  PLAN_AUDITOR_CHECK_GID="$(id -g pa-check)" \
  /usr/local/bin/plan-auditor audit /srv/pa-workspace
```

The path `/usr/local/bin/plan-auditor` is illustrative; it must point to a
trusted root-managed installation. The host must separately activate and seal
its authoritative plan and retain ownership of `.plan-auditor`; the agent must
not control the supervisor service's environment. The check identity must not
be root and must not have access to the HMAC file or control-state directory.

This mode rejects unsupported platforms, non-root supervisors, invalid IDs,
world/group-readable key files, insecure key parents, and writable workspace
ancestors without root ownership and sticky-bit protection. A failure stops the
check with a nonzero result; it never silently falls back to same-user execution.
Ordinary installations without these variables retain the documented default,
which **does not protect against a deliberately malicious same-user process**.

This is a Linux user-permissions boundary, **not** a namespace, seccomp, resource
quota, or network sandbox. Host operators may additionally put the untrusted
check identity in a separately restricted container/VM and must not grant it
sensitive groups, writable privileged paths, ambient capabilities or sudo rights.

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
