"""Regression coverage for the pre-execution trust gate and the removal of shell.

The gate closes a remote-code-execution hole: a plan JSON is untrusted input, and
any repository can ship one. Before this change ``plan-auditor run <dir>`` would
execute the ``run``/``exec`` checks of an unsealed, unsigned plan, so cloning a
hostile repository and running the CLI in it was enough to run attacker-chosen
programs with the victim's privileges.

Each test states the attack, the mechanism that stops it, and the recovery step
the operator is told to take.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import audit_check as core
from scripts.contract import (
    PlanTrustError,
    canonical_digest,
    canonical_json,
    payload_without_auth,
    plan_hash,
)
from scripts.exec_trust import require_plan_trust
from supervisor.cli import main as cli_main
from tests.request_fixture import activate_for_plan
from tests.trusted_workspace import establish_trust

ROOT = Path(__file__).resolve().parents[1]

#: Writes a file only if the plan's command is actually executed.
MARKER = "PWNED.txt"
_MARKER_WRITE = (
    "import pathlib;pathlib.Path('PWNED.txt').write_text('executed')"
)
MARKER_CMD = f"python -c \"{_MARKER_WRITE}\""


def _plan(command: str = MARKER_CMD, *, status: str = "pending") -> dict:
    return {
        "task": "prove a plan cannot execute untrusted commands",
        "created": "2026-10-01T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "the declared check", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "the declared check",
                "covers": ["REQ-001"],
                "verify": [{"type": "run", "cmd": command, "expect_exit": 0}],
                "status": status,
            }
        ],
    }


def _workspace(tmp_path: Path, plan: dict | None = None) -> Path:
    (tmp_path / ".plan-auditor").mkdir(parents=True)
    (tmp_path / ".plan-auditor" / "plan.json").write_text(
        json.dumps(plan if plan is not None else _plan(), indent=2) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _marker(root: Path) -> Path:
    return root / MARKER


# --------------------------------------------------------------------------
# (1) A plan is untrusted until it is sealed.
# --------------------------------------------------------------------------

def test_unsealed_plan_refuses_to_execute_and_names_the_sealing_step(tmp_path: Path):
    """The original P0: only plan.json present, no seal, no request contract."""
    root = _workspace(tmp_path)
    assert not _marker(root).exists()

    assert cli_main(["run", str(root), "1"]) == 2
    assert not _marker(root).exists(), "an unsealed plan must never execute"


def test_unsealed_plan_refusal_names_the_sealing_command(tmp_path: Path):
    root = _workspace(tmp_path)
    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    message = str(excinfo.value)
    assert "untrusted" in message
    assert "plan-auditor plan verify" in message


def test_unsealed_plan_is_refused_by_the_real_cli_entry_point(tmp_path: Path):
    """End-to-end through the console script a user actually invokes."""
    root = _workspace(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "run", str(root), "1"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert not _marker(root).exists()
    assert "plan-auditor plan verify" in proc.stdout


def test_unsealed_plan_is_refused_for_full_audit_too(tmp_path: Path):
    root = _workspace(tmp_path)
    assert cli_main(["audit", str(root)]) == 2
    assert not _marker(root).exists()


def test_forged_plan_after_sealing_is_refused(tmp_path: Path):
    """A hostile edit to a previously sealed plan must not execute."""
    root = _workspace(tmp_path)
    establish_trust(root)

    forged = _plan("python -c \"import pathlib;pathlib.Path('FORGED.txt').write_text('x')\"")
    (root / ".plan-auditor" / "plan.json").write_text(json.dumps(forged, indent=2), encoding="utf-8")

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    assert "after it was sealed" in str(excinfo.value)

    assert cli_main(["run", str(root), "1"]) == 2
    assert not (root / "FORGED.txt").exists()


def test_legacy_seal_format_cannot_authorise_execution(tmp_path: Path):
    root = _workspace(tmp_path)
    establish_trust(root)
    seal_file = root / ".plan-auditor" / "seal.json"
    seal = json.loads(seal_file.read_text(encoding="utf-8"))
    seal["format_version"] = 3
    seal_file.write_text(json.dumps(seal, indent=2), encoding="utf-8")

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    assert "format_version=3" in str(excinfo.value)
    assert "migrate-seal" in str(excinfo.value)


def test_missing_plan_hash_cannot_authorise_execution(tmp_path: Path):
    root = _workspace(tmp_path)
    establish_trust(root)
    seal_file = root / ".plan-auditor" / "seal.json"
    seal = json.loads(seal_file.read_text(encoding="utf-8"))
    seal["plan_hash"] = ""
    seal_file.write_text(json.dumps(seal, indent=2), encoding="utf-8")

    with pytest.raises(PlanTrustError):
        require_plan_trust(str(root), core.load_plan(str(root)))


def test_a_validly_sealed_plan_still_executes(tmp_path: Path):
    """The gate must not be a blanket refusal: trusted plans keep working."""
    root = _workspace(tmp_path)
    establish_trust(root)
    assert cli_main(["run", str(root), "1"]) == 0
    assert _marker(root).exists()


# --------------------------------------------------------------------------
# (2) shell=True is gone; metacharacters are literal arguments.
# --------------------------------------------------------------------------

def test_shell_true_is_rejected_by_the_schema(tmp_path: Path):
    assert core.validate_plan(_plan(MARKER_CMD)) == []

    plan = _plan()
    plan["steps"][0]["verify"] = [
        {"type": "run", "cmd": MARKER_CMD, "shell": True, "expect_exit": 0}
    ]
    errors = core.validate_plan(plan)
    assert any("shell" in item and "kaldırıldı" in item for item in errors), errors


def test_shell_true_is_rejected_at_execution(tmp_path: Path):
    """A plan that asks for a shell cannot even be sealed, and never runs."""
    root = _workspace(tmp_path)
    plan = _plan()
    plan["steps"][0]["verify"] = [
        {"type": "run", "cmd": MARKER_CMD, "shell": True, "expect_exit": 0}
    ]
    (root / ".plan-auditor" / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # The schema refuses it, so the executor is never reached.
    assert any("shell" in err for err in core.validate_plan(plan))
    ok, detail, _ = core.run_check(core.norm_check(plan["steps"][0]["verify"][0]), str(root))
    assert ok is False
    assert "kaldırıldı" in detail
    assert not _marker(root).exists()


def test_shell_true_is_rejected_for_exec_checks(tmp_path: Path):
    root = _workspace(tmp_path)
    check = {"type": "exec", "cmd": MARKER_CMD, "shell": True, "expect_exit": 0}
    with pytest.raises(ValueError) as excinfo:
        core.norm_check(check)
    assert "kaldırıldı" in str(excinfo.value)
    assert not _marker(root).exists()


@pytest.mark.parametrize(
    "injected",
    [
        "python -c \"import sys;sys.exit(0)\" ; touch pwned",
        "python -c \"import sys;sys.exit(0)\" && touch pwned",
        "python -c \"import sys;sys.exit(0)\" | touch pwned",
        "python -c \"import sys;sys.exit(0)\" $(touch pwned)",
        "python -c \"import sys;sys.exit(0)\" `touch pwned`",
        "python -c \"import sys;sys.exit(0)\" & touch pwned",
        "python -c \"import sys;sys.exit(0)\" > pwned",
    ],
)
def test_shell_metacharacters_never_become_control_flow(tmp_path: Path, injected: str):
    """No shell means ``;``, ``&&``, ``|``, ``$()``, backticks, ``&`` and ``>`` are
    ordinary argument characters. Executing the split argv must run exactly one
    program and never create the injected file."""
    argv = core._legacy_split(injected)
    assert "pwned" in " ".join(argv), "the injected text stays inside the argument list"

    rc, state, output, overflow = core._bounded_command(argv, str(tmp_path), 60, 2_000_000)
    assert state in {"ok", "start"}, (state, output)
    assert not (tmp_path / "pwned").exists(), "injection produced a second command"
    # Exactly one program ran: python received the metacharacters as arguments.
    assert argv[0].endswith("python") or argv[0].endswith("python3")


def test_command_injection_through_argv_does_not_execute(tmp_path: Path):
    """A hostile ``cmd`` string cannot smuggle a second command through."""
    root = _workspace(tmp_path)
    establish_trust(root)
    payload = (
        "python -c \"import sys; sys.exit(0)\" ; python -c "
        f"\"import pathlib;pathlib.Path('{MARKER}').write_text('x')\""
    )
    plan = _plan(payload)
    (root / ".plan-auditor" / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # The plan changed after sealing, so trust fails before anything runs.
    assert cli_main(["run", str(root), "1"]) == 2
    assert not _marker(root).exists()


def test_argv_arguments_are_passed_literally(tmp_path: Path):
    """argv is a list: nothing is split, escaped or interpreted."""
    argv = core._command_spec({"argv": ["python", "-c", "print('a;b&&c')"]})
    assert argv == ["python", "-c", "print('a;b&&c')"]


def test_command_spec_never_returns_a_shell_flag(tmp_path: Path):
    assert core._command_spec({"cmd": "python -c print"}) == ["python", "-c", "print"]
    with pytest.raises(ValueError) as excinfo:
        core._command_spec({"cmd": "echo hi", "shell": True})
    assert "kaldırıldı" in str(excinfo.value)


def test_bounded_command_executes_without_a_shell(tmp_path: Path):
    marker = tmp_path / "noshell.txt"
    rc, state, output, overflow = core._bounded_command(
        ["python", "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('1')",
         str(marker)],
        str(tmp_path),
        30,
        2_000_000,
    )
    assert rc == 0 and state == "ok" and not overflow
    assert marker.exists()


def test_unescaped_quote_in_cmd_is_rejected_not_guessed(tmp_path: Path):
    """Ambiguous quoting must fail loudly instead of being silently repaired."""
    if os.name != "nt":
        pytest.skip("Windows tokenizer-specific behaviour")
    with pytest.raises(ValueError):
        core._windows_argv('python -c "unterminated')


def test_windows_argv_handles_quotes_and_backslashes():
    if os.name != "nt":
        pytest.skip("Windows tokenizer-specific behaviour")
    # Double quotes group.
    assert core._windows_argv('py -c "a b"') == ["py", "-c", "a b"]
    # A backslash before a quote escapes it into a literal quote character.
    assert core._windows_argv(r'py "a\"b"') == ["py", 'a"b']
    # Backslashes not followed by a quote stay literal (Windows paths).
    assert core._windows_argv(r"py C:\dir\x") == ["py", r"C:\dir\x"]
    assert core._windows_argv(r'py "a\\b"') == ["py", "a\\\\b"]
    # Empty quoted argument is preserved rather than collapsed.
    assert core._windows_argv(r'py ""') == ["py", ""]


# --------------------------------------------------------------------------
# (3) The request contract is cryptographically bound to the sealed plan.
# --------------------------------------------------------------------------

def test_swapped_request_is_refused(tmp_path: Path):
    """A request substituted after sealing must not be honoured."""
    root = _workspace(tmp_path)
    establish_trust(root)

    request_file = root / ".plan-auditor" / "request.json"
    original = json.loads(request_file.read_text(encoding="utf-8"))
    assert original["plan_contract_sha256s"]["default"] == plan_hash(core.load_plan(str(root)))

    swapped = dict(original)
    swapped["task"] = "attacker substituted requirement"
    swapped["requirements"] = [
        {"id": "REQ-001", "description": "anything goes", "priority": "may"}
    ]
    request_file.write_text(json.dumps(swapped, indent=2), encoding="utf-8")

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    assert "swapped after sealing" in str(excinfo.value)

    assert cli_main(["run", str(root), "1"]) == 2
    assert not _marker(root).exists()


def test_whitespace_only_request_edit_still_changes_the_digest(tmp_path: Path):
    """Key order and indentation must not be able to hide a semantic change."""
    root = _workspace(tmp_path)
    establish_trust(root)
    request_file = root / ".plan-auditor" / "request.json"
    original = json.loads(request_file.read_text(encoding="utf-8"))

    reordered = {key: original[key] for key in reversed(list(original))}
    assert canonical_digest(payload_without_auth(reordered)) == canonical_digest(
        payload_without_auth(original)
    ), "canonical digests must be insensitive to key order"

    changed = dict(original)
    changed["task"] = original["task"] + " "
    assert canonical_digest(payload_without_auth(changed)) != canonical_digest(
        payload_without_auth(original)
    )


def test_request_derived_from_a_different_plan_is_refused(tmp_path: Path):
    """A request stamped for plan A cannot authorise plan B."""
    root = _workspace(tmp_path)
    plan = _plan()
    (root / ".plan-auditor" / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    activate_for_plan(root, plan)
    request_file = root / ".plan-auditor" / "request.json"
    stamped = json.loads(request_file.read_text(encoding="utf-8"))["plan_contract_sha256s"]["default"]

    # Re-seal against a genuinely different plan while leaving the request alone.
    other = _plan("python -c \"print('other')\"")
    (root / ".plan-auditor" / "plan.json").write_text(json.dumps(other, indent=2), encoding="utf-8")
    from supervisor.config import load_config
    from supervisor.contracts import environment_contract
    from supervisor.plans import seal_path
    from supervisor.sealing import save_seal, seal_plan

    cfg = load_config(str(root))
    seal = seal_plan(other, "swap", "2026-10-01T00:00:00+00:00",
                     environment=environment_contract(root, cfg))
    save_seal(seal, str(seal_path(root)))

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), other)
    assert "derived from a different plan" in str(excinfo.value)
    assert stamped in str(excinfo.value)


def test_request_binds_every_active_plan_not_only_the_default(tmp_path: Path):
    """Regression: a workspace sealing a default and a named plan under one
    request must authorise both, so the binding is per plan."""
    root = _workspace(tmp_path)
    plans_dir = root / ".plan-auditor" / "plans"
    plans_dir.mkdir(parents=True)
    named = _plan("python -c \"print('named')\"")
    named["task"] = "named plan"
    (plans_dir / "named.json").write_text(json.dumps(named, indent=2), encoding="utf-8")

    default_plan = _plan()
    (root / ".plan-auditor" / "plan.json").write_text(
        json.dumps(default_plan, indent=2), encoding="utf-8"
    )
    activate_for_plan(root, default_plan)
    request = json.loads((root / ".plan-auditor" / "request.json").read_text(encoding="utf-8"))
    bindings = request["plan_contract_sha256s"]
    assert bindings["default"] == plan_hash(default_plan)
    assert bindings["named"] == plan_hash(named), "each active plan must be bound"


def test_request_activation_binds_the_plan_it_approves(tmp_path: Path):
    root = _workspace(tmp_path)
    plan = _plan()
    activate_for_plan(root, plan)
    request = json.loads((root / ".plan-auditor" / "request.json").read_text(encoding="utf-8"))
    assert request["plan_contract_sha256s"]["default"] == plan_hash(core.load_plan(str(root)))


def test_seal_binds_the_request_digest(tmp_path: Path):
    root = _workspace(tmp_path)
    establish_trust(root)
    seal = json.loads((root / ".plan-auditor" / "seal.json").read_text(encoding="utf-8"))
    request = json.loads((root / ".plan-auditor" / "request.json").read_text(encoding="utf-8"))
    assert seal["environment"]["request_sha256"] == canonical_digest(
        payload_without_auth(request)
    )


# --------------------------------------------------------------------------
# (4) Canonical serialization is the single hashing input.
# --------------------------------------------------------------------------

def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": {"d": 2, "c": 3}}) == '{"a":{"c":3,"d":2},"b":1}'
    assert " " not in canonical_json({"a": [1, 2]})


def test_plan_hash_is_independent_of_runtime_status(tmp_path: Path):
    plan = _plan()
    pending = plan_hash(plan)
    plan["steps"][0]["status"] = "verified"
    assert plan_hash(plan) == pending


def test_plan_hash_changes_when_a_command_changes():
    assert plan_hash(_plan("python -c \"print(1)\"")) != plan_hash(_plan("python -c \"print(2)\""))


def test_core_and_supervisor_hash_a_plan_identically():
    """One hashing implementation, so a seal written by either side verifies."""
    from supervisor.sealing import plan_hash as supervisor_plan_hash

    plan = _plan()
    assert plan_hash(plan) == supervisor_plan_hash(plan)
    # ``supervisor.sealing`` must re-export the shared function, not a copy.
    assert supervisor_plan_hash is plan_hash


# --------------------------------------------------------------------------
# (5) HMAC: no silent downgrade to unsigned trust.
# --------------------------------------------------------------------------

def _hmac_env(monkeypatch, key: str = "k" * 48):
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", key)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)


def test_seal_mac_is_required_when_a_key_is_configured(tmp_path: Path, monkeypatch):
    root = _workspace(tmp_path)
    establish_trust(root)
    _hmac_env(monkeypatch)

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    assert "HMAC" in str(excinfo.value)


def test_unsigned_seal_with_mac_but_no_key_is_refused(tmp_path: Path, monkeypatch):
    """An authenticated seal must not be silently accepted when the key is absent."""
    root = _workspace(tmp_path)
    establish_trust(root)
    _hmac_env(monkeypatch)
    assert cli_main(["integrity", "init", str(root)]) == 0
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY")

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    message = str(excinfo.value)
    assert "HMAC" in message and "PLAN_AUDITOR_HMAC_KEY" in message


def test_seal_tampered_after_signing_is_refused(tmp_path: Path, monkeypatch):
    root = _workspace(tmp_path)
    establish_trust(root)
    _hmac_env(monkeypatch)
    assert cli_main(["integrity", "init", str(root)]) == 0

    seal_file = root / ".plan-auditor" / "seal.json"
    seal = json.loads(seal_file.read_text(encoding="utf-8"))
    seal["criteria_count"] = int(seal.get("criteria_count", 1)) + 1
    seal_file.write_text(json.dumps(seal, indent=2), encoding="utf-8")

    with pytest.raises(PlanTrustError) as excinfo:
        require_plan_trust(str(root), core.load_plan(str(root)))
    assert "HMAC authentication failed" in str(excinfo.value)


def test_a_different_key_cannot_authorise(tmp_path: Path, monkeypatch):
    root = _workspace(tmp_path)
    establish_trust(root)
    _hmac_env(monkeypatch)
    assert cli_main(["integrity", "init", str(root)]) == 0

    _hmac_env(monkeypatch, key="z" * 48)
    with pytest.raises(PlanTrustError):
        require_plan_trust(str(root), core.load_plan(str(root)))


def test_hmac_key_file_inside_the_workspace_is_rejected(tmp_path: Path, monkeypatch):
    from scripts.integrity import IntegrityKeyError, load_key

    root = _workspace(tmp_path)
    inside = root / "key.bin"
    inside.write_bytes(b"k" * 48)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(inside))
    with pytest.raises(IntegrityKeyError):
        load_key(root, required=True)