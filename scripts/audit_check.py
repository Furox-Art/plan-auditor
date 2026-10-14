#!/usr/bin/env python3
"""L10 — deterministic Plan Auditor core.

The core never trusts an agent narrative. It executes concrete checks, keeps a
cross-archive append-only evidence chain, limits retries across rotations,
supports safe multi-plan addressing and transactional snapshots, and binds full
audits to deterministic plan/workspace fingerprints.

Exit codes: 0 pass, 1 verification failure, 2 evidence-integrity failure.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - type checkers see the single package import
    from scripts.check_isolation import check_launch_options
    from scripts.contract import PlanTrustError
    from scripts.exec_trust import require_plan_trust
else:
    # Direct-script execution puts ``scripts/`` itself on sys.path, so these are
    # importable unprefixed. The runtime fallback is required; the TYPE_CHECKING
    # branch keeps static analysis from seeing the names bound twice.
    try:
        from scripts.check_isolation import check_launch_options
        from scripts.contract import PlanTrustError
        from scripts.exec_trust import require_plan_trust
    except ImportError:
        from check_isolation import check_launch_options
        from contract import PlanTrustError
        from exec_trust import require_plan_trust

try:
    from scripts.integrity import (
        EVIDENCE_HEAD_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        IntegrityKeyError,
        make_auth,
        runtime_key,
        verify_auth,
    )
except ImportError:
    from integrity import (
        EVIDENCE_HEAD_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        IntegrityKeyError,
        make_auth,
        runtime_key,
        verify_auth,
    )
try:
    from scripts.plan_graph import (
        PlanGraphError,
        effective_dependencies,
        output_index,
        required_outputs,
        topological_order,
        validate_output_links,
    )
except ImportError:
    from plan_graph import (
        PlanGraphError,
        effective_dependencies,
        output_index,
        required_outputs,
        topological_order,
        validate_output_links,
    )
from supervisor.evidence import load_evidence_head as supervisor_load_evidence_head
from supervisor.evidence import verify_evidence_head as supervisor_verify_evidence_head
from supervisor.plans import MAX_PLAN_BYTES

PG_DIR = ".plan-auditor"
EVIDENCE_HEAD = "evidence.head.json"
CHECK_TYPES = {"run", "exec", "file_exists", "regex", "pytest"}
MAX_ATTEMPTS = 3
#: ``auth.alg`` descriptor for records written without a configured HMAC key.
#: Kept local to avoid widening the dual-import redefinition surface.
UNSIGNED_ALG = "none"
ROTATE_BYTES = 2_000_000
SNAPSHOT_DIR = "snapshots"
MAX_OUTPUT_BYTES = 2_000_000
EVIDENCE_LOCK_TIMEOUT = 10.0
EVIDENCE_LOCK_STALE = 60.0
SNAPSHOT_MANIFEST = "__plan_auditor_manifest__.json"
_PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FINGERPRINT_SKIP_DIRS = {".git", PG_DIR, "__pycache__", ".pytest_cache"}

_VALID_RUNTIME_MODES = {"serial", "parallel-warn", "parallel-strict"}

#: Rotation archives carry a monotonically increasing sequence so archive
#: order survives a clock rollback; legacy stamp-only names still sort first
#: ("evidence-" + digit < "evidence-seq"), so their order is preserved too.
_ROTATION_SEQ_RE = re.compile(r"^evidence-seq(\d{8})-")
_SEQ_MARKER = "-seq"


def _strict_runtime_int(data, key, default, minimum, maximum):
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % key)
    if not minimum <= value <= maximum:
        raise ValueError("%s must be between %s..%s" % (key, minimum, maximum))
    return value


def _validated_runtime_config(base):
    path = os.path.join(base, PG_DIR, "supervisor.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid supervisor config: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ValueError("supervisor config root must be an object")

    profile = data.get("profile", "standard")
    if not isinstance(profile, str) or profile.lower() not in {"light", "standard", "strict"}:
        raise ValueError("profile must be the string light/standard/strict")
    tier = data.get("tier", 1)
    if isinstance(tier, bool) or not isinstance(tier, int) or tier not in {1, 2, 3, 4}:
        raise ValueError("tier must be an integer between 1..4")
    mode = data.get("mode", "serial")
    if not isinstance(mode, str) or mode not in _VALID_RUNTIME_MODES:
        raise ValueError("mode must be serial/parallel-warn/parallel-strict")
    pg_dir = data.get("pg_dir", PG_DIR)
    if not isinstance(pg_dir, str) or pg_dir != PG_DIR:
        raise ValueError("pg_dir must be exactly .plan-auditor")
    policies = data.get("policies_dir", "policies")
    if not isinstance(policies, str) or not policies:
        raise ValueError("policies_dir must be a non-empty string")
    if os.path.isabs(policies) or ".." in policies.replace("\\", "/").split("/"):
        raise ValueError("policies_dir must be a relative path inside the workspace")
    if "extra" in data and not isinstance(data.get("extra"), dict):
        raise ValueError("extra must be an object")

    _strict_runtime_int(data, "max_attempts", MAX_ATTEMPTS, 1, 100)
    _strict_runtime_int(data, "owner_timeout_sec", 300, 1, 86_400)
    _strict_runtime_int(data, "heartbeat_sec", 30, 1, 3_600)
    _strict_runtime_int(data, "rotate_bytes", ROTATE_BYTES, 1_024, 1_000_000_000)
    return data


def _runtime_limits(base):
    data = _validated_runtime_config(base)
    max_attempts = (
        _strict_runtime_int(data, "max_attempts", MAX_ATTEMPTS, 1, 100)
        if "max_attempts" in data else MAX_ATTEMPTS
    )
    rotate_bytes = (
        _strict_runtime_int(data, "rotate_bytes", ROTATE_BYTES, 1_024, 1_000_000_000)
        if "rotate_bytes" in data else ROTATE_BYTES
    )
    return max_attempts, rotate_bytes



def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def validate_plan_name(name):
    if name in (None, "", "default"):
        return None
    value = str(name)
    if value in {".", ".."} or not _PLAN_NAME_RE.fullmatch(value) or "/" in value or "\\" in value:
        raise ValueError("invalid plan name; only [A-Za-z0-9._-] and a safe basename are allowed")
    return value


def plan_contract_fingerprint(plan):
    """Hash the immutable verification contract, ignoring runtime status."""
    contract = {
        "contract_version": 3,
        "task": plan.get("task"),
        "requirements": plan.get("requirements"),
        "required_tools": plan.get("required_tools", []),
        "steps": [
            {
                "id": step.get("id"),
                "title": step.get("title"),
                "depends_on": step.get("depends_on"),
                "requires_outputs": step.get("requires_outputs", []),
                "outputs": step.get("outputs", []),
                "covers": step.get("covers", []),
                "verify": step.get("verify", []),
            }
            for step in plan.get("steps", [])
            if isinstance(step, dict)
        ],
    }
    return hashlib.sha256(canonical(contract).encode("utf-8")).hexdigest()


def workspace_fingerprint(base):
    """Content/type/mode hash of workspace product state.

    Auditor/git/cache metadata and mtimes are excluded. Symlinks are hashed as
    links and never followed. Directory entries are included so empty-directory
    and executable/permission changes invalidate a fresh audit.
    """
    root = os.path.realpath(base)
    digest = hashlib.sha256()
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _FINGERPRINT_SKIP_DIRS)
        for dirname in dirnames:
            path = os.path.join(dirpath, dirname)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append((rel, path, "dir"))
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append((rel, path, "file"))

    for rel, path, hint in sorted(entries):
        digest.update(b"PATH\0")
        digest.update(rel.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        try:
            info = os.lstat(path)
            digest.update(("MODE:%o\0" % stat.S_IMODE(info.st_mode)).encode("ascii"))
            if stat.S_ISLNK(info.st_mode):
                digest.update(b"LINK\0")
                digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            elif stat.S_ISREG(info.st_mode):
                digest.update(b"FILE\0")
                with open(path, "rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            elif stat.S_ISDIR(info.st_mode) or hint == "dir":
                digest.update(b"DIR\0")
            else:
                digest.update(b"OTHER\0")
        except OSError as exc:
            digest.update(b"UNREADABLE\0")
            digest.update(type(exc).__name__.encode("ascii", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


# ---------------------------------------------------------------- plan io

def plan_path(base, name=None):
    safe = validate_plan_name(name)
    if safe:
        root = os.path.realpath(os.path.join(base, PG_DIR, "plans"))
        target = os.path.realpath(os.path.join(root, safe + ".json"))
        if os.path.commonpath([root, target]) != root:
            raise ValueError("plan path escapes .plan-auditor/plans")
        return target
    return os.path.join(base, PG_DIR, "plan.json")


def plan_key(name=None):
    return validate_plan_name(name) or "default"


def all_plan_paths(base):
    paths = []
    default = plan_path(base)
    if os.path.isfile(default):
        paths.append((None, default))
    plans_dir = os.path.join(base, PG_DIR, "plans")
    if os.path.isdir(plans_dir):
        for filename in sorted(os.listdir(plans_dir)):
            if not filename.endswith(".json"):
                continue
            stem = filename[:-5]
            try:
                validate_plan_name(stem)
            except ValueError:
                continue
            paths.append((stem, os.path.join(plans_dir, filename)))
    return paths


def load_plan(base, name=None):
    try:
        path = plan_path(base, name)
    except ValueError as exc:
        sys.exit("HATA: %s" % exc)
    if not os.path.isfile(path):
        where = path if not name else "%s (--plan %s)" % (path, name)
        sys.exit("HATA: plan yok: %s" % where)
    # The plan is untrusted input, so it is bounded before it is parsed. See
    # ``supervisor.plans.MAX_PLAN_BYTES``: the same bound the trusted read path
    # uses, so both paths accept the same plans instead of disagreeing.
    size = os.path.getsize(path)
    if size > MAX_PLAN_BYTES:
        sys.exit(
            f"HATA: plan cok buyuk: {path} ({size} bayt, sinir {MAX_PLAN_BYTES} bayt); "
            "plani kucultun veya adlandirilmis planlara bolun"
        )
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save_plan(base, plan, name=None):
    path = plan_path(base, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(plan, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)



def validate_plan(data):
    errs = []

    def add(message):
        if message not in errs:
            errs.append(message)

    def safe_relative(value):
        if not isinstance(value, str) or not value.strip():
            return False
        if os.path.isabs(value) or os.path.splitdrive(value)[0]:
            return False
        parts = value.replace("\\", "/").split("/")
        return ".." not in parts

    def validate_runtime_fields(check, label):
        if "timeout" in check:
            value = check.get("timeout")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0 < value <= 86_400):
                add("%s: timeout must be a number between 0..86400" % label)
        if "expect_exit" in check:
            value = check.get("expect_exit")
            if isinstance(value, bool) or not isinstance(value, int) or not (-255 <= value <= 255):
                add("%s: expect_exit must be an int between -255..255" % label)
        if "max_output_bytes" in check:
            value = check.get("max_output_bytes")
            if isinstance(value, bool) or not isinstance(value, int) or not (1_024 <= value <= 50_000_000):
                add("%s: max_output_bytes must be an int between 1024..50000000" % label)
        if "output_regex" in check:
            value = check.get("output_regex")
            if not isinstance(value, str) or not value:
                add("%s: output_regex must be a non-empty string" % label)
            else:
                try:
                    re.compile(value)
                except re.error as exc:
                    add("%s: invalid output_regex: %s" % (label, exc))

    def validate_check(check, sid, label):
        if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
            add("%s: invalid check %r" % (label, check))
            return
        kind = check["type"]
        if kind in ("file_exists", "regex"):
            path = check.get("path")
            if not safe_relative(path):
                add("%s: %s check requires a safe relative 'path'" % (label, kind))
        if kind == "regex":
            pattern = check.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                add("%s: regex check requires a non-empty 'pattern'" % label)
            else:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    add("%s: invalid regex pattern: %s" % (label, exc))
        if kind in ("run", "exec"):
            has_cmd_key = "cmd" in check
            has_argv_key = "argv" in check
            cmd = check.get("cmd")
            argv = check.get("argv")
            has_cmd = isinstance(cmd, str) and bool(cmd.strip())
            has_argv = (
                isinstance(argv, list) and bool(argv)
                and all(isinstance(arg, str) and bool(arg) for arg in argv)
            )
            if has_cmd_key == has_argv_key:
                add("%s: %s tam olarak bir 'cmd' veya 'argv' ister" % (label, kind))
            if has_cmd_key and not has_cmd:
                add("%s: %s cmd must be a non-empty string" % (label, kind))
            if has_argv_key and not has_argv:
                add("%s: %s argv must be a non-empty list of strings" % (label, kind))
            if "shell" in check:
                add(f"{label}: {kind} shell was removed; the 'shell' key is no longer "
                    "accepted; use an argv list or a shell-less parsed "
                    "'cmd' instead")
            validate_runtime_fields(check, label)
        elif kind == "pytest":
            if any(key in check for key in ("cmd", "argv", "shell")):
                add("%s: pytest does not accept cmd/argv/shell; use args only" % label)
            args = check.get("args", "")
            if not (
                isinstance(args, str)
                or (isinstance(args, list) and all(isinstance(arg, str) and bool(arg) for arg in args))
            ):
                add("%s: pytest args must be a string or a list of strings" % label)
            validate_runtime_fields(check, label)

    if not isinstance(data, dict):
        return ["plan root must be an object"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        add("task: must be a non-empty string")
    created = data.get("created")
    if not isinstance(created, str) or not created.strip():
        add("created: must be an ISO timestamp")
    else:
        try:
            datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            add("created: must be a valid ISO timestamp")
    if "snapshot" in data:
        raw_snapshot = data.get("snapshot")
        if not isinstance(raw_snapshot, list) or any(not safe_relative(item) for item in raw_snapshot):
            add("snapshot: must be a list of safe relative file/directory paths")
    if "required_tools" in data:
        raw_tools = data.get("required_tools")
        if (
            not isinstance(raw_tools, list)
            or any(not isinstance(item, str) or not item.strip() for item in raw_tools)
        ):
            add("required_tools: must be a non-empty list of strings")
    if "requirements" in data:
        requirements = data.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            add("requirements: if given must be a non-empty list")
        else:
            seen_req = set()
            for index, req in enumerate(requirements, 1):
                if isinstance(req, str):
                    if not req.strip():
                        add("requirement %s must not be an empty string" % index)
                    continue
                if not isinstance(req, dict):
                    add("requirement %s must be an object or a string" % index)
                    continue
                rid = req.get("id")
                if not isinstance(rid, str) or not rid.strip():
                    add("requirement %s id ister" % index)
                elif rid in seen_req:
                    add("duplicate requirement id: %s" % rid)
                else:
                    seen_req.add(rid)
                if not isinstance(req.get("description"), str) or not req.get("description", "").strip():
                    add("requirement %s description ister" % (rid or index))
                priority = req.get("priority", "must")
                if not isinstance(priority, str) or priority.lower() not in {"must", "should", "may"}:
                    add("requirement %s priority must be the string must/should/may" % (rid or index))

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        add("steps: must be a non-empty list")
        return errs

    seen = set()
    for step in steps:
        if not isinstance(step, dict):
            add("step must be an object: %r" % (step,))
            continue
        sid = step.get("id")
        if isinstance(sid, bool) or not isinstance(sid, int) or sid < 1:
            add("step id must be a positive int: %r" % (sid,))
        elif sid in seen:
            add("duplicate step id: %s" % sid)
        else:
            seen.add(sid)
        if not isinstance(step.get("title"), str) or not step.get("title", "").strip():
            add("step %s: title must not be empty" % sid)
        if "covers" in step and (
            not isinstance(step.get("covers"), list)
            or any(not isinstance(item, str) or not item.strip() for item in step.get("covers", []))
        ):
            add("step %s: covers must be a list of strings" % sid)

        checks = step.get("verify")
        if not isinstance(checks, list) or not checks:
            add("step %s: verify must not be empty" % sid)
        else:
            behavioral = [
                check for check in checks
                if isinstance(check, dict) and check.get("type") in ("run", "pytest", "exec")
            ]
            if not behavioral:
                add(
                    "step %s: at least one BEHAVIORAL check (run/pytest/exec) is required — "
                    "a step cannot be verified with file_exists/regex alone" % sid
                )
            for check in checks:
                validate_check(check, sid, "step %s" % sid)

        try:
            declared_outputs = output_index(step)
        except PlanGraphError as exc:
            add("output graph: %s" % exc)
            declared_outputs = {}
        for name, output in declared_outputs.items():
            for check in output.get("verify", []):
                validate_check(check, sid, "step %s output %r" % (sid, name))

    try:
        effective_dependencies(data)
        topological_order(data)
    except PlanGraphError as exc:
        add("dependency graph: %s" % exc)
    for problem in validate_output_links(data):
        add("output graph: %s" % problem)
    return errs



def norm_check(check):
    if check["type"] == "pytest":
        args = check.get("args", "")
        extra = _legacy_split(args) if isinstance(args, str) else list(args)
        normalized = {
            "type": "run",
            "argv": [sys.executable, "-m", "pytest"] + extra,
            "expect_exit": check.get("expect_exit", 0),
        }
        for key in ("timeout", "output_regex", "max_output_bytes"):
            if key in check:
                normalized[key] = check[key]
        return normalized
    if check["type"] == "exec":
        _reject_shell(check)
        normalized = {"type": "run", "expect_exit": check.get("expect_exit", 0)}
        if "argv" in check:
            normalized["argv"] = list(check["argv"])
        else:
            normalized["cmd"] = check["cmd"]
        for key in ("timeout", "output_regex", "max_output_bytes"):
            if key in check:
                normalized[key] = check[key]
        return normalized
    return check


def _safe_path(base, relative):
    if not isinstance(relative, str) or not relative:
        raise ValueError("path must be a non-empty string")
    root = os.path.realpath(base)
    target = os.path.realpath(os.path.join(root, relative))
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False
    if not inside:
        raise ValueError("path escapes the workspace: %s" % relative)
    return target


def _windows_argv(command: str) -> list[str]:
    """Split a Windows command line into argv the way ``CommandLineToArgvW`` does.

    No shell is involved, so ``;``, ``|``, ``&``, ``&&`` and redirections are
    ordinary argument characters and can never become control flow. Double quotes
    group, and a backslash is literal except immediately before a closing quote.
    """
    argv = []
    current = []
    quoted = False
    # A quoted empty string is a real argument (""), so token existence is tracked
    # separately from token content; otherwise argv length would silently shrink.
    started = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if char == "\\":
            backslashes = 0
            while index < length and command[index] == "\\":
                backslashes += 1
                index += 1
            started = True
            if index < length and command[index] == '"':
                # CommandLineToArgvW rule: 2n backslashes before a quote emit n
                # backslashes and a literal quote, 2n+1 emit n backslashes and an
                # escaped quote. Either way the quote is never a delimiter.
                current.append("\\" * (backslashes // 2))
                current.append('"')
                index += 1
            else:
                current.append("\\" * backslashes)
            continue
        if char == '"':
            quoted = not quoted
            started = True
            index += 1
            continue
        if char in " \t" and not quoted:
            if started:
                argv.append("".join(current))
                current = []
                started = False
            index += 1
            continue
        current.append(char)
        started = True
        index += 1
    if quoted:
        raise ValueError("cmd could not be parsed: unclosed quote")
    if started:
        argv.append("".join(current))
    return argv


def _legacy_split(cmd: str) -> list[str]:
    """Split a plan ``cmd`` string into argv without invoking a shell."""
    if os.name == "nt":
        argv = _windows_argv(cmd)
    else:
        try:
            argv = shlex.split(cmd, posix=True)
        except ValueError as exc:
            raise ValueError("cmd could not be parsed: %s" % exc) from exc
    if not argv:
        raise ValueError("cmd parsed to an empty command")
    return argv


#: Reported whenever a plan still asks for shell execution. Shell mode handed the
#: entire command line to an interpreter, so ``;``, ``&&``, pipes and redirection
#: became control flow instead of literal arguments.
_SHELL_UNSUPPORTED = (
    "shell execution was removed: 'shell': true is no longer usable because it "
    "passed the whole command line to a shell interpreter. Use 'argv' "
    "(an argument list; no character is interpreted) or keep 'cmd' — "
    "'cmd' is parsed to argv without a shell."
)


def _reject_shell(check: dict) -> dict:
    """Refuse any residual request for shell execution."""
    if check.get("shell") is True:
        raise ValueError(_SHELL_UNSUPPORTED)
    return check


def _command_spec(check: dict) -> list[str]:
    """Return the argv list to execute. A shell is never involved."""
    _reject_shell(check)
    if "argv" in check:
        raw = check.get("argv")
        if not isinstance(raw, list) or not raw or not all(isinstance(arg, str) and bool(arg) for arg in raw):
            raise ValueError("argv must be a non-empty list of strings")
        # Every element was just validated as a non-empty str, so this preserves
        # the argv exactly while giving the caller a concretely typed list.
        return [arg for arg in raw if isinstance(arg, str)]
    cmd = check.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd must be a non-empty string")
    return _legacy_split(cmd)



def _kill_process_tree(proc):
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


def _bounded_command(command, base, timeout, max_output):
    """Execute ``command`` (an argv list) with no shell and bounded resources."""
    kwargs = {
        "cwd": base,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        # Optional Linux root-run UID/GID drop. Even with no isolation enabled,
        # never forward the HMAC key or key-file locator to behavioral checks.
        kwargs.update(check_launch_options(base))
        proc = subprocess.Popen(command, **kwargs)
    except (OSError, ValueError) as exc:
        return None, "start", str(exc), False

    tail = bytearray()
    total = [0]
    overflow_event = threading.Event()

    def drain():
        stream = proc.stdout
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                total[0] += len(chunk)
                tail.extend(chunk)
                if len(tail) > max_output:
                    del tail[: len(tail) - max_output]
                if total[0] > max_output:
                    overflow_event.set()
                    _kill_process_tree(proc)
                    break
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=drain, name="plan-auditor-output-drain", daemon=True)
    reader.start()
    deadline = time.monotonic() + float(timeout)
    state = "ok"
    while proc.poll() is None:
        if overflow_event.is_set():
            state = "overflow"
            _kill_process_tree(proc)
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            state = "timeout"
            _kill_process_tree(proc)
            break
        try:
            proc.wait(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            continue

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    reader.join(timeout=2)
    if reader.is_alive() and proc.stdout is not None:
        try:
            proc.stdout.close()
        except OSError:
            pass
    output = bytes(tail).decode("utf-8", errors="replace")
    overflow = overflow_event.is_set() or total[0] > max_output
    if overflow:
        state = "overflow"
    return proc.returncode, state, output, overflow



def run_check(check, base, timeout=300):
    """Return ``(passed, detail, output_tail)`` with strict runtime bounds."""
    kind = check["type"]
    if kind == "run":
        try:
            command = _command_spec(check)
            max_output = check.get("max_output_bytes", MAX_OUTPUT_BYTES)
            timeout_value = check.get("timeout", timeout)
            expected = check.get("expect_exit", 0)
            if isinstance(max_output, bool) or not isinstance(max_output, int) or not (1_024 <= max_output <= 50_000_000):
                raise ValueError("max_output_bytes must be an int between 1024..50000000")
            if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)) or not (0 < timeout_value <= 86_400):
                raise ValueError("timeout must be a number between 0..86400")
            if isinstance(expected, bool) or not isinstance(expected, int) or not (-255 <= expected <= 255):
                raise ValueError("expect_exit must be an int between -255..255")
        except (TypeError, ValueError) as exc:
            return False, "command could not start: %s" % exc, ""
        rc, state, output, overflow = _bounded_command(
            command, base, timeout_value, max_output
        )
        if state == "timeout":
            return False, "command timed out; process tree terminated", output[-1500:]
        if state == "overflow":
            return False, "output limit exceeded (%s bytes); process tree terminated" % max_output, output[-1500:]
        if state == "start":
            return False, "command could not start: %s" % output, ""
        ok = rc == expected and not overflow
        detail = "exit=%s (expected %s)" % (rc, expected)
        pattern = check.get("output_regex")
        if pattern is not None:
            if not isinstance(pattern, str) or not pattern:
                return False, "output_regex must be a non-empty string", output[-1500:]
            try:
                matched = re.search(pattern, output) is not None
            except re.error as exc:
                return False, "invalid output_regex: %s" % exc, output[-1500:]
            ok = ok and matched
            detail += "; output_regex=%s" % ("matched" if matched else "DID NOT MATCH")
        return ok, detail, output[-1500:]

    if kind == "file_exists":
        try:
            path = _safe_path(base, check["path"])
        except (KeyError, ValueError) as exc:
            return False, str(exc), ""
        ok = os.path.isfile(path)
        return ok, "%s %s" % (check["path"], "EXISTS" if ok else "MISSING"), ""

    if kind == "regex":
        try:
            path = _safe_path(base, check["path"])
        except (KeyError, ValueError) as exc:
            return False, str(exc), ""
        if not os.path.isfile(path):
            return False, "%s MISSING" % check["path"], ""
        # The scan is bounded so a huge file cannot be pulled into memory whole.
        # Truncation is surfaced in the detail so a "did not match" against a
        # truncated prefix is never mistaken for a full scan.
        limit = check.get("max_bytes", MAX_OUTPUT_BYTES)
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1_024 <= limit <= 50_000_000):
            return False, "max_bytes must be an int between 1024..50000000", ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read(limit)
            truncated = handle.read(1) != ""
        pattern = check.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return False, "regex pattern must be a non-empty string", ""
        try:
            ok = re.search(pattern, content) is not None
        except re.error as exc:
            return False, "invalid regex: %s" % exc, ""
        detail = "pattern %s" % ("matched" if ok else "DID NOT MATCH")
        if truncated:
            detail += f" (scan truncated at {limit} bytes)"
        return ok, detail, ""

    return False, "unknown check type: %s" % kind, ""


def evidence_path(base):
    return os.path.join(base, PG_DIR, "evidence.jsonl")


def _last_record_hash(path):
    """The chain hash of the final record, read in a bounded backward window.

    The tail is needed on a hot-ish path (append derivation and rotation), so
    the whole log must not be slurped: the record is the last non-empty line,
    and a window that doubles from 64 KiB until it holds that line is enough.
    An unreadable, empty or unparsable tail reports GENESIS, matching the
    semantics of the full-read implementation.
    """
    if not os.path.isfile(path):
        return "GENESIS"
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            offset = handle.tell()
            window = 65536
            while True:
                start = max(0, offset - window)
                handle.seek(start)
                chunk = handle.read(offset - start)
                if start == 0 or chunk.count(b"\n") >= 2:
                    break
                window *= 2
    except OSError:
        return "GENESIS"
    # rstrip also drops trailing whitespace-only lines, so the last non-empty
    # line is what remains after the final newline.
    text = chunk.decode("utf-8", errors="replace").rstrip()
    if not text:
        return "GENESIS"
    try:
        value = json.loads(text.rsplit("\n", 1)[-1])
    except json.JSONDecodeError:
        return "GENESIS"
    if not isinstance(value, dict):
        return "GENESIS"
    return value.get("hash") or "GENESIS"


def _archive_paths(base):
    directory = os.path.join(base, PG_DIR, "archive")
    if not os.path.isdir(directory):
        return []
    return [
        os.path.join(directory, filename)
        for filename in sorted(os.listdir(directory))
        if filename.startswith("evidence-") and filename.endswith(".jsonl")
    ]


def _next_rotation_sequence(base: str) -> int:
    highest = 0
    directory = os.path.join(base, PG_DIR, "archive")
    try:
        names = os.listdir(directory)
    except OSError:
        return 1
    for name in names:
        match = _ROTATION_SEQ_RE.match(name)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _latest_archive_tail(base):
    paths = _archive_paths(base)
    return _last_record_hash(paths[-1]) if paths else None


def _evidence_hash_payload(rec):
    return {k: v for k, v in rec.items() if k not in {"hash", "auth"}}


def _evidence_auth_payload(rec):
    return {k: v for k, v in rec.items() if k != "auth"}


def _base_from_evidence_path(path):
    return os.path.dirname(os.path.dirname(os.path.realpath(path)))


def _record_count(path):
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _evidence_head_path(base):
    return os.path.join(base, PG_DIR, EVIDENCE_HEAD)


def _load_evidence_head(base: str) -> dict[str, Any] | None:
    """The last committed head checkpoint, or None when there is none.

    O(1) in the size of the evidence log: the checkpoint is a small JSON file
    by design, which is what makes the append path incremental. Read through
    the L11 implementation so the writer here and the reader cannot drift.
    """
    return supervisor_load_evidence_head(base)


def _current_archive_tail(base: str) -> str | None:
    head = _load_evidence_head(base)
    if head is not None and "archive_tail" in head:
        tail = head["archive_tail"]
        return tail if isinstance(tail, str) else None
    tail = _latest_archive_tail(base)
    return tail if isinstance(tail, str) else None


def _expected_evidence_head(base, key):
    active = evidence_path(base)
    archives = _archive_paths(base)
    return {
        "format_version": 2,
        "key_id": key.key_id,
        "active_count": _record_count(active),
        "active_tail": _last_record_hash(active),
        "archive_tail": _last_record_hash(archives[-1]) if archives else None,
    }


def _write_evidence_head(base, key, new_count: int | None = None, new_tail: str | None = None) -> None:
    # The append path passes the two values it already knows (the record it
    # just wrote), which keeps every append O(1) instead of O(N): with a full
    # scan per write, an N-record chain costs N^2 line reads. Rotation and the
    # explicit verifier still take the full-scan path because the archive tail
    # genuinely changed there.
    if new_count is not None and new_tail is not None:
        payload = {
            "format_version": 2,
            "key_id": key.key_id,
            "active_count": new_count,
            "active_tail": new_tail,
            "archive_tail": _current_archive_tail(base),
        }
    else:
        payload = _expected_evidence_head(base, key)
    value = dict(payload)
    value["auth"] = make_auth(key, EVIDENCE_HEAD_DOMAIN, payload)
    path = _evidence_head_path(base)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(canonical(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _verify_evidence_head(base, key):
    # Delegated to L11: the checkpoint is written here (incrementally) but
    # read and verified by exactly one implementation, which is the
    # security-critical direction of the two.
    return supervisor_verify_evidence_head(base, key)


def _write_evidence_record(path, rec, prev=None):
    base = _base_from_evidence_path(path)
    key = runtime_key(base)
    is_active = os.path.realpath(path) == os.path.realpath(evidence_path(base))
    # The committed head checkpoint is the O(1) source for the chain tail and
    # count, but it can lag the log by one record when a previous append was
    # interrupted between the record fsync and the head replace. The bounded
    # log-tail read below cross-checks the checkpoint: agreement keeps the
    # append O(1), a one-record lag continues from the real tail and repairs
    # the checkpoint, and anything else (a deleted, truncated or rewritten
    # log) is deliberately not healed — the checkpoint tail is used instead,
    # so verify_chain reports the break rather than the gap being papered
    # over.
    head = _load_evidence_head(base) if (is_active and prev is None) else None
    count: int | None = None
    repair = False
    if prev is not None:
        previous = prev
    elif head is not None and isinstance(head.get("active_count"), int) and head["active_count"] > 0:
        tail = _last_record_hash(path)
        if tail == (head.get("active_tail") or "GENESIS"):
            previous = tail
            count = head["active_count"]
        else:
            scan = _record_count(path)
            if tail != "GENESIS" and scan == head["active_count"] + 1:
                previous = tail
            else:
                previous = head.get("active_tail") or _current_archive_tail(base) or "GENESIS"
            repair = True
    elif os.path.isfile(path) and _record_count(path):
        previous = _last_record_hash(path)
    elif is_active:
        previous = _latest_archive_tail(base) or "GENESIS"
    else:
        previous = "GENESIS"
    rec = dict(rec)
    rec["prev"] = previous
    rec["hash"] = hashlib.sha256(canonical(_evidence_hash_payload(rec)).encode("utf-8")).hexdigest()
    if key is not None:
        rec["auth"] = make_auth(key, EVIDENCE_RECORD_DOMAIN, _evidence_auth_payload(rec))
    else:
        # Written explicitly rather than left absent so every record states its
        # own trust class: a record with no auth at all cannot be audited for
        # "was this produced without a key, or was the field stripped?".
        rec["auth"] = {"alg": UNSIGNED_ALG}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(canonical(rec) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if key is not None and is_active:
        # Incremental head update: the writer already knows the new tail hash,
        # and the checkpoint read at entry supplies the count without
        # re-reading the log. A full scan runs when no checkpoint was readable
        # (first append or pre-checkpoint state) and when the checkpoint and
        # log disagreed at entry (the cached values cannot be trusted then).
        if repair:
            _write_evidence_head(base, key)
        else:
            previous_count = count if count is not None else (
                head.get("active_count") if head is not None else None
            )
            if isinstance(previous_count, int) and previous_count >= 0:
                new_count = previous_count + 1
            else:
                new_count = _record_count(path)
            _write_evidence_head(base, key, new_count=new_count, new_tail=rec["hash"])
    return rec["hash"]


def _pid_is_alive(pid: object) -> bool:
    """Best-effort liveness probe; only a provably dead PID reports dead.

    ``os.kill(pid, 0)`` is the portable probe: POSIX raises ProcessLookupError
    for a missing process, and CPython's Windows implementation maps it to an
    OpenProcess existence check (ERROR_INVALID_PARAMETER, winerror 87, for a
    PID that no longer exists; access-denied for one that is alive). Anything
    unprovable counts as alive, because the caller only steals locks from
    provably dead holders.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError as exc:
        return getattr(exc, "winerror", None) != 87
    return True


def _lock_holder_dead(lock_path: str) -> bool:
    """Whether an existing lock file is provably abandoned.

    Stale is not dead: a long-running or suspended writer must not be robbed.
    A lock counts as abandoned only when it names this host (a PID from
    another machine cannot be probed) and its PID no longer exists. An
    unreadable lock — including the pre-host format written by older
    versions — is treated as alive, so the caller times out fail-closed.
    """
    try:
        with open(lock_path, encoding="utf-8") as handle:
            info = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(info, dict):
        return False
    if info.get("host") != socket.gethostname():
        return False
    return not _pid_is_alive(info.get("pid"))


@contextmanager
def _evidence_lock(base):
    pg = os.path.join(base, PG_DIR)
    os.makedirs(pg, exist_ok=True)
    lock_path = os.path.join(pg, "evidence.write.lock")
    deadline = time.monotonic() + EVIDENCE_LOCK_TIMEOUT
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                record = {"pid": os.getpid(), "host": socket.gethostname(), "ts": time.time()}
                os.write(fd, canonical(record).encode("utf-8"))
            finally:
                os.close(fd)
            break
        except (FileExistsError, PermissionError):
            # O_EXCL losing a race raises EEXIST (FileExistsError) on POSIX, but
            # Windows reports the same collision as EACCES (PermissionError) when
            # another thread holds the freshly created lock file open. Both mean
            # "someone else has the lock", so retry in either case.
            try:
                stale = time.time() - os.stat(lock_path).st_mtime > EVIDENCE_LOCK_STALE
            except OSError:
                stale = False
            if stale and _lock_holder_dead(lock_path):
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
                continue
            if time.monotonic() >= deadline:
                raise RuntimeError("evidence write lock timeout")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            os.unlink(lock_path)
        except OSError:
            pass



def maybe_rotate(base):
    """Rotate a large active log using the validated supervisor limit."""
    _max_attempts, rotate_bytes = _runtime_limits(base)
    path = evidence_path(base)
    if not os.path.isfile(path) or os.path.getsize(path) < rotate_bytes:
        return
    archive_dir = os.path.join(base, PG_DIR, "archive")
    os.makedirs(archive_dir, exist_ok=True)
    anchor = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": "archive_anchor",
        "plan": "default",
        "step": 0,
        "results": [],
        "status": "verified",
        "previous_archive_hash": _latest_archive_tail(base),
    }
    _write_evidence_record(path, anchor)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    name = f"evidence-seq{_next_rotation_sequence(base):08d}-{stamp}.jsonl"
    os.replace(path, os.path.join(archive_dir, name))
    key = runtime_key(base)
    if key is not None:
        _write_evidence_head(base, key)
    print("NOT: evidence log archived (rotation) — %s" % name)


def append_evidence(base, rec):
    with _evidence_lock(base):
        maybe_rotate(base)
        return _write_evidence_record(evidence_path(base), rec)


def _all_evidence_paths(base):
    return _archive_paths(base) + ([evidence_path(base)] if os.path.isfile(evidence_path(base)) else [])


def failed_attempt_counts(base, mode="run"):
    """Return {(plan, step): failed attempt count} in one pass over the evidence.

    ``audit_steps`` needs this number for every step it is about to run. Reading
    it one step at a time re-read the entire log once per step, which is quadratic
    in the number of steps once the log holds one record per step: a 50-step plan
    against a rotated history parsed the log fifty times. The numbers are the same
    either way, so they are computed once here.
    """
    counts: dict[tuple[str, int], int] = {}
    for path in _all_evidence_paths(base):
        try:
            handle = open(path, encoding="utf-8")
        except OSError:
            continue
        with handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict) or rec.get("mode") != mode:
                    continue
                if rec.get("status") != "failed":
                    continue
                step = rec.get("step")
                plan = rec.get("plan", "default")
                # A record whose step or plan is not a usable key cannot be
                # counted against any real step; it is skipped rather than
                # refusing the run.
                if isinstance(step, bool) or not isinstance(step, int) or not isinstance(plan, str):
                    continue
                key = (plan, step)
                counts[key] = counts.get(key, 0) + 1
    return counts


def count_failed_attempts(base, step_id, plan="default", mode="run"):
    """Genuine failed attempts for one step. Reads the aggregate, one pass total."""
    return failed_attempt_counts(base, mode=mode).get((plan, step_id), 0)


def verify_chain(base):
    path = evidence_path(base)
    try:
        key = runtime_key(base)
    except IntegrityKeyError as exc:
        return False, 0, str(exc)
    if not os.path.isfile(path):
        if key is not None:
            ok, problem = _verify_evidence_head(base, key)
            return ok, 0, problem
        if os.path.isfile(_evidence_head_path(base)):
            return False, 0, "authenticated evidence head requires HMAC key"
        return True, 0, ""

    prev = _latest_archive_tail(base) or "GENESIS"
    count = 0
    with open(path, encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, count, "line %s is not JSON" % line_no
            if rec.get("prev") != prev:
                return False, count, "line %s: prev chain broken" % line_no
            actual = rec.get("hash")
            expected = hashlib.sha256(canonical(_evidence_hash_payload(rec)).encode("utf-8")).hexdigest()
            if actual != expected:
                return False, count, "line %s: hash mismatch (tampered?)" % line_no
            auth = rec.get("auth")
            if key is not None:
                if not verify_auth(key, EVIDENCE_RECORD_DOMAIN, _evidence_auth_payload(rec), auth):
                    return False, count, "line %s: HMAC verification failed" % line_no
            elif isinstance(auth, dict) and auth.get("alg") == UNSIGNED_ALG:
                # Deliberately unsigned record. The hash chain still binds the
                # record, but the chain is rebuildable by anyone with write
                # access to the workspace, so it is tamper-evidence only —
                # NOT authentication. The completion gate gets that verdict
                # from evidence_is_authenticated, not from this function.
                pass
            elif auth is None:
                # Records written before unsigned records carried an explicit
                # descriptor are treated as unsigned under the same rule:
                # absence of authentication is reported, never assumed.
                pass
            else:
                return False, count, "line %s: authenticated evidence requires an HMAC key" % line_no
            prev = actual
            count += 1
    if key is not None:
        ok, problem = _verify_evidence_head(base, key)
        if not ok:
            return False, count, problem
    elif os.path.isfile(_evidence_head_path(base)):
        return False, count, "authenticated evidence head requires HMAC key"
    return True, count, ""


def evidence_is_authenticated(base):
    """Report whether the active evidence chain is HMAC-authenticated.

    A hash chain proves only that the records have not been edited since they
    were written. Without an external HMAC key it can be rebuilt identically,
    so it is tamper-evidence, not proof of authorship. This function separates
    the two questions the gate depends on: ``verify_chain`` reports chain
    integrity; this reports whether the records are attributable to a key
    holder. Any state that is not an authenticated key-backed chain — a key
    resolution failure, unsigned records, records predating the explicit
    descriptor, or a chain that cannot exist yet — fails closed, with a reason
    the operator can act on.
    """
    try:
        key = runtime_key(base)
    except IntegrityKeyError as exc:
        return False, f"integrity configuration is not usable: {exc}"
    if key is not None:
        return True, ""
    path = evidence_path(base)
    if not os.path.isfile(path):
        return False, ("no active evidence chain exists, so there is nothing to "
                       "authenticate; the completion gate cannot treat a "
                       "keyless chain as proof of completion")
    unsigned = 0
    with open(path, encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, f"active evidence line {line_no} is not JSON"
            auth = rec.get("auth") if isinstance(rec, dict) else None
            if isinstance(auth, dict) and auth.get("alg") == UNSIGNED_ALG:
                unsigned += 1
            elif auth is None:
                unsigned += 1
            else:
                return False, (
                    f"active evidence line {line_no} carries an unrecognised auth "
                    "descriptor; a key was configured or the record was tampered "
                    "with after being written"
                )
    if unsigned == 0:
        return False, "active evidence chain contains no records to authenticate"
    return False, (
        f"{unsigned} active evidence record(s) are unsigned because no "
        f"{'PLAN_AUDITOR_HMAC_KEY'} or PLAN_AUDITOR_HMAC_KEY_FILE is configured; "
        "a keyless chain is tamper-evident only and cannot gate completion"
    )


# ---------------------------------------------------------------- snapshot / rollback

def _normalize_snapshot_rel(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("snapshot path must be a non-empty string")
    if os.path.isabs(value) or os.path.splitdrive(value)[0]:
        raise ValueError("snapshot path must be relative: %s" % value)
    parts = value.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("snapshot path must consist of safe basename parts: %s" % value)
    if parts[0] in _FINGERPRINT_SKIP_DIRS:
        raise ValueError("auditor/git/cache metadata cannot be included in a snapshot: %s" % value)
    return "/".join(parts)


def _snapshot_lexical_path(base, rel):
    rel = _normalize_snapshot_rel(rel)
    root = os.path.realpath(base)
    target = os.path.abspath(os.path.join(root, *rel.split("/")))
    try:
        if os.path.commonpath([root, target]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("snapshot path escapes the workspace: %s" % rel) from exc
    parent = os.path.realpath(os.path.dirname(target))
    try:
        if os.path.commonpath([root, parent]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("snapshot parent symlink escapes the workspace: %s" % rel) from exc
    return target


def _safe_snapshot_symlink_target(base, rel, target):
    if not isinstance(target, str) or not target:
        raise ValueError("symlink target must not be empty: %s" % rel)
    if os.path.isabs(target) or os.path.splitdrive(target)[0]:
        raise ValueError("snapshot does not accept external-target symlinks: %s" % rel)
    root = os.path.realpath(base)
    link_path = _snapshot_lexical_path(base, rel)
    resolved = os.path.realpath(os.path.join(os.path.dirname(link_path), target))
    try:
        if os.path.commonpath([root, resolved]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("symlink target escapes the workspace: %s" % rel) from exc
    return target


def _snapshot_manifest_entry(base, rel):
    rel = _normalize_snapshot_rel(rel)
    path = _snapshot_lexical_path(base, rel)
    info = os.lstat(path)
    entry = {"path": rel, "mode": stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        entry["type"] = "symlink"
        entry["target"] = _safe_snapshot_symlink_target(base, rel, os.readlink(path))
    elif stat.S_ISDIR(info.st_mode):
        entry["type"] = "dir"
    elif stat.S_ISREG(info.st_mode):
        entry["type"] = "file"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        entry["sha256"] = digest.hexdigest()
    else:
        raise ValueError("snapshot supports only regular file/dir/symlink: %s" % rel)
    return entry


def _walk_snapshot_tree(base, start_rel=None):
    root = os.path.realpath(base)
    start = root if start_rel is None else _snapshot_lexical_path(base, start_rel)
    entries = {}
    if start_rel is not None:
        first = _snapshot_manifest_entry(base, start_rel)
        entries[first["path"]] = first
        if first["type"] != "dir":
            return entries
    for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
        if start_rel is None:
            dirnames[:] = sorted(name for name in dirnames if name not in _FINGERPRINT_SKIP_DIRS)
        else:
            dirnames[:] = sorted(dirnames)
        kept = []
        for dirname in dirnames:
            path = os.path.join(dirpath, dirname)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entry = _snapshot_manifest_entry(base, rel)
            entries[rel] = entry
            if entry["type"] == "dir":
                kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entry = _snapshot_manifest_entry(base, rel)
            entries[rel] = entry
    return entries


def snapshots_dir(base):
    return os.path.join(base, PG_DIR, SNAPSHOT_DIR)


def _next_snapshot_sequence(base: str) -> int:
    highest = 0
    try:
        names = os.listdir(snapshots_dir(base))
    except OSError:
        return 1
    for name in names:
        if not name.endswith(".zip"):
            continue
        marker = name.rfind(_SEQ_MARKER)
        if marker < 0:
            continue
        digits = name[marker + len(_SEQ_MARKER):marker + len(_SEQ_MARKER) + 8]
        if len(digits) == 8 and digits.isdigit():
            highest = max(highest, int(digits))
    return highest + 1


def make_snapshot(base, plan, label="snapshot"):
    explicit = plan.get("snapshot") or []
    scope = "explicit" if explicit else "full-workspace"
    entries = {}
    absent = []
    roots = []
    if explicit:
        for raw in explicit:
            rel = _normalize_snapshot_rel(raw)
            if rel not in roots:
                roots.append(rel)
            path = _snapshot_lexical_path(base, rel)
            if not os.path.lexists(path):
                absent.append(rel)
                continue
            entries.update(_walk_snapshot_tree(base, rel))
    else:
        entries = _walk_snapshot_tree(base)

    os.makedirs(snapshots_dir(base), exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    zpath = os.path.join(
        snapshots_dir(base),
        f"{label}-seq{_next_snapshot_sequence(base):08d}-{stamp}.zip",
    )
    manifest = {
        "format_version": 3,
        "scope": scope,
        "roots": sorted(roots),
        "absent": sorted(set(absent)),
        "entries": [entries[key] for key in sorted(entries)],
    }
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(SNAPSHOT_MANIFEST, canonical(manifest))
        for entry in manifest["entries"]:
            if entry["type"] == "file":
                archive.write(_snapshot_lexical_path(base, entry["path"]), entry["path"])
    append_evidence(base, {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": label,
        "step": 0,
        "results": [],
        "status": "verified",
        "files": sum(1 for entry in manifest["entries"] if entry["type"] == "file"),
        "entries": len(manifest["entries"]),
        "archive": os.path.basename(zpath),
        "scope": scope,
    })
    print("SNAPSHOT: %s (%s entries)" % (os.path.basename(zpath), len(manifest["entries"])))
    return zpath


def _current_snapshot_entries(base):
    return _walk_snapshot_tree(base)


def _remove_snapshot_path(base, rel):
    target = _snapshot_lexical_path(base, rel)
    if not os.path.lexists(target):
        return
    if os.path.islink(target) or not os.path.isdir(target):
        os.unlink(target)
    else:
        shutil.rmtree(target)


def _entry_kind(path):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    if stat.S_ISREG(info.st_mode):
        return "file"
    return "other"


def _restore_snapshot_v3(base, archive, manifest):
    entries = manifest.get("entries")
    roots = manifest.get("roots", [])
    absent = manifest.get("absent", [])
    scope = manifest.get("scope")
    if scope not in {"full-workspace", "explicit"} or not isinstance(entries, list):
        raise ValueError("snapshot v3 manifest is invalid")
    if not isinstance(roots, list) or not isinstance(absent, list):
        raise ValueError("snapshot v3 roots/absent list is invalid")

    by_path = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("snapshot manifest entry must be an object")
        rel = _normalize_snapshot_rel(entry.get("path"))
        if rel in by_path:
            raise ValueError("snapshot manifest duplicate path: %s" % rel)
        kind = entry.get("type")
        if kind not in {"file", "dir", "symlink"}:
            raise ValueError("snapshot manifest type is invalid: %s" % rel)
        mode = entry.get("mode")
        if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0:
            raise ValueError("snapshot mode is invalid: %s" % rel)
        if kind == "file" and not isinstance(entry.get("sha256"), str):
            raise ValueError("snapshot file hash eksik: %s" % rel)
        if kind == "symlink":
            _safe_snapshot_symlink_target(base, rel, entry.get("target"))
        by_path[rel] = dict(entry, path=rel)

    roots = [_normalize_snapshot_rel(value) for value in roots]
    absent = [_normalize_snapshot_rel(value) for value in absent]
    for rel in by_path:
        parts = rel.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent in by_path and by_path[parent]["type"] != "dir":
                raise ValueError("snapshot child sits under a non-directory parent: %s" % rel)

    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError("snapshot archive contains a duplicate member")
    expected_members = {SNAPSHOT_MANIFEST} | {
        rel for rel, entry in by_path.items() if entry["type"] == "file"
    }
    if set(names) != expected_members:
        raise ValueError("snapshot archive contains off-manifest/missing payload")

    current = _current_snapshot_entries(base)
    allowed = set(by_path)

    def in_scope(rel):
        if scope == "full-workspace":
            return True
        return any(rel == root or rel.startswith(root + "/") for root in roots + absent)

    for rel in sorted(current, key=lambda item: (item.count("/"), item), reverse=True):
        if in_scope(rel) and rel not in allowed:
            _remove_snapshot_path(base, rel)

    for rel, entry in sorted(by_path.items(), key=lambda item: (item[0].count("/"), item[0])):
        target = _snapshot_lexical_path(base, rel)
        if os.path.lexists(target) and _entry_kind(target) != entry["type"]:
            _remove_snapshot_path(base, rel)
        if entry["type"] == "dir":
            os.makedirs(target, exist_ok=True)

    restored = []
    for rel, entry in sorted(by_path.items(), key=lambda item: (item[0].count("/"), item[0])):
        target = _snapshot_lexical_path(base, rel)
        if entry["type"] == "dir":
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target):
            _remove_snapshot_path(base, rel)
        if entry["type"] == "symlink":
            os.symlink(entry["target"], target)
        else:
            digest = hashlib.sha256()
            with archive.open(rel) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    dst.write(chunk)
            if digest.hexdigest() != entry["sha256"]:
                raise ValueError("snapshot hash mismatch: %s" % rel)
            if os.name != "nt":
                os.chmod(target, entry["mode"])
        restored.append(rel)

    if os.name != "nt":
        for rel, entry in sorted(by_path.items(), key=lambda item: item[0].count("/"), reverse=True):
            if entry["type"] == "dir":
                os.chmod(_snapshot_lexical_path(base, rel), entry["mode"])

    for rel, entry in by_path.items():
        target = _snapshot_lexical_path(base, rel)
        if not os.path.lexists(target) or _entry_kind(target) != entry["type"]:
            raise ValueError("snapshot restore type verification failed: %s" % rel)
        if entry["type"] == "symlink" and os.readlink(target) != entry["target"]:
            raise ValueError("snapshot symlink verification failed: %s" % rel)
        if entry["type"] == "file":
            digest = hashlib.sha256()
            with open(target, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != entry["sha256"]:
                raise ValueError("snapshot restore hash verification failed: %s" % rel)
    for rel in absent:
        if os.path.lexists(_snapshot_lexical_path(base, rel)):
            raise ValueError("snapshot absent path could not be restored: %s" % rel)
    return restored


def _restore_snapshot_v2(base, archive, manifest):
    entries = manifest.get("files", [])
    if not isinstance(entries, list):
        raise ValueError("snapshot manifest files list is invalid")
    allowed = {_normalize_snapshot_rel(item.get("path")) for item in entries if isinstance(item, dict)}
    if manifest.get("scope") == "full-workspace":
        current = _current_snapshot_entries(base)
        for rel in sorted(current, key=lambda item: (item.count("/"), item), reverse=True):
            if rel not in allowed:
                _remove_snapshot_path(base, rel)
    restored = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("snapshot manifest entry is invalid")
        rel = _normalize_snapshot_rel(entry["path"])
        target = _snapshot_lexical_path(base, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target):
            _remove_snapshot_path(base, rel)
        if entry.get("type") == "symlink":
            target_value = _safe_snapshot_symlink_target(base, rel, str(entry.get("target", "")))
            os.symlink(target_value, target)
        else:
            if rel not in archive.namelist():
                raise ValueError("snapshot archive file missing: %s" % rel)
            digest = hashlib.sha256()
            with archive.open(rel) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    dst.write(chunk)
            expected = entry.get("sha256")
            if expected and digest.hexdigest() != expected:
                raise ValueError("snapshot hash mismatch: %s" % rel)
            if os.name != "nt" and isinstance(entry.get("mode"), int):
                os.chmod(target, entry["mode"])
        restored.append(rel)
    return restored


def restore_snapshot(base, zpath):
    with zipfile.ZipFile(zpath) as archive:
        if SNAPSHOT_MANIFEST not in archive.namelist():
            raise ValueError("legacy snapshot has no manifest; take a new snapshot for safe rollback")
        manifest = json.loads(archive.read(SNAPSHOT_MANIFEST).decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("snapshot manifest must be an object")
        version = manifest.get("format_version")
        if version == 3:
            names = _restore_snapshot_v3(base, archive, manifest)
        elif version == 2:
            names = _restore_snapshot_v2(base, archive, manifest)
        else:
            raise ValueError("unsupported snapshot format: %r" % version)
    append_evidence(base, {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": "rollback",
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(names),
        "archive": os.path.basename(zpath),
    })
    print("RESTORE: %s → %s entries restored onto the project." % (os.path.basename(zpath), len(names)))


def latest_snapshot(base):
    directory = snapshots_dir(base)
    if not os.path.isdir(directory):
        return None
    zips = sorted(filename for filename in os.listdir(directory) if filename.endswith(".zip"))
    return os.path.join(directory, zips[-1]) if zips else None

# ---------------------------------------------------------------- output / execution

def print_table(plan, name=None):
    if name:
        print("PLAN: %s" % name)
    print("%-4s %-42s %-9s %s" % ("ID", "STEP", "STATUS", "CHECKS"))
    print("-" * 70)
    for step in plan["steps"]:
        title = (step.get("title") or "")[:40]
        checks = step.get("verify", [])
        print("%-4s %-42s %-9s %s" % (
            step["id"], title, step.get("status", "pending").upper(), "%s checks" % len(checks),
        ))


def _run_check_list(raw_checks, base):
    results = []
    ok_all = True
    for raw_check in raw_checks:
        check = norm_check(raw_check)
        ok, detail, tail = run_check(check, base)
        ok_all = ok_all and ok
        results.append({
            "check": check,
            "passed": ok,
            "detail": detail,
            "output_tail": tail,
        })
    return ok_all, results


def _run_output_contract(output, base):
    ok, results = _run_check_list(output.get("verify", []), base)
    return {"name": output.get("name"), "passed": ok, "results": results}


def _prerequisite_gate(base, plan, step, passed_this_run, selected, mode):
    deps = effective_dependencies(plan).get(step["id"], [])
    by_id = {item["id"]: item for item in plan["steps"] if isinstance(item, dict)}
    dependency_results = []
    ok = True
    for dep in deps:
        if mode == "audit" or dep in selected:
            dep_ok = passed_this_run.get(dep) is True
            source = "current_pass"
        else:
            dep_ok = by_id[dep].get("status") == "verified"
            source = "persisted_status"
        dependency_results.append({"step": dep, "passed": dep_ok, "source": source})
        ok = ok and dep_ok

    required_results = []
    if ok:
        for ref in required_outputs(step):
            source_step = by_id[ref["step"]]
            contract = output_index(source_step)[ref["name"]]
            output_result = _run_output_contract(contract, base)
            item = {
                "step": ref["step"],
                "name": ref["name"],
                "passed": output_result["passed"],
                "results": output_result["results"],
            }
            required_results.append(item)
            ok = ok and item["passed"]
    return ok, deps, dependency_results, required_results



def audit_steps(base, plan, ids=None, mode="run", name=None, force=False):
    try:
        max_attempts, _rotate_bytes = _runtime_limits(base)
        order = topological_order(plan)
        effective_dependencies(plan)
        output_problems = validate_output_links(plan)
        if output_problems:
            raise PlanGraphError("; ".join(output_problems))
    except (PlanGraphError, ValueError) as exc:
        print("[FAIL] plan/runtime contract is invalid: %s" % exc)
        return False

    by_id = {step["id"]: step for step in plan["steps"] if isinstance(step, dict)}
    if ids is None or mode == "audit":
        selected = set(order)
    else:
        selected = set(ids)
        unknown = sorted(selected - set(by_id))
        if unknown:
            sys.exit("HATA: verilen id'ler planda yok: %s" % unknown)
        if not selected:
            return True
    target = [by_id[sid] for sid in order if sid in selected]
    key = plan_key(name)
    all_ok = True
    passed_this_run = {}
    audit_baseline = workspace_fingerprint(base) if mode == "audit" else None
    # One pass over the evidence log answers the attempt limit for every step;
    # each step visits this loop exactly once, so a per-step re-read would only
    # re-read the same file. See ``failed_attempt_counts``.
    failed_attempts = failed_attempt_counts(base, mode=mode) if mode == "run" else {}

    for step in target:
        sid = step["id"]
        if mode == "audit" and workspace_fingerprint(base) != audit_baseline:
            step["status"] = "failed"
            passed_this_run[sid] = False
            all_ok = False
            append_evidence(base, {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
                "mode": "audit_guard",
                "plan": key,
                "step": sid,
                "results": [],
                "status": "failed",
                "reason": "workspace changed between final-audit steps",
            })
            break

        prereq_ok, deps, dependency_results, required_results = _prerequisite_gate(
            base, plan, step, passed_this_run, selected, mode
        )
        if not prereq_ok:
            step["status"] = "blocked"
            passed_this_run[sid] = False
            all_ok = False
            append_evidence(base, {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
                "mode": mode,
                "plan": key,
                "step": sid,
                "dependencies": deps,
                "dependency_results": dependency_results,
                "required_outputs": required_results,
                "outputs": [],
                "results": [],
                "status": "blocked",
                "reason": "prerequisite step or required output is not independently verified",
            })
            print("[BLOCKED] step %s: prerequisite/output validation failed" % sid)
            continue

        attempt = 1
        if mode == "run":
            attempt = failed_attempts.get((key, sid), 0) + 1
            if attempt > max_attempts and not force:
                print("[SKIPPED] step %s: %s previous genuine failed attempts — %s limit exceeded." % (
                    sid, step.get("title", ""), max_attempts,
                ))
                passed_this_run[sid] = False
                all_ok = False
                continue

        step_before = workspace_fingerprint(base) if mode == "audit" else None
        ok_all, results = _run_check_list(step.get("verify", []), base)
        output_results = []
        try:
            declared = output_index(step)
        except PlanGraphError as exc:
            declared = {}
            ok_all = False
            results.append({"check": {"type": "output_contract"}, "passed": False, "detail": str(exc), "output_tail": ""})
        for output in declared.values():
            output_result = _run_output_contract(output, base)
            output_results.append(output_result)
            ok_all = ok_all and output_result["passed"]

        if mode == "audit":
            step_after = workspace_fingerprint(base)
            if step_after != step_before or step_after != audit_baseline:
                ok_all = False
                results.append({
                    "check": {"type": "audit_purity"},
                    "passed": False,
                    "detail": (
                        "final-audit verification mutated workspace content/type/mode; "
                        "verification must be observational"
                    ),
                    "output_tail": "",
                })

        step["status"] = "verified" if ok_all else "failed"
        passed_this_run[sid] = ok_all
        all_ok = all_ok and ok_all
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "mode": mode,
            "plan": key,
            "step": sid,
            "dependencies": deps,
            "dependency_results": dependency_results,
            "required_outputs": required_results,
            "outputs": output_results,
            "results": results,
            "status": step["status"],
        }
        if mode == "run":
            rec["attempt"] = attempt
        append_evidence(base, rec)

        mark = "OK " if ok_all else "FAIL"
        label = "step %s: %s" % (sid, step.get("title", ""))
        if mode == "run":
            label += " (attempt %s/%s)" % (min(attempt, max_attempts), max_attempts)
        print("[%s] %s" % (mark, label))
        for result in results:
            print("       - %s | %s" % ("passed" if result["passed"] else "FAILED", result["detail"]))
            if not result["passed"] and result["output_tail"]:
                print("         output: %s" % result["output_tail"][-400:].replace("\n", " | "))
        for output in output_results:
            print("       - output %s | %s" % (output["name"], "passed" if output["passed"] else "FAILED"))

    save_plan(base, plan, name)
    if mode == "audit":
        final_fingerprint = workspace_fingerprint(base)
        if final_fingerprint != audit_baseline:
            all_ok = False
            append_evidence(base, {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
                "mode": "audit_guard",
                "plan": key,
                "step": 0,
                "results": [],
                "status": "failed",
                "reason": "workspace changed during complete final audit",
                "before": audit_baseline,
                "after": final_fingerprint,
            })
        append_evidence(base, {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "mode": "audit_complete",
            "plan": key,
            "step": 0,
            "results": [],
            "status": "verified" if all_ok else "failed",
            "steps": len(plan.get("steps", [])),
            "topological_order": order,
            "plan_fingerprint": plan_contract_fingerprint(plan),
            "workspace_fingerprint": final_fingerprint,
        })
    return all_ok



def cmd_validate(args):
    try:
        _validated_runtime_config(args.dir)
    except ValueError as exc:
        print("CONFIG HATASI: %s" % exc)
        return 1
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("SCHEMA ERROR: %s" % err)
        return 1
    print("Schema valid: %s steps" % len(plan["steps"]))
    return 0



def cmd_run(args):
    try:
        _validated_runtime_config(args.dir)
    except ValueError as exc:
        print("CONFIG HATASI: %s" % exc)
        return 2
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("EVIDENCE CHAIN TAMPERED: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("SCHEMA ERROR: %s" % err)
        return 1
    ids = args.ids or None
    target_ids = [step["id"] for step in plan["steps"] if step.get("status") != "verified"] if ids is None else ids
    # Unconditional and fail-closed: `run` is the command-execution surface, so it
    # must require trust on every invocation, not only when steps are pending.
    try:
        require_plan_trust(args.dir, plan, args.plan)
    except PlanTrustError as exc:
        print("SECURITY: %s" % exc)
        return 2
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run", name=args.plan, force=args.force)
    return 0 if all_ok else 1



def cmd_audit(args):
    try:
        _validated_runtime_config(args.dir)
    except ValueError as exc:
        print("CONFIG HATASI: %s" % exc)
        return 2
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("EVIDENCE CHAIN TAMPERED: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("SCHEMA ERROR: %s" % err)
        return 1
    try:
        require_plan_trust(args.dir, plan, args.plan)
    except PlanTrustError as exc:
        print("SECURITY: %s" % exc)
        return 2
    print("FULL AUDIT: all steps are being retested in fresh subprocesses...\n")
    all_ok = audit_steps(args.dir, plan, ids=None, mode="audit", name=args.plan)
    print()
    print_table(plan, args.plan)
    if not all_ok:
        print("\nRESULT: audit FAILED — the task is not counted as done.")
        return 1
    # The completion gate is authenticated-evidence only (2.5.0). The core
    # `audit` entry point is documented as usable without the supervisor CLI
    # (README, docs/cli.md), so it must enforce the same rule here: a keyless
    # chain is tamper-evident but rebuildable, and must never print PASS.
    authenticated, problem = evidence_is_authenticated(args.dir)
    if not authenticated:
        print(f"\nRESULT: audit FAILED — evidence is not authenticated: {problem}")
        print("Completion requires an authenticated chain: configure "
              "PLAN_AUDITOR_HMAC_KEY (or PLAN_AUDITOR_HMAC_KEY_FILE) and run "
              "'plan-auditor integrity init .'.")
        return 2
    print("\nRESULT: audit PASSED — every step is proven.")
    return 0


def cmd_status(args):
    ok, count, problem = verify_chain(args.dir)
    plan = load_plan(args.dir, args.plan)
    print_table(plan, args.plan)
    print("\nevidence records: %s" % (count if ok else "CHAIN BROKEN"))
    if not ok:
        print("EVIDENCE CHAIN TAMPERED: %s" % problem)
        return 2
    done = sum(1 for step in plan["steps"] if step.get("status") == "verified")
    print("summary: %s/%s steps verified" % (done, len(plan["steps"])))
    return 0


def cmd_snapshot(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("EVIDENCE CHAIN TAMPERED: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    return 0 if make_snapshot(args.dir, plan) else 1


def cmd_rollback(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("EVIDENCE CHAIN TAMPERED: %s" % problem)
        return 2
    if args.to:
        candidate = os.path.join(snapshots_dir(args.dir), args.to)
        zpath = candidate if os.path.isfile(candidate) else (args.to if os.path.isfile(args.to) else None)
        if not zpath:
            sys.exit("ERROR: snapshot not found: %s" % args.to)
    else:
        zpath = latest_snapshot(args.dir)
        if not zpath:
            sys.exit("ERROR: no snapshot exists — run 'snapshot' first.")
    try:
        restore_snapshot(args.dir, zpath)
    except (ValueError, zipfile.BadZipFile, json.JSONDecodeError, OSError) as exc:
        print("ERROR: safe rollback failed: %s" % exc)
        return 1
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="Plan Auditor deterministic core")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("validate", "run", "audit", "status", "snapshot", "rollback"):
        item = sub.add_parser(name)
        item.add_argument("dir", nargs="?", default=".", help="proje dizini")
        item.add_argument("--plan", help="plan name (.plan-auditor/plans/<name>.json); default: plan.json")
        if name == "run":
            item.add_argument("ids", nargs="*", type=int, help="step ids to audit")
            item.add_argument("--force", action="store_true", help="force past the %s attempt limit" % MAX_ATTEMPTS)
        if name == "rollback":
            item.add_argument("--to", help="zip to restore; default: the most recent one")

    args = parser.parse_args()
    args.dir = os.path.abspath(args.dir)
    if not os.path.isdir(args.dir):
        sys.exit("HATA: dizin yok: %s" % args.dir)
    if getattr(args, "plan", None):
        try:
            validate_plan_name(args.plan)
        except ValueError as exc:
            print("HATA: %s" % exc, file=sys.stderr)
            return 1
    return {
        "validate": cmd_validate,
        "run": cmd_run,
        "audit": cmd_audit,
        "status": cmd_status,
        "snapshot": cmd_snapshot,
        "rollback": cmd_rollback,
    }[args.mode](args)


if __name__ == "__main__":
    raise SystemExit(main())
