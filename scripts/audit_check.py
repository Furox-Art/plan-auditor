#!/usr/bin/env python3
"""Deterministic Plan Auditor core.

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
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager

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

PG_DIR = ".plan-auditor"
EVIDENCE_HEAD = "evidence.head.json"
CHECK_TYPES = {"run", "exec", "file_exists", "regex", "pytest"}
MAX_ATTEMPTS = 3
ROTATE_BYTES = 2_000_000
SNAPSHOT_DIR = "snapshots"
MAX_OUTPUT_BYTES = 2_000_000
EVIDENCE_LOCK_TIMEOUT = 10.0
EVIDENCE_LOCK_STALE = 60.0
SNAPSHOT_MANIFEST = "__plan_auditor_manifest__.json"
_PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FINGERPRINT_SKIP_DIRS = {".git", PG_DIR, "__pycache__", ".pytest_cache"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def validate_plan_name(name):
    if name in (None, "", "default"):
        return None
    value = str(name)
    if value in {".", ".."} or not _PLAN_NAME_RE.fullmatch(value) or "/" in value or "\\" in value:
        raise ValueError("geçersiz plan adı; yalnız [A-Za-z0-9._-] ve güvenli basename kullanılabilir")
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
            raise ValueError("plan yolu .plan-auditor/plans dışına çıkıyor")
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

    def validate_check(check, sid, label):
        if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
            errs.append("%s: geçersiz kontrol %r" % (label, check))
            return
        kind = check["type"]
        if kind in ("file_exists", "regex") and not check.get("path"):
            errs.append("%s: %s kontrolü 'path' ister" % (label, kind))
        if kind == "regex" and not check.get("pattern"):
            errs.append("%s: regex kontrolü 'pattern' ister" % label)
        if kind in ("run", "exec"):
            cmd = check.get("cmd")
            argv = check.get("argv")
            has_cmd = isinstance(cmd, str) and bool(cmd.strip())
            has_argv = isinstance(argv, list) and bool(argv) and all(
                isinstance(arg, str) and bool(arg) for arg in argv
            )
            if not (has_cmd or has_argv):
                errs.append("%s: %s kontrolü boş olmayan 'cmd' string veya 'argv' listesi ister" % (label, kind))
            if "argv" in check and not has_argv:
                errs.append("%s: %s argv boş olmayan string listesi olmalı" % (label, kind))
            if "shell" in check and not isinstance(check.get("shell"), bool):
                errs.append("%s: %s shell boolean olmalı" % (label, kind))
            if check.get("shell") is True and has_argv:
                errs.append("%s: %s shell=true ile argv birlikte kullanılamaz" % (label, kind))
            if "max_output_bytes" in check:
                try:
                    value = int(check["max_output_bytes"])
                    if value < 1024 or value > 50_000_000:
                        raise ValueError
                except (TypeError, ValueError):
                    errs.append("%s: max_output_bytes 1024..50000000 arası int olmalı" % label)

    if not isinstance(data, dict):
        return ["plan kökü bir obje olmalı"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        errs.append("task: boş olmayan string olmalı")
    if not isinstance(data.get("created"), str) or not data["created"].strip():
        errs.append("created: ISO zaman damgası olmalı")
    if "snapshot" in data and not isinstance(data["snapshot"], list):
        errs.append("snapshot: dosya yolu listesi olmalı (opsiyonel)")
    if "required_tools" in data and (
        not isinstance(data["required_tools"], list)
        or any(not isinstance(item, str) or not item.strip() for item in data["required_tools"])
    ):
        errs.append("required_tools: boş olmayan string listesi olmalı")
    if "requirements" in data:
        if not isinstance(data["requirements"], list) or not data["requirements"]:
            errs.append("requirements: verildiyse boş olmayan liste olmalı")
        else:
            seen_req = set()
            for index, req in enumerate(data["requirements"], 1):
                if isinstance(req, str):
                    continue
                if not isinstance(req, dict):
                    errs.append("requirement %s obje veya string olmalı" % index)
                    continue
                rid = req.get("id")
                if not isinstance(rid, str) or not rid.strip():
                    errs.append("requirement %s id ister" % index)
                elif rid in seen_req:
                    errs.append("requirement id tekrarlı: %s" % rid)
                else:
                    seen_req.add(rid)
                if not isinstance(req.get("description"), str) or not req.get("description", "").strip():
                    errs.append("requirement %s description ister" % (rid or index))
                if str(req.get("priority", "must")).lower() not in {"must", "should", "may"}:
                    errs.append("requirement %s priority must/should/may olmalı" % (rid or index))

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("steps: boş olmayan liste olmalı")
        return errs

    seen = set()
    for step in steps:
        if not isinstance(step, dict):
            errs.append("adım obje olmalı: %r" % (step,))
            continue
        sid = step.get("id")
        if not isinstance(sid, int) or sid < 1:
            errs.append("adım id pozitif int olmalı: %r" % (sid,))
        elif sid in seen:
            errs.append("adım id tekrarlı: %s" % sid)
        seen.add(sid)
        if not isinstance(step.get("title"), str) or not step["title"].strip():
            errs.append("adım %s: title boş olamaz" % sid)
        if "covers" in step and (
            not isinstance(step.get("covers"), list)
            or any(not isinstance(item, str) or not item.strip() for item in step.get("covers", []))
        ):
            errs.append("adım %s: covers string listesi olmalı" % sid)

        checks = step.get("verify")
        if not isinstance(checks, list) or not checks:
            errs.append("adım %s: verify boş olamaz" % sid)
        else:
            behavioral = [check for check in checks if isinstance(check, dict) and check.get("type") in ("run", "pytest", "exec")]
            if not behavioral:
                errs.append("adım %s: en az bir DAVRANIŞSAL kontrol (run/pytest/exec) zorunlu — yalnızca file_exists/regex ile adım doğrulanamaz" % sid)
            for check in checks:
                validate_check(check, sid, "adım %s" % sid)

        outputs = step.get("outputs", [])
        if outputs is not None and isinstance(outputs, list):
            for output in outputs:
                if not isinstance(output, dict):
                    continue
                name = output.get("name")
                output_checks = output.get("verify", [])
                if isinstance(output_checks, list):
                    for check in output_checks:
                        validate_check(check, sid, "adım %s output %r" % (sid, name))

    try:
        effective_dependencies(data)
        topological_order(data)
    except PlanGraphError as exc:
        errs.append("dependency graph: %s" % exc)
    for problem in validate_output_links(data):
        message = "output graph: %s" % problem
        if message not in errs:
            errs.append(message)
    return errs


def norm_check(check):
    if check["type"] == "pytest":
        return {
            "type": "run",
            "cmd": ("python -m pytest " + check.get("args", "")).strip(),
            "expect_exit": 0,
        }
    if check["type"] == "exec":
        normalized = {"type": "run", "expect_exit": check.get("expect_exit", 0)}
        if "argv" in check:
            normalized["argv"] = list(check["argv"])
        else:
            normalized["cmd"] = check["cmd"]
        if check.get("shell") is True:
            normalized["shell"] = True
        for key in ("timeout", "output_regex", "max_output_bytes"):
            if key in check:
                normalized[key] = check[key]
        return normalized
    return check


# ---------------------------------------------------------------- confinement / checks

def _safe_path(base, relative):
    if not isinstance(relative, str) or not relative:
        raise ValueError("path boş olmayan string olmalı")
    root = os.path.realpath(base)
    target = os.path.realpath(os.path.join(root, relative))
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False
    if not inside:
        raise ValueError("path workspace dışına çıkıyor: %s" % relative)
    return target


def _legacy_split(cmd):
    try:
        argv = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError as exc:
        raise ValueError("cmd ayrıştırılamadı: %s" % exc) from exc
    if os.name == "nt":
        argv = [arg[1:-1] if len(arg) >= 2 and arg[0] == arg[-1] == '"' else arg for arg in argv]
    if not argv:
        raise ValueError("cmd boş komuta dönüştü")
    return argv


def _command_spec(check):
    """Return ``(command, use_shell)`` with shell disabled by default."""
    if "argv" in check:
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and bool(arg) for arg in argv):
            raise ValueError("argv boş olmayan string listesi olmalı")
        if check.get("shell") is True:
            raise ValueError("shell=true ile argv birlikte kullanılamaz")
        return list(argv), False
    cmd = check.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd boş olmayan string olmalı")
    if check.get("shell") is True:
        return cmd, True
    return _legacy_split(cmd), False


def _bounded_command(command, use_shell, base, timeout, max_output):
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        try:
            proc = subprocess.Popen(
                command,
                shell=use_shell,
                cwd=base,
                stdout=output_file,
                stderr=subprocess.STDOUT,
            )
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return None, "timeout", "", False
        except (OSError, ValueError) as exc:
            return None, "start", str(exc), False
        size = output_file.tell()
        overflow = size > max_output
        read_size = min(size, max_output)
        output_file.seek(max(0, size - read_size))
        raw = output_file.read(read_size)
        text = raw.decode("utf-8", errors="replace")
        return returncode, "ok", text, overflow


def run_check(check, base, timeout=300):
    """Return ``(passed, detail, output_tail)``."""
    kind = check["type"]
    if kind == "run":
        try:
            command, use_shell = _command_spec(check)
            max_output = int(check.get("max_output_bytes", MAX_OUTPUT_BYTES))
        except (TypeError, ValueError) as exc:
            return False, "komut başlatılamadı: %s" % exc, ""
        rc, state, output, overflow = _bounded_command(
            command,
            use_shell,
            base,
            check.get("timeout", timeout),
            max_output,
        )
        if state == "timeout":
            return False, "komut zaman aşımına uğradı", ""
        if state == "start":
            return False, "komut başlatılamadı: %s" % output, ""
        expected = check.get("expect_exit", 0)
        ok = rc == expected and not overflow
        detail = "exit=%s (beklenen %s)" % (rc, expected)
        if overflow:
            detail += "; çıktı limiti aşıldı (%s byte)" % max_output
        pattern = check.get("output_regex")
        if pattern:
            try:
                matched = re.search(pattern, output) is not None
            except re.error as exc:
                return False, "geçersiz output_regex: %s" % exc, output[-1500:]
            ok = ok and matched
            detail += "; output_regex=%s" % ("eşleşti" if matched else "EŞLEŞMEDİ")
        return ok, detail, output[-1500:]

    if kind == "file_exists":
        try:
            path = _safe_path(base, check["path"])
        except ValueError as exc:
            return False, str(exc), ""
        ok = os.path.isfile(path)
        return ok, "%s %s" % (check["path"], "VAR" if ok else "YOK"), ""

    if kind == "regex":
        try:
            path = _safe_path(base, check["path"])
        except ValueError as exc:
            return False, str(exc), ""
        if not os.path.isfile(path):
            return False, "%s YOK" % check["path"], ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        try:
            ok = re.search(check["pattern"], content) is not None
        except re.error as exc:
            return False, "geçersiz regex: %s" % exc, ""
        return ok, "pattern %s" % ("eşleşti" if ok else "EŞLEŞMEDİ"), ""

    return False, "bilinmeyen kontrol tipi: %s" % kind, ""


# ---------------------------------------------------------------- evidence

def evidence_path(base):
    return os.path.join(base, PG_DIR, "evidence.jsonl")


def _last_record_hash(path):
    if not os.path.isfile(path):
        return "GENESIS"
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return "GENESIS"
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            return json.loads(line).get("hash") or "GENESIS"
        except json.JSONDecodeError:
            return "GENESIS"
    return "GENESIS"


def _archive_paths(base):
    directory = os.path.join(base, PG_DIR, "archive")
    if not os.path.isdir(directory):
        return []
    return [
        os.path.join(directory, filename)
        for filename in sorted(os.listdir(directory))
        if filename.startswith("evidence-") and filename.endswith(".jsonl")
    ]


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


def _write_evidence_head(base, key):
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
    path = _evidence_head_path(base)
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False, "evidence authenticated head missing or invalid"
    if not isinstance(value, dict):
        return False, "evidence authenticated head is not an object"
    auth = value.get("auth")
    payload = {k: v for k, v in value.items() if k != "auth"}
    expected = _expected_evidence_head(base, key)
    if payload != expected:
        return False, "evidence authenticated head checkpoint mismatch"
    if not verify_auth(key, EVIDENCE_HEAD_DOMAIN, payload, auth):
        return False, "evidence authenticated head HMAC failed"
    return True, ""


def _write_evidence_record(path, rec, prev=None):
    base = _base_from_evidence_path(path)
    key = runtime_key(base)
    if prev is not None:
        previous = prev
    elif os.path.isfile(path) and _record_count(path):
        previous = _last_record_hash(path)
    elif os.path.realpath(path) == os.path.realpath(evidence_path(base)):
        previous = _latest_archive_tail(base) or "GENESIS"
    else:
        previous = "GENESIS"
    rec = dict(rec)
    rec["prev"] = previous
    rec["hash"] = hashlib.sha256(canonical(_evidence_hash_payload(rec)).encode("utf-8")).hexdigest()
    if key is not None:
        rec["auth"] = make_auth(key, EVIDENCE_RECORD_DOMAIN, _evidence_auth_payload(rec))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(canonical(rec) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if key is not None and os.path.realpath(path) == os.path.realpath(evidence_path(base)):
        _write_evidence_head(base, key)
    return rec["hash"]


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
                os.write(fd, canonical({"pid": os.getpid(), "ts": time.time()}).encode("utf-8"))
            finally:
                os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - os.stat(lock_path).st_mtime > EVIDENCE_LOCK_STALE:
                    os.unlink(lock_path)
                    continue
            except OSError:
                pass
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
    """Rotate a large active log and anchor it to the previous archive."""
    path = evidence_path(base)
    if not os.path.isfile(path) or os.path.getsize(path) < ROTATE_BYTES:
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
    name = "evidence-%s.jsonl" % stamp
    os.replace(path, os.path.join(archive_dir, name))
    print("NOT: evidence log arşivlendi (rotasyon) — %s" % name)


def append_evidence(base, rec):
    with _evidence_lock(base):
        maybe_rotate(base)
        return _write_evidence_record(evidence_path(base), rec)


def _all_evidence_paths(base):
    return _archive_paths(base) + ([evidence_path(base)] if os.path.isfile(evidence_path(base)) else [])


def count_failed_attempts(base, step_id, plan="default", mode="run"):
    count = 0
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
                if (
                    rec.get("mode") == mode
                    and rec.get("step") == step_id
                    and rec.get("plan", "default") == plan
                    and rec.get("status") == "failed"
                ):
                    count += 1
    return count


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
                return False, count, "satır %s JSON değil" % line_no
            if rec.get("prev") != prev:
                return False, count, "satır %s: prev zinciri kopuk" % line_no
            actual = rec.get("hash")
            expected = hashlib.sha256(canonical(_evidence_hash_payload(rec)).encode("utf-8")).hexdigest()
            if actual != expected:
                return False, count, "satır %s: hash uyuşmuyor (kurcalama?)" % line_no
            auth = rec.get("auth")
            if key is not None:
                if not verify_auth(key, EVIDENCE_RECORD_DOMAIN, _evidence_auth_payload(rec), auth):
                    return False, count, "satır %s: HMAC doğrulaması başarısız" % line_no
            elif auth is not None:
                return False, count, "satır %s: authenticated evidence requires HMAC key" % line_no
            prev = actual
            count += 1
    if key is not None:
        ok, problem = _verify_evidence_head(base, key)
        if not ok:
            return False, count, problem
    elif os.path.isfile(_evidence_head_path(base)):
        return False, count, "authenticated evidence head requires HMAC key"
    return True, count, ""


# ---------------------------------------------------------------- snapshot / rollback

def _workspace_snapshot_files(base):
    root = os.path.realpath(base)
    result = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _FINGERPRINT_SKIP_DIRS)
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            result.append(rel)
    return result


def snapshot_sources(base, plan):
    explicit = list(plan.get("snapshot") or [])
    files = explicit if explicit else _workspace_snapshot_files(base)
    safe = []
    for rel in files:
        try:
            path = _safe_path(base, rel)
        except ValueError:
            continue
        if os.path.isfile(path) or os.path.islink(path):
            safe.append(rel)
    return safe


def snapshots_dir(base):
    return os.path.join(base, PG_DIR, SNAPSHOT_DIR)


def _snapshot_manifest_entry(base, rel):
    path = _safe_path(base, rel)
    info = os.lstat(path)
    entry = {"path": rel.replace(os.sep, "/"), "mode": stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        entry["type"] = "symlink"
        entry["target"] = os.readlink(path)
    else:
        entry["type"] = "file"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        entry["sha256"] = digest.hexdigest()
    return entry


def make_snapshot(base, plan, label="snapshot"):
    sources = snapshot_sources(base, plan)
    if not sources:
        print("ANLIK GÖRÜNTÜ YOK: workspace içinde snapshot alınacak dosya bulunamadı.")
        return None
    os.makedirs(snapshots_dir(base), exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    zpath = os.path.join(snapshots_dir(base), "%s-%s.zip" % (label, stamp))
    scope = "explicit" if plan.get("snapshot") else "full-workspace"
    manifest = {
        "format_version": 2,
        "scope": scope,
        "files": [_snapshot_manifest_entry(base, rel) for rel in sources],
    }
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(SNAPSHOT_MANIFEST, canonical(manifest))
        for entry in manifest["files"]:
            if entry["type"] == "file":
                archive.write(_safe_path(base, entry["path"]), entry["path"])
    append_evidence(base, {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": label,
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(sources),
        "archive": os.path.basename(zpath),
        "scope": scope,
    })
    print("ANLIK GÖRÜNTÜ: %s (%s dosya)" % (os.path.basename(zpath), len(sources)))
    return zpath


def _remove_introduced_files(base, allowed):
    for rel in _workspace_snapshot_files(base):
        normalized = rel.replace(os.sep, "/")
        if normalized in allowed:
            continue
        try:
            path = _safe_path(base, normalized)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
        except OSError:
            pass


def restore_snapshot(base, zpath):
    names = []
    with zipfile.ZipFile(zpath) as archive:
        manifest = None
        if SNAPSHOT_MANIFEST in archive.namelist():
            manifest = json.loads(archive.read(SNAPSHOT_MANIFEST).decode("utf-8"))
        if isinstance(manifest, dict) and manifest.get("format_version") == 2:
            entries = manifest.get("files", [])
            if not isinstance(entries, list):
                raise ValueError("snapshot manifest files listesi geçersiz")
            allowed = {str(item.get("path")) for item in entries if isinstance(item, dict)}
            if manifest.get("scope") == "full-workspace":
                _remove_introduced_files(base, allowed)
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise ValueError("snapshot manifest kaydı geçersiz")
                rel = entry["path"]
                target = _safe_path(base, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if os.path.lexists(target):
                    if os.path.isdir(target) and not os.path.islink(target):
                        raise ValueError("snapshot dosyası mevcut dizinle çakışıyor: %s" % rel)
                    os.unlink(target)
                if entry.get("type") == "symlink":
                    os.symlink(str(entry.get("target", "")), target)
                else:
                    if rel not in archive.namelist():
                        raise ValueError("snapshot archive dosyası eksik: %s" % rel)
                    with archive.open(rel) as src, open(target, "wb") as dst:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                    if os.name != "nt" and isinstance(entry.get("mode"), int):
                        os.chmod(target, entry["mode"])
                    expected = entry.get("sha256")
                    if expected:
                        digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
                        if digest != expected:
                            raise ValueError("snapshot hash uyuşmuyor: %s" % rel)
                names.append(rel)
        else:
            for info in archive.infolist():
                if info.filename == SNAPSHOT_MANIFEST:
                    continue
                target = _safe_path(base, info.filename)
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                names.append(info.filename)
    append_evidence(base, {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": "rollback",
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(names),
        "archive": os.path.basename(zpath),
    })
    print("GERİ YÜKLEME: %s → %s dosya proje üzerine geri yüklendi." % (os.path.basename(zpath), len(names)))


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
    print("%-4s %-42s %-9s %s" % ("ID", "ADIM", "DURUM", "KONTROL"))
    print("-" * 70)
    for step in plan["steps"]:
        title = (step.get("title") or "")[:40]
        checks = step.get("verify", [])
        print("%-4s %-42s %-9s %s" % (
            step["id"], title, step.get("status", "pending").upper(), "%s kontrol" % len(checks),
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
            "output_tail": tail if not ok else "",
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
        order = topological_order(plan)
        effective_dependencies(plan)
        output_problems = validate_output_links(plan)
        if output_problems:
            raise PlanGraphError("; ".join(output_problems))
    except PlanGraphError as exc:
        print("[FAIL] dependency graph geçersiz: %s" % exc)
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

    for step in target:
        sid = step["id"]
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
            print("[BLOK] adım %s: prerequisite/output doğrulaması geçmedi" % sid)
            continue

        attempt = 1
        if mode == "run":
            attempt = count_failed_attempts(base, sid, plan=key) + 1
            if attempt > MAX_ATTEMPTS and not force:
                print("[ATLADI] adım %s: %s önceki gerçek başarısız deneme — %s sınırı aşıldı." % (
                    sid, step.get("title", ""), MAX_ATTEMPTS,
                ))
                passed_this_run[sid] = False
                all_ok = False
                continue

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
        label = "adım %s: %s" % (sid, step.get("title", ""))
        if mode == "run":
            label += " (deneme %s/%s)" % (min(attempt, MAX_ATTEMPTS), MAX_ATTEMPTS)
        print("[%s] %s" % (mark, label))
        for result in results:
            print("       - %s | %s" % ("geçti" if result["passed"] else "KALDI", result["detail"]))
            if not result["passed"] and result["output_tail"]:
                print("         çıktı: %s" % result["output_tail"][-400:].replace("\n", " | "))
        for output in output_results:
            print("       - output %s | %s" % (output["name"], "geçti" if output["passed"] else "KALDI"))

    save_plan(base, plan, name)
    if mode == "audit":
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
            "workspace_fingerprint": workspace_fingerprint(base),
        })
    return all_ok


# ---------------------------------------------------------------- commands

def cmd_validate(args):
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("ŞEMA HATASI: %s" % err)
        return 1
    print("Şema geçerli: %s adım" % len(plan["steps"]))
    return 0


def cmd_run(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    ids = args.ids or None
    target_ids = [step["id"] for step in plan["steps"] if step.get("status") != "verified"] if ids is None else ids
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run", name=args.plan, force=args.force)
    return 0 if all_ok else 1


def cmd_audit(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    print("TAM DENETİM: tüm adımlar taze subprocess ile yeniden test ediliyor...\n")
    all_ok = audit_steps(args.dir, plan, ids=None, mode="audit", name=args.plan)
    print()
    print_table(plan, args.plan)
    if not all_ok:
        print("\nSONUÇ: audit KALDI — görev bitmiş sayılmaz.")
        return 1
    print("\nSONUÇ: audit GEÇTİ — tüm adımlar kanıtlı.")
    return 0


def cmd_status(args):
    ok, count, problem = verify_chain(args.dir)
    plan = load_plan(args.dir, args.plan)
    print_table(plan, args.plan)
    print("\nevidence kaydı: %s" % (count if ok else "ZİNCİR KOPUK"))
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    done = sum(1 for step in plan["steps"] if step.get("status") == "verified")
    print("özet: %s/%s adım verified" % (done, len(plan["steps"])))
    return 0


def cmd_snapshot(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    return 0 if make_snapshot(args.dir, plan) else 1


def cmd_rollback(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    if args.to:
        candidate = os.path.join(snapshots_dir(args.dir), args.to)
        zpath = candidate if os.path.isfile(candidate) else (args.to if os.path.isfile(args.to) else None)
        if not zpath:
            sys.exit("HATA: anlık görüntü bulunamadı: %s" % args.to)
    else:
        zpath = latest_snapshot(args.dir)
        if not zpath:
            sys.exit("HATA: anlık görüntü yok — önce 'snapshot' çalıştır.")
    try:
        restore_snapshot(args.dir, zpath)
    except (ValueError, zipfile.BadZipFile, json.JSONDecodeError, OSError) as exc:
        print("HATA: güvenli rollback başarısız: %s" % exc)
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
        item.add_argument("--plan", help="plan adı (.plan-auditor/plans/<ad>.json); varsayılan: plan.json")
        if name == "run":
            item.add_argument("ids", nargs="*", type=int, help="denetlenecek adım id'leri")
            item.add_argument("--force", action="store_true", help="%s deneme sınırını zorla aş" % MAX_ATTEMPTS)
        if name == "rollback":
            item.add_argument("--to", help="geri yüklenecek zip; varsayılan: en yenisi")

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
