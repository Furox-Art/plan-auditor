#!/usr/bin/env python3
"""Apply the second root-hardening patch deterministically on CI."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{rel}: expected exactly one match, found {count}: {old[:100]!r}")
    write(rel, text.replace(old, new, 1))


def replace_function(rel: str, name: str, new_source: str) -> None:
    text = read(rel)
    match = re.search(rf"^def {re.escape(name)}\(", text, flags=re.MULTILINE)
    if not match:
        raise RuntimeError(f"{rel}: function {name} not found")
    start = match.start()
    next_match = re.search(r"^def [A-Za-z_]\w*\(", text[match.end():], flags=re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    replacement = new_source.rstrip() + "\n\n\n"
    write(rel, text[:start] + replacement + text[end:])


def replace_section(rel: str, start_marker: str, end_marker: str, new_source: str) -> None:
    text = read(rel)
    start = text.find(start_marker)
    end = text.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise RuntimeError(f"{rel}: section markers not found")
    write(rel, text[:start] + new_source.rstrip() + "\n\n" + text[end:])


# ---------------------------------------------------------------- audit core imports / runtime config
replace_once(
    "scripts/audit_check.py",
    "import re\nimport shlex\nimport stat\nimport subprocess\nimport sys\nimport tempfile\nimport time\nimport zipfile\n",
    "import re\nimport shlex\nimport shutil\nimport signal\nimport stat\nimport subprocess\nimport sys\nimport tempfile\nimport threading\nimport time\nimport zipfile\n",
)

runtime_marker = '_FINGERPRINT_SKIP_DIRS = {".git", PG_DIR, "__pycache__", ".pytest_cache"}\n'
runtime_helpers = r'''
_VALID_RUNTIME_MODES = {"serial", "parallel-warn", "parallel-strict"}


def _strict_runtime_int(data, key, default, minimum, maximum):
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s integer olmalı" % key)
    if not minimum <= value <= maximum:
        raise ValueError("%s %s..%s aralığında olmalı" % (key, minimum, maximum))
    return value


def _validated_runtime_config(base):
    path = os.path.join(base, PG_DIR, "supervisor.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("geçersiz supervisor config: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ValueError("supervisor config kökü obje olmalı")

    profile = data.get("profile", "standard")
    if not isinstance(profile, str) or profile.lower() not in {"light", "standard", "strict"}:
        raise ValueError("profile light/standard/strict string olmalı")
    tier = data.get("tier", 1)
    if isinstance(tier, bool) or not isinstance(tier, int) or tier not in {1, 2, 3, 4}:
        raise ValueError("tier 1..4 arası integer olmalı")
    mode = data.get("mode", "serial")
    if not isinstance(mode, str) or mode not in _VALID_RUNTIME_MODES:
        raise ValueError("mode serial/parallel-warn/parallel-strict olmalı")
    pg_dir = data.get("pg_dir", PG_DIR)
    if not isinstance(pg_dir, str) or pg_dir != PG_DIR:
        raise ValueError("pg_dir sabit olarak .plan-auditor olmalı")
    policies = data.get("policies_dir", "policies")
    if not isinstance(policies, str) or not policies:
        raise ValueError("policies_dir boş olmayan string olmalı")
    if os.path.isabs(policies) or ".." in policies.replace("\\", "/").split("/"):
        raise ValueError("policies_dir workspace içinde göreli yol olmalı")
    if "extra" in data and not isinstance(data.get("extra"), dict):
        raise ValueError("extra obje olmalı")

    _strict_runtime_int(data, "max_attempts", MAX_ATTEMPTS, 1, 100)
    _strict_runtime_int(data, "owner_timeout_sec", 300, 1, 86_400)
    _strict_runtime_int(data, "heartbeat_sec", 30, 1, 3_600)
    _strict_runtime_int(data, "rotate_bytes", ROTATE_BYTES, 1_024, 1_000_000_000)
    return data


def _runtime_limits(base):
    data = _validated_runtime_config(base)
    return (
        _strict_runtime_int(data, "max_attempts", MAX_ATTEMPTS, 1, 100),
        _strict_runtime_int(data, "rotate_bytes", ROTATE_BYTES, 1_024, 1_000_000_000),
    )
'''
replace_once(
    "scripts/audit_check.py",
    runtime_marker,
    runtime_marker + runtime_helpers + "\n",
)

validate_plan_source = r'''
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
                add("%s: timeout 0..86400 arası sayı olmalı" % label)
        if "expect_exit" in check:
            value = check.get("expect_exit")
            if isinstance(value, bool) or not isinstance(value, int) or not (-255 <= value <= 255):
                add("%s: expect_exit -255..255 arası int olmalı" % label)
        if "max_output_bytes" in check:
            value = check.get("max_output_bytes")
            if isinstance(value, bool) or not isinstance(value, int) or not (1_024 <= value <= 50_000_000):
                add("%s: max_output_bytes 1024..50000000 arası int olmalı" % label)
        if "output_regex" in check:
            value = check.get("output_regex")
            if not isinstance(value, str) or not value:
                add("%s: output_regex boş olmayan string olmalı" % label)
            else:
                try:
                    re.compile(value)
                except re.error as exc:
                    add("%s: geçersiz output_regex: %s" % (label, exc))

    def validate_check(check, sid, label):
        if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
            add("%s: geçersiz kontrol %r" % (label, check))
            return
        kind = check["type"]
        if kind in ("file_exists", "regex"):
            path = check.get("path")
            if not safe_relative(path):
                add("%s: %s kontrolü güvenli göreli 'path' ister" % (label, kind))
        if kind == "regex":
            pattern = check.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                add("%s: regex kontrolü boş olmayan 'pattern' ister" % label)
            else:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    add("%s: geçersiz regex pattern: %s" % (label, exc))
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
                add("%s: %s cmd boş olmayan string olmalı" % (label, kind))
            if has_argv_key and not has_argv:
                add("%s: %s argv boş olmayan string listesi olmalı" % (label, kind))
            if "shell" in check and not isinstance(check.get("shell"), bool):
                add("%s: %s shell boolean olmalı" % (label, kind))
            if check.get("shell") is True and has_argv_key:
                add("%s: %s shell=true ile argv birlikte kullanılamaz" % (label, kind))
            validate_runtime_fields(check, label)
        elif kind == "pytest":
            if any(key in check for key in ("cmd", "argv", "shell")):
                add("%s: pytest cmd/argv/shell kabul etmez; yalnız args kullan" % label)
            args = check.get("args", "")
            if not (
                isinstance(args, str)
                or (isinstance(args, list) and all(isinstance(arg, str) and bool(arg) for arg in args))
            ):
                add("%s: pytest args string veya string listesi olmalı" % label)
            validate_runtime_fields(check, label)

    if not isinstance(data, dict):
        return ["plan kökü bir obje olmalı"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        add("task: boş olmayan string olmalı")
    created = data.get("created")
    if not isinstance(created, str) or not created.strip():
        add("created: ISO zaman damgası olmalı")
    else:
        try:
            datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            add("created: geçerli ISO zaman damgası olmalı")
    if "snapshot" in data:
        raw_snapshot = data.get("snapshot")
        if not isinstance(raw_snapshot, list) or any(not safe_relative(item) for item in raw_snapshot):
            add("snapshot: güvenli göreli dosya/dizin yolu listesi olmalı")
    if "required_tools" in data:
        raw_tools = data.get("required_tools")
        if (
            not isinstance(raw_tools, list)
            or any(not isinstance(item, str) or not item.strip() for item in raw_tools)
        ):
            add("required_tools: boş olmayan string listesi olmalı")
    if "requirements" in data:
        requirements = data.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            add("requirements: verildiyse boş olmayan liste olmalı")
        else:
            seen_req = set()
            for index, req in enumerate(requirements, 1):
                if isinstance(req, str):
                    if not req.strip():
                        add("requirement %s boş string olamaz" % index)
                    continue
                if not isinstance(req, dict):
                    add("requirement %s obje veya string olmalı" % index)
                    continue
                rid = req.get("id")
                if not isinstance(rid, str) or not rid.strip():
                    add("requirement %s id ister" % index)
                elif rid in seen_req:
                    add("requirement id tekrarlı: %s" % rid)
                else:
                    seen_req.add(rid)
                if not isinstance(req.get("description"), str) or not req.get("description", "").strip():
                    add("requirement %s description ister" % (rid or index))
                priority = req.get("priority", "must")
                if not isinstance(priority, str) or priority.lower() not in {"must", "should", "may"}:
                    add("requirement %s priority must/should/may string olmalı" % (rid or index))

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        add("steps: boş olmayan liste olmalı")
        return errs

    seen = set()
    for step in steps:
        if not isinstance(step, dict):
            add("adım obje olmalı: %r" % (step,))
            continue
        sid = step.get("id")
        if isinstance(sid, bool) or not isinstance(sid, int) or sid < 1:
            add("adım id pozitif int olmalı: %r" % (sid,))
        elif sid in seen:
            add("adım id tekrarlı: %s" % sid)
        else:
            seen.add(sid)
        if not isinstance(step.get("title"), str) or not step.get("title", "").strip():
            add("adım %s: title boş olamaz" % sid)
        if "covers" in step and (
            not isinstance(step.get("covers"), list)
            or any(not isinstance(item, str) or not item.strip() for item in step.get("covers", []))
        ):
            add("adım %s: covers string listesi olmalı" % sid)

        checks = step.get("verify")
        if not isinstance(checks, list) or not checks:
            add("adım %s: verify boş olamaz" % sid)
        else:
            behavioral = [
                check for check in checks
                if isinstance(check, dict) and check.get("type") in ("run", "pytest", "exec")
            ]
            if not behavioral:
                add(
                    "adım %s: en az bir DAVRANIŞSAL kontrol (run/pytest/exec) zorunlu — "
                    "yalnızca file_exists/regex ile adım doğrulanamaz" % sid
                )
            for check in checks:
                validate_check(check, sid, "adım %s" % sid)

        try:
            declared_outputs = output_index(step)
        except PlanGraphError as exc:
            add("output graph: %s" % exc)
            declared_outputs = {}
        for name, output in declared_outputs.items():
            for check in output.get("verify", []):
                validate_check(check, sid, "adım %s output %r" % (sid, name))

    try:
        effective_dependencies(data)
        topological_order(data)
    except PlanGraphError as exc:
        add("dependency graph: %s" % exc)
    for problem in validate_output_links(data):
        add("output graph: %s" % problem)
    return errs
'''
replace_function("scripts/audit_check.py", "validate_plan", validate_plan_source)

norm_source = r'''
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
'''
replace_function("scripts/audit_check.py", "norm_check", norm_source)

bounded_source = r'''
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


def _bounded_command(command, use_shell, base, timeout, max_output):
    kwargs = {
        "shell": use_shell,
        "cwd": base,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
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
'''
replace_function("scripts/audit_check.py", "_bounded_command", bounded_source)

run_check_source = r'''
def run_check(check, base, timeout=300):
    """Return ``(passed, detail, output_tail)`` with strict runtime bounds."""
    kind = check["type"]
    if kind == "run":
        try:
            command, use_shell = _command_spec(check)
            max_output = check.get("max_output_bytes", MAX_OUTPUT_BYTES)
            timeout_value = check.get("timeout", timeout)
            expected = check.get("expect_exit", 0)
            if isinstance(max_output, bool) or not isinstance(max_output, int) or not (1_024 <= max_output <= 50_000_000):
                raise ValueError("max_output_bytes 1024..50000000 arası int olmalı")
            if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)) or not (0 < timeout_value <= 86_400):
                raise ValueError("timeout 0..86400 arası sayı olmalı")
            if isinstance(expected, bool) or not isinstance(expected, int) or not (-255 <= expected <= 255):
                raise ValueError("expect_exit -255..255 arası int olmalı")
        except (TypeError, ValueError) as exc:
            return False, "komut başlatılamadı: %s" % exc, ""
        rc, state, output, overflow = _bounded_command(
            command, use_shell, base, timeout_value, max_output
        )
        if state == "timeout":
            return False, "komut zaman aşımına uğradı; process tree sonlandırıldı", output[-1500:]
        if state == "overflow":
            return False, "çıktı limiti aşıldı (%s byte); process tree sonlandırıldı" % max_output, output[-1500:]
        if state == "start":
            return False, "komut başlatılamadı: %s" % output, ""
        ok = rc == expected and not overflow
        detail = "exit=%s (beklenen %s)" % (rc, expected)
        pattern = check.get("output_regex")
        if pattern is not None:
            if not isinstance(pattern, str) or not pattern:
                return False, "output_regex boş olmayan string olmalı", output[-1500:]
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
        except (KeyError, ValueError) as exc:
            return False, str(exc), ""
        ok = os.path.isfile(path)
        return ok, "%s %s" % (check["path"], "VAR" if ok else "YOK"), ""

    if kind == "regex":
        try:
            path = _safe_path(base, check["path"])
        except (KeyError, ValueError) as exc:
            return False, str(exc), ""
        if not os.path.isfile(path):
            return False, "%s YOK" % check["path"], ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read()
        pattern = check.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return False, "regex pattern boş olmayan string olmalı", ""
        try:
            ok = re.search(pattern, content) is not None
        except re.error as exc:
            return False, "geçersiz regex: %s" % exc, ""
        return ok, "pattern %s" % ("eşleşti" if ok else "EŞLEŞMEDİ"), ""

    return False, "bilinmeyen kontrol tipi: %s" % kind, ""
'''
replace_function("scripts/audit_check.py", "run_check", run_check_source)

maybe_rotate_source = r'''
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
    name = "evidence-%s.jsonl" % stamp
    os.replace(path, os.path.join(archive_dir, name))
    key = runtime_key(base)
    if key is not None:
        _write_evidence_head(base, key)
    print("NOT: evidence log arşivlendi (rotasyon) — %s" % name)
'''
replace_function("scripts/audit_check.py", "maybe_rotate", maybe_rotate_source)

snapshot_section = r'''# ---------------------------------------------------------------- snapshot / rollback

def _normalize_snapshot_rel(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("snapshot yolu boş olmayan string olmalı")
    if os.path.isabs(value) or os.path.splitdrive(value)[0]:
        raise ValueError("snapshot yolu göreli olmalı: %s" % value)
    parts = value.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("snapshot yolu güvenli basename parçalarından oluşmalı: %s" % value)
    if parts[0] in _FINGERPRINT_SKIP_DIRS:
        raise ValueError("auditor/git/cache metadata snapshot kapsamına alınamaz: %s" % value)
    return "/".join(parts)


def _snapshot_lexical_path(base, rel):
    rel = _normalize_snapshot_rel(rel)
    root = os.path.realpath(base)
    target = os.path.abspath(os.path.join(root, *rel.split("/")))
    try:
        if os.path.commonpath([root, target]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("snapshot yolu workspace dışına çıkıyor: %s" % rel) from exc
    parent = os.path.realpath(os.path.dirname(target))
    try:
        if os.path.commonpath([root, parent]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("snapshot parent symlink workspace dışına çıkıyor: %s" % rel) from exc
    return target


def _safe_snapshot_symlink_target(base, rel, target):
    if not isinstance(target, str) or not target:
        raise ValueError("symlink hedefi boş olamaz: %s" % rel)
    if os.path.isabs(target) or os.path.splitdrive(target)[0]:
        raise ValueError("snapshot dış hedefli symlink kabul etmez: %s" % rel)
    root = os.path.realpath(base)
    link_path = _snapshot_lexical_path(base, rel)
    resolved = os.path.realpath(os.path.join(os.path.dirname(link_path), target))
    try:
        if os.path.commonpath([root, resolved]) != root:
            raise ValueError
    except ValueError as exc:
        raise ValueError("symlink hedefi workspace dışına çıkıyor: %s" % rel) from exc
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
        raise ValueError("snapshot yalnız regular file/dir/symlink destekler: %s" % rel)
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
    zpath = os.path.join(snapshots_dir(base), "%s-%s.zip" % (label, stamp))
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
    print("ANLIK GÖRÜNTÜ: %s (%s kayıt)" % (os.path.basename(zpath), len(manifest["entries"])))
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
        raise ValueError("snapshot v3 manifest geçersiz")
    if not isinstance(roots, list) or not isinstance(absent, list):
        raise ValueError("snapshot v3 roots/absent listesi geçersiz")

    by_path = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("snapshot manifest kaydı obje olmalı")
        rel = _normalize_snapshot_rel(entry.get("path"))
        if rel in by_path:
            raise ValueError("snapshot manifest duplicate path: %s" % rel)
        kind = entry.get("type")
        if kind not in {"file", "dir", "symlink"}:
            raise ValueError("snapshot manifest type geçersiz: %s" % rel)
        mode = entry.get("mode")
        if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0:
            raise ValueError("snapshot mode geçersiz: %s" % rel)
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
                raise ValueError("snapshot child non-directory parent altında: %s" % rel)

    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError("snapshot archive duplicate member içeriyor")
    expected_members = {SNAPSHOT_MANIFEST} | {
        rel for rel, entry in by_path.items() if entry["type"] == "file"
    }
    if set(names) != expected_members:
        raise ValueError("snapshot archive manifest dışı/eksik payload içeriyor")

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
                raise ValueError("snapshot hash uyuşmuyor: %s" % rel)
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
            raise ValueError("snapshot restore type doğrulaması başarısız: %s" % rel)
        if entry["type"] == "symlink" and os.readlink(target) != entry["target"]:
            raise ValueError("snapshot symlink doğrulaması başarısız: %s" % rel)
        if entry["type"] == "file":
            digest = hashlib.sha256()
            with open(target, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != entry["sha256"]:
                raise ValueError("snapshot restore hash doğrulaması başarısız: %s" % rel)
    for rel in absent:
        if os.path.lexists(_snapshot_lexical_path(base, rel)):
            raise ValueError("snapshot absent path geri yüklenemedi: %s" % rel)
    return restored


def _restore_snapshot_v2(base, archive, manifest):
    entries = manifest.get("files", [])
    if not isinstance(entries, list):
        raise ValueError("snapshot manifest files listesi geçersiz")
    allowed = {_normalize_snapshot_rel(item.get("path")) for item in entries if isinstance(item, dict)}
    if manifest.get("scope") == "full-workspace":
        current = _current_snapshot_entries(base)
        for rel in sorted(current, key=lambda item: (item.count("/"), item), reverse=True):
            if rel not in allowed:
                _remove_snapshot_path(base, rel)
    restored = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("snapshot manifest kaydı geçersiz")
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
                raise ValueError("snapshot archive dosyası eksik: %s" % rel)
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
                raise ValueError("snapshot hash uyuşmuyor: %s" % rel)
            if os.name != "nt" and isinstance(entry.get("mode"), int):
                os.chmod(target, entry["mode"])
        restored.append(rel)
    return restored


def restore_snapshot(base, zpath):
    with zipfile.ZipFile(zpath) as archive:
        if SNAPSHOT_MANIFEST not in archive.namelist():
            raise ValueError("legacy snapshot manifest içermiyor; güvenli rollback için yeniden snapshot alın")
        manifest = json.loads(archive.read(SNAPSHOT_MANIFEST).decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("snapshot manifest obje olmalı")
        version = manifest.get("format_version")
        if version == 3:
            names = _restore_snapshot_v3(base, archive, manifest)
        elif version == 2:
            names = _restore_snapshot_v2(base, archive, manifest)
        else:
            raise ValueError("desteklenmeyen snapshot formatı: %r" % version)
    append_evidence(base, {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
        "mode": "rollback",
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(names),
        "archive": os.path.basename(zpath),
    })
    print("GERİ YÜKLEME: %s → %s kayıt proje üzerine geri yüklendi." % (os.path.basename(zpath), len(names)))


def latest_snapshot(base):
    directory = snapshots_dir(base)
    if not os.path.isdir(directory):
        return None
    zips = sorted(filename for filename in os.listdir(directory) if filename.endswith(".zip"))
    return os.path.join(directory, zips[-1]) if zips else None
'''
replace_section(
    "scripts/audit_check.py",
    "# ---------------------------------------------------------------- snapshot / rollback",
    "# ---------------------------------------------------------------- output / execution",
    snapshot_section,
)

audit_steps_source = r'''
def audit_steps(base, plan, ids=None, mode="run", name=None, force=False):
    try:
        max_attempts, _rotate_bytes = _runtime_limits(base)
        order = topological_order(plan)
        effective_dependencies(plan)
        output_problems = validate_output_links(plan)
        if output_problems:
            raise PlanGraphError("; ".join(output_problems))
    except (PlanGraphError, ValueError) as exc:
        print("[FAIL] plan/runtime contract geçersiz: %s" % exc)
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
            print("[BLOK] adım %s: prerequisite/output doğrulaması geçmedi" % sid)
            continue

        attempt = 1
        if mode == "run":
            attempt = count_failed_attempts(base, sid, plan=key) + 1
            if attempt > max_attempts and not force:
                print("[ATLADI] adım %s: %s önceki gerçek başarısız deneme — %s sınırı aşıldı." % (
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
        label = "adım %s: %s" % (sid, step.get("title", ""))
        if mode == "run":
            label += " (deneme %s/%s)" % (min(attempt, max_attempts), max_attempts)
        print("[%s] %s" % (mark, label))
        for result in results:
            print("       - %s | %s" % ("geçti" if result["passed"] else "KALDI", result["detail"]))
            if not result["passed"] and result["output_tail"]:
                print("         çıktı: %s" % result["output_tail"][-400:].replace("\n", " | "))
        for output in output_results:
            print("       - output %s | %s" % (output["name"], "geçti" if output["passed"] else "KALDI"))

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
'''
replace_function("scripts/audit_check.py", "audit_steps", audit_steps_source)

cmd_validate_source = r'''
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
            print("ŞEMA HATASI: %s" % err)
        return 1
    print("Şema geçerli: %s adım" % len(plan["steps"]))
    return 0
'''
replace_function("scripts/audit_check.py", "cmd_validate", cmd_validate_source)

cmd_run_source = r'''
def cmd_run(args):
    try:
        _validated_runtime_config(args.dir)
    except ValueError as exc:
        print("CONFIG HATASI: %s" % exc)
        return 2
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("ŞEMA HATASI: %s" % err)
        return 1
    ids = args.ids or None
    target_ids = [step["id"] for step in plan["steps"] if step.get("status") != "verified"] if ids is None else ids
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run", name=args.plan, force=args.force)
    return 0 if all_ok else 1
'''
replace_function("scripts/audit_check.py", "cmd_run", cmd_run_source)

cmd_core_audit_source = r'''
def cmd_audit(args):
    try:
        _validated_runtime_config(args.dir)
    except ValueError as exc:
        print("CONFIG HATASI: %s" % exc)
        return 2
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    errs = validate_plan(plan)
    if errs:
        for err in errs:
            print("ŞEMA HATASI: %s" % err)
        return 1
    print("TAM DENETİM: tüm adımlar taze subprocess ile yeniden test ediliyor...\n")
    all_ok = audit_steps(args.dir, plan, ids=None, mode="audit", name=args.plan)
    print()
    print_table(plan, args.plan)
    if not all_ok:
        print("\nSONUÇ: audit KALDI — görev bitmiş sayılmaz.")
        return 1
    print("\nSONUÇ: audit GEÇTİ — tüm adımlar kanıtlı.")
    return 0
'''
replace_function("scripts/audit_check.py", "cmd_audit", cmd_core_audit_source)

# ---------------------------------------------------------------- integrated CLI freeze
cli_audit_source = r'''
def cmd_audit(args: argparse.Namespace) -> int:
    from .agents import MultiAgentRegistry
    from .audit_session import AuditSessionError, final_audit_session
    from .config import load_config
    from .contracts import environment_contract
    from .orchestrator import evaluate_workspace
    from .plans import load_plan_ref, seal_path
    from .sealing import SealIntegrityError, check_environment, check_monotonic, load_seal

    root = _root(args.dir)
    try:
        refs = _selected_refs(root, args.plan)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    request_status, request_alignment, request_errors = _request_gate(root)
    if request_errors:
        _json({"outcome": "FAIL", "request_contract": request_status.as_dict(), "request_errors": request_errors})
        return 2
    cfg = load_config(str(root))
    policy_errors = _policy_errors(root, cfg)
    if cfg.errors or policy_errors:
        _json({"outcome": "FAIL", "configuration_errors": cfg.errors, "policy_errors": policy_errors})
        return 2
    env = environment_contract(root, cfg)

    for ref in refs:
        try:
            plan = load_plan_ref(ref)
            seal = load_seal(str(seal_path(root, ref.name)))
        except (OSError, ValueError, json.JSONDecodeError, SealIntegrityError) as exc:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": str(exc)})
            return 2
        if not seal:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": "plan is not sealed; run plan verify first"})
            return 2
        if seal.format_version < 4:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": "legacy seal requires explicit reseal"})
            return 2
        monotonic = check_monotonic(seal.as_plan(), plan)
        env_check = check_environment(seal, env)
        if not monotonic.ok or not env_check.ok:
            _json({
                "outcome": "FAIL", "plan": ref.key,
                "reason": "sealed verification contract changed",
                "violations": monotonic.violations + env_check.violations,
            })
            return 2

    registry = MultiAgentRegistry(str(root), owner_timeout=cfg.owner_timeout_sec)
    try:
        with final_audit_session(root, registry):
            for ref in refs:
                argv = ["audit", str(root)]
                if ref.name != "default":
                    argv += ["--plan", ref.name]
                rc = _forward_core(argv)
                if rc != 0:
                    return rc

            assessment = evaluate_workspace(str(root), profile=cfg.profile.value, mode=cfg.mode)
            if assessment.get("outcome") != "PASS":
                _json(assessment)
                return 3 if assessment.get("outcome") == "UNKNOWN" else 2
    except AuditSessionError as exc:
        _json({"outcome": "FAIL", "reason": "final audit quiescence/integrity failure", "detail": str(exc)})
        return 2

    _json({
        "outcome": "PASS",
        "plans": {name: item.get("outcome") for name, item in assessment.get("plans", {}).items()},
        "deterministic_core": "fresh audit PASS for every active plan under workspace-wide freeze",
        "gate": assessment.get("gate"),
    })
    return 0
'''
replace_function("supervisor/cli.py", "cmd_audit", cli_audit_source)

replace_once(
    "supervisor/orchestrator.py",
    "from .workspace import capture_workspace\n",
    "from .workspace import capture_workspace, tool_available\n",
)
required_tools_source = r'''
def _required_tools(plan: Dict[str, Any], available: Dict[str, bool]) -> List[str]:
    raw = plan.get("required_tools", [])
    if not isinstance(raw, list):
        return ["<invalid required_tools>"]
    missing = set()
    for item in raw:
        tool = str(item)
        if available.get(tool) is True:
            continue
        if tool_available(tool):
            available[tool] = True
            continue
        available[tool] = False
        missing.add(tool)
    return sorted(missing)
'''
replace_function("supervisor/orchestrator.py", "_required_tools", required_tools_source)

# ---------------------------------------------------------------- migrate tests for interpreter-safe pytest normalization
replace_once(
    "tests/test_audit_check.py",
    '    assert c["cmd"] == "python -m pytest tests/ -q"\n    assert c["expect_exit"] == 0\n',
    '    assert c["argv"] == [sys.executable, "-m", "pytest", "tests/", "-q"]\n    assert c["expect_exit"] == 0\n',
)

# ---------------------------------------------------------------- installed-wheel smoke: activate request + real supervisor lifecycle
wheel = read("tests/wheel_cli_smoke.py")
request_anchor = '    (pg / "plan.json").write_text(json.dumps(default_plan, indent=2), encoding="utf-8")\n    (pg / "plans" / "named.json").write_text(json.dumps(named_plan, indent=2), encoding="utf-8")\n'
if request_anchor not in wheel:
    raise RuntimeError("wheel smoke plan-write anchor missing")
request_block = request_anchor + r'''
    request_source = {
        "format_version": 1,
        "task": "Verify the installed wheel and both active plans",
        "requirements": [
            {
                "id": "REQ-001",
                "description": "Produce an upstream artifact",
                "priority": "must",
                "acceptance_checks": default_plan["steps"][0]["verify"],
            },
            {
                "id": "REQ-002",
                "description": "Consume the verified upstream artifact",
                "priority": "must",
                "acceptance_checks": default_plan["steps"][1]["verify"],
            },
            {
                "id": "REQ-N1",
                "description": "Execute a named-plan behavioral check",
                "priority": "must",
                "acceptance_checks": named_plan["steps"][0]["verify"],
            },
        ],
    }
    request_source_path = pg / "request-source.json"
    request_source_path.write_text(json.dumps(request_source, indent=2), encoding="utf-8")
'''
wheel = wheel.replace(request_anchor, request_block, 1)
verify_anchor = '    _run([str(cli), "validate", str(workspace)], cwd=root, env=clean_env)\n    _run([str(cli), "validate", str(workspace), "--plan", "named"], cwd=root, env=clean_env)\n    _run([str(cli), "plan", "verify", str(workspace)], cwd=root, env=clean_env)\n'
if verify_anchor not in wheel:
    raise RuntimeError("wheel smoke verify anchor missing")
verify_block = '    _run([str(cli), "request", "init", str(workspace), "--file", str(request_source_path)], cwd=root, env=clean_env)\n' + verify_anchor
wheel = wheel.replace(verify_anchor, verify_block, 1)
health_anchor = '    _run([str(cli), "task", "list", str(workspace)], cwd=root, env=auth_env)\n'
if health_anchor not in wheel:
    raise RuntimeError("wheel smoke health anchor missing")
supervisor_block = r'''    _run([str(cli), "supervisor", "start", "--profile", "standard", "--mode", "serial", str(workspace)], cwd=root, env=auth_env)
    try:
        status_data = None
        for _ in range(40):
            proc = subprocess.run(
                [str(cli), "supervisor", "status", str(workspace)],
                cwd=str(root), env=auth_env, text=True, capture_output=True,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    status_data = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    status_data = None
            if (
                isinstance(status_data, dict)
                and status_data.get("running") is True
                and (status_data.get("assessment") or {}).get("outcome") == "PASS"
            ):
                break
            import time
            time.sleep(0.2)
        else:
            raise SystemExit(f"installed-wheel supervisor did not reach running+PASS: {status_data}")
    finally:
        _run([str(cli), "supervisor", "stop", str(workspace)], cwd=root, env=auth_env)
    stopped = subprocess.run(
        [str(cli), "supervisor", "status", str(workspace)],
        cwd=str(root), env=auth_env, text=True, capture_output=True,
    )
    if stopped.returncode == 0:
        raise SystemExit("installed-wheel supervisor still reports running after stop")

'''
wheel = wheel.replace(health_anchor, supervisor_block + health_anchor, 1)
write("tests/wheel_cli_smoke.py", wheel)

print("stage2 runtime hardening patch applied")
