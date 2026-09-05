#!/usr/bin/env python3
"""Deterministic Plan Auditor core.

The core never trusts an agent's narrative. It executes concrete checks, keeps
append-only SHA-256 evidence, limits retries, supports multi-plan operation and
snapshot/rollback, anchors evidence rotations, and binds every full audit to a
deterministic plan/workspace fingerprint.

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
import subprocess
import sys
import zipfile

PG_DIR = ".plan-auditor"
CHECK_TYPES = {"run", "exec", "file_exists", "regex", "pytest"}
MAX_ATTEMPTS = 3
ROTATE_BYTES = 2_000_000
SNAPSHOT_DIR = "snapshots"
_FINGERPRINT_SKIP_DIRS = {".git", PG_DIR, "__pycache__", ".pytest_cache"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def plan_contract_fingerprint(plan):
    """Hash the immutable verification contract, ignoring runtime status."""
    contract = {
        "task": plan.get("task"),
        "requirements": plan.get("requirements"),
        "steps": [
            {
                "id": step.get("id"),
                "title": step.get("title"),
                "verify": step.get("verify", []),
            }
            for step in plan.get("steps", [])
            if isinstance(step, dict)
        ],
    }
    return hashlib.sha256(canonical(contract).encode("utf-8")).hexdigest()


def workspace_fingerprint(base):
    """Content hash of product/source state outside auditor/git/cache metadata.

    File mtimes are deliberately ignored: they are not stable across processes,
    filesystems, checkouts, or fast consecutive writes. Symlinks are hashed as
    links (target text), never followed outside the workspace.
    """
    root = os.path.realpath(base)
    digest = hashlib.sha256()
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _FINGERPRINT_SKIP_DIRS)
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append((rel, path))

    for rel, path in sorted(entries):
        digest.update(b"PATH\0")
        digest.update(rel.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        try:
            if os.path.islink(path):
                digest.update(b"LINK\0")
                digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            elif os.path.isfile(path):
                digest.update(b"FILE\0")
                with open(path, "rb") as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            else:
                digest.update(b"OTHER\0")
        except OSError as exc:
            digest.update(b"UNREADABLE\0")
            digest.update(type(exc).__name__.encode("ascii", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


# ---------------------------------------------------------------- plan io

def plan_path(base, name=None):
    if name:
        return os.path.join(base, PG_DIR, "plans", name + ".json")
    return os.path.join(base, PG_DIR, "plan.json")


def plan_key(name=None):
    return name if name else "default"


def all_plan_paths(base):
    paths = []
    default = plan_path(base)
    if os.path.isfile(default):
        paths.append((None, default))
    plans_dir = os.path.join(base, PG_DIR, "plans")
    if os.path.isdir(plans_dir):
        for filename in sorted(os.listdir(plans_dir)):
            if filename.endswith(".json"):
                paths.append((filename[:-5], os.path.join(plans_dir, filename)))
    return paths


def load_plan(base, name=None):
    path = plan_path(base, name)
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
    os.replace(tmp, path)


def validate_plan(data):
    errs = []
    if not isinstance(data, dict):
        return ["plan kökü bir obje olmalı"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        errs.append("task: boş olmayan string olmalı")
    if not isinstance(data.get("created"), str) or not data["created"].strip():
        errs.append("created: ISO zaman damgası olmalı")
    if "snapshot" in data and not isinstance(data["snapshot"], list):
        errs.append("snapshot: dosya yolu listesi olmalı (opsiyonel)")
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
        checks = step.get("verify")
        if not isinstance(checks, list) or not checks:
            errs.append("adım %s: verify boş olamaz" % sid)
            continue
        behavioral = [
            c for c in checks
            if isinstance(c, dict) and c.get("type") in ("run", "pytest", "exec")
        ]
        if not behavioral:
            errs.append(
                "adım %s: en az bir DAVRANIŞSAL kontrol (run/pytest/exec) zorunlu — "
                "yalnızca file_exists/regex ile adım doğrulanamaz" % sid
            )
        for check in checks:
            if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
                errs.append("adım %s: geçersiz kontrol %r" % (sid, check))
                continue
            kind = check["type"]
            if kind in ("file_exists", "regex") and not check.get("path"):
                errs.append("adım %s: %s kontrolü 'path' ister" % (sid, kind))
            if kind == "regex" and not check.get("pattern"):
                errs.append("adım %s: regex kontrolü 'pattern' ister" % sid)
            if kind in ("run", "exec"):
                cmd = check.get("cmd")
                argv = check.get("argv")
                has_cmd = isinstance(cmd, str) and bool(cmd.strip())
                has_argv = (
                    isinstance(argv, list) and bool(argv)
                    and all(isinstance(arg, str) and bool(arg) for arg in argv)
                )
                if not (has_cmd or has_argv):
                    errs.append(
                        "adım %s: %s kontrolü boş olmayan 'cmd' string veya 'argv' listesi ister"
                        % (sid, kind)
                    )
                if "argv" in check and not has_argv:
                    errs.append("adım %s: %s argv boş olmayan string listesi olmalı" % (sid, kind))
                if "shell" in check and not isinstance(check.get("shell"), bool):
                    errs.append("adım %s: %s shell boolean olmalı" % (sid, kind))
                if check.get("shell") is True and has_argv:
                    errs.append("adım %s: %s shell=true ile argv birlikte kullanılamaz" % (sid, kind))
    return errs


def norm_check(check):
    if check["type"] == "pytest":
        return {
            "type": "run",
            "cmd": ("python -m pytest " + check.get("args", "")).strip(),
            "expect_exit": 0,
        }
    if check["type"] == "exec":
        normalized = {
            "type": "run",
            "expect_exit": check.get("expect_exit", 0),
        }
        if "argv" in check:
            normalized["argv"] = list(check["argv"])
        else:
            normalized["cmd"] = check["cmd"]
        if check.get("shell") is True:
            normalized["shell"] = True
        for key in ("timeout", "output_regex"):
            if key in check:
                normalized[key] = check[key]
        return normalized
    return check


# ---------------------------------------------------------------- confinement / checks

def _safe_path(base, relative):
    root = os.path.realpath(base)
    target = os.path.realpath(os.path.join(root, relative))
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False
    if not inside:
        raise ValueError("path workspace dışına çıkıyor: %s" % relative)
    return target


def _command_spec(check):
    """Return ``(command, use_shell)`` with shell disabled by default.

    ``argv`` is the preferred, cross-platform form. Legacy ``cmd`` strings are
    parsed with ``shlex`` and executed directly. Shell interpretation is only
    enabled when a plan explicitly sets ``shell: true``.
    """
    if "argv" in check:
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(arg, str) and bool(arg) for arg in argv
        ):
            raise ValueError("argv boş olmayan string listesi olmalı")
        if check.get("shell") is True:
            raise ValueError("shell=true ile argv birlikte kullanılamaz")
        return list(argv), False

    cmd = check.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd boş olmayan string olmalı")
    if check.get("shell") is True:
        return cmd, True
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError as exc:
        raise ValueError("cmd ayrıştırılamadı: %s" % exc) from exc
    if not argv:
        raise ValueError("cmd boş komuta dönüştü")
    return argv, False


def run_check(check, base, timeout=300):
    """Return ``(passed, detail, output_tail)``."""
    kind = check["type"]
    if kind == "run":
        try:
            command, use_shell = _command_spec(check)
            proc = subprocess.run(
                command, shell=use_shell, cwd=base, capture_output=True,
                text=True, timeout=check.get("timeout", timeout),
            )
        except subprocess.TimeoutExpired:
            return False, "komut zaman aşımına uğradı", ""
        except (OSError, ValueError) as exc:
            return False, "komut başlatılamadı: %s" % exc, ""
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        expected = check.get("expect_exit", 0)
        ok = proc.returncode == expected
        detail = "exit=%s (beklenen %s)" % (proc.returncode, expected)
        pattern = check.get("output_regex")
        if pattern:
            matched = re.search(pattern, output) is not None
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
        ok = re.search(check["pattern"], content) is not None
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


def _write_evidence_record(path, rec, prev=None):
    previous = prev if prev is not None else _last_record_hash(path)
    rec = dict(rec)
    rec["prev"] = previous
    rec["hash"] = hashlib.sha256(
        canonical({k: v for k, v in rec.items() if k != "hash"}).encode("utf-8")
    ).hexdigest()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(canonical(rec) + "\n")
    return rec["hash"]


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
    maybe_rotate(base)
    return _write_evidence_record(evidence_path(base), rec)


def count_failed_attempts(base, step_id, plan="default", mode="run"):
    path = evidence_path(base)
    count = 0
    if not os.path.isfile(path):
        return count
    with open(path, encoding="utf-8") as handle:
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
                and rec.get("status") != "verified"
            ):
                count += 1
    return count


def verify_chain(base):
    path = evidence_path(base)
    if not os.path.isfile(path):
        return True, 0, ""
    prev = "GENESIS"
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
            expected = hashlib.sha256(
                canonical({k: v for k, v in rec.items() if k != "hash"}).encode("utf-8")
            ).hexdigest()
            if actual != expected:
                return False, count, "satır %s: hash uyuşmuyor (kurcalama?)" % line_no
            prev = actual
            count += 1
    return True, count, ""


# ---------------------------------------------------------------- snapshot

def snapshot_sources(base, plan):
    files = list(plan.get("snapshot") or [])
    if not files and os.path.isdir(os.path.join(base, ".git")):
        try:
            proc = subprocess.run(
                ["git", "ls-files"], shell=False, cwd=base, capture_output=True,
                text=True, timeout=60,
            )
            files = [line for line in (proc.stdout or "").splitlines() if line.strip()]
        except Exception:
            files = []
    safe = []
    for rel in files:
        try:
            path = _safe_path(base, rel)
        except ValueError:
            continue
        if os.path.isfile(path):
            safe.append(rel)
    return safe


def snapshots_dir(base):
    return os.path.join(base, PG_DIR, SNAPSHOT_DIR)


def make_snapshot(base, plan, label="snapshot"):
    sources = snapshot_sources(base, plan)
    if not sources:
        print("ANLIK GÖRÜNTÜ YOK: plan 'snapshot' listesi boş ve git deposu bulunamadı.")
        return None
    os.makedirs(snapshots_dir(base), exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    zpath = os.path.join(snapshots_dir(base), "%s-%s.zip" % (label, stamp))
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as archive:
        for rel in sources:
            archive.write(_safe_path(base, rel), rel)
    append_evidence(base, {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "mode": label,
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(sources),
        "archive": os.path.basename(zpath),
    })
    print("ANLIK GÖRÜNTÜ: %s (%s dosya)" % (os.path.basename(zpath), len(sources)))
    return zpath


def restore_snapshot(base, zpath):
    names = []
    with zipfile.ZipFile(zpath) as archive:
        for info in archive.infolist():
            try:
                target = _safe_path(base, info.filename)
            except ValueError:
                raise ValueError("snapshot workspace dışına yazmaya çalışıyor: %s" % info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())
            names.append(info.filename)
    append_evidence(base, {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "mode": "rollback",
        "step": 0,
        "results": [],
        "status": "verified",
        "files": len(names),
        "archive": os.path.basename(zpath),
    })
    print("GERİ YÜKLEME: %s → %s dosya proje üzerine yazıldı." % (os.path.basename(zpath), len(names)))


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
            step["id"], title, step.get("status", "pending").upper(),
            "%s kontrol" % len(checks),
        ))


def audit_steps(base, plan, ids=None, mode="run", name=None, force=False):
    target = [step for step in plan["steps"] if ids is None or step["id"] in ids]
    if ids is not None and not target:
        sys.exit("HATA: verilen id'ler planda yok: %s" % ids)
    if mode == "audit":
        target = plan["steps"]
    key = plan_key(name)
    all_ok = True

    for step in target:
        attempt = 1
        if mode == "run":
            attempt = count_failed_attempts(base, step["id"], plan=key) + 1
            if attempt > MAX_ATTEMPTS and not force:
                print("[ATLADI] adım %s: %s önceki deneme — %s sınırı aşıldı." % (
                    step["id"], step.get("title", ""), MAX_ATTEMPTS,
                ))
                all_ok = False
                continue

        results = []
        ok_all = True
        for raw_check in step.get("verify", []):
            check = norm_check(raw_check)
            ok, detail, tail = run_check(check, base)
            ok_all = ok_all and ok
            results.append({
                "check": check,
                "passed": ok,
                "detail": detail,
                "output_tail": tail if not ok else "",
            })

        step["status"] = "verified" if ok_all else "failed"
        all_ok = all_ok and ok_all
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "mode": mode,
            "plan": key,
            "step": step["id"],
            "results": results,
            "status": step["status"],
        }
        if mode == "run":
            rec["attempt"] = attempt
        append_evidence(base, rec)

        mark = "OK " if ok_all else "FAIL"
        label = "adım %s: %s" % (step["id"], step.get("title", ""))
        if mode == "run":
            label += " (deneme %s/%s)" % (min(attempt, MAX_ATTEMPTS), MAX_ATTEMPTS)
        print("[%s] %s" % (mark, label))
        for result in results:
            print("       - %s | %s" % (
                "geçti" if result["passed"] else "KALDI", result["detail"],
            ))
            if not result["passed"] and result["output_tail"]:
                print("         çıktı: %s" % result["output_tail"][-400:].replace("\n", " | "))

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
    target_ids = (
        [step["id"] for step in plan["steps"] if step.get("status") != "verified"]
        if ids is None else ids
    )
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run",
                         name=args.plan, force=args.force)
    return 0 if all_ok else 1


def cmd_audit(args):
    ok, _count, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    print("TAM DENETİM: tüm adımlar taze kabukta yeniden test ediliyor...\n")
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
    except (ValueError, zipfile.BadZipFile) as exc:
        print("HATA: güvenli rollback başarısız: %s" % exc)
        return 1
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="PlanGuard bağımsız denetleyici v1.1+")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("validate", "run", "audit", "status", "snapshot", "rollback"):
        item = sub.add_parser(name)
        item.add_argument("dir", nargs="?", default=".", help="proje dizini")
        item.add_argument("--plan", help="plan adı (.plan-auditor/plans/<ad>.json); varsayılan: plan.json")
        if name == "run":
            item.add_argument("ids", nargs="*", type=int,
                              help="denetlenecek adım id'leri (boş: verified olmayanlar)")
            item.add_argument("--force", action="store_true",
                              help="%s deneme sınırını zorla aş" % MAX_ATTEMPTS)
        if name == "rollback":
            item.add_argument("--to", help="geri yüklenecek zip; varsayılan: en yenisi")

    args = parser.parse_args()
    args.dir = os.path.abspath(args.dir)
    if not os.path.isdir(args.dir):
        sys.exit("HATA: dizin yok: %s" % args.dir)
    sys.exit({
        "validate": cmd_validate,
        "run": cmd_run,
        "audit": cmd_audit,
        "status": cmd_status,
        "snapshot": cmd_snapshot,
        "rollback": cmd_rollback,
    }[args.mode](args))


if __name__ == "__main__":
    main()
