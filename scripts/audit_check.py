#!/usr/bin/env python3
"""audit_check.py — PlanGuard bağımsız denetleyici.

Kanıt tabanlı adım denetimi: ajanın raporuna güvenmez, yalnızca komut
çıktısı / dosya durumu gibi somut kanıtlara bakar. Kanıt kaydı append-only
ve SHA-256 hash zincirlidir; sonradan değiştirilirse uyarır ve denetimi
düşürür.

Modlar:
  validate <dir>            plan.json şema kontrolü
  run <dir> [id id ...]     bekleyen (veya verilen) adımları denetle
  audit <dir>               TÜM adımları yeniden denetle (final gate)
  status <dir>              tablo (hiçbir şey çalıştırmadan)

Exit kodları: 0 = geçti, 1 = en az bir adım doğrulanamadı, 2 = kayıt zinciri kurcalanmış.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

PG_DIR = ".plan-auditor"
CHECK_TYPES = {"run", "file_exists", "regex", "pytest"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------- plan io

def plan_path(base):
    return os.path.join(base, PG_DIR, "plan.json")


def load_plan(base):
    p = plan_path(base)
    if not os.path.isfile(p):
        sys.exit("HATA: %s yok — önce /plan-auditor ile plan yazılmalı." % p)
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_plan(base, plan):
    p = plan_path(base)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)


def validate_plan(data):
    errs = []
    if not isinstance(data, dict):
        return ["plan kökü bir obje olmalı"]
    if not isinstance(data.get("task"), str) or not data["task"].strip():
        errs.append("task: boş olmayan string olmalı")
    if not isinstance(data.get("created"), str) or not data["created"].strip():
        errs.append("created: ISO zaman damgası olmalı")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("steps: boş olmayan liste olmalı")
        return errs
    seen = set()
    for s in steps:
        if not isinstance(s, dict):
            errs.append("adım obje olmalı: %r" % (s,))
            continue
        sid = s.get("id")
        if not isinstance(sid, int) or sid < 1:
            errs.append("adım id pozitif int olmalı: %r" % (sid,))
        elif sid in seen:
            errs.append("adım id tekrarlı: %s" % sid)
        seen.add(sid)
        if not isinstance(s.get("title"), str) or not s["title"].strip():
            errs.append("adım %s: title boş olamaz" % sid)
        checks = s.get("verify")
        if not isinstance(checks, list) or not checks:
            errs.append("adım %s: verify boş olamaz" % sid)
            continue
        for c in checks:
            if not isinstance(c, dict) or c.get("type") not in CHECK_TYPES:
                errs.append("adım %s: geçersiz kontrol %r" % (sid, c))
                continue
            t = c["type"]
            if t in ("file_exists", "regex") and not c.get("path"):
                errs.append("adım %s: %s kontrolü 'path' ister" % (sid, t))
            if t == "regex" and not c.get("pattern"):
                errs.append("adım %s: regex kontrolü 'pattern' ister" % sid)
            if t == "run" and not c.get("cmd"):
                errs.append("adım %s: run kontrolü 'cmd' ister" % sid)
    return errs


def norm_check(c):
    if c["type"] == "pytest":
        return {"type": "run",
                "cmd": ("python -m pytest " + c.get("args", "")).strip(),
                "expect_exit": 0}
    return c


# ---------------------------------------------------------------- checks

def run_check(c, base, timeout=300):
    """Döner: (passed, detail, output_tail)"""
    t = c["type"]
    if t == "run":
        try:
            p = subprocess.run(c["cmd"], shell=True, cwd=base,
                               capture_output=True, text=True,
                               timeout=c.get("timeout", timeout))
        except subprocess.TimeoutExpired:
            return False, "komut zaman aşımına uğradı", ""
        out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
        exp = c.get("expect_exit", 0)
        ok = p.returncode == exp
        detail = "exit=%s (beklenen %s)" % (p.returncode, exp)
        pat = c.get("output_regex")
        if pat:
            m = re.search(pat, out) is not None
            ok = ok and m
            detail += "; output_regex=%s" % ("eşleşti" if m else "EŞLEŞMEDİ")
        return ok, detail, out[-1500:]
    if t == "file_exists":
        path = os.path.join(base, c["path"])
        ok = os.path.isfile(path)
        return ok, "%s %s" % (c["path"], "VAR" if ok else "YOK"), ""
    if t == "regex":
        path = os.path.join(base, c["path"])
        if not os.path.isfile(path):
            return False, "%s YOK" % c["path"], ""
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        ok = re.search(c["pattern"], content) is not None
        return ok, "pattern %s" % ("eşleşti" if ok else "EŞLEŞMEDİ"), ""
    return False, "bilinmeyen kontrol tipi: %s" % t, ""


# ---------------------------------------------------------------- evidence

def evidence_path(base):
    return os.path.join(base, PG_DIR, "evidence.jsonl")


def append_evidence(base, rec):
    path = evidence_path(base)
    prev = "GENESIS"
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        prev = json.loads(line).get("hash", prev)
                    except json.JSONDecodeError:
                        pass
    rec["prev"] = prev
    rec["hash"] = hashlib.sha256(
        canonical({k: v for k, v in rec.items() if k != "hash"}).encode("utf-8")
    ).hexdigest()
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical(rec) + "\n")
    return rec["hash"]


def verify_chain(base):
    """Döner: (sağlam_mı, kayıt_sayısı, sorun_açıklaması)"""
    path = evidence_path(base)
    if not os.path.isfile(path):
        return True, 0, ""
    prev = "GENESIS"
    n = 0
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, n, "satır %s JSON değil" % i
            if rec.get("prev") != prev:
                return False, n, "satır %s: prev zinciri kopuk" % i
            h = rec.pop("hash", None)
            expect = hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()
            rec["hash"] = h
            if h != expect:
                return False, n, "satır %s: hash uyuşmuyor (kurcalama?)" % i
            prev = h
            n += 1
    return True, n, ""


# ---------------------------------------------------------------- output

def print_table(plan):
    print("%-4s %-42s %-9s %s" % ("ID", "ADIM", "DURUM", "KONTROL"))
    print("-" * 70)
    for s in plan["steps"]:
        title = (s.get("title") or "")[:40]
        checks = s.get("verify", [])
        print("%-4s %-42s %-9s %s" % (s["id"], title, s.get("status", "pending").upper(),
                                      "%s kontrol" % len(checks)))


def audit_steps(base, plan, ids=None, mode="run"):
    target = [s for s in plan["steps"] if ids is None or s["id"] in ids]
    if ids is not None and not target:
        sys.exit("HATA: verilen id'ler planda yok: %s" % ids)
    if mode == "audit":
        target = plan["steps"]
    all_ok = True
    for s in target:
        results = []
        ok_all = True
        for c in s.get("verify", []):
            c = norm_check(c)
            ok, detail, tail = run_check(c, base)
            ok_all = ok_all and ok
            results.append({"check": c, "passed": ok, "detail": detail,
                            "output_tail": tail if not ok else ""})
        s["status"] = "verified" if ok_all else "failed"
        all_ok = all_ok and ok_all
        rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
               "mode": mode, "step": s["id"], "results": results,
               "status": s["status"]}
        append_evidence(base, rec)
        mark = "OK " if ok_all else "FAIL"
        print("[%s] adım %s: %s" % (mark, s["id"], s.get("title", "")))
        for r in results:
            print("       - %s | %s" % ("geçti" if r["passed"] else "KALDI",
                                        r["detail"]))
            if not r["passed"] and r["output_tail"]:
                print("         çıktı: %s" % r["output_tail"][-400:].replace("\n", " | "))
    save_plan(base, plan)
    return all_ok


# ---------------------------------------------------------------- commands

def cmd_validate(args):
    plan = load_plan(args.dir)
    errs = validate_plan(plan)
    if errs:
        for e in errs:
            print("ŞEMA HATASI: %s" % e)
        return 1
    print("Şema geçerli: %s adım" % len(plan["steps"]))
    return 0


def cmd_run(args):
    ok, n, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir)
    ids = args.ids or None
    target_ids = ids or [s["id"] for s in plan["steps"] if s.get("status") != "verified"]
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run")
    if not all_ok:
        return 1
    return 0


def cmd_audit(args):
    ok, n, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir)
    print("TAM DENETİM: tüm adımlar taze kabukta yeniden test ediliyor...\n")
    all_ok = audit_steps(args.dir, plan, ids=None, mode="audit")
    print()
    print_table(plan)
    if not all_ok:
        print("\nSONUÇ: audit KALDI — görev bitmiş sayılmaz.")
        return 1
    print("\nSONUÇ: audit GEÇTİ — tüm adımlar kanıtlı.")
    return 0


def cmd_status(args):
    ok, n, problem = verify_chain(args.dir)
    plan = load_plan(args.dir)
    print_table(plan)
    print("\nevidence kaydı: %s" % (n if ok else "ZİNCİR KOPUK"))
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    done = sum(1 for s in plan["steps"] if s.get("status") == "verified")
    print("özet: %s/%s adım verified" % (done, len(plan["steps"])))
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="PlanGuard bağımsız denetleyici")
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("validate", "run", "audit", "status"):
        p = sub.add_parser(name)
        p.add_argument("dir", nargs="?", default=".", help="proje dizini")
        if name == "run":
            p.add_argument("ids", nargs="*", type=int, help="denetlenecek adım id'leri (boş: verified olmayanlar)")
    args = ap.parse_args()
    args.dir = os.path.abspath(args.dir)
    if not os.path.isdir(args.dir):
        sys.exit("HATA: dizin yok: %s" % args.dir)
    sys.exit({"validate": cmd_validate, "run": cmd_run,
              "audit": cmd_audit, "status": cmd_status}[args.mode](args))


if __name__ == "__main__":
    main()
