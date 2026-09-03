#!/usr/bin/env python3
"""audit_check.py — PlanGuard bağımsız denetleyici (v1.1.0).

Kanıt tabanlı adım denetimi: ajanın raporuna güvenmez, yalnızca komut
çıktısı / dosya durumu gibi somut kanıtlara bakar. Kanıt kaydı append-only
ve SHA-256 hash zincirlidir; sonradan değiştirilirse uyarır ve denetimi
düşürür. Büyük loglar otomatik arşivlenir (rotasyon).

v1.1 yenilikleri:
  --plan <ad>        çoklu plan desteği (.plan-auditor/plans/<ad>.json)
  run --force        3 deneme sınırını zorla aşma (varsayılan: reddeder)
  snapshot/rollback  planın "snapshot" listesindeki dosyaların yedeğini
                     al / geri yükle (liste boşsa git ls-files)

Modlar:
  validate <dir>            plan.json şema kontrolü
  run <dir> [id id ...]     bekleyen (veya verilen) adımları denetle
  audit <dir>               TÜM adımları yeniden denetle (final gate)
  status <dir>              tablo (hiçbir şey çalıştırmadan)
  snapshot <dir>            dosya anlık görüntüsü al
  rollback <dir>            son (veya --to ile verilen) anlık görüntüyü geri yükle

Exit kodları: 0 = geçti, 1 = en az bir adım doğrulanamadı / sınır aşıldı,
2 = kayıt zinciri kurcalanmış.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile

PG_DIR = ".plan-auditor"
CHECK_TYPES = {"run", "exec", "file_exists", "regex", "pytest"}
MAX_ATTEMPTS = 3
ROTATE_BYTES = 2_000_000
SNAPSHOT_DIR = "snapshots"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------- plan io

def plan_path(base, name=None):
    if name:
        return os.path.join(base, PG_DIR, "plans", name + ".json")
    return os.path.join(base, PG_DIR, "plan.json")


def plan_key(name=None):
    return name if name else "default"


def all_plan_paths(base):
    """Varsayılan plan + plans/ altındaki tüm planlar."""
    paths = []
    default = plan_path(base)
    if os.path.isfile(default):
        paths.append((None, default))
    plans_dir = os.path.join(base, PG_DIR, "plans")
    if os.path.isdir(plans_dir):
        for f in sorted(os.listdir(plans_dir)):
            if f.endswith(".json"):
                paths.append((f[:-5], os.path.join(plans_dir, f)))
    return paths


def load_plan(base, name=None):
    p = plan_path(base, name)
    if not os.path.isfile(p):
        where = p if not name else "%s (--plan %s)" % (p, name)
        sys.exit("HATA: plan yok: %s" % where)
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_plan(base, plan, name=None):
    p = plan_path(base, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
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
    if "snapshot" in data and not isinstance(data["snapshot"], list):
        errs.append("snapshot: dosya yolu listesi olmalı (opsiyonel)")
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
        behavioral = [c for c in checks
                      if isinstance(c, dict) and c.get("type") in ("run", "pytest", "exec")]
        if not behavioral:
            errs.append("adım %s: en az bir DAVRANIŞSAL kontrol (run/pytest/exec) zorunlu — "
                        "yalnızca file_exists/regex ile adım doğrulanamaz" % sid)
        for c in checks:
            if not isinstance(c, dict) or c.get("type") not in CHECK_TYPES:
                errs.append("adım %s: geçersiz kontrol %r" % (sid, c))
                continue
            t = c["type"]
            if t in ("file_exists", "regex") and not c.get("path"):
                errs.append("adım %s: %s kontrolü 'path' ister" % (sid, t))
            if t == "regex" and not c.get("pattern"):
                errs.append("adım %s: regex kontrolü 'pattern' ister" % sid)
            if t in ("run", "exec") and not c.get("cmd"):
                errs.append("adım %s: %s kontrolü 'cmd' ister" % (sid, t))
    return errs


def norm_check(c):
    if c["type"] in ("pytest", "exec"):
        if c["type"] == "pytest":
            return {"type": "run",
                    "cmd": ("python -m pytest " + c.get("args", "")).strip(),
                    "expect_exit": 0}
        # exec: harici denetçi (derlenmiş C++/Rust ikilisi, jar, betik...)
        return {"type": "run", "cmd": c["cmd"],
                "expect_exit": c.get("expect_exit", 0)}
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


def maybe_rotate(base):
    """Log 2 MB'ı aşınca arşive taşı, taze zincirle devam et."""
    path = evidence_path(base)
    if not os.path.isfile(path) or os.path.getsize(path) < ROTATE_BYTES:
        return
    archive_dir = os.path.join(base, PG_DIR, "archive")
    os.makedirs(archive_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    os.replace(path, os.path.join(archive_dir, "evidence-%s.jsonl" % ts))
    print("NOT: evidence log arşivlendi (rotasyon) — evidence-%s.jsonl" % ts)


def append_evidence(base, rec):
    path = evidence_path(base)
    maybe_rotate(base)
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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical(rec) + "\n")
    return rec["hash"]


def count_failed_attempts(base, step_id, plan="default", mode="run"):
    """Bir adımın önceki başarısız deneme sayısı (evidence logdan)."""
    path = evidence_path(base)
    n = 0
    if not os.path.isfile(path):
        return n
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (rec.get("mode") == mode and rec.get("step") == step_id
                    and rec.get("plan", "default") == plan
                    and rec.get("status") != "verified"):
                n += 1
    return n


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


# ---------------------------------------------------------------- snapshot

def snapshot_sources(base, plan):
    files = list(plan.get("snapshot") or [])
    if not files and os.path.isdir(os.path.join(base, ".git")):
        try:
            out = subprocess.run("git ls-files", shell=True, cwd=base,
                                 capture_output=True, text=True, timeout=60)
            files = [l for l in (out.stdout or "").splitlines() if l.strip()]
        except Exception:
            files = []
    return [f for f in files if os.path.isfile(os.path.join(base, f))]


def snapshots_dir(base):
    return os.path.join(base, PG_DIR, SNAPSHOT_DIR)


def make_snapshot(base, plan, label="snapshot"):
    src = snapshot_sources(base, plan)
    if not src:
        print("ANLIK GÖRÜNTÜ YOK: plan 'snapshot' listesi boş ve git deposu bulunamadı.")
        return None
    os.makedirs(snapshots_dir(base), exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    zpath = os.path.join(snapshots_dir(base), "%s-%s.zip" % (label, ts))
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in src:
            z.write(os.path.join(base, f), f)
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "mode": label, "step": 0, "results": [],
           "status": "verified", "files": len(src), "archive": os.path.basename(zpath)}
    append_evidence(base, rec)
    print("ANLIK GÖRÜNTÜ: %s (%s dosya)" % (os.path.basename(zpath), len(src)))
    return zpath


def restore_snapshot(base, zpath):
    with zipfile.ZipFile(zpath) as z:
        names = z.namelist()
        z.extractall(base)
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "mode": "rollback", "step": 0, "results": [],
           "status": "verified", "files": len(names),
           "archive": os.path.basename(zpath)}
    append_evidence(base, rec)
    print("GERİ YÜKLEME: %s → %s dosya proje üzerine yazıldı." % (os.path.basename(zpath), len(names)))


def latest_snapshot(base):
    d = snapshots_dir(base)
    if not os.path.isdir(d):
        return None
    zips = sorted(f for f in os.listdir(d) if f.endswith(".zip"))
    return os.path.join(d, zips[-1]) if zips else None


# ---------------------------------------------------------------- output

def print_table(plan, name=None):
    if name:
        print("PLAN: %s" % name)
    print("%-4s %-42s %-9s %s" % ("ID", "ADIM", "DURUM", "KONTROL"))
    print("-" * 70)
    for s in plan["steps"]:
        title = (s.get("title") or "")[:40]
        checks = s.get("verify", [])
        print("%-4s %-42s %-9s %s" % (s["id"], title, s.get("status", "pending").upper(),
                                      "%s kontrol" % len(checks)))


def audit_steps(base, plan, ids=None, mode="run", name=None, force=False):
    target = [s for s in plan["steps"] if ids is None or s["id"] in ids]
    if ids is not None and not target:
        sys.exit("HATA: verilen id'ler planda yok: %s" % ids)
    if mode == "audit":
        target = plan["steps"]
    key = plan_key(name)
    all_ok = True
    for s in target:
        attempt = 1
        if mode == "run":
            attempt = count_failed_attempts(base, s["id"], plan=key) + 1
            if attempt > MAX_ATTEMPTS and not force:
                print("[ATLADI] adım %s: %s önceki deneme — %s sınırı aşıldı. "
                      "Kontrolü gevşetme; kullanıcıya rapor ver veya --force ile zorla."
                      % (s["id"], s.get("title", ""), MAX_ATTEMPTS))
                all_ok = False
                continue
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
               "mode": mode, "plan": key, "step": s["id"], "results": results,
               "status": s["status"]}
        if mode == "run":
            rec["attempt"] = attempt
        append_evidence(base, rec)
        mark = "OK " if ok_all else "FAIL"
        label = "adım %s: %s" % (s["id"], s.get("title", ""))
        if mode == "run":
            label += " (deneme %s/%s)" % (min(attempt, MAX_ATTEMPTS), MAX_ATTEMPTS)
        print("[%s] %s" % (mark, label))
        for r in results:
            print("       - %s | %s" % ("geçti" if r["passed"] else "KALDI",
                                        r["detail"]))
            if not r["passed"] and r["output_tail"]:
                print("         çıktı: %s" % r["output_tail"][-400:].replace("\n", " | "))
        if mode == "run" and not ok_all and attempt >= MAX_ATTEMPTS:
            print("       ! ESKALASYON: %s deneme tamamlandı — kontrolü gevşetmeden "
                  "kullanıcıya kanıtla rapor ver ve nasıl devam edileceğini sor. "
                  "Geri almak istersen: snapshot/rollback." % MAX_ATTEMPTS)
    save_plan(base, plan, name)
    return all_ok


# ---------------------------------------------------------------- commands

def cmd_validate(args):
    plan = load_plan(args.dir, args.plan)
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
    plan = load_plan(args.dir, args.plan)
    ids = args.ids or None
    if ids is None:
        target_ids = [s["id"] for s in plan["steps"] if s.get("status") != "verified"]
    else:
        target_ids = ids
    all_ok = audit_steps(args.dir, plan, ids=target_ids, mode="run",
                         name=args.plan, force=args.force)
    return 0 if all_ok else 1


def cmd_audit(args):
    ok, n, problem = verify_chain(args.dir)
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
    ok, n, problem = verify_chain(args.dir)
    plan = load_plan(args.dir, args.plan)
    print_table(plan, args.plan)
    print("\nevidence kaydı: %s" % (n if ok else "ZİNCİR KOPUK"))
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    done = sum(1 for s in plan["steps"] if s.get("status") == "verified")
    print("özet: %s/%s adım verified" % (done, len(plan["steps"])))
    return 0


def cmd_snapshot(args):
    ok, n, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    plan = load_plan(args.dir, args.plan)
    zpath = make_snapshot(args.dir, plan)
    return 0 if zpath else 1


def cmd_rollback(args):
    ok, n, problem = verify_chain(args.dir)
    if not ok:
        print("KAYIT ZİNCİRİ KURCALANMIŞ: %s" % problem)
        return 2
    if args.to:
        zpath = os.path.join(snapshots_dir(args.dir), args.to)
        if not os.path.isfile(zpath):
            zpath = args.to if os.path.isfile(args.to) else None
        if not zpath:
            sys.exit("HATA: anlık görüntü bulunamadı: %s" % args.to)
    else:
        zpath = latest_snapshot(args.dir)
        if not zpath:
            sys.exit("HATA: anlık görüntü yok — önce 'snapshot' çalıştır.")
    restore_snapshot(args.dir, zpath)
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="PlanGuard bağımsız denetleyici v1.1.0")
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("validate", "run", "audit", "status", "snapshot", "rollback"):
        p = sub.add_parser(name)
        p.add_argument("dir", nargs="?", default=".", help="proje dizini")
        p.add_argument("--plan", help="plan adı (.plan-auditor/plans/<ad>.json); varsayılan: plan.json")
        if name == "run":
            p.add_argument("ids", nargs="*", type=int, help="denetlenecek adım id'leri (boş: verified olmayanlar)")
            p.add_argument("--force", action="store_true",
                           help="%s deneme sınırını zorla aş" % MAX_ATTEMPTS)
        if name == "rollback":
            p.add_argument("--to", help="geri yüklenecek zip (dosya adı veya tam yol); varsayılan: en yenisi")
    args = ap.parse_args()
    args.dir = os.path.abspath(args.dir)
    if not os.path.isdir(args.dir):
        sys.exit("HATA: dizin yok: %s" % args.dir)
    sys.exit({"validate": cmd_validate, "run": cmd_run, "audit": cmd_audit,
              "status": cmd_status, "snapshot": cmd_snapshot,
              "rollback": cmd_rollback}[args.mode](args))


if __name__ == "__main__":
    main()
