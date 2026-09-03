#!/usr/bin/env python3
"""stop_gate.py — PlanGuard Stop hook kapısı (v1.1.0: çoklu plan desteği).

Command Code'un Stop eventine bağlanır: ajan turu bitirmek üzereyken,
proje dizininde AKTİF bir plan varsa (varsayılan plan.json VEYA
.plan-auditor/plans/*.json) ve o planda `verified` olmayan adım varsa
turu bloklar (exit 2) ve modele denetçiyi çalıştırması gerektiğini söyler.
Plan yoksa veya tüm adımlar doğrulanmışsa sessizce geçer.
"""
import glob
import json
import os
import sys

AUDITOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_check.py")


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        sys.exit(0)  # bozuk payload bizim işimiz değil

    base = os.environ.get("COMMANDCODE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    pg = os.path.join(base, ".plan-auditor")
    if not os.path.isdir(pg):
        sys.exit(0)  # aktif plan yok — bu tur plan-auditor işi değil

    incomplete = []  # (plan_adı, [id'ler])
    for name, path in _plan_files(pg):
        try:
            with open(path, encoding="utf-8") as f:
                plan = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        ids = [s.get("id") for s in plan.get("steps", []) if s.get("status") != "verified"]
        if ids:
            incomplete.append((name or "plan.json", ids))

    if not incomplete:
        sys.exit(0)  # her şey doğrulanmış — geç

    detail = "; ".join("%s: adımlar %s" % (n, ", ".join(str(i) for i in ids))
                       for n, ids in incomplete)
    sys.stderr.write(
        "PLAN-AUDITOR DENETİMİ BEKLENİYOR: %s hâlâ 'verified' değil.\n"
        "Bitirmeden önce: python \"%s\" run \"%s\"\n"
        "  FAIL adımları düzelt, sonra: python \"%s\" audit \"%s\" (exit 0).\n"
        "Planda iş kalmadıysa ilgili plan dosyasını .plan-auditor/archive/ altına taşı.\n"
        % (detail, AUDITOR, base, AUDITOR, base)
    )
    sys.exit(2)


def _plan_files(pg):
    files = []
    default = os.path.join(pg, "plan.json")
    if os.path.isfile(default):
        files.append((None, default))
    plans_dir = os.path.join(pg, "plans")
    for p in sorted(glob.glob(os.path.join(plans_dir, "*.json"))):
        files.append((os.path.splitext(os.path.basename(p))[0], p))
    return files


if __name__ == "__main__":
    main()
