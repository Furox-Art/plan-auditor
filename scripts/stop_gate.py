#!/usr/bin/env python3
"""stop_gate.py — PlanGuard Stop hook kapısı.

Command Code'un Stop eventine bağlanır: ajan turu bitirmek üzereyken,
proje dizininde aktif bir .plan-auditor planı varsa ve her adım `verified`
değilse turu bloklar (exit 2) ve modele denetçiyi çalıştırması gerektiğini
söyler. Plan yoksa veya tüm adımlar doğrulanmışsa sessizce geçer.

Motor tarafında tur başına 3 retry limiti vardır; bu script döngü koruması
için ekstra bir şey yapmaz — sıkı mod: plan eksik olduğu sürece her
tur sonunda bloklar.
"""
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
    plan_path = os.path.join(base, ".plan-auditor", "plan.json")
    if not os.path.isfile(plan_path):
        sys.exit(0)  # aktif plan yok — bu tur plan-auditor işi değil

    try:
        with open(plan_path, encoding="utf-8") as f:
            plan = json.load(f)
        steps = plan.get("steps", [])
    except (json.JSONDecodeError, OSError):
        sys.exit(0)  # okunamayan plana tur kapatmayı bloklamayalım

    incomplete = [s for s in steps if s.get("status") != "verified"]
    if not incomplete:
        sys.exit(0)  # her şey doğrulanmış — geç

    ids = ", ".join(str(s.get("id")) for s in incomplete)
    sys.stderr.write(
        "PLAN-AUDITOR DENETİMİ BEKLENİYOR: plan adımları %s hâlâ 'verified' değil.\n"
        "Bitirmeden önce: python \"%s\" run \"%s\"  — FAIL olan adımları düzelt, "
        "sonra python \"%s\" audit \"%s\" (exit 0) al. Planda iş yoksa planı "
        "arşivle: .plan-auditor/ klasörünü taşı.\n"
        % (ids, AUDITOR, base, AUDITOR, base)
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
