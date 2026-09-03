---
name: plan-auditor
description: Katı plan + bağımsız denetçi iş akışı — verilen görevi makineyle doğrulanabilir adımlara böler, her adımı gerçek komut çıktısıyla (kanıtla) test eder, ajanın kendi "yaptım" sözüne asla güvenmez ve görev ancak tam denetim geçilirse bitmiş sayılır. Kullanıcı bir şeyi yaptırırken işin yarım kalmamasını istiyorsa, "planla", "denetle", "yarım bırakma", "gerçekten yaptın mı" derse veya /plan-auditor çağrılırsa kullan.
argument-hint: "<görev metni>"
metadata:
  version: "1.0.0"
---

# Plan-Auditor: Net Plan + Bağımsız Denetçi

Sen bu iş akışında İKİ rol oynarsın ve rolleri asla karıştırmazsın:
- **Planlayıcı:** görevi ölçülebilir adımlara böl.
- **Denetçi:** her adımı kanıtla test et — kendi anlatımına, hafızana, "ben yaptım" sözüne güvenme; yalnızca komut çıktısına güven.

## Katı kurallar (istisnasız)

1. **Kanıt yoksa adım yapılmamıştır.** Bir adım `verified` yalnızca denetçi scripti tüm kontrolleri geçti derse olur.
2. **Yargıç yalnızca düşürür.** Kontroller geçse bile işin gerçekte doğru olmadığına inanıyorsan `verified`'ı geçerli sayma — daha sıkı bir kontrol ekleyip scripti tekrar çalıştır. Hiçbir zaman başarısız kanıtı "geçti"ye çeviremezsin.
3. **Doğrulanamayan = başarısız.** Kanıt üretilemeyen adım `failed`'tır.
4. **Kayıt append-only.** `evidence.jsonl` ve kayıtların `hash` zinciri asla elle düzenlenmez; scriptin dışında hiçbir şey log'a yazamaz.
5. **Kontrol spesifikasyonu kilidi.** İş başladıktan sonra `plan.json` içindeki `verify` listelerini gevşetmek yasak; yalnızca yeni/sıkı kontrol EKLEYEBİLİRSİN.
6. **Tam denetim kapısı.** Görevi "bitti" demeden önce `audit` modu exit 0 dönmeli. Dönmeden bitirme.

## Dosyalar

- Plan: `<proje>/.plan-auditor/plan.json` (format: `references/plan-format.md`)
- Kanıt: `<proje>/.plan-auditor/evidence.jsonl` (script yazar, append-only, hash zincirli)
- Denetçi scripti: bu skill dizinindeki `scripts/audit_check.py`

Scripti her seferinde TAM YOLLA çağır (`~` senin shell'de açılabilir):

```
python ~/.commandcode/skills/plan-auditor/scripts/audit_check.py <mod> <proje-dizini> [id id ...]
```

Modlar: `validate` (şema kontrolü) · `run` (bekleyen — veya `run <dir> 1 2` gibi verilen id'li — adımları denetle) · `audit` (TÜM adımları yeniden denetle, final gate) · `status` (tablo, çalıştırmadan). Dizin adı `id`'lerden ÖNCE gelir.

## İş akışı

### 1. PLAN
- Görevi al, `references/plan-format.md`'deki şemaya göre `<proje>/.plan-auditor/plan.json` yaz.
- Her adımın `verify` listesi SOMUT ve makineyle çalıştırılabilir olmalı: komut + beklenen exit kodu, dosya varlığı, regex, pytest. "Düzgün çalışıyor" gibi ölçüsüz kriter YOK.
- Yeni görev başlatırken eski plan varsa `.plan-auditor/archive/<tarih>-<slug>.json`'a taşı.
- Yazınca `validate` çalıştır; hata varsa düzelt ve tekrar çalıştır. Planı kullanıcıya kısaca özetle.

### 2. YÜRÜT + HER ADIMDA KANITLA + KURTARMA DÖNGÜSÜ
- Adımları sırayla yap. Her adımın işi bittiğinde HEMEN `run <id>` çalıştır.
- `verified` değilse: adım bitmemiştir. Kurtarma döngüsü:
  1. evidence çıktısındaki KALDI satırlarından teşhis koy (hangi kontrol, neden düştü).
  2. Kök nedeni düzelt (semptomu değil — test sahte geçiyorsa testi gevşetmek YASAK, ürünü düzelt).
  3. Aynı adım için `run <id>` tekrar.
- Adım başına en fazla **3 kurtarma denemesi**. 3 denemeden sonra hâlâ `verified` değilse DUR: kullanıcıya kanıt çıktısıyla rapor ver ve nasıl devam edileceğini sor. Asla kontrolü gevşeterek, adımı atlayarak veya "yeterince iyi" diyerek geçme.
- Sonraki adıma yalnızca önceki adım `verified` olduktan sonra geç.

### 3. TAM DENETİM
- Tüm adımlar `verified` olduktan sonra `audit` çalıştır (tümünü taze kabukta yeniden test eder).
- Exit 0 değilse rapordan devam et: hangi adım neden düşmüş, düzelt, audit'i tekrarla.

### 4. RAPOR
- Tablo halinde bildir: adım, kontrol sayısı, durum, kanıt özeti (komut çıktılarından alıntı).
- "Yaptım" deme; "audit geçti, kanıtlar şunlar" de.

## Örnek

Görev: "fib.py'de fibonacci yaz, testi olsun."

```json
{
  "task": "fib.py'de fibonacci fonksiyonu ve testi",
  "created": "2026-09-03T12:00:00",
  "steps": [
    {
      "id": 1,
      "title": "fib fonksiyonu yaz",
      "verify": [
        {"type": "file_exists", "path": "fib.py"},
        {"type": "regex", "path": "fib.py", "pattern": "def\\s+fib\\s*\\("},
        {"type": "run", "cmd": "python -c \"from fib import fib; assert fib(10)==55\"", "expect_exit": 0}
      ],
      "status": "pending"
    },
    {
      "id": 2,
      "title": "pytest testi yaz ve geçir",
      "verify": [
        {"type": "pytest", "args": "test_fib.py -q"}
      ],
      "status": "pending"
    }
  ]
}
```

Sonra: adımları yap → her adımda `run` → sonda `audit` → tabloyla raporla.
