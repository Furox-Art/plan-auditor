# plan.json Formatı

Yer: `<proje>/.plan-auditor/plan.json` · UTF-8 · `validate` modu şemayı zorunlu kılar.

## Üst seviye

| Alan | Tip | Zorunlu | Açıklama |
|---|---|---|---|
| `task` | string | evet | Görevin tek cümlelik tanımı |
| `created` | string | evet | ISO-8601 zaman damgası |
| `steps` | liste | evet | En az 1 adım; `id` benzersiz pozitif tam sayı |

## Adım

| Alan | Tip | Zorunlu | Açıklama |
|---|---|---|---|
| `id` | int | evet | Benzersiz, 1'den başlar |
| `title` | string | evet | Kısa başlık |
| `verify` | liste | evet | En az 1 kontrol; **boş bırakılamaz** |
| `status` | string | hayır | `pending` (başlangıç) — script `verified`/`failed` yazar |

## Kontrol tipleri (`verify` öğeleri)

| Tip | Alanlar | Anlamı |
|---|---|---|
| `run` | `cmd`, `expect_exit` (vars 0), `output_regex` (ops) | Komutu taze kabukta çalıştır; exit kodu ve (verildiyse) birleşik çıktı regex'i eşleşmeli |
| `file_exists` | `path` | Dosya mevcut olmalı (proje dizinine göre) |
| `regex` | `path`, `pattern` | Dosya içeriğinde regex eşleşmeli |
| `pytest` | `args` (ops) | `python -m pytest <args>` çalışır, exit 0 beklenir (`run`'a normalize edilir) |
| `exec` | `cmd`, `expect_exit` (vars 0) | Harici denetçi çalıştırır — derlenmiş C++/Rust ikilisi, jar, betik... Dil fark etmez; exit kodu kanıttır |

## Kural örnekleri

İyi — ölçülebilir:
- `{"type": "run", "cmd": "python -m pytest tests/ -q", "expect_exit": 0}`
- `{"type": "regex", "path": "src/auth.py", "pattern": "def\\s+login"}`

Kötü — ölçüsüz, reddedilir mantık olarak:
- "kod düzgün çalışıyor" · "test edildi" · "görsel olarak doğru"

**Zorunlu:** Her adım en az bir DAVRANIŞSAL kontrol içermelidir (`run` veya `pytest`). Yalnızca `file_exists`/`regex` kombinasyonu bir adımı doğrulayamaz — dosyanın var olması işin *doğru* olduğu anlamına gelmez.

## Notlar

- `verify` listesi iş başladıktan sonra gevşetilemez; yalnızca sıkılaştırılabilir/eklenebilir.
- Windows cmd uyumluluğu: komutlar `shell=True` ile çalışır; `/` veya `\\` fark etmez.
- evidence.jsonl kayıtları `{ts, mode, step, results, status, prev, hash}` biçiminde; her kayıt öncekinin SHA-256'sını `prev` ile taşır (hash zinciri) — sonradan değiştirilirse `status`/`audit` uyarı verir.

## Command execution safety

Behavioral checks disable shell interpretation by default. Prefer structured
`argv` for exact, cross-platform execution, for example:

```json
{"type":"run","argv":["python","-m","pytest","tests/","-q"],"expect_exit":0}
```

Legacy `cmd` strings remain supported, but are parsed into an argument vector
and executed without a shell. Shell operators such as `>`, `&&`, pipes, globbing,
and variable expansion are therefore inert unless the check explicitly sets
`"shell": true`. Shell mode is an explicit trust-boundary opt-in and cannot be
combined with `argv`.
