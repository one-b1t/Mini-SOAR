# Harness pengujian Telegram — 3 lapis

Dari murah ke mahal. Makin ke bawah makin kuat buktinya, makin mahal ongkosnya.

| Lapis | File | Butuh | Membuktikan |
|---|---|---|---|
| 1. Unit | `tests/test_bot_args.py`, `tests/test_bot.py` | — | logika handler: validasi arg, format reply, auth_guard |
| 2. Smoke | `tests/test_telegram_e2e.py` | token bot | bot hidup, command terdaftar, polling tidak terblokir webhook |
| 3. E2E userbot | `tests/test_telegram_e2e_user.py` | akun user + telethon | bot benar-benar membalas / menolak user sungguhan di server Telegram |

Lapis 2 dan 3 ditandai `@pytest.mark.e2e` dan **tidak jalan secara default**
(`pytest.ini`: `addopts = -m "not e2e"`), jadi `./minisoar.sh test` tetap offline.

> Catatan venv: python3.12 tidak ada di mesin ini, jadi semua contoh memakai
> `PYTHONPATH=.venv/lib/python3.12/site-packages python3`.

## Lapis 1 — unit, tanpa jaringan

```bash
PYTHONPATH=.venv/lib/python3.12/site-packages python3 -m pytest tests/test_bot_args.py -q
```

## Lapis 2 — smoke ke bot sungguhan

Token diambil otomatis dari `.env` (`TELEGRAM_TOKEN`, fallback `TELEGRAM_BOT`),
resolusi yang sama dengan `minisoar/config.py`, jadi biasanya cukup:

```bash
PYTHONPATH=.venv/lib/python3.12/site-packages python3 -m pytest tests/test_telegram_e2e.py -m e2e -q -s
```

Semua panggilan read-only. Kalau `test_no_webhook_blocking_polling` merah,
webhook masih terpasang dan polling tidak akan pernah menerima update —
hapus dengan (mengubah state bot produksi, karena itu opt-in):

```bash
TELEGRAM_E2E_FIX_WEBHOOK=1 \
PYTHONPATH=.venv/lib/python3.12/site-packages \
python3 -m pytest tests/test_telegram_e2e.py::test_no_webhook_blocking_polling -m e2e -q -s
```

## Lapis 3 — E2E lewat userbot (MTProto)

Satu-satunya lapis yang membuktikan `auth_guard` menolak user sungguhan.
Butuh `pip install telethon` dan kredensial akun user dari <https://my.telegram.org>.

Bikin session string sekali, di mesin lokal:

```bash
python3 -c "
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
with TelegramClient(StringSession(), API_ID, 'API_HASH') as c:
    print(c.session.save())"
```

Lalu jalankan:

```bash
TELEGRAM_API_ID=123456 \
TELEGRAM_API_HASH=abc... \
TELEGRAM_SESSION_STRING=1Bx... \
TELEGRAM_E2E_BOT=@nama_bot_anda \
PYTHONPATH=.venv/lib/python3.12/site-packages \
python3 -m pytest tests/test_telegram_e2e_user.py -m e2e -q -s
```

Test menyesuaikan diri dengan `ALLOWED_USERS`: kalau id akun user ada di sana,
ia menuntut bot merespons normal; kalau tidak, ia menuntut bot membalas
"tidak punya akses" **dan** tidak sempat memproses blokir.

⚠️ `TELEGRAM_SESSION_STRING` setara kredensial penuh akun Telegram. Simpan di
secret store, jangan commit, jangan taruh di CI yang log-nya terbuka.
