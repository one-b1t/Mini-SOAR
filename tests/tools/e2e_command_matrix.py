"""E2E: kirim tiap command bot lewat userbot Telethon, catat balasan.

Read-only terhadap repo; hanya mengirim pesan ke bot.
Dipakai manual, bukan bagian suite pytest (butuh kredensial + jaringan).

PATH
  File ini dulu di `scratch/`, tapi `scratch/` ada di .gitignore (baris 131),
  jadi seluruh kemampuan mode real hilang begitu mesin ini mati dan tidak
  ada yang bisa mereview. Dipindah ke `tests/tools/` yang ter-track.
  `scripts/` memang sudah ada, tapi isinya tool operasional (start/stop/
  health), bukan harness uji. Yang bikin modul ini tidak bisa diimpor tanpa
  Telethon adalah CLI-nya, bukan logikanya; impor Telethon sudah dipindah ke
  dalam fungsi, jadi select_cases/undo_plan/self_check diuji di
  `tests/test_e2e_harness.py` tanpa Telegram.

MODE
  default            : mode mock. Kasus write hanya boleh jalan kalau bot
                       terbukti MINISOAR_MOCK=1 (lihat PENGAMAN).
  --mock             : set MINISOAR_MOCK=1 di os.environ proses skrip ini.
                       Skrip ini TIDAK menjalankan bot, jadi flag ini tidak
                       mengubah bot yang sudah hidup - bot harus DISTART
                       sendiri dengan MINISOAR_MOCK=1.
  --real             : kirim kasus write ke perimeter NYATA. Bot tidak boleh
                       mock; skrip memeriksa itu lebih dulu dan berhenti kalau
                       ternyata masih mock, supaya "lulus" palsu tidak terjadi.
  --cleanup-only     : lewati semua kasus uji, hanya kirim perintah undo lalu
                       verifikasi. Pakai kalau run sebelumnya mati sebelum
                       cleanup selesai.
  --self-check       : cek invarian matriks (tanpa jaringan), lalu keluar.

  --allow-host sudah DILOCK. Lihat BUG P0 di bawah.

BUG P0 YANG BELUM SELESAI: /isolate_host TIDAK AMAN
  `edr/kaspersky.py find_host_by_ip` mengirim `wstrFilter: ""` tanpa filter,
  tidak menyaring hasil per IP, lalu `isolate_host` mengambil `hosts[0]`.
  Artinya /isolate_host 10.0.0.50 akan mengisolasi HOST PERTAMA dari KSC
  produksi, bukan host dengan IP 10.0.0.50. Mengganti IP ke TEST-NET tidak
  menolong, karena IP tidak pernah dipakai sebagai filter.
  Sampai fix itu di-merge, `HOST_ISOLATION_BLOCKED = True` membuat sel
  kind="host" tidak bisa dipilih di mode real BAWAH APA PUN - bukan sekadar
  default mati, dan bukan_andalkan flag. Set konstantanya ke False setelah fix
  P0 masuk, lalu test di tests/test_e2e_harness.py akan otomatis berubah.

BATAS MODE REAL
  Real mode berhenti di lapisan candidate/list. `/commit_palo` =
  `paloalto.partial_commit(admin=PA_ADMIN)` yang meng-commit SEMUA pending
  change milik admin itu, jadi perubahan milik operator bisa ikut naik ke
  produksi; dan kalau commit#1 sukses lalu commit#2 gagal, tidak ada yang
  menyelesaikannya (auto-unblock daemon memakai commit=False, daemon.py:328).
  Karena itu `commitpalo` dan `activateakamai` ber-kind no_undo/mock_only dan
  TIDAK PERNAH dikirim di real mode.
  Trade-off yang harus dipahami: block_palo/unblock_palo di real mode hanya
  menyentuh candidate session, tidak pernah aktif config. Jadi test ini
  membuktikan jalur API Palo Alto benar, TIDAK membuktikan blokir benar-benar
  berlaku di firewall. Kalau yang kedua yang mau dibuktikan, itu perlu
  procedures yang Birdshot komit eksplisit - di luar cakupan harness ini.

PEMBERSIHAN (selalu aktif, mock maupun real)
  Setiap kasus kind="write" wajib punya perintah undo di kolom ke-4. Setelah
  semua kasus dikirim -sukses, gagal, atau Ctrl-C- skrip mengirim tiap undo
  dalam urutan terbalik lewat jalur yang sama, lalu memverifikasi apakah
  jejak tes tertinggal. Hasilnya dicetak sebagai tabel CLEANUP dan ditulis ke
  scratch/e2e_cleanup-<mode>.json.

  Yang TIDAK bisa diverifikasi sekarang, dan tidak boleh disamarkan:
  `mitigation.core.get_active_blocklist` hanya membaca Redis ZSET
  minisoar:pending_unblocks dan key minisoar:edr_ioc_synced:*. Tapi
  bot.py:1104 (block_cf) dan bot.py:1134 (block_forti) tidak pernah menulis
  Redis sama sekali. Jadi /blocked TIDAK bisa membuktikan apa-apa soal
  Cloudflare dan FortiGate, dan tidak ada command bot lain yang membaca
  blocklist kedua sistem itu. Akamai dan Imperva hanya terlihat sebagai
  candidate di Redis, bukan konfigurasi nyata. Satu-satunya read-back yang
  benar-benar membuktikan keadaan nyata adalah /whitelists, karena ia
  membaca file whitelist lokal. Lihat PERIMETER dan verify_clean().

Contoh:  python tests/tools/e2e_command_matrix.py --read-only
        python tests/tools/e2e_command_matrix.py --read-only intel
        python tests/tools/e2e_command_matrix.py --mock block
        python tests/tools/e2e_command_matrix.py --real
        python tests/tools/e2e_command_matrix.py --real block
        python tests/tools/e2e_command_matrix.py --cleanup-only --real
        python tests/tools/e2e_command_matrix.py --self-check
"""
import argparse
import asyncio
import json
import os
import sys
import time

try:  # Telethon hanya dibutuhkan saat benar-benar mengirim pesan. Logika
    # select_cases/undo_plan/self_check harus bisa diimpor dan diuji tanpa
    # Telegram sama sekali, jadi jangan jadikan import modul-level.
    from telethon import TelegramClient
    from telethon.errors import RPCError
except ImportError:  # pragma: no cover
    TelegramClient = None
    RPCError = Exception

CRED_PATH = "tests/tg_credentials.json"
ARTIFACT_DIR = "scratch"  # gitignored; hanya tempat output, bukan source

# Target uji. Semua dari TEST-NET (RFC 5737) kecuali yang ditandai.
BLOCK_TEST_IP = "203.0.113.88"        # TEST-NET-3, tidak pernah routable
WHITELIST_TEST_IP = "198.51.100.55"   # TEST-NET-2
HOST_TEST_TARGET = "10.0.0.50"        # RFC1918 - BISA jadi host internal asli
# Yang dicek pada read-back yang memang bisa dipakai.
TRACKED_IPS = (BLOCK_TEST_IP, WHITELIST_TEST_IP)

# Ganti ke False setelah fix `find_host_by_ip` (wstrFilter per IP) sudah merge.
HOST_ISOLATION_BLOCKED = True
HOST_ISOLATION_REASON = (
    "edr/kaspersky.py find_host_by_ip mengirim wstrFilter kosong lalu "
    "isolate_host mengambil hosts[0], jadi /isolate_host akan mengisolasi host "
    "pertama di KSC produksi, bukan host dengan IP yang diminta. IP TEST-NET "
    "tidak menolong karena IP tidak pernah dipakai sebagai filter."
)

# Provider perimeter yang aktif dan boleh disentuh di mode real (user 2026-09-28:
# Cloudflare, FortiGate, dan Kaspersky Security Center DIMATIKAN TOTAL.
# Perimeter aktif hanya PaloAlto, Akamai, TrendMicro Vision One, ditambah
# whitelist lokal).
REAL_ALLOWED_PROVIDERS = {"palo", "paloalto", "akamai", "trendmicro", "whitelist"}
REAL_ALLOWED_PERIMETERS = REAL_ALLOWED_PROVIDERS

REAL_DISABLED_PERIMETERS = {
    "cloudflare": "Perimeter Cloudflare dimatikan total (user 2026-09-28)",
    "fortigate": "Perimeter FortiGate dimatikan total (user 2026-09-28)",
    "edr-kaspersky": "Kaspersky Security Center (KSC) dimatikan total (user 2026-09-28)",
    "imperva": "Perimeter Imperva di luar daftar provider aktif real (hanya PaloAlto, Akamai, TrendMicro)",
}

# Satu command per handler unik. Kolom: handler, command, kind, undo, perimeter.
#
# kind:
#   read       hanya membaca, tidak mengubah apa pun
#   write      mengubah state di perimeter, WAJIB punya undo
#   host       seperti write tapi menyasar host (dikunci, lihat BUG P0)
#   no_undo    tidak ada perintah bot yang membatalkannya -> dilarang di real
#   mock_only  aktifkan produksi / tulis model -> hanya boleh saat mock
#
# undo: command pembatal. Hanya boleh memuat salah satu VERB_UNDO di bawah,
# supaya tidak ada salah ketik yang menghapus data orang lain. Kasus yang
# command-nya sudah menetralkan state (unblock/restore/whitelist_remove)
# dikosongkan - "undo" untuk kasus begitu justru memblokir lagi.
#
# perimeter: kunci PERIMETER yang benar-benar disentuh command ini, atau None
# kalau tidak menyentuh perimeter sama sekali. DICATAT PER KASUS, bukan ditebak
# dari nama handler. Dulu pemetaannya pakai substring pada nama handler, dan
# itu rapuh: "tracev" (handler /trace_imperva) tidak memuat kata "imperva",
# jadi /trace_imperva lolos dari exclusion mode real. Nama handler juga bisa
# jadi substring nama lain - tracev vs tracevakamai vs tracevpalo - sehingga
# satu pintu masuk bisa men-seret kasus lain. Sekarang tidak ada mapping
# terpisah yang bisa menyimpang dari daftar di bawah.
#
# Kenapa /query_host dan /add_edr_ioc tetap "edr-kaspersky" meski Kaspersky
# sudah dimatikan total: keduanya adalah sisi Kaspersky dari lapisan EDR, dan
# ditahan dari mode real secara konservatif. Itu keputusan sengaja, bukan sisa
# pemetaan lama.
CASES = [
    ("help",              "/help",                          "read",     None,                    None),
    ("health",            "/health",                        "read",     None,                    None),
    ("cases_cmd",         "/cases",                         "read",     None,                    None),
    ("case_cmd",          "/case INC-20260818-001",          "read",     None,                    None),
    ("exportcase_cmd",    "/export_case INC-20260818-001",   "read",     None,                    None),
    ("socmetrics_cmd",    "/socmetrics",                    "read",     None,                    None),
    ("edrstatus",         "/edrstatus",                     "read",     None,                    None),
    ("blocked_cmd",       "/blocked",                       "read",     None,                    None),
    ("whitelists_cmd",    "/whitelists",                    "read",     None,                    None),
    ("intel_cmd",         "/intel 8.8.8.8",                 "read",     None,                    None),
    ("tracev",            "/trace_imperva 758812345 1",     "read",     None,                    "imperva"),
    ("tracevakamai",      "/trace_akamai 12345678",         "read",     None,                    "akamai"),
    ("tracevpalo",        "/trace_palo 999888",             "read",     None,                    "palo"),
    ("queryhost",         "/query_host 10.0.0.50",          "read",     None,                    "edr-kaspersky"),
    ("askai_cmd",         "/ask_ai ringkasan incident 42",  "read",     None,                    None),
    ("rca_cmd",           "/rca 8.8.8.8",                   "read",     None,                    None),
    ("aiprovider_cmd",    "/ai_provider",                   "read",     None,                    None),
    ("aimodel_cmd",       "/ai_model",                      "read",     None,                    None),
    # Mutasi record case/jira sungguhan. Tidak ada command undo-nya, jadi
    # menimpa status investigating milik orang lain tidak bisa ditarik back.
    ("updatecase_cmd",    "/update_case INC-20260818-001 INVESTIGATING tes-e2e", "no_undo", None, None),
    ("syncticket_cmd",    "/sync_ticket INC-20260818-001",  "no_undo",  None,                    None),
    ("blockonimperva",    "/block_imperva 203.0.113.88",    "write",    "/unblock_imperva 203.0.113.88", "imperva"),
    ("unblockonimperva",  "/unblock_imperva 203.0.113.88",  "write",    None,                    "imperva"),
    ("blockonpalo",       "/block_palo 203.0.113.88",       "write",    "/unblock_palo 203.0.113.88",  "palo"),
    ("unblockonpalo",     "/unblock_palo 203.0.113.88",     "write",    None,                    "palo"),
    ("blockonakamai",     "/block_akamai 203.0.113.88",     "write",    "/unblock_akamai 203.0.113.88", "akamai"),
    ("unblockonakamai",   "/unblock_akamai 203.0.113.88",   "write",    None,                    "akamai"),
    ("blockoncf_cmd",     "/block_cf 203.0.113.88",         "write",    "/unblock_cf 203.0.113.88", "cloudflare"),
    ("unblockoncf_cmd",   "/unblock_cf 203.0.113.88",       "write",    None,                    "cloudflare"),
    ("blockonforti_cmd",  "/block_forti 203.0.113.88",      "write",    "/unblock_forti 203.0.113.88", "fortigate"),
    ("unblockonforti_cmd","/unblock_forti 203.0.113.88",    "write",    None,                    "fortigate"),
    ("whitelist_add_cmd", "/whitelist_add 198.51.100.55 tes-e2e", "write", "/whitelist_remove 198.51.100.55", "whitelist"),
    ("whitelist_remove_cmd", "/whitelist_remove 198.51.100.55",  "write", None,  "whitelist"),
    # partial_commit() meng-commit SEMUA pending change milik admin itu, bukan
    # hanya milik test, jadi tidak boleh dipicu harness mana pun.
    ("commitpalo",        "/commit_palo",                   "no_undo",  None,                    "palo"),
    # Dikunci oleh HOST_ISOLATION_BLOCKED, bukan sekadar default mati.
    ("isolatehost",       "/isolate_host 10.0.0.50 trendmicro", "host", "/restore_host 10.0.0.50 trendmicro", "trendmicro"),
    ("restorehost",       "/restore_host 10.0.0.50 trendmicro", "host",  None,                    "trendmicro"),
    # Tidak ada /remove_edr_ioc di bot, dan scripts/cleanup_minisoar_edr_iocs.py
    # TIDAK akan mengapus ini: handler memberi comment "Manual IoC by @user",
    # sedangkan cleaner hanya mau marker "threatintel rep:", "event:alert_",
    # "minisoar automated", "minisoar-block-", dan 4 playbook lain
    # (cleanup_minisoar_edr_iocs.py:90-101). Kunci redis-nya TTL 24 jam.
    ("addedrioc",         "/add_edr_ioc 10.0.0.50 all",     "no_undo",  None,                    "edr-kaspersky"),
    # Guard MINISOAR_MOCK (bot.py activateakamai & retrainmodel_cmd) membalas
    # "Mode mock aktif ... dilewati". BUKAN "read": tanpa mock keduanya
    # menyentuh produksi (aktivasi Akamai network PRODUCTION; ES minisoar-
    # labels-* + tulis model), jadi tidak boleh masuk mode real.
    ("activateakamai",    "/activate_akamai",               "mock_only", None,                   "akamai"),
    ("retrainmodel_cmd",  "/retrainmodel",                  "mock_only", None,                   None),
]

# Perintah pembatal yang boleh dipakai sebagai undo. Daftar putih ini yang
# menjaga kolom undo tidak pernah berisi command destruktif.
VERB_UNDO = ("/unblock_", "/restore_host", "/whitelist_remove")

# Command yang SENDIRINYA mengembalikan state ke netral, jadi kasus seperti ini
# tidak butuh undo (meng-undo jadi memblokir lagi, arahnya salah).
NEUTRALIZER = ("/unblock_", "/restore_host", "/whitelist_remove")

# Kind yang wajib lolos pengaman mock SEBELUM mode real dipakai.
GATED_KINDS = {"write", "host", "mock_only", "no_undo"}

# -> sistem yang dibaca
#      readback : command bot yang bisa membuktikannya, None = tidak ada
#      bukti     : apa yang sebenarnya dibuktikan readback itu
#      alasan    : kenapa readback tidak tersedia (dipakai di laporan)
PERIMETER = {
    "imperva":    ("/blocked", "candidate-redis",
                   "Redis menyimpan candidate block, bukan daftar blokir aktif Imperva"),
    "palo":       ("/blocked", "candidate-redis",
                   "Redis menyimpan candidate block; tanpa /commit_palo config aktif tidak pernah berubah"),
    "akamai":     ("/blocked", "candidate-redis",
                   "Redis menyimpan candidate block; tanpa /activate_akamai network aktif tidak pernah berubah"),
    "cloudflare": (None, "tidak-ada",
                   "bot.py blockoncf_cmd tidak menulis Redis dan tidak ada command yang membaca blocklist Cloudflare"),
    "fortigate":  (None, "tidak-ada",
                   "bot.py blockonforti_cmd tidak menulis Redis dan tidak ada command yang membaca blocklist FortiGate"),
    "whitelist":  ("/whitelists", "file-whitelist",
                   "/whitelists membaca minisoar-whitelist.txt langsung, jadi ini read-back sebenarnya"),
    "trendmicro": (None, "tidak-ada",
                   "/edrstatus hanya melaporkan konektivitas agent, bukan daftar host yang terisolasi; "
                   "tidak ada command bot yang membaca state TrendMicro"),
    "edr-kaspersky": (None, "tidak-ada",
                      "Kaspersky KSC dimatikan total; tidak boleh disentuh di mode real"),
    "edr":        (None, "tidak-ada",
                   "/edrstatus hanya melaporkan konektivitas agent, bukan daftar host yang terisolasi; "
                   "tidak ada command bot yang membaca state Kaspersky/TrendMicro"),
}

# Probe mock: jawaban tetap copilot.call_llm() saat MINISOAR_MOCK=1.
MOCK_PROBE_CMD = "/ask_ai e2e-mock-probe"
MOCK_PROBE_MARKER = "Mock Analysis"

# Tidak diuji, dan alasannya.
SKIPPED = [
    ("aiprovider_cmd(set)", "/ai_provider <nama>",
     "set_active_provider mengganti os.environ['AI_PROVIDER'] proses bot secara "
     "live (bukan .env; hilang saat restart), tanpa guard mock. Tetap mengubah "
     "perilaku AI untuk semua user bot sampai restart."),
    ("aimodel_cmd(set)", "/ai_model <nama>",
     "set_active_model mengganti os.environ['AI_MODEL'] proses bot secara live "
     "(bukan .env; hilang saat restart). Sama seperti di atas."),
]

TIMEOUT = 90
# Balasan bot kadang telat >5s (unblock* butuh ES + redis + label). Tunggu
# sampai SUNYI selama SETTLE detik, kalau tidak reply yang lambat akan
# masuk ke command berikutnya.
SETTLE = 9.0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--read-only", action="store_true",
                    help="hanya kirim command kind=read")
    ap.add_argument("--mock", action="store_true",
                    help="set MINISOAR_MOCK=1 di proses skrip (tidak mengubah bot yang sudah jalan)")
    ap.add_argument("--real", action="store_true",
                    help="kirim ke perimeter nyata; bot wajib terbukti TIDAK mock, "
                         "dan setiap kasus write dibersihkan sesudahnya")
    ap.add_argument("--allow-host", action="store_true",
                    help="DIKUNCI: selalu gagal selama HOST_ISOLATION_BLOCKED=True "
                         "(bug P0 find_host_by_ip). Flag ini sengaja tidak hilang "
                         "supaya niatnya tetap terlihat di --help.")
    ap.add_argument("--cleanup-only", action="store_true",
                    help="hanya kirim perintah undo + verifikasi, tanpa kasus uji")
    ap.add_argument("--self-check", action="store_true",
                    help="cek invarian matriks (tanpa jaringan), lalu keluar")
    ap.add_argument("only", nargs="?", help="filter substring nama handler, mis. 'block'")
    return ap.parse_args(argv)


def get_real_skip_reason(case):
    """Alasan mengapa kasus dibuang saat mode real aktif."""
    handler, cmd, kind, _undo, perim = case
    if perim in REAL_DISABLED_PERIMETERS:
        return REAL_DISABLED_PERIMETERS[perim]
    if perim and perim not in REAL_ALLOWED_PROVIDERS:
        return f"perimeter '{perim}' di luar provider real yang diizinkan ({', '.join(sorted(REAL_ALLOWED_PROVIDERS))})"
    if kind in ("no_undo", "mock_only"):
        return f"kind={kind} tidak dikirim di mode real"
    if kind == "host" and HOST_ISOLATION_BLOCKED:
        return f"kind=host dikunci: {HOST_ISOLATION_REASON}"
    return None


def select_cases(read_only=False, only=None, real=False, allow_host=False, skipped_reasons=None):
    """Pilih kasus. `real` membuang semua yang tidak bisa dibersihkan atau provider nonaktif."""
    out = []
    for c in CASES:
        handler, kind = c[0], c[2]
        if only and only not in handler:
            continue
        if read_only and kind != "read":
            continue
        if real:
            reason = get_real_skip_reason(c)
            if reason:
                if skipped_reasons is not None:
                    skipped_reasons[handler] = reason
                continue
            if kind == "host" and not allow_host:
                if skipped_reasons is not None:
                    skipped_reasons[handler] = "kind=host butuh --allow-host"
                continue
        out.append(c)
    return out


def undo_plan(cases):
    """[(handler, command)] untuk setiap kasus yang meninggalkan jejak."""
    return [(c[0], c[3]) for c in cases if c[3]]


def touched_perimeters(cases):
    """Sistem mana saja yang benar-benar disentuh kasus yang dipilih."""
    out = []
    for c in cases:
        key = c[4]
        if key and key not in out:
            out.append(key)
    return out


def self_check():
    """Invarian matriks. Tidak butuh jaringan; jalankan sebelum mode real."""
    problems = []
    for c in CASES:
        handler, cmd, kind, undo, perim = c
        neutral = cmd.startswith(NEUTRALIZER)
        if kind in ("write", "host"):
            # Kasus yang berubah state harus punya undo, kecuali command-nya
            # sudah mengembalikan state ke netral.
            if not undo and not neutral:
                problems.append(f"{handler}: kind={kind} mengubah state tanpa undo")
        if kind in ("read", "no_undo", "mock_only") and undo:
            problems.append(f"{handler}: punya undo tapi kind={kind}")
        if undo and not undo.startswith(VERB_UNDO):
            problems.append(f"{handler}: undo {undo!r} di luar daftar putih {VERB_UNDO}")
        if undo == cmd:
            problems.append(f"{handler}: undo sama dengan command aslinya")
        if undo and ("/block" in undo or " isolate_host" in undo):
            # Undo yang mengembalikan state ke "blocked" tidak pernah boleh
            # jadi pembatal: justru memperpanjang masalah.
            problems.append(f"{handler}: undo {undo!r} memblokir, bukan membatalkan")

    real_all = select_cases(real=True, allow_host=True)
    real_names = {c[0] for c in real_all}
    for c in CASES:
        if c[2] in ("no_undo", "mock_only") and c[0] in real_names:
            problems.append(f"{c[0]}: kind={c[2]} bocor ke mode real")
        if perim and perim not in REAL_ALLOWED_PROVIDERS and c[0] in real_names:
            problems.append(f"{c[0]}: perimeter '{perim}' bocor ke mode real padahal tidak aktif")
    if HOST_ISOLATION_BLOCKED:
        for c in CASES:
            if c[2] == "host" and c[0] in real_names:
                problems.append(f"{c[0]}: kind=host bocor ke real padahal P0 belum diperbaiki")
    else:
        for c in CASES:
            if c[2] == "host" and c[0] not in real_names:
                problems.append(f"{c[0]}: kind=host tidak bisa dipilih walau P0 sudah diperbaiki")

    # Setiap sistem yang disentuh harus punya read-back yang jujur: boleh None,
    # tapi kalau ada readback harus ada alasan. Tidak boleh diam-diam "bersih".
    for key, (readback, bukti, alasan) in PERIMETER.items():
        if readback is None and not alasan:
            problems.append(f"PERIMETER[{key}]: tanpa readback tapi tanpa alasan")
        if readback is None and bukti != "tidak-ada":
            problems.append(f"PERIMETER[{key}]: tanpa readback tapi bukti={bukti!r}")
        if readback is not None and alasan is None:
            problems.append(f"PERIMETER[{key}]: readback tanpa penjelasan")

    # Setiap kasus write harus terhubung ke sistem perimeter yang bisa dilacak.
    for c in CASES:
        if c[2] in ("write", "host") and c[4] is None:
            problems.append(f"{c[0]}: kind={c[2]} tidak terhubung ke PERIMETER, "
                            "cleanup tidak akan memverifikasinya")

    # Kunci perimeter harus benar-benar ada di PERIMETER. Salah ketik di kolom
    # akan membuat verify_clean() melempar KeyError di tengah cleanup, jauh
    # setelah command sudah terkirim ke perimeter nyata.
    for c in CASES:
        if c[4] is not None and c[4] not in PERIMETER:
            problems.append(f"{c[0]}: perimeter '{c[4]}' tidak ada di PERIMETER")

    # Nama handler tidak boleh jadi sumber kebenaran pemetaan. Kalau suatu saat
    # ada yang menambahkan kembali pemetaan berbasis substring, guard ini
    # menangkapnya: dua handler yang namanya substring satu sama lain WAJIB
    # punya perimeter berbeda, kecuali pasangannya memang satu perimeter yang
    # berlawanan arah (unblockonX vs blockonX).
    for a in CASES:
        for b in CASES:
            if (a is not b and a[0] != b[0] and a[0] in b[0]
                    and a[4] is not None and a[4] == b[4]
                    and b[0] != "un" + a[0]):
                problems.append(
                    f"{a[0]} adalah substring dari {b[0]} tapi keduanya sudah "
                    f"petakan ke '{a[4]}'; pemetaan berbasis nama handler "
                    f"tidak akan bisa membedakan keduanya")

    if problems:
        print(f"SELF-CHECK GAGAL ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return False
    dirty = sum(1 for c in CASES if c[2] in ("no_undo", "mock_only"))
    print(f"SELF-CHECK OK: {len(CASES)} kasus, {len(undo_plan(CASES))} punya undo, "
          f"{len(CASES) - len(undo_plan(CASES)) - dirty} netral (tidak perlu undo), "
          f"{dirty} ditolak di mode real.")
    # Hanya relevan untuk perimeter yang benar-benar bisa disentuh di mode real.
    # Yang ada di REAL_DISABLED_PERIMETERS tidak pernah dijalankan, dan yang tidak
    # dipakai kasus apa pun juga tidak akan di-cleanup, jadi menyebutnya di sini
    # membuat operator mengira ada cleanup yang belum terverifikasi.
    used = {c[4] for c in CASES if c[4]}
    unver = sorted(k for k, v in PERIMETER.items()
                   if v[0] is None and k in used and k not in REAL_DISABLED_PERIMETERS)
    if unver:
        print(f"  CATATAN: {len(unver)} perimeter tidak punya read-back via bot "
              f"({', '.join(unver)}); cleanup tidak akan bisa membuktikannya bersih.")
    return True


async def boundary(client, bot):
    """Id pesan tertinggi yang ada sebelum command berikutnya."""
    try:
        top = await client.get_messages(bot, limit=1)
        return top[0].id if top else 0
    except RPCError:
        return 0


async def one(client, bot, handler, cmd, kind, before):
    """Kirim cmd, kumpulkan balasan bot dalam rentang id (before, ...]."""
    t0 = time.time()
    try:
        sent = await client.send_message(bot, cmd)
    except RPCError as e:
        return dict(handler=handler, cmd=cmd, kind=kind, status="SEND_FAIL",
                    elapsed=0.0, replies=[str(e)])
    replies, last = [], time.time()
    while time.time() - last < SETTLE and time.time() - t0 < TIMEOUT:
        try:
            # Tanpa limit: dulu limit=20 membuat `fresh` mentok di 20 sehingga
            # `len(fresh) > len(replies)` tidak pernah naik lagi dan snapshot
            # membeku. min_id=sent.id sudah membatasi rentangnya.
            msgs = await client.get_messages(bot, limit=None, min_id=sent.id)
        except RPCError:
            break
        # Hanya pesan setelah command ini, dan hanya yang dikirim bot.
        fresh = sorted((m for m in msgs
                        if m.id > sent.id and m.sender_id == bot.id),
                       key=lambda m: m.id)
        if len(fresh) > len(replies):
            replies = fresh
            last = time.time()
        await asyncio.sleep(0.8)
    texts = [m.text for m in replies]
    joined = "\n".join(texts)
    if not texts:
        status = "NO_REPLY"
    elif "tidak punya akses" in joined.lower():
        status = "DENIED"
    elif any(t in joined for t in ("Traceback", "NameError", "AttributeError",
                                   "TypeError", "KeyError", "ValueError")):
        status = "EXCEPTION"
    elif "Terjadi kesalahan" in joined or "error" in joined.lower():
        status = "ERROR_TEXT"
    else:
        status = "OK"
    return dict(handler=handler, cmd=cmd, kind=kind, status=status,
                elapsed=round(time.time() - t0, 1), replies=texts)


async def drain_backlog(client, bot, quiet=SETTLE, max_wait=180):
    """Tunggu sampai bot berhenti mengirim pesan selama `quiet` detik.

    Bot yang baru start memproses update Telegram yang tertunda (command yang
    dikirim saat bot mati) - balasannya bisa jatuh di jendela probe/kasus
    pertama dan tercampur. Return (sunyi?, pesan bot yang dibalas selama drain).
    """
    start_id = await boundary(client, bot)
    t0 = last = time.time()
    seen = []
    while time.time() - last < quiet:
        if time.time() - t0 > max_wait:
            return False, seen
        try:
            msgs = await client.get_messages(bot, limit=None, min_id=start_id)
        except RPCError:
            return False, seen
        fresh = sorted((m for m in msgs if m.sender_id == bot.id), key=lambda m: m.id)
        if len(fresh) > len(seen):
            seen = fresh
            last = time.time()
        await asyncio.sleep(0.8)
    return True, seen


async def verify_bot_is_mock(client, bot):
    """True hanya bila balasan /ask_ai memuat penanda jawaban mock."""
    before = await boundary(client, bot)
    r = await one(client, bot, "mock_probe", MOCK_PROBE_CMD, "read", before)
    return any(MOCK_PROBE_MARKER in (t or "") for t in r["replies"]), r


async def verify_clean(client, bot, perimeters):
    """Coba buktikan jejak tes tidak tertinggal - sebatas yang memang bisa.

    Return dict dengan tiga bagian, yang HARUS dibaca terpisah:
      verified   : [(perimeter, "aman" | "SISA: ...")] - ada read-back nyata
      unverified : [(perimeter, alasan)] - TIDAK ada command bot yang bisa
                   membuktikannya, jadi tidak boleh dilaporkan "bersih"
      unreadable : [(perimeter, status)] - read-back ada tapi balancernya gagal

    Sistem tanpa read-back sengaja TIDAK diasumsikan bersih. Diam saja di sini
    lebih berbahaya daripada tidak melapor: operator akan percaya.
    """
    verified, unverified, unreadable = [], [], []
    for key in perimeters:
        readback, bukti, alasan = PERIMETER[key]
        if readback is None:
            unverified.append((key, alasan))
            continue
        before = await boundary(client, bot)
        r = await one(client, bot, f"verify_{key}", readback, "read", before)
        # Hanya balesan yang benar-benar berhasil yang dipakai. Kalau /blocked
        # balas "Redis OFFLINE" (ERROR_TEXT), daftarnya memang tak terbaca -
        # bukan bukti bersih, dan harus dilaporkan sebagai tidak bisa dicek.
        if r["status"] != "OK":
            unreadable.append((key, f"{readback} -> {r['status']}"))
            continue
        joined = "\n".join(t or "" for t in r["replies"])
        sisa = [ip for ip in TRACKED_IPS if ip in joined]
        if sisa:
            verified.append((key, "SISA: " + ", ".join(sisa) + f" masih ada di {readback}"))
        else:
            verified.append((key, f"aman (bukti: {bukti})"))
    return dict(verified=verified, unverified=unverified, unreadable=unreadable)


async def run_cleanup(client, bot, cases, mode):
    """Kirim semua undo (terbalik), lalu verifikasi - sebatas yang bisa.

    Dipanggil dari finally: cleanup tetap jalan walau run utama exception,
    KeyboardInterrupt, atau subprocess dibunuh setelah masuk blok try.
    """
    plan = undo_plan(cases)
    perimeters = touched_perimeters(cases)
    print(f"\n=== CLEANUP ({len(plan)} perintah undo) ===")
    if not plan:
        print("  tidak ada yang perlu dibersihkan")
    rows = []
    for handler, cmd in reversed(plan):
        before = await boundary(client, bot)
        r = await one(client, bot, f"undo:{handler}", cmd, "cleanup", before)
        rows.append(r)
        print(f"[{r['status']:11s}] {r['elapsed']:5.1f}s  {cmd}")
        for t in r["replies"]:
            print(f"                 -> {' '.join((t or '').split())[:150]}")

    report = await verify_clean(client, bot, perimeters)
    print("\n--- verifikasi ---")
    for key, note in report["verified"]:
        print(f"  {key:11s} {note}")
    for key, note in report["unreadable"]:
        print(f"  {key:11s} TIDAK BISA DIBACA: {note}")
    if report["unverified"]:
        print("\n" + "!" * 72)
        print("PERINGATAN: BAGIAN INI TIDAK BISA DIBUKTIKAN BERSIH")
        for key, note in report["unverified"]:
            print(f"  - {key}: {note}")
        print("  Undo di atas sudah dikirim, tapi tidak ada command bot yang")
        print("  membaca daftar blokir sistem ini. Cek manual di console")
        print("  respective sebelum menyatakan run ini bersih.")
        print("!" * 72)
    elif not report["unreadable"]:
        print(f"  semua yang disentuh punya read-back: aman")

    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    leftover = [k for k, n in report["verified"] if n.startswith("SISA")]
    json.dump({"undo": rows, "perimeters": perimeters, **report,
               "leftovers": leftover},
              open(f"{ARTIFACT_DIR}/e2e_cleanup-{mode}.json", "w"), indent=1)

    if leftover:
        return 2  # ada jejak tes yang terbukti tertinggal
    if report["unverified"] or report["unreadable"]:
        return 3  # tidak bisa dibuktikan bersih
    return 0


async def main():
    # Balasan bot mengandung emoji; stdout Windows default ke cp1252 dan
    # print() akan menunca skrip. errors="replace" supaya tidak ada lagi yang
    # hilang diam-diam.
    for _s in (sys.stdout, sys.stderr):
        _s.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()
    if args.mock:
        os.environ["MINISOAR_MOCK"] = "1"
    if args.self_check:
        sys.exit(0 if self_check() else 1)
    if args.real and args.mock:
        print("BATAL: --real dan --mock tidak bisa dipakai bersamaan.")
        return 1
    if args.allow_host and HOST_ISOLATION_BLOCKED:
        print("BATAL: --allow-host dikunci.\n" + HOST_ISOLATION_REASON)
        return 1

    real = args.real
    # Cleanup-only tetap memakai himpunan undo fullest: sisa dari run yang
    # sebelumnya terpenggal harus tetap bisa dibersihkan meski filter narrower.
    if args.cleanup_only:
        cases = select_cases(only=args.only, real=True, allow_host=False)
    else:
        cases = select_cases(args.read_only, args.only, real, args.allow_host)
    mode = "real" if real else ("read-only" if args.read_only else "mock")

    cred = json.load(open(CRED_PATH))
    bot_username = cred["bot_username"]
    client = TelegramClient("tests/telegram_testing",
                            int(cred["api_id"]), cred["api_hash"])
    await client.connect()
    if not await client.is_user_authorized():
        print("SESSION TIDAK AUTHORIZED")
        return 1
    bot = await client.get_entity(bot_username)
    me = await client.get_me()
    print(f"bot={bot_username}  userbot={me.username}({me.id})  mode={mode}  "
          f"kasus={len(cases)}/{len(CASES)}  undo={len(undo_plan(cases))}\n")

    quiet, drained = await drain_backlog(client, bot)
    if drained:
        print(f"[backlog: {len(drained)} pesan bot dari update tertunda, diabaikan]")
        for m in drained:
            print(f"   ~> {' '.join((m.text or '').split())[:150]}")
    if not quiet:
        print(f"BATAL: bot tidak sunyi dalam 180s (backlog belum habis). "
              "Tidak ada command yang dikirim.")
        await client.disconnect()
        return 1
    print("[chat sunyi, mulai]\n")

    gated = any(c[2] in GATED_KINDS for c in cases)
    if gated:
        is_mock, probe = await verify_bot_is_mock(client, bot)
        if real:
            # Sebaliknya dari mode mock: kalau bot masih mock, hasil run ini
            # tidak membuktikan apa-apa soal perimeter nyata.
            if is_mock:
                print(f"BATAL: --real tapi bot masih MINISOAR_MOCK=1 "
                      f"({MOCK_PROBE_CMD} memuat {MOCK_PROBE_MARKER!r}). "
                      "Restart bot tanpa MINISOAR_MOCK, lalu ulangi. "
                      "Tidak ada command yang dikirim.")
                for t in probe["replies"]:
                    print(f"   -> {' '.join((t or '').split())[:150]}")
                await client.disconnect()
                return 1
            print(f"[bot terbukti NYATA: {MOCK_PROBE_CMD} tidak memuat penanda mock]\n")
        elif not is_mock:
            print(f"BATAL: bot tidak terbukti MINISOAR_MOCK=1 ({MOCK_PROBE_CMD} tidak "
                  f"memuat {MOCK_PROBE_MARKER!r}). Tidak ada command yang dikirim.")
            for t in probe["replies"]:
                print(f"   -> {' '.join((t or '').split())[:150]}")
            await client.disconnect()
            return 1
        else:
            print(f"[mock terverifikasi via {MOCK_PROBE_CMD}]\n")

    if real and not args.cleanup_only:
        print("MODE REAL. Perimeter yang disentuh:")
        for c in cases:
            if c[2] in ("write", "host"):
                print(f"  {c[1]}   -> undo: {c[3]}")
        unver = [k for k in touched_perimeters(cases) if PERIMETER[k][0] is None]
        if unver:
            print("\n  TIDAK AKAN BISA DIVERIFIKASI: " + ", ".join(unver))
            print("  Tidak ada command bot yang membaca blocklist sistem ini,")
            print("  jadi setelah cleanup tetap harus dicek manual.")
        print()

    results = []
    code = 0
    try:
        for handler, cmd, kind, _undo, _perim in cases:
            before = await boundary(client, bot)
            r = await one(client, bot, handler, cmd, kind, before)
            results.append(r)
            print(f"[{r['status']:11s}] {r['elapsed']:5.1f}s  {r['cmd']}")
            for t in r["replies"]:
                head = " ".join((t or "").split())[:150]
                print(f"                 -> {head}")
    finally:
        code = await run_cleanup(client, bot, cases, mode)

    await client.disconnect()
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    json.dump(results, open(f"{ARTIFACT_DIR}/e2e_results-{mode}.json", "w"), indent=1)
    print("\n=== RINGKASAN ===")
    for r in results:
        print(f"  {r['status']:11s} {r['handler']:20s} {r['cmd']}")
    print("\n=== DILEWATI ===")
    for h, c, why in SKIPPED:
        print(f"  {h:22s} {c:22s} {why}")
    if real:
        for c in CASES:
            reason = get_real_skip_reason(c)
            if reason:
                print(f"  {c[0]:22s} {c[1]:22s} {reason}")
            elif c[2] == "host" and not args.allow_host:
                print(f"  {c[0]:22s} {c[1]:22s} kind=host dilewati (butuh --allow-host)")
    else:
        for c in CASES:
            if c[2] == "no_undo":
                print(f"  {c[0]:22s} {c[1]:22s} kind=no_undo (hanya mock)")
        if HOST_ISOLATION_BLOCKED:
            print("  isolate/restore_host 10.0.0.50   DIKUNCI: " + HOST_ISOLATION_REASON)
    # Exit code cuma bermakna di mode real: di mode mock tidak ada perimeter
    # nyata yang perlu dibuktikan, jadi exit 3 bukan kegagalan.
    return code if real else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
