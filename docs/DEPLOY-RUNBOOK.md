# PANDUAN OPERASIONAL DEPLOYMENT (RUNBOOK)
## Prosedur & Mitigasi Risiko Rilis MiniSOAR Enterprise (Branch `dev` -> Produksi)

Dokumen ini ditujukan bagi **Operator Sistem / Tim DevOps** yang mengeksekusi pembaruan sistem MiniSOAR di server produksi Linux. Dokumen ini merangkum seluruh potensi bahaya operasional, dependensi jalur berkas, dan perubahan perilaku runtime yang berasal dari serangkaian commit terbaru di branch `dev`. Rincian commit ada di `git log`; dokumen ini sengaja **tidak** mengunci jumlah commit tertentu karena akan cepat basi.

---

## DAFTAR ISI
1. [Syarat Mutlak Pre-Deployment Gate](#1-syarat-mutlak-pre-deployment-gate)
2. [11 Risiko Kritis Produksi & Prosedur Mitigasi](#2-11-risiko-kritis-produksi--prosedur-mitigasi)
   - [Poin 1: Jalur File Whitelist (Paling Kritis)](#poin-1-jalur-file-whitelist-paling-kritis)
   - [Poin 2: Sanitasi Duplikasi Entri Whitelist](#poin-2-sanitasi-duplikasi-entri-whitelist)
   - [Poin 3: Mekanisme Auto-Reload Whitelist pada Daemon](#poin-3-mekanisme-auto-reload-whitelist-pada-daemon)
   - [Poin 4: Penanganan Redis Timeout pada Koneksi & BLPOP](#poin-4-penanganan-redis-timeout-pada-koneksi--blpop)
   - [Poin 5: Pencegahan Proses Ganda / Zombie Polling Telegram](#poin-5-pencegahan-proses-ganda--zombie-polling-telegram)
   - [Poin 6: Definisi & Batasan Cakupan MINISOAR_MOCK](#poin-6-definisi--batasan-cakupan-minisoar_mock)
   - [Poin 7: Lokasi Audit Log Tindakan (tele-soar-actions.log)](#poin-7-lokasi-audit-log-tindakan-tele-soar-actionslog)
   - [Poin 8: Status Model ML (active_model.joblib) - OPEN TODO](#poin-8-status-model-ml-active_modeljoblib---open-todo)
   - [Poin 9: Token Bot Telegram Bocor ke Log (journald) - WAJIB ROTASI](#poin-9-token-bot-telegram-bocor-ke-log-journald---wajib-rotasi)
   - [Poin 10: Command yang Dikirim Saat Bot Mati Dieksekusi Saat Bot Hidup Lagi](#poin-10-command-yang-dikirim-saat-bot-mati-dieksekusi-saat-bot-hidup-lagi)
   - [Poin 11: Jumlah Command di Menu Bot (34 vs 38)](#poin-11-jumlah-command-di-menu-bot-34-vs-38)
3. [Checklist Urutan Eksekusi Deployment (Step-by-Step)](#3-checklist-urutan-eksekusi-deployment-step-by-step)

---

## 1. Syarat Mutlak Pre-Deployment Gate

DILARANG melanjutkan proses deployment ke server produksi jika suite pengujian otomatis belum dinyatakan 100% lulus (hijau).

### Prosedur Pengecekan
Jalankan perintah berikut di lingkungan build/staging server:

```bash
python -m pytest tests -q -m "not e2e"
```

### Kriteria Kelulusan
- **Wajib:** **0 failed, 0 error** pada seluruh suite test non-e2e. Jangan berpatokan pada satu angka eksak (misal 256) karena jumlah pengujian bertambah seiring commit baru di branch `dev`.
- Semua pengujian mock socket dan isolasi jaringan harus lulus tanpa memicu `NetworkAccessDenied`.
- Jika terdapat kegagalan uji (misalnya test WIP yang belum terselesaikan di repo utama), **DILARANG MELAKUKAN DEPLOYMENT** sampai suite dinyatakan 100% hijau.
- Dilarang berasumsi suite sudah hijau tanpa mengeksekusi perintah di atas secara langsung.

---

## 2. 11 Risiko Kritis Produksi & Prosedur Mitigasi

### Poin 1: Jalur File Whitelist (Paling Kritis)

#### Apa yang Terjadi & Risiko
Pada versi terdahulu, worker `daemon.py` membaca berkas whitelist dari jalur relatif kerja (`<cwd>/minisoar-whitelist.txt`), sedangkan bot menulis ke `/etc/logstash/minisoar-whitelist.txt`. 
Mulai commit `0771e41`, fungsi `resolve_whitelist_path()` menyatukan jalur baca dan tulis: di Linux, jika direktori `/etc/logstash` ada dan *writable*, sistem otomatis mengarah ke `/etc/logstash/minisoar-whitelist.txt`.

> [!CAUTION]
> **BAHAYA FALSE POSITIVE / PEMUTUSAN AKSES INFRASTRUKTUR:**
> Berkas `./minisoar-whitelist.txt` di server produksi saat ini memuat **19 entri IP/CIDR infrastruktur nyata** (termasuk segmen gateway `192.168.1.1`, jaringan internal `10.0.0.0/8`, `172.30.*`, dan subnet publik `103.8.76.0/24`). Angka ini hasil hitung pada 2026-09-28; **verifikasi ulang dengan perintah di bawah**, jangan memakai angka ini sebagai acuan tetap karena daftar bisa bertambah. Yang penting: berkas lokal **tidak boleh kosong**. Jika operator melakukan deploy tanpa memindahkan entri ini, daemon akan membaca berkas `/etc/logstash/minisoar-whitelist.txt` yang kosong. Akibatnya, lalu lintas server internal dapat dianggap ancaman dan diblokir otomatis oleh WAF/Firewall!

#### Cara Memeriksa Sebelum Deploy
Jalankan perintah berikut di server produksi:

```bash
# 1. Cek keberadaan kedua berkas (jalur resmi /etc vs jalur lokal)
ls -la /etc/logstash/minisoar-whitelist.txt 2>/dev/null || echo "PERINGATAN: /etc/logstash/minisoar-whitelist.txt BELUM ADA!"
ls -la ./minisoar-whitelist.txt 2>/dev/null || echo "INFO: ./minisoar-whitelist.txt lokal tidak ditemukan."

# 2. Hitung jumlah entri aktif di berkas lokal (harus NON-ZEROL; 19 pada 2026-09-28)
#    Yang wajib dicek adalah berkas ini tidak kosong. Jangan memakai angka tetap.
if [ -f "./minisoar-whitelist.txt" ]; then
    echo -n "Jumlah entri IP aktif lokal: "
    grep -vE '^\s*(#|$)' ./minisoar-whitelist.txt | wc -l
fi
```

#### Tindakan Perbaikan Operator
Lakukan 4 langkah konkret ini sebelum me-restart service bot atau daemon:

```bash
# LANGKAH A: Buat direktori /etc/logstash dan setel kepemilikan user minisoar
sudo mkdir -p /etc/logstash
sudo touch /etc/logstash/minisoar-whitelist.txt
sudo chown -R minisoar:minisoar /etc/logstash
sudo chmod 664 /etc/logstash/minisoar-whitelist.txt

# LANGKAH B: Gabungkan entri dari berkas lokal ke berkas resmi /etc/logstash
if [ -f "./minisoar-whitelist.txt" ]; then
    echo "Menggabungkan entri lokal ke /etc/logstash/minisoar-whitelist.txt..."
    cat ./minisoar-whitelist.txt | sudo tee -a /etc/logstash/minisoar-whitelist.txt > /dev/null
    sort -u /etc/logstash/minisoar-whitelist.txt -o /etc/logstash/minisoar-whitelist.txt
    sudo chown minisoar:minisoar /etc/logstash/minisoar-whitelist.txt
fi

# LANGKAH C: Kunci jalur secara eksplisit di file .env produksi
if grep -q "^WHITELIST_PATH=" .env; then
    sed -i 's|^WHITELIST_PATH=.*|WHITELIST_PATH=/etc/logstash/minisoar-whitelist.txt|' .env
else
    echo "WHITELIST_PATH=/etc/logstash/minisoar-whitelist.txt" >> .env
fi

# LANGKAH D: Verifikasi bahwa file tujuan terisi dan memuat IP internal
echo "--- ISI /etc/logstash/minisoar-whitelist.txt ---"
cat /etc/logstash/minisoar-whitelist.txt
# Verifikasi mata: pastikan 10.0.0.0/8, 192.168.1.1, dan 172.30.* muncul di daftar!
```

---

### Poin 2: Sanitasi Duplikasi Entri Whitelist

#### Apa yang Terjadi & Risiko
Mulai commit `7182817`, perintah `/whitelist_add` di Telegram menolak duplikasi IP meskipun baris memiliki komentar berbeda (`<ip>  # alasan`). Namun, berkas whitelist lama yang sudah terlanjur ada di server masih mungkin memiliki baris duplikat yang dapat membingungkan pembacaan manual operator.

#### Cara Memeriksa Sebelum Deploy
```bash
# Cek apakah ada IP yang muncul lebih dari satu kali
awk -F'#' '{print $1}' /etc/logstash/minisoar-whitelist.txt | tr -d ' ' | grep -v '^$' | sort | uniq -d
```

#### Tindakan Perbaikan Operator
Jika perintah di atas memunculkan output IP duplikat, lakukan perapian berkas:
```bash
# Backup berkas terlebih dahulu
cp /etc/logstash/minisoar-whitelist.txt /etc/logstash/minisoar-whitelist.txt.bak_$(date +%F_%H%M%S)

# Simpan versi bersih dengan mempertahankan satu entri unik per IP
awk -F'#' '!seen[$1]++' /etc/logstash/minisoar-whitelist.txt.bak_* > /etc/logstash/minisoar-whitelist.txt
```

---

### Poin 3: Mekanisme Auto-Reload Whitelist pada Daemon

#### Apa yang Terjadi (Informational)
Mulai pembaruan sesi ini, `minisoar/daemon.py` mengimpor dan memakai fungsi `reload_cidr_list_if_changed` yang defensive-IP-nya berada di `minisoar/utils.py` (baris ~864). Worker memantau metadata berkas (`st_mtime_ns` dan `st_size`). Setiap kali analis menambahkan IP via Telegram (`/whitelist_add`), daemon langsung memuat entri baru tersebut pada event berikutnya tanpa perlu di-restart.

#### Tindakan Operator
- **Operasional Harian:** Operator **TIDAK PERLU** me-restart service `minisoar-daemon` saat analis SOC menambah atau menghapus whitelist via bot Telegram.
- **Saat Deployment Kode:** Service `minisoar-daemon` **TETAP WAJIB** di-restart satu kali agar pembaruan skrip Python aktif di memori:
  ```bash
  sudo systemctl restart minisoar-daemon
  ```

---

### Poin 4: Penanganan Redis Timeout pada Koneksi & BLPOP

#### Apa yang Terjadi & Risiko
Pada commit `05ad34d`, penambahan parameter `socket_timeout=2.0s` pada `database.py:redis_client()` menimbulkan *regresi blocking* pada loop worker `daemon.py:318` (`item = r.blpop(redis_key, timeout=10)`). Karena batas timeout soket client (2 detik) lebih pendek dari timeout tunggu BLPOP (10 detik), daemon mengalami error timeout setiap 2 detik saat antrean sedang kosong (kondisi idle normal), lalu tertidur 5 detik dan menunda proses alert baru.

#### Status Perbaikan
- **Status:** Belum final. Status ini **berlaku sampai ada catatan pembaruan di dokumen ini** — jangan dianggap selesai hanya karena terlihat di commit lama.
- **Yang sudah ada (verifikasi kode 2026-09-28):** `database.py:redis_client()` kini sudah memasang `retry=Retry(NoBackoff(), 1)`, `socket_connect_timeout=5.0s`, dan `health_check_interval=30`. Jadi pernyataan lama bahwa "belum ada mekanisme retry" **tidak lagi akurat** — percobaan ulang sudah terpasang di kode.
- **Yang belum terbukti:** apakah `retry` tersebut benar-benar menyelesaikan kasus BLPOP blocking, dan bagaimana sisi daemon dikonfigurasi. Modul `tests/test_redis_timeouts.py` ada di working tree tetapi **belum di-commit**, jadi perilakunya belum tercakup regresi terverifikasi.
- **Tindakan operator:** DILARANG mengasumsikan perbaikan sudah final. Verifikasi commit log resmi terbaru dan pastikan tes regresi di atas sudah masuk repo sebelum menyatakan aman.

#### Cara Memeriksa Sebelum Deploy
```bash
# 1. Periksa riwayat commit terkait perbaikan timeout Redis
git log -n 5 --grep="timeout" --grep="redis" -i --oneline

# 2. Jalankan pengujian redis timeouts (pastikan lulus 100%, 0 failed)
python -m pytest tests/test_redis_timeouts.py -v
```

#### Verifikasi Pasca-Deploy
Setelah service daemon di-restart, pantau log selama 30 detik:
```bash
sudo journalctl -u minisoar-daemon -n 50 -f
```
*Pastikan TIDAK ADA perulangan pesan:* `Redis loop error: Timeout connecting to server` *saat antrean kosong.*

---

### Poin 5: Pencegahan Proses Ganda / Zombie Polling Telegram

#### Apa yang Terjadi & Risiko
Arsitektur bot Telegram PTB (`python-telegram-bot`) menggunakan *Long Polling* (`getUpdates`). Jika terdapat lebih dari satu instance bot yang berjalan bersamaan dengan token yang sama (misalnya service systemd aktif dan proses manual di tmux/screen tertinggal), kedua proses akan saling berebut paket update.
**Dampak:** Perintah analis di Telegram atau interaksi tombol mitigasi bisa tidak direspons, tertelan, atau memicu respons ganda.

#### Cara Memeriksa Sebelum Deploy
```bash
# Cari semua proses bot Telegram yang sedang berjalan di mesin
pgrep -af "minisoar.bot"
```

#### Tindakan Perbaikan Operator
```bash
# 1. Hentikan service systemd resmi
sudo systemctl stop minisoar-bot

# 2. Periksa kembali apakah masih ada proses orphan/zombie
ZOMBIE_PIDS=$(pgrep -f "minisoar.bot")
if [ -n "$ZOMBIE_PIDS" ]; then
    echo "Menemukan proses zombie PID: $ZOMBIE_PIDS. Mematikan paksa..."
    sudo kill -9 $ZOMBIE_PIDS
fi

# 3. Pastikan output pgrep benar-benar bersih (kosong)
pgrep -af "minisoar.bot" || echo "Bersih: Tidak ada instance bot yang berjalan."
```

---

### Poin 6: Definisi & Batasan Cakupan MINISOAR_MOCK

#### Apa yang Terjadi (Konsep Proteksi)
Variabel lingkungan `MINISOAR_MOCK=1` dirancang khusus untuk memblokir penembakan aksi ke **Perimeter Keamanan Produksi** (Palo Alto Firewall, Imperva WAF, Akamai CDN, FortiGate, EDR Kaspersky/TrendMicro, Elasticsearch write).
**Telegram BUKAN perimeter:** Telegram adalah antarmuka komunikasi bot. Dalam mode mock, bot Telegram **WAJIB TETAP MELAKUKAN POLLING** agar operator dan QA dapat menguji alur perintah secara interaktif tanpa merusak konfigurasi firewall jaringan nyata.

#### Aturan Deployment
- Pada server **PRODUKSI AKTIF (LIVE)**:
  ```bash
  # Pastikan MINISOAR_MOCK dimatikan (0) atau tidak didefinisikan
  grep "MINISOAR_MOCK" .env
  ```
  Nilai harus `MINISOAR_MOCK=0` atau `MINISOAR_MOCK=false`.
- Jangan pernah mematikan loop polling Telegram bot dengan dalih "agar mode mock lebih aman".

---

### Poin 7: Lokasi Audit Log Tindakan (`tele-soar-actions.log`)

#### Apa yang Terjadi & Risiko
Fungsi `log_user_action()` mencatat seluruh tindakan analis (blokir, unblock, commit) ke dalam file log audit JSON. Jika variabel `LOGFILE` tidak didefinisikan di `.env`, log jatuh ke direktori kerja saat ini (`./tele-soar-actions.log`).
Saat eksekusi testing lokal dilakukan, bertambahnya baris di berkas lokal adalah aktivitas pengujian, bukan indikasi pelanggaran keamanan. Cadangan berkas produksi lama telah diamankan di `scratch/tele-soar-actions.log.bak-*`.

#### Cara Memeriksa Sebelum Deploy
```bash
# Pastikan target audit log resmi terkonfigurasi di .env
grep "LOGFILE=" .env || echo "LOGFILE belum disetel di .env"
```

#### Tindakan Perbaikan Operator
Setel target log resmi sistem pada `.env`:
```bash
# Pastikan jalur mengarah ke lokasi log terpusat
grep -q "^LOGFILE=" .env && sed -i 's|^LOGFILE=.*|LOGFILE=/var/log/tele-soar-actions.log|' .env || echo "LOGFILE=/var/log/tele-soar-actions.log" >> .env

# Buat file dan berikan izin tulis untuk user minisoar
sudo touch /var/log/tele-soar-actions.log
sudo chown minisoar:minisoar /var/log/tele-soar-actions.log
sudo chmod 660 /var/log/tele-soar-actions.log
```

---

### Poin 8: Status Model ML (`active_model.joblib`) - OPEN TODO

#### Status Arsitektur
> [!WARNING]
> **STATUS: OPEN TODO (KEPUTUSAN USER MASIH TERBUKA - BELUM FINAL):**
> Arsitektur model machine learning terkait transisi antara model baseline (`baseline_model.joblib`), model penantang (`challenger_model.joblib`), dan penamaan model aktif (`active_model.joblib`) **MASIH BELUM SELESAI DAN BELUM FINAL**. Jangan menganggap subsistem model ML ini telah stabil atau selesai dikerjakan.

#### Tindakan Operator
1. **JANGAN** menjalankan atau mengotomatisasikan cron `minisoar.ml.autotrain` di server produksi sampai ada rilis resmi lanjutan.
2. Ingatkan analis SOC untuk **TIDAK MENGGUNAKAN** perintah Telegram `/retrain_model` (alias `/retrainmodel`, `/rm`) di lingkungan produksi live hingga arsitektur model diverifikasi tuntas.
3. Pastikan berkas model yang digunakan saat ini tetap merujuk pada model stabil yang ada di repositori:
   ```bash
   # PENTING: berkas .joblib berada di ROOT repo, bukan di minisoar/ml/.
   # minisoar/ml/train.py dan autotrain.py menulis ke root_dir.
   ls -la ./*.joblib
   ```
   Yang diharapkan: ada `baseline_model.joblib` (model stabil, sekitar 827 KB pada 2026-09-28). Berkas `.joblib` tidak disimpan di Git (sudah di-`.gitignore`), jadi harus ada salinan di server.

   > **CATATAN PENTING (verifikasi 2026-09-28):** `active_model.joblib` di root repo saat ini **rusak** — ukurannya hanya 2251 byte, bukan ~827 KB, dan isinya sebuah `LogisticRegression` dengan `n_features_in_=9`, sedangkan `baseline_model.joblib` (utuh, 827493 byte) memakai `RandomForestClassifier` dengan `n_features_in_=14`. Jumlah feature tidak cocok, sehingga model aktif **tidak kompatibel** dengan pipeline bot. Aslinya sudah hilang: tidak ada di Git dan tidak ada salinan di disk.
   >
   > **Tindakan operator:** JANGAN mengandalkan `active_model.joblib` yang ada sekarang. Salinkan `baseline_model.joblib` sebagai `active_model.joblib` (sebagai model stabil) sampai retraining yang benar sudah dijalankan, dan **jangan** menjalankan cron autotrain lebih dulu karena itu yang menghasilkan model dengan jumlah feature salah.

---

### Poin 9: Token Bot Telegram Bocor ke Log (journald) - WAJIB ROTASI

#### Apa yang Terjadi & Risiko
Sebelum perbaikan di branch `dev`, bot dan daemon memanggil `logging.basicConfig(level=INFO)`. Logger `httpx` (dipakai python-telegram-bot) lalu mencatat **setiap** request Telegram lengkap dengan URL-nya:
```
INFO:httpx:HTTP Request: POST https://api.telegram.org/bot<TOKEN>/getUpdates "HTTP/1.1 200 OK"
```
Artinya token bot tertulis **plaintext** ke stderr, yang di server produksi masuk ke **journald** (`journalctl -u minisoar-bot`), berkali-kali per menit. Siapa pun yang bisa membaca journal (root, grup `adm`/`systemd-journal`, atau salinan/ekspor log) bisa mengambil token dan mengendalikan bot, termasuk mengirim perintah blokir/isolasi atas nama bot.

Perbaikan kode (commit `e2bbf7a` untuk bot, `ac4a8bb` untuk daemon) menaikkan level `httpx`/`httpcore` ke WARNING dan memasang filter sensor `bot<REDACTED>`. **Perbaikan ini hanya mencegah kebocoran BERIKUTNYA.** Token yang sudah tertulis di journal tetap valid sampai dirotasi.

Kelas bocor kedua yang juga sudah ditutup di kode: API key Gemini di URL `...:generateContent?key=<KEY>` bisa ikut tercetak saat request REST Gemini gagal, baik di log (commit `4ca120f`) maupun di **balasan chat** `/ask_ai`/`/rca` (commit `4c020ca`).

#### Cara Memeriksa (tanpa mencetak rahasia)
```bash
# Hitung saja - JANGAN tampilkan barisnya, karena isinya token.
sudo journalctl -u minisoar-bot -u minisoar-daemon --no-pager | grep -cE 'api\.telegram\.org/bot[0-9]+:'
sudo journalctl -u minisoar-bot -u minisoar-daemon --no-pager | grep -c 'generateContent?key=AI'
```
> Pola `grep` pertama sudah diverifikasi terhadap log bot hasil uji lokal (menemukan 144 baris bertoken dalam satu sesi ~9 menit). Perintah `journalctl` di server produksi **BELUM DIVERIFIKASI** (nama unit `minisoar-bot`/`minisoar-daemon` diambil dari bagian lain runbook ini). Pola kedua (Gemini) **BELUM DIVERIFIKASI** terhadap log nyata.

Angka > 0 berarti rahasia pernah tertulis. Angka 0 **tidak** membuktikan aman bila journal lama sudah terhapus/terotasi: anggap token sudah bocor dan tetap rotasi.

#### Tindakan Perbaikan Operator (WAJIB, setelah kode baru ter-deploy)
1. **Revoke token lama** di @BotFather: buka chat @BotFather → `/mybots` → pilih bot → **API Token** → **Revoke current token**, lalu salin token baru. *(Urutan menu BotFather **BELUM DIVERIFIKASI** di sesi ini; bila tampilannya berbeda, gunakan fitur revoke/regenerate token milik bot yang sama.)*
2. **Ganti di `.env` produksi:** isi token baru ke variabel yang dipakai (`TELEGRAM_TOKEN`, atau `TELEGRAM_BOT` bila itu yang ada; bot membaca `TELEGRAM_TOKEN` lebih dulu). Jangan menempelkannya di chat, tiket, atau riwayat shell.
3. **Restart KEDUA service**, karena daemon juga mengirim alert memakai token yang sama:
   ```bash
   sudo systemctl restart minisoar-daemon minisoar-bot
   ```
4. **Verifikasi log baru tidak memuat `bot<TOKEN>`:** jalankan perintah hitung di atas, catat angkanya, tunggu beberapa menit, lalu jalankan lagi. Angkanya **tidak boleh bertambah**. Pastikan juga bot membalas `/health`.
5. **API key Gemini:** bila hitungan `generateContent?key=` > 0, rotasi key di konsol Google tempat key itu dibuat, lalu perbarui `.env` dan restart. *(Langkah konsol Google **BELUM DIVERIFIKASI**.)*

> **Tegas:** perbaikan kode hanya mencegah kebocoran **berikutnya**. Bila rotasi dilewati, token yang sudah tertulis di journald lama **masih hidup**, dan siapa pun yang bisa membaca journald (root, grup `adm`/`systemd-journal`, ekspor/salinan log) memegang token itu dan bisa mengendalikan bot.

Opsional: menghapus journal lama (`journalctl --vacuum-*`) ikut menghapus **semua** log lama termasuk jejak audit lain; putuskan bersama tim keamanan. Setelah rotasi, token di log lama sudah tidak berguna.

---

### Poin 10: Command yang Dikirim Saat Bot Mati Dieksekusi Saat Bot Hidup Lagi

> [!WARNING]
> **STATUS: KEPUTUSAN USER MENUNGGU.** Bagian ini menjelaskan fakta dan opsi. Belum ada keputusan perilaku mana yang diinginkan, dan kode **belum** diubah.

#### Fakta
- `app.run_polling()` di `minisoar/bot.py` (fungsi `main`) dipanggil **tanpa** `drop_pending_updates`. Saat bot start, python-telegram-bot memproses semua pesan yang tertunda di Telegram selama bot mati.
- **Dibuktikan di uji E2E 2026-09-28:** 17 command yang dikirim saat bot mati (`/unblock_imperva`, `/block_palo`, `/unblock_palo`, `/block_akamai`, `/unblock_akamai`, `/block_cf`, `/unblock_cf`, `/block_forti`, `/unblock_forti`, `/isolate_host`, `/restore_host`, `/add_edr_ioc`, `/commit_palo`, `/whitelist_add`, `/whitelist_remove`, `/activate_akamai`, `/retrainmodel`) dieksekusi **~6 menit kemudian**, begitu bot dinyalakan, tanpa konfirmasi ulang. (Uji itu berjalan dengan `MINISOAR_MOCK=1`, jadi tidak ada aksi nyata.)
- Batas berapa lama Telegram menyimpan pesan tertunda **BELUM DIVERIFIKASI** di sesi ini.

#### Konsekuensi untuk bot SOC
- `/block_palo` yang dikirim analis jam 03.00 saat outage bisa dieksekusi jam 09.00 saat bot dinyalakan lagi, **tanpa operator tahu**, padahal situasinya mungkin sudah berubah (IP sudah tidak relevan, sudah ditangani manual).
- Urutan bisa terputus: `/commit_palo` bisa berjalan tanpa `/block_palo` yang seharusnya menyertainya (misalnya salah satunya dikirim sebelum outage, yang lain saat outage), sehingga commit berisi perubahan yang tidak diharapkan.
- Command dari sesi **uji/mock** (IP uji seperti `203.0.113.88`, `10.0.0.50`) yang masih tertunda akan dieksekusi **sungguhan** bila instance berikutnya start dengan `MINISOAR_MOCK=0`.

#### Opsi & Trade-off (untuk keputusan user)
| Opsi | Keuntungan | Kerugian |
|---|---|---|
| **A. `run_polling(drop_pending_updates=True)`** | Tidak ada command basi yang tereksekusi berjam-jam kemudian. | Command **sah** yang dikirim analis saat downtime **hilang diam-diam**; analis mengira sudah terkirim. |
| **B. Biarkan seperti sekarang** | Tidak ada command yang hilang. | Command bisa tereksekusi berjam-jam kemudian tanpa operator tahu; backlog sesi mock bisa tereksekusi di produksi. |
| **C. Ide (belum ada kode):** tolak/minta konfirmasi untuk command yang umurnya lebih dari N menit | Command lama tidak jalan diam-diam dan tidak hilang tanpa pemberitahuan. | Butuh perubahan kode dan penentuan N; **BELUM DIVERIFIKASI** dan belum dirancang. |

#### Yang bisa dilakukan operator sekarang (tanpa mengubah kode) - BELUM DIVERIFIKASI
Snippet berikut memakai Bot API Telegram standar (`getWebhookInfo`, `deleteWebhook`) dan membaca token dari `.env` tanpa mencetaknya. Keduanya **BELUM DIVERIFIKASI** dijalankan terhadap bot MiniSOAR; uji dulu di bot non-produksi.

Cek jumlah pesan tertunda **sebelum** `systemctl start minisoar-bot`:
```bash
python3 - <<'EOF'
import json, urllib.request
from dotenv import dotenv_values
env = dotenv_values(".env")
t = env.get("TELEGRAM_TOKEN") or env.get("TELEGRAM_BOT")
r = json.load(urllib.request.urlopen(f"https://api.telegram.org/bot{t}/getWebhookInfo", timeout=10))
print("pending_update_count =", r["result"].get("pending_update_count"))
EOF
```
Bila > 0 dan antrean itu memang tidak boleh dieksekusi (misalnya sisa sesi uji/mock), antrean bisa dibuang. Ini setara Opsi A untuk satu kali restart saja, dengan kerugian yang sama: command sah di antrean ikut hilang, jadi konfirmasi dulu ke analis dan minta mereka mengirim ulang yang masih relevan.
```bash
python3 - <<'EOF'
import json, urllib.request
from dotenv import dotenv_values
env = dotenv_values(".env")
t = env.get("TELEGRAM_TOKEN") or env.get("TELEGRAM_BOT")
r = json.load(urllib.request.urlopen(f"https://api.telegram.org/bot{t}/deleteWebhook?drop_pending_updates=true", timeout=10))
print("drop pending:", r.get("ok"))
EOF
```

---

### Poin 11: Jumlah Command di Menu Bot (34 vs 38)

#### Apa yang Terjadi (Informational)
Saat start, bot mengisi menu command Telegram sesuai provider yang terkonfigurasi di `.env` (`post_init` di `minisoar/bot.py`), lalu mencatat:
```
[BOT] Successfully updated Telegram Bot interactive menu with N commands.
```
Rincian N: 7 dasar + Imperva 3 + Palo Alto 4 + Akamai 4 + **Cloudflare 2** + **FortiGate 2** + EDR 5 + 11 case/AI/lainnya = **38** bila semua provider aktif.

Pada 2026-09-28 bot mencatat **34** = 38 − 2 (`/block_cf`, `/unblock_cf`) − 2 (`/block_forti`, `/unblock_forti`), karena kredensial Cloudflare (`CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ZONE_ID`) dan FortiGate (`FORTIGATE_HOST` + `FORTIGATE_API_TOKEN`) tidak diisi di `.env`. Itu **perilaku yang benar**, bukan error.

Catatan untuk operator:
- Yang disembunyikan hanya **menu**. Handler `/block_cf`, `/unblock_cf`, `/block_forti`, `/unblock_forti` tetap terdaftar, jadi bisa diketik manual. Tanpa kredensial, balasannya berupa pesan "not configured"; di mode mock, balasannya sukses bertanda `(Mock)`. Itulah sebabnya uji E2E mock menguji keempatnya walaupun menu hanya berisi 34.
- Menu menganggap provider "terkonfigurasi" bila **salah satu** variabelnya terisi, sedangkan modul mitigasi mensyaratkan **keduanya**. Kalau hanya satu variabel diisi, command muncul di menu tetapi tetap membalas "not configured". Isi **pasangan** variabelnya lengkap atau kosongkan keduanya.
- **FortiGate:** modul membaca `FORTIGATE_API_TOKEN` (sesuai `env.example`), sedangkan pengecekan menu (`get_configured_providers` di `minisoar/config.py`) membaca `FORTIGATE_API_KEY`. Pakai **`FORTIGATE_API_TOKEN`** di `.env`; menu tetap muncul karena `FORTIGATE_HOST` terisi.
- Angka 38 kasus di harness E2E (`scratch/e2e_command_matrix.py`) kebetulan sama dengan 38 command di menu, tetapi dihitung dengan cara berbeda. Jangan dicocokkan satu per satu.

---

## 3. Checklist Urutan Eksekusi Deployment (Step-by-Step)

Operator diwajibkan mengikuti tahapan berikut secara berurutan:

### Langkah 1: Persiapan & Sinkronisasi Repositori
```bash
cd /opt/minisoar   # (sesuaikan direktori instalasi produksi)
git fetch origin
git checkout dev
git pull origin dev
```

### Langkah 2: Verifikasi Kualitas Kode (Pre-Flight Gate)
```bash
source .venv/bin/activate
python -m pytest tests -q -m "not e2e"
# SYARAT MUTLAK: 0 failed, 0 error (seluruh test yang berjalan harus 100% hijau).
# Jika masih ada test yang gagal, DILARANG MELANJUTKAN DEPLOYMENT!
```

### Langkah 3: Migrasi & Sanitasi Berkas Whitelist
```bash
# 1. Pastikan folder /etc/logstash ada dan berizin tepat
sudo mkdir -p /etc/logstash
sudo touch /etc/logstash/minisoar-whitelist.txt
sudo chown -R minisoar:minisoar /etc/logstash
sudo chmod 664 /etc/logstash/minisoar-whitelist.txt

# 2. Gabungkan entri dari ./minisoar-whitelist.txt jika ada
if [ -f "./minisoar-whitelist.txt" ]; then
    cat ./minisoar-whitelist.txt | sudo tee -a /etc/logstash/minisoar-whitelist.txt > /dev/null
    sort -u /etc/logstash/minisoar-whitelist.txt -o /etc/logstash/minisoar-whitelist.txt
    sudo chown minisoar:minisoar /etc/logstash/minisoar-whitelist.txt
fi

# 3. Kunci WHITELIST_PATH di .env
grep -q "^WHITELIST_PATH=" .env && sed -i 's|^WHITELIST_PATH=.*|WHITELIST_PATH=/etc/logstash/minisoar-whitelist.txt|' .env || echo "WHITELIST_PATH=/etc/logstash/minisoar-whitelist.txt" >> .env
```

### Langkah 4: Validasi File Konfigurasi `.env`
Periksa file `.env` produksi dan pastikan variabel-variabel kunci berikut terisi:
```bash
# Cek ketersediaan variabel kritis
grep -E '^(TELEGRAM_TOKEN|TELEGRAM_BOT|ALLOWED_USERS|WHITELIST_PATH|LOGFILE|MINISOAR_MOCK)=' .env
```
*Pastikan:*
- `ALLOWED_USERS` memuat ID Telegram analis yang berhak (format: angka dipisah koma, contoh: `12345678,98765432`).
- `WHITELIST_PATH=/etc/logstash/minisoar-whitelist.txt`
- `LOGFILE=/var/log/tele-soar-actions.log`
- `MINISOAR_MOCK=0`

### Langkah 5: Pembersihan Proses Lama & Restart Services
```bash
# 1. Hentikan service
sudo systemctl stop minisoar-bot minisoar-daemon

# 2. Pastikan tidak ada proses zombie
sudo kill -9 $(pgrep -f "minisoar.bot") 2>/dev/null || true
sudo kill -9 $(pgrep -f "minisoar.daemon") 2>/dev/null || true

# 3. Nyalakan daemon
sudo systemctl start minisoar-daemon

# 3a. SEBELUM start bot: pahami Poin 10. Command yang dikirim selama bot mati
#     akan langsung dieksekusi begitu bot start (keputusan perilaku masih
#     MENUNGGU user). Bila perlu, cek pending_update_count dengan snippet di
#     Poin 10 (BELUM DIVERIFIKASI) dan konfirmasi ke analis SOC.

# 3b. Nyalakan bot
sudo systemctl start minisoar-bot

# 4. Aktifkan auto-start saat reboot
sudo systemctl enable minisoar-bot minisoar-daemon
```

### Langkah 6: Verifikasi Pasca-Deployment (Smoke Check)
1. **Periksa status service systemd:**
   ```bash
   sudo systemctl status minisoar-bot --no-pager
   sudo systemctl status minisoar-daemon --no-pager
   ```
2. **Periksa log inisialisasi bot:**
   ```bash
   sudo journalctl -u minisoar-bot -n 30 --no-pager
   # Pastikan ada pesan: "[BOT] Successfully updated Telegram Bot interactive menu with N commands."
   # (Jumlah N berubah sesuai provider yang dikonfigurasi di .env; 38 adalah nilai
   #  maksimal saat semua provider aktif. Yang wajib dicek hanya pesan ini MUNCUL,
   #  bukan angka spesifik di dalamnya. Tanpa kredensial Cloudflare & FortiGate
   #  nilainya 34 - lihat Poin 11.)
   # Pastikan TIDAK ADA: "TOKEN TELEGRAM DITOLAK" atau "AttributeError"
   ```
3. **Periksa log daemon:**
   ```bash
   sudo journalctl -u minisoar-daemon -n 30 --no-pager
   # Pastikan TIDAK ADA: perulangan "Redis loop error: Timeout connecting to server"
   ```
4. **Verifikasi Interaktif Telegram:**
   - Kirim perintah `/health` dari akun Telegram analis yang terdaftar di `ALLOWED_USERS`.
   - Pastikan bot membalas dengan status kesehatan modul SOAR (Redis, ES, AI).
   - Kirim perintah `/whitelists` dan pastikan daftar entri IP/CIDR tampil lengkap (jumlahnya sesuai isi berkas whitelist di server; 19 pada 2026-09-28 — yang penting tidak kosong).
5. **Pastikan token tidak lagi tertulis ke journal** (lihat Poin 9):
   ```bash
   # Catat angkanya, tunggu beberapa menit bot berjalan, lalu jalankan lagi: angkanya TIDAK BOLEH bertambah.
   sudo journalctl -u minisoar-bot -u minisoar-daemon --no-pager | grep -cE 'api\.telegram\.org/bot[0-9]+:'
   ```

### Langkah 7: Rotasi Kredensial yang Pernah Bocor (WAJIB, sekali)
Setelah Langkah 6 lulus dengan kode baru, jalankan rotasi di **Poin 9**: revoke token bot di @BotFather → ganti di `.env` → restart kedua service → verifikasi log baru tidak memuat `bot<TOKEN>` (dan rotasi API key Gemini bila terdeteksi). Kode baru hanya mencegah kebocoran berikutnya; token yang sudah tertulis di journal tetap berlaku sampai dirotasi.
