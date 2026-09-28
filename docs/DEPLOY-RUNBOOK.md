# PANDUAN OPERASIONAL DEPLOYMENT (RUNBOOK)
## Prosedur & Mitigasi Risiko Rilis MiniSOAR Enterprise (Branch `dev` -> Produksi)

Dokumen ini ditujukan bagi **Operator Sistem / Tim DevOps** yang mengeksekusi pembaruan sistem MiniSOAR di server produksi Linux. Dokumen ini merangkum seluruh potensi bahaya operasional, dependensi jalur berkas, dan perubahan perilaku runtime yang berasal dari 11 commit terakhir di branch `dev`.

---

## DAFTAR ISI
1. [Syarat Mutlak Pre-Deployment Gate](#1-syarat-mutlak-pre-deployment-gate)
2. [8 Risiko Kritis Produksi & Prosedur Mitigasi](#2-8-risiko-kritis-produksi--prosedur-mitigasi)
   - [Poin 1: Jalur File Whitelist (Paling Kritis)](#poin-1-jalur-file-whitelist-paling-kritis)
   - [Poin 2: Sanitasi Duplikasi Entri Whitelist](#poin-2-sanitasi-duplikasi-entri-whitelist)
   - [Poin 3: Mekanisme Auto-Reload Whitelist pada Daemon](#poin-3-mekanisme-auto-reload-whitelist-pada-daemon)
   - [Poin 4: Penanganan Redis Timeout pada Koneksi & BLPOP](#poin-4-penanganan-redis-timeout-pada-koneksi--blpop)
   - [Poin 5: Pencegahan Proses Ganda / Zombie Polling Telegram](#poin-5-pencegahan-proses-ganda--zombie-polling-telegram)
   - [Poin 6: Definisi & Batasan Cakupan MINISOAR_MOCK](#poin-6-definisi--batasan-cakupan-minisoar_mock)
   - [Poin 7: Lokasi Audit Log Tindakan (tele-soar-actions.log)](#poin-7-lokasi-audit-log-tindakan-tele-soar-actionslog)
   - [Poin 8: Status Model ML (active_model.joblib) - OPEN TODO](#poin-8-status-model-ml-active_modeljoblib---open-todo)
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

## 2. 8 Risiko Kritis Produksi & Prosedur Mitigasi

### Poin 1: Jalur File Whitelist (Paling Kritis)

#### Apa yang Terjadi & Risiko
Pada versi terdahulu, worker `daemon.py` membaca berkas whitelist dari jalur relatif kerja (`<cwd>/minisoar-whitelist.txt`), sedangkan bot menulis ke `/etc/logstash/minisoar-whitelist.txt`. 
Mulai commit `0771e41`, fungsi `resolve_whitelist_path()` menyatukan jalur baca dan tulis: di Linux, jika direktori `/etc/logstash` ada dan *writable*, sistem otomatis mengarah ke `/etc/logstash/minisoar-whitelist.txt`.

> [!CAUTION]
> **BAHAYA FALSE POSITIVE / PEMUTUSAN AKSES INFRASTRUKTUR:**
> Berkas `./minisoar-whitelist.txt` di server produksi saat ini memuat **20 entri IP/CIDR infrastruktur nyata** (termasuk segmen gateway `192.168.1.1`, jaringan internal `10.0.0.0/8`, `172.30.*`, dan subnet publik `103.8.76.0/24`). Jika operator melakukan deploy tanpa memindahkan entri ini, daemon akan membaca berkas `/etc/logstash/minisoar-whitelist.txt` yang kosong. Akibatnya, lalu lintas server internal dapat dianggap ancaman dan diblokir otomatis oleh WAF/Firewall!

#### Cara Memeriksa Sebelum Deploy
Jalankan perintah berikut di server produksi:

```bash
# 1. Cek keberadaan kedua berkas (jalur resmi /etc vs jalur lokal)
ls -la /etc/logstash/minisoar-whitelist.txt 2>/dev/null || echo "PERINGATAN: /etc/logstash/minisoar-whitelist.txt BELUM ADA!"
ls -la ./minisoar-whitelist.txt 2>/dev/null || echo "INFO: ./minisoar-whitelist.txt lokal tidak ditemukan."

# 2. Hitung jumlah entri aktif di berkas lokal (harus ada ~20 entri IP/CIDR produksi)
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
Mulai pembaruan sesi ini, worker `daemon.py` dilengkapi fungsi `reload_cidr_list_if_changed`. Worker memantau metadata berkas (`st_mtime_ns` dan `st_size`). Setiap kali analis menambahkan IP via Telegram (`/whitelist_add`), daemon langsung memuat entri baru tersebut pada event berikutnya tanpa perlu di-restart.

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
- **Status Perbaikan:** Perubahan sudah masuk, baca commit-nya.
- **Catatan Operasional:** Solusi pemisahan timeout untuk operasi blocking (`blpop`) vs connect timeout saat ini sedang difinalisasi di branch `dev`. Operator **DILARANG** mengasumsikan detail implementasi internal tanpa memverifikasi commit log resmi terbaru.

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
2. Ingatkan analis SOC untuk **TIDAK MENGGUNAKAN** perintah Telegram `/retrain_model` di lingkungan produksi live hingga arsitektur model diverifikasi tuntas.
3. Pastikan berkas model yang digunakan saat ini tetap merujuk pada model stabil yang ada di repositori:
   ```bash
   ls -la minisoar/ml/*.joblib
   ```

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

# 3. Nyalakan service kembali
sudo systemctl start minisoar-daemon
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
   # Pastikan ada pesan: "[BOT] Successfully updated Telegram Bot interactive menu with 34 commands."
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
   - Kirim perintah `/whitelists` dan pastikan daftar 20 entri IP/CIDR tampil lengkap.
