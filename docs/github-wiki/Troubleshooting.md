# MiniSOAR Troubleshooting & Diagnostic Guide

## 1. Alat Diagnostik Cepat

Gunakan perintah bawaan pada `minisoar.sh` sebagai langkah pertama investigasi masalah:

```bash
# Diagnostik konektivitas seluruh komponen
./minisoar.sh doctor

# Cek status kesehatan cluster Elasticsearch
./minisoar.sh check-elk

# Cek antrian alert Redis yang tertahan
./minisoar.sh check-redis

# Pantau log stream secara real-time
./minisoar.sh logs
```

---

## 2. Masalah Umum & Solusi (Common Issues & Solutions)

### A. Antrian Redis Menumpuk (Queue Backpressure / Lag)
- **Gejala:** Panjang antrian pada `LLEN logstash_alert_queue` terus meningkat dan notifikasi Telegram terlambat.
- **Penyebab:**
  1. Daemon MiniSOAR terhenti atau mengalami error fatal.
  2. Latensi timeout ke salah satu API perimeter/EDR eksternal.
- **Solusi:**
  ```bash
  # Periksa status proses
  ./minisoar.sh status

  # Periksa log error daemon
  tail -n 100 logs/daemon.log

  # Restart daemon
  ./minisoar.sh restart daemon
  ```

---

### B. Gagal Terhubung ke Elasticsearch (ELK Connection Error / Timeout)
- **Gejala:** `[FAIL] Gagal menghubungi node https://...: SSL certificate verify failed` atau `Connection refused`.
- **Penyebab:**
  1. Sertifikat self-signed pada cluster Elasticsearch ditolak.
  2. Kredensial `ES_USER` / `ES_PASS` salah.
- **Solusi:**
  - Jika menggunakan self-signed certificate, set `ES_VERIFY=0` atau `ES_VERIFY=no` di file `.env`.
  - Jalankan `./minisoar.sh check-elk` untuk memvalidasi ulang respons node.

---

### C. Logstash Gagal Memulai atau Error Pipeline
- **Gejala:** `systemctl status logstash` menunjukkan status `failed` atau `exited`.
- **Penyebab:** Kesalahan sintaks pada file `.conf` atau konflik binding port input.
- **Solusi:**
  ```bash
  # Uji validasi sintaks secara manual
  sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

  # Lihat log detail Logstash
  sudo journalctl -u logstash -n 50 --no-pager
  ```

---

### D. Kesalahan Autentikasi EDR (Kaspersky KSC / TrendMicro)
- **Gejala:** Error `KSC Error: StartSession failed` atau `TrendMicro API Error: 401 Unauthorized`.
- **Penyebab:**
  1. KSC API Gateway belum diaktifkan pada port 13299.
  2. API Key TrendMicro Vision One kedaluwarsa atau tidak memiliki role *Mitigation*.
  3. Format `KSC_VERIFY_SSL` tidak sesuai.
- **Solusi:**
  - Pastikan `KSC_VERIFY_SSL=no` jika menggunakan sertifikat internal KSC.
  - Jalankan `./minisoar.sh doctor` untuk melihat diagnosa EDR layer.

---

### E. Telegram Bot Tidak Merespons Command
- **Gejala:** Bot tidak membalas pesan `/status`, `/cases`, atau `/block`.
- **Penyebab:**
  1. User ID Telegram Anda belum terdaftar di `ALLOWED_USER_IDS`.
  2. Token `TELEGRAM_BOT_TOKEN` salah atau koneksi ke `api.telegram.org` terblokir firewall.
- **Solusi:**
  - Dapatkan Telegram ID Anda via `@userinfobot`, lalu tambahkan ke `.env`:
    ```env
    ALLOWED_USER_IDS=123456789,987654321
    ```
  - Restart bot: `./minisoar.sh restart bot`.
