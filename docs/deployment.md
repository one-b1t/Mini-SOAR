# MiniSOAR Production Deployment Guide

## 1. Persyaratan Sistem & Hardware

### A. Kebutuhan Minimum
- **Sistem Operasi:** Linux (Ubuntu 22.04 LTS / Debian 12 / Rocky Linux 9 / RHEL 9)
- **CPU:** 4 Core vCPU
- **RAM:** 8 GB (16 GB disarankan jika Logstash & Redis berada di host yang sama)
- **Storage:** 50 GB SSD (disesuaikan dengan volume log)
- **Runtime:** Python 3.10+, Java OpenJDK 17 (untuk Logstash)

### B. Dependensi Layanan Eksternal
- **Redis Server 6.x / 7.x:** Sebagai message broker antrian alert & sliding-window cache.
- **Elasticsearch Cluster 8.x:** Sebagai penyimpanan event telemetri dan log insiden.
- **Logstash 8.x:** Sebagai parser dan normalizer aliran log.

---

## 2. Alur Deployment Cepat (Quick Production Deploy)

```bash
# 1. Clone repositori ke server produksi
git clone <repo_url> /opt/minisoar
cd /opt/minisoar

# 2. Berikan hak akses eksekusi pada script manajemen
chmod +x minisoar.sh

# 3. Jalankan alur instalasi otomatis penuh
./minisoar.sh install-all
```

Script di atas akan secara otomatis:
1. Membangun virtual environment Python (`.venv`) dan menginstal paket di `requirements.txt`.
2. Menginstal package Logstash dan dependensi Java 17 via APT / YUM.
3. Menyalin konfigurasi pipeline `01-detection.conf` dan `02-alert-redis.conf` ke `/etc/logstash/conf.d/`.
4. Mengaktifkan dan me-restart service Logstash.
5. Menjalankan MiniSOAR Daemon dan Telegram Bot.

---

## 3. Konfigurasi Lingkungan Produksi (`.env`)

Salin template `env.example` ke `.env` dan lengkapi variabel yang sesuai:

```bash
cp env.example .env
chmod 600 .env
```

Pastikan variabel kritis berikut telah diisi:
- `TELEGRAM_BOT_TOKEN` & `ALLOWED_USER_IDS`
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
- `ES_HOSTS`, `ES_USER`, `ES_PASS`
- Kredensial Perimeter (Palo Alto, Imperva, Akamai, Cloudflare, FortiGate)
- Kredensial EDR (Kaspersky KSC, TrendMicro Vision One)
- Kredensial AI Copilot (Gemini, Claude, OpenAI, Ollama)
- `MINISOAR_MOCK=0` (Nonaktifkan mode simulasi saat di produksi)

---

## 4. Setup Service Systemd (Linux Auto-Start on Boot)

Untuk memastikan daemon dan bot berjalan otomatis saat server restart:

```bash
# 1. Generate file unit service
./minisoar.sh systemd

# 2. Salin file unit ke direktori systemd
sudo cp logs/minisoar-*.service /etc/systemd/system/

# 3. Reload daemon dan aktifkan service
sudo systemctl daemon-reload
sudo systemctl enable --now minisoar-daemon.service
sudo systemctl enable --now minisoar-bot.service

# 4. Periksa status service
sudo systemctl status minisoar-daemon minisoar-bot
```

---

## 5. Keamanan & Hardening

1. **Hak Akses Kredensial:** Pastikan file `.env` dan berkas autentikasi AI (`AI_AUTH_FILE`, `GEMINI_AUTH_FILE`, dll) memiliki permission ketat:
   ```bash
   chmod 600 .env
   chmod 600 /path/to/credentials/*.json
   ```
2. **Firewall / Network ACL:**
   - Batasi akses port Redis (`6379`) hanya dari `127.0.0.1` atau IP internal daemon.
   - Pastikan server dapat melakukan koneksi HTTPS keluar (*outbound*) ke endpoint API Telegram (`api.telegram.org:443`), perimeter WAF/Firewall, dan EDR servers.
3. **Audit Log:** Seluruh tindakan mitigasi dicatat di `tele-soar-actions.log` dan dapat diekspor ke SIEM eksternal.
