# ⚡ MiniSOAR Official Documentation & Wiki

Selamat datang di **Wiki Resmi MiniSOAR** (*Security Orchestration, Automation, and Response*).

---

## 📚 Daftar Navigasi Dokumentasi (Table of Contents)

| Halaman Wiki | Deskripsi Dokumen |
| :--- | :--- |
| 📖 **[System Overview](Overview)** | Peta kapabilitas 5-Tier, arsitektur modular, dan integrasi enterprise. |
| 🏗️ **[System Architecture](Architecture)** | Aliran siklus hidup event, diagram pipeline, korelasi log, dan orkestrasi playbook. |
| 🧠 **[MLOps & Auto-Retraining](MLOps)** | Alur 7-Step ML lifecycle, evaluasi threshold, pencegahan bias data, dan SecureSphere attack replay. |
| 🗄️ **[Database & Cache](Database)** | Skema indeks Elasticsearch cluster, struktur key Redis, dan TTL audit log. |
| 📡 **[API & Command Reference](API-Reference)** | Referensi lengkap command interaktif Telegram Bot dan CLI `minisoar.sh`. |
| 🚀 **[Production Deployment](Deployment)** | Panduan deployment bare-metal/systemd/container, hardening keamanan, dan rotasi credential. |
| 🧪 **[Testing & Quality Gates](Testing)** | Strategi pengujian unit/integrasi (Pytest), cakupan pengujian, dan CI gates. |
| 🛠️ **[Troubleshooting Runbook](Troubleshooting)** | Prosedur diagnostik insiden umum, pemulihan antrean Redis, dan recovery model ML. |
| 📝 **[Changelog](Changelog)** | Riwayat rilis versi, fitur baru, refactoring, dan perbaikan keamanan. |

---



# ⚡ MiniSOAR Wiki & Dokumentasi Resmi

MiniSOAR adalah purwarupa *Security Orchestration, Automation, and Response* (SOAR) ringan yang didesain khusus untuk mengotomatisasi pemblokiran IP mencurigakan melalui integrasi ELK (Logstash), Telegram Bot, dan *Machine Learning*.

## 📖 1. Penjelasan Sistem (Architecture)

MiniSOAR bekerja dengan cara mendengarkan (berlangganan) pada antrean notifikasi (Redis/Logstash). Saat sebuah anomali web (XSS, SQLi, LFI, RCE) terdeteksi, MiniSOAR akan mengambil alih alur dengan langkah berikut:
1. **Penyaringan (Filtering):** Memeriksa apakah IP penyerang berada dalam *Whitelist* atau *Bypass list*.
2. **Kalkulasi ML (AI Inference):** Mengukur skor probabilitas serangan berdasarkan model historis (akurasi, reputasi, tipe serangan).
3. **Validasi Mode:** Mengeksekusi blokir secara otomatis ke WAF tujuan (Akamai, Imperva, Palo Alto) ATAU melempar keputusan kepada Manusia via tombol persetujuan di Telegram.

---

## 🚀 2. Quick Start (Mulai Cepat)

### Persyaratan Sistem
- Python 3.10+
- Redis Server (untuk *Message Queue*)
- Elasticsearch (opsional, dibutuhkan untuk pelatih ulang ML)
- Telegram Bot Token & Chat ID

### Menjalankan MiniSOAR
1. **Menyalin Konfigurasi:**
   Buat file `.env` (bisa dengan menyalin `env.example` jika ada) dan isi Token Bot Telegram serta IP Redis Anda.
2. **Menjalankan Daemon Utama:**
   Jalankan program *listener* utama yang tidak boleh mati.
   ```powershell
   python 14_redis_telegram_alert.py
   ```
3. **Menguji Notifikasi (Simulasi):**
   Gunakan alat *mock* bawaan untuk menembakkan 30 jenis serangan campuran.
   ```powershell
   python scratch/mock_traffic.py
   ```

---

## ⚙️ 3. Konfigurasi & Mode Operasi

MiniSOAR mengadopsi prinsip operasi keamanan tiga tingkat (`MINISOAR_BLOCKING_MODE` di dalam `.env`):

*   **MANUAL**: Sangat aman. Tidak ada pemblokiran otomatis. Seluruh anomali akan terkirim ke Telegram menunggu tombol "Block" ditekan.
*   **SEMI**: Hibrida. AI akan mengambil alih. Jika skor kepastian AI **> 70%**, IP langsung diblokir (*Auto-Mitigation*). Jika skor meragukan (<70%), bot Telegram akan bertanya kepada Admin.
*   **AUTO**: Sepenuhnya diserahkan ke AI. Seluruh prediksi berbahaya akan di-*drop* di WAF.

### Berkas Konfigurasi Pendukung
- **`minisoar-perimeter.yml`**: Memetakan target mitigasi. Anda dapat merutekan serangan di `api.target.com` ke Imperva, dan `*.target.com` (wildcard) ke Akamai.
- **`minisoar-whitelist.txt`**: IP/CIDR yang dijamin bebas blokir, namun **notifikasinya tetap dikirim**. Admin tidak akan melihat tombol "Block" di Telegram.
- **`minisoar-bypass.txt`**: IP/CIDR mutlak yang diabaikan sepenuhnya (*silent drop*). Notifikasi tidak akan membanjiri Telegram.

---

## 🧠 4. Panduan Machine Learning (Retraining)

Fitur ML di MiniSOAR bertugas mempelajari *behavior* tombol yang diklik oleh Admin di masa lalu (apakah admin lebih sering memblokir SQLi atau justru mengabaikannya). 

Data ini ditarik dari Elasticsearch dan sudah dioptimalkan menggunakan kueri *Bulk Terms* secara massal agar **10.000 log** dapat ditarik secara kilat tanpa masalah latensi HTTP (bebas *N+1 Query Bottleneck*).

### Cara Mentraining Model Baru:
**Langkah 1: Ekstraksi Data (Export)**
Tarik data terbaru dari Elasticsearch. Jika ES mati/kosong, sistem otomatis mencetak 10.000 baris data sintetis. Dataset ini kini sangat detail mencakup *Source/Target IP, Port,* hingga *Domain/URL*.
```powershell
python -m minisoar.ml.export
```
*(Anda akan melihat output pembuatan `dataset.csv`)*

**Langkah 2: Proses Training**
Latih data tersebut. Skrip ini menggunakan *Logistic Regression*, otomatis mengeksekusi *One-Hot Encoding* pada jenis serangan baru, dan mencetak laporan metrik (*Accuracy / ROC-AUC*).
```powershell
python -m minisoar.ml.train
```
*(Hasilnya akan disimpan sebagai `baseline_model.joblib`)*

**Langkah 3: Terapkan ke Otak Daemon**
Daemon utama (Skrip 14) hanya membaca model ke dalam RAM satu kali di awal *(on boot)*. Anda wajib merestart *daemon* tersebut agar menggunakan kepintaran yang baru:
1. Tekan `Ctrl+C` pada *Daemon*.
2. Nyalakan lagi: `python 14_redis_telegram_alert.py`.

---

*Wiki ini dibuat dan dioptimasi oleh AI Assistant (Antigravity).*


---

## 📄 Ringkasan Teknis (Readme)

# MiniSOAR

MiniSOAR adalah platform **Security Orchestration, Automation, and Response** (SOAR) modular enterprise yang menggabungkan deteksi log berkecepatan tinggi, korelasi ancaman berbasis sliding-window, mesin playbook deklaratif, orkestrasi mitigasi multi-perimeter (Palo Alto, Imperva, Akamai, Cloudflare, FortiGate), penahanan endpoint EDR (Kaspersky KSC, TrendMicro Vision One), integrasi ticketing pihak ketiga opsional, serta asisten AI SOC Copilot multi-provider dengan MLOps continuous auto-retraining.

---

## Requirements

- **Runtime:** Python 3.10+ & Java OpenJDK 17 (untuk Logstash)
- **Message Broker & Cache:** Redis 6.x / 7.x
- **Log Telemetry & Database:** Elasticsearch Cluster 8.x
- **Log Processing Pipeline:** Logstash 8.x
- **Notification & Interface:** Telegram Bot API
- **Perimeter & EDR (Sesuai Kebutuhan):** Palo Alto, Imperva, Akamai, Cloudflare, FortiGate, Kaspersky KSC, TrendMicro

---

## Quick Start

### 1. Instalasi Otomatis (Full Automated Setup)
Gunakan script manajemen terpadu `minisoar.sh`:

```bash
# Berikan permission eksekusi
chmod +x minisoar.sh

# Jalankan alur setup menyeluruh (Python -> Logstash -> Config -> Start -> Verify)
./minisoar.sh install-all
```

### 2. Instalasi Manual / Modular
```bash
# 1. Setup virtualenv dan install dependensi Python
./minisoar.sh setup

# 2. Salin dan sesuaikan konfigurasi environment
cp env.example .env
chmod 600 .env

# 3. Instal & sinkronkan pipeline Logstash
./minisoar.sh install-logstash
./minisoar.sh setup-logstash

# 4. Jalankan seluruh layanan di background
./minisoar.sh start all

# 5. Periksa status layanan
./minisoar.sh status
```

---

## Environment Variables

Salin template konfigurasi dari `env.example` ke `.env`:

```bash
cp env.example .env
```

Lihat file [`env.example`](file:///f:/Kantor/Program/MiniSOAR/env.example) untuk panduan konfigurasi lengkap seluruh parameter (Telegram, Redis, Elasticsearch, EDR, Perimeters, AI Copilot, dan 3rd-Party Ticketing).

---

## Project Structure

```text
MiniSOAR/
├── minisoar.sh              # CLI manajemen & deployment utama
├── minisoar/                # Core Python Package
│   ├── ai/                  # Tier 5: Multi-Provider AI SOC Copilot SDK & Auth Resolver
│   ├── cases/               # Tier 3: Case Management, SLA Metrics, & 3rd-Party Ticketing
│   ├── edr/                 # Tier 2: EDR Controllers (Kaspersky KSC & TrendMicro)
│   ├── mitigation/          # Tier 1 & 4: Multi-Perimeter Routers (PA, Imp, Ak, CF, Forti)
│   ├── ml/                  # Tier 5: Fast Inference Engine & MLOps Auto-Retraining
│   ├── playbook/            # Tier 2: YAML Playbook Engine & Safe AST Evaluator
│   ├── playbooks/           # Direktori definisi playbook respon insiden (.yml)
│   ├── bot.py               # Telegram Bot Interface & Interactive Commands
│   ├── config.py            # Environment Loader & Parser
│   ├── correlation.py       # Sliding-Window Correlation & Anti-Alert Storm Throttling
│   ├── daemon.py            # Alert Ingestion Daemon & Event Dispatcher
│   ├── database.py          # Elasticsearch Data Access Layer & Label Storage
│   └── utils.py             # Security Helpers, Whitelist & Reputation Scoring
├── logstash/                # Pipeline Logstash & Template Elasticsearch
│   ├── 01-detection.conf    # Filter normalisasi log & deteksi serangan
│   ├── 02-alert-redis.conf  # Formatting alert & output ke Redis queue
│   └── minisoar_es_template.json
├── docs/                    # Dokumentasi Teknis Lengkap
│   ├── overview.md          # Gambaran umum & peta kemampuan 5-Tier
│   ├── architecture.md      # Arsitektur sistem, aliran data & diagram
│   ├── mlops.md             # Panduan lengkap MLOps, 7-Step Workflow & Attack Replay
│   ├── database.md          # Skema indeks Elasticsearch & namespace Redis
│   ├── api.md               # Referensi command Telegram & CLI minisoar.sh
│   ├── testing.md           # Strategi pengujian & panduan test suite
│   ├── deployment.md        # Panduan deployment produksi & hardening
│   └── troubleshooting.md   # Diagnostik masalah umum & solusinya
├── tests/                   # Automated Pytest Suite (53 unit tests)
├── env.example              # Template variabel lingkungan
└── requirements.txt         # Dependensi Python
```

---

## Running Tests

Jalankan seluruh 53 unit test suite yang mencakup seluruh layer arsitektur:

```bash
# Menggunakan script manajemen
./minisoar.sh test

# Atau menggunakan pytest langsung
pytest --assert=plain -v
```

---

## Documentation

Dokumentasi detail dan mendalam tersedia di folder [`docs/`](file:///f:/Kantor/Program/MiniSOAR/docs/):

- 📖 [Overview & Capability Roadmap](Overview)
- 🏗️ [Architecture & System Flow](Architecture)
- 🗄️ [Database & Redis Key Specifications](Database)
- 📡 [API & Command Reference](API-Reference)
- 🧪 [Testing & Quality Gates](Testing)
- 🚀 [Production Deployment Guide](Deployment)
- 🛠️ [Troubleshooting & Diagnostic Runbook](Troubleshooting)

---

## Contributor

- **SOC Engineering & Security Architecture Team**
- **MiniSOAR Core Development Team**
