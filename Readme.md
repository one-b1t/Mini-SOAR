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
│   ├── database.md          # Skema indeks Elasticsearch & namespace Redis
│   ├── api.md               # Referensi command Telegram & CLI minisoar.sh
│   ├── testing.md           # Strategi pengujian & panduan test suite
│   ├── deployment.md        # Panduan deployment produksi & hardening
│   └── troubleshooting.md   # Diagnostik masalah umum & solusinya
├── tests/                   # Automated Pytest Suite (37 unit tests)
├── env.example              # Template variabel lingkungan
└── requirements.txt         # Dependensi Python
```

---

## Running Tests

Jalankan seluruh 37 unit test suite yang mencakup seluruh layer arsitektur:

```bash
# Menggunakan script manajemen
./minisoar.sh test

# Atau menggunakan pytest langsung
pytest --assert=plain -v
```

---

## Documentation

Dokumentasi detail dan mendalam tersedia di folder [`docs/`](file:///f:/Kantor/Program/MiniSOAR/docs/):

- 📖 [Overview & Capability Roadmap](file:///f:/Kantor/Program/MiniSOAR/docs/overview.md)
- 🏗️ [Architecture & System Flow](file:///f:/Kantor/Program/MiniSOAR/docs/architecture.md)
- 🗄️ [Database & Redis Key Specifications](file:///f:/Kantor/Program/MiniSOAR/docs/database.md)
- 📡 [API & Command Reference](file:///f:/Kantor/Program/MiniSOAR/docs/api.md)
- 🧪 [Testing & Quality Gates](file:///f:/Kantor/Program/MiniSOAR/docs/testing.md)
- 🚀 [Production Deployment Guide](file:///f:/Kantor/Program/MiniSOAR/docs/deployment.md)
- 🛠️ [Troubleshooting & Diagnostic Runbook](file:///f:/Kantor/Program/MiniSOAR/docs/troubleshooting.md)

---

## Contributor

- **SOC Engineering & Security Architecture Team**
- **MiniSOAR Core Development Team**
