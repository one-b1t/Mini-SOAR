# MiniSOAR: Security Orchestration, Automation, and Response

MiniSOAR adalah orkestrator keamanan otomatis ringan berbasis bot Telegram yang digunakan untuk memproses alert anomali, melakukan pengayaan threat intelligence IP penyerang, dan memicu aksi pemblokiran/mitigasi di tingkat perimeter keamanan (Palo Alto, Akamai, dan Imperva).

---

## 1. Konfigurasi Integrasi & Kredensial (.env Template)

Berikut adalah detail konfigurasi dan kredensial penting untuk menjalankan layanan MiniSOAR. Buat berkas `.env` di root direktori dengan template berikut:

```ini
# === Redis Buffer Queue ===
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_KEY=logstash_alert_queue

# === Integrasi Telegram Bot ===
# Token Bot dan Chat ID Utama untuk menerima alert trafik anomali
TELEGRAM_BOT=YOUR_TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID

# (Opsional) Penampung log audit proses (seperti eksekusi blokir/unblokir).
# Kosongkan jika ingin menyatukan notifikasi trafik dan proses ke chat utama!
TELEGRAM_PROCESS_CHAT_ID=YOUR_TELEGRAM_PROCESS_CHAT_ID

# === Threat Intelligence API ===
ABUSEIPDB_API_KEY=YOUR_ABUSEIPDB_API_KEY
ABUSEIPDB_CACHE_TTL=21600
IPAPI_CACHE_TTL=43200
LOOKUP_TIMEOUT=4

# === Elasticsearch Cluster ===
ES_HOSTS=https://YOUR_ELASTICSEARCH_HOST:9200
ES_USER=YOUR_ES_USER
ES_PASS=YOUR_ES_PASS
ES_VERIFY=false
ES_EVENTS_INDEX_PREFIX=minisoar-events
ES_LABELS_INDEX_PREFIX=minisoar-labels
ES_TIMEOUT=6
MINISOAR_EVENT_WINDOW=60

# === Mode Simulasi & Pengujian ===
# Set ke 1 untuk menyimulasikan pemblokiran (mencegah pemanggilan API riil ke Palo Alto/Akamai/Imperva)
MINISOAR_MOCK=1

# === Mode Keputusan Pemblokiran (AUTO / SEMI / MANUAL) ===
# AUTO  : AI otomatis memblokir IP berbahaya (tanpa tombol tindakan di bot)
# SEMI  : AI menyajikan rekomendasi (Block/Allow), operator tetap memilih secara manual
# MANUAL: Tanpa saran keputusan aktif (default, tombol tindakan klasik)
MINISOAR_BLOCKING_MODE=AUTO
```

---

## 2. Fitur Utama & Keunggulan Sistem

1. **Resolusi Path Otomatis (Cross-platform):** Skrip secara otomatis mendeteksi OS. Jika berjalan di Windows Host, seluruh berkas bypass (`minisoar-bypass.txt`), perimeter map (`minisoar-perimeter.yml`), log audit, dan log unmapped dialihkan secara otomatis ke direktori proyek lokal tanpa memicu error OS (`WinError 3`).
2. **Penyelamatan Pemuatan Env:** Fallback `override=True` otomatis diaktifkan untuk `.env` jika terdeteksi variabel Telegram bernilai kosong di system env.
3. **Pemisahan Log Proses asinkron:** Menyediakan dual-chat ID untuk memisahkan saluran alert trafik dari log proses tindakan analis, yang dikirimkan secara asinkron menggunakan asyncio task tanpa memblokir thread eksekusi utama.
4. **Mock Mode Staging:** Fitur sandboxing `MINISOAR_MOCK=1` menyimulasikan pemanggilan API perimeter demi keamanan pengujian lokal.
5. **Shutdown KeyboardInterrupt Anggun:** Menangani interupsi terminal (`Ctrl+C`) secara bersih untuk mencegah cetakan traceback error yang mengotori konsol.

---

## 3. Instalasi & Dependensi

Layanan ini dibangun menggunakan Python 3. Instal semua pustaka dependensi yang dibutuhkan sebelum menjalankan script:

```bash
pip install redis requests xmltodict python-telegram-bot edgegrid-python pyyaml pandas scikit-learn joblib python-dotenv
```

---

## 4. Menjalankan Layanan

MiniSOAR terdiri dari dua modul Python utama yang berjalan terus-menerus sebagai background daemon:

1. **Modul Pengambil Alert & Notifikasi (Ingestion & Enrichment):**
   ```bash
   python -m minisoar.daemon
   ```
2. **Modul Interaksi & Bot Handler (Mitigation & Decision Bot):**
   ```bash
   python -m minisoar.bot
   ```

---

## 5. Daftar Perintah Bot Telegram

Gunakan perintah-perintah berikut di dalam ruang obrolan Telegram Bot untuk kontrol manual:

| Perintah | Deskripsi | Platform |
| :--- | :--- | :--- |
| `/help` | Menampilkan pesan bantuan dan ringkasan perintah. | Bot |
| `/blockonimperva <ip>` | Memasukkan IP ke daftar blokir Imperva. | Imperva |
| `/unblockonimperva <ip>`| Menghapus IP dari daftar blokir Imperva. | Imperva |
| `/blocklistimperva` | Menampilkan halaman IP yang diblokir di Imperva. | Imperva |
| `/tracev <event_id>` | Melakukan tracing violation di Imperva. | Imperva |
| `/blockonpalo <ip>` | Memasukkan IP ke grup alamat Palo Alto. | Palo Alto |
| `/unblockonpalo <ip>` | Menghapus IP dari grup alamat Palo Alto. | Palo Alto |
| `/commitpalo` | Melakukan partial commit untuk mengaktifkan perubahan. | Palo Alto |
| `/blockonakamai <ip>` | Menambah IP ke Akamai Client List. | Akamai |
| `/unblockonakamai <ip>`| Menghapus IP dari Akamai Client List. | Akamai |
| `/blocklistakamai` | Menampilkan halaman IP yang diblokir di Akamai. | Akamai |
| `/activateakamai` | Mengaktivasi konfigurasi Akamai ke STAGING & PRODUCTION. | Akamai |
| `/activationstatus <id>`| Mengecek status aktivasi EdgeGrid Akamai. | Akamai |

---

## 6. Pengujian & Mock Traffic

Untuk menyimulasikan data log dari Logstash dan menguji kapabilitas respons MiniSOAR secara _end-to-end_, Anda dapat menyuntikkan _mock payload_ langsung ke antrean Redis. Jalankan perintah Python _one-liner_ berikut di terminal Windows/PowerShell Anda saat kedua daemon sedang berjalan:

```bash
python -c "import redis, json, datetime; r = redis.StrictRedis(host='127.0.0.1', port=6379); payload = {'alert': {'type': 'alert_webshell_immediate', 'server_name': 'mock-target.com', 'src_ip': '8.8.8.8', 'method': 'POST', 'url': '/api/upload.php', 'status': '200', 'severity': 'high'}, 'tags': ['alert_webshell_immediate'], '@timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()}; r.lpush('logstash_alert_queue', json.dumps(payload)); print('Mock traffic berhasil dikirim ke Redis!')"
```

Pastikan Anda telah mengaktifkan mode _mock_ (`MINISOAR_MOCK=1` pada `.env`) jika Anda ingin menguji integrasi pemblokiran perimeter tanpa benar-benar mengeksekusi *API Call* riil.
