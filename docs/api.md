# MiniSOAR API & Command Reference

## 1. Telegram Bot Command Reference

MiniSOAR Telegram Bot menyediakan antarmuka interaktif yang aman untuk analis SOC. Hanya pengguna yang terdaftar pada variabel `ALLOWED_USER_IDS` di `.env` yang dapat mengeksekusi aksi mitigasi.

### A. Investigasi & Mitigasi Perimeter

| Command | Argumen | Deskripsi |
| :--- | :--- | :--- |
| `/block` | `<ip> [alasan]` | Memblokir IP pada semua perimeter yang terkonfigurasi (Palo Alto, Imperva, Akamai, Cloudflare, FortiGate). |
| `/unblock` | `<ip>` | Membuka blokir IP dari semua perimeter. |
| `/blockoncf` | `<ip> [alasan]` | Memblokir IP spesifik pada Cloudflare Edge WAF. |
| `/unblockoncf` | `<ip>` | Membuka blokir IP spesifik pada Cloudflare Edge WAF. |
| `/blockonforti` | `<ip> [alasan]` | Memblokir IP spesifik pada firewall Fortinet FortiGate. |
| `/unblockonforti` | `<ip>` | Membuka blokir IP spesifik pada firewall Fortinet FortiGate. |
| `/status` | `<ip>` | Memeriksa status blokir, reputation score, dan riwayat alert IP. |
| `/commit` | - | Melakukan commit manual konfigurasi policy pada firewall Palo Alto. |

---

### B. Endpoint Detection & Response (EDR)

| Command | Argumen | Deskripsi |
| :--- | :--- | :--- |
| `/isolatehost` | `<ip_or_host_id> [provider]` | Mengisolasi endpoint terinfeksi pada Kaspersky KSC atau TrendMicro Vision One. |
| `/restorehost` | `<ip_or_host_id> [provider]` | Memulihkan konektivitas jaringan endpoint yang terisolasi. |
| `/queryhost` | `<ip_or_host_id> [provider]` | Menampilkan detail status kesehatan dan versi agen EDR pada endpoint. |
| `/addedrioc` | `<type> <value> [desc]` | Mendaftarkan IoC baru (IP, MD5, SHA256) ke repository EDR. |
| `/edrstatus` | - | Menampilkan diagnostik konektivitas ke server KSC dan TrendMicro. |

---

### C. Case Management & 3rd-Party Ticketing

| Command | Argumen | Deskripsi |
| :--- | :--- | :--- |
| `/cases` | `[limit]` | Menampilkan daftar insiden aktif yang sedang ditangani. |
| `/case` | `<case_id>` | Menampilkan detail investigasi insiden, timeline audit, dan SLA timer. |
| `/updatecase` | `<case_id> <status>` | Memperbarui status kasus (`INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`). |
| `/syncticket` | `<case_id>` | Mengekspor/sinkronisasi insiden ke ticketing pihak ke-3 (TheHive, Jira, ServiceNow, Webhook). |
| `/socmetrics` | - | Menampilkan statistik metrik SOC: MTTD, MTTR, jumlah insiden aktif, dan kepatuhan SLA. |
| `/exportcase` | `<case_id> [md\|html]` | Mengunduh laporan investigasi kasus dalam format Markdown atau Standalone HTML. |

---

### D. AI SOC Copilot & MLOps

| Command | Argumen | Deskripsi |
| :--- | :--- | :--- |
| `/askai` | `<pertanyaan>` | Mengajukan pertanyaan analisis ancaman ke AI SOC Copilot (Gemini, Claude, OpenAI, Ollama). |
| `/rca` | `<event_id_or_ip>` | Menghasilkan Root Cause Analysis (RCA) lengkap berbasis riwayat log. |
| `/retrainmodel` | - | Memicu training model Challenger secara on-demand dan memverifikasi skor ROC-AUC. |

---

## 2. CLI Management Commands (`minisoar.sh`)

| Perintah | Fungsi |
| :--- | :--- |
| `./minisoar.sh install-all` | Menjalankan seluruh alur setup dari awal (Python + Logstash + Config + Start + Verify). |
| `./minisoar.sh check-elk` | Diagnostik koneksi cluster Elasticsearch, cluster health, node, dan indeks. |
| `./minisoar.sh check-redis` | Menguji koneksi Redis, memori, dan panjang antrian alert (`LLEN logstash_alert_queue`). |
| `./minisoar.sh doctor` | Diagnostik konektivitas menyeluruh ke seluruh perimeter, EDR, AI, dan database. |
| `./minisoar.sh start [all\|daemon\|bot]` | Menjalankan service MiniSOAR di background dengan manajemen PID. |
| `./minisoar.sh stop [all\|daemon\|bot]` | Menghentikan service secara anggun (*graceful termination*). |
| `./minisoar.sh restart` | Me-restart seluruh service MiniSOAR. |
| `./minisoar.sh status` | Menampilkan tabel status live service dan unit systemd. |
| `./minisoar.sh logs [daemon\|bot\|actions]` | Streaming log secara real-time. |
| `./minisoar.sh test` | Menjalankan seluruh unit test suite pytest. |
| `./minisoar.sh retrain` | Menjalankan auto-retraining model Challenger MLOps. |
| `./minisoar.sh systemd` | Membuat file unit service Linux (`/etc/systemd/system/minisoar-*.service`). |
| `./minisoar.sh clean` | Membersihkan cache Python dan file temporer. |
