# MiniSOAR API & Command Reference

## 1. Telegram Bot Command Reference

MiniSOAR Telegram Bot menyediakan antarmuka interaktif yang aman untuk analis SOC. Hanya pengguna yang terdaftar pada variabel `ALLOWED_USER_IDS` di `.env` yang dapat mengeksekusi aksi mitigasi.

### A. Threat Intel & System Diagnostics

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/intel` | `/lookup`, `/ip` | `<ip>` | Ringkasan kartu intelijen IP (Whitelist, ES hit count, event terbaru, host EDR). |
| `/health` | `/soar_status`, `/hp` | - | Dashboard diagnostik real-time Redis, Elasticsearch, EDR, dan AI Copilot. |

---

### B. Whitelist Management

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/whitelist_add` | `/wa` | `<ip/cidr> [alasan]` | Menambahkan IP/CIDR ke daftar `minisoar-whitelist.txt` secara live. |
| `/whitelist_remove` | `/wr` | `<ip/cidr>` | Menghapus IP/CIDR dari daftar whitelist. |
| `/whitelists` | `/wl` | - | Menampilkan daftar seluruh IP/CIDR whitelist aktif. |

---

### C. Investigasi & Mitigasi Perimeter

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/block_imperva` | `/bi` | `<ip>` | Memblokir IP pada Imperva WAF. |
| `/unblock_imperva` | `/ubi` | `<ip>` | Membuka blokir IP pada Imperva WAF. |
| `/trace_imperva` | `/ti` | `<event_id> [days]` | Trace violation log Imperva berdasarkan Event ID. |
| `/block_palo` | `/bp` | `<ip>` | Menambahkan IP ke dynamic block group Palo Alto. |
| `/unblock_palo` | `/ubp` | `<ip>` | Menghapus IP dari dynamic block group Palo Alto. |
| `/commit_palo` | `/cp` | - | Partial commit konfigurasi pada firewall Palo Alto. |
| `/trace_palo` | `/tp` | `<threat_id>` | Trace threat log Palo Alto berdasarkan threat ID, session, atau IP. |
| `/block_akamai` | `/ba` | `<ip>` | Menambahkan IP ke Client List Akamai. |
| `/unblock_akamai` | `/uba` | `<ip>` | Menghapus IP dari Client List Akamai. |
| `/activate_akamai` | `/aa` | - | Mengaktivasi daftar IP pada jaringan Staging & Production Akamai. |
| `/trace_akamai` | `/ta` | `<event_id>` | Trace SIEM security event Akamai berdasarkan Event ID. |
| `/block_cf` | `/bcf` | `<ip>` | Memblokir IP spesifik pada Cloudflare Edge WAF. |
| `/unblock_cf` | `/ubcf` | `<ip>` | Membuka blokir IP spesifik pada Cloudflare Edge WAF. |
| `/block_forti` | `/bforti` | `<ip>` | Memblokir IP spesifik pada firewall Fortinet FortiGate. |
| `/unblock_forti` | `/ubforti` | `<ip>` | Membuka blokir IP spesifik pada firewall Fortinet FortiGate. |

---

### B. Endpoint Detection & Response (EDR)

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/isolate_host` | `/ih` | `<ip_or_host_id> [provider]` | Mengisolasi endpoint terinfeksi pada Kaspersky KSC atau TrendMicro Vision One. |
| `/restore_host` | `/rh` | `<ip_or_host_id> [provider]` | Memulihkan konektivitas jaringan endpoint yang terisolasi. |
| `/query_host` | `/qh` | `<ip>` | Menampilkan detail inventory dan status kesehatan endpoint EDR. |
| `/add_edr_ioc` | `/aei` | `<ioc_value> [provider]` | Mendaftarkan IoC baru (IP, SHA256, Domain) ke repository EDR. |
| `/edr_status` | `/es` | - | Menampilkan diagnostik konektivitas server KSC dan TrendMicro. |

---

### C. Case Management & 3rd-Party Ticketing

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/cases` | `/cs` | `[status]` | Menampilkan daftar insiden aktif (misal `NEW`, `RESOLVED`). |
| `/case` | `/c` | `<case_id>` | Menampilkan detail laporan insiden, timeline audit, dan SLA timer. |
| `/update_case` | `/uc` | `<case_id> <status> [notes]` | Memperbarui status kasus (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`). |
| `/sync_ticket` | `/st` | `<case_id>` | Mendispatch insiden ke ticketing pihak ke-3 (TheHive, Jira, ServiceNow, Webhook). |
| `/soc_metrics` | `/sm` | - | Menampilkan statistik metrik SOC: MTTD, MTTR, insiden aktif, dan SLA. |
| `/export_case` | `/ec` | `<case_id>` | Mengekspor laporan kasus dalam format Markdown. |

---

### D. AI SOC Copilot & MLOps

| Command Standard | Alias Singkat | Argumen | Deskripsi |
| :--- | :--- | :--- | :--- |
| `/ask_ai` | `/ai` | `<pertanyaan>` | Mengajukan pertanyaan analisis ancaman ke AI SOC Copilot (Gemini, Claude, OpenAI, Ollama). |
| `/rca` | `/rca` | `<ip_or_event_id>` | Menghasilkan Root Cause Analysis (RCA) lengkap berbasis riwayat log. |
| `/ai_model` | `/aim` | `[nama_model]` | Melihat atau mengganti model AI yang aktif secara live (runtime) tanpa edit kode. |
| `/ai_provider` | `/aip` | `[gemini\|claude\|openai\|ollama]` | Melihat atau mengganti AI provider aktif secara live (runtime). |
| `/retrain_model` | `/rm` | - | Memicu training model Challenger secara on-demand dan memverifikasi skor ROC-AUC. |

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
