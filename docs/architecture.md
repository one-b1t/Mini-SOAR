# MiniSOAR Architecture & System Design

## 1. Diagram Arsitektur Sistem Terpadu (Archify & Interactive Viewer)

MiniSOAR mengadopsi pola arsitektur **Event-Driven & Micro-Engine Architecture** yang memisahkan lapisan *Ingestion*, *Buffer & State Caching*, *Correlation & Decision*, *Response & Containment*, serta *Triple-Interface Telegram & AI Intelligence Layer*.

> [!TIP]
> **Diagram Arsitektur Interaktif (Archify v2.16)**
> - 🌐 **Buka Aplikasi Viewer Interaktif:** [`docs/minisoar-architecture.html`](./minisoar-architecture.html)
> - 📄 **Spesifikasi JSON-IR Archify:** [`docs/minisoar-architecture.architecture.json`](./minisoar-architecture.architecture.json)
> - ✨ **Fitur:** Dukungan Dark / Light theme, Pan & Zoom tak terbatas, 3 Guided Focus Views (*Threat-to-Mitigation*, *SOC Collaboration*, *Response Orchestration*), relationship tracing otomatis, dan ekspor instan (SVG / PNG / WebP / WebM).

![MiniSOAR Architecture Diagram (Dark Preview)](./minisoar-architecture.visual-check.1440x900.dark.png)

<details>
<summary><b>🔍 Klik untuk melihat Diagram dalam Light Theme</b></summary>

![MiniSOAR Architecture Diagram (Light Preview)](./minisoar-architecture.visual-check.1440x900.light.png)

</details>

---

## 2. Arsitektur 3-Interface Telegram (Triple-Interface Telegram Subsystem)

MiniSOAR mengimplementasikan pemisahan antarmuka Telegram menjadi **3 kanal independen** untuk membedakan aliran informasi deteksi, audit operasional, dan interaksi perintah analis:

```mermaid
flowchart LR
    subgraph SYSTEM_ALERTS["MiniSOAR Core"]
        D1[Alert Ingestion Daemon]
        M1[Mitigation & Playbook Engine]
        B1[Interactive Bot Handler]
    end

    subgraph TELEGRAM_CHANNELS["Telegram Subsystem (3 Interfaces)"]
        D1 -->|Broadcast Alerts| IF1["📢 1. Channel Notification\n(TELEGRAM_CHAT_ID)"]
        M1 -->|Audit Trail Logs| IF2["📋 2. Channel Action Log\n(TELEGRAM_PROCESS_CHAT_ID)"]
        ANALYST[👨‍💻 SOC Analyst] <-->|Commands & Callbacks| IF3["🤖 3. Bot Message Interface\n(Private DM / Authorized Group)"]
    end

    IF1 -->|View Context & Click Buttons| ANALYST
    IF2 -->|Monitor Execution Stream| ANALYST
    IF3 -->|Execute Commands & AI Queries| SYSTEM_ALERTS
```

### A. Interface 1: Channel Notification (`TELEGRAM_CHAT_ID`)
- **Tujuan:** Kanal siaran khusus (*alert broadcast feed*) untuk seluruh tim SOC.
- **Fungsi & Karakteristik:**
  - Menerima pesan alert keamanan terstruktur dari Daemon saat event anomali terdeteksi.
  - Menampilkan ringkasan ancaman: Tipe Serangan, Emoji Severity, Target Host, Path URL, IP Penyerang, dan Skor Reputasi IP (AbuseIPDB/ip-api).
  - Dilengkapi **Inline Action Buttons** (`[Block IP]`, `[Ignore]`, `[Details]`) jika sistem berada pada `MINISOAR_BLOCKING_MODE=SEMI`.

### B. Interface 2: Channel Action & Audit Log (`TELEGRAM_PROCESS_CHAT_ID`)
- **Tujuan:** Kanal audit stream khusus (*operational transparency & audit trail*) untuk memantau setiap aksi yang dieksekusi sistem atau analis.
- **Fungsi & Karakteristik:**
  - Dipisahkan dari Channel Notif agar percakapan alert tidak tertimbun log eksekusi.
  - Setiap tindakan mitigasi (`[BLOCKED] IP on Palo Alto / Cloudflare`, `[UNBLOCKED] IP`, `[ISOLATED] Host on Kaspersky KSC`, `[CASE CREATED] Case #102`, `[TICKET SYNC] Jira SEC-401`) otomatis dikirimkan ke kanal ini melalui fungsi `notify_action_log()`.
  - Berisi identitas eksekutor (nama analis, user ID Telegram, atau `Playbook Engine`), timestamp eksekusi, provider tujuan, dan alasan tindakan.

### C. Interface 3: Interactive Bot Message Interface (`minisoar/bot.py`)
- **Tujuan:** Antarmuka interaksi langsung dua arah (*conversational command center*) antara analis SOC dan engine MiniSOAR via pesan pribadi (DM) atau grup terotorisasi.
- **Fungsi & Karakteristik:**
  - **Role-Based Access Control (RBAC):** Memvalidasi setiap pengirim perintah terhadap daftar `ALLOWED_USER_IDS` di `.env`. Perintah dari unauthorized user akan langsung ditolak dan dicatat.
  - **Interactive Callback Handlers:** Memproses klik tombol inline keyboard dari Channel Notif.
  - **Pusat Eksekusi Perintah Komprehensif:**
    - *Perimeter:* `/block`, `/unblock`, `/blockoncf`, `/blockonforti`, `/commit`, `/status`.
    - *EDR Endpoint:* `/isolatehost`, `/restorehost`, `/queryhost`, `/addedrioc`, `/edrstatus`.
    - *Case & SLA:* `/cases`, `/case`, `/updatecase`, `/syncticket`, `/socmetrics`, `/exportcase`.
    - *GenAI Copilot:* `/askai <pertanyaan>`, `/rca <ip_or_id>`, `/retrainmodel`.

---

## 3. Aliran Siklus Hidup Event (End-to-End Event Lifecycle)

```mermaid
sequenceDiagram
    autonumber
    participant ES as Elasticsearch (Log Pool)
    participant LS as Logstash Detection
    participant RD as Redis (Queue & Cache)
    participant DM as MiniSOAR Daemon
    participant PB as Playbook Engine
    participant PM as Perimeter & EDR Routers
    participant TG_N as Telegram Channel Notif
    participant TG_A as Telegram Channel Action
    participant TG_B as Telegram Bot (Analyst)
    participant AI as AI SOC Copilot

    ES->>LS: Ingest Raw Traffic Logs
    LS->>LS: Filter Regex, Webshell Heuristics, Gambling Pattern
    LS->>RD: LPUSH alert payload to logstash_alert_queue
    RD->>DM: LPOP alert payload
    DM->>DM: Whitelist Check & AbuseIPDB Enrichment
    DM->>RD: Sliding-Window Aggregation & Anti-Storm Throttle Check
    
    alt Alert Throttled (Storm Suppression)
        DM->>DM: Suppress duplicate notification
    else Alert Valid & Not Throttled
        DM->>PB: Evaluate YAML Playbook Rules (Safe AST)
        
        alt Playbook Matches (Auto Containment)
            PB->>PM: Trigger Auto Containment (Perimeter Block + EDR Isolate)
            PM-->>TG_A: Send Audit Log: [AUTO-CONTAINED] IP on WAF & Host on EDR
            DM->>TG_N: Broadcast High Severity Alert + Containment Status
        else Semi-Automated / Manual Mode
            DM->>TG_N: Broadcast Alert with Inline Buttons [Block] [Ignore]
            TG_B->>DM: Analyst clicks [Block IP] or types /block
            DM->>PM: Execute Mitigation on Target Perimeters
            PM-->>TG_A: Send Audit Log: [MANUAL BLOCK] IP blocked by @analyst_user
        end
        
        opt GenAI RCA / Investigation Requested
            TG_B->>AI: Analyst runs /rca <event_id> or /askai
            AI-->>TG_B: Return MITRE ATT&CK Mapping & Root Cause Analysis
        end
        
        DM->>ES: Store event record to minisoar-events-YYYY.MM.DD
    end
```

---

## 4. Rincian Komponen & Sub-Engine

### A. Sliding-Window Correlation & Anti-Storm Engine (`minisoar/correlation.py`)
- **Tujuan:** Mencegah *alert fatigue* dan mendeteksi serangan multi-vektor / terdistribusi.
- **Mekanisme Teknis:**
  - **Hit Aggregation:** Menggunakan Redis `ZADD` (skor = epoch unix) dan `ZREMRANGEBYSCORE` untuk menghitung frekuensi hit serangan dalam rentang waktu geser (`MINISOAR_EVENT_WINDOW`, default 60s).
  - **Anti-Storm Throttling:** Mencegah pengiriman alert duplikat untuk kombinasi `<src_ip>:<alert_type>` yang sama dalam jendela waktu throttling (`throttle:<ip>:<type>`).
  - **Distributed Campaign Detection:** Melacak himpunan IP unik per target asset (`campaign:<server_name>`). Jika jumlah penyerang unik melebihi ambang batas, sistem menaikkan severity menjadi `[DISTRIBUTED CAMPAIGN]`.

---

### B. Declarative Playbook Engine (`minisoar/playbook/`)
- **Tujuan:** Mengotomatiskan alur kerja respons insiden (SOP) secara fleksibel tanpa mengubah kode sumber.
- **Fitur Utama:**
  - **Definisi YAML:** Disimpan di direktori `minisoar/playbooks/` dengan deklarasi `trigger`, `conditions`, dan langkah `steps` terurut.
  - **Safe AST Condition Evaluator (`conditions.py`):** Mengevaluasi ekspresi boolean kompleks (contoh: `alert.severity == 'high' and reputation_score >= 80 and not is_whitelisted`) menggunakan pohon sintaks abstrak (`ast.parse`) yang aman dari eksekusi kode berbahaya.
  - **Action Registry (`actions.py`):** Mendukung aksi mitigasi perimeter (`mitigation.block_ip`, `mitigation.cloudflare_block`, `mitigation.fortigate_block`), aksi EDR (`edr.isolate_endpoint`, `edr.add_ioc`), manajemen kasus (`case.create_case`, `case.update_case`), notifikasi Telegram, dan AI Copilot (`ai.copilot_analyze`).

---

### C. Unified Perimeter & EDR Routers
- **Perimeter Router (`minisoar/mitigation/core.py`):**
  Mengabstraksi operasi blokir dan unblokir ke 5 provider perimeter:
  - **Palo Alto Networks:** Address object dan dynamic address group (DAG) manipulation via PAN-OS XML API.
  - **Imperva WAF:** Site IP ACL and security rule modification via SecureSphere REST API.
  - **Akamai Kona Site Defender:** Network List update and staging/production activation via EdgeGrid API.
  - **Cloudflare Edge WAF:** IP Access Rules API (Block/Challenge) pada level Zone atau Account.
  - **Fortinet FortiGate:** Firewall Address Objects dan Address Groups via FortiOS REST API.
- **EDR Router (`minisoar/edr/core.py`):**
  Mengabstraksi operasi penahanan host dan distribusi IoC:
  - **Kaspersky Security Center (KSC 15.1 OpenAPI):** Session token lifecycle, HostGroup network isolation, dan IoC repository insertion.
  - **TrendMicro Vision One & Cloud One:** Endpoint network suspension dan response task execution.

---

### D. Case Management & Optional 3rd-Party Ticketing (`minisoar/cases/`)
- **Incident Lifecycle:** Pelacakan status insiden (`NEW` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `RESOLVED` $\rightarrow$ `CLOSED` / `FALSE_POSITIVE`).
- **SLA & SOC Metrics:** Perhitungan otomatis Mean Time to Detect (MTTD) dan Mean Time to Respond (MTTR).
- **Executive Reporting:** Generator laporan investigasi otomatis dalam format Markdown dan Standalone HTML.
- **Konektor Pihak Ketiga (100% Opsional):**
  - **TheHive 4/5:** Sinkronisasi case dan IoC observable.
  - **Jira Service Management:** Pembuatan tiket insiden pada project key target.
  - **ServiceNow Table API:** Pembuatan incident record dengan mapping otomatis Urgency & Impact.
  - **Generic Webhooks:** Integrasi fleksibel ke Zendesk, Freshservice, Slack, atau Microsoft Teams.

---

### E. Dual-Engine AI SOC Copilot & Continuous MLOps (`minisoar/ai/` & `minisoar/ml/`)
- **Fast-Path Traffic Processing:** Model machine learning lokal (`active_model.joblib`) berbasis scikit-learn untuk klasifikasi inferensi sub-milidetik pada lalu lintas data Redis real-time.
- **GenAI Copilot:** Asisten analis interaktif multi-provider (Google Antigravity/Gemini, Anthropic Claude, OpenAI Codex, Local Ollama) dengan dukungan berkas autentikasi terisolasi (`AI_AUTH_FILE`, `GEMINI_AUTH_FILE`, `CLAUDE_AUTH_FILE`).
- **Continuous Auto-Retraining (MLOps):** Pipeline otomatis yang mengekstrak label ground-truth analis dari `minisoar-labels-*`, melatih model Challenger, memvalidasi ambang batas kualitas (ROC-AUC $\ge 0.85$), dan me-reload model aktif secara hot-reload tanpa restart daemon.

---

### F. Alur & Metode Generasi Machine Learning Baseline (`minisoar/ml/`)

Model baseline machine learning (`baseline_model.joblib`) berfungsi sebagai model *fallback* berkecepatan tinggi (*sub-millisecond local inference*) pada Core Daemon untuk memprediksi klasifikasi biner pemblokiran (`label: 0` = Allow/Ignore, `label: 1` = Block IP) ketika model dinamis `active_model.joblib` belum terbentuk atau saat inisialisasi lingkungan baru (*cold start*).

#### 1. Diagram Arsitektur & Pipeline Baseline ML (Archify Interactive)

> [!TIP]
> **Diagram Alur Machine Learning Interaktif (Archify v2.16)**
> - 🌐 **Buka Aplikasi Viewer Interaktif:** [`docs/minisoar-ml-pipeline.html`](./minisoar-ml-pipeline.html)
> - 📄 **Spesifikasi JSON-IR Archify:** [`docs/minisoar-ml-pipeline.architecture.json`](./minisoar-ml-pipeline.architecture.json)
> - ✨ **Fitur:** Tampilan Dark/Light theme, Pan & Zoom tak terbatas, 3 Guided Focus Views (*Dataset extraction*, *Training & validation*, *Runtime hot-reload*), tracing relasi otomatis, serta ekspor format SVG / PNG / WebP / WebM.

![MiniSOAR ML Pipeline Diagram (Dark Preview)](./minisoar-ml-pipeline.visual-check.1440x900.dark.png)

<details>
<summary><b>🔍 Klik untuk melihat Diagram ML dalam Light Theme</b></summary>

![MiniSOAR ML Pipeline Diagram (Light Preview)](./minisoar-ml-pipeline.visual-check.1440x900.light.png)

</details>

---

#### 2. Rincian Metode & Algoritma

1. **Ekstraksi Dataset & Fallback Bootstrap (`minisoar/ml/export.py`):**
   - **Mode Ground-Truth:** Mengambil label analis SOC dari indeks `minisoar-labels-*`, kemudian melakukan join secara chunked (1.000 record/batch) ke indeks `minisoar-events-*` untuk mengumpulkan nilai telemetri sebenarnya.
   - **Mode Fallback Bootstrap (`write_synthetic_dataset`):** Jika Elasticsearch kosong atau tidak dapat diakses, sistem secara deterministik (`Random(42)`) membangkitkan 10.000 sampel data latih yang mencerminkan profil ancaman dunia nyata:
     - `alert_webshell_immediate`: Skor reputasi 80–100, hit count 10–150, probabilitas block 98%.
     - `alert_webshell_name` & `alert_webshell_heur`: Skor reputasi 50–95, hit count 5–80, probabilitas block 85%.
     - `alert_gambling_slot`: Skor reputasi 40–90, hit count 50–1000, probabilitas block 90%.
     - `alert_distributed_error`: Skor reputasi 10–60, hit count 100–5000, probabilitas block 20%.
     - `alert_url_probe`: Skor reputasi 20–85, hit count 1–50, probabilitas block 40%.
     - Whitelisted Traffic: Skor reputasi 0–10, hit count 1–10, probabilitas block 0%.

2. **Feature Engineering & Transformasi Data (`minisoar/ml/train.py`):**
   - **Fitur Numerik:**
     - `reputation_score`: Skor reputasi eksternal IP penyerang (rentang 0–100 dari AbuseIPDB / ip-api).
     - `hit_count`: Frekuensi hit anomali dalam jendela waktu geser (*sliding window*).
     - `is_whitelisted`: Flag biner (0 atau 1) penanda daftar putih aset internal/rekanan.
     - `severity_encoded`: Ordinal encoding (`low: 0`, `medium: 1`, `high: 2`).
   - **Fitur Kategorikal (One-Hot Encoding):**
     - `detector_type`: Pola detektor yang memicu alert (contoh: `detector_type_alert_webshell_immediate`).
     - `perimeter_vendor`: Vendor perimeter target (contoh: `perimeter_vendor_paloalto`, `perimeter_vendor_cloudflare`).
   - **Pemisahan Data:** `train_test_split` dengan rasio 80:20, `random_state=42`, dan *stratified sampling* berdasarkan label kelas target untuk menjamin proporsi kelas yang seimbang.

3. **Algoritma Model Baseline:**
   - Menggunakan **Logistic Regression** (`sklearn.linear_model.LogisticRegression`) dengan parameter `max_iter=1000` dan `random_state=42`.
   - Alasan pemilihan algoritma:
     - **Interpretabilitas Tinggi:** Koefisien bobot fitur dapat diinspeksi secara langsung untuk audit keamanan SOC.
     - **Latency Rendah:** Operasi dot-product linier memungkinkan waktu inferensi sub-milidetik ($< 1\text{ ms}$) tanpa beban komputasi GPU.
     - **Stabilitas Output:** Menghasilkan nilai probabilitas terkalibrasi (`predict_proba`) yang langsung digunakan Playbook Engine sebagai skor keyakinan (*confidence score*).

4. **Metrik Evaluasi & Quality Assurance:**
   - **Accuracy & ROC-AUC:** Mengukur kapabilitas pemisahan sinyal serangan terhadap traffic benign.
   - **Confusion Matrix:** Memastikan False Positive (FP) seminimal mungkin agar tidak terjadi pemblokiran salah sasaran pada IP bisnis yang sah.
   - **Classification Report:** Memvalidasi metrik Precision, Recall, dan F1-Score untuk kedua kelas (`Allow = 0`, `Block = 1`).

5. **Serialisasi Artifact & Hot-Reloading (`minisoar/ml/inference.py`):**
   - Model disimpan ke berkas `baseline_model.joblib` bersama metadata kolom fitur (`feature_columns`), pemetaan severity, dan timestamp pelatihan.
   - Fungsi `load_model_artifact()` memantau `st_mtime` berkas model. Ketika model diperbarui atau digantikan oleh model Challenger dari MLOps (`active_model.joblib`), daemon otomatis memuat ulang (*hot-reload*) bobot model ke dalam memori tanpa memerlukan *restart* proses daemon.

