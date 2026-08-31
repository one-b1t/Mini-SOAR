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

### Topologi Alur Kerja Komponen (Mermaid Flowchart)

```mermaid
flowchart TD
    %% Styling Classes
    classDef ingest fill:#0d2030,stroke:#00bcd4,stroke-width:2px,color:#e0f7fa;
    classDef buffer fill:#1a2332,stroke:#29b6f6,stroke-width:2px,color:#e1f5fe;
    classDef core fill:#13281e,stroke:#00e676,stroke-width:2px,color:#e8f5e9;
    classDef perimeter fill:#30141e,stroke:#ff5252,stroke-width:2px,color:#ffebee;
    classDef edr fill:#261833,stroke:#ba68c8,stroke-width:2px,color:#f3e5f5;
    classDef telegram fill:#0f2b38,stroke:#03a9f4,stroke-width:2px,color:#e1f5fe;
    classDef ai fill:#2a1b3d,stroke:#ab47bc,stroke-width:2px,color:#f3e5f5;
    classDef caseMgmt fill:#2e2412,stroke:#ffb300,stroke-width:2px,color:#fff8e1;

    subgraph INGESTION["1. Ingestion & Detection Layer"]
        L1["🌐 Web / Proxy / WAF Logs"]:::ingest
        ES[("📊 Elasticsearch Cluster :9200")]:::ingest
        LS["⚙️ Logstash Normalizer & Pipeline"]:::ingest
        L1 -->|syslog / beats| ES
        ES -->|query / index| LS
    end

    subgraph BUFFER["2. Async Buffer & State Cache"]
        RQ[("⚡ Redis: logstash_alert_queue")]:::buffer
        RD_STATE[("🗄️ Redis: Sliding-Window & State Cache")]:::buffer
        LS -->|LPUSH alert| RQ
    end

    subgraph CORE_DAEMON["3. MiniSOAR Daemon Core Engine"]
        DAEMON["🛡️ Daemon Ingestion Worker"]:::core
        CORR["📈 Sliding-Window Correlation & Anti-Storm"]:::core
        
        subgraph DUAL_ENGINE["Dual-Engine Decision System"]
            ML_FAST["⚡ Fast ML Inference\n(active_model.joblib)"]:::core
            PLAYBOOK["📜 Declarative Playbook Engine\n(Safe AST DAG)"]:::core
        end

        RQ -->|LPOP| DAEMON
        DAEMON <-->|Hit Aggregation| RD_STATE
        DAEMON --> CORR
        CORR --> DUAL_ENGINE
    end

    subgraph EXECUTION["4. Unified Response & Containment"]
        PERIM_ROUTER["🧱 Unified Perimeter Router"]:::perimeter
        EDR_ROUTER["💻 Unified EDR Router"]:::edr
        CASE_ENGINE["📋 Case & SLA Management"]:::caseMgmt

        PLAYBOOK -->|block IP| PERIM_ROUTER
        PLAYBOOK -->|isolate host| EDR_ROUTER
        PLAYBOOK -->|create incident| CASE_ENGINE

        subgraph PERIMETER_LAYER["Perimeter Mitigations"]
            PA["Palo Alto Firewall / DAG"]:::perimeter
            IMP["Imperva Cloud / On-Prem WAF"]:::perimeter
            AK["Akamai Kona Network List"]:::perimeter
            CF["Cloudflare Edge WAF Rules"]:::perimeter
            FG["Fortinet FortiGate Firewall"]:::perimeter
            PERIM_ROUTER --> PA & IMP & AK & CF & FG
        end

        subgraph EDR_LAYER["Endpoint Detection & Response"]
            KSC["Kaspersky KSC 15.1 OpenAPI"]:::edr
            TM["TrendMicro Cloud / Vision One"]:::edr
            EDR_ROUTER --> KSC & TM
        end

        subgraph TICKETING_LAYER["Ticketing & Cases"]
            TICKET["TheHive / Jira / ServiceNow"]:::caseMgmt
            CASE_ENGINE --> TICKET
        end
    end

    subgraph TELEGRAM_3_INTERFACE["5. Triple-Interface Telegram Subsystem"]
        CH_NOTIF["📢 Channel Notif\n(TELEGRAM_CHAT_ID)"]:::telegram
        CH_ACTION["📋 Channel Action Log\n(TELEGRAM_PROCESS_CHAT_ID)"]:::telegram
        BOT_CMD["🤖 Bot Command Handler\n(minisoar/bot.py)"]:::telegram
        ANALYST["👨‍💻 SOC Analyst"]:::telegram
        AI_COPILOT["🧠 AI SOC Copilot\n(Gemini / Claude / Local)"]:::ai

        DAEMON -->|Broadcast Alerts| CH_NOTIF
        PERIM_ROUTER -.->|Audit Trail Logs| CH_ACTION
        EDR_ROUTER -.->|Audit Trail Logs| CH_ACTION
        CASE_ENGINE -.->|Case Updates| CH_ACTION

        ANALYST <-->|Inline Buttons & Commands| BOT_CMD
        BOT_CMD --> PERIM_ROUTER
        BOT_CMD --> EDR_ROUTER
        BOT_CMD --> CASE_ENGINE
        BOT_CMD <--> AI_COPILOT
    end

    subgraph MLOPS_LOOP["6. Telemetry & Continuous MLOps"]
        ES_EVENTS[("minisoar-events-*")]:::ingest
        ES_LABELS[("minisoar-labels-*")]:::ingest
        MLOPS["🔄 Automated Retraining Pipeline"]:::core
        DAEMON -->|Index Event| ES_EVENTS
        ANALYST -->|Feedback Labeling| ES_LABELS
        ES_LABELS --> MLOPS
        MLOPS -->|Champion-Challenger Gate| ML_FAST
    end
```

---

## 2. Arsitektur 3-Interface Telegram (Triple-Interface Telegram Subsystem)

MiniSOAR mengimplementasikan pemisahan antarmuka Telegram menjadi **3 kanal independen** untuk membedakan aliran informasi deteksi, audit operasional, dan interaksi perintah analis:

```mermaid
flowchart LR
    classDef coreEngine fill:#13281e,stroke:#00e676,stroke-width:2px,color:#e8f5e9;
    classDef tgChannel fill:#0f2b38,stroke:#03a9f4,stroke-width:2px,color:#e1f5fe;
    classDef socActor fill:#2a1b3d,stroke:#ab47bc,stroke-width:2px,color:#f3e5f5;

    subgraph SYSTEM_ALERTS["🛡️ MiniSOAR Core Engine"]
        D1["Alert Ingestion Daemon"]:::coreEngine
        M1["Mitigation & Playbook Engine"]:::coreEngine
        B1["Interactive Bot Handler"]:::coreEngine
    end

    subgraph TELEGRAM_CHANNELS["📱 Telegram Subsystem (3 Kanal Terpisah)"]
        IF1["📢 1. Channel Notification\n(TELEGRAM_CHAT_ID)\n• Broadcast Feed Alert\n• Inline Buttons Action"]:::tgChannel
        IF2["📋 2. Channel Action Log\n(TELEGRAM_PROCESS_CHAT_ID)\n• Audit Trail Mitigasi\n• Real-Time Stream Log"]:::tgChannel
        IF3["🤖 3. Bot Command Interface\n(Private DM / Auth Group)\n• RBAC Command Console\n• GenAI SOC Copilot"]:::tgChannel
    end

    ANALYST["👨‍💻 SOC Analyst"]:::socActor

    D1 -->|1. Siaran Alert Cepat| IF1
    M1 -->|2. Audit Log Otomatis| IF2
    IF1 -->|Lihat Konteks & Klik Tombol| ANALYST
    IF2 -->|Monitor Eksekusi Tindakan| ANALYST
    ANALYST <-->|3. Eksekusi Perintah & AI| IF3
    IF3 -->|Perintah Eksekusi| B1
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
    
    box rgb(13, 32, 48) Ingestion & Cache
        participant ES as Elasticsearch (Log Pool)
        participant LS as Logstash Detection
        participant RD as Redis (Queue & Cache)
    end
    
    box rgb(19, 40, 30) MiniSOAR Core Engine
        participant DM as MiniSOAR Daemon
        participant PB as Playbook Engine
    end
    
    box rgb(48, 20, 30) Enforcement
        participant PM as Perimeter & EDR Routers
    end
    
    box rgb(15, 43, 56) Telegram & Operations
        participant TG_N as Telegram Notif
        participant TG_A as Telegram Action Log
        participant TG_B as Telegram Bot (Analyst)
        participant AI as AI SOC Copilot
    end

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
