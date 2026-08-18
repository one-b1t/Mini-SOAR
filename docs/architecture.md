# MiniSOAR Architecture & Design

## 1. Diagram Arsitektur Sistem

MiniSOAR mengadopsi pola arsitektur **Event-Driven & Micro-Engine Architecture** yang memisahkan ingestion, buffer queue, correlation, decision, dan execution layers.

```mermaid
flowchart TD
    subgraph INGESTION["1. Ingestion Layer"]
        L1[Web Server / Proxy Logs] --> ES[(Elasticsearch 8.x)]
        ES --> LS[Logstash Filter & Detection]
    end

    subgraph BUFFER["2. Async Buffer & Cache"]
        LS -->|List Push| RQ[(Redis: logstash_alert_queue)]
        RD_STATE[(Redis: Sliding Window & Cache)]
    end

    subgraph CORE_DAEMON["3. MiniSOAR Daemon Core"]
        RQ -->|LPOP| DAEMON[Alert Ingestion Daemon]
        DAEMON <--> RD_STATE
        DAEMON --> CORR[Sliding-Window Correlation Engine]
        DAEMON --> DUAL[Dual-Engine Classification]
        
        subgraph DUAL_ENGINE["Dual-Engine Decision"]
            ML_FAST[Fast ML Inference\nactive_model.joblib]
            PLAYBOOK[Declarative Playbook Engine\nYAML Directed Acyclic Graph]
        end
        DUAL --> ML_FAST
        DUAL --> PLAYBOOK
    end

    subgraph EXECUTION["4. Unified Response & Containment"]
        PLAYBOOK --> PERIM_ROUTER[Unified Perimeter Router]
        PLAYBOOK --> EDR_ROUTER[Unified EDR Router]
        PLAYBOOK --> CASE_ENGINE[Case & SLA Engine]
        
        PERIM_ROUTER --> PA[Palo Alto Firewall]
        PERIM_ROUTER --> IMP[Imperva WAF]
        PERIM_ROUTER --> AK[Akamai Edge]
        PERIM_ROUTER --> CF[Cloudflare Edge WAF]
        PERIM_ROUTER --> FG[Fortinet FortiGate]
        
        EDR_ROUTER --> KSC[Kaspersky KSC 15.1 OpenAPI]
        EDR_ROUTER --> TM[TrendMicro Vision One]
        
        CASE_ENGINE -->|Optional 3rd-Party| TICKET[TheHive / Jira / ServiceNow / Webhook]
    end

    subgraph INTERFACE_AI["5. Interface & Intelligence Layer"]
        DAEMON --> TELE[Telegram Bot Interface]
        TELE --> ANALYST[SOC Analyst]
        ANALYST -->|Commands / Confirmations| TELE
        TELE --> AI_COPILOT[AI SOC Copilot\nGemini / Claude / OpenAI / Ollama]
        AI_COPILOT --> ANALYST
        ANALYST -->|Feedback Labels| LABELS[(minisoar-labels)]
        LABELS --> MLOPS[MLOps Continuous Auto-Retrain]
        MLOPS -->|Hot-Reload Champion Model| ML_FAST
    end
```

---

## 2. Rincian Komponen Inti

### A. Sliding-Window Correlation Engine (`minisoar/correlation.py`)
- **Tujuan:** Mencegah alert fatigue dan mendeteksi pola serangan terdistribusi.
- **Mekanisme:**
  - **Hit Aggregation:** Menggunakan Redis `ZADD` dan `ZREMRANGEBYSCORE` dengan timestamp epoch unix.
  - **Anti-Storm Throttling:** Mencegah pengiriman lebih dari 1 notifikasi per interval jendela waktu per IP/alert type.
  - **Campaign Detection:** Menghitung jumlah IP penyerang unik yang menargetkan server atau pola URL yang sama.

### B. Declarative Playbook Engine (`minisoar/playbook/`)
- **Tujuan:** Mengotomatiskan SOP mitigasi tanpa mengubah kode sumber Python.
- **Fitur Utama:**
  - Definisi workflow berbasis YAML di `minisoar/playbooks/`.
  - **Safe AST Evaluator:** Mengevaluasi kondisi rule (`alert.severity == 'high' and reputation_score >= 80`) menggunakan `ast.parse` tanpa fungsi `eval()` berbahaya.
  - **Extensible Action Registry:** Mendukung aksi perimeter (`mitigation.block_ip`), EDR (`edr.isolate_endpoint`, `edr.add_ioc`), ticketing (`case.create_case`), dan AI Copilot (`ai.copilot_analyze`).

### C. Unified Perimeter & EDR Routers
- **Perimeter Router (`minisoar/mitigation/core.py`):** Mengabstraksi panggilan API ke 5 provider perimeter (Palo Alto, Imperva, Akamai, Cloudflare, FortiGate) dengan fallback parsing IP, normalisasi status, dan rollback unblock.
- **EDR Router (`minisoar/edr/core.py`):** Mengabstraksi isolasi host internal dan distribusi IoC ke Kaspersky KSC (OpenAPI Session, HostGroup) dan TrendMicro (Cloud One & Vision One).

### D. Dual-Engine AI SOC Copilot & MLOps
- **Fast-Path Traffic Classification:** Inferensi sub-milidetik menggunakan model scikit-learn (`active_model.joblib`) berbasis ekstraksi fitur TF-IDF + metadata keamanan.
- **GenAI Copilot:** Asisten analis interaktif berbasis SDK (Google Antigravity/Gemini, Anthropic Claude, OpenAI Codex, Ollama) untuk deobfuskasi skrip kompleks, RCA, dan MITRE ATT&CK mapping.
- **MLOps Auto-Retraining (`minisoar/ml/autotrain.py`):** Membaca dataset umpan balik dari analis (`minisoar-labels`), melatih model Challenger, memverifikasi ambang batas kualitas (ROC-AUC $\ge 0.85$), dan me-reload model secara hot-reload tanpa downtime.
