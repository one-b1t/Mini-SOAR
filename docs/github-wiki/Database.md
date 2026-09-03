# MiniSOAR Database & Storage Specifications

## 1. Elasticsearch Index Architecture

MiniSOAR menggunakan cluster Elasticsearch untuk menyimpan telemetry log, audit mitigasi, siklus hidup insiden (cases), dan ground-truth label analis untuk MLOps.

### A. Pola Penamaan Indeks (Index Naming Conventions)

| Pola Indeks | Deskripsi | Retensi Disarankan |
| :--- | :--- | :--- |
| `minisoar-events-YYYY.MM.DD` | Telemetry event alert mentah & hasil enrichment | 90 Hari |
| `minisoar-cases` | Record lifecycle insiden kasus & audit SLA | 365 Hari |
| `minisoar-labels-YYYY.MM` | Keputusan feedback analis (Ground-truth ML) | 180 Hari |
| `minisoar-mitigations-YYYY.MM` | Log audit eksekusi blokir/unblokir perimeter | 180 Hari |

---

### B. Index Mapping Schema: `minisoar-events-*`

```json
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "event_id": { "type": "keyword" },
      "src_ip": { "type": "ip" },
      "server_name": { "type": "keyword" },
      "url": { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
      "method": { "type": "keyword" },
      "status": { "type": "integer" },
      "alert_type": { "type": "keyword" },
      "severity": { "type": "keyword" },
      "reputation_score": { "type": "float" },
      "ml_prediction": {
        "properties": {
          "should_block": { "type": "boolean" },
          "confidence": { "type": "float" },
          "model_version": { "type": "keyword" }
        }
      },
      "tags": { "type": "keyword" },
      "mitigation_status": { "type": "keyword" }
    }
  }
}
```

---

### C. Index Mapping Schema: `minisoar-cases`

```json
{
  "mappings": {
    "properties": {
      "case_id": { "type": "keyword" },
      "title": { "type": "text" },
      "description": { "type": "text" },
      "severity": { "type": "keyword" },
      "status": { "type": "keyword" },
      "created_at": { "type": "date" },
      "updated_at": { "type": "date" },
      "contained_at": { "type": "date" },
      "resolved_at": { "type": "date" },
      "attacker_ips": { "type": "ip" },
      "target_assets": { "type": "keyword" },
      "external_ticket": {
        "properties": {
          "provider": { "type": "keyword" },
          "ticket_id": { "type": "keyword" },
          "ticket_url": { "type": "keyword" }
        }
      },
      "timeline": {
        "type": "nested",
        "properties": {
          "timestamp": { "type": "date" },
          "actor": { "type": "keyword" },
          "action": { "type": "keyword" },
          "message": { "type": "text" }
        }
      }
    }
  }
}
```

---

## 2. Redis Key Structure & Caching Conventions

Redis digunakan sebagai antrian asinkron, sliding-window hit aggregator, anti-storm throttler, dan cache status blokir sementara.

| Namespace Key | Tipe Data | TTL Default | Fungsi |
| :--- | :--- | :--- | :--- |
| `logstash_alert_queue` | `List` | - | Antrian utama alert dari Logstash menuju Daemon Python |
| `block:<ip>` | `String` / `Hash` | 86400s (24h) | Cache IP yang sedang aktif diblokir di perimeter |
| `throttle:<ip>:<alert_type>` | `String` | 300s (5m) | Kunci pembatas frekuensi notifikasi Telegram per insiden |
| `window:<ip>` | `Sorted Set (ZSET)` | 3600s (1h) | Agregasi sliding-window hit serangan (skor = epoch unix) |
| `campaign:<server_name>` | `Set (SET)` | 600s (10m) | Himpunan IP unik untuk deteksi serangan terdistribusi |
| `ioc:edr:<hash/ip>` | `Hash` | 604800s (7d) | Cache distribusi IoC ke Kaspersky KSC & TrendMicro |
| `ml:active_model_mtime` | `String` | - | Timestamp model aktif untuk mekanisme hot-reloading |
