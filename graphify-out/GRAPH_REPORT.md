# Graph Report - MiniSOAR  (2026-05-26)

## Corpus Check
- 14 files · ~12,464 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 281 nodes · 610 edges · 25 communities (14 shown, 11 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 13 edges (avg confidence: 0.7)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Telegram Bot Event Routing|Telegram Bot Event Routing]]
- [[_COMMUNITY_Palo Alto Firewall Client|Palo Alto Firewall Client]]
- [[_COMMUNITY_Imperva WAF Client|Imperva WAF Client]]
- [[_COMMUNITY_Telegram UI Pagination|Telegram UI Pagination]]
- [[_COMMUNITY_Event ID & Whitelist Checks|Event ID & Whitelist Checks]]
- [[_COMMUNITY_Akamai CDN Client|Akamai CDN Client]]
- [[_COMMUNITY_Elasticsearch SOC Decisions|Elasticsearch SOC Decisions]]
- [[_COMMUNITY_IP Threat Intelligence|IP Threat Intelligence]]
- [[_COMMUNITY_Time Format Utilities|Time Format Utilities]]
- [[_COMMUNITY_Security Perimeter Config|Security Perimeter Config]]
- [[_COMMUNITY_Imperva SecureSphere API|Imperva SecureSphere API]]
- [[_COMMUNITY_Violation Data Normalizer|Violation Data Normalizer]]
- [[_COMMUNITY_IP Enrichment Semantic Group|IP Enrichment Semantic Group]]
- [[_COMMUNITY_Telegram Alert Notifications|Telegram Alert Notifications]]
- [[_COMMUNITY_Unmapped Site Log Diagnostics|Unmapped Site Log Diagnostics]]
- [[_COMMUNITY_Project Architecture Context|Project Architecture Context]]
- [[_COMMUNITY_ML Target Goals & Foundations|ML Target Goals & Foundations]]
- [[_COMMUNITY_Whitelist IP Check Semantic|Whitelist IP Check Semantic]]
- [[_COMMUNITY_Bypass IP Check Semantic|Bypass IP Check Semantic]]
- [[_COMMUNITY_Perimeter Info Check Semantic|Perimeter Info Check Semantic]]
- [[_COMMUNITY_Existing Architecture Config|Existing Architecture Config]]
- [[_COMMUNITY_ML Modeling Classifiers|ML Modeling Classifiers]]
- [[_COMMUNITY_ML Decision Rules & Guardrails|ML Decision Rules & Guardrails]]

## God Nodes (most connected - your core abstractions)
1. `str` - 31 edges
2. `callback_query_handler()` - 22 edges
3. `log_user_action()` - 19 edges
4. `DEFAULT_TYPE` - 17 edges
5. `Update` - 16 edges
6. `trigger_auto_block()` - 15 edges
7. `log_user_action()` - 15 edges
8. `is_user_allowed()` - 14 edges
9. `blockonpalo()` - 14 edges
10. `unblockonpalo()` - 14 edges

## Surprising Connections (you probably didn't know these)
- `log_user_action` --semantically_similar_to--> `log_unmapped_site_once_per_day`  [INFERRED] [semantically similar]
  09-tele-soar.py → 14_redis_telegram_alert.py
- `_es_index` --semantically_similar_to--> `_es_index`  [INFERRED] [semantically similar]
  09-tele-soar.py → 14_redis_telegram_alert.py
- `str` --uses--> `MockAkamaiSession`  [INFERRED]
  09-tele-soar.py → perimeter_mitigation.py
- `datetime` --uses--> `MockAkamaiSession`  [INFERRED]
  09-tele-soar.py → perimeter_mitigation.py
- `int` --uses--> `MockAkamaiSession`  [INFERRED]
  09-tele-soar.py → perimeter_mitigation.py

## Hyperedges (group relationships)
- **SOC Decision Labeling Workflow** — 09_tele_soar_callback_query_handler, 09_tele_soar_store_label, 14_redis_telegram_alert_send_telegram, mini_soar_ml_context_telegram_callback_labeling [EXTRACTED 1.00]
- **Security Perimeter Blocking Integrations** — 09_tele_soar_blockonimperva, 09_tele_soar_blockonpalo, 09_tele_soar_blockonakamai [EXTRACTED 1.00]

## Communities (25 total, 11 thin omitted)

### Community 0 - "Telegram Bot Event Routing"
Cohesion: 0.14
Nodes (27): _es_find_latest_event_id_by_ip, _es_index, activateakamai, activationstatus, blocklistakamai, blocklistimperva, blockonakamai, blockonimperva (+19 more)

### Community 1 - "Palo Alto Firewall Client"
Cohesion: 0.15
Nodes (30): blockonpalo(), get_response_message(), unblockonpalo(), build_pa_object_name(), _es_host(), _es_index(), _es_verify_value(), get_blocked_ip_list() (+22 more)

### Community 2 - "Imperva WAF Client"
Cohesion: 0.16
Nodes (44): DEFAULT_TYPE, activateakamai(), activationstatus(), akamai_session(), akamai_url(), blocklistakamai(), blocklistimperva(), blockonakamai() (+36 more)

### Community 3 - "Telegram UI Pagination"
Cohesion: 0.06
Nodes (34): 10. Decision Logic (Target), 11. Phase 0 – Definition of Done, 12. Next Phase (Setelah Phase 0), 13. Prinsip Penting, 1. Kondisi Awal Sistem (Existing), 2. Tujuan Pengembangan, 3. Pendekatan Machine Learning yang Dipilih, 4. Arsitektur Target (High Level) (+26 more)

### Community 4 - "Event ID & Whitelist Checks"
Cohesion: 0.10
Nodes (49): bool, datetime, int, str, Any, float, abuseipdb_lookup(), _build_callback_data() (+41 more)

### Community 5 - "Akamai CDN Client"
Cohesion: 0.15
Nodes (12): files, code, document, image, paper, video, graphifyignore_patterns, needs_graph (+4 more)

### Community 6 - "Elasticsearch SOC Decisions"
Cohesion: 0.12
Nodes (18): datetime, int, str, _es_find_latest_event_id_by_ip(), _es_host(), _es_index(), _es_verify_value(), fmt() (+10 more)

### Community 7 - "IP Threat Intelligence"
Cohesion: 0.15
Nodes (12): 1. Pendahuluan, 2. Fitur Baru & Peningkatan Arsitektur, 3. Hasil Pengujian Verifikasi & Regresi, 4. Parameter Konfigurasi Baru (.env Template), 5. Kesimpulan & Rekomendasi, A. Sistem Resolusi Path Dinamis (Cross-Platform), B. Force-Load Fallback Kredensial (.env), C. Mode Simulasi / Sandboxing (Mock Mode) (+4 more)

### Community 8 - "Time Format Utilities"
Cohesion: 0.18
Nodes (10): 1. Konfigurasi Integrasi & Kredensial (.env Template), 2. Fitur Utama & Keunggulan Sistem, 3. Instalasi & Dependensi, 4. Menjalankan Layanan, 5. Daftar Perintah Bot Telegram, code:ini (# === Redis Buffer Queue ===), code:bash (pip install redis requests xmltodict python-telegram-bot edg), code:bash (python 14_redis_telegram_alert.py) (+2 more)

### Community 9 - "Security Perimeter Config"
Cohesion: 0.33
Nodes (5): [1.2.0] - 2026-05-26, Added, Changed, Changelog, Fixed

### Community 10 - "Imperva SecureSphere API"
Cohesion: 0.60
Nodes (4): es_request(), main(), Generates a synthetic dataset for testing/bootstrap purposes if Elasticsearch is, write_synthetic_dataset()

### Community 12 - "IP Enrichment Semantic Group"
Cohesion: 0.50
Nodes (4): abuseipdb_lookup, build_message, enrich_ip, ipapi_lookup

## Knowledge Gaps
- **67 isolated node(s):** `code`, `document`, `paper`, `image`, `video` (+62 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `log_user_action()` connect `Imperva WAF Client` to `Palo Alto Firewall Client`, `Event ID & Whitelist Checks`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **Why does `trigger_auto_block()` connect `Palo Alto Firewall Client` to `Imperva WAF Client`, `Event ID & Whitelist Checks`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **What connects `code`, `document`, `paper` to the rest of the system?**
  _89 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Telegram Bot Event Routing` be split into smaller, more focused modules?**
  _Cohesion score 0.13675213675213677 - nodes in this community are weakly interconnected._
- **Should `Palo Alto Firewall Client` be split into smaller, more focused modules?**
  _Cohesion score 0.14583333333333334 - nodes in this community are weakly interconnected._
- **Should `Telegram UI Pagination` be split into smaller, more focused modules?**
  _Cohesion score 0.05714285714285714 - nodes in this community are weakly interconnected._
- **Should `Event ID & Whitelist Checks` be split into smaller, more focused modules?**
  _Cohesion score 0.10448979591836735 - nodes in this community are weakly interconnected._