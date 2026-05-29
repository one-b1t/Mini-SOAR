# Graph Report - .  (2026-05-25)

## Corpus Check
- Corpus is ~8,203 words - fits in a single context window. You may not need a graph.

## Summary
- 131 nodes · 256 edges · 24 communities (15 shown, 9 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.88)
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
- [[_COMMUNITY_Perimeter Injection Utilities|Perimeter Injection Utilities]]
- [[_COMMUNITY_Project Architecture Context|Project Architecture Context]]
- [[_COMMUNITY_ML Target Goals & Foundations|ML Target Goals & Foundations]]
- [[_COMMUNITY_Whitelist IP Check Semantic|Whitelist IP Check Semantic]]
- [[_COMMUNITY_Bypass IP Check Semantic|Bypass IP Check Semantic]]
- [[_COMMUNITY_Perimeter Info Check Semantic|Perimeter Info Check Semantic]]
- [[_COMMUNITY_Existing Architecture Config|Existing Architecture Config]]
- [[_COMMUNITY_ML Modeling Classifiers|ML Modeling Classifiers]]
- [[_COMMUNITY_ML Decision Rules & Guardrails|ML Decision Rules & Guardrails]]

## God Nodes (most connected - your core abstractions)
1. `log_user_action()` - 15 edges
2. `is_user_allowed()` - 14 edges
3. `log_user_action` - 14 edges
4. `is_user_allowed` - 13 edges
5. `callback_query_handler()` - 12 edges
6. `callback_query_handler` - 8 edges
7. `blockonpalo()` - 7 edges
8. `unblockonpalo()` - 7 edges
9. `akamai_session()` - 7 edges
10. `akamai_url()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `log_user_action` --semantically_similar_to--> `log_unmapped_site_once_per_day`  [INFERRED] [semantically similar]
  09-tele-soar.py → 14_redis_telegram_alert.py
- `_es_index` --semantically_similar_to--> `_es_index`  [INFERRED] [semantically similar]
  09-tele-soar.py → 14_redis_telegram_alert.py
- `store_label` --implements--> `Telegram Callback Labeling`  [EXTRACTED]
  09-tele-soar.py → mini_soar_ml_context.md
- `callback_query_handler` --shares_data_with--> `send_telegram`  [INFERRED]
  09-tele-soar.py → 14_redis_telegram_alert.py
- `callback_query_handler` --references--> `Telegram Callback Labeling`  [EXTRACTED]
  09-tele-soar.py → mini_soar_ml_context.md

## Hyperedges (group relationships)
- **SOC Decision Labeling Workflow** — 09_tele_soar_callback_query_handler, 09_tele_soar_store_label, 14_redis_telegram_alert_send_telegram, mini_soar_ml_context_telegram_callback_labeling [EXTRACTED 1.00]
- **Security Perimeter Blocking Integrations** — 09_tele_soar_blockonimperva, 09_tele_soar_blockonpalo, 09_tele_soar_blockonakamai [EXTRACTED 1.00]

## Communities (24 total, 9 thin omitted)

### Community 0 - "Telegram Bot Event Routing"
Cohesion: 0.14
Nodes (27): _es_find_latest_event_id_by_ip, _es_index, activateakamai, activationstatus, blocklistakamai, blocklistimperva, blockonakamai, blockonimperva (+19 more)

### Community 1 - "Palo Alto Firewall Client"
Cohesion: 0.31
Nodes (11): blockonpalo(), build_pa_object_name(), commitpalo(), get_response_message(), pa_add_address_object(), pa_add_to_group(), pa_delete_address_object(), pa_partial_commit() (+3 more)

### Community 2 - "Imperva WAF Client"
Cohesion: 0.42
Nodes (10): blocklistimperva(), blockonimperva(), callback_query_handler(), ip_blocklist_api(), is_user_allowed(), log_user_action(), login_via_api(), action : string pendek, misal 'block_imperva', 'unblock_palo', 'activate_akamai' (+2 more)

### Community 3 - "Telegram UI Pagination"
Cohesion: 0.27
Nodes (6): blocklistakamai(), get_blocked_ip_list(), pagination_callback_handler(), _parse_callback_payload(), send_akamai_page(), send_ip_page()

### Community 4 - "Event ID & Whitelist Checks"
Cohesion: 0.29
Nodes (7): _es_host(), _es_index(), _ip_in_nets(), is_ip_bypassed(), is_ip_whitelisted(), make_event_id(), _sig_hash()

### Community 5 - "Akamai CDN Client"
Cohesion: 0.48
Nodes (7): activateakamai(), activationstatus(), akamai_session(), akamai_url(), blockonakamai(), unblockonakamai(), valid_ip()

### Community 6 - "Elasticsearch SOC Decisions"
Cohesion: 0.33
Nodes (7): _es_find_latest_event_id_by_ip(), _es_host(), _es_index(), _es_verify_value(), Best-effort lookup of event_id from minisoar-events-* by IP and time window., Store SOC decision label to Elasticsearch (Phase 0).      We try to store `event, store_label()

### Community 7 - "IP Threat Intelligence"
Cohesion: 0.29
Nodes (7): abuseipdb_lookup(), build_message(), enrich_ip(), enrich_multi_ip(), _gx(), ipapi_lookup(), _normalize_ip_list()

### Community 8 - "Time Format Utilities"
Cohesion: 0.47
Nodes (6): _bullet_last_seen(), _fmt_last_seen(), _humanize_ago(), _parse_iso8601_relaxed(), _parse_ts_epoch(), _pick_ts_field()

### Community 9 - "Security Perimeter Config"
Cohesion: 0.4
Nodes (6): get_perimeter_info(), get_perimeter_provider(), _load_perimeter_cfg(), _norm_provider(), provider_badge(), provider_label()

### Community 10 - "Imperva SecureSphere API"
Cohesion: 0.5
Nodes (4): imperva_api_request(), imperva_get_violation_by_event_id(), imperva_get_violation_by_event_number(), Imperva SecureSphere v15.3:     - eventNumber harus dikombinasikan dengan time r

### Community 11 - "Violation Data Normalizer"
Cohesion: 0.5
Nodes (4): format_violation(), normalize_violation(), pick(), HANYA field yang terbukti ada di response Postman (v15.3.10) kamu.     Field lai

### Community 12 - "IP Enrichment Semantic Group"
Cohesion: 0.5
Nodes (4): abuseipdb_lookup, build_message, enrich_ip, ipapi_lookup

### Community 13 - "Telegram Alert Notifications"
Cohesion: 0.67
Nodes (3): _build_callback_data(), Kirim alert ke Telegram.      - Sesuai rencana baru: hanya 1 tombol action, terg, send_telegram()

### Community 14 - "Unmapped Site Log Diagnostics"
Cohesion: 0.67
Nodes (3): log_unmapped_site_once_per_day(), Log website yang belum termapping (unmapped) ke file, max 1x/hari per website., _safe_append_line()

## Knowledge Gaps
- **23 isolated node(s):** `action : string pendek, misal 'block_imperva', 'unblock_palo', 'activate_akamai'`, `Best-effort lookup of event_id from minisoar-events-* by IP and time window.`, `Store SOC decision label to Elasticsearch (Phase 0).      We try to store `event`, `Imperva SecureSphere v15.3:     - eventNumber harus dikombinasikan dengan time r`, `HANYA field yang terbukti ada di response Postman (v15.3.10) kamu.     Field lai` (+18 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **9 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What connects `action : string pendek, misal 'block_imperva', 'unblock_palo', 'activate_akamai'`, `Best-effort lookup of event_id from minisoar-events-* by IP and time window.`, `Store SOC decision label to Elasticsearch (Phase 0).      We try to store `event` to the rest of the system?**
  _23 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Telegram Bot Event Routing` be split into smaller, more focused modules?**
  _Cohesion score 0.14 - nodes in this community are weakly interconnected._