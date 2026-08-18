# MiniSOAR Testing Strategy & Quality Gates

## 1. Filosofi & Pendekatan Pengujian

MiniSOAR mengadopsi standar pengujian **Zero Regression & Defensive Architecture**. Pengujian diotomatiskan menggunakan `pytest` dengan cakupan mencakup:
- **Rule & AST Evaluation:** Menjamin keamanan parsing ekspresi logika tanpa potensi code injection.
- **Correlation & Throttling:** Memvalidasi sliding-window time buckets dan pembatasan anti-storm.
- **Multi-Perimeter Integration:** Menguji respon sukses dan error handling pada Palo Alto, Imperva, Akamai, Cloudflare, dan FortiGate.
- **EDR Server Integration:** Menguji session lifecycle dan network isolation pada Kaspersky KSC dan TrendMicro.
- **Case Lifecycle & SLA:** Memvalidasi transisi status insiden, perhitungan MTTD/MTTR, dan format laporan Markdown/HTML.
- **3rd-Party Ticketing Connectors:** Memvalidasi TheHive, Jira, ServiceNow, Generic Webhook, serta mode Disabled.
- **AI Copilot & Auth Resolution:** Menguji resolusi kredensial multi-sumber (JSON, text, environment variable, default path).
- **MLOps Quality Gate:** Memastikan promosi model hanya dilakukan jika skor metrik Challenger melampaui Champion (ROC-AUC $\ge 0.85$).

---

## 2. Struktur Test Suite

```text
tests/
├── test_autotrain.py            # Pengujian MLOps auto-training & model promotion
├── test_config.py               # Pengujian parsing konfigurasi .env & allowed users
├── test_correlation.py          # Pengujian sliding-window, throttling, dan campaign detection
├── test_database.py             # Pengujian parsing event, timestamp, dan labeling
├── test_edr.py                  # Pengujian EDR router, KSC 15.1 OpenAPI, dan TrendMicro
├── test_extended_perimeters.py  # Pengujian Cloudflare Edge WAF & Fortinet FortiGate
├── test_mitigation.py           # Pengujian Palo Alto, Imperva, Akamai, dan Redis helpers
├── test_ml.py                   # Pengujian ML inference, Cases, SLA, Ticketing, AI Copilot
├── test_playbook.py             # Pengujian AST Safe Evaluator dan eksekusi DAG Playbook
└── test_utils.py                # Pengujian validasi IP, whitelist, dan ekstraksi skor
```

---

## 3. Menjalankan Automated Tests

### A. Menggunakan Script CLI (Disarankan)
```bash
./minisoar.sh test
```

### B. Menggunakan Pytest Langsung
```bash
# Menjalankan seluruh test suite
pytest --assert=plain -v

# Menjalankan modul test spesifik
pytest --assert=plain -v tests/test_edr.py
pytest --assert=plain -v tests/test_extended_perimeters.py
pytest --assert=plain -v tests/test_ml.py
```

---

## 4. Mode Simulasi & Mock Fixtures

MiniSOAR menyediakan mode simulasi penuh (`MINISOAR_MOCK=1`) yang memungkinkan pengujian seluruh pipeline SOAR secara lokal tanpa memerlukan kredensial server produksi:
- Perimeter mitigasi mensimulasikan respons `200 OK` dan pencatatan audit.
- EDR server mensimulasikan pembuatan token sesi OpenAPI dan isolasi host.
- AI Copilot menghasilkan respon analisis keamanan terstruktur tanpa melakukan panggilan API berbayar.
