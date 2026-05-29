# Context Pengembangan miniSOAR + Machine Learning Decision Engine

Dokumen ini merangkum seluruh diskusi dan keputusan desain terkait pengembangan **miniSOAR dengan Machine Learning untuk auto-verification & auto-block IP**, sebagai konteks bersama (human + Codex).

---

## 1. Kondisi Awal Sistem (Existing)

### Arsitektur saat ini
- **Elastic Stack (Free Version)**
  - Elasticsearch: penyimpanan log & event
  - Logstash: filtering & detection (`01-detection.conf`, `02-alert-redis.conf`)
- **Redis**
  - Buffer event & alert
  - Builder notifikasi Telegram (`redis-telegram-alert.py`)
- **Telegram Bot**
  - Mengirim alert anomaly ke SOC
  - Inline button untuk verifikasi manual (BLOCK / dll)
- **Firewall (Imperva On‑prem)**
  - Di-trigger via API oleh bot handler (`tele-soar.py`)

### Jenis anomaly
- Webshell burst (minor/major)
- Burst access
- Distributed error
- Dll

SOC saat ini melakukan **human verification** dengan klik tombol Telegram.

---

## 2. Tujuan Pengembangan

1. Mengubah keputusan SOC (klik Telegram) menjadi **label training ML**
2. Mengembangkan **Machine Learning decision engine** untuk:
   - AUTO BLOCK (confidence tinggi)
   - NEEDS SOC REVIEW (confidence ragu)
   - AUTO ALLOW / IGNORE
3. Transisi bertahap:
   - Dual-channel (SOC + ML shadow mode)
   - ML-first routing
   - SOC hanya untuk kasus ragu / override

Prinsip utama: **aman, explainable, mudah diintegrasikan**.

---

## 3. Pendekatan Machine Learning yang Dipilih

### Bukan:
- ❌ Deep Learning
- ❌ Elastic ML berbayar
- ❌ LLM sebagai decision maker

### Digunakan:
- **Supervised tabular classification**
- **Human-in-the-loop / Active Learning**

### Tools utama
- Python
- scikit-learn (baseline)
- LightGBM / XGBoost (model utama)
- Pandas (feature engineering)
- (Opsional) MLflow, FastAPI, EvidentlyAI

Model berperan sebagai **Decision Engine**, bukan detector baru.

---

## 4. Arsitektur Target (High Level)

1. Logstash mendeteksi anomaly
2. Python builder membuat **event JSON standar + event_id deterministik**
3. Event:
   - Disimpan ke Elasticsearch (`minisoar-events-*`)
   - Dipublish ke Redis
4. Redis dikonsumsi oleh:
   - SOC notifier (Telegram SOC)
   - ML worker (shadow mode / scoring)
5. SOC klik Telegram → label disimpan (`minisoar-labels-*`)
6. ML belajar dari data SOC
7. ML mengambil keputusan otomatis jika confidence tinggi
8. SOC tetap tersedia untuk override / review

---

## 5. Phase 0 – Fondasi Data (WAJIB)

### Tujuan Phase 0
- Semua anomaly punya **event_id stabil**
- Semua event & keputusan SOC tersimpan
- Event & label bisa di-join untuk training

### Index Elasticsearch

#### `minisoar-events-*`
Field utama:
- `@timestamp`
- `event_id` (keyword, deterministik)
- `detector_type`
- `severity`
- `asset.id`
- `src.ip`
- `perimeter.vendor`
- `reputation.score`
- `metrics.hit_count`
- `metrics.window_seconds`
- `samples.paths_top`

#### `minisoar-labels-*`
Field utama:
- `@timestamp`
- `event_id`
- `label` (block / allow / ignore / unblock)
- `actor.username`
- `reason_code` (opsional)

---

## 6. Event ID Deterministik

### Konsep
Event yang sama dalam window waktu yang sama → **event_id sama**

### Komponen event_id
- detector_type
- asset_id
- src_ip
- time_bucket (dibulatkan per window)
- signature (hash dari top paths / rule_id)

### Fungsi Python
```python
make_event_id(detector_type, asset_id, src_ip, ts_epoch, window_seconds, top_paths)
```

Digunakan di **Python builder**, bukan di Logstash.

---

## 7. Kontrak Data Event (Template)

Event dikirim ke Redis & disimpan ke ES dalam bentuk JSON standar:
- metadata (asset, perimeter)
- metrics (hit_count, status ratio)
- samples (top request paths)
- reputation & geo
- event_id

Event disarankan di-index ke ES dengan `_id = event_id` (idempotent).

---

## 8. Telegram Callback sebagai Label Training

### Callback Data (ringkas)
- `BLK|<event_id>`
- `ALW|<event_id>`
- `IGN|<event_id>`
- `UNB|<event_id>`

### Saat SOC klik
1. Parse action + event_id
2. Ambil event (ES lookup)
3. Simpan label ke `minisoar-labels-*`
4. Jika BLOCK → trigger firewall
5. Edit message Telegram

SOC decision = **ground truth label**.

---

## 9. Dual-Channel Strategy

### Tahap awal
- Event yang sama dikirim ke:
  - SOC (Telegram)
  - ML worker (shadow mode)

### Tahap lanjut
- ML ambil keputusan utama
- SOC hanya menerima:
  - cases dengan confidence ragu
  - notifikasi auto-block (audit)

---

## 10. Decision Logic (Target)

Berdasarkan probabilitas `p_block`:
- `p >= 0.98` → AUTO BLOCK
- `0.6 <= p < 0.98` → SOC REVIEW
- `< 0.6` → AUTO ALLOW / IGNORE

Ditambah **guardrails**:
- allowlist
- rate-limit auto-block
- internal / partner IP

---

## 11. Phase 0 – Definition of Done

Phase 0 dianggap selesai jika:
- [ ] Semua anomaly punya event_id
- [ ] Event tersimpan di `minisoar-events-*`
- [ ] SOC click tersimpan di `minisoar-labels-*`
- [ ] Bisa join event + label menjadi dataset training

---

## 12. Next Phase (Setelah Phase 0)

### Phase 1
- Export dataset training (events + labels)
- Baseline Logistic Regression

### Phase 2
- Upgrade ke LightGBM
- Shadow mode (no auto-block)

### Phase 3
- Partial automation (high confidence only)

---

## 13. Prinsip Penting

- Safety > automation
- Precision auto-block > recall
- SOC override selalu tersedia
- Semua keputusan harus bisa diaudit

---

Dokumen ini adalah **single source of context** untuk koordinasi dengan Codex / developer lain.

