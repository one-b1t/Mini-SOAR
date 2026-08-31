# ⚡ MiniSOAR Wiki & Dokumentasi Resmi

MiniSOAR adalah purwarupa *Security Orchestration, Automation, and Response* (SOAR) ringan yang didesain khusus untuk mengotomatisasi pemblokiran IP mencurigakan melalui integrasi ELK (Logstash), Telegram Bot, dan *Machine Learning*.

## 📖 1. Penjelasan Sistem (Architecture)

MiniSOAR bekerja dengan cara mendengarkan (berlangganan) pada antrean notifikasi (Redis/Logstash). Saat sebuah anomali web (XSS, SQLi, LFI, RCE) terdeteksi, MiniSOAR akan mengambil alih alur dengan langkah berikut:
1. **Penyaringan (Filtering):** Memeriksa apakah IP penyerang berada dalam *Whitelist* atau *Bypass list*.
2. **Kalkulasi ML (AI Inference):** Mengukur skor probabilitas serangan berdasarkan model historis (akurasi, reputasi, tipe serangan).
3. **Validasi Mode:** Mengeksekusi blokir secara otomatis ke WAF tujuan (Akamai, Imperva, Palo Alto) ATAU melempar keputusan kepada Manusia via tombol persetujuan di Telegram.

---

## 🚀 2. Quick Start (Mulai Cepat)

### Persyaratan Sistem
- Python 3.10+
- Redis Server (untuk *Message Queue*)
- Elasticsearch (opsional, dibutuhkan untuk pelatih ulang ML)
- Telegram Bot Token & Chat ID

### Menjalankan MiniSOAR
1. **Menyalin Konfigurasi:**
   Buat file `.env` (bisa dengan menyalin `env.example` jika ada) dan isi Token Bot Telegram serta IP Redis Anda.
2. **Menjalankan Daemon Utama:**
   Jalankan program *listener* utama yang tidak boleh mati.
   ```powershell
   python 14_redis_telegram_alert.py
   ```
3. **Menguji Notifikasi (Simulasi):**
   Gunakan alat *mock* bawaan untuk menembakkan 30 jenis serangan campuran.
   ```powershell
   python scratch/mock_traffic.py
   ```

---

## ⚙️ 3. Konfigurasi & Mode Operasi

MiniSOAR mengadopsi prinsip operasi keamanan tiga tingkat (`MINISOAR_BLOCKING_MODE` di dalam `.env`):

*   **MANUAL**: Sangat aman. Tidak ada pemblokiran otomatis. Seluruh anomali akan terkirim ke Telegram menunggu tombol "Block" ditekan.
*   **SEMI**: Hibrida. AI akan mengambil alih. Jika skor kepastian AI **> 70%**, IP langsung diblokir (*Auto-Mitigation*). Jika skor meragukan (<70%), bot Telegram akan bertanya kepada Admin.
*   **AUTO**: Sepenuhnya diserahkan ke AI. Seluruh prediksi berbahaya akan di-*drop* di WAF.

### Berkas Konfigurasi Pendukung
- **`minisoar-perimeter.yml`**: Memetakan target mitigasi. Anda dapat merutekan serangan di `api.target.com` ke Imperva, dan `*.target.com` (wildcard) ke Akamai.
- **`minisoar-whitelist.txt`**: IP/CIDR yang dijamin bebas blokir, namun **notifikasinya tetap dikirim**. Admin tidak akan melihat tombol "Block" di Telegram.
- **`minisoar-bypass.txt`**: IP/CIDR mutlak yang diabaikan sepenuhnya (*silent drop*). Notifikasi tidak akan membanjiri Telegram.

---

## 🧠 4. Panduan Machine Learning (Retraining)

Fitur ML di MiniSOAR bertugas mempelajari *behavior* tombol yang diklik oleh Admin di masa lalu (apakah admin lebih sering memblokir SQLi atau justru mengabaikannya). 

Data ini ditarik dari Elasticsearch dan sudah dioptimalkan menggunakan kueri *Bulk Terms* secara massal agar **10.000 log** dapat ditarik secara kilat tanpa masalah latensi HTTP (bebas *N+1 Query Bottleneck*).

### Cara Mentraining Model Baru:
**Langkah 1: Ekstraksi Data (Export)**
Tarik data terbaru dari Elasticsearch. Jika ES mati/kosong, sistem otomatis mencetak 10.000 baris data sintetis. Dataset ini kini sangat detail mencakup *Source/Target IP, Port,* hingga *Domain/URL*.
```powershell
python -m minisoar.ml.export
```
*(Anda akan melihat output pembuatan `dataset.csv`)*

**Langkah 2: Proses Training**
Latih data tersebut. Skrip ini menggunakan *Logistic Regression*, otomatis mengeksekusi *One-Hot Encoding* pada jenis serangan baru, dan mencetak laporan metrik (*Accuracy / ROC-AUC*).
```powershell
python -m minisoar.ml.train
```
*(Hasilnya akan disimpan sebagai `baseline_model.joblib`)*

**Langkah 3: Terapkan ke Otak Daemon**
Daemon utama (Skrip 14) hanya membaca model ke dalam RAM satu kali di awal *(on boot)*. Anda wajib merestart *daemon* tersebut agar menggunakan kepintaran yang baru:
1. Tekan `Ctrl+C` pada *Daemon*.
2. Nyalakan lagi: `python 14_redis_telegram_alert.py`.

---

*Wiki ini dibuat dan dioptimasi oleh AI Assistant (Antigravity).*
