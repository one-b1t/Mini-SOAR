# Changelog

Semua perubahan penting pada proyek **MiniSOAR** akan dicatat di dokumen ini.

Format changelog berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.2] - 2026-06-12

### Added
- **Timed Commit/Activation Batching:** Menambahkan mekanisme penundaan commit berkala (`MINISOAR_COMMIT_INTERVAL`, default 1 jam) untuk Palo Alto dan Akamai guna menghindari overload CPU dan limitasi rate API WAF.
- **Logstash Configurations Grouping:** Mengelompokkan semua berkas konfigurasi Logstash (`01-detection.conf`, `02-alert-redis.conf`, `minisoar-perimeter.yml`, `minisoar-whitelist.yml`) ke dalam folder `/logstash/`.
- **Temporary Perimeter Blocking & Dynamic Extension:** Pemblokiran perimeter keamanan (Imperva, Palo Alto, Akamai) kini bersifat sementara (10 menit, dikonfigurasi via `MINISOAR_BLOCK_DURATION`). Jika ada serangan lagi sebelum masa blokir habis, durasi blokir otomatis diperpanjang 10 menit.
- **Automatic IP Unblocking Daemon:** Worker daemon secara berkala memantau status pemblokiran via Redis Sorted Set (`minisoar:pending_unblocks`) dan melakukan unblocking otomatis saat masa blokir berakhir.
- **Unmapped Perimeter Fallback Blocking:** Jika perimeter website unmapped/tidak dikenali, dan prediksi blokir AI berkekuatan tinggi (high confidence), pemblokiran otomatis dialihkan untuk diproses pada Imperva saja.

### Changed
- **Folder Reorganization:** Memindahkan file operational wrapper (`export_dataset.py`, `train_baseline.py`) ke folder `/scripts/` dengan import path dinamis.
- **Documentation Updates:** Memperbarui bagan struktur proyek dan tabel file konfigurasi pendukung di `Readme.md` serta Decision Log di `Context.md`.
- **Bot Handler Upgrades:** Mengubah bot command `/blockon*`, `/unblockon*`, dan inline button callback untuk menggunakan core API pemblokiran sementara dan sinkronisasi status ke Redis.

### Fixed
- **Location-Independent Script Execution:** Memperbaiki resolusi berkas `.env`, `dataset.csv`, dan `baseline_model.joblib` di `export_dataset.py` dan `train_baseline.py` agar bernilai relatif terhadap letak kode program (`Path(__file__)`) dan bukan direktori kerja saat ini (`Path.cwd()`), sehingga skrip dapat dipanggil secara aman dari folder `/scripts/`.
- **Conditional Commit Status Notification:** Memperbaiki notifikasi alert Telegram agar hanya menampilkan status "Commit pending" jika target pemblokiran melibatkan Palo Alto atau Akamai, sedangkan pemblokiran yang hanya melibatkan Imperva (real-time) tidak lagi menampilkan status tersebut untuk menghindari kebingungan analis.

## [1.2.1] - 2026-06-11

### Added
- **Perimeter Environment Variables:** Menambahkan contoh variabel lingkungan perimeter keamanan (Imperva, Palo Alto, Akamai) ke [env.example](file:///c:/Users/bandar/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/env.example).
- **Initial IP Whitelist Configuration:** Membuat berkas [minisoar-whitelist.txt](file:///c:/Users/bandar/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/minisoar-whitelist.txt) yang menampung daftar awal segmen IP/CIDR internal komdigi untuk mencegah kekeliruan pemblokiran.

### Fixed
- **Whitelist Test Bug:** Memperbaiki bug pada `test_whitelist` di [test_utils.py](file:///c:/Users/rezy0/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/tests/test_utils.py) yang memanggil `is_ip_whitelisted` tanpa argumen `nets` yang wajib disuplai.

### Changed
- Dokumentasi [Context.md](file:///c:/Users/rezy0/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/Context.md) dipulihkan kembali dan dilengkapi dengan Decision Log sesuai aturan pengembangan codebase.
- Mengintegrasikan variabel lingkungan mitigasi perimeter keamanan ke dalam [Readme.md](file:///c:/Users/bandar/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/Readme.md).
- Memperbarui petunjuk instalasi Linux di [Readme.md](file:///c:/Users/bandar/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/Readme.md) dengan panduan pembuatan virtual environment (`venv`) untuk mengatasi error `externally-managed-environment` (PEP 668).

## [1.2.0] - 2026-05-26


### Added
- Parameter `MINISOAR_BLOCKING_MODE` di dalam berkas `.env` untuk mendukung 3 mode pemblokiran: `AUTO`, `SEMI`, dan `MANUAL`.
- Pembaruan dokumentasi integrasi AI dan panduan mode pemblokiran di `Readme.md`.

### Fixed
- **Pengiriman Reputasi ke AI/ML:** Memperbaiki bug di `14_redis_telegram_alert.py` yang mengirimkan reputasi IP kosong (`""`) ke fungsi `predict_block`, yang sekarang memanfaatkan data reputasi riil dari cache AbuseIPDB.
- **Path Dinamis di Script Pengujian:** Mengubah hardcoded path absolut profil user pada `scratch/test_predict.py` menjadi resolusi path dinamis berbasis `Path(__file__)`.

### Changed
- Dokumentasi `Context.md` diperbarui untuk menggambarkan status integrasi ML terkini dengan mode `AUTO`.
