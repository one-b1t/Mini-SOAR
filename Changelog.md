# Changelog

Semua perubahan penting pada proyek **MiniSOAR** akan dicatat di dokumen ini.

Format changelog berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.1] - 2026-06-11

### Fixed
- **Whitelist Test Bug:** Memperbaiki bug pada `test_whitelist` di [test_utils.py](file:///c:/Users/rezy0/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/tests/test_utils.py) yang memanggil `is_ip_whitelisted` tanpa argumen `nets` yang wajib disuplai.

### Changed
- Dokumentasi [Context.md](file:///c:/Users/rezy0/OneDrive%20-%20Kementerian%20Komunikasi%20dan%20Informatika/Documents/Kantor/Program/MiniSOAR/Context.md) dipulihkan kembali dan dilengkapi dengan Decision Log sesuai aturan pengembangan codebase.

## [1.2.0] - 2026-05-26


### Added
- Parameter `MINISOAR_BLOCKING_MODE` di dalam berkas `.env` untuk mendukung 3 mode pemblokiran: `AUTO`, `SEMI`, dan `MANUAL`.
- Pembaruan dokumentasi integrasi AI dan panduan mode pemblokiran di `Readme.md`.

### Fixed
- **Pengiriman Reputasi ke AI/ML:** Memperbaiki bug di `14_redis_telegram_alert.py` yang mengirimkan reputasi IP kosong (`""`) ke fungsi `predict_block`, yang sekarang memanfaatkan data reputasi riil dari cache AbuseIPDB.
- **Path Dinamis di Script Pengujian:** Mengubah hardcoded path absolut profil user pada `scratch/test_predict.py` menjadi resolusi path dinamis berbasis `Path(__file__)`.

### Changed
- Dokumentasi `Context.md` diperbarui untuk menggambarkan status integrasi ML terkini dengan mode `AUTO`.
