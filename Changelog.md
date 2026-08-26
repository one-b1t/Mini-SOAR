# Changelog

Semua perubahan penting pada proyek **MiniSOAR** akan dicatat di dokumen ini.

Format changelog berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.3.4] - 2026-08-26

### Added
- **Trend Micro Vision One Singapore Region Integration**: Menambahkan kredensial API Key Bearer token JWT dan konfigurasi base URL regional Singapore (`https://api.sg.xdr.trendmicro.com`) pada berkas `.env` untuk integrasi modul EDR.
- **Vision One v3.0 EndpointSecurity Native Support (`find_endpoint_by_ip`)**: Memperbarui adapter EDR `minisoar/edr/trendmicro.py` untuk secara native mendukung REST API v3.0 EndpointSecurity (`/v3.0/endpointSecurity/endpoints`) dengan resolusi IP address dan agent GUID, serta health check otomatis.

## [1.3.3] - 2026-08-21


### Added
- **Dynamic Native Telegram Command Menu (`set_my_commands`)**: Mengintegrasikan hook `post_init` pada bot Telegram sehingga menu popup command bawaan Telegram (autocomplete saat mengetik `/` atau tombol Menu Telegram) secara dinamis hanya menampilkan command untuk Perimeter dan EDR yang kredensialnya benar-benar telah dikonfigurasi di file `.env`.
- **Active Blocklist & IoC Query Command (`/blocked` & `./minisoar.sh blocked`)**: Menambahkan command bot Telegram (`/blocked [perimeter|edr]`, `/blocklist`, `/bl`) dan CLI (`./minisoar.sh blocked [target]`) untuk menginspeksi secara real-time seluruh IP yang sedang aktif diblokir pada Perimeter Security (Redis ZSET dengan sisa durasi TTL) dan terdaftar pada EDR IoC Repository (Kaspersky KSC & Trend Micro).
- **Dynamic Configured Perimeter Help Menu (`get_configured_providers`)**: Mengoptimalkan menu bantuan Telegram Bot (`/help`, `/start`) agar secara cerdas hanya merender command untuk Perimeter (Imperva, Palo Alto, Akamai, Cloudflare, FortiGate) dan EDR Server yang kredensialnya benar-benar telah dikonfigurasi di file `.env`, menjadikan antarmuka bot jauh lebih ringkas, bersih, dan kontekstual.
- **Visual EDR IoC Protection Badge (`inject_edr_line`)**: Menambahkan baris badge visual `• EDR IoC: 🛡️ Kaspersky & Trend Micro (Synced)` pada kartu pesan alert Telegram secara otomatis setiap kali IP penyerang telah terdaftar dalam repositori IoC / Suspicious Objects EDR.
- **Dedicated Telegram Action Log Notifications (`notify_action_log`)**: Mengirimkan notifikasi audit otomatis ke channel operasional Telegram (`TELEGRAM_PROCESS_CHAT_ID`) saat sinkronisasi IoC EDR berhasil dilakukan oleh Threat Intel maupun Playbook.
- **Security Alert & Traffic Simulator (`simulate_alert.sh` & `./minisoar.sh simulate`)**: Script bash interaktif dan berbasis CLI untuk menginjeksi berbagai payload alert serangan keamanan (Webshell Immediate, SQL Injection, XSS, Brute Force 401 Burst, C2 Communication IoC, Path Probe, dan Mode Burst Multi-Serangan) langsung ke antrean Redis (`logstash_alert_queue`) guna memvalidasi respon Alert Daemon, eksekusi Playbook, notifikasi Telegram, dan pendeteksian anomali secara real-time.
- **Threat Intelligence EDR IoC Auto-Sync (`sync_edr_ioc_if_malicious`)**: Otomasi pendaftaran IP penyerang/C2 yang terkonfirmasi berbahaya oleh Threat Intelligence (AbuseIPDB reputation $\ge 50\%$, permanent block, ML prediction, atau serangan webshell/injeksi kritis) ke daftar Suspicious Objects / IoC Repository EDR (Kaspersky KSC & Trend Micro Vision One) dengan caching 24 jam di Redis.
- **EDR Safety Policy (`MINISOAR_EDR_ALLOW_AUTO_ISOLATE=0`)**: Menambahkan pengaman kebijakan agar isolasi host endpoint otomatis dinonaktifkan secara default untuk melindungi ketersediaan server web produksi, sembari tetap mempertahankan fungsi isolasi manual oleh analis SOC via Telegram bot (`/isolate_host`).
- **WSL PowerShell Execution Wrapper (`run-wsl.ps1`)**: Script helper PowerShell untuk memfasilitasi eksekusi lifecycle command, CLI `minisoar.sh`, dan interactive bash shell secara mulus di environment WSL (Windows Subsystem for Linux) langsung dari Windows host terminal dengan translasi direktori otomatis, dukungan custom distro, dan propagasi exit code.
- **Redis Service Auto-Provisioning & Health CLI (`minisoar.sh`)**: Otomasi instalasi dan verifikasi layanan `redis-server` di WSL/Linux pada `cmd_setup`, integrasi diagnostik Redis Queue & Elasticsearch pada `cmd_doctor`, serta penambahan alias perintah `./minisoar.sh health`.

### Changed
- **Total Elimination of Raw JSON Fallback (`build_message`)**: Menghapus seluruh fallback format raw JSON pada modul pembentuk pesan notifikasi Telegram, menggantikannya dengan format kartu alert Markdown SOC yang terstruktur, human-readable, dan konsisten untuk seluruh kategori ancaman (termasuk C2 Communication, Ransomware Activity, Random URL Spray, dan Generic Anomaly).
- **Permission Safe Path Resolution (`resolve_log_path`)**: Menambahkan pemeriksaan `os.access(parent, os.W_OK)` agar proses non-root di lingkungan WSL otomatis melakukan fallback ke direktori kerja lokal jika direktori sistem `/var/log/` tidak memiliki izin tulis.
- **Repository Hygiene (`.gitignore`)**: Menambahkan `run-wsl.ps1` dan `*.ps1` ke daftar pengecualian git repository agar berkas otomasi lokal host Windows tidak ter-commit ke repositori.
- **WSL Virtualenv Compatibility**: Menggunakan `virtualenv --always-copy` pada `cmd_setup` untuk menangani batasan symlink NTFS/DrvFs pada mount path WSL (`/mnt/f/...`).
- **Playbook EDR Enhancement**: Menambahkan step registrasi `edr.add_ioc` pada Playbook Webshell Immediate (`01_webshell_immediate.yml`) dan Web Injection (`03_injection_attacks.yml`).

## [1.3.2] - 2026-08-18

### Added
- **Threat Intelligence Summary (`/intel <ip>`)**: Perintah Telegram bot untuk menampilkan rangkuman intelijen IP (status Whitelist, total hit keamanan ES, event serangan terbaru, website terkait, dan jumlah host EDR).
- **SOAR Health Dashboard (`/health`)**: Perintah Telegram bot untuk mendiagnosa kesehatan sistem secara real-time (status antrean Redis, Elasticsearch cluster health, AI Copilot model, dan konektivitas EDR).
- **Live Whitelist Management (`/whitelist_add`, `/whitelist_remove`, `/whitelists`)**: Fitur pengelolaan berkas whitelist IP/CIDR secara langsung melalui Telegram tanpa perlu edit file server manual.
- **Interactive Case Action Buttons**: Tombol interaksi cepat (`[✅ Resolve Case]`, `[🎟️ Sync Ticket]`, `[📄 Export MD]`) pada laporan insiden `/case <case_id>`.

## [1.3.1] - 2026-08-18

### Changed
- **Telegram Bot Command Standardization**: Mengubah seluruh perintah Telegram bot menjadi format `snake_case` yang rapi dan konsisten (misal `/block_imperva`, `/unblock_imperva`, `/trace_imperva`, `/block_palo`, `/isolate_host`, `/ask_ai`).
- **Telegram Command Aliases**: Menambahkan alias singkatan untuk mengeksekusi perintah lebih cepat dari Telegram (misal `/bi`, `/ti`, `/bp`, `/cp`, `/ih`, `/ai`). Alias terdaftar di sistem dan didokumentasikan di `docs/api.md`, namun disembunyikan dari `/help` agar tampilan menu utama tetap bersih.
- **Telegram HTML Parse Mode**: Mengubah `parse_mode` pesan notifikasi dan balasan bot menjadi **Telegram HTML (`parse_mode="HTML"`)**, mencegah error parsing karakter khusus pada IP address, hash, log trace, atau payload URL.
- **Easy Copyable Syntax**: Memperbarui pesan error/penggunaan format perintah dengan template `<code>` dan contoh konkret yang dapat disalin dengan 1 ketukan (*1-tap copy*) di aplikasi Telegram.
- **Unit Test Expansion**: Menambahkan `tests/test_bot.py` untuk menguji generator format HTML usage dan validasi pengguna bot.

## [1.3.0] - 2026-08-18

### Added
- **EDR Server Integration (Kaspersky KSC & TrendMicro Vision One):** Menambahkan package `minisoar/edr/` yang menghubungkan MiniSOAR dengan server EDR untuk melakukan isolasi host endpoint (`isolate_endpoint`), pemulihan jaringan (`restore_endpoint`), sinkronisasi IoC / suspicious objects (`add_edr_ioc`), dan query inventory endpoint (`query_endpoint`).
- **EDR Telegram Bot Commands:** Menambahkan perintah `/isolatehost`, `/restorehost`, `/queryhost`, `/addedrioc`, dan `/edrstatus` pada `minisoar/bot.py`.
- **EDR Playbook Actions & Template:** Menambahkan action handler `edr.isolate_endpoint`, `edr.restore_endpoint`, `edr.add_ioc`, serta playbook bawaan `04_host_compromise_edr.yml`.
- **Declarative YAML Playbook Engine:** Menambahkan package `minisoar/playbook/` yang mendukung perancangan alur kerja mitigasi modular berbasis YAML (`minisoar/playbooks/`), parser skema aman, evaluasi kondisi berbasis AST, registri aksi (`mitigation.auto_block`, `notification.telegram`, `database.store_label`), dan eksekusi bertahap (DAG).
- **Default Playbooks:** Menyediakan playbook bawaan untuk `01_webshell_immediate.yml`, `02_bruteforce_attack.yml`, `03_injection_attacks.yml`, `04_host_compromise_edr.yml`, dan `99_default_fallback.yml`.
- **Alert Correlation & Anti-Alert Storm Engine:** Menambahkan `minisoar/correlation.py` dengan Redis-backed sliding-window aggregation, alert throttling untuk mencegah kebanjiran notifikasi Telegram saat serangan berkelanjutan, dan deteksi multi-IP campaign (> 5 penyerang).
- **Unit Test Suite:** Menambahkan `tests/test_playbook.py`, `tests/test_correlation.py`, dan `tests/test_edr.py` dengan cakupan pengujian lengkap.

### Changed
- **Modernized UTC Datetimes:** Memperbarui penggunaan `datetime.datetime.utcnow()` di `minisoar/database.py` menjadi `datetime.datetime.now(datetime.timezone.utc)` untuk kompatibilitas penuh Python 3.14+.
- **Daemon Integration:** Mengintegrasikan Correlation Engine, Playbook Engine, dan EDR Connectivity Check ke dalam loop worker `minisoar/daemon.py` dengan mode `PLAYBOOK` dan kompatibilitas mundur penuh untuk mode `AUTO`/`SEMI`/`MANUAL`.

## [1.2.4] - 2026-06-18

### Added
- **Enhanced GitLab CI/CD Pipeline:** Menambahkan modular stages/jobs (`security`, `lint`, `test`) yang mencakup scanning kredensial (`gitleaks`), pemindaian kerentanan kode Python (`bandit`), pemeriksaan standard gaya kode (`ruff`), type checking statis (`mypy`), dan pengujian otomatis draft/non-blocking (`pytest`) yang dikonfigurasi agar hanya berjalan melalui trigger manual (`when: manual`).
- **GitHub Actions Workflow:** Membuat konfigurasi workflow `.github/workflows/ci.yml` yang setara dengan pipeline GitLab CI untuk menjalankan seluruh pemeriksaan kualitas dan keamanan, dikonfigurasi agar hanya dapat dijalankan secara manual (`workflow_dispatch`).

## [1.2.3] - 2026-06-15

### Added
- **GitLab CI/CD Pipeline Configuration:** Menambahkan berkas `.gitlab-ci.yml` untuk mengintegrasikan static code analysis dengan SonarQube menggunakan model `sonarsource/sonar-scanner-cli`.

### Changed
- **GitLab CI/CD Improvements:** Memperbarui konfigurasi `.gitlab-ci.yml` untuk menyertakan runner tags (`sonar-scanner`), caching directory `.sonar/cache`, opsi menunggu Quality Gate (`sonar.qualitygate.wait=true`), serta membatasi pemicu pipeline hanya untuk branch `dev`.

### Fixed
- **Bypass Blocking for Whitelisted IPs:** Memperbaiki bug pada mode pemblokiran `AUTO` dan `SEMI` di `minisoar/daemon.py` yang tetap memblokir IP whitelisted apabila prediksi ML bernilai bahaya (high confidence). Sekarang, sistem secara mutlak melompati instruksi pemblokiran jika IP terdaftar dalam whitelist.

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
