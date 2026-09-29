# Design Specification: Pengaktifan Parsial Kaspersky Security Center (KSC)

**Tanggal:** 29 September 2026  
**Status:** Approved  
**Topik:** Pengaktifan fitur query host, isolasi endpoint, restorasi endpoint, dan diagnostik pada Kaspersky KSC 15.1 OpenAPI dengan penonaktifan terisolasi khusus pada fitur Add IoC.

---

## 1. Latar Belakang & Tujuan

Sebelumnya, Kaspersky Security Center (KSC) dinonaktifkan secara total di `PERIMETER_NONAKTIF` bersama Cloudflare dan FortiGate karena implementasi repositori IoC KSC (`IoCRepository.AddObject`) belum memiliki alur konfigurasi listener/repositori yang jelas di lingkungan operasional.

Namun, organisasi memiliki lisensi dan infrastruktur Kaspersky Security Center (KSC) 15.1 OpenAPI yang aktif untuk manajemen endpoint. Fitur-fitur inti endpoint seperti:
- Pencarian inventori host berdasarkan alamat IP (`find_host_by_ip`),
- Isolasi jaringan host endpoint terkompromi (`isolate_host`),
- Pemulihan jaringan endpoint (`restore_host`), dan
- Diagnostik konektivitas EDR (`check_connectivity`),

tetap dibutuhkan oleh analis SOC dan playbook otomatis MiniSOAR.

Tujuan dari perubahan ini adalah:
1. Mengeluarkan `kaspersky` dari daftar perimeter mati total (`PERIMETER_NONAKTIF`).
2. Mengaktifkan kembali seluruh endpoint operasional KSC (query, isolasi, pemulihan, dan health check).
3. Menerapkan guardrail defensif berlapis khusus pada fungsi `Add IoC` Kaspersky agar pendaftaran IoC otomatis (`provider="all"`) hanya diarahkan ke Trend Micro Vision One, dan pemanggilan manual eksplisit KSC Add IoC ditolak secara aman dengan pesan informatif.

---

## 2. Arsitektur & Komponen Terdampak

### 2.1 Konfigurasi Global (`minisoar/config.py`)
- `PERIMETER_NONAKTIF` diperbarui menjadi:
  ```python
  PERIMETER_NONAKTIF: frozenset[str] = frozenset({"cloudflare", "fortigate"})
  ```
- Fungsi `is_perimeter_active("kaspersky")` kini mengembalikan `True`.
- Pesan `perimeter_disabled_message` diperbarui untuk mencantumkan Kaspersky sebagai EDR aktif (dengan batasan IoC).

### 2.2 Konektor Kaspersky EDR (`minisoar/edr/kaspersky.py`)
- **Direct Connector Guard pada `add_ioc()`:**
  Fungsi `add_ioc(ioc_type, ioc_value, *, comment=...)` dipasangi guardrail internal di baris awal. Fungsi langsung mengembalikan:
  ```python
  return False, "Fitur Add IoC pada Kaspersky KSC dinonaktifkan (repositori IoC KSC tidak aktif/belum dikonfigurasi). Operasi isolasi dan query host tetap aktif."
  ```
  Ini mencegah eksekusi HTTP POST ke `IoCRepository.AddObject` dan panggilan login KSC yang tidak perlu, bahkan jika modul diimpor langsung tanpa melalui controller.
- Fungsi `find_host_by_ip()`, `isolate_host()`, `restore_host()`, dan `check_connectivity()` tetap aktif penuh dan siap melayani permintaan.

### 2.3 Kontroller Terpadu EDR (`minisoar/edr/core.py`)
- **`add_edr_ioc(ioc_type, ioc_value, *, provider="all", comment=...)`:**
  - Jika `provider == "all"`: Daftar provider yang dieksekusi untuk IoC hanya `trendmicro` (Kaspersky otomatis dilewati tanpa mencatat error kegagalan, sehingga respons keseluruhan tetap sukses).
  - Jika `provider` dipanggil eksplisit untuk Kaspersky (`kaspersky`, `ksc`, `kl`): Fungsi mengembalikan `False` beserta pesan penolakan informatif yang menyarankan penggunaan Trend Micro Vision One.
- **`query_endpoint(ip, *, provider="all")`:**
  - Menjalankan pencarian inventori host di Kaspersky KSC jika `provider in {"all", "kaspersky"}`.
- **`isolate_endpoint(target, *, provider="all", reason=...)`:**
  - Mengizinkan penargetan Kaspersky KSC (`provider="kaspersky"` atau `provider="all"`).
- **`restore_endpoint(target, *, provider="all")`:**
  - Mengizinkan restorasi host pada Kaspersky KSC.
- **`check_all_edr_connectivity()`:**
  - Mengeksekusi diagnostik konektivitas KSC melalui `kaspersky.check_connectivity()`.

### 2.4 Daemon Alert & Integrasi Bot (`minisoar/daemon.py` & `minisoar/bot.py`)
- **Sinkronisasi Threat Intel (`sync_edr_ioc_if_malicious`):**
  - Pemanggilan `add_edr_ioc("ip", ip, ...)` secara default beroperasi pada `all` sehingga langsung mendaftarkan IP berbahaya ke Trend Micro Vision One secara mulus.
  - Teks notifikasi Telegram audit disesuaikan agar menyatakan pendaftaran IoC diarahkan ke Trend Micro Vision One.
- **Bot Command Handler (`/add_edr_ioc`):**
  - Jika operator memasukkan `/add_edr_ioc <ip> all`, bot mendaftarkan ke Trend Micro.
  - Jika operator memasukkan `/add_edr_ioc <ip> kaspersky`, bot membalas dengan penolakan ramah bahwa Add IoC KSC dinonaktifkan.
- **Bot Command Handler (`/isolate_host`, `/restore_host`, `/query_host`):**
  - Kini dapat menerima target `kaspersky` maupun `all` dan memprosesnya ke server KSC.

---

## 3. Data Flow

```
1. Query Host (/query_host <ip>):
   Operator/Playbook -> minisoar/edr/core.py -> kaspersky.find_host_by_ip -> KSC API (HostGroup.FindHosts) -> Endpoint Data

2. Isolate Host (/isolate_host <ip> kaspersky):
   Operator/Playbook -> minisoar/edr/core.py -> kaspersky.isolate_host -> KSC API (HostGroup.SetHostNetworkIsolation) -> Success

3. Restore Host (/restore_host <ip> kaspersky):
   Operator/Playbook -> minisoar/edr/core.py -> kaspersky.restore_host -> KSC API (HostGroup.SetHostNetworkIsolation) -> Success

4. Add IoC (/add_edr_ioc <ip> all / Daemon Auto-Sync):
   Operator/Daemon -> minisoar/edr/core.py:add_edr_ioc(provider="all")
                   |-> Kaspersky: SKIPPED (KSC IoC disabled)
                   |-> TrendMicro: REGISTERED via add_suspicious_object -> Success

5. Add IoC Explicit (/add_edr_ioc <ip> kaspersky):
   Operator -> minisoar/edr/core.py:add_edr_ioc(provider="kaspersky") -> Refused (Friendly info message)
```

---

## 4. Rencana Pengujian (Test Plan)

1. **Unit & Regression Testing (`tests/`):**
   - Perbarui `tests/test_perimeter_ssot.py` & `tests/test_perimeter_disabled.py`:
     - Verifikasi `PERIMETER_NONAKTIF` hanya memuat `cloudflare` dan `fortigate`.
     - Verifikasi `is_perimeter_active("kaspersky") == True`.
   - Perbarui/tambahkan di `tests/test_edr.py`:
     - `test_kaspersky_add_ioc_direct_guard_disabled`: Memastikan panggilan langsung `kaspersky.add_ioc()` menolak pendaftaran tanpa koneksi jaringan.
     - `test_add_edr_ioc_all_skips_kaspersky_and_succeeds_trendmicro`: Memastikan panggilan `add_edr_ioc(..., provider="all")` sukses di Trend Micro dan tidak gagal karena KSC.
     - `test_add_edr_ioc_kaspersky_explicit_returns_informative_message`: Memastikan panggilan `add_edr_ioc(..., provider="kaspersky")` ditolak dengan pesan yang jelas.
     - `test_kaspersky_query_endpoint_active`: Memastikan `query_endpoint(..., provider="kaspersky")` aktif dan memanggil `find_host_by_ip`.
     - `test_kaspersky_isolate_and_restore_active`: Memastikan `isolate_endpoint` dan `restore_endpoint` aktif untuk KSC.
2. **Full Regression Verification:**
   - Jalankan seluruh suite test pytest non-E2E (478+ test) untuk memastikan seluruh fungsionalitas lain tetap 100% hijau.
