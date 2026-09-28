"""Konfigurasi suite: bikin test offline secara default.

Sebelum ini beberapa test benar-benar menembak jaringan (KSC di 172.30.103.21,
AbuseIPDB, Elasticsearch, Redis) dan hanya "lulus" karena koneksinya timeout
lalu jatuh ke fallback. Hasilnya tetap hijau, tapi suite makan ~43 detik dan
bergantung pada topologi jaringan mesin yang menjalankannya — di CI tanpa route
ke 172.30.103.21 itu lambat dan rapuh.

Dua lapis pertahanan, dua-duanya hanya untuk test NON-e2e:

1. `MINISOAR_MOCK=1` — sakelar yang sudah dipakai modul mitigation/edr/cases.
2. Blokir socket — jaring pengaman untuk modul yang BELUM punya sakelar itu
   (`utils.abuseipdb_lookup`, `database.*` ke Elasticsearch/Redis). Tanpa ini
   suite tetap diam-diam menembak jaringan.

Lapis 2 sekaligus alat diagnosa: kalau nanti ada test baru yang menembak
jaringan, ia gagal cepat dengan pesan jelas, bukan menambah 10 detik timeout.

Test berlabel `e2e` DIKECUALIKAN dari keduanya — lapis itu memang harus bicara
ke Telegram sungguhan.
"""

import socket

import pytest


class NetworkAccessDenied(RuntimeError):
    """Test non-e2e mencoba membuka koneksi keluar."""


@pytest.fixture(autouse=True)
def _offline_by_default(request, monkeypatch):
    if request.node.get_closest_marker("e2e"):
        return

    monkeypatch.setenv("MINISOAR_MOCK", "1")

    # Token produksi bisa ikut ter-load dari .env lewat load_env(); jangan
    # sampai test unit memakainya tanpa sengaja.
    for var in ("TELEGRAM_TOKEN", "TELEGRAM_BOT"):
        monkeypatch.delenv(var, raising=False)

    def _deny(*args, **kwargs):
        raise NetworkAccessDenied(
            f"{request.node.nodeid} mencoba akses jaringan. "
            "Mock pemanggilnya, atau tandai test ini @pytest.mark.e2e."
        )

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
