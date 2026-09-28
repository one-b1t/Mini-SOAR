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


# Loopback TETAP diteruskan ke socket asli: di Windows, asyncio membuat
# self-pipe event loop lewat socketpair() yang beralamat 127.0.0.1, jadi
# memblokir loopback membuat setiap asyncio.run() gagal sebelum test-nya jalan.
# Yang dilarang tetap host DI LUAR — proteksi kebocoran ke produksi tidak
# dikurangi sedikit pun.
#
# Originals diambil di sini, waktu modul ini di-import: monkeypatch di bawah
# baru berlaku saat fixture berjalan, jadi kalau originals diambil di dalam
# fixture, yang kena adalah versi yang sudah dipatch.
_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_CREATE_CONNECTION = socket.create_connection

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", "::"})


def _is_loopback(address):
    # socket.socket.connect() dengan address str = path AF_UNIX, yaitu IPC
    # lokal pada filesystem, bukan egress jaringan.
    if not isinstance(address, tuple):
        return True
    if not address:
        return True
    host = address[0]
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("ascii", "replace")
    return str(host) in _LOOPBACK_HOSTS


@pytest.fixture(autouse=True)
def _offline_by_default(request, monkeypatch):
    if request.node.get_closest_marker("e2e"):
        return

    monkeypatch.setenv("MINISOAR_MOCK", "1")

    # Token produksi bisa ikut ter-load dari .env lewat load_env(); jangan
    # sampai test unit memakainya tanpa sengaja.
    for var in ("TELEGRAM_TOKEN", "TELEGRAM_BOT"):
        monkeypatch.delenv(var, raising=False)

    def _deny(address, *args, **kwargs):
        if _is_loopback(address):
            return None
        raise NetworkAccessDenied(
            f"{request.node.nodeid} mencoba akses jaringan ke {address!r}. "
            "Mock pemanggilnya, atau tandai test ini @pytest.mark.e2e."
        )

    def _connect(self, address, *args, **kwargs):
        _deny(address)
        return _REAL_CONNECT(self, address, *args, **kwargs)

    def _connect_ex(self, address, *args, **kwargs):
        _deny(address)
        return _REAL_CONNECT_EX(self, address, *args, **kwargs)

    def _create_connection(address, *args, **kwargs):
        _deny(address)
        return _REAL_CREATE_CONNECTION(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _connect_ex)
    monkeypatch.setattr(socket, "create_connection", _create_connection)
