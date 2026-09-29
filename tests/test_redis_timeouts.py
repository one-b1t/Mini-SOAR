"""socket_timeout Redis vs operasi blocking (BLPOP daemon).

Regresi 05ad34d: redis_client() memasang socket_timeout=REDIS_TIMEOUT (2s)
untuk SEMUA pemanggil. Daemon memanggil r.blpop(timeout=10); saat antrean
idle, Redis baru menjawab di detik ke-10, tapi socket read sudah timeout di
detik ke-2 -> redis.exceptions.TimeoutError -> logger.error + sleep(5).
Kondisi idle (paling sering) jadi jalur error.

Tidak memakai Redis sungguhan: _FakeRedisServer adalah server RESP minimal
di loopback yang meniru semantik BLPOP (diam sampai timeout, lalu nil).
"""

import socket
import threading
import time

import pytest
import redis

import minisoar.daemon as daemon
from minisoar import database


class _FakeRedisServer:
    """RESP server minimal. BLPOP: diam `timeout` detik lalu jawab nil.

    silent=True: terima koneksi tapi tidak pernah menjawab apa pun (Redis
    menggantung) - untuk menguji sisi bot harus gagal cepat.
    """

    def __init__(self, silent=False):
        self.silent = silent
        self.blpops_answered = 0
        self.connections = 0
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_command(f):
        line = f.readline()
        if not line:
            return None
        n = int(line[1:])
        args = []
        for _ in range(n):
            size = int(f.readline()[1:])
            args.append(f.read(size + 2)[:-2].decode())
        return args

    def _serve(self, conn):
        f = conn.makefile("rb")
        proto = 2
        try:
            while not self._stop.is_set():
                cmd = self._read_command(f)
                if cmd is None:
                    return
                if self.silent:
                    continue
                name = cmd[0].upper()
                if name == "HELLO":
                    proto = 3
                    # redis-py 8 membuka tiap koneksi dengan HELLO 3 (RESP3).
                    conn.sendall(b"%2\r\n+server\r\n+redis\r\n+proto\r\n:3\r\n")
                elif name == "BLPOP":
                    # Event.wait, bukan time.sleep: test daemon menambal time.sleep
                    # (modul global) untuk menghentikan loop.
                    self._stop.wait(float(cmd[-1]))
                    conn.sendall(b"_\r\n" if proto == 3 else b"*-1\r\n")
                    self.blpops_answered += 1
                elif name == "PING":
                    conn.sendall(b"+PONG\r\n")
                elif name in {"CLIENT", "SELECT"}:
                    conn.sendall(b"+OK\r\n")
                elif name in {"GET", "HGET"}:
                    conn.sendall(b"_\r\n")
                elif name in {"LLEN", "EXISTS", "DEL", "SETEX", "SET", "EXPIRE"}:
                    conn.sendall(b":0\r\n")
                else:
                    conn.sendall(b"*0\r\n")
        except OSError:
            return
        finally:
            conn.close()

    def close(self):
        self._stop.set()
        self._srv.close()


@pytest.fixture
def fake_redis(monkeypatch):
    srv = _FakeRedisServer()
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", str(srv.port))
    yield srv
    srv.close()


@pytest.fixture
def silent_redis(monkeypatch):
    srv = _FakeRedisServer(silent=True)
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", str(srv.port))
    yield srv
    srv.close()


def test_daemon_idle_blpop_is_not_an_error(fake_redis, monkeypatch, tmp_path):
    """Antrean kosong lebih lama dari REDIS_TIMEOUT tidak boleh jadi TimeoutError.

    Skala waktu diperkecil: REDIS_TIMEOUT=0.3s (sisi bot), BLPOP 1s.
    """
    monkeypatch.setenv("REDIS_TIMEOUT", "0.3")
    monkeypatch.setattr(daemon, "BLPOP_TIMEOUT", 1, raising=False)
    monkeypatch.setattr(daemon, "load_env", lambda *a, **kw: None)
    for k, v in {"LOGFILE": "audit.log", "UNMAPPED_LOG_PATH": "unmapped.log", "WHITELIST_PATH": "wl.txt"}.items():
        monkeypatch.setenv(k, str(tmp_path / v))

    errors = []
    real_error = daemon.logger.error

    def spy_error(msg, *args, **kw):
        errors.append(msg % args if args else msg)
        return real_error(msg, *args, **kw)

    blpop_results = []

    def client_factory(*a, **kw):
        # Klien Redis ASLI (redis-py) ke server palsu; hanya blpop yang dibungkus
        # supaya loop daemon berhenti setelah satu siklus idle.
        client = database.redis_client(*a, **kw)
        real_blpop = client.blpop

        def blpop(*ba, **bkw):
            if blpop_results:
                raise KeyboardInterrupt
            try:
                res = real_blpop(*ba, **bkw)
            except Exception as e:
                blpop_results.append(e)
                raise
            blpop_results.append(res)
            return res

        client.blpop = blpop
        return client

    def stop_on_sleep(seconds):
        # Jalur error loop utama (except -> sleep(5)).
        raise KeyboardInterrupt

    monkeypatch.setattr(daemon, "redis_client", client_factory)
    monkeypatch.setattr(daemon.logger, "error", spy_error)
    monkeypatch.setattr(daemon.time, "sleep", stop_on_sleep)

    daemon.main()

    assert blpop_results == [None], f"BLPOP idle harus selesai normal (nil), didapat: {blpop_results!r}"
    assert errors == [], f"siklus idle menghasilkan error log: {errors}"


def test_blocking_client_socket_timeout_exceeds_blpop_timeout(monkeypatch):
    """Kontrak konfigurasi: klien daemon harus menunggu lebih lama dari BLPOP-nya."""
    monkeypatch.setenv("REDIS_TIMEOUT", "2.0")
    r = database.redis_client(blocking_timeout=daemon.BLPOP_TIMEOUT)
    kw = r.connection_pool.connection_kwargs
    assert kw["socket_timeout"] > daemon.BLPOP_TIMEOUT
    assert kw["socket_connect_timeout"] == 2.0, "connect harus tetap gagal cepat"


def test_bot_client_still_fails_fast_when_redis_hangs(silent_redis, monkeypatch):
    """Fix /blocked (05ad34d) tidak boleh ikut rusak: klien default tetap gagal cepat."""
    monkeypatch.setenv("REDIS_TIMEOUT", "0.3")
    r = database.redis_client()
    kw = r.connection_pool.connection_kwargs
    assert kw["socket_timeout"] == 0.3 and kw["socket_connect_timeout"] == 0.3

    t0 = time.monotonic()
    with pytest.raises(redis.exceptions.TimeoutError):
        r.ping()
    elapsed = time.monotonic() - t0
    # redis-py 8.x default: Retry(ExponentialWithJitterBackoff, 10) -> 11 percobaan,
    # ~8s untuk 0.3s (~25s untuk REDIS_TIMEOUT=2.0 produksi).
    assert silent_redis.connections <= 2, f"{silent_redis.connections} koneksi: retry default redis-py masih aktif"
    assert elapsed < 1.5, f"klien bot menggantung {elapsed:.1f}s saat Redis tidak menjawab"
