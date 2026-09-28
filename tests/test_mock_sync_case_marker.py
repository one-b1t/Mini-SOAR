"""Penanda mock di pesan sukses `cases.sync_case_to_ticketing`.

`core.py` membangun string suksesnya sendiri, bukan meneruskan pesan dari
connector, jadi penanda mock harus dipasang di sini juga. Kalau tidak,
operator di mode mock membaca "SUCCESS ... ticket ID ..." padahal tidak ada
ticket yang pernah dibuat.

Dua arah diuji: mock-on harus bertanda, mock-off harus byte-identik dengan
teks produksi. Penandanya spesifik (" (Mock)" atau "[MOCK]"), bukan
`"mock" in msg.lower()` - pesan penolakan jaringan dari conftest memuat kata
"Mock" dan akan membuat cek longgar salah lulus.
"""
import pytest

from minisoar.cases import core

# Persis seperti core.py:187 sebelum penanda ditambahkan. Kalau ini ikut
# berubah di mode non-mock, berarti teks produksi ikut berubah dan itu bug.
PRODUCTION_MSG = "SUCCESS: Incident synced to THEHIVE with ticket ID TH-CASE-MOCK-43790"


class _FakeCase:
    def __init__(self):
        self.title = "Tesk-judul"
        self.description = "deskripsi"
        self.severity = "HIGH"
        self.attacker_ip = "203.0.113.88"
        self.target_asset = "host-a"
        self.tags = ["e2e"]
        self.external_tickets: dict[str, str] = {}
        self.timeline = []

    def add_timeline(self, actor, kind, text):
        self.timeline.append((actor, kind, text))


def _stub_dispatch(monkeypatch):
    """Semua collaborator dipalsukan; tidak ada jaringan sama sekali."""
    case = _FakeCase()
    monkeypatch.setattr(core, "get_case", lambda _cid: case)
    monkeypatch.setattr(core, "save_case", lambda _c: None)
    monkeypatch.setattr(core, "is_ticketing_enabled", lambda: True)
    monkeypatch.setattr(core, "get_ticketing_provider", lambda: "thehive")
    monkeypatch.setattr(
        core, "dispatch_external_ticket",
        # Kunci payload mengikuti yang dibaca core.py:183 - ticket_id, lalu key,
        # lalu number.
        lambda **kw: (True, "SUCCESS: TheHive case created (Mock)",
                      {"ticket_id": "TH-CASE-MOCK-43790"}),
    )
    return case


def _marked(msg: str) -> bool:
    return "(Mock)" in msg or "[MOCK]" in msg


def test_mock_run_is_marked(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "1")
    _stub_dispatch(monkeypatch)
    ok, msg = core.sync_case_to_ticketing("INC-20260818-001")
    assert ok is True
    assert _marked(msg), msg
    assert msg == "SUCCESS: Incident synced to THEHIVE with ticket ID TH-CASE-MOCK-43790 (Mock)"


@pytest.mark.parametrize("value", ["", "0", "false", "no"])
def test_non_mock_run_is_byte_identical_to_production(monkeypatch, value):
    monkeypatch.setenv("MINISOAR_MOCK", value)
    _stub_dispatch(monkeypatch)
    ok, msg = core.sync_case_to_ticketing("INC-20260818-001")
    assert ok is True
    assert not _marked(msg), msg
    assert msg == PRODUCTION_MSG


def test_failure_branch_still_passes_connector_message_through(monkeypatch):
    # core.py:188 `return False, msg` memang sudah benar membawa penanda dari
    # connector. Jalur ini tidak boleh diubah.
    monkeypatch.setenv("MINISOAR_MOCK", "1")
    case = _FakeCase()
    monkeypatch.setattr(core, "get_case", lambda _cid: case)
    monkeypatch.setattr(core, "is_ticketing_enabled", lambda: True)
    monkeypatch.setattr(
        core, "dispatch_external_ticket",
        lambda **kw: (False, "TheHive unreachable", {}),
    )
    ok, msg = core.sync_case_to_ticketing("INC-20260818-001")
    assert ok is False
    assert msg == "TheHive unreachable"


def test_marker_is_appended_not_substituted(monkeypatch):
    # Penanda harus menempel di akhir; teks sukses aslinya tidak boleh hilang
    # atau berubah urutan.
    monkeypatch.setenv("MINISOAR_MOCK", "yes")
    _stub_dispatch(monkeypatch)
    _ok, msg = core.sync_case_to_ticketing("INC-20260818-001")
    assert msg.startswith("SUCCESS: Incident synced to THEHIVE with ticket ID TH-CASE-MOCK-43790")
    assert msg.endswith(" (Mock)")


def test_ticket_is_still_recorded_even_in_mock(monkeypatch):
    # Penanda hanya mengubah kalimat balasan; data internal case tetap harus
    # konsisten supaya test lain tidak bocor.
    monkeypatch.setenv("MINISOAR_MOCK", "1")
    case = _stub_dispatch(monkeypatch)
    core.sync_case_to_ticketing("INC-20260818-001")
    assert case.external_tickets == {"thehive": "TH-CASE-MOCK-43790"}
