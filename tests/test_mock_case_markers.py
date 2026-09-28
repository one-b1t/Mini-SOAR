"""Penanda mode mock di balasan /new_case (TheHive, Jira, ServiceNow).

Kelas bug yang sama seperti e4a656a. Dengan MINISOAR_MOCK=1 tidak ada case
atau ticket sungguhan yang dibuat, tapi balasan tetap "SUCCESS: ... created
with ID ..." tanpa penanda. Operator bisa mengira tiketnya benar-benar dibuat
di TheHive/Jira/ServiceNow.

send_generic_webhook di file yang sama sudah memakai pola " (Mock)", jadi
pola itu bukan ciptaan baru. Test ini mengunci keempatnya pada pola itu.

Dua arah: mock-on wajib bertanda, mock-off wajib tetap polos supaya teks
produksi tidak ikut berubah.
"""

import pytest

from minisoar.cases.connectors import (
    add_thehive_observable,
    create_jira_issue,
    create_servicenow_incident,
    create_thehive_case,
)

CASES = [("1", True), ("0", False)]
IDS = ["mock-on", "mock-off"]


def _marked(msg: str) -> bool:
    """Cek penanya yang spesifik, bukan kata 'mock' seenakanya.

    Pesan error dari conftest juga memuat kata 'Mock' ("Mock pemanggilnya..."),
    jadi pencarian substring longgar akan salah menilai arah mock-off.
    """
    return "(Mock)" in msg or "[MOCK]" in msg


def _check(monkeypatch, value, expected, call):
    monkeypatch.setenv("MINISOAR_MOCK", value)
    ok, msg = call()[:2]
    if value == "1":
        assert ok, msg
    assert _marked(msg) == expected, msg


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_thehive_create_case_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: create_thehive_case("MiniSOAR alert", "detail", observables=[]))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_thehive_add_observable_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: add_thehive_observable("TH-CASE-MOCK-1", "ip", "10.0.0.50"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_jira_create_issue_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: create_jira_issue("MiniSOAR alert", "detail"))


@pytest.mark.parametrize("value,expected", CASES, ids=IDS)
def test_servicenow_create_incident_reply_marker(monkeypatch, value, expected):
    _check(monkeypatch, value, expected,
           lambda: create_servicenow_incident("MiniSOAR alert", "detail"))
