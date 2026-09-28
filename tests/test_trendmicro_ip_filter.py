"""TrendMicro: endpoint TANPA field IP tidak boleh dianggap cocok.

Fallback legacy eiqs (find_endpoint_by_ip) dulu memakai `if not ips or ip in ips`,
sehingga endpoint yang sama sekali tidak punya ipAddresses/ip/lastUsedIp lolos
sebagai "cocok". isolate_endpoint/restore_endpoint lalu mengambil endpoints[0] ->
host yang salah bisa terisolasi (kelas bug yang sama dengan P0 Kaspersky).
Server eiqs tidak terbukti menghormati parameter ?ip=, jadi filter lokal wajib ketat.
"""

from unittest.mock import MagicMock, patch

import pytest

from minisoar.edr import trendmicro

TARGET_IP = "203.0.113.50"


@pytest.fixture
def legacy_eiqs(monkeypatch):
    """Vision One endpointSecurity -> 404 (paksa fallback eiqs); eiqs mengembalikan `items`."""
    monkeypatch.setenv("MINISOAR_MOCK", "0")
    monkeypatch.setenv("TRENDMICRO_API_KEY", "fake-token-for-tests")
    monkeypatch.setenv("TRENDMICRO_BASE_URL", "https://api.xdr.trendmicro.test")
    monkeypatch.delenv("TRENDMICRO_PLATFORM", raising=False)

    posted = []

    def use(items):
        def fake_get(url, *a, **kw):
            resp = MagicMock()
            if "eiqs/endpoints" in url:
                resp.status_code = 200
                resp.json.return_value = {"items": items}
            else:
                resp.status_code = 404
                resp.text = "Not found"
            return resp

        def fake_post(url, *a, json=None, **kw):
            posted.append((url, json))
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "{}"
            resp.json.return_value = {}
            return resp

        return patch("requests.get", side_effect=fake_get), patch("requests.post", side_effect=fake_post)

    return use, posted


NO_IP_ENDPOINT = {"agentGuid": "guid-no-ip", "endpointName": "HOST-TANPA-IP", "osName": "Windows"}
TARGET_ENDPOINT = {"agentGuid": "guid-target", "endpointName": "HOST-TARGET", "ipAddresses": [TARGET_IP]}


def test_endpoint_without_ip_field_is_not_a_match(legacy_eiqs):
    use, _ = legacy_eiqs
    g, p = use([NO_IP_ENDPOINT])
    with g, p:
        eps, err = trendmicro.find_endpoint_by_ip(TARGET_IP)

    assert err is None
    assert eps == [], f"endpoint tanpa IP dianggap cocok: {eps}"


def test_isolate_does_not_hit_endpoint_without_ip(legacy_eiqs):
    use, posted = legacy_eiqs
    g, p = use([NO_IP_ENDPOINT])
    with g, p:
        ok, msg, _ = trendmicro.isolate_endpoint(ip=TARGET_IP)
        ok_r, _, _ = trendmicro.restore_endpoint(ip=TARGET_IP)

    assert (ok, ok_r) == (False, False), msg
    assert posted == [], f"POST isolate/restore terkirim ke endpoint yang salah: {posted}"


def test_endpoint_without_ip_listed_first_is_skipped(legacy_eiqs):
    """Endpoint tanpa IP di urutan pertama tidak boleh menggeser target yang benar."""
    use, posted = legacy_eiqs
    g, p = use([NO_IP_ENDPOINT, TARGET_ENDPOINT])
    with g, p:
        eps, _ = trendmicro.find_endpoint_by_ip(TARGET_IP)
        ok, _, _ = trendmicro.isolate_endpoint(ip=TARGET_IP)

    assert [e["endpointId"] for e in eps] == ["guid-target"]
    assert ok is True
    assert [body[0]["endpointId"] for _, body in posted] == ["guid-target"]


@pytest.mark.parametrize("field", [{"ipAddresses": []}, {"ip": ""}, {"ip": None}, {"lastUsedIp": ""}])
def test_empty_ip_values_are_not_a_match(legacy_eiqs, field):
    use, _ = legacy_eiqs
    g, p = use([{**NO_IP_ENDPOINT, **field}])
    with g, p:
        eps, _ = trendmicro.find_endpoint_by_ip(TARGET_IP)
    assert eps == [], f"{field} dianggap cocok: {eps}"


@pytest.mark.parametrize("field", [{"ip": TARGET_IP}, {"ip": [TARGET_IP]}, {"lastUsedIp": TARGET_IP}])
def test_real_ip_formats_still_match(legacy_eiqs, field):
    """Arah sebaliknya: format IP yang sah (string, list, lastUsedIp) tetap cocok."""
    use, _ = legacy_eiqs
    g, p = use([{"agentGuid": "guid-x", **field}])
    with g, p:
        eps, _ = trendmicro.find_endpoint_by_ip(TARGET_IP)
    assert [e["endpointId"] for e in eps] == ["guid-x"]
    assert TARGET_IP in eps[0]["ip"]
