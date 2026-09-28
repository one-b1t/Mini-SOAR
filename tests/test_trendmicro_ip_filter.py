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


# --- Kasus wajib dari brief (IP 10.0.0.50 persis) ---------------------------------

def test_brief_case_a_only_10_0_0_50_passes(legacy_eiqs):
    """(a) dua endpoint: satu ber-IP 10.0.0.50, satu tanpa field IP -> hanya yang 10.0.0.50 lolos."""
    use, _ = legacy_eiqs
    g, p = use([
        {"agentGuid": "guid-no-ip", "endpointName": "HOST-TANPA-IP"},
        {"agentGuid": "guid-1050", "endpointName": "HOST-1050", "ipAddresses": ["10.0.0.50"]},
    ])
    with g, p:
        eps, err = trendmicro.find_endpoint_by_ip("10.0.0.50")
    assert err is None
    assert [e["endpointId"] for e in eps] == ["guid-1050"]


@pytest.mark.parametrize("action", ["isolate_endpoint", "restore_endpoint"])
def test_brief_case_b_no_match_says_not_found_without_api_call(legacy_eiqs, action):
    """(b) tidak ada yang cocok -> kosong; isolate/restore bilang 'not found' dan tidak memanggil API."""
    use, posted = legacy_eiqs
    g, p = use([{"agentGuid": "guid-no-ip"}, {"agentGuid": "guid-other", "ipAddresses": ["10.0.0.51"]}])
    with g, p:
        eps, _ = trendmicro.find_endpoint_by_ip("10.0.0.50")
        ok, msg, _ = getattr(trendmicro, action)(ip="10.0.0.50")
    assert eps == []
    # Pesan yang ada: "No endpoint found matching IP <ip>" (setara "not found").
    assert ok is False and "found" in msg.lower() and "10.0.0.50" in msg, msg
    assert posted == [], f"{action} memanggil API walau tidak ada endpoint cocok: {posted}"


# --- Jalur Vision One utama harus konsisten ----------------------------------------

@pytest.fixture
def vision_one(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "0")
    monkeypatch.setenv("TRENDMICRO_API_KEY", "fake-token-for-tests")
    monkeypatch.setenv("TRENDMICRO_BASE_URL", "https://api.xdr.trendmicro.test")

    def use(items):
        def fake_get(url, *a, **kw):
            resp = MagicMock()
            resp.status_code = 200 if "endpointSecurity/endpoints" in url else 404
            resp.json.return_value = {"items": items}
            return resp
        return patch("requests.get", side_effect=fake_get)

    return use


def test_vision_one_path_uses_same_strict_match(vision_one):
    with vision_one([
        {"agentGuid": "guid-no-ip"},
        {"agentGuid": "guid-str", "ipAddresses": "10.0.0.50"},   # string, bukan list
        {"agentGuid": "guid-last", "lastUsedIp": "10.0.0.50"},
    ]):
        eps, _ = trendmicro.find_endpoint_by_ip("10.0.0.50")
    assert [e["endpointId"] for e in eps] == ["guid-str", "guid-last"]


# --- Cloud One Workload (computers/search) ----------------------------------------
# Jalur ini hanya mengandalkan searchCriteria sisi server. Tidak ada bukti bahwa
# server memfilter ketat, dan isolate/restore mengambil endpoints[0], jadi satu
# computer yang tidak cocok = host yang salah gets contained.


@pytest.fixture
def cloud_one(monkeypatch):
    monkeypatch.setenv("MINISOAR_MOCK", "0")
    monkeypatch.setenv("TRENDMICRO_API_KEY", "fake-token-for-tests")
    monkeypatch.setenv("TRENDMICRO_BASE_URL", "https://workload.us-1.cloudone.trendmicro.com/api")

    posted = []

    def use(computers):
        def fake_post(url, *a, json=None, **kw):
            posted.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "{}"
            if "computers/search" in url:
                resp.json.return_value = {"computers": computers}
            else:
                resp.json.return_value = {}
            return resp

        return patch("requests.post", side_effect=fake_post), posted

    return use


def test_cloud_one_only_matching_computer_passes(cloud_one):
    p, _ = cloud_one([
        {"ID": 1, "displayName": "HOST-LAIN", "ipAddresses": ["10.0.0.51"]},
        {"ID": 2, "displayName": "HOST-TARGET", "ipAddresses": ["10.0.0.50"]},
    ])
    with p:
        eps, err = trendmicro.find_endpoint_by_ip("10.0.0.50")
    assert err is None
    assert [e["endpointId"] for e in eps] == ["2"], eps


def test_cloud_one_computer_without_ip_is_not_a_match(cloud_one):
    p, _ = cloud_one([
        {"ID": 1, "displayName": "HOST-TANPA-IP"},
        {"ID": 2, "displayName": "HOST-LAIN", "ipAddresses": ["10.0.0.51"]},
    ])
    with p:
        eps, _ = trendmicro.find_endpoint_by_ip("10.0.0.50")
    assert eps == [], eps


@pytest.mark.parametrize("action", ["isolate_endpoint", "restore_endpoint"])
def test_cloud_one_no_match_does_not_call_action_api(cloud_one, action):
    p, posted = cloud_one([{"ID": 1, "displayName": "HOST-TANPA-IP"}])
    with p:
        ok, msg, _ = getattr(trendmicro, action)(ip="10.0.0.50")
    assert ok is False and "10.0.0.50" in msg, msg
    assert all("computers/search" in u for u in posted), f"{action} memanggil API action: {posted}"


def test_cloud_one_matched_ip_is_reported(cloud_one):
    """Arah sebaliknya: computer yang IP-nya cocok tetap ditemukan."""
    p, _ = cloud_one([{"ID": 7, "displayName": "HOST-TARGET", "hostName": "h7", "ipAddresses": ["10.0.0.50"]}])
    with p:
        eps, _ = trendmicro.find_endpoint_by_ip("10.0.0.50")
    assert [e["endpointId"] for e in eps] == ["7"]
    assert "10.0.0.50" in eps[0]["ip"]
