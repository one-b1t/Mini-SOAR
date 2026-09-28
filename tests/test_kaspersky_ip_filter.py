from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from minisoar.edr import kaspersky


@pytest.fixture(autouse=True)
def disable_mock_env(monkeypatch):
    """Ensure MINISOAR_MOCK is disabled so we test actual KSC parsing logic."""
    monkeypatch.setenv("MINISOAR_MOCK", "0")
    monkeypatch.setenv("KSC_SERVER_URL", "https://192.168.1.50:13299/api/v1.0")
    monkeypatch.setenv("KSC_USERNAME", "admin")
    monkeypatch.setenv("KSC_PASSWORD", "secret")


def _mock_ksc_responses(raw_hosts: list[dict]):
    """Helper to mock KSC login, FindHosts, and GetItemsChunk."""
    mock_post = MagicMock()

    # Call 1: login
    # Call 2: HostGroup.FindHosts
    # Call 3: ChunkAccessor.GetItemsChunk
    # Call 4: (optional) SetHostNetworkIsolation

    def side_effect(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "Session.StartSession" in url:
            resp.json.return_value = {"PxgRetVal": "mock-token-xyz"}
        elif "HostGroup.FindHosts" in url:
            resp.json.return_value = {
                "strAccessor": "accessor-123",
                "PxgRetVal": len(raw_hosts),
            }
        elif "ChunkAccessor.GetItemsChunk" in url:
            iterator_array = [{"value": h} for h in raw_hosts]
            resp.json.return_value = {
                "pChunk": {"KLCSP_ITERATOR_ARRAY": iterator_array}
            }
        elif "HostGroup.SetHostNetworkIsolation" in url:
            resp.json.return_value = {"PxgRetVal": True}
        else:
            resp.json.return_value = {}
        return resp

    mock_post.side_effect = side_effect
    return mock_post


def test_find_host_by_ip_filters_exact_and_stores_ip():
    """Verify that find_host_by_ip only returns matching host and stores ipAddress."""
    # 10.0.0.50 in big-endian int = 167772210
    # 10.0.0.51 in big-endian int = 167772211
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-01",
            "KLHST_WKS_ID": "ksc-host-001",
            "KLHST_WKS_IP_LONG": 167772210,
            "KLHST_WKS_OS_NAME": "Windows Server 2022",
            "KLHST_WKS_ISOLATED": False,
        },
        {
            "KLHST_WKS_HOSTNAME": "SERVER-02",
            "KLHST_WKS_ID": "ksc-host-002",
            "KLHST_WKS_IP_LONG": 167772211,
            "KLHST_WKS_OS_NAME": "Ubuntu 22.04",
            "KLHST_WKS_ISOLATED": False,
        },
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        hosts, err = kaspersky.find_host_by_ip("10.0.0.50")
        assert err is None
        assert len(hosts) == 1
        assert hosts[0]["hostId"] == "ksc-host-001"
        assert hosts[0]["hostName"] == "SERVER-01"
        assert hosts[0]["ipAddress"] == "10.0.0.50"


def test_find_host_by_ip_little_endian_integer():
    """Verify that find_host_by_ip handles little-endian integer byte order."""
    # 10.0.0.50 in little-endian int: (50 << 24) + 10 = 838860810
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-LE",
            "KLHST_WKS_ID": "ksc-host-le",
            "KLHST_WKS_IP_LONG": 838860810,
            "KLHST_WKS_OS_NAME": "Windows 11",
            "KLHST_WKS_ISOLATED": False,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        hosts, err = kaspersky.find_host_by_ip("10.0.0.50")
        assert err is None
        assert len(hosts) == 1
        assert hosts[0]["hostId"] == "ksc-host-le"
        assert hosts[0]["ipAddress"] == "10.0.0.50"


def test_find_host_by_ip_signed_integer():
    """Verify that find_host_by_ip handles negative signed 32-bit integer."""
    # 192.168.1.100 as unsigned = 3232235876, as signed 32-bit = -1062731420
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-SIGNED",
            "KLHST_WKS_ID": "ksc-host-signed",
            "KLHST_WKS_IP_LONG": -1062731420,
            "KLHST_WKS_OS_NAME": "Windows Server 2019",
            "KLHST_WKS_ISOLATED": False,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        hosts, err = kaspersky.find_host_by_ip("192.168.1.100")
        assert err is None
        assert len(hosts) == 1
        assert hosts[0]["hostId"] == "ksc-host-signed"
        assert hosts[0]["ipAddress"] == "192.168.1.100"


def test_find_host_by_ip_string_format():
    """Verify that find_host_by_ip handles string dot-decimal IP format."""
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-STR",
            "KLHST_WKS_ID": "ksc-host-str",
            "KLHST_WKS_IP_LONG": "10.0.0.50",
            "KLHST_WKS_OS_NAME": "Debian 12",
            "KLHST_WKS_ISOLATED": False,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        hosts, err = kaspersky.find_host_by_ip("10.0.0.50")
        assert err is None
        assert len(hosts) == 1
        assert hosts[0]["hostId"] == "ksc-host-str"
        assert hosts[0]["ipAddress"] == "10.0.0.50"


def test_find_host_by_ip_no_match_returns_empty():
    """Verify that find_host_by_ip returns [] (not error) when IP does not match."""
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-01",
            "KLHST_WKS_ID": "ksc-host-001",
            "KLHST_WKS_IP_LONG": 167772210,  # 10.0.0.50
            "KLHST_WKS_OS_NAME": "Windows Server 2022",
            "KLHST_WKS_ISOLATED": False,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        hosts, err = kaspersky.find_host_by_ip("10.0.0.99")
        assert err is None
        assert hosts == []


def test_isolate_host_by_ip_does_not_isolate_wrong_host_when_not_found():
    """P0 Safety Check: isolate_host must FAIL and NOT isolate arbitrary first host when IP is not found."""
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "CRITICAL-DC",
            "KLHST_WKS_ID": "ksc-host-dc",
            "KLHST_WKS_IP_LONG": 167772210,  # 10.0.0.50
            "KLHST_WKS_OS_NAME": "Windows Server 2022",
            "KLHST_WKS_ISOLATED": False,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        # We query IP 10.0.0.99 which DOES NOT exist in KSC
        ok, msg, data = kaspersky.isolate_host(ip="10.0.0.99")
        assert ok is False
        assert "No host found matching IP 10.0.0.99" in msg or "not found" in msg.lower()

        # CRITICAL: Verify that SetHostNetworkIsolation was NEVER called!
        for call_args in mock_post.call_args_list:
            url = call_args[0][0]
            assert "SetHostNetworkIsolation" not in url, f"Dangerous isolation call made to {url}!"


def test_isolate_host_by_ip_targets_correct_host_not_first():
    """Verify that isolate_host selects the matching host, not blindly hosts[0]."""
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-01",
            "KLHST_WKS_ID": "ksc-host-001",
            "KLHST_WKS_IP_LONG": 167772210,  # 10.0.0.50
            "KLHST_WKS_OS_NAME": "Windows Server 2022",
            "KLHST_WKS_ISOLATED": False,
        },
        {
            "KLHST_WKS_HOSTNAME": "TARGET-INFECTED",
            "KLHST_WKS_ID": "ksc-host-target-999",
            "KLHST_WKS_IP_LONG": 167772211,  # 10.0.0.51
            "KLHST_WKS_OS_NAME": "Ubuntu 22.04",
            "KLHST_WKS_ISOLATED": False,
        },
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        ok, msg, data = kaspersky.isolate_host(ip="10.0.0.51")
        assert ok is True

        # Check what was sent to SetHostNetworkIsolation
        isolation_calls = [
            call for call in mock_post.call_args_list
            if "SetHostNetworkIsolation" in call[0][0]
        ]
        assert len(isolation_calls) == 1
        payload = isolation_calls[0][1]["json"]
        assert payload["strHostName"] == "ksc-host-target-999"
        assert payload["bIsolate"] is True


def test_restore_host_by_ip_does_not_restore_wrong_host_when_not_found():
    """P0 Safety Check: restore_host must FAIL when IP is not found."""
    raw_hosts = [
        {
            "KLHST_WKS_HOSTNAME": "SERVER-01",
            "KLHST_WKS_ID": "ksc-host-001",
            "KLHST_WKS_IP_LONG": 167772210,  # 10.0.0.50
            "KLHST_WKS_OS_NAME": "Windows Server 2022",
            "KLHST_WKS_ISOLATED": True,
        }
    ]

    mock_post = _mock_ksc_responses(raw_hosts)
    with patch("requests.post", mock_post):
        ok, msg, data = kaspersky.restore_host(ip="10.0.0.99")
        assert ok is False
        assert "No host found matching IP 10.0.0.99" in msg or "not found" in msg.lower()

        # CRITICAL: Verify that SetHostNetworkIsolation was NEVER called!
        for call_args in mock_post.call_args_list:
            url = call_args[0][0]
            assert "SetHostNetworkIsolation" not in url


def test_trendmicro_legacy_eiqs_filtering_and_safety(monkeypatch):
    """Verify Trend Micro legacy eiqs fallback normalizes and filters strictly by IP."""
    from minisoar.edr import trendmicro

    monkeypatch.setenv("MINISOAR_MOCK", "0")
    monkeypatch.setenv("TRENDMICRO_API_KEY", "mock-token-xyz")
    monkeypatch.setenv("TRENDMICRO_BASE_URL", "https://api.xdr.trendmicro.com")

    # Mock response for v3.0/endpointSecurity/endpoints -> 404 (trigger legacy eiqs)
    # Mock response for v3.0/eiqs/endpoints -> returns 2 items
    mock_get = MagicMock()

    def get_side_effect(url, *args, **kwargs):
        resp = MagicMock()
        if "endpointSecurity/endpoints" in url:
            resp.status_code = 404
            resp.text = "Not found"
        elif "eiqs/endpoints" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "items": [
                    {
                        "agentGuid": "guid-001",
                        "endpointName": "SERVER-TM-1",
                        "ipAddresses": ["10.0.0.50"],
                        "osName": "Windows Server 2022",
                        "isolationStatus": "off",
                    },
                    {
                        "agentGuid": "guid-002",
                        "endpointName": "SERVER-TM-2",
                        "ipAddresses": ["10.0.0.51"],
                        "osName": "Linux",
                        "isolationStatus": "off",
                    },
                ]
            }
        else:
            resp.status_code = 404
        return resp

    mock_get.side_effect = get_side_effect
    with patch("requests.get", mock_get):
        # 1. Matching IP
        eps, err = trendmicro.find_endpoint_by_ip("10.0.0.50")
        assert err is None
        assert len(eps) == 1
        assert eps[0]["endpointId"] == "guid-001"
        assert eps[0]["endpointName"] == "SERVER-TM-1"

        # 2. Non-matching IP
        eps_none, err_none = trendmicro.find_endpoint_by_ip("10.0.0.99")
        assert err_none is None
        assert eps_none == []

        # 3. isolate_endpoint when IP not found must fail safely
        ok_iso, msg_iso, _ = trendmicro.isolate_endpoint(ip="10.0.0.99")
        assert ok_iso is False
        assert "No endpoint found matching IP 10.0.0.99" in msg_iso

        # 4. restore_endpoint when IP not found must fail safely
        ok_res, msg_res, _ = trendmicro.restore_endpoint(ip="10.0.0.99")
        assert ok_res is False
        assert "No endpoint found matching IP 10.0.0.99" in msg_res

