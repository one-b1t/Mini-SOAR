from __future__ import annotations

import logging
import os
from typing import Any

import requests
from akamai.edgegrid import EdgeGridAuth

logger = logging.getLogger(__name__)


def akamai_session(*, client_token: str, client_secret: str, access_token: str):
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return MockAkamaiSession()

    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
    )
    return session


def akamai_url(baseurl: str, path: str, *, account_switch: str | None = None) -> str:
    url = f"{baseurl}{path}"
    if account_switch:
        url += f"?accountSwitchKey={account_switch}"
    return url


class MockAkamaiSession:
    def post(self, url, headers=None, json=None, timeout=None):
        logger.info("[MOCK] Akamai session POST: url=%s", url)
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"status": "success", "message": "mocked response", "activationStatus": "RECEIVED", "activationId": "999", "version": 1}'
        return resp

    def get(self, url, headers=None, timeout=None):
        logger.info("[MOCK] Akamai session GET: url=%s", url)
        if "/siem/" in url:
            resp = requests.Response()
            resp.status_code = 200
            resp._content = bytes(
                '{"total":1,"offset":0,"limit":100,"events":['
                '{"_id":"MOCK_EVENT_ID","format":"json",'
                '"attackData":{"attackID":"MOCK_ATTACK","ruleID":"MOCK_RULE","ruleMessage":"Mock Akamai security event"},'
                '"geo":{"country":"ID"},"httpMessage":{"start":1735600000,"host":"mock.example.com","path":"/test","request":"GET /test HTTP/1.1","statusCode":403,"clientIP":"203.0.113.10"}}]}',
                "utf-8",
            )
            return resp
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"status": "success", "items": [], "activationStatus": "ACTIVE", "network": "STAGING", "version": 1}'
        return resp


def query_siem_events(
    baseurl: str,
    *,
    client_token: str,
    client_secret: str,
    access_token: str,
    config_id: str,
    event_id: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list[dict], str | None]:
    """Fetch security events from Akamai SIEM API.

    Returns (events[], error_str). Events are the raw dict entries from
    the API response's "events" array.

    Endpoint: GET /siem/v1/configs/{configId}/events
    """
    session = akamai_session(
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
    )

    path = f"/siem/v1/configs/{config_id}/events"
    url = f"{baseurl}{path}"
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if event_id:
        params["eventId"] = event_id

    account_switch = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None
    if account_switch:
        params["accountSwitchKey"] = account_switch

    try:
        resp = session.get(url, headers={"accept": "application/json"}, params=params, timeout=20)
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}: {resp.text[:500]}"
        data = resp.json()
        events = data.get("events") or []
        return events, None
    except Exception as e:
        return [], f"Request failed: {e}"
