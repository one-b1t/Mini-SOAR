from __future__ import annotations

import logging
import os

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
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"status": "success", "items": [], "activationStatus": "ACTIVE", "network": "STAGING", "version": 1}'
        return resp
