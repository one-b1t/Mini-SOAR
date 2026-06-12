from __future__ import annotations

"""Unified automatic mitigation controller."""

import logging
import os
import time

from ..config import norm_provider

from . import imperva, paloalto, akamai

logger = logging.getLogger(__name__)


def trigger_commit(provider: str) -> tuple[bool, str]:
    p = norm_provider(provider)

    if p == "paloalto":
        pa_host = os.getenv("PA_HOST", "")
        pa_api_key = os.getenv("PA_API_KEY", "")
        pa_admin = os.getenv("PA_ADMIN", "")
        resp_commit = paloalto.partial_commit(pa_host, pa_api_key, admin=pa_admin)
        ok_commit = paloalto.response_message(resp_commit, "Commit")
        return "SUCCESS" in ok_commit, ok_commit

    if p == "akamai":
        baseurl = os.getenv("AKAMAI_BASEURL", "")
        list_id = os.getenv("AKAMAI_LIST_ID", "")
        client_token = os.getenv("AKAMAI_CLIENT_TOKEN", "")
        client_secret = os.getenv("AKAMAI_CLIENT_SECRET", "")
        access_token = os.getenv("AKAMAI_ACCESS_TOKEN", "")
        account_switch = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None

        session = akamai.akamai_session(
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )

        url_act = akamai.akamai_url(baseurl, f"/client-list/v1/lists/{list_id}/activations", account_switch=account_switch)
        headers = {"accept": "application/json", "content-type": "application/json"}
        act_results = []
        success = True
        try:
            for network in ["STAGING", "PRODUCTION"]:
                act_body = {"action": "ACTIVATE", "network": network, "comments": "Auto-activation by MiniSOAR ML"}
                resp_act = session.post(url_act, headers=headers, json=act_body, timeout=15)
                act_results.append(f"{network}:{resp_act.status_code}")
                if resp_act.status_code != 200:
                    success = False
            return success, f"Akamai activations: {', '.join(act_results)}"
        except Exception as e:
            return False, f"Akamai activation error: {e}"

    return False, f"Provider '{provider}' does not support commit/activation."


def trigger_auto_block(ip: str, provider: str, commit: bool = True) -> tuple[bool, str]:
    p = norm_provider(provider)

    # Imperva
    if p == "imperva":
        base_url = os.getenv("IMPERVA_BASE_URL", "")
        username = os.getenv("IMPERVA_USERNAME", "")
        password = os.getenv("IMPERVA_PASSWORD", "")
        group_name = os.getenv("IMPERVA_GROUP_NAME", "Blocked-IP-Addresses")

        cookies = imperva.login_via_api(base_url, username, password)
        if not cookies:
            return False, "Gagal login ke API Imperva."
        ok, msg = imperva.ip_blocklist_api(base_url, group_name, cookies, ip, action="add")
        return ok, msg

    # Palo Alto
    if p == "paloalto":
        pa_host = os.getenv("PA_HOST", "")
        pa_api_key = os.getenv("PA_API_KEY", "")
        pa_vsys = os.getenv("PA_VSYS", "vsys1")
        pa_group = os.getenv("PA_GROUP", "")

        resp_obj = paloalto.add_address_object(pa_host, pa_api_key, ip=ip, vsys=pa_vsys)
        resp_grp = paloalto.add_to_group(pa_host, pa_api_key, ip=ip, vsys=pa_vsys, group=pa_group)
        ok_obj = paloalto.response_message(resp_obj, "Add address object")
        ok_grp = paloalto.response_message(resp_grp, f"Add to group {pa_group}")

        if "SUCCESS" in ok_obj and "SUCCESS" in ok_grp:
            if commit:
                success, ok_commit = trigger_commit("paloalto")
                return True, f"PA: {ok_obj} | {ok_grp} | Commit: {ok_commit}"
            return True, f"PA: {ok_obj} | {ok_grp} (Commit pending)"

        return False, f"PA FAILED: {ok_obj} | {ok_grp}"

    # Akamai
    if p == "akamai":
        baseurl = os.getenv("AKAMAI_BASEURL", "")
        list_id = os.getenv("AKAMAI_LIST_ID", "")
        client_token = os.getenv("AKAMAI_CLIENT_TOKEN", "")
        client_secret = os.getenv("AKAMAI_CLIENT_SECRET", "")
        access_token = os.getenv("AKAMAI_ACCESS_TOKEN", "")
        account_switch = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None

        session = akamai.akamai_session(
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )

        url = akamai.akamai_url(baseurl, f"/client-list/v1/lists/{list_id}/items", account_switch=account_switch)
        headers = {"accept": "application/json", "content-type": "application/json"}
        body = {"append": [{"value": ip, "description": "Auto-blocked by MiniSOAR ML", "type": "IP"}]}

        try:
            resp = session.post(url, headers=headers, json=body, timeout=15)
            if resp.status_code == 200:
                if commit:
                    success, act_msg = trigger_commit("akamai")
                    return True, f"Akamai: IP added. {act_msg}"
                return True, "Akamai: IP added (Activation pending)"
            return False, f"Akamai failed adding IP: {resp.text}"
        except Exception as e:
            return False, f"Akamai error: {e}"

    return False, f"No mitigation action configured for provider '{provider}'"


def trigger_auto_unblock(ip: str, provider: str, commit: bool = True) -> tuple[bool, str]:
    p = norm_provider(provider)

    # Imperva
    if p == "imperva":
        base_url = os.getenv("IMPERVA_BASE_URL", "")
        username = os.getenv("IMPERVA_USERNAME", "")
        password = os.getenv("IMPERVA_PASSWORD", "")
        group_name = os.getenv("IMPERVA_GROUP_NAME", "Blocked-IP-Addresses")

        cookies = imperva.login_via_api(base_url, username, password)
        if not cookies:
            return False, "Gagal login ke API Imperva."
        ok, msg = imperva.ip_blocklist_api(base_url, group_name, cookies, ip, action="remove")
        return ok, msg

    # Palo Alto
    if p == "paloalto":
        pa_host = os.getenv("PA_HOST", "")
        pa_api_key = os.getenv("PA_API_KEY", "")
        pa_vsys = os.getenv("PA_VSYS", "vsys1")
        pa_group = os.getenv("PA_GROUP", "")

        resp_grp = paloalto.remove_from_group(pa_host, pa_api_key, ip=ip, vsys=pa_vsys, group=pa_group)
        resp_obj = paloalto.delete_address_object(pa_host, pa_api_key, ip=ip, vsys=pa_vsys)
        ok_grp = paloalto.response_message(resp_grp, f"Remove from group {pa_group}")
        ok_obj = paloalto.response_message(resp_obj, "Delete address object")

        if "SUCCESS" in ok_grp and "SUCCESS" in ok_obj:
            if commit:
                success, ok_commit = trigger_commit("paloalto")
                return True, f"PA: {ok_grp} | {ok_obj} | Commit: {ok_commit}"
            return True, f"PA: {ok_grp} | {ok_obj} (Commit pending)"

        return False, f"PA FAILED: {ok_grp} | {ok_obj}"

    # Akamai
    if p == "akamai":
        baseurl = os.getenv("AKAMAI_BASEURL", "")
        list_id = os.getenv("AKAMAI_LIST_ID", "")
        client_token = os.getenv("AKAMAI_CLIENT_TOKEN", "")
        client_secret = os.getenv("AKAMAI_CLIENT_SECRET", "")
        access_token = os.getenv("AKAMAI_ACCESS_TOKEN", "")
        account_switch = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None

        session = akamai.akamai_session(
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )

        url = akamai.akamai_url(baseurl, f"/client-list/v1/lists/{list_id}/items", account_switch=account_switch)
        headers = {"accept": "application/json", "content-type": "application/json"}
        body = {"delete": [{"value": ip}]}

        try:
            resp = session.post(url, headers=headers, json=body, timeout=15)
            if resp.status_code == 200:
                if commit:
                    success, act_msg = trigger_commit("akamai")
                    return True, f"Akamai: IP removed. {act_msg}"
                return True, "Akamai: IP removed (Activation pending)"
            return False, f"Akamai failed removing IP: {resp.text}"
        except Exception as e:
            return False, f"Akamai error: {e}"

    return False, f"No mitigation action configured for provider '{provider}'"


# ---------------------------------------------
# Temporary Block State Tracking in Redis ZSET
# ---------------------------------------------

REDIS_ZSET_KEY = "minisoar:pending_unblocks"


def is_ip_blocked(r, ip: str, provider: str) -> bool:
    p = norm_provider(provider)
    member = f"{p}:{ip}"
    try:
        score = r.zscore(REDIS_ZSET_KEY, member)
        if score is not None:
            return float(score) > time.time()
    except Exception as e:
        logger.error("Redis zscore check failed: %s", e)
    return False


def register_block_state(r, ip: str, provider: str, duration: int = 600) -> bool:
    """Registers block state in Redis. Returns True if successfully registered, False if already blocked."""
    p = norm_provider(provider)
    member = f"{p}:{ip}"
    now = time.time()
    try:
        score = r.zscore(REDIS_ZSET_KEY, member)
        if score is not None and float(score) > now:
            # Already blocked
            return False
        
        # Store expiration timestamp
        expiry = now + duration
        r.zadd(REDIS_ZSET_KEY, {member: expiry})
        logger.info("[TEMP-BLOCK] Registered %s on %s for %d seconds", ip, p, duration)
        return True
    except Exception as e:
        logger.error("Redis zadd failed: %s", e)
        return False


def extend_block_state(r, ip: str, provider: str, duration: int = 600) -> None:
    p = norm_provider(provider)
    member = f"{p}:{ip}"
    expiry = time.time() + duration
    try:
        r.zadd(REDIS_ZSET_KEY, {member: expiry})
        logger.info("[TEMP-BLOCK] Extended block for %s on %s by %d seconds (new expiry: %s)", ip, p, duration, time.ctime(expiry))
    except Exception as e:
        logger.error("Redis zadd extend failed: %s", e)


def get_expired_blocks(r) -> list[tuple[str, str]]:
    """Returns a list of (ip, provider) tuples that have expired."""
    now = time.time()
    try:
        expired_members = r.zrangebyscore(REDIS_ZSET_KEY, 0, now)
        out = []
        for m in expired_members:
            if ":" in m:
                p, ip = m.split(":", 1)
                out.append((ip, p))
        return out
    except Exception as e:
        logger.error("Redis zrangebyscore failed: %s", e)
        return []


def remove_block_state(r, ip: str, provider: str) -> bool:
    """Removes the block tracking state. Returns True if removed successfully."""
    p = norm_provider(provider)
    member = f"{p}:{ip}"
    try:
        res = r.zrem(REDIS_ZSET_KEY, member)
        return res > 0
    except Exception as e:
        logger.error("Redis zrem failed: %s", e)
        return False

