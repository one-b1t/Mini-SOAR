from __future__ import annotations

"""Unified automatic mitigation controller."""

import logging
import os
import time
import traceback

from ..config import norm_provider
from . import akamai, cloudflare, fortigate, imperva, paloalto

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

    # Cloudflare
    if p == "cloudflare":
        return cloudflare.block_ip(ip)

    # FortiGate
    if p == "fortigate":
        return fortigate.block_ip(ip)

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

    # Cloudflare
    if p == "cloudflare":
        return cloudflare.unblock_ip(ip)

    # FortiGate
    if p == "fortigate":
        return fortigate.unblock_ip(ip)

    return False, f"No unblock action configured for provider '{provider}'"


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


def get_active_blocklist(r=None) -> dict[str, Any]:
    """Returns all currently blocked IPs across Security Perimeters (Redis ZSET) and synced EDR IoCs."""
    if r is None:
        try:
            from ..database import redis_client
            r = redis_client()
        except Exception:
            r = None

    now = time.time()
    perimeters: list[dict[str, Any]] = []
    edr_iocs: list[dict[str, Any]] = []

    if r:
        # 1. Perimeter Blocks from Redis ZSET
        try:
            members_with_scores = r.zrangebyscore(REDIS_ZSET_KEY, now, "+inf", withscores=True)
            for member, score in members_with_scores:
                if ":" in member:
                    p, ip = member.split(":", 1)
                    ttl_sec = max(0, int(score - now))
                    perimeters.append({
                        "ip": ip,
                        "provider": p,
                        "ttl_sec": ttl_sec,
                        "expires_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(score)),
                    })
        except Exception as e:
            logger.error("Failed to read perimeter blocklist from Redis: %s", e)

        # 2. EDR IoC Synced IPs from Redis Cache Keys
        try:
            keys = r.keys("minisoar:edr_ioc_synced:*")
            for k in keys:
                ip = k.replace("minisoar:edr_ioc_synced:", "")
                ttl = r.ttl(k)
                edr_iocs.append({
                    "ip": ip,
                    "provider": "Kaspersky & Trend Micro",
                    "ttl_sec": ttl if ttl > 0 else 86400,
                    "status": "Active (IoC Repository)",
                })
        except Exception as e:
            logger.error("Failed to read EDR IoC list from Redis: %s", e)

    return {
        "perimeters": perimeters,
        "edr_iocs": edr_iocs,
        "total_perimeter": len(perimeters),
        "total_edr": len(edr_iocs),
    }


# ---------------------------------------------
# Perimeter connectivity check (startup diagnostics)
# ---------------------------------------------

def check_perimeter_connectivity() -> list[dict]:
    """Probe every perimeter provider that has credentials configured in env.

    Each result dict has: provider, configured, ok, error, hint, and
    (only on unexpected exceptions) traceback — so callers can log the
    root cause and a fix suggestion without re-deriving them.
    """
    results: list[dict] = []

    # Palo Alto
    pa_host = os.getenv("PA_HOST", "")
    pa_api_key = os.getenv("PA_API_KEY", "")
    if pa_host and pa_api_key:
        entry = {"provider": "paloalto", "configured": True, "ok": False, "error": None, "hint": None}
        try:
            resp = paloalto.palo_api_request(
                pa_host,
                {"type": "op", "cmd": "<show><system><info></info></system></show>", "key": pa_api_key},
            )
            if "error" in resp:
                entry["error"] = resp["error"]
                entry["hint"] = "Periksa PA_HOST bisa dijangkau (jaringan/firewall) dan port HTTPS terbuka."
            elif resp.get("response", {}).get("@status") == "success":
                entry["ok"] = True
            else:
                entry["error"] = resp.get("response", {}).get("msg", "Unknown error")
                entry["hint"] = "Periksa PA_API_KEY masih valid (belum revoked/expired)."
        except Exception as e:
            entry["error"] = str(e)
            entry["hint"] = "Exception saat menghubungi Palo Alto API. Periksa PA_HOST dan konektivitas jaringan."
            entry["traceback"] = traceback.format_exc()
        results.append(entry)
    else:
        results.append({"provider": "paloalto", "configured": False, "ok": None, "error": None, "hint": None})

    # Imperva
    imperva_base = os.getenv("IMPERVA_BASE_URL", "")
    imperva_user = os.getenv("IMPERVA_USERNAME", "")
    imperva_pass = os.getenv("IMPERVA_PASSWORD", "")
    if imperva_base and imperva_user and imperva_pass:
        entry = {"provider": "imperva", "configured": True, "ok": False, "error": None, "hint": None}
        try:
            cookies = imperva.login_via_api(imperva_base, imperva_user, imperva_pass)
            if cookies:
                entry["ok"] = True
            else:
                entry["error"] = "Login gagal (kredensial ditolak atau endpoint tidak terjangkau)."
                entry["hint"] = "Periksa IMPERVA_BASE_URL, IMPERVA_USERNAME, IMPERVA_PASSWORD, dan konektivitas jaringan."
        except Exception as e:
            entry["error"] = str(e)
            entry["hint"] = "Exception saat login ke Imperva API. Periksa IMPERVA_BASE_URL dan konektivitas jaringan."
            entry["traceback"] = traceback.format_exc()
        results.append(entry)
    else:
        results.append({"provider": "imperva", "configured": False, "ok": None, "error": None, "hint": None})

    # Akamai
    akamai_baseurl = os.getenv("AKAMAI_BASEURL", "")
    akamai_list_id = os.getenv("AKAMAI_LIST_ID", "")
    akamai_client_token = os.getenv("AKAMAI_CLIENT_TOKEN", "")
    akamai_client_secret = os.getenv("AKAMAI_CLIENT_SECRET", "")
    akamai_access_token = os.getenv("AKAMAI_ACCESS_TOKEN", "")
    if akamai_baseurl and akamai_list_id and akamai_client_token and akamai_client_secret and akamai_access_token:
        entry = {"provider": "akamai", "configured": True, "ok": False, "error": None, "hint": None}
        try:
            session = akamai.akamai_session(
                client_token=akamai_client_token,
                client_secret=akamai_client_secret,
                access_token=akamai_access_token,
            )
            account_switch = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None
            url = akamai.akamai_url(akamai_baseurl, f"/client-list/v1/lists/{akamai_list_id}", account_switch=account_switch)
            resp = session.get(url, headers={"accept": "application/json"}, timeout=10)
            if resp.status_code == 200:
                entry["ok"] = True
            else:
                entry["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                entry["hint"] = "Periksa AKAMAI_LIST_ID valid dan kredensial EdgeGrid (CLIENT_TOKEN/SECRET/ACCESS_TOKEN) belum expired."
        except Exception as e:
            entry["error"] = str(e)
            entry["hint"] = "Exception saat menghubungi Akamai API. Periksa AKAMAI_BASEURL dan konektivitas jaringan."
            entry["traceback"] = traceback.format_exc()
        results.append(entry)
    else:
        results.append({"provider": "akamai", "configured": False, "ok": None, "error": None, "hint": None})

    # Cloudflare
    results.append(cloudflare.check_connectivity())

    # FortiGate
    results.append(fortigate.check_connectivity())

    return results

