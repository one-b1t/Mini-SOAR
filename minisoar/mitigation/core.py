from __future__ import annotations

"""Unified automatic mitigation controller."""

import os

from ..config import norm_provider

from . import imperva, paloalto, akamai


def trigger_auto_block(ip: str, provider: str) -> tuple[bool, str]:
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
        pa_admin = os.getenv("PA_ADMIN", "")

        resp_obj = paloalto.add_address_object(pa_host, pa_api_key, ip=ip, vsys=pa_vsys)
        resp_grp = paloalto.add_to_group(pa_host, pa_api_key, ip=ip, vsys=pa_vsys, group=pa_group)
        ok_obj = paloalto.response_message(resp_obj, "Add address object")
        ok_grp = paloalto.response_message(resp_grp, f"Add to group {pa_group}")

        if "SUCCESS" in ok_obj and "SUCCESS" in ok_grp:
            resp_commit = paloalto.partial_commit(pa_host, pa_api_key, admin=pa_admin)
            ok_commit = paloalto.response_message(resp_commit, "Commit")
            return True, f"PA: {ok_obj} | {ok_grp} | {ok_commit}"

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
                url_act = akamai.akamai_url(baseurl, f"/client-list/v1/lists/{list_id}/activations", account_switch=account_switch)
                act_results = []
                for network in ["STAGING", "PRODUCTION"]:
                    act_body = {"action": "ACTIVATE", "network": network, "comments": "Auto-activation by MiniSOAR ML"}
                    resp_act = session.post(url_act, headers=headers, json=act_body, timeout=15)
                    act_results.append(f"{network}:{resp_act.status_code}")
                return True, f"Akamai: IP added. Activations: {', '.join(act_results)}"
            return False, f"Akamai failed adding IP: {resp.text}"
        except Exception as e:
            return False, f"Akamai error: {e}"

    return False, f"No mitigation action configured for provider '{provider}'"
