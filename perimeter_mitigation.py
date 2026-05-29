import os
import requests
import urllib3
import xmltodict
import ipaddress
import logging
import datetime
from pathlib import Path
from requests.auth import HTTPBasicAuth
from akamai.edgegrid import EdgeGridAuth

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ==== CONFIGURATIONS ====
IMPERVA_BASE_URL = os.getenv("IMPERVA_BASE_URL", "")
IMPERVA_USERNAME = os.getenv("IMPERVA_USERNAME", "")
IMPERVA_PASSWORD = os.getenv("IMPERVA_PASSWORD", "")
IMPERVA_GROUP_NAME = os.getenv("IMPERVA_GROUP_NAME", "Blocked-IP-Addresses")

BASE_URL = IMPERVA_BASE_URL
USERNAME = IMPERVA_USERNAME
PASSWORD = IMPERVA_PASSWORD
GROUP_NAME = IMPERVA_GROUP_NAME

PA_HOST = os.getenv("PA_HOST", "")
PA_API_KEY = os.getenv("PA_API_KEY", "")
PA_VSYS = os.getenv("PA_VSYS", "vsys1")
PA_GROUP = os.getenv("PA_GROUP", "")
PA_ADMIN = os.getenv("PA_ADMIN", "")

AKAMAI_BASEURL = os.getenv("AKAMAI_BASEURL", "")
AKAMAI_LIST_ID = os.getenv("AKAMAI_LIST_ID", "")
AKAMAI_CLIENT_TOKEN = os.getenv("AKAMAI_CLIENT_TOKEN", "")
AKAMAI_CLIENT_SECRET = os.getenv("AKAMAI_CLIENT_SECRET", "")
AKAMAI_ACCESS_TOKEN = os.getenv("AKAMAI_ACCESS_TOKEN", "")
AKAMAI_ACCOUNT_SWITCH = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None

# ==== LOGFILE PATH RESOLUTION ====
def resolve_log_path(env_key: str, default_linux_path: str, default_win_filename: str) -> str:
    val = os.getenv(env_key)
    if val:
        return val
    script_dir = Path(__file__).resolve().parent
    if os.name == "nt":
        return str(script_dir / default_win_filename)
    try:
        parent = os.path.dirname(default_linux_path)
        if parent and os.path.exists(parent):
            return default_linux_path
    except Exception:
        pass
    return str(script_dir / default_win_filename)

LOGFILE = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

# ==== UTILITIES ====
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def _norm_provider(p) -> str:
    s = (p or "").strip().lower()
    if s in {"palo", "paloalto", "palo-alto", "palo_alto", "pan", "panos"}:
        return "paloalto"
    if s in {"akamai", "ak"}:
        return "akamai"
    if s in {"imperva", "imp"}:
        return "imperva"
    if s in {"none", "external", "eksternal", "outside", "off"}:
        return "none"
    return s or "none"

# ==== LOGGING AND TELEGRAM NOTIFICATIONS ====
def send_process_log_telegram_sync(action, username, user_id, ip=None, target="-", source="-", note=None):
    telegram_token = os.environ.get("TELEGRAM_TOKEN") or os.environ.get("TELEGRAM_BOT", "")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    telegram_process_chat_id = os.environ.get("TELEGRAM_PROCESS_CHAT_ID", "") or telegram_chat_id
    
    if not telegram_process_chat_id or not telegram_token:
        return
        
    actor = f"@{username}" if username else f"id:{user_id}"
    text = (
        f"⚙️ *[PROSES LOG]*\n"
        f"• *Action:* `{action}`\n"
        f"• *Actor:* {actor} (`{user_id}`)\n"
        f"• *Target IP:* `{ip or '-'}`\n"
        f"• *Platform:* `{target}`\n"
        f"• *Source:* `{source}`\n"
    )
    if note:
        text += f"• *Note:* `{note}`\n"
        
    url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
    payload = {
        "chat_id": telegram_process_chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code >= 400:
            logger.error(f"Failed to send process log: {resp.text}")
    except Exception as e:
        logger.error(f"Exception sending process log: {e}")

def log_user_action(action, user, ip=None, target="-", source="-", note=None, chat_id=None):
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if hasattr(user, "id"):
            user_id = user.id
            username = getattr(user, "username", None) or getattr(user, "full_name", None) or f"id:{user_id}"
        elif isinstance(user, dict):
            user_id = user.get("id", "system")
            username = user.get("username", "system")
        else:
            user_id = "system"
            username = str(user)

        line = (
            f"[{ts}] ACTION={action} | user={username} (id:{user_id})"
            f" | ip={ip or '-'} | target={target} | source={source}"
        )
        if chat_id is not None:
            line += f" | chat={chat_id}"
        if note:
            line += f" | note={note}"
        line += "\n"

        with open(LOGFILE, "a") as f:
            f.write(line)

        logger.info(line.strip())
        send_process_log_telegram_sync(action, username, user_id, ip, target, source, note)

    except Exception as e:
        logger.error(f"Logfile write error: {e}")

# ==== IMPERVA MITIGATION FUNCTIONS ====
def login_via_api():
    login_url = f"{BASE_URL}/SecureSphere/api/v1/auth/session"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = requests.post(
            login_url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers=headers,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            session_id = response.json().get("session-id")
            if session_id:
                cookies = {}
                for item in session_id.split(";"):
                    if "=" in item:
                        key, value = item.strip().split("=", 1)
                        cookies[key] = value
                return cookies
    except Exception as e:
        logger.error(f"Imperva login API connection failed: {e}")
    return None

def imperva_api_request(method: str, path: str, cookies: dict, *, params=None, json=None, timeout=20):
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info(f"[MOCK] Imperva API request: {method} {path} (params: {params}, json: {json})")
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b'{"status": "success", "message": "mocked response"}'
        return mock_resp

    url = f"{BASE_URL}{path}"
    headers = {"Accept": "application/json"}
    if json is not None:
        headers["Content-Type"] = "application/json"

    resp = requests.request(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        params=params,
        json=json,
        verify=False,
        timeout=timeout
    )
    return resp

def ip_blocklist_api(api_cookies: dict, ip_address: str, action: str = "add"):
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info(f"[MOCK] Imperva Blocklist API: action={action}, IP={ip_address}")
        return True, f"✅ [MOCK] IP {ip_address} berhasil di{'blokir' if action == 'add' else 'unblokir'} di Imperva On-prem."

    api_url = f"{BASE_URL}/SecureSphere/api/v1/conf/ipGroups/{GROUP_NAME}/data"
    payload = {
        "entries": [
            {
                "operation": action,
                "type": "single",
                "ipAddressFrom": ip_address
            }
        ]
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = requests.put(
            api_url,
            json=payload,
            headers=headers,
            cookies=api_cookies,
            verify=False,
            timeout=15
        )
        if response.status_code == 200:
            return True, f"✅ IP {ip_address} berhasil di{'blokir' if action == 'add' else 'unblokir'} di Imperva On-prem."
        else:
            return False, f"❌ Gagal {'blokir' if action == 'add' else 'unblokir'} IP {ip_address} ({response.status_code}): {response.text}"
    except Exception as e:
        return False, f"❌ Connection error during Imperva blocklist update: {e}"

def get_blocked_ip_list(api_cookies: dict, group_name: str = GROUP_NAME):
    api_url = f"{BASE_URL}/SecureSphere/api/v1/conf/ipGroups/{group_name}/data"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = requests.get(
            api_url,
            headers=headers,
            cookies=api_cookies,
            verify=False,
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            ip_entries = [
                entry['ipAddressFrom']
                for entry in data.get('entries', [])
                if entry.get("type") == "single"
            ]
            return ip_entries
    except Exception as e:
        logger.error(f"Failed to fetch blocked IP list from Imperva: {e}")
    return None

def imperva_get_violation_by_event_number(cookies: dict, event_number: str, days: int = 7, limit: int = 50):
    path = "/SecureSphere/api/v1/monitor/violations/"
    event_number_str = str(event_number).strip()

    params = {
        "lastFewDays": days,
        "eventNumber": event_number_str,
        "limit": int(limit),
    }

    try:
        resp = imperva_api_request("GET", path, cookies, params=params)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text}"
        data = resp.json()
    except Exception as e:
        return None, f"Request failed: {e}"

    if isinstance(data, dict):
        violations = data.get("violations") or []
    elif isinstance(data, list):
        violations = data
    else:
        violations = []

    if not violations:
        return None, "Violation not found"

    exact = []
    for v in violations:
        if isinstance(v, dict) and str(v.get("eventNumber", "")).strip() == event_number_str:
            exact.append(v)

    if exact:
        return exact[0], None

    return None, "Violation not found"

def imperva_get_violation_by_event_id(cookies: dict, event_id: str, days: int = 7):
    return imperva_get_violation_by_event_number(cookies, event_number=event_id, days=days)


# ==== PALO ALTO XML API MITIGATION FUNCTIONS ====
def build_pa_object_name(ip):
    return f"{ip}minisoar"

def palo_api_request(params):
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        logger.info(f"[MOCK] Palo Alto API request: params={params}")
        action = params.get("action")
        if action == "commit":
            return {
                "response": {
                    "@status": "success",
                    "result": {
                        "job": "1234",
                        "msg": "Commit job started"
                    }
                }
            }
        return {
            "response": {
                "@status": "success",
                "result": "Mocked configuration command successful"
            }
        }

    try:
        url = f"{PA_HOST}/api/"
        r = requests.get(url, params=params, verify=False, timeout=10)
        r.raise_for_status()
        return xmltodict.parse(r.text)
    except Exception as e:
        return {"error": str(e)}

def pa_add_address_object(ip):
    name = build_pa_object_name(ip)
    params = {
        "type": "config",
        "action": "set",
        "key": PA_API_KEY,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{PA_VSYS}']/address",
        "element": f"<entry name='{name}'><ip-netmask>{ip}</ip-netmask></entry>"
    }
    return palo_api_request(params)

def pa_add_to_group(ip):
    name = build_pa_object_name(ip)
    params = {
        "type": "config",
        "action": "set",
        "key": PA_API_KEY,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{PA_VSYS}']/address-group/entry[@name='{PA_GROUP}']/static",
        "element": f"<member>{name}</member>"
    }
    return palo_api_request(params)

def pa_remove_from_group(ip):
    name = build_pa_object_name(ip)
    params = {
        "type": "config",
        "action": "delete",
        "key": PA_API_KEY,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{PA_VSYS}']/address-group/entry[@name='{PA_GROUP}']/static/member[text()='{name}']"
    }
    return palo_api_request(params)

def pa_delete_address_object(ip):
    name = build_pa_object_name(ip)
    params = {
        "type": "config",
        "action": "delete",
        "key": PA_API_KEY,
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{PA_VSYS}']/address/entry[@name='{name}']"
    }
    return palo_api_request(params)

def pa_partial_commit():
    params = {
        "type": "commit",
        "key": PA_API_KEY,
        "cmd": f"<commit><partial><admin><member>{PA_ADMIN}</member></admin></partial></commit>"
    }
    return palo_api_request(params)

def get_response_message(resp, action_desc):
    if "error" in resp:
        return f"{action_desc}: ERROR - {resp['error']}"
    try:
        status = resp["response"]["@status"]
        if status == "success":
            return f"{action_desc}: SUCCESS"
        else:
            msg = resp["response"].get("msg", "Unknown error")
            return f"{action_desc}: FAILED - {msg}"
    except Exception:
        return f"{action_desc}: ERROR - Invalid response format"


# ==== AKAMAI MITIGATION FUNCTIONS ====
class MockAkamaiSession:
    def post(self, url, headers=None, json=None, timeout=None):
        logger.info(f"[MOCK] Akamai session POST: url={url}, json={json}")
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"status": "success", "message": "mocked response", "activationStatus": "RECEIVED", "activationId": "999", "version": 1}'
        return resp
    def get(self, url, headers=None, timeout=None):
        logger.info(f"[MOCK] Akamai session GET: url={url}")
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"status": "success", "items": [], "activationStatus": "ACTIVE", "network": "STAGING", "version": 1}'
        return resp

def akamai_session():
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return MockAkamaiSession()

    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=AKAMAI_CLIENT_TOKEN,
        client_secret=AKAMAI_CLIENT_SECRET,
        access_token=AKAMAI_ACCESS_TOKEN
    )
    return session

def akamai_url(path):
    url = f"{AKAMAI_BASEURL}{path}"
    if AKAMAI_ACCOUNT_SWITCH:
        url += f"?accountSwitchKey={AKAMAI_ACCOUNT_SWITCH}"
    return url


# ==== UNIFIED AUTOMATIC BLOCK CONTROLLER ====
def trigger_auto_block(ip: str, provider: str) -> tuple[bool, str]:
    """
    Executes an automatic block on the specified perimeter.
    Returns (success, message)
    """
    p = _norm_provider(provider)
    if p == "imperva":
        cookies = login_via_api()
        if not cookies:
            return False, "Gagal login ke API Imperva."
        ok, msg = ip_blocklist_api(cookies, ip, action="add")
        return ok, msg
        
    elif p == "paloalto":
        resp_obj = pa_add_address_object(ip)
        resp_grp = pa_add_to_group(ip)
        ok_obj = get_response_message(resp_obj, "Add address object")
        ok_grp = get_response_message(resp_grp, f"Add to group {PA_GROUP}")
        
        if "SUCCESS" in ok_obj and "SUCCESS" in ok_grp:
            resp_commit = pa_partial_commit()
            ok_commit = get_response_message(resp_commit, "Commit")
            return True, f"PA: {ok_obj} | {ok_grp} | {ok_commit}"
        return False, f"PA FAILED: {ok_obj} | {ok_grp}"
        
    elif p == "akamai":
        session = akamai_session()
        url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/items")
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }
        body = {
            "append": [{
                "value": ip,
                "description": "Auto-blocked by MiniSOAR ML",
                "type": "IP"
            }]
        }
        try:
            resp = session.post(url, headers=headers, json=body, timeout=15)
            if resp.status_code == 200:
                # Trigger edge activation immediately
                url_act = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/activations")
                act_results = []
                for network in ["STAGING", "PRODUCTION"]:
                    act_body = {
                        "action": "ACTIVATE",
                        "network": network,
                        "comments": "Auto-activation by MiniSOAR ML"
                    }
                    resp_act = session.post(url_act, headers=headers, json=act_body, timeout=15)
                    act_results.append(f"{network}:{resp_act.status_code}")
                return True, f"Akamai: IP added. Activations: {', '.join(act_results)}"
            else:
                return False, f"Akamai failed adding IP: {resp.text}"
        except Exception as e:
            return False, f"Akamai error: {e}"
            
    return False, f"No mitigation action configured for provider '{provider}'"


# ==== ELASTICSEARCH LABEL LOGGING ====
ES_HOSTS = os.getenv("ES_HOSTS", "")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")
ES_VERIFY = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
ES_CA_BUNDLE = os.getenv("ES_CA_BUNDLE", "").strip()
ES_LABELS_INDEX_PREFIX = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
ES_TIMEOUT = int(os.getenv("ES_TIMEOUT", "6"))

def _es_host() -> str:
    if not ES_HOSTS:
        return ""
    hosts = [h.strip() for h in ES_HOSTS.split(",") if h.strip()]
    return hosts[0] if hosts else ""

def _es_verify_value():
    return ES_CA_BUNDLE or ES_VERIFY

def _es_index(index_name: str, doc_id: str, payload: dict):
    host = _es_host()
    if not host:
        return
    url = f"{host.rstrip('/')}/{index_name}/_doc/{doc_id}"
    auth = (ES_USER, ES_PASS) if ES_USER or ES_PASS else None
    try:
        resp = requests.put(url, json=payload, auth=auth, verify=_es_verify_value(), timeout=ES_TIMEOUT)
        if resp.status_code >= 400:
            logger.warning("ES label index error %s: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("ES label index exception: %s", e)

def store_label(event_id: str, label: str, user, reason_code: str, *, ip: str = None, telegram_message_id: str = None, chat_id: str = None):
    ts = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    index_name = f"{ES_LABELS_INDEX_PREFIX}-{datetime.datetime.utcnow().strftime('%Y.%m.%d')}"
    
    if hasattr(user, "id"):
        user_id = getattr(user, "id")
        username = getattr(user, "username", None) or getattr(user, "full_name", None)
    elif isinstance(user, dict):
        user_id = user.get("id")
        username = user.get("username")
    else:
        user_id = "system"
        username = str(user)

    doc = {
        "@timestamp": ts,
        "event_id": event_id,
        "label": label,
        "actor": {
            "username": username,
            "id": user_id,
        },
        "reason_code": reason_code,
    }
    if ip:
        doc["src"] = {"ip": ip}
    if telegram_message_id is not None or chat_id is not None:
        doc["telegram"] = {}
        if telegram_message_id is not None:
            doc["telegram"]["message_id"] = str(telegram_message_id)
        if chat_id is not None:
            doc["telegram"]["chat_id"] = str(chat_id)

    base = event_id or ip or "na"
    doc_id = f"{base}:{label}:{user_id}:{telegram_message_id or 'na'}"
    _es_index(index_name, doc_id, doc)

