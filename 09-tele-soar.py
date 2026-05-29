from dotenv import load_dotenv
from pathlib import Path
import os

# Load env (prioritas system, fallback lokal)
load_dotenv("/root/tele-soar/.env", override=False)
load_dotenv(Path(__file__).with_name(".env"), override=False)

# Force load from local .env if critical variables are empty/missing in environment
if not os.environ.get("TELEGRAM_TOKEN") and not os.environ.get("TELEGRAM_BOT"):
    load_dotenv(Path(__file__).with_name(".env"), override=True)


import logging

logger = logging.getLogger(__name__)
import os
import requests
import urllib3
import xmltodict
import ipaddress
import datetime
import asyncio
from telegram import Update, Bot
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from requests.auth import HTTPBasicAuth
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters, ContextTypes
from telegram import InlineKeyboardMarkup
from akamai.edgegrid import EdgeGridAuth
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from perimeter_mitigation import (
    log_user_action,
    login_via_api,
    imperva_api_request,
    ip_blocklist_api,
    palo_api_request,
    pa_add_address_object,
    pa_add_to_group,
    pa_remove_from_group,
    pa_delete_address_object,
    pa_partial_commit,
    get_response_message,
    MockAkamaiSession,
    akamai_session,
    akamai_url,
    valid_ip,
    imperva_get_violation_by_event_number,
    imperva_get_violation_by_event_id,
    store_label
)

# === TELEGRAM CONFIG ===
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN") or os.getenv("TELEGRAM_BOT", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_PROCESS_CHAT_ID = os.getenv("TELEGRAM_PROCESS_CHAT_ID", "") or TELEGRAM_CHAT_ID

# === AUTHORIZED USER ===
ALLOWED_USERS = [
    int(x) for x in os.getenv("ALLOWED_USERS", "").split(",") if x.strip().isdigit()
]
# === HELPER AUTH USER ===
def is_user_allowed(user_id):
    return user_id in ALLOWED_USERS

# === KONFIGURASI AKAMAI CLIENT LIST ===
AKAMAI_BASEURL = os.getenv("AKAMAI_BASEURL", "")
AKAMAI_LIST_ID = os.getenv("AKAMAI_LIST_ID", "")
AKAMAI_CLIENT_TOKEN = os.getenv("AKAMAI_CLIENT_TOKEN", "")
AKAMAI_CLIENT_SECRET = os.getenv("AKAMAI_CLIENT_SECRET", "")
AKAMAI_ACCESS_TOKEN = os.getenv("AKAMAI_ACCESS_TOKEN", "")
AKAMAI_ACCOUNT_SWITCH = os.getenv("AKAMAI_ACCOUNT_SWITCH") or None


# === KONFIGURASI PALO ALTO XML API ===
PA_HOST = os.getenv("PA_HOST", "")
PA_API_KEY = os.getenv("PA_API_KEY", "")
PA_VSYS = os.getenv("PA_VSYS", "vsys1")
PA_GROUP = os.getenv("PA_GROUP", "")
PA_ADMIN = os.getenv("PA_ADMIN", "")


# === KONFIGURASI IMPERVA ON-PREM ===
BASE_URL = os.getenv("IMPERVA_BASE_URL", "")
USERNAME = os.getenv("IMPERVA_USERNAME", "")
PASSWORD = os.getenv("IMPERVA_PASSWORD", "")
GROUP_NAME = os.getenv("IMPERVA_GROUP_NAME", "Blocked-IP-Addresses")


# === KONFIGURASI ELASTICSEARCH (LABEL STORAGE) ===
ES_HOSTS = os.getenv("ES_HOSTS", "")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")
ES_VERIFY = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
ES_CA_BUNDLE = os.getenv("ES_CA_BUNDLE", "").strip()
ES_LABELS_INDEX_PREFIX = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
ES_TIMEOUT = int(os.getenv("ES_TIMEOUT", "6"))


# === FILE LOG AUDIT ===
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
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


# === HELPER BROADCAST PROSES KE TELEGRAM ===
async def broadcast_process_log(action, user, ip=None, target="-", source="-", note=None):
    if not TELEGRAM_PROCESS_CHAT_ID or not TELEGRAM_TOKEN:
        return
    try:
        uname = getattr(user, "username", None)
        if uname:
            actor = f"@{uname}"
        else:
            actor = getattr(user, "full_name", None) or f"id:{user.id}"
            
        # Format notifikasi audit log proses
        text = (
            f"⚙️ *[PROSES LOG]*\n"
            f"• *Action:* `{action}`\n"
            f"• *Actor:* {actor} (`{user.id}`)\n"
            f"• *Target IP:* `{ip or '-'}`\n"
            f"• *Platform:* `{target}`\n"
            f"• *Source:* `{source}`\n"
        )
        if note:
            text += f"• *Note:* `{note}`\n"
            
        bot = Bot(token=TELEGRAM_TOKEN)
        await bot.send_message(chat_id=TELEGRAM_PROCESS_CHAT_ID, text=text, parse_mode="Markdown")
    except Exception as e:
        logging.error(f"Failed to broadcast process log to telegram: {e}")

def _es_host() -> str:
    if not ES_HOSTS:
        return ""
    hosts = [h.strip() for h in ES_HOSTS.split(",") if h.strip()]
    return hosts[0] if hosts else ""

def _es_verify_value():
    return ES_CA_BUNDLE or ES_VERIFY

def _es_find_latest_event_id_by_ip(ip: str, approx_dt: datetime.datetime = None, window_minutes: int = 30):
    """Best-effort lookup of event_id from minisoar-events-* by IP and time window.

    This is used when callback_data cannot carry event_id (Telegram 64-byte limit),
    so we can still write `minisoar-labels-*` with the correct event_id.
    """
    host = _es_host()
    if not host or not ip:
        return None

    auth = (ES_USER, ES_PASS) if ES_USER or ES_PASS else None
    url = f"{host.rstrip('/')}/minisoar-events-*/_search"

    must = []
    if approx_dt:
        try:
            if getattr(approx_dt, "tzinfo", None) is not None:
                approx_dt = approx_dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        except Exception:
            pass
        # range window around the message time
        start = (approx_dt - datetime.timedelta(minutes=window_minutes)).replace(microsecond=0).isoformat() + "Z"
        end = (approx_dt + datetime.timedelta(minutes=window_minutes)).replace(microsecond=0).isoformat() + "Z"
        must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

    # cover common field variants
    should = [
        {"term": {"src.ip.keyword": ip}},
        {"term": {"src.ip": ip}},
        {"term": {"alert.src_ip.keyword": ip}},
        {"term": {"alert.src_ip": ip}},
        {"term": {"event.src.ip.keyword": ip}},
        {"term": {"event.src.ip": ip}},
        {"term": {"event.alert.src_ip.keyword": ip}},
        {"term": {"event.alert.src_ip": ip}},
    ]

    query = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["event_id", "event.event_id", "alert.src_ip", "src.ip", "@timestamp"],
        "query": {
            "bool": {
                "must": must,
                "should": should,
                "minimum_should_match": 1,
            }
        }
    }

    try:
        resp = requests.get(url, json=query, auth=auth, verify=_es_verify_value(), timeout=ES_TIMEOUT)
        if resp.status_code >= 400:
            logging.warning("ES event lookup error %s: %s", resp.status_code, resp.text[:200])
            return None
        data = resp.json()
        hits = (data.get("hits") or {}).get("hits") or []
        if not hits:
            return None
        src = hits[0].get("_source") or {}
        return src.get("event_id") or (src.get("event") or {}).get("event_id")
    except Exception as e:
        logging.warning("ES event lookup exception: %s", e)
        return None


def _parse_callback_payload(payload: str):
    if "|" in payload:
        ip, event_id = payload.split("|", 1)
        return ip, event_id
    return payload, None

# === COMMAND HANDLERS IMPERVA ===
async def blockonimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Format: /blockonimperva <ip>")
        return

    ip = context.args[0]
    # LOGGING
    log_user_action(
        action="block_imperva",
        user=user,
        ip=ip,
        target="Imperva",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Memproses blokir IP {ip}...")

    cookies = login_via_api()
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva. Cek kredensial/API.")
        return

    ok, msg = ip_blocklist_api(cookies, ip, action="add")
    await update.message.reply_text(msg)

async def unblockonimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Format: /unblockonimperva <ip>")
        return

    ip = context.args[0]
    # LOGGING
    log_user_action(
        action="unblock_imperva",
        user=user,
        ip=ip,
        target="Imperva",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Memproses unblock IP {ip}...")

    cookies = login_via_api()
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva. Cek kredensial/API.")
        return

    ok, msg = ip_blocklist_api(cookies, ip, action="remove")
    await update.message.reply_text(msg)


# ======== HANDLER UNTUK CALLBACK DATA TOMBOL BLOCK IP  =========
async def callback_query_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user = query.from_user
    user_id = user.id

    if not is_user_allowed(user_id):
        await query.answer("❌ Maaf, kamu tidak punya akses untuk blokir IP ini.", show_alert=True)
        return

    data = query.data

    # ====== HILANGKAN SEMUA TOMBOL SETELAH ACTION ======
    await query.edit_message_reply_markup(reply_markup=None)

    # ====== Lanjut proses sesuai tombol yang di-klik ======
    if data.startswith("blockonimperva:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        # LOGGING
        log_user_action(
            action="block_imperva",
            user=user,
            ip=ip_to_block,
            target="Imperva",
            source="button",
            chat_id=update.effective_chat.id,
            note="inline_button"
        )

        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Memproses blokir IP [{ip_to_block}](http://{ip_to_block}) ...",
            parse_mode="Markdown"
        )
        cookies = login_via_api()
        if not cookies:
            await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Gagal login ke API Imperva. Cek kredensial/API.")
            return
        ok, msg = ip_blocklist_api(cookies, ip_to_block, action="add")
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)
        if not event_id:
            event_id = _es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Blokir di Imperva diproses!")

    elif data.startswith("blockonpalo:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        # LOGGING
        log_user_action(
            action="block_palo",
            user=user,
            ip=ip_to_block,
            target="PaloAlto",
            source="button",
            chat_id=update.effective_chat.id,
            note="inline_button"
        )

        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Menambah {ip_to_block} ke IP group di Palo Alto ...",
            parse_mode="Markdown"
        )
        resp_obj = pa_add_address_object(ip_to_block)
        resp_grp = pa_add_to_group(ip_to_block)
        msg = "\n".join([
            f"✅{ip_to_block} berhasil ditambahkan ke {PA_GROUP}.\n"
            f"Jangan lupa jalankan /commitpalo untuk mengaktifkan konfigurasi."
        ])
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)
        if not event_id:
            event_id = _es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Penambahan IP ke Palo Alto diproses!, Jangan lupa commit!")

    elif data.startswith("blockonakamai:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        # LOGGING
        log_user_action(
            action="block_akamai",
            user=user,
            ip=ip_to_block,
            target="Akamai",
            source="button",
            chat_id=update.effective_chat.id,
            note="inline_button"
        )

        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Menambah {ip_to_block} ke Akamai Client List..."
        )
        session = akamai_session()
        url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/items")
        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }
        body = {
            "append": [{
                "value": ip_to_block,
                "description": "added via button",
                "type": "IP"
            }]
        }
        resp = session.post(url, headers=headers, json=body)
        if resp.status_code == 200:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"✅ {ip_to_block} berhasil ditambahkan ke client list Akamai.\n"
                     f"Jangan lupa jalankan /activateakamai untuk commit ke edge."
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ Gagal add IP ke Akamai: {resp.text}"
            )
        if not event_id:
            event_id = _es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Block di Akamai diproses!")
    elif data.startswith("ignore:"):
        payload = data.split(":", 1)[1].strip()
        ip_to_ignore, event_id = _parse_callback_payload(payload)

        # LOGGING
        log_user_action(
            action="ignore_alert",
            user=user,
            ip=ip_to_ignore,
            target="miniSOAR",
            source="button",
            chat_id=update.effective_chat.id,
            note="inline_button"
        )

        # best-effort event_id lookup for Phase 0 labeling
        if not event_id:
            event_id = _es_find_latest_event_id_by_ip(ip_to_ignore, getattr(query.message, "date", None))

        store_label(
            event_id,
            "ignore",
            user,
            "ignore",
            ip=ip_to_ignore,
            telegram_message_id=getattr(query.message, "message_id", None),
            chat_id=update.effective_chat.id
        )

        await query.answer("Diabaikan (ignore).")
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"🙈 Ignored: `{ip_to_ignore}`",
            parse_mode="Markdown"
        )

    else:
        await query.edit_message_text("Perintah tidak dikenali.")

# ==== HANDLER UNTUK TOMBOL PAGINATION LISTBLOCKED ====
async def pagination_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data

    if data.startswith("blocklistimperva:"):
        page = int(data.split(":", 1)[1])
        context.user_data['page'] = page
        await send_ip_page(update, context, page=page)
        await query.answer()
    elif data.startswith("blocklistakamai:"):
        page = int(data.split(":", 1)[1])
        context.user_data['akamai_page'] = page
        await send_akamai_page(update, context, page=page)
        await query.answer()
    else:
        return

# ==== HANDLER /LISTBLOCK WITH PAGINATION ====
IP_PAGE_SIZE = 10  # Jumlah IP per halaman

async def blocklistimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    cookies = login_via_api()
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva.")
        return

    ip_list = get_blocked_ip_list(cookies)
    if ip_list is None:
        await update.message.reply_text("❌ Gagal query daftar IP dari Imperva.")
        return

    context.user_data['ip_list'] = ip_list
    context.user_data['page'] = 0

    # LOGGING (view list)
    log_user_action(
        action="list_imperva_block",
        user=user,
        ip=None,
        target="Imperva",
        source="command",
        chat_id=update.effective_chat.id,
        note=f"total_ip={len(ip_list)}"
    )

    await send_ip_page(update, context, page=0)

# ==== FUNCTION HELPER TO SEND PAGE ====
async def send_ip_page(update, context, page=0):
    ip_list = context.user_data.get('ip_list', [])
    total = len(ip_list)
    per_page = IP_PAGE_SIZE
    max_page = (total - 1) // per_page

    start = page * per_page
    end = min(start + per_page, total)
    page_ips = ip_list[start:end]

    text = f"*Blocked IP Addresses* (Page {page + 1}/{max_page + 1})\n"
    text += "\n".join([f"{start + i + 1}. `{ip}`" for i, ip in enumerate(page_ips)])

    buttons = []
    if page > 0:
        buttons.append({"text": "⬅️ Prev", "callback_data": f"blocklistimperva:{page-1}"})
    if end < total:
        buttons.append({"text": "Next ➡️", "callback_data": f"blocklistimperva:{page+1}"})

    reply_markup = {"inline_keyboard": [buttons]} if buttons else None

    if update.callback_query:
        await update.callback_query.edit_message_text(
            text=text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            text=text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )


# ====== HELPERS (POSTMAN-ALIGNED ONLY) ======
def pick(d: dict, *keys, default="-"):
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


def normalize_violation(v: dict) -> dict:
    """
    HANYA field yang terbukti ada di response Postman (v15.3.10) kamu.
    Field lain dihapus supaya tidak pernah tampil kosong di Telegram.
    """
    return {
        # identity
        "event_id": pick(v, "eventNumber"),
        "violation_id": pick(v, "violationId"),
        "alert_number": pick(v, "alertNumber"),

        # time + severity + action + type
        "time": pick(v, "time"),
        "severity": pick(v, "severity"),
        "action": pick(v, "action"),
        "violation_type": pick(v, "violationType"),

        # traffic
        "source_ip": pick(v, "sourceIp"),
        "source_port": pick(v, "sourcePort"),
        "dest_ip": pick(v, "destIp"),
        "dest_port": pick(v, "destPort"),

        # context
        "server_group": pick(v, "serverGroupName"),
        "service": pick(v, "serviceName"),
        "application": pick(v, "applicationName"),
        "gateway": pick(v, "gatewayName"),

        # detection/detail
        "description": pick(v, "description"),
        "violated_item": pick(v, "violatedItem"),

        # signature (di Postman kamu ada 2: signature pattern & signature name)
        "signature_name": pick(v, "signatureName"),
        "signature_pattern": pick(v, "signature"),

        # request path
        "url_path": pick(v, "requestUrlPath"),
    }


def fmt(nv: dict, key: str, default="-") -> str:
    val = nv.get(key, default)
    if val in (None, "", [], {}):
        return default
    return str(val)


def format_violation(v: dict) -> str:
    nv = normalize_violation(v)

    def add(lines, label, key, wrap_backtick=True):
        val = nv.get(key)
        if val in (None, "", [], {}, "-"):
            return
        if wrap_backtick:
            lines.append(f"• {label:<11}: `{val}`")
        else:
            lines.append(f"• {label:<11}: {val}")

    lines = ["*Imperva Violation Trace*"]
    add(lines, "Event ID", "event_id")
    add(lines, "Time", "time")
    add(lines, "Severity", "severity")
    add(lines, "Action", "action")
    add(lines, "Type", "violation_type")
    add(lines, "Alert #", "alert_number")
    add(lines, "ViolationID", "violation_id")

    traffic = ["", "*Traffic*"]
    # Source/Destination formatting khusus
    src_ip = nv.get("source_ip")
    src_port = nv.get("source_port")
    if src_ip not in (None, "", "-", []):
        if src_port not in (None, "", "-", []):
            traffic.append(f"• {'Source':<11}: `{src_ip}`:{src_port}")
        else:
            traffic.append(f"• {'Source':<11}: `{src_ip}`")

    dst_ip = nv.get("dest_ip")
    dst_port = nv.get("dest_port")
    if dst_ip not in (None, "", "-", []):
        if dst_port not in (None, "", "-", []):
            traffic.append(f"• {'Destination':<11}: `{dst_ip}`:{dst_port}")
        else:
            traffic.append(f"• {'Destination':<11}: `{dst_ip}`")

    # sisa traffic
    for label, key in [
        ("Service", "service"),
        ("App", "application"),
        ("Gateway", "gateway"),
        ("ServerGroup", "server_group"),
    ]:
        val = nv.get(key)
        if val not in (None, "", [], {}, "-"):
            traffic.append(f"• {label:<11}: `{val}`")

    detect = ["", "*Detection*"]
    for label, key in [
        ("Desc", "description"),
        ("Violated", "violated_item"),
        ("Sig Name", "signature_name"),
        ("Sig Pattern", "signature_pattern"),
    ]:
        val = nv.get(key)
        if val not in (None, "", [], {}, "-"):
            detect.append(f"• {label:<11}: `{val}`")

    http = []
    urlp = nv.get("url_path")
    if urlp not in (None, "", [], {}, "-"):
        http = ["", "*HTTP*", f"• {'URL/Path':<11}: `{urlp}`"]

    return "\n".join(lines + traffic + detect + http)



# ====== COMMAND HANDLER: /tracev <event_id> [days] ======
async def tracev(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) not in (1, 2):
        await update.message.reply_text("Format: /tracev <event_id> [lastFewDays]\nContoh: /tracev 7588... 1")
        return

    event_id = context.args[0].strip()
    days = int(context.args[1]) if len(context.args) == 2 and context.args[1].isdigit() else 7

    log_user_action(
        action="trace_imperva_violation",
        user=user,
        ip=None,
        target="Imperva",
        source="command",
        chat_id=update.effective_chat.id,
        note=f"event_id={event_id}, lastFewDays={days}"
    )

    await update.message.reply_text(
        f"Mencari violation by Event ID `{event_id}` (lastFewDays={days}) ...",
        parse_mode="Markdown"
    )

    cookies = login_via_api()
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva. Cek kredensial/API.")
        return

    # Pakai fungsi yang benar (eventNumber) tapi tetap pakai variable event_id dari user input (UI: Event ID)
    violation, err = imperva_get_violation_by_event_number(cookies, event_number=event_id, days=days)
    if err:
        await update.message.reply_text(f"❌ Query gagal: {err}")
        return
    if not violation:
        await update.message.reply_text(f"❌ Tidak ditemukan violation untuk Event ID `{event_id}`.", parse_mode="Markdown")
        return

    msg = format_violation(violation)
    await update.message.reply_text(msg, parse_mode="Markdown")



# === COMMAND HANDLER PALO ALTO ===
async def blockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /blockonpalo <ip>")
        return

    ip = context.args[0]

    # LOGGING
    log_user_action(
        action="block_palo",
        user=user,
        ip=ip,
        target="PaloAlto",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Menambah {ip} ke IP group di Palo Alto...")

    resp_obj = pa_add_address_object(ip)
    resp_grp = pa_add_to_group(ip)
    msg = "\n".join([
        get_response_message(resp_obj, f"PA: Add object {ip}"),
        get_response_message(resp_grp, f"PA: Add to group {PA_GROUP}")
    ])
    await update.message.reply_text(msg)

async def unblockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /unblockonpalo <ip>")
        return

    ip = context.args[0]

    # LOGGING
    log_user_action(
        action="unblock_palo",
        user=user,
        ip=ip,
        target="PaloAlto",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Menghapus {ip} dari IP group Palo Alto...")

    resp_grp = pa_remove_from_group(ip)
    resp_obj = pa_delete_address_object(ip)
    msg = "\n".join([
        get_response_message(resp_grp, f"PA: Remove from group {PA_GROUP}"),
        get_response_message(resp_obj, f"PA: Delete object {ip}")
    ])
    await update.message.reply_text(msg)

async def commitpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    # LOGGING
    log_user_action(
        action="commit_palo",
        user=user,
        ip=None,
        target="PaloAlto",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Memproses partial commit Palo Alto (user {PA_ADMIN}) ...")
    resp_commit = pa_partial_commit()
    msg = get_response_message(resp_commit, f"PA: Partial commit user {PA_ADMIN}")
    await update.message.reply_text(msg)

# ==== COMMAND HANDLER AKAMAI ====
async def blockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /blockonakamai <ip>")
        return

    ip = context.args[0]

    # LOGGING
    log_user_action(
        action="block_akamai",
        user=user,
        ip=ip,
        target="Akamai",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Menambah {ip} ke Akamai Client List...")

    session = akamai_session()
    url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/items")
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    body = {
        "append": [{
            "value": ip,
            "description": "added via bot",
            "tags": ["bot"]
        }]
    }
    resp = session.post(url, headers=headers, json=body)
    if resp.status_code == 200:
        await update.message.reply_text(f"✅ {ip} berhasil ditambahkan ke client list Akamai.")
    else:
        await update.message.reply_text(f"❌ Gagal add IP ke Akamai: {resp.text}")

async def unblockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /unblockonakamai <ip>")
        return

    ip = context.args[0]

    # LOGGING
    log_user_action(
        action="unblock_akamai",
        user=user,
        ip=ip,
        target="Akamai",
        source="command",
        chat_id=update.effective_chat.id
    )

    await update.message.reply_text(f"Menghapus {ip} dari Akamai Client List...")

    session = akamai_session()
    url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/items")
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    body = {
        "delete": [{"value": ip}]
    }
    resp = session.post(url, headers=headers, json=body)
    if resp.status_code == 200:
        await update.message.reply_text(f"✅ {ip} berhasil dihapus dari client list Akamai.")
    else:
        await update.message.reply_text(f"❌ Gagal hapus IP dari Akamai: {resp.text}")

async def blocklistakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    session = akamai_session()
    url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/items")
    headers = {"accept": "application/json"}
    resp = session.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        ip_entries = [
            entry
            for entry in data.get("content", [])
            if entry.get("type") == "IP"
        ]
        if not ip_entries:
            await update.message.reply_text("Client list kosong.")
        else:
            context.user_data['akamai_list'] = ip_entries
            context.user_data['akamai_page'] = 0
            log_user_action(
                action="list_akamai_block",
                user=user,
                ip=None,
                target="Akamai",
                source="command",
                chat_id=update.effective_chat.id,
                note=f"total_ip={len(ip_entries)}"
            )
            await send_akamai_page(update, context, page=0)
    else:
        await update.message.reply_text(f"❌ Gagal get client list: {resp.text}")

async def send_akamai_page(update, context, page=0):
    ip_list = context.user_data.get('akamai_list', [])
    total = len(ip_list)
    per_page = IP_PAGE_SIZE
    max_page = (total - 1) // per_page if total > 0 else 0

    start = page * per_page
    end = min(start + per_page, total)
    page_ips = ip_list[start:end]

    text = f"*Akamai Client List* (Page {page + 1}/{max_page + 1})\n"
    lines = []
    for i, entry in enumerate(page_ips):
        value = entry.get("value", "-")
        desc = entry.get("description", "")
        if isinstance(desc, str) and len(desc) > 120:
            desc = desc[:117] + "..."
        suffix = f" ({desc})" if desc else ""
        lines.append(f"{start + i + 1}. `{value}`{suffix}")
    if lines:
        text += "\n".join(lines)
    else:
        text += "No IPs on this page."

    buttons = []
    if page > 0:
        buttons.append({"text": "⬅️ Prev", "callback_data": f"blocklistakamai:{page-1}"})
    if end < total:
        buttons.append({"text": "Next ➡️", "callback_data": f"blocklistakamai:{page+1}"})

    reply_markup = {"inline_keyboard": [buttons]} if buttons else None

    if update.callback_query:
        await update.callback_query.edit_message_text(
            text=text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            text=text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )

async def activateakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    # LOGGING
    log_user_action(
        action="activate_akamai",
        user=user,
        ip=None,
        target="Akamai",
        source="command",
        chat_id=update.effective_chat.id
    )

    session = akamai_session()
    url = akamai_url(f"/client-list/v1/lists/{AKAMAI_LIST_ID}/activations")
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    results = []
    for network in ["STAGING", "PRODUCTION"]:
        body = {
            "action": "ACTIVATE",
            "network": network,
            "comments": f"Aktivasi manual ke {network} via bot"
        }
        resp = session.post(url, headers=headers, json=body)
        try:
            data = resp.json()
        except Exception:
            data = {}
        results.append((network, resp.status_code, data))

    msg = ""
    for net, code, d in results:
        if code == 200:
            msg += (
                f"✅ Aktivasi *{net}* dimulai\n"
                f"• Status : `{d.get('activationStatus')}`\n"
                f"• ID     : `{d.get('activationId')}`\n"
                f"• Versi  : `{d.get('version')}`\n\n"
            )
        else:
            msg += f"❌ Gagal aktivasi *{net}* : {d}\n"
    await update.message.reply_text(msg, parse_mode="Markdown")

async def activationstatus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    if not is_user_allowed(user_id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not context.args[0].isdigit():
        await update.message.reply_text("Format: /activationstatus <activation_id>")
        return

    activation_id = context.args[0]

    # LOGGING
    log_user_action(
        action="activation_status",
        user=user,
        ip=None,
        target="Akamai",
        source="command",
        chat_id=update.effective_chat.id,
        note=f"activation_id={activation_id}"
    )

    session = akamai_session()
    url = akamai_url(f"/client-list/v1/activations/{activation_id}")
    headers = {"accept": "application/json"}
    resp = session.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        await update.message.reply_text(
            f"*Status Aktivasi ID {activation_id}:*\n"
            f"- Status: `{data.get('activationStatus')}`\n"
            f"- Network: `{data.get('network')}`\n"
            f"- Versi: `{data.get('version')}`\n"
            f"- Create: `{data.get('createDate')}`\n"
            f"- By: `{data.get('createdBy')}`",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(f"❌ Gagal get activation status: {resp.text}")

# ========================================================================================

async def help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bot miniSOAR siap!\n\n"
        "🟠 Palo Alto\n"
        "/blockonpalo <ip address> : untuk menambahkan IP di blocklist Palo Alto\n"
        "/unblockonpalo <ip address> : untuk menghapus IP dari blocklist di Palo Alto\n"
        "/commitpalo : untuk commit konfigurasi di Palo Alto\n\n"
        "🟢 Akamai\n"
        "/blockonakamai <ip address> : untuk menambahkan IP di blocklist Akamai\n"
        "/unblockonakamai <ip address> : untuk menghapus IP dari blocklist Akamai \n"
        "/blocklistakamai : untuk menampilkan blocked-list IP di Akamai\n"
        "/activateakamai : untuk melakukan Aktivasi Konfigurasi di Staging and Production\n\n"
        "🔵 Imperva\n"
        "/blockonimperva <ip address> : untuk menambahkan IP di blocklist Imperva\n"
        "/unblockonimperva <ip address> : untuk menghapus IP dari blocklist Imperva\n"
        "/blocklistimperva : untuk menampilkan blocked-list IP di Imperva\n"
	"/tracev <event ID> : untuk melakukan tracing violation di Imperva\n"
    )

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception", exc_info=context.error)


# === MAIN ===
if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

        app.add_handler(CommandHandler("help", help))
        app.add_handler(CommandHandler("blockonimperva", blockonimperva))
        app.add_handler(CommandHandler("unblockonimperva", unblockonimperva))
        app.add_handler(CommandHandler("tracev", tracev))

        app.add_handler(CommandHandler("blockonpalo", blockonpalo))
        app.add_handler(CommandHandler("unblockonpalo", unblockonpalo))
        app.add_handler(CommandHandler("commitpalo", commitpalo))

        app.add_handler(CommandHandler("blockonakamai", blockonakamai))
        app.add_handler(CommandHandler("unblockonakamai", unblockonakamai))
        app.add_handler(CommandHandler("blocklistakamai", blocklistakamai))
        app.add_handler(CommandHandler("activateakamai", activateakamai))
        app.add_handler(CommandHandler("activationstatus", activationstatus))
        app.add_handler(CallbackQueryHandler(pagination_callback_handler, pattern="^blocklistakamai:"))

        app.add_handler(CommandHandler("blocklistimperva", blocklistimperva))
        app.add_handler(CallbackQueryHandler(pagination_callback_handler, pattern="^blocklistimperva:"))

        app.add_handler(CallbackQueryHandler(callback_query_handler))
        app.add_error_handler(on_error)

        print("Bot Telegram miniSOAR aktif...")
        app.run_polling()
    except KeyboardInterrupt:
        print("\n[INFO] Bot Telegram dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")
