from __future__ import annotations

"""MiniSOAR telegram bot entry module.

This module implements the Telegram bot application, command handlers, and
callback queries for interacting with perimeter security APIs.
"""

import logging
import os

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from .config import load_env, parse_allowed_users, telegram_config
from .database import (
    es_find_latest_event_id_by_ip,
    store_label,
    redis_client,
    es_get_event_website_by_id,
    es_get_latest_event_website_by_ip,
)
from .mitigation import (
    akamai,
    cloudflare,
    fortigate,
    imperva,
    paloalto,
    trigger_auto_block,
    trigger_auto_unblock,
    is_ip_blocked,
    register_block_state,
    extend_block_state,
    remove_block_state,
)
from .utils import log_user_action, resolve_log_path, valid_ip, get_perimeter_info
from . import ai, cases, edr

logger = logging.getLogger(__name__)


def is_user_allowed(user_id: int) -> bool:
    allowed = parse_allowed_users(os.getenv("ALLOWED_USERS"))
    return user_id in allowed


def _parse_callback_payload(payload: str) -> tuple[str, str | None]:
    if "|" in payload:
        ip, event_id = payload.split("|", 1)
        return ip, event_id
    return payload, None


# -----------------
# IMPERVA
# -----------------
async def blockonimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /blockonimperva <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    await update.message.reply_text(f"Memproses blokir IP {ip} pada Imperva...")

    r = redis_client()
    duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))
    ok, msg = trigger_auto_block(ip, "imperva")
    if ok:
        register_block_state(r, ip, "imperva", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
    await update.message.reply_text(msg)


async def unblockonimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /unblockonimperva <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    await update.message.reply_text(f"Memproses unblock IP {ip} pada Imperva...")

    r = redis_client()
    ok, msg = trigger_auto_unblock(ip, "imperva")
    if ok:
        remove_block_state(r, ip, "imperva")
    await update.message.reply_text(msg)


async def tracev(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) not in (1, 2):
        await update.message.reply_text("Format: /tracev <event_id> [lastFewDays]\nContoh: /tracev 7588... 1")
        return

    event_id = context.args[0].strip()
    days = int(context.args[1]) if len(context.args) == 2 and context.args[1].isdigit() else 7

    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("trace_imperva_violation", user, ip=None, target="Imperva", source="command", chat_id=update.effective_chat.id, note=f"event_id={event_id}, lastFewDays={days}", logfile=logfile)

    await update.message.reply_text(f"Mencari violation by Event ID `{event_id}` (lastFewDays={days}) ...", parse_mode="Markdown")

    base_url = os.getenv("IMPERVA_BASE_URL", "")
    cookies = imperva.login_via_api(base_url, os.getenv("IMPERVA_USERNAME", ""), os.getenv("IMPERVA_PASSWORD", ""))
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva. Cek kredensial/API.")
        return

    violation, err = imperva.get_violation_by_event_number(base_url, cookies, event_number=event_id, days=days)
    if err:
        await update.message.reply_text(f"❌ Query gagal: {err}")
        return
    if not violation:
        await update.message.reply_text(f"❌ Tidak ditemukan violation untuk Event ID `{event_id}`.", parse_mode="Markdown")
        return

    # A simple formatter for the violation since legacy format_violation had many specifics
    # Using a reduced, clean Markdown representation.
    msg = f"*Imperva Violation Trace*\n• Event ID: `{violation.get('eventNumber', '-')}`\n• Time: `{violation.get('time', '-')}`\n• ViolationType: `{violation.get('violationType', '-')}`\n• Source IP: `{violation.get('sourceIp', '-')}`\n• Dest IP: `{violation.get('destIp', '-')}`\n• Desc: `{violation.get('description', '-')}`"
    await update.message.reply_text(msg, parse_mode="Markdown")


# -----------------
# PALO ALTO THREAT TRACE
# -----------------
async def tracevpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Query threat logs by Violation ID (threatid), session ID, or source IP on Palo Alto.

    Format:
      /tracevpalo <violation_id>          — threatid filter
      /tracevpalo sid <session_id>        — session ID filter
      /tracevpalo src <ip>                — source IP filter
    """
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(
            "Format:\n"
            "  /tracevpalo <threat_id>       — cari by threat ID\n"
            "  /tracevpalo sid <session_id>  — cari by session ID\n"
            "  /tracevpalo src <ip>          — cari by source IP"
        )
        return

    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    pa_host = os.getenv("PA_HOST", "")
    pa_api_key = os.getenv("PA_API_KEY", "")

    if not pa_host or not pa_api_key:
        await update.message.reply_text("❌ PA_HOST atau PA_API_KEY belum dikonfigurasi di env.")
        return

    if len(context.args) == 2 and context.args[0].lower() in ("sid", "session", "sessionid", "src", "src_ip", "srcip"):
        filter_type = context.args[0].lower()
        value = context.args[1].strip()
        if filter_type in ("sid", "session", "sessionid"):
            field_label = "Session ID"
            await update.message.reply_text(f"Mencari threat log Palo Alto by Session ID `{value}` ...", parse_mode="Markdown")
            log_user_action("trace_palo_violation", user, ip=None, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"sid={value}", logfile=logfile)
            resp = paloalto.query_threat_log(pa_host, pa_api_key, session_id=value)
        else:
            field_label = "Source IP"
            await update.message.reply_text(f"Mencari threat log Palo Alto by Source IP `{value}` ...", parse_mode="Markdown")
            log_user_action("trace_palo_violation", user, ip=value, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"src={value}", logfile=logfile)
            resp = paloalto.query_threat_log(pa_host, pa_api_key, src_ip=value)
    else:
        value = context.args[0].strip()
        field_label = "Violation/Threat ID"
        await update.message.reply_text(f"Mencari threat log Palo Alto by Violation ID `{value}` ...", parse_mode="Markdown")
        log_user_action("trace_palo_violation", user, ip=None, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"threatid={value}", logfile=logfile)
        resp = paloalto.query_threat_log(pa_host, pa_api_key, threat_id=value)

    entries, err = paloalto.parse_threat_logs(resp)
    if err:
        await update.message.reply_text(f"❌ Query gagal: {err}")
        return
    if not entries:
        await update.message.reply_text(f"❌ Tidak ditemukan threat log untuk {field_label} `{value}`.", parse_mode="Markdown")
        return

    # Format results — show up to 5 entries
    header = f"*Palo Alto Threat Log Trace*\n• {field_label}: `{value}`\n• Jumlah: {len(entries)}\n"
    body_parts = [header]
    for i, e in enumerate(entries[:5]):
        body_parts.append(
            f"*#{i+1}*\n"
            f"• Time   : `{e.get('time_generated', '-')}`\n"
            f"• Src    : `{e.get('src', '-')}`\n"
            f"• Dst    : `{e.get('dst', '-')}`\n"
            f"• App    : `{e.get('app', '-')}`\n"
            f"• Action : `{e.get('action', '-')}`\n"
            f"• Threat : `{e.get('threatid', '-')}`\n"
            f"• Name   : `{e.get('name', '-')}`\n"
            f"• Severity: `{e.get('severity', '-')}`\n"
            f"• Category: `{e.get('category', '-')}`\n"
            f"• Session: `{e.get('sessionid', '-')}`"
        )
    msg = "\n\n".join(body_parts)
    if len(entries) > 5:
        msg += f"\n\n_...dan {len(entries)-5} entry lainnya._"
    await update.message.reply_text(msg, parse_mode="Markdown")


# -----------------
# PALO ALTO
# -----------------
async def blockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /blockonpalo <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    
    # Check domain mapping
    website = es_get_latest_event_website_by_ip(ip)
    perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
    _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

    r = redis_client()
    duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))

    if website and not mapped:
        await update.message.reply_text(
            f"⚠️ Domain `{website}` untuk IP `{ip}` belum dimapping. Mengalihkan pemblokiran ke Imperva..."
        )
        log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_block(ip, "imperva")
        if ok:
            register_block_state(r, ip, "imperva", duration=duration)
            event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
            store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik) di Imperva."
        await update.message.reply_text(msg)
        return

    log_user_action("block_palo", user, ip=ip, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah {ip} ke IP group Palo Alto...")

    ok, msg = trigger_auto_block(ip, "paloalto", commit=False)
    if ok:
        register_block_state(r, ip, "paloalto", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nJangan lupa jalankan /commitpalo.\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
    await update.message.reply_text(msg)


async def unblockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /unblockonpalo <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

    # Check domain mapping
    website = es_get_latest_event_website_by_ip(ip)
    perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
    _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

    r = redis_client()

    if website and not mapped:
        await update.message.reply_text(
            f"⚠️ Domain `{website}` untuk IP `{ip}` belum dimapping. Mengalihkan unblock ke Imperva..."
        )
        log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_unblock(ip, "imperva")
        if ok:
            remove_block_state(r, ip, "imperva")
        await update.message.reply_text(msg)
        return

    log_user_action("unblock_palo", user, ip=ip, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menghapus {ip} dari IP group Palo Alto...")

    ok, msg = trigger_auto_unblock(ip, "paloalto", commit=False)
    if ok:
        remove_block_state(r, ip, "paloalto")
        msg += "\nJangan lupa jalankan /commitpalo."
    await update.message.reply_text(msg)


async def commitpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("commit_palo", user, ip=None, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    pa_admin = os.getenv("PA_ADMIN", "")
    await update.message.reply_text(f"Memproses partial commit Palo Alto (user {pa_admin}) ...")
    resp_commit = paloalto.partial_commit(os.getenv("PA_HOST", ""), os.getenv("PA_API_KEY", ""), admin=pa_admin)
    msg = paloalto.response_message(resp_commit, f"PA: Partial commit user {pa_admin}")
    await update.message.reply_text(msg)


# -----------------
# AKAMAI
# -----------------
async def blockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /blockonakamai <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    
    # Check domain mapping
    website = es_get_latest_event_website_by_ip(ip)
    perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
    _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

    r = redis_client()
    duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))

    if website and not mapped:
        await update.message.reply_text(
            f"⚠️ Domain `{website}` untuk IP `{ip}` belum dimapping. Mengalihkan pemblokiran ke Imperva..."
        )
        log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_block(ip, "imperva")
        if ok:
            register_block_state(r, ip, "imperva", duration=duration)
            event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
            store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik) di Imperva."
        await update.message.reply_text(msg)
        return

    log_user_action("block_akamai", user, ip=ip, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah {ip} ke Akamai Client List...")

    ok, msg = trigger_auto_block(ip, "akamai", commit=False)
    if ok:
        register_block_state(r, ip, "akamai", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nJangan lupa jalankan /activateakamai.\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
    await update.message.reply_text(msg)


async def unblockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text("Format: /unblockonakamai <ip>")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

    # Check domain mapping
    website = es_get_latest_event_website_by_ip(ip)
    perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
    _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

    r = redis_client()

    if website and not mapped:
        await update.message.reply_text(
            f"⚠️ Domain `{website}` untuk IP `{ip}` belum dimapping. Mengalihkan unblock ke Imperva..."
        )
        log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_unblock(ip, "imperva")
        if ok:
            remove_block_state(r, ip, "imperva")
        await update.message.reply_text(msg)
        return

    log_user_action("unblock_akamai", user, ip=ip, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menghapus {ip} dari Akamai Client List...")

    ok, msg = trigger_auto_unblock(ip, "akamai", commit=False)
    if ok:
        remove_block_state(r, ip, "akamai")
        msg += "\nJangan lupa jalankan /activateakamai."
    await update.message.reply_text(msg)


async def activateakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("activate_akamai", user, ip=None, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    session = akamai.akamai_session(
        client_token=os.getenv("AKAMAI_CLIENT_TOKEN", ""),
        client_secret=os.getenv("AKAMAI_CLIENT_SECRET", ""),
        access_token=os.getenv("AKAMAI_ACCESS_TOKEN", "")
    )
    url = akamai.akamai_url(os.getenv("AKAMAI_BASEURL", ""), f"/client-list/v1/lists/{os.getenv('AKAMAI_LIST_ID', '')}/activations")
    headers = {"accept": "application/json", "content-type": "application/json"}

    results = []
    for network in ["STAGING", "PRODUCTION"]:
        body = {"action": "ACTIVATE", "network": network, "comments": "Aktivasi manual ke {network} via bot"}
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


async def tracevakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Trace an Akamai security event/violation by event ID via SIEM API.

    Format: /tracevakamai <event_id>
    Requires env: AKAMAI_BASEURL, AKAMAI_CLIENT_TOKEN, AKAMAI_CLIENT_SECRET,
    AKAMAI_ACCESS_TOKEN, AKAMAI_SIEM_CONFIG_ID
    """
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Format: /tracevakamai <event_id>")
        return

    event_id = context.args[0].strip()
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

    baseurl = os.getenv("AKAMAI_BASEURL", "")
    config_id = os.getenv("AKAMAI_SIEM_CONFIG_ID", "")
    client_token = os.getenv("AKAMAI_CLIENT_TOKEN", "")
    client_secret = os.getenv("AKAMAI_CLIENT_SECRET", "")
    access_token = os.getenv("AKAMAI_ACCESS_TOKEN", "")

    if not all([baseurl, config_id, client_token, client_secret, access_token]):
        await update.message.reply_text(
            "❌ Konfigurasi Akamai SIEM belum lengkap. "
            "Periksa AKAMAI_BASEURL, AKAMAI_SIEM_CONFIG_ID, dan kredensial EdgeGrid."
        )
        return

    log_user_action("trace_akamai_violation", user, ip=None, target="Akamai", source="command", chat_id=update.effective_chat.id, note=f"event_id={event_id}", logfile=logfile)
    await update.message.reply_text(f"Mencari Akamai security event `{event_id}` ...", parse_mode="Markdown")

    events, err = akamai.query_siem_events(
        baseurl,
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
        config_id=config_id,
        event_id=event_id,
    )
    if err:
        await update.message.reply_text(f"❌ Query gagal: {err}")
        return
    if not events:
        await update.message.reply_text(f"❌ Tidak ditemukan event untuk ID `{event_id}`.", parse_mode="Markdown")
        return

    parts = [f"*Akamai Security Event Trace*\n• Event ID: `{event_id}`\n• Total: {len(events)}"]
    for i, ev in enumerate(events[:5]):
        attack = ev.get("attackData") or {}
        http_msg = ev.get("httpMessage") or {}
        geo = ev.get("geo") or {}
        parts.append(
            f"*#{i+1}*\n"
            f"• _id        : `{ev.get('_id', '-')}`\n"
            f"• Attack ID  : `{attack.get('attackID', '-')}`\n"
            f"• Rule ID    : `{attack.get('ruleID', '-')}`\n"
            f"• Rule Msg   : `{attack.get('ruleMessage', '-')}`\n"
            f"• Rule Name  : `{attack.get('policy', '-')}`\n"
            f"• Client IP  : `{http_msg.get('clientIP', '-')}`\n"
            f"• Host       : `{http_msg.get('host', '-')}`\n"
            f"• Path       : `{http_msg.get('path', '-')}`\n"
            f"• Method     : `{http_msg.get('request', '-')}`\n"
            f"• Status     : `{http_msg.get('statusCode', '-')}`\n"
            f"• Country    : `{geo.get('country', '-')}`"
        )
    msg = "\n\n".join(parts)
    if len(events) > 5:
        msg += f"\n\n_...dan {len(events)-5} event lainnya._"
    await update.message.reply_text(msg, parse_mode="Markdown")


# -----------------
# INLINE CALLBACKS
# -----------------
async def callback_query_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user = query.from_user
    if not is_user_allowed(user.id):
        await query.answer("❌ Maaf, kamu tidak punya akses untuk blokir IP ini.", show_alert=True)
        return

    data = query.data
    await query.edit_message_reply_markup(reply_markup=None)
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")

    if data.startswith("blockonimperva:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Memproses blokir IP [{ip_to_block}](http://{ip_to_block}) pada Imperva ...", parse_mode="Markdown")

        r = redis_client()
        duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))
        ok, msg = trigger_auto_block(ip_to_block, "imperva")
        if ok:
            register_block_state(r, ip_to_block, "imperva", duration=duration)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Blokir di Imperva diproses!")

    elif data.startswith("blockonpalo:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        # Check domain mapping
        website = None
        if event_id:
            website = es_get_event_website_by_id(event_id)
        if not website:
            website = es_get_latest_event_website_by_ip(ip_to_block)
            
        perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
        _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

        r = redis_client()
        duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))

        if website and not mapped:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"⚠️ Domain `{website}` belum dimapping. Mengalihkan pemblokiran ke Imperva...",
            )
            log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button_redirect", logfile=logfile)
            ok, msg = trigger_auto_block(ip_to_block, "imperva")
            if ok:
                register_block_state(r, ip_to_block, "imperva", duration=duration)
                msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)

            if not event_id:
                event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
            store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
            await query.answer("Blokir di Imperva diproses!")
            return

        log_user_action("block_palo", user, ip=ip_to_block, target="PaloAlto", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Menambah {ip_to_block} ke IP group Palo Alto ...", parse_mode="Markdown")

        ok, msg = trigger_auto_block(ip_to_block, "paloalto", commit=False)
        if ok:
            register_block_state(r, ip_to_block, "paloalto", duration=duration)
            msg += f"\nJangan lupa jalankan /commitpalo.\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Penambahan IP ke Palo Alto diproses!, Jangan lupa commit!")

    elif data.startswith("blockonakamai:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        # Check domain mapping
        website = None
        if event_id:
            website = es_get_event_website_by_id(event_id)
        if not website:
            website = es_get_latest_event_website_by_ip(ip_to_block)
            
        perimeter_map_path = resolve_log_path("PERIMETER_MAP_PATH", "/etc/logstash/minisoar-perimeter.yml", "logstash/minisoar-perimeter.yml")
        _, mapped, _ = get_perimeter_info(website, perimeter_map_path) if website else ([], False, None)

        r = redis_client()
        duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))

        if website and not mapped:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"⚠️ Domain `{website}` belum dimapping. Mengalihkan pemblokiran ke Imperva...",
            )
            log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button_redirect", logfile=logfile)
            ok, msg = trigger_auto_block(ip_to_block, "imperva")
            if ok:
                register_block_state(r, ip_to_block, "imperva", duration=duration)
                msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)

            if not event_id:
                event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
            store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
            await query.answer("Blokir di Imperva diproses!")
            return

        log_user_action("block_akamai", user, ip=ip_to_block, target="Akamai", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Menambah {ip_to_block} ke Akamai Client List...")

        ok, msg = trigger_auto_block(ip_to_block, "akamai", commit=False)
        if ok:
            register_block_state(r, ip_to_block, "akamai", duration=duration)
            msg += f"\nJangan lupa jalankan /activateakamai.\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Block di Akamai diproses!")

    elif data.startswith("ignore:"):
        payload = data.split(":", 1)[1].strip()
        ip_to_ignore, event_id = _parse_callback_payload(payload)

        log_user_action("ignore_alert", user, ip=ip_to_ignore, target="miniSOAR", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_ignore, getattr(query.message, "date", None))

        store_label(event_id, "ignore", user, "ignore", ip=ip_to_ignore, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)

        await query.answer("Diabaikan (ignore).")
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"🙈 Ignored: `{ip_to_ignore}`", parse_mode="Markdown")
    else:
        await query.edit_message_text("Perintah tidak dikenali.")


# -----------------
# EDR (KASPERSKY KSC & TRENDMICRO VISION ONE)
# -----------------
async def isolatehost(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 1:
        await update.message.reply_text("Format: /isolatehost <ip/host_id> [ksc|trendmicro|all]")
        return

    target = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("isolate_host", user, ip=target if valid_ip(target) else None, target=f"EDR-{provider.upper()}", source="command", chat_id=update.effective_chat.id, note=f"target={target}", logfile=logfile)

    await update.message.reply_text(f"Memproses isolasi host `{target}` pada EDR ({provider.upper()}) ...", parse_mode="Markdown")
    ok, msg, _ = edr.isolate_endpoint(target=target, provider=provider, reason=f"Manual isolation by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *Hasil Isolasi EDR:*\n{msg}", parse_mode="Markdown")


async def restorehost(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 1:
        await update.message.reply_text("Format: /restorehost <ip/host_id> [ksc|trendmicro|all]")
        return

    target = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("restore_host", user, ip=target if valid_ip(target) else None, target=f"EDR-{provider.upper()}", source="command", chat_id=update.effective_chat.id, note=f"target={target}", logfile=logfile)

    await update.message.reply_text(f"Memproses pemulihan host `{target}` pada EDR ({provider.upper()}) ...", parse_mode="Markdown")
    ok, msg, _ = edr.restore_endpoint(target=target, provider=provider)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *Hasil Pemulihan EDR:*\n{msg}", parse_mode="Markdown")


async def queryhost(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Format: /queryhost <ip>")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Mencari inventory endpoint untuk IP `{ip}` di Kaspersky KSC & TrendMicro Vision One ...", parse_mode="Markdown")
    res = edr.query_endpoint(ip, provider="all")
    msg_parts = [f"*EDR Host Query: `{ip}`*"]

    if res.get("trendmicro"):
        msg_parts.append("\n*🔵 TrendMicro Vision One:*")
        for h in res["trendmicro"]:
            msg_parts.append(f"• ID: `{h.get('endpointId', '-')}`\n• Host: `{h.get('endpointName', '-')}`\n• OS: `{h.get('osName', '-')}`\n• Isolation: `{h.get('isolationStatus', 'normal')}`")
    else:
        msg_parts.append("\n*🔵 TrendMicro:* Tidak ditemukan endpoint")

    if res.get("kaspersky"):
        msg_parts.append("\n*🟢 Kaspersky Security Center (KSC):*")
        for h in res["kaspersky"]:
            msg_parts.append(f"• ID: `{h.get('hostId', '-')}`\n• Host: `{h.get('hostName', '-') or h.get('KLHST_WKS_HOSTNAME', '-')}`\n• OS: `{h.get('osName', '-') or h.get('KLHST_WKS_OS_NAME', '-')}`\n• Isolated: `{h.get('networkIsolated', False)}`")
    else:
        msg_parts.append("\n*🟢 Kaspersky KSC:* Tidak ditemukan host")

    if res.get("errors"):
        msg_parts.append(f"\n⚠️ *Errors:* {'; '.join(res['errors'])}")

    await update.message.reply_text("\n".join(msg_parts), parse_mode="Markdown")


async def addedrioc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 1:
        await update.message.reply_text("Format: /addedrioc <ip/sha256/domain> [ksc|trendmicro|all]")
        return

    val = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    ioc_type = "ip" if valid_ip(val) else ("sha256" if len(val) == 64 else "domain")
    ok, msg = edr.add_edr_ioc(ioc_type=ioc_type, ioc_value=val, provider=provider, comment=f"Manual IoC by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *Pendaftaran IoC EDR ({ioc_type.upper()}):*\n{msg}", parse_mode="Markdown")


async def edrstatus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    results = edr.check_all_edr_connectivity()
    parts = ["*🛡️ Status Konektivitas EDR Server:*\n"]
    for r in results:
        prov = r.get("provider", "unknown").upper()
        if r.get("ok"):
            parts.append(f"• *{prov}:* ✅ Terhubung (OK)")
        elif not r.get("configured"):
            parts.append(f"• *{prov}:* ⚪ Belum Dikonfigurasi")
        else:
            parts.append(f"• *{prov}:* ❌ Gagal - `{r.get('error')}`")
    await update.message.reply_text("\n".join(parts), parse_mode="Markdown")


# -----------------
# TIER 3: CASE MANAGEMENT COMMANDS
# -----------------
async def cases_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    status_filter = context.args[0].upper() if context.args else None
    case_list = cases.list_cases(status=status_filter, limit=10)
    if not case_list:
        await update.message.reply_text(f"Tidak ada incident case aktif{' dengan status ' + status_filter if status_filter else ''}.")
        return

    parts = [f"*📋 Daftar Incident Cases ({len(case_list)} Terakhir):*\n"]
    for c in case_list:
        parts.append(
            f"• *{c.case_id}* | `[{c.severity.upper()}]` | `{c.status}`\n"
            f"  Title: {c.title}\n"
            f"  Attacker: `{c.attacker_ip or 'N/A'}` | Target: `{c.target_asset or 'N/A'}`"
        )
    parts.append("\n_Gunakan `/case <id>` untuk melihat detail atau `/updatecase <id> <status>` untuk update._")
    await update.message.reply_text("\n".join(parts), parse_mode="Markdown")


async def case_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text("Format: /case <case_id>")
        return

    cid = context.args[0].strip()
    c = cases.get_case(cid)
    if not c:
        await update.message.reply_text(f"❌ Case `{cid}` tidak ditemukan.", parse_mode="Markdown")
        return

    report_md = cases.generate_case_markdown_report(c)
    await update.message.reply_text(report_md[:4000], parse_mode="Markdown")


async def updatecase_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 2:
        await update.message.reply_text("Format: /updatecase <case_id> <NEW|INVESTIGATING|CONTAINED|RESOLVED|CLOSED|FALSE_POSITIVE> [notes]")
        return

    cid = context.args[0].strip()
    new_status = context.args[1].strip()
    notes = " ".join(context.args[2:]) if len(context.args) > 2 else ""

    ok, msg, c = cases.update_case_status(cid, new_status, actor=f"@{user.username or user.id}", notes=notes)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} {msg}")


async def socmetrics_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    m = cases.get_soc_metrics()
    parts = [
        "📊 *SOC Operational & SLA Metrics:*",
        f"• *Total Cases:* `{m['total_cases']}`",
        f"• *Avg MTTD (Time to Detect):* `{m['avg_mttd_seconds']}s`",
        f"• *Avg MTTR (Time to Resolve):* `{m['avg_mttr_minutes']} mins` (`{m['avg_mttr_seconds']}s`)\n",
        "*Status Distribution:*",
    ]
    for st, count in m["status_distribution"].items():
        if count > 0:
            parts.append(f"  - `{st}`: {count}")

    parts.append("\n*Severity Distribution:*")
    for sv, count in m["severity_distribution"].items():
        if count > 0:
            parts.append(f"  - `{sv.upper()}`: {count}")

    if m["top_attackers"]:
        parts.append("\n*Top Attackers:*")
        for ip, cnt in m["top_attackers"]:
            parts.append(f"  - `{ip}`: {cnt} incidents")

    await update.message.reply_text("\n".join(parts), parse_mode="Markdown")


async def exportcase_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text("Format: /exportcase <case_id>")
        return

    cid = context.args[0].strip()
    c = cases.get_case(cid)
    if not c:
        await update.message.reply_text(f"❌ Case `{cid}` tidak ditemukan.", parse_mode="Markdown")
        return

    report_md = cases.generate_case_markdown_report(c)
    await update.message.reply_text(f"```markdown\n{report_md[:3800]}\n```", parse_mode="Markdown")


async def syncticket_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text("Format: /syncticket <case_id>")
        return

    cid = context.args[0].strip()
    await update.message.reply_text(f"Mendispatch case `{cid}` ke aplikasi ticketing pihak ke-3...", parse_mode="Markdown")
    ok, msg = cases.sync_case_to_ticketing(cid, actor=f"@{user.username or user.id}")
    prefix = "✅" if ok else "⚠️"
    await update.message.reply_text(f"{prefix} {msg}")


# -----------------
# TIER 4: EXTENDED PERIMETERS (CLOUDFLARE & FORTIGATE)
# -----------------
async def blockoncf_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text("Format: /blockoncf <ip>")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses blokir IP `{ip}` di Cloudflare WAF ...", parse_mode="Markdown")
    ok, msg = cloudflare.block_ip(ip, notes=f"Manual block by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *Cloudflare:* {msg}", parse_mode="Markdown")


async def unblockoncf_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text("Format: /unblockoncf <ip>")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses unblock IP `{ip}` di Cloudflare ...", parse_mode="Markdown")
    ok, msg = cloudflare.unblock_ip(ip)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *Cloudflare:* {msg}", parse_mode="Markdown")


async def blockonforti_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text("Format: /blockonforti <ip>")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses blokir IP `{ip}` di FortiGate Firewall ...", parse_mode="Markdown")
    ok, msg = fortigate.block_ip(ip, comment=f"Manual block by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *FortiGate:* {msg}", parse_mode="Markdown")


async def unblockonforti_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text("Format: /unblockonforti <ip>")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses unblock IP `{ip}` di FortiGate ...", parse_mode="Markdown")
    ok, msg = fortigate.unblock_ip(ip)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} *FortiGate:* {msg}", parse_mode="Markdown")


# -----------------
# TIER 5: AI SOC COPILOT & MLOPS COMMANDS
# -----------------
async def askai_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text("Format: /askai <pertanyaan keamanan atau analisa payload>")
        return

    question = " ".join(context.args)
    await update.message.reply_text("🤖 _AI SOC Copilot sedang menganalisis..._", parse_mode="Markdown")
    answer = ai.ask_copilot(question)
    await update.message.reply_text(answer[:4000], parse_mode="Markdown")


async def rca_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text("Format: /rca <ip_or_event_id>")
        return

    target = context.args[0].strip()
    await update.message.reply_text(f"🔍 _AI Copilot sedang menyusun Root Cause Analysis (RCA) untuk `{target}`..._", parse_mode="Markdown")
    rca_text = ai.generate_rca(target)
    await update.message.reply_text(rca_text[:4000], parse_mode="Markdown")


async def retrainmodel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    from .ml.autotrain import run_autotrain_from_file

    await update.message.reply_text("⚙️ Memulai proses auto-retraining model ML Challenger...", parse_mode="Markdown")
    ok, metrics, msg = run_autotrain_from_file()
    prefix = "✅" if ok else "⚠️"
    details = f"\n• Metrics: ROC-AUC={metrics.get('roc_auc', '-')}, Acc={metrics.get('accuracy', '-')}" if metrics else ""
    await update.message.reply_text(f"{prefix} *Hasil Auto-Retraining:*\n{msg}{details}", parse_mode="Markdown")


# -----------------
# HELP & ERROR
# -----------------
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bot miniSOAR Enterprise siap!\n\n"
        "🟠 Perimeter (Palo Alto, Akamai, Imperva)\n"
        "/blockonpalo <ip> | /unblockonpalo <ip> | /commitpalo\n"
        "/blockonakamai <ip> | /unblockonakamai <ip> | /activateakamai\n"
        "/blockonimperva <ip> | /unblockonimperva <ip> | /tracev <event ID>\n\n"
        "🌐 Extended Perimeters (Cloudflare & FortiGate)\n"
        "/blockoncf <ip> | /unblockoncf <ip> : Cloudflare WAF Access Rules\n"
        "/blockonforti <ip> | /unblockonforti <ip> : Fortinet FortiGate Firewall\n\n"
        "🛡️ EDR Server (Kaspersky KSC & TrendMicro)\n"
        "/isolatehost <ip/id> [ksc|trendmicro|all] : Isolasi jaringan host endpoint\n"
        "/restorehost <ip/id> [ksc|trendmicro|all] : Pulihkan jaringan host endpoint\n"
        "/queryhost <ip> | /addedrioc <ioc> | /edrstatus\n\n"
        "📋 Case Management & SLA Metrics (Tier 3)\n"
        "/cases [status] : Lihat daftar insiden aktif\n"
        "/case <case_id> : Detail laporan insiden\n"
        "/updatecase <id> <status> [notes] : Update status insiden\n"
        "/syncticket <case_id> : Dispatch insiden ke aplikasi ticketing pihak ke-3\n"
        "/socmetrics : Metrik SLA (MTTD / MTTR / Top Attackers)\n"
        "/exportcase <id> : Export laporan Markdown insiden\n\n"
        "🤖 AI SOC Copilot & MLOps (Tier 5)\n"
        "/askai <pertanyaan> : Konsultasi investigasi AI Copilot\n"
        "/rca <ip/event_id> : Generate Root Cause Analysis otomatis\n"
        "/retrainmodel : Trigger auto-retraining model ML trafik\n"
    )

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception", exc_info=context.error)


def main() -> None:
    load_env()
    logging.basicConfig(level=logging.INFO)
    cfg = telegram_config()

    if not cfg.token:
        logger.error("TELEGRAM_TOKEN is not configured!")
        return

    try:
        app = ApplicationBuilder().token(cfg.token).build()

        app.add_handler(CommandHandler("help", help_cmd))
        app.add_handler(CommandHandler("blockonimperva", blockonimperva))
        app.add_handler(CommandHandler("unblockonimperva", unblockonimperva))
        app.add_handler(CommandHandler("tracev", tracev))

        app.add_handler(CommandHandler("blockonpalo", blockonpalo))
        app.add_handler(CommandHandler("unblockonpalo", unblockonpalo))
        app.add_handler(CommandHandler("commitpalo", commitpalo))
        app.add_handler(CommandHandler("tracevpalo", tracevpalo))

        app.add_handler(CommandHandler("blockonakamai", blockonakamai))
        app.add_handler(CommandHandler("unblockonakamai", unblockonakamai))
        app.add_handler(CommandHandler("activateakamai", activateakamai))
        app.add_handler(CommandHandler("tracevakamai", tracevakamai))

        # EDR Handlers
        app.add_handler(CommandHandler("isolatehost", isolatehost))
        app.add_handler(CommandHandler("restorehost", restorehost))
        app.add_handler(CommandHandler("queryhost", queryhost))
        app.add_handler(CommandHandler("addedrioc", addedrioc))
        app.add_handler(CommandHandler("edrstatus", edrstatus))

        # Tier 3: Case Management & Ticketing Handlers
        app.add_handler(CommandHandler("cases", cases_cmd))
        app.add_handler(CommandHandler("case", case_cmd))
        app.add_handler(CommandHandler("updatecase", updatecase_cmd))
        app.add_handler(CommandHandler("syncticket", syncticket_cmd))
        app.add_handler(CommandHandler("socmetrics", socmetrics_cmd))
        app.add_handler(CommandHandler("exportcase", exportcase_cmd))

        # Tier 4: Extended Perimeters Handlers
        app.add_handler(CommandHandler("blockoncf", blockoncf_cmd))
        app.add_handler(CommandHandler("unblockoncf", unblockoncf_cmd))
        app.add_handler(CommandHandler("blockonforti", blockonforti_cmd))
        app.add_handler(CommandHandler("unblockonforti", unblockonforti_cmd))

        # Tier 5: AI SOC Copilot & MLOps Handlers
        app.add_handler(CommandHandler("askai", askai_cmd))
        app.add_handler(CommandHandler("rca", rca_cmd))
        app.add_handler(CommandHandler("retrainmodel", retrainmodel_cmd))

        app.add_handler(CallbackQueryHandler(callback_query_handler))
        app.add_error_handler(on_error)

        print("Bot Telegram miniSOAR Enterprise aktif...")
        app.run_polling()
    except KeyboardInterrupt:
        print("\n[INFO] Bot Telegram dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")


if __name__ == "__main__":
    main()

