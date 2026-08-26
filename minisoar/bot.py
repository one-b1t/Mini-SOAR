from __future__ import annotations

"""MiniSOAR telegram bot entry module.

This module implements the Telegram bot application, command handlers, and
callback queries for interacting with perimeter security APIs.
"""

import html
import logging
import os

from telegram import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from . import ai, cases, edr
from .config import (
    get_configured_providers,
    load_env,
    norm_provider,
    parse_allowed_users,
    telegram_config,
)
from .database import (
    es_count_hits_by_ip,
    es_find_latest_event_id_by_ip,
    es_get_event_website_by_id,
    es_get_latest_event_website_by_ip,
    get_system_health,
    redis_client,
    store_label,
)
from .mitigation import (
    akamai,
    cloudflare,
    fortigate,
    get_active_blocklist,
    imperva,
    paloalto,
    register_block_state,
    remove_block_state,
    trigger_auto_block,
    trigger_auto_unblock,
)
from .utils import (
    add_to_whitelist,
    get_perimeter_info,
    get_whitelist_entries,
    log_user_action,
    provider_badge,
    remove_from_whitelist,
    resolve_log_path,
    valid_ip,
)

logger = logging.getLogger(__name__)


def is_user_allowed(user_id: int) -> bool:
    allowed = parse_allowed_users(os.getenv("ALLOWED_USERS"))
    return user_id in allowed


def _format_usage_html(cmd: str, syntax: str, example: str, desc: str = "") -> str:
    """Build a clean HTML usage message for Telegram commands with easy copyable examples."""
    cmd_clean = cmd.lstrip("/")
    msg = f"❌ <b>Format Tidak Valid</b>\n\n📌 <b>Penggunaan:</b> <code>/{cmd_clean} {html.escape(syntax)}</code>\n"
    if desc:
        msg += f"<i>{html.escape(desc)}</i>\n"
    msg += f"\n💡 <b>Contoh (Ketuk untuk menyalin):</b>\n<code>/{cmd_clean} {html.escape(example)}</code>"
    return msg


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
        await update.message.reply_text(_format_usage_html("block_imperva", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    await update.message.reply_text(f"Memproses blokir IP <code>{html.escape(ip)}</code> pada Imperva...", parse_mode="HTML")

    r = redis_client()
    duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))
    ok, msg = trigger_auto_block(ip, "imperva")
    if ok:
        register_block_state(r, ip, "imperva", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
    await update.message.reply_text(msg, parse_mode="HTML")


async def unblockonimperva(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text(_format_usage_html("unblock_imperva", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0]
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, logfile=logfile)

    await update.message.reply_text(f"Memproses unblock IP <code>{html.escape(ip)}</code> pada Imperva...", parse_mode="HTML")

    r = redis_client()
    ok, msg = trigger_auto_unblock(ip, "imperva")
    if ok:
        remove_block_state(r, ip, "imperva")
    await update.message.reply_text(msg, parse_mode="HTML")


async def tracev(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) not in (1, 2):
        await update.message.reply_text(_format_usage_html("trace_imperva", "<event_id> [lastFewDays]", "758812345 1"), parse_mode="HTML")
        return

    event_id = context.args[0].strip()
    days = int(context.args[1]) if len(context.args) == 2 and context.args[1].isdigit() else 7

    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("trace_imperva_violation", user, ip=None, target="Imperva", source="command", chat_id=update.effective_chat.id, note=f"event_id={event_id}, lastFewDays={days}", logfile=logfile)

    await update.message.reply_text(f"Mencari violation by Event ID <code>{html.escape(event_id)}</code> (lastFewDays={days}) ...", parse_mode="HTML")

    base_url = os.getenv("IMPERVA_BASE_URL", "")
    cookies = imperva.login_via_api(base_url, os.getenv("IMPERVA_USERNAME", ""), os.getenv("IMPERVA_PASSWORD", ""))
    if not cookies:
        await update.message.reply_text("❌ Gagal login ke API Imperva. Cek kredensial/API.")
        return

    violation, err = imperva.get_violation_by_event_number(base_url, cookies, event_number=event_id, days=days)
    if err:
        await update.message.reply_text(f"❌ Query gagal: {html.escape(str(err))}", parse_mode="HTML")
        return
    if not violation:
        await update.message.reply_text(f"❌ Tidak ditemukan violation untuk Event ID <code>{html.escape(event_id)}</code>.", parse_mode="HTML")
        return

    msg = (
        "<b>Imperva Violation Trace</b>\n"
        f"• <b>Event ID:</b> <code>{html.escape(str(violation.get('eventNumber', '-')))}</code>\n"
        f"• <b>Time:</b> <code>{html.escape(str(violation.get('time', '-')))}</code>\n"
        f"• <b>Violation Type:</b> <code>{html.escape(str(violation.get('violationType', '-')))}</code>\n"
        f"• <b>Source IP:</b> <code>{html.escape(str(violation.get('sourceIp', '-')))}</code>\n"
        f"• <b>Dest IP:</b> <code>{html.escape(str(violation.get('destIp', '-')))}</code>\n"
        f"• <b>Desc:</b> <code>{html.escape(str(violation.get('description', '-')))}</code>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")


# -----------------
# PALO ALTO THREAT TRACE
# -----------------
async def tracevpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Query threat logs by Violation ID (threatid), session ID, or source IP on Palo Alto.

    Format:
      /trace_palo <violation_id>          — threatid filter
      /trace_palo sid <session_id>        — session ID filter
      /trace_palo src <ip>                — source IP filter
    """
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(
            "❌ <b>Format Tidak Valid</b>\n\n"
            "📌 <b>Penggunaan /trace_palo:</b>\n"
            "• <code>/trace_palo &lt;threat_id&gt;</code> — Cari by threat ID\n"
            "• <code>/trace_palo sid &lt;session_id&gt;</code> — Cari by session ID\n"
            "• <code>/trace_palo src &lt;ip&gt;</code> — Cari by source IP\n\n"
            "💡 <b>Contoh (Ketuk untuk menyalin):</b>\n"
            "<code>/trace_palo 991024</code>",
            parse_mode="HTML"
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
            await update.message.reply_text(f"Mencari threat log Palo Alto by Session ID <code>{html.escape(value)}</code> ...", parse_mode="HTML")
            log_user_action("trace_palo_violation", user, ip=None, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"sid={value}", logfile=logfile)
            resp = paloalto.query_threat_log(pa_host, pa_api_key, session_id=value)
        else:
            field_label = "Source IP"
            await update.message.reply_text(f"Mencari threat log Palo Alto by Source IP <code>{html.escape(value)}</code> ...", parse_mode="HTML")
            log_user_action("trace_palo_violation", user, ip=value, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"src={value}", logfile=logfile)
            resp = paloalto.query_threat_log(pa_host, pa_api_key, src_ip=value)
    else:
        value = context.args[0].strip()
        field_label = "Violation/Threat ID"
        await update.message.reply_text(f"Mencari threat log Palo Alto by Violation ID <code>{html.escape(value)}</code> ...", parse_mode="HTML")
        log_user_action("trace_palo_violation", user, ip=None, target="PaloAlto", source="command", chat_id=update.effective_chat.id, note=f"threatid={value}", logfile=logfile)
        resp = paloalto.query_threat_log(pa_host, pa_api_key, threat_id=value)

    entries, err = paloalto.parse_threat_logs(resp)
    if err:
        await update.message.reply_text(f"❌ Query gagal: {html.escape(str(err))}", parse_mode="HTML")
        return
    if not entries:
        await update.message.reply_text(f"❌ Tidak ditemukan threat log untuk {html.escape(field_label)} <code>{html.escape(value)}</code>.", parse_mode="HTML")
        return

    # Format results — show up to 5 entries
    header = f"<b>Palo Alto Threat Log Trace</b>\n• <b>{html.escape(field_label)}:</b> <code>{html.escape(value)}</code>\n• <b>Jumlah:</b> {len(entries)}\n"
    body_parts = [header]
    for i, e in enumerate(entries[:5]):
        body_parts.append(
            f"<b>#{i+1}</b>\n"
            f"• Time   : <code>{html.escape(str(e.get('time_generated', '-')))}</code>\n"
            f"• Src    : <code>{html.escape(str(e.get('src', '-')))}</code>\n"
            f"• Dst    : <code>{html.escape(str(e.get('dst', '-')))}</code>\n"
            f"• App    : <code>{html.escape(str(e.get('app', '-')))}</code>\n"
            f"• Action : <code>{html.escape(str(e.get('action', '-')))}</code>\n"
            f"• Threat : <code>{html.escape(str(e.get('threatid', '-')))}</code>\n"
            f"• Name   : <code>{html.escape(str(e.get('name', '-')))}</code>\n"
            f"• Severity: <code>{html.escape(str(e.get('severity', '-')))}</code>\n"
            f"• Category: <code>{html.escape(str(e.get('category', '-')))}</code>\n"
            f"• Session: <code>{html.escape(str(e.get('sessionid', '-')))}</code>"
        )
    msg = "\n\n".join(body_parts)
    if len(entries) > 5:
        msg += f"\n\n<i>...dan {len(entries)-5} entry lainnya.</i>"
    await update.message.reply_text(msg, parse_mode="HTML")


# -----------------
# PALO ALTO
# -----------------
async def blockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text(_format_usage_html("block_palo", "<ip>", "192.168.1.100"), parse_mode="HTML")
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
            f"⚠️ Domain <code>{html.escape(website)}</code> untuk IP <code>{html.escape(ip)}</code> belum dimapping. Mengalihkan pemblokiran ke Imperva...",
            parse_mode="HTML"
        )
        log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_block(ip, "imperva")
        if ok:
            register_block_state(r, ip, "imperva", duration=duration)
            event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
            store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik) di Imperva."
        await update.message.reply_text(msg, parse_mode="HTML")
        return

    log_user_action("block_palo", user, ip=ip, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah <code>{html.escape(ip)}</code> ke IP group Palo Alto...", parse_mode="HTML")

    ok, msg = trigger_auto_block(ip, "paloalto", commit=False)
    if ok:
        register_block_state(r, ip, "paloalto", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nJangan lupa jalankan <code>/commit_palo</code>.\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
    await update.message.reply_text(msg, parse_mode="HTML")


async def unblockonpalo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text(_format_usage_html("unblock_palo", "<ip>", "192.168.1.100"), parse_mode="HTML")
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
            f"⚠️ Domain <code>{html.escape(website)}</code> untuk IP <code>{html.escape(ip)}</code> belum dimapping. Mengalihkan unblock ke Imperva...",
            parse_mode="HTML"
        )
        log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_unblock(ip, "imperva")
        if ok:
            remove_block_state(r, ip, "imperva")
        await update.message.reply_text(msg, parse_mode="HTML")
        return

    log_user_action("unblock_palo", user, ip=ip, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menghapus <code>{html.escape(ip)}</code> dari IP group Palo Alto...", parse_mode="HTML")

    ok, msg = trigger_auto_unblock(ip, "paloalto", commit=False)
    if ok:
        remove_block_state(r, ip, "paloalto")
        msg += "\nJangan lupa jalankan <code>/commit_palo</code>."
    await update.message.reply_text(msg, parse_mode="HTML")

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
    await update.message.reply_text(f"Memproses partial commit Palo Alto (user <code>{html.escape(pa_admin)}</code>) ...", parse_mode="HTML")
    resp_commit = paloalto.partial_commit(os.getenv("PA_HOST", ""), os.getenv("PA_API_KEY", ""), admin=pa_admin)
    msg = paloalto.response_message(resp_commit, f"PA: Partial commit user {pa_admin}")
    await update.message.reply_text(html.escape(msg), parse_mode="HTML")


# -----------------
# AKAMAI
# -----------------
async def blockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text(_format_usage_html("block_akamai", "<ip>", "192.168.1.100"), parse_mode="HTML")
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
            f"⚠️ Domain <code>{html.escape(website)}</code> untuk IP <code>{html.escape(ip)}</code> belum dimapping. Mengalihkan pemblokiran ke Imperva...",
            parse_mode="HTML"
        )
        log_user_action("block_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_block(ip, "imperva")
        if ok:
            register_block_state(r, ip, "imperva", duration=duration)
            event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
            store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik) di Imperva."
        await update.message.reply_text(msg, parse_mode="HTML")
        return

    log_user_action("block_akamai", user, ip=ip, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah <code>{html.escape(ip)}</code> ke Akamai Client List...", parse_mode="HTML")

    ok, msg = trigger_auto_block(ip, "akamai", commit=False)
    if ok:
        register_block_state(r, ip, "akamai", duration=duration)
        event_id = es_find_latest_event_id_by_ip(ip, approx_dt=update.message.date)
        store_label(event_id, "block", user, "telegram_command", ip=ip, telegram_message_id=str(update.message.message_id), chat_id=update.effective_chat.id)
        msg += f"\nJangan lupa jalankan <code>/activate_akamai</code>.\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
    await update.message.reply_text(msg, parse_mode="HTML")


async def unblockonakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return
    if len(context.args) != 1 or not valid_ip(context.args[0]):
        await update.message.reply_text(_format_usage_html("unblock_akamai", "<ip>", "192.168.1.100"), parse_mode="HTML")
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
            f"⚠️ Domain <code>{html.escape(website)}</code> untuk IP <code>{html.escape(ip)}</code> belum dimapping. Mengalihkan unblock ke Imperva...",
            parse_mode="HTML"
        )
        log_user_action("unblock_imperva", user, ip=ip, target="Imperva", source="command", chat_id=update.effective_chat.id, note="redirect_unmapped", logfile=logfile)
        ok, msg = trigger_auto_unblock(ip, "imperva")
        if ok:
            remove_block_state(r, ip, "imperva")
        await update.message.reply_text(msg, parse_mode="HTML")
        return

    log_user_action("unblock_akamai", user, ip=ip, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menghapus <code>{html.escape(ip)}</code> dari Akamai Client List...", parse_mode="HTML")

    ok, msg = trigger_auto_unblock(ip, "akamai", commit=False)
    if ok:
        remove_block_state(r, ip, "akamai")
        msg += "\nJangan lupa jalankan <code>/activate_akamai</code>."
    await update.message.reply_text(msg, parse_mode="HTML")


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
                f"✅ Aktivasi <b>{net}</b> dimulai\n"
                f"• Status : <code>{html.escape(str(d.get('activationStatus')))}</code>\n"
                f"• ID     : <code>{html.escape(str(d.get('activationId')))}</code>\n"
                f"• Versi  : <code>{html.escape(str(d.get('version')))}</code>\n\n"
            )
        else:
            msg += f"❌ Gagal aktivasi <b>{net}</b> : {html.escape(str(d))}\n"
    await update.message.reply_text(msg, parse_mode="HTML")


async def tracevakamai(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Trace an Akamai security event/violation by event ID via SIEM API.

    Format: /trace_akamai <event_id>
    Requires env: AKAMAI_BASEURL, AKAMAI_CLIENT_TOKEN, AKAMAI_CLIENT_SECRET,
    AKAMAI_ACCESS_TOKEN, AKAMAI_SIEM_CONFIG_ID
    """
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text(_format_usage_html("trace_akamai", "<event_id>", "12345678"), parse_mode="HTML")
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
    await update.message.reply_text(f"Mencari Akamai security event <code>{html.escape(event_id)}</code> ...", parse_mode="HTML")

    events, err = akamai.query_siem_events(
        baseurl,
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
        config_id=config_id,
        event_id=event_id,
    )
    if err:
        await update.message.reply_text(f"❌ Query gagal: {html.escape(str(err))}", parse_mode="HTML")
        return
    if not events:
        await update.message.reply_text(f"❌ Tidak ditemukan event untuk ID <code>{html.escape(event_id)}</code>.", parse_mode="HTML")
        return

    parts = [f"<b>Akamai Security Event Trace</b>\n• <b>Event ID:</b> <code>{html.escape(event_id)}</code>\n• <b>Total:</b> {len(events)}"]
    for i, ev in enumerate(events[:5]):
        attack = ev.get("attackData") or {}
        http_msg = ev.get("httpMessage") or {}
        geo = ev.get("geo") or {}
        parts.append(
            f"<b>#{i+1}</b>\n"
            f"• _id        : <code>{html.escape(str(ev.get('_id', '-')))}</code>\n"
            f"• Attack ID  : <code>{html.escape(str(attack.get('attackID', '-')))}</code>\n"
            f"• Rule ID    : <code>{html.escape(str(attack.get('ruleID', '-')))}</code>\n"
            f"• Rule Msg   : <code>{html.escape(str(attack.get('ruleMessage', '-')))}</code>\n"
            f"• Rule Name  : <code>{html.escape(str(attack.get('policy', '-')))}</code>\n"
            f"• Client IP  : <code>{html.escape(str(http_msg.get('clientIP', '-')))}</code>\n"
            f"• Host       : <code>{html.escape(str(http_msg.get('host', '-')))}</code>\n"
            f"• Path       : <code>{html.escape(str(http_msg.get('path', '-')))}</code>\n"
            f"• Method     : <code>{html.escape(str(http_msg.get('request', '-')))}</code>\n"
            f"• Status     : <code>{html.escape(str(http_msg.get('statusCode', '-')))}</code>\n"
            f"• Country    : <code>{html.escape(str(geo.get('country', '-')))}</code>"
        )
    msg = "\n\n".join(parts)
    if len(events) > 5:
        msg += f"\n\n<i>...dan {len(events)-5} event lainnya.</i>"
    await update.message.reply_text(msg, parse_mode="HTML")


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

    if data.startswith("blockonimperva:") or data.startswith("block_imperva:"):
        payload = data.split(":", 1)[1]
        ip_to_block, event_id = _parse_callback_payload(payload)

        log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Memproses blokir IP <code>{html.escape(ip_to_block)}</code> pada Imperva ...", parse_mode="HTML")

        r = redis_client()
        duration = int(os.environ.get("MINISOAR_BLOCK_DURATION", "600"))
        ok, msg = trigger_auto_block(ip_to_block, "imperva")
        if ok:
            register_block_state(r, ip_to_block, "imperva", duration=duration)
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Blokir di Imperva diproses!")

    elif data.startswith("blockonpalo:") or data.startswith("block_palo:"):
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
                text=f"⚠️ Domain <code>{html.escape(website)}</code> belum dimapping. Mengalihkan pemblokiran ke Imperva...",
                parse_mode="HTML",
            )
            log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button_redirect", logfile=logfile)
            ok, msg = trigger_auto_block(ip_to_block, "imperva")
            if ok:
                register_block_state(r, ip_to_block, "imperva", duration=duration)
                msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

            if not event_id:
                event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
            store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
            await query.answer("Blokir di Imperva diproses!")
            return

        log_user_action("block_palo", user, ip=ip_to_block, target="PaloAlto", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Menambah <code>{html.escape(ip_to_block)}</code> ke IP group Palo Alto ...", parse_mode="HTML")

        ok, msg = trigger_auto_block(ip_to_block, "paloalto", commit=False)
        if ok:
            register_block_state(r, ip_to_block, "paloalto", duration=duration)
            msg += f"\nJangan lupa jalankan <code>/commit_palo</code>.\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Penambahan IP ke Palo Alto diproses!, Jangan lupa commit!")

    elif data.startswith("blockonakamai:") or data.startswith("block_akamai:"):
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
                text=f"⚠️ Domain <code>{html.escape(website)}</code> belum dimapping. Mengalihkan pemblokiran ke Imperva...",
                parse_mode="HTML",
            )
            log_user_action("block_imperva", user, ip=ip_to_block, target="Imperva", source="button", chat_id=update.effective_chat.id, note="inline_button_redirect", logfile=logfile)
            ok, msg = trigger_auto_block(ip_to_block, "imperva")
            if ok:
                register_block_state(r, ip_to_block, "imperva", duration=duration)
                msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

            if not event_id:
                event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
            store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
            await query.answer("Blokir di Imperva diproses!")
            return

        log_user_action("block_akamai", user, ip=ip_to_block, target="Akamai", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Menambah <code>{html.escape(ip_to_block)}</code> ke Akamai Client List...", parse_mode="HTML")

        ok, msg = trigger_auto_block(ip_to_block, "akamai", commit=False)
        if ok:
            register_block_state(r, ip_to_block, "akamai", duration=duration)
            msg += f"\nJangan lupa jalankan <code>/activate_akamai</code>.\nℹ️ IP terdaftar dalam pemblokiran sementara (<b>{duration}</b> detik)."
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_block, getattr(query.message, "date", None))
        store_label(event_id, "block", user, "telegram_button", ip=ip_to_block, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)
        await query.answer("Block di Akamai diproses!")

    elif data.startswith("ioc_edr:") or data.startswith("add_ioc:") or data.startswith("add_ioc_edr:"):
        payload = data.split(":", 1)[1].strip()
        ip_to_add, event_id = _parse_callback_payload(payload)

        log_user_action("add_ioc_edr", user, ip=ip_to_add, target="EDR-ALL", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"🛡️ Mendaftarkan IP <code>{html.escape(ip_to_add)}</code> ke repositori IoC EDR/XDR (Kaspersky & Trend Micro)...",
            parse_mode="HTML",
        )

        ok, msg = edr.add_edr_ioc(
            ioc_type="ip",
            ioc_value=ip_to_add,
            provider="all",
            comment=f"Manual SOC IoC trigger by @{user.username or user.id}",
        )
        r = redis_client()
        if r:
            r.setex(f"minisoar:edr_ioc_synced:{ip_to_add}", 86400, "1")

        prefix = "✅" if ok else "⚠️"
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"{prefix} <b>Hasil Registrasi IoC EDR/XDR:</b>\n• IP: <code>{html.escape(ip_to_add)}</code>\n• Status: {html.escape(msg)}",
            parse_mode="HTML",
        )

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_add, getattr(query.message, "date", None))
        store_label(
            event_id,
            "ioc_edr",
            user,
            "telegram_button",
            ip=ip_to_add,
            telegram_message_id=getattr(query.message, "message_id", None),
            chat_id=update.effective_chat.id,
        )
        await query.answer("IP berhasil didaftarkan ke IoC EDR/XDR!")

    elif data.startswith("ignore:"):
        payload = data.split(":", 1)[1].strip()
        ip_to_ignore, event_id = _parse_callback_payload(payload)

        log_user_action("ignore_alert", user, ip=ip_to_ignore, target="miniSOAR", source="button", chat_id=update.effective_chat.id, note="inline_button", logfile=logfile)

        if not event_id:
            event_id = es_find_latest_event_id_by_ip(ip_to_ignore, getattr(query.message, "date", None))

        store_label(event_id, "ignore", user, "ignore", ip=ip_to_ignore, telegram_message_id=getattr(query.message, "message_id", None), chat_id=update.effective_chat.id)

        await query.answer("Diabaikan (ignore).")
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"🙈 Ignored: <code>{html.escape(ip_to_ignore)}</code>", parse_mode="HTML")

    elif data.startswith("resolvecase:"):
        cid = data.split(":", 1)[1].strip()
        ok, msg, _ = cases.update_case_status(cid, "RESOLVED", actor=f"@{user.username or user.id}", notes="Resolved via Telegram inline button")
        prefix = "✅" if ok else "❌"
        await query.answer(f"Case {cid} Resolved!")
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"{prefix} {html.escape(msg)}", parse_mode="HTML")

    elif data.startswith("syncticket:"):
        cid = data.split(":", 1)[1].strip()
        ok, msg = cases.sync_case_to_ticketing(cid, actor=f"@{user.username or user.id}")
        prefix = "✅" if ok else "⚠️"
        await query.answer(f"Sync ticket case {cid}!")
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"{prefix} {html.escape(msg)}", parse_mode="HTML")

    elif data.startswith("exportcase:"):
        cid = data.split(":", 1)[1].strip()
        c = cases.get_case(cid)
        if c:
            report_md = cases.generate_case_markdown_report(c)
            await query.answer(f"Export case {cid}!")
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"<pre>{html.escape(report_md[:3800])}</pre>", parse_mode="HTML")
        else:
            await query.answer("Case tidak ditemukan.")
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
        await update.message.reply_text(_format_usage_html("isolate_host", "<ip/host_id> [ksc|trendmicro|all]", "10.0.0.50 all"), parse_mode="HTML")
        return

    target = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("isolate_host", user, ip=target if valid_ip(target) else None, target=f"EDR-{provider.upper()}", source="command", chat_id=update.effective_chat.id, note=f"target={target}", logfile=logfile)

    await update.message.reply_text(f"Memproses isolasi host <code>{html.escape(target)}</code> pada EDR ({html.escape(provider.upper())}) ...", parse_mode="HTML")
    ok, msg, _ = edr.isolate_endpoint(target=target, provider=provider, reason=f"Manual isolation by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>Hasil Isolasi EDR:</b>\n{html.escape(msg)}", parse_mode="HTML")


async def restorehost(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 1:
        await update.message.reply_text(_format_usage_html("restore_host", "<ip/host_id> [ksc|trendmicro|all]", "10.0.0.50 all"), parse_mode="HTML")
        return

    target = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    logfile = resolve_log_path("LOGFILE", "/var/log/tele-soar-actions.log", "tele-soar-actions.log")
    log_user_action("restore_host", user, ip=target if valid_ip(target) else None, target=f"EDR-{provider.upper()}", source="command", chat_id=update.effective_chat.id, note=f"target={target}", logfile=logfile)

    await update.message.reply_text(f"Memproses pemulihan host <code>{html.escape(target)}</code> pada EDR ({html.escape(provider.upper())}) ...", parse_mode="HTML")
    ok, msg, _ = edr.restore_endpoint(target=target, provider=provider)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>Hasil Pemulihan EDR:</b>\n{html.escape(msg)}", parse_mode="HTML")


async def queryhost(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) != 1:
        await update.message.reply_text(_format_usage_html("query_host", "<ip>", "10.0.0.50"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Mencari inventory endpoint untuk IP <code>{html.escape(ip)}</code> di Kaspersky KSC & TrendMicro Vision One ...", parse_mode="HTML")
    res = edr.query_endpoint(ip, provider="all")
    msg_parts = [f"<b>EDR Host Query:</b> <code>{html.escape(ip)}</code>"]

    if res.get("trendmicro"):
        msg_parts.append("\n<b>🔵 TrendMicro Vision One:</b>")
        for h in res["trendmicro"]:
            msg_parts.append(f"• ID: <code>{html.escape(str(h.get('endpointId', '-')))}</code>\n• Host: <code>{html.escape(str(h.get('endpointName', '-')))}</code>\n• OS: <code>{html.escape(str(h.get('osName', '-')))}</code>\n• Isolation: <code>{html.escape(str(h.get('isolationStatus', 'normal')))}</code>")
    else:
        msg_parts.append("\n<b>🔵 TrendMicro:</b> Tidak ditemukan endpoint")

    if res.get("kaspersky"):
        msg_parts.append("\n<b>🟢 Kaspersky Security Center (KSC):</b>")
        for h in res["kaspersky"]:
            msg_parts.append(f"• ID: <code>{html.escape(str(h.get('hostId', '-')))}</code>\n• Host: <code>{html.escape(str(h.get('hostName', '-') or h.get('KLHST_WKS_HOSTNAME', '-')))}</code>\n• OS: <code>{html.escape(str(h.get('osName', '-') or h.get('KLHST_WKS_OS_NAME', '-')))}</code>\n• Isolated: <code>{html.escape(str(h.get('networkIsolated', False)))}</code>")
    else:
        msg_parts.append("\n<b>🟢 Kaspersky KSC:</b> Tidak ditemukan host")

    if res.get("errors"):
        msg_parts.append(f"\n⚠️ <b>Errors:</b> {html.escape('; '.join(res['errors']))}")

    await update.message.reply_text("\n".join(msg_parts), parse_mode="HTML")


async def addedrioc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 1:
        await update.message.reply_text(_format_usage_html("add_edr_ioc", "<ip/sha256/domain> [ksc|trendmicro|all]", "192.168.1.100 all"), parse_mode="HTML")
        return

    val = context.args[0].strip()
    provider = context.args[1].strip() if len(context.args) > 1 else "all"
    ioc_type = "ip" if valid_ip(val) else ("sha256" if len(val) == 64 else "domain")
    ok, msg = edr.add_edr_ioc(ioc_type=ioc_type, ioc_value=val, provider=provider, comment=f"Manual IoC by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>Pendaftaran IoC EDR ({ioc_type.upper()}):</b>\n{html.escape(msg)}", parse_mode="HTML")


async def edrstatus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    results = edr.check_all_edr_connectivity()
    parts = ["<b>🛡️ Status Konektivitas EDR Server:</b>\n"]
    for r in results:
        prov = r.get("provider", "unknown").upper()
        if r.get("ok"):
            parts.append(f"• <b>{prov}:</b> ✅ Terhubung (OK)")
        elif not r.get("configured"):
            parts.append(f"• <b>{prov}:</b> ⚪ Belum Dikonfigurasi")
        else:
            parts.append(f"• <b>{prov}:</b> ❌ Gagal - <code>{html.escape(str(r.get('error')))}</code>")
    await update.message.reply_text("\n".join(parts), parse_mode="HTML")


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
        await update.message.reply_text(f"Tidak ada incident case aktif{' dengan status ' + html.escape(status_filter) if status_filter else ''}.")
        return

    parts = [f"<b>📋 Daftar Incident Cases ({len(case_list)} Terakhir):</b>\n"]
    for c in case_list:
        parts.append(
            f"• <b>{html.escape(c.case_id)}</b> | <code>[{html.escape(c.severity.upper())}]</code> | <code>{html.escape(c.status)}</code>\n"
            f"  Title: {html.escape(c.title)}\n"
            f"  Attacker: <code>{html.escape(c.attacker_ip or 'N/A')}</code> | Target: <code>{html.escape(c.target_asset or 'N/A')}</code>"
        )
    parts.append("\n<i>Gunakan <code>/case &lt;id&gt;</code> untuk melihat detail atau <code>/update_case &lt;id&gt; &lt;status&gt;</code> untuk update.</i>")
    await update.message.reply_text("\n".join(parts), parse_mode="HTML")


async def case_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("case", "<case_id>", "INC-20260818-001"), parse_mode="HTML")
        return

    cid = context.args[0].strip()
    c = cases.get_case(cid)
    if not c:
        await update.message.reply_text(f"❌ Case <code>{html.escape(cid)}</code> tidak ditemukan.", parse_mode="HTML")
        return

    report_md = cases.generate_case_markdown_report(c)
    reply_markup = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Resolve Case", callback_data=f"resolvecase:{c.case_id}"),
            InlineKeyboardButton("🎟️ Sync Ticket", callback_data=f"syncticket:{c.case_id}"),
            InlineKeyboardButton("📄 Export MD", callback_data=f"exportcase:{c.case_id}"),
        ]
    ])
    await update.message.reply_text(f"<pre>{html.escape(report_md[:3900])}</pre>", parse_mode="HTML", reply_markup=reply_markup)



async def updatecase_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if len(context.args) < 2:
        await update.message.reply_text(_format_usage_html("update_case", "<case_id> <NEW|INVESTIGATING|CONTAINED|RESOLVED|CLOSED|FALSE_POSITIVE> [notes]", "INC-20260818-001 RESOLVED Telah ditangani"), parse_mode="HTML")
        return

    cid = context.args[0].strip()
    new_status = context.args[1].strip()
    notes = " ".join(context.args[2:]) if len(context.args) > 2 else ""

    ok, msg, c = cases.update_case_status(cid, new_status, actor=f"@{user.username or user.id}", notes=notes)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} {html.escape(msg)}", parse_mode="HTML")


async def socmetrics_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    m = cases.get_soc_metrics()
    parts = [
        "<b>📊 SOC Operational & SLA Metrics:</b>",
        f"• <b>Total Cases:</b> <code>{m['total_cases']}</code>",
        f"• <b>Avg MTTD (Time to Detect):</b> <code>{m['avg_mttd_seconds']}s</code>",
        f"• <b>Avg MTTR (Time to Resolve):</b> <code>{m['avg_mttr_minutes']} mins</code> (<code>{m['avg_mttr_seconds']}s</code>)\n",
        "<b>Status Distribution:</b>",
    ]
    for st, count in m["status_distribution"].items():
        if count > 0:
            parts.append(f"  - <code>{html.escape(st)}</code>: {count}")

    parts.append("\n<b>Severity Distribution:</b>")
    for sv, count in m["severity_distribution"].items():
        if count > 0:
            parts.append(f"  - <code>{html.escape(sv.upper())}</code>: {count}")

    if m["top_attackers"]:
        parts.append("\n<b>Top Attackers:</b>")
        for ip, cnt in m["top_attackers"]:
            parts.append(f"  - <code>{html.escape(ip)}</code>: {cnt} incidents")

    await update.message.reply_text("\n".join(parts), parse_mode="HTML")


async def exportcase_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("export_case", "<case_id>", "INC-20260818-001"), parse_mode="HTML")
        return

    cid = context.args[0].strip()
    c = cases.get_case(cid)
    if not c:
        await update.message.reply_text(f"❌ Case <code>{html.escape(cid)}</code> tidak ditemukan.", parse_mode="HTML")
        return

    report_md = cases.generate_case_markdown_report(c)
    await update.message.reply_text(f"<pre>{html.escape(report_md[:3800])}</pre>", parse_mode="HTML")


async def syncticket_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("sync_ticket", "<case_id>", "INC-20260818-001"), parse_mode="HTML")
        return

    cid = context.args[0].strip()
    await update.message.reply_text(f"Mendispatch case <code>{html.escape(cid)}</code> ke aplikasi ticketing pihak ke-3...", parse_mode="HTML")
    ok, msg = cases.sync_case_to_ticketing(cid, actor=f"@{user.username or user.id}")
    prefix = "✅" if ok else "⚠️"
    await update.message.reply_text(f"{prefix} {html.escape(msg)}", parse_mode="HTML")


# -----------------
# TIER 4: EXTENDED PERIMETERS (CLOUDFLARE & FORTIGATE)
# -----------------
async def blockoncf_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text(_format_usage_html("block_cf", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses blokir IP <code>{html.escape(ip)}</code> di Cloudflare WAF ...", parse_mode="HTML")
    ok, msg = cloudflare.block_ip(ip, notes=f"Manual block by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>Cloudflare:</b> {html.escape(msg)}", parse_mode="HTML")


async def unblockoncf_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text(_format_usage_html("unblock_cf", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses unblock IP <code>{html.escape(ip)}</code> di Cloudflare ...", parse_mode="HTML")
    ok, msg = cloudflare.unblock_ip(ip)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>Cloudflare:</b> {html.escape(msg)}", parse_mode="HTML")


async def blockonforti_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text(_format_usage_html("block_forti", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses blokir IP <code>{html.escape(ip)}</code> di FortiGate Firewall ...", parse_mode="HTML")
    ok, msg = fortigate.block_ip(ip, comment=f"Manual block by @{user.username or user.id}")
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>FortiGate:</b> {html.escape(msg)}", parse_mode="HTML")


async def unblockonforti_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text(_format_usage_html("unblock_forti", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"Memproses unblock IP <code>{html.escape(ip)}</code> di FortiGate ...", parse_mode="HTML")
    ok, msg = fortigate.unblock_ip(ip)
    prefix = "✅" if ok else "❌"
    await update.message.reply_text(f"{prefix} <b>FortiGate:</b> {html.escape(msg)}", parse_mode="HTML")


# -----------------
# TIER 5: AI SOC COPILOT & MLOPS COMMANDS
# -----------------
async def askai_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("ask_ai", "<pertanyaan/payload>", "Analisis log serangan SQLi ini"), parse_mode="HTML")
        return

    question = " ".join(context.args)
    await update.message.reply_text("🤖 <i>AI SOC Copilot sedang menganalisis...</i>", parse_mode="HTML")
    answer = ai.ask_copilot(question)
    await update.message.reply_text(html.escape(answer[:4000]), parse_mode="HTML")


async def rca_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("rca", "<ip_or_event_id>", "192.168.1.100"), parse_mode="HTML")
        return

    target = context.args[0].strip()
    await update.message.reply_text(f"🔍 <i>AI Copilot sedang menyusun Root Cause Analysis (RCA) untuk <code>{html.escape(target)}</code>...</i>", parse_mode="HTML")
    rca_text = ai.generate_rca(target)
    await update.message.reply_text(html.escape(rca_text[:4000]), parse_mode="HTML")


async def retrainmodel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    from .ml.autotrain import run_autotrain_from_file

    await update.message.reply_text("⚙️ Memulai proses auto-retraining model ML Challenger...", parse_mode="HTML")
    ok, metrics, msg = run_autotrain_from_file()
    prefix = "✅" if ok else "⚠️"
    details = f"\n• Metrics: ROC-AUC={metrics.get('roc_auc', '-')}, Acc={metrics.get('accuracy', '-')}" if metrics else ""
    await update.message.reply_text(f"{prefix} <b>Hasil Auto-Retraining:</b>\n{html.escape(msg)}{html.escape(details)}", parse_mode="HTML")


async def aimodel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    from .ai import copilot
    info = copilot.get_auth_info()

    if not context.args:
        await update.message.reply_text(
            f"🤖 <b>AI SOC Copilot Model Status:</b>\n"
            f"• <b>Provider:</b> <code>{html.escape(info['provider'])}</code>\n"
            f"• <b>Model Aktif:</b> <code>{html.escape(info['model'])}</code>\n"
            f"• <b>Auth Source:</b> <code>{html.escape(info['auth_source'])}</code>\n"
            f"• <b>Key:</b> <code>{html.escape(info['key_masked'] or 'none')}</code>\n\n"
            f"💡 <i>Untuk mengubah model aktif secara live:</i>\n"
            f"<code>/ai_model &lt;nama_model&gt;</code> (contoh: <code>/ai_model gemini-1.5-pro</code>)\n"
            f"<i>Anda juga dapat mengganti default permanen melalui variabel <code>AI_MODEL</code> di file <code>.env</code>.</i>",
            parse_mode="HTML",
        )
        return

    new_model = context.args[0].strip()
    set_model = copilot.set_active_model(new_model)
    await update.message.reply_text(
        f"✅ <b>Model AI Copilot Berhasil Diubah!</b>\n"
        f"• <b>Provider:</b> <code>{html.escape(info['provider'])}</code>\n"
        f"• <b>Model Baru:</b> <code>{html.escape(set_model)}</code>\n\n"
        f"<i>Seluruh query <code>/ask_ai</code> dan <code>/rca</code> berikutnya akan langsung menggunakan model ini.</i>",
        parse_mode="HTML",
    )


async def aiprovider_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    from .ai import copilot
    info = copilot.get_auth_info()

    if not context.args:
        await update.message.reply_text(
            f"🤖 <b>AI SOC Copilot Provider:</b>\n"
            f"• <b>Provider Aktif:</b> <code>{html.escape(info['provider'])}</code>\n"
            f"• <b>Pilihan:</b> <code>gemini</code> (Google Antigravity) | <code>claude</code> (Anthropic) | <code>openai</code> (Codex/GPT) | <code>ollama</code> (Local)\n\n"
            f"💡 <i>Gunakan <code>/ai_provider &lt;nama_provider&gt;</code> untuk beralih provider live.</i>",
            parse_mode="HTML",
        )
        return

    new_prov = context.args[0].strip().lower()
    set_prov = copilot.set_active_provider(new_prov)
    await update.message.reply_text(
        f"✅ <b>AI Provider Berhasil Dialihkan!</b>\n"
        f"• <b>Provider Baru:</b> <code>{html.escape(set_prov)}</code>\n"
        f"• <b>Model:</b> <code>{html.escape(copilot.get_auth_info()['model'])}</code>",
        parse_mode="HTML",
    )


# -----------------
# THREAT INTEL & DIAGNOSTICS
# -----------------
async def intel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args or not valid_ip(context.args[0].strip()):
        await update.message.reply_text(_format_usage_html("intel", "<ip>", "192.168.1.100"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    await update.message.reply_text(f"🔍 <i>Mengumpulkan data intelijen untuk IP <code>{html.escape(ip)}</code>...</i>", parse_mode="HTML")

    wl_entries = get_whitelist_entries()
    is_whitelisted = any(ip == line.split("#")[0].strip() for line in wl_entries)
    wl_badge = "🟢 Whitelisted" if is_whitelisted else "🔴 Not Whitelisted"

    total_hits, latest_act = es_count_hits_by_ip(ip)
    website = es_get_latest_event_website_by_ip(ip)

    edr_res = edr.query_endpoint(ip, provider="all")
    edr_count = len(edr_res.get("trendmicro", [])) + len(edr_res.get("kaspersky", []))

    msg = (
        "<b>🔍 MiniSOAR Threat Intelligence Summary</b>\n\n"
        f"• <b>Target IP:</b> <code>{html.escape(ip)}</code>\n"
        f"• <b>Whitelist Status:</b> {wl_badge}\n"
        f"• <b>Total ES Security Hits:</b> <code>{total_hits}</code>\n"
        f"• <b>Latest Threat Event:</b> <code>{html.escape(str(latest_act or 'N/A'))}</code>\n"
        f"• <b>Associated Website:</b> <code>{html.escape(str(website or 'N/A'))}</code>\n"
        f"• <b>EDR Managed Hosts:</b> <code>{edr_count} endpoints</code>\n\n"
        f"💡 <i>Gunakan <code>/block_imperva {html.escape(ip)}</code> atau <code>/isolate_host {html.escape(ip)}</code> untuk mitigasi cepat.</i>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")


async def health_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    await update.message.reply_text("⚙️ <i>Mengumpulkan diagnostik kesehatan MiniSOAR...</i>", parse_mode="HTML")
    h = get_system_health()

    r_status = f"✅ OK (Queue length: <code>{h['redis'].get('queue_len', 0)}</code>)" if h["redis"]["status"] == "OK" else f"❌ {html.escape(str(h['redis'].get('error', 'OFFLINE')))}"
    es_st = h["elasticsearch"].get("status", "OFFLINE")
    es_badge = "🟢 GREEN" if es_st == "GREEN" else ("🟡 YELLOW" if es_st == "YELLOW" else f"🔴 {html.escape(es_st)}")

    edr_results = edr.check_all_edr_connectivity()
    edr_status_str = ", ".join([f"{r.get('provider','').upper()}: {'✅' if r.get('ok') else '❌'}" for r in edr_results]) or "N/A"

    import datetime
    msg = (
        "<b>🏥 MiniSOAR System Health Dashboard</b>\n\n"
        f"• <b>Redis Queue:</b> {r_status}\n"
        f"• <b>Elasticsearch Cluster:</b> {es_badge}\n"
        f"• <b>AI SOC Copilot:</b> <code>{html.escape(str(h['ai'].get('provider', 'none')))}</code> (Model: <code>{html.escape(str(h['ai'].get('model', 'none')))}</code>)\n"
        f"• <b>EDR Servers:</b> {edr_status_str}\n\n"
        f"<i>Status diperbarui pada: <code>{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</code></i>"
    )
    await update.message.reply_text(msg, parse_mode="HTML")


# -----------------
# WHITELIST MANAGEMENT
# -----------------
async def whitelist_add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("whitelist_add", "<ip/cidr> [alasan]", "10.2.57.246 Internal Server"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    reason = " ".join(context.args[1:]) if len(context.args) > 1 else f"Added by @{user.username or user.id}"
    ok, msg = add_to_whitelist(ip, reason)
    await update.message.reply_text(msg, parse_mode="HTML")


async def whitelist_remove_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    if not context.args:
        await update.message.reply_text(_format_usage_html("whitelist_remove", "<ip/cidr>", "10.2.57.246"), parse_mode="HTML")
        return

    ip = context.args[0].strip()
    ok, msg = remove_from_whitelist(ip)
    await update.message.reply_text(msg, parse_mode="HTML")


async def whitelists_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    entries = get_whitelist_entries()
    if not entries:
        await update.message.reply_text("ℹ️ Belum ada IP/CIDR yang terdaftar dalam whitelist.")
        return

    parts = ["<b>🛡️ Daftar Whitelist IP/CIDR Aktif:</b>\n"]
    for e in entries:
        parts.append(f"• <code>{html.escape(e)}</code>")
    parts.append("\n<i>Gunakan <code>/whitelist_add &lt;ip&gt;</code> atau <code>/whitelist_remove &lt;ip&gt;</code> untuk mengelola.</i>")
    await update.message.reply_text("\n".join(parts), parse_mode="HTML")


async def blocked_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lists all currently blocked IPs in Perimeter blocklists and synced EDR IoC repositories."""
    user = update.effective_user
    if not is_user_allowed(user.id):
        await update.message.reply_text("❌ Maaf, kamu tidak punya akses ke bot ini.")
        return

    filter_target = context.args[0].lower() if context.args else "all"

    data = get_active_blocklist()
    perimeters = data.get("perimeters", [])
    edr_iocs = data.get("edr_iocs", [])

    lines = ["🛡️ <b>MiniSOAR Active Block List & IoC Repository</b> 🛡️\n"]

    # 1. Perimeter section
    if filter_target in {"all", "perimeter", "perimeters", "palo", "paloalto", "imperva", "akamai", "cloudflare", "cf", "forti", "fortigate"}:
        matched_perim = perimeters
        if filter_target not in {"all", "perimeter", "perimeters"}:
            matched_perim = [p for p in perimeters if norm_provider(filter_target) == norm_provider(p["provider"])]

        lines.append(f"🧱 <b>Perimeter Block List ({len(matched_perim)} IP aktif):</b>")
        if matched_perim:
            for item in matched_perim:
                p_badge = provider_badge([item["provider"]], True)
                lines.append(f"• <code>{html.escape(item['ip'])}</code> ({p_badge}) — Sisa: <b>{item['ttl_sec']}s</b> (s/d {item['expires_at']})")
        else:
            lines.append("<i>Tidak ada IP yang sedang dalam status temporary block.</i>")
        lines.append("")

    # 2. EDR section
    if filter_target in {"all", "edr", "ioc", "iocs", "ksc", "kaspersky", "trendmicro", "trend"}:
        lines.append(f"💻 <b>EDR IoC Repository ({len(edr_iocs)} IP terdaftar):</b>")
        if edr_iocs:
            for item in edr_iocs:
                lines.append(f"• <code>{html.escape(item['ip'])}</code> — 🛡️ {item['provider']} (Cache: <b>{item['ttl_sec']}s</b>)")
        else:
            lines.append("<i>Tidak ada IP IoC yang terdaftar di repositori EDR.</i>")
        lines.append("")

    lines.append("💡 <i>Gunakan <code>/blocked perimeter</code> atau <code>/blocked edr</code> untuk memfilter.</i>")
    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


# -----------------
# HELP & ERROR
# -----------------
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conf = get_configured_providers()

    sections = [
        "⚡ <b>MiniSOAR Enterprise Bot Command Center</b> ⚡\n",
        "🔍 <b>Threat Intel & System Diagnostics</b>\n"
        "• <code>/intel &lt;ip&gt;</code> — Summary kartu intelijen IP & reputasi\n"
        "• <code>/blocked [perimeter|edr]</code> — Daftar IP aktif di Block List & EDR\n"
        "• <code>/health</code> — Dashboard kesehatan Redis, ES, EDR & AI\n",
        "🛡️ <b>Whitelist Management</b>\n"
        "• <code>/whitelist_add &lt;ip/cidr&gt; [alasan]</code> — Tambah IP ke whitelist\n"
        "• <code>/whitelist_remove &lt;ip/cidr&gt;</code> — Hapus IP dari whitelist\n"
        "• <code>/whitelists</code> — Daftar IP whitelist aktif\n",
    ]

    # Perimeter Commands (Hanya menampilkan perimeter yang terkonfigurasi di .env)
    perim_cmds = []
    if conf.get("imperva"):
        perim_cmds.extend([
            "• <code>/block_imperva &lt;ip&gt;</code> — Blokir IP di Imperva WAF",
            "• <code>/unblock_imperva &lt;ip&gt;</code> — Unblock IP di Imperva WAF",
            "• <code>/trace_imperva &lt;event_id&gt; [days]</code> — Trace violation log Imperva",
        ])
    if conf.get("paloalto"):
        perim_cmds.extend([
            "• <code>/block_palo &lt;ip&gt;</code> — Tambah IP ke group Palo Alto",
            "• <code>/unblock_palo &lt;ip&gt;</code> — Hapus IP dari group Palo Alto",
            "• <code>/commit_palo</code> — Partial commit konfigurasi Palo Alto",
            "• <code>/trace_palo &lt;threat_id&gt;</code> — Trace threat log Palo Alto",
        ])
    if conf.get("akamai"):
        perim_cmds.extend([
            "• <code>/block_akamai &lt;ip&gt;</code> — Tambah IP ke Akamai Client List",
            "• <code>/unblock_akamai &lt;ip&gt;</code> — Hapus IP dari Akamai Client List",
            "• <code>/activate_akamai</code> — Aktivasi daftar IP di Akamai",
            "• <code>/trace_akamai &lt;event_id&gt;</code> — Trace SIEM event Akamai",
        ])
    if conf.get("cloudflare"):
        perim_cmds.extend([
            "• <code>/block_cf &lt;ip&gt;</code> — Blokir IP di Cloudflare WAF",
            "• <code>/unblock_cf &lt;ip&gt;</code> — Unblock IP di Cloudflare WAF",
        ])
    if conf.get("fortigate"):
        perim_cmds.extend([
            "• <code>/block_forti &lt;ip&gt;</code> — Blokir IP di FortiGate Firewall",
            "• <code>/unblock_forti &lt;ip&gt;</code> — Unblock IP di FortiGate Firewall",
        ])

    if perim_cmds:
        active_perim_names = [p.upper() if p in {"cf"} else p.title() for p, ok in conf.items() if ok and p in {"imperva", "paloalto", "akamai", "cloudflare", "fortigate"}]
        sections.append(f"🟠 <b>Perimeter Security ({', '.join(active_perim_names)})</b>\n" + "\n".join(perim_cmds) + "\n")

    # EDR Commands (Hanya jika KSC atau TrendMicro terkonfigurasi)
    edr_active = [p for p in ["kaspersky", "trendmicro"] if conf.get(p)]
    if edr_active:
        edr_labels = " & ".join(["Kaspersky KSC" if p == "kaspersky" else "TrendMicro Vision One" for p in edr_active])
        sections.append(
            f"💻 <b>EDR Server ({edr_labels})</b>\n"
            "• <code>/isolate_host &lt;ip/id&gt; [ksc|trendmicro|all]</code> — Isolasi host endpoint\n"
            "• <code>/restore_host &lt;ip/id&gt; [ksc|trendmicro|all]</code> — Pulihkan host endpoint\n"
            "• <code>/query_host &lt;ip&gt;</code> — Query inventory host EDR\n"
            "• <code>/add_edr_ioc &lt;ioc&gt; [ksc|trendmicro|all]</code> — Registrasi IoC ke EDR\n"
            "• <code>/edr_status</code> — Cek status konektivitas EDR server\n"
        )

    sections.extend([
        "📋 <b>Case Management & SLA Metrics</b>\n"
        "• <code>/cases [status]</code> — Daftar incident case aktif\n"
        "• <code>/case &lt;case_id&gt;</code> — Detail laporan incident case\n"
        "• <code>/update_case &lt;id&gt; &lt;status&gt; [notes]</code> — Update status case\n"
        "• <code>/sync_ticket &lt;case_id&gt;</code> — Dispatch case ke ticketing 3rd party\n"
        "• <code>/soc_metrics</code> — Metrik SLA SOC (MTTD / MTTR / Top Attackers)\n"
        "• <code>/export_case &lt;id&gt;</code> — Export laporan case format Markdown\n",
        "🤖 <b>AI SOC Copilot & MLOps</b>\n"
        "• <code>/ask_ai &lt;pertanyaan&gt;</code> — Konsultasi investigasi AI Copilot\n"
        "• <code>/rca &lt;ip/event_id&gt;</code> — Generate Root Cause Analysis otomatis\n"
        "• <code>/ai_model [model]</code> — Cek / ganti model AI live\n"
        "• <code>/ai_provider [provider]</code> — Cek / ganti AI provider live\n"
        "• <code>/retrain_model</code> — Trigger auto-retraining model ML",
    ])

    await update.message.reply_text("\n".join(sections), parse_mode="HTML")


async def post_init(application) -> None:
    """Dynamically sets Telegram Bot interactive command menu (set_my_commands) based on configured providers in .env."""
    conf = get_configured_providers()

    commands = [
        BotCommand("help", "Bantuan & panduan command bot"),
        BotCommand("intel", "Summary kartu intelijen IP & reputasi"),
        BotCommand("blocked", "Daftar IP aktif di Block List & EDR"),
        BotCommand("health", "Dashboard kesehatan SOAR, Redis & AI"),
        BotCommand("whitelists", "Daftar IP whitelist aktif"),
        BotCommand("whitelist_add", "Tambah IP ke whitelist"),
        BotCommand("whitelist_remove", "Hapus IP dari whitelist"),
    ]

    # Perimeter Commands (Hanya menampilkan perimeter yang terkonfigurasi di .env)
    if conf.get("imperva"):
        commands.extend([
            BotCommand("block_imperva", "Blokir IP di Imperva WAF"),
            BotCommand("unblock_imperva", "Unblock IP di Imperva WAF"),
            BotCommand("trace_imperva", "Trace violation log Imperva"),
        ])
    if conf.get("paloalto"):
        commands.extend([
            BotCommand("block_palo", "Tambah IP ke group Palo Alto"),
            BotCommand("unblock_palo", "Hapus IP dari group Palo Alto"),
            BotCommand("commit_palo", "Commit konfigurasi Palo Alto"),
            BotCommand("trace_palo", "Trace threat log Palo Alto"),
        ])
    if conf.get("akamai"):
        commands.extend([
            BotCommand("block_akamai", "Tambah IP ke Akamai Client List"),
            BotCommand("unblock_akamai", "Hapus IP dari Akamai Client List"),
            BotCommand("activate_akamai", "Aktivasi daftar IP di Akamai"),
            BotCommand("trace_akamai", "Trace SIEM event Akamai"),
        ])
    if conf.get("cloudflare"):
        commands.extend([
            BotCommand("block_cf", "Blokir IP di Cloudflare WAF"),
            BotCommand("unblock_cf", "Unblock IP di Cloudflare WAF"),
        ])
    if conf.get("fortigate"):
        commands.extend([
            BotCommand("block_forti", "Blokir IP di FortiGate Firewall"),
            BotCommand("unblock_forti", "Unblock IP di FortiGate Firewall"),
        ])

    # EDR Server Commands (Hanya jika terkonfigurasi di .env)
    if conf.get("kaspersky") or conf.get("trendmicro"):
        commands.extend([
            BotCommand("isolate_host", "Isolasi host endpoint via EDR"),
            BotCommand("restore_host", "Pulihkan host endpoint via EDR"),
            BotCommand("query_host", "Query inventory host EDR"),
            BotCommand("add_edr_ioc", "Registrasi IoC ke EDR"),
            BotCommand("edr_status", "Cek status konektivitas EDR"),
        ])

    # Case Management & AI Copilot Commands
    commands.extend([
        BotCommand("cases", "Daftar incident case aktif"),
        BotCommand("case", "Detail laporan incident case"),
        BotCommand("update_case", "Update status incident case"),
        BotCommand("sync_ticket", "Dispatch case ke ticketing 3rd party"),
        BotCommand("soc_metrics", "Metrik SLA SOC (MTTD / MTTR)"),
        BotCommand("export_case", "Export laporan case format Markdown"),
        BotCommand("ask_ai", "Konsultasi investigasi AI Copilot"),
        BotCommand("rca", "Generate Root Cause Analysis otomatis"),
        BotCommand("ai_model", "Cek / ganti model AI live"),
        BotCommand("ai_provider", "Cek / ganti AI provider live"),
        BotCommand("retrain_model", "Trigger auto-retraining model ML"),
    ])

    try:
        await application.bot.set_my_commands(commands)
        logger.info("[BOT] Successfully updated Telegram Bot interactive menu with %d commands.", len(commands))
    except Exception as e:
        logger.warning("[BOT] Failed to set_my_commands on Telegram: %s", e)


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
        app = ApplicationBuilder().token(cfg.token).post_init(post_init).build()

        app.add_handler(CommandHandler(["help", "h", "start"], help_cmd))

        # Threat Intel & Diagnostics Handlers
        app.add_handler(CommandHandler(["intel", "lookup", "ip"], intel_cmd))
        app.add_handler(CommandHandler(["blocked", "blocklist", "bl"], blocked_cmd))
        app.add_handler(CommandHandler(["health", "soar_status", "hp"], health_cmd))

        # Whitelist Management Handlers
        app.add_handler(CommandHandler(["whitelist_add", "wa"], whitelist_add_cmd))
        app.add_handler(CommandHandler(["whitelist_remove", "wr"], whitelist_remove_cmd))
        app.add_handler(CommandHandler(["whitelists", "wl"], whitelists_cmd))

        # Imperva
        app.add_handler(CommandHandler(["block_imperva", "bi", "blockonimperva"], blockonimperva))
        app.add_handler(CommandHandler(["unblock_imperva", "ubi", "unblockonimperva"], unblockonimperva))
        app.add_handler(CommandHandler(["trace_imperva", "ti", "tracev"], tracev))

        # Palo Alto
        app.add_handler(CommandHandler(["block_palo", "bp", "blockonpalo"], blockonpalo))
        app.add_handler(CommandHandler(["unblock_palo", "ubp", "unblockonpalo"], unblockonpalo))
        app.add_handler(CommandHandler(["commit_palo", "cp", "commitpalo"], commitpalo))
        app.add_handler(CommandHandler(["trace_palo", "tp", "tracevpalo"], tracevpalo))

        # Akamai
        app.add_handler(CommandHandler(["block_akamai", "ba", "blockonakamai"], blockonakamai))
        app.add_handler(CommandHandler(["unblock_akamai", "uba", "unblockonakamai"], unblockonakamai))
        app.add_handler(CommandHandler(["activate_akamai", "aa", "activateakamai"], activateakamai))
        app.add_handler(CommandHandler(["trace_akamai", "ta", "tracevakamai"], tracevakamai))

        # EDR Handlers
        app.add_handler(CommandHandler(["isolate_host", "ih", "isolatehost"], isolatehost))
        app.add_handler(CommandHandler(["restore_host", "rh", "restorehost"], restorehost))
        app.add_handler(CommandHandler(["query_host", "qh", "queryhost"], queryhost))
        app.add_handler(CommandHandler(["add_edr_ioc", "aei", "addedrioc"], addedrioc))
        app.add_handler(CommandHandler(["edr_status", "es", "edrstatus"], edrstatus))

        # Case Management & Ticketing Handlers
        app.add_handler(CommandHandler(["cases", "cs"], cases_cmd))
        app.add_handler(CommandHandler(["case", "c"], case_cmd))
        app.add_handler(CommandHandler(["update_case", "uc", "updatecase"], updatecase_cmd))
        app.add_handler(CommandHandler(["sync_ticket", "st", "syncticket"], syncticket_cmd))
        app.add_handler(CommandHandler(["soc_metrics", "sm", "socmetrics"], socmetrics_cmd))
        app.add_handler(CommandHandler(["export_case", "ec", "exportcase"], exportcase_cmd))

        # Extended Perimeters Handlers
        app.add_handler(CommandHandler(["block_cf", "bcf", "blockoncf"], blockoncf_cmd))
        app.add_handler(CommandHandler(["unblock_cf", "ubcf", "unblockoncf"], unblockoncf_cmd))
        app.add_handler(CommandHandler(["block_forti", "bforti", "blockonforti"], blockonforti_cmd))
        app.add_handler(CommandHandler(["unblock_forti", "ubforti", "unblockonforti"], unblockonforti_cmd))

        # AI SOC Copilot & MLOps Handlers
        app.add_handler(CommandHandler(["ask_ai", "ai", "askai"], askai_cmd))
        app.add_handler(CommandHandler(["rca"], rca_cmd))
        app.add_handler(CommandHandler(["ai_model", "aim", "aimodel"], aimodel_cmd))
        app.add_handler(CommandHandler(["ai_provider", "aip", "aiprovider"], aiprovider_cmd))
        app.add_handler(CommandHandler(["retrain_model", "rm", "retrainmodel"], retrainmodel_cmd))

        app.add_handler(CallbackQueryHandler(callback_query_handler))
        app.add_error_handler(on_error)

        print("Bot Telegram miniSOAR Enterprise aktif...")
        app.run_polling()

    except KeyboardInterrupt:
        print("\n[INFO] Bot Telegram dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")


if __name__ == "__main__":
    main()

