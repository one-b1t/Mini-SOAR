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
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik) di Imperva."
        await update.message.reply_text(msg)
        return

    log_user_action("block_palo", user, ip=ip, target="PaloAlto", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah {ip} ke IP group Palo Alto...")

    ok, msg = trigger_auto_block(ip, "paloalto", commit=False)
    if ok:
        register_block_state(r, ip, "paloalto", duration=duration)
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
            msg += f"\nℹ️ IP terdaftar dalam pemblokiran sementara ({duration} detik) di Imperva."
        await update.message.reply_text(msg)
        return

    log_user_action("block_akamai", user, ip=ip, target="Akamai", source="command", chat_id=update.effective_chat.id, logfile=logfile)
    await update.message.reply_text(f"Menambah {ip} ke Akamai Client List...")

    ok, msg = trigger_auto_block(ip, "akamai", commit=False)
    if ok:
        register_block_state(r, ip, "akamai", duration=duration)
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
# HELP & ERROR
# -----------------
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bot miniSOAR siap!\n\n"
        "🟠 Palo Alto\n"
        "/blockonpalo <ip address> : untuk menambahkan IP di blocklist Palo Alto\n"
        "/unblockonpalo <ip address> : untuk menghapus IP dari blocklist di Palo Alto\n"
        "/commitpalo : untuk commit konfigurasi di Palo Alto\n\n"
        "🟢 Akamai\n"
        "/blockonakamai <ip address> : untuk menambahkan IP di blocklist Akamai\n"
        "/unblockonakamai <ip address> : untuk menghapus IP dari blocklist Akamai \n"
        "/activateakamai : untuk melakukan Aktivasi Konfigurasi di Staging and Production\n\n"
        "🔵 Imperva\n"
        "/blockonimperva <ip address> : untuk menambahkan IP di blocklist Imperva\n"
        "/unblockonimperva <ip address> : untuk menghapus IP dari blocklist Imperva\n"
        "/tracev <event ID> : untuk melakukan tracing violation di Imperva\n"
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

        app.add_handler(CommandHandler("blockonakamai", blockonakamai))
        app.add_handler(CommandHandler("unblockonakamai", unblockonakamai))
        app.add_handler(CommandHandler("activateakamai", activateakamai))

        app.add_handler(CallbackQueryHandler(callback_query_handler))
        app.add_error_handler(on_error)

        print("Bot Telegram miniSOAR aktif...")
        app.run_polling()
    except KeyboardInterrupt:
        print("\n[INFO] Bot Telegram dihentikan oleh pengguna (Ctrl+C). Keluar secara anggun...")


if __name__ == "__main__":
    main()
