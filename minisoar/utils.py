from __future__ import annotations

"""Shared utilities.

This module consolidates helper functions that were duplicated across
09-tele-soar.py, 14_redis_telegram_alert.py, and perimeter_mitigation.py.

Goals:
- side-effect free imports where possible
- keep behavior compatible with existing scripts
"""

import datetime
import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from .config import telegram_config

logger = logging.getLogger(__name__)

ISO_FRACTION_RE = re.compile(
    r"^(?P<ymdhms>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)


def resolve_log_path(env_key: str, default_linux_path: str, default_win_filename: str) -> str:
    val = os.getenv(env_key)
    if val:
        return val

    base = Path.cwd()
    if os.name == "nt":
        return str(base / default_win_filename)

    try:
        parent = os.path.dirname(default_linux_path)
        if parent and os.path.exists(parent):
            return default_linux_path
    except Exception:
        pass

    return str(base / default_win_filename)


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_iso8601_relaxed(s: str) -> datetime.datetime:
    s = s.strip()
    m = ISO_FRACTION_RE.match(s)
    if not m:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    ymdhms = m.group("ymdhms")
    frac = m.group("frac") or ""
    tz = m.group("tz") or "+00:00"
    if frac:
        frac = "." + (frac[1:7])
    if tz == "Z":
        tz = "+00:00"
    return datetime.datetime.fromisoformat(ymdhms + frac + tz)


def extract_reputation_score(rep_str: str) -> int:
    if not rep_str:
        return 0
    match = re.search(r"(\d+)/100", rep_str)
    if match:
        return int(match.group(1))
    return 0


def send_process_log_telegram_sync(
    action: str,
    username: str | None,
    user_id: str | int,
    *,
    ip: str | None = None,
    target: str = "-",
    source: str = "-",
    note: str | None = None,
) -> None:
    cfg = telegram_config()
    if not cfg.process_chat_id or not cfg.token:
        return

    actor = f"@{username}" if username else f"id:{user_id}"
    text = (
        "⚙️ *[PROSES LOG]*\n"
        f"• *Action:* `{action}`\n"
        f"• *Actor:* {actor} (`{user_id}`)\n"
        f"• *Target IP:* `{ip or '-'}`\n"
        f"• *Platform:* `{target}`\n"
        f"• *Source:* `{source}`\n"
    )
    if note:
        text += f"• *Note:* `{note}`\n"

    url = f"https://api.telegram.org/bot{cfg.token}/sendMessage"
    payload = {"chat_id": cfg.process_chat_id, "text": text, "parse_mode": "Markdown"}

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code >= 400:
            logger.error("Failed to send process log: %s", resp.text[:200])
    except Exception as e:
        logger.error("Exception sending process log: %s", e)


def log_user_action(
    action: str,
    user: Any,
    *,
    ip: str | None = None,
    target: str = "-",
    source: str = "-",
    note: str | None = None,
    chat_id: str | int | None = None,
    logfile: str | None = None,
) -> None:
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

        if logfile:
            with open(logfile, "a", encoding="utf-8") as f:
                f.write(line)

        logger.info(line.strip())
        send_process_log_telegram_sync(action, getattr(user, "username", None) if hasattr(user, "id") else None, user_id, ip=ip, target=target, source=source, note=note)

    except Exception as e:
        logger.error("Logfile write error: %s", e)
