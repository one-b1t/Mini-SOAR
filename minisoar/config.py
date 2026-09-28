from __future__ import annotations

"""Central configuration utilities for MiniSOAR.

The current codebase historically loaded env variables directly in each script.
As part of the refactor, we consolidate common parsing logic here.

This module is intentionally light-weight and side-effect free.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def load_env(*, linux_fallback: str = "/root/tele-soar/.env") -> None:
    """Load environment variables.

    Order:
    1) Linux/WSL canonical path if present
    2) Package-root .env (next to minisoar/ directory)
    3) Local .env in current working directory (CWD)
    4) Forced override from package-root or CWD if telegram vars are missing
    """

    try:
        load_dotenv(linux_fallback, override=False)
    except OSError:
        pass

    pkg_root = Path(__file__).resolve().parent.parent
    if (pkg_root / ".env").exists():
        load_dotenv(pkg_root / ".env", override=False)
    load_dotenv(Path.cwd() / ".env", override=False)

    if not os.environ.get("TELEGRAM_TOKEN") and not os.environ.get("TELEGRAM_BOT"):
        if (pkg_root / ".env").exists():
            load_dotenv(pkg_root / ".env", override=True)
        load_dotenv(Path.cwd() / ".env", override=True)


def resolve_path(env_key: str, default_linux_path: str, default_win_filename: str) -> str:
    """Resolve a config path in a cross-platform way."""

    val = os.environ.get(env_key)
    if val:
        return val

    script_dir = Path.cwd()
    if os.name == "nt":
        return str(script_dir / default_win_filename)

    try:
        parent = os.path.dirname(default_linux_path)
        if parent and os.path.exists(parent):
            return default_linux_path
    except OSError:
        pass

    return str(script_dir / default_win_filename)


def norm_provider(provider: str | None) -> str:
    s = (provider or "").strip().lower()
    if s in {"palo", "paloalto", "palo-alto", "palo_alto", "pan", "panos"}:
        return "paloalto"
    if s in {"akamai", "ak"}:
        return "akamai"
    if s in {"imperva", "imp"}:
        return "imperva"
    if s in {"cloudflare", "cf"}:
        return "cloudflare"
    if s in {"fortigate", "forti", "fg", "fortios"}:
        return "fortigate"
    if s in {"ksc", "kaspersky", "kl"}:
        return "kaspersky"
    if s in {"none", "external", "eksternal", "outside", "off"}:
        return "none"
    return s or "none"


# Provider yang DIMATIKAN TOTAL — sumber kebenaran tunggal, semua jalur (mitigation,
# EDR, bot, diagnostics) wajib populate dari sini sebelum menyentuh API.
# Alasan: ketiganya tidak dimiliki di tempat kerja ini (Kaspersky: belum jelas dari
# mana IoC ditambahkan), jadi blokir lewat MiniSOAR hanya menimbulkan rasa aman
# semu. Perimeter aktif & terkonfirmasi: PaloAlto, Akamai, TrendMicro Vision One.
# Boleh dihapus dari daftar ini kalau kredensial resmi dimiliki DAN operator
# mengonfirmasi ada kebutuhan nyata memblokir lewat perimeter tersebut.
# PERINGATAN saat menghidupkan kembali: cakupan regresi deteksi FORTIGATE_API_TOKEN
# (commit e559e54, tests/test_fortigate_env.py) hilang sementara fortigate mati di
# sini, jadi pulihkan test itu sebelum provider diaktifkan kembali.
PERIMETER_NONAKTIF: frozenset[str] = frozenset({"cloudflare", "fortigate", "kaspersky"})


def canonical_perimeter(provider: str | None) -> str:
    """Nama kanonik lintas jalur; alias EDR (ksc/kl) ikut dinormalkan."""
    return norm_provider(provider)


def is_perimeter_active(provider: str | None) -> bool:
    """False bila provider ada di PERIMETER_NONAKTIF (alias ikut dikenali)."""
    return canonical_perimeter(provider) not in PERIMETER_NONAKTIF


def perimeter_disabled_message(provider: str | None) -> str:
    """Pesan penolakan baku untuk provider nonaktif, atau string kosong bila aktif."""
    p = canonical_perimeter(provider)
    if p not in PERIMETER_NONAKTIF:
        return ""
    return (
        f"Provider '{p}' TIDAK AKTIF / DIMATIKAN TOTAL di MiniSOAR: perimeter ini "
        f"tidak dimiliki di tempat kerja, jadi tidak ada panggilan API yang dikirim. "
        f"Perimeter aktif: paloalto, akamai, trendmicro."
    )


def parse_allowed_users(raw: str | None) -> list[int]:
    if not raw:
        return []
    out: list[int] = []
    for part in raw.split(","):
        s = part.strip()
        if s.isdigit():
            out.append(int(s))
    return out


@dataclass(frozen=True)
class TelegramConfig:
    token: str
    chat_id: str
    process_chat_id: str


def telegram_config() -> TelegramConfig:
    token = os.getenv("TELEGRAM_TOKEN") or os.getenv("TELEGRAM_BOT", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    process_chat_id = os.getenv("TELEGRAM_PROCESS_CHAT_ID", "") or chat_id
    return TelegramConfig(token=token, chat_id=chat_id, process_chat_id=process_chat_id)


def get_configured_providers() -> dict[str, bool]:
    """Returns a dictionary indicating which perimeter security and EDR providers have valid credentials configured in .env.

    Provider di PERIMETER_NONAKTIF selalu False walau env var-nya terisi: kredensial
    sisa di .env tidak boleh membuat MiniSOAR berpikir jalur itu hidup.
    """
    configured = {
        "imperva": bool(os.getenv("IMPERVA_BASE_URL") or os.getenv("IMPERVA_API_ID") or os.getenv("IMPERVA_USERNAME")),
        "paloalto": bool(os.getenv("PA_HOST") or os.getenv("PALO_ALTO_HOST") or os.getenv("PA_API_KEY")),
        "akamai": bool(os.getenv("AKAMAI_BASEURL") or os.getenv("AKAMAI_HOST") or os.getenv("AKAMAI_CLIENT_TOKEN")),
        "cloudflare": bool(os.getenv("CLOUDFLARE_API_TOKEN") or os.getenv("CLOUDFLARE_ZONE_ID")),
        "fortigate": bool(os.getenv("FORTIGATE_HOST") or os.getenv("FORTIGATE_API_TOKEN") or os.getenv("FORTIGATE_API_KEY")),
        "kaspersky": bool(os.getenv("KSC_SERVER_URL") or os.getenv("KASPERSKY_KSC_HOST") or os.getenv("KSC_HOST")),
        "trendmicro": bool(os.getenv("TRENDMICRO_API_KEY") or os.getenv("TRENDMICRO_VISION_ONE_URL")),
    }
    return {p: False if p in PERIMETER_NONAKTIF else v for p, v in configured.items()}
