"""E2E: kirim tiap command bot lewat userbot Telethon, catat balasan.

Read-only terhadap repo; hanya mengirim pesan ke bot.
Dipakai manual, bukan bagian suite pytest (butuh kredensial + jaringan).
"""
import asyncio
import json
import sys
import time

from telethon import TelegramClient
from telethon.errors import RPCError

CRED = json.load(open("tests/tg_credentials.json"))
BOT = CRED["bot_username"]

# Satu command per handler unik. Alias lainmapped ke handler yang sama.
CASES = [
    ("help",              "/help",                          "read"),
    ("health",            "/health",                        "read"),
    ("cases_cmd",         "/cases",                         "read"),
    ("case_cmd",          "/case INC-20260818-001",          "read"),
    ("exportcase_cmd",    "/export_case INC-20260818-001",   "read"),
    ("socmetrics_cmd",    "/socmetrics",                    "read"),
    ("edrstatus",         "/edrstatus",                     "read"),
    ("blocked_cmd",       "/blocked",                       "read"),
    ("whitelists_cmd",    "/whitelists",                    "read"),
    ("intel_cmd",         "/intel 8.8.8.8",                 "read"),
    ("tracev",            "/trace_imperva 758812345 1",     "read"),
    ("tracevakamai",      "/trace_akamai 12345678",         "read"),
    ("tracevpalo",        "/trace_palo 999888",             "read"),
    ("queryhost",         "/query_host 10.0.0.50",          "read"),
    ("askai_cmd",         "/ask_ai ringkasan incident 42",  "read"),
    ("rca_cmd",           "/rca 8.8.8.8",                   "read"),
    ("aiprovider_cmd",    "/ai_provider",                   "read"),
    ("aimodel_cmd",       "/ai_model",                      "read"),
    ("updatecase_cmd",    "/update_case INC-20260818-001 INVESTIGATING tes-e2e", "write"),
    ("syncticket_cmd",    "/sync_ticket INC-20260818-001",  "write"),
    ("blockonimperva",    "/block_imperva 203.0.113.88",    "write"),
    ("unblockonimperva",  "/unblock_imperva 203.0.113.88",  "write"),
    ("blockonpalo",       "/block_palo 203.0.113.88",       "write"),
    ("unblockonpalo",     "/unblock_palo 203.0.113.88",     "write"),
    ("blockonakamai",     "/block_akamai 203.0.113.88",     "write"),
    ("unblockonakamai",   "/unblock_akamai 203.0.113.88",   "write"),
    ("blockoncf_cmd",     "/block_cf 203.0.113.88",         "write"),
    ("unblockoncf_cmd",   "/unblock_cf 203.0.113.88",       "write"),
    ("blockonforti_cmd",  "/block_forti 203.0.113.88",      "write"),
    ("unblockonforti_cmd","/unblock_forti 203.0.113.88",    "write"),
    ("isolatehost",       "/isolate_host 10.0.0.50 all",    "write"),
    ("restorehost",       "/restore_host 10.0.0.50 all",    "write"),
    ("addedrioc",         "/add_edr_ioc 10.0.0.50 all",     "write"),
    ("commitpalo",        "/commit_palo",                   "write"),
    ("whitelist_add_cmd", "/whitelist_add 198.51.100.55 tes-e2e", "write"),
    ("whitelist_remove_cmd", "/whitelist_remove 198.51.100.55",  "write"),
]

# Tidak diuji, dan alasannya.
SKIPPED = [
    ("activateakamai", "/activate_akamai",
     "session.post langsung ke API Akamai nyata (list 217280_IPBLOCKLIST, "
     "network PRODUCTION) dengan kredensial asli. TIDAK di-guard MINISOAR_MOCK."),
    ("retrainmodel_cmd", "/retrainmodel",
     "run_autotrain_from_file() tanpa mock guard; menarik sampel dari index "
     "ES minisoar-labels-* dan menulis model produksi."),
    ("aiprovider_cmd(set)", "/ai_provider <nama>",
     "set_active_provider menulis .env permanen."),
    ("aimodel_cmd(set)", "/ai_model <nama>",
     "set_active_model menulis .env permanen."),
]

TIMEOUT = 90
# Balasan bot kadang telat >5s (unblock* butuh ES + redis + label). Tunggu
# sampai SUNYI selama SETTLE detik, kalau tidak reply yang lambat akan
# masuk ke command berikutnya.
SETTLE = 9.0


async def boundary(client, bot):
    """Id pesan tertinggi yang ada sebelum command berikutnya."""
    try:
        top = await client.get_messages(bot, limit=1)
        return top[0].id if top else 0
    except RPCError:
        return 0


async def one(client, bot, handler, cmd, kind, before):
    """Kirim cmd, kumpulkan balasan bot dalam rentang id (before, ...]."""
    t0 = time.time()
    try:
        sent = await client.send_message(bot, cmd)
    except RPCError as e:
        return dict(handler=handler, cmd=cmd, kind=kind, status="SEND_FAIL",
                    elapsed=0.0, replies=[str(e)])
    replies, last = [], time.time()
    while time.time() - last < SETTLE and time.time() - t0 < TIMEOUT:
        try:
            msgs = await client.get_messages(bot, limit=20, min_id=before)
        except RPCError:
            break
        # Hanya pesan setelah command ini, dan hanya yang dikirim bot.
        fresh = sorted((m for m in msgs
                        if m.id > sent.id and m.sender_id == bot.id),
                       key=lambda m: m.id)
        if len(fresh) > len(replies):
            replies = fresh
            last = time.time()
        await asyncio.sleep(0.8)
    texts = [m.text for m in replies]
    joined = "\n".join(texts)
    if not texts:
        status = "NO_REPLY"
    elif "tidak punya akses" in joined.lower():
        status = "DENIED"
    elif any(t in joined for t in ("Traceback", "NameError", "AttributeError",
                                   "TypeError", "KeyError", "ValueError")):
        status = "EXCEPTION"
    elif "Terjadi kesalahan" in joined or "error" in joined.lower():
        status = "ERROR_TEXT"
    else:
        status = "OK"
    return dict(handler=handler, cmd=cmd, kind=kind, status=status,
                elapsed=round(time.time() - t0, 1), replies=texts)


async def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    client = TelegramClient("tests/telegram_testing",
                            int(CRED["api_id"]), CRED["api_hash"])
    await client.connect()
    if not await client.is_user_authorized():
        print("SESSION TIDAK AUTHORIZED")
        return
    bot = await client.get_entity(BOT)
    me = await client.get_me()
    print(f"bot={BOT}  userbot={me.username}({me.id})  total kasus={len(CASES)}\n")

    results = []
    for handler, cmd, kind in CASES:
        if only and only not in handler:
            continue
        before = await boundary(client, bot)
        r = await one(client, bot, handler, cmd, kind, before)
        results.append(r)
        print(f"[{r['status']:11s}] {r['elapsed']:5.1f}s  {r['cmd']}")
        for t in r["replies"]:
            head = " ".join(t.split())[:150]
            print(f"                 -> {head}")
    await client.disconnect()
    json.dump(results, open("scratch/e2e_results.json", "w"), indent=1)
    print("\n=== RINGKASAN ===")
    for r in results:
        print(f"  {r['status']:11s} {r['handler']:20s} {r['cmd']}")
    print("\n=== DILEWATI ===")
    for h, c, why in SKIPPED:
        print(f"  {h:22s} {c:22s} {why}")


async def me_str(client):
    me = await client.get_me()
    return f"{me.username}({me.id})"





if __name__ == "__main__":
    asyncio.run(main())
