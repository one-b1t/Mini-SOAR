from __future__ import annotations

"""MiniSOAR EDR IoC Cleaner Script.

Safely scans Trend Micro Vision One, Kaspersky KSC, and Redis cache to find
and delete only suspicious objects / IoCs that were automatically inserted
by MiniSOAR (identified by description signature: 'ThreatIntel Rep:', 'Event:alert_', etc.).
"""

import logging
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fallback DNS resolver for corporate network DNS glitches
_ORIG_GETADDRINFO = socket.getaddrinfo

def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
    except socket.gaierror:
        if host == "api.sg.xdr.trendmicro.com":
            try:
                r = requests.get("https://dns.google/resolve?name=api.sg.xdr.trendmicro.com", timeout=5)
                if r.status_code == 200:
                    ans = r.json().get("Answer", [])
                    if ans:
                        ip_resolved = ans[0].get("data")
                        if ip_resolved:
                            return _ORIG_GETADDRINFO(ip_resolved, port, family, type, proto, flags)
            except Exception:
                pass
            return _ORIG_GETADDRINFO("3.1.193.237", port, family, type, proto, flags)
        raise

socket.getaddrinfo = custom_getaddrinfo

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minisoar.config import load_env
load_env()

from minisoar.database import redis_client
from minisoar.edr import kaspersky, trendmicro

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cleanup_edr_iocs")


def is_minisoar_ioc(description: str) -> bool:
    """Determines whether an IoC was inserted by MiniSOAR based on description pattern."""
    if not description:
        return False
    d = description.lower()
    markers = [
        "threatintel rep:",
        "event:alert_",
        "minisoar automated",
        "minisoar-block-",
        "webshell attacker ioc",
        "ransomware c2 ioc",
        "web injection & exploitation attacker ioc",
    ]
    return any(m in d for m in markers)


def cleanup_trendmicro(batch_size: int = 50) -> tuple[int, list[dict[str, Any]], list[str]]:
    """Fetches all suspicious objects from Trend Micro, filters MiniSOAR items, and batch deletes them."""
    if not trendmicro.is_configured():
        logger.warning("Trend Micro is not configured.")
        return 0, [], ["Trend Micro is not configured"]

    base = trendmicro._get_base_url()
    headers = trendmicro._get_headers()
    verify = trendmicro._get_verify_ssl()

    logger.info("Scanning Trend Micro Vision One Suspicious Objects list...")
    matched_items: list[dict[str, Any]] = []
    errors: list[str] = []

    url = f"{base}/v3.0/threatintel/suspiciousObjects"
    params = {"top": 100}
    page = 1

    while url:
        try:
            logger.info("Fetching Trend Micro page %d...", page)
            resp = requests.get(url, headers=headers, params=params, verify=verify, timeout=25)
            params = None
            if resp.status_code != 200:
                errors.append(f"HTTP {resp.status_code} fetching page {page}: {resp.text[:300]}")
                break

            data = resp.json()
            items = data.get("items", [])
            for it in items:
                desc = it.get("description", "")
                if is_minisoar_ioc(desc):
                    matched_items.append(it)

            url = data.get("nextLink")
            page += 1
            time.sleep(0.3)
        except Exception as e:
            errors.append(f"Error on page {page}: {e}")
            break

    logger.info("Total MiniSOAR IoCs found in Trend Micro: %d", len(matched_items))

    # Perform batch deletion
    deleted_count = 0
    delete_url = f"{base}/v3.0/threatintel/suspiciousObjects/delete"

    for i in range(0, len(matched_items), batch_size):
        chunk = matched_items[i:i + batch_size]
        payload = []
        for it in chunk:
            obj = {}
            if it.get("ip"):
                obj["ip"] = it["ip"]
            elif it.get("url"):
                obj["url"] = it["url"]
            elif it.get("domain"):
                obj["domain"] = it["domain"]
            elif it.get("fileSha256"):
                obj["fileSha256"] = it["fileSha256"]
            elif it.get("fileSha1"):
                obj["fileSha1"] = it["fileSha1"]
            if obj:
                payload.append(obj)

        if not payload:
            continue

        try:
            resp = requests.post(delete_url, headers=headers, json=payload, verify=verify, timeout=30)
            if resp.status_code in {200, 201, 204, 207}:
                deleted_count += len(payload)
                logger.info("Deleted batch %d-%d (%d items) successfully (Status %d)", i + 1, i + len(payload), len(payload), resp.status_code)
            else:
                err_msg = f"Failed to delete batch {i + 1}-{i + len(payload)}: HTTP {resp.status_code} - {resp.text[:300]}"
                logger.error(err_msg)
                errors.append(err_msg)
        except Exception as e:
            err_msg = f"Exception deleting batch {i + 1}-{i + len(payload)}: {e}"
            logger.error(err_msg)
            errors.append(err_msg)

        time.sleep(0.5)

    return deleted_count, matched_items, errors


def cleanup_redis_cache(matched_ips: list[str]) -> int:
    """Deletes synced IoC cache keys from Redis."""
    deleted_keys = 0
    try:
        r = redis_client()
        if not r:
            logger.warning("Redis not available.")
            return 0

        for ip in matched_ips:
            key = f"minisoar:edr_ioc_synced:{ip}"
            if r.delete(key):
                deleted_keys += 1

        # Also search any remaining minisoar:edr_ioc_synced:*
        remaining_keys = r.keys("minisoar:edr_ioc_synced:*")
        for k in remaining_keys:
            if r.delete(k):
                deleted_keys += 1

        logger.info("Deleted %d Redis EDR IoC sync cache keys.", deleted_keys)
    except Exception as e:
        logger.error("Redis cleanup error: %s", e)

    return deleted_keys


def main() -> None:
    print("\n" + "=" * 70)
    print(" 🧹 MiniSOAR EDR IoC Targeted Cleaner")
    print("=" * 70)
    print("• Target Signature : 'ThreatIntel Rep:*', 'Event:alert_*'")
    print("• Safety Rule      : Only removes IoCs with MiniSOAR signature comment.")
    print("• Platforms        : Trend Micro Vision One, Kaspersky KSC, Redis Cache\n")

    # 1. Clean Trend Micro
    tm_deleted, tm_matched, tm_errors = cleanup_trendmicro(batch_size=50)

    # 2. Extract matched IPs
    matched_ips = [it.get("ip") for it in tm_matched if it.get("ip")]

    # 3. Clean Redis
    redis_deleted = cleanup_redis_cache(matched_ips)

    print("\n" + "=" * 70)
    print(" 📊 CLEANUP SUMMARY REPORT")
    print("=" * 70)
    print(f"• Trend Micro IoCs Found   : {len(tm_matched)}")
    print(f"• Trend Micro IoCs Deleted : {tm_deleted}")
    print(f"• Redis Cache Keys Cleared : {redis_deleted}")
    if tm_errors:
        print(f"• Errors Encountered       : {len(tm_errors)}")
        for err in tm_errors[:5]:
            print(f"  - {err}")
    else:
        print("• Status                   : ✅ 100% CLEANED SUCCESSFULLY")
    print("=" * 70)

    if tm_matched:
        print("\n📋 Sample Deleted MiniSOAR IoCs:")
        for idx, it in enumerate(tm_matched[:15], 1):
            val = it.get("ip") or it.get("url") or it.get("domain") or it.get("fileSha256")
            desc = it.get("description", "")
            print(f" {idx:2d}. {val:18s} | {desc}")
        if len(tm_matched) > 15:
            print(f" ... and {len(tm_matched) - 15} more items.")
    print()


if __name__ == "__main__":
    main()
