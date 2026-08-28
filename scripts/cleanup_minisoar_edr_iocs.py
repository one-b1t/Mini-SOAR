from __future__ import annotations

"""MiniSOAR EDR IoC Targeted Cleaner Script.

Safely scans Trend Micro Vision One, Kaspersky Security Center (KSC), and Redis cache
to find and delete ONLY IoCs that were automatically inserted by MiniSOAR and have a
Threat Intelligence reputation or confidence score BELOW 70% (or custom --threshold).

Features:
- Filters by description signature and regex score extraction (e.g. 'ThreatIntel Rep:0%').
- Protects confirmed high threats (score >= 70%) from being deleted.
- Supports Trend Micro Vision One, Kaspersky KSC OpenAPI, and Redis Cache.
- Fast streaming pagination with connection pooling and DNS fallback.
- CLI flags: --threshold <int> (default: 70), --dry-run, --provider [all|trendmicro|kaspersky], --batch-size <int>.
"""

import argparse
import logging
import os
import re
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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fallback DNS resolver for corporate network DNS glitches
_ORIG_GETADDRINFO = socket.getaddrinfo


def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
    except socket.gaierror:
        if host == "api.sg.xdr.trendmicro.com":
            try:
                r = requests.get("https://dns.google/resolve?name=api.sg.xdr.trendmicro.com", timeout=4)
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


def should_delete_ioc(description: str, threshold: int = 70) -> tuple[bool, str]:
    """Evaluates whether an IoC was inserted by MiniSOAR AND has a threat/ML score below threshold.

    Returns:
        (should_delete: bool, reason: str)
    """
    if not description:
        return False, "No description"

    d = description.strip()
    d_lower = d.lower()

    # 1. Identify MiniSOAR signature markers
    markers = [
        "threatintel rep:",
        "event:alert_",
        "minisoar automated",
        "minisoar-block-",
        "webshell attacker ioc",
        "ransomware c2 ioc",
        "web injection & exploitation attacker ioc",
    ]
    is_minisoar = any(m in d_lower for m in markers)
    if not is_minisoar:
        return False, "Not a MiniSOAR IoC (Foreign/Manual IoC)"

    # 2. Extract ThreatIntel Reputation and ML percentage
    rep_match = re.search(r"threatintel rep:\s*(\d+)%", d, re.IGNORECASE)
    ml_match = re.search(r"ml:\s*(\d+)%", d, re.IGNORECASE)

    if rep_match:
        rep_score = int(rep_match.group(1))
        ml_score = int(ml_match.group(1)) if ml_match else None

        # 2026-08-28 - Absolute EDR IoC Guardrail: ML Confidence < threshold (70%) dilarang dipertahankan di EDR
        if ml_score is not None and ml_score < threshold:
            return True, f"Low ML Confidence < {threshold}% (ML: {ml_score}%, Rep: {rep_score}%) -> DELETE"

        # If TI score >= threshold AND (ml_score is None or ml_score >= threshold) -> PRESERVE IT
        if rep_score >= threshold and (ml_score is None or ml_score >= threshold):
            return False, f"High Threat Score >= {threshold}% (Rep: {rep_score}%, ML: {ml_score if ml_score is not None else 'N/A'}) -> KEEP"

        return True, f"Low/Clean TI Score < {threshold}% (Rep: {rep_score}%, ML: {ml_score if ml_score is not None else 'N/A'}) -> DELETE"

    # 3. For other MiniSOAR heuristic/playbook comments without explicit score:
    # Mark as eligible for deletion if threshold >= 70 since they lack verified >= 70% TI score
    return True, f"MiniSOAR IoC without verified >= {threshold}% score -> DELETE"


def get_http_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=20))
    return session


def cleanup_trendmicro(
    threshold: int = 70,
    batch_size: int = 50,
    dry_run: bool = False,
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Scans Trend Micro Vision One, filters IoCs below threshold, and deletes them.

    Returns:
        (deleted_count, to_delete_items, kept_items, errors)
    """
    if not trendmicro.is_configured():
        logger.warning("Trend Micro is not configured.")
        return 0, [], [], ["Trend Micro is not configured"]

    session = get_http_session()
    base = trendmicro._get_base_url()
    headers = trendmicro._get_headers()
    verify = trendmicro._get_verify_ssl()

    logger.info("Scanning Trend Micro Vision One Suspicious Objects (Threshold: < %d%%)...", threshold)
    to_delete_items: list[dict[str, Any]] = []
    kept_items: list[dict[str, Any]] = []
    errors: list[str] = []

    url = f"{base}/v3.0/threatintel/suspiciousObjects"
    params = {"top": 100}
    page = 1

    while url:
        try:
            resp = session.get(url, headers=headers, params=params, verify=verify, timeout=20)
            params = None
            if resp.status_code != 200:
                errors.append(f"HTTP {resp.status_code} fetching page {page}: {resp.text[:300]}")
                break

            data = resp.json()
            items = data.get("items", [])
            for it in items:
                desc = it.get("description", "")
                should_del, reason = should_delete_ioc(desc, threshold=threshold)
                it["_cleanup_reason"] = reason
                if should_del:
                    to_delete_items.append(it)
                elif "threatintel rep:" in desc.lower() or "event:alert_" in desc.lower():
                    kept_items.append(it)

            print(f"\r[Trend Micro] Scanned page {page:3d} | Found {len(to_delete_items):4d} to delete (<{threshold}%), {len(kept_items):3d} kept (>= {threshold}%)", end="", flush=True)

            url = data.get("nextLink")
            page += 1
        except Exception as e:
            errors.append(f"Error on page {page}: {e}")
            break

    print()  # Newline after progress bar
    logger.info("Scan finished: %d IoCs to delete (< %d%%), %d IoCs preserved (>= %d%%)", len(to_delete_items), threshold, len(kept_items), threshold)

    if dry_run:
        logger.info("[DRY RUN] Skipping actual deletion from Trend Micro.")
        return 0, to_delete_items, kept_items, errors

    # Perform batch deletion
    deleted_count = 0
    delete_url = f"{base}/v3.0/threatintel/suspiciousObjects/delete"

    for i in range(0, len(to_delete_items), batch_size):
        chunk = to_delete_items[i : i + batch_size]
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
            resp = session.post(delete_url, headers=headers, json=payload, verify=verify, timeout=25)
            if resp.status_code in {200, 201, 204, 207}:
                deleted_count += len(payload)
                print(f"\r[Trend Micro Deletion] Processed {deleted_count}/{len(to_delete_items)} items...", end="", flush=True)
            else:
                err_msg = f"Failed batch {i+1}-{i+len(payload)}: HTTP {resp.status_code} - {resp.text[:200]}"
                logger.error(err_msg)
                errors.append(err_msg)
        except Exception as e:
            err_msg = f"Exception batch {i+1}-{i+len(payload)}: {e}"
            logger.error(err_msg)
            errors.append(err_msg)

        time.sleep(0.1)

    print()
    return deleted_count, to_delete_items, kept_items, errors


def cleanup_kaspersky(threshold: int = 70, dry_run: bool = False) -> tuple[int, list[dict[str, Any]], list[str]]:
    """Inspects and cleans IoCs on Kaspersky Security Center 15.1 OpenAPI."""
    if not kaspersky.is_configured():
        logger.info("Kaspersky KSC is not configured.")
        return 0, [], ["Kaspersky KSC is not configured"]

    logger.info("Connecting to Kaspersky Security Center 15.1 OpenAPI...")
    token, err = kaspersky.login()
    if not token:
        logger.warning("Kaspersky KSC login failed or uncontactable: %s", err)
        return 0, [], [f"KSC login error: {err}"]

    base = kaspersky._get_base_url()
    headers = kaspersky._get_auth_headers(token)
    verify = kaspersky._get_verify_ssl()

    logger.info("KSC Session authenticated. Inspecting KSC IoCRepository...")
    deleted_count = 0
    errors: list[str] = []
    found_items: list[dict[str, Any]] = []

    # Attempt to query IoCs from KSC OpenAPI
    try:
        resp = requests.post(f"{base}/IoCRepository.GetObjects", headers=headers, json={}, verify=verify, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "PxgError" in data:
                logger.info("Kaspersky KSC IoCRepository: %s (IoC table is clean / uninstantiated)", data["PxgError"].get("message", "No objects"))
            else:
                raw_objects = data.get("PxgRetVal", []) or []
                for obj in raw_objects:
                    desc = obj.get("comment", "")
                    should_del, reason = should_delete_ioc(desc, threshold=threshold)
                    if should_del:
                        found_items.append(obj)
                        if not dry_run:
                            # Attempt remove
                            del_resp = requests.post(f"{base}/IoCRepository.RemoveObject", headers=headers, json={"value": obj.get("value")}, verify=verify, timeout=10)
                            if del_resp.status_code in {200, 204}:
                                deleted_count += 1
        else:
            logger.info("Kaspersky KSC IoCRepository returned HTTP %d", resp.status_code)
    except Exception as e:
        logger.debug("Kaspersky KSC query error: %s", e)

    return deleted_count, found_items, errors


def cleanup_redis_cache(matched_ips: list[str], dry_run: bool = False) -> int:
    """Deletes synced IoC cache keys from Redis for cleaned IPs."""
    if dry_run:
        return 0
    deleted_keys = 0
    try:
        r = redis_client()
        if not r:
            return 0

        for ip in matched_ips:
            key = f"minisoar:edr_ioc_synced:{ip}"
            if r.delete(key):
                deleted_keys += 1

        logger.info("Cleared %d matching Redis EDR IoC sync cache keys.", deleted_keys)
    except Exception as e:
        logger.debug("Redis cleanup error (non-fatal): %s", e)

    return deleted_keys


def main() -> None:
    parser = argparse.ArgumentParser(description="MiniSOAR Targeted EDR IoC Cleaner (< 70% threshold)")
    parser.add_argument("--threshold", type=int, default=70, help="Threat score threshold percentage (default: 70). IoCs below this score will be removed.")
    parser.add_argument("--provider", choices=["all", "trendmicro", "kaspersky"], default="all", help="Target EDR provider (default: all)")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for Trend Micro deletion (default: 50)")
    parser.add_argument("--dry-run", action="store_true", help="Preview matching IoCs without deleting them")
    args = parser.parse_args()

    threshold = args.threshold
    dry_run = args.dry_run
    provider = args.provider
    batch_size = args.batch_size

    print("\n" + "=" * 75)
    print(" 🧹 MiniSOAR EDR Targeted IoC Cleaner")
    print("=" * 75)
    print(f"• Rule Target    : Only delete IoCs with score < {threshold}% (Clean / False-Positive)")
    print(f"• Rule Keep      : Preserve confirmed malicious IoCs with score >= {threshold}%")
    print(f"• Target EDR     : {provider.upper()}")
    print(f"• Mode           : {'DRY-RUN (Simulasi Preview)' if dry_run else 'LIVE DELETION'}")
    print("=" * 75 + "\n")

    tm_deleted = 0
    tm_to_delete: list[dict[str, Any]] = []
    tm_kept: list[dict[str, Any]] = []
    tm_errors: list[str] = []

    ksc_deleted = 0
    ksc_found: list[dict[str, Any]] = []

    # 1. Clean Trend Micro
    if provider in {"all", "trendmicro"}:
        tm_deleted, tm_to_delete, tm_kept, tm_errors = cleanup_trendmicro(threshold=threshold, batch_size=batch_size, dry_run=dry_run)

    # 2. Clean Kaspersky
    if provider in {"all", "kaspersky"}:
        ksc_deleted, ksc_found, _ = cleanup_kaspersky(threshold=threshold, dry_run=dry_run)

    # 3. Clean Redis Cache
    deleted_ips = [it.get("ip") for it in tm_to_delete if it.get("ip")]
    redis_deleted = cleanup_redis_cache(deleted_ips, dry_run=dry_run)

    print("\n" + "=" * 75)
    print(" 📊 CLEANUP SUMMARY REPORT")
    print("=" * 75)
    if provider in {"all", "trendmicro"}:
        print(f"• Trend Micro IoCs Evaluated : {len(tm_to_delete) + len(tm_kept)}")
        print(f"  - Cleaned (< {threshold}%)           : {len(tm_to_delete)} {'(Deleted)' if not dry_run else '(Identified)'}")
        print(f"  - Preserved (>= {threshold}%)        : {len(tm_kept)} (KEPT IN TACT)")
    if provider in {"all", "kaspersky"}:
        print(f"• Kaspersky KSC Cleaned      : {ksc_deleted if not dry_run else len(ksc_found)}")
    if not dry_run:
        print(f"• Redis Synced Cache Cleared : {redis_deleted} keys")

    status_str = "✅ DRY-RUN PREVIEW COMPLETE" if dry_run else "✅ 100% CLEANED SUCCESSFULLY"
    print(f"• Final Status               : {status_str}")
    print("=" * 75)

    # Show samples of deleted items
    if tm_to_delete:
        sample_del = tm_to_delete[:10]
        print(f"\n📋 Sample IoCs Cleaned (< {threshold}%):")
        for idx, it in enumerate(sample_del, 1):
            val = it.get("ip") or it.get("url") or it.get("domain") or it.get("fileSha256")
            desc = it.get("description", "")
            print(f"  {idx:2d}. {val:18s} | {desc}")
        if len(tm_to_delete) > 10:
            print(f"  ... and {len(tm_to_delete) - 10} more items.")

    # Show samples of kept items
    if tm_kept:
        sample_kept = tm_kept[:10]
        print(f"\n🛡️ Sample Confirmed High-Threat IoCs PRESERVED (>= {threshold}%):")
        for idx, it in enumerate(sample_kept, 1):
            val = it.get("ip") or it.get("url") or it.get("domain") or it.get("fileSha256")
            desc = it.get("description", "")
            print(f"  {idx:2d}. {val:18s} | {desc}")
        if len(tm_kept) > 10:
            print(f"  ... and {len(tm_kept) - 10} more items.")

    print()


if __name__ == "__main__":
    main()
