from __future__ import annotations

"""SecureSphere Cyber Attack Replay & ML Model Validation Engine for MiniSOAR.

Features:
1. Inspects and extracts real cyber attack traffic from Imperva SecureSphere WAF logs in Elasticsearch.
2. Categorizes attack patterns (SQLi, XSS, Webshell, Directory Traversal, Web Profile, HTTP Violations, etc.).
3. Reconstructs and mimics realistic SOAR alert events based on historical attack traffic.
4. Evaluates ML model detection rates, confidence scores, and false negatives per attack category.
5. Optionally injects mimicked attack payloads into Redis queue for end-to-end daemon & bot testing.
"""

import argparse
import json
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..config import load_env
from .export import (
    es_request,
    estimate_securesphere_reputation,
    normalize_securesphere_detector,
    normalize_securesphere_severity,
)
from .inference import load_model_artifact, predict_block

logger = logging.getLogger(__name__)


def categorize_attack(msg: str, policy: str, violation: str) -> str:
    """Classifies an attack log into a high-level cyber threat category."""
    text = f"{msg} {policy} {violation}".lower()
    if "sql" in text or "sqli" in text:
        return "SQL Injection (SQLi)"
    if "script" in text or "xss" in text:
        return "Cross-Site Scripting (XSS)"
    if "webshell" in text or "shell" in text or "php code injection" in text:
        return "Remote Code Execution / WebShell"
    if "traversal" in text or "directory traversal" in text or "path" in text:
        return "Directory / Path Traversal"
    if "unauthorized method" in text or "known url" in text or "profile" in text:
        return "Web Profile / Policy Violation"
    if "correlation" in text or "multiple" in text:
        return "Web Correlation Anomaly"
    if "leech" in text or "crawler" in text or "scan" in text or "probe" in text:
        return "Reconnaissance / Web Leech"
    if "illegal content length" in text or "malformed" in text or "header" in text:
        return "HTTP Protocol / Header Violation"
    return "Generic WAF Signature Attack"


def fetch_securesphere_attack_traffic(
    index_pattern: str | None = None,
    sample_size: int = 500,
    only_blocked: bool = True,
) -> list[dict[str, Any]]:
    """Fetches real historical cyber attack traffic recorded by Imperva SecureSphere in Elasticsearch."""
    load_env()
    pattern = index_pattern or os.getenv("ES_SECURESPHERE_INDEX_PATTERN", "logs-imperva.securesphere-*")

    actions = ["Block", "block", "Drop", "drop", "Deny", "deny"] if only_blocked else ["Block", "None", "alert"]
    query = {
        "size": min(sample_size, 5000),
        "query": {
            "terms": {"event.action": actions}
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        res = es_request("POST", f"{pattern.lstrip('/')}/_search", body=query)
        hits = res.get("hits", {}).get("hits", [])
        records = []
        for h in hits:
            src = h.get("_source", {})
            records.append(src)
        return records
    except Exception as e:
        logger.error("Failed to query SecureSphere attack traffic from Elasticsearch: %s", e)
        return []


def build_mimicked_soar_event(attack_src: dict[str, Any]) -> dict[str, Any]:
    """Transforms a raw SecureSphere Elasticsearch log into a full MiniSOAR alert payload."""
    sec = attack_src.get("imperva", {}).get("securesphere", {}) or {}
    event_dict = attack_src.get("event", {}) or {}

    eid = str(event_dict.get("id") or sec.get("event", {}).get("id") or "sim_sec_001")
    msg = str(attack_src.get("message") or "Web Threat")
    policy = str(sec.get("policy", {}).get("name") or attack_src.get("rule", {}).get("name") or "SecureSphere WAF")
    violation = str(sec.get("violation", {}).get("description") or "-")

    detector = normalize_securesphere_detector(msg, policy)
    severity = normalize_securesphere_severity(sec.get("severity") or event_dict.get("severity"))
    rep_score = estimate_securesphere_reputation(severity, str(event_dict.get("action") or "Block"))

    src_ip = str(attack_src.get("source", {}).get("ip") or "185.220.101.5")
    dst_ip = str(attack_src.get("destination", {}).get("ip") or "10.0.0.1")
    domain = str(sec.get("application", {}).get("name") or "target.internal")
    url_path = violation[:120] if violation != "-" else f"/attack-{detector}"
    category = categorize_attack(msg, policy, violation)

    soar_payload = {
        "@timestamp": attack_src.get("@timestamp") or attack_src.get("event", {}).get("ingested"),
        "event_id": f"sec_{eid}",
        "detector_type": detector,
        "attack_category": category,
        "severity": severity,
        "perimeter": {
            "vendor": "imperva",
            "device": "SecureSphere WAF",
            "policy": policy,
        },
        "alert": {
            "type": detector,
            "signature": msg,
            "violation_details": violation,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "server_name": domain,
            "url": url_path,
            "severity": severity,
            "count": 1,
            "reputation_score": rep_score,
            "whitelisted": False,
        },
        "metrics": {
            "hit_count": 1,
        },
        "original_action": str(event_dict.get("action") or "Block"),
    }
    return soar_payload


def validate_model_against_attacks(
    attack_logs: list[dict[str, Any]],
    model_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validates MiniSOAR ML model against historical SecureSphere cyber attacks.

    Computes:
    - Overall detection rate & block percentage
    - Breakdown by cyber attack category
    - Average confidence probability per category
    - List of false negatives (threats not flagged as block)
    """
    if not model_artifact:
        model_artifact = load_model_artifact()

    if not attack_logs:
        return {"error": "No attack logs provided for validation."}

    category_stats = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0, "prob_sum": 0.0})
    total_attacks = len(attack_logs)
    total_detected = 0
    missed_attacks = []

    for raw_log in attack_logs:
        event = build_mimicked_soar_event(raw_log)
        category = event["attack_category"]
        src_ip = event["alert"]["src_ip"]
        rep_score = event["alert"]["reputation_score"]
        rep_str = f"🛑 Malicious ({rep_score}/100)"

        pred, prob = predict_block(
            event=event,
            ip=src_ip,
            provider="imperva",
            whitelisted=False,
            rep_str=rep_str,
            model_artifact=model_artifact,
        )

        category_stats[category]["total"] += 1
        category_stats[category]["prob_sum"] += prob

        if pred == 1:
            category_stats[category]["detected"] += 1
            total_detected += 1
        else:
            category_stats[category]["missed"] += 1
            missed_attacks.append({
                "event_id": event["event_id"],
                "category": category,
                "detector": event["detector_type"],
                "src_ip": src_ip,
                "url": event["alert"]["url"][:60],
                "pred_probability": round(prob, 4),
            })

    # Summarize results
    category_summary = {}
    for cat, stats in sorted(category_stats.items()):
        cnt = stats["total"]
        det = stats["detected"]
        rate = (det / cnt) * 100.0 if cnt > 0 else 0.0
        avg_prob = (stats["prob_sum"] / cnt) if cnt > 0 else 0.0
        category_summary[cat] = {
            "total_tested": cnt,
            "detected_blocks": det,
            "detection_rate_pct": round(rate, 2),
            "avg_probability": round(avg_prob, 4),
        }

    overall_detection_rate = (total_detected / total_attacks) * 100.0 if total_attacks > 0 else 0.0

    return {
        "total_attacks_tested": total_attacks,
        "total_detected_blocks": total_detected,
        "total_missed_attacks": len(missed_attacks),
        "overall_detection_rate_pct": round(overall_detection_rate, 2),
        "decision_threshold_used": model_artifact.get("decision_threshold", 0.50) if model_artifact else 0.50,
        "model_version": model_artifact.get("model_version", "unknown") if model_artifact else "fallback_heuristic",
        "category_summary": category_summary,
        "missed_sample_details": missed_attacks[:5],
    }


def inject_attacks_to_redis(
    events: list[dict[str, Any]],
    redis_host: str = "127.0.0.1",
    redis_port: int = 6379,
    redis_key: str = "logstash_alert_queue",
    redis_password: str | None = None,
    limit: int = 10,
) -> int:
    """Injects mimicked attack payloads into Redis queue for end-to-end integration testing."""
    import redis

    r = redis.Redis(host=redis_host, port=redis_port, password=redis_password or None, socket_timeout=5)
    injected = 0
    for ev in events[:limit]:
        payload_str = json.dumps(ev)
        r.lpush(redis_key, payload_str)
        injected += 1
    return injected


def run_securesphere_validation_cli(sample_size: int = 500, inject_redis: bool = False, redis_limit: int = 5) -> None:
    """CLI runner to fetch attacks, run validation, print report, and optionally inject to Redis."""
    print("=" * 75)
    print(" [SEC] MiniSOAR - SecureSphere Cyber Attack Replay & Model Validation")
    print("=" * 75)
    print(f"Mengambil trafik serangan cyber dari SecureSphere di Elasticsearch (sample={sample_size:,})...")

    attack_logs = fetch_securesphere_attack_traffic(sample_size=sample_size, only_blocked=True)
    if not attack_logs:
        print("[ERROR] Tidak dapat mengambil trafik serangan dari SecureSphere. Periksa konfigurasi Elasticsearch.")
        return

    print(f"Berhasil menarik {len(attack_logs):,} rekaman serangan cyber riil dari Elasticsearch.\n")

    model_art = load_model_artifact()
    version = model_art.get("model_version", "active_model") if model_art else "heuristic"
    th = model_art.get("decision_threshold", 0.50) if model_art else 0.50
    print(f"Model yang diuji: {version} (Calibrated Threshold: {th:.2f})")
    print("Menjalankan simulasi peniruan serangan & evaluasi inferensi...")

    report = validate_model_against_attacks(attack_logs, model_artifact=model_art)

    print("\n" + "-" * 75)
    print(f"HASIL VALIDASI MODEL TERHADAP SERANGAN SECURESPHERE:")
    print("-" * 75)
    print(f"- Total Serangan Diuji   : {report['total_attacks_tested']:,}")
    print(f"- Serangan Terdeteksi    : {report['total_detected_blocks']:,} blokir")
    print(f"- Serangan Lolos (Miss)  : {report['total_missed_attacks']:,}")
    print(f"- Overall Detection Rate : {report['overall_detection_rate_pct']:.2f}%")
    print("-" * 75)

    print(f"{'Kategori Serangan Cyber':<36} | {'Total':<6} | {'Terdeteksi':<10} | {'Rate (%)':<8} | {'Avg Prob'}")
    print("-" * 75)
    for cat, data in report["category_summary"].items():
        print(f"{cat:<36} | {data['total_tested']:<6} | {data['detected_blocks']:<10} | {data['detection_rate_pct']:>7.2f}% | {data['avg_probability']:.4f}")
    print("-" * 75)

    if report["total_missed_attacks"] > 0:
        print(f"\n[WARN] Sampel Serangan yang Terlewat ({len(report['missed_sample_details'])} dari {report['total_missed_attacks']}):")
        for m in report["missed_sample_details"]:
            print(f"  - [{m['category']}] IP: {m['src_ip']} | URL: {m['url']} | Prob: {m['pred_probability']}")
    else:
        print("\n[PERFECT] Seluruh serangan cyber yang diuji berhasil dideteksi dan diblokir oleh Model ML!")

    if inject_redis:
        load_env()
        r_host = os.getenv("REDIS_HOST", "127.0.0.1")
        r_port = int(os.getenv("REDIS_PORT", "6379"))
        r_key = os.getenv("REDIS_KEY", "logstash_alert_queue")
        r_pass = os.getenv("REDIS_PASSWORD") or None

        events = [build_mimicked_soar_event(x) for x in attack_logs]
        print(f"\nMenginjeksikan {redis_limit} serangan tiruan ke Redis ({r_host}:{r_port} queue: {r_key})...")
        try:
            inj = inject_attacks_to_redis(events, redis_host=r_host, redis_port=r_port, redis_key=r_key, redis_password=r_pass, limit=redis_limit)
            print(f"[OK] Berhasil menginjeksi {inj} event serangan ke Redis queue untuk live testing!")
        except Exception as e:
            print(f"[ERROR] Gagal menginjeksi ke Redis: {e}")

    print("=" * 75)


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureSphere Cyber Attack Replay & Model Validation")
    parser.add_argument("--samples", type=int, default=500, help="Number of real attack samples to fetch from Elasticsearch (default: 500)")
    parser.add_argument("--inject-redis", action="store_true", help="Inject mimicked attacks into Redis queue")
    parser.add_argument("--redis-limit", type=int, default=5, help="Max attacks to inject into Redis (default: 5)")
    args = parser.parse_args()

    run_securesphere_validation_cli(sample_size=args.samples, inject_redis=args.inject_redis, redis_limit=args.redis_limit)


if __name__ == "__main__":
    main()
