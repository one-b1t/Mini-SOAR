import csv
import logging
import os
import random
from pathlib import Path
from typing import Any

import requests

from ..config import load_env

logger = logging.getLogger(__name__)


def es_request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    load_env()
    hosts_str = os.getenv("ES_HOSTS", "") or os.getenv("ES_HOST", "http://127.0.0.1:9200")
    host = hosts_str.split(",")[0].strip()
    if not host:
        raise ValueError("Elasticsearch host is not configured.")
    url = f"{host.rstrip('/')}/{path.lstrip('/')}"
    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_verify = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
    es_timeout = int(os.getenv("ES_TIMEOUT", "6"))
    auth = (es_user, es_pass) if (es_user or es_pass) else None

    resp = requests.request(method=method, url=url, json=body, auth=auth, verify=es_verify, timeout=es_timeout)
    resp.raise_for_status()
    return resp.json()


def write_synthetic_dataset(csv_path: Path) -> int:
    headers = [
        "event_id",
        "detector_type",
        "severity",
        "reputation_score",
        "hit_count",
        "perimeter_vendor",
        "is_whitelisted",
        "source_ip",
        "destination_ip",
        "domain",
        "url_path",
        "source_port",
        "target_port",
        "label",
    ]

    detector_types = [
        "alert_webshell_immediate",
        "alert_webshell_name",
        "alert_webshell_heur",
        "alert_url_probe",
        "alert_gambling_slot",
        "alert_distributed_error",
    ]
    perimeters = ["imperva", "akamai", "paloalto", "none"]

    rows = []
    rng = random.Random(42)  # nosec B311 (Non-cryptographic PRNG for ML bootstrap simulation)
    for i in range(10000):
        detector = rng.choice(detector_types)
        perimeter = rng.choice(perimeters)
        is_whitelisted = 1 if rng.random() < 0.05 else 0

        if is_whitelisted == 1:
            reputation = rng.randint(0, 10)
            hit_count = rng.randint(1, 10)
            severity = "low"
            label = 0
        else:
            if detector == "alert_webshell_immediate":
                reputation = rng.randint(80, 100)
                hit_count = rng.randint(10, 150)
                severity = "high"
                label = 1 if rng.random() < 0.98 else 0
            elif detector in ["alert_webshell_name", "alert_webshell_heur"]:
                reputation = rng.randint(50, 95)
                hit_count = rng.randint(5, 80)
                severity = rng.choice(["high", "medium"])
                label = 1 if rng.random() < 0.85 else 0
            elif detector == "alert_gambling_slot":
                reputation = rng.randint(40, 90)
                hit_count = rng.randint(50, 1000)
                severity = "high"
                label = 1 if rng.random() < 0.90 else 0
            elif detector == "alert_distributed_error":
                reputation = rng.randint(10, 60)
                hit_count = rng.randint(100, 5000)
                severity = "medium"
                label = 0 if rng.random() < 0.80 else 1
            else:
                reputation = rng.randint(20, 85)
                hit_count = rng.randint(1, 50)
                severity = rng.choice(["medium", "low"])
                label = 1 if rng.random() < 0.40 else 0

        event_id = f"evt_{i:04d}_{rng.randint(1000, 9999)}"
        src_ip = f"{rng.randint(1,255)}.{rng.randint(1,255)}.{rng.randint(1,255)}.{rng.randint(1,255)}"
        dst_ip = f"10.0.{rng.randint(1,5)}.{rng.randint(1,255)}"
        domain = rng.choice(["api.target.com", "staging.target.com", "target.com", "internal.local"])
        url_path = rng.choice(["/login", "/api/v1/data", "/admin/config", "/wp-login.php", "/?id=1'"])
        src_port = rng.randint(1024, 65535)
        dst_port = rng.choice([80, 443, 8080])

        rows.append([
            event_id, detector, severity, reputation, hit_count, perimeter, is_whitelisted,
            src_ip, dst_ip, domain, url_path, src_port, dst_port, label
        ])

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    return len(rows)


def normalize_securesphere_detector(msg: str, policy: str) -> str:
    """Normalizes SecureSphere CEF message / policy to MiniSOAR detector type."""
    combined = f"{msg} {policy}".lower()
    if "sql" in combined or "sqli" in combined:
        return "alert_sqli"
    if "script" in combined or "xss" in combined:
        return "alert_xss"
    if "webshell" in combined or "shell" in combined:
        return "alert_webshell"
    if "traversal" in combined or "path" in combined:
        return "alert_dir_traversal"
    if "unauthorized method" in combined or "profile" in combined:
        return "alert_web_profile"
    if "correlation" in combined:
        return "alert_web_correlation"
    if "probe" in combined or "scan" in combined or "enumeration" in combined:
        return "alert_url_probe"
    return "alert_securesphere_waf"


def normalize_securesphere_severity(sev_val: Any) -> str:
    """Normalizes severity into low, medium, high."""
    s = str(sev_val).strip().lower()
    if s in {"high", "critical"} or s in {"7", "8", "9", "10"}:
        return "high"
    if s in {"low", "info", "informational"} or s in {"0", "1", "2", "3"}:
        return "low"
    return "medium"


def estimate_securesphere_reputation(severity: str, action: str) -> int:
    """Estimates reputation score (0-100) based on severity and enforcement action."""
    act_lower = action.lower()
    is_blocked = any(b in act_lower for b in ["block", "drop", "deny"])
    if is_blocked:
        return 90 if severity == "high" else 75 if severity == "medium" else 55
    return 35 if severity == "high" else 20 if severity == "medium" else 5


def extract_minisoar_samples(labels_prefix: str, events_prefix: str) -> list[list[Any]]:
    """Extracts joined event-label samples from MiniSOAR internal indices."""
    rows: list[list[Any]] = []
    try:
        labels_data = es_request("GET", f"{labels_prefix}-*/_search", body={"size": 10000})
        label_hits = labels_data.get("hits", {}).get("hits", [])
        if not label_hits:
            logger.info("No records found in MiniSOAR labels index (%s)", labels_prefix)
            return rows

        label_map: dict[str, int] = {}
        for hit in label_hits:
            src = hit.get("_source", {})
            eid = src.get("event_id")
            if not eid:
                continue
            label_str = str(src.get("label", "")).lower()
            label_map[eid] = 1 if "block" in label_str else 0

        event_ids = list(label_map.keys())
        chunk_size = 1000
        for i in range(0, len(event_ids), chunk_size):
            chunk = event_ids[i:i + chunk_size]
            try:
                event_data = es_request(
                    "GET",
                    f"{events_prefix}-*/_search",
                    body={"size": len(chunk), "query": {"terms": {"event_id": chunk}}}
                )
                for ehit in event_data.get("hits", {}).get("hits", []):
                    evt_src = ehit.get("_source", {})
                    eid = evt_src.get("event_id")
                    if not eid or eid not in label_map:
                        continue
                    rows.append([
                        eid,
                        evt_src.get("detector_type", "alert_generic"),
                        evt_src.get("severity", "medium"),
                        evt_src.get("alert", {}).get("reputation_score", 0) or evt_src.get("reputation", {}).get("score", 0),
                        evt_src.get("metrics", {}).get("hit_count", 1) or 1,
                        evt_src.get("perimeter", {}).get("vendor", "none"),
                        1 if evt_src.get("alert", {}).get("whitelisted") else 0,
                        evt_src.get("alert", {}).get("src_ip", "-"),
                        evt_src.get("alert", {}).get("dst_ip", "-"),
                        evt_src.get("alert", {}).get("server_name", "-"),
                        evt_src.get("alert", {}).get("url", "-"),
                        evt_src.get("alert", {}).get("src_port", 0),
                        evt_src.get("alert", {}).get("dst_port", 0),
                        label_map[eid],
                    ])
            except Exception as e:
                logger.warning("Error querying MiniSOAR event chunk: %s", e)
    except Exception as e:
        logger.warning("MiniSOAR index extraction encountered error: %s", e)
    return rows


def extract_securesphere_samples(
    index_pattern: str,
    max_samples: int = 10000,
    balance_ratio: float = 0.5,
) -> list[list[Any]]:
    """Extracts balanced ground-truth samples from Imperva SecureSphere WAF logs."""
    rows: list[list[Any]] = []
    target_block = max(1, int(max_samples * balance_ratio))
    target_allow = max(1, max_samples - target_block)

    # 1. Fetch Block samples
    try:
        q_block = {
            "size": min(target_block, 5000),
            "query": {
                "terms": {
                    "event.action": ["Block", "block", "Drop", "drop", "Deny", "deny"]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        res_block = es_request("POST", f"{index_pattern.lstrip('/')}/_search", body=q_block)
        for hit in res_block.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            sec_dict = src.get("imperva", {}).get("securesphere", {}) or {}
            event_dict = src.get("event", {}) or {}
            eid = str(event_dict.get("id") or sec_dict.get("event", {}).get("id") or hit.get("_id"))
            msg = str(src.get("message") or "")
            policy = str(sec_dict.get("policy", {}).get("name") or src.get("rule", {}).get("name") or "")
            detector = normalize_securesphere_detector(msg, policy)
            sev = normalize_securesphere_severity(sec_dict.get("severity") or event_dict.get("severity"))
            rep = estimate_securesphere_reputation(sev, "Block")
            src_ip = str(src.get("source", {}).get("ip") or "-")
            dst_ip = str(src.get("destination", {}).get("ip") or "-")
            domain = str(sec_dict.get("application", {}).get("name") or "-")
            url_path = str(sec_dict.get("violation", {}).get("description") or "-")[:120]
            src_port = int(src.get("source", {}).get("port") or 0)
            dst_port = int(src.get("destination", {}).get("port") or 80)

            rows.append([
                f"sec_{eid}", detector, sev, rep, 1, "imperva", 0,
                src_ip, dst_ip, domain, url_path, src_port, dst_port, 1
            ])
    except Exception as e:
        logger.warning("Failed to extract SecureSphere Block samples: %s", e)

    # 2. Fetch Allow/None samples
    try:
        q_allow = {
            "size": min(target_allow, 5000),
            "query": {
                "terms": {
                    "event.action": ["None", "none", "Alert", "alert", "Allow", "allow"]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        res_allow = es_request("POST", f"{index_pattern.lstrip('/')}/_search", body=q_allow)
        for hit in res_allow.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            sec_dict = src.get("imperva", {}).get("securesphere", {}) or {}
            event_dict = src.get("event", {}) or {}
            eid = str(event_dict.get("id") or sec_dict.get("event", {}).get("id") or hit.get("_id"))
            msg = str(src.get("message") or "")
            policy = str(sec_dict.get("policy", {}).get("name") or src.get("rule", {}).get("name") or "")
            detector = normalize_securesphere_detector(msg, policy)
            sev = normalize_securesphere_severity(sec_dict.get("severity") or event_dict.get("severity"))
            rep = estimate_securesphere_reputation(sev, "None")
            src_ip = str(src.get("source", {}).get("ip") or "-")
            dst_ip = str(src.get("destination", {}).get("ip") or "-")
            domain = str(sec_dict.get("application", {}).get("name") or "-")
            url_path = str(sec_dict.get("violation", {}).get("description") or "-")[:120]
            src_port = int(src.get("source", {}).get("port") or 0)
            dst_port = int(src.get("destination", {}).get("port") or 80)

            rows.append([
                f"sec_{eid}", detector, sev, rep, 1, "imperva", 0,
                src_ip, dst_ip, domain, url_path, src_port, dst_port, 0
            ])
    except Exception as e:
        logger.warning("Failed to extract SecureSphere Allow/None samples: %s", e)

    return rows


def export_dataset_from_es(csv_path: Path | None = None, fallback_synthetic: bool = True) -> tuple[bool, int, str]:
    """Extracts ground-truth security telemetry from both MiniSOAR and SecureSphere in Elasticsearch.

    Returns:
        (success: bool, sample_count: int, status_message: str)
    """
    load_env()
    root_dir = Path(__file__).resolve().parent.parent.parent
    target_path = csv_path or (root_dir / "dataset.csv")

    labels_prefix = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
    events_prefix = os.getenv("ES_EVENTS_INDEX_PREFIX", "minisoar-events")
    securesphere_pattern = os.getenv("ES_SECURESPHERE_INDEX_PATTERN", "logs-imperva.securesphere-*")
    securesphere_enabled = os.getenv("ES_SECURESPHERE_ENABLED", "true").lower() in {"1", "true", "yes"}
    max_securesphere = int(os.getenv("ES_SECURESPHERE_MAX_SAMPLES", "10000"))

    headers = [
        "event_id", "detector_type", "severity", "reputation_score", "hit_count",
        "perimeter_vendor", "is_whitelisted", "source_ip", "destination_ip",
        "domain", "url_path", "source_port", "target_port", "label"
    ]

    combined_rows: list[list[Any]] = []
    source_stats: list[str] = []

    try:
        # 1. MiniSOAR Internal Telemetry & Labels
        minisoar_rows = extract_minisoar_samples(labels_prefix, events_prefix)
        if minisoar_rows:
            combined_rows.extend(minisoar_rows)
            source_stats.append(f"MiniSOAR: {len(minisoar_rows):,}")

        # 2. SecureSphere WAF Telemetry & Ground-Truth
        if securesphere_enabled:
            sec_rows = extract_securesphere_samples(securesphere_pattern, max_samples=max_securesphere)
            if sec_rows:
                combined_rows.extend(sec_rows)
                source_stats.append(f"SecureSphere: {len(sec_rows):,}")

        if not combined_rows:
            if fallback_synthetic:
                count = write_synthetic_dataset(target_path)
                return True, count, f"Elasticsearch indices empty or unreachable; generated {count:,} bootstrap synthetic samples in {target_path.name}."
            return False, 0, "No data extracted from Elasticsearch indices."

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(combined_rows)

        msg = f"Successfully exported {len(combined_rows):,} samples ({', '.join(source_stats)}) into {target_path.name}"
        logger.info(msg)
        return True, len(combined_rows), msg

    except Exception as e:
        logger.warning("Elasticsearch export encountered error: %s", e)
        if fallback_synthetic:
            count = write_synthetic_dataset(target_path)
            return True, count, f"Elasticsearch export failed ({e}); generated {count:,} bootstrap samples in {target_path.name}."
        return False, 0, f"Elasticsearch export failed: {e}"


def main() -> None:
    ok, count, msg = export_dataset_from_es()
    print(f"[{'OK' if ok else 'FAIL'}] {msg}")


if __name__ == "__main__":
    main()


