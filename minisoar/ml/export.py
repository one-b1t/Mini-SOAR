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


def export_dataset_from_es(csv_path: Path | None = None, fallback_synthetic: bool = True) -> tuple[bool, int, str]:
    """Extracts ground-truth security decision labels and telemetry from Elasticsearch to produce dataset.csv.

    Returns:
        (success: bool, sample_count: int, status_message: str)
    """
    load_env()
    root_dir = Path(__file__).resolve().parent.parent.parent
    target_path = csv_path or (root_dir / "dataset.csv")

    labels_prefix = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
    events_prefix = os.getenv("ES_EVENTS_INDEX_PREFIX", "minisoar-events")

    headers = [
        "event_id", "detector_type", "severity", "reputation_score", "hit_count",
        "perimeter_vendor", "is_whitelisted", "source_ip", "destination_ip",
        "domain", "url_path", "source_port", "target_port", "label"
    ]

    try:
        labels_data = es_request("GET", f"{labels_prefix}-*/_search", body={"size": 10000})
        label_hits = labels_data.get("hits", {}).get("hits", [])

        if not label_hits:
            if fallback_synthetic:
                count = write_synthetic_dataset(target_path)
                return True, count, f"Elasticsearch labels are empty; generated {count:,} bootstrap synthetic samples in {target_path.name}."
            return False, 0, "No labels found in Elasticsearch index."

        label_map: dict[str, int] = {}
        for hit in label_hits:
            src = hit.get("_source", {})
            event_id = src.get("event_id")
            if not event_id:
                continue
            label_str = str(src.get("label", "")).lower()
            label_map[event_id] = 1 if "block" in label_str else 0

        event_ids = list(label_map.keys())
        rows: list[list[Any]] = []
        chunk_size = 1000

        for i in range(0, len(event_ids), chunk_size):
            chunk = event_ids[i:i + chunk_size]
            try:
                event_data = es_request(
                    "GET",
                    f"{events_prefix}-*/_search",
                    body={"size": len(chunk), "query": {"terms": {"event_id": chunk}}}
                )
                event_hits = event_data.get("hits", {}).get("hits", [])

                for ehit in event_hits:
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
                logger.warning("Error querying event chunk from Elasticsearch: %s", e)
                continue

        if not rows:
            if fallback_synthetic:
                count = write_synthetic_dataset(target_path)
                return True, count, f"Elasticsearch labels could not be matched to events; generated {count:,} bootstrap samples."
            return False, 0, "No joined event-label rows found in Elasticsearch."

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        msg = f"Successfully exported {len(rows):,} ground-truth samples from Elasticsearch into {target_path.name}"
        logger.info(msg)
        return True, len(rows), msg

    except Exception as e:
        logger.warning("Elasticsearch export failed: %s", e)
        if fallback_synthetic:
            count = write_synthetic_dataset(target_path)
            return True, count, f"Elasticsearch unreachable ({e}); generated {count:,} bootstrap samples in {target_path.name}."
        return False, 0, f"Elasticsearch export failed: {e}"


def main() -> None:
    ok, count, msg = export_dataset_from_es()
    print(f"[{'OK' if ok else 'FAIL'}] {msg}")


if __name__ == "__main__":
    main()

