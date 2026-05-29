from __future__ import annotations

import csv
import os
import random
from pathlib import Path

import requests
from dotenv import load_dotenv


def es_request(method: str, path: str, body=None):
    host = os.getenv("ES_HOSTS", "").split(",")[0].strip()
    if not host:
        raise ValueError("ES_HOSTS is not configured in .env.")
    url = f"{host.rstrip('/')}/{path}"
    es_user = os.getenv("ES_USER", "")
    es_pass = os.getenv("ES_PASS", "")
    es_verify = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
    auth = (es_user, es_pass) if es_user or es_pass else None
    resp = requests.request(method=method, url=url, json=body, auth=auth, verify=es_verify, timeout=5)
    resp.raise_for_status()
    return resp.json()


def write_synthetic_dataset(csv_path: Path):
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
    for i in range(10000):
        detector = random.choice(detector_types)
        perimeter = random.choice(perimeters)
        is_whitelisted = 1 if random.random() < 0.05 else 0

        if is_whitelisted == 1:
            reputation = random.randint(0, 10)
            hit_count = random.randint(1, 10)
            severity = "low"
            label = 0
        else:
            if detector == "alert_webshell_immediate":
                reputation = random.randint(80, 100)
                hit_count = random.randint(10, 150)
                severity = "high"
                label = 1 if random.random() < 0.98 else 0
            elif detector in ["alert_webshell_name", "alert_webshell_heur"]:
                reputation = random.randint(50, 95)
                hit_count = random.randint(5, 80)
                severity = random.choice(["high", "medium"])
                label = 1 if random.random() < 0.85 else 0
            elif detector == "alert_gambling_slot":
                reputation = random.randint(40, 90)
                hit_count = random.randint(50, 1000)
                severity = "high"
                label = 1 if random.random() < 0.90 else 0
            elif detector == "alert_distributed_error":
                reputation = random.randint(10, 60)
                hit_count = random.randint(100, 5000)
                severity = "medium"
                label = 0 if random.random() < 0.80 else 1
            else:
                reputation = random.randint(20, 85)
                hit_count = random.randint(1, 50)
                severity = random.choice(["medium", "low"])
                label = 1 if random.random() < 0.40 else 0

        event_id = f"evt_{i:04d}_{random.randint(1000, 9999)}"
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"10.0.{random.randint(1,5)}.{random.randint(1,255)}"
        domain = random.choice(["api.target.com", "staging.target.com", "target.com", "internal.local"])
        url_path = random.choice(["/login", "/api/v1/data", "/admin/config", "/wp-login.php", "/?id=1'"])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080])

        rows.append([
            event_id, detector, severity, reputation, hit_count, perimeter, is_whitelisted,
            src_ip, dst_ip, domain, url_path, src_port, dst_port, label
        ])

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def main():
    load_dotenv(Path.cwd() / ".env")
    csv_path = Path("dataset.csv")
    labels_prefix = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")
    events_prefix = os.getenv("ES_EVENTS_INDEX_PREFIX", "minisoar-events")

    try:
        labels_data = es_request("GET", f"{labels_prefix}-*/_search", body={"size": 10000})
        label_hits = labels_data.get("hits", {}).get("hits", [])

        if not label_hits:
            write_synthetic_dataset(csv_path)
            print("No labels found; synthetic dataset generated.")
            return

        label_map = {}
        for hit in label_hits:
            src = hit.get("_source", {})
            event_id = src.get("event_id")
            if not event_id:
                continue
            label_str = src.get("label", "").lower()
            label_map[event_id] = 1 if "block" in label_str else 0

        event_ids = list(label_map.keys())
        rows = []
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
                print(f"Error fetching chunk {i}: {e}")
                continue

        if not rows:
            write_synthetic_dataset(csv_path)
            print("No joined rows found; synthetic dataset generated.")
            return

        headers = [
            "event_id", "detector_type", "severity", "reputation_score", "hit_count", 
            "perimeter_vendor", "is_whitelisted", "source_ip", "destination_ip", 
            "domain", "url_path", "source_port", "target_port", "label"
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"Exported {len(rows)} rows to {csv_path}")

    except Exception as e:
        print(f"Could not retrieve data from Elasticsearch: {e}")
        write_synthetic_dataset(csv_path)
        print("Synthetic dataset generated.")


if __name__ == "__main__":
    main()
