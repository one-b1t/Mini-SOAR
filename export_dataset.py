import os
import json
import csv
import random
import requests
import urllib3
from pathlib import Path
from dotenv import load_dotenv

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment configurations
load_dotenv(Path(__file__).parent / ".env")

ES_HOST = os.getenv("ES_HOSTS", "").split(",")[0].strip()
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")
ES_VERIFY = os.getenv("ES_VERIFY", "true").lower() not in {"0", "false", "no"}
ES_EVENTS_PREFIX = os.getenv("ES_EVENTS_INDEX_PREFIX", "minisoar-events")
ES_LABELS_PREFIX = os.getenv("ES_LABELS_INDEX_PREFIX", "minisoar-labels")

CSV_PATH = Path("dataset.csv")

def es_request(method, path, body=None):
    if not ES_HOST:
        raise ValueError("ES_HOSTS is not configured in .env.")
    url = f"{ES_HOST.rstrip('/')}/{path}"
    auth = (ES_USER, ES_PASS) if ES_USER or ES_PASS else None
    resp = requests.request(
        method=method,
        url=url,
        json=body,
        auth=auth,
        verify=ES_VERIFY,
        timeout=5
    )
    resp.raise_for_status()
    return resp.json()

def write_synthetic_dataset():
    """Generates a synthetic dataset for testing/bootstrap purposes if Elasticsearch is offline."""
    print("Generating synthetic dataset (dataset.csv)...")
    headers = [
        "event_id", "detector_type", "severity", "reputation_score", 
        "hit_count", "perimeter_vendor", "is_whitelisted", "label"
    ]
    
    detector_types = [
        "alert_webshell_immediate", "alert_webshell_name", "alert_webshell_heur", 
        "alert_url_probe", "alert_gambling_slot", "alert_distributed_error"
    ]
    
    perimeters = ["imperva", "akamai", "paloalto", "none"]
    
    rows = []
    # Generate 500 samples
    for i in range(500):
        detector = random.choice(detector_types)
        perimeter = random.choice(perimeters)
        is_whitelisted = 1 if random.random() < 0.05 else 0  # 5% whitelist rate
        
        # Logic to make labels realistic based on features
        if is_whitelisted == 1:
            reputation = random.randint(0, 10)
            hit_count = random.randint(1, 10)
            severity = "low"
            label = 0  # Whitelisted IPs are always allowed/ignored (0)
        else:
            if detector == "alert_webshell_immediate":
                reputation = random.randint(80, 100)
                hit_count = random.randint(10, 150)
                severity = "high"
                label = 1 if random.random() < 0.98 else 0  # 98% blocked
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
                label = 0 if random.random() < 0.80 else 1  # Often ignored/allowed
            else:  # alert_url_probe
                reputation = random.randint(20, 85)
                hit_count = random.randint(1, 50)
                severity = random.choice(["medium", "low"])
                label = 1 if random.random() < 0.40 else 0  # 40% blocked
                
        event_id = f"evt_{i:04d}_{random.randint(1000, 9999)}"
        rows.append([
            event_id, detector, severity, reputation, 
            hit_count, perimeter, is_whitelisted, label
        ])
        
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"Successfully generated {len(rows)} rows in dataset.csv.")

def main():
    print("Checking connection to Elasticsearch...")
    try:
        info = es_request("GET", "")
        print(f"Connected to Elasticsearch: {info.get('cluster_name', 'cluster')}")
        
        # Real query: Retrieve all labels and matching events
        print(f"Fetching labels from indices: {ES_LABELS_PREFIX}-*")
        labels_data = es_request("GET", f"{ES_LABELS_PREFIX}-*/_search", body={"size": 10000})
        label_hits = labels_data.get("hits", {}).get("hits", [])
        
        if not label_hits:
            print("No labels found in Elasticsearch indices.")
            write_synthetic_dataset()
            return
            
        print(f"Found {len(label_hits)} label entries. Fetching associated events...")
        
        rows = []
        for hit in label_hits:
            src = hit.get("_source", {})
            event_id = src.get("event_id")
            label_str = src.get("label", "").lower()
            
            # Map action label to binary classification
            # 1 = block, 0 = allow/ignore
            label = 1 if "block" in label_str else 0
            
            # Look up matching event
            if event_id:
                try:
                    event_data = es_request("GET", f"{ES_EVENTS_PREFIX}-*/_search", body={
                        "size": 1,
                        "query": {"term": {"event_id": event_id}}
                    })
                    event_hits = event_data.get("hits", {}).get("hits", [])
                    if event_hits:
                        evt_src = event_hits[0].get("_source", {})
                        detector_type = evt_src.get("detector_type", "alert_generic")
                        severity = evt_src.get("severity", "medium")
                        rep_score = evt_src.get("alert", {}).get("reputation_score", 0) or evt_src.get("reputation", {}).get("score", 0)
                        hit_count = evt_src.get("metrics", {}).get("hit_count", 1) or 1
                        perimeter_vendor = evt_src.get("perimeter", {}).get("vendor", "none")
                        is_whitelisted = 1 if evt_src.get("alert", {}).get("whitelisted") else 0
                        
                        rows.append([
                            event_id, detector_type, severity, rep_score, 
                            hit_count, perimeter_vendor, is_whitelisted, label
                        ])
                except Exception as lookup_err:
                    print(f"Event ID {event_id} lookup error: {lookup_err}")
                    
        if not rows:
            print("Could not join labels with events in Elasticsearch.")
            write_synthetic_dataset()
            return
            
        headers = [
            "event_id", "detector_type", "severity", "reputation_score", 
            "hit_count", "perimeter_vendor", "is_whitelisted", "label"
        ]
        with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"Successfully exported {len(rows)} joined rows from Elasticsearch to dataset.csv.")
        
    except Exception as e:
        print(f"Could not retrieve data from Elasticsearch: {e}")
        write_synthetic_dataset()

if __name__ == "__main__":
    main()
