import redis
import json
import datetime
import random
import time

def generate_mock_traffic(count=10):
    r = redis.StrictRedis(host='127.0.0.1', port=6379)
    
    alert_types = [
        ("alert_webshell_immediate", "high"),
        ("alert_url_major", "high"),
        ("alert_url_minor", "medium"),
        ("alert_gambling_slot", "high"),
        ("alert_webshell_name", "high"),
        ("alert_webshell_heur", "medium"),
        ("alert_url_probe", "medium"),
        ("alert_sqli_attack", "high"),
        ("alert_xss_attack", "medium"),
        ("alert_lfi_attempt", "high"),
        ("alert_rce_heur", "critical")
    ]
    
    ips = [
        "8.8.8.8",        # Clean Google DNS
        "1.1.1.1",        # Clean Cloudflare
        "141.98.11.20",   # Random IP 1
        "45.133.1.20",    # Random IP 2
        "185.220.101.14", # Tor Exit Node (High risk)
        "104.248.112.11", # Known Scanner
        "103.8.77.26",    # Whitelisted IP (from utils.py)
        "172.30.100.26",  # Bypassed IP (from .env)
        "10.0.5.55"       # Internal IP (Whitelist CIDR 10.0.0.0/8)
    ]
    
    servers = [
        "mock-target.com",
        "api.mock-target.com",
        "staging.mock-target.com",
        "internal-portal.local",
        "test-site.com"
    ]
    
    urls = [
        "/api/upload.php",
        "/admin/login",
        "/slot/gacor/login.php",
        "/shell.jsp",
        "/info.php",
        "/wp-login.php",
        "/index.php?id=1' OR '1'='1",
        "/?search=<script>alert(1)</script>",
        "/download.php?file=../../../../etc/passwd",
        "/api/v1/health"
    ]

    print(f"Mengirim {count} mock traffic ke Redis ('logstash_alert_queue')...")
    
    for i in range(count):
        alert_type, severity = random.choice(alert_types)
        src_ip = random.choice(ips)
        server_name = random.choice(servers)
        url = random.choice(urls)
        
        payload = {
            "alert": {
                "type": alert_type,
                "server_name": server_name,
                "src_ip": src_ip,
                "method": random.choice(["GET", "POST"]),
                "url": url,
                "status": str(random.choice([200, 403, 404, 500])),
                "severity": severity,
                "count": random.randint(1, 50)
            },
            "tags": [alert_type, "mock_test"],
            "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        
        r.lpush('logstash_alert_queue', json.dumps(payload))
        print(f"[{i+1}/{count}] Dikirim: {alert_type} dari {src_ip} ke {server_name}")
        time.sleep(1)  # Jeda 1 detik agar pengiriman tidak terlalu cepat dan notifikasi Telegram rapi

    print("\nSelesai! Silakan cek log daemon dan Telegram Anda.")

if __name__ == "__main__":
    generate_mock_traffic(30)
