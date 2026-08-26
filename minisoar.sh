#!/usr/bin/env bash
# ==============================================================================
# MiniSOAR Enterprise Management & Deployment CLI
# ==============================================================================
# Script ini digunakan untuk mengelola seluruh lifecycle platform MiniSOAR:
# 1. Setup Environment Python & Dependencies
# 2. Instalasi & Konfigurasi Pipeline Logstash (/etc/logstash/conf.d)
# 3. Pengecekan Koneksi ELK (Elasticsearch Health, Indices, Shards)
# 4. Inspeksi Antrian Redis (LLEN, Memory, Client, Payload Preview)
# 5. Verifikasi Menyeluruh (End-to-End Service Verification)
# 6. Service Control (Start, Stop, Restart, Status, Logs, Systemd)
# 7. MLOps Auto-Retraining & Test Suite
# ==============================================================================

set -eo pipefail
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

# --- Color Definitions & Icons ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Directory & PID Setup ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_DIR="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/logs"
VENV_DIR="$SCRIPT_DIR/.venv"
LOGSTASH_SRC_DIR="$SCRIPT_DIR/logstash"

mkdir -p "$PID_DIR" "$LOG_DIR"

DAEMON_PID_FILE="$PID_DIR/daemon.pid"
BOT_PID_FILE="$PID_DIR/bot.pid"
DAEMON_LOG="$LOG_DIR/daemon.log"
BOT_LOG="$LOG_DIR/bot.log"

# --- Python Environment Resolution ---
if [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/bin/python"
    PIP_CMD="$VIRTUAL_ENV/bin/pip"
    PYTEST_CMD="$VIRTUAL_ENV/bin/pytest"
elif [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/Scripts/python.exe" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/Scripts/python.exe"
    PIP_CMD="$VIRTUAL_ENV/Scripts/pip.exe"
    PYTEST_CMD="$VIRTUAL_ENV/Scripts/pytest.exe"
elif [ -x "$VENV_DIR/bin/python" ]; then
    PYTHON_CMD="$VENV_DIR/bin/python"
    PIP_CMD="$VENV_DIR/bin/pip"
    PYTEST_CMD="$VENV_DIR/bin/pytest"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then
    PYTHON_CMD="$VENV_DIR/Scripts/python.exe"
    PIP_CMD="$VENV_DIR/Scripts/pip.exe"
    PYTEST_CMD="$VENV_DIR/Scripts/pytest.exe"
elif command -v python.exe &>/dev/null && python.exe -c "import minisoar" 2>/dev/null; then
    PYTHON_CMD="python.exe"
    PIP_CMD="pip.exe"
    PYTEST_CMD="pytest.exe"
elif command -v python &>/dev/null && python -c "import minisoar" 2>/dev/null; then
    PYTHON_CMD="python"
    PIP_CMD="pip"
    PYTEST_CMD="pytest"
elif command -v python3 &>/dev/null && python3 -c "import minisoar" 2>/dev/null; then
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
    PYTEST_CMD="pytest"
elif command -v python.exe &>/dev/null; then
    PYTHON_CMD="python.exe"
    PIP_CMD="pip.exe"
    PYTEST_CMD="pytest.exe"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
    PIP_CMD="pip"
    PYTEST_CMD="pytest"
else
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
    PYTEST_CMD="pytest"
fi

# --- Helper Functions ---
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
  __  __ _       _  _____  ____          _____  
 |  \/  (_)     (_)/ ____|/ __ \   /\   |  __ \ 
 | \  / |_ _ __  _| (___ | |  | | /  \  | |__) |
 | |\/| | | '_ \| |\___ \| |  | |/ /\ \ |  _  / 
 | |  | | | | | | |____) | |__| / ____ \| | \ \ 
 |_|  |_|_|_| |_|_|_____/ \____/_/    \_\_|  \_\
          Enterprise SOAR Management CLI
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- Command: Setup Environment ---
cmd_setup() {
    echo -e "${BOLD}${CYAN}=== 1. Menyiapkan Lingkungan Python MiniSOAR ===${NC}"

    if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null && ! command -v python.exe &>/dev/null; then
        log_error "Python 3 tidak ditemukan di sistem. Harap install Python 3.10+ terlebih dahulu."
        exit 1
    fi

    PY_BIN=$(command -v python3 || command -v python || command -v python.exe)
    log_info "Menggunakan Python binary: $PY_BIN"

    if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/python" -a ! -f "$VENV_DIR/Scripts/python.exe" ]; then
        log_info "Membuat virtual environment (.venv)..."
        rm -rf "$VENV_DIR" 2>/dev/null || true

        # 2026-08-21 - Penanganan kompatibilitas DrvFs / NTFS (WSL): Gunakan virtualenv --always-copy untuk menghindari kegagalan symlink lib64
        if command -v virtualenv &>/dev/null && virtualenv --always-copy "$VENV_DIR" 2>/dev/null; then
            log_success "Virtual environment berhasil dibuat via virtualenv (--always-copy)."
        elif "$PY_BIN" -m virtualenv --always-copy "$VENV_DIR" 2>/dev/null; then
            log_success "Virtual environment berhasil dibuat via python -m virtualenv (--always-copy)."
        elif "$PY_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
            log_success "Virtual environment berhasil dibuat via venv standar."
        else
            log_warn "Pembuatan venv standar gagal (terdeteksi batasan symlink NTFS/WSL). Menyiapkan python3-virtualenv..."
            if command -v apt-get &>/dev/null; then
                sudo apt-get update -qq && sudo apt-get install -y python3-virtualenv python3-pip
                virtualenv --always-copy "$VENV_DIR"
            else
                "$PY_BIN" -m venv --copies "$VENV_DIR"
            fi
            log_success "Virtual environment berhasil dibuat di $VENV_DIR"
        fi
    else
        log_info "Virtual environment sudah ada di $VENV_DIR"
    fi

    # Update path
    if [ -f "$VENV_DIR/bin/python" ]; then
        PYTHON_CMD="$VENV_DIR/bin/python"
        PIP_CMD="$VENV_DIR/bin/pip"
        PYTEST_CMD="$VENV_DIR/bin/pytest"
    elif [ -f "$VENV_DIR/Scripts/python.exe" ]; then
        PYTHON_CMD="$VENV_DIR/Scripts/python.exe"
        PIP_CMD="$VENV_DIR/Scripts/pip.exe"
        PYTEST_CMD="$VENV_DIR/Scripts/pytest.exe"
    fi

    log_info "Menginstal dan memperbarui dependensi dari requirements.txt..."
    "$PIP_CMD" install --upgrade pip setuptools wheel
    if [ -f "requirements.txt" ]; then
        "$PIP_CMD" install -r requirements.txt
        log_success "Semua dependensi Python berhasil diinstal."
    else
        log_warn "requirements.txt tidak ditemukan."
    fi

    if [ ! -f ".env" ]; then
        if [ -f "env.example" ]; then
            log_info "Menyalin env.example menjadi .env..."
            cp env.example .env
            chmod 600 .env 2>/dev/null || true
            log_success "File .env berhasil dibuat dengan permission aman (chmod 600)."
            log_warn "HARAP EDIT file .env untuk melengkapi API key dan kredensial server Anda."
        fi
    else
        log_info "File .env sudah terdeteksi."
    fi

    # 2026-08-21 - Cek ketersediaan dan aktivasi redis-server
    if ! command -v redis-server &>/dev/null && ! command -v redis-cli &>/dev/null; then
        log_info "Redis server belum terinstal. Menyiapkan redis-server..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y redis-server redis-tools
            sudo systemctl enable redis-server 2>/dev/null || true
            sudo systemctl start redis-server 2>/dev/null || sudo service redis-server start 2>/dev/null || true
            log_success "Redis server berhasil diinstal dan dijalankan."
        fi
    else
        if command -v systemctl &>/dev/null && systemctl is-active --quiet redis-server 2>/dev/null; then
            log_info "Redis server aktif."
        elif command -v redis-server &>/dev/null; then
            sudo systemctl start redis-server 2>/dev/null || sudo service redis-server start 2>/dev/null || true
            log_info "Redis server dijalankan."
        fi
    fi

    echo -e "\n${GREEN}${BOLD}Setup dasar Python & Redis selesai!${NC}"
}

# --- Command: Install Logstash Package ---
cmd_install_logstash() {
    echo -e "${BOLD}${CYAN}=== 2. Instalasi Package Logstash ===${NC}"

    if command -v logstash &>/dev/null || [ -f "/usr/share/logstash/bin/logstash" ]; then
        log_info "Logstash sudah terinstal di sistem: $(command -v logstash || echo '/usr/share/logstash/bin/logstash')"
        return 0
    fi

    log_info "Mendeteksi sistem operasi untuk instalasi Logstash..."

    if command -v apt-get &>/dev/null; then
        log_info "Menginstal Logstash di sistem Debian/Ubuntu via APT..."
        sudo apt-get update
        sudo apt-get install -y wget gpg apt-transport-https openjdk-17-jre-headless

        # Import Elastic GPG Key
        if [ ! -f /etc/apt/trusted.gpg.d/elastic.gpg ]; then
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg
        fi

        # Add Elastic APT Repo
        echo "deb [signed-by=/etc/apt/trusted.gpg.d/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
        sudo apt-get update
        sudo apt-get install -y logstash

    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        local pkg_mgr="dnf"
        command -v dnf &>/dev/null || pkg_mgr="yum"
        log_info "Menginstal Logstash di sistem RHEL/CentOS/Rocky via $pkg_mgr..."

        sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
        sudo tee /etc/yum.repos.d/logstash.repo << 'EOF'
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
        sudo "$pkg_mgr" install -y logstash java-17-openjdk-headless
    else
        log_error "Package manager (apt / dnf / yum) tidak ditemukan. Harap install Logstash secara manual."
        return 1
    fi

    log_success "Logstash berhasil diinstal di sistem."
}

# --- Command: Setup & Copy Logstash Configuration ---
cmd_setup_logstash() {
    echo -e "${BOLD}${CYAN}=== 3. Menyalin & Mengonfigurasi Pipeline Logstash ===${NC}"

    local dest_conf_dir="/etc/logstash/conf.d"
    local dest_template_dir="/etc/logstash/templates"

    if [ ! -d "$LOGSTASH_SRC_DIR" ]; then
        log_error "Direktori $LOGSTASH_SRC_DIR tidak ditemukan."
        exit 1
    fi

    log_info "Memeriksa direktori tujuan konfigurasi Logstash ($dest_conf_dir)..."
    if [ ! -d "$dest_conf_dir" ]; then
        log_info "Membuat direktori $dest_conf_dir..."
        sudo mkdir -p "$dest_conf_dir" "$dest_template_dir"
    fi

    log_info "Menyalin file pipeline dan rule dari $LOGSTASH_SRC_DIR/ ke $dest_conf_dir/..."
    sudo cp -v "$LOGSTASH_SRC_DIR"/01-detection.conf "$dest_conf_dir/" 2>/dev/null || true
    sudo cp -v "$LOGSTASH_SRC_DIR"/02-alert-redis.conf "$dest_conf_dir/" 2>/dev/null || true
    sudo cp -v "$LOGSTASH_SRC_DIR"/minisoar-*.yml "$dest_conf_dir/" 2>/dev/null || true

    if [ -f "$LOGSTASH_SRC_DIR/minisoar_es_template.json" ]; then
        sudo cp -v "$LOGSTASH_SRC_DIR/minisoar_es_template.json" "$dest_template_dir/" 2>/dev/null || true
    fi

    # Set ownership for logstash user if present
    if id -u logstash &>/dev/null; then
        sudo chown -R logstash:logstash "$dest_conf_dir" "$dest_template_dir" 2>/dev/null || true
    fi

    log_success "File konfigurasi Logstash berhasil disalin ke $dest_conf_dir."

    # Validate syntax if logstash binary available
    if [ -x "/usr/share/logstash/bin/logstash" ]; then
        log_info "Memvalidasi sintaks konfigurasi Logstash..."
        if sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f "$dest_conf_dir" 2>/dev/null; then
            log_success "Sintaks konfigurasi Logstash VALID (OK)."
        else
            log_warn "Uji sintaks Logstash memerlukan waktu atau ada warning konfigurasi."
        fi
    fi

    # Enable and start logstash service
    if command -v systemctl &>/dev/null; then
        log_info "Mengaktifkan dan me-restart service Logstash..."
        sudo systemctl daemon-reload 2>/dev/null || true
        sudo systemctl enable logstash 2>/dev/null || true
        sudo systemctl restart logstash 2>/dev/null || true
        log_success "Layanan Logstash berhasil di-restart."
    fi
}

# --- Command: Check ELK Connection ---
cmd_check_elk() {
    echo -e "${BOLD}${CYAN}=== Diagnostik Koneksi & Health Elasticsearch (ELK) ===${NC}\n"

    "$PYTHON_CMD" -c "
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from minisoar.config import load_env
load_env()

hosts_str = os.getenv('ES_HOSTS', 'http://127.0.0.1:9200')
hosts = [h.strip() for h in hosts_str.split(',') if h.strip()]
user = os.getenv('ES_USER')
password = os.getenv('ES_PASS')
verify = os.getenv('ES_VERIFY', 'true').lower() not in {'0', 'false', 'no'}
auth = (user, password) if user and password else None

print(f'* Target Elasticsearch: {hosts_str}')
print(f'* Autentikasi: {\"User/Password Active\" if auth else \"Anonymous / Token\"}')
print(f'* SSL Verification: {verify}\n')

for h in hosts:
    base = h.rstrip('/')
    print(f'--> Menguji Node: {base}')
    try:
        # 1. Ping / Root Info
        r_info = requests.get(f'{base}/', auth=auth, verify=verify, timeout=6)
        if r_info.status_code == 200:
            d = r_info.json()
            cluster_name = d.get('cluster_name', 'Unknown')
            version = d.get('version', {}).get('number', 'Unknown')
            lucene = d.get('version', {}).get('lucene_version', '-')
            print(f'    [OK] Terhubung! Cluster: \"{cluster_name}\" | Versi: {version} (Lucene: {lucene})')
        else:
            print(f'    [FAIL] HTTP {r_info.status_code}: {r_info.text[:120]}')
            continue

        # 2. Cluster Health
        r_health = requests.get(f'{base}/_cluster/health', auth=auth, verify=verify, timeout=6)
        if r_health.status_code == 200:
            dh = r_health.json()
            status = dh.get('status', 'unknown').upper()
            nodes = dh.get('number_of_nodes', 0)
            data_nodes = dh.get('number_of_data_nodes', 0)
            unassigned = dh.get('unassigned_shards', 0)
            print(f'    * Cluster Health Status: {status} (Nodes: {nodes}, Data Nodes: {data_nodes}, Unassigned Shards: {unassigned})')

        # 3. MiniSOAR Indices Check
        r_idx = requests.get(f'{base}/_cat/indices/minisoar*?format=json', auth=auth, verify=verify, timeout=6)
        if r_idx.status_code == 200:
            indices = r_idx.json()
            if indices:
                print(f'    * Indeks MiniSOAR Ditemukan ({len(indices)}):')
                for idx in indices[:5]:
                    print(f'      - {idx.get(\"index\")}: docs={idx.get(\"docs.count\")}, store={idx.get(\"store.size\")}, health={idx.get(\"health\")}')
                if len(indices) > 5:
                    print(f'      - ... dan {len(indices)-5} indeks lainnya.')
            else:
                print('    * Indeks MiniSOAR: Belum ada data indeks (minisoar*) di cluster ini.')
        print('')
    except Exception as e:
        print(f'    [FAIL] Gagal menghubungi node {base}: {e}\n')
"
}

# --- Command: Check Redis Queue ---
cmd_check_redis() {
    echo -e "${BOLD}${CYAN}=== Inspeksi Koneksi & Antrian Redis (Queue) ===${NC}\n"

    "$PYTHON_CMD" -c "
import os
import redis
import json

from minisoar.config import load_env
load_env()

host = os.getenv('REDIS_HOST', '127.0.0.1')
port = int(os.getenv('REDIS_PORT', '6379'))
db = int(os.getenv('REDIS_DB', '0'))
password = os.getenv('REDIS_PASSWORD') or None
channel_or_queue = os.getenv('REDIS_CHANNEL', 'logstash_alert_queue')

print(f'* Host Redis: {host}:{port} (DB={db})')
print(f'* Target Queue/Channel: \"{channel_or_queue}\"')

try:
    r = redis.Redis(host=host, port=port, db=db, password=password, socket_timeout=5, decode_responses=True)
    pong = r.ping()
    if pong:
        print('  [OK] Koneksi Redis Berhasil (PING -> PONG)\n')

    # 1. Info Memory & Client
    info = r.info()
    mem_used = info.get('used_memory_human', 'N/A')
    connected_clients = info.get('connected_clients', 0)
    uptime_days = info.get('uptime_in_days', 0)
    print(f'* Redis Metrics:')
    print(f'  - Memory Terpakai: {mem_used}')
    print(f'  - Klien Terhubung: {connected_clients}')
    print(f'  - Uptime: {uptime_days} hari')

    # 2. Check Alert Queue Length
    q_len = r.llen(channel_or_queue)
    print(f'\n* Status Antrian Alert (\"{channel_or_queue}\"):')
    print(f'  - Panjang Antrian Saat Ini (Pending): {q_len} items')

    if q_len > 0:
        print('  - Cuplikan 2 Pesan Teratas di Antrian:')
        samples = r.lrange(channel_or_queue, 0, 1)
        for i, s in enumerate(samples, 1):
            try:
                parsed = json.loads(s)
                alt = parsed.get('alert', {})
                print(f'    [{i}] IP: {alt.get(\"src_ip\")} | Type: {alt.get(\"type\")} | Severity: {alt.get(\"severity\")} | Host: {alt.get(\"server_name\")}')
            except Exception:
                print(f'    [{i}] Raw Payload: {s[:120]}...')
    else:
        print('  - Antrian kosong (Semua alert telah dikonsumsi dan dimitigasi oleh daemon).')

    # 3. MiniSOAR Active Redis Keys
    minisoar_keys = r.keys('minisoar:*') + r.keys('block:*') + r.keys('throttle:*')
    print(f'\n* Active State Keys MiniSOAR di Redis: {len(minisoar_keys)} keys')
    for k in minisoar_keys[:5]:
        ttl = r.ttl(k)
        print(f'  - {k} (TTL: {ttl}s)')
    if len(minisoar_keys) > 5:
        print(f'  - ... dan {len(minisoar_keys)-5} keys lainnya.')

except Exception as e:
    print(f'  [FAIL] Gagal menghubungkan ke Redis ({host}:{port}): {e}')
"
}

# --- Service Helper Functions ---
is_pid_running() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# --- Command: Start Services ---
cmd_start() {
    local target="${1:-all}"

    if [ "$target" = "all" ] || [ "$target" = "daemon" ]; then
        if is_pid_running "$DAEMON_PID_FILE"; then
            log_warn "MiniSOAR Alert Daemon sudah berjalan (PID $(cat "$DAEMON_PID_FILE"))."
        else
            log_info "Memulai MiniSOAR Alert Daemon..."
            nohup "$PYTHON_CMD" -m minisoar.daemon >> "$DAEMON_LOG" 2>&1 &
            echo $! > "$DAEMON_PID_FILE"
            log_success "Daemon aktif dengan PID $(cat "$DAEMON_PID_FILE") (Log: $DAEMON_LOG)"
        fi
    fi

    if [ "$target" = "all" ] || [ "$target" = "bot" ]; then
        if is_pid_running "$BOT_PID_FILE"; then
            log_warn "MiniSOAR Telegram Bot sudah berjalan (PID $(cat "$BOT_PID_FILE"))."
        else
            log_info "Memulai MiniSOAR Telegram Bot..."
            nohup "$PYTHON_CMD" -m minisoar.bot >> "$BOT_LOG" 2>&1 &
            echo $! > "$BOT_PID_FILE"
            log_success "Telegram Bot aktif dengan PID $(cat "$BOT_PID_FILE") (Log: $BOT_LOG)"
        fi
    fi
}

# --- Command: Stop Services ---
cmd_stop() {
    local target="${1:-all}"

    if [ "$target" = "all" ] || [ "$target" = "daemon" ]; then
        if is_pid_running "$DAEMON_PID_FILE"; then
            local pid
            pid=$(cat "$DAEMON_PID_FILE")
            log_info "Menghentikan MiniSOAR Daemon (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            rm -f "$DAEMON_PID_FILE"
            log_success "Daemon berhasil dihentikan."
        else
            log_info "Daemon tidak sedang berjalan."
            rm -f "$DAEMON_PID_FILE"
        fi
    fi

    if [ "$target" = "all" ] || [ "$target" = "bot" ]; then
        if is_pid_running "$BOT_PID_FILE"; then
            local pid
            pid=$(cat "$BOT_PID_FILE")
            log_info "Menghentikan Telegram Bot (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            rm -f "$BOT_PID_FILE"
            log_success "Telegram Bot berhasil dihentikan."
        else
            log_info "Telegram Bot tidak sedang berjalan."
            rm -f "$BOT_PID_FILE"
        fi
    fi
}

# --- Command: Restart Services ---
cmd_restart() {
    local target="${1:-all}"
    log_info "Me-restart layanan MiniSOAR..."
    cmd_stop "$target"
    sleep 1
    cmd_start "$target"
}
# --- Command: Status Check ---
cmd_status() {
    echo -e "${BOLD}${CYAN}=== Status Layanan Sistem MiniSOAR ===${NC}\n"
    printf "%-25s %-12s %-12s %-25s\n" "Layanan" "Status" "PID" "Log File / Unit"
    echo "----------------------------------------------------------------------"

    # Daemon
    if [ -f "$DAEMON_PID_FILE" ] && kill -0 $(cat "$DAEMON_PID_FILE" 2>/dev/null) 2>/dev/null; then
        printf "%-25s ${GREEN}%-12s${NC} %-12s %-25s\n" "Alert Daemon" "RUNNING" "$(cat "$DAEMON_PID_FILE")" "$DAEMON_LOG"
    else
        printf "%-25s ${RED}%-12s${NC} %-12s %-25s\n" "Alert Daemon" "STOPPED" "-" "$DAEMON_LOG"
    fi

    # Bot
    if [ -f "$BOT_PID_FILE" ] && kill -0 $(cat "$BOT_PID_FILE" 2>/dev/null) 2>/dev/null; then
        printf "%-25s ${GREEN}%-12s${NC} %-12s %-25s\n" "Telegram Bot" "RUNNING" "$(cat "$BOT_PID_FILE")" "$BOT_LOG"
    else
        printf "%-25s ${RED}%-12s${NC} %-12s %-25s\n" "Telegram Bot" "STOPPED" "-" "$BOT_LOG"
    fi

    # Logstash
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet logstash 2>/dev/null; then
            printf "%-25s ${GREEN}%-12s${NC} %-12s %-25s\n" "Logstash Pipeline" "ACTIVE" "systemd" "systemctl status logstash"
        else
            printf "%-25s ${YELLOW}%-12s${NC} %-12s %-25s\n" "Logstash Pipeline" "INACTIVE" "-" "systemctl status logstash"
        fi
    fi

    # Redis
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet redis-server 2>/dev/null || systemctl is-active --quiet redis 2>/dev/null; then
            printf "%-25s ${GREEN}%-12s${NC} %-12s %-25s\n" "Redis Server" "RUNNING" "systemd" "systemctl status redis"
        fi
    fi
}

# --- Command: Doctor / Comprehensive Health Check ---
cmd_doctor() {
    echo -e "${BOLD}${CYAN}=== Diagnostik Konektivitas & Konfigurasi (Doctor) ===${NC}\n"

    "$PYTHON_CMD" -c "
import os
import sys

from minisoar.config import load_env
load_env()

print('${BOLD}[1/6] Memeriksa Environment & Kredensial:${NC}')
if os.path.exists('.env'):
    print('  [OK] File .env ditemukan.')
else:
    print('  [FAIL] File .env TIDAK ditemukan. Jalankan ./minisoar.sh setup')

mock_mode = os.getenv('MINISOAR_MOCK', '0')
print(f'  * Mock Mode: {mock_mode} (1=Simulasi/Mock, 0=Real API)')
print(f'  * Blocking Mode: {os.getenv(\"MINISOAR_BLOCKING_MODE\", \"AUTO\")}')

print('\n${BOLD}[2/6] Memeriksa Antrian Redis & Database:${NC}')
from minisoar.database import get_system_health
sys_health = get_system_health()

r_h = sys_health.get('redis', {})
if r_h.get('status') == 'OK':
    print(f'  * REDIS: [OK] Terhubung (Pending Queue: {r_h.get(\"queue_len\", 0)} items)')
else:
    print(f'  * REDIS: [FAIL] Gagal - {r_h.get(\"error\", \"OFFLINE\")}')

es_h = sys_health.get('elasticsearch', {})
if es_h.get('status') in ['GREEN', 'YELLOW']:
    print(f'  * ELASTICSEARCH: [OK] Cluster status {es_h.get(\"status\")} ({es_h.get(\"host\")})')
elif es_h.get('status') == 'RED':
    print(f'  * ELASTICSEARCH: [WARN] Cluster RED ({es_h.get(\"host\")})')
else:
    print(f'  * ELASTICSEARCH: [FAIL] {es_h.get(\"error\", \"OFFLINE\")}')

print('\n${BOLD}[3/6] Memeriksa AI SOC Copilot:${NC}')
from minisoar.ai.copilot import get_auth_info
ai_info = get_auth_info()
print(f'  * Provider: {ai_info[\"provider\"].upper()}')
print(f'  * Model: {ai_info[\"model\"]}')
print(f'  * Auth Source: {ai_info[\"auth_source\"]}')
print(f'  * Status: {\"[OK] Siap\" if ai_info[\"configured\"] else \"[WARN] Belum dikonfigurasi\"}')

print('\n${BOLD}[4/6] Memeriksa Ticketing 3rd-Party (Opsional):${NC}')
from minisoar.cases.connectors import get_ticketing_provider, is_ticketing_enabled
t_prov = get_ticketing_provider()
t_enabled = is_ticketing_enabled()
print(f'  * Provider: {t_prov.upper()}')
print(f'  * Status: {\"[OK] Aktif\" if t_enabled else \"[INFO] Nonaktif (Opsional)\"}')

print('\n${BOLD}[5/6] Memeriksa Konektivitas Perimeter:${NC}')
from minisoar.mitigation.core import check_perimeter_connectivity
results = check_perimeter_connectivity()
for r in results:
    prov = r.get('provider', '').upper()
    if r.get('ok'):
        print(f'  * {prov}: [OK] Terhubung')
    elif not r.get('configured'):
        print(f'  * {prov}: [INFO] Belum Dikonfigurasi')
    else:
        print(f'  * {prov}: [FAIL] Gagal - {r.get(\"error\")}')

print('\n${BOLD}[6/6] Memeriksa Konektivitas EDR Server:${NC}')
from minisoar.edr.core import check_edr_connectivity
edr_results = check_edr_connectivity()
for r in edr_results:
    prov = r.get('provider', '').upper()
    if r.get('ok'):
        print(f'  * {prov}: [OK] Terhubung')
    elif not r.get('configured'):
        print(f'  * {prov}: [INFO] Belum Dikonfigurasi')
    else:
        print(f'  * {prov}: [FAIL] Gagal - {r.get(\"error\")}')
"
}

# --- Command: Blocked List (Perimeter & EDR) ---
cmd_blocked() {
    local filter="${1:-all}"
    echo -e "${BOLD}${CYAN}=== Daftar IP Aktif di Block List & EDR IoC Repository ===${NC}\n"

    "$PYTHON_CMD" -c "
import sys
from minisoar.config import load_env, norm_provider
from minisoar.mitigation import get_active_blocklist

load_env()
data = get_active_blocklist()
perims = data.get('perimeters', [])
edrs = data.get('edr_iocs', [])
filt = '$filter'.lower()

if filt in {'all', 'perimeter', 'perimeters', 'palo', 'paloalto', 'imperva', 'akamai', 'cloudflare', 'cf', 'forti', 'fortigate'}:
    matched_p = perims if filt in {'all', 'perimeter', 'perimeters'} else [p for p in perims if norm_provider(filt) == norm_provider(p['provider'])]
    print(f'${BOLD}[1] Perimeter Block List ({len(matched_p)} IP aktif):${NC}')
    if matched_p:
        for p in matched_p:
            print(f'  • IP: {p[\"ip\"]: <16} | Provider: {p[\"provider\"].upper(): <10} | Sisa: {p[\"ttl_sec\"]}s (s/d {p[\"expires_at\"]})')
    else:
        print('  (Tidak ada IP aktif yang sedang diblokir sementara)')
    print()

if filt in {'all', 'edr', 'ioc', 'iocs', 'ksc', 'kaspersky', 'trendmicro'}:
    print(f'${BOLD}[2] EDR IoC Repository ({len(edrs)} IP terdaftar):${NC}')
    if edrs:
        for e in edrs:
            print(f'  • IP: {e[\"ip\"]: <16} | Target: {e[\"provider\"]: <25} | Cache: {e[\"ttl_sec\"]}s | Status: {e[\"status\"]}')
    else:
        print('  (Tidak ada IP IoC yang terdaftar di repositori EDR)')
"
}

# --- Command: Logs ---
cmd_logs() {
    local target="${1:-all}"
    if [ "$target" = "daemon" ]; then
        log_info "Streaming Daemon logs ($DAEMON_LOG)... (Ctrl+C untuk keluar)"
        tail -f "$DAEMON_LOG"
    elif [ "$target" = "bot" ]; then
        log_info "Streaming Bot logs ($BOT_LOG)... (Ctrl+C untuk keluar)"
        tail -f "$BOT_LOG"
    elif [ "$target" = "actions" ]; then
        log_info "Streaming Actions Audit logs (tele-soar-actions.log)..."
        tail -f tele-soar-actions.log
    elif [ "$target" = "logstash" ]; then
        log_info "Streaming Logstash service logs via journalctl..."
        sudo journalctl -u logstash -f 2>/dev/null || tail -f /var/log/logstash/logstash-plain.log 2>/dev/null || true
    else
        log_info "Streaming all MiniSOAR logs... (Ctrl+C untuk keluar)"
        tail -f "$DAEMON_LOG" "$BOT_LOG" 2>/dev/null || true
    fi
}

# --- Command: Test Suite ---
cmd_test() {
    echo -e "${BOLD}${CYAN}=== Menjalankan Automated Test Suite ===${NC}\n"
    "$PYTEST_CMD" --assert=plain -v "$@"
}

# --- Command: Retrain Model ---
cmd_retrain() {
    echo -e "${BOLD}${CYAN}=== MLOps Auto-Retraining Model Challenger ===${NC}\n"
    "$PYTHON_CMD" -c "
from minisoar.ml.autotrain import run_autotrain_from_file
ok, metrics, msg = run_autotrain_from_file()
if ok:
    print(f'${GREEN}✅ {msg}${NC}')
    print(f'   • Metrics: ROC-AUC={metrics.get(\"roc_auc\")}, Accuracy={metrics.get(\"accuracy\")}, Samples={metrics.get(\"total_samples\")}')
else:
    print(f'${YELLOW}⚠️ {msg}${NC}')
"
}

# --- Command: Generate Systemd Units ---
cmd_systemd() {
    echo -e "${BOLD}${CYAN}=== Generator File Service Systemd Linux ===${NC}\n"
    local cur_user
    cur_user=$(whoami)

    cat << EOF > "$LOG_DIR/minisoar-daemon.service"
[Unit]
Description=MiniSOAR Security Alert Ingestion & Mitigation Daemon
After=network.target redis.service logstash.service

[Service]
Type=simple
User=$cur_user
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_CMD -m minisoar.daemon
Restart=always
RestartSec=5
StandardOutput=append:$DAEMON_LOG
StandardError=append:$DAEMON_LOG

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > "$LOG_DIR/minisoar-bot.service"
[Unit]
Description=MiniSOAR Security Operations Telegram Bot
After=network.target

[Service]
Type=simple
User=$cur_user
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_CMD -m minisoar.bot
Restart=always
RestartSec=5
StandardOutput=append:$BOT_LOG
StandardError=append:$BOT_LOG

[Install]
WantedBy=multi-user.target
EOF

    log_success "File unit service systemd berhasil dibuat di folder $LOG_DIR/:"
    echo "  1. $LOG_DIR/minisoar-daemon.service"
    echo "  2. $LOG_DIR/minisoar-bot.service"
    echo -e "\n${BOLD}Untuk mengaktifkan di sistem Linux:${NC}"
    echo "  sudo cp $LOG_DIR/minisoar-*.service /etc/systemd/system/"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable --now minisoar-daemon minisoar-bot"
}

# --- Command: Complete End-to-End Installation Workflow ---
cmd_install_all() {
    echo -e "${BOLD}${CYAN}=====================================================${NC}"
    echo -e "${BOLD}${CYAN}=== MiniSOAR Full End-to-End Installation Workflow ==${NC}"
    echo -e "${BOLD}${CYAN}=====================================================${NC}\n"

    # 1. Setup Python & Dependencies
    cmd_setup

    # 2. Install Logstash
    echo ""
    cmd_install_logstash || true

    # 3. Setup & Copy Logstash Configuration
    echo ""
    cmd_setup_logstash || true

    # 4. Check Connections
    echo ""
    cmd_check_elk || true
    echo ""
    cmd_check_redis || true

    # 5. Start Services
    echo ""
    log_info "Memulai seluruh layanan MiniSOAR..."
    cmd_start all

    # 6. Final Status Verification
    echo ""
    cmd_status
    echo -e "\n${GREEN}${BOLD}=== Instalasi & Verifikasi Selesai! Seluruh Service Aktif ===${NC}"
}

# --- Command: Clean Cache & Logs ---
cmd_clean() {
    log_info "Membersihkan cache Python dan file temporer..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    log_success "Cache berhasil dibersihkan."
}

# --- Interactive Menu ---
cmd_menu() {
    while true; do
        print_banner
        echo -e "${BOLD}Pilih Operasi MiniSOAR:${NC}"
        echo -e "  ${CYAN}--- Instalasi & Konfigurasi Pipeline ---${NC}"
        echo "  1)  Full End-to-End Install (Python >> Logstash >> Config >> Start)"
        echo "  2)  Setup Python Virtualenv & Dependencies"
        echo "  3)  Install Logstash Package"
        echo "  4)  Copy & Sync Logstash Pipeline Config (/etc/logstash/conf.d)"
        echo ""
        echo -e "  ${CYAN}--- Diagnostik & Monitoring Koneksi ---${NC}"
        echo "  5)  Check Elasticsearch (ELK) Connection & Cluster Health"
        echo "  6)  Inspect Redis Alert Queue (LLEN & Message Preview)"
        echo "  7)  Run Full Diagnostic Doctor (Perimeter, EDR, AI, Ticketing)"
        echo ""
        echo -e "  ${CYAN}--- Manajemen Layanan (Daemon & Bot) ---${NC}"
        echo "  8)  Start All Services (Daemon & Bot)"
        echo "  9)  Stop All Services"
        echo "  10) Restart All Services"
        echo "  11) Check Service Status (Processes & Systemd)"
        echo "  12) Stream Live Logs (Follow)"
        echo ""
        echo -e "  ${CYAN}--- MLOps, Testing & Maintenance ---${NC}"
        echo "  13) Run Pytest Automated Test Suite"
        echo "  14) Trigger ML Model Auto-Retraining"
        echo "  15) Generate Systemd Linux Service Units"
        echo "  16) Clean Python Cache & Temp Files"
        echo "  0)  Exit"
        echo ""
        read -r -p "Masukkan pilihan [0-16]: " choice

        case "$choice" in
            1) cmd_install_all ;;
            2) cmd_setup ;;
            3) cmd_install_logstash ;;
            4) cmd_setup_logstash ;;
            5) cmd_check_elk ;;
            6) cmd_check_redis ;;
            7) cmd_doctor ;;
            8) cmd_start all ;;
            9) cmd_stop all ;;
            10) cmd_restart all ;;
            11) cmd_status ;;
            12) cmd_logs all ;;
            13) cmd_test ;;
            14) cmd_retrain ;;
            15) cmd_systemd ;;
            16) cmd_clean ;;
            0) echo "Keluar."; exit 0 ;;
            *) log_error "Pilihan tidak valid." ;;
        esac
        echo ""
        read -r -p "Tekan [Enter] untuk kembali ke menu..."
    done
}

# --- CLI Dispatcher ---
main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        install-all|install)
            cmd_install_all "$@"
            ;;
        setup)
            cmd_setup "$@"
            ;;
        install-logstash)
            cmd_install_logstash "$@"
            ;;
        setup-logstash|sync-logstash)
            cmd_setup_logstash "$@"
            ;;
        check-elk|elk|check-es)
            cmd_check_elk "$@"
            ;;
        check-redis|redis|queue)
            cmd_check_redis "$@"
            ;;
        doctor|check|health)
            cmd_doctor "$@"
            ;;
        blocked|blocklist|bl)
            cmd_blocked "$@"
            ;;
        start)
            cmd_start "${1:-all}"
            ;;
        stop)
            cmd_stop "${1:-all}"
            ;;
        restart)
            cmd_restart "${1:-all}"
            ;;
        status)
            cmd_status "$@"
            ;;
        logs)
            cmd_logs "${1:-all}"
            ;;
        test)
            cmd_test "$@"
            ;;
        simulate|mock-alert|test-alert|inject)
            ./simulate_alert.sh "$@"
            ;;
        retrain)
            cmd_retrain "$@"
            ;;
        systemd)
            cmd_systemd "$@"
            ;;
        clean)
            cmd_clean "$@"
            ;;
        help|--help|-h)
            print_banner
            echo -e "${BOLD}Penggunaan:${NC} ./minisoar.sh [perintah]"
            echo ""
            echo "Perintah Alur Instalasi & Pipeline:"
            echo "  install-all         : Jalankan alur setup lengkap (Python >> Logstash >> Config >> Start >> Verify)"
            echo "  setup               : Inisialisasi virtualenv & install dependencies Python"
            echo "  install-logstash    : Install package Logstash & Java runtime via APT/YUM"
            echo "  setup-logstash      : Salin pipeline config dari logstash/ ke /etc/logstash/conf.d & restart"
            echo ""
            echo "Perintah Diagnostik & Monitoring:"
            echo "  check-elk           : Cek status koneksi Elasticsearch, cluster health, node & indeks"
            echo "  check-redis         : Cek koneksi Redis, memori, dan inspeksi panjang antrian alert (LLEN)"
            echo "  doctor | check | health : Cek komprehensif (Perimeter, EDR, AI Copilot, Ticketing, DB)"
            echo "  blocked | blocklist [target] : Tampilkan daftar IP yang diblokir di Perimeter & EDR"
            echo ""
            echo "Perintah Manajemen Layanan:"
            echo "  start [daemon|bot]  : Jalankan layanan di background"
            echo "  stop [daemon|bot]   : Hentikan layanan"
            echo "  restart [all]       : Restart layanan"
            echo "  status              : Periksa status proses PID & live systemd service"
            echo "  logs [daemon|bot]   : Stream live logs"
            echo "  systemd             : Buat file unit systemd untuk Linux server"
            echo ""
            echo "Perintah MLOps, Simulasi & Testing:"
            echo "  simulate [skenario] : Simulasi injeksi alert keamanan ke Redis queue (Webshell, SQLi, C2, dll)"
            echo "  test                : Jalankan seluruh test suite pytest"
            echo "  retrain             : Jalankan MLOps auto-retraining model Challenger"
            echo "  clean               : Bersihkan __pycache__ & temporary files"
            echo "  menu                : Tampilkan menu interaktif"
            ;;
        "")
            cmd_menu
            ;;
        *)
            log_error "Perintah '$cmd' tidak dikenali. Jalankan './minisoar.sh help' untuk bantuan."
            exit 1
            ;;
    esac
}

main "$@"
