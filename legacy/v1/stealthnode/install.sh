#!/usr/bin/env bash
# ============================================================
# StealthNode — установщик персонального VPN-сервера.
# Целевая система: чистый VPS с Ubuntu 24.04 LTS (2 ГБ RAM, 20 ГБ диск).
#
# Установка одной командой:
#   curl -fsSL https://raw.githubusercontent.com/Rimlin-UNC/home_VPN/main/stealthnode/install.sh | sudo bash
#
# Что разворачивается (стек под ТСПУ-2026, БЕЗ AmneziaWG):
#   * Xray VLESS + REALITY — три транспорта: TCP/Vision :443 (основной),
#     gRPC и XHTTP (резервы, переживают детект vision-профиля);
#   * Hysteria2 + Salamander (QUIC/UDP) — резерв для сетей с потерями
#     и провайдеров, где TCP-профиль уже блокируется;
#   * dnscrypt-proxy — весь DNS пользователей уходит шифрованным;
#   * Веб-панель (FastAPI + WebSocket) за Caddy на случайном порту
#     и секретном пути /p-XXXXXXXX/ с QR для всех ссылок;
#   * Изолированный торговый бот OKX (по умолчанию — симуляция).
#
# Скрипт идемпотентен там, где возможно: повторный запуск не
# затирает существующий .env и ключи (переконфигурация — setup.sh).
# ============================================================
set -euo pipefail

# ---------------- Константы ----------------
readonly INSTALL_DIR_DEFAULT="/opt/stealthnode"
readonly LOG_FILE="/var/log/stealthnode-install.log"
readonly CREDS_FILE="/root/stealthnode-credentials.txt"
readonly REPO_URL_DEFAULT="https://github.com/Rimlin-UNC/home_VPN.git"

# ---------------- Цветной вывод и логирование ----------------
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'
    C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_BLD=""; C_RST=""
fi
exec > >(tee -a "$LOG_FILE") 2>&1  # весь вывод дублируем в лог

info()  { echo "${C_BLU}[*]${C_RST} $*"; }
ok()    { echo "${C_GRN}[+]${C_RST} $*"; }
warn()  { echo "${C_YLW}[!]${C_RST} $*"; }
die()   { echo "${C_RED}[x] ОШИБКА:${C_RST} $*" >&2; exit 1; }
title() { echo; echo "${C_BLD}=== $* ===${C_RST}"; }

# ---------------- Параметры командной строки ----------------
INSTALL_DIR="$INSTALL_DIR_DEFAULT"
REPO_URL="${STEALTHNODE_REPO:-$REPO_URL_DEFAULT}"
NON_INTERACTIVE=0
SSH_HARDEN_DEFAULT="n"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)            INSTALL_DIR="$2"; shift 2 ;;
        --repo)           REPO_URL="$2"; shift 2 ;;
        --yes|-y)         NON_INTERACTIVE=1; shift ;;
        --ssh-harden)     SSH_HARDEN_DEFAULT="y"; shift ;;
        -h|--help)
            echo "Использование: install.sh [--dir КАТАЛОГ] [--repo URL] [--yes] [--ssh-harden]"
            exit 0 ;;
        *) die "Неизвестный аргумент: $1" ;;
    esac
done

# ============================================================
# ШАГ 0. Проверки окружения
# ============================================================
title "StealthNode: проверка окружения"

[[ $EUID -eq 0 ]] || die "Скрипт нужно запускать от root: sudo bash install.sh"

[[ -f /etc/os-release ]] || die "Не найден /etc/os-release — система не поддерживается"
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || warn "ОС не Ubuntu (${ID:-unknown}). Продолжаем на свой риск."
if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    warn "Рекомендуется Ubuntu 24.04 LTS (у вас ${VERSION_ID:-unknown})"
fi

RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
DISK_GB=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
CPU_N=$(nproc)
info "Обнаружено: CPU ${CPU_N} vCPU, RAM ${RAM_MB} МБ, свободно на диске ${DISK_GB} ГБ"
[[ "$RAM_MB" -ge 900 ]] || die "Нужно минимум ~1 ГБ RAM (рекомендуется 2 ГБ)"
[[ "$DISK_GB" -ge 12 ]] || die "Нужно минимум 12 ГБ свободного места"

command -v apt-get >/dev/null || die "apt-get не найден — нужен Debian/Ubuntu"
ok "Проверки пройдены"

# ============================================================
# ШАГ 1. Bootstrap: если это «голый» install.sh — клонируем проект
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}" 2>/dev/null)" && pwd || echo "$PWD")"

if [[ ! -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
    title "Bootstrap: загрузка проекта StealthNode"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git curl ca-certificates
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
        # Основной путь — git clone. Запасной — tar-архив codeload:
        # у части провайдеров (в т.ч. в РФ) github.com/порты SDK глушатся,
        # а codeload (тот же CDN GitHub) остаётся доступен.
        if ! git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            warn "git clone не удался — GitHub недоступен? Пробую codeload-архив…"
            local_repo="${REPO_URL#https://github.com/}"; local_repo="${local_repo%.git}"
            rm -rf "$INSTALL_DIR"; mkdir -p "$INSTALL_DIR"
            curl -fsSL --retry 3 "https://codeload.github.com/${local_repo}/tar.gz/refs/heads/main" \
                | tar -xz --strip-components=1 -C "$INSTALL_DIR" \
                || die "Не удалось скачать проект ни git, ни codeload. Проверьте доступ к GitHub."
        fi
    fi
    SRC="$INSTALL_DIR"
    [[ -f "$SRC/stealthnode/docker-compose.yml" ]] && SRC="$INSTALL_DIR/stealthnode"
    [[ -f "$SRC/docker-compose.yml" ]] || die "Не найден docker-compose.yml после клонирования"
    ok "Проект загружен в $SRC"
    SCRIPT_DIR="$SRC"
else
    info "Запуск из локальной копии: $SCRIPT_DIR"
fi
cd "$SCRIPT_DIR"

# ============================================================
# ШАГ 2. Интерактивный сбор параметров
# ============================================================
title "Настройка параметров установки"

# --- Внешний IP сервера ---
detect_public_ip() {
    local ip
    for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
        ip=$(curl -4 -fsS --max-time 8 "$svc" 2>/dev/null | tr -dc '0-9.' || true)
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$ip"; return 0
        fi
    done
    return 1
}
SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-$(detect_public_ip || true)}"
if [[ -z "$SERVER_PUBLIC_IP" && $NON_INTERACTIVE -eq 0 ]]; then
    read -rp "Не удалось определить внешний IP, введите вручную: " SERVER_PUBLIC_IP
fi
[[ -n "${SERVER_PUBLIC_IP:-}" ]] || die "Внешний IP обязателен (нужен клиентским ссылкам)"
ok "Внешний IP сервера: $SERVER_PUBLIC_IP"

# --- Пароль администратора ---
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
if [[ $NON_INTERACTIVE -eq 0 && -z "$ADMIN_PASSWORD" ]]; then
    while true; do
        read -rsp "Пароль администратора панели (минимум 16 символов): " ADMIN_PASSWORD; echo
        [[ ${#ADMIN_PASSWORD} -ge 16 ]] && break
        warn "Слишком короткий пароль (минимум 16 символов)"
    done
    read -rsp "Повторите пароль: " ADMIN_PASSWORD2; echo
    [[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]] || die "Пароли не совпадают"
fi
if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
    GENERATED_PASSWORD=1
else
    GENERATED_PASSWORD=0
fi
[[ ${#ADMIN_PASSWORD} -ge 16 ]] || die "Пароль должен быть минимум 16 символов"

# --- Домен маскировки REALITY ---
REALITY_SNI="${REALITY_SNI:-}"
if [[ $NON_INTERACTIVE -eq 0 && -z "$REALITY_SNI" ]]; then
    echo
    echo "Домен маскировки REALITY (НЕ google.com/microsoft.com!)"
    echo "  Требования: TLS 1.3 + HTTP/2, популярен у провайдера, из «белого списка» РФ."
    echo "  Примеры: max.ru, yandex.ru, mail.ru, vk.com, ozon.ru"
    read -rp "Домен маскировки [max.ru]: " REALITY_SNI
fi
REALITY_SNI="${REALITY_SNI:-max.ru}"
[[ "$REALITY_SNI" =~ google\.com$|microsoft\.com$ ]] && \
    die "Домен $REALITY_SNI использовать нельзя (мониторится цензорами)"
ok "Домен маскировки: $REALITY_SNI"

# --- Домен панели (опционально, для Let's Encrypt) ---
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
if [[ $NON_INTERACTIVE -eq 0 && -z "${PANEL_DOMAIN_SET:-}" ]]; then
    read -rp "Домен для панели (Enter — без домена, самоподписанный сертификат): " PANEL_DOMAIN || true
fi
if [[ -n "$PANEL_DOMAIN" ]]; then
    PANEL_SITE="$PANEL_DOMAIN"
    PANEL_TLS=""
    ok "Панель будет на https://$PANEL_DOMAIN:PORT (Let's Encrypt)"
else
    PANEL_SITE=":443"
    PANEL_TLS="internal"
    ok "Панель будет на https://$SERVER_PUBLIC_IP:PORT (самоподписанный сертификат)"
fi

# --- API-ключи OKX (опционально) ---
OKX_API_KEY="${OKX_API_KEY:-}"; OKX_API_SECRET="${OKX_API_SECRET:-}"
OKX_API_PASSPHRASE="${OKX_API_PASSPHRASE:-}"
if [[ $NON_INTERACTIVE -eq 0 ]]; then
    echo
    echo "Ключи API OKX для торгового бота (Enter — пропустить, бот будет в режиме симуляции)."
    echo "  Рекомендация: ключ с правом Trade, БЕЗ права вывода средств!"
    read -rp "  OKX API Key: " OKX_API_KEY
    if [[ -n "$OKX_API_KEY" ]]; then
        read -rsp "  OKX API Secret: " OKX_API_SECRET; echo
        read -rsp "  OKX API Passphrase: " OKX_API_PASSPHRASE; echo
        read -rp "  Включить РЕАЛЬНУЮ торговлю? (yes — боевые ордера) [no]: " OKX_LIVE
        [[ "${OKX_LIVE:-no}" == "yes" ]] && OKX_DRY_RUN="false" || OKX_DRY_RUN="true"
    else
        OKX_DRY_RUN="true"
    fi
fi
OKX_DRY_RUN="${OKX_DRY_RUN:-true}"

# ============================================================
# ШАГ 3. Системные пакеты
# ============================================================
title "Установка системных пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    curl wget git jq qrencode ca-certificates gnupg openssl \
    ufw fail2ban nftables unattended-upgrades iproute2 iptables
ok "Пакеты установлены"

# ============================================================
# ШАГ 4. Docker (официальный репозиторий)
# ============================================================
if ! command -v docker >/dev/null 2>&1; then
    title "Установка Docker"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME:-noble} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
else
    info "Docker уже установлен ($(docker --version | head -c 60)...)"
fi
docker compose version >/dev/null 2>&1 || die "Плагин docker compose не найден"
ok "Docker готов"

# ============================================================
# ШАГ 5. Ядро: BBR и защитные sysctl (прокси не требует форвардинга)
# ============================================================
title "Настройка ядра (BBR, hardening)"

cat >/etc/sysctl.d/99-stealthnode.conf <<'EOF'
# StealthNode: параметры ядра.
# BBR заметно быстрее CUBIC на каналах с потерями (важно для TCP-профилей)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# Защита от спуфинга и redirect-атак
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
# SYN-флод
net.ipv4.tcp_syncookies = 1
# Буферы под высокую скорость VPN
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-stealthnode.conf
ok "Ядро настроено"

# ============================================================
# ШАГ 6. Автоматические обновления безопасности
# ============================================================
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
ok "Автообновления безопасности включены"

# ============================================================
# ШАГ 7. Генерация секретов и конфигов (только при первом запуске)
# ============================================================
title "Генерация ключей и конфигурации"

rand_port() { shuf -i "$1"-"$2" -n 1; }

# Ключи X25519 для REALITY без внешних зависимостей: python3 + openssl есть
# на любой Ubuntu 24.04. Если python3-cryptography недоступен — используем
# запасной путь через временный контейнер позже; базово это работает.
gen_reality_keys() {
    python3 - <<'PYEOF'
import base64, subprocess, sys
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = X25519PrivateKey.generate()
    p = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    u = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # base64url без '=' — формат `xray x25519`, безопасен в URL ссылок vless://
    print(base64.urlsafe_b64encode(p).decode().rstrip('='))
    print(base64.urlsafe_b64encode(u).decode().rstrip('='))
except ImportError:
    # cryptography нет — берём ключи совместимого формата из openssl + X25519 pub
    sys.exit(42)
PYEOF
}

if [[ ! -f .env ]]; then
    umask 077

    # --- Случайные порты и путь панели ---
    PANEL_PORT=$(rand_port 10000 59999)
    XRAY_GRPC_PORT=$(rand_port 20000 59999)
    XRAY_XHTTP_PORT=$(rand_port 20000 59999)
    HY2_PORT=$(rand_port 20000 60000)
    while [[ "$XRAY_XHTTP_PORT" == "$XRAY_GRPC_PORT" ]]; do XRAY_XHTTP_PORT=$(rand_port 20000 59999); done
    while [[ "$HY2_PORT" == "$XRAY_GRPC_PORT" || "$HY2_PORT" == "$XRAY_XHTTP_PORT" ]]; do HY2_PORT=$(rand_port 20000 60000); done
    PANEL_PATH="p-$(openssl rand -hex 4)"
    JWT_SECRET=$(openssl rand -hex 48)

    # --- Ключи REALITY (X25519) ---
    if ! KEYS=$(gen_reality_keys) || [[ $(echo "$KEYS" | wc -l) -lt 2 ]]; then
        info "python3-cryptography недоступен — ставлю пакет для генерации ключей"
        apt-get install -y -qq python3-cryptography >/dev/null
        KEYS=$(gen_reality_keys) || die "Не удалось сгенерировать ключи REALITY"
    fi
    REALITY_PRIVATE_KEY=$(echo "$KEYS" | sed -n '1p')
    REALITY_PUBLIC_KEY=$(echo "$KEYS" | sed -n '2p')
    [[ -n "$REALITY_PRIVATE_KEY" && -n "$REALITY_PUBLIC_KEY" ]] || die "Пустые ключи REALITY"

    # --- Прочие идентификаторы ---
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    XRAY_ADMIN_UUID=$(cat /proc/sys/kernel/random/uuid)
    GRPC_SERVICE="svc-$(openssl rand -hex 4)"       # случайное имя gRPC-сервиса
    XHTTP_PATH=$(openssl rand -hex 12)              # случайный путь XHTTP
    HY2_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)
    SALAMANDER_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)

    # --- .env ---
    cat >.env <<EOF
# StealthNode — сгенерировано install.sh $(date -u '+%F %T UTC')
# ВНИМАНИЕ: файл содержит секреты. Права 600, только root.
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASSWORD
JWT_SECRET=$JWT_SECRET
PANEL_PATH=$PANEL_PATH
PANEL_PORT=$PANEL_PORT
PANEL_DOMAIN=$PANEL_DOMAIN
PANEL_SITE=$PANEL_SITE
PANEL_TLS=$PANEL_TLS
SERVER_PUBLIC_IP=$SERVER_PUBLIC_IP
REALITY_SNI=$REALITY_SNI
REALITY_SHORT_ID=$REALITY_SHORT_ID
XRAY_ADMIN_UUID=$XRAY_ADMIN_UUID
XRAY_GRPC_PORT=$XRAY_GRPC_PORT
XRAY_XHTTP_PORT=$XRAY_XHTTP_PORT
GRPC_SERVICE=$GRPC_SERVICE
XHTTP_PATH=$XHTTP_PATH
HY2_PORT=$HY2_PORT
HY2_PASSWORD=$HY2_PASSWORD
SALAMANDER_PASSWORD=$SALAMANDER_PASSWORD
OKX_DRY_RUN=$OKX_DRY_RUN
EOF
    chmod 600 .env

    # --- Конфиг Xray из шаблона (три транспорта + StatsService) ---
    mkdir -p xray/conf
    sed -e "s|@XRAY_ADMIN_UUID@|$XRAY_ADMIN_UUID|g" \
        -e "s|@REALITY_SNI@|$REALITY_SNI|g" \
        -e "s|@REALITY_PRIVATE_KEY@|$REALITY_PRIVATE_KEY|" \
        -e "s|@REALITY_SHORT_ID@|$REALITY_SHORT_ID|" \
        -e "s|@GRPC_SERVICE@|$GRPC_SERVICE|" \
        -e "s|@XHTTP_PATH@|$XHTTP_PATH|" \
        xray/conf/config.json.tmpl > xray/conf/config.json
    chmod 600 xray/conf/config.json

    # --- Конфиг Hysteria2 + самоподписанный сертификат ---
    mkdir -p hysteria/conf
    sed -e "s|@HY2_PASSWORD@|$HY2_PASSWORD|" \
        -e "s|@SALAMANDER_PASSWORD@|$SALAMANDER_PASSWORD|" \
        -e "s|@REALITY_SNI@|$REALITY_SNI|" \
        hysteria/conf/hysteria.yaml.tmpl > hysteria/conf/hysteria.yaml
    chmod 600 hysteria/conf/hysteria.yaml
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout hysteria/conf/server.key -out hysteria/conf/server.crt \
        -days 3650 -subj "/CN=$REALITY_SNI" 2>/dev/null
    chmod 600 hysteria/conf/server.key

    # --- Caddyfile из шаблона ---
    cp caddy/Caddyfile.tmpl caddy/Caddyfile
    # Если задан домен (PANEL_TLS пустой) — директива tls не нужна:
    # Caddy сам выпустит сертификат Let's Encrypt для указанного имени.
    if [[ -z "$PANEL_TLS" ]]; then
        sed -i '/tls {\$PANEL_TLS}/d' caddy/Caddyfile
    fi

    # --- bot.env для торгового бота ---
    mkdir -p trading-bot/logs
    cat >trading-bot/bot.env <<EOF
# StealthNode — ключи и параметры бота OKX (права 600!)
OKX_API_KEY=$OKX_API_KEY
OKX_API_SECRET=$OKX_API_SECRET
OKX_API_PASSPHRASE=$OKX_API_PASSPHRASE
OKX_DRY_RUN=$OKX_DRY_RUN
OKX_SYMBOL=BTC/USDT
OKX_MAX_ORDER_USDT=10
OKX_GRID_STEP_PCT=0.5
OKX_GRID_LEVELS=4
OKX_LOOP_SEC=30
EOF
    chmod 600 trading-bot/bot.env

    # --- Файл ссылок владельца (для setup.sh и итогов установки) ---
    mkdir -p xray/conf/share
    Q_BASE="security=reality&encryption=none&pbk=${REALITY_PUBLIC_KEY}&fp=chrome&sni=${REALITY_SNI}&sid=${REALITY_SHORT_ID}"
    {
        echo "vless://${XRAY_ADMIN_UUID}@${SERVER_PUBLIC_IP}:443?${Q_BASE}&type=tcp&flow=xtls-rprx-vision#StealthNode-admin-tcp"
        echo "vless://${XRAY_ADMIN_UUID}@${SERVER_PUBLIC_IP}:${XRAY_GRPC_PORT}?${Q_BASE}&type=grpc&serviceName=${GRPC_SERVICE}&alpn=h2#StealthNode-admin-grpc"
        echo "vless://${XRAY_ADMIN_UUID}@${SERVER_PUBLIC_IP}:${XRAY_XHTTP_PORT}?${Q_BASE}&type=xhttp&path=%2F${XHTTP_PATH}&mode=auto#StealthNode-admin-xhttp"
        echo "hy2://${HY2_PASSWORD}@${SERVER_PUBLIC_IP}:${HY2_PORT}/?obfs=salamander&obfs-password=${SALAMANDER_PASSWORD}&sni=${REALITY_SNI}&insecure=1#StealthNode-HY2"
    } > xray/conf/share/admin-links.txt
    chmod 600 xray/conf/share/admin-links.txt

    ok "Ключи и конфиги сгенерированы"
else
    warn ".env уже существует — ключи и конфиги НЕ перегенерирую (используйте setup.sh)"
    # Подхватываем значения для фаервола и итогов.
    # Безопасный разбор KEY=VALUE без eval: пароль может содержать спецсимволы.
    while IFS='=' read -r _k _v; do
        [[ "$_k" =~ ^[A-Z_]+$ ]] && export "$_k=$_v"
    done < <(grep -E '^[A-Z_]+=' .env || true)
fi
umask 022

# ============================================================
# ШАГ 8. Фаервол UFW
# ============================================================
title "Настройка фаервола (UFW)"
ufw --force default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
CURRENT_SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
ufw allow "$CURRENT_SSH_PORT"/tcp comment 'SSH' >/dev/null
ufw allow 443/tcp comment 'StealthNode Xray TCP/Vision' >/dev/null
ufw allow "$XRAY_GRPC_PORT"/tcp comment 'StealthNode Xray gRPC' >/dev/null
ufw allow "$XRAY_XHTTP_PORT"/tcp comment 'StealthNode Xray XHTTP' >/dev/null
ufw allow "$HY2_PORT"/udp comment 'StealthNode Hysteria2' >/dev/null
ufw allow "$PANEL_PORT"/tcp comment 'StealthNode Panel' >/dev/null
if [[ "${PANEL_TLS:-internal}" == "" ]]; then
    ufw allow 80/tcp comment 'LetsEncrypt HTTP-01' >/dev/null
fi
ufw --force enable >/dev/null
ok "UFW: 443/tcp (Vision), $XRAY_GRPC_PORT (gRPC), $XRAY_XHTTP_PORT (XHTTP), $HY2_PORT/udp (HY2), $PANEL_PORT (панель)"

# ============================================================
# ШАГ 9. Fail2ban (бан SSH после 3 попыток — по ТЗ)
# ============================================================
title "Настройка Fail2ban"
cat >/etc/fail2ban/jail.d/stealthnode.conf <<EOF
# StealthNode: защита SSH от брутфорса
[sshd]
enabled = true
port = $CURRENT_SSH_PORT
maxretry = 3
findtime = 10m
bantime = 24h
EOF
systemctl enable --now fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1 || true
ok "Fail2ban: бан на 24 часа после 3 неудачных попыток (SSH)"
# Защита панели от перебора — на уровне приложения: 5 попыток/мин
# + бан IP на 24 часа (см. backend/app/api/auth.py).

# ============================================================
# ШАГ 10. (Опционально) Усиление SSH
# ============================================================
if [[ "$SSH_HARDEN_DEFAULT" == "y" ]]; then
    SSH_ANSWER="y"
elif [[ $NON_INTERACTIVE -eq 1 ]]; then
    SSH_ANSWER="n"
else
    echo
    warn "Усиление SSH: нестандартный порт, вход только по ключам, root — по ключу."
    warn "ВАЖНО: убедитесь, что ваш ключ УЖЕ добавлен в authorized_keys текущего пользователя!"
    read -rp "Применить усиление SSH? [y/N]: " SSH_ANSWER
fi
if [[ "${SSH_ANSWER:-n}" =~ ^[yYдД]$ ]]; then
    if [[ $NON_INTERACTIVE -eq 0 ]]; then
        read -rp "Новый SSH-порт [20422]: " NEW_SSH_PORT
    fi
    NEW_SSH_PORT=${NEW_SSH_PORT:-20422}
    cat >/etc/ssh/sshd_config.d/stealthnode.conf <<EOF
# StealthNode: усиление SSH
Port $NEW_SSH_PORT
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
    ufw allow "$NEW_SSH_PORT"/tcp comment 'SSH (new)' >/dev/null
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    warn "SSH переведён на порт $NEW_SSH_PORT, парольный вход отключён."
    warn "НЕ ЗАКРЫВАЙТЕ текущую сессию, пока не проверите новое подключение!"
fi

# ============================================================
# ШАГ 11. Сборка и запуск стека
# ============================================================
title "Сборка и запуск контейнеров (может занять 5–15 минут)"
docker compose pull --quiet 2>/dev/null || true   # базовые образы (caddy)
docker compose build
docker compose up -d
ok "Контейнеры запущены"

info "Ожидание готовности панели..."
READY=0
for i in $(seq 1 40); do
    if curl -sk --max-time 3 \
        "https://127.0.0.1:${PANEL_PORT}/${PANEL_PATH}/api/health" 2>/dev/null | grep -q '"ok"'; then
        READY=1; break
    fi
    sleep 3
done
if [[ "$READY" -eq 1 ]]; then
    ok "Панель отвечает"
else
    warn "Панель пока не ответила — проверьте: docker compose -f $SCRIPT_DIR/docker-compose.yml logs backend"
fi

# ============================================================
# ШАГ 12. Итоговая информация + QR основной ссылки владельца
# ============================================================
PANEL_HOST="$SERVER_PUBLIC_IP"
[[ -n "$PANEL_DOMAIN" ]] && PANEL_HOST="$PANEL_DOMAIN"
PANEL_URL="https://${PANEL_HOST}:${PANEL_PORT}/${PANEL_PATH}/"

MAIN_LINK=$(sed -n '1p' xray/conf/share/admin-links.txt 2>/dev/null || echo "")

{
    echo "StealthNode — данные для доступа ($(date '+%F %T'))"
    echo "=================================================="
    echo "Веб-панель:      $PANEL_URL"
    echo "Логин:           admin"
    echo "Пароль:          $ADMIN_PASSWORD"
    echo ""
    echo "VPN-профили Xray: 443/tcp (Vision), $XRAY_GRPC_PORT (gRPC), $XRAY_XHTTP_PORT (XHTTP)"
    echo "Hysteria2 резерв: $HY2_PORT/udp (Salamander)"
    echo "Маскировка:      $REALITY_SNI"
    echo ""
    echo "Ссылки владельца (все транспорты + HY2):"
    cat xray/conf/share/admin-links.txt 2>/dev/null || true
    echo ""
    echo "Режим торгового бота: $([[ "$OKX_DRY_RUN" == "true" ]] && echo 'СИМУЛЯЦИЯ (paper)' || echo 'БОЕВОЙ')"
} >"$CREDS_FILE"
chmod 600 "$CREDS_FILE"

title "УСТАНОВКА ЗАВЕРШЕНА"
echo
echo "  🌐 Веб-панель:  ${C_BLD}$PANEL_URL${C_RST}"
echo "  👤 Логин:       admin"
if [[ "$GENERATED_PASSWORD" -eq 1 ]]; then
    echo "  🔑 Пароль:      ${C_BLD}$ADMIN_PASSWORD${C_RST} (сгенерирован, сохранён)"
else
    echo "  🔑 Пароль:      (указанный вами при установке)"
fi
echo "  📄 Все данные:  $CREDS_FILE"
echo
echo "  🚀 VPN: VLESS+REALITY 443/tcp (основной), $XRAY_GRPC_PORT (gRPC), $XRAY_XHTTP_PORT (XHTTP)"
echo "  🛟 Резерв Hysteria2: $HY2_PORT/udp  •  Маскировка: $REALITY_SNI"
echo "  🤖 Торговый бот: $([[ "$OKX_DRY_RUN" == "true" ]] && echo 'режим симуляции' || echo 'БОЕВОЙ режим')"
echo
if [[ -n "$MAIN_LINK" ]]; then
    echo "Основная ссылка владельца (отсканируйте в клиенте: v2rayNG / Streisand / Nekoray / Happ):"
    echo
    echo "$MAIN_LINK" | qrencode -t ansiutf8 || warn "qrencode не сработал — ссылки в $CREDS_FILE"
    echo
    echo "Резервные ссылки (gRPC, XHTTP, HY2) — в файле $CREDS_FILE и в панели (Настройки)."
fi
echo
ok "Готово. Управление: docker compose -f $SCRIPT_DIR/docker-compose.yml [logs|ps|restart]"
