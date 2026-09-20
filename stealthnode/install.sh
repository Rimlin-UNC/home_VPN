#!/usr/bin/env bash
# ============================================================
# StealthNode — установщик персонального VPN-сервера.
# Целевая система: чистый VPS с Ubuntu 24.04 LTS (2 ГБ RAM, 20 ГБ диск).
#
# Установка одной командой:
#   curl -fsSL https://raw.githubusercontent.com/Rimlin-UNC/home_VPN/main/stealthnode/install.sh | sudo bash
#
# Или из клонированного репозитория:
#   sudo ./stealthnode/install.sh
#
# Что делает скрипт:
#   1. Проверяет окружение (root, ОС, RAM, диск);
#   2. Интерактивно спрашивает параметры (пароль, домен маскировки, ключи OKX);
#   3. Ставит Docker, UFW, Fail2ban, nftables, автообновления;
#   4. Включает BBR, форвардинг, защитные sysctl, модули ifb;
#   5. Генерирует все ключи (AmneziaWG, REALITY, JWT, UUID);
#   6. Рендерит конфиги и запускает стек docker compose;
#   7. Настраивает фаервол и (опционально) усиливает SSH;
#   8. Печатает итоговую информацию и QR-код админского конфига.
#
# Скрипт идемпотентен там, где это возможно: повторный запуск не
# затирает существующий .env и ключи (используйте setup.sh для
# переконфигурации).
# ============================================================
set -euo pipefail

# ---------------- Константы ----------------
readonly INSTALL_DIR_DEFAULT="/opt/stealthnode"
readonly LOG_FILE="/var/log/stealthnode-install.log"
readonly CREDS_FILE="/root/stealthnode-credentials.txt"
# Репозиторий для bootstrap-режима (когда скачан один install.sh)
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
NON_INTERACTIVE=0        # 1 — без вопросов (значения из env/по умолчанию)
SSH_HARDEN_DEFAULT="n"   # ответ по умолчанию на вопрос об усилении SSH

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

# Проверка ОС (жёстко — только семейство Debian/Ubuntu; 24.04 рекомендована)
[[ -f /etc/os-release ]] || die "Не найден /etc/os-release — система не поддерживается"
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || warn "ОС не Ubuntu (${ID:-unknown}). Продолжаем на свой риск."
if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    warn "Рекомендуется Ubuntu 24.04 LTS (у вас ${VERSION_ID:-unknown})"
fi

# Проверка ресурсов
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
    apt-get install -y -qq git
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
        git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    fi
    # В репозитории проект лежит в подкаталоге stealthnode/
    SRC="$INSTALL_DIR"
    [[ -f "$SRC/stealthnode/docker-compose.yml" ]] && SRC="$INSTALL_DIR/stealthnode"
    [[ -f "$SRC/docker-compose.yml" ]] || die "Не найден docker-compose.yml после клонирования"
    ok "Проект загружен в $SRC (этот шаг больше не понадобится)"
    SCRIPT_DIR="$SRC"
else
    # Запуск из локальной копии: ничего скачивать не нужно
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
[[ -n "${SERVER_PUBLIC_IP:-}" ]] || die "Внешний IP обязателен (нужен клиентским конфигам)"
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
    # Неинтерактивный режим без заданного пароля: генерируем и показываем в итогах
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
    echo "Домен маскировки для Xray REALITY (НЕ google.com/microsoft.com!)"
    echo "  Требования: TLS 1.3 + HTTP/2, популярен у провайдера, не заблокирован."
    echo "  Примеры: www.tbank.ru, www.gosuslugi.ru, ozon.ru"
    read -rp "Домен маскировки [www.tbank.ru]: " REALITY_SNI
fi
REALITY_SNI="${REALITY_SNI:-www.tbank.ru}"
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
    PANEL_TLS=""          # Caddy сам выпустит LE-сертификат (HTTP-01, порт 80)
    ok "Панель будет на https://$PANEL_DOMAIN:PORT (Let's Encrypt)"
else
    PANEL_SITE=":443"
    PANEL_TLS="internal"  # локальный CA Caddy (самоподписанный сертификат)
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
    curl wget git jq qrencode ca-certificates gnupg \
    ufw fail2ban nftables wireguard-tools unattended-upgrades \
    iproute2 iptables kmod
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
    # shellcheck disable=SC1091
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
# ШАГ 5. Ядро: BBR, форвардинг, защитные sysctl, модули для шейпера
# ============================================================
title "Настройка ядра (BBR, ip_forward, hardening)"

cat >/etc/sysctl.d/99-stealthnode.conf <<'EOF'
# StealthNode: параметры ядра (см. ТЗ §4.1)
# Форвардинг (VPN-туннель)
net.ipv4.ip_forward = 1
# Перегрузки: BBR заметно быстрее CUBIC на каналах с потерями
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
# Буферы под высокую скорость туннеля
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-stealthnode.conf

# Модули для шейпинга гостей (tc + ifb): грузим на хосте и после перезагрузки
cat >/etc/modules-load.d/stealthnode.conf <<'EOF'
# StealthNode: модули для лимитов скорости гостей (ТЗ §6.1)
ifb
act_mirred
sch_hfsc
EOF
modprobe ifb numifbs=1 2>/dev/null || warn "Модуль ifb не загрузился (критично только для лимитов upload)"
modprobe act_mirred 2>/dev/null || true
modprobe sch_hfsc 2>/dev/null || true
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

if [[ ! -f .env ]]; then
    umask 077   # .env и конфиги — только для root (600)

    # --- Случайные порты и путь панели ---
    AWG_PORT=$(rand_port 20000 60000)
    PANEL_PORT=$(rand_port 10000 59999)
    while [[ "$PANEL_PORT" == "$AWG_PORT" ]]; do PANEL_PORT=$(rand_port 10000 59999); done
    PANEL_PATH="p-$(openssl rand -hex 4)"          # например p-a7f3b2c1
    JWT_SECRET=$(openssl rand -hex 48)

    # --- Ключи AmneziaWG (Curve25519, как у WireGuard) ---
    AWG_SERVER_PRIVATE_KEY=$(wg genkey)
    AWG_SERVER_PUBLIC_KEY=$(echo "$AWG_SERVER_PRIVATE_KEY" | wg pubkey)

    # --- Ключи REALITY: формат X25519 идентичен WireGuard-ключам,
    #     поэтому wg genkey/pubkey даёт валидную пару для Xray ---
    REALITY_PRIVATE_KEY=$(wg genkey)
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    XRAY_ADMIN_UUID=$(cat /proc/sys/kernel/random/uuid)

    # --- Параметры обфускации AmneziaWG (случайные, в рамках ТЗ §6.4) ---
    AWG_JC=$(rand_port 4 12)
    AWG_JMIN=40
    AWG_JMAX=70
    # S1/S2 — уникальные небольшие значения (различимые размеры пакетов)
    AWG_S1=$(rand_port 10 25)
    AWG_S2=$(rand_port 26 50)
    AWG_S3=$(rand_port 51 75)
    AWG_S4=$(rand_port 76 100)
    # H1–H4 — случайные 32-битные «магические» заголовки (вне диапазона 1–4!)
    AWG_H1=$(rand_port 1000000000 2000000000)
    AWG_H2=$(rand_port 2000000001 3000000000)
    AWG_H3=$(rand_port 3000000001 4000000000)
    AWG_H4=$(rand_port 100000000 999999999)

    # --- Клиент admin (первое устройство владельца) ---
    ADMIN_CLIENT_PRIVATE=$(wg genkey)
    ADMIN_CLIENT_PUBLIC=$(echo "$ADMIN_CLIENT_PRIVATE" | wg pubkey)
    ADMIN_CLIENT_PSK=$(wg genkey)
    ADMIN_CLIENT_IP="10.8.0.2"

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
AWG_PORT=$AWG_PORT
AWG_SUBNET=10.8.0.0/24
AWG_SERVER_IP=10.8.0.1
AWG_MTU=1280
AWG_JC=$AWG_JC
AWG_JMIN=$AWG_JMIN
AWG_JMAX=$AWG_JMAX
AWG_S1=$AWG_S1
AWG_S2=$AWG_S2
AWG_S3=$AWG_S3
AWG_S4=$AWG_S4
AWG_H1=$AWG_H1
AWG_H2=$AWG_H2
AWG_H3=$AWG_H3
AWG_H4=$AWG_H4
AWG_EXTRA_SET_ARGS=
REALITY_SNI=$REALITY_SNI
REALITY_SHORT_ID=$REALITY_SHORT_ID
XRAY_ADMIN_UUID=$XRAY_ADMIN_UUID
OKX_DRY_RUN=$OKX_DRY_RUN
EOF
    chmod 600 .env

    # --- Серверный конфиг AmneziaWG из шаблона ---
    mkdir -p amneziawg/conf/clients
    sed -e "s|@AWG_SERVER_PRIVATE_KEY@|$AWG_SERVER_PRIVATE_KEY|" \
        -e "s|@AWG_SERVER_IP@|10.8.0.1|" \
        -e "s|@AWG_MTU@|1280|" \
        -e "s|@AWG_JC@|$AWG_JC|" -e "s|@AWG_JMIN@|$AWG_JMIN|" -e "s|@AWG_JMAX@|$AWG_JMAX|" \
        -e "s|@AWG_S1@|$AWG_S1|" -e "s|@AWG_S2@|$AWG_S2|" \
        -e "s|@AWG_S3@|$AWG_S3|" -e "s|@AWG_S4@|$AWG_S4|" \
        -e "s|@AWG_H1@|$AWG_H1|" -e "s|@AWG_H2@|$AWG_H2|" \
        -e "s|@AWG_H3@|$AWG_H3|" -e "s|@AWG_H4@|$AWG_H4|" \
        amneziawg/conf/awg0.conf.tmpl > amneziawg/conf/awg0.conf
    # Первый пир — устройство владельца
    cat >>amneziawg/conf/awg0.conf <<EOF

[Peer]
# Имя: admin
PublicKey = $ADMIN_CLIENT_PUBLIC
PresharedKey = $ADMIN_CLIENT_PSK
AllowedIPs = $ADMIN_CLIENT_IP/32
PersistentKeepalive = 25
EOF
    chmod 600 amneziawg/conf/awg0.conf

    # --- Клиентский конфиг владельца (.conf + будет показан QR) ---
    cat >amneziawg/conf/clients/admin.conf <<EOF
[Interface]
PrivateKey = $ADMIN_CLIENT_PRIVATE
Address = $ADMIN_CLIENT_IP/32
DNS = 10.8.0.1
MTU = 1280
Jc = $AWG_JC
Jmin = $AWG_JMIN
Jmax = $AWG_JMAX
S1 = $AWG_S1
S2 = $AWG_S2
S3 = $AWG_S3
S4 = $AWG_S4
H1 = $AWG_H1
H2 = $AWG_H2
H3 = $AWG_H3
H4 = $AWG_H4

[Peer]
PublicKey = $AWG_SERVER_PUBLIC_KEY
PresharedKey = $ADMIN_CLIENT_PSK
AllowedIPs = 0.0.0.0/0
Endpoint = $SERVER_PUBLIC_IP:$AWG_PORT
PersistentKeepalive = 25
EOF
    chmod 600 amneziawg/conf/clients/admin.conf

    # --- Конфиг Xray из шаблона ---
    mkdir -p xray/conf
    sed -e "s|@XRAY_ADMIN_UUID@|$XRAY_ADMIN_UUID|" \
        -e "s|@REALITY_SNI@|$REALITY_SNI|g" \
        -e "s|@REALITY_PRIVATE_KEY@|$REALITY_PRIVATE_KEY|" \
        -e "s|@REALITY_SHORT_ID@|$REALITY_SHORT_ID|" \
        xray/conf/config.json.tmpl > xray/conf/config.json
    chmod 600 xray/conf/config.json

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

    ok "Ключи и конфиги сгенерированы"
else
    warn ".env уже существует — ключи и конфиги НЕ перегенерирую (используйте setup.sh)"
    # Подхватываем значения для фаервола и итогов.
    # Безопасный разбор KEY=VALUE без eval: пароль может содержать
    # пробелы/спецсимволы, наивный `source` здесь опасен.
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
# Текущий SSH-порт обязан быть открыт ДО включения фаервола
CURRENT_SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
ufw allow "$CURRENT_SSH_PORT"/tcp comment 'SSH' >/dev/null
ufw allow "$AWG_PORT"/udp comment 'StealthNode AmneziaWG' >/dev/null
ufw allow 443/tcp comment 'StealthNode Xray REALITY' >/dev/null
ufw allow "$PANEL_PORT"/tcp comment 'StealthNode Panel' >/dev/null
if [[ "${PANEL_TLS:-internal}" == "" ]]; then
    ufw allow 80/tcp comment 'LetsEncrypt HTTP-01' >/dev/null
fi
ufw --force enable >/dev/null
ok "UFW: deny incoming + открыты SSH($CURRENT_SSH_PORT), AWG($AWG_PORT/udp), 443/tcp, панель($PANEL_PORT)"
# Примечание: опубликованные порты Docker пробрасываются через NAT до UFW —
# это нормально: наружу открыты ровно порты сервисов выше (см. SECURITY.md).

# ============================================================
# ШАГ 9. Fail2ban (Защита SSH; бан после 3 попыток — по ТЗ)
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

# Ожидание готовности бэкенда (до ~2 минут)
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
# ШАГ 12. Итоговая информация + QR админского конфига
# ============================================================
PANEL_HOST="$SERVER_PUBLIC_IP"
[[ -n "$PANEL_DOMAIN" ]] && PANEL_HOST="$PANEL_DOMAIN"
PANEL_URL="https://${PANEL_HOST}:${PANEL_PORT}/${PANEL_PATH}/"

{
    echo "StealthNode — данные для доступа ($(date '+%F %T'))"
    echo "=================================================="
    echo "Веб-панель:      $PANEL_URL"
    echo "Логин:           admin"
    echo "Пароль:          $ADMIN_PASSWORD"
    echo ""
    echo "Порт AmneziaWG:  $AWG_PORT/udp"
    echo "Xray REALITY:    443/tcp (маскировка: $REALITY_SNI)"
    echo ""
    echo "Конфиг владельца AmneziaWG: $SCRIPT_DIR/amneziawg/conf/clients/admin.conf"
    echo "Режим торгового бота: $([[ "$OKX_DRY_RUN" == "true" ]] && echo 'СИМУЛЯЦИЯ (paper)' || echo 'БОЕВОЙ')"
} >"$CREDS_FILE"
chmod 600 "$CREDS_FILE"

title "УСТАНОВКА ЗАВЕРШЕНА"
echo
echo "  🌐 Веб-панель:     ${C_BLD}$PANEL_URL${C_RST}"
echo "  👤 Логин:          admin"
if [[ "$GENERATED_PASSWORD" -eq 1 ]]; then
    echo "  🔑 Пароль:         ${C_BLD}$ADMIN_PASSWORD${C_RST} (сгенерирован, сохранён)"
else
    echo "  🔑 Пароль:         (указанный вами при установке)"
fi
echo "  📄 Все данные:     $CREDS_FILE"
echo
echo "  📡 AmneziaWG порт: $AWG_PORT/udp   •   Xray REALITY: 443/tcp ($REALITY_SNI)"
echo "  🤖 Торговый бот:   $([[ "$OKX_DRY_RUN" == "true" ]] && echo 'режим симуляции' || echo 'БОЕВОЙ режим')"
echo
echo "Отсканируйте QR-код приложением AmneziaVPN (устройство владельца):"
echo
qrencode -t ansiutf8 < amneziawg/conf/clients/admin.conf || \
    warn "qrencode не сработал — возьмите конфиг из amneziawg/conf/clients/admin.conf"
echo
ok "Готово. Управление: docker compose -f $SCRIPT_DIR/docker-compose.yml [logs|ps|restart]"
