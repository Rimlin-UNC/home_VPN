#!/usr/bin/env bash
# StealthNode: предварительные проверки сервера перед установкой.
# shellcheck shell=bash

check_os() {
    [[ -r /etc/os-release ]] || die "не найден /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == "24.04" ]]; then
        ok "ОС: ${PRETTY_NAME}"
    elif [[ ${OPT_FORCE_OS:-0} == 1 ]]; then
        warn "ОС ${PRETTY_NAME:-?} не проверялась (рассчитано на Ubuntu 24.04) — продолжаем по --force-os"
    else
        die "нужна Ubuntu 24.04 LTS (обнаружено: ${PRETTY_NAME:-неизвестно}); принудительно: --force-os"
    fi
    case "$(uname -m)" in
        x86_64 | amd64 | aarch64 | arm64) ok "архитектура: $(uname -m)" ;;
        *) die "архитектура $(uname -m) не поддерживается (нужна amd64 или arm64)" ;;
    esac
    command -v systemctl > /dev/null || die "нужен systemd"
}

check_resources() {
    local mem_mb disk_mb
    mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    disk_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    ((mem_mb >= 450)) || die "мало памяти: ${mem_mb} МБ (нужно от 512 МБ)"
    ((disk_mb >= 2048)) || die "мало места на диске: ${disk_mb} МБ свободно (нужно от 2 ГБ)"
    ok "ресурсы: RAM ${mem_mb} МБ, свободно на диске ${disk_mb} МБ"
    SN_MEM_MB=${mem_mb}
}

# Чей процесс слушает порт (пусто — свободен).
port_owner() {
    local proto=$1 port=$2 flag=-lnt
    [[ ${proto} == udp ]] && flag=-lnu
    ss -H "${flag}p" "sport = :${port}" 2> /dev/null | grep -oP 'users:\(\("\K[^"]+' | head -n1 || true
}

check_ports() {
    local item proto port owner
    for item in "tcp:80" "tcp:${SN_XHTTP_PORT:-443}" "tcp:${SN_VISION_PORT:-8443}" "udp:${SN_HY2_PORT:-443}"; do
        proto=${item%%:*}
        port=${item##*:}
        owner=$(port_owner "${proto}" "${port}")
        case "${owner}" in
            "") ;;
            xray* | x-ui | caddy) info "порт ${port}/${proto} уже занят нашим ${owner} (повторная установка)" ;;
            *) die "порт ${port}/${proto} занят процессом «${owner}» — освободите его (например: systemctl disable --now ${owner})" ;;
        esac
    done
    ok "нужные порты свободны"
}

detect_public_ip() {
    local url ip=""
    for url in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip https://checkip.amazonaws.com; do
        ip=$(curl -4 -fsS --max-time 6 "${url}" 2> /dev/null | tr -d '[:space:]') || true
        if is_ipv4 "${ip}"; then
            break
        fi
        ip=""
    done
    if [[ -z ${ip} ]]; then
        ip=$(ip -4 route get 1.1.1.1 2> /dev/null | grep -oP 'src \K[0-9.]+' || true)
        [[ -n ${ip} ]] && warn "внешний IP определён по маршруту: ${ip} (сервисы определения IP недоступны)"
    fi
    [[ -n ${ip} ]] || die "не удалось определить внешний IPv4 сервера"
    SN_PUBLIC_IP=${ip}
    ok "внешний IPv4: ${SN_PUBLIC_IP}"
}

detect_ipv6() {
    SN_FREEDOM_STRATEGY="UseIPv4"
    if ip -6 route show default 2> /dev/null | grep -q default &&
        curl -6 -fsS --max-time 6 https://api64.ipify.org > /dev/null 2>&1; then
        SN_FREEDOM_STRATEGY="UseIPv4v6"
        ok "IPv6 работает — Xray будет ходить в интернет по IPv4 и IPv6"
    else
        info "IPv6 нет или не работает — исходящие соединения Xray только по IPv4"
    fi
}

# Проверка A-записи домена. Без неё Let's Encrypt не выдаст сертификат.
check_dns_record() {
    local domain=$1 expected=$2 resolved
    resolved=$(getent ahostsv4 "${domain}" 2> /dev/null | awk '{print $1}' | sort -u | paste -sd' ' - || true)
    if [[ -z ${resolved} ]]; then
        warn "домен ${domain} не разрешается в IPv4. Создайте A-запись ${domain} → ${expected} (TTL 300)."
        SN_DNS_OK=0
    elif [[ " ${resolved} " == *" ${expected} "* ]]; then
        ok "A-запись ${domain} → ${expected}"
        SN_DNS_OK=1
    else
        warn "A-запись ${domain} указывает на ${resolved}, а IP сервера ${expected}"
        SN_DNS_OK=0
    fi
    if [[ ${SN_DNS_OK} == 0 && ${SN_TLS_MODE:-acme} == acme ]]; then
        warn "Caddy будет повторять выпуск сертификата сам; панель станет доступна по HTTPS после исправления DNS."
        warn "До этого Hysteria2 работает с self-signed сертификатом + pinSHA256 (безопасно)."
        if [[ ${OPT_STRICT_DNS:-0} == 1 ]]; then
            die "--strict-dns: исправьте A-запись и запустите установку снова"
        fi
    fi
}

preflight() {
    check_os
    check_resources
    check_ports
    detect_public_ip
    detect_ipv6
    check_dns_record "${SN_DOMAIN_ARG}" "${SN_PUBLIC_IP}"
}
