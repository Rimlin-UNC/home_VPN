#!/usr/bin/env bash
# StealthNode: Caddy — HTTPS для панели 3x-ui и подписки на отдельном порту.
# 443/tcp занят Xray (REALITY), поэтому сертификат выпускается через HTTP-01 на :80.
# shellcheck shell=bash

install_caddy() {
    if command -v caddy > /dev/null; then
        ok "Caddy уже установлен: $(caddy version | awk '{print $1}')"
        return 0
    fi
    local keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
    if retry 3 5 curl -fsSL --max-time 60 "${CADDY_GPG_URL}" -o /tmp/caddy.gpg.key &&
        retry 3 5 curl -fsSL --max-time 60 "${CADDY_LIST_URL}" -o /tmp/caddy-stable.list; then
        gpg --batch --yes --dearmor -o "${keyring}" /tmp/caddy.gpg.key
        chmod 644 "${keyring}"
        install -m 644 /tmp/caddy-stable.list /etc/apt/sources.list.d/caddy-stable.list
        retry 3 10 apt_get update
        apt_install caddy
    else
        warn "репозиторий Caddy недоступен — ставим caddy из Ubuntu (версия старее)"
        apt_install caddy
    fi
    rm -f /tmp/caddy.gpg.key /tmp/caddy-stable.list
    ok "Caddy установлен: $(caddy version | awk '{print $1}')"
}

caddy_cert_path() {
    find /var/lib/caddy/.local/share/caddy/certificates -mindepth 3 -maxdepth 3 \
        -path "*/${SN_DOMAIN}/${SN_DOMAIN}.crt" 2> /dev/null |
        grep -v -e '/local/' -e staging | head -n1 || true
}

# Переменные SN_CADDY_* используются в render_template по имени.
# shellcheck disable=SC2034
configure_caddy() {
    local SN_CADDY_GLOBAL_EMAIL="" SN_CADDY_TLS
    if [[ ${SN_TLS_MODE} == internal ]]; then
        SN_CADDY_TLS="tls internal"
    elif [[ -n ${SN_ACME_EMAIL:-} ]]; then
        SN_CADDY_GLOBAL_EMAIL="email ${SN_ACME_EMAIL}"
        SN_CADDY_TLS=$'tls {\n\t\tissuer acme {\n\t\t\temail '"${SN_ACME_EMAIL}"$'\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}'
    else
        SN_CADDY_TLS=$'tls {\n\t\tissuer acme {\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}'
    fi
    install -d -m 700 "${SN_ROOT}/caddy"
    render_template "${SN_SRC}/templates/Caddyfile.tmpl" "${SN_ROOT}/caddy/Caddyfile" 600 \
        SN_DOMAIN SN_PANEL_PORT SN_PANEL_PATH SN_SUB_PATH SN_XUI_PORT SN_SUB_PORT SN_CADDY_TLS SN_CADDY_GLOBAL_EMAIL
    caddy fmt --overwrite "${SN_ROOT}/caddy/Caddyfile" > /dev/null 2>&1 || true
    # Caddy работает от пользователя caddy и читает /etc/caddy (каталог /opt/stealthnode закрыт: 700).
    # Проверяем конфиг тоже от caddy: `caddy validate` открывает файлы журнала, и запуск от root
    # оставил бы /var/log/caddy/caddy.log недоступным для службы.
    install -d -m 755 -o caddy -g caddy /var/log/caddy
    chown -R caddy:caddy /var/log/caddy
    install -m 644 "${SN_ROOT}/caddy/Caddyfile" /etc/caddy/Caddyfile.new
    info "проверка Caddyfile (caddy validate)"
    if ! runuser -u caddy -- caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile.new > /tmp/caddy-validate.log 2>&1; then
        cat /tmp/caddy-validate.log >&2
        rm -f /etc/caddy/Caddyfile.new
        die "Caddyfile не прошёл проверку (caddy validate), см. вывод выше"
    fi
    rm -f /tmp/caddy-validate.log
    chown -R caddy:caddy /var/log/caddy
    mv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
    systemctl enable caddy > /dev/null 2>&1
    info "применение конфигурации Caddy"
    if systemctl is-active --quiet caddy; then
        systemctl reload caddy || systemctl restart caddy
    else
        systemctl restart caddy
    fi
    sleep 1
    systemctl is-active --quiet caddy || die "Caddy не запустился: journalctl -u caddy --no-pager | tail -n 30"
    ok "Caddy: https://${SN_DOMAIN}:${SN_PANEL_PORT}/ → панель и подписка"
}

wait_caddy_cert() {
    [[ ${SN_TLS_MODE} == acme ]] || return 0
    local crt=""
    for _ in $(seq 1 45); do
        crt=$(caddy_cert_path)
        [[ -n ${crt} ]] && break
        sleep 2
    done
    if [[ -n ${crt} ]]; then
        ok "сертификат Let's Encrypt получен: ${crt}"
    else
        warn "сертификат Let's Encrypt ещё не получен (DNS? порт 80?). Caddy продолжит попытки сам;"
        warn "проверьте: journalctl -u caddy --no-pager | tail -n 30"
    fi
}

setup_caddy() {
    install_caddy
    configure_caddy
    wait_caddy_cert
}
