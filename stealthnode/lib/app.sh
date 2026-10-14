#!/usr/bin/env bash
# StealthNode: установка CLI `stealthnode`, параметры (.env), провижининг панели, таймеры.
# shellcheck shell=bash

install_app() {
    install -d -m 700 "${SN_ROOT}" "${SN_ROOT}/users" "${SN_ROOT}/backups" "${SN_ROOT}/xray" "${SN_ROOT}/xray/share" \
        "${SN_ROOT}/hysteria" "${SN_ROOT}/caddy"
    install -d -m 755 "${SN_APP_DIR}"
    rm -rf "${SN_APP_DIR}/python.new"
    cp -a "${SN_SRC}/python" "${SN_APP_DIR}/python.new"
    find "${SN_APP_DIR}/python.new" -name '__pycache__' -type d -prune -exec rm -rf {} +
    rm -rf "${SN_APP_DIR}/python"
    mv "${SN_APP_DIR}/python.new" "${SN_APP_DIR}/python"
    rm -rf "${SN_APP_DIR}/templates"
    cp -a "${SN_SRC}/templates" "${SN_APP_DIR}/templates"
    install -m 644 "${SN_SRC}/versions.env" "${SN_APP_DIR}/versions.env"
    install -m 644 "${SN_SRC}/../VERSION" "${SN_ROOT}/VERSION"
    install -m 755 "${SN_SRC}/bin/stealthnode" /usr/local/sbin/stealthnode
    chmod -R go-w "${SN_APP_DIR}"
    ok "CLI установлен: /usr/local/sbin/stealthnode ($(sn_cli version))"
}

init_env() {
    local args=()
    [[ -n ${OPT_RESTORE:-} ]] && sn_cli restore --env-only "${OPT_RESTORE}"
    args+=("SN_DOMAIN=${SN_DOMAIN_ARG}")
    args+=("SN_PUBLIC_IP=${SN_PUBLIC_IP}")
    args+=("SN_FREEDOM_STRATEGY=${SN_FREEDOM_STRATEGY}")
    [[ -n ${OPT_EMAIL:-} ]] && args+=("SN_ACME_EMAIL=${OPT_EMAIL}")
    [[ -n ${OPT_TLS_MODE:-} ]] && args+=("SN_TLS_MODE=${OPT_TLS_MODE}")
    [[ -n ${OPT_SNI:-} ]] && args+=("SN_REALITY_SNI=${OPT_SNI}" "SN_REALITY_TARGET=${OPT_TARGET:-${OPT_SNI}:443}")
    [[ -z ${OPT_SNI:-} && -n ${OPT_TARGET:-} ]] && args+=("SN_REALITY_TARGET=${OPT_TARGET}")
    [[ -n ${OPT_SSH_PORT:-} ]] && args+=("SN_SSH_PORT=${OPT_SSH_PORT}")
    # SSH-опции запоминаются: повторный запуск без флагов не должен ослабить защиту.
    [[ ${OPT_SSH_KEYS_ONLY:-0} == 1 ]] && args+=("SN_SSH_KEYS_ONLY=1")
    [[ ${OPT_SSH_CLOSE_22:-0} == 1 ]] && args+=("SN_SSH_CLOSE_22=1")
    # IP владельца для исключений fail2ban тоже запоминается (раньше терялся при повторном запуске).
    [[ -n ${OPT_ADMIN_IP:-} ]] && args+=("SN_ADMIN_IP=${OPT_ADMIN_IP}")
    # Связка «мост → выход» (docs/RELAY.md): роль сервера запоминается.
    [[ -n ${OPT_EXIT_FOR:-} ]] && args+=("SN_EXIT_BRIDGE_IP=${OPT_EXIT_FOR}")
    [[ -n ${OPT_EXIT_LINK:-} ]] && args+=("SN_BRIDGE_EXIT_LINK=${OPT_EXIT_LINK}")
    [[ ${OPT_NO_RU_DIRECT:-0} == 1 ]] && args+=("SN_BRIDGE_RU_DIRECT=0")
    [[ -n ${OPT_PANEL_PORT:-} ]] && args+=("SN_PANEL_PORT=${OPT_PANEL_PORT}")
    [[ -n ${OPT_HY2_PORT:-} ]] && args+=("SN_HY2_PORT=${OPT_HY2_PORT}")
    [[ -n ${OPT_LIMIT_GB:-} ]] && args+=("SN_DEFAULT_LIMIT_GB=${OPT_LIMIT_GB}")
    [[ -n ${OPT_IP_LIMIT:-} ]] && args+=("SN_DEFAULT_IP_LIMIT=${OPT_IP_LIMIT}")
    sn_cli env init "${args[@]}"
    load_env
}

run_provision() {
    local args=() u
    for u in "${OPT_USERS[@]}"; do args+=(--user "${u}"); done
    if [[ -n ${OPT_RESTORE:-} ]]; then
        info "восстановление базы панели и профилей из ${OPT_RESTORE}"
        # .env уже восстановлен в init_env и дополнен параметрами ЭТОГО сервера (IP, роль в связке):
        # повторное восстановление вернуло бы IP старого сервера и стёрло --exit-link.
        sn_cli restore --no-env "${OPT_RESTORE}"
        sn_cli token-rotate
        load_env
    fi
    sn_cli provision "${args[@]}"
}

setup_timers() {
    local unit
    for unit in stealthnode-backup.service stealthnode-backup.timer stealthnode-certsync.service stealthnode-certsync.timer; do
        install -m 644 "${SN_SRC}/templates/systemd/${unit}" "/etc/systemd/system/${unit}"
    done
    systemctl daemon-reload
    systemctl enable --now stealthnode-backup.timer stealthnode-certsync.timer > /dev/null 2>&1
    ok "таймеры: ежедневная резервная копия (хранится 14), синхронизация сертификата Hysteria2"
}

final_summary() {
    load_env
    local owner_sub
    owner_sub=$(grep -A1 'Подписка владельца' /root/stealthnode-credentials.txt 2> /dev/null | tail -n1 || true)
    printf '\n%s================ StealthNode установлен ================%s\n' "${C_BOLD}" "${C_OFF}"
    printf 'Панель 3X-UI:  https://%s:%s/%s/\n' "${SN_DOMAIN}" "${SN_PANEL_PORT}" "${SN_PANEL_PATH}"
    printf 'Логин/пароль:  в файле /root/stealthnode-credentials.txt (права 600)\n'
    printf 'Подписка владельца: %s\n' "${owner_sub:-см. файл учётных данных}"
    printf 'Профили и QR:  %s/users/<имя>/\n' "${SN_ROOT}"
    printf 'Проверка:      stealthnode doctor --e2e\n'
    printf 'Пользователи:  stealthnode user add mama   (по умолчанию %s ГБ/мес, %s IP)\n' \
        "${SN_DEFAULT_LIMIT_GB}" "${SN_DEFAULT_IP_LIMIT}"
    printf 'Журнал:        %s\n' "${SN_LOG_FILE}"
    if [[ -n ${SN_BRIDGE_EXIT_LINK:-} ]]; then
        printf 'Роль:          мост (РФ) → выход %s\n' "$(sed -E 's#^vless://[^@]*@([^?]+).*#\1#' <<< "${SN_BRIDGE_EXIT_LINK}")"
    fi
    if [[ -n ${SN_EXIT_BRIDGE_IP:-} ]]; then
        printf 'Роль:          выход для моста %s (порт %s/tcp)\n' "${SN_EXIT_BRIDGE_IP}" "${SN_EXIT_PORT:-?}"
        printf 'Ссылка выхода: sudo stealthnode exit link   (для install.sh --exit-link на мосту)\n'
    fi
    printf '%s=========================================================%s\n' "${C_BOLD}" "${C_OFF}"
}
