#!/usr/bin/env bash
# StealthNode: установка и базовая настройка панели 3X-UI.
# Используется официальный установщик 3x-ui с git-тега (версия закреплена в versions.env,
# скрипт проверяется по SHA256, архив релиза он сам проверяет по .sha256 из релиза).
# shellcheck shell=bash

XUI_BIN=/usr/local/x-ui/x-ui

xui_installed_version() {
    [[ -x ${XUI_BIN} ]] || return 1
    "${XUI_BIN}" -v 2> /dev/null | tr -d '[:space:]v' || true
}

install_xui() {
    local have
    have=$(xui_installed_version || true)
    if [[ -n ${have} && ${have} == "${XUI_VERSION#v}" && ${OPT_REINSTALL_XUI:-0} != 1 ]]; then
        ok "3x-ui ${XUI_VERSION} уже установлена"
        return 0
    fi
    [[ -n ${have} ]] && info "установлена 3x-ui ${have}, ставим ${XUI_VERSION}"
    local script
    script=$(mktemp /tmp/xui-install.XXXXXX.sh)
    retry 3 10 curl -fsSL --max-time 120 -o "${script}" "${XUI_INSTALL_URL}" ||
        die "не удалось скачать установщик 3x-ui (${XUI_INSTALL_URL})"
    local sum
    sum=$(sha256sum "${script}" | awk '{print $1}')
    [[ ${sum} == "${XUI_INSTALL_SHA256}" ]] ||
        die "SHA256 установщика 3x-ui не совпадает: ${sum} (ожидалось ${XUI_INSTALL_SHA256})"
    ok "установщик 3x-ui ${XUI_VERSION} проверен (SHA256)"
    # Неинтерактивный режим: данные панели — наши, SSL выключен (HTTPS делает Caddy).
    XUI_NONINTERACTIVE=1 \
        XUI_USERNAME="${SN_XUI_USERNAME}" \
        XUI_PASSWORD="${SN_XUI_PASSWORD}" \
        XUI_PANEL_PORT="${SN_XUI_PORT}" \
        XUI_WEB_BASE_PATH="${SN_PANEL_PATH}" \
        XUI_SSL_MODE=none \
        XUI_DB_TYPE=sqlite \
        XUI_ENABLE_FAIL2BAN=true \
        bash "${script}" "${XUI_VERSION}" < /dev/null 2>&1 |
        sed -E 's/(Password|Пароль|password|apiToken|API Token)([^:]*):.*/\1\2: ***скрыто***/' ||
        die "установщик 3x-ui завершился с ошибкой"
    rm -f "${script}"
    have=$(xui_installed_version || true)
    [[ ${have} == "${XUI_VERSION#v}" ]] || die "после установки 3x-ui версия ${have:-неизвестна}, ожидалась ${XUI_VERSION}"
    ok "3x-ui ${XUI_VERSION} установлена"
}

xui_api_ok() {
    curl -fsS --max-time 5 -H "Authorization: Bearer ${SN_XUI_API_TOKEN}" \
        "http://127.0.0.1:${SN_XUI_PORT}/${SN_PANEL_PATH}/panel/api/server/status" > /dev/null 2>&1
}

# Дождаться, пока панель начнёт отвечать по HTTP (любым кодом).
wait_xui_port() {
    for _ in $(seq 1 60); do
        curl -s -o /dev/null --max-time 3 "http://127.0.0.1:${SN_XUI_PORT}/" && return 0
        sleep 2
    done
    return 1
}

configure_xui() {
    # Панель слушает только 127.0.0.1; наружу её публикует Caddy по HTTPS.
    systemctl stop x-ui
    "${XUI_BIN}" setting -listenIP 127.0.0.1 -port "${SN_XUI_PORT}" -webBasePath "${SN_PANEL_PATH}" \
        -username "${SN_XUI_USERNAME}" -password "${SN_XUI_PASSWORD}" > /dev/null
    if [[ -n ${OPT_TG_TOKEN:-} && -n ${OPT_TG_CHAT:-} ]]; then
        "${XUI_BIN}" setting -tgbottoken "${OPT_TG_TOKEN}" -tgbotchatid "${OPT_TG_CHAT}" -enabletgbot > /dev/null
        ok "Telegram-бот 3x-ui включён (чат ${OPT_TG_CHAT})"
    fi
    systemctl enable x-ui > /dev/null 2>&1
    systemctl start x-ui
    wait_xui_port || die "панель 3x-ui не запустилась (journalctl -u x-ui)"
    load_env
    if [[ -z ${SN_XUI_API_TOKEN:-} ]] || ! xui_api_ok; then
        local out token
        out=$("${XUI_BIN}" setting -tokenName stealthnode -tokenScope admin -getApiToken 2>&1)
        token=$(grep -oP 'apiToken:\s*\K\S+' <<< "${out}" || true)
        [[ -n ${token} ]] || die "не удалось выпустить API-токен 3x-ui: ${out}"
        sn_cli env set "SN_XUI_API_TOKEN=${token}"
        load_env
        retry 10 2 xui_api_ok || die "API панели 3x-ui не отвечает (http://127.0.0.1:${SN_XUI_PORT}/${SN_PANEL_PATH}/)"
    fi
    ok "панель 3x-ui: 127.0.0.1:${SN_XUI_PORT}, API-токен работает"
}
