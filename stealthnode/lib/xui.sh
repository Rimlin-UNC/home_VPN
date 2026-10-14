#!/usr/bin/env bash
# StealthNode: установка и базовая настройка панели 3X-UI.
# Используется официальный установщик 3x-ui с git-тега (версия закреплена в versions.env,
# скрипт проверяется по SHA256, архив релиза он сам проверяет по .sha256 из релиза).
# shellcheck shell=bash

XUI_BIN=/usr/local/x-ui/x-ui
XUI_DB=/etc/x-ui/x-ui.db
XUI_FRESH_INSTALL=0

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
    # Чистая панель (базы ещё нет) — только ей configure_xui задаёт логин/пароль из .env.
    [[ -f ${XUI_DB} ]] || XUI_FRESH_INSTALL=1
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

# Логин/пароль из .env задаются только чистой панели или стандартным admin/admin.
# Пароль, который владелец сменил в веб-интерфейсе, повторный запуск НЕ сбрасывает
# (до 2.0.1 сбрасывал — после смены пароля в панели и повторного install.sh вход «ломался»).
# Сверка идёт по bcrypt-хешу в БД, без попытки входа (лимит 3x-ui и fail2ban не задеваются).
apply_panel_credentials() {
    local state
    state=$(sn_cli panel-password --state 2> /dev/null | tail -n1 || true)
    case ${state} in
        match)
            ok "логин/пароль панели совпадают с ${SN_ROOT}/.env"
            return 0
            ;;
        default | missing) ;;
        *)
            # changed, unknown или сбой проверки: чужой пароль не трогаем (кроме чистой панели).
            if [[ ${XUI_FRESH_INSTALL} != 1 ]]; then
                if [[ ${state} == changed ]]; then
                    info "логин/пароль панели изменены в веб-интерфейсе — оставляем как есть"
                else
                    warn "не удалось сверить пароль панели с .env — оставляем как есть"
                fi
                info "забыли пароль или не пускает: sudo stealthnode panel-password"
                return 0
            fi
            state=fresh
            ;;
    esac
    # default (admin/admin), missing (нет администратора) или только что установленная панель.
    "${XUI_BIN}" setting -username "${SN_XUI_USERNAME}" -password "${SN_XUI_PASSWORD}" > /dev/null
    ok "логин/пароль панели заданы из ${SN_ROOT}/.env (${state})"
}

configure_xui() {
    # Панель слушает только 127.0.0.1; наружу её публикует Caddy по HTTPS.
    systemctl stop x-ui
    "${XUI_BIN}" setting -listenIP 127.0.0.1 -port "${SN_XUI_PORT}" -webBasePath "${SN_PANEL_PATH}" > /dev/null
    apply_panel_credentials
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
