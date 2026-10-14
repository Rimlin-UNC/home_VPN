#!/usr/bin/env bats
# Тесты функций установщика, которые не требуют root и сети.

setup() {
    REPO="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
    export NO_COLOR=1
    # shellcheck source=../../stealthnode/lib/common.sh
    source "${REPO}/stealthnode/lib/common.sh"
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "${TMP}"
}

@test "is_port принимает 1..65535 и отвергает мусор" {
    is_port 1
    is_port 443
    is_port 65535
    ! is_port 0
    ! is_port 65536
    ! is_port abc
    ! is_port ""
}

@test "is_ipv4" {
    is_ipv4 203.0.113.7
    ! is_ipv4 256.1.1.1
    ! is_ipv4 1.2.3
    ! is_ipv4 "1.2.3.4 "
}

@test "render_template подставляет только перечисленные переменные" {
    printf 'a=${SN_A} keep=${distro_id} b=${SN_B}\n' > "${TMP}/t.tmpl"
    SN_A=1 SN_B="два" render_template "${TMP}/t.tmpl" "${TMP}/out" 600 SN_A SN_B
    run cat "${TMP}/out"
    [ "${output}" = 'a=1 keep=${distro_id} b=два' ]
    run stat -c %a "${TMP}/out"
    [ "${output}" = "600" ]
}

@test "render_template: многострочные значения и спецсимволы буквально" {
    printf 'x {\n\t${SN_BLOCK}\n}\n' > "${TMP}/t.tmpl"
    SN_BLOCK=$'tls {\n\t\tissuer & \\1 $HOME\n\t}' render_template "${TMP}/t.tmpl" "${TMP}/out" 644 SN_BLOCK
    run cat "${TMP}/out"
    [ "${output}" = $'x {\n\ttls {\n\t\tissuer & \\1 $HOME\n\t}\n}' ]
}

@test "render_template падает на незаданной переменной" {
    printf '${SN_NOPE}\n' > "${TMP}/t.tmpl"
    unset SN_NOPE
    run render_template "${TMP}/t.tmpl" "${TMP}/out" 600 SN_NOPE
    [ "${status}" -ne 0 ]
}

@test "write_if_changed сообщает об изменении" {
    run bash -c "source '${REPO}/stealthnode/lib/common.sh'; echo x | write_if_changed '${TMP}/f' 640"
    [ "${status}" -eq 0 ]
    run bash -c "source '${REPO}/stealthnode/lib/common.sh'; echo x | write_if_changed '${TMP}/f' 640"
    [ "${status}" -eq 1 ]
    run stat -c %a "${TMP}/f"
    [ "${output}" = "640" ]
}

@test "retry повторяет и сдаётся" {
    run retry 3 0 false
    [ "${status}" -eq 1 ]
    calls=0
    flaky() {
        calls=$((calls + 1))
        ((calls >= 2))
    }
    retry 3 0 flaky
    [ "${calls}" -eq 2 ]
}

@test "install.sh --help работает без root" {
    run bash "${REPO}/stealthnode/install.sh" --help
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"--domain"* ]]
    [[ "${output}" == *"--ssh-keys-only"* ]]
}

@test "install.sh отвергает неизвестный параметр и плохой домен" {
    run bash "${REPO}/stealthnode/install.sh" --bogus
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"неизвестный параметр"* ]]
    run bash "${REPO}/stealthnode/install.sh" --domain "bad domain"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"некорректный домен"* ]]
    run bash "${REPO}/stealthnode/install.sh" --tls wrong
    [ "${status}" -ne 0 ]
}

@test "шаблон unattended-upgrades сохраняет переменные apt" {
    SN_REBOOT=true SN_REBOOT_TIME=01:30 render_template \
        "${REPO}/stealthnode/templates/apt-52stealthnode-unattended.tmpl" "${TMP}/u" 644 SN_REBOOT SN_REBOOT_TIME
    grep -q '${distro_id}:${distro_codename}-security' "${TMP}/u"
    grep -q 'Automatic-Reboot "true"' "${TMP}/u"
}

@test "CLI-обёртка запускает пакет из репозитория" {
    run env SN_APP_DIR="${REPO}/stealthnode" bash "${REPO}/stealthnode/bin/stealthnode" version
    [ "${status}" -eq 0 ]
    [ "${output}" = "$(cat "${REPO}/VERSION")" ]
}

# --- пароль панели: повторный install.sh не сбрасывает пароль, изменённый в веб-интерфейсе ---

# Заглушки: sn_cli печатает состояние из STATE, «x-ui» записывает аргументы в журнал.
panel_stubs() {
    # shellcheck source=../../stealthnode/lib/xui.sh
    source "${REPO}/stealthnode/lib/xui.sh"
    XUI_BIN="${TMP}/x-ui"
    printf '#!/bin/sh\necho "$@" >> "%s/x-ui.calls"\n' "${TMP}" > "${XUI_BIN}"
    chmod +x "${XUI_BIN}"
    SN_ROOT="${TMP}"
    SN_XUI_USERNAME=snowner
    SN_XUI_PASSWORD='p@ss w0rd'
    sn_cli() {
        [ "$*" = "panel-password --state" ] || return 9
        [ -n "${STATE_FAIL:-}" ] && { echo "[ОШИБ] traceback"; return 1; }
        echo "${STATE}"
    }
}

@test "пароль панели: совпадает с .env — x-ui не вызывается" {
    panel_stubs
    STATE=match XUI_FRESH_INSTALL=0 apply_panel_credentials
    [ ! -e "${TMP}/x-ui.calls" ]
}

@test "пароль панели: изменён в веб-интерфейсе — повторный запуск его не трогает" {
    panel_stubs
    STATE=changed XUI_FRESH_INSTALL=0 run apply_panel_credentials
    [ "${status}" -eq 0 ]
    [[ ${output} == *"изменены в веб-интерфейсе"* ]]
    [[ ${output} == *"stealthnode panel-password"* ]]
    [ ! -e "${TMP}/x-ui.calls" ]
}

@test "пароль панели: сбой проверки или неизвестное состояние — тоже не трогаем" {
    panel_stubs
    STATE=unknown XUI_FRESH_INSTALL=0 apply_panel_credentials
    STATE_FAIL=1 XUI_FRESH_INSTALL=0 apply_panel_credentials
    STATE=garbage XUI_FRESH_INSTALL=0 apply_panel_credentials
    [ ! -e "${TMP}/x-ui.calls" ]
}

@test "пароль панели: admin/admin, пустая БД и чистая установка — задаётся из .env" {
    panel_stubs
    STATE=default XUI_FRESH_INSTALL=0 apply_panel_credentials
    STATE=missing XUI_FRESH_INSTALL=0 apply_panel_credentials
    STATE=changed XUI_FRESH_INSTALL=1 apply_panel_credentials
    STATE_FAIL=1 XUI_FRESH_INSTALL=1 apply_panel_credentials
    run cat "${TMP}/x-ui.calls"
    [ "${#lines[@]}" -eq 4 ]
    [ "${lines[0]}" = "setting -username snowner -password p@ss w0rd" ]
}

# --- связка «мост в РФ → выход за рубежом» ---

@test "install.sh: параметры связки проверяются до любых изменений" {
    run bash "${REPO}/stealthnode/install.sh" --exit-for not-an-ip
    [ "${status}" -ne 0 ]
    [[ ${output} == *"--exit-for"* ]]
    run bash "${REPO}/stealthnode/install.sh" --exit-link 'https://example.com/'
    [ "${status}" -ne 0 ]
    [[ ${output} == *"vless://"* ]]
    run bash "${REPO}/stealthnode/install.sh" --exit-for 31.59.126.178 --exit-link 'vless://u@95.182.99.147:40001'
    [ "${status}" -ne 0 ]
    [[ ${output} == *"на разных серверах"* ]]
    run bash "${REPO}/stealthnode/install.sh" --help
    [[ ${output} == *"--exit-link"* && ${output} == *"--exit-for"* && ${output} == *"--no-ru-direct"* ]]
}
