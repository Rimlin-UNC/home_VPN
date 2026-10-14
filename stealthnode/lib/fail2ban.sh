#!/usr/bin/env bash
# StealthNode: fail2ban — SSH (3 попытки за 10 мин → бан 24 ч), перебор пароля панели,
# recidive для повторных нарушителей. Jail 3x-ipl (лимит IP) создаёт сама 3x-ui.
# shellcheck shell=bash

setup_fail2ban() {
    local SN_F2B_SSH_PORTS SN_F2B_PANEL_PORT=${SN_PANEL_PORT} SN_F2B_IGNOREIP="127.0.0.1/8 ::1"
    SN_F2B_SSH_PORTS=$( (sshd_cmd -T 2> /dev/null || true) | awk '$1=="port" {print $2}' | sort -un | paste -sd, -)
    [[ -n ${SN_F2B_SSH_PORTS} ]] || SN_F2B_SSH_PORTS=${SN_SSH_PORT:-22}
    # SN_ADMIN_IP (из --admin-ip, хранится в .env): IP/подсети через пробел или запятую.
    [[ -n ${SN_ADMIN_IP:-} ]] && SN_F2B_IGNOREIP+=" ${SN_ADMIN_IP//,/ }"
    install -d -m 755 /var/log/x-ui
    touch /var/log/x-ui/3xui.log
    render_template "${SN_SRC}/templates/fail2ban/stealthnode.local.tmpl" /etc/fail2ban/jail.d/stealthnode.local 644 \
        SN_F2B_SSH_PORTS SN_F2B_PANEL_PORT SN_F2B_IGNOREIP
    install -m 644 "${SN_SRC}/templates/fail2ban/stealthnode-panel.conf" /etc/fail2ban/filter.d/stealthnode-panel.conf
    # 3x-ipl банит «лишний» IP клиента на всех портах, кроме SSH и панели. Панель у нас за Caddy
    # на другом порту — добавляем его в исключения, чтобы родственник мог обновить подписку.
    if [[ -f /etc/fail2ban/action.d/3x-ipl.conf ]]; then
        printf '[Init]\nexemptports = %s,%s\n' "${SN_F2B_SSH_PORTS}" "${SN_F2B_PANEL_PORT}" |
            write_if_changed /etc/fail2ban/action.d/3x-ipl.local 644 || true
    fi
    fail2ban-client -t > /dev/null || die "fail2ban: ошибка конфигурации (fail2ban-client -t)"
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban
    for _ in $(seq 1 15); do
        fail2ban-client ping > /dev/null 2>&1 && break
        sleep 1
    done
    local jails
    jails=$( (fail2ban-client status 2> /dev/null || true) | sed -n 's/.*Jail list:\s*//p')
    [[ ${jails} == *sshd* ]] || die "fail2ban: jail sshd не запустился (${jails})"
    [[ ${jails} == *stealthnode-panel* ]] || die "fail2ban: jail stealthnode-panel не запустился (${jails})"
    ok "fail2ban: ${jails}"
}
