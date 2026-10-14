#!/usr/bin/env bash
# StealthNode: файрвол UFW. Наружу открыты только нужные порты;
# внутренние порты панели 3x-ui и сервера подписки НЕ открываются (они на 127.0.0.1).
# shellcheck shell=bash

# Порты, на которых sshd реально слушает сейчас (чтобы не отрезать себе доступ).
current_ssh_ports() {
    {
        ss -Hltnp 2> /dev/null | awk '/"sshd"|"systemd"/ && /:22 |sshd/ {print $4}' | grep -oE '[0-9]+$' || true
        sshd_cmd -T 2> /dev/null | awk '$1=="port" {print $2}' || true
    } | sort -un
}

ufw_allow() {
    local rule=$1 comment=$2 action=${3:-allow}
    ufw "${action}" "${rule}" comment "${comment}" > /dev/null
}

setup_ufw() {
    local p ssh_ports
    ssh_ports=$( (
        current_ssh_ports
        echo "${SN_SSH_PORT}"
    ) | sort -un)
    ufw --force default deny incoming > /dev/null
    ufw --force default allow outgoing > /dev/null
    for p in ${ssh_ports}; do
        is_port "${p}" || continue
        # limit: не более 6 подключений за 30 с с одного IP (в дополнение к fail2ban).
        ufw_allow "${p}/tcp" "StealthNode SSH" limit
        info "UFW: SSH ${p}/tcp (limit)"
    done
    ufw_allow "80/tcp" "StealthNode ACME HTTP-01 (Caddy)"
    ufw_allow "${SN_XHTTP_PORT}/tcp" "StealthNode VLESS XHTTP REALITY"
    ufw_allow "${SN_VISION_PORT}/tcp" "StealthNode VLESS TCP REALITY Vision"
    ufw_allow "${SN_HY2_PORT}/udp" "StealthNode Hysteria2"
    ufw_allow "${SN_PANEL_PORT}/tcp" "StealthNode panel HTTPS (Caddy)"
    ufw --force enable > /dev/null
    ufw reload > /dev/null
    ok "UFW: открыты SSH, 80/tcp, ${SN_XHTTP_PORT}/tcp, ${SN_VISION_PORT}/tcp, ${SN_HY2_PORT}/udp, ${SN_PANEL_PORT}/tcp"
}
