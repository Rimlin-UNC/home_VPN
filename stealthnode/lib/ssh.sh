#!/usr/bin/env bash
# StealthNode: усиление SSH (по флагам). Защита от потери доступа:
#  * вход только по ключам включается, лишь если ключ уже лежит в authorized_keys;
#  * при смене порта старый 22 остаётся открытым до явного --ssh-close-22.
# В Ubuntu 24.04 sshd запускается через ssh.socket, поэтому порт меняется и в
# сокет-юните (drop-in), иначе смена Port в sshd_config не подействует.
# shellcheck shell=bash

SSHD_DROPIN=/etc/ssh/sshd_config.d/00-stealthnode.conf
SSH_SOCKET_DROPIN=/etc/systemd/system/ssh.socket.d/stealthnode.conf

has_authorized_key() {
    local f user home
    for user in root "${SUDO_USER:-}"; do
        [[ -n ${user} ]] || continue
        home=$(getent passwd "${user}" | cut -d: -f6)
        f="${home}/.ssh/authorized_keys"
        if [[ -s ${f} ]] && grep -qE '^(ssh-(ed25519|rsa)|ecdsa-sha2-|sk-ssh-ed25519|sk-ecdsa-sha2-)' "${f}"; then
            return 0
        fi
    done
    return 1
}

ssh_uses_socket() {
    systemctl is-enabled ssh.socket > /dev/null 2>&1 || systemctl is-active ssh.socket > /dev/null 2>&1
}

apply_ssh_config() {
    local ports=$1 keys_only=$2 content p
    content="# StealthNode: управляется install.sh (не редактируйте вручную)\n"
    for p in ${ports}; do content+="Port ${p}\n"; done
    if [[ ${keys_only} == 1 ]]; then
        content+="PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        content+="PermitRootLogin prohibit-password\n"
    fi
    content+="MaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\n"
    printf '%b' "${content}" | write_if_changed "${SSHD_DROPIN}" 644 || true
    sshd_cmd -t || die "sshd -t: ошибка в конфигурации SSH (файл ${SSHD_DROPIN})"
    if ssh_uses_socket; then
        # Порты задаёт сокет-юнит; служба получает слушающие сокеты от него при запуске.
        local sock="[Socket]\nListenStream=\n"
        for p in ${ports}; do sock+="ListenStream=${p}\n"; done
        printf '%b' "${sock}" | write_if_changed "${SSH_SOCKET_DROPIN}" 644 || true
        systemctl daemon-reload
        systemctl restart ssh.socket
        # Текущие SSH-сессии при этом не обрываются (у каждой свой процесс sshd).
        if systemctl is-active --quiet ssh.service; then
            systemctl restart ssh.service
        fi
    else
        systemctl restart ssh 2> /dev/null || systemctl restart sshd
    fi
}

setup_ssh() {
    local want_port=${SN_SSH_PORT:-22} keys_only=${SN_SSH_KEYS_ONLY:-${OPT_SSH_KEYS_ONLY:-0}} ports
    if [[ ${keys_only} == 1 ]] && ! has_authorized_key; then
        die "--ssh-keys-only: в authorized_keys нет ни одного ключа — сначала добавьте ключ (ssh-copy-id), иначе потеряете доступ"
    fi
    if [[ ${want_port} == 22 ]]; then
        ports=22
    elif [[ ${SN_SSH_CLOSE_22:-${OPT_SSH_CLOSE_22:-0}} == 1 ]]; then
        ports=${want_port}
    else
        ports="22 ${want_port}"
    fi
    if [[ ${keys_only} == 0 && ${want_port} == 22 && ! -f ${SSHD_DROPIN} ]]; then
        info "SSH не меняется (опции --ssh-keys-only / --ssh-port не заданы)"
        return 0
    fi
    apply_ssh_config "${ports}" "${keys_only}"
    if [[ ${ports} == "${want_port}" && ${want_port} != 22 ]]; then
        ufw delete limit 22/tcp > /dev/null 2>&1 || true
        ufw delete allow 22/tcp > /dev/null 2>&1 || true
        info "UFW: правило для 22/tcp удалено"
    fi
    ok "SSH: порты ${ports}$([[ ${keys_only} == 1 ]] && echo ', вход только по ключам')"
    if [[ ${ports} == "22 ${want_port}" ]]; then
        warn "SSH слушает 22 и ${want_port}. Проверьте вход: ssh -p ${want_port} root@${SN_PUBLIC_IP:-<IP>}"
        warn "затем закройте 22: sudo bash install.sh --ssh-port ${want_port} --ssh-close-22"
    fi
}
