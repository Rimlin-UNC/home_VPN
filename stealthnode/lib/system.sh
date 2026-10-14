#!/usr/bin/env bash
# StealthNode: пакеты, ядро (BBR, sysctl), swap, автообновления, журнал.
# shellcheck shell=bash

SN_PACKAGES=(
    ca-certificates curl gnupg openssl iproute2 procps
    python3 qrencode sqlite3 dnsutils tar gzip
    ufw fail2ban python3-systemd nftables
    unattended-upgrades apt-listchanges
    dnscrypt-proxy
    debian-keyring debian-archive-keyring apt-transport-https
)

system_packages() {
    retry 3 15 apt_get update
    if [[ ${OPT_SKIP_UPGRADE:-0} == 1 ]]; then
        info "обновление установленных пакетов пропущено (--skip-upgrade)"
    else
        info "обновление системы (apt upgrade) — может занять несколько минут"
        retry 2 15 apt_get upgrade
    fi
    apt_install "${SN_PACKAGES[@]}"
    # nftables ставится ради бинарника nft (fail2ban), но службу НЕ включаем:
    # её `flush ruleset` при загрузке стёр бы правила UFW.
    systemctl disable --now nftables.service > /dev/null 2>&1 || true
    ok "пакеты установлены"
}

system_tuning() {
    install -m 644 "${SN_SRC}/templates/sysctl-99-stealthnode.conf" /etc/sysctl.d/99-stealthnode.conf
    printf 'tcp_bbr\n' | write_if_changed /etc/modules-load.d/stealthnode-bbr.conf 644 || true
    modprobe tcp_bbr 2> /dev/null || true
    sysctl --system > /dev/null
    local cc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ ${cc} == bbr ]]; then
        ok "TCP BBR включён (очередь $(sysctl -n net.core.default_qdisc))"
    else
        warn "BBR не включился (сейчас ${cc}); ядро без модуля tcp_bbr?"
    fi
    setup_swap
    install -D -m 644 "${SN_SRC}/templates/journald-stealthnode.conf" /etc/systemd/journald.conf.d/stealthnode.conf
    systemctl restart systemd-journald || true
    timedatectl set-ntp true 2> /dev/null || true
}

setup_swap() {
    if swapon --noheadings --show=NAME | grep -q .; then
        info "swap уже есть: $(swapon --noheadings --show=NAME,SIZE | xargs)"
        return 0
    fi
    if ((${SN_MEM_MB:-4096} >= 2000)); then
        info "RAM ≥ 2 ГБ — swap не нужен"
        return 0
    fi
    local size_mb=1024
    ((SN_MEM_MB < 1000)) && size_mb=2048
    if [[ ! -f /swapfile ]]; then
        fallocate -l "${size_mb}M" /swapfile 2> /dev/null || dd if=/dev/zero of=/swapfile bs=1M count="${size_mb}" status=none
        chmod 600 /swapfile
        mkswap /swapfile > /dev/null
    fi
    swapon /swapfile 2> /dev/null || {
        warn "swapon не удался (контейнерная виртуализация?) — пропускаем"
        return 0
    }
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    ok "создан swap ${size_mb} МБ (/swapfile)"
}

setup_unattended() {
    install -m 644 "${SN_SRC}/templates/apt-20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
    local SN_REBOOT="false" SN_REBOOT_TIME="${OPT_REBOOT_TIME:-01:30}"
    [[ ${OPT_AUTO_REBOOT:-1} == 1 ]] && SN_REBOOT="true"
    render_template "${SN_SRC}/templates/apt-52stealthnode-unattended.tmpl" \
        /etc/apt/apt.conf.d/52stealthnode-unattended 644 SN_REBOOT SN_REBOOT_TIME
    systemctl enable --now unattended-upgrades > /dev/null 2>&1 || true
    if [[ ${SN_REBOOT} == true ]]; then
        ok "автообновления безопасности включены (перезагрузка при необходимости в ${SN_REBOOT_TIME} UTC)"
    else
        ok "автообновления безопасности включены (без автоматической перезагрузки)"
    fi
}
