#!/usr/bin/env bash
# StealthNode: dnscrypt-proxy — шифрованный DNS для Xray (127.0.2.1:53, socket activation).
# Системный резолвер сервера не трогаем; Xray ходит в dnscrypt-proxy напрямую
# (tcp+local://127.0.2.1:53), а при его сбое — в DoH 1.1.1.1.
# shellcheck shell=bash

setup_dnscrypt() {
    local cfg=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
    if write_if_changed "${cfg}" 644 < "${SN_SRC}/templates/dnscrypt-proxy.toml"; then
        info "конфигурация dnscrypt-proxy обновлена"
    fi
    systemctl enable dnscrypt-proxy.socket > /dev/null 2>&1 || true
    systemctl restart dnscrypt-proxy.socket 2> /dev/null || true
    systemctl restart dnscrypt-proxy 2> /dev/null || true
    local answer=""
    for _ in $(seq 1 30); do
        answer=$(dig +short +time=2 +tries=1 @127.0.2.1 example.com A 2> /dev/null | grep -E '^[0-9.]+$' | head -n1 || true)
        [[ -n ${answer} ]] && break
        sleep 2
    done
    if [[ -n ${answer} ]]; then
        ok "dnscrypt-proxy отвечает (example.com → ${answer})"
    else
        warn "dnscrypt-proxy пока не отвечает — Xray временно использует резервный DoH; проверьте: journalctl -u dnscrypt-proxy"
    fi
}
