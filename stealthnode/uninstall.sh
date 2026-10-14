#!/usr/bin/env bash
# StealthNode: удаление. По умолчанию удаляются только компоненты StealthNode
# (CLI, таймеры, конфиги fail2ban/Caddy/dnscrypt, правила UFW). Панель 3x-ui с
# пользователями и резервные копии остаются, если не указаны флаги.
#
#   sudo bash uninstall.sh                 # убрать StealthNode, оставить 3x-ui и бэкапы
#   sudo bash uninstall.sh --purge-panel   # плюс удалить 3x-ui (x-ui uninstall) и Caddy
#   sudo bash uninstall.sh --purge-all     # плюс удалить /opt/stealthnode (включая бэкапы!)
set -Eeuo pipefail

PURGE_PANEL=0
PURGE_ALL=0
for arg in "$@"; do
    case "${arg}" in
        --purge-panel) PURGE_PANEL=1 ;;
        --purge-all)
            PURGE_PANEL=1
            PURGE_ALL=1
            ;;
        -h | --help)
            sed -n '2,9p' "$0"
            exit 0
            ;;
        *)
            echo "неизвестный параметр: ${arg}" >&2
            exit 2
            ;;
    esac
done

[[ ${EUID} -eq 0 ]] || {
    echo "запустите от root" >&2
    exit 1
}

say() { printf '[StealthNode] %s\n' "$*"; }

if [[ ${PURGE_ALL} == 0 && -x /usr/local/sbin/stealthnode ]]; then
    say "резервная копия перед удалением"
    /usr/local/sbin/stealthnode backup --keep 30 || true
fi

for unit in stealthnode-backup.timer stealthnode-certsync.timer stealthnode-backup.service stealthnode-certsync.service; do
    systemctl disable --now "${unit}" > /dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${unit}"
done
systemctl daemon-reload

rm -f /etc/fail2ban/jail.d/stealthnode.local /etc/fail2ban/filter.d/stealthnode-panel.conf /etc/fail2ban/action.d/3x-ipl.local
systemctl restart fail2ban > /dev/null 2>&1 || true

# Правила UFW с комментарием StealthNode (кроме SSH — чтобы не потерять доступ).
while read -r num; do
    yes | ufw delete "${num}" > /dev/null 2>&1 || true
done < <(ufw status numbered 2> /dev/null | grep 'StealthNode' | grep -v 'SSH' | grep -oP '^\[\s*\K[0-9]+' | sort -rn)

rm -f /usr/local/sbin/stealthnode /etc/sysctl.d/99-stealthnode.conf /etc/modules-load.d/stealthnode-bbr.conf \
    /etc/systemd/journald.conf.d/stealthnode.conf /etc/apt/apt.conf.d/52stealthnode-unattended

if [[ ${PURGE_PANEL} == 1 ]]; then
    say "удаление 3x-ui и Caddy"
    if command -v x-ui > /dev/null; then
        printf 'y\n' | x-ui uninstall > /dev/null 2>&1 || true
    fi
    systemctl disable --now caddy > /dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get -y -q purge caddy > /dev/null 2>&1 || true
fi

if [[ ${PURGE_ALL} == 1 ]]; then
    say "удаление /opt/stealthnode и учётных данных"
    rm -rf /opt/stealthnode /root/stealthnode-credentials.txt
else
    say "оставлено: /opt/stealthnode (параметры, профили, бэкапы), /root/stealthnode-credentials.txt"
fi
say "готово"
