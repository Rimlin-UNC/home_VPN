#!/usr/bin/env bash
# ============================================================
# StealthNode — переконфигурация УЖЕ установленного сервера.
# Запускать от root из каталога проекта: sudo ./setup.sh
#
# Позволяет:
#   * сменить пароль администратора панели;
#   * сменить домен маскировки REALITY (с перезапуском Xray);
#   * показать итоговую информацию и QR конфига владельца.
# Первичная установка — ТОЛЬКО через install.sh!
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'; C_RST=$'\033[0m'
ok()   { echo "${C_GRN}[+]${C_RST} $*"; }
warn() { echo "${C_YLW}[!]${C_RST} $*"; }
die()  { echo "${C_RED}[x] ОШИБКА:${C_RST} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускайте от root: sudo ./setup.sh"
[[ -f .env ]] || die ".env не найден — сначала выполните установку (install.sh)"

# Безопасный разбор .env без eval (значения могут содержать спецсимволы)
while IFS='=' read -r _k _v; do
    [[ "$_k" =~ ^[A-Z_]+$ ]] && export "$_k=$_v"
done < <(grep -E '^[A-Z_]+=' .env || true)

echo
echo "Что настроить?"
echo "  1) Сменить пароль администратора панели"
echo "  2) Сменить домен маскировки REALITY"
echo "  3) Показать данные доступа и QR конфига владельца"
echo "  4) Выход"
read -rp "Выбор [3]: " CHOICE
CHOICE="${CHOICE:-3}"

case "$CHOICE" in
  1)
    # --- Смена пароля через CLI бэкенда (Argon2id, отзыв сессий) ---
    while true; do
        read -rsp "Новый пароль (мин. 16 символов): " P1; echo
        [[ ${#P1} -ge 16 ]] && break
        warn "Минимум 16 символов"
    done
    read -rsp "Повторите: " P2; echo
    [[ "$P1" == "$P2" ]] || die "Пароли не совпадают"
    docker compose exec -T backend python -m app.utils.setpassword "$P1" \
        && ok "Пароль изменён, все сессии завершены"
    ;;

  2)
    # --- Смена домена маскировки: правим config.json и .env, рестарт Xray ---
    read -rp "Новый домен маскировки [$REALITY_SNI]: " NEW_SNI
    NEW_SNI="${NEW_SNI:-$REALITY_SNI}"
    [[ "$NEW_SNI" =~ google\.com$|microsoft\.com$ ]] && \
        die "Домен $NEW_SNI использовать нельзя (мониторится цензорами)"
    sed -i -E "s|\"dest\": \"[^\"]+:443\"|\"dest\": \"${NEW_SNI}:443\"|" xray/conf/config.json
    sed -i -E "s|\"serverNames\": \[\"[^\"]+\"\]|\"serverNames\": [\"${NEW_SNI}\"]|" xray/conf/config.json
    sed -i "s|^REALITY_SNI=.*|REALITY_SNI=$NEW_SNI|" .env
    docker compose restart xray >/dev/null
    ok "REALITY теперь маскируется под $NEW_SNI. НЕ ЗАБУДЬТЕ обновить Xray-клиенты!"
    ;;

  3)
    # --- Итоговая информация ---
    PANEL_HOST="$SERVER_PUBLIC_IP"
    [[ -n "${PANEL_DOMAIN:-}" ]] && PANEL_HOST="$PANEL_DOMAIN"
    echo
    echo "  Веб-панель:  https://${PANEL_HOST}:${PANEL_PORT}/${PANEL_PATH}/"
    echo "  Логин:       admin"
    echo "  AWG порт:    ${AWG_PORT}/udp   •   REALITY: 443/tcp ($REALITY_SNI)"
    echo
    if [[ -f amneziawg/conf/clients/admin.conf ]]; then
        echo "QR конфига владельца (AmneziaVPN):"
        qrencode -t ansiutf8 < amneziawg/conf/clients/admin.conf || \
            warn "Конфиг в amneziawg/conf/clients/admin.conf"
    else
        warn "amneziawg/conf/clients/admin.conf не найден — создайте устройство в панели"
    fi
    ;;

  4) exit 0 ;;
  *) die "Неизвестный выбор" ;;
esac
