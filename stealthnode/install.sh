#!/usr/bin/env bash
# =============================================================================
# StealthNode v2 — установщик личного VPN на чистую Ubuntu 24.04.
#
#   VLESS + XHTTP + REALITY   443/tcp  (основной, Android/Windows/macOS)
#   VLESS + TCP + REALITY     8443/tcp (iOS, flow xtls-rprx-vision)
#   Hysteria2 + Salamander    443/udp  (резерв, если режут TCP)
#   Панель 3X-UI (HTTPS через Caddy), подписки, лимиты трафика и IP,
#   dnscrypt-proxy, UFW, fail2ban, BBR, автообновления безопасности.
#
# Запуск:  sudo bash stealthnode/install.sh --domain vpn.shprv.ru [--email you@mail]
# Повторный запуск безопасен: секреты и пользователи сохраняются.
# Справка: sudo bash stealthnode/install.sh --help
# =============================================================================
# shellcheck source-path=SCRIPTDIR
set -Eeuo pipefail

SN_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SN_SRC

# shellcheck source=lib/common.sh
source "${SN_SRC}/lib/common.sh"
# shellcheck source=versions.env
source "${SN_SRC}/versions.env"
# shellcheck source=lib/preflight.sh
source "${SN_SRC}/lib/preflight.sh"
# shellcheck source=lib/system.sh
source "${SN_SRC}/lib/system.sh"
# shellcheck source=lib/firewall.sh
source "${SN_SRC}/lib/firewall.sh"
# shellcheck source=lib/ssh.sh
source "${SN_SRC}/lib/ssh.sh"
# shellcheck source=lib/fail2ban.sh
source "${SN_SRC}/lib/fail2ban.sh"
# shellcheck source=lib/dnscrypt.sh
source "${SN_SRC}/lib/dnscrypt.sh"
# shellcheck source=lib/xui.sh
source "${SN_SRC}/lib/xui.sh"
# shellcheck source=lib/caddy.sh
source "${SN_SRC}/lib/caddy.sh"
# shellcheck source=lib/app.sh
source "${SN_SRC}/lib/app.sh"

SN_VERSION="$(tr -d '[:space:]' < "${SN_SRC}/../VERSION")"

usage() {
    cat << EOF
StealthNode ${SN_VERSION} — установка личного VPN (3X-UI + Xray + Caddy) на Ubuntu 24.04

Использование: sudo bash $0 [параметры]

Основные:
  --domain ДОМЕН          домен сервера (A-запись → IP VPS), по умолчанию vpn.shprv.ru
  --email ПОЧТА           e-mail для Let's Encrypt (уведомления об истечении)
  --sni ДОМЕН             SNI/цель REALITY (по умолчанию max.ru; проверка: stealthnode sni-check)
  --target ХОСТ:ПОРТ      цель REALITY, если отличается от <SNI>:443
  --user ИМЯ[:ГБ[:IP]]    создать пользователя (можно несколько раз), напр. --user mama:50:2
  --limit-gb N            лимит по умолчанию для новых пользователей, ГБ/мес (50)
  --ip-limit N            лимит одновременных IP по умолчанию (2)

Безопасность SSH (по желанию):
  --ssh-keys-only         вход только по ключам (проверяется наличие ключа)
  --ssh-port N            дополнительный порт SSH (22 остаётся до --ssh-close-22)
  --ssh-close-22          закрыть порт 22 (после проверки входа по новому порту)
  --admin-ip IP[,IP]      не банить эти IP/подсети в fail2ban (запоминается)

Связка «мост в РФ → выход за рубежом» (если из РФ зарубежный сервер недоступен; docs/RELAY.md):
  --exit-for IP           (на зарубежном сервере) принимать трафик российского моста с этого IP
  --exit-link 'vless://…' (на российском сервере) работать мостом: трафик уходит на выход по ссылке
                          из «stealthnode exit link»; вместе с --restore <архив выхода>
  --no-ru-direct          (на мосту) российские сайты тоже через выход (по умолчанию — напрямую)
  --proxy URL             загрузки по HTTPS (GitHub, Caddy) через прокси, если с сервера в РФ они
                          недоступны; напр. SSH-туннель к выходу: ssh -fN -D 1080 root@<IP выхода>
                          и --proxy socks5h://127.0.0.1:1080 (внешний IP определяется напрямую)

Прочее:
  --panel-port N          внешний порт панели (по умолчанию случайный 20000-29999)
  --hy2-port N            UDP-порт Hysteria2 (443)
  --tg-token ТОКЕН --tg-chat ID   включить Telegram-бот 3x-ui (уведомления, бэкапы)
  --restore АРХИВ         перенос с другого сервера (ключи, пользователи, ссылки сохраняются)
  --tls internal          без Let's Encrypt (тесты; сертификат от внутреннего CA Caddy)
  --strict-dns            остановиться, если A-запись домена не указывает на сервер
  --skip-upgrade          не выполнять apt upgrade
  --no-auto-reboot        не перезагружать сервер после обновлений ядра
  --reinstall-panel       переустановить 3x-ui той же версии
  --force-os              продолжить на ОС, отличной от Ubuntu 24.04
  --no-doctor             не запускать проверку в конце
  -h, --help              эта справка

Повторный запуск безопасен: ключи, порты, пользователи и пароль панели (в том числе
изменённый в веб-интерфейсе) сохраняются. Забыли пароль панели: sudo stealthnode panel-password
EOF
}

OPT_USERS=()
parse_args() {
    SN_DOMAIN_ARG=""
    while (($#)); do
        case "$1" in
            --domain)
                SN_DOMAIN_ARG=${2:?}
                shift
                ;;
            --email)
                OPT_EMAIL=${2:?}
                shift
                ;;
            --sni)
                OPT_SNI=${2:?}
                shift
                ;;
            --target)
                OPT_TARGET=${2:?}
                shift
                ;;
            --user)
                OPT_USERS+=("${2:?}")
                shift
                ;;
            --limit-gb)
                OPT_LIMIT_GB=${2:?}
                shift
                ;;
            --ip-limit)
                OPT_IP_LIMIT=${2:?}
                shift
                ;;
            --ssh-keys-only) OPT_SSH_KEYS_ONLY=1 ;;
            --ssh-port)
                OPT_SSH_PORT=${2:?}
                shift
                ;;
            --ssh-close-22) OPT_SSH_CLOSE_22=1 ;;
            --admin-ip)
                OPT_ADMIN_IP=${2:?}
                shift
                ;;
            --exit-for)
                OPT_EXIT_FOR=${2:?}
                shift
                ;;
            --exit-link)
                OPT_EXIT_LINK=${2:?}
                shift
                ;;
            --no-ru-direct) OPT_NO_RU_DIRECT=1 ;;
            --proxy)
                OPT_PROXY=${2:?}
                shift
                ;;
            --panel-port)
                OPT_PANEL_PORT=${2:?}
                shift
                ;;
            --hy2-port)
                OPT_HY2_PORT=${2:?}
                shift
                ;;
            --tg-token)
                OPT_TG_TOKEN=${2:?}
                shift
                ;;
            --tg-chat)
                OPT_TG_CHAT=${2:?}
                shift
                ;;
            --restore)
                OPT_RESTORE=$(readlink -f "${2:?}")
                shift
                ;;
            --tls)
                OPT_TLS_MODE=${2:?}
                shift
                ;;
            --strict-dns) OPT_STRICT_DNS=1 ;;
            --skip-upgrade) OPT_SKIP_UPGRADE=1 ;;
            --no-auto-reboot) OPT_AUTO_REBOOT=0 ;;
            --reboot-time)
                OPT_REBOOT_TIME=${2:?}
                shift
                ;;
            --reinstall-panel) OPT_REINSTALL_XUI=1 ;;
            --force-os) OPT_FORCE_OS=1 ;;
            --no-doctor) OPT_NO_DOCTOR=1 ;;
            -h | --help)
                usage
                exit 0
                ;;
            *) die "неизвестный параметр: $1 (см. --help)" ;;
        esac
        shift
    done
    # Домен: параметр → сохранённый в .env → значение из ТЗ.
    if [[ -z ${SN_DOMAIN_ARG} && -f ${SN_ROOT}/.env ]]; then
        SN_DOMAIN_ARG=$(grep -oP "^SN_DOMAIN='\K[^']+" "${SN_ROOT}/.env" || true)
    fi
    SN_DOMAIN_ARG=${SN_DOMAIN_ARG:-vpn.shprv.ru}
    SN_DOMAIN_ARG=${SN_DOMAIN_ARG,,}
    [[ ${SN_DOMAIN_ARG} =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] ||
        die "некорректный домен: ${SN_DOMAIN_ARG}"
    [[ -z ${OPT_TLS_MODE:-} || ${OPT_TLS_MODE} =~ ^(acme|internal)$ ]] || die "--tls: допустимо acme или internal"
    [[ -z ${OPT_SSH_PORT:-} ]] || is_port "${OPT_SSH_PORT}" || die "--ssh-port: некорректный порт"
    [[ -z ${OPT_PANEL_PORT:-} ]] || is_port "${OPT_PANEL_PORT}" || die "--panel-port: некорректный порт"
    [[ -z ${OPT_HY2_PORT:-} ]] || is_port "${OPT_HY2_PORT}" || die "--hy2-port: некорректный порт"
    if [[ -n ${OPT_TG_TOKEN:-} || -n ${OPT_TG_CHAT:-} ]] && [[ -z ${OPT_TG_TOKEN:-} || -z ${OPT_TG_CHAT:-} ]]; then
        die "--tg-token и --tg-chat задаются вместе"
    fi
    [[ -z ${OPT_RESTORE:-} || -f ${OPT_RESTORE} ]] || die "--restore: файл не найден"
    [[ -z ${OPT_EXIT_FOR:-} || ${OPT_EXIT_FOR} =~ ^[0-9a-fA-F.:]+$ ]] || die "--exit-for: ожидается IP-адрес моста"
    [[ -z ${OPT_EXIT_LINK:-} || ${OPT_EXIT_LINK} == vless://* ]] ||
        die "--exit-link: ожидается ссылка vless://… (на выходе: stealthnode exit link)"
    if [[ -n ${OPT_EXIT_FOR:-} && -n ${OPT_EXIT_LINK:-} ]]; then
        die "--exit-for (выход) и --exit-link (мост) задаются на разных серверах"
    fi
    [[ -z ${OPT_PROXY:-} || ${OPT_PROXY} =~ ^(socks5h?|https?)://[^[:space:]]+$ ]] ||
        die "--proxy: ожидается socks5h://хост:порт или http://хост:порт"
    return 0
}

# Прокси только для загрузок по HTTPS (GitHub, Caddy) в этом процессе и в установщике 3x-ui.
# apt по http (зеркала Ubuntu) идёт напрямую; локальные адреса — всегда напрямую.
use_proxy() {
    [[ -n ${OPT_PROXY:-} ]] || return 0
    export https_proxy=${OPT_PROXY} HTTPS_PROXY=${OPT_PROXY}
    export no_proxy="localhost,127.0.0.1,::1" NO_PROXY="localhost,127.0.0.1,::1"
    info "загрузки по HTTPS — через прокси ${OPT_PROXY}"
}

run_doctor_final() {
    if [[ ${OPT_NO_DOCTOR:-0} == 1 ]]; then
        return 0
    fi
    sn_cli doctor --e2e || warn "doctor нашёл проблемы — см. вывод выше (установка завершена, можно исправить и запустить: stealthnode doctor --e2e)"
}

main() {
    parse_args "$@"
    require_root
    setup_logging
    enable_error_trap
    info "StealthNode ${SN_VERSION}: домен ${SN_DOMAIN_ARG}, 3x-ui ${XUI_VERSION}"
    use_proxy
    SN_TLS_MODE=${OPT_TLS_MODE:-acme}

    step "Предварительные проверки" preflight
    step "Пакеты и обновления системы" system_packages
    step "Приложение и параметры StealthNode" install_app
    step "Параметры и секреты (/opt/stealthnode/.env)" init_env
    step "Ядро: BBR, sysctl, swap, журнал" system_tuning
    step "Автообновления безопасности" setup_unattended
    step "Файрвол UFW" setup_ufw
    step "SSH" setup_ssh
    step "dnscrypt-proxy" setup_dnscrypt
    step "Панель 3X-UI ${XUI_VERSION}" install_xui
    step "Настройка панели" configure_xui
    step "Caddy (HTTPS панели и подписки)" setup_caddy
    step "Инбаунды, пользователи, ссылки" run_provision
    step "fail2ban" setup_fail2ban
    step "Таймеры обслуживания" setup_timers
    step "Проверка (doctor --e2e)" run_doctor_final
    final_summary
}

main "$@"
