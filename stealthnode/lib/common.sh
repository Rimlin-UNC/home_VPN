#!/usr/bin/env bash
# StealthNode: общие функции установщика (журнал, ошибки, повторы, шаблоны).
# Подключается через `source`; сам по себе не запускается.
# shellcheck shell=bash

SN_LOG_DIR="${SN_LOG_DIR:-/var/log/stealthnode}"
SN_ROOT="${SN_ROOT:-/opt/stealthnode}"
SN_APP_DIR="${SN_APP_DIR:-${SN_ROOT}/app}"
SN_LOG_FILE="${SN_LOG_FILE:-}"
SN_STEP="подготовка"
SN_STEP_NO=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_CYAN=$'\033[36m' C_BOLD=$'\033[1m' C_OFF=$'\033[0m'
else
    C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_BOLD="" C_OFF=""
fi

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { printf '%s %s\n' "$(_ts)" "$*" >> "${SN_LOG_FILE:-/dev/null}" 2> /dev/null || true; }
info() {
    printf '%s[ИНФО]%s %s\n' "${C_CYAN}" "${C_OFF}" "$*"
    log "INFO $*"
}
ok() {
    printf '%s[ OK ]%s %s\n' "${C_GREEN}" "${C_OFF}" "$*"
    log "OK   $*"
}
warn() {
    printf '%s[ВНИМ]%s %s\n' "${C_YELLOW}" "${C_OFF}" "$*" >&2
    log "WARN $*"
}
err() {
    printf '%s[ОШИБ]%s %s\n' "${C_RED}" "${C_OFF}" "$*" >&2
    log "ERR  $*"
}
die() {
    err "$*"
    exit 1
}

# Журнал установки: весь вывод команд дублируется в файл (секреты в него не пишем).
setup_logging() {
    install -d -m 700 "${SN_LOG_DIR}"
    SN_LOG_FILE="${SN_LOG_DIR}/install-$(date '+%Y%m%d-%H%M%S').log"
    : > "${SN_LOG_FILE}"
    chmod 600 "${SN_LOG_FILE}"
    exec > >(tee -a "${SN_LOG_FILE}") 2>&1
    info "журнал установки: ${SN_LOG_FILE}"
}

# Обработчик ошибок: какая команда, где и на каком шаге упала.
on_error() {
    local code=$? line=${BASH_LINENO[0]:-?} cmd=${BASH_COMMAND:-?} src=${BASH_SOURCE[1]:-?}
    err "шаг «${SN_STEP}» прерван: код ${code}, ${src##*/}:${line}: ${cmd}"
    err "подробности в журнале: ${SN_LOG_FILE:-нет журнала}"
    err "установку можно безопасно запустить повторно после исправления причины"
    exit "${code}"
}

enable_error_trap() {
    set -Eeuo pipefail
    trap on_error ERR
}

step() {
    local title=$1
    shift
    SN_STEP_NO=$((SN_STEP_NO + 1))
    SN_STEP="${title}"
    printf '\n%s==> [%d] %s%s\n' "${C_BOLD}" "${SN_STEP_NO}" "${title}" "${C_OFF}"
    log "STEP ${SN_STEP_NO}: ${title}"
    local started=${SECONDS}
    "$@"
    ok "${title} — готово за $((SECONDS - started)) с"
}

# retry <попыток> <пауза_с> команда... — повтор сетевых операций.
retry() {
    local _attempts=$1 _delay=$2 _try=1
    shift 2
    until "$@"; do
        if ((_try >= _attempts)); then
            return 1
        fi
        warn "попытка ${_try}/${_attempts} не удалась: $*; повтор через ${_delay} с"
        sleep "${_delay}"
        _try=$((_try + 1))
    done
}

require_root() {
    [[ ${EUID} -eq 0 ]] || die "запустите от root: sudo bash $0 ..."
}

apt_get() {
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y -q \
        -o DPkg::Lock::Timeout=600 \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        "$@"
}

apt_install() {
    retry 3 10 apt_get install --no-install-recommends "$@"
}

# render_template <шаблон> <результат> <режим> VAR...
# Подставляет только перечисленные ${VAR} (остальные $ и {} не трогаются).
# Чистый bash, без envsubst; значения подставляются буквально (в т.ч. '&' и '\').
render_template() {
    local src=$1 dst=$2 mode=$3
    shift 3
    local content v pat val tmp
    content=$(< "${src}")
    for v in "$@"; do
        [[ -v ${v} ]] || die "render_template: переменная ${v} не задана (${src##*/})"
        pat="\${${v}}"
        val=${!v}
        content=${content//"${pat}"/"${val}"}
    done
    tmp=$(mktemp "${dst}.XXXXXX")
    printf '%s\n' "${content}" > "${tmp}"
    chmod "${mode}" "${tmp}"
    mv -f "${tmp}" "${dst}"
}

# Записать файл, только если содержимое изменилось. Код 0 — изменён, 1 — без изменений.
write_if_changed() {
    local dst=$1 mode=$2 tmp
    tmp=$(mktemp)
    cat > "${tmp}"
    if [[ -f ${dst} ]] && cmp -s "${tmp}" "${dst}"; then
        rm -f "${tmp}"
        return 1
    fi
    install -D -m "${mode}" "${tmp}" "${dst}"
    rm -f "${tmp}"
    return 0
}

is_port() { [[ $1 =~ ^[0-9]+$ ]] && (($1 >= 1 && $1 <= 65535)); }

is_ipv4() {
    local ip=$1 IFS=. o
    [[ ${ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for o in ${ip}; do ((o <= 255)) || return 1; done
}

# sshd -t / sshd -T требуют /run/sshd. В Ubuntu 24.04 (ssh.socket) каталог создаётся только
# при первом запуске sshd, поэтому на свежей системе проверки конфигурации падают.
sshd_cmd() {
    install -d -m 755 /run/sshd 2> /dev/null || true
    sshd "$@"
}

# Вызов CLI StealthNode из установленного приложения.
sn_cli() {
    PYTHONPATH="${SN_APP_DIR}/python" python3 -m stealthnode "$@"
}

# Подгрузить /opt/stealthnode/.env в текущий shell (значения в одинарных кавычках).
load_env() {
    local f="${SN_ROOT}/.env"
    [[ -f ${f} ]] || die "нет ${f}"
    # shellcheck disable=SC1090
    source "${f}"
}
