#!/usr/bin/env bash
# ============================================================
# StealthNode — точка входа контейнера AmneziaWG.
# 1. Поднимает интерфейс awg0 через amneziawg-go (userspace).
# 2. Применяет пиров из конфига и параметры обфускации 3.1.
# 3. Включает NAT (маскарад) и перехват DNS -> dnscrypt-proxy.
# 4. Инициализирует шейпер tc/hfsc + ifb (лимиты гостей).
# 5. Инициализирует nftables-счётчики квот.
# 6. Следит за туннелем и корректно гасится по сигналам.
# ============================================================
set -euo pipefail

IFACE="${AWG_IFACE:-awg0}"
CONF="/etc/amneziawg/awg0.conf"
LISTEN_PORT="51820"                     # внутри контейнера порт фиксирован
ADDRESS="${AWG_SERVER_IP:-10.8.0.1}"    # адрес сервера в туннеле
MTU="${AWG_MTU:-1280}"
DNSCRYPT_IP="${DNSCRYPT_IP:-172.20.0.10}"

log() { echo "[amneziawg] $(date '+%F %T') $*"; }

# ---------- 1. Извлекаем приватный ключ сервера из конфига ----------
SERVER_PRIV="$(awk -F' = ' '/^PrivateKey/{print $2; exit}' "$CONF" || true)"
if [[ -z "${SERVER_PRIV}" ]]; then
    log "ОШИБКА: в $CONF не найден PrivateKey сервера"; exit 1
fi
echo "${SERVER_PRIV}" > /tmp/server.key; chmod 600 /tmp/server.key

# ---------- 2. Поднимаем userspace-интерфейс ----------
if ip link show "${IFACE}" >/dev/null 2>&1; then
    ip link del "${IFACE}" || true
fi
log "Запуск amneziawg-go (интерфейс ${IFACE})"
amneziawg-go "${IFACE}"
sleep 1
ip address replace "${ADDRESS}/24" dev "${IFACE}"
ip link set mtu "${MTU}" up dev "${IFACE}"

# ---------- 3. Пиры из конфига (setconf: ключи+порт+пиры) ----------
# awg-quick strip убирает wg-quick-специфику (Address, DNS, MTU и обфускацию),
# оставляя то, что принимает setconf. Интерфейс выводится из имени файла.
TMPSTRIP="$(mktemp)"
awg-quick strip "$CONF" > "${TMPSTRIP}" 2>/dev/null \
    || grep -Ev '^(Address|DNS|MTU|Jc|Jmin|Jmax|S[1-4]|H[1-4])[ =]' "$CONF" > "${TMPSTRIP}"
awg setconf "${IFACE}" "${TMPSTRIP}"
rm -f "${TMPSTRIP}"
awg set "${IFACE}" listen-port "${LISTEN_PORT}" private-key /tmp/server.key

# ---------- 4. Параметры обфускации AmneziaWG ----------
# Применяем явно (setconf их игнорирует). S3/S4 опциональны.
set +e
AWG_SET_ARGS=()
[[ -n "${AWG_JC:-}"   && "${AWG_JC}" != "0" ]]   && AWG_SET_ARGS+=(jc   "${AWG_JC}")
[[ -n "${AWG_JMIN:-}" && "${AWG_JMIN}" != "0" ]] && AWG_SET_ARGS+=(jmin "${AWG_JMIN}")
[[ -n "${AWG_JMAX:-}" && "${AWG_JMAX}" != "0" ]] && AWG_SET_ARGS+=(jmax "${AWG_JMAX}")
[[ -n "${AWG_S1:-}"   && "${AWG_S1}" != "0" ]]   && AWG_SET_ARGS+=(s1   "${AWG_S1}")
[[ -n "${AWG_S2:-}"   && "${AWG_S2}" != "0" ]]   && AWG_SET_ARGS+=(s2   "${AWG_S2}")
[[ -n "${AWG_S3:-}"   && "${AWG_S3}" != "0" ]]   && AWG_SET_ARGS+=(s3   "${AWG_S3}")
[[ -n "${AWG_S4:-}"   && "${AWG_S4}" != "0" ]]   && AWG_SET_ARGS+=(s4   "${AWG_S4}")
[[ -n "${AWG_H1:-}" ]] && AWG_SET_ARGS+=(h1 "${AWG_H1}")
[[ -n "${AWG_H2:-}" ]] && AWG_SET_ARGS+=(h2 "${AWG_H2}")
[[ -n "${AWG_H3:-}" ]] && AWG_SET_ARGS+=(h3 "${AWG_H3}")
[[ -n "${AWG_H4:-}" ]] && AWG_SET_ARGS+=(h4 "${AWG_H4}")
if [[ ${#AWG_SET_ARGS[@]} -gt 0 ]]; then
    log "Обфускация: awg set ${IFACE} ${AWG_SET_ARGS[*]} ${AWG_EXTRA_SET_ARGS:-}"
    awg set "${IFACE}" "${AWG_SET_ARGS[@]}" ${AWG_EXTRA_SET_ARGS:-} \
        || log "ВНИМАНИЕ: часть параметров обфускации не применена (проверьте версию awg)"
fi
set -e

# ---------- 5. NAT: маскарад клиентской подсети ----------
# Одно правило покрывает и выход в интернет, и обращения к dnscrypt-proxy.
iptables -t nat -C POSTROUTING -o eth0 -s "${ADDRESS}/24" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o eth0 -s "${ADDRESS}/24" -j MASQUERADE

# ---------- 6. Перехват DNS клиентов -> dnscrypt-proxy ----------
# Защита от утечек: ЛЮБОЙ DNS-запрос из туннеля (даже на жёстко
# прописанный 8.8.8.8) заворачивается на внутренний резолвер.
for proto in udp tcp; do
    iptables -t nat -C PREROUTING -i "${IFACE}" -p "${proto}" --dport 53 \
        -j DNAT --to-destination "${DNSCRYPT_IP}:53" 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "${IFACE}" -p "${proto}" --dport 53 \
            -j DNAT --to-destination "${DNSCRYPT_IP}:53"
done

# ---------- 7. Шейпер tc/hfsc + ifb (лимиты скорости гостей) ----------
# Скачивание клиента = egress на awg0; загрузка клиента = ingress на awg0,
# который заворачиваем на ifb0 и там шейпим (hfsc).
shaper_init() {
    tc qdisc del dev "${IFACE}" root    2>/dev/null || true
    tc qdisc del dev "${IFACE}" ingress 2>/dev/null || true
    ip link del ifb0 2>/dev/null || true

    tc qdisc add dev "${IFACE}" root handle 1: hfsc default 10
    tc class add dev "${IFACE}" parent 1: classid 1:1 \
        hfsc sc rate 10gbit ul rate 10gbit
    tc class add dev "${IFACE}" parent 1:1 classid 1:10 \
        hfsc sc rate 10gbit ul rate 10gbit

    ip link add ifb0 type ifb 2>/dev/null || true
    ip link set ifb0 up 2>/dev/null || true
    if ip link show ifb0 >/dev/null 2>&1; then
        tc qdisc add dev "${IFACE}" handle ffff: ingress
        tc filter add dev "${IFACE}" parent ffff: protocol all u32 \
            match u32 0 0 action mirred egress redirect dev ifb0
        tc qdisc add dev ifb0 root handle 1: hfsc default 10
        tc class add dev ifb0 parent 1: classid 1:1 hfsc sc rate 10gbit ul rate 10gbit
        tc class add dev ifb0 parent 1:1 classid 1:10 hfsc sc rate 10gbit ul rate 10gbit
        log "Шейпер инициализирован (egress awg0 + ifb0 для ingress)"
    else
        log "ВНИМАНИЕ: ifb0 не создан (модуль ifb на хосте?). Лимиты upload недоступны."
    fi
}
shaper_init

# ---------- 8. nftables: таблица счётчиков квот ----------
nft list table ip vpn_quota >/dev/null 2>&1 || {
    nft add table ip vpn_quota
    nft 'add chain ip vpn_quota forward { type filter hook forward priority 0; policy accept; }'
    log "Таблица nftables vpn_quota создана"
}

# ---------- 9. Сигналы и надзор ----------
down() {
    log "Остановка..."
    ip link del ifb0 2>/dev/null || true
    ip link del "${IFACE}" 2>/dev/null || true
    exit 0
}
trap down TERM INT

log "AmneziaWG поднят: ${ADDRESS} (UDP ${LISTEN_PORT}), MTU ${MTU}"
# Надзорный цикл: если интерфейс упал — перезапуск через падение контейнера
while true; do
    ip link show "${IFACE}" >/dev/null 2>&1 || { log "Интерфейс ${IFACE} пропал!"; exit 1; }
    sleep 5 &
    wait $!
done
