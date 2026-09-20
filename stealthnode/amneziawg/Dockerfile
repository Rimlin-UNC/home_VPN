# ============================================================
# StealthNode — контейнер AmneziaWG 3.1.
# Собираем из исходников (двухстадийная сборка):
#   * amneziawg-go    — userspace-реализация протокола (не нужен
#                       модуль ядра на VPS, работает везде через TUN);
#   * amneziawg-tools — утилита `awg` (управление пирами,
#                       совместима по синтаксису с `wg`).
# ============================================================

# ---------- Стадия 1: сборка amneziawg-go ----------
FROM golang:1.25-bookworm AS build-go
ARG AWG_GO_REF=v3.1.20260812
# git уже есть в golang-образе; собираем статический бинарник
RUN git clone --depth 1 --branch "${AWG_GO_REF}" \
        https://github.com/amnezia-vpn/amneziawg-go /src \
    && cd /src \
    && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/amneziawg-go .

# ---------- Стадия 2: сборка amneziawg-tools (утилита awg) ----------
FROM debian:bookworm-slim AS build-tools
ARG AWG_TOOLS_REF=v3.1.20260812
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${AWG_TOOLS_REF}" \
        https://github.com/amnezia-vpn/amneziawg-tools /src \
    && make -C /src/src \
    && install -m 0755 /src/src/wg /out-awg-bin \
    && install -m 0755 /src/src/wg-quick/linux.bash /out-awg-quick
# Примечание: бинарь называем awg (так его ищут скрипты), quick — awg-quick.

# ---------- Финальный образ ----------
FROM ubuntu:24.04
LABEL org.opencontainers.image.title="StealthNode AmneziaWG" \
      org.opencontainers.image.description="AmneziaWG 3.1 userspace + tc/ifb/nftables"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables nftables iputils-ping curl \
        ca-certificates procps kmod bash \
    && rm -rf /var/lib/apt/lists/*

# Переименовываем в awg/awg-quick — «родные» имена инструментов AmneziaWG
COPY --from=build-go    /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=build-tools /out-awg-bin      /usr/local/bin/awg
COPY --from=build-tools /out-awg-quick    /usr/local/bin/awg-quick

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/awg-quick

# Точка входа: поднимает awg0, применяет конфиг, NAT, DNS-перехват, шейпер
ENTRYPOINT ["/entrypoint.sh"]
