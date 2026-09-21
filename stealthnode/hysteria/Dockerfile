# ============================================================
# StealthNode — контейнер Hysteria2 (резервный протокол).
# QUIC/UDP + обфускация Salamander — работает там, где ТСПУ
# уже выучил TCP-профиль VLESS, и быстрее на сетях с потерями.
# Бинарник — официальный релиз apernet/hysteria (готовый артефакт).
# ============================================================
FROM ubuntu:24.04
ARG HYSTERIA_VERSION=2.12.3
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# Маппинг архитектуры Docker на имена ассетов релиза
RUN set -e; \
    case "${TARGETARCH:-amd64}" in \
        amd64) HARCH="amd64" ;; \
        arm64) HARCH="arm64" ;; \
        *) echo "Неподдерживаемая архитектура: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fSL -o /usr/local/bin/hysteria \
        "https://github.com/apernet/hysteria/releases/download/app%2Fv${HYSTERIA_VERSION}/hysteria-linux-${HARCH}" \
    && chmod 0755 /usr/local/bin/hysteria

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -x hysteria >/dev/null 2>&1 || exit 1

# Конфиг монтируется из ./hysteria/conf (генерируется install.sh)
CMD ["hysteria", "server", "-c", "/etc/hysteria/hysteria.yaml"]
