# ============================================================
# StealthNode — контейнер Xray-core (VLESS + REALITY, резервный туннель).
# Бинарник скачивается с официальных релизов GitHub, версия закреплена.
# ============================================================
FROM ubuntu:24.04
ARG XRAY_VERSION=26.7.28
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# Маппинг архитектуры Docker (amd64/arm64) на имена ассетов Xray
RUN set -e; \
    case "${TARGETARCH:-amd64}" in \
        amd64) XARCH="64" ;; \
        arm64) XARCH="arm64-v8a" ;; \
        *) echo "Неподдерживаемая архитектура: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    cd /tmp \
    && curl -fSL -o xray.zip \
        "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XARCH}.zip" \
    && unzip -o xray.zip -d /tmp/xray-dist \
    && install -m 0755 /tmp/xray-dist/xray /usr/local/bin/xray \
    && mkdir -p /usr/local/share/xray \
    && install -m 0644 /tmp/xray-dist/geoip.dat   /usr/local/share/xray/ \
    && install -m 0644 /tmp/xray-dist/geosite.dat /usr/local/share/xray/ \
    && rm -rf /tmp/xray.zip /tmp/xray-dist

# geoip/geosite ищем рядом с бинарником
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -x xray >/dev/null 2>&1 || exit 1

# Конфиг монтируется из ./xray/conf (генерируется install.sh)
CMD ["xray", "run", "-c", "/etc/xray/config.json"]
