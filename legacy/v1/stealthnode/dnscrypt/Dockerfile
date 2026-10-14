# ============================================================
# StealthNode — контейнер dnscrypt-proxy.
# DNS-резолвер всех контейнеров стека (xray/hysteria и др. ходят через
# него, см. dns: в docker-compose): исходящие запросы уходят наружу уже
# шифрованными (DNSCrypt/DoH, в 2.1.18 — с PQDNSCrypt). Plaintext-DNS
# клиентов проксирует сам Xray (freedom/outbound), никакого DNAT нет.
# ============================================================
FROM ubuntu:24.04
ARG DNSCRYPT_VERSION=2.1.18
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# Маппинг архитектуры на имена ассетов релиза
RUN set -e; \
    case "${TARGETARCH:-amd64}" in \
        amd64) DARCH="x86_64" ;; \
        arm64) DARCH="arm64" ;; \
        *) echo "Неподдерживаемая архитектура: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    cd /tmp \
    && curl -fSL -o dnscrypt.tar.gz \
        "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${DNSCRYPT_VERSION}/dnscrypt-proxy-linux_${DARCH}-${DNSCRYPT_VERSION}.tar.gz" \
    && tar xzf dnscrypt.tar.gz \
    && install -m 0755 linux-${DARCH}/dnscrypt-proxy /usr/local/bin/dnscrypt-proxy \
    && rm -rf /tmp/dnscrypt.tar.gz /tmp/linux-${DARCH}

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -x dnscrypt-proxy >/dev/null 2>&1 || exit 1

CMD ["dnscrypt-proxy", "-config", "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"]
