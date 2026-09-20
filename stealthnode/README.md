# StealthNode

Персональный VPN-сервер с веб-панелью для одного VPS (Ubuntu 24.04),
реализованный по ТЗ из [корневого README](../README.md).

**Установка одной командой:**

```bash
curl -fsSL https://raw.githubusercontent.com/Rimlin-UNC/home_VPN/main/stealthnode/install.sh | sudo bash
```

## Структура проекта

```
stealthnode/
├── install.sh              # ← главный установщик (запускать на сервере)
├── setup.sh                # переконфигурация после установки
├── docker-compose.yml      # оркестрация стека
├── .env.example            # описание всех переменных окружения
├── amneziawg/              # AmneziaWG 3.1: Dockerfile (сборка из исходников),
│   ├── entrypoint.sh       #   поднятие туннеля, NAT, DNS-перехват, tc/ifb
│   └── conf/awg0.conf.tmpl
├── xray/                   # Xray 26.7.28 VLESS+REALITY: Dockerfile + шаблон конфига
├── dnscrypt/               # dnscrypt-proxy 2.1.18: Dockerfile + toml
├── backend/                # FastAPI-панель: API, WebSocket, сервисы, SPA-фронтенд
├── trading-bot/            # торговый бот OKX (ccxt, симуляция по умолчанию)
├── caddy/Caddyfile.tmpl    # HTTPS + сокрытие панели за секретным путём
└── docs/
    ├── README.md           # ← полная документация (хостинги, установка, пользование)
    ├── SECURITY.md         # модель безопасности
    └── TROUBLESHOOTING.md  # решение типовых проблем
```

Документация: [docs/README.md](docs/README.md)
