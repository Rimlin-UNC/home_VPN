# 🛡️ StealthNode — установщик персонального VPN-сервера

Одна команда на чистом **Ubuntu 24.04 LTS** — и у вас устойчивый к ТСПУ
личный VPN с веб-панелью: VLESS+REALITY (TCP/Vision :443 + gRPC + XHTTP),
резервный Hysteria2, закрытая панель по секретному пути, гости с лимитами и
изолированный торговый бот OKX. Готовые проекты (Xray, Hysteria, dnscrypt,
Caddy) + наш установщик, панель и логика квот.

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/Rimlin-UNC/home_VPN/main/stealthnode/install.sh | sudo bash
```

или для дебага: `git clone … && cd stealthnode && sudo ./install.sh`.

## Управление

- `sudo ./setup.sh` — смена пароля/домена маскировки, показ ссылок и QR;
- панель: `<SECRET_PATH>` из `/root/stealthnode-credentials.txt`;
- [docs/README.md](docs/README.md) — стек и клиенты;
- [docs/SECURITY.md](docs/SECURITY.md) — меры и компромиссы;
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — диагностика, включая детект ТСПУ.

## Структура

```
stealthnode/
├── install.sh              # точка входа «одной ссылкой»
├── setup.sh                # управление после установки
├── docker-compose.yml      # 6 контейнеров: xray, hysteria, dnscrypt, backend, caddy, bot
├── .env.example
├── xray/                   # официальный образ, шаблон конфига (3 транспорта + stats API)
├── hysteria/               # официальный бинарник, шаблон конфига (QUIC+Salamander)
├── dnscrypt/               # официальные релизы dnscrypt-proxy
├── caddy/                  # HTTPS-терминация и сокрытие панели
├── backend/                # наша панель (FastAPI) — см. backend/README.md
└── trading-bot/            # изолированный бот OKX — см. trading-bot/README.md
```
