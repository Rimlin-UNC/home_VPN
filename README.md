# StealthNode 2 — личный VPN для семьи, устойчивый к DPI

Установщик личного VPN на один зарубежный VPS с Ubuntu 24.04: **VLESS + XHTTP + REALITY**,
**VLESS + TCP + REALITY + Vision** (iOS) и **Hysteria2 + Salamander** (резерв по UDP) под
управлением панели **3X-UI** с HTTPS, подписками, QR-кодами и лимитами трафика на человека.

> Версия: **2.0.0** ([журнал изменений](CHANGELOG.md)) · Xray 26.10.10 · 3X-UI 3.10.0 · Caddy 2.11

## Быстрый старт

1. VPS за рубежом с **Ubuntu 24.04**, от 1 ГБ RAM, публичный IPv4.
2. A-запись домена (по умолчанию `vpn.shprv.ru`) → IP сервера, TTL 300.
3. На сервере от root:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/Rimlin-UNC/home_VPN.git && cd home_VPN
sudo bash stealthnode/install.sh --domain vpn.shprv.ru --email you@example.com \
    --user mama:50:2 --user papa:50:2
```

4. Через 5–10 минут: учётные данные — в `/root/stealthnode-credentials.txt`, профили с QR —
   в `/opt/stealthnode/users/<имя>/`, проверка — `sudo stealthnode doctor --e2e`.

Подробно: **[docs/INSTALL.md](docs/INSTALL.md)**. Какие приложения ставить на телефоны и ПК:
**[docs/CLIENTS.md](docs/CLIENTS.md)**.

## Что получится

| Профиль | Порт | Для чего |
|---|---|---|
| VLESS + XHTTP (stream-one) + REALITY, fp=firefox | 443/tcp | основной: Android, Windows, macOS |
| VLESS + TCP + REALITY + Vision | 8443/tcp | iOS и запасной вариант |
| Hysteria2 + Salamander | 443/udp | если оператор режет TCP |
| Панель 3X-UI + подписки (Caddy, Let's Encrypt) | случайный порт | администрирование |

- **Один пользователь — одна квота на все протоколы** (например, 50 ГБ/мес с автосбросом) и
  лимит одновременных устройств (IP); одна ссылка-подписка на все профили.
- Панель и подписки — только по HTTPS; сырые порты закрыты; fail2ban, UFW, BBR, автообновления
  безопасности, dnscrypt-proxy, ежедневные резервные копии.
- Переезд на новый VPS при блокировке IP: `--restore <архив>` + смена A-записи — у пользователей
  ничего менять не нужно.

## Обслуживание

```bash
sudo stealthnode doctor --e2e          # проверить всё, включая реальное подключение
sudo stealthnode user add sister --gb 50 --ip 2
sudo stealthnode user show sister --qr # ссылки и QR-код в терминале
sudo stealthnode user list             # трафик и лимиты
sudo stealthnode backup                # резервная копия (ещё и ежедневно по таймеру)
sudo stealthnode sni-check             # подобрать SNI для REALITY с этого сервера
```

Все команды: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Документация

| Документ | Содержание |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | установка по шагам, параметры, переезд, частые проблемы |
| [docs/CLIENTS.md](docs/CLIENTS.md) | приложения для iOS/Android/Windows/macOS и совместимость |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | пользователи, лимиты, бэкапы, обновления, журналы |
| [docs/SECURITY.md](docs/SECURITY.md) | модель угроз и что защищено |
| [docs/TESTING.md](docs/TESTING.md) | тесты раздела 8 ТЗ, ручные проверки, автотесты |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | устройство, порты, файлы |
| [docs/TZ-v2.md](docs/TZ-v2.md) · [docs/TZ-REVIEW.md](docs/TZ-REVIEW.md) | ТЗ и разбор его пробелов |
| [PLAN.md](PLAN.md) · [CHANGELOG.md](CHANGELOG.md) | план работ и журнал версий |

## Важные ограничения

- Совместимы только клиенты на **Xray-core ≥ 26.3.23** (v2rayNG, v2rayN, Happ, Streisand/V2Box):
  REALITY в Xray ≥ 26.9.8 требует X25519MLKEM768, а клиенты на sing-box (NekoBox, Hiddify,
  Nekoray/Throne, Karing) подключиться не смогут. См. [CLIENTS.md](docs/CLIENTS.md).
- Режим «белых списков» мобильных операторов один зарубежный сервер не обходит — нужен
  российский relay (следующая фаза, см. [PLAN.md](PLAN.md)).
- Домен `.ru` со словом «vpn» заметнее для блокировок (CT-логи) — домен меняется параметром `--domain`.

Предыдущая версия (Docker, своя панель, торговый бот) — в [legacy/](legacy/README.md).
