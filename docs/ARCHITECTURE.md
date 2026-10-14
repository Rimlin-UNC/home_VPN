# Архитектура StealthNode 2

## Схема

```
 Телефон/ПК (v2rayNG, v2rayN, Happ, Streisand…)
   │
   │  443/tcp  VLESS + XHTTP(stream-one) + REALITY(fp=firefox, SNI max.ru)
   │  8443/tcp VLESS + TCP + REALITY + Vision
   │  443/udp  Hysteria2 + Salamander
   ▼
┌───────────────────────────── VPS, Ubuntu 24.04 ─────────────────────────────┐
│ UFW: SSH, 80, 443/tcp, 8443/tcp, 443/udp, порт панели                        │
│                                                                              │
│  x-ui.service (3X-UI v3.10.0, 127.0.0.1:3xxxx) ── БД /etc/x-ui/x-ui.db       │
│     ├─ запускает Xray 26.10.10: инбаунды sn-vless-xhttp / sn-vless-vision /  │
│     │   sn-hysteria2, клиенты = пользователи (общая квота), статистика, лимиты│
│     │   └─ DNS → dnscrypt-proxy (tcp+local://127.0.2.1:53) → резерв DoH       │
│     ├─ сервер подписок 127.0.0.1:2096                                        │
│     └─ лимит IP → журнал 3xipl.log → fail2ban jail 3x-ipl                    │
│                                                                              │
│  caddy.service :2xxxx (HTTPS, Let's Encrypt через HTTP-01 на :80)            │
│     ├─ /<путь панели>/*   → 127.0.0.1:3xxxx                                   │
│     ├─ /<путь подписки>/* → 127.0.0.1:2096                                   │
│     └─ всё остальное      → 404                                              │
│                                                                              │
│  fail2ban: sshd, stealthnode-panel, recidive, 3x-ipl                         │
│  таймеры: stealthnode-backup (ежедневно), stealthnode-certsync (6 ч)          │
└──────────────────────────────────────────────────────────────────────────────┘
          REALITY без ключа → прозрачно проксируется на настоящий max.ru:443
```

## Компоненты и ответственность

| Компонент | Роль | Почему так |
|---|---|---|
| `stealthnode/install.sh` + `lib/*.sh` | системная часть: пакеты, ядро, UFW, SSH, fail2ban, dnscrypt, установка 3x-ui и Caddy, таймеры | bash — естественен для настройки ОС; модули по зонам ответственности |
| Python-пакет `stealthnode` (только stdlib) | параметры и секреты, API 3x-ui, провижининг, пользователи, ссылки/QR, doctor, бэкапы | логика с JSON и HTTP тестируется unit-тестами; не нужен pip на сервере |
| 3X-UI v3 | панель, пользователи, лимиты, подписки, бот, ядро Xray | клиенты v3 — общая запись на все инбаунды (одна квота), встроенный лимит IP и бот |
| Caddy | TLS для панели/подписки, автопродление | проще и надёжнее acme.sh внутри 3x-ui; не требует 443 |
| dnscrypt-proxy | шифрованный DNS для Xray | требование ТЗ; системный резолвер не трогаем (меньше рисков) |

## Источники правды

| Данные | Где | Кто меняет |
|---|---|---|
| Параметры, ключи REALITY, пароли, порты | `/opt/stealthnode/.env` (600) | `install.sh`, `stealthnode env/sni-set` |
| Инбаунды, пользователи, трафик | БД 3x-ui `/etc/x-ui/x-ui.db` | `stealthnode provision/user`, панель |
| Конфиг Xray | генерирует 3x-ui из БД; копия для справки — `/opt/stealthnode/xray/config.json` | — |
| Ссылки и QR | `/opt/stealthnode/users/<имя>/`, `xray/share/admin-links.txt` | `stealthnode links` |
| Сертификат Hysteria2 | `/opt/stealthnode/hysteria/server.{crt,key}` (копия LE из Caddy или self-signed) | `stealthnode cert-sync` |
| Caddyfile | `/opt/stealthnode/caddy/Caddyfile` → установлен в `/etc/caddy/Caddyfile` | `install.sh` |

## Идемпотентность

Повторный запуск `install.sh`: значения из `.env` сохраняются (генерируются только недостающие),
3x-ui переустанавливается лишь при смене версии, провижининг сравнивает желаемое состояние с
текущим (`payloads.inbound_diff`) и правит только отличия, пользователи и их трафик не
трогаются. Это же позволяет «чинить» сервер повторным запуском и обновлять StealthNode.

## Структура репозитория

```
stealthnode/
  install.sh, uninstall.sh, versions.env
  lib/        common, preflight, system, firewall, ssh, fail2ban, dnscrypt, xui, caddy, app
  python/stealthnode/  cli, config, envfile, x25519, xui, payloads, provision, users,
                       links, certs, doctor, backup, util
  templates/  Caddyfile, dnscrypt-proxy.toml, sysctl, apt, fail2ban, systemd
  bin/stealthnode      обёртка CLI
tests/  unit (pytest + фейковый API 3x-ui), bats, e2e (Xray/Hysteria), ci (контракт с 3x-ui)
docs/   документация; legacy/ — версия 1
```
