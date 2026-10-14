# План работ StealthNode v2

Рабочий план агента. Обновляется по ходу работы: `[x]` — сделано и проверено,
`[~]` — в работе, `[ ]` — не начато, `[-]` — отменено (с причиной).
История изменений по версиям — в [CHANGELOG.md](CHANGELOG.md).

## 0. Исследование и решения
- [x] Разобрать ТЗ v2, сверить с актуальным состоянием (Xray v26.10.10, 3x-ui v3.10.0,
      поведение ТСПУ лета 2026, требования REALITY к X25519MLKEM768).
- [~] Зафиксировать пробелы ТЗ и принятые решения → [docs/TZ-REVIEW.md](docs/TZ-REVIEW.md).
- [x] Решение заказчика: v1 (Docker + своя панель + торговый бот) → `legacy/v1/`.
- [x] Решение заказчика: домен `vpn.shprv.ru` везде, но как параметр установщика.

## 1. Структура репозитория и журнал версий
- [x] Перенести v1 в `legacy/v1/` (`git mv`, история сохранена).
- [~] `PLAN.md`, `CHANGELOG.md` (Keep a Changelog + SemVer), `VERSION`.
- [ ] `docs/TZ-v2.md` (требования ТЗ), `docs/TZ-REVIEW.md` (разбор).
- [ ] Новый корневой `README.md`.

## 2. Установщик (bash, `stealthnode/install.sh` + `stealthnode/lib/*.sh`)
- [ ] Каркас: строгий режим, лог в `/var/log/stealthnode/`, trap ошибок с номером строки,
      повторный запуск без поломок (идемпотентность), секреты в `/opt/stealthnode/.env` (600).
- [ ] Предпроверки: root, Ubuntu 24.04, архитектура, RAM/диск, свободные порты, DNS-запись домена.
- [ ] Система: пакеты, BBR + sysctl, swap при RAM < 2 ГБ, unattended-upgrades (только security).
- [ ] UFW (SSH, 80, 443/tcp, 8443/tcp, 443/udp, порт панели) — сырые порты панели/подписки закрыты.
- [ ] SSH (опционально): только ключи, нестандартный порт с безопасным переходом (ssh.socket в 24.04).
- [ ] fail2ban: sshd 3 попытки/10 мин → 24 ч; перебор пароля панели; recidive; 3x-ipl (лимит IP).
- [ ] dnscrypt-proxy (127.0.2.1:53) + DoH-резерв внутри Xray.
- [ ] 3X-UI v3.10.0: официальный установщик, закреплённая версия + SHA256, неинтерактивно,
      панель только на 127.0.0.1, случайные порт/путь/логин/пароль, API-токен.
- [ ] Caddy: HTTPS для панели и подписки на отдельном порту (443 занят Xray), HTTP-01 на :80.

## 3. Провижининг (Python stdlib, `stealthnode/python/stealthnode/`)
- [ ] Клиент API 3x-ui (Bearer-токен).
- [ ] Инбаунды: VLESS+XHTTP+REALITY :443 (stream-one, без flow, fp=firefox),
      VLESS+TCP+REALITY+Vision :8443 (те же ключи/shortId), Hysteria2+Salamander :443/udp.
- [ ] Настройки панели: подписка на 127.0.0.1 за Caddy, внешний URL подписки, часовой пояс, язык бота.
- [ ] Шаблон Xray: DNS через dnscrypt-proxy + DoH-резерв, стратегия IPv4/IPv6 по факту наличия IPv6.
- [ ] Пользователи: владелец без лимита; родственники — N ГБ/мес с ежемесячным сбросом, лимит IP;
      один пользователь = одна квота на все три протокола, одна подписка.
- [ ] Ссылки/QR: `/opt/stealthnode/users/<имя>/`, `xray/share/admin-links.txt`.
- [ ] Сертификат Hysteria2: Let's Encrypt от Caddy (синхронизация), иначе self-signed + pinSHA256.

## 4. CLI `stealthnode`
- [ ] `doctor` (проверки §8 ТЗ, исправленные), `doctor --e2e` (реальное подключение через Xray).
- [ ] `info`, `user add|del|list|show|reset`, `links`, `backup` (+ ежедневный таймер), `cert-sync`,
      `sni-check`, `export-config`, `version`.

## 5. Проверка ошибок и тесты
- [ ] shellcheck + shfmt для всех bash-скриптов.
- [ ] pytest: генераторы конфигов, парсер ссылок, .env, x25519 (векторы RFC 7748), провижининг
      против фейкового API 3x-ui.
- [ ] bats: функции установщика.
- [ ] E2E протоколов локально: Xray v26.10.10 сервер+клиент (XHTTP/REALITY, TCP/Vision/REALITY,
      Hysteria2/Salamander с LE-подобным и self-signed+pin сертификатом), официальный клиент Hysteria2.
- [ ] `caddy validate` шаблона, `fail2ban-regex` для фильтра панели, `xray -test` экспортов.
- [ ] CI GitHub Actions: линтеры + unit + полная установка на ubuntu-24.04 + `doctor --e2e`.

## 6. Документация (RU)
- [ ] INSTALL, CLIENTS (совместимость клиентов с Xray ≥ 26.9.8), OPERATIONS, SECURITY, TESTING, ARCHITECTURE.

## 7. Следующие фазы (вне v2.0.0)
- [ ] Российский relay-VPS (Yandex/VK Cloud) для режима «белых списков» на мобильном интернете.
- [ ] Port hopping для Hysteria2.
- [ ] Отдельный Telegram-бот поверх API (сейчас — встроенный бот 3x-ui).
