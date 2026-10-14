# Обслуживание StealthNode

Все команды — от root (`sudo`). Справка: `stealthnode --help`, `stealthnode user --help`.

## Пользователи

```bash
stealthnode user list                       # все пользователи: трафик, лимит, IP, онлайн
stealthnode user add sister                 # лимиты по умолчанию (SN_DEFAULT_LIMIT_GB / SN_DEFAULT_IP_LIMIT)
stealthnode user add guest --gb 10 --ip 1 --days 30   # временный доступ на 30 дней
stealthnode user add me2 --unlimited        # без лимитов
stealthnode user show sister --qr           # подписка, ссылки, QR-код в терминале
stealthnode user limit sister --gb 80 --ip 3  # изменить лимиты (трафик сбрасывается 1-го числа)
stealthnode user reset sister               # обнулить трафик сейчас
stealthnode user del guest --yes            # удалить
stealthnode links                           # пересоздать файлы ссылок и QR для всех
```

Файлы для отправки пользователю: `/opt/stealthnode/users/<имя>/links.txt`,
`qr-subscription.png` (главный), `qr-xhttp.png`, `qr-vision.png`, `qr-hysteria2.png`.
Скачать к себе: `scp root@<IP>:/opt/stealthnode/users/mama/qr-subscription.png .`

То же можно делать в панели 3X-UI («Клиенты»): пользователь, созданный в панели, должен быть
привязан ко всем трём инбаундам `SN-*` (команда `stealthnode provision` привяжет недостающие).

### Как работают лимиты

- **Трафик** — одна квота на человека для всех трёх профилей. При исчерпании 3x-ui отключает
  пользователя (соединения рвутся), 1-го числа месяца трафик обнуляется и доступ возвращается
  (часовой пояс — `SN_TIMEZONE`, по умолчанию Europe/Moscow).
- **IP** — сколько разных IP могут быть подключены одновременно. Превышение: «лишний» старый IP
  блокируется fail2ban (jail `3x-ipl`) на 30 минут на всех портах, кроме SSH и панели.

## Проверка состояния

```bash
stealthnode doctor           # службы, порты, UFW, BBR, fail2ban, DNS, HTTPS, REALITY, подписка, права
stealthnode doctor --e2e     # + реальное подключение по каждому профилю
stealthnode doctor --e2e --speed   # + замер скорости через туннель (с сервера)
stealthnode info             # сводка: адреса, порты, версии
```

## Резервные копии

- Автоматически каждый день около 03:15 (таймер `stealthnode-backup.timer`), хранится 14 архивов
  в `/opt/stealthnode/backups/` (права 600).
- Вручную: `stealthnode backup [--keep N]`.
- Что внутри: БД панели (согласованный снимок SQLite), `.env` (ключи и пароли), профили
  пользователей, сертификаты Hysteria2, Caddyfile, файл учётных данных.
- **Храните копию вне сервера** (архив содержит секреты — только в надёжном месте):
  `scp root@<IP>:/opt/stealthnode/backups/stealthnode-*.tar.gz ~/backup/`.
- Восстановление на том же сервере: `stealthnode restore <архив>`;
  на новом — `install.sh --restore <архив>` ([INSTALL.md](INSTALL.md#переезд-на-новый-vps-например-ip-заблокирован)).
- Telegram-бот 3x-ui (если включён) умеет присылать бэкап БД панели.

## Обновления

| Что | Как |
|---|---|
| Ubuntu (безопасность) | автоматически (unattended-upgrades), перезагрузка при обновлении ядра в 01:30 UTC |
| StealthNode | `cd ~/home_VPN && git pull && sudo bash stealthnode/install.sh` (повторный запуск безопасен) |
| 3X-UI и Xray | версия закреплена в `stealthnode/versions.env`; обновляется вместе с StealthNode после проверки в CI. Встроенное обновление панели (`x-ui update`) возможно, но не проверено нами — сначала `stealthnode backup` |
| Caddy | из официального APT-репозитория вместе с системными пакетами (`apt upgrade`) |

## Сертификаты

- Панель и подписка: Caddy получает и продлевает Let's Encrypt сам (нужен открытый 80/tcp).
- Hysteria2: таймер `stealthnode-certsync.timer` каждые 6 часов копирует сертификат Caddy в
  `/opt/stealthnode/hysteria/` и перезапускает Xray при изменении. Вручную: `stealthnode cert-sync`.

## Смена SNI или ключей REALITY

```bash
stealthnode sni-check                  # проверить кандидатов с сервера
stealthnode sni-set ya.ru              # сменить SNI и цель на обоих VLESS-профилях
# новые ключи REALITY (если ключ скомпрометирован):
stealthnode env set SN_REALITY_PRIVATE_KEY= SN_REALITY_SHORT_ID=
sudo bash ~/home_VPN/stealthnode/install.sh   # сгенерирует новые и применит
```

После смены пользователям нужно **обновить подписку** в приложении (или подождать автообновления).

## Журналы

| Что | Где |
|---|---|
| Установка | `/var/log/stealthnode/install-*.log` |
| Панель 3x-ui и Xray | `journalctl -u x-ui`, `/var/log/x-ui/3xui.log` (журнал подключений Xray не ведётся — приватность) |
| Caddy | `journalctl -u caddy`, `/var/log/caddy/caddy.log` |
| fail2ban | `fail2ban-client status sshd`, `/var/log/fail2ban.log` |
| dnscrypt-proxy | `journalctl -u dnscrypt-proxy` |

Разблокировать IP: `fail2ban-client set sshd unbanip 1.2.3.4` (или `stealthnode-panel`, `3x-ipl`).

## Telegram-бот

Встроенный бот 3x-ui (русский язык): статистика, уведомления о входе в панель, исчерпании
трафика, бэкапы. Включение: создайте бота у @BotFather, узнайте свой chat id (например, через
@userinfobot) и выполните `sudo bash stealthnode/install.sh --tg-token <токен> --tg-chat <id>`
(или в панели: «Настройки» → «Telegram-бот»).

## Удаление

```bash
sudo bash stealthnode/uninstall.sh               # убрать StealthNode, оставить 3x-ui, профили и бэкапы
sudo bash stealthnode/uninstall.sh --purge-panel # + удалить 3x-ui и Caddy
sudo bash stealthnode/uninstall.sh --purge-all   # + удалить /opt/stealthnode (включая бэкапы)
```
