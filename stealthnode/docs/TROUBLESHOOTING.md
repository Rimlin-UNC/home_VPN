# 🛠️ StealthNode — диагностика типовых проблем

Общая команда для осмотра стека (из каталога установки, обычно `/opt/stealthnode`):

```bash
docker compose ps                          # состояние контейнеров
docker compose logs --tail=100 amneziawg   # логи конкретного сервиса:
                                           # amneziawg | xray | dnscrypt | backend | caddy | trading-bot
```

---

## 1. Панель не открывается

- Проверьте URL целиком: `https://IP:ПОРТ/p-XXXX/` — важен **секретный путь и слэш
  в конце**. На любом другом пути сервер отвечает 404 — так задумано.
- Данные — в `/root/stealthnode-credentials.txt` или через `sudo ./setup.sh` (п.3).
- Самоподписанный сертификат: браузер просит подтвердить исключение — это нормально.
- Проверьте, что контейнеры живы: `docker compose ps`, лог `caddy` и `backend`.

## 2. Клиент не подключается к AmneziaWG

1. Устройство не выключено в панели? (точка слева от имени должна быть зелёной)
2. Параметры обфускации клиента и сервера **должны совпадать**: если меняли Jc/H* в
   панели — перевыпустите ВСЕ клиентские конфиги.
3. Провайдер может резать UDP на конкретном порту: смените `AWG_PORT` в `.env`
   (другой случайный порт 20000–60000) и выполните
   `docker compose up -d --force-recreate amneziawg`, затем обновите Endpoint в клиенте.
4. Временно проверьте handshake: `docker compose exec amneziawg awg show` —
   у «мёртвого» пира `latest handshake` пустой.
5. DPI-блокировка по «магическим» H1–H4: перевыпустите установку на другом сервере —
   параметры обфускации случайны при каждой установке.

## 3. Нет интернета через туннель (handshake есть)

- Маскарад: `docker compose exec amneziawg iptables -t nat -L POSTROUTING -v -n` —
  должно быть правило MASQUERADE для `10.8.0.0/24`.
- DNS: `docker compose logs dnscrypt` — резолвер должен писать про успешные запросы;
  перехват настраивается автоматически (см. правила DNAT в `amneziawg/entrypoint.sh`).
- MTU: если сайты «наполовину» открываются — снизьте MTU до 1240 в `.env` (`AWG_MTU`)
  и в клиентском конфиге, пересоздайте контейнер.

## 4. Лимиты скорости гостей не работают

- Проверьте, что модуль ifb загружен на хосте: `lsmod | grep ifb`;
  загрузка: `modprobe ifb numifbs=1` (install.sh прописывает автозагрузку).
- Лог контейнера: `docker compose logs amneziawg | grep -i шейпер`.
- На отдельных ядрах qdisc на TUN-интерфейсе не поддерживается — классика ядра
  Linux для userspace-туннелей. Обходной путь: лимит только download через
  классы на `awg0`, либо переход на ядерный модуль AmneziaWG (PPA amnezia).

## 5. Xray/REALITY: клиент не соединяется

- Версия клиента должна поддерживать классический REALITY (без ML-KEM):
  v2rayNG < 1.9.x сборок с поддержкой X25519MLKEM768 наоборот может ломать
  совместимость — сервер сознательно зафиксирован на Xray 26.7.28.
- Время на сервере: REALITY чувствителен к расхождению часов — `timedatectl status`.
- Домен маскировки должен поддерживать TLS 1.3 **и** HTTP/2:
  `curl -sI --http2 https://ДОМЕН` должен вернуть `HTTP/2 200`.
- Проверка: `docker compose logs xray` — ошибки формата укажут на битый config.json.

## 6. Торговый бот

- **Офлайн в панели:** `docker compose logs trading-bot`. Бот не падает молча —
  в логе видно причину (сеть, ключи, пара).
- **401/403 от OKX:** проверьте ключ, секрет и passphrase; IP VPS должен быть в
  белом списке ключа; права — Trade (Withdraw НЕ включайте).
- **«Нет сделок»:** в симуляции сделки случаются при движении цены на
  `OKX_GRID_STEP_PCT` от опорной цены — на спокойном рынке подождите.
- **Ресурсы:** лимиты `cpus: 0.5 / memory: 512M` заданы в compose специально —
  не снимайте их: бот не должен мешать VPN.

## 7. Забыл пароль панели

```bash
cd /opt/stealthnode
docker compose exec backend python -m app.utils.setpassword 'НовыйПароль12345678'
```

Все сессии при этом завершаются (refresh-токены отзываются).

## 8. Полное переустановление «с нуля»

```bash
cd /opt/stealthnode
docker compose down --rmi local      # остановить стек и удалить СОБРАННЫЕ образы
sudo rm -f .env amneziawg/conf/awg0.conf xray/conf/config.json \
           amneziawg/conf/clients/*.conf trading-bot/bot.env
sudo rm -rf data
sudo ./install.sh                    # повторная установка с новыми ключами
```

## 9. Где что лежит

| Путь | Содержимое |
|---|---|
| `/opt/stealthnode/.env` | секреты и порты (600) |
| `amneziawg/conf/awg0.conf` | серверный конфиг AWG |
| `amneziawg/conf/clients/` | клиентские .conf |
| `xray/conf/config.json` | конфиг Xray REALITY |
| `data/stealthnode.db` | база панели (учётки, устройства, снапшоты) |
| `trading-bot/bot.env` | ключи OKX (600) |
| `trading-bot/logs/` | логи и status.json бота |
| `/root/stealthnode-credentials.txt` | итоговые данные установки |
| `/var/log/stealthnode-install.log` | журнал установщика |
