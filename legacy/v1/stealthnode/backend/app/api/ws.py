# ============================================================
# StealthNode — WebSocket: real-time данные дашборда (каждые 2 сек).
# Скорости устройств (↓/↑), суммарный трафик, нагрузка сервера,
# статусы сервисов. Аутентификация — access-токеном в query (?token=).
# ============================================================
import asyncio
import time

import psutil
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..config import settings
from ..security import decode_access_token
from ..services import docker_client, xray_manager
from ..services.traffic_monitor import monitor

router = APIRouter()

PUSH_PERIOD = 2.0  # секунд (по ТЗ)


def _auth_ok(token: str | None) -> bool:
    return bool(token) and decode_access_token(token) is not None


@router.websocket("/api/ws")
async def dashboard_ws(ws: WebSocket):
    token = ws.query_params.get("token")
    if not _auth_ok(token):
        await ws.close(code=4401)
        return
    await ws.accept()

    prev: dict[str, dict[str, int]] = {}
    prev_t = time.monotonic()
    prev_net = psutil.net_io_counters()
    tick = 0

    try:
        while True:
            started = time.monotonic()
            try:
                # Один замер статистики Xray на тик: и скорости, и статусы
                raw = xray_manager.user_traffic()
                cum = monitor.cumulative(raw)
            except Exception:
                # Ядро VPN недоступно (перезапуск и т.п.) — шлём «пустой» тик,
                # соединение не рвём: панель продолжит ждать данные
                cum = {}
            now = time.monotonic()
            dt = max(now - prev_t, 0.001)

            # Скорость по каждому пользователю (байт/с) из приращения
            peers_out = []
            total_rx_rate = total_tx_rate = 0.0
            for email, cur in cum.items():
                old = prev.get(email, cur)
                rx_rate = max(0, cur["rx"] - old["rx"]) / dt
                tx_rate = max(0, cur["tx"] - old["tx"]) / dt
                total_rx_rate += rx_rate
                total_tx_rate += tx_rate
                peers_out.append({
                    "name": email,
                    "online": monitor.is_online(email),
                    "rx_rate": round(rx_rate, 1),   # ↑ загрузка КЛИЕНТА
                    "tx_rate": round(tx_rate, 1),   # ↓ скачивание КЛИЕНТА
                    "cum_rx": cur["rx"], "cum_tx": cur["tx"],
                })
            prev = cum
            prev_t = now

            # Нагрузка сервера
            net = psutil.net_io_counters()
            mem = psutil.virtual_memory()
            payload = {
                "ts": int(time.time()),
                "peers": peers_out,
                "summary": {"rx_rate": round(total_rx_rate, 1), "tx_rate": round(total_tx_rate, 1)},
                "system": {
                    "cpu_pct": psutil.cpu_percent(interval=None),
                    "mem_pct": mem.percent,
                    "mem_used_mb": round(mem.used / 2**20),
                    "mem_total_mb": round(mem.total / 2**20),
                    "net_rx_rate": round(max(0, net.bytes_recv - prev_net.bytes_recv) / dt, 1),
                    "net_tx_rate": round(max(0, net.bytes_sent - prev_net.bytes_sent) / dt, 1),
                },
            }
            prev_net = net

            # Статусы сервисов — не каждый тик (docker stats дорогой), а раз в ~10 сек
            if tick % 5 == 0:
                payload["services"] = [
                    docker_client.container_status(n) for n in settings.container_list()
                ]

            await ws.send_json(payload)
            tick += 1
            await asyncio.sleep(max(0.2, PUSH_PERIOD - (time.monotonic() - started)))
    except (WebSocketDisconnect, RuntimeError):
        return
