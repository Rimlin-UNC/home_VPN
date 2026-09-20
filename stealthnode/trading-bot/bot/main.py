# ============================================================
# StealthNode — торговый бот OKX (упрощённая grid-стратегия).
#
# Два режима:
#   * DRY_RUN (по умолчанию): полная симуляция на живых котировках
#     OKX (публичный API, ключи не нужны) — виртуальный баланс,
#     виртуальные сделки, честный PnL для панели;
#   * Боевой: реальные спотовые ордера через ccxt с защитным
#     лимитом OKX_MAX_ORDER_USDT.
#
# Статус пишется в /app/logs/status.json (читает веб-панель),
# журнал — в stdout (docker logs) и /app/logs/bot.log.
# Бот НИКОГДА не падает окончательно: любое исключение -> пауза
# и новый цикл (контейнер всё равно поднял бы restart-policy).
# ============================================================
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import ccxt

from .config import BotConfig

# Каталог логов: в контейнере — смонтированный том /app/logs;
# переопределяется переменной окружения (удобно для локальных тестов)
LOG_DIR = Path(os.environ.get("BOT_LOG_DIR", "/app/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s bot: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(LOG_DIR / "bot.log", maxBytes=2_000_000, backupCount=3),
    ],
)
log = logging.getLogger("okx-bot")


class PaperTrader:
    """
    Бумажная торговля: эмуляция простого grid'а «купить на просадке /
    продать на отскоке» относительно скользящей опорной цены.
    """

    def __init__(self, cfg: BotConfig):
        self.cfg = cfg
        self.usdt = cfg.paper_start_usdt
        self.base = 0.0                 # количество базового актива
        self.anchor: float | None = None  # опорная цена сетки
        self.trades_total = 0
        self.trades_day = 0
        self.day_marker = datetime.now(timezone.utc).date()
        self.realized_pnl = 0.0
        self.day_start_equity = cfg.paper_start_usdt
        self.positions: list[dict] = []

    def _new_day_reset(self, equity: float) -> None:
        today = datetime.now(timezone.utc).date()
        if today != self.day_marker:
            self.day_marker = today
            self.trades_day = 0
            self.day_start_equity = equity

    def equity(self, price: float) -> float:
        return self.usdt + self.base * price

    def step(self, price: float) -> None:
        cfg = self.cfg
        equity = self.equity(price)
        self._new_day_reset(equity)

        if self.anchor is None:
            self.anchor = price
            log.info("Опорная цена сетки: %.2f", price)
            return

        step = cfg.grid_step_pct / 100.0
        # Просадка ниже сетки -> докупаем на max_order_usdt
        if price <= self.anchor * (1 - step) and self.usdt >= cfg.max_order_usdt:
            amount = cfg.max_order_usdt / price
            self.usdt -= cfg.max_order_usdt
            self.base += amount
            self.trades_total += 1
            self.trades_day += 1
            self.positions.append({"side": "buy", "amount": round(amount, 8),
                                   "price": price, "ts": _now_iso()})
            log.info("BUY %.8f по %.2f (на %.2f USDT)", amount, price, cfg.max_order_usdt)
            self.anchor = price
        # Отскок выше сетки -> продаём часть
        elif price >= self.anchor * (1 + step) and self.base > 0:
            sell_usdt = min(cfg.max_order_usdt, self.base * price)
            amount = sell_usdt / price
            self.base -= amount
            self.usdt += sell_usdt
            self.trades_total += 1
            self.trades_day += 1
            self.positions.append({"side": "sell", "amount": round(amount, 8),
                                   "price": price, "ts": _now_iso()})
            self.positions = self.positions[-20:]  # шлём в панель только хвост
            log.info("SELL %.8f по %.2f (на %.2f USDT)", amount, price, sell_usdt)
            self.anchor = price

    def status(self, price: float) -> dict:
        equity = round(self.equity(price), 2)
        return {
            "dry_run": True,
            "symbol": self.cfg.symbol,
            "equity_usdt": equity,
            "pnl_day_usdt": round(equity - self.day_start_equity, 2),
            "pnl_total_usdt": round(equity - self.cfg.paper_start_usdt, 2),
            "trades_day": self.trades_day,
            "trades_total": self.trades_total,
            "positions": self.positions[-10:],
            "last_price": price,
            "updated": _now_iso(),
        }


class LiveTrader:
    """Боевой режим: реальные спотовые ордера (защитный лимит по размеру)."""

    def __init__(self, cfg: BotConfig):
        self.cfg = cfg
        self.exchange = ccxt.okx({
            "apiKey": cfg.api_key,
            "secret": cfg.api_secret,
            "password": cfg.api_passphrase,
            "enableRateLimit": True,
        })
        self.trades_total = 0
        self.trades_day = 0
        self.anchor: float | None = None

    def step(self, price: float) -> None:
        cfg = self.cfg
        if self.anchor is None:
            self.anchor = price
            return
        step = cfg.grid_step_pct / 100.0
        if price <= self.anchor * (1 - step):
            amount = cfg.max_order_usdt / price
            self.exchange.create_market_buy_order(cfg.symbol, amount)
            self.trades_total += 1
            self.trades_day += 1
            log.info("БОЕВОЙ BUY %.8f %s по %.2f", amount, cfg.symbol, price)
            self.anchor = price
        elif price >= self.anchor * (1 + step):
            balance = self.exchange.fetch_balance()
            base_ccy = cfg.symbol.split("/")[0]
            free_base = float(balance.get(base_ccy, {}).get("free") or 0)
            amount = min(cfg.max_order_usdt / price, free_base)
            if amount > 0:
                self.exchange.create_market_sell_order(cfg.symbol, amount)
                self.trades_total += 1
                self.trades_day += 1
                log.info("БОЕВОЙ SELL %.8f %s по %.2f", amount, cfg.symbol, price)
                self.anchor = price

    def status(self, price: float) -> dict:
        try:
            balance = self.exchange.fetch_balance()
            equity = float(balance.get("USDT", {}).get("total") or 0)
        except Exception:
            equity = 0.0
        return {
            "dry_run": False,
            "symbol": self.cfg.symbol,
            "equity_usdt": round(equity, 2),
            "pnl_day_usdt": None,
            "pnl_total_usdt": None,
            "trades_day": self.trades_day,
            "trades_total": self.trades_total,
            "positions": [],
            "last_price": price,
            "updated": _now_iso(),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_status(status: dict) -> None:
    """Атомарная запись status.json (читается веб-панелью)."""
    tmp = LOG_DIR / "status.json.tmp"
    tmp.write_text(json.dumps(status, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, LOG_DIR / "status.json")


def fetch_price(exchange: ccxt.Exchange, symbol: str) -> float:
    ticker = exchange.fetch_ticker(symbol)
    return float(ticker["last"])


def main() -> None:
    cfg = BotConfig()
    log.info("Старт бота: %s, режим=%s, лимит ордера=%.2f USDT",
             cfg.symbol, "СИМУЛЯЦИЯ" if cfg.effective_dry_run else "БОЕВОЙ",
             cfg.max_order_usdt)

    # Публичный клиент для котировок (без ключей) — нужен в обоих режимах
    public = ccxt.okx({"enableRateLimit": True})
    trader = PaperTrader(cfg) if cfg.effective_dry_run else LiveTrader(cfg)

    while True:
        try:
            price = fetch_price(public, cfg.symbol)
            trader.step(price)
            write_status(trader.status(price))
        except ccxt.NetworkError as exc:
            log.warning("Сетевая ошибка (повтор через цикл): %s", exc)
        except Exception as exc:  # noqa: BLE001 — бот не должен умирать
            log.exception("Неожиданная ошибка цикла: %s", exc)
        time.sleep(max(5, cfg.loop_sec))


if __name__ == "__main__":
    main()
