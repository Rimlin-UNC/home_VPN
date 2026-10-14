# ============================================================
# StealthNode — конфигурация торгового бота (из bot.env).
# Секреты НИКОГДА не пишутся в лог (см. ТЗ п.4.4).
# ============================================================
import os
from dataclasses import dataclass, field


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, "") or default)
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, "") or default)
    except ValueError:
        return default


@dataclass
class BotConfig:
    api_key: str = field(default_factory=lambda: os.environ.get("OKX_API_KEY", ""))
    api_secret: str = field(default_factory=lambda: os.environ.get("OKX_API_SECRET", ""))
    api_passphrase: str = field(default_factory=lambda: os.environ.get("OKX_API_PASSPHRASE", ""))
    # DRY_RUN по умолчанию ВКЛЮЧЁН: реальные ордера только при явном "false"
    dry_run: bool = field(
        default_factory=lambda: os.environ.get("OKX_DRY_RUN", "true").lower() != "false"
    )
    symbol: str = field(default_factory=lambda: os.environ.get("OKX_SYMBOL", "BTC/USDT"))
    max_order_usdt: float = field(default_factory=lambda: _env_float("OKX_MAX_ORDER_USDT", 10.0))
    grid_step_pct: float = field(default_factory=lambda: _env_float("OKX_GRID_STEP_PCT", 0.5))
    grid_levels: int = field(default_factory=lambda: _env_int("OKX_GRID_LEVELS", 4))
    loop_sec: int = field(default_factory=lambda: _env_int("OKX_LOOP_SEC", 30))
    # Стартовый виртуальный баланс для бумажной торговли
    paper_start_usdt: float = 10_000.0

    def has_keys(self) -> bool:
        """Полный набор API-ключей задан?"""
        return bool(self.api_key and self.api_secret and self.api_passphrase)

    @property
    def effective_dry_run(self) -> bool:
        """Фактический режим: без ключей — всегда симуляция."""
        return self.dry_run or not self.has_keys()
