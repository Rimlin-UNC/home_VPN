# ============================================================
# StealthNode — настройки бэкенда (читаются из переменных окружения).
# ============================================================
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Все параметры приходят из .env (см. .env.example в корне проекта)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Доступ к панели ---
    admin_username: str = "admin"
    admin_password: str = ""            # используется только при первой инициализации
    jwt_secret: str = "INSECURE-CHANGE-ME"
    access_ttl_min: int = 30            # автовыход через 30 минут (по ТЗ)
    refresh_ttl_days: int = 14
    login_ban_threshold: int = 5        # неудачных попыток до бана
    login_ban_hours: int = 24           # длительность бана (по ТЗ)

    # --- Инфраструктура ---
    server_public_ip: str = ""
    panel_path: str = "p-change-me"
    reality_sni: str = "www.tbank.ru"
    awg_port: int = 51820
    awg_subnet: str = "10.8.0.0/24"
    awg_server_ip: str = "10.8.0.1"
    awg_mtu: int = 1280

    # --- Пути и контейнеры ---
    awg_container: str = "stealthnode-amneziawg"
    xray_container: str = "stealthnode-xray"
    bot_container: str = "stealthnode-trading-bot"
    managed_containers: str = (
        "stealthnode-amneziawg,stealthnode-xray,stealthnode-dnscrypt,"
        "stealthnode-backend,stealthnode-caddy,stealthnode-trading-bot"
    )
    awg_conf_path: Path = Path("/etc/amneziawg/awg0.conf")
    clients_dir: Path = Path("/etc/amneziawg/clients")
    xray_conf_path: Path = Path("/etc/xray/config.json")
    data_dir: Path = Path("/app/data")
    bot_env_path: Path = Path("/app/bot/bot.env")
    bot_logs_dir: Path = Path("/app/bot/logs")

    # --- База данных ---
    db_url: str = "sqlite:////app/data/stealthnode.db"

    def container_list(self) -> list[str]:
        """Список имён контейнеров стека для мониторинга статуса."""
        return [c.strip() for c in self.managed_containers.split(",") if c.strip()]


settings = Settings()
