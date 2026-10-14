# ============================================================
# StealthNode — модели базы данных (SQLAlchemy 2).
# ============================================================
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class AdminUser(Base):
    """Единственный администратор панели (по ТЗ — один владелец)."""

    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))  # Argon2id
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class RefreshToken(Base):
    """Refresh-токены с ротацией: храним только SHA-256 хеш токена."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admin_users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), index=True)  # sha256 hex
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class LoginBan(Base):
    """Бан IP после серии неудачных входов (аналог Fail2ban для панели)."""

    __tablename__ = "login_bans"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    fails: Mapped[int] = mapped_column(Integer, default=0)
    banned_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class Device(Base):
    """VPN-устройство = пользователь Xray (UUID + email во всех транспортах)."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(8), default="xray")  # зарезервировано
    public_key: Mapped[str] = mapped_column(String(64), index=True)  # UUID VLESS
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin_device: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # delete-orphan: удаление устройства удаляет и гостевую запись
    guest: Mapped[Optional["Guest"]] = relationship(
        back_populates="device", uselist=False, cascade="all, delete-orphan"
    )


class Guest(Base):
    """Гостевой аккаунт (до 5 по ТЗ) с лимитами трафика, окном и сроком.

    Пер-юзерное ограничение СКОРОСТИ в прокси-стеке недоступно (трафик
    клиентов неразличим внутри TLS до выхода из Xray) — вместо него:
    лимиты трафика, временное окно, срок действия, приоритет-метка.
    """

    __tablename__ = "guests"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), unique=True)
    # Лимиты трафика в мегабайтах; NULL — безлимит
    quota_daily_mb: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    quota_weekly_mb: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    quota_monthly_mb: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    quota_total_mb: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Временное окно доступа (время суток, локальное), формат "HH:MM"
    window_start: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)
    window_end: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)
    # Срок действия аккаунта
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    priority: Mapped[str] = mapped_column(String(8), default="normal")  # low|normal|high
    # Служебный статус: active | disabled_admin | expired | quota | window
    status: Mapped[str] = mapped_column(String(16), default="active")
    status_detail: Mapped[str] = mapped_column(String(128), default="")

    device: Mapped[Device] = relationship(back_populates="guest")


class TrafficSnapshot(Base):
    """Снапшот накопленного трафика устройства (пишется раз в минуту)."""

    __tablename__ = "traffic_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True, server_default=func.now())
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    cum_rx: Mapped[int] = mapped_column(BigInteger, default=0)  # накоплено: сервер <- клиент
    cum_tx: Mapped[int] = mapped_column(BigInteger, default=0)  # накоплено: сервер -> клиент


class AuditLog(Base):
    """Журнал всех действий администратора (по ТЗ п.4.1)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True, server_default=func.now())
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(45), default="")


class Setting(Base):
    """Прочие персистентные значения (офсеты счётчиков трафика и т.п.)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
