# ============================================================
# StealthNode — подключение к базе данных (SQLite через SQLAlchemy 2).
# SQLite выбран осознанно: один VPS, 2 ГБ RAM; отдельный Postgres
# избыточен для одного админа и до 5 гостей.
# ============================================================
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


# check_same_thread=False — SQLite используется из threadpool'а FastAPI
engine = create_engine(settings.db_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@event.listens_for(engine, "connect")
def _sqlite_pragma(dbapi_conn, _record):
    """Включаем FK-констрейнты: SQLite по умолчанию их игнорирует,
    а нам нужны каскадные удаления (устройство -> гость/снапшоты)."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_db():
    """Зависимость FastAPI: выдаёт сессию БД и гарантированно закрывает её."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Создание таблиц при старте приложения."""
    from . import models  # noqa: F401 — регистрируем модели в метаданных

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
