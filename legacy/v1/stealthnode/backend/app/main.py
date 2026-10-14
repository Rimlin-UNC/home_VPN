# ============================================================
# StealthNode — точка входа бэкенда (FastAPI).
# * REST API (/api/...), WebSocket (/api/ws);
# * статика панели (SPA) отдаётся с корня "/"
#   (наружу проброшена Caddy только под секретным путём);
# * при старте: БД, администратор, импорт пиров,
#   фоновые задачи (снапшоты трафика, квоты гостей);
# * строгие security-заголовки (CSP и др.).
# ============================================================
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .config import settings
from .database import SessionLocal, init_db
from .api import auth, bot, devices, guests, settings as settings_api, stats, ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("stealthnode")

STATIC_DIR = Path(__file__).parent / "static"


def _ensure_admin() -> None:
    """Первичная инициализация администратора из переменных окружения."""
    from .models import AdminUser
    from .security import hash_password

    db = SessionLocal()
    try:
        if db.query(AdminUser).count() > 0:
            return
        if len(settings.admin_password) < 16:
            log.warning("ADMIN_PASSWORD короче 16 символов — панель НЕ инициализирована! "
                        "Задайте пароль и перезапустите backend.")
            return
        db.add(AdminUser(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
        ))
        db.commit()
        log.info("Администратор '%s' инициализирован (пароль из .env, Argon2id)",
                 settings.admin_username)
    finally:
        db.close()


def _sync_devices() -> None:
    """Импорт клиентов из конфига Xray в БД при первом запуске
    (install.sh создал там клиента 'admin')."""
    from .models import Device
    from .services import xray_manager

    db = SessionLocal()
    try:
        for client_uuid, email in xray_manager.list_clients():
            if not email:
                email = client_uuid[:8]
            exists = db.query(Device).filter(Device.public_key == client_uuid).first()
            if exists:
                continue
            db.add(Device(
                name=email, kind="xray", public_key=client_uuid,
                enabled=True, is_admin_device=(email == "admin"),
            ))
            log.info("Импортирован клиент из конфига Xray: %s", email)
        db.commit()
    except Exception as exc:
        log.warning("Импорт устройств: %s", exc)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _ensure_admin()
    _sync_devices()

    # Фоновые задачи
    from .services import quota_manager, traffic_monitor

    tasks = [
        asyncio.create_task(traffic_monitor.snapshot_loop(60)),
        asyncio.create_task(quota_manager.quota_loop()),
    ]
    log.info("StealthNode backend запущен (панель: /%s/)", settings.panel_path)
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(
    title="StealthNode Panel",
    version="1.0.0",
    docs_url=None, redoc_url=None, openapi_url=None,  # API-доки наружу не светим
    lifespan=lifespan,
)


# ---------------- Security-заголовки (CSP и др., по ТЗ) ----------------
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ---------------- Health (без авторизации, для healthcheck'ов) ----------------
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "stealthnode-backend"}


@app.exception_handler(Exception)
async def unhandled(request, exc):
    log.exception("Необработанная ошибка: %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка сервера"})


# ---------------- Роутеры API ----------------
app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(guests.router)
app.include_router(stats.router)
app.include_router(bot.router)
app.include_router(settings_api.router)
app.include_router(ws.router)


# ---------------- Статика панели (SPA) ----------------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
