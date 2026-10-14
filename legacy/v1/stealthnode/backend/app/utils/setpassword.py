# ============================================================
# StealthNode — CLI смены пароля администратора извне панели.
# Использование (на сервере):
#   docker compose -f /opt/stealthnode/docker-compose.yml exec backend \
#       python -m app.utils.setpassword 'НовыйПароль123456'
# ============================================================
import sys

from ..database import SessionLocal, init_db
from ..models import AdminUser, RefreshToken
from ..security import hash_password


def main() -> int:
    if len(sys.argv) != 2 or len(sys.argv[1]) < 16:
        print("Использование: python -m app.utils.setpassword '<новый пароль>' (мин. 16 символов)")
        return 1
    init_db()
    db = SessionLocal()
    try:
        admin = db.query(AdminUser).first()
        if admin is None:
            print("Администратор ещё не инициализирован")
            return 1
        admin.password_hash = hash_password(sys.argv[1])
        db.query(RefreshToken).filter(RefreshToken.admin_id == admin.id).update({"revoked": True})
        db.commit()
        print("Пароль администратора обновлён, все сессии завершены.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
