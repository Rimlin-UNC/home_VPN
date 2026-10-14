# ============================================================
# StealthNode — аудит действий администратора (по ТЗ п.4.1).
# Каждое изменяющее действие панели пишется в журнал.
# ============================================================
import logging

from sqlalchemy.orm import Session

from ..models import AuditLog

log = logging.getLogger("stealthnode.audit")


def audit(db: Session, action: str, detail: str = "", ip: str = "") -> None:
    """Запись события в аудит-лог (в той же транзакции, что и действие)."""
    db.add(AuditLog(action=action, detail=detail[:500], ip=ip))
    log.info("AUDIT %s: %s (%s)", action, detail, ip)
