import uuid
from typing import Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditLog

def log_event(
    db: Session,
    organization_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    action: str,
    target: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None
) -> AuditLog:
    """
    Creates and commits an audit log entry.
    Audit logs are append-only records tracking critical system operations.
    """
    audit_log = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        target=target,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log
