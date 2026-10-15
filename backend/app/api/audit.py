import uuid
from typing import List, Any, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas.models import AuditLogResponse

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
def list_audit_logs(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    action: Optional[str] = Query(None, description="Filter by event action (e.g. USER_LOGIN, SCAN_START)"),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user UUID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200)
) -> Any:
    """
    Query the immutable audit log for the current tenant organization.
    Supports filtering by action, user ID, and pagination.
    """
    query = db.query(AuditLog).filter(
        AuditLog.organization_id == current_user.organization_id
    )
    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    logs = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
    return logs
