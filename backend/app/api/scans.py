import uuid
from typing import List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user, require_operator
from app.models.user import User
from app.models.engagement import Engagement, Scope
from app.models.scan import Scan
from app.schemas.models import ScanCreate, ScanResponse
from app.core.scope import ScopeService
from app.tasks.scan_task import run_scan
from app.core.audit import log_event

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator),
    scan_in: ScanCreate,
    request: Request
) -> Any:
    """
    Triggers a security scan against a verified, in-scope target domain/URL.
    """
    # 1. Fetch engagement and verify ownership
    engagement = db.query(Engagement).filter(
        Engagement.id == scan_in.engagement_id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )

    # Guard: Must be verified first
    if not engagement.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain authorization not verified yet. Please perform target verification first."
        )

    # Guard: Target must lie inside permitted scope rules
    scope_rules = db.query(Scope).filter(Scope.engagement_id == engagement.id).all()
    if not ScopeService.is_allowed(scan_in.target, scope_rules):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target '{scan_in.target}' is outside the authorized scope or explicitly excluded."
        )

    # 2. Create the Scan record
    scan = Scan(
        engagement_id=engagement.id,
        target=scan_in.target,
        profile=scan_in.profile,
        status="pending"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 3. Queue the task to Redis/Celery worker
    run_scan.delay(str(scan.id))

    # Audit log
    ip_address = request.client.host if request.client else None
    log_event(
        db=db,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="SCAN_START",
        target=str(scan.id),
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent"),
        details={
            "target": scan.target,
            "profile": scan.profile,
            "engagement_id": str(engagement.id)
        }
    )

    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_id: Optional[uuid.UUID] = None
) -> Any:
    """
    List all scans configured. Can optionally filter by engagement_id.
    """
    query = db.query(Scan).join(Engagement).filter(
        Engagement.organization_id == current_user.organization_id
    )
    if engagement_id:
        query = query.filter(Scan.engagement_id == engagement_id)
        
    return query.all()

@router.get("/{id}", response_model=ScanResponse)
def get_scan(
    id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get detailed execution status of a scan job.
    """
    scan = db.query(Scan).join(Engagement).filter(
        Scan.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found."
        )
    return scan
