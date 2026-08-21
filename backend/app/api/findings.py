import uuid
from typing import List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.engagement import Engagement
from app.models.scan import Finding
from app.schemas.models import FindingResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingResponse])
def list_findings(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    severity: Optional[str] = None
) -> Any:
    """
    List all findings for the tenant organization, optionally filtering by engagement, scan, or severity.
    """
    query = db.query(Finding).join(Engagement).filter(
        Engagement.organization_id == current_user.organization_id
    )
    
    if engagement_id:
        query = query.filter(Finding.engagement_id == engagement_id)
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
        
    return query.all()

@router.get("/{id}", response_model=FindingResponse)
def get_finding(
    id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Retrieve details of a specific security finding.
    """
    finding = db.query(Finding).join(Engagement).filter(
        Finding.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found."
        )
    return finding
