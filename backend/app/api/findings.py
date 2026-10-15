import uuid
from typing import List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user, require_operator
from app.models.user import User
from app.models.engagement import Engagement
from app.models.scan import Finding
from app.schemas.models import FindingResponse, FindingUpdate
from app.core.audit import log_event

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingResponse])
def list_findings(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None
) -> Any:
    """
    List all findings for the tenant organization, optionally filtering by engagement, scan, severity, or status.
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
    if status_filter:
        query = query.filter(Finding.status == status_filter)
        
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

@router.patch("/{id}", response_model=FindingResponse)
def update_finding(
    id: uuid.UUID,
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_operator),
    finding_in: FindingUpdate,
    request: Request
) -> Any:
    """
    Triage and update lifecycle status, severity, or remediation details of a finding.
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

    changes = {}
    if finding_in.status is not None and finding_in.status != finding.status:
        changes["old_status"] = finding.status
        changes["new_status"] = finding_in.status
        finding.status = finding_in.status

    if finding_in.severity is not None and finding_in.severity != finding.severity:
        changes["old_severity"] = finding.severity
        changes["new_severity"] = finding_in.severity
        finding.severity = finding_in.severity

    if finding_in.remediation is not None:
        finding.remediation = finding_in.remediation
        changes["remediation_updated"] = True

    if finding_in.technical_details is not None:
        finding.technical_details = finding_in.technical_details
        changes["technical_details_updated"] = True

    if changes:
        db.add(finding)
        db.commit()
        db.refresh(finding)

        ip_address = request.client.host if request.client else None
        log_event(
            db=db,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            action="FINDING_TRIAGE",
            target=str(finding.id),
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent"),
            details=changes
        )

    return finding
