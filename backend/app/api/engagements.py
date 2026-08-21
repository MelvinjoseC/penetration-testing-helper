import uuid
from typing import List, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.deps import get_current_user
from app.models.user import User
from app.models.engagement import Engagement, Scope, Asset
from app.schemas.models import (
    EngagementCreate, EngagementResponse,
    ScopeCreate, ScopeResponse, VerificationRequest
)
from app.core.audit import log_event
from app.core.verification import (
    generate_verification_token, verify_domain_dns, verify_domain_http
)

router = APIRouter(prefix="/engagements", tags=["Engagements"])

@router.post("", response_model=EngagementResponse, status_code=status.HTTP_201_CREATED)
def create_engagement(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    engagement_in: EngagementCreate,
    request: Request
) -> Any:
    """
    Create a new security engagement under the current user's organization scope.
    """
    engagement = Engagement(
        organization_id=current_user.organization_id,
        name=engagement_in.name,
        company=engagement_in.company,
        description=engagement_in.description,
        authorization_reference=engagement_in.authorization_reference,
        start_date=engagement_in.start_date,
        end_date=engagement_in.end_date,
        created_by_id=current_user.id,
        status="active"
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    
    # Audit log
    ip_address = request.client.host if request.client else None
    log_event(
        db=db,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="ENGAGEMENT_CREATE",
        target=str(engagement.id),
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent"),
        details={"name": engagement.name, "company": engagement.company}
    )
    return engagement

@router.get("", response_model=List[EngagementResponse])
def list_engagements(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    List all active engagements for the tenant organization.
    """
    engagements = db.query(Engagement).filter(
        Engagement.organization_id == current_user.organization_id
    ).all()
    return engagements

@router.get("/{id}", response_model=EngagementResponse)
def get_engagement(
    id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Retrieve details of a specific engagement.
    """
    engagement = db.query(Engagement).filter(
        Engagement.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )
    return engagement

@router.post("/{id}/scope", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
def add_scope_rule(
    id: uuid.UUID,
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scope_in: ScopeCreate,
    request: Request
) -> Any:
    """
    Add a scan target scope inclusion or exclusion pattern to an engagement.
    """
    engagement = db.query(Engagement).filter(
        Engagement.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )
        
    scope = Scope(
        engagement_id=engagement.id,
        type=scope_in.type,
        pattern=scope_in.pattern,
        is_excluded=scope_in.is_excluded
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    
    # Audit log
    ip_address = request.client.host if request.client else None
    log_event(
        db=db,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="SCOPE_ADD",
        target=str(scope.id),
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent"),
        details={
            "engagement_id": str(engagement.id),
            "type": scope.type,
            "pattern": scope.pattern,
            "is_excluded": scope.is_excluded
        }
    )
    return scope

@router.get("/{id}/scope", response_model=List[ScopeResponse])
def get_scope_rules(
    id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    List all scope rules configured for the engagement.
    """
    engagement = db.query(Engagement).filter(
        Engagement.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )
    return engagement.scopes

@router.post("/{id}/verify")
def verify_engagement_target(
    id: uuid.UUID,
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    domain: str,
    verify_in: VerificationRequest,
    request: Request
) -> Any:
    """
    Verifies domain ownership and validates authorization.
    """
    engagement = db.query(Engagement).filter(
        Engagement.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )

    token = generate_verification_token(engagement.id)
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    verified = False
    
    # Check verification method
    if verify_in.method == "dns":
        verified = verify_domain_dns(domain, token)
    elif verify_in.method == "http":
        verified = verify_domain_http(domain, token)
    elif verify_in.method == "manual":
        # Only administrators can override manually
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrative users can perform manual overrides."
            )
        if not verify_in.manual_override_reference:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Manual override requires a document/ticket reference."
            )
        verified = True
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification method specified."
        )

    if verified:
        engagement.is_verified = True
        db.add(engagement)
        db.commit()
        
        # Log audit entry
        log_event(
            db=db,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            action="ENGAGEMENT_VERIFY",
            target=str(engagement.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "domain": domain,
                "method": verify_in.method,
                "reference": verify_in.manual_override_reference
            }
        )
        return {
            "status": "success",
            "message": "Domain authorization successfully verified.",
            "is_verified": True
        }
        
    return {
        "status": "failed",
        "message": f"Verification failed. Please add verification token: '{token}' to {domain}.",
        "is_verified": False
    }

@router.get("/{id}/token")
def get_verification_token(
    id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Retrieve the expected domain verification token for the engagement.
    """
    engagement = db.query(Engagement).filter(
        Engagement.id == id,
        Engagement.organization_id == current_user.organization_id
    ).first()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found."
        )
    token = generate_verification_token(engagement.id)
    return {
        "token": token,
        "dns_host": f"_security-verification",
        "http_path": "/.well-known/security-verification.txt"
    }
