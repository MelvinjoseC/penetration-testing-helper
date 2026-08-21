from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.security import verify_password, get_password_hash, create_access_token
from app.auth.deps import get_current_user
from app.models.user import User, Organization
from app.schemas.auth import UserCreate, UserRegisterResponse, UserResponse, Token
from app.core.audit import log_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
    request: Request
) -> Any:
    """
    Register a new tenant organization and its administrative user.
    """
    # 1. Check if email already registered
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    
    # 2. Create the Organization
    organization = Organization(name=user_in.organization_name)
    db.add(organization)
    db.commit()
    db.refresh(organization)
    
    # 3. Create the administrative User for the Org
    hashed_password = get_password_hash(user_in.password)
    user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        role="admin",  # Default first user to admin
        organization_id=organization.id,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # 4. Log events
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    log_event(
        db=db,
        organization_id=organization.id,
        user_id=None,  # Not authenticated yet
        action="ORGANIZATION_CREATE",
        target=str(organization.id),
        ip_address=ip_address,
        user_agent=user_agent,
        details={"organization_name": organization.name}
    )
    
    log_event(
        db=db,
        organization_id=organization.id,
        user_id=user.id,
        action="USER_REGISTER",
        target=str(user.id),
        ip_address=ip_address,
        user_agent=user_agent,
        details={"email": user.email, "role": user.role}
    )
    
    return user

@router.post("/login", response_model=Token)
def login_access_token(
    *,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request
) -> Any:
    """
    OAuth2 compatible token login, retrieve a JWT access token.
    """
    # 1. Authenticate user
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    elif not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # 2. Log login event
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    log_event(
        db=db,
        organization_id=user.organization_id,
        user_id=user.id,
        action="USER_LOGIN",
        target=str(user.id),
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    # 3. Create access token
    access_token = create_access_token(
        subject=user.id,
        organization_id=user.organization_id,
        role=user.role
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserResponse)
def read_user_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user profile.
    """
    return current_user
