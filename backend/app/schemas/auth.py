import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class OrganizationBase(BaseModel):
    name: str = Field(..., max_length=255)

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationResponse(OrganizationBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    organization_name: str = Field(..., max_length=255)  # Creating a new tenant organization

class UserRegisterResponse(UserBase):
    id: uuid.UUID
    role: str
    is_active: bool
    organization_id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class UserResponse(UserBase):
    id: uuid.UUID
    role: str
    is_active: bool
    organization_id: uuid.UUID
    created_at: datetime
    organization: OrganizationResponse

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: EmailStr  # OAuth2 username matches email
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None  # user_id
    org: Optional[str] = None  # organization_id
    role: Optional[str] = None  # role
