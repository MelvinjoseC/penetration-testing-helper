import uuid
from datetime import datetime
from typing import Optional
import re
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationResponse(OrganizationBase):
    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    organization_name: str = Field(..., min_length=1, max_length=255)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one numerical digit.")
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one alphabetical letter.")
        return v

class UserRegisterResponse(UserBase):
    id: uuid.UUID
    role: str
    is_active: bool
    organization_id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserResponse(UserBase):
    id: uuid.UUID
    role: str
    is_active: bool
    organization_id: uuid.UUID
    created_at: datetime
    organization: OrganizationResponse

    model_config = ConfigDict(from_attributes=True)

class UserLogin(BaseModel):
    username: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    org: Optional[str] = None
    role: Optional[str] = None
