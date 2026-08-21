import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# --- Scope Schemas ---
class ScopeBase(BaseModel):
    type: str = Field(..., description="domain, subdomain, ip, cidr, url")
    pattern: str = Field(..., description="e.g. *.mycompany.com, 192.168.1.0/24")
    is_excluded: bool = Field(False, description="Whether this pattern is excluded from scanning")

class ScopeCreate(ScopeBase):
    pass

class ScopeResponse(ScopeBase):
    id: uuid.UUID
    engagement_id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

# --- Asset Schemas ---
class AssetResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    type: str
    value: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True

# --- Engagement Schemas ---
class EngagementBase(BaseModel):
    name: str = Field(..., max_length=255)
    company: str = Field(..., max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    authorization_reference: str = Field(..., max_length=255, description="Written authorization ticket or reference")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class EngagementCreate(EngagementBase):
    pass

class EngagementResponse(EngagementBase):
    id: uuid.UUID
    organization_id: uuid.UUID
    status: str
    created_by_id: uuid.UUID
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    scopes: List[ScopeResponse] = []
    assets: List[AssetResponse] = []

    class Config:
        from_attributes = True

# --- Scan Schemas ---
class ScanCreate(BaseModel):
    engagement_id: uuid.UUID
    target: str = Field(..., description="The domain, URL, or IP to scan")
    profile: str = Field("safe", description="safe, passive")

class ScanResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target: str
    profile: str
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# --- Finding Schemas ---
class FindingResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    title: str
    severity: str
    confidence: str
    url: Optional[str] = None
    endpoint: Optional[str] = None
    description: str
    technical_details: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    request: Optional[str] = None
    response: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss: Optional[float] = None
    remediation: Optional[str] = None
    scanner: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Verification Schema ---
class VerificationRequest(BaseModel):
    method: str = Field(..., description="dns, http, manual")
    manual_override_reference: Optional[str] = Field(None, description="Ticket number/reference if manual method used")
