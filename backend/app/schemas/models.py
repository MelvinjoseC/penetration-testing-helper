import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- Scope Schemas ---
class ScopeBase(BaseModel):
    type: str = Field(..., description="domain, subdomain, ip, cidr, url")
    pattern: str = Field(..., min_length=1, max_length=255, description="e.g. *.mycompany.com, 192.168.1.0/24")
    is_excluded: bool = Field(False, description="Whether this pattern is excluded from scanning")

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        valid_types = {"domain", "subdomain", "ip", "cidr", "url"}
        v_clean = v.strip().lower()
        if v_clean not in valid_types:
            raise ValueError(f"Invalid scope type '{v}'. Allowed types: {', '.join(sorted(valid_types))}")
        return v_clean

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("Pattern cannot be empty or whitespace only")
        return v_clean

class ScopeCreate(ScopeBase):
    pass

class ScopeUpdate(BaseModel):
    type: Optional[str] = Field(None, description="domain, subdomain, ip, cidr, url")
    pattern: Optional[str] = Field(None, min_length=1, max_length=255)
    is_excluded: Optional[bool] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            valid_types = {"domain", "subdomain", "ip", "cidr", "url"}
            v_clean = v.strip().lower()
            if v_clean not in valid_types:
                raise ValueError(f"Invalid scope type '{v}'. Allowed types: {', '.join(sorted(valid_types))}")
            return v_clean
        return v

class ScopeResponse(ScopeBase):
    id: uuid.UUID
    engagement_id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Asset Schemas ---
class AssetResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    type: str
    value: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Engagement Schemas ---
class EngagementBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    company: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    authorization_reference: str = Field(..., min_length=1, max_length=255, description="Written authorization ticket or reference")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class EngagementCreate(EngagementBase):
    pass

class EngagementUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    company: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    authorization_reference: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[str] = Field(None, description="active, archived, completed")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

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

    model_config = ConfigDict(from_attributes=True)

# --- Scan Schemas ---
class ScanCreate(BaseModel):
    engagement_id: uuid.UUID
    target: str = Field(..., min_length=1, max_length=2048, description="The domain, URL, or IP to scan")
    profile: str = Field("safe", description="safe, passive")

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        valid_profiles = {"safe", "passive"}
        v_clean = v.strip().lower()
        if v_clean not in valid_profiles:
            raise ValueError(f"Invalid scan profile '{v}'. Allowed profiles: {', '.join(sorted(valid_profiles))}")
        return v_clean

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("Target cannot be empty")
        return v_clean

class ScanResponse(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target: str
    profile: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Finding Schemas ---
class FindingUpdate(BaseModel):
    status: Optional[str] = Field(None, description="New, Confirmed, False Positive, Resolved, Risk Accepted")
    severity: Optional[str] = Field(None, description="Critical, High, Medium, Low, Info")
    remediation: Optional[str] = None
    technical_details: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            valid_statuses = {"New", "Confirmed", "False Positive", "Resolved", "Risk Accepted"}
            if v not in valid_statuses:
                raise ValueError(f"Invalid status '{v}'. Allowed: {', '.join(sorted(valid_statuses))}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
            if v not in valid_severities:
                raise ValueError(f"Invalid severity '{v}'. Allowed: {', '.join(sorted(valid_severities))}")
        return v

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

    model_config = ConfigDict(from_attributes=True)

# --- Verification Schema ---
class VerificationRequest(BaseModel):
    method: str = Field(..., description="dns, http, manual")
    manual_override_reference: Optional[str] = Field(None, description="Ticket number/reference if manual method used")

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        valid_methods = {"dns", "http", "manual"}
        v_clean = v.strip().lower()
        if v_clean not in valid_methods:
            raise ValueError(f"Invalid verification method '{v}'. Allowed: {', '.join(sorted(valid_methods))}")
        return v_clean
