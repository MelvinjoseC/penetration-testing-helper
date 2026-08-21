import uuid
from typing import List, Optional
from sqlalchemy import String, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimeStampedUUIDModel

class Organization(Base, TimeStampedUUIDModel):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Relationships
    users: Mapped[List["User"]] = relationship(
        "User", 
        back_populates="organization", 
        cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog", 
        back_populates="organization", 
        cascade="all, delete-orphan"
    )

class User(Base, TimeStampedUUIDModel):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="tester", nullable=False)  # admin, tester, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), 
        nullable=False
    )
    
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog", 
        back_populates="user", 
        cascade="all, delete-orphan"
    )
