import uuid
from typing import List, Optional
from sqlalchemy import String, ForeignKey, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimeStampedUUIDModel

class Engagement(Base, TimeStampedUUIDModel):
    __tablename__ = "engagements"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    company: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)  # active, archived
    authorization_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    
    start_date: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False
    )
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    scopes: Mapped[List["Scope"]] = relationship(
        "Scope",
        back_populates="engagement",
        cascade="all, delete-orphan"
    )
    assets: Mapped[List["Asset"]] = relationship(
        "Asset",
        back_populates="engagement",
        cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="engagement",
        cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="engagement",
        cascade="all, delete-orphan"
    )

class Scope(Base, TimeStampedUUIDModel):
    __tablename__ = "scopes"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, subdomain, ip, cidr, url
    pattern: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., *.example.com, 10.0.0.0/24
    is_excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="scopes")

class Asset(Base, TimeStampedUUIDModel):
    __tablename__ = "assets"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, subdomain, ip, service, web_app, api
    value: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., staging.mycompany.com
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="assets")
