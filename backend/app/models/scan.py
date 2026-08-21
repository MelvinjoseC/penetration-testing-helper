import uuid
from typing import Optional
from sqlalchemy import String, ForeignKey, Float, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimeStampedUUIDModel

class Scan(Base, TimeStampedUUIDModel):
    __tablename__ = "scans"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(50), default="safe", nullable=False)  # passive, safe
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)  # pending, running, completed, failed

    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

class Finding(Base, TimeStampedUUIDModel):
    __tablename__ = "findings"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True
    )
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="Medium", nullable=False)  # Critical, High, Medium, Low, Info
    confidence: Mapped[str] = mapped_column(String(50), default="Potential", nullable=False)  # Confirmed, Likely, Potential
    
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    technical_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    request: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., CWE-200
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # e.g., A01:2021-Broken Access Control
    cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="New", nullable=False)  # New, Potential, Confirmed, False Positive, Resolved
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # SHA-256 deduplication identifier

    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="findings")
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    asset: Mapped[Optional["Asset"]] = relationship("Asset")
