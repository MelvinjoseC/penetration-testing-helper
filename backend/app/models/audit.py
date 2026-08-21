import uuid
from typing import Optional
from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimeStampedUUIDModel

class AuditLog(Base, TimeStampedUUIDModel):
    __tablename__ = "audit_logs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), 
        nullable=False
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), 
        nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., USER_LOGIN, SCAN_START, FINDING_EDIT
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # e.g., resource type or id
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # JSON metadata

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="audit_logs")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")
