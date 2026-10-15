"""Add performance indexes for multi-tenant queries and triage workflows

Revision ID: a8c2f10d4b99
Revises: 734d2eb64468
Create Date: 2026-10-15 12:40:00.000000

"""
from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a8c2f10d4b99'
down_revision: Union[str, None] = '734d2eb64468'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Performance indexes for findings queries and triage
    op.create_index('ix_findings_severity', 'findings', ['severity'], unique=False)
    op.create_index('ix_findings_status', 'findings', ['status'], unique=False)
    op.create_index('ix_findings_engagement_id', 'findings', ['engagement_id'], unique=False)

    # Performance indexes for scan tracking
    op.create_index('ix_scans_status', 'scans', ['status'], unique=False)
    op.create_index('ix_scans_engagement_id', 'scans', ['engagement_id'], unique=False)

    # Performance indexes for audit logs and tenant isolation
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'], unique=False)
    op.create_index('ix_audit_logs_organization_id', 'audit_logs', ['organization_id'], unique=False)
    op.create_index('ix_engagements_organization_id', 'engagements', ['organization_id'], unique=False)

def downgrade() -> None:
    op.drop_index('ix_engagements_organization_id', table_name='engagements')
    op.drop_index('ix_audit_logs_organization_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_action', table_name='audit_logs')
    op.drop_index('ix_scans_engagement_id', table_name='scans')
    op.drop_index('ix_scans_status', table_name='scans')
    op.drop_index('ix_findings_engagement_id', table_name='findings')
    op.drop_index('ix_findings_status', table_name='findings')
    op.drop_index('ix_findings_severity', table_name='findings')
