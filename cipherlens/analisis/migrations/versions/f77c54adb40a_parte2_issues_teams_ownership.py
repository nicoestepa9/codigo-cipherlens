"""parte2_issues_teams_ownership

Revision ID: f77c54adb40a
Revises: 8dd8fe088a89
Create Date: 2026-10-18 02:06:32.136795

Solo agrega los objetos de la Parte 2 (issues/teams/ownership). Los cambios de la
Parte 1 (auth) ya estan en la revision 8dd8fe088a89.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f77c54adb40a'
down_revision: Union[str, Sequence[str], None] = '8dd8fe088a89'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_table(table: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return inspector.has_table(table)


def upgrade() -> None:
    if not _has_table("teams"):
        op.create_table(
            'teams',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('organization_id', sa.Integer(), nullable=True),
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.Column('description', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('teams', schema=None) as batch_op:
            batch_op.create_index('uq_teams_org_name', ['organization_id', 'name'], unique=True)

    if not _has_table("team_members"):
        op.create_table(
            'team_members',
            sa.Column('team_id', sa.String(length=36), nullable=False),
            sa.Column('user_id', sa.String(length=36), nullable=False),
            sa.Column('added_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
            sa.PrimaryKeyConstraint('team_id', 'user_id')
        )

    if not _has_table("issues"):
        op.create_table(
            'issues',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('organization_id', sa.Integer(), nullable=True),
            sa.Column('service_id', sa.String(length=36), nullable=False),
            sa.Column('source_document', sa.String(length=32), nullable=False),
            sa.Column('rule_id', sa.String(length=64), nullable=False),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('severity', sa.String(length=20), nullable=False),
            sa.Column('status', sa.String(length=32), nullable=False),
            sa.Column('owner_user_id', sa.String(length=36), nullable=True),
            sa.Column('owner_team_id', sa.String(length=36), nullable=True),
            sa.Column('first_seen_at', sa.DateTime(), nullable=False),
            sa.Column('last_seen_at', sa.DateTime(), nullable=True),
            sa.Column('last_scan_id', sa.String(length=36), nullable=True),
            sa.Column('due_at', sa.DateTime(), nullable=True),
            sa.Column('resolved_at', sa.DateTime(), nullable=True),
            sa.Column('resolved_by', sa.String(length=16), nullable=True),
            sa.Column('verified_at', sa.DateTime(), nullable=True),
            sa.Column('clean_scans_since_resolved', sa.Integer(), nullable=False),
            sa.Column('risk_accepted_by', sa.String(length=36), nullable=True),
            sa.Column('risk_acceptance_reason', sa.Text(), nullable=True),
            sa.Column('risk_accepted_until', sa.DateTime(), nullable=True),
            sa.Column('reopened_count', sa.Integer(), nullable=False),
            sa.Column('last_certificate_fingerprint', sa.String(length=128), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['last_scan_id'], ['scans.id'], ),
            sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
            sa.ForeignKeyConstraint(['owner_team_id'], ['teams.id'], ),
            sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ),
            sa.ForeignKeyConstraint(['risk_accepted_by'], ['users.id'], ),
            sa.ForeignKeyConstraint(['service_id'], ['services.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('issues', schema=None) as batch_op:
            batch_op.create_index('ix_issues_service_id', ['service_id'], unique=False)
            batch_op.create_index('uq_issues_identity', ['service_id', 'source_document', 'rule_id'], unique=True)

    if not _has_table("issue_history"):
        op.create_table(
            'issue_history',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('issue_id', sa.String(length=36), nullable=False),
            sa.Column('ts', sa.DateTime(), nullable=False),
            sa.Column('actor_user_id', sa.String(length=36), nullable=True),
            sa.Column('actor_type', sa.String(length=16), nullable=False),
            sa.Column('event_type', sa.String(length=32), nullable=False),
            sa.Column('from_value', sa.String(length=64), nullable=True),
            sa.Column('to_value', sa.String(length=64), nullable=True),
            sa.Column('comment', sa.Text(), nullable=True),
            sa.Column('scan_id', sa.String(length=36), nullable=True),
            sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ),
            sa.ForeignKeyConstraint(['issue_id'], ['issues.id'], ),
            sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('issue_history', schema=None) as batch_op:
            batch_op.create_index('ix_issue_history_issue_id', ['issue_id'], unique=False)
            batch_op.create_index('ix_issue_history_ts', ['ts'], unique=False)

    if not _has_column("alerts", "related_issue_id"):
        with op.batch_alter_table('alerts', schema=None) as batch_op:
            batch_op.add_column(sa.Column('related_issue_id', sa.String(length=36), nullable=True))
            batch_op.create_index('ix_alerts_related_issue_id', ['related_issue_id'], unique=False)

    if not _has_column("certificates", "owner_user_id"):
        with op.batch_alter_table('certificates', schema=None) as batch_op:
            batch_op.add_column(sa.Column('owner_user_id', sa.String(length=36), nullable=True))
            batch_op.add_column(sa.Column('owner_team_id', sa.String(length=36), nullable=True))

    if not _has_column("findings", "issue_id"):
        with op.batch_alter_table('findings', schema=None) as batch_op:
            batch_op.add_column(sa.Column('issue_id', sa.String(length=36), nullable=True))
            batch_op.create_index('ix_findings_issue_id', ['issue_id'], unique=False)

    if not _has_column("services", "default_owner_user_id"):
        with op.batch_alter_table('services', schema=None) as batch_op:
            batch_op.add_column(sa.Column('default_owner_user_id', sa.String(length=36), nullable=True))
            batch_op.add_column(sa.Column('default_owner_team_id', sa.String(length=36), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('services', schema=None) as batch_op:
        if _has_column("services", "default_owner_team_id"):
            batch_op.drop_column('default_owner_team_id')
        if _has_column("services", "default_owner_user_id"):
            batch_op.drop_column('default_owner_user_id')

    with op.batch_alter_table('findings', schema=None) as batch_op:
        if _has_column("findings", "issue_id"):
            batch_op.drop_index('ix_findings_issue_id')
            batch_op.drop_column('issue_id')

    with op.batch_alter_table('certificates', schema=None) as batch_op:
        if _has_column("certificates", "owner_user_id"):
            batch_op.drop_column('owner_team_id')
            batch_op.drop_column('owner_user_id')

    with op.batch_alter_table('alerts', schema=None) as batch_op:
        if _has_column("alerts", "related_issue_id"):
            batch_op.drop_index('ix_alerts_related_issue_id')
            batch_op.drop_column('related_issue_id')

    if _has_table("issue_history"):
        op.drop_table('issue_history')
    if _has_table("issues"):
        op.drop_table('issues')
    if _has_table("team_members"):
        op.drop_table('team_members')
    if _has_table("teams"):
        op.drop_table('teams')
