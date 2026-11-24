"""parte5_agents_ingest

Revision ID: a3f1c9d27b64
Revises: f77c54adb40a
Create Date: 2026-10-19 00:00:00.000000

Parte 5: agentes on-premise. Crea la tabla ``agents``, agrega ``agent_id`` al
inventario (assets/services/scans/discovery_jobs), ``client_scan_id``/
``client_job_id`` para idempotencia y los indices unicos (incluidos los
parciales de identidad de ``Service`` por ``(agent_id, host, port)``).

Los datos existentes quedan con ``agent_id = NULL`` (plataforma local).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a3f1c9d27b64'
down_revision: Union[str, Sequence[str], None] = 'f77c54adb40a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_table(table: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return inspector.has_table(table)


def _safe_exec(sql: str) -> None:
    """Ejecuta DDL de indices ignorando duplicados/colisiones de datos."""
    try:
        op.get_bind().exec_driver_sql(sql)
    except Exception:  # indice ya existente o datos que violan unicidad
        pass


def upgrade() -> None:
    if not _has_table("agents"):
        op.create_table(
            'agents',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('organization_id', sa.Integer(), nullable=True),
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.Column('site_label', sa.String(length=128), nullable=False),
            sa.Column('api_key_id', sa.String(length=36), nullable=True),
            sa.Column('version', sa.String(length=64), nullable=True),
            sa.Column('last_seen_at', sa.DateTime(), nullable=True),
            sa.Column('last_ip', sa.String(length=64), nullable=True),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('revoked_at', sa.DateTime(), nullable=True),
            sa.Column('schema_version', sa.Integer(), nullable=True),
            sa.Column('rules_version', sa.String(length=32), nullable=True),
            sa.ForeignKeyConstraint(['api_key_id'], ['api_keys.id'], ),
            sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
            sa.PrimaryKeyConstraint('id'),
        )

    for table, column in (
        ("assets", "agent_id"),
        ("services", "agent_id"),
        ("scans", "agent_id"),
        ("scans", "client_scan_id"),
        ("scans", "upload_level"),
        ("scans", "rules_version"),
        ("discovery_jobs", "agent_id"),
        ("discovery_jobs", "client_job_id"),
    ):
        if _has_table(table) and not _has_column(table, column):
            with op.batch_alter_table(table, schema=None) as batch_op:
                batch_op.add_column(sa.Column(column, sa.String(length=64), nullable=True))

    _safe_exec("CREATE INDEX IF NOT EXISTS ix_assets_agent_id ON assets (agent_id)")
    _safe_exec("CREATE INDEX IF NOT EXISTS ix_services_agent_id ON services (agent_id)")
    _safe_exec("CREATE INDEX IF NOT EXISTS ix_scans_agent_id ON scans (agent_id)")
    _safe_exec("CREATE INDEX IF NOT EXISTS ix_discovery_jobs_agent_id ON discovery_jobs (agent_id)")
    _safe_exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_services_agent_host_port "
        "ON services (agent_id, host, port) WHERE agent_id IS NOT NULL"
    )
    _safe_exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_services_platform_host_port "
        "ON services (host, port) WHERE agent_id IS NULL"
    )
    _safe_exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_agent_client "
        "ON scans (agent_id, client_scan_id)"
    )
    _safe_exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_jobs_agent_client "
        "ON discovery_jobs (agent_id, client_job_id)"
    )


def downgrade() -> None:
    for index in (
        "uq_discovery_jobs_agent_client",
        "uq_scans_agent_client",
        "uq_services_platform_host_port",
        "uq_services_agent_host_port",
        "ix_scans_agent_id",
        "ix_services_agent_id",
        "ix_assets_agent_id",
    ):
        _safe_exec(f"DROP INDEX IF EXISTS {index}")

    for table, column in (
        ("discovery_jobs", "client_job_id"),
        ("discovery_jobs", "agent_id"),
        ("scans", "client_scan_id"),
        ("scans", "agent_id"),
        ("services", "agent_id"),
        ("assets", "agent_id"),
    ):
        if _has_table(table) and _has_column(table, column):
            with op.batch_alter_table(table, schema=None) as batch_op:
                batch_op.drop_column(column)

    if _has_table("agents"):
        op.drop_table('agents')
