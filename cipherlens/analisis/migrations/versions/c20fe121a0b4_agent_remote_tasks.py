"""Add agent-pulled remote tasks and idempotent result links.

Revision ID: c20fe121a0b4
Revises: b6a492f30e17
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c20fe121a0b4"
down_revision: Union[str, Sequence[str], None] = "b6a492f30e17"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    if "agent_tasks" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "agent_tasks",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column(
                "organization_id",
                sa.Integer(),
                sa.ForeignKey("organizations.id"),
                nullable=False,
            ),
            sa.Column(
                "agent_id", sa.String(length=36), sa.ForeignKey("agents.id"),
                nullable=False,
            ),
            sa.Column("type", sa.String(length=16), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column(
                "requested_by_user_id",
                sa.String(length=36),
                sa.ForeignKey("users.id"),
                nullable=True,
            ),
            sa.Column(
                "recurring_scan_id",
                sa.Integer(),
                sa.ForeignKey("recurring_scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("claimed_at", sa.DateTime(), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column(
                "result_scan_id",
                sa.String(length=36),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "result_job_id",
                sa.String(length=36),
                sa.ForeignKey("discovery_jobs.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.CheckConstraint(
                "type IN ('scan', 'discovery')", name="ck_agent_tasks_type"
            ),
            sa.CheckConstraint(
                "status IN ('queued', 'claimed', 'running', 'done', 'failed', "
                "'rejected', 'expired', 'cancelled')",
                name="ck_agent_tasks_status",
            ),
        )

    for table in ("scans", "discovery_jobs"):
        if "task_id" not in _columns(table):
            op.add_column(
                table, sa.Column("task_id", sa.String(length=36), nullable=True)
            )
        index = f"ix_{table}_task_id"
        existing_indexes = {
            idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)
        }
        if index not in existing_indexes:
            op.create_index(index, table, ["task_id"], unique=False)

    recurring_columns = _columns("recurring_scans")
    if "agent_id" not in recurring_columns:
        with op.batch_alter_table("recurring_scans") as batch:
            batch.add_column(sa.Column("agent_id", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_recurring_scans_agent_id_agents",
                "agents",
                ["agent_id"],
                ["id"],
                ondelete="SET NULL",
            )
    recurring_indexes = {
        idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes("recurring_scans")
    }
    if "ix_recurring_scans_agent_id" not in recurring_indexes:
        op.create_index(
            "ix_recurring_scans_agent_id", "recurring_scans", ["agent_id"]
        )

    for table in ("scans", "discovery_jobs"):
        index = f"uq_{table}_task_id"
        existing_indexes = {
            idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)
        }
        if index not in existing_indexes:
            op.create_index(
                index,
                table,
                ["task_id"],
                unique=True,
                sqlite_where=sa.text("task_id IS NOT NULL"),
                postgresql_where=sa.text("task_id IS NOT NULL"),
            )

    inspector = sa.inspect(op.get_bind())
    task_indexes = {
        idx["name"] for idx in inspector.get_indexes("agent_tasks")
    }
    for name, columns in (
        ("ix_agent_tasks_agent_status", ["agent_id", "status", "created_at"]),
        ("ix_agent_tasks_org_status", ["organization_id", "status", "created_at"]),
    ):
        if name not in task_indexes:
            op.create_index(name, "agent_tasks", columns, unique=False)


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "agent_tasks" in tables:
        op.drop_table("agent_tasks")
    for table in ("scans", "discovery_jobs"):
        if table not in tables:
            continue
        existing = {idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes(table)}
        for index in (f"uq_{table}_task_id", f"ix_{table}_task_id"):
            if index in existing:
                op.drop_index(index, table_name=table)
        if "task_id" in _columns(table):
            op.drop_column(table, "task_id")
    if "recurring_scans" in tables:
        indexes = {
            idx["name"]
            for idx in sa.inspect(op.get_bind()).get_indexes("recurring_scans")
        }
        if "ix_recurring_scans_agent_id" in indexes:
            op.drop_index("ix_recurring_scans_agent_id", table_name="recurring_scans")
        if "agent_id" in _columns("recurring_scans"):
            # SQLite does not preserve the named FK in sqlite_master, so let the
            # batch table rebuild drop it together with the column.
            with op.batch_alter_table("recurring_scans") as batch:
                batch.drop_column("agent_id")
