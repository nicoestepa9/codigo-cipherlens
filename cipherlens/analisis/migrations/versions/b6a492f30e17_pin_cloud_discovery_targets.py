"""Persist DNS-pinned cloud discovery targets.

Revision ID: b6a492f30e17
Revises: da42b1f2c841
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b6a492f30e17"
down_revision: Union[str, Sequence[str], None] = "da42b1f2c841"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "discovery_jobs" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("discovery_jobs")}
        if "resolved_targets" not in columns:
            op.add_column(
                "discovery_jobs",
                sa.Column("resolved_targets", sa.JSON(), nullable=True),
            )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "discovery_jobs" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("discovery_jobs")}
        if "resolved_targets" in columns:
            op.drop_column("discovery_jobs", "resolved_targets")
