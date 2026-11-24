"""Add per-organization SLA day targets.

Revision ID: b7d2e4f6a8c1
Revises: e91f3a7c2d10
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b7d2e4f6a8c1"
down_revision: Union[str, Sequence[str], None] = "e91f3a7c2d10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS = (
    "sla_days_critical",
    "sla_days_high",
    "sla_days_medium",
)


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch:
        for column in COLUMNS:
            batch.add_column(sa.Column(column, sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("organizations") as batch:
        for column in reversed(COLUMNS):
            batch.drop_column(column)
