"""Restore tenant parent foreign keys lost by SQLite batch migrations.

Revision ID: e91f3a7c2d10
Revises: c20fe121a0b4
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "e91f3a7c2d10"
down_revision: Union[str, Sequence[str], None] = "c20fe121a0b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

FOREIGN_KEYS = (
    ("services", "fk_services_default_owner_user_id", ["default_owner_user_id"], "users", ["id"]),
    ("services", "fk_services_default_owner_team_id", ["default_owner_team_id"], "teams", ["id"]),
    ("certificates", "fk_certificates_owner_user_id", ["owner_user_id"], "users", ["id"]),
    ("certificates", "fk_certificates_owner_team_id", ["owner_team_id"], "teams", ["id"]),
    ("findings", "fk_findings_issue_id", ["issue_id"], "issues", ["id"]),
)


def _existing_foreign_keys(connection) -> set[tuple[str, str, tuple[str, ...], str]]:
    inspector = sa.inspect(connection)
    existing = set()
    for table in inspector.get_table_names():
        for foreign_key in inspector.get_foreign_keys(table):
            existing.add(
                (
                    table,
                    foreign_key["name"] or "",
                    tuple(foreign_key["constrained_columns"] or ()),
                    foreign_key["referred_table"],
                )
            )
    return existing


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    existing = _existing_foreign_keys(connection)
    tables = set(inspector.get_table_names())
    for table, name, columns, referred_table, referred_columns in FOREIGN_KEYS:
        if table not in tables:
            continue
        if any(
            current_table == table
            and list(current_columns) == columns
            and current_referred == referred_table
            for current_table, _, current_columns, current_referred in existing
        ):
            continue
        if connection.dialect.name == "sqlite":
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.create_foreign_key(
                    name, referred_table, columns, referred_columns
                )
        else:
            op.create_foreign_key(
                name, table, referred_table, columns, referred_columns
            )


def downgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())
    for table, name, columns, referred_table, referred_columns in reversed(FOREIGN_KEYS):
        if table not in tables:
            continue
        existing = inspector.get_foreign_keys(table)
        if not any(
            foreign_key["name"] == name
            or (
                list(foreign_key["constrained_columns"] or ()) == columns
                and foreign_key["referred_table"] == referred_table
            )
            for foreign_key in existing
        ):
            continue
        if connection.dialect.name == "sqlite":
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.drop_constraint(name, type_="foreignkey")
        else:
            op.drop_constraint(name, table, type_="foreignkey")
