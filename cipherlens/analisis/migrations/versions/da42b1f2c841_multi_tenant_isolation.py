"""Add organization ownership and non-null tenant boundaries.

Revision ID: da42b1f2c841
Revises: a3f1c9d27b64
"""
from __future__ import annotations

import re
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "da42b1f2c841"
down_revision: Union[str, Sequence[str], None] = "a3f1c9d27b64"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_TABLES = (
    "users", "teams", "issues", "agents", "services", "assets", "certificates",
    "scans", "findings", "team_members", "issue_history", "discovery_jobs",
    "discovery_results", "recurring_scans", "alerts", "alert_thresholds",
    "compliance_windows", "api_keys", "integrations", "audit_logs",
    "refresh_tokens", "scan_cve_matches",
)

ORGANIZATION_COLUMNS = (
    ("users", "organization_id", sa.Integer()),
    ("teams", "organization_id", sa.Integer()),
    ("issues", "organization_id", sa.Integer()),
    ("agents", "organization_id", sa.Integer()),
    ("services", "organization_id", sa.Integer()),
    ("assets", "organization_id", sa.Integer()),
    ("certificates", "organization_id", sa.Integer()),
    ("scans", "organization_id", sa.Integer()),
    ("findings", "organization_id", sa.Integer()),
    ("team_members", "organization_id", sa.Integer()),
    ("issue_history", "organization_id", sa.Integer()),
    ("discovery_jobs", "organization_id", sa.Integer()),
    ("discovery_results", "organization_id", sa.Integer()),
    ("recurring_scans", "organization_id", sa.Integer()),
    ("alerts", "organization_id", sa.Integer()),
    ("alert_thresholds", "organization_id", sa.Integer()),
    ("compliance_windows", "organization_id", sa.Integer()),
    ("api_keys", "organization_id", sa.Integer()),
    ("integrations", "organization_id", sa.Integer()),
    ("audit_logs", "organization_id", sa.Integer()),
    ("refresh_tokens", "organization_id", sa.Integer()),
    ("scan_cve_matches", "organization_id", sa.Integer()),
)


def _columns(connection, table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(connection).get_columns(table)}


def _ensure_column(connection, table: str, name: str, type_: sa.types.TypeEngine) -> None:
    if table in sa.inspect(connection).get_table_names() and name not in _columns(connection, table):
        op.add_column(
            table,
            sa.Column(
                name,
                type_,
                nullable=True,
            ),
        )


def _backfill(connection) -> int:
    rows = connection.execute(sa.text("SELECT id, name, slug FROM organizations ORDER BY id")).all()
    used: set[str] = set()
    for row in rows:
        base = re.sub(r"[^a-z0-9]+", "-", (row.name or "").lower()).strip("-")
        base = (base or f"org-{row.id}")[:54]
        slug = row.slug or base
        if slug in used:
            slug = f"{base[:54]}-{row.id}"
        used.add(slug)
        connection.execute(
            sa.text(
                "UPDATE organizations SET slug=:slug, "
                "status=COALESCE(status, 'active'), "
                "ai_mode=COALESCE(ai_mode, 'template'), "
                "max_agents=COALESCE(max_agents, 0), "
                "max_cloud_scans_per_hour=COALESCE(max_cloud_scans_per_hour, 0), "
                "max_recurring_scans=COALESCE(max_recurring_scans, 0) WHERE id=:id"
            ),
            {"slug": slug, "id": row.id},
        )

    if not rows:
        connection.execute(
            sa.text(
                "INSERT INTO organizations "
                "(name, slug, status, ai_mode, max_agents, "
                "max_cloud_scans_per_hour, max_recurring_scans) "
                "VALUES ('Default Org', 'default', 'active', 'template', 0, 0, 0)"
            )
        )
        default_org_id = connection.execute(
            sa.text("SELECT id FROM organizations WHERE slug='default'")
        ).scalar_one()
    else:
        default_org_id = rows[0].id

    mappings = (
        "UPDATE assets SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=assets.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE services SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=services.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE scans SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=scans.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE discovery_jobs SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=discovery_jobs.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE api_keys SET organization_id=(SELECT organization_id FROM users WHERE users.id=api_keys.user_id) WHERE organization_id IS NULL AND user_id IS NOT NULL",
        "UPDATE api_keys SET organization_id=(SELECT organization_id FROM agents WHERE agents.api_key_id=api_keys.id) WHERE organization_id IS NULL AND EXISTS (SELECT 1 FROM agents WHERE agents.api_key_id=api_keys.id)",
        "UPDATE findings SET organization_id=(SELECT organization_id FROM scans WHERE scans.id=findings.scan_id) WHERE organization_id IS NULL",
        "UPDATE team_members SET organization_id=(SELECT organization_id FROM teams WHERE teams.id=team_members.team_id) WHERE organization_id IS NULL",
        "UPDATE issue_history SET organization_id=(SELECT organization_id FROM issues WHERE issues.id=issue_history.issue_id) WHERE organization_id IS NULL",
        "UPDATE discovery_results SET organization_id=(SELECT organization_id FROM discovery_jobs WHERE discovery_jobs.id=discovery_results.discovery_job_id) WHERE organization_id IS NULL",
        "UPDATE scan_cve_matches SET organization_id=(SELECT organization_id FROM scans WHERE scans.id=scan_cve_matches.scan_id) WHERE organization_id IS NULL",
    )
    for statement in mappings:
        connection.execute(sa.text(statement))
    for table in TENANT_TABLES:
        connection.execute(
            sa.text(
                f'UPDATE "{table}" SET organization_id=:org_id '
                "WHERE organization_id IS NULL"
            ),
            {"org_id": default_org_id},
        )
    return default_org_id


def _ensure_indexes(connection) -> None:
    existing = {
        table: {index["name"] for index in sa.inspect(connection).get_indexes(table)}
        for table in sa.inspect(connection).get_table_names()
    }

    def create(table: str, name: str, columns: list[str], *, unique: bool = False, where=None):
        if name not in existing.get(table, set()):
            kwargs = {}
            if where is not None:
                kwargs["sqlite_where"] = where
                kwargs["postgresql_where"] = where
            op.create_index(name, table, columns, unique=unique, **kwargs)

    for table in TENANT_TABLES:
        create(table, f"ix_{table}_organization_id", ["organization_id"])
    create("teams", "uq_teams_org_name", ["organization_id", "name"], unique=True)
    create("services", "uq_services_agent_host_port", ["agent_id", "host", "port"],
           unique=True, where=sa.text("agent_id IS NOT NULL"))
    create("services", "uq_services_platform_host_port",
           ["organization_id", "host", "port"], unique=True,
           where=sa.text("agent_id IS NULL"))
    create("assets", "uq_assets_agent_identity",
           ["agent_id", "ip_address", "hostname"], unique=True,
           where=sa.text("agent_id IS NOT NULL"))
    create("assets", "uq_assets_platform_identity",
           ["organization_id", "ip_address", "hostname"], unique=True,
           where=sa.text("agent_id IS NULL"))
    create("organizations", "uq_organizations_slug", ["slug"], unique=True)


def _deduplicate_assets(connection) -> None:
    """Merge legacy duplicate asset identities before adding tenant uniques."""
    if "assets" not in sa.inspect(connection).get_table_names():
        return
    rows = connection.execute(sa.text(
        "SELECT id, organization_id, agent_id, ip_address, hostname, source, "
        "is_internal, first_seen, last_seen FROM assets ORDER BY id"
    )).mappings().all()
    grouped: dict[tuple, list] = {}
    for row in rows:
        if row["agent_id"] is None:
            identity = (
                "organization", row["organization_id"],
                row["ip_address"], row["hostname"],
            )
        else:
            identity = (
                "agent", row["agent_id"], row["ip_address"], row["hostname"],
            )
        grouped.setdefault(identity, []).append(row)

    references = []
    for table in sa.inspect(connection).get_table_names():
        if table == "assets":
            continue
        for foreign_key in sa.inspect(connection).get_foreign_keys(table):
            if foreign_key.get("referred_table") != "assets":
                continue
            for local_column, remote_column in zip(
                foreign_key.get("constrained_columns") or (),
                foreign_key.get("referred_columns") or (),
            ):
                if remote_column == "id":
                    references.append((table, local_column))
    if "discovery_results" in sa.inspect(connection).get_table_names():
        if "matched_asset_id" in _columns(connection, "discovery_results"):
            references.append(("discovery_results", "matched_asset_id"))

    for duplicates in grouped.values():
        if len(duplicates) < 2:
            continue
        canonical = duplicates[0]
        duplicate_ids = [row["id"] for row in duplicates[1:]]
        source = (
            "manual"
            if any(row["source"] == "manual" for row in duplicates)
            else canonical["source"]
        )
        first_seen_values = [row["first_seen"] for row in duplicates if row["first_seen"]]
        last_seen_values = [row["last_seen"] for row in duplicates if row["last_seen"]]
        connection.execute(
            sa.text(
                "UPDATE assets SET source=:source, is_internal=:is_internal, "
                "first_seen=:first_seen, last_seen=:last_seen WHERE id=:id"
            ),
            {
                "source": source,
                "is_internal": any(row["is_internal"] for row in duplicates),
                "first_seen": min(first_seen_values) if first_seen_values else None,
                "last_seen": max(last_seen_values) if last_seen_values else None,
                "id": canonical["id"],
            },
        )
        for table, local_column in references:
            placeholders = ", ".join(
                ":duplicate_" + str(index)
                for index in range(len(duplicate_ids))
            )
            connection.execute(
                sa.text(
                    f'UPDATE "{table}" SET "{local_column}"=:canonical_id '
                    f'WHERE "{local_column}" IN ({placeholders})'
                ),
                {
                    "canonical_id": canonical["id"],
                    **{
                        f"duplicate_{i}": duplicate_id
                        for i, duplicate_id in enumerate(duplicate_ids)
                    },
                },
            )
        connection.execute(
            sa.text(
                "DELETE FROM assets WHERE id IN ("
                + ", ".join(
                    f":duplicate_{i}" for i in range(len(duplicate_ids))
                )
                + ")"
            ),
            {
                f"duplicate_{i}": duplicate_id
                for i, duplicate_id in enumerate(duplicate_ids)
            },
        )


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())

    for table, name, type_ in (
        ("organizations", "slug", sa.String(64)),
        ("organizations", "status", sa.String(16)),
        ("organizations", "ai_mode", sa.String(16)),
        ("organizations", "max_agents", sa.Integer()),
        ("organizations", "max_cloud_scans_per_hour", sa.Integer()),
        ("organizations", "max_recurring_scans", sa.Integer()),
        ("users", "must_change_password", sa.Boolean()),
        ("agents", "reported_capabilities", sa.JSON()),
    ):
        _ensure_column(connection, table, name, type_)

    for table, name, type_ in ORGANIZATION_COLUMNS:
        _ensure_column(connection, table, name, type_)

    # Existing installs always have organizations; fail loudly if an earlier
    # migration was skipped instead of silently assigning tenant rows to NULL.
    if "organizations" not in tables:
        raise RuntimeError("organizations table is missing; upgrade prior revisions first")

    _backfill(connection)

    for table in TENANT_TABLES:
        foreign_keys = sa.inspect(connection).get_foreign_keys(table)
        has_org_fk = any(
            fk.get("constrained_columns") == ["organization_id"]
            and fk.get("referred_table") == "organizations"
            for fk in foreign_keys
        )
        column = next(
            col for col in sa.inspect(connection).get_columns(table)
            if col["name"] == "organization_id"
        )
        if column["nullable"] or not has_org_fk:
            kwargs = {"recreate": "always"} if connection.dialect.name == "sqlite" else {}
            with op.batch_alter_table(table, **kwargs) as batch:
                if column["nullable"]:
                    batch.alter_column(
                        "organization_id",
                        existing_type=sa.Integer(),
                        nullable=False,
                    )
                if not has_org_fk:
                    batch.create_foreign_key(
                        f"fk_{table}_organization_id",
                        "organizations",
                        ["organization_id"],
                        ["id"],
                    )

    # Organization-level settings are populated before constraints are applied.
    with op.batch_alter_table("organizations") as batch:
        for name, type_, default in (
            ("slug", sa.String(64), "default"),
            ("status", sa.String(16), "active"),
            ("ai_mode", sa.String(16), "template"),
            ("max_agents", sa.Integer(), 0),
            ("max_cloud_scans_per_hour", sa.Integer(), 0),
            ("max_recurring_scans", sa.Integer(), 0),
        ):
            column = next(
                col for col in sa.inspect(connection).get_columns("organizations")
                if col["name"] == name
            )
            if column["nullable"]:
                batch.alter_column(name, existing_type=type_, nullable=False)

    if "must_change_password" in _columns(connection, "users"):
        column = next(
            col for col in sa.inspect(connection).get_columns("users")
            if col["name"] == "must_change_password"
        )
        if column["nullable"]:
            with op.batch_alter_table("users") as batch:
                batch.alter_column(
                    "must_change_password",
                    existing_type=sa.Boolean(),
                    nullable=False,
                    server_default=sa.false(),
                )

    _deduplicate_assets(connection)
    _ensure_indexes(connection)


def downgrade() -> None:
    raise RuntimeError(
        "Tenant ownership is irreversible without risking cross-organization data exposure"
    )
