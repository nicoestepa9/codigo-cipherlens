"""normalize source_document to short codes with backup

Revision ID: c9a4f2b81d37
Revises: b7d2e4f6a8c1
Create Date: 2026-10-27 13:00:00.000000

"""
from typing import Sequence, Union
import json
import os
from datetime import datetime

from alembic import op
import sqlalchemy as sa


revision = 'c9a4f2b81d37'
down_revision = 'b7d2e4f6a8c1'
branch_labels = None
depends_on = None


MAPPING = {
    "NIST SP 800-52 Rev.2 (Aug 2019)": "80052",
    "NIST SP 800-57 Part 1 Rev.5 (May 2020)": "80057",
    "NIST SP 800-131A Rev.2 (March 2019)": "800131a",
}


def _backup_data(connection):
    findings = connection.execute(sa.text("SELECT id, source_document FROM findings")).fetchall()
    issues = connection.execute(sa.text("SELECT id, source_document FROM issues")).fetchall()
    backup = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "findings": [{"id": r[0], "source_document": r[1]} for r in findings],
        "issues": [{"id": r[0], "source_document": r[1]} for r in issues],
    }
    backup_dir = os.environ.get("TLS_ANALYSIS_BACKUP_DIR") or os.path.join(os.path.expanduser("~"), ".local", "share", "cryptoguard", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    path_b = os.path.join(backup_dir, f"source_document_backup_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(path_b, "w", encoding="utf-8") as f:
        json.dump(backup, f, ensure_ascii=False, indent=2)
    return path_b


def upgrade():
    connection = op.get_bind()
    backup_path = _backup_data(connection)
    for old, new in MAPPING.items():
        connection.execute(sa.text("UPDATE findings SET source_document = :new WHERE source_document = :old"), {"old": old, "new": new})
        connection.execute(sa.text("UPDATE issues SET source_document = :new WHERE source_document = :old"), {"old": old, "new": new})
    print("BACKUP_PATH:" + backup_path)


def downgrade():
    pass
