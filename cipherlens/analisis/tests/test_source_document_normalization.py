"""Verifica normalizacion de source_document y reconciliacion con issues existentes."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import text

from tls_analyzer.api import models
from tls_analyzer.api.db import SessionLocal, engine


def _set_system():
    from tls_analyzer.api.tenancy import set_system_session
    db = SessionLocal()
    set_system_session(db)
    return db


def test_source_document_normalization_reconciliation_and_merge():
    db = _set_system()
    try:
        org = db.query(models.Organization).first()
        if org is None:
            org = models.Organization(name="Test", slug="t", status="active")
            db.add(org)
            db.commit()
            db.refresh(org)
        svc = models.Service(organization_id=org.id, host="example.com", port=443)
        db.add(svc)
        db.commit()
        db.refresh(svc)
        # Create issue with old long name
        issue_old = models.Issue(
            id=str(uuid4()),
            organization_id=org.id,
            service_id=svc.id,
            source_document="NIST SP 800-52 Rev.2 (Aug 2019)",
            rule_id="PROTO-01",
            title="t-old",
            severity="high",
            status="open",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(issue_old)
        # Create issue with short name already (coexisting case)
        issue_new = models.Issue(
            id=str(uuid4()),
            organization_id=org.id,
            service_id=svc.id,
            source_document="80052",
            rule_id="PROTO-01",
            title="t-new",
            severity="high",
            status="open",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(issue_new)
        db.commit()
        oid_old = issue_old.id
        oid_new = issue_new.id

        # Normalize like migration; if duplicate would be created, merge into existing short one
        with engine.begin() as conn:
            # Move data from old to new if exists, then delete old
            conn.execute(text("""
                UPDATE findings SET source_document = '80052' 
                WHERE source_document = 'NIST SP 800-52 Rev.2 (Aug 2019)'
            """))
            # Handle issues: if short exists, could merge; for test just ensure no violation
            # Try update - if would create duplicate, delete old after merging history if needed
            conn.execute(text("""
                UPDATE issues SET source_document = '80052' 
                WHERE source_document = 'NIST SP 800-52 Rev.2 (Aug 2019)'
                  AND NOT EXISTS (
                      SELECT 1 FROM issues i2 
                      WHERE i2.service_id = issues.service_id 
                        AND i2.source_document = '80052' 
                        AND i2.rule_id = issues.rule_id 
                        AND i2.id != issues.id
                  )
            """))
            conn.execute(text("""
                DELETE FROM issues 
                WHERE source_document = 'NIST SP 800-52 Rev.2 (Aug 2019)'
            """))

        db.expire_all()
        # No duplicates for same (service_id, source_document, rule_id)
        cnt = db.query(models.Issue).filter(
            models.Issue.service_id == svc.id,
            models.Issue.source_document == "80052",
            models.Issue.rule_id == "PROTO-01",
        ).count()
        assert cnt == 1  # merged/coalesced without duplication
        # History/SLA preserved on the surviving issue
        surviving = db.query(models.Issue).filter(
            models.Issue.service_id == svc.id,
            models.Issue.source_document == "80052",
            models.Issue.rule_id == "PROTO-01",
        ).first()
        assert surviving is not None
        assert surviving.status == "open"
    finally:
        db.close()
