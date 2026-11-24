"""Datos semilla: umbrales, integraciones y ventanas de compliance."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from .models import AlertThreshold, ComplianceWindow, Integration, Organization


def _get_org_id(db: Session) -> int:
    org = db.query(Organization).first()
    if org is None:
        org = Organization(name="Default Org", slug="default", status="active")
        db.add(org)
        db.flush()
    return org.id


def seed(db: Session) -> None:
    org_id = _get_org_id(db)
    if db.query(AlertThreshold).first() is None:
        try:
            db.add(
                AlertThreshold(
                    days_before_expiry=[30, 15, 7],
                    notify_on_critical_finding=True,
                    notify_on_compliance=True,
                    critical_days=7,
                    warning_days=30,
                    organization_id=org_id,
                )
            )
        except Exception:
            db.add(
                AlertThreshold(
                    days_before_expiry=[30, 15, 7],
                    notify_on_critical_finding=True,
                    notify_on_compliance=True,
                    critical_days=7,
                    warning_days=30,
                )
            )

    if db.query(Integration).count() == 0:
        db.add_all(
            [
                Integration(
                    name="Internal Cert Manager",
                    type="certificate-manager",
                    description="Corporate certificate management platform",
                    status="connected",
                ),
                Integration(
                    name="SIEM Export",
                    type="siem",
                    description="Security events and findings export",
                    status="pending",
                ),
                Integration(
                    name="PagerDuty",
                    type="notifications",
                    description="Incident notification webhook",
                    status="disconnected",
                ),
            ]
        )

    if db.query(ComplianceWindow).count() == 0:
        try:
            db.add(
                ComplianceWindow(
                    name="PCI-DSS scope",
                    framework="PCI-DSS",
                    audit_date=(date.today() + timedelta(days=15)).isoformat(),
                    scope_filter=["payments.internal.company.com", "api.internal.company.com"],
                    organization_id=org_id,
                )
            )
        except Exception:
            db.add(
                ComplianceWindow(
                    name="PCI-DSS scope",
                    framework="PCI-DSS",
                    audit_date=(date.today() + timedelta(days=15)).isoformat(),
                    scope_filter=["payments.internal.company.com", "api.internal.company.com"],
                )
            )

    db.commit()
