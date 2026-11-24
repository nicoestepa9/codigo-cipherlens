import type { Alert, AlertStatus, AlertType } from "@/types/alert";
import type { Severity } from "@/types/severity";
import { daysAgo } from "@/lib/format";

interface AlertSeed {
  severity: Severity;
  type: AlertType;
  title: string;
  description: string;
  ageDays: number;
  status: AlertStatus;
  relatedTarget?: string;
  relatedCertificateId?: string;
  relatedScanId?: string;
  actionLabel?: string;
  actionHref?: string;
}

const SEEDS: AlertSeed[] = [
  {
    severity: "critical",
    type: "expiration",
    title: "Certificate expired",
    description: "api.internal.company.com certificate expired 3 days ago. Client validation is failing for all consumers.",
    ageDays: 3,
    status: "unread",
    relatedTarget: "api.internal.company.com",
    relatedCertificateId: "cert_1",
    actionLabel: "View Certificate",
    actionHref: "/certificates/cert_1",
  },
  {
    severity: "critical",
    type: "vulnerability",
    title: "TLS 1.0 enabled on payments gateway",
    description: "payments.internal.company.com negotiates TLS 1.0. Payment data in transit is exposed to downgrade attacks.",
    ageDays: 1,
    status: "unread",
    relatedTarget: "payments.internal.company.com",
    relatedScanId: "scan_hist_7",
    actionLabel: "View Analysis",
    actionHref: "/scanner/scan_hist_7",
  },
  {
    severity: "high",
    type: "vulnerability",
    title: "Weak Cipher Suite detected (3DES)",
    description: "legacy.internal.company.com accepts TLS_RSA_WITH_3DES_EDE_CBC_SHA. 3DES is no longer cryptographically safe.",
    ageDays: 2,
    status: "unread",
    relatedTarget: "legacy.internal.company.com",
    actionLabel: "View Analysis",
    actionHref: "/scanner/scan_hist_6",
  },
  {
    severity: "medium",
    type: "expiration",
    title: "Certificate expires in 12 days",
    description: "vpn.company.com certificate expires in 12 days. Renew before the 7-day critical threshold.",
    ageDays: 0,
    status: "unread",
    relatedTarget: "vpn.company.com",
    relatedCertificateId: "cert_12",
    actionLabel: "Renew / View Certificate",
    actionHref: "/certificates/cert_12",
  },
  {
    severity: "info",
    type: "compliance",
    title: "PCI audit in 15 days: 3 affected sites",
    description: "Auditoría PCI programada en 15 días: 3 sitios dentro del alcance tienen hallazgos abiertos (payments, billing, portal).",
    ageDays: 0,
    status: "unread",
    actionLabel: "View Scope",
    actionHref: "/vulnerabilities",
  },
  {
    severity: "high",
    type: "compliance",
    title: "NIST SP 800-52 non-compliance window",
    description: "6 external services still allow TLS 1.1. Internal policy requires enforcement before the next compliance review.",
    ageDays: 5,
    status: "read",
    actionLabel: "Review",
    actionHref: "/vulnerabilities",
  },
  {
    severity: "critical",
    type: "expiration",
    title: "Certificate expired (billing.internal.company.com)",
    description: "billing.internal.company.com certificate expired 2 days ago. Automated reconciliation is failing.",
    ageDays: 2,
    status: "read",
    relatedTarget: "billing.internal.company.com",
    actionLabel: "View Certificate",
    actionHref: "/certificates",
  },
  {
    severity: "medium",
    type: "expiration",
    title: "Certificate expires in 20 days",
    description: "db-primary.internal.company.com certificate expires in 20 days. Schedule renewal.",
    ageDays: 1,
    status: "read",
    relatedTarget: "db-primary.internal.company.com",
    actionLabel: "View Certificate",
    actionHref: "/certificates",
  },
  {
    severity: "high",
    type: "discovery",
    title: "Shadow IT: new web service detected",
    description: "Shadow IT asset temp-web.internal.company.com (10.0.0.42:8080) serving HTTP outside the declared inventory.",
    ageDays: 2,
    status: "read",
    relatedTarget: "temp-web.internal.company.com",
    actionLabel: "Open Discovery",
    actionHref: "/discovery",
  },
  {
    severity: "medium",
    type: "discovery",
    title: "Unexpected database exposed internally",
    description: "legacy-db.internal.company.com (10.0.0.44:5432) is not part of the declared asset inventory.",
    ageDays: 4,
    status: "read",
    relatedTarget: "legacy-db.internal.company.com",
    actionLabel: "Open Discovery",
    actionHref: "/discovery",
  },
  {
    severity: "critical",
    type: "vulnerability",
    title: "SHA-1 signed certificate in production",
    description: "erp.internal.company.com serves a certificate signed with SHA-1. Re-issue immediately.",
    ageDays: 6,
    status: "resolved",
    relatedTarget: "erp.internal.company.com",
  },
  {
    severity: "medium",
    type: "expiration",
    title: "Certificate expires in 25 days",
    description: "wiki.internal.company.com certificate expires in 25 days.",
    ageDays: 3,
    status: "read",
    relatedTarget: "wiki.internal.company.com",
  },
  {
    severity: "medium",
    type: "system",
    title: "Certificate sync delay",
    description: "Integration with Internal Cert Manager has been delayed by 40 minutes for 2 certificates.",
    ageDays: 1,
    status: "read",
  },
  {
    severity: "info",
    type: "system",
    title: "Scheduled scan completed",
    description: "Nightly discovery of 10.0.0.0/24 completed. 41 assets found, 3 new shadow IT.",
    ageDays: 1,
    status: "read",
    actionLabel: "View Results",
    actionHref: "/discovery",
  },
  {
    severity: "high",
    type: "expiration",
    title: "Certificate expires in 5 days (critical window)",
    description: "portal.company.com certificate expires in 5 days. Inside the 7-day critical window.",
    ageDays: 0,
    status: "unread",
    relatedTarget: "portal.company.com",
    actionLabel: "Renew / View Certificate",
    actionHref: "/certificates",
  },
  {
    severity: "medium",
    type: "vulnerability",
    title: "CBC cipher without Encrypt-then-MAC",
    description: "legacy.internal.company.com negotiates CBC suites without Encrypt-then-MAC (Lucky13 risk).",
    ageDays: 8,
    status: "read",
    relatedTarget: "legacy.internal.company.com",
  },
  {
    severity: "medium",
    type: "compliance",
    title: "SOC 2 evidence window opens in 30 days",
    description: "Certificate lifecycle reports must be exported for the SOC 2 audit. 14 certificates lack manual-load documentation.",
    ageDays: 1,
    status: "unread",
    actionLabel: "Review Inventory",
    actionHref: "/certificates",
  },
  {
    severity: "info",
    type: "compliance",
    title: "Certificate origin coverage",
    description: "15% of certificates were loaded manually (origin=manual). Consider automating ingestion via the API.",
    ageDays: 2,
    status: "read",
    actionLabel: "API Docs",
    actionHref: "/integrations",
  },
  {
    severity: "high",
    type: "discovery",
    title: "Shadow IT: public surface not declared",
    description: "test-api.company.com (198.51.100.11:443) found on the public attack surface without inventory declaration.",
    ageDays: 1,
    status: "unread",
    relatedTarget: "test-api.company.com",
    actionLabel: "Open Discovery",
    actionHref: "/discovery",
  },
  {
    severity: "critical",
    type: "expiration",
    title: "Certificate expired (legacy-db.internal.company.com)",
    description: "legacy-db.internal.company.com certificate expired. Intermittent TLS errors reported by legacy clients.",
    ageDays: 7,
    status: "read",
    relatedTarget: "legacy-db.internal.company.com",
  },
  {
    severity: "medium",
    type: "system",
    title: "API rate limit approaching",
    description: "Manual certificate loads reached 80% of the daily API quota.",
    ageDays: 0,
    status: "read",
    actionLabel: "Integrations",
    actionHref: "/integrations",
  },
  {
    severity: "medium",
    type: "expiration",
    title: "Certificate expires in 18 days",
    description: "grafana.internal.company.com certificate expires in 18 days.",
    ageDays: 4,
    status: "read",
    relatedTarget: "grafana.internal.company.com",
  },
];

let ALERTS: Alert[] | null = null;

export function initAlerts(): Alert[] {
  if (ALERTS) return ALERTS;
  ALERTS = SEEDS.map((seed, index) => ({
    id: `alert_${index + 1}`,
    severity: seed.severity,
    type: seed.type,
    title: seed.title,
    description: seed.description,
    createdAt: daysAgo(seed.ageDays),
    status: seed.status,
    relatedTarget: seed.relatedTarget,
    relatedCertificateId: seed.relatedCertificateId,
    relatedScanId: seed.relatedScanId,
    actionLabel: seed.actionLabel,
    actionHref: seed.actionHref,
  }));
  return ALERTS;
}

export function getMockAlerts(): Alert[] {
  return initAlerts();
}

export function setAlertStatus(id: string, status: AlertStatus): void {
  const alerts = initAlerts();
  const alert = alerts.find((a) => a.id === id);
  if (alert) alert.status = status;
}
