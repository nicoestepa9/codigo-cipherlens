import type { DashboardSummary } from "@/types/dashboard";
import { getMockCertificates } from "./certificates";
import { getGlobalFindings } from "./findings";
import { getDiscoveryResults } from "./discovery";
import { getMockServices } from "./services";
import { initAlerts } from "./alerts";
import { seedHistory } from "./scans";

export function getDashboardSummary(): DashboardSummary {
  const certs = getMockCertificates();
  const services = getMockServices();
  const findings = getGlobalFindings();
  const discovery = getDiscoveryResults();
  const alerts = initAlerts();
  const history = seedHistory();

  const expiringSoon = certs.filter((c) => c.daysUntilExpiry >= 0 && c.daysUntilExpiry < 30).length;
  const criticalVulnerabilities = findings.filter((f) => f.severity === "critical").length;
  const highVulnerabilities = findings.filter((f) => f.severity === "high").length;
  const shadowItDetected = discovery.filter((d) => d.shadowIt).length;

  const secure = services.filter((s) => s.securityStatus === "secure").length;
  const warning = services.filter((s) => s.securityStatus === "warning").length;
  const critical = services.filter((s) => s.securityStatus === "critical").length;

  const weight = 82;
  const lastScanAt = history.find((h) => h.kind === "tls_scan")?.date ?? null;

  return {
    totalServices: services.length,
    totalCertificates: certs.length,
    certificatesExpiringSoon: expiringSoon,
    criticalVulnerabilities,
    highVulnerabilities,
    shadowItDetected,
    lastScanAt,
    securityScore: weight,
    secure,
    warning,
    critical,
    unreadAlerts: alerts.filter((a) => a.status === "unread").length,
  };
}
