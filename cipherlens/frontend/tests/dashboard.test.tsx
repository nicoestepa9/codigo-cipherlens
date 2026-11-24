import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "@/app/dashboard/page";
import { api } from "@/services/apiClient";
import type { DashboardSummary } from "@/types/dashboard";
import type { ExpirationStats } from "@/services/certificatesService";
import type { Alert } from "@/types/alert";

vi.mock("@/services/apiClient", () => ({ api: { get: vi.fn() } }));

vi.mock("recharts", async (importOriginal) => {
  const charts = await importOriginal<typeof import("recharts")>();
  return {
    ...charts,
    // Give the real charts dimensions in jsdom, which has no layout engine.
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
      <charts.ResponsiveContainer width={600} height={240}>{children}</charts.ResponsiveContainer>
    ),
    Pie: (props: React.ComponentProps<typeof charts.Pie>) => (
      <charts.Pie {...props} isAnimationActive={false} />
    ),
  };
});

const summary: DashboardSummary = {
  totalServices: 10, totalCertificates: 17, certificatesExpiringSoon: 3,
  criticalVulnerabilities: 2, highVulnerabilities: 3, shadowItDetected: 1,
  lastScanAt: null, securityScore: 87, secure: 6, warning: 2, critical: 2, unreadAlerts: 8,
};

const expiration: ExpirationStats = {
  expired: 1, critical: 1, warning: 2, healthy: 13, total: 17,
  criticalDays: 5, warningDays: 21,
  byWindow: [
    { label: "0–5 days", min: 0, max: 5, count: 1 },
    { label: "6–21 days", min: 6, max: 21, count: 2 },
    { label: "22+ days", min: 22, max: 365, count: 13 },
  ],
};

const alerts: Alert[] = Array.from({ length: 6 }, (_, index) => ({
  id: String(index), title: `Alert ${index}`, description: "Review the service",
  severity: index === 5 ? "critical" : "high", type: "vulnerability", status: "unread",
  createdAt: `2026-11-0${index + 1}T00:00:00Z`,
}));

function respondWith(alertItems: Alert[]) {
  vi.mocked(api.get).mockImplementation(async (path) => {
    switch (path) {
      case "/dashboard": return summary;
      case "/certificates/expiration-stats": return expiration;
      case "/alerts": return [...alertItems];
      default: throw new Error(`Unexpected dashboard request: ${path}`);
    }
  });
}

describe("security dashboard", () => {
  beforeEach(() => respondWith(alerts));

  it("renders the security score returned by the API", async () => {
    render(<DashboardPage />);
    expect(await screen.findByText("87")).toBeVisible();
    expect(screen.getByText("/ 100")).toBeVisible();
  });

  it("renders certificate totals, expiring count, and configured thresholds", async () => {
    render(<DashboardPage />);
    expect(await screen.findByText("17")).toBeVisible();
    expect(screen.getByText("3 expiring <= 21d")).toBeVisible();
    expect(screen.getByText(/5 \/ 21 day thresholds/)).toBeVisible();
  });

  it("renders the critical service count and alert severities", async () => {
    render(<DashboardPage />);
    const newest = await screen.findByText("Alert 5");
    expect(within(newest.parentElement!.parentElement!).getByText("Critical")).toBeVisible();
    expect(screen.getByText(/6 secure.*2 critical/)).toBeVisible();
  });

  it("shows the unread total and only the five newest alerts in order", async () => {
    render(<DashboardPage />);
    const unreadLabel = await screen.findByText("Unread Alerts");
    expect(within(unreadLabel.parentElement!).getByText("8")).toBeVisible();
    expect(screen.getAllByText(/^Alert \d$/).map((element) => element.textContent)).toEqual([
      "Alert 5", "Alert 4", "Alert 3", "Alert 2", "Alert 1",
    ]);
  });

  it("shows the empty alert state when the API returns none", async () => {
    respondWith([]);
    render(<DashboardPage />);
    expect(await screen.findByText("No alerts.")).toBeVisible();
  });

  it("plots certificate expiration windows in order", async () => {
    render(<DashboardPage />);
    await screen.findByText("Certificate Expiration");
    const windows = await screen.findAllByText(/^(0–5 days|6–21 days|22\+ days)$/);
    expect(windows.map((label) => label.textContent)).toEqual(["0–5 days", "6–21 days", "22+ days"]);
  });

  it("renders all three service posture counts in the pie chart", async () => {
    render(<DashboardPage />);
    expect(await screen.findByText("Secure (6)")).toBeInTheDocument();
    expect(screen.getByText("Warning (2)")).toBeInTheDocument();
    expect(screen.getByText("Critical (2)")).toBeInTheDocument();
  });
});
