import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import IssueDetailPage from "@/app/issues/[id]/page";
import { AuthProvider } from "@/components/auth/AuthContext";
import { api } from "@/services/apiClient";
import { fetchMe } from "@/services/authService";
import type { AuthUser, Role } from "@/types/auth";
import type { Issue } from "@/types/issue";

const router = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "issue-1" }), useRouter: () => router }));
vi.mock("@/services/apiClient", () => ({ api: { get: vi.fn(), patch: vi.fn(), post: vi.fn() }, setAccessToken: vi.fn() }));
vi.mock("@/services/authService", () => ({ fetchMe: vi.fn() }));

const issue: Issue = {
  id: "issue-1", title: "Expired TLS certificate", ruleId: "CERT-01", sourceDocument: "80052",
  serviceId: null, severity: "critical", status: "open", ownerUserId: null, ownerTeamId: null,
  effectiveOwnerUserId: null, effectiveOwnerTeamId: null, ownerName: null,
  firstSeenAt: null, lastSeenAt: null, dueAt: "2026-11-18T12:00:00Z", isOverdue: true,
  resolvedAt: null, resolvedBy: null, verifiedAt: null, cleanScansSinceResolved: 0,
  riskAcceptedBy: null, riskAcceptanceReason: null, riskAcceptedUntil: null,
  reopenedCount: 0, lastCertificateFingerprint: null,
};

function openIssue(role: Role = "admin") {
  const user: AuthUser = {
    id: "current-user", name: "Test User", email: "user@example.test", role,
    isActive: true, createdAt: null, lastLoginAt: null, organization_id: "org-1",
  };
  localStorage.setItem("authToken", "test-token");
  vi.mocked(fetchMe).mockResolvedValue(user);
  return render(<AuthProvider><IssueDetailPage /></AuthProvider>);
}

describe("issue details and management", () => {
  let currentIssue: Issue;

  beforeEach(() => {
    currentIssue = { ...issue };
    vi.mocked(api.get).mockImplementation(async (path) => {
      switch (path) {
        case "/issues/issue-1": return currentIssue;
        case "/teams": return [];
        case "/users/directory": return [
          { id: "owner-1", name: "Ana Owner", email: "ana@example.test", role: "user", organization_id: "org-1" },
          { id: "external", name: "Other Tenant", email: "other@example.test", role: "user", organization_id: "org-2" },
        ];
        default: throw new Error(`Unexpected issue request: ${path}`);
      }
    });
    vi.mocked(api.patch).mockImplementation(async (_path, options) => {
      const { reason, ...patch } = options?.body as Partial<Issue> & { reason?: string };
      currentIssue = { ...currentIssue, ...patch };
      if (currentIssue.ownerUserId) currentIssue.ownerName = "Ana Owner";
      if (reason) currentIssue.riskAcceptanceReason = reason;
      return currentIssue;
    });
  });

  it("assigns a same-tenant user and refetches the updated owner", async () => {
    const user = userEvent.setup();
    openIssue();
    const assign = await screen.findByRole("button", { name: "Asignar" });
    expect(assign).toBeDisabled();
    const ownerSelect = screen.getAllByRole("combobox").find((select) => select.textContent === "Seleccionar usuario");
    expect(ownerSelect).toBeEnabled();
    await user.click(ownerSelect!);
    expect(screen.queryByRole("option", { name: /Other Tenant/ })).toBeNull();
    await user.click(screen.getByRole("option", { name: /Ana Owner/ }));
    await user.click(assign);

    expect(api.patch).toHaveBeenCalledWith("/issues/issue-1", {
      body: { ownerUserId: "owner-1", ownerTeamId: null },
    });
    expect(await screen.findByText("Ana Owner (usuario)")).toBeVisible();
  });

  it("sends the selected status and renders the refreshed issue", async () => {
    openIssue();
    fireEvent.click(await screen.findByRole("button", { name: "En progreso" }));
    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/issues/issue-1", { body: { status: "in_progress" } }));
    await waitFor(() => expect(screen.getAllByText("En progreso")).toHaveLength(2));
    expect(screen.queryByRole("button", { name: "En progreso" })).toBeNull();
  });

  it("renders the SLA due date and marks an overdue issue", async () => {
    openIssue();
    expect(await screen.findByText("Vencido", { exact: true })).toBeVisible();
    const dueRow = screen.getByText("Vence").parentElement!;
    expect(within(dueRow).getByText(/Nov 18, 2026.*vencido/i)).toBeVisible();
  });

  it("submits the risk acceptance deadline with the reason", async () => {
    const { container } = openIssue();
    fireEvent.click(await screen.findByRole("button", { name: "Riesgo aceptado" }));
    fireEvent.change(screen.getByPlaceholderText("Motivo (obligatorio)"), { target: { value: " Mitigation scheduled " } });
    fireEvent.change(container.querySelector('input[type="date"]')!, { target: { value: "2026-12-31" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirmar" }));

    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/issues/issue-1", {
      body: { status: "risk_accepted", reason: "Mitigation scheduled", riskAcceptedUntil: "2026-12-31T00:00:00.000Z" },
    }));
    expect(await screen.findByText("Mitigation scheduled")).toBeVisible();
  });

  it("blocks assignment and status changes for a read-only viewer", async () => {
    openIssue("viewer");
    expect(await screen.findByText("Solo lectura para tu rol.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Asignar" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "En progreso" })).toBeNull();
    expect(api.patch).not.toHaveBeenCalled();
  });

  it("clears an existing owner and refetches the unassigned issue", async () => {
    currentIssue = { ...currentIssue, ownerUserId: "owner-1", ownerName: "Ana Owner" };
    vi.mocked(api.patch).mockImplementationOnce(async () => {
      currentIssue = { ...currentIssue, ownerUserId: null, ownerName: null };
      return currentIssue;
    });
    openIssue();
    fireEvent.click(await screen.findByRole("button", { name: "Quitar" }));

    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/issues/issue-1", {
      body: { ownerUserId: null, ownerTeamId: null },
    }));
    expect(await screen.findAllByText("Sin asignar")).toHaveLength(2);
  });

  it("reopens a resolved issue and refreshes its status", async () => {
    currentIssue = { ...currentIssue, status: "resolved" };
    vi.mocked(api.patch).mockImplementationOnce(async () => {
      currentIssue = { ...currentIssue, status: "open" };
      return currentIssue;
    });
    openIssue();
    fireEvent.click(await screen.findByRole("button", { name: "Reabrir" }));

    await waitFor(() => expect(api.patch).toHaveBeenCalledWith("/issues/issue-1", { body: { status: "reopened" } }));
    expect(await screen.findAllByText("Abierto")).toHaveLength(2);
  });
});
