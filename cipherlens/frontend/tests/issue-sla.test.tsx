import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import SettingsPage from "@/app/settings/page";
import { AuthProvider } from "@/components/auth/AuthContext";
import { SettingsProvider } from "@/context/settings-context";
import { api } from "@/services/apiClient";
import { fetchMe } from "@/services/authService";
import type { AuthUser, Role } from "@/types/auth";
import type { OrganizationSettings } from "@/types/organization";

vi.mock("next/navigation", () => ({
  useRouter: () => router,
}));
const router = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("@/services/authService", () => ({ fetchMe: vi.fn() }));
vi.mock("@/services/apiClient", () => ({
  api: { get: vi.fn(), put: vi.fn() },
  setAccessToken: vi.fn(),
}));

const organization: OrganizationSettings = {
  id: 1, name: "Test Org", slug: "test-org", status: "active", aiMode: "template",
  maxAgents: 10, maxCloudScansPerHour: 60, maxRecurringScans: 10,
  slaDaysCritical: 5, slaDaysHigh: 12, slaDaysMedium: 25,
};

beforeEach(() => {
  vi.mocked(api.put).mockReset();
  vi.mocked(api.get).mockImplementation(async (path) => {
    switch (path) {
      case "/settings/organization": return organization;
      case "/settings/thresholds": return { criticalDays: 7, warningDays: 30 };
      case "/settings/compliance-windows": return [];
      case "/settings/ai-status": return { provider: "template", anonymization: "internal", externalLlm: false };
      default: throw new Error(`Unexpected settings request: ${path}`);
    }
  });
});

function input(severity: string) {
  const card = screen.getByText("Issue SLA targets").closest<HTMLElement>('[data-slot="card"]');
  return within(card!).getByRole("spinbutton", { name: `${severity} (days)` });
}

async function openSettings(role: Role) {
  const user: AuthUser = {
    id: "user-1", name: "Test User", email: "user@example.test", role,
    isActive: true, createdAt: null, lastLoginAt: null, organization_id: "1",
  };
  localStorage.setItem("authToken", "test-token");
  vi.mocked(fetchMe).mockResolvedValue(user);
  render(<AuthProvider><SettingsProvider><SettingsPage /></SettingsProvider></AuthProvider>);
  await waitFor(() => expect(input("Critical")).toHaveValue(5));
}

it.each(["lead", "user", "viewer"] as const)("renders SLA targets read-only for %s", async (role) => {
  await openSettings(role);
  for (const [severity, value] of [["Critical", 5], ["High", 12], ["Medium", 25]] as const) {
    expect(input(severity)).toHaveValue(value);
    expect(input(severity)).toBeDisabled();
  }
  expect(screen.queryByRole("button", { name: "Save SLA targets" })).not.toBeInTheDocument();
  expect(api.put).not.toHaveBeenCalled();
});

it("saves admin edits through the SLA endpoint and displays the stored targets", async () => {
  const pending = Promise.withResolvers<OrganizationSettings>();
  vi.mocked(api.put).mockReturnValue(pending.promise);
  await openSettings("admin");

  for (const [severity, value] of [["Critical", "3"], ["High", "10"], ["Medium", "27"]]) {
    fireEvent.change(input(severity), { target: { value } });
  }
  const save = screen.getByRole("button", { name: "Save SLA targets" });
  fireEvent.click(save);

  expect(api.put).toHaveBeenCalledWith("/settings/sla", {
    body: { criticalDays: 3, highDays: 10, mediumDays: 27 },
  });
  expect(save).toBeDisabled();
  expect(input("Critical")).toBeDisabled();

  await act(async () => pending.resolve({
    ...organization, slaDaysCritical: 3, slaDaysHigh: 10, slaDaysMedium: 27,
  }));
  expect(screen.getByText("SLA targets updated.")).toBeVisible();
  expect(input("Critical")).toHaveValue(3);
  expect(input("High")).toHaveValue(10);
  expect(input("Medium")).toHaveValue(27);
  expect(save).toBeEnabled();
});

it("shows the save error and re-enables the controls", async () => {
  vi.mocked(api.put).mockRejectedValue(new Error("Could not save organization settings"));
  await openSettings("admin");
  fireEvent.change(input("High"), { target: { value: "18" } });
  const save = screen.getByRole("button", { name: "Save SLA targets" });
  fireEvent.click(save);
  expect(await screen.findByText("Could not save organization settings")).toBeVisible();
  expect(input("High")).toHaveValue(18);
  expect(save).toBeEnabled();
});
