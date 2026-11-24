import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "@/components/auth/AuthContext";
import { ScannerForm } from "@/components/features/scanner/scanner-form";
import { CloudAuthorizationDialog } from "@/components/shared/cloud-authorization-dialog";
import { SettingsProvider } from "@/context/settings-context";
import { api } from "@/services/apiClient";
import { CLOUD_SCAN_AUTHORIZATION_VERSION } from "@/services/cloudAuthorization";

const router = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => router }));
vi.mock("@/services/apiClient", () => ({ api: { post: vi.fn() } }));

async function renderScanner() {
  await act(async () => {
    render(
      <AuthProvider>
        <SettingsProvider><ScannerForm /><CloudAuthorizationDialog /></SettingsProvider>
      </AuthProvider>,
    );
  });
}

function enterTarget(target: string) {
  fireEvent.change(screen.getByRole("textbox", { name: "Target" }), { target: { value: target } });
}

function start() {
  fireEvent.click(screen.getByRole("button", { name: "Start TLS Analysis" }));
}

async function authorize() {
  await act(async () => fireEvent.click(screen.getByRole("button", { name: "I confirm authorization" })));
}

describe("TLS scanner", () => {
  beforeEach(() => {
    vi.mocked(api.post).mockReset();
  });

  it("requires a target before requesting consent or calling the API", async () => {
    await renderScanner();
    start();
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a target host");
    expect(api.post).not.toHaveBeenCalled();
  });

  it("disables cloud analysis when a private target has no agent", async () => {
    await renderScanner();
    enterTarget("192.168.1.50");
    expect(screen.getByRole("button", { name: "Start TLS Analysis" })).toBeDisabled();
    expect(api.post).not.toHaveBeenCalled();
  });

  it("cancels the launch when cloud authorization is declined", async () => {
    await renderScanner();
    enterTarget("example.test");
    start();
    expect(screen.getByRole("dialog")).toBeVisible();
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Cancel" })));
    expect(screen.getByRole("alert")).toHaveTextContent("Scan not started");
    expect(api.post).not.toHaveBeenCalled();
  });

  it("posts authorized settings, shows progress, and opens the completed report", async () => {
    vi.useFakeTimers();
    vi.mocked(api.post).mockResolvedValue({ id: "scan-42" });
    await renderScanner();
    enterTarget("example.test:8443");
    start();
    await authorize();

    expect(api.post).toHaveBeenCalledWith("/scans", {
      body: {
        target: "example.test:8443",
        options: { timeout: 15, sni: true, profile: "citizen-facing", alternatePorts: [8080, 8000, 4443, 8443] },
        authorizationAccepted: true,
        authorizationVersion: CLOUD_SCAN_AUTHORIZATION_VERSION,
      },
    });
    expect(screen.getByRole("button", { name: "Analyzing..." })).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Target" })).toBeDisabled();
    expect(screen.getByText(/Connecting to target/)).toBeVisible();
    expect(screen.getByText("0/6")).toBeVisible();
    expect(router.push).not.toHaveBeenCalled();

    await act(async () => vi.advanceTimersByTimeAsync(900));
    expect(screen.getByText("1/6")).toBeVisible();
    await act(async () => vi.advanceTimersByTimeAsync(4150));
    expect(screen.getByText("Analysis complete")).toBeVisible();
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(router.push).toHaveBeenCalledWith("/scanner/scan-42");
  });

  it("shows an error and allows a retry when the API rejects the scan", async () => {
    vi.useFakeTimers();
    vi.mocked(api.post).mockRejectedValue(new Error("Network unavailable"));
    await renderScanner();
    enterTarget("example.test");
    start();
    await authorize();
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.getByRole("alert")).toHaveTextContent("The analysis failed. Network unavailable");
    expect(screen.getByRole("button", { name: "Start TLS Analysis" })).toBeEnabled();
    expect(router.push).not.toHaveBeenCalled();
  });

  it("keeps the progress screen visible until the pending scan request completes", async () => {
    vi.useFakeTimers();
    const pending = Promise.withResolvers<{ id: string }>();
    vi.mocked(api.post).mockReturnValue(pending.promise);
    await renderScanner();
    enterTarget("example.test");
    start();
    await authorize();
    await act(async () => vi.advanceTimersByTimeAsync(5050));

    expect(screen.getByText("6/6")).toBeVisible();
    expect(screen.getByRole("progressbar")).toBeVisible();
    expect(screen.getByRole("button", { name: "Analyzing..." })).toBeDisabled();
    expect(screen.queryByText("Analysis complete")).not.toBeInTheDocument();
    expect(router.push).not.toHaveBeenCalled();

    await act(async () => pending.resolve({ id: "pending-scan" }));
    expect(screen.getByText("Analysis complete")).toBeVisible();
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(router.push).toHaveBeenCalledWith("/scanner/pending-scan");
  });
});
