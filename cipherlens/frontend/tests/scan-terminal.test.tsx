import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { ScanProgressTerminal } from "@/components/features/scanner/scan-terminal";
import type { ScanProgressStep } from "@/types/scan";

const steps: ScanProgressStep[] = [
  { label: "Connect", detail: "Opening a connection", state: "done" },
  { label: "Handshake", detail: "Negotiating TLS", state: "running" },
  { label: "Report", detail: "Building the report", state: "pending" },
];

it("updates the completed-step count and reveals only the active step detail", () => {
  const { rerender } = render(<ScanProgressTerminal steps={steps} />);
  expect(screen.getByRole("progressbar")).toBeVisible();
  expect(screen.getByText("1/3")).toBeVisible();
  expect(screen.getByText("Negotiating TLS")).toBeVisible();
  expect(screen.queryByText("Building the report")).not.toBeInTheDocument();

  rerender(<ScanProgressTerminal steps={steps.map((step, index) => ({
    ...step, state: index === 2 ? "running" : "done",
  }))} />);
  expect(screen.getByText("2/3")).toBeVisible();
  expect(screen.getByText("Building the report")).toBeVisible();
  expect(screen.queryByText("Negotiating TLS")).not.toBeInTheDocument();
});

it("renders and updates an explicit progress percentage and status", () => {
  const { rerender } = render(<ScanProgressTerminal steps={steps} progress={72.5} status="Analyzing" />);
  expect(screen.getByText(/73%.*Analyzing/)).toBeVisible();
  const indicator = () => screen.getByRole("progressbar").querySelector("[data-slot=progress-indicator]");
  expect(indicator()).toHaveStyle({ transform: "translateX(-27.5%)" });

  rerender(<ScanProgressTerminal steps={steps} progress={100} status="Completed" />);
  expect(screen.getByText(/100%.*Completed/)).toBeVisible();
  expect(indicator()).toHaveStyle({ transform: "translateX(-0%)" });
});
