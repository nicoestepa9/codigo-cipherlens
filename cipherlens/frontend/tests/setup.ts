import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("cipherlens_mock_mode", "false");
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.clearAllMocks();
});

Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { value: vi.fn() });
Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", { value: () => false });
