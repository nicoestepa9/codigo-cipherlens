export const MOCK_MODE_KEY = "cipherlens_mock_mode";
const LEGACY_MOCK_MODE_KEY = "cryptoguard_mock_mode";

export function isMock(): boolean {
  if (typeof window !== "undefined") {
    const stored = window.localStorage.getItem(MOCK_MODE_KEY) ?? window.localStorage.getItem(LEGACY_MOCK_MODE_KEY);
    if (stored !== null) return stored === "true";
  }
  // Por default usar modo real en desarrollo
  return process.env.NEXT_PUBLIC_USE_MOCK === "true";
}

export function setMockMode(enabled: boolean): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(MOCK_MODE_KEY, String(enabled));
}

// Use the existing Next.js rewrite so requests share the page's origin.
// The backend target belongs in NEXT_PUBLIC_API_PROXY_TARGET (next.config.ts).
export const API_BASE_URL = "/api";

export const MOCK_MIN_DELAY = 250;
export const MOCK_MAX_DELAY = 750;
