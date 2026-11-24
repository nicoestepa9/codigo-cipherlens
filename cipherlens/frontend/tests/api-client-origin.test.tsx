import { afterEach, describe, expect, it, vi } from "vitest";
import { api, setAccessToken } from "@/services/apiClient";

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("API requests through the same-origin Next proxy", () => {
  it("restores the persisted token when the module has lost its in-memory token", async () => {
    localStorage.setItem("authToken", "persisted-session");
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.post("/crypto-ml/analyze", { body: { source: "class Demo {}" } });
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer persisted-session");
  });

  it("renews an expired session with its cookie and retries with the new token", async () => {
    setAccessToken("expired-session");
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"detail":"expired"}', { status: 401 }))
      .mockResolvedValueOnce(new Response('{"accessToken":"renewed-session"}', { status: 200 }))
      .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.post("/crypto-ml/analyze", { body: { source: "class Demo {}" } })).resolves.toEqual({ ok: true });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/auth/refresh");
    expect(fetchMock.mock.calls[1][1].credentials).toBe("same-origin");
    expect(fetchMock.mock.calls[2][1].headers.Authorization).toBe("Bearer renewed-session");
    expect(localStorage.getItem("authToken")).toBe("renewed-session");
  });

  it("clears an unrecoverable session and asks the user to sign in", async () => {
    setAccessToken("expired-session");
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"detail":"Missing credentials"}', { status: 401 }))
      .mockResolvedValueOnce(new Response('{"detail":"Missing refresh token"}', { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.post("/crypto-ml/analyze", { body: {} })).rejects.toMatchObject({ status: 401, message: expect.stringContaining("Volvé a iniciar sesión") });
    expect(localStorage.getItem("authToken")).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("logs in and out through the proxy with session cookies enabled", async () => {
    vi.stubEnv("NEXT_PUBLIC_USE_MOCK", "false");
    localStorage.removeItem("cipherlens_mock_mode");
    const { login, logoutRequest } = await import("@/services/authService");
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"accessToken":"session"}', { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    await login("demo@example.test", "test-password");
    await logoutRequest();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/auth/login");
    expect(fetchMock.mock.calls[0][1].credentials).toBe("same-origin");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/auth/logout");
    expect(fetchMock.mock.calls[1][1].credentials).toBe("same-origin");
  });

  it("posts Java to the page origin and preserves authentication", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: "needs_review" }), {
      status: 200, headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    setAccessToken("test-session-token");
    const body = { filename: "Caso1.java", source: "class Caso1 {}" };
    await expect(api.post("/crypto-ml/analyze", { body })).resolves.toEqual({ status: "needs_review" });
    const [url, options] = fetchMock.mock.calls[0];
    expect(new URL(url).origin).toBe(window.location.origin);
    expect(new URL(url).pathname).toBe("/api/crypto-ml/analyze");
    expect(options.headers.Authorization).toBe("Bearer test-session-token");
    expect(options.body).toBe(JSON.stringify(body));
  });

  it("keeps HTTP errors readable instead of reporting a failed connection", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Missing credentials" }), {
      status: 401, headers: { "Content-Type": "application/json" },
    })));
    await expect(api.post("/auth/login", { body: {} })).rejects.toMatchObject({ status: 401, message: "Missing credentials" });
  });
});
