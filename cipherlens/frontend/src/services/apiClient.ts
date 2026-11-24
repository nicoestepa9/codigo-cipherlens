import { API_BASE_URL } from "./config";

export type QueryValue = string | number | boolean | undefined | null;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  query?: Record<string, QueryValue>;
  body?: unknown;
  apiKey?: string;
  signal?: AbortSignal;
  organization_id?: string;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

let accessToken: string | null = null;
let refreshing: Promise<string | null> | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
  if (typeof window !== "undefined") {
    try {
      if (token) window.localStorage.setItem("authToken", token);
      else window.localStorage.removeItem("authToken");
    } catch {
      // The in-memory session still works when browser storage is unavailable.
    }
  }
}

export function getAccessToken(): string | null {
  if (accessToken || typeof window === "undefined") return accessToken;
  try {
    // Fast Refresh can replace this module while AuthProvider retains its state.
    return window.localStorage.getItem("authToken");
  } catch {
    return null;
  }
}

async function tryRefresh(): Promise<string | null> {
  refreshing ??= (async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: "{}",
      });
      if (!response.ok) return null;
      const payload = (await response.json()) as { accessToken?: string };
      return payload.accessToken ?? null;
    } catch {
      return null;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

async function request<T>(path: string, options: RequestOptions = {}, allowRetry = true): Promise<T> {
  const { method = "GET", query: queryOpts, body, apiKey, signal, organization_id } = options;

  const query: Record<string, QueryValue> = { ...queryOpts };
  if (organization_id) {
    query.organization_id = organization_id;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const token = apiKey ?? getAccessToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(buildUrl(path, query), {
    method,
    headers,
    signal,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (response.status === 401 && allowRetry && !path.startsWith("/auth/") && !apiKey) {
    const fresh = await tryRefresh();
    if (fresh) {
      setAccessToken(fresh);
      return request<T>(path, options, false);
    }
    setAccessToken(null);
  }

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string; error?: string; detail?: string };
      message = payload.detail ?? payload.message ?? payload.error ?? message;
    } catch {
      // ignore parse errors
    }
    if (response.status === 401 && !path.startsWith("/auth/") && !apiKey) {
      message = "Tu sesión venció o no está disponible. Volvé a iniciar sesión.";
    }
    throw new ApiError(response.status, message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const base = typeof window !== "undefined" ? window.location.origin : "http://localhost";
  const url = new URL(`${API_BASE_URL}${path}`, base);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  return request<T>(path, options);
}

export const api = {
  get: <T>(path: string, options?: Omit<RequestOptions, "method" | "body">) =>
    apiRequest<T>(path, { ...options, method: "GET" }),
  post: <T>(path: string, options?: Omit<RequestOptions, "method">) =>
    apiRequest<T>(path, { ...options, method: "POST" }),
  put: <T>(path: string, options?: Omit<RequestOptions, "method">) =>
    apiRequest<T>(path, { ...options, method: "PUT" }),
  patch: <T>(path: string, options?: Omit<RequestOptions, "method">) =>
    apiRequest<T>(path, { ...options, method: "PATCH" }),
  delete: <T>(path: string, options?: Omit<RequestOptions, "method">) =>
    apiRequest<T>(path, { ...options, method: "DELETE" }),
};
