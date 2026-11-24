export const CLOUD_SCAN_AUTHORIZATION_VERSION = "2026-10-v1";
export const CLOUD_SCAN_AUTHORIZATION_TEXT =
  "Confirmo que soy titular de este activo o cuento con autorización para escanearlo.";
export const CLOUD_AUTHORIZATION_REQUEST_EVENT = "cloud-authorization:request";

export interface CloudAuthorizationRequest {
  text: string;
  version: string;
  resolve: (accepted: boolean) => void;
}

export class CloudAuthorizationCancelledError extends Error {
  constructor(
    message = "Escaneo cancelado: se requiere aceptar la declaración de autorización.",
  ) {
    super(message);
    this.name = "CloudAuthorizationCancelledError";
  }
}

const acceptedInMemory = new Set<string>();

function requestCloudAuthorization(): Promise<boolean> {
  if (typeof window === "undefined") return Promise.resolve(false);

  return new Promise((resolve) => {
    const event = new CustomEvent<CloudAuthorizationRequest>(
      CLOUD_AUTHORIZATION_REQUEST_EVENT,
      {
        detail: {
          text: CLOUD_SCAN_AUTHORIZATION_TEXT,
          version: CLOUD_SCAN_AUTHORIZATION_VERSION,
          resolve,
        },
        cancelable: true,
      },
    );
    const handled = !window.dispatchEvent(event);
    if (!handled) resolve(false);
  });
}

function currentUserId(): string {
  try {
    const token = localStorage.getItem("authToken");
    if (!token) return "anonymous-session";
    const payload = token.split(".")[1];
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const claims = JSON.parse(decoded) as { sub?: string };
    return claims.sub || "anonymous-session";
  } catch {
    return "anonymous-session";
  }
}

export interface CloudAuthorizationFields {
  authorizationAccepted: boolean;
  authorizationVersion: string;
}

export interface CloudAuthorizationOptions {
  /** Ignore any cached acceptance and always show the confirmation dialog. */
  alwaysPrompt?: boolean;
}

export async function cloudAuthorizationFields(
  options: CloudAuthorizationOptions = {},
): Promise<CloudAuthorizationFields> {
  const { alwaysPrompt = false } = options;
  const key = `cloud-scan-authorization:${currentUserId()}:${CLOUD_SCAN_AUTHORIZATION_VERSION}`;
  let accepted = false;
  if (!alwaysPrompt) {
    accepted = acceptedInMemory.has(key);
    if (!accepted) {
      try {
        accepted = localStorage.getItem(key) === "accepted";
      } catch {
        // If browser storage is unavailable, request confirmation for this operation.
      }
    }
  }

  if (!accepted) {
    const confirmed = await requestCloudAuthorization();
    if (!confirmed) {
      throw new CloudAuthorizationCancelledError();
    }
    acceptedInMemory.add(key);
    try {
      localStorage.setItem(key, "accepted");
    } catch {
      // The in-memory cache still applies for the current session.
    }
  }

  return {
    authorizationAccepted: true,
    authorizationVersion: CLOUD_SCAN_AUTHORIZATION_VERSION,
  };
}
