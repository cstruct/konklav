// The pending authorization request Konklav handed this page, as
// `?login_request=<id>`.

/**
 * What `GET /v1/login-requests/{id}` answers: a request an OIDC client
 * started (`kind: "oidc"`), or one a native app on this computer started,
 * such as the operator CLI (`kind: "native"`), which names only the app.
 */
export interface LoginRequest {
  /** Older servers leave it out for OIDC requests. */
  kind?: "oidc" | "native";
  /** The OIDC client, for an OIDC request. */
  client_id?: string;
  /** The app, for a native request. */
  app?: string;
  scopes?: string[];
  tenant?: string | null;
  max_age?: number | null;
  acr_values?: string[] | string | null;
  prompt?: string | null;
  login_hint?: string | null;
}

/**
 * The request id from the address, if it is one. The id goes into the path
 * of calls made with this session, so it must be an id and nothing else:
 * with `/`, `?`, `#` or `..` in it, a crafted link could aim those calls at
 * another endpoint.
 */
export function requestId(search: string): { id: string | null; invalid: boolean } {
  const raw = new URLSearchParams(search).get("login_request");
  if (raw === null) return { id: null, invalid: false };
  return /^[A-Za-z0-9_.-]{1,200}$/.test(raw) && !raw.includes("..")
    ? { id: raw, invalid: false }
    : { id: null, invalid: true };
}

export function prompts(request: LoginRequest | null): Set<string> {
  return new Set((request?.prompt ?? "").split(/\s+/).filter(Boolean));
}

export function path(id: string): string {
  return `/login-requests/${encodeURIComponent(id)}`;
}

/** Whether a native app on this computer started the request. */
export function isNative(request: LoginRequest | null): boolean {
  return request?.kind === "native";
}

/** Who the request is for: the OIDC client, or the native app. */
export function requester(request: LoginRequest): string {
  return (isNative(request) ? request.app : request.client_id) ?? "";
}

// A sign-in through an identity provider leaves the page and comes back to
// the provider's return URL, which can't carry the request. The id is kept
// in this tab's sessionStorage meanwhile; it is no secret, since the
// request can only be completed in the browser that started it.
const PENDING = "konklav-login:request";

export function rememberForReturn(id: string | null): void {
  try {
    if (id) sessionStorage.setItem(PENDING, id);
    else sessionStorage.removeItem(PENDING);
  } catch {
    // Storage may be unavailable; the person then starts again at the app.
  }
}

export function recallAfterReturn(): string | null {
  try {
    const id = sessionStorage.getItem(PENDING);
    sessionStorage.removeItem(PENDING);
    return id;
  } catch {
    return null;
  }
}
