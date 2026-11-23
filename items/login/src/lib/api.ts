// Konklav's subject-facing surface, called from the page's own origin.

import { proof } from "./dpop";

/** Konklav's error envelope: `{"error": {"code": "…", "message": "…"}}`. */
export class KonklavError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, body: unknown) {
    const error = (body as { error?: { code?: string; message?: string } } | null)?.error;
    super(error?.message ?? `Konklav answered ${status}`);
    this.status = status;
    this.code = error?.code;
  }
}

/** What a login, MFA step, tenant selection or refresh answers with. */
export interface Tokens {
  access_token: string;
  token_kind: "partial" | "identity" | "tenant" | string;
}

/**
 * Where Konklav's `/v1` is: next to the page's own directory, so the page
 * works under a reverse proxy's prefix as well (`/prefix/login/` calls
 * `/prefix/v1/…`).
 */
export function apiBase(page: URL): URL {
  return new URL("../", new URL("./", page));
}

// r[impl oidc.provider.login-page.storage]
export class Konklav {
  /** The session's access token, in memory only. */
  accessToken: string | null = null;

  constructor(private readonly base: URL) {}

  url(path: string): string {
    return new URL(`v1${path}`, this.base).href;
  }

  /**
   * Calls `/v1{path}`. Every request carries a DPoP proof: one without a
   * token binds a new session to the page's key, one with a token proves
   * the page holds it.
   */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = this.url(path);
    // Konklav requires a custom header on browser endpoints (CSRF defence).
    const headers: Record<string, string> = { "x-konklav-client": "konklav-login" };
    const dpop = await proof(method, url, this.accessToken);
    if (dpop) headers.dpop = dpop;
    if (this.accessToken) headers.authorization = `${dpop ? "DPoP" : "Bearer"} ${this.accessToken}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
    const text = await response.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    if (!response.ok) throw new KonklavError(response.status, data);
    return data as T;
  }

  /** Keeps the access token of a login, refresh or tenant selection. */
  async tokens(method: string, path: string, body?: unknown): Promise<Tokens> {
    const tokens = await this.call<Tokens>(method, path, body);
    this.accessToken = tokens.access_token;
    return tokens;
  }

  /** Restores the session from Konklav's refresh cookie, if there is one. */
  async restore(): Promise<Tokens | null> {
    try {
      return await this.tokens("POST", "/refresh");
    } catch {
      this.accessToken = null;
      return null;
    }
  }
}

/** The claims of an access token the page shows; it never verifies them. */
export function claimsOf(token: string): { sub?: string; tid?: string; exp?: number } {
  try {
    const payload = token.split(".")[1] ?? "";
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(json, (c) => c.charCodeAt(0))));
  } catch {
    return {};
  }
}
