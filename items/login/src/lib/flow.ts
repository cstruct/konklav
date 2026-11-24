// The page's decisions, kept apart from the DOM so they can be tested.

import { prompts, type LoginRequest } from "./login-request";

/** What the page does once it knows the request and whether someone is signed in. */
export type Start =
  /** The address named a request that isn't one, or that has expired. */
  | { kind: "expired" }
  /** Single sign-on: accept the request with the session there is. */
  | { kind: "accept" }
  /** Answer the client without showing anything. */
  | { kind: "reject"; error: "login_required" }
  | { kind: "sign-in" }
  /** Opened without a request: show who is signed in. */
  | { kind: "account" };

/**
 * Whether to look for an existing sign-in: not with `prompt=login`, which
 * asks for a fresh one.
 */
export function shouldRestore(request: LoginRequest | null): boolean {
  return !prompts(request).has("login");
}

export function start(request: LoginRequest | null, expired: boolean, signedIn: boolean): Start {
  if (expired) return { kind: "expired" };
  if (request && signedIn) return { kind: "accept" };
  if (request && prompts(request).has("none")) return { kind: "reject", error: "login_required" };
  if (signedIn) return { kind: "account" };
  return { kind: "sign-in" };
}

/**
 * After accepting failed for a session there was already, such as one too
 * old for the request's `max_age`: `prompt=none` must not show anything, so
 * the client is told a login is required; otherwise the person signs in
 * again.
 */
export function afterRefusedAccept(request: LoginRequest): Start {
  return prompts(request).has("none") ? { kind: "reject", error: "login_required" } : { kind: "sign-in" };
}

/**
 * The tenant to enter before accepting: the one the request asks for
 * (`tenant:<id>`), when the session isn't in it already.
 */
export function tenantToEnter(request: LoginRequest | null, currentTenant: string | undefined): string | null {
  const wanted = request?.tenant ?? null;
  return wanted && wanted !== currentTenant ? wanted : null;
}

/** A message for a failed sign-in, by Konklav's error code. */
export function signInError(code: string | undefined, fallback: string): string {
  switch (code) {
    case "INVALID_CREDENTIALS":
      return "That email address and password don't match.";
    case "RATE_LIMITED":
      return "Too many attempts. Wait a while and try again.";
    case "OVERLOADED":
      return "Sign-in is busy right now. Try again in a moment.";
    default:
      return fallback;
  }
}

/** A message for `?error=…` after an identity provider sent the browser back. */
export function federationError(error: string): string {
  switch (error) {
    case "account_not_linked":
      return "That account isn't linked to anyone here.";
    case "account_linked_elsewhere":
      return "That account is linked to someone else.";
    case "requirements_not_met":
      return "The identity provider's sign-in wasn't strong enough. Try again.";
    case "provider_error":
      return "The identity provider refused the sign-in.";
    default:
      return `The identity provider sign-in failed (${error}).`;
  }
}

/** What `/v1/tenants/{id}/access-request` answers. */
export interface AccessRequest {
  id: string;
  state: "pending" | "approved" | "denied" | "withdrawn";
  created_at: string;
  decided_at?: string | null;
}

export function accessRequestPath(tenant: string): string {
  return `/tenants/${encodeURIComponent(tenant)}/access-request`;
}

/** The tenant a login request names refused the person signed in. */
export class NoAccess extends Error {
  readonly tenant: string;

  constructor(tenant: string, message: string) {
    super(message);
    this.tenant = tenant;
  }
}

/**
 * After the requested tenant refused the person: offer to request access
 * when the server takes requests, except with `prompt=none`, which must not
 * show anything.
 */
// r[impl oidc.provider.login-page.access-requests]
export function afterNoAccess(request: LoginRequest, accessRequests: boolean): Start | { kind: "ask" } {
  if (prompts(request).has("none")) return { kind: "reject", error: "login_required" };
  return accessRequests ? { kind: "ask" } : { kind: "sign-in" };
}
