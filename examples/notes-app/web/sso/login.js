// The login page. Konklav sends the browser here with `?login_request=…`
// when an app starts a sign-in; opened without one, it shows the account.
//
// Nothing goes to localStorage or sessionStorage:
// - Konklav's refresh token is an HttpOnly cookie, set and read by Konklav.
// - The access token is a variable in this module, gone on reload.
// - The DPoP key is a non-extractable CryptoKey in IndexedDB (see dpop.js).

import { proof } from "/shared/dpop.js";

const $ = (id) => document.getElementById(id);
const loginRequest = new URLSearchParams(location.search).get("login_request");

/// The Konklav session's access token, in memory only.
let accessToken = null;

class KonklavError extends Error {
  constructor(status, body) {
    // Konklav's errors are {"error": {"code": "INVALID_CREDENTIALS", "message": …}}.
    super(body?.error?.message ?? `Konklav answered ${status}`);
    this.status = status;
    this.code = body?.error?.code;
  }
}

/// Calls Konklav's subject-facing surface, which this origin proxies. Every
/// request carries a DPoP proof: one without a token binds a new session to
/// the key, one with a token proves the caller holds the key.
async function konklav(method, path, body) {
  const url = new URL(path, location.origin).href;
  const headers = {
    // Konklav requires a custom header on browser endpoints (CSRF defence).
    "x-konklav-client": "example-sso",
    dpop: await proof(method, url, accessToken),
  };
  if (accessToken) headers.authorization = `DPoP ${accessToken}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new KonklavError(response.status, data);
  return data;
}

/// Restores the session from the refresh cookie, if there is one.
async function restore() {
  try {
    accessToken = (await konklav("POST", "/v1/refresh")).access_token;
    return true;
  } catch {
    accessToken = null;
    return false;
  }
}

/// Accepts the app's request with this session and follows Konklav back.
async function accept() {
  const { redirect_to } = await konklav("POST", `/v1/oauth2/login-requests/${loginRequest}/accept`);
  location.replace(redirect_to);
}

async function reject(error) {
  const { redirect_to } = await konklav("POST", `/v1/oauth2/login-requests/${loginRequest}/reject`, { error });
  location.replace(redirect_to);
}

function subjectOf(token) {
  const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(payload)).sub;
}

function show(view) {
  $("status").hidden = true;
  $("sign-in").hidden = view !== "sign-in";
  $("account").hidden = view !== "account";
}

function showAccount() {
  $("subject").textContent = subjectOf(accessToken);
  show("account");
}

function showSignIn(request, message) {
  if (request) {
    $("sign-in-title").textContent = `Sign in to continue to ${request.client_id}`;
    $("cancel").hidden = false;
    if (request.login_hint) $("email").value = request.login_hint;
  }
  $("error").hidden = !message;
  $("error").textContent = message ?? "";
  show("sign-in");
  ($("email").value ? $("password") : $("email")).focus();
}

async function signIn(request) {
  const tokens = await konklav("POST", "/v1/login/password", {
    identifier: $("email").value,
    password: $("password").value,
    // The refresh token comes back as an HttpOnly cookie, not in the body.
    client: "browser",
  });
  accessToken = tokens.access_token;
  if (tokens.token_kind === "partial") {
    throw new Error("This account needs MFA, which this example's login page doesn't implement.");
  }
  if (request) await accept();
  else showAccount();
}

/// The app's pending request, when Konklav sent the browser here with one.
let request = null;

async function main() {
  if (loginRequest) {
    try {
      request = await konklav("GET", `/v1/oauth2/login-requests/${loginRequest}`);
    } catch {
      $("status").textContent = "This sign-in request has expired. Go back to the app and try again.";
      return;
    }
  }
  const prompts = (request?.prompt ?? "").split(" ");
  const signedIn = !prompts.includes("login") && (await restore());

  if (request && signedIn) {
    // Single sign-on: someone is signed in here already.
    try {
      return await accept();
    } catch (error) {
      // Such as a max_age the sign-in is too old for: sign in again.
      if (prompts.includes("none")) return reject("login_required");
      return showSignIn(request, error.message);
    }
  }
  if (request && prompts.includes("none")) return reject("login_required");
  if (signedIn) return showAccount();
  showSignIn(request);
}

$("sign-in").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await signIn(request);
  } catch (error) {
    showSignIn(request, error.code === "INVALID_CREDENTIALS" ? "Wrong email or password." : error.message);
  }
});
$("cancel").addEventListener("click", () => reject("access_denied"));

$("sign-out").addEventListener("click", async () => {
  // Ends this session, and with it every app session started from it.
  try {
    await konklav("POST", "/v1/sign-out");
  } finally {
    accessToken = null;
    location.replace("/");
  }
});

main().catch((error) => {
  $("status").hidden = false;
  $("status").textContent = `Something went wrong: ${error.message}`;
});
