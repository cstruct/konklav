// The app: a public OIDC client that must use DPoP.
//
// - Sign-in: the authorization code flow with PKCE. `dpop_jkt` binds the
//   code to this page's key, and the token request carries a proof, so
//   Konklav issues `DPoP` tokens that work only with that key.
// - Storage: tokens live in the `tokens` variable and nowhere else. The key
//   is a non-extractable CryptoKey in IndexedDB; the PKCE verifier waits
//   there during the redirect and is deleted on return.
// - Reloads: tokens are gone, so the page asks Konklav again with
//   `prompt=none`. The login page finds the single sign-on cookie and
//   answers without showing anything, or refuses with `login_required`.

import { b64url, proof, recall, remember, thumbprint } from "/shared/dpop.js";

const $ = (id) => document.getElementById(id);
const config = await (await fetch("/config.json")).json();
const discovery = await (await fetch(`${config.issuer}/.well-known/openid-configuration`)).json();
const redirectUri = `${location.origin}/callback`;

/// { access_token, refresh_token, id_token, expires_at }, in memory only.
let tokens = null;
/// The last API request's headers, to show that a replay is refused.
let lastRequest = null;
let refreshTimer = null;
/// The app backend's replicas that answered this page, to show the load
/// balancer at work. The Rust version runs one backend and doesn't say.
const replicas = new Set();

const random = (bytes) => b64url(crypto.getRandomValues(new Uint8Array(bytes)));
const sha256 = async (text) => b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

function claimsOf(jwt) {
  const payload = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(payload));
}

// --- Signing in --------------------------------------------------------------

async function authorize({ silent }) {
  const state = random(16);
  const verifier = random(32);
  const nonce = random(16);
  await remember(`pending:${state}`, { verifier, nonce });
  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.client_id,
    redirect_uri: redirectUri,
    scope: "openid email",
    state,
    nonce,
    code_challenge: await sha256(verifier),
    code_challenge_method: "S256",
    dpop_jkt: await thumbprint(),
    ...(silent ? { prompt: "none" } : {}),
  });
  location.assign(url);
}

/// Back from Konklav: exchanges the code. Returns false when nobody is
/// signed in (the silent attempt was refused).
async function callback() {
  const params = new URLSearchParams(location.search);
  history.replaceState(null, "", "/");
  const pending = await recall(`pending:${params.get("state")}`);
  if (!pending) throw new Error("This sign-in wasn't started here (unknown state).");
  if (params.get("iss") !== config.issuer) throw new Error("The response came from another issuer.");
  const error = params.get("error");
  if (error === "login_required" || error === "access_denied") return false;
  if (error) throw new Error(params.get("error_description") ?? error);

  await tokenRequest({
    grant_type: "authorization_code",
    code: params.get("code"),
    redirect_uri: redirectUri,
    code_verifier: pending.verifier,
  });
  if (claimsOf(tokens.id_token).nonce !== pending.nonce) {
    tokens = null;
    throw new Error("The ID token's nonce doesn't match.");
  }
  return true;
}

/// A token request with a proof of this page's key.
async function tokenRequest(params) {
  const response = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: await proof("POST", discovery.token_endpoint),
    },
    body: new URLSearchParams({ client_id: config.client_id, ...params }),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error_description ?? body.error);
  if (body.token_type !== "DPoP") throw new Error(`Expected DPoP tokens, got ${body.token_type}.`);
  tokens = {
    access_token: body.access_token,
    // Refresh tokens rotate: each refresh returns the next one.
    refresh_token: body.refresh_token ?? tokens?.refresh_token,
    id_token: body.id_token ?? tokens?.id_token,
    expires_at: Date.now() + body.expires_in * 1000,
  };
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => refresh().catch(signedOut), Math.max(body.expires_in - 30, 5) * 1000);
  renderTokens();
}

async function refresh() {
  if (!tokens?.refresh_token) throw new Error("no refresh token");
  await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
}

function signOut() {
  // RP-initiated logout ends the sign-in at the login page too, and every
  // session started from it, such as the admin page's.
  const url = new URL(discovery.end_session_endpoint);
  url.search = new URLSearchParams({
    client_id: config.client_id,
    id_token_hint: tokens.id_token,
    post_logout_redirect_uri: `${location.origin}/`,
  });
  tokens = null;
  location.assign(url);
}

// --- Calling the API ---------------------------------------------------------

/// Calls the backend with the token and a fresh proof for this request.
/// On 401 it refreshes once: the token may have expired, or the session
/// been revoked, in which case the refresh fails too.
async function api(method, path, body, retried = false) {
  const url = `${config.api}${path}`;
  const headers = {
    authorization: `DPoP ${tokens.access_token}`,
    dpop: await proof(method, url, tokens.access_token),
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  lastRequest = { method, url, headers };
  const response = await fetch(url, { method, headers, body: body && JSON.stringify(body) });
  if (response.status === 401 && !retried) {
    try {
      await refresh();
    } catch {
      signedOut();
      throw new Error("Your session has ended.");
    }
    return api(method, path, body, true);
  }
  if (response.status === 429) {
    // Rate limited: `Retry-After` says, in seconds, when to try again.
    const retryAfter = Number(response.headers.get("retry-after")) || 1;
    throw Object.assign(new Error(`Too many requests; try again in ${retryAfter} s.`), { retryAfter });
  }
  const data = await response.json();
  if (!response.ok) throw new Error(data.message ?? `${response.status}`);
  if (data.replica) {
    replicas.add(data.replica);
    $("replica").textContent = `Answered by backend replica${replicas.size > 1 ? "s" : ""} ${[...replicas].join(", ")}.`;
  }
  return data;
}

/// After a 429: keeps the Add button disabled until `Retry-After` has
/// passed, counting down, rather than letting the person retry into it.
function holdOff(seconds) {
  const until = Date.now() + seconds * 1000;
  $("add-note").disabled = true;
  const tick = () => {
    const left = Math.ceil((until - Date.now()) / 1000);
    if (left <= 0) {
      $("add-note").disabled = false;
      $("notes-error").hidden = true;
      return;
    }
    $("notes-error").hidden = false;
    $("notes-error").textContent = `You're adding notes too fast. You can add another in ${left} s.`;
    setTimeout(tick, 250);
  };
  tick();
}

async function attack(request) {
  const response = await fetch(request.url, { method: request.method, headers: request.headers });
  $("attack").hidden = false;
  $("attack").textContent =
    `${request.method} ${request.url}\n${Object.entries(request.headers).map(([k, v]) => `${k}: ${v.slice(0, 40)}…`).join("\n")}\n\n` +
    `→ ${response.status} ${response.statusText}\nWWW-Authenticate: ${response.headers.get("www-authenticate")}\n${await response.text()}`;
}

// --- Views -------------------------------------------------------------------

function show(view) {
  $("status").hidden = true;
  $("signed-out").hidden = view !== "signed-out";
  $("signed-in").hidden = view !== "signed-in";
  $("who").hidden = view !== "signed-in";
}

function signedOut() {
  tokens = null;
  clearTimeout(refreshTimer);
  show("signed-out");
}

function renderTokens() {
  if (!tokens) return;
  const claims = claimsOf(tokens.access_token);
  const left = Math.round((tokens.expires_at - Date.now()) / 1000);
  $("tokens").textContent =
    `access token (expires in ${left}s): ${tokens.access_token.slice(0, 32)}…\n` +
    `  aud ${claims.aud}, bound to key cnf.jkt ${claims.cnf?.jkt}\n` +
    `refresh token: ${tokens.refresh_token ? `${tokens.refresh_token.slice(0, 12)}… (works only with the same key)` : "none"}`;
}

/// One request per action: a proof is accepted once, so each decision
/// gets a request, and a proof, of its own.
async function renderAccess() {
  const actions = ["notes:read", "notes:write"];
  const answers = await Promise.all(actions.map((action) => api("GET", `/api/can/${action}`)));
  const may = answers.map(({ action, allowed }) => `${allowed ? "✓" : "✗"} ${action}`);
  $("access").textContent = `Subject ${claimsOf(tokens.id_token).sub}: ${may.join(", ")}`;
}

async function renderNotes() {
  $("notes-error").hidden = true;
  try {
    const { notes } = await api("GET", "/api/notes");
    $("notes").replaceChildren(
      ...notes.map((note) => {
        const item = document.createElement("li");
        const by = document.createElement("div");
        by.className = "muted";
        by.textContent = `${note.author} · ${new Date(note.at).toLocaleTimeString()}`;
        item.append(note.text, by);
        return item;
      }),
    );
  } catch (error) {
    $("notes").replaceChildren();
    $("notes-error").hidden = false;
    $("notes-error").textContent = error.message;
  }
}

async function render() {
  const userinfo = await fetch(discovery.userinfo_endpoint, {
    headers: {
      authorization: `DPoP ${tokens.access_token}`,
      dpop: await proof("GET", discovery.userinfo_endpoint, tokens.access_token),
    },
  }).then((response) => response.json());
  $("email").textContent = userinfo.email ?? claimsOf(tokens.id_token).sub;
  show("signed-in");
  await Promise.all([renderAccess(), renderNotes()]);
}

$("sign-in").addEventListener("click", () => authorize({ silent: false }));
$("sign-out").addEventListener("click", signOut);
$("refresh-access").addEventListener("click", () => Promise.all([renderAccess(), renderNotes()]));
$("new-note").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("POST", "/api/notes", { text: $("note").value });
    $("note").value = "";
    await renderNotes();
  } catch (error) {
    if (error.retryAfter) return holdOff(error.retryAfter);
    $("notes-error").hidden = false;
    $("notes-error").textContent = error.message;
  }
});
$("steal-bearer").addEventListener("click", () =>
  attack({ method: "GET", url: `${config.api}/api/notes`, headers: { authorization: `Bearer ${tokens.access_token}` } }),
);
$("steal-replay").addEventListener("click", () => lastRequest && attack(lastRequest));
setInterval(renderTokens, 1000);

try {
  if (location.pathname === "/callback") {
    if (await callback()) await render();
    else signedOut();
  } else {
    await authorize({ silent: true });
  }
} catch (error) {
  $("status").hidden = false;
  $("status").textContent = `Couldn't sign in: ${error.message}`;
  $("signed-out").hidden = false;
}
