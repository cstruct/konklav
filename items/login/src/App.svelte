<script lang="ts">
  // The login page. Konklav's authorization endpoint sends the browser here
  // with `?login_request=<id>` when an OIDC client starts a sign-in; opened
  // without one, it shows who is signed in.
  //
  // Nothing secret goes to web storage: the refresh token is Konklav's
  // HttpOnly cookie, the access token lives in `konklav` only, and the DPoP
  // key is a non-extractable CryptoKey (see lib/dpop.ts).

  import { onMount } from "svelte";

  import Account from "./Account.svelte";
  import Mfa from "./Mfa.svelte";
  import RequestAccess from "./RequestAccess.svelte";
  import SignIn from "./SignIn.svelte";
  import { Konklav, KonklavError, apiBase, claimsOf, type Tokens } from "./lib/api";
  import { thumbprint } from "./lib/dpop";
  import {
    NoAccess,
    accessRequestPath,
    afterNoAccess,
    afterRefusedAccept,
    federationError,
    shouldRestore,
    signInError,
    start,
    tenantToEnter,
    type AccessRequest,
    type Start,
  } from "./lib/flow";
  import {
    path,
    recallAfterReturn,
    rememberForReturn,
    requestId,
    type LoginRequest,
  } from "./lib/login-request";
  import { DEFAULTS, load, type IdentityProvider, type Settings } from "./lib/settings";
  import { getAssertion, supported as passkeysSupported, type RequestOptionsJson } from "./lib/webauthn";

  type View =
    | { kind: "loading" }
    | { kind: "message"; text: string }
    | { kind: "sign-in"; message?: string }
    | { kind: "mfa" }
    | { kind: "account" }
    | { kind: "no-access"; tenant: string; access: AccessRequest | null; message?: string }
    | { kind: "leaving" };

  const page = new URL(location.href);
  const konklav = new Konklav(apiBase(page));

  let settings: Settings = $state(DEFAULTS);
  let view: View = $state({ kind: "loading" });
  let busy = $state(false);
  let request: LoginRequest | null = $state(null);
  let id: string | null = null;

  const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

  function leave(url: string) {
    view = { kind: "leaving" };
    location.replace(url);
  }

  async function reject(error: string) {
    if (!id) return;
    const { redirect_to } = await konklav.call<{ redirect_to: string }>("POST", `${path(id)}/reject`, { error });
    leave(redirect_to);
  }

  /** Enters the tenant the request names, then accepts the request with this session. */
  async function accept() {
    if (!id || !request) {
      view = { kind: "account" };
      return;
    }
    const tenant = tenantToEnter(request, claimsOf(konklav.accessToken ?? "").tid);
    if (tenant) {
      try {
        await konklav.tokens("POST", "/login/tenant", { tenant });
      } catch (error) {
        // Not a member, or the tenant isn't active.
        if (error instanceof KonklavError && error.code === "FORBIDDEN") throw new NoAccess(tenant, error.message);
        throw error;
      }
    }
    const { redirect_to } = await konklav.call<{ redirect_to: string }>("POST", `${path(id)}/accept`);
    leave(redirect_to);
  }

  async function follow(step: Start, reason?: string): Promise<void> {
    switch (step.kind) {
      case "expired":
        view = {
          kind: "message",
          text: "This sign-in has expired or was already used. Go back to the application and start again.",
        };
        return;
      case "reject":
        return reject(step.error);
      case "accept":
        try {
          return await accept();
        } catch (error) {
          if (error instanceof NoAccess) return noAccess(error);
          // Such as a sign-in too old for the request's max_age.
          konklav.accessToken = null;
          return follow(afterRefusedAccept(request!), message(error));
        }
      case "sign-in":
        view = { kind: "sign-in", message: reason };
        return;
      case "account":
        view = { kind: "account" };
        return;
    }
  }

  /** After a credential succeeded: MFA if it needs more, else on to the client. */
  async function signedIn(tokens: Tokens) {
    if (tokens.token_kind === "partial") {
      view = { kind: "mfa" };
      return;
    }
    try {
      await accept();
    } catch (error) {
      if (error instanceof NoAccess) return noAccess(error);
      view = { kind: "sign-in", message: message(error) };
    }
  }

  /**
   * The person signed in may not enter the tenant the request names: offer
   * to request access, showing the latest request they made for it.
   */
  async function noAccess(refusal: NoAccess, note?: string): Promise<void> {
    const next = afterNoAccess(request!, settings.access_requests);
    if (next.kind !== "ask") {
      konklav.accessToken = null;
      return follow(next, refusal.message);
    }
    let access: AccessRequest | null = null;
    try {
      access = await konklav.call<AccessRequest>("GET", accessRequestPath(refusal.tenant));
    } catch (error) {
      if (!(error instanceof KonklavError && error.code === "NOT_FOUND")) {
        // This tenant takes no requests.
        konklav.accessToken = null;
        return follow({ kind: "sign-in" }, refusal.message);
      }
    }
    view = { kind: "no-access", tenant: refusal.tenant, access, message: note };
  }

  async function onAccess(work: (tenant: string) => Promise<void>) {
    if (view.kind !== "no-access") return;
    const tenant = view.tenant;
    busy = true;
    try {
      await work(tenant);
    } catch (error) {
      if (error instanceof NoAccess) await noAccess(error, "Your request hasn't been approved yet.");
      else if (view.kind === "no-access") view = { ...view, message: message(error) };
    } finally {
      busy = false;
    }
  }

  const askAccess = () =>
    onAccess(async (tenant) => {
      const access = await konklav.call<AccessRequest>("POST", accessRequestPath(tenant));
      view = { kind: "no-access", tenant, access };
    });

  const withdrawAccess = () =>
    onAccess(async (tenant) => {
      const access = await konklav.call<AccessRequest>("DELETE", accessRequestPath(tenant));
      view = { kind: "no-access", tenant, access };
    });

  const checkAccess = () => onAccess(() => accept());

  async function attempt(work: () => Promise<void>) {
    busy = true;
    try {
      await work();
    } catch (error) {
      const code = error instanceof KonklavError ? error.code : undefined;
      view = { kind: "sign-in", message: signInError(code, message(error)) };
    } finally {
      busy = false;
    }
  }

  const password = (identifier: string, secret: string) =>
    attempt(async () => {
      const tokens = await konklav.tokens("POST", "/login/password", {
        identifier,
        password: secret,
        // The refresh token comes back as an HttpOnly cookie, not in the body.
        client: "browser",
      });
      await signedIn(tokens);
    });

  const passkey = () =>
    attempt(async () => {
      const { ceremony, options } = await konklav.call<{ ceremony: string; options: RequestOptionsJson }>(
        "POST",
        "/login/passkey/options",
        {},
      );
      const credential = await getAssertion(options);
      if (!credential) return;
      const tokens = await konklav.tokens("POST", "/login/passkey", { ceremony, credential, client: "browser" });
      await signedIn(tokens);
    });

  const provider = (chosen: IdentityProvider) =>
    attempt(async () => {
      rememberForReturn(id);
      const query = new URLSearchParams();
      if (settings.return_to) query.set("return_to", settings.return_to);
      // A navigation can't carry a proof, so the session is bound by thumbprint.
      const jkt = await thumbprint();
      if (jkt) query.set("dpop_jkt", jkt);
      leave(`${konklav.url(`/login/oidc/${encodeURIComponent(chosen.id)}/start`)}?${query}`);
    });

  const cancel = () => attempt(() => reject("access_denied"));

  async function signOut() {
    busy = true;
    try {
      await konklav.call("POST", "/sign-out");
    } catch {
      // Signed out already, or the session has ended.
    } finally {
      konklav.accessToken = null;
      busy = false;
      view = { kind: "sign-in" };
    }
  }

  async function main() {
    const loading = load(page);
    const found = requestId(page.search);
    id = found.id;
    // Back from an identity provider: `?signed_in=…` or `?error=…` on the
    // provider's return URL, with the request recalled from this tab.
    const signedInParam = page.searchParams.get("signed_in");
    const providerError = page.searchParams.get("error");
    if (signedInParam !== null || providerError !== null) {
      id ??= recallAfterReturn();
      history.replaceState(null, "", `${page.pathname}${id ? `?login_request=${encodeURIComponent(id)}` : ""}`);
    }
    settings = await loading;
    document.title = settings.title;

    let expired = found.invalid;
    if (id) {
      try {
        request = await konklav.call<LoginRequest>("GET", path(id));
      } catch {
        expired = true;
      }
    }
    if (expired) return follow({ kind: "expired" });

    if (providerError !== null) {
      view = { kind: "sign-in", message: federationError(providerError) };
      return;
    }
    if (signedInParam === "mfa_required") {
      await konklav.tokens("POST", "/login/oidc/partial");
      view = { kind: "mfa" };
      return;
    }
    // A sign-in at the provider just now counts even with prompt=login,
    // which only rules out sessions from before the request.
    const restored = (shouldRestore(request) || signedInParam === "true") && (await konklav.restore()) !== null;
    await follow(start(request, false, restored));
  }

  onMount(() => {
    main().catch((error) => {
      view = { kind: "message", text: `Something went wrong: ${message(error)}` };
    });
  });
</script>

<main>
  <div class="card" aria-live="polite">
    {#if view.kind === "loading" || view.kind === "leaving"}
      <h1>{settings.title}</h1>
      <p class="muted">{view.kind === "loading" ? "Checking for a sign-in…" : "Signing you in…"}</p>
    {:else if view.kind === "message"}
      <h1>{settings.title}</h1>
      <p>{view.text}</p>
    {:else if view.kind === "sign-in"}
      <SignIn
        {settings}
        {request}
        {busy}
        message={view.message}
        passkeys={settings.passkeys && passkeysSupported()}
        onPassword={password}
        onPasskey={passkey}
        onProvider={provider}
        onCancel={request ? cancel : undefined}
      />
    {:else if view.kind === "mfa"}
      <Mfa
        title={settings.title}
        {konklav}
        onDone={(tokens) => signedIn(tokens)}
        onCancel={() => {
          konklav.accessToken = null;
          view = { kind: "sign-in" };
        }}
      />
    {:else if view.kind === "no-access"}
      <RequestAccess
        title={settings.title}
        client={request?.client_id ?? ""}
        access={view.access}
        {busy}
        message={view.message}
        onAsk={askAccess}
        onCheck={checkAccess}
        onWithdraw={withdrawAccess}
        onSwitch={signOut}
        onCancel={cancel}
      />
    {:else if view.kind === "account"}
      <Account title={settings.title} token={konklav.accessToken ?? ""} {busy} onSignOut={signOut} />
    {/if}
  </div>
</main>
