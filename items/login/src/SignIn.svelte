<script lang="ts">
  import type { LoginRequest } from "./lib/login-request";
  import type { IdentityProvider, Settings } from "./lib/settings";

  interface Props {
    settings: Settings;
    request: LoginRequest | null;
    busy: boolean;
    message?: string;
    passkeys: boolean;
    onPassword: (identifier: string, password: string) => void;
    onPasskey: () => void;
    onProvider: (provider: IdentityProvider) => void;
    onCancel?: () => void;
  }

  let { settings, request, busy, message, passkeys, onPassword, onPasskey, onProvider, onCancel }: Props = $props();

  // svelte-ignore state_referenced_locally
  let identifier = $state(request?.login_hint ?? "");
  let password = $state("");

  const others = $derived(passkeys || settings.identity_providers.length > 0);

  function submit(event: SubmitEvent) {
    event.preventDefault();
    onPassword(identifier.trim(), password);
    password = "";
  }
</script>

<h1>{settings.title}</h1>
{#if request}
  <p class="muted">to continue to <strong>{request.client_id}</strong></p>
{:else}
  <p class="muted">Sign in to your account.</p>
{/if}

{#if message}
  <p class="error" role="alert">{message}</p>
{/if}

<form onsubmit={submit}>
  <label>
    Email
    <!-- svelte-ignore a11y_autofocus -->
    <input
      name="username"
      type="text"
      inputmode="email"
      autocomplete="username webauthn"
      autocapitalize="none"
      spellcheck="false"
      required
      autofocus={!identifier}
      bind:value={identifier}
    />
  </label>
  <label>
    Password
    <!-- svelte-ignore a11y_autofocus -->
    <input
      name="password"
      type="password"
      autocomplete="current-password"
      required
      autofocus={!!identifier}
      bind:value={password}
    />
  </label>
  <button type="submit" disabled={busy}>Sign in</button>
</form>

{#if others}
  <div class="divider">or</div>
  <div class="stack">
    {#if passkeys}
      <button type="button" class="secondary" disabled={busy} onclick={onPasskey}>Sign in with a passkey</button>
    {/if}
    {#each settings.identity_providers as provider (provider.id)}
      <button type="button" class="secondary" disabled={busy} onclick={() => onProvider(provider)}>
        Continue with {provider.name}
      </button>
    {/each}
  </div>
{/if}

{#if onCancel}
  <div class="footer">
    <button type="button" class="link" disabled={busy} onclick={onCancel}>Cancel and go back</button>
  </div>
{/if}
