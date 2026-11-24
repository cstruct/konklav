<script lang="ts">
  // Shown when the person signed in isn't a member of the tenant the client
  // asked for, and the server takes access requests.
  import type { AccessRequest } from "./lib/flow";

  interface Props {
    title: string;
    client: string;
    /** The person's latest request for the tenant, if any. */
    access: AccessRequest | null;
    busy: boolean;
    message?: string;
    onAsk: () => void;
    onCheck: () => void;
    onWithdraw: () => void;
    onSwitch: () => void;
    onCancel: () => void;
  }

  let { title, client, access, busy, message, onAsk, onCheck, onWithdraw, onSwitch, onCancel }: Props = $props();
</script>

<h1>{title}</h1>
{#if access?.state === "pending"}
  <p>Your request for access is waiting for an administrator.</p>
  <p class="muted">
    Once it's approved, continue to <strong>{client}</strong> from here, or start signing in to it again.
  </p>
{:else if access?.state === "denied"}
  <p>Your request for access was denied.</p>
{:else if access?.state === "approved"}
  <p>Your request for access was approved.</p>
{:else}
  <p>You're signed in, but you don't have access to what <strong>{client}</strong> asked for.</p>
  <p class="muted">You can ask an administrator for access.</p>
{/if}

{#if message}
  <p class="error" role="alert">{message}</p>
{/if}

<div class="stack">
  {#if access?.state === "pending" || access?.state === "approved"}
    <button type="button" disabled={busy} onclick={onCheck}>Continue</button>
    {#if access.state === "pending"}
      <button type="button" class="secondary" disabled={busy} onclick={onWithdraw}>Withdraw request</button>
    {/if}
  {:else}
    <button type="button" disabled={busy} onclick={onAsk}>Request access</button>
  {/if}
  <button type="button" class="secondary" disabled={busy} onclick={onSwitch}>Use another account</button>
</div>

<div class="footer">
  <button type="button" class="link" disabled={busy} onclick={onCancel}>Cancel and go back</button>
</div>
