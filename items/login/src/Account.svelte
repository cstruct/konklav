<script lang="ts">
  import { claimsOf } from "./lib/api";

  interface Props {
    title: string;
    token: string;
    busy: boolean;
    onSignOut: () => void;
  }

  let { title, token, busy, onSignOut }: Props = $props();

  const claims = $derived(claimsOf(token));
</script>

<h1>{title}</h1>
<p>You're signed in.</p>
<p class="muted">Subject <code>{claims.sub ?? "unknown"}</code></p>
<p class="muted">
  Applications that sign in through this page use this sign-in until you sign out. Signing out ends it
  for all of them.
</p>
<button type="button" class="secondary" disabled={busy} onclick={onSignOut}>Sign out</button>
