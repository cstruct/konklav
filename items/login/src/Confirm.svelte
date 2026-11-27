<script lang="ts">
  // Asks before a native app on this computer, such as the operator CLI,
  // gets a session of its own (`r[session.native-handoff.confirm]`).

  interface Props {
    title: string;
    app: string;
    busy: boolean;
    onAllow: () => void;
    onCancel: () => void;
  }

  let { title, app, busy, onAllow, onCancel }: Props = $props();
</script>

<h1>{title}</h1>
<p>Sign in to <strong>{app}</strong> on this computer?</p>
<p class="muted">
  It gets a session of its own that can do anything you can, until it signs out or the session ends.
  Signing out here doesn't end it. Only continue if you just started this sign-in yourself.
</p>
<div class="stack">
  <button type="button" disabled={busy} onclick={onAllow}>Sign in to {app}</button>
  <button type="button" class="secondary" disabled={busy} onclick={onCancel}>Cancel</button>
</div>
