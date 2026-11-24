<script lang="ts">
  import { onMount } from "svelte";

  import { KonklavError, type Konklav, type Tokens } from "./lib/api";

  interface Factor {
    id: string;
    kind: "totp" | "email_code" | string;
  }

  interface Props {
    title: string;
    konklav: Konklav;
    onDone: (tokens: Tokens) => void;
    onCancel: () => void;
  }

  let { title, konklav, onDone, onCancel }: Props = $props();

  let factors: Factor[] = $state([]);
  let chosen: string = $state("");
  let code = $state("");
  let busy = $state(false);
  let sent = $state(false);
  let error: string | null = $state(null);
  let more = $state(false);

  const factor = $derived(factors.find((f) => f.id === chosen));
  const label = (f: Factor) =>
    f.kind === "totp" ? "Authenticator app" : f.kind === "email_code" ? "Code by email" : f.kind;

  async function list() {
    // A partial session sees only its active factors.
    factors = await konklav.call<Factor[]>("GET", "/mfa");
    chosen = factors[0]?.id ?? "";
    sent = false;
    if (factors.length === 0) error = "This account needs a second factor, but has none set up.";
  }

  async function send() {
    if (!factor) return;
    busy = true;
    error = null;
    try {
      await konklav.call("POST", `/mfa/${encodeURIComponent(factor.id)}/send`);
      sent = true;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!factor) return;
    busy = true;
    error = null;
    try {
      const tokens = await konklav.tokens("POST", "/login/mfa", { factor_id: factor.id, code: code.trim() });
      code = "";
      if (tokens.token_kind === "partial") {
        // The credential requires another factor.
        more = true;
        await list();
        return;
      }
      onDone(tokens);
    } catch (e) {
      error =
        e instanceof KonklavError && e.code === "INVALID_CREDENTIALS"
          ? "That code isn't right. Try again."
          : e instanceof Error
            ? e.message
            : String(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    list().catch((e) => (error = e instanceof Error ? e.message : String(e)));
  });
</script>

<h1>{title}</h1>
<p class="muted">{more ? "One more step to confirm it's you." : "Confirm it's you with your second factor."}</p>

{#if error}
  <p class="error" role="alert">{error}</p>
{/if}

{#if factors.length > 0}
  <form onsubmit={submit}>
    {#if factors.length > 1}
      <label>
        Method
        <select bind:value={chosen} onchange={() => (sent = false)}>
          {#each factors as f (f.id)}
            <option value={f.id}>{label(f)}</option>
          {/each}
        </select>
      </label>
    {/if}
    {#if factor?.kind === "email_code" && !sent}
      <button type="button" disabled={busy} onclick={send}>Email me a code</button>
    {:else}
      {#if factor?.kind === "email_code"}
        <p class="muted">We've sent a code to your email address.</p>
      {/if}
      <label>
        Code
        <!-- svelte-ignore a11y_autofocus -->
        <input
          name="code"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          required
          autofocus
          bind:value={code}
        />
      </label>
      <button type="submit" disabled={busy}>Continue</button>
    {/if}
  </form>
{/if}

<div class="footer">
  <button type="button" class="link" disabled={busy} onclick={onCancel}>Start over</button>
</div>
