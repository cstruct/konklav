// What the server says about this deployment, from `config.json` next to
// the page.

export interface IdentityProvider {
  id: string;
  name: string;
}

export interface Settings {
  title: string;
  /** Whether passkey sign-in is configured. */
  passkeys: boolean;
  /** Identity providers to offer, in configuration order. */
  identity_providers: IdentityProvider[];
  /**
   * The address identity providers send the browser back to, which must be
   * one of their return URLs exactly.
   */
  return_to: string | null;
}

export const DEFAULTS: Settings = { title: "Sign in", passkeys: false, identity_providers: [], return_to: null };

export async function load(page: URL): Promise<Settings> {
  try {
    const response = await fetch(new URL("config.json", new URL("./", page)), { cache: "no-store" });
    if (!response.ok) return DEFAULTS;
    return { ...DEFAULTS, ...((await response.json()) as Partial<Settings>) };
  } catch {
    return DEFAULTS;
  }
}
