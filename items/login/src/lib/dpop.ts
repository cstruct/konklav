// DPoP proofs (RFC 9449) signed with a WebCrypto P-256 key the page can use
// but never read: it is created non-extractable. The CryptoKey is kept in
// this origin's IndexedDB, so a reload keeps the key and can still use the
// session bound to it. No token is ever stored, only the key.

import { encode } from "./base64url";

const DATABASE = "konklav-login";
const STORE = "keys";
const KEY = "dpop";

const encoder = new TextEncoder();

interface StoredKey {
  privateKey: CryptoKey;
  jwk: { kty: string; crv: string; x: string; y: string };
}

function done<T>(operation: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error);
  });
}

async function store(mode: IDBTransactionMode): Promise<IDBObjectStore> {
  const opening = indexedDB.open(DATABASE, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore(STORE);
  const db = await done(opening);
  return db.transaction(STORE, mode).objectStore(STORE);
}

// r[impl oidc.provider.login-page.storage]
async function loadOrCreate(): Promise<StoredKey> {
  const stored = (await done((await store("readonly")).get(KEY))) as StoredKey | undefined;
  if (stored) return stored;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // non-extractable: scripts can sign, not export
    ["sign", "verify"],
  );
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const key: StoredKey = { privateKey: pair.privateKey, jwk: { kty: kty!, crv: crv!, x: x!, y: y! } };
  await done((await store("readwrite")).put(key, KEY));
  return key;
}

let pending: Promise<StoredKey | null> | null = null;

/**
 * The page's key, or null where the browser can't keep one (no IndexedDB,
 * as in some private windows): sessions are then unbound, unless Konklav
 * requires DPoP and refuses them.
 */
function key(): Promise<StoredKey | null> {
  pending ??= loadOrCreate().catch(() => null);
  return pending;
}

/** The key's thumbprint (RFC 7638), for `dpop_jkt`. */
export async function thumbprint(): Promise<string | null> {
  const stored = await key();
  if (!stored) return null;
  const { crv, kty, x, y } = stored.jwk;
  const canonical = JSON.stringify({ crv, kty, x, y });
  return encode(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
}

/**
 * A proof for one request to `url` (its query and fragment are dropped),
 * with the access token's hash when one is presented.
 */
export async function proof(method: string, url: string, accessToken: string | null): Promise<string | null> {
  const stored = await key();
  if (!stored) return null;
  const htu = new URL(url, location.href);
  htu.search = "";
  htu.hash = "";
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: htu.href,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken) {
    claims.ath = encode(await crypto.subtle.digest("SHA-256", encoder.encode(accessToken)));
  }
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: stored.jwk };
  const input = `${encode(encoder.encode(JSON.stringify(header)))}.${encode(encoder.encode(JSON.stringify(claims)))}`;
  // WebCrypto's ECDSA signature is already the raw r || s that ES256 uses.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    stored.privateKey,
    encoder.encode(input),
  );
  return `${input}.${encode(signature)}`;
}
