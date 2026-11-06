// DPoP proofs (RFC 9449) signed with a WebCrypto P-256 key that the page can
// use but never read: it is created non-extractable. The CryptoKey object is
// kept in IndexedDB, which is per origin, so a reload keeps the same key and
// can still use tokens bound to it. No token is ever stored, only the key.

const DATABASE = "konklav-example";
const STORE = "keys";
const KEY = "dpop";

const encoder = new TextEncoder();

export function b64url(bytes) {
  let text = "";
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function done(operation) {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error);
  });
}

async function store(mode) {
  const opening = indexedDB.open(DATABASE, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore(STORE);
  const db = await done(opening);
  return db.transaction(STORE, mode).objectStore(STORE);
}

/// A value kept in this origin's IndexedDB next to the key, such as a
/// pending authorization request.
export async function remember(name, value) {
  await done((await store("readwrite")).put(value, name));
}

/// Reads and deletes a remembered value.
export async function recall(name) {
  const value = await done((await store("readonly")).get(name));
  await done((await store("readwrite")).delete(name));
  return value;
}

async function loadOrCreate() {
  const stored = await done((await store("readonly")).get(KEY));
  if (stored) return stored;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // non-extractable: scripts can sign, not export
    ["sign", "verify"],
  );
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const key = { privateKey: pair.privateKey, jwk: { kty, crv, x, y } };
  await done((await store("readwrite")).put(key, KEY));
  return key;
}

let pending = null;
const key = () => (pending ??= loadOrCreate());

/// The key's thumbprint (RFC 7638), for `dpop_jkt`.
export async function thumbprint() {
  const { jwk } = await key();
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
}

/// A proof for one request: `method` and `url` (without query or
/// fragment), with the access token's hash when one is presented.
export async function proof(method, url, accessToken) {
  const { privateKey, jwk } = await key();
  const htu = new URL(url, location.href);
  htu.search = "";
  htu.hash = "";
  const claims = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: htu.href,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken) {
    claims.ath = b64url(await crypto.subtle.digest("SHA-256", encoder.encode(accessToken)));
  }
  const header = { typ: "dpop+jwt", alg: "ES256", jwk };
  const input = `${b64url(encoder.encode(JSON.stringify(header)))}.${b64url(encoder.encode(JSON.stringify(claims)))}`;
  // WebCrypto's ECDSA signature is already the raw r || s that ES256 uses.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoder.encode(input),
  );
  return `${input}.${b64url(signature)}`;
}
