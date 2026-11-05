// DPoP proofs (RFC 9449) for the console, with a WebCrypto P-256 key the
// page can use but never read: it is created non-extractable. The key is
// kept in IndexedDB, so a reload can still refresh the bound session.
// r[impl item.console.dpop]

const DATABASE = "konklav-console";
const STORE = "keys";
const KEY = "dpop";

const encoder = new TextEncoder();

function b64url(bytes) {
  let text = "";
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function request(operation) {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error);
  });
}

async function store(mode) {
  const opening = indexedDB.open(DATABASE, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore(STORE);
  const db = await request(opening);
  return db.transaction(STORE, mode).objectStore(STORE);
}

async function loadOrCreate() {
  let stored = null;
  try {
    stored = await request((await store("readonly")).get(KEY));
  } catch (error) {
    console.warn("konklav: IndexedDB unavailable; the DPoP key won't survive a reload", error);
  }
  if (stored) return stored;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const key = { privateKey: pair.privateKey, jwk: { kty, crv, x, y } };
  try {
    await request((await store("readwrite")).put(key, KEY));
  } catch (error) {
    console.warn("konklav: couldn't keep the DPoP key", error);
  }
  return key;
}

let pending = null;

function key() {
  pending ??= loadOrCreate();
  return pending;
}

/// A proof for `method` and `url` (resolved against the page), with the
/// access token's hash when one is presented.
export async function dpopProof(method, url, accessToken) {
  const { privateKey, jwk } = await key();
  const claims = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: new URL(url, location.href).href,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken) {
    claims.ath = b64url(await crypto.subtle.digest("SHA-256", encoder.encode(accessToken)));
  }
  const header = { typ: "dpop+jwt", alg: "ES256", jwk };
  const input = `${b64url(encoder.encode(JSON.stringify(header)))}.${b64url(encoder.encode(JSON.stringify(claims)))}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoder.encode(input),
  );
  return `${input}.${b64url(signature)}`;
}
