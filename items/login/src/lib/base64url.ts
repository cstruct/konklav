/** Unpadded base64url, as JOSE and WebAuthn's JSON forms use it. */
export function encode(bytes: ArrayBuffer | Uint8Array): string {
  let text = "";
  for (const byte of new Uint8Array(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))) {
    text += String.fromCharCode(byte);
  }
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes base64url, padded or not, or plain base64. */
export function decode(text: string): Uint8Array<ArrayBuffer> {
  const plain = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(plain + "=".repeat((4 - (plain.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
