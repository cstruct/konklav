// Passkey sign-in: Konklav's options (webauthn-rs' JSON, binary fields in
// base64url) to `navigator.credentials.get` and the assertion back.

import { decode, encode } from "./base64url";

interface Descriptor {
  type: string;
  id: string;
  transports?: string[];
}

export interface RequestOptionsJson {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Descriptor[];
    userVerification?: UserVerificationRequirement;
    hints?: string[];
    extensions?: Record<string, unknown>;
  };
  mediation?: CredentialMediationRequirement;
}

export function supported(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && !!navigator.credentials;
}

/** The options as WebAuthn wants them, with binary fields decoded. */
export function requestOptions(json: RequestOptionsJson): PublicKeyCredentialRequestOptions {
  const { challenge, allowCredentials, timeout, rpId, userVerification } = json.publicKey;
  return {
    challenge: decode(challenge),
    timeout,
    rpId,
    userVerification,
    allowCredentials: allowCredentials?.map((descriptor) => ({
      type: "public-key",
      id: decode(descriptor.id),
      transports: descriptor.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

/** An assertion in the JSON form Konklav (webauthn-rs) reads. */
export function assertionJson(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encode(response.authenticatorData),
      clientDataJSON: encode(response.clientDataJSON),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults?.() ?? {},
  };
}

/** Asks the browser for a passkey; null when the person cancels. */
export async function getAssertion(json: RequestOptionsJson): Promise<Record<string, unknown> | null> {
  try {
    const credential = (await navigator.credentials.get({
      publicKey: requestOptions(json),
    })) as PublicKeyCredential | null;
    return credential ? assertionJson(credential) : null;
  } catch (error) {
    if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
      return null;
    }
    throw error;
  }
}
