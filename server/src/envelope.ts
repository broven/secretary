// End-to-end credential Envelope (ADR-0002): ephemeral ECDH P-256 + HKDF-SHA256
// + AES-256-GCM, AAD bound to the request id. Ported from the Windmill
// request.ts reference; the info/AAD strings are re-versioned for secretary and
// cli/src/secretary.ts carries the matching decrypt side.

import type { CredentialEnvelope } from "./types.ts";
import { UUID } from "./types.ts";

const ENVELOPE_INFO = new TextEncoder().encode("secretary:credential-envelope:v1");

export function credentialEnvelopeAad(requestId: string): Uint8Array {
  const id = requestId.toLowerCase();
  if (!UUID.test(id)) throw new Error("request_id invalid");
  return new TextEncoder().encode(`secretary:credential-envelope:v1\nrequest_id=${id}`);
}

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function fromBase64Url(value: string, maximumBytes: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maximumBytes * 4 / 3) + 4) {
    throw new Error("credential envelope format invalid");
  }
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (bytes.length === 0 || bytes.length > maximumBytes || Buffer.from(bytes).toString("base64url") !== value) {
    throw new Error("credential envelope format invalid");
  }
  return bytes;
}

export function parseClientPublicKeyJwk(value: unknown): JsonWebKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("client_public_key_jwk invalid");
  }
  const jwk = value as JsonWebKey;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" || "d" in jwk) {
    throw new Error("client_public_key_jwk must be a P-256 public key");
  }
  for (const coordinate of [jwk.x, jwk.y]) {
    if (!/^[A-Za-z0-9_-]+$/.test(coordinate)) throw new Error("client_public_key_jwk coordinate invalid");
    const bytes = Buffer.from(coordinate, "base64url");
    if (bytes.length !== 32 || bytes.toString("base64url") !== coordinate) {
      throw new Error("client_public_key_jwk coordinate invalid");
    }
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

export async function encryptCredentialEnvelope(
  credentials: Record<string, string>,
  clientPublicKeyJwk: JsonWebKey,
  requestId: string,
): Promise<CredentialEnvelope> {
  const clientPublicKey = await crypto.subtle.importKey(
    "jwk",
    parseClientPublicKeyJwk(clientPublicKeyJwk),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const serverKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPublicKey },
    serverKeyPair.privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  new Uint8Array(sharedSecret).fill(0);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: ENVELOPE_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));
  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: credentialEnvelopeAad(requestId), tagLength: 128 },
      key,
      plaintext,
    );
  } finally {
    plaintext.fill(0);
  }
  return {
    version: 1,
    algorithm: "P256-HKDF-SHA256+A256GCM",
    server_public_key: await crypto.subtle.exportKey("jwk", serverKeyPair.publicKey),
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

/**
 * Decrypt side of the same format. The CLI ships its own copy; this one exists
 * so the encrypt→decrypt round trip is provable in one test suite.
 */
export async function decryptCredentialEnvelope(
  envelope: CredentialEnvelope,
  privateKey: CryptoKey,
  requestId: string,
): Promise<Record<string, string>> {
  if (!envelope || envelope.version !== 1 || envelope.algorithm !== "P256-HKDF-SHA256+A256GCM" ||
    !envelope.server_public_key || envelope.server_public_key.kty !== "EC" ||
    envelope.server_public_key.crv !== "P-256" || "d" in envelope.server_public_key ||
    typeof envelope.salt !== "string" || typeof envelope.iv !== "string" ||
    typeof envelope.ciphertext !== "string") {
    throw new Error("credential envelope format invalid");
  }
  const serverPublicKey = await crypto.subtle.importKey(
    "jwk",
    envelope.server_public_key,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const salt = fromBase64Url(envelope.salt, 32);
  const iv = fromBase64Url(envelope.iv, 12);
  if (salt.length !== 32 || iv.length !== 12) throw new Error("credential envelope format invalid");
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPublicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  new Uint8Array(sharedSecret).fill(0);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: ENVELOPE_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: credentialEnvelopeAad(requestId), tagLength: 128 },
      key,
      fromBase64Url(envelope.ciphertext, 1024 * 1024),
    );
  } catch {
    throw new Error("cannot decrypt credential envelope");
  }
  const bytes = new Uint8Array(plaintext);
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("credential envelope content invalid");
    }
    return value as Record<string, string>;
  } finally {
    bytes.fill(0);
  }
}
