import { describe, expect, test } from "bun:test";
import {
  credentialEnvelopeAad,
  decryptCredentialEnvelope,
  encryptCredentialEnvelope,
  parseClientPublicKeyJwk,
} from "../src/envelope.ts";

async function clientKeys() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { privateKey: pair.privateKey, publicKeyJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

const REQUEST_ID = "11111111-2222-4333-8444-555555555555";

describe("credential envelope", () => {
  test("server encrypt → client decrypt round trip", async () => {
    const keys = await clientKeys();
    const credentials = { API_TOKEN: "secret-value", OTHER: "x".repeat(1000) };
    const envelope = await encryptCredentialEnvelope(credentials, keys.publicKeyJwk, REQUEST_ID);
    expect(envelope.version).toBe(1);
    expect(envelope.algorithm).toBe("P256-HKDF-SHA256+A256GCM");
    expect(JSON.stringify(envelope)).not.toContain("secret-value");
    expect(await decryptCredentialEnvelope(envelope, keys.privateKey, REQUEST_ID)).toEqual(credentials);
  });

  test("wrong private key cannot decrypt", async () => {
    const right = await clientKeys();
    const wrong = await clientKeys();
    const envelope = await encryptCredentialEnvelope({ A: "b" }, right.publicKeyJwk, REQUEST_ID);
    expect(decryptCredentialEnvelope(envelope, wrong.privateKey, REQUEST_ID))
      .rejects.toThrow("cannot decrypt");
  });

  test("AAD binds the request id — a different id fails", async () => {
    const keys = await clientKeys();
    const envelope = await encryptCredentialEnvelope({ A: "b" }, keys.publicKeyJwk, REQUEST_ID);
    expect(decryptCredentialEnvelope(envelope, keys.privateKey, "99999999-2222-4333-8444-555555555555"))
      .rejects.toThrow("cannot decrypt");
  });

  test("tampered ciphertext fails", async () => {
    const keys = await clientKeys();
    const envelope = await encryptCredentialEnvelope({ A: "b" }, keys.publicKeyJwk, REQUEST_ID);
    const tampered = { ...envelope, ciphertext: envelope.ciphertext.slice(0, -2) + (envelope.ciphertext.endsWith("aa") ? "bb" : "aa") };
    expect(decryptCredentialEnvelope(tampered, keys.privateKey, REQUEST_ID)).rejects.toThrow();
  });

  test("aad requires a UUID request id", () => {
    expect(() => credentialEnvelopeAad("not-a-uuid")).toThrow("request_id");
    expect(new TextDecoder().decode(credentialEnvelopeAad(REQUEST_ID.toUpperCase())))
      .toBe(`secretary:credential-envelope:v1\nrequest_id=${REQUEST_ID}`);
  });

  test("public key validation rejects private keys and bad coordinates", async () => {
    const keys = await clientKeys();
    expect(() => parseClientPublicKeyJwk({ ...keys.publicKeyJwk, d: "AAAA" })).toThrow("P-256 public");
    expect(() => parseClientPublicKeyJwk({ kty: "EC", crv: "P-256", x: "short", y: "short" })).toThrow("coordinate");
    expect(() => parseClientPublicKeyJwk("not-an-object")).toThrow("client_public_key_jwk");
    expect(parseClientPublicKeyJwk(keys.publicKeyJwk)).toMatchObject({ kty: "EC", crv: "P-256" });
  });
});
