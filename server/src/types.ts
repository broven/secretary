// Wire contract between the secretary CLI and the broker, plus shared
// validation constants. cli/src/secretary.ts mirrors these types — change both
// sides together.

import type { SecretField } from "./vault.ts";

export type { SecretField };

/** Grant TTL choices; "once" is the inline-shell-only "this run, no grant" pass. */
export type SecretGrantTtl = "1h" | "8h" | "7d";
export type ApprovalTtl = SecretGrantTtl | "once";

export const SECRET_GRANT_TTLS: readonly SecretGrantTtl[] = ["1h", "8h", "7d"];
const TTL_HOURS: Readonly<Record<SecretGrantTtl, number>> = { "1h": 1, "8h": 8, "7d": 168 };

export function isSecretGrantTtl(value: unknown): value is SecretGrantTtl {
  return typeof value === "string" && (SECRET_GRANT_TTLS as readonly string[]).includes(value);
}

export function secretGrantTtlHours(ttl: SecretGrantTtl): number {
  return TTL_HOURS[ttl];
}

export type WireBinding = { field: SecretField; env: string };
export type WireItemRequest = { name: string; bindings: WireBinding[] };

/** POST /v1/requests body. */
export type RequestBody = {
  /** Client-generated UUID: idempotency key and Envelope AAD binding. */
  request_id: string;
  reason: string;
  repo: string;
  host: string;
  user: string;
  agent?: string;
  /** Full argv — approval display, command fingerprint, inline-shell detection. */
  command_argv: string[];
  items: WireItemRequest[];
  client_public_key_jwk: JsonWebKey;
  /** Optional cross-check; must match the client the bearer token maps to. */
  client_id?: string;
};

export type CredentialEnvelope = {
  version: 1;
  algorithm: "P256-HKDF-SHA256+A256GCM";
  server_public_key: JsonWebKey;
  salt: string;
  iv: string;
  ciphertext: string;
};

/** POST /v1/requests response body (200). Errors are non-2xx `{ "error": string }`. */
export type RequestResult =
  | {
    approved: true;
    ttl: ApprovalTtl;
    expires_at: string;
    lease_id: string;
    grant_reused?: boolean;
    decided_by?: string;
    decided_at?: string;
    credential_envelope: CredentialEnvelope;
  }
  | { approved: false; denied_reason: "denied" | "timeout" };

/** GET /v1/catalog response body. */
export type CatalogResponse = {
  items: Array<{ name: string; description: string; fields: SecretField[] }>;
};

export const MIN_REASON_LENGTH = 10;
export const MAX_REASON_LENGTH = 2000;
export const MAX_ITEMS_PER_REQUEST = 10;
export const MAX_ARGV_ENTRIES = 200;
export const MAX_ARGV_ENTRY_LENGTH = 4096;

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Env names the CLI refuses as aliases and the broker refuses again server-side:
// once env names left the grant scope, the server became the last place that can
// hold this line.
export const RESERVED_ENV = new Set([
  "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "TMPDIR",
  "NODE_OPTIONS", "BUN_OPTIONS", "BITWARDENCLI_APPDATA_DIR",
]);
export const RESERVED_ENV_PREFIXES = [
  "SECRETARY_", "WMILL_", "FNOX_", "SENV_", "BW_", "MISE_", "APPROVED_SECRET_",
];
export const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;

export function isReservedSecretEnv(name: string): boolean {
  return RESERVED_ENV.has(name) || RESERVED_ENV_PREFIXES.some((prefix) => name.startsWith(prefix));
}
