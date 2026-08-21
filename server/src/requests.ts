// Request orchestration: parse → inline-shell detection → vault resolution →
// Grant containment check → fast path or Approval path → Envelope → response.
// Ported from the Windmill request.ts reference minus all Windmill
// orchestration: parking is an in-memory Promise, timeout fails closed.

import type { Approver, ApprovalCard, ApprovalCardItem, SightingCard } from "./approver.ts";
import { encryptCredentialEnvelope, parseClientPublicKeyJwk } from "./envelope.ts";
import {
  commandFingerprint,
  GrantStore,
  secretGrantKey,
  type SecretGrantIdentity,
  type SecretGrantUnit,
} from "./grants.ts";
import type { RequestBody, RequestResult, SecretField, WireBinding, WireItemRequest } from "./types.ts";
import {
  ENV_NAME,
  isReservedSecretEnv,
  isSecretGrantTtl,
  MAX_ARGV_ENTRIES,
  MAX_ARGV_ENTRY_LENGTH,
  MAX_ITEMS_PER_REQUEST,
  MAX_REASON_LENGTH,
  MIN_REASON_LENGTH,
  secretGrantTtlHours,
  UUID,
  type ApprovalTtl,
} from "./types.ts";
import { valueKey, type ResolvedItem, type Vault } from "./vault.ts";

export class RequestError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message);
  }
}

/** Telegram messages have a hard length cap; long commands are truncated with the argv fingerprint appended. */
export const MAX_COMMAND_DISPLAY = 900;

const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh"]);
const INLINE_INTERPRETERS = new Set(["python", "python3", "perl", "ruby", "node", "bun", "deno", "php"]);

/**
 * Inline shell / interpreter code detection.
 *
 * These commands are fully visible in argv, so they are not forbidden —
 * forbidding them would just push agents into opaque temp scripts. The price:
 * every run needs human approval and never writes a Grant. Detection is
 * best-effort (the threat model is mistakes, not malice): `env A=1 sh -c ...`
 * is unwrapped and still detected, deliberate evasion is out of scope.
 */
export function isInlineShellCommand(argv: string[]): boolean {
  if (!Array.isArray(argv) || argv.length === 0) return false;
  let parts = argv;
  // `env` is the most common transparent wrapper: strip it plus VAR=VAL prefixes.
  while (parts.length > 1 && (parts[0].split("/").pop() || "") === "env") {
    let index = 1;
    while (index < parts.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[index])) index++;
    if (index >= parts.length) return false;
    parts = parts.slice(index);
  }
  const binary = (parts[0].split("/").pop() || "").toLowerCase();
  const flags = parts.slice(1);
  if (SHELL_BINARIES.has(binary)) return flags.some((flag) => /^-[a-zA-Z]*c$/.test(flag));
  if (INLINE_INTERPRETERS.has(binary)) {
    return flags.some((flag) => flag === "-c" || flag === "-e" || flag === "-E" || flag === "--eval");
  }
  return false;
}

/** Full command on the approval card; over-long commands keep a verifiable fingerprint. */
export function formatCommandDisplay(argv: string[]): string {
  const rendered = argv
    .map((part) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(part) ? part : JSON.stringify(part)))
    .join(" ");
  if (rendered.length <= MAX_COMMAND_DISPLAY) return rendered;
  return `${rendered.slice(0, MAX_COMMAND_DISPLAY)}…（已截断；完整 argv sha256=${commandFingerprint(argv)}）`;
}

export function assertReason(value: unknown): string {
  const reason = String(value ?? "").trim().replace(/\s+/g, " ");
  if (reason.length < MIN_REASON_LENGTH) {
    throw new RequestError(`reason must be at least ${MIN_REASON_LENGTH} characters`);
  }
  if (reason.length > MAX_REASON_LENGTH) throw new RequestError("reason too long");
  return reason;
}

function assertShortText(value: unknown, field: string, max: number, required: boolean): string {
  const text = String(value ?? "").trim();
  if (required && !text) throw new RequestError(`${field} required`);
  if (text.length > max || /[\u0000-\u001f\u007f]/.test(text)) throw new RequestError(`${field} invalid`);
  return text;
}

export function parseCommandArgv(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ARGV_ENTRIES) {
    throw new RequestError("command_argv invalid");
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_ARGV_ENTRY_LENGTH) {
      throw new RequestError("command_argv entry invalid");
    }
    return entry;
  });
}

export function parseItems(value: unknown): WireItemRequest[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ITEMS_PER_REQUEST) {
    throw new RequestError(`items must contain 1–${MAX_ITEMS_PER_REQUEST} entries`);
  }
  const seenNames = new Set<string>();
  const seenEnvs = new Set<string>();
  return value.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new RequestError("item invalid");
    const item = raw as Record<string, unknown>;
    const name = assertShortText(item.name, "item name", 200, true);
    if (seenNames.has(name)) throw new RequestError(`duplicate item: ${name}`);
    seenNames.add(name);
    if (!Array.isArray(item.bindings) || item.bindings.length === 0 || item.bindings.length > 2) {
      throw new RequestError("item bindings invalid");
    }
    const seenFields = new Set<string>();
    const bindings: WireBinding[] = item.bindings.map((rawBinding) => {
      if (!rawBinding || typeof rawBinding !== "object") throw new RequestError("binding invalid");
      const binding = rawBinding as Record<string, unknown>;
      if (binding.field !== "username" && binding.field !== "password") {
        throw new RequestError("binding field invalid");
      }
      if (typeof binding.env !== "string" || binding.env.length > 128 || !ENV_NAME.test(binding.env)) {
        throw new RequestError("binding env invalid");
      }
      // The client already refuses reserved names; the server is the last line
      // that can hold this rule against callers bypassing the client.
      if (isReservedSecretEnv(binding.env)) throw new RequestError(`env name is reserved: ${binding.env}`);
      if (seenFields.has(binding.field)) throw new RequestError(`duplicate field in item ${name}`);
      seenFields.add(binding.field);
      if (seenEnvs.has(binding.env)) throw new RequestError(`duplicate env: ${binding.env}`);
      seenEnvs.add(binding.env);
      return { field: binding.field as SecretField, env: binding.env };
    });
    bindings.sort((a, b) => a.env.localeCompare(b.env));
    return { name, bindings };
  });
}

export type ParsedRequest = {
  request_id: string;
  reason: string;
  repo: string;
  host: string;
  user: string;
  agent: string;
  command_argv: string[];
  items: WireItemRequest[];
  client_public_key_jwk: JsonWebKey;
  client_id?: string;
};

export function parseRequestBody(value: unknown): ParsedRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RequestError("request body invalid");
  const body = value as Partial<RequestBody> & Record<string, unknown>;
  const requestId = String(body.request_id ?? "").toLowerCase();
  if (!UUID.test(requestId)) throw new RequestError("request_id must be a UUID");
  return {
    request_id: requestId,
    reason: assertReason(body.reason),
    repo: assertShortText(body.repo, "repo", 200, true),
    host: assertShortText(body.host, "host", 200, false),
    user: assertShortText(body.user, "user", 200, false),
    agent: assertShortText(body.agent, "agent", 200, false),
    command_argv: parseCommandArgv(body.command_argv),
    items: parseItems(body.items),
    client_public_key_jwk: parseClientPublicKeyJwk(body.client_public_key_jwk),
    client_id: body.client_id === undefined ? undefined : assertShortText(body.client_id, "client_id", 128, true),
  };
}

export const ONCE_LEASE_MS = 5 * 60 * 1000;

export function leaseExpiresAt(ttl: ApprovalTtl, now: number): string {
  const ms = ttl === "once" ? ONCE_LEASE_MS : secretGrantTtlHours(ttl) * 60 * 60 * 1000;
  return new Date(now + ms).toISOString();
}

export type AuthedClient = { client_id: string; name: string };

export type BrokerDeps = {
  vault: Vault;
  grants: GrantStore;
  approver: Approver;
  approvalTimeoutMs: number;
  now?: () => number;
  log?: (message: string) => void;
};

/** How long a settled request_id keeps answering duplicate deliveries. */
const COMPLETED_RESULT_TTL_MS = 10 * 60 * 1000;

export class RequestBroker {
  private readonly now: () => number;
  private readonly log: (message: string) => void;
  /** request_id (scoped by client) → in-flight or recently settled result. */
  private readonly inflight = new Map<string, { promise: Promise<RequestResult>; expiresAt: number | null }>();

  constructor(private readonly deps: BrokerDeps) {
    this.now = deps.now ?? Date.now;
    this.log = deps.log ?? ((message) => console.log(message));
  }

  /** Idempotent entry point: duplicate deliveries of one request_id share one execution. */
  handle(body: unknown, client: AuthedClient): Promise<RequestResult> {
    const parsed = parseRequestBody(body);
    if (parsed.client_id !== undefined && parsed.client_id !== client.client_id) {
      throw new RequestError("client_id does not match the presented token", 403);
    }
    const key = `${client.client_id}\0${parsed.request_id}`;
    const existing = this.inflight.get(key);
    if (existing && (existing.expiresAt === null || existing.expiresAt > this.now())) {
      return existing.promise;
    }
    const entry: { promise: Promise<RequestResult>; expiresAt: number | null } = {
      promise: this.execute(parsed, client).finally(() => {
        entry.expiresAt = this.now() + COMPLETED_RESULT_TTL_MS;
        this.sweepInflight();
      }),
      expiresAt: null,
    };
    this.inflight.set(key, entry);
    return entry.promise;
  }

  private sweepInflight(): void {
    const now = this.now();
    for (const [key, entry] of this.inflight) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) this.inflight.delete(key);
    }
  }

  private async execute(request: ParsedRequest, client: AuthedClient): Promise<RequestResult> {
    const inlineShell = isInlineShellCommand(request.command_argv);
    const commandDisplay = formatCommandDisplay(request.command_argv);
    const commandHash = commandFingerprint(request.command_argv);

    let resolved: ResolvedItem[];
    try {
      resolved = await this.deps.vault.resolveByName(request.items.map((item) => item.name));
    } catch (error) {
      // Name-resolution failures are caller-visible: the message names items,
      // never values.
      throw error instanceof RequestError
        ? error
        : new RequestError(error instanceof Error ? error.message : String(error));
    }
    const resolvedByName = new Map(resolved.map((item) => [item.name, item]));
    for (const item of request.items) {
      const entry = resolvedByName.get(item.name)!;
      for (const binding of item.bindings) {
        if (!entry.fields.includes(binding.field)) {
          throw new RequestError(`item "${item.name}" has no ${binding.field} field`);
        }
      }
    }

    const identity: SecretGrantIdentity = {
      caller_id: client.name,
      client_id: client.client_id,
      repo: request.repo,
    };
    const units: SecretGrantUnit[] = request.items.flatMap((item) =>
      item.bindings.map((binding) => ({
        item_id: resolvedByName.get(item.name)!.item_id,
        field: binding.field,
      }))
    );
    const grantKeys = units.map((unit) => secretGrantKey(identity, unit));
    const itemIds = [...new Set(units.map((unit) => unit.item_id))];
    const cardItems: ApprovalCardItem[] = request.items.map((item) => ({
      name: item.name,
      description: resolvedByName.get(item.name)!.description || undefined,
      bindings: item.bindings,
    }));

    // Inline shell never consumes and never writes grants: always human-approved.
    if (!inlineShell) {
      const active = this.deps.grants.findActive(grantKeys);
      if (grantKeys.every((key) => active.has(key))) {
        const grants = grantKeys.map((key) => active.get(key)!);
        // The reuse window ends when the earliest unit expires — after that the set no longer hits.
        const expiresAt = grants.map((grant) => grant.expires_at).sort()[0];
        const ttl = grants.map((grant) => grant.ttl)
          .sort((a, b) => secretGrantTtlHours(a) - secretGrantTtlHours(b))[0];
        const sighting = this.deps.grants.recordSighting(identity, commandHash, itemIds);
        if (!sighting.seen_before) {
          const card: SightingCard = {
            id: request.request_id,
            reason: request.reason,
            command: commandDisplay,
            items: cardItems,
            repo: request.repo,
            host: request.host,
            user: request.user,
            agent: request.agent || undefined,
            client_name: client.name,
            expires_at: expiresAt,
            grant_keys: grantKeys,
          };
          // Fire and forget: a Sighting informs, it never gates delivery.
          void this.deps.approver.notifySighting(card).catch((error) => {
            this.log(`sighting notification failed: ${error instanceof Error ? error.message : String(error)}`);
          });
        }
        const envelope = await this.encryptForRequest(request, units);
        this.log(`request ${request.request_id}: fast path (${client.name} @ ${request.repo})`);
        return {
          approved: true,
          ttl,
          expires_at: expiresAt,
          lease_id: grants[0].approval_id,
          grant_reused: true,
          decided_by: grants[0].decided_by,
          decided_at: grants[0].decided_at,
          credential_envelope: envelope,
        };
      }
    }

    // Approval path: park in memory until decision or timeout (fail closed).
    const timeoutMs = this.deps.approvalTimeoutMs;
    const card: ApprovalCard = {
      id: request.request_id,
      reason: request.reason,
      command: commandDisplay,
      inline_shell: inlineShell,
      items: cardItems,
      repo: request.repo,
      host: request.host,
      user: request.user,
      agent: request.agent || undefined,
      client_name: client.name,
      expires_at: new Date(this.now() + timeoutMs).toISOString(),
    };
    this.log(`request ${request.request_id}: awaiting approval (${client.name} @ ${request.repo}${inlineShell ? ", inline shell" : ""})`);
    const decision = await this.deps.approver.requestApproval(card, timeoutMs);
    if (!decision.approved) {
      this.log(`request ${request.request_id}: ${decision.reason}`);
      return { approved: false, denied_reason: decision.reason };
    }

    const ttl: ApprovalTtl = inlineShell ? "once" : (isSecretGrantTtl(decision.ttl) ? decision.ttl : "1h");
    let expiresAt = leaseExpiresAt(ttl, this.now());
    if (ttl !== "once") {
      const saved = this.deps.grants.save(
        identity,
        units,
        ttl,
        request.request_id,
        decision.decided_by,
        decision.decided_at,
      );
      expiresAt = saved.map((grant) => grant.expires_at).sort()[0];
      // The command just reviewed on the card must be remembered, or the next
      // fast-path hit would immediately re-notify.
      this.deps.grants.recordSighting(identity, commandHash, itemIds);
    }
    const envelope = await this.encryptForRequest(request, units);
    this.log(`request ${request.request_id}: approved ttl=${ttl} by ${decision.decided_by ?? "?"}`);
    return {
      approved: true,
      ttl,
      expires_at: expiresAt,
      lease_id: request.request_id,
      decided_by: decision.decided_by,
      decided_at: decision.decided_at,
      credential_envelope: envelope,
    };
  }

  private async encryptForRequest(request: ParsedRequest, units: SecretGrantUnit[]) {
    const values = await this.deps.vault.readValues(units);
    const credentials: Record<string, string> = {};
    // units was built by iterating items/bindings in this exact order.
    let unitIndex = 0;
    for (const item of request.items) {
      for (const binding of item.bindings) {
        const { item_id } = units[unitIndex++];
        const value = values.get(valueKey(item_id, binding.field));
        if (value === undefined) throw new Error("vault did not return a requested credential");
        credentials[binding.env] = value;
      }
    }
    return encryptCredentialEnvelope(credentials, request.client_public_key_jwk, request.request_id);
  }
}

export type { ResolvedItem };
