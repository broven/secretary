// Integration: the real broker stack (http.ts + requests.ts + grants.ts +
// clients.ts + envelope.ts + TelegramApprover) with only the mandated fakes —
// a fake Telegram Bot API server and an injected fake vault layer.

import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ClientRegistry } from "../src/clients.ts";
import { decryptCredentialEnvelope } from "../src/envelope.ts";
import { GrantStore } from "../src/grants.ts";
import { startHttpServer } from "../src/http.ts";
import { RequestBroker } from "../src/requests.ts";
import { TelegramApprover } from "../src/approver_telegram.ts";
import { createAutoApprover } from "../src/approver_auto.ts";
import type { ResolvedItem, SecretField, Vault } from "../src/vault.ts";
import { resolveNamesAgainstCatalog, valueKey } from "../src/vault.ts";
import { startFakeTelegram, type FakeTelegram } from "./helpers/fake_telegram.ts";

const OWNER = 42;

class FakeVault implements Vault {
  syncCount = 0;
  constructor(
    private readonly items: Array<ResolvedItem & { values: Partial<Record<SecretField, string>> }>,
  ) {}
  async catalog(query = "") {
    const normalized = query.trim().toLowerCase();
    return this.items
      .filter((item) => !normalized || item.name.toLowerCase().includes(normalized))
      .map(({ name, description, fields }) => ({ name, description, fields }));
  }
  async resolveByName(names: string[]) {
    return resolveNamesAgainstCatalog(names, this.items);
  }
  async readValues(units: Array<{ item_id: string; field: SecretField }>) {
    this.syncCount++;
    const map = new Map<string, string>();
    for (const unit of units) {
      const item = this.items.find((candidate) => candidate.item_id === unit.item_id);
      const value = item?.values[unit.field];
      if (value === undefined) throw new Error("fake vault: missing value");
      map.set(valueKey(unit.item_id, unit.field), value);
    }
    return map;
  }
}

type Stack = {
  url: string;
  token: string;
  telegram: FakeTelegram;
  approver: TelegramApprover;
  grants: GrantStore;
  vault: FakeVault;
  stop(): void;
};

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

async function startStack(options: { approvalTimeoutMs?: number } = {}): Promise<Stack> {
  const db = new Database(":memory:");
  const grants = new GrantStore(db);
  const clients = new ClientRegistry(db);
  const { token } = clients.add("test-agent");
  const vault = new FakeVault([
    {
      item_id: "11111111-aaaa-bbbb-cccc-000000000001",
      revision: "2030-01-01T00:00:00.000Z",
      name: "Example API",
      description: "test item",
      fields: ["username", "password", "api_key"],
      values: { username: "svc-user", password: "example-secret-value", api_key: "custom-field-value" },
    },
    {
      item_id: "11111111-aaaa-bbbb-cccc-000000000002",
      revision: "2030-01-01T00:00:00.000Z",
      name: "Other API",
      description: "",
      fields: ["password"],
      values: { password: "other-secret-value" },
    },
  ]);
  const telegram = await startFakeTelegram();
  const approver = new TelegramApprover(
    { botToken: "test-bot-token", chatId: "100", allowedUserIds: [OWNER], apiBase: telegram.url },
    { onRevoke: (sightingId) => grants.revokeByHandle(sightingId) },
    { log: () => {} },
  );
  approver.start();
  const broker = new RequestBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: options.approvalTimeoutMs ?? 5_000,
    log: () => {},
  });
  const server = startHttpServer({
    clients,
    broker,
    vault,
    hostname: "127.0.0.1",
    port: 0,
    log: () => {},
  });
  const stack: Stack = {
    url: `http://127.0.0.1:${server.port}`,
    token,
    telegram,
    approver,
    grants,
    vault,
    stop() {
      approver.stop();
      telegram.stop();
      server.stop(true);
    },
  };
  cleanups.push(() => stack.stop());
  return stack;
}

async function clientKeys() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { privateKey: pair.privateKey, publicKeyJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

function requestBody(overrides: Record<string, unknown>, publicKeyJwk: JsonWebKey) {
  return {
    request_id: crypto.randomUUID(),
    reason: "integration test exercising the approval path",
    repo: "github.com/example/repo",
    host: "test-host",
    user: "test-user",
    agent: "code-agent",
    command_argv: ["deploy-tool", "--push"],
    items: [{ name: "Example API", bindings: [{ field: "password", env: "EXAMPLE_TOKEN" }] }],
    ...overrides,
    client_public_key_jwk: publicKeyJwk,
  };
}

async function postRequest(stack: Stack, body: unknown) {
  const response = await fetch(`${stack.url}/v1/requests`, {
    method: "POST",
    headers: { Authorization: `Bearer ${stack.token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: JSON.parse(text.trim()) };
}

/** Wait until the fake telegram has recorded `count` sent messages. */
async function waitForMessages(telegram: FakeTelegram, count: number, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (telegram.sentMessages.length < count) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${count} telegram messages`);
    await Bun.sleep(20);
  }
}

function firstCallback(telegram: FakeTelegram, index: number, prefix: string): string {
  const markup = telegram.sentMessages[index].reply_markup as {
    inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
  };
  const buttons = markup.inline_keyboard.flat();
  const match = buttons.find((button) => button.callback_data.includes(prefix));
  if (!match) throw new Error(`no button matching ${prefix} in ${JSON.stringify(buttons)}`);
  return match.callback_data;
}

describe("broker integration (fake telegram + fake vault)", () => {
  test("approve → grant written → second request takes the fast path", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({}, keys.publicKeyJwk);

    const pending = postRequest(stack, body);
    await waitForMessages(stack.telegram, 1);
    expect(stack.telegram.sentMessages[0].text).toContain("Example API");
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_8h"), OWNER);

    const { status, body: result } = await pending;
    expect(status).toBe(200);
    expect(result.approved).toBe(true);
    expect(result.ttl).toBe("8h");
    expect(result.grant_reused).toBeUndefined();
    const credentials = await decryptCredentialEnvelope(
      result.credential_envelope,
      keys.privateKey,
      body.request_id as string,
    );
    expect(credentials).toEqual({ EXAMPLE_TOKEN: "example-secret-value" });

    // Second request, same identity/item/field, different command: fast path,
    // no new approval card; the unseen command fires exactly one sighting.
    const keys2 = await clientKeys();
    const body2 = requestBody({ command_argv: ["other-tool", "run"] }, keys2.publicKeyJwk);
    const started = Date.now();
    const second = await postRequest(stack, body2);
    const fastPathMs = Date.now() - started;
    expect(second.status).toBe(200);
    expect(second.body.approved).toBe(true);
    expect(second.body.grant_reused).toBe(true);
    const credentials2 = await decryptCredentialEnvelope(
      second.body.credential_envelope,
      keys2.privateKey,
      body2.request_id as string,
    );
    expect(credentials2).toEqual({ EXAMPLE_TOKEN: "example-secret-value" });
    expect(fastPathMs).toBeLessThan(1000);

    await waitForMessages(stack.telegram, 2);
    const sighting = stack.telegram.sentMessages[1];
    expect(sighting.text).toContain("免审");
    const revokeData = firstCallback(stack.telegram, 1, "rv:");

    // Revoke via the sighting button, then the next request must re-approve.
    const answeredBefore = stack.telegram.answeredCallbacks.length;
    stack.telegram.pressButton(revokeData, OWNER);
    const revokeDeadline = Date.now() + 3_000;
    while (stack.telegram.answeredCallbacks.length <= answeredBefore) {
      if (Date.now() > revokeDeadline) throw new Error("revoke callback was never processed");
      await Bun.sleep(20);
    }
    const body3 = requestBody({ command_argv: ["third-tool"] }, (await clientKeys()).publicKeyJwk);
    const third = postRequest(stack, body3);
    await waitForMessages(stack.telegram, 3);
    stack.telegram.pressButton(firstCallback(stack.telegram, 2, ":deny"), OWNER);
    expect((await third).body).toEqual({ approved: false, denied_reason: "denied" });
  }, 20_000);

  test("the sighting revoke button survives a broker restart (P1-c)", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    // Approve once, then hit the fast path with a new command to emit a sighting.
    const first = postRequest(stack, requestBody({}, keys.publicKeyJwk));
    await waitForMessages(stack.telegram, 1);
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_7d"), OWNER);
    expect((await first).body.approved).toBe(true);
    const reused = await postRequest(stack, requestBody(
      { command_argv: ["another-tool"] },
      (await clientKeys()).publicKeyJwk,
    ));
    expect(reused.body.grant_reused).toBe(true);
    await waitForMessages(stack.telegram, 2);
    const revokeData = firstCallback(stack.telegram, 1, "rv:");

    // "Restart" the broker: a fresh approver with EMPTY memory over the same
    // SQLite — the revoke handle must resolve durably.
    stack.approver.stop();
    const approver2 = new TelegramApprover(
      { botToken: "test-bot-token", chatId: "100", allowedUserIds: [OWNER], apiBase: stack.telegram.url },
      { onRevoke: (sightingId) => stack.grants.revokeByHandle(sightingId) },
      { log: () => {} },
    );
    approver2.start();
    cleanups.push(() => approver2.stop());
    const answeredBefore = stack.telegram.answeredCallbacks.length;
    stack.telegram.pressButton(revokeData, OWNER);
    const deadline = Date.now() + 3_000;
    while (stack.telegram.answeredCallbacks.length <= answeredBefore) {
      if (Date.now() > deadline) throw new Error("revoke callback was never processed");
      await Bun.sleep(20);
    }
    expect(stack.telegram.answeredCallbacks.at(-1)!.text).toContain("已吊销");
    expect(stack.telegram.answeredCallbacks.at(-1)!.text).not.toContain("0 行");
  }, 20_000);

  test("reject → fail closed, no grant written", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({}, keys.publicKeyJwk);
    const pending = postRequest(stack, body);
    await waitForMessages(stack.telegram, 1);
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":deny"), OWNER);
    const { status, body: result } = await pending;
    expect(status).toBe(200);
    expect(result).toEqual({ approved: false, denied_reason: "denied" });

    // A follow-up request must go to approval again (no grant was written).
    const body2 = requestBody({}, (await clientKeys()).publicKeyJwk);
    const pending2 = postRequest(stack, body2);
    await waitForMessages(stack.telegram, 2);
    stack.telegram.pressButton(firstCallback(stack.telegram, 1, ":deny"), OWNER);
    expect((await pending2).body.approved).toBe(false);
  }, 15_000);

  test("timeout → fail closed", async () => {
    const stack = await startStack({ approvalTimeoutMs: 400 });
    const keys = await clientKeys();
    const { status, body: result } = await postRequest(stack, requestBody({}, keys.publicKeyJwk));
    expect(status).toBe(200);
    expect(result).toEqual({ approved: false, denied_reason: "timeout" });
  }, 15_000);

  test("inline shell always approves, never writes a grant", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({ command_argv: ["sh", "-c", "echo $EXAMPLE_TOKEN | tool"] }, keys.publicKeyJwk);
    const pending = postRequest(stack, body);
    await waitForMessages(stack.telegram, 1);
    // Inline shell card offers only once + deny.
    const markup = stack.telegram.sentMessages[0].reply_markup as {
      inline_keyboard: Array<Array<{ callback_data: string }>>;
    };
    const keysOffered = markup.inline_keyboard.flat().map((button) => button.callback_data.split(":").pop());
    expect(keysOffered).toContain("approve_once");
    expect(keysOffered).not.toContain("approve_8h");
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_once"), OWNER);
    const { body: result } = await pending;
    expect(result.approved).toBe(true);
    expect(result.ttl).toBe("once");

    // Same command again: still needs approval (no grant was written).
    const body2 = requestBody({
      command_argv: ["sh", "-c", "echo $EXAMPLE_TOKEN | tool"],
    }, (await clientKeys()).publicKeyJwk);
    const pending2 = postRequest(stack, body2);
    await waitForMessages(stack.telegram, 2);
    stack.telegram.pressButton(firstCallback(stack.telegram, 1, ":deny"), OWNER);
    expect((await pending2).body.approved).toBe(false);
  }, 15_000);

  test("auth and validation: bad token 401, unknown item 400-ish error, reserved env rejected", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const unauthorized = await fetch(`${stack.url}/v1/requests`, {
      method: "POST",
      headers: { Authorization: "Bearer wrong-token-wrong-token", "Content-Type": "application/json" },
      body: JSON.stringify(requestBody({}, keys.publicKeyJwk)),
    });
    expect(unauthorized.status).toBe(401);

    const unknownItem = await postRequest(stack, requestBody({
      items: [{ name: "No Such Item", bindings: [{ field: "password", env: "X_TOKEN" }] }],
    }, keys.publicKeyJwk));
    expect(unknownItem.body.error).toContain("No Such Item");
    expect(unknownItem.body.approved).toBeUndefined();

    const reserved = await postRequest(stack, requestBody({
      items: [{ name: "Example API", bindings: [{ field: "password", env: "BW_SESSION" }] }],
    }, keys.publicKeyJwk));
    expect(reserved.status).toBe(400);
    expect(reserved.body.error).toContain("reserved");

    const catalog = await fetch(`${stack.url}/v1/catalog?query=example`, {
      headers: { Authorization: `Bearer ${stack.token}` },
    });
    expect(catalog.status).toBe(200);
    const catalogBody = await catalog.json() as { items: Array<{ name: string }> };
    expect(catalogBody.items.map((item) => item.name)).toEqual(["Example API"]);
    expect(JSON.stringify(catalogBody)).not.toContain("example-secret-value");

    const health = await fetch(`${stack.url}/healthz`);
    expect(health.status).toBe(200);
  }, 15_000);

  test("a client disconnect mid-long-poll never crashes the broker", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({}, keys.publicKeyJwk);

    // Start a request, then drop the connection while it is parked.
    const abort = new AbortController();
    const doomed = fetch(`${stack.url}/v1/requests`, {
      method: "POST",
      headers: { Authorization: `Bearer ${stack.token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: abort.signal,
    }).catch(() => null);
    await waitForMessages(stack.telegram, 1);
    abort.abort();
    await doomed;
    await Bun.sleep(50);

    // The Owner answers AFTER the client is gone: the decision must still be
    // processed (grant written per documented semantics) and, critically, the
    // resolve path must not blow up the process on the dead stream.
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_8h"), OWNER);
    await Bun.sleep(200);

    // Broker still alive and serving…
    const health = await fetch(`${stack.url}/healthz`);
    expect(health.status).toBe(200);
    // …and the late decision wrote the grant: a fresh request takes the fast path.
    const keys2 = await clientKeys();
    const body2 = requestBody({ command_argv: ["post-disconnect-tool"] }, keys2.publicKeyJwk);
    const second = await postRequest(stack, body2);
    expect(second.status).toBe(200);
    expect(second.body.approved).toBe(true);
    expect(second.body.grant_reused).toBe(true);
    const credentials = await decryptCredentialEnvelope(
      second.body.credential_envelope,
      keys2.privateKey,
      body2.request_id as string,
    );
    expect(credentials).toEqual({ EXAMPLE_TOKEN: "example-secret-value" });
  }, 15_000);

  test("chunked bodies past 256 KiB are rejected while streaming (P2-i)", async () => {
    const stack = await startStack();
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    // A streamed body with no content-length: the server must cut it off at
    // the cap instead of buffering it fully.
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index < 6; index++) controller.enqueue(chunk);
        controller.close();
      },
    });
    const response = await fetch(`${stack.url}/v1/requests`, {
      method: "POST",
      headers: { Authorization: `Bearer ${stack.token}`, "Content-Type": "application/json" },
      body,
    });
    expect(response.status).toBe(413);
    expect(((await response.json()) as { error: string }).error).toContain("too large");
  }, 15_000);

  test("duplicate request_id shares one execution (idempotent delivery)", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({}, keys.publicKeyJwk);
    const first = postRequest(stack, body);
    const second = postRequest(stack, body);
    await waitForMessages(stack.telegram, 1);
    // Only ONE approval card despite two deliveries.
    await Bun.sleep(100);
    expect(stack.telegram.sentMessages.length).toBe(1);
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_1h"), OWNER);
    const [a, b] = await Promise.all([first, second]);
    expect(a.body.approved).toBe(true);
    expect(b.body.approved).toBe(true);
  }, 15_000);

  test("custom fields flow end to end (P2-1)", async () => {
    const stack = await startStack();
    const keys = await clientKeys();
    const body = requestBody({
      items: [{
        name: "Example API",
        bindings: [
          { field: "password", env: "EXAMPLE_TOKEN" },
          { field: "api_key", env: "EXAMPLE_API_KEY" },
        ],
      }],
    }, keys.publicKeyJwk);
    const pending = postRequest(stack, body);
    await waitForMessages(stack.telegram, 1);
    stack.telegram.pressButton(firstCallback(stack.telegram, 0, ":approve_1h"), OWNER);
    const { body: result } = await pending;
    expect(result.approved).toBe(true);
    const credentials = await decryptCredentialEnvelope(
      result.credential_envelope,
      keys.privateKey,
      body.request_id as string,
    );
    expect(credentials).toEqual({
      EXAMPLE_TOKEN: "example-secret-value",
      EXAMPLE_API_KEY: "custom-field-value",
    });
    // A field the item does not offer is rejected before approval.
    const bad = await postRequest(stack, requestBody({
      items: [{ name: "Other API", bindings: [{ field: "nope", env: "X_TOKEN" }] }],
    }, (await clientKeys()).publicKeyJwk));
    expect(bad.body.error).toContain("nope");
  }, 15_000);

  test("credential payloads past the client decrypt cap fail closed server-side (P2-8)", async () => {
    const db = new Database(":memory:");
    const grants = new GrantStore(db);
    const clients = new ClientRegistry(db);
    const { token } = clients.add("big-agent");
    // 10 items × 2 fields × 65,536-byte values ≈ 1.31 MB serialized — past the cap.
    const bigItems = Array.from({ length: 10 }, (_, index) => ({
      item_id: `11111111-aaaa-bbbb-cccc-9000000000${String(index).padStart(2, "0")}`,
      revision: "r",
      name: `Big ${index}`,
      description: "",
      fields: ["username", "password"],
      values: { username: "u".repeat(65_536), password: "p".repeat(65_536) },
    }));
    const vault = new FakeVault(bigItems);
    const approver = createAutoApprover({ env: { SECRETARY_DEV_AUTO_APPROVE: "1" }, log: () => {} });
    const broker = new RequestBroker({ vault, grants, approver, approvalTimeoutMs: 2_000, log: () => {} });
    const keys = await clientKeys();
    const body = requestBody({
      items: bigItems.map((item, index) => ({
        name: item.name,
        bindings: [
          { field: "username", env: `BIG_USER_${index}` },
          { field: "password", env: `BIG_PASS_${index}` },
        ],
      })),
    }, keys.publicKeyJwk);
    expect(broker.handle(body, { client_id: "c-big", name: "big-agent" }))
      .rejects.toThrow("credential payload too large");
  }, 15_000);

  test("dev auto-approver approves without telegram (gated)", async () => {
    const db = new Database(":memory:");
    const grants = new GrantStore(db);
    const clients = new ClientRegistry(db);
    const { token } = clients.add("dev-agent");
    const vault = new FakeVault([{
      item_id: "11111111-aaaa-bbbb-cccc-000000000009",
      revision: "r",
      name: "Dev Item",
      description: "",
      fields: ["password"],
      values: { password: "dev-secret" },
    }]);
    expect(() => createAutoApprover({ env: {}, log: () => {} })).toThrow();
    expect(() => createAutoApprover({
      env: { SECRETARY_DEV_AUTO_APPROVE: "1", NODE_ENV: "production" },
      log: () => {},
    })).toThrow();
    const approver = createAutoApprover({ env: { SECRETARY_DEV_AUTO_APPROVE: "1" }, log: () => {} });
    const broker = new RequestBroker({ vault, grants, approver, approvalTimeoutMs: 2_000, log: () => {} });
    const server = startHttpServer({ clients, broker, vault, hostname: "127.0.0.1", port: 0, log: () => {} });
    cleanups.push(() => server.stop(true));
    const keys = await clientKeys();
    const body = requestBody({
      items: [{ name: "Dev Item", bindings: [{ field: "password", env: "DEV_TOKEN" }] }],
    }, keys.publicKeyJwk);
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/requests`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = JSON.parse((await response.text()).trim());
    expect(result.approved).toBe(true);
    expect(result.decided_by).toBe("dev-auto-approver");
    const credentials = await decryptCredentialEnvelope(
      result.credential_envelope,
      keys.privateKey,
      body.request_id as string,
    );
    expect(credentials).toEqual({ DEV_TOKEN: "dev-secret" });
  }, 15_000);
});
