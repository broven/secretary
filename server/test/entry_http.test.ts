// The Entry Form over HTTP: the nonce is the only credential, it works once,
// and unknown / expired / spent links are indistinguishable from each other.

import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type {
  ApprovalCard,
  ApprovalDecision,
  Approver,
  SightingCard,
  WriteCard,
  WriteDecision,
  WriteNote,
} from "../src/approver.ts";
import { ClientRegistry } from "../src/clients.ts";
import { GrantStore } from "../src/grants.ts";
import { startHttpServer } from "../src/http.ts";
import { RequestBroker } from "../src/requests.ts";
import type { BwItem, Vault, VaultItemSnapshot } from "../src/vault.ts";
import { itemFieldValue, snapshotItemsNamed } from "../src/vault.ts";
import { WriteBroker } from "../src/writes.ts";

class FakeVault implements Vault {
  items: BwItem[] = [];
  async catalog() {
    return [];
  }
  async resolveByName(): Promise<never> {
    throw new Error("not used");
  }
  async readValues(): Promise<never> {
    throw new Error("not used");
  }
  async findItemsByName(name: string): Promise<VaultItemSnapshot[]> {
    return snapshotItemsNamed(this.items, name);
  }
  async createItem(payload: unknown): Promise<void> {
    const item = JSON.parse(JSON.stringify(payload)) as BwItem;
    (item as Record<string, unknown>).id = "aaaaaaaa-bbbb-cccc-dddd-000000000001";
    this.items.push(item);
  }
  async replaceItem(): Promise<void> {}
  async trashItem(): Promise<void> {}
}

class FakeApprover implements Approver {
  notes: WriteNote[] = [];
  async requestApproval(_card: ApprovalCard): Promise<ApprovalDecision> {
    throw new Error("not used");
  }
  async notifySighting(_card: SightingCard): Promise<void> {}
  async requestWriteApproval(_card: WriteCard): Promise<WriteDecision> {
    throw new Error("the entry path must not ask for an approval");
  }
  async notifyWrite(note: WriteNote): Promise<void> {
    this.notes.push(note);
  }
  start(): void {}
  stop(): void {}
}

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

function makeStack() {
  const db = new Database(":memory:");
  const grants = new GrantStore(db);
  const clients = new ClientRegistry(db);
  const { client_id, token } = clients.add("laptop");
  const vault = new FakeVault();
  const approver = new FakeApprover();
  const broker = new RequestBroker({ vault, grants, approver, approvalTimeoutMs: 1_000, log: () => {} });
  const writes = new WriteBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: 1_000,
    entryTtlMs: 10_000,
    log: () => {},
  });
  const server = startHttpServer({
    clients,
    broker,
    writes,
    vault,
    hostname: "127.0.0.1",
    port: 0,
    log: () => {},
  });
  cleanups.push(() => {
    server.stop(true);
    db.close();
  });
  return { url: `http://127.0.0.1:${server.port}`, client_id, token, vault, approver };
}

async function requestEntry(url: string, token: string): Promise<string> {
  const response = await fetch(`${url}/v1/writes`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      request_id: "00000001-1111-4222-8333-444444444444",
      operation: "create",
      item: "Acme Prod",
      description: "Acme 生产部署账号",
      reason: "注册完账号，把凭据存进 vault",
      repo: "broven/deploy",
      host: "mac",
      user: "metajs",
      fields: [{ name: "username", source: "inline" }, { name: "password", source: "owner" }],
      values: { username: "ops@acme.com" },
    }),
  });
  const result = JSON.parse((await response.text()).trim());
  expect(result.status).toBe("pending_entry");
  return result.entry_path as string;
}

test("the form renders, writes once, and then reports the same 'gone' page as any bad nonce", async () => {
  const { url, token, vault, approver } = makeStack();
  const path = await requestEntry(url, token);

  // The page needs no bearer token: the nonce is the capability.
  const page = await fetch(`${url}${path}`);
  expect(page.status).toBe(200);
  expect(page.headers.get("cache-control")).toContain("no-store");
  const html = await page.text();
  expect(html).toContain("Acme Prod");
  expect(html).toContain('name="f_password"');
  // Write-only: the agent-supplied value is named but never rendered.
  expect(html).toContain("username");
  expect(html).not.toContain("ops@acme.com");

  const submit = await fetch(`${url}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ f_password: "owner-typed" }),
  });
  expect(submit.status).toBe(200);
  expect(await submit.text()).toContain("已写入");
  expect(itemFieldValue(vault.items[0]!, "password")).toBe("owner-typed");
  expect(approver.notes).toHaveLength(1);

  const replay = await fetch(`${url}${path}`);
  expect(replay.status).toBe(404);
  const spent = await replay.text();
  const unknown = await (await fetch(`${url}/entry/not-a-real-nonce`)).text();
  // Spent and never-existed must be indistinguishable.
  expect(spent).toBe(unknown);
});

test("an empty box re-renders the form instead of burning the link", async () => {
  const { url, token, vault } = makeStack();
  const path = await requestEntry(url, token);
  const submit = await fetch(`${url}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ f_password: "" }),
  });
  expect(submit.status).toBe(400);
  expect(await submit.text()).toContain("请填写 password");
  expect(vault.items).toHaveLength(0);
  // Still usable.
  expect((await fetch(`${url}${path}`)).status).toBe(200);
});

test("oversized entry forms are rejected before parsing without burning the link", async () => {
  const { url, token, vault } = makeStack();
  const contentLengthPath = await requestEntry(url, token);
  const oversized = `f_password=${"x".repeat(256 * 1024)}`;
  const contentLengthSubmit = await fetch(`${url}${contentLengthPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: oversized,
  });
  expect(contentLengthSubmit.status).toBe(400);
  expect(await contentLengthSubmit.text()).toContain("表单读取失败，请重试。");
  expect(vault.items).toHaveLength(0);
  expect((await fetch(`${url}${contentLengthPath}`)).status).toBe(200);

  const streamedPath = contentLengthPath;
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode("f_password="));
      controller.enqueue(encoder.encode("x".repeat(256 * 1024)));
      controller.close();
    },
  });
  const streamedSubmit = await fetch(`${url}${streamedPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: stream,
  });
  expect(streamedSubmit.status).toBe(400);
  expect(await streamedSubmit.text()).toContain("表单读取失败，请重试。");
  expect(vault.items).toHaveLength(0);
  expect((await fetch(`${url}${streamedPath}`)).status).toBe(200);

  const unknownUrl = `${url}/entry/not-a-real-nonce`;
  const gone = await (await fetch(unknownUrl)).text();
  const oversizedUnknown = await fetch(unknownUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: oversized,
  });
  expect(oversizedUnknown.status).toBe(404);
  expect(await oversizedUnknown.text()).toBe(gone);
});

test("the write API still requires a bearer token", async () => {
  const { url } = makeStack();
  const response = await fetch(`${url}/v1/writes`, { method: "POST", body: "{}" });
  expect(response.status).toBe(401);
});

test("write preflight errors use HTTP error statuses before the long poll starts", async () => {
  const { url, token, client_id } = makeStack();
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

  const malformed = await fetch(`${url}/v1/writes`, {
    method: "POST",
    headers,
    body: "{}",
  });
  expect(malformed.status).toBe(400);
  expect(await malformed.json()).toEqual({ error: "request_id must be a UUID" });

  const mismatched = await fetch(`${url}/v1/writes`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      request_id: "00000002-1111-4222-8333-444444444444",
      operation: "remove",
      item: "Acme Prod",
      reason: "删除已经不再使用的 vault 条目",
      repo: "broven/deploy",
      host: "mac",
      user: "metajs",
      client_id: client_id.replace(/^./, client_id[0] === "0" ? "1" : "0"),
    }),
  });
  expect(mismatched.status).toBe(403);
  expect(await mismatched.json()).toEqual({ error: "client_id does not match the authenticated client" });
});
