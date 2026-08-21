// Write path: parsing, declarative idempotency, approval cards, the Entry Form,
// and the grant cleanup a destructive write is responsible for.

import { afterEach, describe, expect, test } from "bun:test";
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
import {
  GrantRevokedDuringApprovalError,
  GrantStore,
  type GrantRevocationSnapshot,
} from "../src/grants.ts";
import type { AuthedClient } from "../src/requests.ts";
import type { BwItem, SecretField, Vault, VaultItemSnapshot } from "../src/vault.ts";
import { itemFieldValue, snapshotItemsNamed } from "../src/vault.ts";
import { makeFingerprinter, parseWriteBody, WriteBroker, WriteError } from "../src/writes.ts";

const CLIENT: AuthedClient = { client_id: "11111111-2222-3333-4444-555555555555", name: "laptop" };
const ITEM_ID = "aaaaaaaa-bbbb-cccc-dddd-000000000001";

function uuid(n: number): string {
  return `${String(n).padStart(8, "0")}-1111-4222-8333-444444444444`;
}

/** In-memory vault with a real write surface: every apply is observable. */
class FakeVault implements Vault {
  items: BwItem[];
  trashed: string[] = [];
  syncs = 0;
  constructor(items: BwItem[] = []) {
    this.items = items;
  }
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
    this.syncs++;
    return snapshotItemsNamed(this.items, name);
  }
  async createItem(payload: unknown): Promise<void> {
    const item = JSON.parse(JSON.stringify(payload)) as BwItem;
    (item as Record<string, unknown>).id = ITEM_ID;
    this.items.push(item);
  }
  async replaceItem(itemId: string, payload: unknown): Promise<void> {
    const index = this.items.findIndex((item) => item.id === itemId);
    if (index < 0) throw new Error("fake vault: no such item");
    this.items[index] = JSON.parse(JSON.stringify(payload)) as BwItem;
  }
  async trashItem(itemId: string): Promise<void> {
    this.trashed.push(itemId);
    this.items = this.items.filter((item) => item.id !== itemId);
  }
}

class FakeApprover implements Approver {
  cards: WriteCard[] = [];
  notes: WriteNote[] = [];
  decision: WriteDecision = { approved: true, decided_by: "owner", decided_at: "2030-01-01T00:00:00.000Z" };
  beforeDecision?: () => void | Promise<void>;
  async requestApproval(_card: ApprovalCard): Promise<ApprovalDecision> {
    throw new Error("not used");
  }
  async notifySighting(_card: SightingCard): Promise<void> {}
  async requestWriteApproval(card: WriteCard): Promise<WriteDecision> {
    this.cards.push(card);
    await this.beforeDecision?.();
    return this.decision;
  }
  async notifyWrite(note: WriteNote): Promise<void> {
    this.notes.push(note);
  }
  start(): void {}
  stop(): void {}
}

function loginItem(overrides: Partial<BwItem> = {}): BwItem {
  return {
    id: ITEM_ID,
    type: 1,
    name: "Acme Prod",
    notes: "Acme 生产部署账号",
    revisionDate: "2030-01-01T00:00:00.000Z",
    creationDate: "2029-01-01T00:00:00.000Z",
    login: { username: "ops@acme.com", password: "old-secret" },
    fields: [],
    ...overrides,
  };
}

const dbs: Database[] = [];
afterEach(() => {
  while (dbs.length) dbs.pop()!.close();
});

function makeBroker(items: BwItem[] = []) {
  const db = new Database(":memory:");
  dbs.push(db);
  const grants = new GrantStore(db);
  const vault = new FakeVault(items);
  const approver = new FakeApprover();
  const broker = new WriteBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: 1_000,
    entryTtlMs: 10_000,
  });
  return { broker, vault, approver, grants };
}

function body(extra: Record<string, unknown>): Record<string, unknown> {
  return {
    request_id: uuid(1),
    reason: "把刚轮换的部署 token 同步进 vault",
    repo: "broven/deploy",
    host: "mac",
    user: "metajs",
    ...extra,
  };
}

// ---------------------------------------------------------------------------

describe("parseWriteBody", () => {
  test("@owner is refused outside create: the unapproved lane may only add", () => {
    expect(() =>
      parseWriteBody(body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "owner" }],
      }))
    ).toThrow("@owner 只能用于 create");
  });

  test("update refuses to change two kinds of thing at once", () => {
    expect(() =>
      parseWriteBody(body({
        operation: "update",
        item: "Acme Prod",
        rename: "Acme Production",
        description: "一个足够长的新描述文本",
      }))
    ).toThrow("一次只能改一类东西");
  });

  test("a create description must be long enough to identify the item", () => {
    expect(() =>
      parseWriteBody(body({
        operation: "create",
        item: "X",
        description: "短",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "v" },
      }))
    ).toThrow("description 至少");
  });

  test("every inline field needs a value and every value needs a field", () => {
    expect(() =>
      parseWriteBody(body({
        operation: "create",
        item: "X",
        description: "足够长的描述文本内容",
        fields: [{ name: "password", source: "inline" }],
      }))
    ).toThrow("values missing");
    expect(() =>
      parseWriteBody(body({
        operation: "create",
        item: "X",
        description: "足够长的描述文本内容",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "v", stray: "v" },
      }))
    ).toThrow("no matching inline field");
  });
});

describe("fingerprints", () => {
  test("are stable within one card, distinct for changed values, and unlinkable across cards", () => {
    const firstCard = makeFingerprinter(new Uint8Array(32).fill(1));
    const secondCard = makeFingerprinter(new Uint8Array(32).fill(2));

    expect(firstCard("1234")).toMatch(/^[0-9a-f]{8}$/);
    expect(firstCard("1234")).toBe(firstCard("1234"));
    expect(firstCard("1234")).not.toBe(firstCard("5678"));
    expect(firstCard("1234")).not.toBe(secondCard("1234"));
  });
});

describe("create", () => {
  test("creates a login item with the description as notes and hidden custom fields", async () => {
    const { broker, vault, approver } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [
          { name: "username", source: "inline" },
          { name: "api_key", source: "inline" },
        ],
        values: { username: "ops@acme.com", api_key: "k-123" },
      }),
      CLIENT,
    );
    expect(result.status).toBe("applied");
    const created = vault.items[0]!;
    expect(created.type).toBe(1);
    expect(created.notes).toBe("Acme 生产部署账号");
    expect(created.login?.username).toBe("ops@acme.com");
    expect(created.fields).toEqual([{ name: "api_key", value: "k-123", type: 1 }]);
    // The card carries fingerprints, never the values.
    const card = approver.cards[0]!;
    expect(card.kind).toBe("create_item");
    const rendered = JSON.stringify(card);
    expect(rendered).not.toContain("k-123");
    expect(card.lines.find((line) => line.label === "字段 api_key")?.value).toMatch(/^[0-9a-f]{8}$/);
  });

  test("a taken name is an error, not a silent success", async () => {
    const { broker } = makeBroker([loginItem()]);
    await expect(broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "另一个完全无关的东西",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "v" },
      }),
      CLIENT,
    )).rejects.toThrow("已存在");
  });

  test("without --description it adds a field to the existing item", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        fields: [{ name: "api_key", source: "inline" }],
        values: { api_key: "k-456" },
      }),
      CLIENT,
    );
    expect(result.status).toBe("applied");
    expect(approver.cards[0]!.kind).toBe("create_field");
    expect(itemFieldValue(vault.items[0]!, "api_key")).toBe("k-456");
    // The existing password is untouched: create never overwrites.
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("old-secret");
  });

  test("adding a field preserves unrelated changes made while approval is pending", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        notes: "由另一个 vault 客户端更新的说明",
      });
    };

    await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        fields: [{ name: "api_key", source: "inline" }],
        values: { api_key: "k-456" },
      }),
      CLIENT,
    );

    expect(itemFieldValue(vault.items[0]!, "api_key")).toBe("k-456");
    expect(vault.items[0]!.notes).toBe("由另一个 vault 客户端更新的说明");
    expect(vault.items[0]!.revisionDate).toBe("2030-01-02T00:00:00.000Z");
  });

  test("adding a field that already exists is refused and points at update", async () => {
    const { broker } = makeBroker([loginItem()]);
    await expect(broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "v" },
      }),
      CLIENT,
    )).rejects.toThrow("已有字段 password");
  });

  test("a missing item without --description points at create", async () => {
    const { broker } = makeBroker();
    await expect(broker.handle(
      body({
        operation: "create",
        item: "Nope",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "v" },
      }),
      CLIENT,
    )).rejects.toThrow("不存在");
  });
});

describe("entry form", () => {
  test("@owner fields defer the write, and submitting completes it and notifies", async () => {
    const { broker, vault, approver } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [
          { name: "username", source: "inline" },
          { name: "password", source: "owner" },
        ],
        values: { username: "ops@acme.com" },
      }),
      CLIENT,
    );
    expect(result.status).toBe("pending_entry");
    if (result.status !== "pending_entry") throw new Error("unreachable");
    expect(result.fields).toEqual(["password"]);
    // Nothing is written and nobody is asked to approve until the form lands.
    expect(vault.items).toHaveLength(0);
    expect(approver.cards).toHaveLength(0);

    const nonce = result.entry_path.slice("/entry/".length);
    const draft = broker.entries.take(nonce)!;
    expect(draft).toBeTruthy();
    await broker.submitEntry(draft, new Map([["password", "owner-typed"]]));

    expect(itemFieldValue(vault.items[0]!, "password")).toBe("owner-typed");
    expect(itemFieldValue(vault.items[0]!, "username")).toBe("ops@acme.com");
    // Nothing changes the vault silently.
    const note = approver.notes[0]!;
    expect(note.headline).toContain("新建条目");
    expect(JSON.stringify(note)).not.toContain("owner-typed");
    expect(note.lines.find((line) => line.label.includes("password"))?.value).toMatch(/^[0-9a-f]{8}$/);
  });

  test("a stalled completion notification does not hold the Entry Form submission open", async () => {
    const { broker, vault, approver } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [{ name: "password", source: "owner" }],
      }),
      CLIENT,
    );
    if (result.status !== "pending_entry") throw new Error("expected pending_entry");

    approver.notifyWrite = async () => await new Promise<void>(() => {});
    const nonce = result.entry_path.slice("/entry/".length);
    const draft = broker.entries.take(nonce)!;
    const submitted = broker.submitEntry(draft, new Map([["password", "owner-typed"]]));

    expect(await Promise.race([
      submitted.then(() => true),
      Bun.sleep(25).then(() => false),
    ])).toBe(true);
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("owner-typed");
  });

  test("a synchronously failing completion notification does not fail the applied write", async () => {
    const { broker, vault, approver } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [{ name: "password", source: "owner" }],
      }),
      CLIENT,
    );
    if (result.status !== "pending_entry") throw new Error("expected pending_entry");

    approver.notifyWrite = () => {
      throw new Error("notification unavailable");
    };
    const nonce = result.entry_path.slice("/entry/".length);
    const draft = broker.entries.take(nonce)!;

    await expect(broker.submitEntry(draft, new Map([["password", "owner-typed"]]))).resolves.toBeUndefined();
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("owner-typed");
  });

  test("a rejected completion notification does not fail the applied write", async () => {
    const { broker, vault, approver } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [{ name: "password", source: "owner" }],
      }),
      CLIENT,
    );
    if (result.status !== "pending_entry") throw new Error("expected pending_entry");

    approver.notifyWrite = async () => {
      throw new Error("notification unavailable");
    };
    const nonce = result.entry_path.slice("/entry/".length);
    const draft = broker.entries.take(nonce)!;

    await expect(broker.submitEntry(draft, new Map([["password", "owner-typed"]]))).resolves.toBeUndefined();
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("owner-typed");
  });

  test("a nonce works exactly once", async () => {
    const { broker } = makeBroker();
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [{ name: "password", source: "owner" }],
      }),
      CLIENT,
    );
    if (result.status !== "pending_entry") throw new Error("expected pending_entry");
    const nonce = result.entry_path.slice("/entry/".length);
    expect(broker.entries.take(nonce)).toBeTruthy();
    expect(broker.entries.take(nonce)).toBeNull();
  });

  test("an unused link expires and the Owner still hears about it", async () => {
    let clock = 1_000;
    const db = new Database(":memory:");
    dbs.push(db);
    const approver = new FakeApprover();
    const broker = new WriteBroker({
      vault: new FakeVault(),
      grants: new GrantStore(db),
      approver,
      approvalTimeoutMs: 1_000,
      entryTtlMs: 10_000,
      now: () => clock,
    });
    const result = await broker.handle(
      body({
        operation: "create",
        item: "Acme Prod",
        description: "Acme 生产部署账号",
        fields: [{ name: "password", source: "owner" }],
      }),
      CLIENT,
    );
    if (result.status !== "pending_entry") throw new Error("expected pending_entry");
    clock += 20_000;
    broker.entries.sweep();
    expect(broker.entries.size).toBe(0);
    expect(approver.notes[0]!.headline).toContain("已过期");
  });
});

describe("update", () => {
  test("a field already holding the requested value is unchanged and silent", async () => {
    const { broker, approver } = makeBroker([loginItem()]);
    const result = await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "old-secret" },
      }),
      CLIENT,
    );
    expect(result.status).toBe("unchanged");
    expect(approver.cards).toHaveLength(0);
  });

  test("a changed value is approved with an old -> new fingerprint pair", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    const result = await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-secret" },
      }),
      CLIENT,
    );
    expect(result.status).toBe("applied");
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("new-secret");
    const card = approver.cards[0]!;
    expect(card.kind).toBe("update_value");
    const [before, after] = card.lines[0]!.value.split(" -> ");
    expect(before).toMatch(/^[0-9a-f]{8}$/);
    expect(after).toMatch(/^[0-9a-f]{8}$/);
    expect(before).not.toBe(after);
    expect(JSON.stringify(card)).not.toContain("new-secret");
  });

  test("applies an approved field delta to the latest item revision", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        login: { username: "changed-elsewhere@example.com", password: "old-secret" },
      });
    };

    const result = await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-secret" },
      }),
      CLIENT,
    );

    expect(result.status).toBe("applied");
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("new-secret");
    expect(itemFieldValue(vault.items[0]!, "username")).toBe("changed-elsewhere@example.com");
    expect(vault.items[0]!.revisionDate).toBe("2030-01-02T00:00:00.000Z");
  });

  test("fails closed if the approved field itself changes while approval is pending", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        login: { username: "ops@acme.com", password: "changed-elsewhere" },
      });
    };

    const pending = broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-secret" },
      }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("changed-elsewhere");
  });

  test("fails closed if a custom field becomes ambiguous while update approval is pending", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "", type: 1 }] });
    const { broker, vault, approver } = makeBroker([item]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        fields: [
          { name: "api_key", value: "", type: 1 },
          { name: "api_key", value: "", type: 1 },
        ],
      });
    };

    const pending = broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "api_key", source: "inline" }],
        values: { api_key: "replacement" },
      }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.fields).toEqual([
      { name: "api_key", value: "", type: 1 },
      { name: "api_key", value: "", type: 1 },
    ]);
  });

  test("updating a field that does not exist points at create", async () => {
    const { broker } = makeBroker([loginItem()]);
    await expect(broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "api_key", source: "inline" }],
        values: { api_key: "v" },
      }),
      CLIENT,
    )).rejects.toThrow("没有字段 api_key");
  });

  test("refuses to update duplicate custom fields with the same name", async () => {
    const duplicate = loginItem({
      fields: [
        { name: "api_key", value: "first", type: 1 },
        { name: "api_key", value: "second", type: 1 },
      ],
    });
    const { broker, vault, approver } = makeBroker([duplicate]);

    const pending = broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "api_key", source: "inline" }],
        values: { api_key: "replacement" },
      }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.fields).toEqual(duplicate.fields);
    expect(approver.cards).toHaveLength(0);
  });

  test("a custom reserved name cannot stand in for a missing login field on update", async () => {
    const item = loginItem({
      login: { username: "ops@acme.com", password: null },
      fields: [{ name: "password", value: "custom-value", type: 1 }],
    });
    const { broker, vault, approver } = makeBroker([item]);

    const pending = broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "replacement" },
      }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.login?.password).toBeNull();
    expect(vault.items[0]!.fields).toEqual(item.fields);
    expect(approver.cards).toHaveLength(0);
  });

  test("updating a login field preserves a custom field with the same reserved name", async () => {
    const item = loginItem({ fields: [{ name: "password", value: "custom-value", type: 1 }] });
    const { broker, vault } = makeBroker([item]);

    const result = await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "replacement" },
      }),
      CLIENT,
    );

    expect(result.status).toBe("applied");
    expect(vault.items[0]!.login?.password).toBe("replacement");
    expect(vault.items[0]!.fields).toEqual(item.fields);
  });

  test("a rename warns that existing grants survive but the old name stops resolving", async () => {
    const { broker, vault, approver, grants } = makeBroker([loginItem()]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "password" }],
      "7d",
      uuid(2),
    );
    const result = await broker.handle(
      body({ operation: "update", item: "Acme Prod", rename: "Acme Production" }),
      CLIENT,
    );
    expect(result.status).toBe("applied");
    expect(vault.items[0]!.name).toBe("Acme Production");
    expect(approver.cards[0]!.warnings.join(" ")).toContain("1 条现有授权会保留");
    // The rename is not a revocation: the grant is still there.
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(1);
  });

  test("renaming preserves unrelated changes made while approval is pending", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        notes: "由另一个 vault 客户端更新的说明",
      });
    };

    await broker.handle(
      body({ operation: "update", item: "Acme Prod", rename: "Acme Production" }),
      CLIENT,
    );

    expect(vault.items[0]!.name).toBe("Acme Production");
    expect(vault.items[0]!.notes).toBe("由另一个 vault 客户端更新的说明");
    expect(vault.items[0]!.revisionDate).toBe("2030-01-02T00:00:00.000Z");
  });

  test("renaming onto a taken name is refused", async () => {
    const other = loginItem({ id: "aaaaaaaa-bbbb-cccc-dddd-000000000002", name: "Acme Production" });
    const { broker } = makeBroker([loginItem(), other]);
    await expect(broker.handle(
      body({ operation: "update", item: "Acme Prod", rename: "Acme Production" }),
      CLIENT,
    )).rejects.toThrow("已存在");
  });

  test("a rename locks its target against a concurrent create", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    let releaseApproval!: () => void;
    const approvalGate = new Promise<void>((resolve) => {
      releaseApproval = resolve;
    });
    approver.beforeDecision = () => approvalGate;

    const rename = broker.handle(
      body({ operation: "update", item: "Acme Prod", rename: "Acme Production" }),
      CLIENT,
    );
    await Bun.sleep(0);
    expect(approver.cards).toHaveLength(1);

    const create = broker.handle(
      body({
        request_id: uuid(8),
        operation: "create",
        item: "Acme Production",
        description: "新建一个同名但完全不同的部署账号",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-item-secret" },
      }),
      CLIENT,
    );
    await Bun.sleep(0);
    const cardsBeforeRelease = approver.cards.length;
    releaseApproval();

    const [renameResult, createResult] = await Promise.allSettled([rename, create]);
    expect(cardsBeforeRelease).toBe(1);
    expect(renameResult.status).toBe("fulfilled");
    expect(createResult.status).toBe("rejected");
    expect(vault.items.filter((item) => item.name === "Acme Production")).toHaveLength(1);
  });

  test("a description diff renders in the clear, since it is not a credential", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    await broker.handle(
      body({ operation: "update", item: "Acme Prod", description: "改成一个新的用途说明文本" }),
      CLIENT,
    );
    expect(vault.items[0]!.notes).toBe("改成一个新的用途说明文本");
    const card = approver.cards[0]!;
    expect(card.kind).toBe("update_description");
    expect(card.lines.every((line) => line.plain)).toBe(true);
    expect(card.lines[1]!.value).toBe("改成一个新的用途说明文本");
  });

  test("updating a description preserves unrelated changes made while approval is pending", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        login: { username: "changed-elsewhere@example.com", password: "old-secret" },
      });
    };

    await broker.handle(
      body({ operation: "update", item: "Acme Prod", description: "改成一个新的用途说明文本" }),
      CLIENT,
    );

    expect(vault.items[0]!.notes).toBe("改成一个新的用途说明文本");
    expect(itemFieldValue(vault.items[0]!, "username")).toBe("changed-elsewhere@example.com");
    expect(vault.items[0]!.revisionDate).toBe("2030-01-02T00:00:00.000Z");
  });
});

describe("remove", () => {
  test("removing an item trashes it and revokes the grants that pointed at it", async () => {
    const { broker, vault, approver, grants } = makeBroker([loginItem()]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "password" }, { item_id: ITEM_ID, field: "username" }],
      "7d",
      uuid(3),
    );
    const result = await broker.handle(body({ operation: "remove", item: "Acme Prod" }), CLIENT);
    expect(result.status).toBe("applied");
    expect(vault.trashed).toEqual([ITEM_ID]);
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(0);
    const warnings = approver.cards[0]!.warnings.join(" ");
    expect(warnings).toContain("回收站");
    expect(warnings).toContain("将吊销 2 条授权");
  });

  test("a read resolved while item trashing is in flight cannot issue a late grant", async () => {
    const { broker, vault, grants } = makeBroker([loginItem()]);
    const unit = { item_id: ITEM_ID, field: "password" };
    let readSnapshot!: GrantRevocationSnapshot;
    const trashItem = vault.trashItem.bind(vault);
    vault.trashItem = async (itemId) => {
      // The first revocation already happened, but the Item is still visible
      // while the external vault mutation is in flight.
      expect(vault.items).toHaveLength(1);
      readSnapshot = grants.snapshotRevocations([unit]);
      await trashItem(itemId);
    };

    await broker.handle(body({ operation: "remove", item: "Acme Prod" }), CLIENT);

    expect(() => grants.save(
      { caller_id: "reader", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [unit],
      "8h",
      uuid(5),
      undefined,
      undefined,
      readSnapshot,
    )).toThrow(GrantRevokedDuringApprovalError);
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(0);
  });

  test("a grant revocation failure leaves the item untouched", async () => {
    const { broker, vault, grants } = makeBroker([loginItem()]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "password" }],
      "7d",
      uuid(3),
    );
    grants.revokeForItem = () => {
      throw new Error("fake grant store unavailable");
    };

    const pending = broker.handle(body({ operation: "remove", item: "Acme Prod" }), CLIENT);

    await expect(pending).rejects.toThrow("fake grant store unavailable");
    expect(vault.trashed).toEqual([]);
    expect(vault.items).toHaveLength(1);
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(1);
  });

  test("a vault trash failure leaves the item grants safely revoked", async () => {
    const { broker, vault, grants } = makeBroker([loginItem()]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "password" }],
      "7d",
      uuid(3),
    );
    vault.trashItem = async () => {
      throw new Error("fake vault unavailable");
    };

    const pending = broker.handle(body({ operation: "remove", item: "Acme Prod" }), CLIENT);

    await expect(pending).rejects.toThrow("fake vault unavailable");
    expect(vault.items).toHaveLength(1);
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(0);
  });

  test("fails closed if the item is renamed while removal approval is pending", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({ name: "Acme Production" });
    };

    const pending = broker.handle(body({ operation: "remove", item: "Acme Prod" }), CLIENT);

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.trashed).toEqual([]);
    expect(vault.items[0]!.name).toBe("Acme Production");
  });

  test("removing a field is flagged irreversible and revokes only that field", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "k-789", type: 1 }] });
    const { broker, vault, approver, grants } = makeBroker([item]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "password" }, { item_id: ITEM_ID, field: "api_key" }],
      "7d",
      uuid(4),
    );
    const result = await broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );
    expect(result.status).toBe("applied");
    expect(itemFieldValue(vault.items[0]!, "api_key")).toBeNull();
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("old-secret");
    expect(grants.activeForItem(ITEM_ID).map((grant) => grant.field)).toEqual(["password"]);
    expect(approver.cards[0]!.warnings.join(" ")).toContain("不可恢复");
  });

  test("a read resolved while field removal is in flight cannot issue a late grant", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "k-789", type: 1 }] });
    const { broker, vault, grants } = makeBroker([item]);
    const unit = { item_id: ITEM_ID, field: "api_key" };
    let readSnapshot!: GrantRevocationSnapshot;
    const replaceItem = vault.replaceItem.bind(vault);
    vault.replaceItem = async (itemId, payload) => {
      // The first revocation already happened, but the Field is still visible
      // while the external vault mutation is in flight.
      expect(itemFieldValue(vault.items[0]!, "api_key")).toBe("k-789");
      readSnapshot = grants.snapshotRevocations([unit]);
      await replaceItem(itemId, payload);
    };

    await broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    expect(() => grants.save(
      { caller_id: "reader", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [unit],
      "8h",
      uuid(6),
      undefined,
      undefined,
      readSnapshot,
    )).toThrow(GrantRevokedDuringApprovalError);
    expect(grants.activeForItem(ITEM_ID, "api_key")).toHaveLength(0);
  });

  test("a grant revocation failure leaves the field untouched", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "k-789", type: 1 }] });
    const { broker, vault, grants } = makeBroker([item]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "api_key" }],
      "7d",
      uuid(4),
    );
    grants.revokeForItem = () => {
      throw new Error("fake grant store unavailable");
    };

    const pending = broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    await expect(pending).rejects.toThrow("fake grant store unavailable");
    expect(itemFieldValue(vault.items[0]!, "api_key")).toBe("k-789");
    expect(grants.activeForItem(ITEM_ID, "api_key")).toHaveLength(1);
  });

  test("a vault field-removal failure leaves that field's grants safely revoked", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "k-789", type: 1 }] });
    const { broker, vault, grants } = makeBroker([item]);
    grants.save(
      { caller_id: "metajs", client_id: CLIENT.client_id, repo: "broven/deploy" },
      [{ item_id: ITEM_ID, field: "api_key" }],
      "7d",
      uuid(4),
    );
    vault.replaceItem = async () => {
      throw new Error("fake vault unavailable");
    };

    const pending = broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    await expect(pending).rejects.toThrow("fake vault unavailable");
    expect(itemFieldValue(vault.items[0]!, "api_key")).toBe("k-789");
    expect(grants.activeForItem(ITEM_ID, "api_key")).toHaveLength(0);
  });

  test("removing one usable custom field preserves an unsupported same-name field", async () => {
    const item = loginItem({
      fields: [
        { name: "api_key", value: "usable", type: 1 },
        { name: "api_key", value: "unsupported", type: 2 },
      ],
    });
    const { broker, vault } = makeBroker([item]);

    const result = await broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    expect(result.status).toBe("applied");
    expect(vault.items[0]!.fields).toEqual([
      { name: "api_key", value: "unsupported", type: 2 },
    ]);
  });

  test("refuses to remove duplicate custom fields with the same name", async () => {
    const duplicate = loginItem({
      fields: [
        { name: "api_key", value: "first", type: 1 },
        { name: "api_key", value: "second", type: 1 },
      ],
    });
    const { broker, vault, approver } = makeBroker([duplicate]);

    const pending = broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.fields).toEqual(duplicate.fields);
    expect(approver.cards).toHaveLength(0);
  });

  test("a custom reserved name cannot stand in for a missing login field on remove", async () => {
    const item = loginItem({
      login: { username: "ops@acme.com", password: null },
      fields: [{ name: "password", value: "custom-value", type: 1 }],
    });
    const { broker, vault, approver } = makeBroker([item]);

    const pending = broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "password" }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.login?.password).toBeNull();
    expect(vault.items[0]!.fields).toEqual(item.fields);
    expect(approver.cards).toHaveLength(0);
  });

  test("removing a login field preserves a custom field with the same reserved name", async () => {
    const item = loginItem({ fields: [{ name: "password", value: "custom-value", type: 1 }] });
    const { broker, vault } = makeBroker([item]);

    const result = await broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "password" }),
      CLIENT,
    );

    expect(result.status).toBe("applied");
    expect(vault.items[0]!.login?.password).toBeNull();
    expect(vault.items[0]!.fields).toEqual(item.fields);
  });

  test("removing a field preserves unrelated changes made while approval is pending", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "k-789", type: 1 }] });
    const { broker, vault, approver } = makeBroker([item]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        revisionDate: "2030-01-02T00:00:00.000Z",
        notes: "由另一个 vault 客户端更新的说明",
        fields: [{ name: "api_key", value: "k-789", type: 1 }],
      });
    };

    await broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    expect(itemFieldValue(vault.items[0]!, "api_key")).toBeNull();
    expect(vault.items[0]!.notes).toBe("由另一个 vault 客户端更新的说明");
    expect(vault.items[0]!.revisionDate).toBe("2030-01-02T00:00:00.000Z");
  });

  test("fails closed if a custom field becomes ambiguous while removal approval is pending", async () => {
    const item = loginItem({ fields: [{ name: "api_key", value: "", type: 1 }] });
    const { broker, vault, approver } = makeBroker([item]);
    approver.beforeDecision = () => {
      vault.items[0] = loginItem({
        fields: [
          { name: "api_key", value: "", type: 1 },
          { name: "api_key", value: "", type: 1 },
        ],
      });
    };

    const pending = broker.handle(
      body({ operation: "remove", item: "Acme Prod", field: "api_key" }),
      CLIENT,
    );

    await expect(pending).rejects.toMatchObject({ status: 409 });
    expect(vault.items[0]!.fields).toEqual([
      { name: "api_key", value: "", type: 1 },
      { name: "api_key", value: "", type: 1 },
    ]);
  });

  test("removing what is already gone is unchanged, not an error", async () => {
    const { broker, approver } = makeBroker();
    const result = await broker.handle(body({ operation: "remove", item: "Ghost" }), CLIENT);
    expect(result.status).toBe("unchanged");
    expect(approver.cards).toHaveLength(0);
  });
});

describe("approval outcomes", () => {
  test("a denied write leaves the vault untouched", async () => {
    const { broker, vault, approver } = makeBroker([loginItem()]);
    approver.decision = { approved: false, reason: "denied" };
    const result = await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-secret" },
      }),
      CLIENT,
    );
    expect(result).toEqual({ status: "rejected", reason: "denied" });
    expect(itemFieldValue(vault.items[0]!, "password")).toBe("old-secret");
  });

  test("a write never creates a grant", async () => {
    const { broker, grants } = makeBroker([loginItem()]);
    await broker.handle(
      body({
        operation: "update",
        item: "Acme Prod",
        fields: [{ name: "password", source: "inline" }],
        values: { password: "new-secret" },
      }),
      CLIENT,
    );
    expect(grants.activeForItem(ITEM_ID)).toHaveLength(0);
  });

  test("a mismatched client_id is refused", () => {
    const { broker } = makeBroker([loginItem()]);
    expect(() => broker.handle(
      body({ operation: "remove", item: "Acme Prod", client_id: uuid(9) }),
      CLIENT,
    )).toThrow(WriteError);
  });

  test("preflight validation throws synchronously so HTTP can set an error status", () => {
    const { broker } = makeBroker();
    let malformedError: unknown;
    try {
      void broker.handle({} as never, CLIENT).catch(() => undefined);
    } catch (error) {
      malformedError = error;
    }
    expect(malformedError).toBeInstanceOf(WriteError);

    let clientError: unknown;
    try {
      void broker.handle(
        body({ operation: "remove", item: "Acme Prod", client_id: uuid(9) }),
        CLIENT,
      ).catch(() => undefined);
    } catch (error) {
      clientError = error;
    }
    expect(clientError).toBeInstanceOf(WriteError);
    expect((clientError as WriteError).status).toBe(403);
  });
});

describe("state is always read fresh", () => {
  test("every operation forces a vault sync before deciding", async () => {
    const { broker, vault } = makeBroker([loginItem()]);
    await broker.handle(body({ operation: "remove", item: "Ghost" }), CLIENT);
    expect(vault.syncs).toBeGreaterThan(0);
  });
});
