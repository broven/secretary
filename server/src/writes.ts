// WriteBroker: the Write Request pipeline (CONTEXT.md "Write Request").
//
// Shape of every write, regardless of Operation:
//   validate -> lock the Item name -> force a vault sync -> read current state
//   -> is it already the requested state? (then say so, leave the Owner alone)
//   -> Approval -> bracket destructive applies with grant revocation.
//
// Two rules run through all of it:
// - Writes never create Grants. "Store this" and "let this agent use it" are
//   different decisions judged on different evidence (CONTEXT.md "Approval").
// - Values only ever reach the Owner as Fingerprints. A card that carried a
//   credential would be a disclosure channel with no Grant behind it.

import { createHmac, randomBytes } from "node:crypto";
import type { Approver, WriteCard, WriteCardKind, WriteCardLine, WriteNote } from "./approver.ts";
import { ENTRY_PATH_PREFIX, EntryStore, mintEntryNonce, type EntryDraft } from "./entry.ts";
import type { GrantStore } from "./grants.ts";
import type { AuthedClient } from "./requests.ts";
import {
  MAX_DESCRIPTION_LENGTH,
  MAX_FIELD_VALUE_LENGTH,
  MAX_ITEM_NAME_LENGTH,
  MAX_WRITE_FIELDS,
  MIN_DESCRIPTION_LENGTH,
  UUID,
  isWriteOperation,
  type WireWriteField,
  type WriteFieldSource,
  type WriteOperation,
  type WriteRequestBody,
  type WriteResult,
} from "./types.ts";
import {
  isValidFieldName,
  itemFieldValue,
  type BwItem,
  type SecretField,
  type Vault,
  type VaultItemSnapshot,
} from "./vault.ts";

/** Control characters are rejected everywhere: they corrupt approval-card
 * rendering and can smuggle line breaks into what the Owner reads. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
/** Descriptions are prose and may wrap, so tabs and newlines survive. */
const CONTROL_CHARS_ALLOW_WRAP = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export class WriteError extends Error {
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

/** Build a per-card keyed Fingerprint function. The key is never rendered or
 * persisted, so low-entropy values cannot be guessed offline and equal values
 * cannot be correlated across cards. Within one card, equal values remain
 * stable and different values are forced to distinct 8-hex labels. */
export function makeFingerprinter(key: Uint8Array = randomBytes(32)): (value: string) => string {
  const cardKey = Buffer.from(key);
  const byValue = new Map<string, string>();
  const used = new Set<string>();
  return (value: string): string => {
    const existing = byValue.get(value);
    if (existing) return existing;
    let counter = 0;
    let result: string;
    do {
      result = createHmac("sha256", cardKey)
        .update(String(counter++), "utf8")
        .update("\0", "utf8")
        .update(value, "utf8")
        .digest("hex")
        .slice(0, 8);
    } while (used.has(result));
    byValue.set(value, result);
    used.add(result);
    return result;
  };
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

export type ParsedWriteField = { name: SecretField; source: WriteFieldSource };

export type ParsedWrite = {
  request_id: string;
  operation: WriteOperation;
  item: string;
  reason: string;
  repo: string;
  host: string;
  user: string;
  agent: string;
  description?: string;
  rename?: string;
  fields: ParsedWriteField[];
  values: Map<SecretField, string>;
  field?: SecretField;
  client_id?: string;
};

const MIN_REASON = 10;
const MAX_REASON = 2000;

function text(value: unknown, field: string, max: number, required: boolean): string {
  const out = String(value ?? "").trim();
  if (required && !out) throw new WriteError(`${field} required`);
  if (out.length > max || CONTROL_CHARS.test(out)) throw new WriteError(`${field} invalid`);
  return out;
}

function assertItemName(value: unknown): string {
  const name = String(value ?? "").trim();
  if (!name) throw new WriteError("item required");
  if (name.length > MAX_ITEM_NAME_LENGTH || CONTROL_CHARS.test(name)) throw new WriteError("item invalid");
  return name;
}

function assertDescription(value: unknown): string {
  const description = String(value ?? "").trim();
  if (description.length < MIN_DESCRIPTION_LENGTH) {
    throw new WriteError(
      `description 至少 ${MIN_DESCRIPTION_LENGTH} 个字符：它是别的 agent 判断这个条目是不是自己要找的东西的唯一依据`,
    );
  }
  if (description.length > MAX_DESCRIPTION_LENGTH) throw new WriteError("description too long");
  if (CONTROL_CHARS_ALLOW_WRAP.test(description)) throw new WriteError("description invalid");
  return description;
}

function parseFields(value: unknown, operation: WriteOperation): ParsedWriteField[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_WRITE_FIELDS) throw new WriteError("fields invalid");
  const seen = new Set<string>();
  return value.map((entry) => {
    const raw = entry as Partial<WireWriteField>;
    const name = String(raw?.name ?? "");
    // Snapshot the display form first: the type predicate narrows `name` to
    // never on the failing branch.
    const shown = name.slice(0, 32);
    if (!isValidFieldName(name)) throw new WriteError(`field name invalid: ${shown}`);
    if (seen.has(name)) throw new WriteError(`field listed twice: ${name}`);
    seen.add(name);
    const source = raw?.source;
    if (source !== "inline" && source !== "owner") throw new WriteError("field source invalid");
    // ADR-0004: the lane that skips an Approval may only add, never overwrite.
    if (source === "owner" && operation !== "create") {
      throw new WriteError("@owner 只能用于 create：修改已有值必须走审批（改用 @stdin）");
    }
    return { name, source };
  });
}

function parseValues(value: unknown, fields: ParsedWriteField[]): Map<SecretField, string> {
  const inline = fields.filter((field) => field.source === "inline").map((field) => field.name);
  const values = new Map<SecretField, string>();
  if (value === undefined) {
    if (inline.length > 0) throw new WriteError("values missing for inline fields");
    return values;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WriteError("values invalid");
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!inline.includes(key)) throw new WriteError(`values has no matching inline field: ${key.slice(0, 32)}`);
    const raw = record[key];
    if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_FIELD_VALUE_LENGTH) {
      throw new WriteError(`value for ${key} invalid`);
    }
    values.set(key, raw);
  }
  for (const name of inline) {
    if (!values.has(name)) throw new WriteError(`value missing for field: ${name}`);
  }
  return values;
}

export function parseWriteBody(value: unknown): ParsedWrite {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WriteError("request body invalid");
  const body = value as Partial<WriteRequestBody> & Record<string, unknown>;
  const requestId = String(body.request_id ?? "").toLowerCase();
  if (!UUID.test(requestId)) throw new WriteError("request_id must be a UUID");
  if (!isWriteOperation(body.operation)) throw new WriteError("operation invalid");
  const operation = body.operation;

  const reason = String(body.reason ?? "").trim();
  if (reason.length < MIN_REASON) throw new WriteError(`reason must be at least ${MIN_REASON} characters`);
  if (reason.length > MAX_REASON) throw new WriteError("reason too long");
  if (CONTROL_CHARS.test(reason)) throw new WriteError("reason invalid");

  const fields = parseFields(body.fields, operation);
  const parsed: ParsedWrite = {
    request_id: requestId,
    operation,
    item: assertItemName(body.item),
    reason,
    repo: text(body.repo, "repo", 200, true),
    host: text(body.host, "host", 200, false),
    user: text(body.user, "user", 200, false),
    agent: text(body.agent, "agent", 200, false),
    fields,
    values: parseValues(body.values, fields),
    client_id: body.client_id === undefined ? undefined : text(body.client_id, "client_id", 128, true),
  };

  if (body.description !== undefined) parsed.description = assertDescription(body.description);
  if (body.rename !== undefined) parsed.rename = assertItemName(body.rename);
  if (body.field !== undefined) {
    const field = String(body.field);
    if (!isValidFieldName(field)) throw new WriteError("field invalid");
    parsed.field = field;
  }

  if (operation === "create") {
    if (parsed.fields.length === 0) throw new WriteError("create 至少需要一个 --field");
    if (parsed.rename !== undefined) throw new WriteError("create 不接受 --rename");
    if (parsed.field !== undefined) throw new WriteError("create 不接受 --remove-field");
  } else if (operation === "update") {
    if (parsed.field !== undefined) throw new WriteError("update 不接受 --remove-field");
    // One Request changes one kind of thing, so the card is never ambiguous
    // about what it is asking the Owner to approve.
    const intents = [
      parsed.rename !== undefined,
      parsed.description !== undefined,
      parsed.fields.length > 0,
    ].filter(Boolean).length;
    if (intents === 0) throw new WriteError("update 需要 --field / --rename / --description 之一");
    if (intents > 1) throw new WriteError("update 一次只能改一类东西：字段值、条目名、描述，请分开提交");
  } else {
    if (parsed.fields.length > 0) throw new WriteError("remove 不接受 --field NAME=…");
    if (parsed.rename !== undefined) throw new WriteError("remove 不接受 --rename");
    if (parsed.description !== undefined) throw new WriteError("remove 不接受 --description");
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Item payload construction
// ---------------------------------------------------------------------------

/** Shape of `bw get template item`, so a created Item looks exactly like one
 * the official clients would make. */
export function newLoginItemPayload(
  name: string,
  description: string,
  values: Map<SecretField, string>,
): Record<string, unknown> {
  const item: Record<string, unknown> = {
    organizationId: null,
    collectionIds: null,
    folderId: null,
    type: 1,
    name,
    notes: description,
    favorite: false,
    fields: [],
    login: { uris: [], username: null, password: null, totp: null },
    reprompt: 0,
  };
  for (const [field, value] of values) setItemField(item as BwItem, field, value);
  return item;
}

/** Deep copy so a failed apply can never leave a half-mutated snapshot behind. */
export function cloneItem(item: BwItem): BwItem {
  return JSON.parse(JSON.stringify(item)) as BwItem;
}

export function setItemField(item: BwItem, field: SecretField, value: string): void {
  const target = item as Record<string, unknown>;
  if (field === "username" || field === "password") {
    const login = (item.login ?? {}) as Record<string, unknown>;
    login[field] = value;
    target.login = login;
    return;
  }
  const fields = Array.isArray(item.fields) ? item.fields : [];
  const existing = fields.find((entry) => entry?.name === field && (entry.type === 0 || entry.type === 1));
  if (existing) {
    existing.value = value;
  } else {
    // Hidden, not text: a credential should not be legible over the Owner's
    // shoulder in the vault UI by default.
    fields.push({ name: field, value, type: 1 });
  }
  target.fields = fields;
}

export function dropItemField(item: BwItem, field: SecretField): void {
  const target = item as Record<string, unknown>;
  if (field === "username" || field === "password") {
    const login = (item.login ?? {}) as Record<string, unknown>;
    login[field] = null;
    target.login = login;
    return;
  }
  target.fields = (item.fields ?? []).filter((entry) =>
    entry?.name !== field || (entry.type !== 0 && entry.type !== 1)
  );
}

function assertUniqueUsableField(itemName: string, item: BwItem, field: SecretField): void {
  if (field === "username" || field === "password") {
    const value = item.login?.[field];
    if (typeof value === "string" && value.length > 0) return;
  } else {
    const matches = (item.fields ?? []).filter((entry) =>
      entry?.name === field && (entry.type === 0 || entry.type === 1)
    );
    if (matches.length === 1) return;
  }
  throw new WriteError(`条目 "${itemName}" 的字段 ${field} 重名或不可用`, 409);
}

// ---------------------------------------------------------------------------
// Broker
// ---------------------------------------------------------------------------

export type EntryPayload = {
  parsed: ParsedWrite;
  client: AuthedClient;
  /** null -> a brand new Item; otherwise the Item the Fields are added to. */
  existing_item_id: string | null;
};

export type WriteBrokerDeps = {
  vault: Vault;
  grants: GrantStore;
  approver: Approver;
  approvalTimeoutMs: number;
  entryTtlMs: number;
  now?: () => number;
  log?: (message: string) => void;
};

export class WriteBroker {
  private readonly deps: WriteBrokerDeps;
  private readonly now: () => number;
  private readonly log: (message: string) => void;
  /** One in-flight write per normalized Item name: "check then create" must
   * be atomic, and a rename holds both its source and target names. */
  private readonly locks = new Map<string, Promise<unknown>>();
  readonly entries: EntryStore<EntryPayload>;

  constructor(deps: WriteBrokerDeps) {
    this.deps = deps;
    this.now = deps.now ?? Date.now;
    this.log = deps.log ?? (() => {});
    this.entries = new EntryStore<EntryPayload>({
      now: this.now,
      onExpire: (draft) => {
        const payload = draft.payload as EntryPayload;
        void this.deps.approver.notifyWrite({
          id: payload.parsed.request_id,
          headline: `录入链接已过期，未写入：${draft.item}`,
          lines: [
            { label: "待填字段", value: draft.owner_fields.join("、"), plain: true },
            { label: "理由", value: payload.parsed.reason, plain: true },
          ],
          repo: payload.parsed.repo,
          host: payload.parsed.host,
          user: payload.parsed.user,
          agent: payload.parsed.agent || undefined,
          client_name: payload.client.name,
        });
      },
    });
  }

  /** Serialize by Item name so check-then-write is atomic within the broker. */
  private async withItemLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const key = name.normalize("NFKC").toLowerCase();
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.then(fn, fn);
    const settled = run.then(() => undefined, () => undefined);
    this.locks.set(key, settled);
    try {
      return await run;
    } finally {
      // Only the last waiter clears the slot, so a queued write is never
      // orphaned by an earlier one finishing.
      if (this.locks.get(key) === settled) this.locks.delete(key);
    }
  }

  /** Acquire multiple name locks in one canonical order, avoiding deadlock
   * when concurrent renames have overlapping source and target names. */
  private withItemLocks<T>(names: string[], fn: () => Promise<T>): Promise<T> {
    const keys = [...new Set(names.map((name) => name.normalize("NFKC").toLowerCase()))].sort();
    const acquire = (index: number): Promise<T> => {
      const key = keys[index];
      return key === undefined ? fn() : this.withItemLock(key, () => acquire(index + 1));
    };
    return acquire(0);
  }

  handle(body: unknown, client: AuthedClient): Promise<WriteResult> {
    const parsed = parseWriteBody(body);
    if (parsed.client_id && parsed.client_id !== client.client_id) {
      throw new WriteError("client_id does not match the authenticated client", 403);
    }
    const lockNames = parsed.operation === "update" && parsed.rename !== undefined
      ? [parsed.item, parsed.rename]
      : [parsed.item];
    return this.withItemLocks(lockNames, async () => {
      if (parsed.operation === "create") return this.create(parsed, client);
      if (parsed.operation === "update") return this.update(parsed, client);
      return this.remove(parsed, client);
    });
  }

  // -- create ---------------------------------------------------------------

  private async create(parsed: ParsedWrite, client: AuthedClient): Promise<WriteResult> {
    const snapshots = await this.deps.vault.findItemsByName(parsed.item);
    let existing: VaultItemSnapshot | null = null;

    if (parsed.description !== undefined) {
      // New-Item intent. A taken name is an error, never a silent success: the
      // Item behind it may be a stranger's (ADR-0005).
      if (snapshots.length > 0) {
        throw new WriteError(
          `条目 "${parsed.item}" 已存在。如果这是重试，说明上一次已经写入成功；` +
            `请先 list 看它的描述和创建时间确认。若要给它增加字段，去掉 --description 重试；` +
            `若这是另一个东西，请换一个条目名。`,
          409,
        );
      }
    } else {
      // New-Field intent.
      if (snapshots.length === 0) {
        throw new WriteError(`条目 "${parsed.item}" 不存在。若要新建条目，请加上 --description。`, 404);
      }
      if (snapshots.length > 1) throw new WriteError(ambiguous(parsed.item), 409);
      existing = snapshots[0]!;
      for (const field of parsed.fields) {
        if (existing.field_names.includes(field.name)) {
          throw new WriteError(
            `条目 "${parsed.item}" 已有字段 ${field.name}。如果这是重试，说明上一次已经写入成功；` +
              `若要改它的值请用 update。`,
            409,
          );
        }
      }
    }

    const ownerFields = parsed.fields.filter((field) => field.source === "owner").map((field) => field.name);
    if (ownerFields.length > 0) return this.mintEntry(parsed, client, existing, ownerFields);

    const fingerprint = makeFingerprinter();
    const card = this.card(parsed, client, existing ? "create_field" : "create_item", [
      ...(parsed.description !== undefined
        ? [{ label: "描述", value: parsed.description, plain: true } as WriteCardLine]
        : []),
      ...parsed.fields.map((field) => ({
        label: `字段 ${field.name}`,
        value: fingerprint(parsed.values.get(field.name)!),
      })),
    ], []);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    let latest = existing;
    if (existing) {
      latest = await this.latestItemForApply(parsed.item, existing.item_id);
      for (const field of parsed.fields) {
        if (latest.field_names.includes(field.name)) throw changedDuringApproval(parsed.item, `字段 ${field.name}`);
      }
    } else if ((await this.deps.vault.findItemsByName(parsed.item)).length > 0) {
      throw changedDuringApproval(parsed.item);
    }
    await this.applyCreate(parsed, latest, parsed.values);
    return {
      status: "applied",
      operation: "create",
      item: parsed.item,
      detail: existing
        ? `已在 ${parsed.item} 上新增字段：${parsed.fields.map((f) => f.name).join("、")}`
        : `已新建条目 ${parsed.item}`,
    };
  }

  private async applyCreate(
    parsed: ParsedWrite,
    existing: VaultItemSnapshot | null,
    values: Map<SecretField, string>,
  ): Promise<void> {
    if (!existing) {
      await this.deps.vault.createItem(newLoginItemPayload(parsed.item, parsed.description ?? "", values));
      return;
    }
    const draft = cloneItem(existing.raw);
    for (const [field, value] of values) setItemField(draft, field, value);
    await this.deps.vault.replaceItem(existing.item_id, draft);
  }

  private mintEntry(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot | null,
    ownerFields: SecretField[],
  ): WriteResult {
    const nonce = mintEntryNonce();
    const expiresAt = this.now() + this.deps.entryTtlMs;
    this.entries.put({
      nonce,
      expires_at: expiresAt,
      item: parsed.item,
      description: parsed.description ?? existing?.description ?? "",
      owner_fields: ownerFields,
      inline_fields: parsed.fields.filter((f) => f.source === "inline").map((f) => f.name),
      payload: { parsed, client, existing_item_id: existing?.item_id ?? null },
    });
    // The nonce is the capability: it never appears in a log line.
    this.log(`write ${parsed.request_id}: entry link issued for "${parsed.item}" (${client.name})`);
    return {
      status: "pending_entry",
      entry_path: `${ENTRY_PATH_PREFIX}${nonce}`,
      expires_at: new Date(expiresAt).toISOString(),
      fields: ownerFields,
    };
  }

  /** Complete a Create from the Entry Form. Re-checks state: time has passed. */
  async submitEntry(draft: EntryDraft<EntryPayload>, ownerValues: Map<SecretField, string>): Promise<void> {
    const { parsed, client } = draft.payload;
    for (const field of draft.owner_fields) {
      const value = ownerValues.get(field);
      if (!value || value.length > MAX_FIELD_VALUE_LENGTH) throw new WriteError(`字段 ${field} 未填写`);
    }
    await this.withItemLock(parsed.item, async () => {
      const snapshots = await this.deps.vault.findItemsByName(parsed.item);
      let existing: VaultItemSnapshot | null = null;
      if (draft.payload.existing_item_id === null) {
        if (snapshots.length > 0) throw new WriteError(`条目 "${parsed.item}" 在此期间已经被创建了`, 409);
      } else {
        existing = snapshots.find((item) => item.item_id === draft.payload.existing_item_id) ?? null;
        if (!existing) throw new WriteError(`条目 "${parsed.item}" 已不在原处`, 409);
        for (const field of parsed.fields) {
          if (existing.field_names.includes(field.name)) {
            throw new WriteError(`条目 "${parsed.item}" 在此期间已经有了字段 ${field.name}`, 409);
          }
        }
      }
      const values = new Map(parsed.values);
      for (const [field, value] of ownerValues) values.set(field, value);
      await this.applyCreate(parsed, existing, values);
    });

    // Nothing changes the vault silently: this write had no blocking Approval,
    // so the Owner gets the record afterwards (ADR-0004).
    const fingerprint = makeFingerprinter();
    const note: WriteNote = {
      id: parsed.request_id,
      headline: draft.payload.existing_item_id === null
        ? `已通过录入表单新建条目：${parsed.item}`
        : `已通过录入表单新增字段：${parsed.item}`,
      lines: [
        ...(draft.description ? [{ label: "描述", value: draft.description, plain: true }] : []),
        ...draft.owner_fields.map((field) => ({
          label: `字段 ${field}（你填写）`,
          value: fingerprint(ownerValues.get(field)!),
        })),
        ...draft.inline_fields.map((field) => ({
          label: `字段 ${field}（agent 提供）`,
          value: fingerprint(parsed.values.get(field)!),
        })),
        { label: "理由", value: parsed.reason, plain: true },
      ],
      repo: parsed.repo,
      host: parsed.host,
      user: parsed.user,
      agent: parsed.agent || undefined,
      client_name: client.name,
    };
    try {
      void this.deps.approver.notifyWrite(note).catch(() => {
        this.log(`write ${parsed.request_id}: entry form completion notification failed`);
      });
    } catch {
      this.log(`write ${parsed.request_id}: entry form completion notification failed`);
    }
    this.log(`write ${parsed.request_id}: entry form applied for "${parsed.item}"`);
  }

  // -- update ---------------------------------------------------------------

  private async update(parsed: ParsedWrite, client: AuthedClient): Promise<WriteResult> {
    const snapshots = await this.deps.vault.findItemsByName(parsed.item);
    if (snapshots.length === 0) throw new WriteError(`条目 "${parsed.item}" 不存在`, 404);
    if (snapshots.length > 1) throw new WriteError(ambiguous(parsed.item), 409);
    const existing = snapshots[0]!;

    if (parsed.rename !== undefined) return this.updateRename(parsed, client, existing);
    if (parsed.description !== undefined) return this.updateDescription(parsed, client, existing);
    return this.updateValues(parsed, client, existing);
  }

  private async updateRename(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot,
  ): Promise<WriteResult> {
    const target = parsed.rename!;
    if (existing.name === target) {
      return { status: "unchanged", operation: "update", item: parsed.item, detail: "条目名已经是目标值" };
    }
    const clash = await this.deps.vault.findItemsByName(target);
    if (clash.length > 0) throw new WriteError(`条目 "${target}" 已存在，改名会造成重名`, 409);

    // Grants survive a rename (they are keyed by item id, not name) -- which is
    // right, and exactly why this looks harmless and is not: every caller still
    // using the old name starts failing to resolve it.
    const affected = this.deps.grants.activeForItem(existing.item_id);
    const card = this.card(parsed, client, "update_rename", [
      { label: "旧名", value: existing.name, plain: true },
      { label: "新名", value: target, plain: true },
    ], affected.length > 0
      ? [`${affected.length} 条现有授权会保留（按条目 id 绑定），但任何仍用旧名调用的 agent 会开始报「找不到条目」`]
      : []);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    const latest = await this.latestItemForApply(parsed.item, existing.item_id);
    if ((await this.deps.vault.findItemsByName(target)).length > 0) {
      throw changedDuringApproval(parsed.item, `改名目标 ${target}`);
    }
    const draft = cloneItem(latest.raw);
    (draft as Record<string, unknown>).name = target;
    await this.deps.vault.replaceItem(existing.item_id, draft);
    return { status: "applied", operation: "update", item: parsed.item, detail: `已改名为 ${target}` };
  }

  private async updateDescription(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot,
  ): Promise<WriteResult> {
    const target = parsed.description!;
    if (existing.description === target) {
      return { status: "unchanged", operation: "update", item: parsed.item, detail: "描述已经是目标值" };
    }
    // Descriptions are not credentials, so the Owner gets the actual diff
    // rather than a Fingerprint they could not act on.
    const card = this.card(parsed, client, "update_description", [
      { label: "现描述", value: existing.description || "（空）", plain: true },
      { label: "新描述", value: target, plain: true },
    ], []);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    const latest = await this.latestItemForApply(parsed.item, existing.item_id);
    if (latest.description !== target) {
      if (latest.description !== existing.description) throw changedDuringApproval(parsed.item, "描述");
      const draft = cloneItem(latest.raw);
      (draft as Record<string, unknown>).notes = target;
      await this.deps.vault.replaceItem(existing.item_id, draft);
    }
    return { status: "applied", operation: "update", item: parsed.item, detail: "已更新描述" };
  }

  private async updateValues(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot,
  ): Promise<WriteResult> {
    for (const field of parsed.fields) {
      if (!existing.field_names.includes(field.name)) {
        throw new WriteError(
          `条目 "${parsed.item}" 没有字段 ${field.name}。新增字段请用 create（不带 --description）。`,
          404,
        );
      }
      assertUniqueUsableField(parsed.item, existing.raw, field.name);
    }
    const pending = parsed.fields.filter((field) =>
      itemFieldValue(existing.raw, field.name) !== parsed.values.get(field.name)
    );
    if (pending.length === 0) {
      return {
        status: "unchanged",
        operation: "update",
        item: parsed.item,
        detail: `字段已经是目标值：${parsed.fields.map((f) => f.name).join("、")}`,
      };
    }
    const fingerprint = makeFingerprinter();
    const card = this.card(parsed, client, "update_value", pending.map((field) => {
      const before = itemFieldValue(existing.raw, field.name);
      return {
        label: `字段 ${field.name}`,
        value: `${before ? fingerprint(before) : "（空）"} -> ${fingerprint(parsed.values.get(field.name)!)}`,
      };
    }), []);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    const latest = await this.latestItemForApply(parsed.item, existing.item_id);
    let changed = false;
    const draft = cloneItem(latest.raw);
    for (const field of parsed.fields) {
      assertUniqueUsableField(parsed.item, latest.raw, field.name);
      const before = itemFieldValue(existing.raw, field.name);
      const current = itemFieldValue(latest.raw, field.name);
      const target = parsed.values.get(field.name)!;
      if (current === target) continue;
      if (current !== before) throw changedDuringApproval(parsed.item, `字段 ${field.name}`);
      setItemField(draft, field.name, target);
      changed = true;
    }
    if (changed) await this.deps.vault.replaceItem(existing.item_id, draft);
    return {
      status: "applied",
      operation: "update",
      item: parsed.item,
      detail: `已更新字段：${pending.map((f) => f.name).join("、")}`,
    };
  }

  // -- remove ---------------------------------------------------------------

  private async remove(parsed: ParsedWrite, client: AuthedClient): Promise<WriteResult> {
    const snapshots = await this.deps.vault.findItemsByName(parsed.item);
    if (snapshots.length === 0) {
      return { status: "unchanged", operation: "remove", item: parsed.item, detail: "条目已不在 vault 中" };
    }
    if (snapshots.length > 1) throw new WriteError(ambiguous(parsed.item), 409);
    const existing = snapshots[0]!;
    return parsed.field === undefined
      ? this.removeItem(parsed, client, existing)
      : this.removeField(parsed, client, existing, parsed.field);
  }

  private async removeItem(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot,
  ): Promise<WriteResult> {
    const affected = this.deps.grants.activeForItem(existing.item_id);
    const card = this.card(parsed, client, "remove_item", [
      { label: "包含字段", value: existing.field_names.join("、") || "（无）", plain: true },
      { label: "描述", value: existing.description || "（空）", plain: true },
    ], [
      "条目会进入 vault 回收站，可以恢复；但下面被吊销的授权不会随之恢复，需要重新审批。",
      ...(affected.length > 0
        ? [`将吊销 ${affected.length} 条授权，涉及 ${new Set(affected.map((g) => g.repo)).size} 个仓库`]
        : []),
    ]);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    const latest = await this.latestItemForApply(parsed.item, existing.item_id);
    // Revoke first so a vault failure can only leave the safer state: the Item
    // still exists, but using it needs a new Approval. Revoking after trashing
    // could strand live grants with no Item identity available to a retry.
    let revoked = this.deps.grants.revokeForItem(existing.item_id);
    await this.deps.vault.trashItem(latest.item_id);
    // Close the mutation window: a read may have resolved the still-visible
    // Item after the first revocation. This second generation bump invalidates
    // its snapshot and deletes any Grant it managed to save before trashing
    // completed.
    revoked += this.deps.grants.revokeForItem(existing.item_id);
    return {
      status: "applied",
      operation: "remove",
      item: parsed.item,
      detail: `已删除条目 ${parsed.item}（回收站可恢复）；吊销 ${revoked} 条授权`,
    };
  }

  private async removeField(
    parsed: ParsedWrite,
    client: AuthedClient,
    existing: VaultItemSnapshot,
    field: SecretField,
  ): Promise<WriteResult> {
    if (!existing.field_names.includes(field)) {
      return { status: "unchanged", operation: "remove", item: parsed.item, detail: `字段 ${field} 已不在条目上` };
    }
    assertUniqueUsableField(parsed.item, existing.raw, field);
    const current = itemFieldValue(existing.raw, field);
    const affected = this.deps.grants.activeForItem(existing.item_id, field);
    const fingerprint = makeFingerprinter();
    const card = this.card(parsed, client, "remove_field", [
      { label: "字段", value: field, plain: true },
      { label: "当前值", value: current ? fingerprint(current) : "（空）" },
    ], [
      "字段删除不可恢复：vault 不为字段保留历史值，删掉就没有了。",
      ...(affected.length > 0 ? [`将吊销 ${affected.length} 条授权`] : []),
    ]);
    const decision = await this.decide(card);
    if (!decision.ok) return decision.result;

    const latest = await this.latestItemForApply(parsed.item, existing.item_id);
    let draft: BwItem | undefined;
    if (latest.field_names.includes(field)) {
      assertUniqueUsableField(parsed.item, latest.raw, field);
      const latestValue = itemFieldValue(latest.raw, field);
      if (latestValue !== current) throw changedDuringApproval(parsed.item, `字段 ${field}`);
      draft = cloneItem(latest.raw);
      dropItemField(draft, field);
    }
    // As with whole-Item removal, fail safe: losing authorization early can be
    // recovered through Approval, while a stale grant after deletion cannot.
    let revoked = this.deps.grants.revokeForItem(existing.item_id, field);
    if (draft) {
      await this.deps.vault.replaceItem(existing.item_id, draft);
      // As above, invalidate reads that resolved the Field while replacement
      // was in flight and remove any Grant saved during that interval.
      revoked += this.deps.grants.revokeForItem(existing.item_id, field);
    }
    return {
      status: "applied",
      operation: "remove",
      item: parsed.item,
      detail: `已删除字段 ${field}（不可恢复）；吊销 ${revoked} 条授权`,
    };
  }

  // -- shared ---------------------------------------------------------------

  private async latestItemForApply(item: string, itemId: string): Promise<VaultItemSnapshot> {
    const snapshots = await this.deps.vault.findItemsByName(item);
    if (snapshots.length !== 1 || snapshots[0]!.item_id !== itemId) {
      throw changedDuringApproval(item);
    }
    return snapshots[0]!;
  }

  private card(
    parsed: ParsedWrite,
    client: AuthedClient,
    kind: WriteCardKind,
    lines: WriteCardLine[],
    warnings: string[],
  ): WriteCard {
    return {
      id: parsed.request_id,
      kind,
      item: parsed.item,
      reason: parsed.reason,
      lines,
      warnings,
      repo: parsed.repo,
      host: parsed.host,
      user: parsed.user,
      agent: parsed.agent || undefined,
      client_name: client.name,
      expires_at: new Date(this.now() + this.deps.approvalTimeoutMs).toISOString(),
    };
  }

  private async decide(card: WriteCard): Promise<{ ok: true } | { ok: false; result: WriteResult }> {
    this.log(`write ${card.id}: awaiting approval (${card.kind} "${card.item}")`);
    const decision = await this.deps.approver.requestWriteApproval(card, this.deps.approvalTimeoutMs);
    if (decision.approved) return { ok: true };
    this.log(`write ${card.id}: ${decision.reason}`);
    return { ok: false, result: { status: "rejected", reason: decision.reason } };
  }
}

function ambiguous(item: string): string {
  return `vault 中有多个名为 "${item}" 的条目，无法定位；请先在 vault 里消除重名。`;
}

function changedDuringApproval(item: string, target = "条目"): WriteError {
  return new WriteError(`${target}在审批期间已发生变化（${item}），请重新提交以审批最新状态`, 409);
}
