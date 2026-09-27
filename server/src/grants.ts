// Bitwarden secret-use grants, persisted in SQLite.
//
// Stores only "which caller/client/repo was approved to use which item's
// which field" — never credential values, Bitwarden sessions, or request
// refs. On a grant hit the worker still re-reads the vault.
//
// Since v3 one row = one (caller, client, repo, item_id, field), so
// authorization is containment matching: after approving {A,B}, a later
// request for just {A} hits directly. Item identity is the bare item_id
// without revision, so rotating a password / editing notes does not revoke
// grants by association (per-request revision tamper checks stay elsewhere).
//
// Each row carries two independent expiries: `expires_at` covers ordinary
// commands, `inline_expires_at` covers inline code (ADR-0009). Inline
// permission is the wider one — it also covers ordinary commands — but
// neither approval path ever moves the other's expiry.
//
// Ported from the Windmill grant_store.ts reference (Postgres DataTable)
// to bun:sqlite. Timestamps are stored as unix milliseconds and exposed as
// ISO strings.

import type { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import {
  isSecretGrantTtl,
  type SecretField,
  type SecretGrantTtl,
  secretGrantTtlHours,
} from "./types.ts";
import type { GrantListEntry } from "./approver.ts";
import { isValidFieldName } from "./vault.ts";

export const SECRET_GRANT_TABLE = "secret_grants";
export const SECRET_SIGHTING_TABLE = "secret_command_sightings";
export const REVOKE_HANDLE_TABLE = "secret_revoke_handles";
export const GRANT_REVOCATION_TABLE = "secret_grant_revocations";

/** Empty is not a valid Field name, so it safely represents the whole Item. */
const ITEM_REVOCATION_SCOPE = "";

/** Sightings only answer "have we seen this command"; 90 days covers the
 * reuse window of the longest 30d grant. */
export const SIGHTING_RETENTION_DAYS = 90;
const SIGHTING_RETENTION_MS = SIGHTING_RETENTION_DAYS * 24 * 60 * 60 * 1000;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/** Stable identity of a call; grants and sightings both hang off it. */
export type SecretGrantIdentity = {
  caller_id: string;
  client_id: string;
  repo: string;
};

/** Smallest grantable unit: one field of one Bitwarden item. */
export type SecretGrantUnit = {
  item_id: string;
  field: SecretField;
};

export type SecretGrant = SecretGrantUnit & {
  grant_key: string;
  caller_id: string;
  client_id: string;
  repo: string;
  ttl: SecretGrantTtl;
  approval_id: string;
  /**
   * ISO timestamp: until when ordinary (non-inline) commands are covered on
   * their own. A row minted by an inline approval starts at the epoch — it has
   * no ordinary-only permission, only the wider inline one.
   */
  expires_at: string;
  /** ISO timestamp: until when inline code is covered. Absent = never granted or revoked. */
  inline_expires_at?: string;
  decided_by?: string;
  /** ISO timestamp. */
  decided_at?: string;
};

/** Generations captured after vault resolution and checked when Approval settles. */
export type GrantRevocationSnapshot = ReadonlyMap<string, number>;

export class GrantRevokedDuringApprovalError extends Error {
  constructor() {
    super("审批期间条目或字段已被移除，请重新发起请求");
    this.name = "GrantRevokedDuringApprovalError";
  }
}

function revocationKey(itemId: string, field: string): string {
  return `${itemId}\0${field}`;
}

export function assertSecretClientId(value: string): string {
  const clientId = String(value || "").trim();
  // Relaxed from the reference's {8,128}: client names can be short.
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(clientId)) throw new Error("invalid client_id");
  return clientId;
}

export function assertSecretRepo(value: string): string {
  const repo = String(value || "").trim();
  if (!repo || repo.length > 200 || CONTROL_CHARACTERS.test(repo)) throw new Error("invalid repo");
  return repo;
}

export function assertSecretItemId(value: string): string {
  const itemId = String(value || "").trim();
  if (!/^[A-Za-z0-9-]{8,128}$/.test(itemId)) throw new Error("invalid grant item_id");
  return itemId;
}

function assertSecretField(value: string): SecretField {
  // "username", "password", or a custom field name (see vault.ts FIELD_NAME).
  if (!isValidFieldName(value)) throw new Error("invalid grant field");
  return value;
}

function normalizeIdentity(identity: SecretGrantIdentity): SecretGrantIdentity {
  return {
    caller_id: assertSecretClientId(identity.caller_id),
    client_id: assertSecretClientId(identity.client_id),
    repo: assertSecretRepo(identity.repo),
  };
}

/**
 * Primary key of one grant unit.
 *
 * Deliberately excludes the env alias and revision: env is only a local
 * alias — renaming it does not change the value released; a revision change
 * means a rotated password, which is a new value of the same authorization
 * object, not a new authorization object.
 */
export function secretGrantKey(identity: SecretGrantIdentity, unit: SecretGrantUnit): string {
  const scope = normalizeIdentity(identity);
  return createHash("sha256").update(JSON.stringify({
    v: 3,
    caller_id: scope.caller_id,
    client_id: scope.client_id,
    repo: scope.repo,
    item_id: assertSecretItemId(unit.item_id),
    field: assertSecretField(unit.field),
  })).digest("hex");
}

export function assertSecretGrantKey(value: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("invalid grant_key");
  return value;
}

/** Command fingerprint hashes argv only: swapping env aliases must not read
 * as a "new command" that bothers the user. */
export function commandFingerprint(argv: string[]): string {
  if (!Array.isArray(argv) || argv.length === 0) throw new Error("invalid command argv");
  return createHash("sha256").update(JSON.stringify(argv)).digest("hex");
}

/**
 * Sighting key = identity + command fingerprint + authorization-unit set.
 *
 * The unit set (grant keys — item AND field) is included to catch "this
 * command got this key for the first time" — the same command picking up a
 * higher-privilege key, or a different field of the same item, is a new fact
 * worth knowing; mere repetition is not.
 */
export function commandSightingKey(
  identity: SecretGrantIdentity,
  commandHash: string,
  unitKeys: string[],
): string {
  const scope = normalizeIdentity(identity);
  if (typeof commandHash !== "string" || !/^[a-f0-9]{64}$/.test(commandHash)) {
    throw new Error("invalid command_hash");
  }
  const units = [...new Set((unitKeys || []).map((key) => {
    const unit = String(key || "").trim();
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(unit)) throw new Error("invalid sighting unit key");
    return unit;
  }))].sort();
  if (units.length === 0 || units.length > 40) throw new Error("invalid sighting unit count");
  return createHash("sha256").update(JSON.stringify({
    v: 1,
    caller_id: scope.caller_id,
    client_id: scope.client_id,
    repo: scope.repo,
    command_hash: commandHash,
    items: units,
  })).digest("hex");
}

type GrantRow = {
  grant_key: string;
  caller_id: string;
  client_id: string;
  repo: string;
  item_id: string;
  field: string;
  ttl: string;
  approval_id: string;
  decided_by: string | null;
  decided_at: string | null;
  expires_at: number;
  inline_expires_at: number | null;
};

const GRANT_COLUMNS = `grant_key, caller_id, client_id, repo, item_id, field, ttl, approval_id,
              decided_by, decided_at, expires_at, inline_expires_at`;

/** A row still authorizes something while either of its expiries lies ahead. */
const ROW_ALIVE = "(expires_at > ? OR inline_expires_at > ?)";

/**
 * Until when this grant covers a Request of the given kind, or null if it does
 * not. Inline code needs the inline expiry; an ordinary command is covered by
 * either, because permission to run arbitrary inline code with a secret
 * already contains permission to run a named command with it.
 */
export function grantCoverageExpiry(grant: SecretGrant, inline: boolean, nowMs: number): string | null {
  const normal = Date.parse(grant.expires_at);
  const inlineMs = grant.inline_expires_at ? Date.parse(grant.inline_expires_at) : 0;
  const until = inline ? inlineMs : Math.max(normal, inlineMs);
  return until > nowMs ? new Date(until).toISOString() : null;
}

/** One Owner decision as it stands now: the live rows it last touched. */
export type ActiveApprovalGrants = {
  approval_id: string;
  caller_id: string;
  client_id: string;
  repo: string;
  units: SecretGrantUnit[];
  /** Earliest live ordinary expiry across the units; absent when none is live. */
  expires_at?: string;
  /** Earliest live inline expiry across the units; absent when none is live. */
  inline_expires_at?: string;
};

function rowToGrant(row: GrantRow): SecretGrant {
  if (!isSecretGrantTtl(row.ttl)) throw new Error("invalid grant ttl");
  return {
    grant_key: row.grant_key,
    caller_id: row.caller_id,
    client_id: row.client_id,
    repo: row.repo,
    item_id: assertSecretItemId(row.item_id),
    field: assertSecretField(row.field),
    ttl: row.ttl,
    approval_id: row.approval_id,
    expires_at: new Date(row.expires_at).toISOString(),
    ...(row.inline_expires_at === null
      ? {}
      : { inline_expires_at: new Date(row.inline_expires_at).toISOString() }),
    decided_by: row.decided_by ?? undefined,
    decided_at: row.decided_at ?? undefined,
  };
}

export class GrantStore {
  private readonly db: Database;
  private readonly now: () => number;

  constructor(db: Database, now: () => number = Date.now) {
    this.db = db;
    this.now = now;
    this.ensureTables();
    this.sweep();
  }

  private ensureTables(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS ${SECRET_GRANT_TABLE} (
        grant_key TEXT PRIMARY KEY,
        caller_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        repo TEXT NOT NULL,
        item_id TEXT NOT NULL,
        field TEXT NOT NULL,
        ttl TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        decided_by TEXT,
        decided_at TEXT,
        expires_at INTEGER NOT NULL,
        inline_expires_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    // Databases created before inline grants existed lack the column; adding
    // it NULL everywhere is exactly "no inline permission", so no backfill.
    const columns = this.db
      .query<{ name: string }, []>(`PRAGMA table_info(${SECRET_GRANT_TABLE})`)
      .all();
    if (!columns.some((column) => column.name === "inline_expires_at")) {
      this.db.run(`ALTER TABLE ${SECRET_GRANT_TABLE} ADD COLUMN inline_expires_at INTEGER`);
    }
    this.db.run(
      `CREATE INDEX IF NOT EXISTS secret_grants_expires_at_idx ON ${SECRET_GRANT_TABLE} (expires_at)`,
    );
    this.db.run(`
      CREATE TABLE IF NOT EXISTS ${SECRET_SIGHTING_TABLE} (
        sighting_key TEXT PRIMARY KEY,
        caller_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        repo TEXT NOT NULL,
        command_hash TEXT NOT NULL,
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
      )
    `);
    // Durable mapping behind Sighting revoke buttons: the Telegram
    // callback_data carries only a short handle (64-byte cap), the grant keys
    // live here — so the button keeps working across broker restarts.
    this.db.run(`
      CREATE TABLE IF NOT EXISTS ${REVOKE_HANDLE_TABLE} (
        handle TEXT PRIMARY KEY,
        grant_keys TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);
    // A generation is advanced before a destructive vault mutation. Pending
    // reads carry the generations they observed after name resolution, so a
    // late Approval cannot recreate a Grant for a removed Item or Field.
    this.db.run(`
      CREATE TABLE IF NOT EXISTS ${GRANT_REVOCATION_TABLE} (
        item_id TEXT NOT NULL,
        field TEXT NOT NULL,
        generation INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (item_id, field)
      )
    `);
  }

  /** Persist the handle → grant-keys mapping for a Sighting's revoke button. */
  saveRevokeHandle(handle: string, grantKeys: string[]): void {
    const keys = [...new Set((grantKeys || []).map(assertSecretGrantKey))];
    if (!/^[A-Za-z0-9-]{8,80}$/.test(handle)) throw new Error("invalid revoke handle");
    if (keys.length === 0 || keys.length > 40) throw new Error("invalid revoke handle key count");
    this.db.run(
      `INSERT INTO ${REVOKE_HANDLE_TABLE} (handle, grant_keys, created_at) VALUES (?, ?, ?)
       ON CONFLICT(handle) DO UPDATE SET grant_keys = excluded.grant_keys`,
      [handle, JSON.stringify(keys), this.now()],
    );
  }

  private handleKeys(handle: string): string[] | null {
    if (!/^[A-Za-z0-9-]{8,80}$/.test(handle)) return null;
    const row = this.db
      .query<{ grant_keys: string }, [string]>(
        `SELECT grant_keys FROM ${REVOKE_HANDLE_TABLE} WHERE handle = ?`,
      )
      .get(handle);
    if (!row) return null;
    try {
      return (JSON.parse(row.grant_keys) as string[]).map(assertSecretGrantKey);
    } catch {
      return null;
    }
  }

  /** Resolve a revoke handle and delete its grant rows. Null = unknown handle. */
  revokeByHandle(handle: string): number | null {
    const keys = this.handleKeys(handle);
    return keys ? this.revoke(keys) : null;
  }

  /** Resolve a revoke handle and clear only the inline permission of its rows. */
  revokeInlineByHandle(handle: string): number | null {
    const keys = this.handleKeys(handle);
    return keys ? this.revokeInline(keys) : null;
  }

  /**
   * Containment-matching read side: query all requested units at once; a
   * request only counts as a hit when every unit hits. The caller gets a
   * key -> grant map of rows alive under EITHER expiry; whether a row covers
   * a given Request is grantCoverageExpiry's call, since that depends on
   * whether the command is inline.
   */
  findActive(grantKeys: string[]): Map<string, SecretGrant> {
    const keys = [...new Set((grantKeys || []).map(assertSecretGrantKey))];
    if (keys.length === 0 || keys.length > 20) throw new Error("invalid grant_key count");
    const placeholders = keys.map(() => "?").join(", ");
    const nowMs = this.now();
    const rows = this.db.query<GrantRow, [...string[], number, number]>(
      `SELECT ${GRANT_COLUMNS}
         FROM ${SECRET_GRANT_TABLE}
        WHERE grant_key IN (${placeholders}) AND ${ROW_ALIVE}`,
    ).all(...keys, nowMs, nowMs);
    const found = new Map<string, SecretGrant>();
    for (const row of rows) {
      const grant = rowToGrant(row);
      found.set(grant.grant_key, grant);
    }
    return found;
  }

  /**
   * Live grants naming this Item, optionally narrowed to one Field.
   *
   * The write path needs this twice: to put a destructive Write Request's blast
   * radius on the approval card, and to clear the rows afterwards. Unlike
   * findActive it is keyed by the Item itself, because a Remove has no grant
   * keys to look up — it is destroying the thing they point at.
   */
  activeForItem(itemId: string, field?: string): SecretGrant[] {
    const item = assertSecretItemId(itemId);
    const nowMs = this.now();
    const rows = field === undefined
      ? this.db.query<GrantRow, [string, number, number]>(
        `SELECT ${GRANT_COLUMNS}
           FROM ${SECRET_GRANT_TABLE}
          WHERE item_id = ? AND ${ROW_ALIVE}`,
      ).all(item, nowMs, nowMs)
      : this.db.query<GrantRow, [string, string, number, number]>(
        `SELECT ${GRANT_COLUMNS}
           FROM ${SECRET_GRANT_TABLE}
          WHERE item_id = ? AND field = ? AND ${ROW_ALIVE}`,
      ).all(item, assertSecretField(field), nowMs, nowMs);
    return rows.map(rowToGrant);
  }

  /** Snapshot the durable generations a pending Approval is allowed to save against. */
  snapshotRevocations(units: SecretGrantUnit[]): GrantRevocationSnapshot {
    if (!Array.isArray(units) || units.length === 0 || units.length > 20) {
      throw new Error("invalid grant unit count");
    }
    const generation = this.db.query<{ generation: number }, [string, string]>(
      `SELECT generation FROM ${GRANT_REVOCATION_TABLE} WHERE item_id = ? AND field = ?`,
    );
    const snapshot = new Map<string, number>();
    for (const unit of units) {
      const itemId = assertSecretItemId(unit.item_id);
      const field = assertSecretField(unit.field);
      for (const scope of [ITEM_REVOCATION_SCOPE, field]) {
        const key = revocationKey(itemId, scope);
        if (!snapshot.has(key)) snapshot.set(key, generation.get(itemId, scope)?.generation ?? 0);
      }
    }
    return snapshot;
  }

  /**
   * Advance the revocation generation and delete matching rows atomically.
   *
   * Advancing first prevents an Approval that was already pending from writing
   * a Grant after this deletion. The marker persists across broker restarts and
   * Bitwarden trash restoration; a fresh Request captures the new generation.
   */
  revokeForItem(itemId: string, field?: string): number {
    const item = assertSecretItemId(itemId);
    const scope = field === undefined ? ITEM_REVOCATION_SCOPE : assertSecretField(field);
    const revoke = this.db.transaction(() => {
      this.db.run(
        `INSERT INTO ${GRANT_REVOCATION_TABLE} (item_id, field, generation, updated_at)
         VALUES (?, ?, 1, ?)
         ON CONFLICT(item_id, field) DO UPDATE SET
           generation = ${GRANT_REVOCATION_TABLE}.generation + 1,
           updated_at = excluded.updated_at`,
        [item, scope, this.now()],
      );
      const result = field === undefined
        ? this.db.run(`DELETE FROM ${SECRET_GRANT_TABLE} WHERE item_id = ?`, [item])
        : this.db.run(
          `DELETE FROM ${SECRET_GRANT_TABLE} WHERE item_id = ? AND field = ?`,
          [item, scope],
        );
      return result.changes;
    });
    return revoke.immediate();
  }

  /**
   * Write side: one approval writes one row per grant unit.
   *
   * The approved expiry takes the MAX of old and new so that a top-up
   * approval for B never shortens A's existing longer grant; shortening or
   * revoking only ever happens through the revoke path.
   *
   * `inline` picks which expiry the approval extends: an inline approval
   * writes inline_expires_at and leaves expires_at alone (a fresh row starts
   * it at 0, "no ordinary-only permission"); an ordinary approval extends
   * expires_at and never touches inline_expires_at.
   */
  save(
    identity: SecretGrantIdentity,
    units: SecretGrantUnit[],
    ttl: SecretGrantTtl,
    approvalId: string,
    decidedBy?: string,
    decidedAt?: string,
    revocationSnapshot?: GrantRevocationSnapshot,
    options: { inline?: boolean } = {},
  ): SecretGrant[] {
    const scope = normalizeIdentity(identity);
    if (!isSecretGrantTtl(ttl)) throw new Error("invalid grant ttl");
    if (!/^[A-Za-z0-9_-]{8,80}$/.test(approvalId)) throw new Error("invalid approval_id");
    if (!Array.isArray(units) || units.length === 0 || units.length > 20) {
      throw new Error("invalid grant unit count");
    }
    const normalizedUnits = units.map((unit) => ({
      item_id: assertSecretItemId(unit.item_id),
      field: assertSecretField(unit.field),
    }));
    const nowMs = this.now();
    const approvedUntil = nowMs + secretGrantTtlHours(ttl) * 60 * 60 * 1000;
    const inline = options.inline === true;
    const expiresAt = inline ? 0 : approvedUntil;
    const inlineExpiresAt = inline ? approvedUntil : null;
    // MAX() in SQLite returns NULL if any argument is NULL, hence the
    // explicit branches for inline_expires_at.
    const upsert = this.db.query(
      `INSERT INTO ${SECRET_GRANT_TABLE}
         (grant_key, caller_id, client_id, repo, item_id, field, ttl, approval_id,
          decided_by, decided_at, expires_at, inline_expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(grant_key) DO UPDATE SET
         ttl = excluded.ttl,
         approval_id = excluded.approval_id,
         decided_by = excluded.decided_by,
         decided_at = excluded.decided_at,
         expires_at = MAX(${SECRET_GRANT_TABLE}.expires_at, excluded.expires_at),
         inline_expires_at = CASE
           WHEN excluded.inline_expires_at IS NULL THEN ${SECRET_GRANT_TABLE}.inline_expires_at
           WHEN ${SECRET_GRANT_TABLE}.inline_expires_at IS NULL THEN excluded.inline_expires_at
           ELSE MAX(${SECRET_GRANT_TABLE}.inline_expires_at, excluded.inline_expires_at)
         END,
         updated_at = excluded.updated_at`,
    );
    const readBack = this.db.query<GrantRow, [string]>(
      `SELECT ${GRANT_COLUMNS}
         FROM ${SECRET_GRANT_TABLE}
        WHERE grant_key = ?`,
    );
    const currentGeneration = this.db.query<{ generation: number }, [string, string]>(
      `SELECT generation FROM ${GRANT_REVOCATION_TABLE} WHERE item_id = ? AND field = ?`,
    );
    const persist = this.db.transaction(() => {
      if (revocationSnapshot) {
        for (const unit of normalizedUnits) {
          for (const revocationField of [ITEM_REVOCATION_SCOPE, unit.field]) {
            const key = revocationKey(unit.item_id, revocationField);
            const expected = revocationSnapshot.get(key);
            const current = currentGeneration.get(unit.item_id, revocationField)?.generation ?? 0;
            if (expected === undefined || current !== expected) {
              throw new GrantRevokedDuringApprovalError();
            }
          }
        }
      }

      const saved: SecretGrant[] = [];
      for (const unit of normalizedUnits) {
        const key = secretGrantKey(scope, unit);
        upsert.run(
          key,
          scope.caller_id,
          scope.client_id,
          scope.repo,
          unit.item_id,
          unit.field,
          ttl,
          approvalId,
          decidedBy || null,
          decidedAt || null,
          expiresAt,
          inlineExpiresAt,
          nowMs,
          nowMs,
        );
        const row = readBack.get(key);
        if (!row) throw new Error("failed to save secret grant");
        saved.push(rowToGrant(row));
      }
      return saved;
    });
    return persist.immediate();
  }

  /** Emergency brake: delete only the given rows, leaving the repo's other
   * grants untouched. Returns the number of rows deleted. */
  revoke(grantKeys: string[]): number {
    const keys = [...new Set((grantKeys || []).map(assertSecretGrantKey))];
    if (keys.length === 0 || keys.length > 20) throw new Error("invalid grant_key count");
    const placeholders = keys.map(() => "?").join(", ");
    const result = this.db.run(
      `DELETE FROM ${SECRET_GRANT_TABLE} WHERE grant_key IN (${placeholders})`,
      keys,
    );
    return result.changes;
  }

  /**
   * Withdraw only the inline permission of the given rows; their ordinary
   * permission (if any) stays. Rows left with nothing live are deleted
   * outright, so a revoked grant never lingers until the next sweep. Returns
   * the number of rows that had inline permission to lose.
   */
  revokeInline(grantKeys: string[]): number {
    const keys = [...new Set((grantKeys || []).map(assertSecretGrantKey))];
    if (keys.length === 0 || keys.length > 20) throw new Error("invalid grant_key count");
    const placeholders = keys.map(() => "?").join(", ");
    const clear = this.db.transaction(() => {
      const result = this.db.run(
        `UPDATE ${SECRET_GRANT_TABLE} SET inline_expires_at = NULL, updated_at = ?
          WHERE grant_key IN (${placeholders}) AND inline_expires_at IS NOT NULL`,
        [this.now(), ...keys],
      );
      this.db.run(
        `DELETE FROM ${SECRET_GRANT_TABLE}
          WHERE grant_key IN (${placeholders}) AND inline_expires_at IS NULL AND expires_at <= ?`,
        [...keys, this.now()],
      );
      return result.changes;
    });
    return clear.immediate();
  }

  /** Live row keys an approval last touched (see listActiveApprovals). */
  private approvalKeys(approvalId: string): string[] {
    if (!/^[A-Za-z0-9_-]{8,80}$/.test(approvalId)) return [];
    const nowMs = this.now();
    return this.db.query<{ grant_key: string }, [string, number, number]>(
      `SELECT grant_key FROM ${SECRET_GRANT_TABLE} WHERE approval_id = ? AND ${ROW_ALIVE}`,
    ).all(approvalId, nowMs, nowMs).map((row) => row.grant_key);
  }

  /** Delete every live row an approval last touched. */
  revokeApproval(approvalId: string): number {
    const keys = this.approvalKeys(approvalId);
    let removed = 0;
    for (let index = 0; index < keys.length; index += 20) removed += this.revoke(keys.slice(index, index + 20));
    return removed;
  }

  /** Clear only the inline permission of every live row an approval last touched. */
  revokeApprovalInline(approvalId: string): number {
    const keys = this.approvalKeys(approvalId);
    let cleared = 0;
    for (let index = 0; index < keys.length; index += 20) cleared += this.revokeInline(keys.slice(index, index + 20));
    return cleared;
  }

  /**
   * Live grants, one entry per approval, earliest expiry first.
   *
   * Grouped by approval_id because that is what the Owner decided on — but a
   * row carries the id of the LAST approval that touched it (a top-up takes
   * the row over), so an entry is "what this approval currently holds", not a
   * historical record of what it once granted.
   */
  listActiveApprovals(): ActiveApprovalGrants[] {
    const nowMs = this.now();
    const rows = this.db.query<GrantRow, [number, number]>(
      `SELECT ${GRANT_COLUMNS} FROM ${SECRET_GRANT_TABLE} WHERE ${ROW_ALIVE}
        ORDER BY approval_id, item_id, field`,
    ).all(nowMs, nowMs);
    const groups = new Map<string, ActiveApprovalGrants & { normalMs?: number; inlineMs?: number }>();
    for (const row of rows) {
      let group = groups.get(row.approval_id);
      if (!group) {
        group = {
          approval_id: row.approval_id,
          caller_id: row.caller_id,
          client_id: row.client_id,
          repo: row.repo,
          units: [],
        };
        groups.set(row.approval_id, group);
      }
      group.units.push({ item_id: row.item_id, field: row.field });
      if (row.expires_at > nowMs) group.normalMs = Math.min(group.normalMs ?? Infinity, row.expires_at);
      if (row.inline_expires_at !== null && row.inline_expires_at > nowMs) {
        group.inlineMs = Math.min(group.inlineMs ?? Infinity, row.inline_expires_at);
      }
    }
    const earliest = (group: { normalMs?: number; inlineMs?: number }) =>
      Math.min(group.normalMs ?? Infinity, group.inlineMs ?? Infinity);
    return [...groups.values()]
      .sort((a, b) => earliest(a) - earliest(b) || a.approval_id.localeCompare(b.approval_id))
      .map(({ normalMs, inlineMs, ...group }) => ({
        ...group,
        ...(normalMs === undefined ? {} : { expires_at: new Date(normalMs).toISOString() }),
        ...(inlineMs === undefined ? {} : { inline_expires_at: new Date(inlineMs).toISOString() }),
      }));
  }

  /**
   * Record and report "has this command been seen with this key set".
   *
   * The approval path records too: a command the user just read verbatim on
   * the approval card should not bother them again on the next reuse.
   */
  recordSighting(
    identity: SecretGrantIdentity,
    commandHash: string,
    unitKeys: string[],
  ): { key: string; seen_before: boolean } {
    const scope = normalizeIdentity(identity);
    const key = commandSightingKey(scope, commandHash, unitKeys);
    const existing = this.db.query<{ sighting_key: string }, [string]>(
      `SELECT sighting_key FROM ${SECRET_SIGHTING_TABLE} WHERE sighting_key = ?`,
    ).get(key);
    const nowMs = this.now();
    this.db.run(
      `INSERT INTO ${SECRET_SIGHTING_TABLE}
         (sighting_key, caller_id, client_id, repo, command_hash, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(sighting_key) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
      [key, scope.caller_id, scope.client_id, scope.repo, commandHash, nowMs, nowMs],
    );
    return { key, seen_before: Boolean(existing) };
  }

  /** Delete expired grants and sightings past the retention window. */
  sweep(): void {
    const nowMs = this.now();
    this.db.run(
      `DELETE FROM ${SECRET_GRANT_TABLE}
        WHERE expires_at <= ? AND (inline_expires_at IS NULL OR inline_expires_at <= ?)`,
      [nowMs, nowMs],
    );
    this.db.run(
      `DELETE FROM ${SECRET_SIGHTING_TABLE} WHERE last_seen_at < ?`,
      [nowMs - SIGHTING_RETENTION_MS],
    );
    // Revoke handles share the sighting retention window: long past the max
    // 7-day grant TTL, so a resolvable handle always outlives its grants.
    this.db.run(
      `DELETE FROM ${REVOKE_HANDLE_TABLE} WHERE created_at < ?`,
      [nowMs - SIGHTING_RETENTION_MS],
    );
  }
}

/**
 * The Owner's /grants listing: live approvals with display names.
 *
 * Grants store only item ids — names change, ids do not — so names come from
 * the vault at listing time. Best effort: a vault that cannot answer, or an
 * Item it no longer lists, shows its id instead of hiding the grant.
 */
export async function listGrantEntries(
  store: GrantStore,
  itemNames?: () => Promise<Map<string, string>>,
  log: (message: string) => void = () => {},
): Promise<GrantListEntry[]> {
  const approvals = store.listActiveApprovals();
  let names = new Map<string, string>();
  if (itemNames && approvals.length > 0) {
    try {
      names = await itemNames();
    } catch (error) {
      log(`grant listing: item names unavailable, showing ids: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return approvals.map((approval) => {
    const fields = new Map<string, string[]>();
    for (const unit of approval.units) {
      fields.set(unit.item_id, [...(fields.get(unit.item_id) ?? []), unit.field]);
    }
    return {
      approval_id: approval.approval_id,
      repo: approval.repo,
      client_name: approval.caller_id,
      items: [...fields].map(([itemId, itemFields]) => ({ name: names.get(itemId) ?? itemId, fields: itemFields })),
      ...(approval.expires_at ? { expires_at: approval.expires_at } : {}),
      ...(approval.inline_expires_at ? { inline_expires_at: approval.inline_expires_at } : {}),
    };
  });
}
