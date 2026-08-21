// Client registry: one row per CLI installation. Tokens are random 32-byte
// values shown exactly once at `client add`; only their SHA-256 is stored.

import type { Database } from "bun:sqlite";
import { createHash, randomBytes, randomUUID } from "node:crypto";

export type ClientRecord = {
  client_id: string;
  name: string;
  created_at: string;
  revoked_at: string | null;
};

export const CLIENT_NAME = /^[A-Za-z0-9._-]{1,64}$/;

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class ClientRegistry {
  constructor(private readonly db: Database, private readonly now: () => number = Date.now) {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
      )
    `);
    // Names are unique among ACTIVE clients only, so a revoked name can be
    // re-issued (revoked rows stay for the audit trail).
    this.db.run(
      "CREATE UNIQUE INDEX IF NOT EXISTS clients_active_name ON clients(name) WHERE revoked_at IS NULL",
    );
  }

  /** Returns the plaintext token — the only moment it ever exists outside the caller. */
  add(name: string): { client_id: string; name: string; token: string } {
    if (!CLIENT_NAME.test(name)) throw new Error(`client name invalid (want ${CLIENT_NAME}): ${name}`);
    const existing = this.db
      .query<{ client_id: string }, [string]>("SELECT client_id FROM clients WHERE name = ? AND revoked_at IS NULL")
      .get(name);
    if (existing) throw new Error(`client already exists: ${name}`);
    const clientId = randomUUID();
    const token = randomBytes(32).toString("base64url");
    this.db.run(
      "INSERT INTO clients (client_id, name, token_hash, created_at, revoked_at) VALUES (?, ?, ?, ?, NULL)",
      [clientId, name, hashToken(token), this.now()],
    );
    return { client_id: clientId, name, token };
  }

  /** Bearer token → client identity, or null. Revoked clients never authenticate. */
  authenticate(token: string): { client_id: string; name: string } | null {
    if (typeof token !== "string" || token.length < 16 || token.length > 512) return null;
    const row = this.db
      .query<{ client_id: string; name: string }, [string]>(
        "SELECT client_id, name FROM clients WHERE token_hash = ? AND revoked_at IS NULL",
      )
      .get(hashToken(token));
    return row ?? null;
  }

  list(): ClientRecord[] {
    return this.db
      .query<{ client_id: string; name: string; created_at: number; revoked_at: number | null }, []>(
        "SELECT client_id, name, created_at, revoked_at FROM clients ORDER BY created_at",
      )
      .all()
      .map((row) => ({
        client_id: row.client_id,
        name: row.name,
        created_at: new Date(row.created_at).toISOString(),
        revoked_at: row.revoked_at === null ? null : new Date(row.revoked_at).toISOString(),
      }));
  }

  revoke(name: string): boolean {
    const result = this.db.run(
      "UPDATE clients SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL",
      [this.now(), name],
    );
    return result.changes > 0;
  }
}
