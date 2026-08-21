#!/usr/bin/env bun
// Broker admin CLI (run inside the container / next to the same SQLite file):
//   bun run server/src/cli_admin.ts client add <name>
//   bun run server/src/cli_admin.ts client list
//   bun run server/src/cli_admin.ts client revoke <name>

import { Database } from "bun:sqlite";
import { ClientRegistry } from "./clients.ts";

const USAGE = "usage: secretary-admin client add <name> | client list | client revoke <name>";

export function runAdmin(
  args: string[],
  db: Database,
  stdout: (message: string) => void,
  stderr: (message: string) => void,
): number {
  const registry = new ClientRegistry(db);
  const [scope, action, name] = args;
  if (scope !== "client") {
    stderr(USAGE);
    return 2;
  }
  try {
    if (action === "add" && name) {
      const created = registry.add(name);
      stdout(`client_id: ${created.client_id}`);
      stdout(`token:     ${created.token}`);
      stdout("The token is shown only this once; store it in the agent machine's Keychain (secretary auth import).");
      return 0;
    }
    if (action === "list" && !name) {
      const rows = registry.list();
      if (rows.length === 0) {
        stdout("no clients registered");
        return 0;
      }
      for (const row of rows) {
        stdout(`${row.name}\t${row.client_id}\tcreated=${row.created_at}${row.revoked_at ? `\trevoked=${row.revoked_at}` : ""}`);
      }
      return 0;
    }
    if (action === "revoke" && name) {
      if (!registry.revoke(name)) {
        stderr(`no active client named: ${name}`);
        return 1;
      }
      stdout(`revoked: ${name}`);
      return 0;
    }
  } catch (error) {
    stderr(error instanceof Error ? error.message : String(error));
    return 1;
  }
  stderr(USAGE);
  return 2;
}

if (import.meta.main) {
  const dbPath = (process.env.DB_PATH ?? "").trim() || "/data/secretary.sqlite";
  const db = new Database(dbPath, { create: true });
  db.run("PRAGMA journal_mode = WAL");
  process.exit(runAdmin(
    process.argv.slice(2),
    db,
    (message) => console.log(message),
    (message) => console.error(message),
  ));
}
