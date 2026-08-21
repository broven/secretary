import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ClientRegistry, hashToken } from "../src/clients.ts";
import { runAdmin } from "../src/cli_admin.ts";

describe("client registry", () => {
  test("add issues a token whose hash (not value) is stored", () => {
    const db = new Database(":memory:");
    const registry = new ClientRegistry(db);
    const created = registry.add("laptop");
    expect(created.token.length).toBeGreaterThanOrEqual(43);
    const stored = db.query<{ token_hash: string }, []>("SELECT token_hash FROM clients").get()!;
    expect(stored.token_hash).toBe(hashToken(created.token));
    expect(stored.token_hash).not.toBe(created.token);
  });

  test("authenticate maps bearer token to client identity", () => {
    const db = new Database(":memory:");
    const registry = new ClientRegistry(db);
    const created = registry.add("laptop");
    expect(registry.authenticate(created.token)).toEqual({ client_id: created.client_id, name: "laptop" });
    expect(registry.authenticate("wrong-token-wrong-token")).toBeNull();
    expect(registry.authenticate("")).toBeNull();
  });

  test("revoked clients stop authenticating; names are unique while active", () => {
    const db = new Database(":memory:");
    const registry = new ClientRegistry(db);
    const created = registry.add("laptop");
    expect(() => registry.add("laptop")).toThrow("already exists");
    expect(registry.revoke("laptop")).toBe(true);
    expect(registry.authenticate(created.token)).toBeNull();
    expect(registry.revoke("laptop")).toBe(false);
  });

  test("a revoked name can be re-issued as a fresh client (P2-6)", () => {
    const db = new Database(":memory:");
    const registry = new ClientRegistry(db);
    const first = registry.add("laptop");
    registry.revoke("laptop");
    const second = registry.add("laptop");
    expect(second.client_id).not.toBe(first.client_id);
    expect(registry.authenticate(second.token)).toEqual({ client_id: second.client_id, name: "laptop" });
    expect(registry.authenticate(first.token)).toBeNull();
    // Both rows remain for the audit trail.
    expect(registry.list().filter((row) => row.name === "laptop")).toHaveLength(2);
  });

  test("rejects invalid names", () => {
    const registry = new ClientRegistry(new Database(":memory:"));
    expect(() => registry.add("bad name!")).toThrow("invalid");
    expect(() => registry.add("")).toThrow("invalid");
  });
});

describe("admin cli", () => {
  test("add / list / revoke round trip", () => {
    const db = new Database(":memory:");
    const out: string[] = [];
    const err: string[] = [];
    expect(runAdmin(["client", "add", "ci-box"], db, (m) => out.push(m), (m) => err.push(m))).toBe(0);
    expect(out.join("\n")).toContain("token:");
    expect(runAdmin(["client", "list"], db, (m) => out.push(m), (m) => err.push(m))).toBe(0);
    expect(out.join("\n")).toContain("ci-box");
    expect(runAdmin(["client", "revoke", "ci-box"], db, (m) => out.push(m), (m) => err.push(m))).toBe(0);
    expect(runAdmin(["client", "revoke", "ci-box"], db, (m) => out.push(m), (m) => err.push(m))).toBe(1);
    expect(runAdmin(["bogus"], db, (m) => out.push(m), (m) => err.push(m))).toBe(2);
  });
});
