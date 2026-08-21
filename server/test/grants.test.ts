import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import {
  assertSecretGrantKey,
  commandFingerprint,
  commandSightingKey,
  GrantStore,
  type SecretGrantIdentity,
  secretGrantKey,
} from "../src/grants.ts";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const identity: SecretGrantIdentity = {
  caller_id: "caller-alpha",
  client_id: "cli",
  repo: "github.com/acme/widgets",
};

const unitA = { item_id: "item-aaaa-0001", field: "password" as const };
const unitB = { item_id: "item-bbbb-0002", field: "username" as const };
const unitC = { item_id: "item-cccc-0003", field: "password" as const };

const APPROVAL_ID = "approval_12345678";

function makeStore(startMs = 1_700_000_000_000) {
  let currentMs = startMs;
  const clock = {
    now: () => currentMs,
    advance: (ms: number) => {
      currentMs += ms;
    },
  };
  const db = new Database(":memory:");
  const store = new GrantStore(db, clock.now);
  return { db, store, clock };
}

describe("GrantStore", () => {
  let db: Database;
  let store: GrantStore;
  let clock: { now: () => number; advance: (ms: number) => void };

  beforeEach(() => {
    ({ db, store, clock } = makeStore());
  });

  describe("containment matching", () => {
    test("approving {A,B} lets a later lookup for just {A} hit", () => {
      store.save(identity, [unitA, unitB], "8h", APPROVAL_ID);
      const keyA = secretGrantKey(identity, unitA);
      const found = store.findActive([keyA]);
      expect(found.size).toBe(1);
      expect(found.get(keyA)?.item_id).toBe(unitA.item_id);
      expect(found.get(keyA)?.field).toBe(unitA.field);
    });

    test("a lookup including an ungranted key misses that key only", () => {
      store.save(identity, [unitA, unitB], "8h", APPROVAL_ID);
      const keyA = secretGrantKey(identity, unitA);
      const keyC = secretGrantKey(identity, unitC);
      const found = store.findActive([keyA, keyC]);
      expect(found.has(keyA)).toBe(true);
      expect(found.has(keyC)).toBe(false);
    });

    test("findActive validates key count and shape", () => {
      expect(() => store.findActive([])).toThrow();
      expect(() => store.findActive(["not-a-key"])).toThrow();
      const keys = Array.from({ length: 21 }, (_, i) =>
        secretGrantKey(identity, { item_id: `item-count-${String(i).padStart(4, "0")}`, field: "password" }));
      expect(() => store.findActive(keys)).toThrow();
    });
  });

  describe("TTL", () => {
    const cases: Array<["1h" | "8h" | "7d", number]> = [
      ["1h", 1],
      ["8h", 8],
      ["7d", 168],
    ];
    for (const [ttl, hours] of cases) {
      test(`${ttl} expires at now + ${hours}h`, () => {
        const [grant] = store.save(identity, [unitA], ttl, APPROVAL_ID);
        expect(Date.parse(grant.expires_at)).toBe(clock.now() + hours * HOUR_MS);
      });
    }
  });

  describe("GREATEST renewal semantics", () => {
    test("re-saving 7d grant with 1h does not shrink expiry", () => {
      const [long] = store.save(identity, [unitA], "7d", APPROVAL_ID);
      const [after] = store.save(identity, [unitA], "1h", "approval_87654321");
      expect(Date.parse(after.expires_at)).toBe(Date.parse(long.expires_at));
      // Other columns still take the latest approval's values.
      expect(after.ttl).toBe("1h");
      expect(after.approval_id).toBe("approval_87654321");
    });

    test("re-saving 1h grant with 8h extends expiry", () => {
      store.save(identity, [unitA], "1h", APPROVAL_ID);
      clock.advance(10 * 60 * 1000);
      const [after] = store.save(identity, [unitA], "8h", APPROVAL_ID);
      expect(Date.parse(after.expires_at)).toBe(clock.now() + 8 * HOUR_MS);
    });
  });

  describe("expiry", () => {
    test("findActive misses once the grant is expired", () => {
      store.save(identity, [unitA], "1h", APPROVAL_ID);
      const keyA = secretGrantKey(identity, unitA);
      clock.advance(HOUR_MS + 1);
      expect(store.findActive([keyA]).size).toBe(0);
    });

    test("sweep deletes expired rows", () => {
      store.save(identity, [unitA], "1h", APPROVAL_ID);
      clock.advance(HOUR_MS + 1);
      store.sweep();
      const count = db.query<{ n: number }, []>("SELECT COUNT(*) AS n FROM secret_grants").get();
      expect(count?.n).toBe(0);
    });
  });

  describe("revoke", () => {
    test("deletes only the given keys", () => {
      store.save(identity, [unitA, unitB], "8h", APPROVAL_ID);
      const keyA = secretGrantKey(identity, unitA);
      const keyB = secretGrantKey(identity, unitB);
      expect(store.revoke([keyA])).toBe(1);
      expect(store.findActive([keyA]).has(keyA)).toBe(false);
      expect(store.findActive([keyB]).has(keyB)).toBe(true);
    });

    test("revoking a missing key returns 0", () => {
      expect(store.revoke([secretGrantKey(identity, unitC)])).toBe(0);
    });
  });

  describe("sightings", () => {
    const argv = ["curl", "-H", "Authorization: Bearer $TOKEN", "https://example.com"];
    const hash = commandFingerprint(argv);

    test("first record is seen_before=false, second is true", () => {
      const first = store.recordSighting(identity, hash, [unitA.item_id]);
      expect(first.seen_before).toBe(false);
      const second = store.recordSighting(identity, hash, [unitA.item_id]);
      expect(second.seen_before).toBe(true);
      expect(second.key).toBe(first.key);
    });

    test("same command with a different item set is a new sighting", () => {
      store.recordSighting(identity, hash, [unitA.item_id]);
      const other = store.recordSighting(identity, hash, [unitA.item_id, unitB.item_id]);
      expect(other.seen_before).toBe(false);
    });

    test("retention sweep removes sightings older than 90 days", () => {
      store.recordSighting(identity, hash, [unitA.item_id]);
      clock.advance(91 * DAY_MS);
      store.sweep();
      const again = store.recordSighting(identity, hash, [unitA.item_id]);
      expect(again.seen_before).toBe(false);
    });

    test("a recent sighting survives the sweep", () => {
      store.recordSighting(identity, hash, [unitA.item_id]);
      clock.advance(89 * DAY_MS);
      store.sweep();
      expect(store.recordSighting(identity, hash, [unitA.item_id]).seen_before).toBe(true);
    });
  });

  describe("constructor sweep", () => {
    test("a new store over an existing db removes expired rows", () => {
      store.save(identity, [unitA], "1h", APPROVAL_ID);
      new GrantStore(db, () => clock.now() + 2 * HOUR_MS);
      const count = db.query<{ n: number }, []>("SELECT COUNT(*) AS n FROM secret_grants").get();
      expect(count?.n).toBe(0);
    });
  });
});

describe("key functions", () => {
  test("secretGrantKey depends only on identity + item_id + field", () => {
    // No env alias or revision enters the hash: same inputs, same key.
    const a = secretGrantKey(identity, unitA);
    const b = secretGrantKey({ ...identity }, { ...unitA });
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    // Any component change changes the key.
    expect(secretGrantKey(identity, unitB)).not.toBe(a);
    expect(secretGrantKey({ ...identity, repo: "github.com/acme/other" }, unitA)).not.toBe(a);
    expect(secretGrantKey(identity, { ...unitA, field: "username" })).not.toBe(a);
  });

  test("short client ids are accepted (relaxed from the reference)", () => {
    expect(() => secretGrantKey({ ...identity, client_id: "a" }, unitA)).not.toThrow();
  });

  test("validation errors on bad inputs", () => {
    expect(() => secretGrantKey({ ...identity, caller_id: "bad id!" }, unitA)).toThrow("invalid client_id");
    expect(() => secretGrantKey({ ...identity, repo: "bad\nrepo" }, unitA)).toThrow("invalid repo");
    expect(() => secretGrantKey(identity, { item_id: "short", field: "password" })).toThrow(
      "invalid grant item_id",
    );
    expect(() => secretGrantKey(identity, { item_id: unitA.item_id, field: "totp" as never })).toThrow(
      "invalid grant field",
    );
  });

  test("assertSecretGrantKey accepts 64-hex and rejects the rest", () => {
    const key = secretGrantKey(identity, unitA);
    expect(assertSecretGrantKey(key)).toBe(key);
    expect(() => assertSecretGrantKey(key.slice(0, 63))).toThrow();
    expect(() => assertSecretGrantKey(key.toUpperCase())).toThrow();
  });

  test("commandFingerprint hashes argv and rejects empty argv", () => {
    expect(commandFingerprint(["ls"])).toMatch(/^[a-f0-9]{64}$/);
    expect(commandFingerprint(["ls"])).toBe(commandFingerprint(["ls"]));
    expect(commandFingerprint(["ls"])).not.toBe(commandFingerprint(["ls", "-la"]));
    expect(() => commandFingerprint([])).toThrow();
  });

  test("commandSightingKey sorts and dedupes item ids, caps at 10", () => {
    const hash = commandFingerprint(["ls"]);
    const k1 = commandSightingKey(identity, hash, [unitB.item_id, unitA.item_id]);
    const k2 = commandSightingKey(identity, hash, [unitA.item_id, unitB.item_id, unitA.item_id]);
    expect(k1).toBe(k2);
    expect(() => commandSightingKey(identity, hash, [])).toThrow();
    const many = Array.from({ length: 11 }, (_, i) => `item-many-${String(i).padStart(4, "0")}`);
    expect(() => commandSightingKey(identity, hash, many)).toThrow();
    expect(() => commandSightingKey(identity, "nothex", [unitA.item_id])).toThrow("invalid command_hash");
  });
});

describe("save validation", () => {
  test("rejects bad approval ids, ttls, and unit counts", () => {
    const { store } = makeStore();
    expect(() => store.save(identity, [unitA], "1h", "short")).toThrow("invalid approval_id");
    expect(() => store.save(identity, [unitA], "2h" as never, APPROVAL_ID)).toThrow("invalid grant ttl");
    expect(() => store.save(identity, [], "1h", APPROVAL_ID)).toThrow("invalid grant unit count");
    const many = Array.from({ length: 21 }, (_, i) => ({
      item_id: `item-bulk-${String(i).padStart(4, "0")}`,
      field: "password" as const,
    }));
    expect(() => store.save(identity, many, "1h", APPROVAL_ID)).toThrow("invalid grant unit count");
  });

  test("persists decided_by and decided_at as given", () => {
    const { store } = makeStore();
    const [grant] = store.save(
      identity,
      [unitA],
      "1h",
      APPROVAL_ID,
      "randy",
      "2026-08-21T00:00:00.000Z",
    );
    expect(grant.decided_by).toBe("randy");
    expect(grant.decided_at).toBe("2026-08-21T00:00:00.000Z");
  });
});
