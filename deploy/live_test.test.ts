// Unit tests for the live-test harness's own logic. The Telegram path itself
// is deliberately NOT faked anywhere in the harness — that is its entire
// point; these tests only cover argument parsing and the fake vault seeding.

import { describe, expect, test } from "bun:test";
import { LIVE_ITEM_ID, LIVE_ITEM_NAME, makeLiveVault, parseLiveTestArgs } from "./live_test.ts";
import { valueKey } from "../server/src/vault.ts";

describe("live_test harness", () => {
  test("argument parsing", () => {
    expect(parseLiveTestArgs([])).toEqual({ startStep: 1 });
    expect(parseLiveTestArgs(["--step", "3"])).toEqual({ startStep: 3 });
    expect(() => parseLiveTestArgs(["--step", "0"])).toThrow("--step");
    expect(() => parseLiveTestArgs(["--step", "5"])).toThrow("--step");
    expect(() => parseLiveTestArgs(["--bogus"])).toThrow("unknown argument");
  });

  test("fake vault seeds one item with username+password and round-trips values", async () => {
    const vault = makeLiveVault({ username: "u-value", password: "p-value" });
    const catalog = await vault.catalog();
    expect(catalog).toEqual([{
      name: LIVE_ITEM_NAME,
      description: "secretary live Telegram test item (in-memory only)",
      fields: ["username", "password"],
      created_at: new Date(0).toISOString(),
    }]);
    expect(await vault.catalog("live-test")).toHaveLength(1);
    expect(await vault.catalog("no-match")).toHaveLength(0);

    const [resolved] = await vault.resolveByName([LIVE_ITEM_NAME]);
    expect(resolved.item_id).toBe(LIVE_ITEM_ID);
    await expect(vault.resolveByName(["missing"])).rejects.toThrow("No vault item");

    const values = await vault.readValues([
      { item_id: LIVE_ITEM_ID, field: "password" },
      { item_id: LIVE_ITEM_ID, field: "username" },
    ]);
    expect(values.get(valueKey(LIVE_ITEM_ID, "password"))).toBe("p-value");
    expect(values.get(valueKey(LIVE_ITEM_ID, "username"))).toBe("u-value");
    await expect(vault.readValues([{ item_id: LIVE_ITEM_ID, field: "nope" }]))
      .rejects.toThrow("no such field");
  });
});
