import { describe, expect, test } from "bun:test";
import { isValidFieldName, parseCatalogItems, readItemValues, valueKey, type BwItem } from "../src/vault.ts";

const BASE: BwItem = {
  id: "11111111-aaaa-bbbb-cccc-000000000001",
  type: 1,
  name: "Svc",
  notes: "",
  revisionDate: "2030-01-01T00:00:00.000Z",
  login: { username: "svc-user", password: "svc-pass" },
};

describe("custom field support (P2-1)", () => {
  test("field name validation", () => {
    expect(isValidFieldName("api_key")).toBe(true);
    expect(isValidFieldName("API Key")).toBe(true);
    expect(isValidFieldName("username")).toBe(true);
    expect(isValidFieldName("a=b")).toBe(false);
    expect(isValidFieldName("a,b")).toBe(false);
    expect(isValidFieldName(" padded ")).toBe(false);
    expect(isValidFieldName("")).toBe(false);
    expect(isValidFieldName("x".repeat(65))).toBe(false);
  });

  test("catalog exposes text/hidden custom fields with usable names and values", () => {
    const item: BwItem = {
      ...BASE,
      fields: [
        { name: "api_key", value: "k-123", type: 1 },
        { name: "region", value: "eu-west-1", type: 0 },
        { name: "a=b", value: "x", type: 0 },          // breaks binding syntax → dropped
        { name: "empty", value: "", type: 0 },          // no value → dropped
        { name: "bool", value: "true", type: 2 },       // boolean type → dropped
        { name: "username", value: "shadow", type: 0 }, // collides with login → dropped
        { name: "dup", value: "1", type: 0 },
        { name: "dup", value: "2", type: 0 },           // ambiguous duplicate → dropped
      ],
    };
    const [parsed] = parseCatalogItems([item]);
    expect(parsed.fields).toEqual(["username", "password", "api_key", "region"]);
  });

  test("readItemValues reads custom fields and rejects ambiguity", () => {
    const item: BwItem = {
      ...BASE,
      fields: [
        { name: "api_key", value: "k-123", type: 1 },
        { name: "dup", value: "1", type: 0 },
        { name: "dup", value: "2", type: 0 },
      ],
    };
    const values = readItemValues([item], [
      { item_id: BASE.id as string, field: "password" },
      { item_id: BASE.id as string, field: "api_key" },
    ]);
    expect(values.get(valueKey(BASE.id as string, "api_key"))).toBe("k-123");
    expect(values.get(valueKey(BASE.id as string, "password"))).toBe("svc-pass");
    expect(() => readItemValues([item], [{ item_id: BASE.id as string, field: "dup" }]))
      .toThrow("no usable dup field");
    expect(() => readItemValues([item], [{ item_id: BASE.id as string, field: "missing" }]))
      .toThrow("no usable missing field");
  });
});
