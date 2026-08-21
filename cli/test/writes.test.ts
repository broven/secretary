// CLI write verbs: the argv-level guarantees. The load-bearing one is that a
// literal value cannot be expressed at all -- `ps`, shell history and the
// agent's own transcript all read argv.

import { describe, expect, test } from "bun:test";
import {
  parseInvocation,
  parseStdinValues,
  parseWriteFieldSpec,
  parseWriteResponse,
} from "../src/secretary.ts";

const CWD = ["--cwd", "/repo"];

describe("--field", () => {
  test("only @stdin and @owner are accepted", () => {
    expect(parseWriteFieldSpec("password=@stdin")).toEqual({ name: "password", source: "inline" });
    expect(parseWriteFieldSpec("api_key=@owner")).toEqual({ name: "api_key", source: "owner" });
  });

  test("a literal value is refused, with the reason", () => {
    expect(() => parseWriteFieldSpec("password=hunter2")).toThrow("明文不能出现在命令行里");
  });
});

describe("create", () => {
  test("parses an item, description and mixed field sources", () => {
    const parsed = parseInvocation([
      ...CWD,
      "create",
      "--item",
      "Acme Prod",
      "--description",
      "Acme 生产部署账号",
      "--field",
      "username=@stdin",
      "--field",
      "password=@owner",
      "--reason",
      "注册完账号，把凭据存进 vault",
    ]);
    expect(parsed).toMatchObject({
      action: "write",
      operation: "create",
      item: "Acme Prod",
      description: "Acme 生产部署账号",
      fields: [{ name: "username", source: "inline" }, { name: "password", source: "owner" }],
    });
  });

  test("needs at least one field", () => {
    expect(() =>
      parseInvocation([...CWD, "create", "--item", "X", "--reason", "一个足够长的理由说明"])
    ).toThrow("至少要一个 --field");
  });
});

describe("update", () => {
  test("refuses @owner and says what to do instead", () => {
    expect(() =>
      parseInvocation([
        ...CWD,
        "update",
        "--item",
        "X",
        "--field",
        "password=@owner",
        "--reason",
        "一个足够长的理由说明",
      ])
    ).toThrow("@owner 只能用于 create");
  });

  test("refuses to change two kinds of thing at once", () => {
    expect(() =>
      parseInvocation([
        ...CWD,
        "update",
        "--item",
        "X",
        "--rename",
        "Y",
        "--field",
        "password=@stdin",
        "--reason",
        "一个足够长的理由说明",
      ])
    ).toThrow("一次只能改一类东西");
  });

  test("needs something to change", () => {
    expect(() => parseInvocation([...CWD, "update", "--item", "X", "--reason", "一个足够长的理由说明"]))
      .toThrow("用法：secretary update");
  });
});

describe("remove", () => {
  test("--field names a field and takes no source", () => {
    expect(parseInvocation([
      ...CWD,
      "remove",
      "--item",
      "X",
      "--field",
      "api_key",
      "--reason",
      "这个凭据已经作废，从 vault 里删掉",
    ])).toMatchObject({ operation: "remove", removeField: "api_key", fields: [] });
  });

  test("without --field it targets the whole item", () => {
    expect(parseInvocation([...CWD, "remove", "--item", "X", "--reason", "这个凭据已经作废，从 vault 里删掉"]))
      .toMatchObject({ operation: "remove", removeField: undefined });
  });
});

describe("stdin values", () => {
  test("one JSON object shape for one field and for many", () => {
    expect(parseStdinValues('{"password":"p"}', ["password"])).toEqual({ password: "p" });
    expect(parseStdinValues('{"a":"1","b":"2"}', ["a", "b"])).toEqual({ a: "1", b: "2" });
  });

  test("preserves __proto__ as an own inline field", () => {
    const values = parseStdinValues('{"__proto__":"secret"}', ["__proto__"]);

    expect(Object.prototype.hasOwnProperty.call(values, "__proto__")).toBe(true);
    expect(values.__proto__).toBe("secret");
    expect(Object.getPrototypeOf(values)).toBe(Object.prototype);
    expect(JSON.stringify(values)).toBe('{"__proto__":"secret"}');
  });

  test("a missing or undeclared key fails closed rather than writing half an item", () => {
    expect(() => parseStdinValues('{"password":"p"}', ["password", "username"])).toThrow("缺少字段值：username");
    expect(() => parseStdinValues('{"password":"p","stray":"x"}', ["password"])).toThrow("未声明的字段");
  });

  test("empty stdin explains what was expected", () => {
    expect(() => parseStdinValues("  ", ["password"])).toThrow("password");
  });
});

describe("responses", () => {
  test("a pending entry must carry a plausible entry path", () => {
    expect(parseWriteResponse({
      status: "pending_entry",
      entry_path: "/entry/abc",
      expires_at: "2030-01-01T00:00:00.000Z",
      fields: ["password"],
    })).toMatchObject({ status: "pending_entry" });
    expect(() =>
      parseWriteResponse({
        status: "pending_entry",
        entry_path: "https://evil.example.com/",
        expires_at: "x",
        fields: [],
      })
    ).toThrow("录入链接无效");
  });

  test("unknown shapes are refused", () => {
    expect(() => parseWriteResponse({ status: "whatever" })).toThrow("返回结构无效");
  });
});
