import { describe, expect, test } from "bun:test";
import { loadConfig, parseAllowedUserIds, parseListenAddr, readSecretEnv } from "../src/config.ts";

const BASE_ENV = {
  VAULT_URL: "https://vault.example.com",
  BW_CLIENTID: "user.abc",
  BW_CLIENTSECRET: "secret",
  BW_EMAIL: "svc@example.com",
  BW_PASSWORD: "master",
  TELEGRAM_BOT_TOKEN: "123:token",
  TELEGRAM_CHAT_ID: "42",
  TELEGRAM_ALLOWED_USER_IDS: "42, 43",
};

describe("readSecretEnv", () => {
  test("reads the plain env value trimmed", () => {
    expect(readSecretEnv({ TOKEN: "  value \n" }, "TOKEN")).toBe("value");
  });

  test("reads the _FILE variant trimmed", () => {
    const files: Record<string, string> = { "/run/secrets/token": "from-file\n" };
    expect(readSecretEnv({ TOKEN_FILE: "/run/secrets/token" }, "TOKEN", (path) => files[path]))
      .toBe("from-file");
  });

  test("rejects both plain and _FILE set at once", () => {
    expect(() => readSecretEnv({ TOKEN: "a", TOKEN_FILE: "/x" }, "TOKEN", () => "b"))
      .toThrow("exactly one");
  });

  test("surfaces unreadable _FILE paths", () => {
    expect(() => readSecretEnv({ TOKEN_FILE: "/missing" }, "TOKEN", () => {
      throw new Error("ENOENT");
    })).toThrow("TOKEN_FILE");
  });

  test("missing env resolves to empty string", () => {
    expect(readSecretEnv({}, "TOKEN")).toBe("");
  });
});

describe("loadConfig", () => {
  test("loads a full telegram config with defaults", () => {
    const config = loadConfig(BASE_ENV);
    expect(config.vault_url).toBe("https://vault.example.com");
    expect(config.telegram_allowed_user_ids).toEqual([42, 43]);
    expect(config.approval_timeout_s).toBe(300);
    expect(config.sync_max_age_s).toBe(60);
    expect(config.db_path).toBe("/data/secretary.sqlite");
    expect(config.listen_addr).toEqual({ hostname: "0.0.0.0", port: 8787 });
    expect(config.dev_auto_approve).toBe(false);
  });

  test("requires telegram settings unless dev auto approve is on", () => {
    const { TELEGRAM_BOT_TOKEN: _token, ...withoutToken } = BASE_ENV;
    expect(() => loadConfig(withoutToken)).toThrow("TELEGRAM_BOT_TOKEN");
    const config = loadConfig({ ...withoutToken, SECRETARY_DEV_AUTO_APPROVE: "1" });
    expect(config.dev_auto_approve).toBe(true);
  });

  test("dev auto approve refuses NODE_ENV=production", () => {
    expect(() => loadConfig({
      ...BASE_ENV,
      TELEGRAM_BOT_TOKEN: "",
      SECRETARY_DEV_AUTO_APPROVE: "1",
      NODE_ENV: "production",
    })).toThrow("TELEGRAM_BOT_TOKEN");
  });

  test("vault url must be bare http(s)", () => {
    expect(() => loadConfig({ ...BASE_ENV, VAULT_URL: "ftp://x" })).toThrow("VAULT_URL");
    expect(() => loadConfig({ ...BASE_ENV, VAULT_URL: "https://u:p@x.example" })).toThrow("VAULT_URL");
    expect(loadConfig({ ...BASE_ENV, VAULT_URL: "http://vaultwarden" }).vault_url).toBe("http://vaultwarden");
  });

  test("approval timeout bounds", () => {
    expect(loadConfig({ ...BASE_ENV, APPROVAL_TIMEOUT_S: "60" }).approval_timeout_s).toBe(60);
    expect(() => loadConfig({ ...BASE_ENV, APPROVAL_TIMEOUT_S: "0" })).toThrow("APPROVAL_TIMEOUT_S");
    expect(() => loadConfig({ ...BASE_ENV, APPROVAL_TIMEOUT_S: "601" })).toThrow("APPROVAL_TIMEOUT_S");
  });
});

describe("listen addr / allowed ids", () => {
  test("parses host:port with defaults", () => {
    expect(parseListenAddr("")).toEqual({ hostname: "0.0.0.0", port: 8787 });
    expect(parseListenAddr("127.0.0.1:9000")).toEqual({ hostname: "127.0.0.1", port: 9000 });
    expect(() => parseListenAddr("host:notaport")).toThrow();
  });

  test("parses and dedupes user ids", () => {
    expect(parseAllowedUserIds("1,2, 2 ,3")).toEqual([1, 2, 3]);
    expect(parseAllowedUserIds("")).toEqual([]);
    expect(() => parseAllowedUserIds("1,abc")).toThrow();
  });
});
