// Broker configuration. Everything comes from the environment; every env that
// carries a secret also accepts a `_FILE` variant pointing at a file whose
// contents (minus one trailing newline) are the value (docker secrets are the
// documented default).

import { readFileSync } from "node:fs";

export type BrokerConfig = {
  vault_url: string;
  bw_clientid: string;
  bw_clientsecret: string;
  bw_email: string;
  bw_password: string;
  telegram_bot_token: string;
  telegram_chat_id: string;
  telegram_allowed_user_ids: number[];
  approval_timeout_s: number;
  /** How long an Entry Form link stays usable. The link IS the capability
   * (ADR-0004), so this window is the main thing bounding a leaked one. */
  entry_ttl_s: number;
  sync_max_age_s: number;
  db_path: string;
  listen_addr: { hostname: string; port: number };
  dev_auto_approve: boolean;
};

export const DEFAULT_APPROVAL_TIMEOUT_S = 300;
export const MAX_APPROVAL_TIMEOUT_S = 600;
export const DEFAULT_SYNC_MAX_AGE_S = 60;
export const DEFAULT_ENTRY_TTL_S = 600;
export const MAX_ENTRY_TTL_S = 3600;

export type Env = Record<string, string | undefined>;

/**
 * Read `NAME` verbatim, or the contents of the file named by `NAME_FILE` with
 * exactly one trailing newline stripped (the editor/echo artifact) — secrets
 * may legitimately contain leading/trailing whitespace, so no trim().
 * Setting both is a configuration error — silently preferring one would make
 * a stale plain-env value shadow the mounted secret (or vice versa).
 */
export function readSecretEnv(
  env: Env,
  name: string,
  readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): string {
  const direct = env[name];
  const filePath = env[`${name}_FILE`];
  if (direct !== undefined && filePath !== undefined) {
    throw new Error(`Both ${name} and ${name}_FILE are set; configure exactly one`);
  }
  if (filePath !== undefined) {
    let value: string;
    try {
      value = readFile(filePath);
    } catch (error) {
      throw new Error(`Cannot read ${name}_FILE (${filePath}): ${error instanceof Error ? error.message : String(error)}`);
    }
    return value.replace(/\r?\n$/, "");
  }
  return direct ?? "";
}

function requireValue(value: string, name: string): string {
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
}

export function parseListenAddr(value: string): { hostname: string; port: number } {
  const raw = value.trim() || "0.0.0.0:8787";
  const separator = raw.lastIndexOf(":");
  if (separator < 0) throw new Error(`LISTEN_ADDR must be host:port, got: ${raw}`);
  const hostname = raw.slice(0, separator) || "0.0.0.0";
  const port = Number(raw.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`LISTEN_ADDR port invalid: ${raw}`);
  }
  return { hostname, port };
}

export function parseAllowedUserIds(value: string): number[] {
  const ids = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const id = Number(entry);
      if (!Number.isInteger(id) || id <= 0) throw new Error(`TELEGRAM_ALLOWED_USER_IDS entry invalid: ${entry}`);
      return id;
    });
  return [...new Set(ids)];
}

function parseBoundedInt(value: string, name: string, fallback: number, min: number, max: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer in [${min}, ${max}], got: ${value}`);
  }
  return parsed;
}

export function parseVaultUrl(value: string): string {
  const raw = requireValue(value, "VAULT_URL").replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`VAULT_URL invalid: ${raw}`);
  }
  // http is allowed for compose-internal vaultwarden; credentials/query never are.
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password || url.search || url.hash) {
    throw new Error("VAULT_URL must be a bare http(s) URL without credentials or query");
  }
  return url.toString().replace(/\/$/, "");
}

export function loadConfig(env: Env = process.env): BrokerConfig {
  const devAutoApprove = env.SECRETARY_DEV_AUTO_APPROVE === "1" && env.NODE_ENV !== "production";
  const telegramBotToken = readSecretEnv(env, "TELEGRAM_BOT_TOKEN");
  const telegramChatId = (env.TELEGRAM_CHAT_ID ?? "").trim();
  const telegramAllowedUserIds = parseAllowedUserIds(env.TELEGRAM_ALLOWED_USER_IDS ?? "");
  if (!devAutoApprove) {
    requireValue(telegramBotToken, "TELEGRAM_BOT_TOKEN");
    requireValue(telegramChatId, "TELEGRAM_CHAT_ID");
    if (telegramAllowedUserIds.length === 0) {
      throw new Error("Missing required configuration: TELEGRAM_ALLOWED_USER_IDS");
    }
  }
  return {
    vault_url: parseVaultUrl(env.VAULT_URL ?? ""),
    bw_clientid: requireValue(readSecretEnv(env, "BW_CLIENTID"), "BW_CLIENTID"),
    bw_clientsecret: requireValue(readSecretEnv(env, "BW_CLIENTSECRET"), "BW_CLIENTSECRET"),
    bw_email: requireValue((env.BW_EMAIL ?? "").trim(), "BW_EMAIL"),
    bw_password: requireValue(readSecretEnv(env, "BW_PASSWORD"), "BW_PASSWORD"),
    telegram_bot_token: telegramBotToken,
    telegram_chat_id: telegramChatId,
    telegram_allowed_user_ids: telegramAllowedUserIds,
    approval_timeout_s: parseBoundedInt(
      (env.APPROVAL_TIMEOUT_S ?? "").trim(),
      "APPROVAL_TIMEOUT_S",
      DEFAULT_APPROVAL_TIMEOUT_S,
      1,
      MAX_APPROVAL_TIMEOUT_S,
    ),
    entry_ttl_s: parseBoundedInt(
      (env.ENTRY_TTL_S ?? "").trim(),
      "ENTRY_TTL_S",
      DEFAULT_ENTRY_TTL_S,
      60,
      MAX_ENTRY_TTL_S,
    ),
    sync_max_age_s: parseBoundedInt(
      (env.SYNC_MAX_AGE_S ?? "").trim(),
      "SYNC_MAX_AGE_S",
      DEFAULT_SYNC_MAX_AGE_S,
      0,
      24 * 60 * 60,
    ),
    db_path: (env.DB_PATH ?? "").trim() || "/data/secretary.sqlite",
    listen_addr: parseListenAddr(env.LISTEN_ADDR ?? ""),
    dev_auto_approve: devAutoApprove,
  };
}
