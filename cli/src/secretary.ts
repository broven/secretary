#!/usr/bin/env bun
// Self-contained secretary client. Runtime dependencies: macOS Keychain
// (optional; SECRETARY_* env vars work everywhere) and HTTPS only.
//
// Wire contract mirrors server/src/types.ts and server/src/envelope.ts — this
// file must stay a single self-contained module (no imports from server/).

import { realpath, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, resolve as resolvePath } from "node:path";
import { hostname, userInfo } from "node:os";

// Keychain locations for the three config settings. Env vars always win.
export const URL_SERVICE = "secretary-url";
export const TOKEN_SERVICE = "secretary-token";
export const CLIENT_SERVICE = "secretary-client-id";
export const KEYCHAIN_ACCOUNT = "secretary";

export const URL_ENV = "SECRETARY_URL";
export const TOKEN_ENV = "SECRETARY_TOKEN";
export const CLIENT_ENV = "SECRETARY_CLIENT_ID";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;
const RESERVED_ENV = new Set([
  "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "TMPDIR",
  "NODE_OPTIONS", "BUN_OPTIONS", "BITWARDENCLI_APPDATA_DIR",
]);
const RESERVED_PREFIXES = ["SECRETARY_", "WMILL_", "FNOX_", "SENV_", "BW_", "MISE_", "APPROVED_SECRET_"];
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
// Headers of the long poll arrive immediately; the body deadline is derived
// from the server-advertised approval timeout (X-Secretary-Approval-Timeout)
// plus this margin, so the client always outlives the server-side window.
const HEADER_TIMEOUT_MS = 30_000;
const DEFAULT_APPROVAL_TIMEOUT_S = 300;
const BODY_TIMEOUT_MARGIN_MS = 30_000;
// The broker rejects bodies over 256 KiB; leave headroom for encoding.
const MAX_REQUEST_BODY_BYTES = 200_000;
const CATALOG_TIMEOUT_MS = 60_000;
const MAX_ITEMS = 10;
const EXEC_USAGE =
  "用法：secretary exec --reason \"申请理由\" --item ITEM field=ENV[,field=ENV] [--item ITEM field=ENV ...] -- command...";
const AUTH_USAGE = "用法：secretary auth import|status|delete|set-url <url>|set-client-id <id>";
const CREATE_USAGE =
  '用法：secretary create --item ITEM [--description "用途"] --field NAME=@stdin|@owner [...] --reason "理由"';
const UPDATE_USAGE =
  '用法：secretary update --item ITEM (--field NAME=@stdin [...] | --rename NEW | --description "用途") --reason "理由"';
const REMOVE_USAGE = '用法：secretary remove --item ITEM [--field NAME] --reason "理由"';
const MAX_WRITE_FIELDS = 20;
/** 理由必传；服务端也会硬拒空/过短，这里先拦一道是为了给调用方一个明确的报错。 */
const MIN_REASON_LENGTH = 10;
const MAX_REASON_LENGTH = 2000;
const MAX_ARGV_ENTRIES = 200;
const MAX_ARGV_ENTRY_LENGTH = 4096;

// "username", "password", or a custom field name on the login item. Custom
// names may not contain '=' or ',' (binding syntax) or control characters.
export type CatalogField = string;
const FIELD_NAME = /^[^=,\u0000-\u001f\u007f]{1,64}$/;
export function isValidFieldName(value: string): boolean {
  return value === value.trim() && FIELD_NAME.test(value);
}
export type Binding = { field: CatalogField; env: string };
export type CatalogResponse = {
  items: Array<{ name: string; description: string; fields: CatalogField[]; created_at: string }>;
};
export type ApprovalResult = {
  approved?: boolean;
  denied_reason?: "denied" | "timeout";
  ttl?: string;
  credential_envelope?: CredentialEnvelope;
  expires_at?: string;
  lease_id?: string;
  grant_reused?: boolean;
};
export type CredentialEnvelope = {
  version: 1;
  algorithm: "P256-HKDF-SHA256+A256GCM";
  server_public_key: JsonWebKey;
  salt: string;
  iv: string;
  ciphertext: string;
};
export type ClientKeyExchange = { privateKey: CryptoKey; publicKeyJwk: JsonWebKey };

const CREDENTIAL_ENVELOPE_INFO = new TextEncoder().encode("secretary:credential-envelope:v1");

function credentialEnvelopeAad(requestId: string): Uint8Array {
  const id = requestId.toLowerCase();
  if (!UUID.test(id)) throw new Error("request_id 无效");
  return new TextEncoder().encode(`secretary:credential-envelope:v1\nrequest_id=${id}`);
}

export type Keychain = {
  read(service: string, account: string): Promise<string | null>;
  write(service: string, account: string, value: string): Promise<void>;
  promptWrite(service: string, account: string): Promise<void>;
  delete(service: string, account: string): Promise<void>;
};

export type ClientDeps = {
  env: Record<string, string | undefined>;
  fetch: typeof fetch;
  keychain: Keychain;
  realpath: typeof realpath;
  stat: typeof stat;
  now: () => number;
  randomUUID: () => string;
  hostname: () => string;
  username: () => string;
  gitRemote: (cwd: string) => string | undefined;
  spawn: (argv: string[], cwd: string, env: Record<string, string>) => Promise<number>;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  /** Whole stdin as text. Field values arrive here and never through argv. */
  readStdin: () => Promise<string>;
  onInterrupt?: (handler: () => void) => () => void;
};

export type AuthAction = "import" | "status" | "delete" | "set-url" | "set-client-id";

export type ExecItem = { itemName: string; bindings: Binding[] };
export type WriteOperation = "create" | "update" | "remove";
export type WriteFieldSpec = { name: CatalogField; source: "inline" | "owner" };

export type ParsedInvocation =
  | { action: "list"; cwd: string; query: string; json: boolean }
  | {
    action: "write";
    cwd: string;
    operation: WriteOperation;
    item: string;
    reason: string;
    description?: string;
    rename?: string;
    fields: WriteFieldSpec[];
    removeField?: string;
  }
  | { action: "exec"; cwd: string; items: ExecItem[]; command: string[]; reason: string }
  | { action: "auth"; cwd: string; authAction: AuthAction; value?: string };

function isReservedEnv(name: string): boolean {
  return RESERVED_ENV.has(name) || RESERVED_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function parseSingleBinding(value: string): Binding {
  const separator = value.indexOf("=");
  if (separator <= 0 || separator === value.length - 1) throw new Error(`无效 binding：${value}`);
  const field = value.slice(0, separator);
  const env = value.slice(separator + 1);
  if (!isValidFieldName(field)) throw new Error(`无效 binding 字段名：${field}`);
  if (!ENV_NAME.test(env)) throw new Error(`无效 binding：${value}`);
  if (isReservedEnv(env)) throw new Error(`不能绑定到环境变量：${env}`);
  return { field, env };
}

// Parse one or more `--item NAME field=ENV[,field=ENV]` groups. Groups naming the
// same item are merged into a single request, so `--item X username=U --item X
// password=P` and `--item X username=U,password=P` produce identical output. A
// field bound twice inside one item, or an env reused across items, fails closed.
export function parseItemGroups(tokens: string[]): ExecItem[] {
  if (tokens[0] !== "--item") throw new Error(EXEC_USAGE);
  const groups: Array<{ name: string; values: string[] }> = [];
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index] !== "--item") {
      groups[groups.length - 1].values.push(tokens[index]);
      continue;
    }
    const name = tokens[++index]?.trim();
    if (!name || name === "--item" || name.length > 200 || [...name].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) {
      throw new Error("ITEM 无效");
    }
    groups.push({ name, values: [] });
  }
  const order: string[] = [];
  const byName = new Map<string, Binding[]>();
  for (const group of groups) {
    const bindings = group.values.flatMap((value) => value.split(",")).filter(Boolean).map(parseSingleBinding);
    if (bindings.length === 0) throw new Error(`条目缺少 field=ENV binding：${group.name}`);
    if (!byName.has(group.name)) {
      byName.set(group.name, []);
      order.push(group.name);
    }
    byName.get(group.name)!.push(...bindings);
  }
  if (order.length > MAX_ITEMS) throw new Error(`一次最多申请 ${MAX_ITEMS} 个条目`);
  const seenEnvs = new Set<string>();
  return order.map((name) => {
    const bindings = byName.get(name)!;
    const seenFields = new Set<string>();
    for (const binding of bindings) {
      if (seenFields.has(binding.field)) throw new Error(`条目「${name}」字段重复绑定：${binding.field}`);
      seenFields.add(binding.field);
      if (seenEnvs.has(binding.env)) throw new Error(`环境变量重复绑定：${binding.env}`);
      seenEnvs.add(binding.env);
    }
    bindings.sort((a, b) => a.field.localeCompare(b.field) || a.env.localeCompare(b.env));
    return { itemName: name, bindings };
  });
}

/**
 * 把 `--reason "..."` 从 exec 的前半段参数里摘出来。
 *
 * 理由由调用方自己写、可以不实——它是审批时的知情依据，不是安全边界。真正的边界
 * 是条目、字段和（内联 shell 时的）逐次人工审批。
 */
export function extractReason(tokens: string[]): { reason: string; tokens: string[] } {
  const rest: string[] = [];
  let reason = "";
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index] !== "--reason") {
      rest.push(tokens[index]);
      continue;
    }
    if (reason) throw new Error("--reason 只能给一次");
    const value = tokens[++index];
    if (value === undefined) throw new Error(EXEC_USAGE);
    reason = value.trim().replace(/\s+/g, " ");
  }
  if (reason.length < MIN_REASON_LENGTH) {
    throw new Error(`必须用 --reason 说明本次用途（至少 ${MIN_REASON_LENGTH} 个字符）`);
  }
  if (reason.length > MAX_REASON_LENGTH) throw new Error("--reason 过长");
  return { reason, tokens: rest };
}

/**
 * `--field NAME=@stdin` or `NAME=@owner`.
 *
 * A literal value is refused by construction, not by convention: argv is
 * visible to every process on the machine via `ps`, lands in shell history,
 * and is echoed in the agent's own transcript. Agent-supplied values come in
 * over stdin as JSON; Owner-supplied ones never reach the agent at all.
 */
export function parseWriteFieldSpec(value: string): WriteFieldSpec {
  const separator = value.indexOf("=");
  if (separator <= 0 || separator === value.length - 1) {
    throw new Error(`无效 --field：${value}（写成 NAME=@stdin 或 NAME=@owner）`);
  }
  const name = value.slice(0, separator);
  const source = value.slice(separator + 1);
  if (!isValidFieldName(name)) throw new Error(`无效字段名：${name}`);
  if (source === "@stdin") return { name, source: "inline" };
  if (source === "@owner") return { name, source: "owner" };
  throw new Error(
    `--field ${name} 的值只能是 @stdin 或 @owner：明文不能出现在命令行里，` +
    `agent 自己有的值请用 @stdin 从标准输入传 JSON`,
  );
}

function takeFlagValue(tokens: string[], index: number, flag: string): string {
  const value = tokens[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} 缺少取值`);
  return value;
}

export function parseWriteInvocation(
  operation: WriteOperation,
  cwd: string,
  rest: string[],
): ParsedInvocation {
  const usage = operation === "create" ? CREATE_USAGE : operation === "update" ? UPDATE_USAGE : REMOVE_USAGE;
  const { reason, tokens } = extractReason(rest);
  let item: string | undefined;
  let description: string | undefined;
  let rename: string | undefined;
  let removeField: string | undefined;
  const fields: WriteFieldSpec[] = [];

  for (let index = 0; index < tokens.length; index++) {
    const flag = tokens[index];
    switch (flag) {
      case "--item":
        if (item !== undefined) throw new Error("--item 只能给一次");
        item = takeFlagValue(tokens, index++, flag).trim();
        break;
      case "--description":
        if (description !== undefined) throw new Error("--description 只能给一次");
        description = takeFlagValue(tokens, index++, flag).trim();
        break;
      case "--rename":
        if (rename !== undefined) throw new Error("--rename 只能给一次");
        rename = takeFlagValue(tokens, index++, flag).trim();
        break;
      case "--field": {
        const value = takeFlagValue(tokens, index++, flag);
        if (operation === "remove") {
          if (removeField !== undefined) throw new Error("remove 的 --field 只能给一次");
          if (!isValidFieldName(value)) throw new Error(`无效字段名：${value}`);
          removeField = value;
          break;
        }
        fields.push(parseWriteFieldSpec(value));
        break;
      }
      default:
        throw new Error(`未知参数：${flag}\n${usage}`);
    }
  }

  if (!item) throw new Error(usage);
  if (item.length > 200 || /[\u0000-\u001f\u007f]/.test(item)) throw new Error("ITEM 无效");
  if (fields.length > MAX_WRITE_FIELDS) throw new Error(`一次最多 ${MAX_WRITE_FIELDS} 个字段`);
  const names = new Set<string>();
  for (const field of fields) {
    if (names.has(field.name)) throw new Error(`字段重复：${field.name}`);
    names.add(field.name);
  }

  if (operation === "create") {
    if (fields.length === 0) throw new Error(`create 至少要一个 --field\n${CREATE_USAGE}`);
    if (rename !== undefined) throw new Error("create 不接受 --rename");
  } else if (operation === "update") {
    // @owner is create-only: the lane that skips an Approval may only add.
    const owner = fields.find((field) => field.source === "owner");
    if (owner) {
      throw new Error(
        `@owner 只能用于 create（字段 ${owner.name}）：修改已有值必须经过审批，请改用 @stdin，` +
        "或者自己去 vault 客户端里改。",
      );
    }
    const intents = [rename !== undefined, description !== undefined, fields.length > 0].filter(Boolean).length;
    if (intents === 0) throw new Error(UPDATE_USAGE);
    if (intents > 1) throw new Error("update 一次只能改一类东西：字段值、条目名、描述，请分开提交");
  } else {
    if (fields.length > 0) throw new Error("remove 的 --field 只写字段名，不带 =");
    if (rename !== undefined || description !== undefined) throw new Error(REMOVE_USAGE);
  }

  return { action: "write", cwd, operation, item, reason, description, rename, fields, removeField };
}

const AUTH_ACTIONS_NO_VALUE: AuthAction[] = ["import", "status", "delete"];
const AUTH_ACTIONS_WITH_VALUE: AuthAction[] = ["set-url", "set-client-id"];

export function parseInvocation(args: string[]): ParsedInvocation {
  // The wrapper script always injects `--cwd <caller dir>` first.
  if (args[0] !== "--cwd" || !args[1]) throw new Error("内部调用缺少 --cwd");
  const cwd = args[1];
  const action = args[2];
  const rest = args.slice(3);
  if (action === "list") {
    const unknown = rest.filter((arg) => arg.startsWith("--") && arg !== "--json");
    if (unknown.length) throw new Error("用法：secretary list [关键词] [--json]");
    return { action, cwd, query: rest.filter((arg) => arg !== "--json").join(" ").trim(), json: rest.includes("--json") };
  }
  if (action === "auth") {
    const sub = rest[0] as AuthAction;
    if (AUTH_ACTIONS_NO_VALUE.includes(sub)) {
      if (rest.length !== 1) throw new Error(AUTH_USAGE);
      return { action, cwd, authAction: sub };
    }
    if (AUTH_ACTIONS_WITH_VALUE.includes(sub)) {
      if (rest.length !== 2 || !rest[1]) throw new Error(AUTH_USAGE);
      return { action, cwd, authAction: sub, value: rest[1] };
    }
    throw new Error(AUTH_USAGE);
  }
  if (action === "create" || action === "update" || action === "remove") {
    return parseWriteInvocation(action, cwd, rest);
  }
  if (action === "exec") {
    const separator = rest.indexOf("--");
    if (separator < 0 || separator === rest.length - 1) throw new Error(EXEC_USAGE);
    const { reason, tokens } = extractReason(rest.slice(0, separator));
    const command = rest.slice(separator + 1);
    if (command.length > MAX_ARGV_ENTRIES) throw new Error(`命令参数过多（上限 ${MAX_ARGV_ENTRIES} 个）`);
    if (command.some((part) => part.length > MAX_ARGV_ENTRY_LENGTH)) throw new Error("命令参数过长");
    return { action, cwd, items: parseItemGroups(tokens), command, reason };
  }
  throw new Error("用法：secretary list|exec|create|update|remove|auth ...");
}

function parseJson(text: string, context: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${context} 返回了无效 JSON`);
  }
}

export function parseCatalogResponse(value: unknown): CatalogResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("密钥目录格式无效");
  const source = value as Record<string, unknown>;
  if (!Array.isArray(source.items) || source.items.length > 1000) throw new Error("密钥目录格式无效");
  const items = source.items.map((raw): CatalogResponse["items"][number] => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("密钥目录条目无效");
    const item = raw as Record<string, unknown>;
    if (typeof item.name !== "string" || !item.name.trim() || item.name.length > 500 ||
      !Array.isArray(item.fields)) throw new Error("密钥目录条目无效");
    const fields = item.fields.filter((field): field is CatalogField =>
      typeof field === "string" && isValidFieldName(field));
    if (fields.length === 0 || fields.length !== item.fields.length || new Set(fields).size !== fields.length) {
      throw new Error("密钥目录字段无效");
    }
    return {
      name: item.name.trim(),
      description: typeof item.description === "string" ? item.description.trim().slice(0, 1000) : "",
      fields: fields.sort(),
      created_at: typeof item.created_at === "string" ? item.created_at.trim().slice(0, 100) : "",
    };
  });
  return { items };
}

function fromBase64Url(value: string, maximumBytes: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maximumBytes * 4 / 3) + 4) {
    throw new Error("凭证密文格式无效");
  }
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (bytes.length === 0 || bytes.length > maximumBytes || Buffer.from(bytes).toString("base64url") !== value) {
    throw new Error("凭证密文格式无效");
  }
  return bytes;
}

export async function generateClientKeyExchange(): Promise<ClientKeyExchange> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  return {
    privateKey: pair.privateKey,
    publicKeyJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}

export async function decryptCredentialEnvelope(
  envelope: CredentialEnvelope,
  privateKey: CryptoKey,
  requestId: string,
): Promise<Record<string, string>> {
  if (!envelope || envelope.version !== 1 || envelope.algorithm !== "P256-HKDF-SHA256+A256GCM" ||
    !envelope.server_public_key || envelope.server_public_key.kty !== "EC" ||
    envelope.server_public_key.crv !== "P-256" || "d" in envelope.server_public_key ||
    typeof envelope.salt !== "string" || typeof envelope.iv !== "string" ||
    typeof envelope.ciphertext !== "string") {
    throw new Error("凭证密文格式无效");
  }
  const serverPublicKey = await crypto.subtle.importKey(
    "jwk",
    envelope.server_public_key,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const salt = fromBase64Url(envelope.salt, 32);
  const iv = fromBase64Url(envelope.iv, 12);
  if (salt.length !== 32 || iv.length !== 12) throw new Error("凭证密文格式无效");
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPublicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  new Uint8Array(sharedSecret).fill(0);
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: CREDENTIAL_ENVELOPE_INFO,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv,
      additionalData: credentialEnvelopeAad(requestId),
      tagLength: 128,
    }, key, fromBase64Url(envelope.ciphertext, 1024 * 1024));
  } catch {
    throw new Error("无法解密凭证结果");
  }
  const bytes = new Uint8Array(plaintext);
  try {
    const value = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes), "凭证密文");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("凭证密文内容无效");
    return value as Record<string, string>;
  } finally {
    bytes.fill(0);
  }
}

// Bun's fetch surfaces TLS verification failures as an Error (not a TypeError)
// carrying an OpenSSL-style `code`, or the opaque message
// "unknown certificate verification error". Detect that family so we can rewrite
// the message with the target host and a concrete remedy — the raw string names
// no host and is nearly impossible to self-diagnose.
export function isTlsCertError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.name === "TimeoutError" || error.name === "AbortError") return false;
  const code = String((error as { code?: unknown }).code ?? "");
  return /CERT|SELF_SIGNED|UNABLE_TO_(GET|VERIFY)|certificate/i.test(`${code} ${error.message}`);
}

export function describeTlsCertError(host: string, error: unknown): Error {
  const code = (error instanceof Error && (error as { code?: unknown }).code)
    ? String((error as { code?: unknown }).code)
    : (error instanceof Error ? error.message : String(error));
  return new Error(
    `TLS 证书校验失败：无法验证 ${host} 的证书（${code}）。` +
    `这通常是本机 TLS 拦截代理（如 Surge）做了中间人；secretary 基于 Bun，只信任内置 CA，不读取 macOS 钥匙串。` +
    `若确认信任该代理，把其根证书导出为 PEM 文件，并在调用前设置 NODE_EXTRA_CA_CERTS 指向该文件后重试。`,
  );
}

// ---------------------------------------------------------------------------
// Config resolution: env var wins over keychain; each setting has one home.

export type SettingSource = "env" | "keychain";
export type BrokerConfig = { url: string; token: string; clientId?: string };

async function resolveSetting(
  deps: ClientDeps,
  envName: string,
  service: string,
): Promise<{ value: string; source: SettingSource } | null> {
  const fromEnv = deps.env[envName]?.trim();
  if (fromEnv) return { value: fromEnv, source: "env" };
  const fromKeychain = (await deps.keychain.read(service, KEYCHAIN_ACCOUNT))?.trim();
  if (fromKeychain) return { value: fromKeychain, source: "keychain" };
  return null;
}

export function normalizeBrokerUrl(raw: string): string {
  const value = raw.trim().replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("broker URL 无效（需要 http(s):// URL）");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("broker URL 无效（需要 http(s):// URL）");
  }
  return value;
}

async function resolveConfig(deps: ClientDeps): Promise<BrokerConfig> {
  const url = await resolveSetting(deps, URL_ENV, URL_SERVICE);
  if (!url) throw new Error(`尚未配置 secretary broker 地址；运行 secretary auth set-url <url> 或设置 ${URL_ENV} 环境变量`);
  const token = await resolveSetting(deps, TOKEN_ENV, TOKEN_SERVICE);
  if (!token) throw new Error(`尚未配置 secretary token；运行 secretary auth import 或设置 ${TOKEN_ENV} 环境变量`);
  if (token.value.length > 8192 || /[\u0000-\u001f\u007f]/.test(token.value)) {
    throw new Error("secretary token 无效");
  }
  const clientId = await resolveSetting(deps, CLIENT_ENV, CLIENT_SERVICE);
  return {
    url: normalizeBrokerUrl(url.value),
    token: token.value,
    clientId: clientId?.value || undefined,
  };
}

// ---------------------------------------------------------------------------
// HTTP: one authenticated JSON request. The broker may flush leading whitespace
// heartbeat bytes before the JSON body — trim before parsing.

async function readTextLimited(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > MAX_RESPONSE_BYTES) throw new Error("secretary 响应超过安全限制");
  if (!response.body) return "";
  // Enforce the cap while streaming: never buffer an oversized body first.
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error("secretary 响应超过安全限制");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function timeoutError(): Error {
  return Object.assign(new Error("secretary 请求超时"), { name: "TimeoutError" });
}

async function brokerJson(
  deps: ClientDeps,
  token: string,
  url: URL,
  init: {
    method: string;
    body?: unknown;
    timeoutMs: number;
    /** When set, the deadline for reading the (long-polled) body is derived
     * from the response headers once they arrive — so the client deadline
     * always exceeds the server's configured approval timeout. */
    bodyTimeoutMsFromResponse?: (response: Response) => number;
    signal?: AbortSignal;
    onNetworkError?: (error: unknown) => Error;
  },
): Promise<unknown> {
  const controller = new AbortController();
  let timer = setTimeout(() => controller.abort(timeoutError()), init.timeoutMs);
  let response: Response;
  let text: string;
  try {
    try {
      response = await deps.fetch(url, {
        method: init.method,
        redirect: "error",
        headers: {
          Authorization: `Bearer ${token}`,
          ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: init.signal
          ? AbortSignal.any([controller.signal, init.signal])
          : controller.signal,
      });
    } catch (error) {
      // A cert failure gets rewritten with the host and remedy. Any other network
      // failure goes through the caller's wrapper (exec fails closed: no resend).
      if (isTlsCertError(error)) throw describeTlsCertError(url.host, error);
      throw init.onNetworkError ? init.onNetworkError(error) : error;
    }
    if (init.bodyTimeoutMsFromResponse) {
      clearTimeout(timer);
      timer = setTimeout(() => controller.abort(timeoutError()), init.bodyTimeoutMsFromResponse(response));
    }
    try {
      text = await readTextLimited(response);
    } catch (error) {
      throw init.onNetworkError ? init.onNetworkError(error) : error;
    }
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    let detail = "";
    try {
      const parsed = JSON.parse(text.trim()) as { error?: unknown };
      if (parsed && typeof parsed.error === "string") detail = `：${parsed.error.slice(0, 500)}`;
    } catch {
      // Non-JSON error body: report the status alone.
    }
    throw new Error(`secretary 请求失败：HTTP ${response.status}${detail}`);
  }
  return parseJson(text.trim(), "secretary");
}

// ---------------------------------------------------------------------------

/** Collision-resistant identity for a local path (no remote, or a path remote). */
function localRepoIdentity(path: string): string {
  const local = `local:${path}`;
  return local.length <= 200 ? local : `local:sha256:${createHash("sha256").update(path).digest("hex")}`;
}

export function normalizeRepoIdentity(remote: string | undefined, cwd: string): string {
  const value = remote?.trim().replace(/\/+$/, "").replace(/\.git$/, "");
  // No origin remote: two unrelated directories sharing a basename must not
  // share Grant keys, so the canonical absolute path is the identity.
  if (!value) return localRepoIdentity(cwd);
  if (value.includes("://")) {
    try {
      const url = new URL(value);
      // file:// remotes are local paths in disguise.
      if (url.protocol === "file:") return localRepoIdentity(decodeURIComponent(url.pathname) || cwd);
      const path = url.pathname.replace(/^\/+/, "");
      // url.host (not hostname) keeps a non-default port: host:8443/x and
      // host/x are different remotes.
      return path ? `${url.host}/${path}` : url.host;
    } catch {
      return localRepoIdentity(resolvePath(cwd, value));
    }
  }
  // Local-path remotes — relative (../remote.git) or absolute — resolve
  // against the caller's cwd so unrelated checkouts never share an identity.
  if (value.startsWith("/") || value.startsWith(".") || !value.includes(":")) {
    return localRepoIdentity(resolvePath(cwd, value));
  }
  const scp = value.match(/^([^@]+@)?([^:]+):(.+)$/);
  if (scp) return `${scp[2]}/${scp[3]}`;
  return localRepoIdentity(resolvePath(cwd, value));
}

export function commandEnvironment(
  source: Record<string, string | undefined>,
  credentials: Record<string, string>,
  cwd: string,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(source)) {
    if (typeof value === "string" && !isReservedEnv(name) && name !== "PWD" && name !== "OLDPWD") result[name] = value;
  }
  for (const name of ["HOME", "USER", "LOGNAME", "SHELL", "TMPDIR"] as const) {
    if (source[name]) result[name] = source[name];
  }
  result.PATH = source.SENV_TARGET_PATH || "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
  result.PWD = cwd;
  for (const [name, value] of Object.entries(credentials)) result[name] = value;
  return result;
}

async function validateApprovalResult(
  value: unknown,
  bindings: Binding[],
  now: number,
  privateKey: CryptoKey,
  requestId: string,
): Promise<ApprovalResult & { credentials: Record<string, string> }> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("secretary 审批结果无效");
  const result = value as ApprovalResult;
  if (result.approved !== true) {
    throw new Error(result.denied_reason === "timeout" ? "审批超时" : "审批被拒绝");
  }
  const expected = bindings.map((binding) => binding.env).sort();
  const credentials = result.credential_envelope
    ? await decryptCredentialEnvelope(result.credential_envelope, privateKey, requestId)
    : undefined;
  if (!credentials || typeof credentials !== "object" || Array.isArray(credentials) ||
    JSON.stringify(Object.keys(credentials).sort()) !== JSON.stringify(expected) ||
    Object.values(credentials).some((value) => typeof value !== "string" || value.length === 0 || value.length > 65_536)) {
    throw new Error("secretary 未返回本次申请的完整凭证");
  }
  const expiry = Date.parse(result.expires_at || "");
  // 最长档位是 7 天；多给 10 分钟容忍时钟偏移。
  if (!Number.isFinite(expiry) || expiry <= now || expiry > now + 7 * 24 * 60 * 60 * 1000 + 10 * 60 * 1000 || !result.lease_id) {
    throw new Error("secretary 返回的授权有效期无效");
  }
  return { ...result, credentials };
}

function formatCatalog(catalog: CatalogResponse): string {
  const headers = ["NAME", "FIELDS", "DESCRIPTION", "CREATED_AT"];
  const rows = catalog.items.map((item) => [
    item.name,
    item.fields.join(","),
    item.description || "-",
    item.created_at || "-",
  ]
    .map((value) => value.replace(/[\u0000-\u001f\u007f]/g, " ")));
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index].length)));
  return [headers, ...rows].map((row) => row.map((cell, index) => cell.padEnd(widths[index])).join("  ").trimEnd()).join("\n") + "\n";
}

async function runAuth(invocation: Extract<ParsedInvocation, { action: "auth" }>, deps: ClientDeps): Promise<void> {
  switch (invocation.authAction) {
    case "import": {
      await deps.keychain.promptWrite(TOKEN_SERVICE, KEYCHAIN_ACCOUNT);
      deps.stdout("secretary token 已保存到 macOS Keychain。\n");
      return;
    }
    case "set-url": {
      const url = normalizeBrokerUrl(invocation.value ?? "");
      await deps.keychain.write(URL_SERVICE, KEYCHAIN_ACCOUNT, url);
      deps.stdout(`secretary broker 地址已保存到 macOS Keychain：${url}\n`);
      return;
    }
    case "set-client-id": {
      const id = (invocation.value ?? "").trim();
      if (!id || id.length > 200 || /[\u0000-\u001f\u007f]/.test(id)) throw new Error("client-id 无效");
      await deps.keychain.write(CLIENT_SERVICE, KEYCHAIN_ACCOUNT, id);
      deps.stdout("secretary client-id 已保存到 macOS Keychain。\n");
      return;
    }
    case "status": {
      // Reports presence and source only — the token value itself never prints.
      const settings: Array<[string, string, string]> = [
        ["broker URL", URL_ENV, URL_SERVICE],
        ["token", TOKEN_ENV, TOKEN_SERVICE],
        ["client-id", CLIENT_ENV, CLIENT_SERVICE],
      ];
      const lines: string[] = [];
      for (const [label, envName, service] of settings) {
        const setting = await resolveSetting(deps, envName, service);
        lines.push(setting
          ? `${label}：已配置（来源：${setting.source === "env" ? `环境变量 ${envName}` : "Keychain"}）`
          : `${label}：未配置`);
      }
      deps.stdout(lines.join("\n") + "\n");
      return;
    }
    case "delete": {
      for (const service of [URL_SERVICE, TOKEN_SERVICE, CLIENT_SERVICE]) {
        await deps.keychain.delete(service, KEYCHAIN_ACCOUNT);
      }
      deps.stdout("secretary 配置已从 macOS Keychain 删除。\n");
      return;
    }
  }
}

export type WriteResponse =
  | { status: "applied"; operation: string; item: string; detail: string }
  | { status: "unchanged"; operation: string; item: string; detail: string }
  | { status: "pending_entry"; entry_path: string; expires_at: string; fields: string[] }
  | { status: "rejected"; reason: "denied" | "timeout" };

/** Inline values arrive as one JSON object on stdin — one shape for one and for
 * many, so the agent never has to decide which form to use. */
export function parseStdinValues(raw: string, expected: string[]): Record<string, string> {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error(`需要从标准输入读取字段值 JSON：{"${expected[0]}":"…"}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("标准输入不是合法 JSON（应为 {\"字段名\":\"值\"} 对象）");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("标准输入应为 JSON 对象：{\"字段名\":\"值\"}");
  }
  const record = parsed as Record<string, unknown>;
  const values: Record<string, string> = {};
  for (const name of expected) {
    const value = record[name];
    if (typeof value !== "string" || value.length === 0) throw new Error(`标准输入缺少字段值：${name}`);
    if (value.length > 65_536) throw new Error(`字段值过长：${name}`);
    // Assignment would invoke Object.prototype.__proto__'s setter instead of
    // creating an own property for that otherwise-valid field name.
    Object.defineProperty(values, name, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  const extra = Object.keys(record).filter((key) => !expected.includes(key));
  // Fail closed rather than silently dropping: an unexpected key usually means
  // a `--field` was forgotten, and quietly ignoring it would write half an item.
  if (extra.length) throw new Error(`标准输入包含未声明的字段：${extra.join("、")}（需要对应的 --field NAME=@stdin）`);
  return values;
}

export function parseWriteResponse(value: unknown): WriteResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("secretary 返回结构无效");
  const body = value as Record<string, unknown>;
  const status = body.status;
  if (status === "applied" || status === "unchanged") {
    if (typeof body.detail !== "string" || typeof body.item !== "string" || typeof body.operation !== "string") {
      throw new Error("secretary 返回结构无效");
    }
    const common = { operation: body.operation, item: body.item, detail: body.detail };
    return status === "applied" ? { status: "applied", ...common } : { status: "unchanged", ...common };
  }
  if (status === "pending_entry") {
    const path = body.entry_path;
    const fields = body.fields;
    if (typeof path !== "string" || !path.startsWith("/entry/") || path.length > 400) {
      throw new Error("secretary 返回的录入链接无效");
    }
    if (typeof body.expires_at !== "string" || !Array.isArray(fields) || fields.some((f) => typeof f !== "string")) {
      throw new Error("secretary 返回结构无效");
    }
    return { status, entry_path: path, expires_at: body.expires_at, fields: fields as string[] };
  }
  if (status === "rejected" && (body.reason === "denied" || body.reason === "timeout")) {
    return { status, reason: body.reason };
  }
  throw new Error("secretary 返回结构无效");
}

async function runWrite(
  invocation: Extract<ParsedInvocation, { action: "write" }>,
  config: BrokerConfig,
  canonicalCwd: string,
  deps: ClientDeps,
): Promise<number> {
  const requestId = deps.randomUUID().toLowerCase();
  if (!UUID.test(requestId)) throw new Error("无法生成安全 request id");
  const inlineNames = invocation.fields.filter((field) => field.source === "inline").map((field) => field.name);
  const values = inlineNames.length ? parseStdinValues(await deps.readStdin(), inlineNames) : undefined;

  const body = {
    request_id: requestId,
    operation: invocation.operation,
    item: invocation.item,
    reason: invocation.reason,
    repo: normalizeRepoIdentity(deps.gitRemote(canonicalCwd), canonicalCwd),
    host: deps.hostname().slice(0, 200),
    user: deps.username().slice(0, 200),
    agent: "code-agent",
    ...(invocation.description !== undefined ? { description: invocation.description } : {}),
    ...(invocation.rename !== undefined ? { rename: invocation.rename } : {}),
    ...(invocation.fields.length ? { fields: invocation.fields } : {}),
    ...(values ? { values } : {}),
    ...(invocation.removeField !== undefined ? { field: invocation.removeField } : {}),
    ...(config.clientId ? { client_id: config.clientId } : {}),
  };
  if (JSON.stringify(body).length > MAX_REQUEST_BODY_BYTES) throw new Error("请求体过大");

  deps.stderr("正在向 secretary 提交 vault 写入申请…");
  let interrupted = false;
  const operationAbort = new AbortController();
  const removeInterruptHandler = deps.onInterrupt?.(() => {
    interrupted = true;
    operationAbort.abort();
  }) ?? (() => {});
  let raw: unknown;
  try {
    raw = await brokerJson(deps, config.token, new URL(`${config.url}/v1/writes`), {
      method: "POST",
      body,
      timeoutMs: HEADER_TIMEOUT_MS,
      bodyTimeoutMsFromResponse: (response) => {
        const advertised = Number(response.headers.get("x-secretary-approval-timeout"));
        const seconds = Number.isFinite(advertised) && advertised >= 1 && advertised <= 3600
          ? advertised
          : DEFAULT_APPROVAL_TIMEOUT_S;
        return seconds * 1000 + BODY_TIMEOUT_MARGIN_MS;
      },
      signal: operationAbort.signal,
      // Never resend: the write may already have landed, and a blind retry of a
      // Create would be refused as a name collision anyway (ADR-0005).
      onNetworkError: (error) => {
        if (interrupted) return new Error("已中断等待审批");
        const message = error instanceof Error ? error.message : String(error);
        return new Error(
          `与 secretary 的连接失败或在请求发出后中断（request_id=${requestId}）；不会自动重发。` +
          `请先用 secretary list "${invocation.item}" 确认写入是否已经生效：${message}`,
        );
      },
    });
  } finally {
    removeInterruptHandler();
  }
  if (raw && typeof raw === "object" && !Array.isArray(raw) && typeof (raw as { error?: unknown }).error === "string") {
    throw new Error(`secretary 服务端错误：${String((raw as { error: string }).error).slice(0, 500)}`);
  }

  const result = parseWriteResponse(raw);
  if (result.status === "applied") {
    deps.stdout(`${result.detail}\n`);
    return 0;
  }
  if (result.status === "unchanged") {
    deps.stdout(`${result.detail}（vault 已经是目标状态，未做改动）\n`);
    return 0;
  }
  if (result.status === "pending_entry") {
    // The link is the capability (ADR-0004): show it to the human once, do not
    // write it anywhere, and do not act as if the write has happened.
    deps.stdout(
      `需要 Owner 本人填写以下字段：${result.fields.join("、")}\n` +
      `录入链接（一次性，${result.expires_at} 前有效）：\n` +
      `${config.url}${result.entry_path}\n` +
      `尚未写入 vault。请把链接交给本人，填完后再继续。\n`,
    );
    return 0;
  }
  deps.stderr(result.reason === "denied" ? "写入被拒绝，vault 未改动。" : "审批超时，vault 未改动。");
  return 1;
}

export async function main(args: string[], deps: ClientDeps = defaultDeps): Promise<number> {
  let invocation: ParsedInvocation;
  try {
    invocation = parseInvocation(args);
  } catch (error) {
    deps.stderr(error instanceof Error ? error.message : String(error));
    return 2;
  }

  try {
    if (invocation.action === "auth") {
      await runAuth(invocation, deps);
      return 0;
    }

    const canonicalCwd = await deps.realpath(invocation.cwd);
    if (!(await deps.stat(canonicalCwd)).isDirectory()) throw new Error("调用目录不是目录");
    const config = await resolveConfig(deps);

    if (invocation.action === "list") {
      const url = new URL(`${config.url}/v1/catalog`);
      if (invocation.query) url.searchParams.set("query", invocation.query);
      const catalog = parseCatalogResponse(await brokerJson(deps, config.token, url, {
        method: "GET",
        timeoutMs: CATALOG_TIMEOUT_MS,
      }));
      deps.stdout(invocation.json ? `${JSON.stringify(catalog, null, 2)}\n` : formatCatalog(catalog));
      return 0;
    }

    if (invocation.action === "write") {
      return await runWrite(invocation, config, canonicalCwd, deps);
    }

    // exec: exactly ONE blocking POST carries request + approval + credentials.
    // The request_id is the idempotency key and the envelope AAD binding.
    const requestId = deps.randomUUID().toLowerCase();
    if (!UUID.test(requestId)) throw new Error("无法生成安全 request id");
    const clientKeys = await generateClientKeyExchange();
    const repo = normalizeRepoIdentity(deps.gitRemote(canonicalCwd), canonicalCwd);
    const allBindings = invocation.items.flatMap((item) => item.bindings);
    const body = {
      request_id: requestId,
      reason: invocation.reason,
      repo,
      host: deps.hostname().slice(0, 200),
      user: deps.username().slice(0, 200),
      agent: "code-agent",
      // 完整 argv 上审批卡片：审批人看得见到底要跑什么，服务端也据此识别内联 shell。
      // 密钥永远不在 argv 里——它只由本进程注入子进程环境。
      command_argv: invocation.command,
      items: invocation.items.map((item) => ({ name: item.itemName, bindings: item.bindings })),
      client_public_key_jwk: clientKeys.publicKeyJwk,
      ...(config.clientId ? { client_id: config.clientId } : {}),
    };

    // 这一行在请求发出**之前**打印，而此时还不知道服务端会不会命中已有授权。
    // 所以措辞必须对两种结果都成立——写死「正在等待审批」会在静默复用时
    // 把人白白支使到手机上去看一条根本没发出的通知。
    // P2-9: the broker caps request bodies at 256 KiB; fail locally with a
    // clear message instead of a post-hoc HTTP 413.
    if (JSON.stringify(body).length > MAX_REQUEST_BODY_BYTES) {
      throw new Error("请求体过大（命令 argv 或条目过多）；请缩短命令或拆分请求");
    }

    deps.stderr("正在向 secretary 申请密钥（无有效授权时会推 Telegram 审批）…");
    let interrupted = false;
    const operationAbort = new AbortController();
    const removeInterruptHandler = deps.onInterrupt?.(() => {
      interrupted = true;
      operationAbort.abort();
    }) ?? (() => {});
    let result: unknown;
    try {
      result = await brokerJson(deps, config.token, new URL(`${config.url}/v1/requests`), {
        method: "POST",
        body,
        // Headers must arrive quickly; the long-polled body deadline is then
        // derived from the server-advertised approval timeout so the client
        // always outlives the server-side parking window.
        timeoutMs: HEADER_TIMEOUT_MS,
        bodyTimeoutMsFromResponse: (response) => {
          const advertised = Number(response.headers.get("x-secretary-approval-timeout"));
          const seconds = Number.isFinite(advertised) && advertised >= 1 && advertised <= 3600
            ? advertised
            : DEFAULT_APPROVAL_TIMEOUT_S;
          return seconds * 1000 + BODY_TIMEOUT_MARGIN_MS;
        },
        signal: operationAbort.signal,
        // Fail closed, never resend: the request may already have reached the
        // broker (an identical resend would be idempotent server-side via
        // request_id, but this client deliberately does not retry).
        onNetworkError: (error) => {
          if (interrupted) return new Error("已中断等待审批");
          const message = error instanceof Error ? error.message : String(error);
          if (error instanceof Error && error.name === "TimeoutError") {
            return new Error(`等待 secretary 审批响应超时（request_id=${requestId}）；不会自动重发，请确认审批状态后重试`);
          }
          return new Error(
            `与 secretary 的连接失败或在请求发出后中断（request_id=${requestId}）；` +
            `为安全起见不会自动重发，请确认服务端状态后重试：${message}`,
          );
        },
      });
    } finally {
      removeInterruptHandler();
    }
    // A long-polled 200 can carry an in-band {error} (vault outage, unknown
    // item, encryption failure) — surface the real cause, never misreport it
    // as an approval denial.
    if (result && typeof result === "object" && !Array.isArray(result) &&
      typeof (result as { error?: unknown }).error === "string") {
      throw new Error(`secretary 服务端错误：${String((result as { error: string }).error).slice(0, 500)}`);
    }
    const approved = await validateApprovalResult(
      result, allBindings, deps.now(), clientKeys.privateKey, requestId,
    );
    if (approved.grant_reused) {
      deps.stderr(`已复用服务端仍有效的授权（到期：${approved.expires_at}）。\n`);
    }
    return await deps.spawn(
      invocation.command,
      canonicalCwd,
      commandEnvironment(deps.env, approved.credentials, canonicalCwd),
    );
  } catch (error) {
    deps.stderr(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Default (real) dependencies.

// Minimal env for /usr/bin/security and git: computed from the real runtime
// identity, never hardcoded to a specific user.
function minimalSecurityEnv(): Record<string, string> {
  const info = (() => {
    try {
      return userInfo();
    } catch {
      return { homedir: "/", username: "unknown" };
    }
  })();
  const home = process.env.HOME || info.homedir;
  const user = process.env.USER || info.username;
  return {
    HOME: home,
    USER: user,
    LOGNAME: process.env.LOGNAME || user,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "C.UTF-8",
  };
}

const darwinKeychain: Keychain = {
  read: async (service, account) => {
    const child = Bun.spawn(["/usr/bin/security", "find-generic-password", "-w", "-s", service, "-a", account], {
      env: minimalSecurityEnv(), stdin: "ignore", stdout: "pipe", stderr: "ignore",
    });
    const output = await new Response(child.stdout).text();
    return await child.exited === 0 ? output.trim() : null;
  },
  write: async (service, account, value) => {
    const child = Bun.spawn([
      "/usr/bin/security", "add-generic-password", "-U", "-s", service, "-a", account,
      "-l", service, "-w",
    ], { env: minimalSecurityEnv(), stdin: "pipe", stdout: "ignore", stderr: "ignore" });
    // `security ... -w` prompts twice when the value is omitted from argv.
    // Supplying both lines over stdin keeps even bootstrap values out of ps output.
    child.stdin.write(`${value}\n${value}\n`);
    child.stdin.end();
    if (await child.exited !== 0) throw new Error("无法写入 macOS Keychain");
  },
  promptWrite: async (service, account) => {
    const child = Bun.spawn([
      "/usr/bin/security", "add-generic-password", "-U", "-s", service, "-a", account,
      "-l", service, "-w",
    ], { env: minimalSecurityEnv(), stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    if (await child.exited !== 0) throw new Error("无法写入 macOS Keychain");
    const verify = Bun.spawn([
      "/usr/bin/security", "find-generic-password", "-w", "-s", service, "-a", account,
    ], { env: minimalSecurityEnv(), stdin: "ignore", stdout: "pipe", stderr: "ignore" });
    const value = (await new Response(verify.stdout).text()).trim();
    if (await verify.exited !== 0 || !value) throw new Error("Keychain 未保存 token，请重新输入并确认两次");
  },
  delete: async (service, account) => {
    const child = Bun.spawn(["/usr/bin/security", "delete-generic-password", "-s", service, "-a", account], {
      env: minimalSecurityEnv(), stdin: "ignore", stdout: "ignore", stderr: "ignore",
    });
    const exit = await child.exited;
    if (exit !== 0 && exit !== 44) throw new Error("无法删除 macOS Keychain 项");
  },
};

// Off macOS there is no keychain: reads resolve to "not configured" so the
// SECRETARY_* env vars remain the sole config channel; writes fail loudly.
const KEYCHAIN_UNAVAILABLE = "Keychain unavailable; use SECRETARY_* environment variables";
const unavailableKeychain: Keychain = {
  read: async () => null,
  write: async () => { throw new Error(KEYCHAIN_UNAVAILABLE); },
  promptWrite: async () => { throw new Error(KEYCHAIN_UNAVAILABLE); },
  delete: async () => { throw new Error(KEYCHAIN_UNAVAILABLE); },
};

export const defaultKeychain: Keychain = process.platform === "darwin" ? darwinKeychain : unavailableKeychain;

export const defaultDeps: ClientDeps = {
  env: process.env,
  fetch,
  keychain: defaultKeychain,
  realpath,
  stat,
  now: Date.now,
  randomUUID: () => crypto.randomUUID(),
  hostname,
  username: () => userInfo().username,
  gitRemote: (cwd) => {
    const result = Bun.spawnSync(["/usr/bin/git", "-C", cwd, "remote", "get-url", "origin"], {
      env: minimalSecurityEnv(), stdout: "pipe", stderr: "ignore",
    });
    return result.exitCode === 0 ? result.stdout.toString().trim() : undefined;
  },
  spawn: async (argv, cwd, env) => {
    const child = Bun.spawn(argv, { cwd, env, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    return await child.exited;
  },
  stdout: (message) => process.stdout.write(message),
  stderr: (message) => process.stderr.write(`${message}\n`),
  readStdin: () => Bun.stdin.text(),
  onInterrupt: (handler) => {
    process.once("SIGINT", handler);
    process.once("SIGTERM", handler);
    return () => {
      process.off("SIGINT", handler);
      process.off("SIGTERM", handler);
    };
  },
};

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
