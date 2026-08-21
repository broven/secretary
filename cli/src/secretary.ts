#!/usr/bin/env bun
// Self-contained secretary client. Runtime dependencies: macOS Keychain
// (optional; SECRETARY_* env vars work everywhere) and HTTPS only.
//
// Wire contract mirrors server/src/types.ts and server/src/envelope.ts — this
// file must stay a single self-contained module (no imports from server/).

import { realpath, stat } from "node:fs/promises";
import { basename } from "node:path";
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
// One blocking POST covers the whole approval: server-side approval timeout is
// 300 s, plus margin for network and heartbeat flushing.
const REQUEST_TIMEOUT_MS = 330_000;
const CATALOG_TIMEOUT_MS = 60_000;
const MAX_ITEMS = 10;
const EXEC_USAGE =
  "用法：secretary exec --reason \"申请理由\" --item ITEM field=ENV[,field=ENV] [--item ITEM field=ENV ...] -- command...";
const AUTH_USAGE = "用法：secretary auth import|status|delete|set-url <url>|set-client-id <id>";
/** 理由必传；服务端也会硬拒空/过短，这里先拦一道是为了给调用方一个明确的报错。 */
const MIN_REASON_LENGTH = 10;
const MAX_REASON_LENGTH = 2000;
const MAX_ARGV_ENTRIES = 200;
const MAX_ARGV_ENTRY_LENGTH = 4096;

export type CatalogField = "username" | "password";
export type Binding = { field: CatalogField; env: string };
export type CatalogResponse = {
  items: Array<{ name: string; description: string; fields: CatalogField[] }>;
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
  onInterrupt?: (handler: () => void) => () => void;
};

export type AuthAction = "import" | "status" | "delete" | "set-url" | "set-client-id";

export type ExecItem = { itemName: string; bindings: Binding[] };
export type ParsedInvocation =
  | { action: "list"; cwd: string; query: string; json: boolean }
  | { action: "exec"; cwd: string; items: ExecItem[]; command: string[]; reason: string }
  | { action: "auth"; cwd: string; authAction: AuthAction; value?: string };

function isReservedEnv(name: string): boolean {
  return RESERVED_ENV.has(name) || RESERVED_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function parseSingleBinding(value: string): Binding {
  const match = value.match(/^(username|password)=([A-Z][A-Z0-9_]*)$/);
  if (!match) throw new Error(`无效 binding：${value}`);
  const field = match[1] as CatalogField;
  const env = match[2];
  if (!ENV_NAME.test(env) || isReservedEnv(env)) throw new Error(`不能绑定到环境变量：${env}`);
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
  if (action === "exec") {
    const separator = rest.indexOf("--");
    if (separator < 0 || separator === rest.length - 1) throw new Error(EXEC_USAGE);
    const { reason, tokens } = extractReason(rest.slice(0, separator));
    const command = rest.slice(separator + 1);
    if (command.length > MAX_ARGV_ENTRIES) throw new Error(`命令参数过多（上限 ${MAX_ARGV_ENTRIES} 个）`);
    if (command.some((part) => part.length > MAX_ARGV_ENTRY_LENGTH)) throw new Error("命令参数过长");
    return { action, cwd, items: parseItemGroups(tokens), command, reason };
  }
  throw new Error("用法：secretary list|exec|auth ...");
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
    const fields = item.fields.filter((field): field is CatalogField => field === "username" || field === "password");
    if (fields.length === 0 || fields.length !== item.fields.length || new Set(fields).size !== fields.length) {
      throw new Error("密钥目录字段无效");
    }
    return {
      name: item.name.trim(),
      description: typeof item.description === "string" ? item.description.trim().slice(0, 1000) : "",
      fields: fields.sort(),
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
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new Error("secretary 响应超过安全限制");
  return text;
}

async function brokerJson(
  deps: ClientDeps,
  token: string,
  url: URL,
  init: {
    method: string;
    body?: unknown;
    timeoutMs: number;
    signal?: AbortSignal;
    onNetworkError?: (error: unknown) => Error;
  },
): Promise<unknown> {
  let response: Response;
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
        ? AbortSignal.any([AbortSignal.timeout(init.timeoutMs), init.signal])
        : AbortSignal.timeout(init.timeoutMs),
    });
  } catch (error) {
    // A cert failure gets rewritten with the host and remedy. Any other network
    // failure goes through the caller's wrapper (exec fails closed: no resend).
    if (isTlsCertError(error)) throw describeTlsCertError(url.host, error);
    throw init.onNetworkError ? init.onNetworkError(error) : error;
  }
  const text = await readTextLimited(response);
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

function normalizeRepoIdentity(remote: string | undefined, cwd: string): string {
  const value = remote?.trim().replace(/\/+$/, "").replace(/\.git$/, "");
  if (!value) return basename(cwd);
  const scp = value.includes("://") ? null : value.match(/^([^@]+@)?([^:]+):(.+)$/);
  if (scp) return `${scp[2]}/${scp[3]}`;
  try {
    const url = new URL(value);
    const path = url.pathname.replace(/^\/+/, "");
    return path ? `${url.hostname}/${path}` : url.hostname;
  } catch {
    return value.slice(0, 200);
  }
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
  const headers = ["NAME", "FIELDS", "DESCRIPTION"];
  const rows = catalog.items.map((item) => [item.name, item.fields.join(","), item.description || "-"]
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
        timeoutMs: REQUEST_TIMEOUT_MS,
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
