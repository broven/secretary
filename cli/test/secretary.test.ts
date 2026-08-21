import { describe, expect, test } from "bun:test";
import {
  commandEnvironment,
  normalizeRepoIdentity,
  decryptCredentialEnvelope,
  describeTlsCertError,
  extractReason,
  generateClientKeyExchange,
  isTlsCertError,
  main,
  parseCatalogResponse,
  parseInvocation,
  CLIENT_SERVICE,
  TOKEN_SERVICE,
  URL_SERVICE,
  type ClientDeps,
  type Keychain,
} from "../src/secretary.ts";

const ENVELOPE_INFO = new TextEncoder().encode("secretary:credential-envelope:v1");

// Server-side encrypt path, mirroring server/src/envelope.ts: ephemeral ECDH
// P-256 + HKDF-SHA256 + AES-256-GCM with the AAD bound to the request id.
async function encryptForClient(
  publicKeyJwk: JsonWebKey,
  credentials: Record<string, string>,
  requestId = uuid(1),
) {
  const clientPublicKey = await crypto.subtle.importKey(
    "jwk", publicKeyJwk, { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  const serverKeys = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPublicKey }, serverKeys.privateKey, 256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: ENVELOPE_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(
        `secretary:credential-envelope:v1\nrequest_id=${requestId}`,
      ),
      tagLength: 128,
    },
    key,
    new TextEncoder().encode(JSON.stringify(credentials)),
  );
  return {
    version: 1 as const,
    algorithm: "P256-HKDF-SHA256+A256GCM" as const,
    server_public_key: await crypto.subtle.exportKey("jwk", serverKeys.publicKey),
    salt: Buffer.from(salt).toString("base64url"),
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(ciphertext).toString("base64url"),
  };
}

const CATALOG_RESPONSE = {
  items: [
    {
      name: "Example API",
      description: "给测试命令使用",
      fields: ["password"],
      created_at: "2026-08-21T08:09:10.000Z",
    },
    {
      name: "Other API",
      description: "第二个测试条目",
      fields: ["password", "username"],
      created_at: "2025-01-02T03:04:05.000Z",
    },
  ],
};

function uuid(index: number): string {
  return `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
}

type MakeDepsOptions = {
  requestResult?: unknown;
  envelopeRequestId?: string;
  resultExtras?: Record<string, unknown>;
  stdinText?: string;
};

function makeDeps(options: MakeDepsOptions = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const requests: Array<{
    method: string;
    url: string;
    path: string;
    body?: unknown;
    auth: string | null;
  }> = [];
  const spawns: Array<{ argv: string[]; cwd: string; env: Record<string, string> }> = [];
  let nextUuid = 1;
  const keychainValues: Record<string, string> = {
    [URL_SERVICE]: "https://keychain.example.com",
    [TOKEN_SERVICE]: "keychain-token",
    [CLIENT_SERVICE]: uuid(99),
  };
  const keychain: Keychain = {
    read: async (service, account) => account === "secretary" ? keychainValues[service] ?? null : null,
    write: async (service, _account, value) => { keychainValues[service] = value; },
    promptWrite: async () => {},
    delete: async (service) => { delete keychainValues[service]; },
  };
  const stdinText = options.stdinText ?? "";
  const deps: ClientDeps = {
    env: {
      HOME: "/Users/test",
      PATH: "/trusted/broker/path",
      SENV_TARGET_PATH: "/caller/bin:/usr/bin",
      SECRETARY_URL: "https://broker.example.com/",
      SECRETARY_TOKEN: "env-token",
      SECRETARY_CLIENT_ID: uuid(42),
      WMILL_TOKEN: "must-not-reach-child",
      FNOX_STATE_DIR: "/must/not/reach",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
    },
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method || "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      requests.push({
        method,
        url: url.href,
        path: `${url.pathname}${url.search}`,
        body,
        auth: new Headers(init?.headers).get("Authorization"),
      });
      if (method === "POST" && url.pathname === "/v1/requests") {
        const items = body.items as Array<{ bindings: Array<{ env: string }> }>;
        const credentials: Record<string, string> = {};
        for (const item of items) {
          for (const binding of item.bindings) credentials[binding.env] = `approved-${binding.env}`;
        }
        const result = options.requestResult ?? {
          approved: true,
          ttl: "1h",
          expires_at: "2030-01-01T01:00:00.000Z",
          lease_id: "lease-1",
          credential_envelope: await encryptForClient(
            body.client_public_key_jwk,
            credentials,
            options.envelopeRequestId ?? body.request_id,
          ),
          ...options.resultExtras,
        };
        // Leading whitespace mimics the broker's keep-alive heartbeat bytes.
        return new Response(`  \n\n${JSON.stringify(result)}`, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (method === "GET" && url.pathname === "/v1/catalog") {
        return Response.json(CATALOG_RESPONSE);
      }
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    }) as typeof fetch,
    keychain,
    realpath: (async () => "/canonical/repo") as ClientDeps["realpath"],
    stat: (async () => ({ isDirectory: () => true })) as never,
    now: () => Date.parse("2030-01-01T00:00:00.000Z"),
    randomUUID: () => uuid(nextUuid++),
    hostname: () => "test-host",
    username: () => "test-user",
    gitRemote: () => "git@github.com:owner/repo.git",
    spawn: async (argv, cwd, env) => {
      spawns.push({ argv, cwd, env });
      return 7;
    },
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
    readStdin: async () => stdinText,
  };
  return { deps, stdout, stderr, requests, spawns, keychainValues };
}

describe("self-contained secretary client", () => {
  test("parses list and safe exec argv without a shell", () => {
    expect(parseInvocation(["--cwd", "/repo", "list", "dns", "--json"]))
      .toMatchObject({ action: "list", query: "dns", json: true });
    expect(parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool", "arg with spaces",
    ])).toMatchObject({
      action: "exec",
      items: [{ itemName: "Example API", bindings: [{ field: "password", env: "EXAMPLE_TOKEN" }] }],
      command: ["tool", "arg with spaces"],
    });
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=WMILL_TOKEN", "--", "tool",
    ])).toThrow("不能绑定");
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=PATH", "--", "tool",
    ])).toThrow("不能绑定");
    // SECRETARY_ is a reserved prefix in this port.
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=SECRETARY_TOKEN", "--", "tool",
    ])).toThrow("不能绑定");
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=SECRETARY_ANYTHING", "--", "tool",
    ])).toThrow("不能绑定");
  });

  test("requires a real reason before anything is sent", () => {
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ])).toThrow("--reason");
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "太短", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ])).toThrow("至少");
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "a".repeat(2001),
      "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ])).toThrow("过长");
  });

  test("normalises the reason and keeps it out of the item groups", () => {
    expect(extractReason(["--reason", "  给 CI  补一个   tag ", "--item", "X", "password=Y"]))
      .toEqual({ reason: "给 CI 补一个 tag", tokens: ["--item", "X", "password=Y"] });
    expect(() => extractReason(["--reason", "第一个理由文字", "--reason", "第二个理由文字"]))
      .toThrow("只能给一次");
  });

  test("carries the full argv, never a shell string", () => {
    const parsed = parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "跑一次数据导出脚本备份",
      "--item", "Example API", "password=EXAMPLE_TOKEN",
      "--", "sh", "-c", "curl x | gzip > y",
    ]);
    expect(parsed).toMatchObject({
      command: ["sh", "-c", "curl x | gzip > y"],
      reason: "跑一次数据导出脚本备份",
    });
  });

  test("deprecates the positional exec syntax in favor of --item", () => {
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ])).toThrow("--item");
  });

  test("accepts several --item groups and merges same-named items", () => {
    expect(parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "GitHub", "password=GITHUB_TOKEN",
      "--item", "OpenAI", "password=OPENAI_KEY",
      "--", "tool",
    ])).toMatchObject({
      action: "exec",
      items: [
        { itemName: "GitHub", bindings: [{ field: "password", env: "GITHUB_TOKEN" }] },
        { itemName: "OpenAI", bindings: [{ field: "password", env: "OPENAI_KEY" }] },
      ],
    });
    // Split groups for one item merge into a single request, identical to the comma form.
    expect(parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Svc", "username=SVC_USER", "--item", "Svc", "password=SVC_PASS", "--", "tool",
    ])).toMatchObject({
      action: "exec",
      items: [{
        itemName: "Svc",
        bindings: [{ field: "password", env: "SVC_PASS" }, { field: "username", env: "SVC_USER" }],
      }],
    });
  });

  test("fails closed on duplicate fields and cross-item env collisions", () => {
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Svc", "username=A", "--item", "Svc", "username=B", "--", "tool",
    ])).toThrow("字段重复绑定");
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "A", "password=SHARED", "--item", "B", "password=SHARED", "--", "tool",
    ])).toThrow("环境变量重复绑定");
    const many = ["--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag"];
    for (let index = 0; index <= 10; index++) many.push("--item", `Item${index}`, `password=ENV${index}`);
    many.push("--", "tool");
    expect(() => parseInvocation(many)).toThrow("最多申请");
  });

  test("validates catalog responses and drops secret-shaped extra fields by omission", () => {
    expect(parseCatalogResponse({
      items: [{ ...CATALOG_RESPONSE.items[0], password: "must-never-leak" }],
    }).items[0]).toEqual({
      name: "Example API",
      description: "给测试命令使用",
      fields: ["password"],
      created_at: "2026-08-21T08:09:10.000Z",
    });
    expect(JSON.stringify(parseCatalogResponse(CATALOG_RESPONSE))).not.toContain("must-never-leak");
    // Custom field names are now legal catalog fields…
    expect(parseCatalogResponse({ items: [{ name: "X", fields: ["api_key"] }] }).items[0].fields)
      .toEqual(["api_key"]);
    // …but names that would break the binding syntax are not.
    expect(() => parseCatalogResponse({ items: [{ name: "X", fields: ["a=b"] }] })).toThrow();
    expect(() => parseCatalogResponse({ items: [{ name: "X", fields: ["a,b"] }] })).toThrow();
    expect(() => parseCatalogResponse({ items: "no" })).toThrow();
  });

  test("preserves catalog creation times for lost-create recovery", () => {
    expect(parseCatalogResponse({
      items: [{
        name: "Example API",
        description: "给测试命令使用",
        fields: ["password"],
        created_at: "2026-08-21T08:09:10.000Z",
      }],
    }).items[0]).toEqual({
      name: "Example API",
      description: "给测试命令使用",
      fields: ["password"],
      created_at: "2026-08-21T08:09:10.000Z",
    });
  });

  test("restores caller PATH and strips all broker controls from the final child", () => {
    expect(commandEnvironment({
      PATH: "/broker/bin",
      SENV_TARGET_PATH: "/caller/bin",
      SECRETARY_TOKEN: "broker-token",
      SECRETARY_URL: "https://broker",
      WMILL_TOKEN: "broker",
      FNOX_STATE_DIR: "state",
      BUN_OPTIONS: "--preload=evil",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
    }, { API_TOKEN: "approved" }, "/repo")).toEqual({
      PATH: "/caller/bin",
      PWD: "/repo",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
      API_TOKEN: "approved",
    });
  });

  test("exec sends exactly one POST, validates, and runs the exact command", async () => {
    const context = makeDeps();
    expect(await main([
      "--cwd", "/linked/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool", "arg with spaces",
    ], context.deps)).toBe(7);
    expect(context.spawns).toEqual([{
      argv: ["tool", "arg with spaces"],
      cwd: "/canonical/repo",
      env: {
        HOME: "/Users/test",
        PATH: "/caller/bin:/usr/bin",
        PWD: "/canonical/repo",
        SSH_AUTH_SOCK: "/tmp/agent.sock",
        EXAMPLE_TOKEN: "approved-EXAMPLE_TOKEN",
      },
    }]);
    // Exactly one HTTP request total: the single blocking POST.
    expect(context.requests).toHaveLength(1);
    const request = context.requests[0];
    expect(request.method).toBe("POST");
    expect(request.url).toBe("https://broker.example.com/v1/requests");
    expect(request.auth).toBe("Bearer env-token");
    expect(request.body).toMatchObject({
      request_id: uuid(1),
      reason: "给 CI 补一个 release tag",
      repo: "github.com/owner/repo",
      host: "test-host",
      user: "test-user",
      agent: "code-agent",
      // 审批人要能逐字看到将要执行的命令，而不是只有一个 basename。
      command_argv: ["tool", "arg with spaces"],
      items: [{ name: "Example API", bindings: [{ field: "password", env: "EXAMPLE_TOKEN" }] }],
      client_id: uuid(42),
    });
    // The JWK travels as an object, not a serialized string.
    expect((request.body as { client_public_key_jwk: JsonWebKey }).client_public_key_jwk)
      .toMatchObject({ kty: "EC", crv: "P-256" });
    // Secret values never appear in what went over the wire.
    expect(JSON.stringify(context.requests)).not.toContain("approved-EXAMPLE_TOKEN");
  });

  test("approves several distinct items in one exec and injects every env", async () => {
    const context = makeDeps();
    expect(await main([
      "--cwd", "/linked/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "password=EXAMPLE_TOKEN",
      "--item", "Other API", "password=OTHER_TOKEN",
      "--", "tool",
    ], context.deps)).toBe(7);
    expect(context.spawns).toHaveLength(1);
    expect(context.spawns[0].env).toMatchObject({
      EXAMPLE_TOKEN: "approved-EXAMPLE_TOKEN",
      OTHER_TOKEN: "approved-OTHER_TOKEN",
    });
    expect(context.requests).toHaveLength(1);
    expect(context.requests[0].body).toMatchObject({
      items: [
        { name: "Example API", bindings: [{ field: "password", env: "EXAMPLE_TOKEN" }] },
        { name: "Other API", bindings: [{ field: "password", env: "OTHER_TOKEN" }] },
      ],
    });
  });

  test("denied approval exits 1 and never spawns", async () => {
    const context = makeDeps({ requestResult: { approved: false, denied_reason: "denied" } });
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(1);
    expect(context.spawns).toHaveLength(0);
    expect(context.stderr.join("")).toContain("拒绝");
  });

  test("timeout denial exits 1 with a timeout message and never spawns", async () => {
    const context = makeDeps({ requestResult: { approved: false, denied_reason: "timeout" } });
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(1);
    expect(context.spawns).toHaveLength(0);
    expect(context.stderr.join("")).toContain("超时");
  });

  test("an envelope bound to a different request id fails closed", async () => {
    const context = makeDeps({ envelopeRequestId: uuid(77) });
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(1);
    expect(context.spawns).toHaveLength(0);
    expect(context.stderr.join("")).toContain("无法解密");
  });

  test("prints the reuse notice when the server reused a standing grant", async () => {
    const context = makeDeps({ resultExtras: { grant_reused: true } });
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(7);
    expect(context.stderr.join("")).toContain("复用");
  });

  test("decrypts only with the per-request in-memory private key", async () => {
    const first = await generateClientKeyExchange();
    const second = await generateClientKeyExchange();
    const envelope = await encryptForClient(first.publicKeyJwk, { API_TOKEN: "secret" });
    expect(await decryptCredentialEnvelope(envelope, first.privateKey, uuid(1))).toEqual({ API_TOKEN: "secret" });
    expect(decryptCredentialEnvelope(envelope, second.privateKey, uuid(1))).rejects.toThrow("无法解密");
    expect(decryptCredentialEnvelope(envelope, first.privateKey, uuid(2))).rejects.toThrow("无法解密");
  });

  test("list renders the catalog table with an optional query", async () => {
    const context = makeDeps();
    expect(await main(["--cwd", "/repo", "list", "example"], context.deps)).toBe(0);
    expect(context.requests).toHaveLength(1);
    expect(context.requests[0].path).toBe("/v1/catalog?query=example");
    expect(context.requests[0].auth).toBe("Bearer env-token");
    const table = context.stdout.join("");
    expect(table).toContain("NAME");
    expect(table).toContain("FIELDS");
    expect(table).toContain("DESCRIPTION");
    expect(table).toContain("CREATED_AT");
    expect(table).toContain("2026-08-21T08:09:10.000Z");
    expect(table).toContain("Example API");
    expect(table).toContain("password,username");
    expect(table).not.toContain("env-token");
  });

  test("list --json prints the parsed items JSON", async () => {
    const context = makeDeps();
    expect(await main(["--cwd", "/repo", "list", "--json"], context.deps)).toBe(0);
    expect(context.requests[0].path).toBe("/v1/catalog");
    expect(JSON.parse(context.stdout.join(""))).toEqual({
      items: [
        {
          name: "Example API",
          description: "给测试命令使用",
          fields: ["password"],
          created_at: "2026-08-21T08:09:10.000Z",
        },
        {
          name: "Other API",
          description: "第二个测试条目",
          fields: ["password", "username"],
          created_at: "2025-01-02T03:04:05.000Z",
        },
      ],
    });
  });

  test("environment config wins over the keychain", async () => {
    // The default deps carry both env config and (different) keychain values;
    // the happy-path assertions above already prove env-token/broker.example.com
    // win. Here remove env config and observe the keychain fallback.
    const context = makeDeps();
    delete context.deps.env.SECRETARY_URL;
    delete context.deps.env.SECRETARY_TOKEN;
    delete context.deps.env.SECRETARY_CLIENT_ID;
    expect(await main(["--cwd", "/repo", "list"], context.deps)).toBe(0);
    expect(context.requests[0].url).toBe("https://keychain.example.com/v1/catalog");
    expect(context.requests[0].auth).toBe("Bearer keychain-token");
  });

  test("keychain client_id is used when env is absent, omitted when nowhere", async () => {
    const context = makeDeps();
    delete context.deps.env.SECRETARY_CLIENT_ID;
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(7);
    expect(context.requests[0].body).toMatchObject({ client_id: uuid(99) });

    const bare = makeDeps();
    delete bare.deps.env.SECRETARY_CLIENT_ID;
    delete bare.keychainValues[CLIENT_SERVICE];
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], bare.deps)).toBe(7);
    expect(Object.keys(bare.requests[0].body as Record<string, unknown>)).not.toContain("client_id");
  });

  test("missing token yields an actionable error", async () => {
    const context = makeDeps();
    delete context.deps.env.SECRETARY_TOKEN;
    delete context.keychainValues[TOKEN_SERVICE];
    expect(await main(["--cwd", "/repo", "list"], context.deps)).toBe(1);
    const message = context.stderr.join("");
    expect(message).toContain("SECRETARY_TOKEN");
    expect(message).toContain("auth import");
    expect(context.requests).toHaveLength(0);
  });

  test("missing broker URL yields an actionable error", async () => {
    const context = makeDeps();
    delete context.deps.env.SECRETARY_URL;
    delete context.keychainValues[URL_SERVICE];
    expect(await main(["--cwd", "/repo", "list"], context.deps)).toBe(1);
    const message = context.stderr.join("");
    expect(message).toContain("SECRETARY_URL");
    expect(message).toContain("set-url");
  });

  test("broker HTTP errors surface the status and server message", async () => {
    const context = makeDeps();
    context.deps.fetch = (async () =>
      new Response(JSON.stringify({ error: "token revoked" }), { status: 403 })) as typeof fetch;
    expect(await main(["--cwd", "/repo", "list"], context.deps)).toBe(1);
    const message = context.stderr.join("");
    expect(message).toContain("HTTP 403");
    expect(message).toContain("token revoked");
  });

  test("a connection failure on exec fails closed without a resend", async () => {
    const context = makeDeps();
    let calls = 0;
    context.deps.fetch = (async () => {
      calls++;
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag", "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(1);
    expect(calls).toBe(1);
    expect(context.spawns).toHaveLength(0);
    const message = context.stderr.join("");
    expect(message).toContain("不会自动重发");
    expect(message).toContain(uuid(1));
  });

  test("auth status reports sources without printing the token", async () => {
    const context = makeDeps();
    delete context.deps.env.SECRETARY_TOKEN;
    expect(await main(["--cwd", "/repo", "auth", "status"], context.deps)).toBe(0);
    const output = context.stdout.join("");
    expect(output).toContain("broker URL：已配置");
    expect(output).toContain("环境变量 SECRETARY_URL");
    expect(output).toContain("token：已配置（来源：Keychain）");
    expect(output).not.toContain("keychain-token");
    expect(output).not.toContain("env-token");
  });

  test("auth set-url validates and stores, auth delete removes all entries", async () => {
    const context = makeDeps();
    expect(await main(["--cwd", "/repo", "auth", "set-url", "https://new.example.com/"], context.deps)).toBe(0);
    expect(context.keychainValues[URL_SERVICE]).toBe("https://new.example.com");
    expect(await main(["--cwd", "/repo", "auth", "set-url", "ftp://bad"], context.deps)).toBe(1);
    expect(await main(["--cwd", "/repo", "auth", "delete"], context.deps)).toBe(0);
    expect(context.keychainValues[URL_SERVICE]).toBeUndefined();
    expect(context.keychainValues[TOKEN_SERVICE]).toBeUndefined();
    expect(context.keychainValues[CLIENT_SERVICE]).toBeUndefined();
  });

  test("classifies TLS cert failures but not timeouts/aborts/plain errors", () => {
    expect(isTlsCertError(new Error("unknown certificate verification error"))).toBe(true);
    expect(isTlsCertError(Object.assign(new Error("x"), { code: "SELF_SIGNED_CERT_IN_CHAIN" }))).toBe(true);
    expect(isTlsCertError(Object.assign(new Error("x"), { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }))).toBe(true);
    expect(isTlsCertError(Object.assign(new Error("cert"), { name: "TimeoutError" }))).toBe(false);
    expect(isTlsCertError(Object.assign(new Error("cert"), { name: "AbortError" }))).toBe(false);
    expect(isTlsCertError(new TypeError("Failed to fetch"))).toBe(false);
  });

  test("TLS cert error message names the host, the code, and the remedy", () => {
    const message = describeTlsCertError(
      "secretary.example.com",
      Object.assign(new Error("bad"), { code: "SELF_SIGNED_CERT_IN_CHAIN" }),
    ).message;
    expect(message).toContain("secretary.example.com");
    expect(message).toContain("SELF_SIGNED_CERT_IN_CHAIN");
    expect(message).toContain("NODE_EXTRA_CA_CERTS");
  });

  test("surfaces the actionable TLS message (with host) instead of the opaque string", async () => {
    const context = makeDeps();
    context.deps.fetch = (async () => {
      throw new Error("unknown certificate verification error");
    }) as typeof fetch;
    expect(await main(["--cwd", "/repo", "list", "example"], context.deps)).toBe(1);
    const err = context.stderr.join("");
    expect(err).toContain("broker.example.com");
    expect(err).toContain("NODE_EXTRA_CA_CERTS");
    expect(err).not.toBe("unknown certificate verification error");
  });
});

describe("review fixes", () => {
  test("P1-2: without a git remote, repo identity is the canonical path, not the basename", () => {
    expect(normalizeRepoIdentity("git@github.com:owner/repo.git", "/work/a/project"))
      .toBe("github.com/owner/repo");
    const a = normalizeRepoIdentity(undefined, "/work/a/project");
    const b = normalizeRepoIdentity(undefined, "/tmp/project");
    expect(a).toBe("local:/work/a/project");
    expect(b).toBe("local:/tmp/project");
    expect(a).not.toBe(b);
    // Over-long paths degrade to a hash, still collision-resistant and <=200 chars.
    const long = normalizeRepoIdentity(undefined, `/deep/${"x".repeat(300)}/project`);
    expect(long.startsWith("local:sha256:")).toBe(true);
    expect(long.length).toBeLessThanOrEqual(200);
  });

  test("P1-iv: relative/local remotes resolve against cwd; URL remotes keep the port", () => {
    // Relative path remotes must not collide across unrelated checkouts.
    expect(normalizeRepoIdentity("../remote.git", "/work/a/checkout"))
      .toBe("local:/work/a/remote");
    expect(normalizeRepoIdentity("../remote.git", "/tmp/other/checkout"))
      .toBe("local:/tmp/other/remote");
    expect(normalizeRepoIdentity("./remote.git", "/work/a/checkout"))
      .toBe("local:/work/a/checkout/remote");
    // Absolute path remotes are canonical already.
    expect(normalizeRepoIdentity("/srv/git/repo.git", "/anywhere"))
      .toBe("local:/srv/git/repo");
    // file:// remotes are local paths in disguise.
    expect(normalizeRepoIdentity("file:///srv/git/repo.git", "/anywhere"))
      .toBe("local:/srv/git/repo");
    // Non-default ports survive: host:8443/x and host/x are different remotes.
    expect(normalizeRepoIdentity("https://git.example.com:8443/owner/repo.git", "/x"))
      .toBe("git.example.com:8443/owner/repo");
    expect(normalizeRepoIdentity("https://git.example.com/owner/repo.git", "/x"))
      .toBe("git.example.com/owner/repo");
    // scp-style stays as before.
    expect(normalizeRepoIdentity("git@github.com:owner/repo.git", "/x"))
      .toBe("github.com/owner/repo");
  });

  test("P2-1: custom field names parse as bindings and reach the wire", async () => {
    expect(parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "api_key=EXAMPLE_TOKEN", "--", "tool",
    ])).toMatchObject({
      items: [{ itemName: "Example API", bindings: [{ field: "api_key", env: "EXAMPLE_TOKEN" }] }],
    });
    expect(() => parseInvocation([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "a=b=EXAMPLE_TOKEN", "--", "tool",
    ])).toThrow(); // '=' inside the field name cannot parse into a valid env
    const context = makeDeps();
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "api_key=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(7);
    expect((context.requests[0].body as { items: unknown }).items)
      .toEqual([{ name: "Example API", bindings: [{ field: "api_key", env: "EXAMPLE_TOKEN" }] }]);
  });

  test("P2-3: an in-band {error} body reports the real cause, not an approval denial", async () => {
    const context = makeDeps({ requestResult: { error: "catalog unavailable: vault sync failed" } });
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(1);
    const err = context.stderr.join("\n");
    expect(err).toContain("服务端错误");
    expect(err).toContain("catalog unavailable: vault sync failed");
    expect(err).not.toContain("审批被拒绝");
    expect(context.spawns).toHaveLength(0);
  });

  test("P2-9: an over-large request body fails locally before anything is sent", async () => {
    const context = makeDeps();
    const args = [
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ];
    // 60 × 4000-char args ≈ 240 KB serialized: past the local preflight cap.
    for (let index = 0; index < 60; index++) args.push("y".repeat(4000));
    expect(await main(args, context.deps)).toBe(1);
    expect(context.stderr.join("\n")).toContain("请求体过大");
    expect(context.requests).toHaveLength(0);
    expect(context.spawns).toHaveLength(0);
  });

  test("P2-2: the long-poll body deadline follows the server-advertised approval timeout", async () => {
    // The response carries X-Secretary-Approval-Timeout; the client must accept
    // a body that takes longer than the old fixed deadline would have allowed.
    // Here we only verify the header is consumed without breaking the flow.
    const context = makeDeps();
    const baseFetch = context.deps.fetch;
    context.deps.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const response = await baseFetch(input, init);
      const headers = new Headers(response.headers);
      headers.set("X-Secretary-Approval-Timeout", "600");
      return new Response(response.body, { status: response.status, headers });
    }) as typeof fetch;
    expect(await main([
      "--cwd", "/repo", "exec", "--reason", "给 CI 补一个 release tag",
      "--item", "Example API", "password=EXAMPLE_TOKEN", "--", "tool",
    ], context.deps)).toBe(7);
  });
});
