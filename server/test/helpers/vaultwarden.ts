// Bootstrap helpers for integration tests against a throwaway vaultwarden.
//
// These are also imported by the compose smoke script, so keep them generic:
// no test-framework imports, no third-party dependencies — only node builtins,
// WebCrypto, fetch, and Bun.spawn.

import { createHmac, createCipheriv, pbkdf2Sync, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { chmod, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";

const KDF_ITERATIONS = 600_000;

type FetchOpts = { fetchImpl?: typeof fetch };

/**
 * A fetch that trusts one extra CA certificate (the throwaway container's
 * self-signed cert). Relies on Bun's `tls` fetch extension.
 */
export function fetchWithCa(caFile: string): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const ca = await readFile(caFile, "utf8");
    return fetch(input, { ...init, tls: { ca } } as RequestInit);
  }) as typeof fetch;
}

/**
 * Minimal PATH for bw subprocesses. bw is a `#!/usr/bin/env node` script, so
 * the directory holding the node interpreter must be reachable.
 */
export function bwSubprocessPath(): string {
  const nodeBin = Bun.which("node");
  const nodeDir = nodeBin ? nodeBin.slice(0, nodeBin.lastIndexOf("/")) : "";
  return ["/usr/bin", "/bin", "/usr/sbin", "/sbin", ...(nodeDir ? [nodeDir] : [])].join(":");
}

function b64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

/** Bitwarden master key: PBKDF2-SHA256(password, lowercased email, 600k iterations). */
function deriveMasterKey(email: string, password: string): Buffer {
  const salt = email.trim().toLowerCase();
  return pbkdf2Sync(password, salt, KDF_ITERATIONS, 32, "sha256");
}

/** Server-side auth hash: PBKDF2-SHA256(masterKey, password, 1 iteration). */
function deriveMasterPasswordHash(masterKey: Buffer, password: string): string {
  return b64(pbkdf2Sync(masterKey, password, 1, 32, "sha256"));
}

/**
 * Stretch the 32-byte master key to enc/mac halves with HKDF-EXPAND only —
 * the master key already is the PRK, so no extract step.
 */
function stretchMasterKey(masterKey: Buffer): { encKey: Buffer; macKey: Buffer } {
  const expand = (info: string): Buffer =>
    createHmac("sha256", masterKey).update(Buffer.concat([Buffer.from(info, "utf8"), Buffer.from([1])])).digest();
  return { encKey: expand("enc"), macKey: expand("mac") };
}

/** Bitwarden EncString type 2: AES-256-CBC + HMAC-SHA256, `2.iv|ct|mac` in standard base64. */
function encStringType2(encKey: Buffer, macKey: Buffer, plaintext: Uint8Array): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

async function generateAccountKeys(userKey: Buffer): Promise<{ publicKey: string; encryptedPrivateKey: string }> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  // The private key is protected with the user key's halves (enc = [0..32), mac = [32..64)).
  const encryptedPrivateKey = encStringType2(userKey.subarray(0, 32), userKey.subarray(32, 64), pkcs8);
  return { publicKey: b64(spki), encryptedPrivateKey };
}

/**
 * Register a new account directly against vaultwarden's API, reimplementing
 * the Bitwarden client registration crypto (kdf 0 / PBKDF2 600k).
 */
export async function registerVaultwardenAccount(
  baseUrl: string,
  email: string,
  password: string,
  opts: FetchOpts = {},
): Promise<void> {
  const doFetch = opts.fetchImpl ?? fetch;
  const masterKey = deriveMasterKey(email, password);
  const masterPasswordHash = deriveMasterPasswordHash(masterKey, password);
  const { encKey, macKey } = stretchMasterKey(masterKey);
  const userKey = randomBytes(64);
  const protectedUserKey = encStringType2(encKey, macKey, userKey);
  const keys = await generateAccountKeys(userKey);

  const body = JSON.stringify({
    name: "secretary-test",
    email,
    masterPasswordHash,
    masterPasswordHint: null,
    key: protectedUserKey,
    kdf: 0,
    kdfIterations: KDF_ITERATIONS,
    keys,
  });
  const post = (path: string) =>
    doFetch(`${baseUrl}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body });

  let response = await post("/identity/accounts/register");
  if (response.status === 404) response = await post("/api/accounts/register");
  if (!response.ok) {
    throw new Error(`vaultwarden register failed (${response.status}): ${await response.text()}`);
  }
}

/** Log in with the master password and mint a personal API key (client_id/client_secret). */
export async function obtainUserApiKey(
  baseUrl: string,
  email: string,
  password: string,
  opts: FetchOpts = {},
): Promise<{ client_id: string; client_secret: string }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const masterKey = deriveMasterKey(email, password);
  const masterPasswordHash = deriveMasterPasswordHash(masterKey, password);

  const form = new URLSearchParams({
    grant_type: "password",
    username: email,
    password: masterPasswordHash,
    scope: "api offline_access",
    client_id: "cli",
    deviceType: "8",
    deviceIdentifier: randomUUID(),
    deviceName: "secretary-bootstrap",
  });
  const tokenResponse = await doFetch(`${baseUrl}/identity/connect/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Auth-Email": Buffer.from(email, "utf8").toString("base64url"),
    },
    body: form.toString(),
  });
  if (!tokenResponse.ok) {
    throw new Error(`vaultwarden token grant failed (${tokenResponse.status}): ${await tokenResponse.text()}`);
  }
  const token = (await tokenResponse.json()) as { access_token?: string };
  if (!token.access_token) throw new Error("vaultwarden token response has no access_token");
  const bearer = { Authorization: `Bearer ${token.access_token}` };

  const profileResponse = await doFetch(`${baseUrl}/api/accounts/profile`, { headers: bearer });
  if (!profileResponse.ok) {
    throw new Error(`vaultwarden profile fetch failed (${profileResponse.status}): ${await profileResponse.text()}`);
  }
  const profile = (await profileResponse.json()) as { id?: string; Id?: string };
  const userId = profile.id ?? profile.Id;
  if (!userId) throw new Error("vaultwarden profile response has no user id");

  const apiKeyResponse = await doFetch(`${baseUrl}/api/accounts/api-key`, {
    method: "POST",
    headers: { ...bearer, "Content-Type": "application/json" },
    body: JSON.stringify({ masterPasswordHash, otp: null }),
  });
  if (!apiKeyResponse.ok) {
    throw new Error(`vaultwarden api-key mint failed (${apiKeyResponse.status}): ${await apiKeyResponse.text()}`);
  }
  const apiKey = (await apiKeyResponse.json()) as { apiKey?: string; ApiKey?: string };
  const clientSecret = apiKey.apiKey ?? apiKey.ApiKey;
  if (!clientSecret) throw new Error("vaultwarden api-key response has no apiKey");

  return { client_id: `user.${userId}`, client_secret: clientSecret };
}

async function runBwStep(
  step: string,
  argv: string[],
  env: Record<string, string>,
  cwd: string,
): Promise<string> {
  const child = Bun.spawn(argv, { cwd, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    // Test tooling with test-only credentials: stderr is safe to surface here.
    throw new Error(`bw step "${step}" failed (exit ${exitCode}): ${stderr.trim() || stdout.trim()}`);
  }
  return stdout.trim();
}

/** Create a login item in the vault by driving the real bw CLI in an isolated appdata dir. */
export async function createLoginItemWithBw(opts: {
  bwPath: string;
  baseUrl: string;
  email: string;
  password: string;
  itemName: string;
  username?: string;
  itemPassword: string;
  appDataDir: string;
  /** CA bundle for a self-signed server cert (bw refuses plain http). */
  tlsCaFile?: string;
}): Promise<void> {
  await mkdir(opts.appDataDir, { recursive: true, mode: 0o700 });
  const baseEnv: Record<string, string> = {
    HOME: opts.appDataDir,
    XDG_CONFIG_HOME: opts.appDataDir,
    TMPDIR: opts.appDataDir,
    BITWARDENCLI_APPDATA_DIR: opts.appDataDir,
    BW_NOINTERACTION: "true",
    PATH: bwSubprocessPath(),
    ...(opts.tlsCaFile ? { NODE_EXTRA_CA_CERTS: opts.tlsCaFile } : {}),
  };
  const cwd = opts.appDataDir;

  await runBwStep("config server", [opts.bwPath, "config", "server", opts.baseUrl], baseEnv, cwd);
  const session = await runBwStep(
    "login",
    [opts.bwPath, "login", opts.email, "--passwordenv", "BW_PASSWORD", "--raw"],
    { ...baseEnv, BW_PASSWORD: opts.password },
    cwd,
  );
  if (!session) throw new Error('bw step "login" returned an empty session key');
  const sessionEnv = { ...baseEnv, BW_SESSION: session };
  try {
    await runBwStep("sync", [opts.bwPath, "sync"], sessionEnv, cwd);
    const item = {
      type: 1,
      name: opts.itemName,
      notes: "secretary integration test",
      login: { username: opts.username ?? null, password: opts.itemPassword },
    };
    const encoded = Buffer.from(JSON.stringify(item), "utf8").toString("base64");
    await runBwStep("create item", [opts.bwPath, "create", "item", encoded], sessionEnv, cwd);
  } finally {
    await runBwStep("logout", [opts.bwPath, "logout"], sessionEnv, cwd).catch(() => undefined);
  }
}

async function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("could not determine a free port"));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

async function runDocker(args: string[]): Promise<string> {
  const child = Bun.spawn(["docker", ...args], { stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`docker ${args[0]} failed (exit ${exitCode}): ${stderr.trim()}`);
  return stdout.trim();
}

async function runOpenssl(args: string[]): Promise<void> {
  const child = Bun.spawn(["/usr/bin/openssl", ...args], { stdin: "ignore", stdout: "ignore", stderr: "pipe" });
  const [stderr, exitCode] = await Promise.all([new Response(child.stderr).text(), child.exited]);
  if (exitCode !== 0) throw new Error(`openssl ${args[0]} failed (exit ${exitCode}): ${stderr.trim()}`);
}

/**
 * Start a throwaway vaultwarden container on a free localhost port and wait
 * until it answers. The container terminates TLS with a freshly generated
 * self-signed certificate because modern bw CLI builds refuse plain-http
 * servers outright; `caFile` is the cert to trust (NODE_EXTRA_CA_CERTS for bw,
 * `fetchWithCa` for direct API calls).
 */
export async function startVaultwardenContainer(
  opts: { image?: string } = {},
): Promise<{ url: string; caFile: string; stop(): Promise<void> }> {
  const image = opts.image ?? "vaultwarden/server:latest";
  // Under /tmp (not os.tmpdir()) so Docker Desktop's default file sharing can
  // bind-mount it into the container.
  const certDir = await mkdtemp("/tmp/secretary-vw-tls-");
  const caFile = join(certDir, "cert.pem");
  const keyFile = join(certDir, "key.pem");
  await runOpenssl([
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyFile, "-out", caFile, "-days", "2",
    "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ]);
  // Test-only throwaway key; must be readable by the container's user.
  await chmod(keyFile, 0o644);

  // Docker cannot map "host port 0", so reserve a free port ourselves first.
  // The tiny race between closing the probe listener and docker binding it is
  // acceptable for a test bootstrap.
  const port = await pickFreePort();
  const containerId = await runDocker([
    "run", "-d", "--rm",
    "-e", "SIGNUPS_ALLOWED=true",
    // Throwaway container: no volume mounted on purpose, data loss is the point.
    "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true",
    "-e", 'ROCKET_TLS={certs="/ssl/cert.pem",key="/ssl/key.pem"}',
    "-v", `${certDir}:/ssl:ro`,
    "-p", `127.0.0.1:${port}:80`,
    image,
  ]).catch(async (error) => {
    await rm(certDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  });
  const url = `https://localhost:${port}`;
  const doFetch = fetchWithCa(caFile);
  const stop = async () => {
    await runDocker(["rm", "-f", containerId]).catch(() => undefined);
    await rm(certDir, { recursive: true, force: true }).catch(() => undefined);
  };

  const deadline = Date.now() + 60_000;
  while (true) {
    try {
      const response = await doFetch(`${url}/alive`, { signal: AbortSignal.timeout(2_000) });
      if (response.status === 200) return { url, caFile, stop };
    } catch {
      // Not up yet; keep polling.
    }
    if (Date.now() > deadline) {
      await stop();
      throw new Error("vaultwarden container did not become healthy within 60s");
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}
