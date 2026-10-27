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
 *
 * Works against both registration flows, because the test vault is meant to be
 * whatever image the deployment would run rather than one pinned to a version
 * that happens to suit this helper:
 *
 * - **Two-step** (vaultwarden ≥ 1.37.4, matching current Bitwarden clients):
 *   ask `…/accounts/register/send-verification-email` for a token, then post
 *   `RegisterData` to `…/accounts/register/finish` carrying it as
 *   `emailVerificationToken`.
 * - **One-step** (≤ 1.37.3): post `RegisterData` straight to
 *   `…/accounts/register`.
 *
 * The legacy endpoint was removed in 1.37.4 ("No current client uses them"),
 * so detecting it by 404 is the only portable option: there is no version
 * endpoint that predates the change.
 */
export async function registerVaultwardenAccount(
  baseUrl: string,
  email: string,
  password: string,
  opts: FetchOpts = {},
): Promise<{ userKey: Buffer; publicKey: string }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const masterKey = deriveMasterKey(email, password);
  const masterPasswordHash = deriveMasterPasswordHash(masterKey, password);
  const { encKey, macKey } = stretchMasterKey(masterKey);
  const userKey = randomBytes(64);
  const protectedUserKey = encStringType2(encKey, macKey, userKey);
  const keys = await generateAccountKeys(userKey);

  const postJson = (path: string, body: string, extraHeaders: Record<string, string> = {}) =>
    doFetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...extraHeaders },
      body,
    });

  const registerData = (emailVerificationToken?: string) => JSON.stringify({
    name: "secretary-test",
    email,
    masterPasswordHash,
    masterPasswordHint: null,
    key: protectedUserKey,
    kdf: 0,
    kdfIterations: KDF_ITERATIONS,
    keys,
    ...(emailVerificationToken ? { emailVerificationToken } : {}),
  });

  // One-step flow first: it is what every release before 1.37.4 accepted, and
  // a 404 is an unambiguous "this server no longer has that endpoint".
  const oneStep = await postJson("/identity/accounts/register", registerData());
  if (oneStep.ok) return { userKey, publicKey: keys.publicKey };
  if (oneStep.status !== 404) {
    throw new Error(`vaultwarden register failed (${oneStep.status}): ${await oneStep.text()}`);
  }

  // Two-step flow. `Accept: application/json` asks for the token in the body;
  // without it the server hands back the token as plain text for the web vault.
  const verification = await postJson(
    "/identity/accounts/register/send-verification-email",
    JSON.stringify({ email, name: "secretary-test" }),
    { Accept: "application/json" },
  );
  if (!verification.ok) {
    throw new Error(
      `vaultwarden send-verification-email failed (${verification.status}): ${await verification.text()}`,
    );
  }
  const verificationText = await verification.text();
  // 204 means the server sent a real email instead of returning the token, which
  // this harness cannot read — the test container runs with mail disabled.
  if (verification.status === 204 || !verificationText) {
    throw new Error(
      "vaultwarden answers registration with an email; this harness needs a vault with " +
        "signups_verify off (the throwaway container has mail disabled)",
    );
  }
  const token = JSON.parse(verificationText) as string;
  const finish = await postJson("/identity/accounts/register/finish", registerData(token));
  if (!finish.ok) {
    throw new Error(`vaultwarden register finish failed (${finish.status}): ${await finish.text()}`);
  }
  return { userKey, publicKey: keys.publicKey };
}

/**
 * Create an Organization with one Collection, owned by the account behind
 * `accessToken`.
 *
 * A Collection has to carry real key material or nothing can be encrypted to
 * it, so this reproduces what a client does: generate an org key pair, wrap
 * the org private key with a fresh 64-byte org symmetric key, hand the creator
 * that symmetric key RSA-encrypted to their own public key (the `key` field),
 * and then symmetric-encrypt it with the creator's user key for transport.
 *
 * Returns the ids the Broker takes as `VAULT_ORG_ID` / `VAULT_COLLECTION_ID`.
 */
export async function createOrganizationWithCollection(opts: {
  baseUrl: string;
  accessToken: string;
  /** From `registerVaultwardenAccount`: the creator's own key material. */
  userKey: Buffer;
  userPublicKey: string;
  name: string;
  collectionName: string;
  fetchImpl?: typeof fetch;
}): Promise<{ organization_id: string; collection_id: string }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const auth = { Authorization: `Bearer ${opts.accessToken}` };

  const orgPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const orgPublicKey = b64(new Uint8Array(await crypto.subtle.exportKey("spki", orgPair.publicKey)));
  const orgPrivateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", orgPair.privateKey));
  const orgKey = randomBytes(64);

  // Type 4 = RSA-2048 OAEP-SHA1, a single base64 part. This is what the server
  // stores as the member's encrypted org key (`akey`), and the client unwraps
  // it with its own RSA private key — so it is NOT wrapped in a symmetric layer.
  const orgKeyForCreator = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    await crypto.subtle.importKey(
      "spki",
      Buffer.from(opts.userPublicKey, "base64"),
      { name: "RSA-OAEP", hash: "SHA-1" },
      false,
      ["encrypt"],
    ),
    orgKey,
  );
  const orgKeyRsa = `4.${b64(new Uint8Array(orgKeyForCreator))}`;

  const response = await doFetch(`${opts.baseUrl}/api/organizations`, {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify({
      billingEmail: "owner@example.com",
      collectionName: opts.collectionName,
      key: orgKeyRsa,
      name: opts.name,
      keys: {
        encryptedPrivateKey: encStringType2(orgKey.subarray(0, 32), orgKey.subarray(32, 64), orgPrivateKey),
        publicKey: orgPublicKey,
      },
      planType: 0,
    }),
  });
  if (!response.ok) {
    throw new Error(`organization create failed (${response.status}): ${await response.text()}`);
  }
  const org = (await response.json()) as { id?: string; Id?: string };
  const organizationId = org.id ?? org.Id;
  if (!organizationId) throw new Error("organization create returned no id");

  const collectionsResponse = await doFetch(`${opts.baseUrl}/api/organizations/${organizationId}/collections`, {
    headers: auth,
  });
  if (!collectionsResponse.ok) {
    throw new Error(`collection list failed (${collectionsResponse.status}): ${await collectionsResponse.text()}`);
  }
  const payload = (await collectionsResponse.json()) as
    | Array<{ id?: string; Id?: string; name?: string; Name?: string }>
    | { data?: Array<{ id?: string; Id?: string; name?: string; Name?: string }> };
  const collections = Array.isArray(payload) ? payload : (payload.data ?? []);
  const created =
    collections.find((entry) => (entry.name ?? entry.Name) === opts.collectionName) ?? collections[0];
  const collectionId = created?.id ?? created?.Id;
  if (!collectionId) throw new Error("organization has no collection");
  return { organization_id: organizationId, collection_id: collectionId };
}

/** Log in with the master password and mint a personal API key (client_id/client_secret). */
export async function obtainUserApiKey(
  baseUrl: string,
  email: string,
  password: string,
  opts: FetchOpts = {},
): Promise<{ client_id: string; client_secret: string; access_token: string }> {
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

  return { client_id: `user.${userId}`, client_secret: clientSecret, access_token: token.access_token };
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
 *
 * Defaults to `latest` on purpose: this harness exists to prove the Broker
 * works against the server a deployment would actually pull, so pinning it here
 * would only hide the next upstream removal behind a green test (which is
 * exactly how the 1.37.4 registration change went unnoticed). Override with
 * `INTEGRATION_VAULTWARDEN_IMAGE=...` to probe a specific release.
 */
export async function startVaultwardenContainer(
  opts: { image?: string } = {},
): Promise<{ url: string; caFile: string; stop(): Promise<void> }> {
  const image = opts.image ?? process.env.INTEGRATION_VAULTWARDEN_IMAGE ?? "vaultwarden/server:latest";
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
