#!/usr/bin/env bun
// End-to-end smoke test, run on the host:
//   bun run deploy/smoke.ts
//
// docker compose --profile vaultwarden up (broker + vaultwarden) → bootstrap a
// vaultwarden automation account + test item → `client add` a token → run the
// real compiled CLI twice (approval path via the dev auto-approver, then the
// fast path) → assert the child process received the exact secret value →
// report wall-clock timings. Cleans up the compose project at the end.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createLoginItemWithBw,
  fetchWithCa,
  obtainUserApiKey,
  registerVaultwardenAccount,
} from "../server/test/helpers/vaultwarden.ts";

const REPO_ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const DEPLOY = join(REPO_ROOT, "deploy");
const COMPOSE = [
  "docker", "compose",
  "--profile", "vaultwarden",
  "-p", "secretary-smoke",
  "-f", join(DEPLOY, "docker-compose.yml"),
  "-f", join(DEPLOY, "docker-compose.smoke.yml"),
];

const VW_URL = "https://localhost:18222";
const TLS_DIR = join(DEPLOY, "smoke-tls");
const CA_FILE = join(TLS_DIR, "cert.pem");
const BROKER_URL = "http://127.0.0.1:8787";
const EMAIL = "secretary-smoke@example.com";
const MASTER_PASSWORD = "smoke-master-password-1";
const ITEM_NAME = "Smoke Test Item";
const SECRET_VALUE = "smoke-secret-value-8d3f";
const BW_PATH = "/usr/local/bin/bw";

function log(message: string) {
  console.log(`[smoke] ${message}`);
}

async function run(argv: string[], opts: { env?: Record<string, string>; input?: string } = {}) {
  const child = Bun.spawn(argv, {
    cwd: REPO_ROOT,
    env: { ...process.env, ...opts.env },
    stdin: opts.input === undefined ? "ignore" : new TextEncoder().encode(opts.input),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { stdout, stderr, exitCode };
}

async function runOrDie(argv: string[], opts: { env?: Record<string, string> } = {}) {
  const result = await run(argv, opts);
  if (result.exitCode !== 0) {
    throw new Error(`command failed (${result.exitCode}): ${argv.join(" ")}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

async function waitForHttp(url: string, timeoutMs: number, fetchImpl: typeof fetch = fetch) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetchImpl(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
    } catch {
      // keep waiting
    }
    await Bun.sleep(500);
  }
  throw new Error(`timed out waiting for ${url}`);
}

/** Throwaway self-signed cert whose SAN covers the compose-internal name. */
async function generateSmokeTls() {
  mkdirSync(TLS_DIR, { recursive: true });
  const child = Bun.spawn([
    "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(TLS_DIR, "key.pem"), "-out", CA_FILE, "-days", "2",
    "-subj", "/CN=vaultwarden",
    "-addext", "subjectAltName=DNS:vaultwarden,DNS:localhost,IP:127.0.0.1",
  ], { stdin: "ignore", stdout: "ignore", stderr: "pipe" });
  const [stderr, exitCode] = await Promise.all([new Response(child.stderr).text(), child.exited]);
  if (exitCode !== 0) throw new Error(`openssl failed: ${stderr}`);
  // Key stays 0600 (the vaultwarden container reads it as root); only the
  // cert is world-readable.
  await run(["chmod", "600", join(TLS_DIR, "key.pem")]);
  await run(["chmod", "644", CA_FILE]);
}

async function main() {
  const started = Date.now();
  const scratch = mkdtempSync(join(tmpdir(), "secretary-smoke-"));
  let composeUp = false;
  try {
    // Secret files the compose file mounts; the telegram token is a dummy —
    // the auto-approver path never talks to Telegram.
    log("writing compose secret files");
    writeFileSync(join(DEPLOY, "secrets", "bw_password"), MASTER_PASSWORD, { mode: 0o600 });
    writeFileSync(join(DEPLOY, "secrets", "telegram_bot_token"), "dummy-not-used", { mode: 0o600 });
    // Placeholders so compose can mount them before the account exists.
    writeFileSync(join(DEPLOY, "secrets", "bw_clientid"), "pending", { mode: 0o600 });
    writeFileSync(join(DEPLOY, "secrets", "bw_clientsecret"), "pending", { mode: 0o600 });

    const composeEnv = {
      BW_EMAIL: EMAIL,
      TELEGRAM_CHAT_ID: "0",
      TELEGRAM_ALLOWED_USER_IDS: "1",
    };

    log("generating throwaway TLS cert (bw refuses plain-http vaults)");
    await generateSmokeTls();
    const vwFetch = fetchWithCa(CA_FILE);

    log("starting vaultwarden");
    await runOrDie([...COMPOSE, "up", "-d", "vaultwarden"], { env: composeEnv });
    composeUp = true;
    await waitForHttp(`${VW_URL}/alive`, 60_000, vwFetch);

    log("bootstrapping vaultwarden account + item");
    await registerVaultwardenAccount(VW_URL, EMAIL, MASTER_PASSWORD, { fetchImpl: vwFetch });
    const apiKey = await obtainUserApiKey(VW_URL, EMAIL, MASTER_PASSWORD, { fetchImpl: vwFetch });
    await createLoginItemWithBw({
      bwPath: BW_PATH,
      baseUrl: VW_URL,
      email: EMAIL,
      password: MASTER_PASSWORD,
      itemName: ITEM_NAME,
      username: "smoke-user",
      itemPassword: SECRET_VALUE,
      appDataDir: mkdtempSync(join(scratch, "bw-")),
      tlsCaFile: CA_FILE,
    });
    writeFileSync(join(DEPLOY, "secrets", "bw_clientid"), apiKey.client_id, { mode: 0o600 });
    writeFileSync(join(DEPLOY, "secrets", "bw_clientsecret"), apiKey.client_secret, { mode: 0o600 });

    log("building + starting broker");
    await runOrDie([...COMPOSE, "up", "-d", "--build", "broker"], { env: composeEnv });
    try {
      await waitForHttp(`${BROKER_URL}/healthz`, 120_000);
    } catch (error) {
      const logs = await run([...COMPOSE, "logs", "--no-color", "broker"], { env: composeEnv });
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nbroker logs:\n${logs.stdout}\n${logs.stderr}`);
    }

    log("issuing a client token");
    const added = await runOrDie([
      ...COMPOSE, "exec", "-T", "broker",
      "bun", "run", "server/src/cli_admin.ts", "client", "add", "smoke-agent",
    ], { env: composeEnv });
    const token = added.stdout.match(/token:\s+(\S+)/)?.[1];
    if (!token) throw new Error(`could not parse token from: ${added.stdout}`);

    log("building the CLI binary");
    await runOrDie(["bash", join(REPO_ROOT, "cli", "build.sh")]);

    // A non-inline-shell probe command: `sh script.sh` (not `sh -c`).
    const probe = join(scratch, "probe.sh");
    writeFileSync(probe, "#!/bin/sh\nprintf '%s' \"$SMOKE_TOKEN\"\n", { mode: 0o755 });

    const cliEnv = { SECRETARY_URL: BROKER_URL, SECRETARY_TOKEN: token };
    const cliArgv = [
      join(REPO_ROOT, "cli", "scripts", "secretary"),
      "exec", "--reason", "end-to-end smoke test of the secretary broker",
      "--item", ITEM_NAME, "password=SMOKE_TOKEN",
      "--", "sh", probe,
    ];

    log("exec #1 (approval path via dev auto-approver)");
    const firstStart = Date.now();
    const first = await run(cliArgv, { env: cliEnv });
    const firstMs = Date.now() - firstStart;
    if (first.exitCode !== 0) throw new Error(`first exec failed: ${first.stderr}`);
    if (first.stdout !== SECRET_VALUE) {
      throw new Error(`first exec child env mismatch: got ${JSON.stringify(first.stdout)}`);
    }

    log("exec #2 (fast path)");
    const secondStart = Date.now();
    const second = await run(cliArgv, { env: cliEnv });
    const secondMs = Date.now() - secondStart;
    if (second.exitCode !== 0) throw new Error(`second exec failed: ${second.stderr}`);
    if (second.stdout !== SECRET_VALUE) {
      throw new Error(`second exec child env mismatch: got ${JSON.stringify(second.stdout)}`);
    }
    if (!second.stderr.includes("已复用")) {
      throw new Error(`second exec did not report grant reuse; stderr: ${second.stderr}`);
    }

    log("");
    log("SMOKE PASSED");
    log(`  exec #1 (auto-approval path): ${firstMs} ms`);
    log(`  exec #2 (fast path):          ${secondMs} ms`);
    log(`  total wall clock:             ${Date.now() - started} ms`);
  } finally {
    if (process.env.SMOKE_KEEP === "1") {
      log("SMOKE_KEEP=1 — leaving the compose stack and secret files in place for debugging");
      return;
    }
    if (composeUp) {
      log("tearing down compose project");
      await run([...COMPOSE, "down", "-v"], {
        env: { BW_EMAIL: EMAIL, TELEGRAM_CHAT_ID: "0", TELEGRAM_ALLOWED_USER_IDS: "1" },
      });
    }
    for (const name of ["bw_clientid", "bw_clientsecret", "bw_password", "telegram_bot_token"]) {
      rmSync(join(DEPLOY, "secrets", name), { force: true });
    }
    rmSync(TLS_DIR, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
}

await main();
