#!/usr/bin/env bun
// Phase A live Telegram test harness (PLAN.md 修订 1 / A).
//
// Drives the REAL broker components (grants, clients, envelope, HTTP API, and
// the real TelegramApprover long-polling api.telegram.org with the test bot)
// plus the real compiled CLI, end to end, while the Owner taps real buttons on
// their phone. Only the vault layer is the mandated in-process fake — no bw
// dependency for this test. Nothing Telegram-related is faked: that is the
// entire point of this harness.
//
// Launch it through the OLD pipeline so the bot token and chat id come from
// Bitwarden at runtime and never touch disk or argv (run from repos/secretary):
//
//   /Users/metajs/.claude/skills/use-approved-secrets/scripts/approved-secret \
//     exec --reason "secretary Phase A: live Telegram approval test with the playground bot" \
//     --item "telegram playground" password=TG_TEST_BOT_TOKEN \
//     --item "telegram-userid" username=TG_OWNER_CHAT_ID \
//     -- bun run deploy/live_test.ts
//
// Optional: `-- bun run deploy/live_test.ts --step N` resumes from step N
// (earlier steps' state — e.g. the 1h grant from step 1 — must still exist on
// the Telegram/grant side for later steps to make sense; the SQLite store is
// temp per run, so resuming mainly helps re-running a failed later step
// within one broker lifetime after editing nothing).
//
// Secrets: the bot token lives only in process env; the test credential is a
// random in-memory value. Neither is ever printed or persisted — assertions
// compare captured child output against the in-memory value and print only
// PASS/FAIL.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";

import { TelegramApprover } from "../server/src/approver_telegram.ts";
import { ClientRegistry } from "../server/src/clients.ts";
import { GrantStore, secretGrantKey } from "../server/src/grants.ts";
import { startHttpServer } from "../server/src/http.ts";
import { RequestBroker } from "../server/src/requests.ts";
import { WriteBroker } from "../server/src/writes.ts";
import {
  resolveNamesAgainstCatalog,
  valueKey,
  type ResolvedItem,
  type SecretField,
  type Vault,
} from "../server/src/vault.ts";
import { normalizeRepoIdentity } from "../cli/src/secretary.ts";

const REPO_ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const CLI_WRAPPER = join(REPO_ROOT, "cli", "scripts", "secretary");
const CLI_BINARY = join(REPO_ROOT, "cli", "bin", "secretary-core");

export const LIVE_ITEM_NAME = "live-test-item";
export const LIVE_ITEM_ID = "11111111-aaaa-bbbb-cccc-livetest0001";
/** How long we wait for the Owner's tap (per waiting phase). */
const OWNER_PATIENCE_MS = 10 * 60 * 1000;
const CLIENT_NAME = "live-test";

// ---------------------------------------------------------------------------
// Small exported pieces (unit-testable without Telegram)
// ---------------------------------------------------------------------------

export function parseLiveTestArgs(argv: string[]): { startStep: number } {
  let startStep = 1;
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] === "--step") {
      const value = Number(argv[++index]);
      if (!Number.isInteger(value) || value < 1 || value > 4) {
        throw new Error("--step must be an integer in [1, 4]");
      }
      startStep = value;
    } else {
      throw new Error(`unknown argument: ${argv[index]} (usage: live_test.ts [--step N])`);
    }
  }
  return { startStep };
}

/** The mandated in-process fake vault: one login item, username + password. */
export function makeLiveVault(secrets: { username: string; password: string }): Vault {
  const item: ResolvedItem = {
    item_id: LIVE_ITEM_ID,
    revision: new Date(0).toISOString(),
    created_at: new Date(0).toISOString(),
    name: LIVE_ITEM_NAME,
    description: "secretary live Telegram test item (in-memory only)",
    fields: ["username", "password"],
  };
  const values = new Map<string, string>([
    [valueKey(LIVE_ITEM_ID, "username"), secrets.username],
    [valueKey(LIVE_ITEM_ID, "password"), secrets.password],
  ]);
  return {
    async catalog(query = "") {
      const normalized = query.trim().toLowerCase();
      return (!normalized || item.name.toLowerCase().includes(normalized))
        ? [{ name: item.name, description: item.description, fields: item.fields, created_at: item.created_at }]
        : [];
    },
    async resolveByName(names: string[]) {
      return resolveNamesAgainstCatalog(names, [item]);
    },
    // The live Telegram harness exercises the read path only.
    async findItemsByName() {
      throw new Error("live vault: read-only");
    },
    async createItem() {
      throw new Error("live vault: read-only");
    },
    async replaceItem() {
      throw new Error("live vault: read-only");
    },
    async trashItem() {
      throw new Error("live vault: read-only");
    },
    async readValues(units: Array<{ item_id: string; field: SecretField }>) {
      const out = new Map<string, string>();
      for (const unit of units) {
        const value = values.get(valueKey(unit.item_id, unit.field));
        if (value === undefined) throw new Error("live vault: no such field");
        out.set(valueKey(unit.item_id, unit.field), value);
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function say(message: string) {
  console.log(`[live] ${message}`);
}

function banner(message: string) {
  console.log(`\n[live] ============================================================`);
  console.log(`[live] ${message}`);
  console.log(`[live] ============================================================`);
}

type ExecResult = { stdout: string; stderr: string; exitCode: number; ms: number };

async function runCli(
  args: string[],
  env: Record<string, string>,
): Promise<ExecResult> {
  const started = Date.now();
  // Minimal, explicit environment: the TG_* variables of this process must
  // never reach the CLI or the probe child.
  const child = Bun.spawn([CLI_WRAPPER, ...args], {
    cwd: REPO_ROOT,
    env: {
      HOME: process.env.HOME ?? "",
      USER: process.env.USER ?? "",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      ...env,
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { stdout, stderr, exitCode, ms: Date.now() - started };
}

type StepOutcome = { name: string; pass: boolean; ms: number; note: string };

async function main(): Promise<void> {
  const { startStep } = parseLiveTestArgs(process.argv.slice(2));

  const botToken = process.env.TG_TEST_BOT_TOKEN ?? "";
  const chatId = (process.env.TG_OWNER_CHAT_ID ?? "").trim();
  if (!botToken || !chatId) {
    console.error(
      "[live] TG_TEST_BOT_TOKEN and TG_OWNER_CHAT_ID are required in env.\n" +
      "[live] Launch through the old pipeline (see the header comment of this file):\n" +
      '[live]   approved-secret exec --reason "..." \\\n' +
      '[live]     --item "telegram playground" password=TG_TEST_BOT_TOKEN \\\n' +
      '[live]     --item "telegram-userid" username=TG_OWNER_CHAT_ID \\\n' +
      "[live]     -- bun run deploy/live_test.ts",
    );
    process.exit(2);
  }
  const ownerUserId = Number(chatId);
  if (!Number.isInteger(ownerUserId) || ownerUserId <= 0) {
    console.error("[live] TG_OWNER_CHAT_ID must be a positive numeric user/chat id");
    process.exit(2);
  }

  if (!(await Bun.file(CLI_BINARY).exists())) {
    say("compiled CLI missing — running cli/build.sh once");
    const build = Bun.spawnSync(["bash", join(REPO_ROOT, "cli", "build.sh")], { cwd: REPO_ROOT });
    if (build.exitCode !== 0) throw new Error("cli/build.sh failed; build the CLI first");
  }

  // In-memory-only test credentials. Never printed.
  const liveSecrets = {
    username: `live-user-${crypto.randomUUID()}`,
    password: `live-pass-${crypto.randomUUID()}`,
  };

  const workDir = mkdtempSync(join(tmpdir(), "secretary-live-"));
  const db = new Database(join(workDir, "live.sqlite"), { create: true });
  db.run("PRAGMA journal_mode = WAL");
  const grants = new GrantStore(db);
  const clients = new ClientRegistry(db);
  const { client_id, token } = clients.add(CLIENT_NAME);
  const vault = makeLiveVault(liveSecrets);

  const approver = new TelegramApprover(
    { botToken, chatId, allowedUserIds: [ownerUserId] },
    { onRevoke: (sightingId) => grants.revokeByHandle(sightingId) },
    { log: (message) => say(`broker: ${message}`) },
  );
  approver.start();
  const broker = new RequestBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: OWNER_PATIENCE_MS,
    log: (message) => say(`broker: ${message}`),
  });
  const writes = new WriteBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: OWNER_PATIENCE_MS,
    entryTtlMs: OWNER_PATIENCE_MS,
    log: (message) => say(`broker: ${message}`),
  });
  const server = startHttpServer({
    clients,
    broker,
    writes,
    vault,
    hostname: "127.0.0.1",
    port: 0,
    approvalTimeoutMs: OWNER_PATIENCE_MS,
    log: (message) => say(`broker: ${message}`),
  });
  const cliEnv = {
    SECRETARY_URL: `http://127.0.0.1:${server.port}`,
    SECRETARY_TOKEN: token,
  };

  // Probe scripts echo one env var; their stdout is compared, never printed.
  const probeA = join(workDir, "probe-a.sh");
  const probeB = join(workDir, "probe-b.sh");
  writeFileSync(probeA, "#!/bin/sh\nprintf '%s' \"$LIVE_TOKEN\"\n", { mode: 0o755 });
  writeFileSync(probeB, "#!/bin/sh\nprintf 'B:%s' \"$LIVE_TOKEN\"\n", { mode: 0o755 });

  const passwordExec = (probe: string) => [
    "exec", "--reason", "secretary Phase A live test: password credential round trip",
    "--item", LIVE_ITEM_NAME, "password=LIVE_TOKEN",
    "--", "sh", probe,
  ];

  // The identity the broker keys grants under for this CLI invocation — used
  // to watch the grant disappear after the Owner taps revoke.
  const repoIdentity = normalizeRepoIdentity(gitRemote(REPO_ROOT), REPO_ROOT);
  const passwordGrantKey = secretGrantKey(
    { caller_id: CLIENT_NAME, client_id, repo: repoIdentity },
    { item_id: LIVE_ITEM_ID, field: "password" },
  );

  const outcomes: StepOutcome[] = [];
  const record = (name: string, pass: boolean, ms: number, note: string) => {
    outcomes.push({ name, pass, ms, note });
    say(`${pass ? "✅ PASS" : "❌ FAIL"} — ${name} (${ms} ms)${note ? ` — ${note}` : ""}`);
    return pass;
  };

  try {
    let ok = true;

    if (ok && startStep <= 1) {
      banner("Step 1/4 — approval path. Check your phone (@tg_randy_playground_bot):");
      say("an approval card for 1 个 Bitwarden 条目 should arrive. Tap 「✅ 批准 1 小时」.");
      say(`Waiting up to ${OWNER_PATIENCE_MS / 60000} minutes for your tap…`);
      const result = await runCli(passwordExec(probeA), cliEnv);
      const pass = result.exitCode === 0 && result.stdout === liveSecrets.password;
      ok = record("approval path (批准 1h → child env correct)", pass, result.ms,
        pass ? "" : `exit=${result.exitCode} stderr=${result.stderr.slice(0, 300)}`);
    }

    if (ok && startStep <= 2) {
      banner("Step 2/4 — fast path. No card should arrive; nothing to tap.");
      const result = await runCli(passwordExec(probeA), cliEnv);
      const pass = result.exitCode === 0 && result.stdout === liveSecrets.password &&
        result.stderr.includes("已复用");
      ok = record("fast path (grant reuse, no card)", pass, result.ms,
        pass ? `end-to-end latency ${result.ms} ms` : `exit=${result.exitCode} stderr=${result.stderr.slice(0, 300)}`);
    }

    if (ok && startStep <= 3) {
      banner("Step 3/4 — reject path. Check your phone:");
      say("a NEW approval card (username field this time) should arrive. Tap 「❌ 拒绝」.");
      say(`Waiting up to ${OWNER_PATIENCE_MS / 60000} minutes for your tap…`);
      const result = await runCli([
        "exec", "--reason", "secretary Phase A live test: this request should be REJECTED by you",
        "--item", LIVE_ITEM_NAME, "username=LIVE_USER",
        "--", "sh", probeA,
      ], cliEnv);
      const pass = result.exitCode === 1 && !result.stdout.includes(liveSecrets.username) &&
        result.stderr.includes("审批被拒绝");
      ok = record("reject path (拒绝 → fail closed)", pass, result.ms,
        pass ? "" : `exit=${result.exitCode} stderr=${result.stderr.slice(0, 300)}`);
    }

    if (ok && startStep <= 4) {
      banner("Step 4/4 — sighting + revoke.");
      say("Running a DIFFERENT command under the still-active grant…");
      const reuse = await runCli(passwordExec(probeB), cliEnv);
      const reusePass = reuse.exitCode === 0 && reuse.stdout === `B:${liveSecrets.password}`;
      if (!reusePass) {
        ok = record("sighting + revoke", false, reuse.ms,
          `pre-step reuse failed: exit=${reuse.exitCode} stderr=${reuse.stderr.slice(0, 300)}`);
      } else {
        say("a 「密钥免审复用」 sighting notification should arrive on your phone.");
        say("Tap 「❌ 立即吊销这套授权」. Waiting for the grant to disappear…");
        const started = Date.now();
        let revoked = false;
        while (Date.now() - started < OWNER_PATIENCE_MS) {
          if (grants.findActive([passwordGrantKey]).size === 0) {
            revoked = true;
            break;
          }
          await Bun.sleep(2_000);
        }
        if (!revoked) {
          ok = record("sighting + revoke", false, Date.now() - started, "revoke tap never landed");
        } else {
          say("Grant revoked. Re-running the original command — a NEW approval card");
          say("should arrive (proving the grant is gone). Tap 「❌ 拒绝」 to finish.");
          const after = await runCli(passwordExec(probeA), cliEnv);
          const pass = after.exitCode === 1 && after.stderr.includes("审批被拒绝");
          ok = record("sighting + revoke (next request re-approves)", pass,
            Date.now() - started,
            pass ? "" : `exit=${after.exitCode} stderr=${after.stderr.slice(0, 300)}`);
        }
      }
    }

    banner("Summary");
    for (const outcome of outcomes) {
      say(`${outcome.pass ? "PASS" : "FAIL"}  ${outcome.name}  (${outcome.ms} ms)`);
    }
    const failed = outcomes.filter((outcome) => !outcome.pass).length;
    say(failed === 0 ? "ALL STEPS PASSED 🎉" : `${failed} step(s) FAILED`);
    process.exitCode = failed === 0 ? 0 : 1;
  } finally {
    approver.stop();
    server.stop(true);
    db.close();
    rmSync(workDir, { recursive: true, force: true });
  }
}

function gitRemote(cwd: string): string | undefined {
  const result = Bun.spawnSync(["git", "-C", cwd, "remote", "get-url", "origin"], {
    stdout: "pipe",
    stderr: "ignore",
  });
  return result.exitCode === 0 ? result.stdout.toString().trim() : undefined;
}

if (import.meta.main) await main();
