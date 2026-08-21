#!/usr/bin/env bun
// Broker entrypoint: load config, open SQLite, establish the resident bw
// session (fail fast on login/unlock errors), pick the Approver, serve HTTP.

import { Database } from "bun:sqlite";
import type { Approver } from "./approver.ts";
import { createAutoApprover } from "./approver_auto.ts";
import { TelegramApprover } from "./approver_telegram.ts";
import { ClientRegistry } from "./clients.ts";
import { loadConfig } from "./config.ts";
import { GrantStore } from "./grants.ts";
import { startHttpServer } from "./http.ts";
import { RequestBroker } from "./requests.ts";
import { BwVault } from "./vault.ts";

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const log = (message: string) => console.log(`[secretary] ${message}`);

  const db = new Database(config.db_path, { create: true });
  db.run("PRAGMA journal_mode = WAL");
  const grants = new GrantStore(db);
  const clients = new ClientRegistry(db);

  const vault = new BwVault({
    vault_url: config.vault_url,
    bw_clientid: config.bw_clientid,
    bw_clientsecret: config.bw_clientsecret,
    bw_email: config.bw_email,
    bw_password: config.bw_password,
    sync_max_age_s: config.sync_max_age_s,
  }, { log });
  // Fail fast: a broker that cannot unlock the vault must not serve requests.
  await vault.start();

  let approver: Approver;
  if (config.dev_auto_approve) {
    approver = createAutoApprover({ env: process.env, log });
    log("WARNING: SECRETARY_DEV_AUTO_APPROVE=1 — every request will be auto-approved without human review");
  } else {
    approver = new TelegramApprover(
      {
        botToken: config.telegram_bot_token,
        chatId: config.telegram_chat_id,
        allowedUserIds: config.telegram_allowed_user_ids,
      },
      { onRevoke: (sightingId) => grants.revokeByHandle(sightingId) },
      { log },
    );
  }
  approver.start();

  const broker = new RequestBroker({
    vault,
    grants,
    approver,
    approvalTimeoutMs: config.approval_timeout_s * 1000,
    log,
  });

  startHttpServer({
    clients,
    broker,
    vault,
    hostname: config.listen_addr.hostname,
    port: config.listen_addr.port,
    approvalTimeoutMs: config.approval_timeout_s * 1000,
    log,
  });

  // Periodic hygiene: expired grants and stale sightings.
  setInterval(() => {
    try {
      grants.sweep();
    } catch (error) {
      log(`grant sweep failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }, 10 * 60 * 1000);
}

main().catch((error) => {
  console.error(`[secretary] fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
