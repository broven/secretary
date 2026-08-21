// End-to-end integration test: real vaultwarden container + real bw CLI.
//
// Opt-in only — run with INTEGRATION_REAL_BW=1. Requires a local docker
// daemon and the Bitwarden CLI at /usr/local/bin/bw.

import { afterAll, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BwVault, valueKey } from "../src/vault";
import {
  bwSubprocessPath,
  createLoginItemWithBw,
  fetchWithCa,
  obtainUserApiKey,
  registerVaultwardenAccount,
  startVaultwardenContainer,
} from "./helpers/vaultwarden";

const enabled = process.env.INTEGRATION_REAL_BW === "1";

const BW_PATH = "/usr/local/bin/bw";
const EMAIL = "secretary-test@example.com";
// Test-only fixed credential values; never real secrets.
const MASTER_PASSWORD = "secretary-it-master-9f2c";
const ITEM_NAME = "Secretary Test Item";
const ITEM_PASSWORD = "s3cret-value-xyz";
const ITEM_USERNAME = "svc-user";

const cleanups: Array<() => Promise<void>> = [];

afterAll(async () => {
  for (const cleanup of cleanups.reverse()) {
    await cleanup().catch(() => undefined);
  }
});

test.skipIf(!enabled)("real vaultwarden + real bw CLI end to end", async () => {
  const container = await startVaultwardenContainer();
  cleanups.push(() => container.stop());
  // The container serves a self-signed cert (bw refuses plain http).
  const fetchImpl = fetchWithCa(container.caFile);

  await registerVaultwardenAccount(container.url, EMAIL, MASTER_PASSWORD, { fetchImpl });
  const apiKey = await obtainUserApiKey(container.url, EMAIL, MASTER_PASSWORD, { fetchImpl });
  expect(apiKey.client_id.startsWith("user.")).toBe(true);
  expect(apiKey.client_secret.length).toBeGreaterThan(0);

  const seedAppData = await mkdtemp(join(tmpdir(), "secretary-bw-seed-"));
  cleanups.push(() => rm(seedAppData, { recursive: true, force: true }));
  await createLoginItemWithBw({
    bwPath: BW_PATH,
    baseUrl: container.url,
    email: EMAIL,
    password: MASTER_PASSWORD,
    itemName: ITEM_NAME,
    username: ITEM_USERNAME,
    itemPassword: ITEM_PASSWORD,
    appDataDir: seedAppData,
    tlsCaFile: container.caFile,
  });

  const vaultAppData = await mkdtemp(join(tmpdir(), "secretary-bw-vault-"));
  cleanups.push(() => rm(vaultAppData, { recursive: true, force: true }));
  const vault = new BwVault(
    {
      vault_url: container.url,
      bw_clientid: apiKey.client_id,
      bw_clientsecret: apiKey.client_secret,
      bw_email: EMAIL,
      bw_password: MASTER_PASSWORD,
      sync_max_age_s: 60,
    },
    {
      binaryPath: BW_PATH,
      appDataDir: vaultAppData,
      log: () => undefined,
      // Same real bw binary and command pipeline; on the macOS host we only
      // have to make the node interpreter reachable (bw is a node script) and
      // teach it to trust the container's self-signed cert. extraEnv reaches
      // every bw process, including the resident `bw serve`.
      extraEnv: { PATH: bwSubprocessPath(), NODE_EXTRA_CA_CERTS: container.caFile },
    },
  );
  cleanups.push(async () => vault.stop());
  await vault.start();

  const catalog = await vault.catalog();
  const entry = catalog.find((item) => item.name === ITEM_NAME);
  expect(entry).toBeDefined();
  expect(entry?.fields).toContain("password");
  expect(entry?.fields).toContain("username");

  const [resolved] = await vault.resolveByName([ITEM_NAME]);
  expect(resolved.name).toBe(ITEM_NAME);

  const values = await vault.readValues([
    { item_id: resolved.item_id, field: "password" },
    { item_id: resolved.item_id, field: "username" },
  ]);
  expect(values.get(valueKey(resolved.item_id, "password"))).toBe(ITEM_PASSWORD);
  expect(values.get(valueKey(resolved.item_id, "username"))).toBe(ITEM_USERNAME);
}, 240_000);
