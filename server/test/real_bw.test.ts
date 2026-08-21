// End-to-end integration test: real vaultwarden container + real bw CLI.
//
// Opt-in only — run with INTEGRATION_REAL_BW=1. Requires a local docker
// daemon and the Bitwarden CLI at /usr/local/bin/bw.

import { afterAll, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BwVault, itemFieldValue, valueKey } from "../src/vault";
import { cloneItem, dropItemField, newLoginItemPayload, setItemField } from "../src/writes";
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
const WRITE_ITEM_NAME = "Secretary Write Item";
const WRITE_ITEM_DESCRIPTION = "created by the secretary write-path integration test";

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

  // -- write surface, against the same real bw + vaultwarden ----------------
  // The fake-vault unit tests cannot prove the payload shape `bw serve`
  // actually accepts; this is the only place that does.

  expect(await vault.findItemsByName(WRITE_ITEM_NAME)).toHaveLength(0);
  await vault.createItem(newLoginItemPayload(
    WRITE_ITEM_NAME,
    WRITE_ITEM_DESCRIPTION,
    new Map([["username", "write-user"], ["password", "write-pass-1"], ["api_key", "write-key-1"]]),
  ));

  const [created] = await vault.findItemsByName(WRITE_ITEM_NAME);
  expect(created).toBeDefined();
  expect(created.description).toBe(WRITE_ITEM_DESCRIPTION);
  expect(created.field_names).toContain("api_key");
  // A hidden custom field must be readable by the read path, or the write
  // would produce an item the broker can see but never deliver.
  const createdValues = await vault.readValues([
    { item_id: created.item_id, field: "password" },
    { item_id: created.item_id, field: "api_key" },
  ]);
  expect(createdValues.get(valueKey(created.item_id, "password"))).toBe("write-pass-1");
  expect(createdValues.get(valueKey(created.item_id, "api_key"))).toBe("write-key-1");

  const writeCatalog = await vault.catalog(WRITE_ITEM_NAME);
  expect(writeCatalog[0]?.created_at).toBeTruthy();

  // Update a value through a full-replace edit built from the raw item.
  const rotated = cloneItem(created.raw);
  setItemField(rotated, "password", "write-pass-2");
  await vault.replaceItem(created.item_id, rotated);
  const [afterRotate] = await vault.findItemsByName(WRITE_ITEM_NAME);
  expect(itemFieldValue(afterRotate.raw, "password")).toBe("write-pass-2");
  expect(itemFieldValue(afterRotate.raw, "api_key")).toBe("write-key-1");

  // Drop one field; the rest of the item survives.
  const trimmed = cloneItem(afterRotate.raw);
  dropItemField(trimmed, "api_key");
  await vault.replaceItem(afterRotate.item_id, trimmed);
  const [afterDrop] = await vault.findItemsByName(WRITE_ITEM_NAME);
  expect(afterDrop.field_names).not.toContain("api_key");
  expect(itemFieldValue(afterDrop.raw, "password")).toBe("write-pass-2");

  // Soft delete: gone from the vault, recoverable from its trash.
  await vault.trashItem(afterDrop.item_id);
  expect(await vault.findItemsByName(WRITE_ITEM_NAME)).toHaveLength(0);
}, 300_000);
