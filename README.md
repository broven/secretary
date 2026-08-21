# secretary

Approval-gated secrets for code agents, backed by Bitwarden / Vaultwarden.

A code agent never sees your vault and never holds a standing credential. It
asks secretary to run a command with named secrets injected as environment
variables; you approve or reject the request from Telegram; the values travel
end-to-end encrypted from the broker to the agent's machine and exist only in
the child process's environment.

```
code agent ──> secretary CLI ──HTTPS──> secretary broker ──> Bitwarden / Vaultwarden
                                              │
                                              └──> Telegram (1h / 8h / 7d / reject)
```

```sh
$ secretary exec --reason "deploy needs the CF token" \
    --item "cloudflare-api-dns-edit" password=CF_API_TOKEN \
    -- npx wrangler deploy
# → an approval card lands on the Owner's phone; on 批准, the command runs
#   with CF_API_TOKEN set. Approve for 8h and repeats run instantly.
```

## Why

Code agents need API keys, tokens, and passwords, but handing them a `.env`
means every prompt-injected or simply confused agent holds your credentials
forever. secretary replaces standing access with **per-use, human-approved,
time-limited grants**:

- **Every use is authorized.** A request is either covered by an unexpired
  Grant or goes to the Owner's phone. No decision within the timeout →
  fail closed.
- **Grants are narrow and expire.** Keyed by (caller, client, repo, item,
  field) with TTLs of 1h / 8h / 7d. The same secret in a different repo needs
  its own approval.
- **Inline code never earns trust.** `sh -c`, `python -c`, `node -e` (and
  their combined-flag and `env`-wrapped variants) always require approval and
  never create a Grant.
- **You stay informed.** The first sighting of a new command under an
  existing Grant sends a non-blocking notification with a one-tap revoke.
- **Secrets stay sealed.** Envelope encryption (ephemeral P-256 ECDH +
  HKDF-SHA256 + AES-256-GCM) means TLS terminators, tunnels, and proxies
  between broker and CLI never see plaintext. Nothing is persisted server-side
  but grants and sightings.
- **It's fast.** A granted request is one HTTP round trip against a resident
  vault session: sub-second in production (measured 0.7–0.9 s over a WireGuard
  link, vs 10–30 s for the Windmill-orchestrated predecessor).

## How it works

The **broker** is the only stateful service: it logs into the vault once at
startup and keeps an unlocked session resident (syncing on demand), stores
Grants in SQLite, talks to Telegram via `getUpdates` long-polling (outbound
only — no public webhook endpoint needed), and parks each pending request
until the Owner taps a button or the timeout fires.

The **CLI** runs on the agent machine behind a strict `env -i` wrapper: it
validates the request, generates an ephemeral keypair, sends one long-polling
HTTPS request, decrypts the envelope, and spawns the child command with the
secrets in its environment — restoring the caller's `PATH`, and nothing else.

Full design: [ARCHITECTURE.md](./ARCHITECTURE.md) · domain glossary:
[CONTEXT.md](./CONTEXT.md) · key decisions: [docs/adr/](./docs/adr/).

## Getting started

### 1. Run the broker

```sh
git clone https://github.com/broven/secretary && cd secretary/deploy
cp .env.example .env          # fill in vault + telegram settings
# put secrets under deploy/secrets/ (bw_clientid, bw_clientsecret,
# bw_password, telegram_bot_token) — docker secrets, never env
docker compose up -d --build broker
# or, to also run a bundled Vaultwarden:
docker compose --profile vaultwarden up -d --build
```

The broker binds `127.0.0.1:8787` by default — front it with your TLS
ingress, tunnel, or VPN before widening the bind. Approvals need only
outbound HTTPS. Step-by-step operator guide (bot setup, vault account,
bundled-vaultwarden TLS): [deploy/README.md](./deploy/README.md).

### 2. Register a client

```sh
docker exec <broker> bun run /app/server/src/cli_admin.ts client add my-mac
# prints client_id + token, shown exactly once
```

### 3. Set up the agent machine

Two commands. The first installs the CLI — a prebuilt binary for your platform,
checksum-verified, no bun or compiler needed:

```sh
curl -fsSL https://raw.githubusercontent.com/broven/secretary/main/install.sh | sh
```

The second installs the agent-facing skill, and asks which of your code agents
should get it:

```sh
npx skills add broven/secretary --skill use-approved-secrets
```

Prefer to read the installer before running it — it is a shell script from the
internet:

```sh
curl -fsSL https://raw.githubusercontent.com/broven/secretary/main/install.sh -o install.sh
less install.sh && sh install.sh
```

It installs into `~/.local/share/secretary/` and links `~/.local/bin/approved-secret`;
override with `SECRETARY_DIR` / `SECRETARY_BIN_DIR`, or pin a release with
`SECRETARY_VERSION=vX.Y.Z`.

Then the bootstrap, which is yours alone — a token must never be pasted into an
agent's conversation:

```sh
approved-secret auth set-url https://secretary.example.com
approved-secret auth set-client-id <client_id>
approved-secret auth import     # prompts for the token → macOS Keychain
```

On Linux, `SECRETARY_URL` / `SECRETARY_TOKEN` env vars replace the Keychain.

### 3. Use it

```sh
secretary list                  # safe catalog: names and fields, no values
secretary exec --reason "why you need it" \
  --item "ITEM NAME" field=ENV_NAME [--item ...] -- command args...
```

`field` is `password`, `username`, or a custom field name. Approve from the
Telegram card; repeats within the TTL run without a card. For code agents,
put the `secretary` wrapper script on `PATH` and tell the agent to use it for
any credential need — the approval discipline comes with the tool.

## Status & scope

Running in production for its author. Single Owner by design; Telegram is the
first Approver implementation behind a small interface. Not yet: multi-user
approval flows, Windows CLI, a web approval fallback. Vault compatibility:
official Bitwarden and Vaultwarden (anything the `bw` CLI accepts — the
broker requires an https vault URL).

## Development

```sh
bun test                                   # unit + integration (fake vault/Telegram)
INTEGRATION_REAL_BW=1 bun test server/test/real_bw.test.ts   # real vaultwarden + bw
bun run deploy/smoke.ts                    # full compose e2e smoke
bun run deploy/live_test.ts                # guided live test against real Telegram
```

The integration suite drives the real broker against a fake Telegram server
and injected vault; the smoke test builds the image and runs the compiled CLI
against a throwaway vaultwarden. No mocks of secretary's own code.
