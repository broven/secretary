# Deploying the secretary broker

Operator guide for running the broker with docker compose. Architecture and
security model: see [../ARCHITECTURE.md](../ARCHITECTURE.md).

## Prerequisites

- Docker with the compose plugin, on an amd64 host or one that can emulate
  linux/amd64 (the Bitwarden CLI ships x64-only; the compose file pins the
  platform).
- A Telegram account (the Owner's).
- A Bitwarden-compatible vault: Bitwarden cloud, an existing Vaultwarden, or
  the bundled `vaultwarden` compose profile.
- For approvals, the broker needs only outbound HTTPS (Telegram long-polling).
  Inbound, only the CLI API port (8787) must be reachable from agent machines,
  however you choose to expose it (reverse proxy, tunnel, VPN, ...).

## 1. Create the Telegram bot

1. Talk to [@BotFather](https://t.me/BotFather), `/newbot`, and save the bot
   token — it becomes the `telegram_bot_token` secret.
2. Get your numeric chat id and user id, e.g. by messaging
   [@userinfobot](https://t.me/userinfobot). Put the chat id in
   `TELEGRAM_CHAT_ID` and your user id in `TELEGRAM_ALLOWED_USER_IDS`
   (comma-separated if several).
3. The token must NOT have an active webhook — the broker uses long polling,
   and Telegram serves only one mode per token. If the token was ever used
   with a webhook, delete it first:
   `curl "https://api.telegram.org/bot<TOKEN>/deleteWebhook"`.
4. Send your bot one message (`/start`) so it can message you back.

## 2. Prepare the vault

Either:

- **Bitwarden cloud**: set `VAULT_URL=https://vault.bitwarden.com` in `.env`.
- **Bundled Vaultwarden**: start it first so you can create the account:

  ```sh
  docker compose --profile vaultwarden up -d vaultwarden
  ```

  Temporarily uncomment the `ports: "8222:80"` mapping in
  `docker-compose.yml` to reach the web UI in a browser, and keep
  `SIGNUPS_ALLOWED=true` for now. After setup, set `SIGNUPS_ALLOWED=false`
  and remove the port mapping again — the broker reaches vaultwarden over
  the compose network. When using this profile, always pass
  `--profile vaultwarden` to compose commands.

### TLS for the bundled vaultwarden

The bw CLI baked into the broker image refuses plain-http vault servers, so
the compose-internal `http://vaultwarden` does NOT work. Terminate TLS inside
the vaultwarden container:

```sh
mkdir -p deploy/vw-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout deploy/vw-tls/key.pem -out deploy/vw-tls/cert.pem \
  -subj "/CN=vaultwarden" \
  -addext "subjectAltName=DNS:vaultwarden,DNS:localhost,IP:127.0.0.1"
chmod 644 deploy/vw-tls/key.pem deploy/vw-tls/cert.pem
```

Then in `docker-compose.yml` uncomment `ROCKET_TLS` and `ROCKET_PORT: "443"`
and the `./vw-tls:/ssl:ro` mount on the vaultwarden service, and
`NODE_EXTRA_CA_CERTS: /vw-tls/cert.pem` plus a `./vw-tls:/vw-tls:ro` mount on
the broker service. The default `VAULT_URL=https://vaultwarden` then resolves
to port 443 and validates against that cert.
(Alternatively front vaultwarden with your own TLS proxy and point
`VAULT_URL` at it.)

Then, in the vault's web UI, with the dedicated automation account:

1. Create the account and store the secrets your agents will need as vault
   items.
2. Create the personal API key: **Settings → Security → Keys → View API key**.
   `client_id` is `BW_CLIENTID`, `client_secret` is `BW_CLIENTSECRET`.
3. `BW_PASSWORD` is the account's master password; `BW_EMAIL` its email.

## 3. Write the secret files

The compose file wires four docker secrets from `deploy/secrets/` (the
directory is gitignored). One value per file, no quotes; trailing newlines are
fine.

```sh
cd deploy
printf '%s' 'user.xxxxxxxx-....' > secrets/bw_clientid
printf '%s' '...client secret...' > secrets/bw_clientsecret
printf '%s' '...master password...' > secrets/bw_password
printf '%s' '123456:ABC-...' > secrets/telegram_bot_token
chmod 600 secrets/bw_clientid secrets/bw_clientsecret secrets/bw_password secrets/telegram_bot_token
```

## 4. Fill .env and start

```sh
cp .env.example .env   # then edit: VAULT_URL, BW_EMAIL, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS
docker compose up -d --build
# or, with the bundled vault:
docker compose --profile vaultwarden up -d --build
docker compose logs -f broker
```

## 5. Issue a client token

Each agent machine gets its own client identity:

```sh
docker compose exec broker bun run server/src/cli_admin.ts client add <name>
```

The token is printed once — copy it now; it is not stored in recoverable form.

## 6. Install the CLI on the agent machine

1. Build it: run `cli/build.sh` (produces a compiled Bun binary).
2. Put `cli/scripts/secretary` on your `PATH`.
3. Store the config:
   - macOS: `secretary auth set-url https://your-broker.example.com` then
     `secretary auth import` (token goes into the Keychain).
   - Linux (or CI): export `SECRETARY_URL` and `SECRETARY_TOKEN` instead.

## 7. Smoke test

```sh
secretary list
secretary exec --reason "smoke test" --item NAME password=MY_TOKEN -- some-command
```

The first `exec` sends an approval card to your Telegram; approve it and the
command runs with `MY_TOKEN` set in its environment only.

## Security notes

- **Fail closed**: no decision within the timeout (default 300 s), or any
  ambiguity, means no secrets.
- **Envelope encryption** is end-to-end (ephemeral P-256 + HKDF + AES-GCM):
  TLS terminators, tunnels, and proxies in front of the broker never see
  plaintext secrets.
- **Secrets as files**: every secret env accepts a `_FILE` variant; the
  docker-secrets wiring in the compose file is the documented default. Plain
  env works but leaks more easily (inspect, logs). Setting both a variable
  and its `_FILE` variant is a configuration error.
- **`SECRETARY_DEV_AUTO_APPROVE` is test-only**: it auto-approves every
  request and refuses to activate when `NODE_ENV=production`. Never set it on
  a real deployment.
