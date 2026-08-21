# Architecture

Terminology: see [CONTEXT.md](./CONTEXT.md). Key decisions with their trade-offs:
[docs/adr/](./docs/adr/).

## Goal

A publishable, self-hostable solution for letting code agents use Bitwarden /
Vaultwarden secrets safely: every use is either covered by a time-limited Grant or
approved by the Owner from Telegram, and the agent only ever sees the secrets as
environment variables of the child process it asked to run.

Non-goals: multi-owner / team approval flows, secret storage of its own (the vault
stays the source of truth), Windows support for the CLI (macOS/Linux first).

## Components

```
┌──────────────────────────────┐          ┌─────────────────────────────────────────┐
│ agent machine (macOS/Linux)  │          │ server (docker compose)                 │
│                              │  HTTPS   │                                         │
│  code agent                  │  bearer  │  ┌───────────┐     ┌─────────────────┐  │
│    └─> secretary CLI ────────┼──token──>│  │  broker    │──> │ vaultwarden     │  │
│        (compiled Bun binary, │          │  │ (Bun/TS)   │    │ (optional        │  │
│         token in Keychain)   │          │  │  SQLite    │    │  profile) or     │  │
│                              │          │  │  bw CLI    │    │  external        │  │
└──────────────────────────────┘          │  │  session   │    │  Bitwarden(VAULT_URL)│
                                          │  └─────┬──────┘    └─────────────────┘  │
                                          └────────┼────────────────────────────────┘
                                                   │ getUpdates long-poll (outbound only)
                                                   v
                                              Telegram Bot API ──> Owner's phone
```

- **Skill** (`skills/use-approved-secrets/`): the agent-facing contract (`SKILL.md`) and its installer. It
  lives next to the CLI that implements it, because the previous split let the doc go
  on describing a retired system for months after the cutover.
- **CLI** (`cli/`): argv parsing, env scrubbing (`env -i` wrapper), Keychain-stored
  bearer token + client_id, repo identity from git remote, Envelope keygen and
  decryption, child spawn with secrets injected. Ported from the existing
  `approved-secret` CLI with the Windmill transport replaced by direct broker HTTP.
- **Broker** (`server/`): the only stateful service. Owns the vault session, the
  Grant store (SQLite), the Approver (Telegram long-polling), Envelope encryption,
  inline-shell detection, Sightings. Ported from the existing Windmill
  `f/secretapprove/` scripts (~1800 lines of TypeScript) minus all Windmill
  orchestration.
- **Vault**: any Bitwarden-compatible server — official Bitwarden cloud or
  Vaultwarden — selected by `VAULT_URL`. The compose file ships a vaultwarden
  service behind an optional profile for users who want the all-in-one deployment.

## Request flow

1. CLI sends one `POST /v1/requests` over HTTPS: reason, items/fields with env
   aliases, argv fingerprint, repo, ephemeral P-256 public key. The connection
   stays open (long poll) until decision or timeout.
2. Broker resolves items against its vault session (resident `BW_SESSION`,
   on-demand `bw sync`), checks Grant containment in SQLite.
3. **Fast path**: all pairs granted → encrypt Envelope, respond on the same
   connection. First-seen argv additionally fires a non-blocking Sighting
   notification with a revoke button.
4. **Approval path**: broker sends the Telegram card (approve 1h/8h/7d, reject),
   parks the request in memory, and resolves it when the button callback arrives
   via getUpdates. First decision wins; timeout (default 300 s) fails closed.
5. CLI decrypts the Envelope and execs the child with secrets in its environment.
   Nothing is persisted server-side but Grants, Sightings, and destructive-write
   revocation watermarks — never job results, write outcomes, or plaintext.

## Write flow

Writes are a separate pipeline (`server/src/writes.ts`) over the same broker, vault
session and Approver. Three Operations — Create, Update, Remove — each on exactly one
Item, so an approval card is never ambiguous about what it is asking for.

1. CLI sends `POST /v1/writes`. Field values arrive as a JSON object on the CLI's
   **stdin**, never in argv: `--field password=@stdin`. A literal value is refused by
   the CLI itself.
2. Broker forces a vault sync, reads the Item's current state, and asks whether the
   vault is *already* in the requested state. If it is, the request succeeds as
   `unchanged` and the Owner is never disturbed — this is what makes a retry safe, and
   why there is no idempotency ledger (ADR-0005). Create is the exception: a taken name
   is an error, because the Item behind it may be somebody else's.
3. Approval card. No TTL buttons — approving changes the vault once and grants nothing.
   Secret values appear only as Fingerprints; non-secret changes (name, description)
   render as a real diff. Destructive cards carry their blast radius: how many Grants
   the change revokes, and whether it can be undone.
4. Bracket a destructive apply with durable revocation-watermark advances and Grant
   revocation: once before the mutation, then again after it succeeds. Apply through
   `bw serve` (`POST /object/item`, `PUT /object/item/{id}`,
   `DELETE /object/item/{id}` — never `--permanent`). The two generations prevent
   reads that were already awaiting Approval, or that resolved while the mutation
   was in flight, from issuing a late Grant.

**Owner-supplied values** (`--field password=@owner`) never enter the agent's context.
The broker parks the request and returns a one-time Entry Form link; the CLI prints it
and exits without writing. The Owner opens it, types the value, and the write lands,
followed by a non-blocking notification through the Approver. The link is bound to no
Approver channel, so a second channel needs no second design — and because holding it
is enough to complete the write, `@owner` is restricted to Create, the one purely
additive Operation (ADR-0004).

## Latency

Design targets (the old Windmill pipeline took 10–30 s even when instantly
approved — three orchestrated jobs, 1.25 s client polling, and up to three full
`bw login+unlock+sync` cycles per exec):

| Path | Target |
| --- | --- |
| Fast path, end-to-end (CLI invoke → child starts), incl. public RTT | p50 < 1 s, p95 < 2 s |
| Approval path, from Owner's button tap → secrets delivered | < 2 s |

What buys it: a single HTTP round trip instead of job orchestration; a resident
unlocked `bw` session with on-demand sync instead of login+sync per step; `bw`
baked into the image instead of downloaded at first use; server-side parking
instead of interval polling.

## Security model

Ported unchanged from the predecessor:

- **Envelope encryption** end-to-end (see ADR-0002) — TLS terminators and tunnels
  in front of the broker never see plaintext.
- **Environment scrubbing**: the CLI wrapper starts from `env -i`, passes an
  allowlist, restores the caller's `PATH` for the child; reserved env prefixes are
  rejected as aliases.
- **Grant model**: containment matching, TTLs of 1h/8h/7d, `GREATEST` semantics on
  extension, no command in the key (Sightings cover that, non-blocking).
- **Inline shell**: always approve, never grant.
- **Fail closed**: timeout or any ambiguity → no secrets.
- **Write path**: every write is approved and creates no Grant; values reach the Owner
  only as Fingerprints; `bw delete --permanent` is never reachable. Its transport
  threat model is deliberately weaker than the read path's — see ADR-0004.
- **Client auth**: static per-client bearer token (issued by `secretary client
  add`), Keychain-stored. A stolen token can *request*, but cannot *receive*
  without Owner approval or a live Grant on that same client identity.
- **Broker credentials**: every secret env (`BW_CLIENTSECRET`, `BW_PASSWORD`,
  Telegram bot token, …) accepts a `_FILE` variant; docker secrets are the
  documented default, plain env works.

Accepted trade-off: the broker keeps an unlocked vault session in memory for its
lifetime (ADR-0003).

## Deployment

`deploy/docker-compose.yml`: `broker` service (image built from `deploy/Dockerfile`
with the pinned `bw` CLI baked in) + `vaultwarden` behind `--profile vaultwarden`.
Location-agnostic: no inbound port is required for approvals (Telegram is
outbound long-polling); only the CLI API needs to be reachable by agent machines,
however the operator chooses to expose it.

One port serves everything, including the Entry Form at `/entry/<nonce>`. That form
accepts a plaintext value over the transport alone (ADR-0004), so the broker must be
reached over a path trusted end to end — a tailnet, a VPN, or TLS terminated by the
broker's own ingress — and **not** through a TLS-terminating tunnel or reverse proxy
you would not trust with the value itself. `ENTRY_TTL_S` (default 600) bounds how long
a link stays usable.

## Migration from the Windmill pipeline

Hard cutover: point the `use-approved-secrets` skill at the new CLI once smoke
tests pass. Existing Grants are not migrated (max TTL is 7 days; each secret
re-approves once). The Windmill scripts, scoped token, and Telegram webhook are
kept one week as a fallback, then deleted — note the bot token can only serve one
mode, so registering long-polling requires deleting the old webhook at cutover.
