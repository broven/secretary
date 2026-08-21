# secretary

Approval-gated secrets for code agents, backed by Bitwarden / Vaultwarden.

A code agent never sees your vault. It asks `secretary` to run a command with named
credentials injected as environment variables; you approve (or reject) the request
from Telegram; the secret values travel end-to-end encrypted from the broker to the
agent's machine and exist only in the child process's environment.

```
code agent ──> secretary CLI ──HTTPS──> secretary broker ──> Bitwarden / Vaultwarden
                                              │
                                              └──> Telegram (approval buttons: 1h / 8h / 7d / reject)
```

## Status

Design phase. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design,
[CONTEXT.md](./CONTEXT.md) for the domain glossary, and [docs/adr/](./docs/adr/)
for key decisions.

This project is the successor of a Windmill-based pipeline; the rewrite exists to
cut per-request latency from 10–30 s to under 1 s and to make the whole thing
deployable by anyone with `docker compose up`.

## Planned layout

```
server/   resident broker service (Bun/TypeScript)
cli/      approved-secret CLI (compiled Bun binary, runs on the agent machine)
skill/    agent skill definition (use-approved-secrets)
deploy/   Dockerfile + docker-compose.yml (broker + optional vaultwarden profile)
```
