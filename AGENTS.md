# Repository Guidance

## Project

Secretary is an approval-gated secret broker for code agents. The CLI requests
named vault fields, the Broker resolves and authorizes them, and the Owner acts
through an Approver channel. Use the canonical terms in `CONTEXT.md`.

## Architecture And Paths

- `cli/`: self-contained Bun CLI, environment scrubbing, platform config, and envelope decryption.
- `server/`: Broker HTTP API, Grants, Approvals, vault access, and write flows.
- `deploy/`: Docker Compose deployment plus smoke and live tests.
- `skills/use-approved-secrets/`: product-facing skill shipped to secretary users; keep it beside the CLI and do not treat it as a repository development skill.
- `ARCHITECTURE.md`: system boundaries and security model.
- `docs/adr/`: accepted architectural decisions.

## Working In This Repository

Start with `ONBOARD.md`. Use `mise run <task>` as the shared interface for
install, test, lint, build, and development entry points. Keep `bun.lock`
frozen during ordinary installs.

Before changing a domain concept, read `CONTEXT.md` and the relevant ADRs.
Preserve the self-contained CLI boundary: it must not import server modules.
Keep changes narrowly scoped and add tests proportional to security impact.

Never commit credential values. Routine tests use fakes or throwaway values;
production Broker credentials stay in the Docker secret files described by
`deploy/README.md`.

## Agent skills

### Issue tracker

Issues are tracked in this repository's GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the five canonical state labels. See `docs/agents/triage-labels.md`.

### Domain docs

Domain documentation uses a single-context layout. See `docs/agents/domain.md`.
