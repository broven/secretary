# Onboarding

This runbook is the contributor entry point for both people and code agents.
It covers the repeatable local loop; production broker deployment remains in
`deploy/README.md`.

## 1. Install tools and dependencies

Prerequisite: install `mise`. Docker is optional and is only required for the
full smoke test or a production-like deployment.

```sh
mise trust
mise install
mise run install
```

`mise install` installs the pinned Bun, ShellCheck, and actionlint versions.
`mise run install` installs the Bun workspaces from `bun.lock`.

## 2. Run the development loop

```sh
mise run test
mise run lint
mise run build
```

There is no single default `dev` process because this repository contains a CLI,
a broker, and deployment tooling. Choose the entry point that matches the work:

```sh
mise run dev:broker  # broker from source; requires broker configuration
mise run smoke       # disposable Vaultwarden + broker + compiled CLI end to end
```

`mise run smoke` requires Docker, OpenSSL, and the host tools documented in
`deploy/README.md`. It creates throwaway credentials and cleans up its Compose
stack when it exits.

## Task reference

| Command | Purpose |
| --- | --- |
| `mise run install` | Install all workspace dependencies |
| `mise run dev` | List the available development entry points |
| `mise run dev:broker` | Run the broker from source using the current environment |
| `mise run test` | Run hermetic unit and integration tests |
| `mise run lint` | Run ShellCheck and actionlint |
| `mise run build` | Test and compile the local CLI binary |
| `mise run smoke` | Run the disposable Docker end-to-end test |

## Secrets and configuration

The routine install, test, lint, and build tasks require no external secrets.
The smoke test creates throwaway values locally and does not use the owner's
vault.

The broker cannot bootstrap its own production credentials through itself.
Production Bitwarden and Telegram credentials therefore use the Docker secret
files documented in `deploy/README.md`; never commit those files or copy their
values into task definitions. No repository-level `approved-secret` binding is
currently required, so there is no inventory entry to register here.

## Repository guidance

- Agent instructions: `AGENTS.md`
- Architecture: `ARCHITECTURE.md`
- Domain language: `CONTEXT.md`
- Architectural decisions: `docs/adr/`
- Issue-tracker and triage configuration: `docs/agents/`
- Product-facing agent skill: `skills/use-approved-secrets/SKILL.md`

## Worktrees

Worktrunk reads `.config/wt.toml`; Orca reads the generated `orca.yaml` wrapper.
A new worktree installs the pinned tools and dependencies through the same mise
tasks used above. No default dev task owns long-lived external resources, so no
repository teardown task is required.
