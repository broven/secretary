# Linux CLI configuration is a protected user file

## Status

Accepted

## Context

The CLI's macOS bootstrap uses the user's Keychain, but a Linux or headless
client usually has no platform keychain. Requiring `SECRETARY_URL` and
`SECRETARY_TOKEN` environment variables made the documented `auth` commands
unusable in that environment. The client token is a bearer credential, so a
plain file is acceptable only with an explicit and narrow security boundary.

## Decision

On Linux, the CLI stores the optional fields `url`, `token`, and `clientId` in:

`${XDG_CONFIG_HOME:-$HOME/.config}/secretary/config.json`

The `secretary` directory must be owned by the current user and have mode
`0700`. The file must be owned by the current user and have mode `0600`.
Reads reject missing ownership, unsafe modes, symbolic links, non-regular files,
invalid JSON, unknown fields, and invalid field values. The CLI never follows a
symbolic link for configuration access.

Updates read the complete existing object, validate it, write a new file in the
same directory with exclusive creation and mode `0600`, `fsync` it, and replace
the configuration with an atomic same-directory rename. Updating one field
therefore preserves the others. `auth delete` is deliberately a cleanup path:
it may remove an owned file even when its contents or permissions are invalid,
and removes an owned configuration symlink itself without following its target.
It refuses files owned by another user.

`auth import` reads the token twice from an interactive terminal with terminal
echo disabled. The token is never accepted from argv and is never printed.
Environment variables (`SECRETARY_URL`, `SECRETARY_TOKEN`, and
`SECRETARY_CLIENT_ID`) have priority over platform storage, but invalid or
unsafe platform storage still fails closed rather than being hidden by an
override. `auth delete` changes only platform storage and never unsets
environment variables.

macOS continues to use Keychain. Linux does not attempt to integrate with
GNOME Keyring, KWallet, Secret Service, or to encrypt the file itself.

## Consequences

The Linux file contains a plaintext bearer token and must be treated as a
credential-equivalent file: users should protect the account and home
filesystem. File permissions and ownership prevent ordinary same-machine users
from reading it, but do not protect against a process already running as the
same user or a compromised root account. This is the intended boundary for a
headless user-level CLI and is documented instead of implying that the file is
cryptographically protected.

The storage format is intentionally small and private to the CLI. There is no
migration from shell profiles; existing environment variables continue to work
and take precedence. Windows support remains out of scope.
