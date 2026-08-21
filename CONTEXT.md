# Domain glossary

The ubiquitous language of secretary. Terms are used with exactly these meanings in
code, docs, and approval UI.

## Broker

The resident server process that owns vault access and mediates every secret
request. The only component that ever holds plaintext secrets and the vault
session.

## Client

One installation of the CLI on one machine, identified by a `client_id` and
authenticated to the Broker with a bearer token. A Client can request, but a
request alone never yields a secret — it must be covered by a Grant or approved by
the Owner.

## Owner

The human who owns the vault and answers approval requests. There is exactly one
Owner per Broker deployment.

## Item / Field

An Item is one vault entry (matched by exact name); a Field is one credential
inside it (password, username, a custom field). Requests name Items and map Fields
to environment variable names (aliases).

## Request

One attempt by a Client to run a command with secrets: the tuple of caller
identity, Client, Repo, Items/Fields, the command argv, and a human-readable
reason. A Request either hits Grants (fast path) or becomes an Approval.

## Approval

An Owner decision on a Request, delivered through an Approver channel. Approving
carries a TTL choice (1h / 8h / 7d) and creates Grants; rejecting fails the
Request. No decision within the timeout fails closed.

## Approver

The channel interface through which the Owner receives Approvals and revocations.
Telegram is the first implementation. One Broker uses one Approver at a time.

## Grant

A stored authorization that lets matching Requests skip Approval until it expires.
Keyed by (caller, client_id, repo, item_id, field) — deliberately *not* by env
alias or item revision, so renaming an alias or rotating a password does not
re-trigger Approval, but adding an Item or Field does. A Request is covered only
if *every* requested (item, field) pair has an unexpired Grant (containment
match). Extending never shortens: a new short TTL cannot cut an existing longer
Grant.

## Repo

The identity of the codebase a Request originates from, derived from the git
remote of the caller's working directory. Part of the Grant key: the same secret
in a different repo needs its own Approval.

## Inline shell

A command whose argv embeds code to evaluate (`sh -c`, `python -c`, …). Inline
shell Requests are detected by the Broker, always require Approval, and never
create Grants — the command string is unauditable, so nothing is remembered.

## Sighting

The first time a given command argv fingerprint is seen under an existing Grant.
A Sighting does not block; it sends the Owner a non-blocking notification with a
revoke button. The command is informational — it is not part of what a Grant
authorizes.

## Envelope

The end-to-end encryption wrapper for secret delivery: the Client generates an
ephemeral P-256 keypair per Request; the Broker encrypts credentials to it
(ECDH + HKDF-SHA256 + AES-256-GCM). Nothing between Broker memory and the Client
process — TLS terminators, tunnels, proxies — can read the secrets.

## Fast path

The Request flow when Grants fully cover it: no Approval, secrets delivered
immediately. The latency budget (p50 < 1 s) is defined against this path.
