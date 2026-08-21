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
Request. No decision within the timeout fails closed. On a Write Request there
is no TTL to choose — approving it changes the vault once and grants nothing.

## Approver

The channel interface through which the Owner receives Approvals and revocations.
It also carries notifications the Owner cannot answer — Sightings, and the record
of a completed Write Request — so that nothing changes the vault silently.
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

## Write Request

One attempt by a Client to change the vault: a Write Operation, one Item, a
reason, and the caller/Client/Repo identity. Every Write Request needs an
Approval and never creates a Grant — storing a credential and being allowed to
use it are separate decisions, judged on different evidence.

## Write Operation

What a Write Request does. Exactly one per Request, on exactly one Item:
**Create** (a new Item, or a new Field on an existing one), **Update** (an
Item's name, its Description, or a Field's value), **Remove** (an Item to the
vault's trash, or a Field — irreversibly, since the vault keeps no history for
Fields).

Write Operations are *declarative*: a Request that asks for a state the vault is
already in succeeds without disturbing the Owner. Create is the exception — a
name already taken is an error, because the Item behind that name may be
somebody else's and silently adopting it would hand the Client the wrong
credential.

## Field Source

Where a Field's value comes from, chosen per Field. **Agent-supplied** means the
plaintext is already in the agent's context; the vault is its archive, not its
first hiding place. **Owner-supplied** means it must never enter that context —
the Owner types it into an Entry Form instead. Owner-supplied values are
confined to Create: the one path that skips an Approval may only add, never
overwrite or destroy.

## Entry Form

The one-time page where the Owner enters Owner-supplied values. Its link *is*
the capability — whoever holds it can complete that one Create, and nothing
else. Deliberately bound to no Approver channel, so a second channel needs no
second design. Write-only, single-use, short-lived, and it never displays a
value already in the vault.

## Description

An Item's stated purpose, carried in the vault's own notes field. It is the only
thing about an Item a Client may read without an Approval, so it is what an
agent uses to tell one Item from another — and therefore required when creating
one.

## Fingerprint

A short per-card keyed digest of a secret value, shown on Approval cards so the
Owner can confirm *which* value is being written without the card ever carrying
the value itself. Every card uses a fresh key: low-entropy values cannot be
guessed offline, and equal values cannot be correlated across cards. Within one
card, equal values keep the same Fingerprint and different values get visibly
different Fingerprints.
