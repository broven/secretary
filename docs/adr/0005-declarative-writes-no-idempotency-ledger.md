# Write Operations are declarative; no idempotency ledger

A write whose response is lost — a dropped connection, a broker restart — leaves
the Client unable to tell whether the vault changed. The obvious fix is an
idempotency ledger: persist each request id with its outcome and replay the
answer. We rejected it. The vault is already the single source of truth for what
exists. The Broker persists Grants plus revocation watermarks that prevent late
Grant issuance after a destructive write, but never a Write Request's outcome.
An outcome ledger would be a second, weaker account of vault state — one that can
drift, expire, or be restored out of step with the vault it describes.

Instead the Operations are defined by the state they assert, so retrying is safe
by construction: an Update whose Field already holds the requested value, or a
Remove whose target is already gone, has reached its goal and returns success
without disturbing the Owner. Each check forces a vault sync first, so a cached
Item list can never answer for the vault.

Create cannot join them. "An Item by this name exists" does not mean *this*
Client created it — the name may have been taken months ago by something
unrelated, and reporting success would hand the agent a credential belonging to
somebody else's account. Create therefore **fails on a name collision**, and the
Client is expected to do what a person would: read the Item's Description, decide
whether it is the one it just wrote or a stranger, and pick a different name or
carry on. Description is required at Create precisely so that this judgement is
possible.

## Consequences

- A lost Create response surfaces as an error the agent must reason about, not a
  silent success. This is the intended division of labour: the protocol refuses
  to guess, the intelligent client decides.
- Retries never produce a duplicate approval card — the state check runs before
  the Approver is involved.
- Two concurrent Creates of the same name could both pass the collision check, so
  the Broker serialises Creates on the Item name in-process.
- Catalog entries carry a creation time so a Client can tell an Item it just made
  from one that predates it.
