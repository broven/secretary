# New Items go where the Owner can see them

Every Item the Broker creates is filed by `bw` in the **vault account's personal
space** by default, and a personal Item is readable by that account alone — not
by an Organization it belongs to, however privileged that account is *inside*
the Organization. So a deployment whose Broker runs as a dedicated automation
account while the Owner logs in as themselves produced a silent split: the
agents' catalog grew, and the Owner's vault showed nothing. The failure was not
a bug in a code path but a missing decision — nothing in the system said who
the Items were for.

We added one: **Vault placement**, an optional `(organization_id,
collection_id)` pair (`VAULT_ORG_ID` / `VAULT_COLLECTION_ID`) applied by
`newLoginItemPayload` to every Create. The pair is deliberately optional rather
than required. A single-account deployment — the Broker running on the Owner's
own API key — has no second account to hide from, and forcing every operator to
provision an Organization and Collection before their first write would buy
them nothing.

## Consequences

- Placement is read at startup and never per-request, so it cannot disagree
  with itself midway through a deployment's life; changing it is a config
  change and a restart, not a write-path feature.
- `bw` validates the pair, not the Broker: a wrong Collection id, or an
  automation account without write access to it, surfaces as a failed Create
  with the vault's own error. Pre-validating would duplicate the check the only
  component that knows the truth already performs.
- Adding a Field to an Item still in the personal space is **refused** when a
  placement is configured. Applying it would keep that Item invisible forever
  while the Owner believed the vault held it; refusing makes the move a
  precondition the Owner can act on. Items created before the placement existed
  therefore need one `bw move` each — deliberate, and the reason the refusal
  names the Item.
- Placement does not move anything by itself. Migration is an explicit vault
  operation, because `bw move` needs the *current* account's own session and
  the correct collection key material, and a Broker that rewrote ownership at
  startup would be a surprise nobody asked for.
