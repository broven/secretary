# The write path is protected by transport only, and its unapproved lane may only add

Reads are wrapped in an Envelope (ADR-0002) so that no TLS-terminating middlebox
ever sees a credential. Writes cannot inherit that protection symmetrically: an
Owner-supplied value is typed into a browser form served by the Broker itself, so
any middlebox able to read the POST body is equally able to rewrite the page that
encrypts it — in-browser envelope encryption would be theatre. We chose one
threat model for the whole write path rather than two: **write bodies are
protected by the transport alone**, and the deployment is expected to reach the
Broker over a path trusted end-to-end (a tailnet, a VPN, or TLS terminated by the
Broker's own ingress). The Agent-supplied lane could have had a real Envelope
cheaply — the broker would need a long-term keypair pinned when a Client's token
is issued — and we deliberately left that on the table to keep the two lanes
telling the same story.

The Entry Form's link is the capability that completes a Create, and it is
returned to whoever called the CLI rather than pushed to the Owner's Approver
channel. That keeps the form independent of Telegram — a second channel needs no
second design — but it means a stolen Client token can complete that one write
with no Owner decision in the loop. We close the damage rather than the hole:
**Owner-supplied values are accepted only by Create**, the one purely additive
Operation. Update and Remove are always blocking and always approved.

## Consequences

- Exposing the Broker beyond a trusted network exposes the write path with it;
  there is one port and no separate switch. Operator docs must say so plainly.
- Worst case for a leaked Entry link or a stolen token is a junk Item in the
  vault, never the destruction of a live credential — Fields have no history in
  Bitwarden, so an unapproved overwrite would have been unrecoverable.
- "Rotate an existing credential without letting the agent see the new value" is
  not expressible. The Owner does that in the vault client, or removes the Field
  and creates it again — both approved, both visible.
- Hardening reads against an *active* middlebox (ADR-0002 only ever promised
  protection against a passive one) needs the same long-term Broker keypair. If
  that is ever built, revisit the Agent-supplied lane in the same change.
