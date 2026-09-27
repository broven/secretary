# Inline code can be granted for a period, on its own expiry

## Status

Accepted. Supersedes the "Inline shell: always approve, never grant" rule.

## Context

Inline code — `sh -c`, `python -c`, `node -e` and their variants — was approved
once per run and never remembered. The reasoning: for inline code the argv *is*
the evidence. The Owner judges the exact code on the card, so an authorization
that outlived the card would authorize code nobody has read.

That boundary turned out to be porous in the direction that matters. `bash
script.sh` and `python3 x.py` are ordinary commands: they earn Grants like any
other, and the card shows only the file name, never its contents. An agent that
wants a reusable authorization for arbitrary code already has one — write the
code to a file first. Inline code was the one form whose contents the Owner
*could* see, and it was the form treated as least trustworthy. The practical
result was an Owner re-approving the same one-liner every few minutes, and a
standing incentive for agents to move code into throwaway files where it becomes
invisible, which is the opposite of what the skill asks for.

## Decision

An inline card keeps **"✅ 批准本次执行"** as its first button, unchanged: this
run only, nothing remembered. Beside it sit 1h / 8h / 7d / 30d buttons, each
labelled with what it actually hands out ("⚠️ 批准 1 小时（含任意内联代码）"),
under a warning line at the top of the card: approving lets *any* inline code in
this repository use these secrets without review. The Owner judges that on the
card. There is no per-Item pre-marking ("this Item may be used inline") and no
repository allow-list in Broker configuration: both would move a judgment the
Owner makes in context into configuration made in advance, and both would be one
more place to keep true.

The permission is a **separate expiry on the same Grant row** — same key, a
second column. An inline approval extends only the inline expiry; an ordinary
approval extends only the ordinary one; both keep the never-shorten rule. Inline
code is covered only by the inline expiry. An ordinary command is covered by
either, since permission to run arbitrary code with a secret contains permission
to run a named command with it. Keeping the expiries apart means the Owner can
withdraw the wide permission and keep the narrow one, and an ordinary top-up
can never quietly extend what inline code may do.

Two things make the wider permission tolerable to live with:

- **Silent Sightings with the code on them.** Every Sighting is sent with
  `disable_notification`; only cards that need a tap to proceed ring. An inline
  Sighting renders the complete code, since the Owner never saw this run's code
  on any card. When the Grant carries inline permission the Sighting offers
  "只撤内联权限" beside "全部吊销".
- **`/grants`.** The Owner can list every live Grant — one entry per Approval,
  earliest expiry first, with both expiries — and revoke all of it or only its
  inline permission from the listing. Before this, a Grant was visible only on
  the card that created it.

## Consequences

- An inline Grant is exactly as wide as its warning says: during its window any
  inline code, from that Client in that repository, may use those Items. The
  Sighting stream is the audit trail, and it no longer interrupts.
- A row created by an inline approval has no ordinary permission of its own, so
  "只撤内联权限" on it leaves nothing behind. That is the independence working
  as designed, not a loss.
- A `/grants` entry is "what this Approval currently holds": a later approval
  that tops up a row takes that row over, so entries are not a history.
- Existing databases gain the column at boot; every existing row reads as "no
  inline permission", so nothing is widened by the upgrade.

## Rejected alternatives

- **Session-scoped grants** — tie inline permission to one agent session rather
  than a period. Considered and dropped in favour of the existing TTL choices
  plus a separately revocable expiry.
- **A per-Item policy field** marking which Items may be used inline. Decided
  once, in advance, away from the code it would cover; the card is where the
  Owner has the context.
- **A repository allow-list in Broker configuration.** Same objection, plus it
  lives on the server, where the Owner does not look while approving.
- **Fixing the "once" trap** — a "this run only" approval landing after the CLI
  gave up its wait (ADR-0006) authorizes a run that no longer exists, and the
  re-run asks again. Kept as is: the period buttons are now the answer for code
  that will be re-run, and "once" keeps meaning exactly once.
