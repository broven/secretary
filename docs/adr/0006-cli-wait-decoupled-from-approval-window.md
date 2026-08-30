# The CLI's wait is bounded by the agent harness, not by the approval window

The CLI blocks on one long-polled round trip until the Owner decides, which
assumed the caller is willing to wait as long as the Broker is. Agent harnesses
are not: Claude Code's shell tool defaults to a **120 s** timeout and caps at
**600 s**, so against the 300 s approval window an agent that does not pass an
explicit timeout has `approved-secret exec` **killed at two minutes** — and the
line the CLI printed on submission dies with the process. What the agent reports
is "the command timed out", which is indistinguishable from a broker outage, a
dead tunnel, or a rejected request. The one thing the design most needs to be
legible — *your Owner has been asked and has not answered yet* — is the thing
that gets lost. No amount of wording fixes it, because the process never lives
long enough to print the wording.

We therefore **decouple how long the CLI waits from how long the Request stays
open**. The CLI waits ~100 s — comfortably under any harness default — and then
exits gracefully, naming the `request_id` and saying that the card was pushed,
that nothing was granted yet, and that re-running the same command after
approval is the way forward. The Broker keeps the Request parked regardless of
whether that connection is still there, for a full window of five cards over
about 25 minutes. Because approving creates the Grant, the agent's re-run is an
ordinary fast-path request and lands in under a second.

Re-notifying means **deleting the previous card and sending a new one**, not
editing it: `editMessageText` produces no push notification, so an edited card
is a card the Owner never learns about. The fifth and final card is edited in
place into a "gave up" state instead of being deleted, so the chat still shows
that something was asked and missed. Any card's button resolves the Request —
only the `request_id` is matched — so tapping a card that was deleted a moment
earlier still works.

The agent side is one rule: on "not yet approved", re-run the same command after
60 s, at most three times, saying which attempt it is on, then stop and ask.
An agent never submits a *second* approval Request; re-pushing cards is the
Broker's job, and a re-run against an existing Grant is not a new ask.

## Consequences

- The agent learns it is waiting on the Owner within ~100 s, using nothing but
  the process's exit — no streamed output, no harness-specific timeout handling,
  no polling of broker internals. This is the legibility the CLI could not
  deliver before, and it arrives as a side effect of giving up on waiting.
- Approval no longer implies the command ran. The Owner may tap a card whose
  caller left minutes ago; for reads that is harmless, because the Grant is the
  durable artifact, but the Owner cannot read a tap as "it worked".
- The write path gets no equivalent. An approved write applies server-side and
  there is nothing for a re-run to hit, so writes keep a short window, an
  explicit "not yet approved, the vault is unchanged" message, and `list` as the
  way to confirm afterwards.
- A Broker restart still drops parked Requests (ADR-0001) — now up to 25 minutes
  of them rather than five. The CLI still fails closed and the Owner's stale
  cards resolve to nothing.
- Deleting superseded cards means the Telegram history is no longer a complete
  record of what was asked; the surviving final card and the Broker's log are.
- The client-side "could not read the response" failure must stop calling itself
  a timeout. It means the opposite of the Broker's approval timeout — the
  Request may well have been approved — and the two messages currently read
  almost identically.
