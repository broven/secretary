# How-to-get is recorded on best effort and is never required

A Description tells a future agent *what* an Item is. It does not tell anyone
*how to obtain another copy* — which is what an Owner actually needs when a
credential has to be regenerated, and what an Owner needs in front of them while
filling an Entry Form for a credential they have not created yet. We add
**How-to-get**: one Item-level plain-text note saying where this credential comes
from and what steps produce a fresh one.

We deliberately did **not** make it required, against the first instinct that
something this useful should be enforced. Five observations of agents asked to
store a credential (four subagents and one fresh Claude Code session, all
driving the shipped skill) showed that the ones which stopped and handed the
work back to the human all stopped on the same thing: a required field they
could not fill honestly. Description is required, the test prompt supplied a
token value but not its scope, and the agents refused to invent one — correctly,
since a token's scope is not derivable from the token. A second required field
that an agent frequently cannot know would manufacture more of exactly that
stopping behaviour, in the name of a field whose whole purpose is to make the
Owner's life easier.

An empty How-to-get is honest. An invented one — "get it from the official site"
— is worse than empty, because it reads as knowledge and nobody will think to
replace it. So the rule is: fill it when you know (in ordinary context the agent
does know: it is proposing the credential and usually named the console page it
comes from), leave it out when you do not, never guess.

Enforcement is the Approval card, not a validator. The text is rendered in full
on the write card, so hand-waving is something the Owner sees and rejects before
it enters the vault. We considered requiring the text to contain an `http(s)`
URL and rejected it: plenty of credentials are not obtained through a web page.

Shape, and why each part is not obvious:

- **Item-level, not per-Field.** Per-Field would be more precise for an Item
  holding credentials with different origins, at the cost of a field per
  credential and a prefix-matching reserved-name rule.
- **A plain-text custom field (`type: 0`), not hidden (`type: 1`).** The write
  path currently hardcodes hidden; this is not a secret and must be readable in
  an ordinary vault client.
- **Excluded from the catalog's field list, and reserved against binding.** It
  travels in the same array as real credentials, so without this an agent could
  `exec --item X how_to_get=SOMETHING` and inject it as though it were one.
- **Sent to Telegram as plain text, never MarkdownV2.** This text is
  agent-authored; a single unescaped `_` or `[` makes `sendMessage` return 400
  and the card is never delivered, which would turn a legibility feature into
  precisely the silent "the Owner was never actually asked" failure ADR-0006
  exists to remove.
- **No markdown library on the Entry Form.** It is agent-authored text rendered
  on the page that collects a secret. Reject `<`, `javascript:` and `data:` at
  write time; render with HTML escaping, newline preservation, and bare-URL
  autolinking only.
- **500 characters.** Enough for a console path and a caveat; short enough to sit
  on a card.

## Consequences

- Existing Items have no How-to-get and are not backfilled. Absence means "not
  recorded", never "cannot be obtained".
- Update may change it — acquisition paths rot as consoles are redesigned.
  Remove may not delete it: an Item with a stale note is better than one with
  none.
- Description stays required. An Item nobody can identify is worse than one
  nobody can re-obtain, and unlike How-to-get its answer is almost always
  available to whoever is creating the Item.
- An agent that genuinely knows neither still stops and asks. That is correct
  behaviour and not a defect to design away; the fix for a stopped agent is
  context, not a laxer contract.
- `ENTRY_TTL_S` rises from 600 s to 1800 s. The Owner now routinely opens the
  Entry Form, follows the How-to-get to a console, generates the credential, and
  comes back — ten minutes was budgeted for typing a value that already existed.

Not yet implemented at the time of writing; ARCHITECTURE.md and CONTEXT.md are
updated when the code lands.
