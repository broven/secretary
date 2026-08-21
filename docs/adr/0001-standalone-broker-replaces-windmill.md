# Standalone resident broker instead of Windmill orchestration

The predecessor ran the approval pipeline as Windmill scripts (catalog / request /
job_control jobs with suspend-resume approval and a Postgres DataTable). It
worked, but a single exec cost ≥3 orchestrated jobs, up to three full
`bw login+unlock+sync` cycles, and 1.25 s client polling granularity — 10–30 s
even when instantly approved — and nobody else could deploy it without adopting
Windmill. We decided to remove Windmill from the secret path entirely and rebuild
the server side as one resident Bun/TypeScript broker (SQLite for Grants, in-memory
request parking, one long-polled HTTP round trip per Request), shipped as a docker
compose next to vaultwarden.

## Consequences

- We re-own what Windmill gave for free: durable approval suspend/resume becomes
  in-memory parking (a broker restart drops in-flight approvals — acceptable, the
  CLI fails closed and retries), and the DataTable becomes SQLite.
- The existing `f/secretapprove/` scripts are the reference implementation to port
  from, then retire.
