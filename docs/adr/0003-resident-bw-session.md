# Resident unlocked `bw` session in the broker

The predecessor opened a fresh Bitwarden CLI session per job (login → unlock →
sync → logout in a temp dir) — the main latency cost, paid up to three times per
exec. The broker instead logs in and unlocks once at startup, keeps `BW_SESSION`
in memory for its lifetime, syncs on demand, and bakes the pinned `bw` binary into
the image (the old path re-downloaded an 80 MB CLI on every cold worker).

Accepted trade-off: broker memory holds a live vault-unlock capability instead of
being locked between requests. The attack surface barely changes — the broker
already holds the master password to perform unattended unlocks — but a memory
compromise now yields an open session directly. We chose `bw` CLI over
reimplementing the Bitwarden crypto protocol (fragile, high-risk) and over the
Secrets Manager SDK (different product, poor Vaultwarden fit); `bw config server`
also gives official-Bitwarden and Vaultwarden support for free.
