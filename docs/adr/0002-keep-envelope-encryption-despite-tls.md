# Keep per-request envelope encryption even though CLI↔broker is direct TLS

With Windmill gone, secrets no longer pass through persisted job results, so plain
TLS would arguably suffice. We kept the ephemeral-key Envelope
(client-side P-256 keypair per Request; broker encrypts with ECDH + HKDF-SHA256 +
AES-256-GCM) anyway: real deployments put TLS-terminating middleboxes in front of
the broker (Cloudflare Tunnel, Traefik, reverse proxies), and the Envelope
guarantees none of them ever see plaintext. The code existed on both sides, so the
port cost was near zero; the predecessor's post-delivery job-result cleanup step
disappears because nothing is persisted to clean.
