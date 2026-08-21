# Broker image. Build context is the repo root (compose sets context: ..).
# The Bitwarden CLI ships x64-only; build/run this image as linux/amd64
# (the compose file pins `platform: linux/amd64`).

# --- Stage 1: fetch the pinned Bitwarden CLI and verify its checksum ---------
FROM debian:bookworm-slim AS bw

ARG BW_VERSION=2026.6.0
ARG BW_SHA256=392549496c712ab86bfbd6c27302df9fd2c431cfc7a47e26941ac3e3893f4d27

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/bw.zip \
        "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip" \
    && echo "${BW_SHA256}  /tmp/bw.zip" | sha256sum -c - \
    && unzip /tmp/bw.zip -d /tmp/bw \
    && install -m 755 /tmp/bw/bw /usr/local/bin/bw

# --- Stage 2: runtime --------------------------------------------------------
FROM oven/bun:1.3-slim

COPY --from=bw /usr/local/bin/bw /usr/local/bin/bw

WORKDIR /app
COPY server/ ./server/

# /data holds the SQLite Grant store; /tmp/secretary-bw is the bw CLI's
# app-data dir. Both must be writable by the non-root `bun` user (uid 1000).
RUN mkdir -p /data /tmp/secretary-bw \
    && chown bun:bun /data /tmp/secretary-bw

USER bun

ENV DB_PATH=/data/secretary.sqlite

EXPOSE 8787

CMD ["bun", "run", "server/src/main.ts"]
