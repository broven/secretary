// HTTP surface: POST /v1/requests (long poll — the connection stays open until
// decision or timeout), GET /v1/catalog, GET /healthz. Bearer token → client
// identity via the ClientRegistry.

import type { ClientRegistry } from "./clients.ts";
import { RequestBroker, RequestError } from "./requests.ts";
import type { Vault } from "./vault.ts";

export type HttpDeps = {
  clients: ClientRegistry;
  broker: RequestBroker;
  vault: Vault;
  hostname: string;
  port: number;
  /** Effective approval timeout, advertised to clients so their HTTP deadline
   * can always exceed the server-side parking window. */
  approvalTimeoutMs?: number;
  log?: (message: string) => void;
};

export const APPROVAL_TIMEOUT_HEADER = "X-Secretary-Approval-Timeout";

const MAX_BODY_BYTES = 256 * 1024;
/** Long-poll heartbeat: harmless leading whitespace before the JSON body keeps
 * intermediaries from killing an idle-looking connection during a 300 s approval. */
const HEARTBEAT_INTERVAL_MS = 20_000;

function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Read the request body, throwing as soon as the byte count passes maxBytes. */
async function readBodyLimited(request: Request, maxBytes: number): Promise<string> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization") ?? "";
  const match = header.match(/^Bearer\s+(\S+)$/);
  return match ? match[1] : null;
}

/**
 * Stream whitespace heartbeats while `pending` is unsettled, then the JSON
 * result. JSON.parse tolerates leading whitespace, so clients just
 * text().trim() — but the connection never looks idle.
 */
function longPollResponse(
  pending: Promise<unknown>,
  log: (message: string) => void,
  extraHeaders: Record<string, string> = {},
): Response {
  const encoder = new TextEncoder();
  let timer: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      timer = setInterval(() => {
        try {
          controller.enqueue(encoder.encode("\n"));
        } catch {
          clearInterval(timer);
        }
      }, HEARTBEAT_INTERVAL_MS);
      pending
        .then((result) => {
          controller.enqueue(encoder.encode(JSON.stringify(result)));
        })
        .catch((error) => {
          // Status is already committed; deliver the error in-band. The client
          // treats a JSON body with `error` as failure (fail closed).
          const message = error instanceof RequestError
            ? error.message
            : (log(`request failed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`),
              "internal error");
          controller.enqueue(encoder.encode(JSON.stringify({ error: message })));
        })
        .finally(() => {
          clearInterval(timer);
          try {
            controller.close();
          } catch {
            // Already errored/cancelled.
          }
        });
    },
    cancel() {
      clearInterval(timer);
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

export function startHttpServer(deps: HttpDeps) {
  const log = deps.log ?? ((message: string) => console.log(message));
  const server = Bun.serve({
    hostname: deps.hostname,
    port: deps.port,
    idleTimeout: 120,
    fetch: async (request, srv) => {
      const url = new URL(request.url);

      if (url.pathname === "/healthz" && request.method === "GET") {
        return json(200, { ok: true });
      }

      const token = bearerToken(request);
      const client = token ? deps.clients.authenticate(token) : null;
      if (!client) return json(401, { error: "unauthorized" });

      if (url.pathname === "/v1/catalog" && request.method === "GET") {
        try {
          const items = await deps.vault.catalog(url.searchParams.get("query") ?? "");
          return json(200, { items });
        } catch (error) {
          log(`catalog failed: ${error instanceof Error ? error.message : String(error)}`);
          return json(500, { error: "catalog unavailable" });
        }
      }

      if (url.pathname === "/v1/requests" && request.method === "POST") {
        const lengthHeader = Number(request.headers.get("content-length") ?? 0);
        if (lengthHeader > MAX_BODY_BYTES) return json(413, { error: "body too large" });
        // Enforce the cap WHILE reading: a chunked body must not buffer past
        // the limit before being rejected.
        let text: string;
        try {
          text = await readBodyLimited(request, MAX_BODY_BYTES);
        } catch {
          return json(413, { error: "body too large" });
        }
        let body: unknown;
        try {
          body = JSON.parse(text);
        } catch {
          return json(400, { error: "invalid JSON body" });
        }
        let pending: Promise<unknown>;
        try {
          // Synchronous validation errors (parse, auth mismatch) become proper
          // HTTP statuses; only the parked wait streams.
          pending = deps.broker.handle(body, client);
        } catch (error) {
          if (error instanceof RequestError) return json(error.status, { error: error.message });
          log(`request rejected: ${error instanceof Error ? error.message : String(error)}`);
          return json(500, { error: "internal error" });
        }
        // Disable the per-connection idle timeout for the approval long poll.
        srv.timeout(request, 0);
        return longPollResponse(pending, log, deps.approvalTimeoutMs
          ? { [APPROVAL_TIMEOUT_HEADER]: String(Math.ceil(deps.approvalTimeoutMs / 1000)) }
          : {});
      }

      return json(404, { error: "not found" });
    },
  });
  log(`secretary broker listening on ${deps.hostname}:${server.port}`);
  return server;
}
