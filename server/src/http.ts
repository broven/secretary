// HTTP surface: POST /v1/requests and POST /v1/writes (long polls — the
// connection stays open until decision or timeout), GET /v1/catalog,
// GET /healthz. Bearer token → client identity via the ClientRegistry.
//
// One exception to the bearer gate: GET/POST /entry/<nonce>, the Entry Form.
// Its nonce IS the capability (CONTEXT.md "Entry Form", ADR-0004) — a browser
// has no token — so it is matched before authentication and answers with HTML.

import {
  ENTRY_HEADERS,
  ENTRY_PATH_PREFIX,
  renderEntryDone,
  renderEntryFailed,
  renderEntryGone,
  renderEntryPage,
} from "./entry.ts";
import type { ClientRegistry } from "./clients.ts";
import { RequestBroker, RequestError } from "./requests.ts";
import type { Vault } from "./vault.ts";
import { WriteBroker, WriteError } from "./writes.ts";

export type HttpDeps = {
  clients: ClientRegistry;
  broker: RequestBroker;
  writes: WriteBroker;
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
  // Once the client disconnects (cancel) or the stream closes, the controller
  // must never be touched again: enqueue() on a closed controller throws, and
  // outside a try it would take the whole process down with it. Every write
  // and close goes through these guards.
  let closed = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const safeEnqueue = (text: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(text));
        } catch {
          // Controller raced into a closed/errored state; stop writing.
          closed = true;
          clearInterval(timer);
        }
      };
      const safeClose = () => {
        clearInterval(timer);
        if (closed) return;
        closed = true;
        try {
          controller.close();
        } catch {
          // Already errored/cancelled.
        }
      };
      timer = setInterval(() => safeEnqueue("\n"), HEARTBEAT_INTERVAL_MS);
      // NOTE on disconnects: the parked approval is deliberately NOT cancelled
      // when the client goes away — the Owner may already be reading the card,
      // and their decision still applies to the Grant store exactly as if the
      // client had waited. Only the response delivery is dropped; the client
      // has already failed closed on its side (no envelope ever reached it).
      pending
        .then((result) => {
          safeEnqueue(JSON.stringify(result));
        })
        .catch((error) => {
          // Status is already committed; deliver the error in-band. The client
          // treats a JSON body with `error` as failure (fail closed).
          const message = error instanceof RequestError || error instanceof WriteError
            ? error.message
            : (log(`request failed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`),
              "internal error");
          safeEnqueue(JSON.stringify({ error: message }));
        })
        .finally(safeClose);
    },
    cancel() {
      // Client disconnected mid-poll.
      closed = true;
      clearInterval(timer);
      log("long-poll client disconnected before the decision; response dropped (request continues)");
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

type BodyOutcome = { value: unknown } | { error: string; status: number };

async function readJsonBody(request: Request): Promise<BodyOutcome> {
  const lengthHeader = Number(request.headers.get("content-length") ?? 0);
  if (lengthHeader > MAX_BODY_BYTES) return { error: "body too large", status: 413 };
  let text: string;
  try {
    text = await readBodyLimited(request, MAX_BODY_BYTES);
  } catch {
    return { error: "body too large", status: 413 };
  }
  try {
    return { value: JSON.parse(text) };
  } catch {
    return { error: "invalid JSON body", status: 400 };
  }
}

async function readEntryFormLimited(request: Request): Promise<FormData> {
  const lengthHeader = Number(request.headers.get("content-length") ?? 0);
  if (lengthHeader > MAX_BODY_BYTES) throw new Error("body too large");

  const text = await readBodyLimited(request, MAX_BODY_BYTES);
  const contentType = request.headers.get("content-type");
  const headers = contentType ? { "Content-Type": contentType } : undefined;
  return new Response(text, { headers }).formData();
}

function html(status: number, body: string): Response {
  return new Response(body, { status, headers: ENTRY_HEADERS });
}

/**
 * The Entry Form. Unknown, expired, and already-used nonces all get the same
 * page and the same status: telling them apart would confirm to a guesser that
 * a nonce once existed. The nonce itself is never logged.
 */
async function handleEntry(
  url: URL,
  request: Request,
  writes: WriteBroker,
  log: (message: string) => void,
): Promise<Response> {
  const nonce = decodeURIComponent(url.pathname.slice(ENTRY_PATH_PREFIX.length));
  if (request.method === "GET") {
    const draft = writes.entries.find(nonce);
    return draft ? html(200, renderEntryPage(draft)) : html(404, renderEntryGone());
  }
  if (request.method !== "POST") return html(405, renderEntryGone());

  const found = writes.entries.find(nonce);
  if (!found) return html(404, renderEntryGone());

  let form: FormData;
  try {
    form = await readEntryFormLimited(request);
  } catch {
    return html(400, renderEntryPage(found, "表单读取失败，请重试。"));
  }
  const values = new Map<string, string>();
  for (const field of found.owner_fields) {
    const raw = form.get(`f_${field}`);
    if (typeof raw !== "string" || raw.length === 0) {
      // Keep the draft alive: an empty box is a slip, not a spent capability.
      return html(400, renderEntryPage(found, `请填写 ${field}。`));
    }
    values.set(field, raw);
  }

  // Single use: consume before applying, so a double submit cannot write twice.
  const draft = writes.entries.take(nonce);
  if (!draft) return html(404, renderEntryGone());
  try {
    await writes.submitEntry(draft, values);
  } catch (error) {
    const message = error instanceof WriteError ? error.message : "写入失败，请检查服务端日志。";
    if (!(error instanceof WriteError)) {
      log(`entry submit failed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
    }
    return html(409, renderEntryFailed(message));
  }
  return html(200, renderEntryDone(draft.item));
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

      if (url.pathname.startsWith(ENTRY_PATH_PREFIX)) {
        return handleEntry(url, request, deps.writes, log);
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

      if (url.pathname === "/v1/writes" && request.method === "POST") {
        const body = await readJsonBody(request);
        if ("error" in body) return json(body.status, { error: body.error });
        let pending: Promise<unknown>;
        try {
          pending = deps.writes.handle(body.value, client);
        } catch (error) {
          if (error instanceof WriteError) return json(error.status, { error: error.message });
          log(`write rejected: ${error instanceof Error ? error.message : String(error)}`);
          return json(500, { error: "internal error" });
        }
        srv.timeout(request, 0);
        return longPollResponse(pending, log, deps.approvalTimeoutMs
          ? { [APPROVAL_TIMEOUT_HEADER]: String(Math.ceil(deps.approvalTimeoutMs / 1000)) }
          : {});
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
