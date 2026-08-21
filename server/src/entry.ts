// Entry Form: the one-time page where the Owner types Owner-supplied values
// (CONTEXT.md "Entry Form", ADR-0004).
//
// Security shape:
// - The link IS the capability. It is deliberately bound to no Approver
//   channel, so a second channel needs no second design — and to keep that
//   affordable, only Create may use it: the unapproved lane can add, never
//   overwrite or destroy.
// - Single use, short TTL, consumed on submit / expiry / rejection.
// - The nonce never appears in a log line, never in a page the browser could
//   leak through a Referer header, and never in an error that distinguishes
//   "wrong nonce" from "expired nonce".
// - The page is write-only: it never renders a value already in the vault.

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { SecretField } from "./vault.ts";

export const ENTRY_PATH_PREFIX = "/entry/";
const NONCE_BYTES = 32;

export function mintEntryNonce(): string {
  return randomBytes(NONCE_BYTES).toString("base64url");
}

export type EntryDraft<T> = {
  nonce: string;
  expires_at: number;
  item: string;
  description: string;
  /** Fields the Owner must fill, in display order. */
  owner_fields: SecretField[];
  /** Fields the agent already supplied — names only, shown so the Owner can
   * cross-check what the agent claims it is writing. */
  inline_fields: SecretField[];
  payload: T;
};

export type EntryStoreDeps = {
  now?: () => number;
  /** Called once when a draft expires unused, so the Owner still hears about it. */
  onExpire?: (draft: EntryDraft<unknown>) => void;
};

/**
 * In-memory, deliberately: a draft holds Agent-supplied plaintext until the
 * Owner completes it, and the broker persists no plaintext, ever. A restart
 * losing pending drafts is the correct failure — the agent's command already
 * returned, and the vault is untouched.
 */
export class EntryStore<T> {
  private readonly drafts = new Map<string, EntryDraft<T>>();
  private readonly now: () => number;
  private readonly onExpire?: (draft: EntryDraft<unknown>) => void;

  constructor(deps: EntryStoreDeps = {}) {
    this.now = deps.now ?? Date.now;
    this.onExpire = deps.onExpire;
  }

  put(draft: EntryDraft<T>): void {
    this.drafts.set(draft.nonce, draft);
  }

  /**
   * Resolve a nonce without leaking which of "unknown" or "expired" it was,
   * and compare in constant time so a timing side channel cannot walk the
   * value out byte by byte.
   */
  find(nonce: string): EntryDraft<T> | null {
    this.sweep();
    if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > 200) return null;
    const candidate = Buffer.from(nonce);
    for (const draft of this.drafts.values()) {
      const known = Buffer.from(draft.nonce);
      if (known.length !== candidate.length) continue;
      if (timingSafeEqual(known, candidate)) return draft;
    }
    return null;
  }

  /** Resolve and consume in one step: a draft may be submitted exactly once. */
  take(nonce: string): EntryDraft<T> | null {
    const draft = this.find(nonce);
    if (!draft) return null;
    this.drafts.delete(draft.nonce);
    return draft;
  }

  drop(nonce: string): void {
    this.drafts.delete(nonce);
  }

  sweep(): void {
    const now = this.now();
    for (const [nonce, draft] of this.drafts) {
      if (draft.expires_at > now) continue;
      this.drafts.delete(nonce);
      this.onExpire?.(draft as EntryDraft<unknown>);
    }
  }

  get size(): number {
    return this.drafts.size;
  }
}

// ---------------------------------------------------------------------------
// Page rendering
// ---------------------------------------------------------------------------

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLE = `
:root { color-scheme: light dark; }
body { margin:0; padding:2rem 1rem; font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:#f6f6f7; color:#1b1b1f; display:flex; justify-content:center; }
@media (prefers-color-scheme: dark) { body { background:#16161a; color:#ececf1; } }
main { width:100%; max-width:34rem; }
.card { background:#fff; border-radius:14px; padding:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,.12); }
@media (prefers-color-scheme: dark) { .card { background:#23232a; box-shadow:none; } }
h1 { font-size:1.15rem; margin:0 0 .25rem; }
.sub { margin:0 0 1.25rem; opacity:.7; font-size:.9rem; }
dl { margin:0 0 1.25rem; display:grid; grid-template-columns:auto 1fr; gap:.35rem .75rem; font-size:.9rem; }
dt { opacity:.6; } dd { margin:0; word-break:break-word; }
label { display:block; margin:0 0 1rem; font-size:.9rem; }
label span { display:block; margin-bottom:.3rem; font-weight:600; }
input[type=password] { width:100%; box-sizing:border-box; padding:.6rem .7rem; font-size:1rem;
  border:1px solid #c9c9cf; border-radius:8px; background:inherit; color:inherit; }
button { width:100%; padding:.7rem; font-size:1rem; font-weight:600; border:0; border-radius:8px;
  background:#2f6feb; color:#fff; cursor:pointer; }
.note { margin-top:1rem; font-size:.82rem; opacity:.65; }
.bad { color:#b3261e; } .good { color:#1a7f37; }
`.trim();

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head><body><main><div class="card">${body}</div></main></body></html>`;
}

export function renderEntryPage(draft: EntryDraft<unknown>, error?: string): string {
  const inputs = draft.owner_fields.map((field) => `
    <label><span>${escapeHtml(field)}</span>
      <input type="password" name="f_${escapeHtml(field)}" autocomplete="new-password"
             autocapitalize="off" autocorrect="off" spellcheck="false" required></label>`).join("");
  const supplied = draft.inline_fields.length
    ? `<dt>agent 已填</dt><dd>${escapeHtml(draft.inline_fields.join("、"))}</dd>`
    : "";
  return page("填写凭据 · secretary", `
    <h1>填写凭据</h1>
    <p class="sub">这些值只会写进你的 vault，不会返回给发起请求的 agent。</p>
    ${error ? `<p class="bad">${escapeHtml(error)}</p>` : ""}
    <dl>
      <dt>条目</dt><dd>${escapeHtml(draft.item)}</dd>
      ${draft.description ? `<dt>描述</dt><dd>${escapeHtml(draft.description)}</dd>` : ""}
      ${supplied}
    </dl>
    <form method="post" autocomplete="off">
      ${inputs}
      <button type="submit">写入 vault</button>
    </form>
    <p class="note">这个链接一次性有效，提交或过期后即失效。</p>`);
}

export function renderEntryDone(item: string): string {
  return page("已写入 · secretary", `
    <h1 class="good">已写入</h1>
    <p class="sub">条目 <strong>${escapeHtml(item)}</strong> 已保存到 vault，可以回去告诉 agent 继续了。</p>
    <p class="note">这个链接已失效。</p>`);
}

export function renderEntryGone(): string {
  // Deliberately one message for unknown / expired / already-used: telling
  // them apart would confirm to a guesser that a nonce once existed.
  return page("链接无效 · secretary", `
    <h1 class="bad">链接无效</h1>
    <p class="sub">这个录入链接不存在、已过期，或者已经用过了。</p>
    <p class="note">请让 agent 重新发起一次请求。</p>`);
}

export function renderEntryFailed(message: string): string {
  return page("写入失败 · secretary", `
    <h1 class="bad">写入失败</h1>
    <p class="sub">${escapeHtml(message)}</p>
    <p class="note">这个链接已失效，请让 agent 重新发起一次请求。</p>`);
}

/** Headers every Entry response carries: no caching, no referrer, no scripts. */
export const ENTRY_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};
