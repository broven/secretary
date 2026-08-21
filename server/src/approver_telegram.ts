// TelegramApprover: delivers approval cards and Sighting notifications to a
// Telegram chat and turns inline-keyboard callbacks into ApprovalDecisions.
//
// Rendering, escaping, field limits, and the callback_data format are ported
// from the Windmill references (f/approval/approval_telegram.ts and
// f/secretapprove/request.ts). The user-facing card copy stays Chinese as
// ported; code and comments are English.
//
// Security notes:
// - The bot token is never logged; errors are reported by method name + HTTP
//   status + Telegram's description only.
// - Cards never contain secret values by construction (see approver.ts), so
//   logging card ids is safe.

import type {
  ApprovalCard,
  ApprovalDecision,
  Approver,
  SightingCard,
} from "./approver.ts";
import { isSecretGrantTtl, type ApprovalTtl } from "./types.ts";

// ---------------------------------------------------------------------------
// Rendering (ported from approval_telegram.ts)
// ---------------------------------------------------------------------------

/** Max fields rendered in one Telegram message (Sighting notifications only —
 * approval cards render completely or fail closed, see buildApprovalMessages). */
export const MAX_TELEGRAM_FIELDS = 6;
/** Character budget for a plain field value. */
export const FIELD_VALUE_LIMIT = 320;
/** Free-form item notes get their own smaller budget so they can never crowd
 * the decision-critical field mapping out of the 320-char field value. */
export const ITEM_DESCRIPTION_LIMIT = 120;
/**
 * Character budget for a block (code) field. Must be wide enough to hold the
 * caller's already-truncated command display including its fingerprint suffix,
 * otherwise the very credential the Owner is supposed to verify gets cut again.
 */
export const BLOCK_VALUE_LIMIT = 1200;

function limit(value: unknown, max: number): string {
  const text = String(value ?? "").trim();
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
}

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

type CardField = { label: string; value: string; block?: boolean; monospace?: boolean };

function renderCardText(subject: string, summary: string, fields: CardField[], footer: string): string {
  const lines = [
    `🔔 <b>${escapeHtml(limit(subject, 180))}</b>`,
    ...(summary ? [escapeHtml(limit(summary, 400))] : []),
    "",
  ];

  // Field order is priority order: only the first MAX_TELEGRAM_FIELDS render,
  // and anything cut must be announced explicitly.
  const renderable = fields
    .filter((field) => limit(field.value, field.block ? BLOCK_VALUE_LIMIT : FIELD_VALUE_LIMIT));
  for (const field of renderable.slice(0, MAX_TELEGRAM_FIELDS)) {
    const label = `<b>${escapeHtml(limit(field.label || "字段", 80))}</b>`;
    if (field.block) {
      // <pre> cannot nest inside other formatting tags, so it gets its own
      // line. Telegram adds a copy button to it.
      lines.push(`${label}:`);
      lines.push(`<pre><code class="language-bash">${escapeHtml(limit(field.value, BLOCK_VALUE_LIMIT))}</code></pre>`);
      continue;
    }
    const value = limit(field.value, FIELD_VALUE_LIMIT);
    const renderedValue = field.monospace === false
      ? escapeHtml(value)
      : `<code>${escapeHtml(value)}</code>`;
    lines.push(`${label}: ${renderedValue}`);
  }
  if (renderable.length > MAX_TELEGRAM_FIELDS) {
    lines.push(`<i>另有 ${renderable.length - MAX_TELEGRAM_FIELDS} 项未显示。</i>`);
  }
  lines.push("", footer);

  const text = lines.join("\n");
  if (text.length <= 4000) return text;
  return [
    `🔔 <b>${escapeHtml(limit(subject, 180))}</b>`,
    ...(summary ? [escapeHtml(limit(summary, 500))] : []),
    "",
    "<i>上下文较长，详情已省略；请谨慎核对后再点击下方按钮。</i>",
  ].join("\n");
}

/** Raw-HTML budget per message, conservatively under Telegram's 4096 cap. */
export const TELEGRAM_MESSAGE_LIMIT = 3900;
/** An approval card may span at most this many messages before failing closed. */
export const MAX_APPROVAL_MESSAGES = 4;

/**
 * Render the approval card COMPLETELY: every item, every field → env mapping,
 * and the full (pre-bounded) command display must appear — split across up to
 * MAX_APPROVAL_MESSAGES messages when needed (the keyboard goes on the last
 * one). Only the free-form pieces (reason, item notes, provenance) are ever
 * truncated. If a complete rendering is impossible, throw — the broker then
 * rejects the request instead of asking the Owner to approve a card that
 * hides part of what it grants.
 */
export function buildApprovalMessages(card: ApprovalCard): string[] {
  const header = [
    `🔔 <b>${escapeHtml(limit(`密钥使用审批：${card.items.length} 个 Bitwarden 条目 @ ${card.repo || "?"}`, 180))}</b>`,
    ...(card.reason ? [escapeHtml(limit(card.reason, 400))] : []),
  ].join("\n");
  const footer = `<i>审批截止：${escapeHtml(card.expires_at)} · 请直接点击下方按钮提交审批决定。</i>`;

  const blocks: string[] = [];
  if (card.command) {
    // The command display is already bounded upstream (formatCommandDisplay
    // truncates at 900 chars + fingerprint); it is never truncated here.
    blocks.push(`<b>命令</b>:\n<pre><code class="language-bash">${escapeHtml(card.command)}</code></pre>`);
  }
  if (card.inline_shell) {
    blocks.push(`<b>注意</b>: ${escapeHtml("内联 shell 代码：只放行本次执行，不会写入免审授权。")}`);
  }
  card.items.forEach((item, index) => {
    // Decision-critical: the mapping renders in full, never limited.
    const mapping = `字段映射：${item.bindings.map((binding) => `${binding.field} → ${binding.env}`).join("，")}`;
    blocks.push([
      `<b>${escapeHtml(limit(`密钥 ${index + 1} · ${item.name}`, 260))}</b>:`,
      escapeHtml(mapping),
      escapeHtml(limit(item.description || "（未填写 notes 描述）", ITEM_DESCRIPTION_LIMIT)),
    ].join("\n"));
  });
  const provenance = [
    `<b>仓库</b>: <code>${escapeHtml(limit(card.repo, FIELD_VALUE_LIMIT))}</code>`,
    `<b>来源</b>: <code>${escapeHtml(limit([card.host, card.user, card.agent].filter(Boolean).join(" · "), FIELD_VALUE_LIMIT))}</code>`,
    ...(card.client_name ? [`<b>客户端</b>: <code>${escapeHtml(limit(card.client_name, FIELD_VALUE_LIMIT))}</code>`] : []),
  ].join("\n");
  blocks.push(provenance);

  const messages: string[] = [];
  let current = header;
  const flush = () => {
    messages.push(current);
    current = `🔔 <b>${escapeHtml(limit(`密钥使用审批（续 ${messages.length + 1}）`, 180))}</b>`;
  };
  for (const block of blocks) {
    if (block.length > TELEGRAM_MESSAGE_LIMIT) {
      throw new Error("approval card cannot be rendered completely; rejecting the request");
    }
    if (current.length + 2 + block.length > TELEGRAM_MESSAGE_LIMIT) flush();
    current += `\n\n${block}`;
  }
  if (current.length + 2 + footer.length > TELEGRAM_MESSAGE_LIMIT) flush();
  current += `\n\n${footer}`;
  messages.push(current);
  if (messages.length > MAX_APPROVAL_MESSAGES) {
    throw new Error("approval card cannot be rendered completely; rejecting the request");
  }
  return messages;
}

export function buildSightingText(card: SightingCard): string {
  // Ported from buildReuseContext: the whole point of this notification is
  // "what ran, with which keys, until when".
  const fields: CardField[] = [
    ...(card.command ? [{ label: "命令", value: card.command, block: true }] : []),
    ...card.items.map((item, index) => ({
      label: `密钥 ${index + 1} · ${item.name}`,
      value: `字段映射：${item.bindings.map((binding) => `${binding.field} → ${binding.env}`).join("，")}`,
      monospace: false,
    })),
    { label: "授权到期", value: card.expires_at },
    { label: "仓库", value: card.repo },
    { label: "来源", value: [card.host, card.user, card.agent].filter(Boolean).join(" · ") },
    ...(card.client_name ? [{ label: "客户端", value: card.client_name }] : []),
  ].filter((field) => field.value);
  return renderCardText(
    `密钥免审复用：${card.items.length} 个条目 @ ${card.repo || "?"}`,
    `这条命令第一次用到这套密钥（已按既有授权放行）。理由：${card.reason}`,
    fields,
    "<i>删除本次用到的授权行；该仓库其它授权不受影响。</i>",
  );
}

// ---------------------------------------------------------------------------
// Keyboards
// ---------------------------------------------------------------------------

export type TelegramInlineKeyboard = {
  inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
};

type ApprovalActionKey = "approve_1h" | "approve_8h" | "approve_7d" | "approve_once" | "deny";
type ApprovalAction = { key: ApprovalActionKey; label: string; style: "primary" | "neutral" | "danger" };

const DENY_ACTION: ApprovalAction = { key: "deny", label: "拒绝", style: "danger" };

/** Inline shell only gets "this run" — no TTL button that would never write a grant. */
function approvalActions(inlineShell: boolean): ApprovalAction[] {
  if (inlineShell) {
    return [{ key: "approve_once", label: "批准本次执行", style: "primary" }, DENY_ACTION];
  }
  return [
    { key: "approve_1h", label: "批准 1 小时", style: "primary" },
    { key: "approve_8h", label: "批准 8 小时", style: "neutral" },
    { key: "approve_7d", label: "批准 7 天", style: "neutral" },
    DENY_ACTION,
  ];
}

function actionEmoji(style: string): string {
  if (style === "danger") return "❌";
  if (style === "primary") return "✅";
  return "▶️";
}

function callbackData(value: string): string {
  if (new TextEncoder().encode(value).length > 64) {
    throw new Error(`Telegram callback_data exceeds 64 bytes: ${value.slice(0, 16)}…`);
  }
  return value;
}

function buttonRows(
  buttons: Array<{ text: string; callback_data: string }>,
): TelegramInlineKeyboard {
  const rows: TelegramInlineKeyboard["inline_keyboard"] = [];
  for (let index = 0; index < buttons.length; index += 2) {
    rows.push(buttons.slice(index, index + 2));
  }
  return { inline_keyboard: rows };
}

export function buildApprovalKeyboard(card: ApprovalCard): TelegramInlineKeyboard {
  return buttonRows(approvalActions(card.inline_shell).map((action) => ({
    text: `${actionEmoji(action.style)} ${limit(action.label, 48)}`,
    callback_data: callbackData(`ap:${card.id}:${action.key}`),
  })));
}

export function buildSightingKeyboard(card: SightingCard): TelegramInlineKeyboard {
  return buttonRows([{
    text: `${actionEmoji("danger")} ${limit("立即吊销这套授权", 48)}`,
    callback_data: callbackData(`rv:${card.id}`),
  }]);
}

// ---------------------------------------------------------------------------
// Approver
// ---------------------------------------------------------------------------

const POLL_TIMEOUT_S = 25;
const RETRY_BACKOFF_MS = 1500;

type TelegramCallbackQuery = {
  id?: unknown;
  from?: { id?: unknown } | null;
  message?: { message_id?: unknown; chat?: { id?: unknown } | null } | null;
  data?: unknown;
};

type TelegramUpdate = { update_id?: unknown; callback_query?: TelegramCallbackQuery | null };

type PendingApproval = {
  resolve: (decision: ApprovalDecision) => void;
  timer: ReturnType<typeof setTimeout>;
  inlineShell: boolean;
};

export type TelegramApproverConfig = {
  botToken: string;
  chatId: string;
  allowedUserIds: number[];
  apiBase?: string;
};

export type TelegramApproverHooks = {
  /**
   * Revoke the grants behind a Sighting card by its id, resolved through a
   * DURABLE store (SQLite) so the button keeps working across broker
   * restarts. Returns the number of rows removed, or null when the id cannot
   * be resolved (unknown/expired handle).
   */
  onRevoke: (sightingId: string) => Promise<number | null> | number | null;
};

export type TelegramApproverDeps = {
  fetchImpl?: typeof fetch;
  log?: (msg: string) => void;
  now?: () => number;
};

export class TelegramApprover implements Approver {
  private readonly botToken: string;
  private readonly chatId: string;
  private readonly allowedUserIds: number[];
  private readonly apiBase: string;
  private readonly hooks: TelegramApproverHooks;
  private readonly fetchImpl: typeof fetch;
  private readonly log: (msg: string) => void;
  private readonly now: () => number;

  private readonly pending = new Map<string, PendingApproval>();
  private abortController: AbortController | null = null;
  private offset = 0;

  constructor(
    config: TelegramApproverConfig,
    hooks: TelegramApproverHooks,
    deps: TelegramApproverDeps = {},
  ) {
    if (!config.botToken) throw new Error("TelegramApprover: botToken is required");
    if (!config.chatId) throw new Error("TelegramApprover: chatId is required");
    if (!config.allowedUserIds.length) throw new Error("TelegramApprover: allowedUserIds is empty");
    this.botToken = config.botToken;
    this.chatId = config.chatId;
    this.allowedUserIds = [...config.allowedUserIds];
    this.apiBase = (config.apiBase ?? "https://api.telegram.org").replace(/\/+$/, "");
    this.hooks = hooks;
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.log = deps.log ?? ((msg) => console.log(msg));
    this.now = deps.now ?? Date.now;
  }

  start(): void {
    if (this.abortController) return;
    const controller = new AbortController();
    this.abortController = controller;
    void this.pollLoop(controller);
  }

  stop(): void {
    const controller = this.abortController;
    this.abortController = null;
    controller?.abort();
    // Fail closed: any still-parked approval resolves as timeout so callers
    // never hang and timers never keep the process alive.
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.resolve({ approved: false, reason: "timeout" });
      this.pending.delete(id);
    }
  }

  async requestApproval(card: ApprovalCard, timeoutMs: number): Promise<ApprovalDecision> {
    // Park the request and arm the deadline BEFORE sending: a stalled
    // sendMessage must never extend the approval window, and the send itself
    // is bounded so it cannot park the request forever.
    let entry: PendingApproval;
    const decision = new Promise<ApprovalDecision>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(card.id);
        resolve({ approved: false, reason: "timeout" });
      }, timeoutMs);
      entry = { resolve, timer, inlineShell: card.inline_shell };
      this.pending.set(card.id, entry);
    });
    try {
      // The card renders completely (every item, every mapping, the command)
      // across one or more messages, or buildApprovalMessages throws and the
      // request is rejected. The keyboard rides on the LAST message so the
      // Owner has scrolled past everything the buttons would grant.
      const texts = buildApprovalMessages(card);
      for (let index = 0; index < texts.length; index++) {
        await this.api("sendMessage", {
          chat_id: this.chatId,
          text: texts[index],
          parse_mode: "HTML",
          disable_web_page_preview: true,
          ...(index === texts.length - 1 ? { reply_markup: buildApprovalKeyboard(card) } : {}),
        }, AbortSignal.timeout(Math.min(timeoutMs, 30_000)));
      }
    } catch (error) {
      // Rendering and sendMessage failures propagate: the caller treats an
      // undeliverable/incomplete card as a failed request (fail closed), not a
      // silent deny — unless a decision somehow already landed.
      if (this.pending.get(card.id) === entry!) {
        clearTimeout(entry!.timer);
        this.pending.delete(card.id);
        throw error;
      }
    }
    return decision;
  }

  async notifySighting(card: SightingCard): Promise<void> {
    try {
      // The revoke button carries only the card id; the id → grant-keys
      // mapping lives in the durable store behind hooks.onRevoke, so the
      // button survives broker restarts.
      await this.api("sendMessage", {
        chat_id: this.chatId,
        text: buildSightingText(card),
        parse_mode: "HTML",
        disable_web_page_preview: true,
        reply_markup: buildSightingKeyboard(card),
      });
    } catch (error) {
      // Best-effort by contract: a Sighting never blocks an execution.
      this.log(`telegram sighting notification failed: ${errorMessage(error)}`);
    }
  }

  // -- long poll ------------------------------------------------------------

  private async pollLoop(controller: AbortController): Promise<void> {
    while (!controller.signal.aborted) {
      try {
        const updates = await this.api<TelegramUpdate[]>("getUpdates", {
          timeout: POLL_TIMEOUT_S,
          offset: this.offset,
          allowed_updates: ["callback_query", "message"],
        }, controller.signal);
        for (const update of updates ?? []) {
          if (typeof update.update_id === "number") this.offset = update.update_id + 1;
          if (update.callback_query) await this.handleCallback(update.callback_query);
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        this.log(`telegram getUpdates failed (retrying): ${errorMessage(error)}`);
        await sleep(RETRY_BACKOFF_MS, controller.signal);
      }
    }
  }

  private async handleCallback(callback: TelegramCallbackQuery): Promise<void> {
    const data = typeof callback.data === "string" ? callback.data : "";
    const callbackId = typeof callback.id === "string" || typeof callback.id === "number"
      ? String(callback.id)
      : "";
    const fromId = typeof callback.from?.id === "number" ? callback.from.id : NaN;

    if (data.startsWith("ap:")) {
      await this.handleApprovalCallback(data, callbackId, fromId, callback);
    } else if (data.startsWith("rv:")) {
      await this.handleRevokeCallback(data.slice(3), callbackId, fromId, callback);
    }
    // Anything else (plain messages, unknown callbacks) is ignored.
  }

  private async handleApprovalCallback(
    data: string,
    callbackId: string,
    fromId: number,
    callback: TelegramCallbackQuery,
  ): Promise<void> {
    const parts = data.split(":");
    if (parts.length !== 3) return;
    const [, cardId, actionKey] = parts;
    const entry = this.pending.get(cardId);
    if (!entry) {
      // First-decision-wins: settled/unknown cards get a passive ack only.
      await this.answerCallback(callbackId, "已处理");
      return;
    }
    if (!this.allowedUserIds.includes(fromId)) {
      await this.answerCallback(callbackId, "无权审批");
      return;
    }
    const decision = decisionForAction(actionKey, entry.inlineShell, fromId, this.now());
    if (!decision) {
      await this.answerCallback(callbackId, "未知操作");
      return;
    }
    clearTimeout(entry.timer);
    this.pending.delete(cardId);
    entry.resolve(decision);
    await this.answerCallback(callbackId, decision.approved ? "已批准" : "已拒绝");
    await this.removeKeyboard(callback);
  }

  private async handleRevokeCallback(
    cardId: string,
    callbackId: string,
    fromId: number,
    callback: TelegramCallbackQuery,
  ): Promise<void> {
    if (!this.allowedUserIds.includes(fromId)) {
      await this.answerCallback(callbackId, "无权审批");
      return;
    }
    let removed: number | null = null;
    try {
      removed = await this.hooks.onRevoke(cardId);
    } catch (error) {
      this.log(`telegram revoke hook failed: ${errorMessage(error)}`);
      await this.answerCallback(callbackId, "吊销失败，请检查服务端日志");
      return;
    }
    if (removed === null) {
      // Honest answer: the handle cannot be resolved (e.g. pre-dates the
      // durable store or was swept) — never claim the grants are gone.
      await this.answerCallback(callbackId, "无法识别该通知，未吊销任何授权；请手动检查");
      return;
    }
    await this.answerCallback(callbackId, `已吊销 ${removed} 行`);
    await this.removeKeyboard(callback);
  }

  // -- Telegram API helpers -------------------------------------------------

  private async api<T = unknown>(method: string, body: unknown, signal?: AbortSignal): Promise<T> {
    // The URL contains the bot token — it must never appear in errors or logs.
    const response = await this.fetchImpl(`${this.apiBase}/bot${this.botToken}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    const payload = await response.json().catch(() => ({})) as {
      ok?: boolean;
      description?: string;
      result?: T;
    };
    if (!response.ok || !payload.ok) {
      throw new Error(
        `Telegram ${method} failed: HTTP ${response.status} ${limit(payload.description || "unknown", 200)}`,
      );
    }
    return payload.result as T;
  }

  /** Best-effort ack shown as a toast to the button presser. */
  private async answerCallback(callbackId: string, text: string): Promise<void> {
    if (!callbackId) return;
    try {
      await this.api("answerCallbackQuery", { callback_query_id: callbackId, text });
    } catch (error) {
      this.log(`telegram answerCallbackQuery failed: ${errorMessage(error)}`);
    }
  }

  /** Best-effort: strip the keyboard after a decision so buttons cannot be re-pressed. */
  private async removeKeyboard(callback: TelegramCallbackQuery): Promise<void> {
    const messageId = callback.message?.message_id;
    const chatId = callback.message?.chat?.id;
    if (messageId === undefined || messageId === null || chatId === undefined || chatId === null) return;
    try {
      await this.api("editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: messageId,
        reply_markup: { inline_keyboard: [] },
      });
    } catch (error) {
      this.log(`telegram editMessageReplyMarkup failed: ${errorMessage(error)}`);
    }
  }

}

function decisionForAction(
  actionKey: string,
  inlineShell: boolean,
  fromId: number,
  nowMs: number,
): ApprovalDecision | null {
  if (actionKey === "deny") return { approved: false, reason: "denied" };
  const decidedAt = new Date(nowMs).toISOString();
  const approve = (ttl: ApprovalTtl): ApprovalDecision => ({
    approved: true,
    ttl,
    decided_by: String(fromId),
    decided_at: decidedAt,
  });
  // Inline-shell cards only ever offered approve_once; a forged TTL callback
  // must not mint a grant (and vice versa).
  if (inlineShell) return actionKey === "approve_once" ? approve("once") : null;
  if (actionKey.startsWith("approve_")) {
    const ttl = actionKey.slice("approve_".length);
    if (isSecretGrantTtl(ttl)) return approve(ttl);
  }
  return null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(() => resolve(), ms);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}
