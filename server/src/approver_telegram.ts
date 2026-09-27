// TelegramApprover: delivers approval cards and Sighting notifications to a
// Telegram chat, turns inline-keyboard callbacks into ApprovalDecisions, and
// answers the Owner's /grants command with a pageable listing.
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
  GrantListEntry,
  SightingCard,
  WriteCard,
  WriteCardKind,
  WriteDecision,
  WriteNote,
} from "./approver.ts";
import { isSecretGrantTtl, type ApprovalTtl } from "./types.ts";

// ---------------------------------------------------------------------------
// Rendering (ported from approval_telegram.ts)
// ---------------------------------------------------------------------------

/** Max fields rendered in one Telegram message (write notes only — approval
 * cards and Sightings render their command completely, see
 * buildApprovalMessages / buildSightingMessages). */
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
/** Escaped HTML budget for one decision-critical value block. */
const COMPLETE_VALUE_CHUNK_LIMIT = 3000;

/** Split before escaping so an HTML entity is never cut across messages. */
function escapeCompleteValue(value: unknown): string[] {
  const chunks: string[] = [];
  let current = "";
  for (const character of String(value ?? "")) {
    const escaped = escapeHtml(character);
    if (current && current.length + escaped.length > COMPLETE_VALUE_CHUNK_LIMIT) {
      chunks.push(current);
      current = "";
    }
    current += escaped;
  }
  chunks.push(current);
  return chunks;
}

function completeValueBlocks(label: string, value: unknown, monospace: boolean): string[] {
  return escapeCompleteValue(value).map((chunk, index) => {
    const renderedLabel = index === 0 ? label : `${label}（续 ${index + 1}）`;
    const renderedValue = monospace ? `<code>${chunk}</code>` : chunk;
    return `<b>${escapeHtml(renderedLabel)}</b>: ${renderedValue}`;
  });
}

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
    // Right under the title, before anything else: this is what a TTL button
    // on an inline card actually hands out (ADR-0009).
    ...(card.inline_shell ? [`⚠️ <b>${escapeHtml(INLINE_GRANT_WARNING)}</b>`] : []),
    ...(card.reason ? [escapeHtml(limit(card.reason, 400))] : []),
  ].join("\n");
  const footer = `<i>审批截止：${escapeHtml(card.expires_at)} · 请直接点击下方按钮提交审批决定。</i>`;

  const blocks: string[] = [];
  if (card.command) {
    // The command display is already bounded upstream (formatCommandDisplay
    // truncates at 900 chars + fingerprint); it is never truncated here.
    blocks.push(`<b>命令</b>:\n<pre><code class="language-bash">${escapeHtml(card.command)}</code></pre>`);
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

const WRITE_CARD_TITLES: Readonly<Record<WriteCardKind, string>> = {
  create_item: "新建条目",
  create_field: "新增字段",
  update_value: "改字段值",
  update_rename: "改条目名",
  update_description: "改条目描述",
  update_how_to_get: "改获取方式",
  remove_item: "删除条目",
  remove_field: "删除字段",
};

/**
 * Render a Write Approval card COMPLETELY or throw. Same contract as
 * buildApprovalMessages: the Owner must never be asked to approve a card that
 * hides part of what it changes. Values never appear — the caller has already
 * reduced every secret to a Fingerprint.
 */
export function buildWriteMessages(card: WriteCard): string[] {
  const title = WRITE_CARD_TITLES[card.kind] ?? "写入";
  const header = [
    `🔑 <b>${escapeHtml(limit(`vault 写入审批 · ${title}`, 180))}</b>`,
    ...(card.reason ? [escapeHtml(limit(card.reason, 400))] : []),
  ].join("\n");
  const footer = `<i>审批截止：${escapeHtml(card.expires_at)} · 本次写入不会产生任何免审授权。</i>`;

  const blocks: string[] = completeValueBlocks("条目", card.item, true);
  for (const line of card.lines) {
    blocks.push(...completeValueBlocks(line.label || "详情", line.value, !line.plain));
  }
  for (const warning of card.warnings) {
    blocks.push(...completeValueBlocks("⚠️ 注意", warning, false));
  }
  blocks.push([
    `<b>仓库</b>: <code>${escapeHtml(limit(card.repo, FIELD_VALUE_LIMIT))}</code>`,
    `<b>来源</b>: <code>${escapeHtml(limit([card.host, card.user, card.agent].filter(Boolean).join(" · "), FIELD_VALUE_LIMIT))}</code>`,
    ...(card.client_name ? [`<b>客户端</b>: <code>${escapeHtml(limit(card.client_name, FIELD_VALUE_LIMIT))}</code>`] : []),
  ].join("\n"));

  const messages: string[] = [];
  let current = header;
  const flush = () => {
    messages.push(current);
    current = `🔑 <b>${escapeHtml(limit(`vault 写入审批（续 ${messages.length + 1}）`, 180))}</b>`;
  };
  for (const block of blocks) {
    if (block.length > TELEGRAM_MESSAGE_LIMIT) {
      throw new Error("write card cannot be rendered completely; rejecting the request");
    }
    if (current.length + 2 + block.length > TELEGRAM_MESSAGE_LIMIT) flush();
    current += `\n\n${block}`;
  }
  if (current.length + 2 + footer.length > TELEGRAM_MESSAGE_LIMIT) flush();
  current += `\n\n${footer}`;
  messages.push(current);
  if (messages.length > MAX_APPROVAL_MESSAGES) {
    throw new Error("write card cannot be rendered completely; rejecting the request");
  }
  return messages;
}

export function buildWriteKeyboard(callbackToken: string): TelegramInlineKeyboard {
  return buttonRows([
    { text: `${actionEmoji("primary")} 确认写入`, callback_data: callbackData(`wr:${callbackToken}:apply`) },
    { text: `${actionEmoji("danger")} 拒绝`, callback_data: callbackData(`wr:${callbackToken}:deny`) },
  ]);
}

export function buildWriteNoteText(note: WriteNote): string {
  const fields: CardField[] = [
    ...note.lines.map((line) => ({
      label: line.label,
      value: line.value,
      monospace: !line.plain,
    })),
    { label: "仓库", value: note.repo },
    { label: "来源", value: [note.host, note.user, note.agent].filter(Boolean).join(" · ") },
    ...(note.client_name ? [{ label: "客户端", value: note.client_name }] : []),
  ].filter((field) => field.value);
  return renderCardText(
    note.headline,
    "",
    fields,
    "<i>这条通知是记录，不需要你操作；如果不是你预期的写入，请到 vault 里核对。</i>",
  );
}

/**
 * Render a Sighting. The whole point of this notification is "what ran, with
 * which keys, until when" (ported from buildReuseContext).
 *
 * The command renders COMPLETELY (split across messages when needed, keyboard
 * on the last): for inline code the code is the only evidence of what the
 * secret was used for, and the Owner never saw this run's code on any card.
 * Only the free-form pieces are truncated.
 */
export function buildSightingMessages(card: SightingCard): string[] {
  const kind = card.inline_shell ? "内联代码免审复用" : "密钥免审复用";
  const header = [
    `🔔 <b>${escapeHtml(limit(`${kind}：${card.items.length} 个条目 @ ${card.repo || "?"}`, 180))}</b>`,
    escapeHtml(limit(`这条命令第一次用到这套密钥（已按既有授权放行）。理由：${card.reason}`, 400)),
  ].join("\n");
  const footer = card.inline_grant
    ? "<i>「只撤内联权限」保留普通命令的免审；「全部吊销」删除本次用到的授权行。该仓库其它授权不受影响。</i>"
    : "<i>删除本次用到的授权行；该仓库其它授权不受影响。</i>";

  const blocks: string[] = [];
  if (card.command) {
    // Already bounded upstream (formatCommandDisplay); chunked here only so
    // worst-case HTML escaping cannot push it past one message.
    escapeCompleteValue(card.command).forEach((chunk, index) => {
      const label = index === 0 ? "命令" : `命令（续 ${index + 1}）`;
      blocks.push(`<b>${label}</b>:\n<pre><code class="language-bash">${chunk}</code></pre>`);
    });
  }
  card.items.forEach((item, index) => {
    const mapping = `字段映射：${item.bindings.map((binding) => `${binding.field} → ${binding.env}`).join("，")}`;
    blocks.push(
      `<b>${escapeHtml(limit(`密钥 ${index + 1} · ${item.name}`, 260))}</b>: ${escapeHtml(limit(mapping, FIELD_VALUE_LIMIT))}`,
    );
  });
  blocks.push([
    `<b>授权到期</b>: <code>${escapeHtml(card.expires_at)}</code>`,
    `<b>仓库</b>: <code>${escapeHtml(limit(card.repo, FIELD_VALUE_LIMIT))}</code>`,
    `<b>来源</b>: <code>${escapeHtml(limit([card.host, card.user, card.agent].filter(Boolean).join(" · "), FIELD_VALUE_LIMIT))}</code>`,
    ...(card.client_name ? [`<b>客户端</b>: <code>${escapeHtml(limit(card.client_name, FIELD_VALUE_LIMIT))}</code>`] : []),
  ].join("\n"));

  const messages: string[] = [];
  let current = header;
  for (const block of blocks) {
    if (current.length + 2 + block.length > TELEGRAM_MESSAGE_LIMIT) {
      messages.push(current);
      current = `🔔 <b>${escapeHtml(`${kind}（续 ${messages.length + 1}）`)}</b>`;
    }
    current += `\n\n${block}`;
  }
  if (current.length + 2 + footer.length > TELEGRAM_MESSAGE_LIMIT) {
    messages.push(current);
    current = `🔔 <b>${escapeHtml(`${kind}（续 ${messages.length + 1}）`)}</b>`;
  }
  messages.push(`${current}\n\n${footer}`);
  return messages;
}

// ---------------------------------------------------------------------------
// Grant listing (/grants)
// ---------------------------------------------------------------------------

/** Entries per /grants page. */
export const GRANTS_PAGE_SIZE = 10;

/** Compact UTC rendering for the listing; cards keep full ISO timestamps. */
function shortTime(iso: string): string {
  return `${iso.slice(0, 16).replace("T", " ")} UTC`;
}

function grantEntryText(entry: GrantListEntry, number: number): string {
  // Every line is bounded so that a full page of worst-case entries still
  // fits one message (10 × ~380 chars + header < 4096).
  const items = entry.items
    .map((item) => `${item.name}（${item.fields.join("、")}）`)
    .join("；");
  return [
    `#${number} ${limit(entry.repo, 100)}`,
    `  条目：${limit(items, 160)}`,
    `  普通到期：${entry.expires_at ? shortTime(entry.expires_at) : "—（仅内联授权）"}`,
    ...(entry.inline_expires_at ? [`  ⚠️ 内联到期：${shortTime(entry.inline_expires_at)}`] : []),
    `  客户端：${limit(entry.client_name, 40)}`,
  ].join("\n");
}

/**
 * One page of the Owner's grant listing, as PLAIN text (no parse_mode): repo
 * and item names are arbitrary strings, and a MarkdownV2 escaping slip would
 * make the listing undeliverable — the same reason How-to-get is plain text.
 */
export function buildGrantsPage(
  entries: GrantListEntry[],
  requestedPage: number,
): { page: number; text: string; reply_markup: TelegramInlineKeyboard } {
  const pages = Math.max(1, Math.ceil(entries.length / GRANTS_PAGE_SIZE));
  const page = Math.min(Math.max(0, Math.floor(requestedPage) || 0), pages - 1);
  if (entries.length === 0) {
    return { page: 0, text: "当前没有生效中的授权。", reply_markup: { inline_keyboard: [] } };
  }
  const slice = entries.slice(page * GRANTS_PAGE_SIZE, (page + 1) * GRANTS_PAGE_SIZE);
  const rows: TelegramInlineKeyboard["inline_keyboard"] = [];
  const texts = slice.map((entry, index) => {
    const number = page * GRANTS_PAGE_SIZE + index + 1;
    const all = `ga:${page}:${entry.approval_id}`;
    const inline = `gi:${page}:${entry.approval_id}`;
    // Approval ids are request UUIDs, well inside callback_data's 64 bytes; an
    // id that somehow is not simply gets no buttons rather than breaking the page.
    if (byteLength(inline) <= 64) {
      rows.push([
        ...(entry.inline_expires_at ? [{ text: `#${number} 只撤内联权限`, callback_data: inline }] : []),
        { text: `❌ #${number} 全部吊销`, callback_data: all },
      ]);
    }
    return grantEntryText(entry, number);
  });
  const nav: Array<{ text: string; callback_data: string }> = [];
  if (page > 0) nav.push({ text: "◀️ 上一页", callback_data: `gp:${page - 1}` });
  if (page < pages - 1) nav.push({ text: "下一页 ▶️", callback_data: `gp:${page + 1}` });
  if (nav.length) rows.push(nav);
  const text = [
    `🔑 生效中的授权：${entries.length} 条（第 ${page + 1}/${pages} 页，最早到期在前）`,
    "",
    texts.join("\n\n"),
  ].join("\n");
  return { page, text: limit(text, TELEGRAM_MESSAGE_LIMIT), reply_markup: { inline_keyboard: rows } };
}

// ---------------------------------------------------------------------------
// Keyboards
// ---------------------------------------------------------------------------

export type TelegramInlineKeyboard = {
  inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
};

type ApprovalActionKey = "approve_1h" | "approve_8h" | "approve_7d" | "approve_30d" | "approve_once" | "deny";
type ApprovalAction = {
  key: ApprovalActionKey;
  label: string;
  style: "primary" | "neutral" | "warning" | "danger";
};

const DENY_ACTION: ApprovalAction = { key: "deny", label: "拒绝", style: "danger" };

/** Top line of every inline card: what a TTL button there hands out. */
export const INLINE_GRANT_WARNING = "批准后，本仓库内任意内联代码可免审使用这些密钥（「批准本次执行」除外）";

/**
 * Inline code keeps "this run" as the first, default-looking choice. The TTL
 * buttons mint inline permission — any inline code in this repo, not just the
 * code on this card — so each label says so on its own face (ADR-0009).
 */
function approvalActions(inlineShell: boolean): ApprovalAction[] {
  if (inlineShell) {
    return [
      { key: "approve_once", label: "批准本次执行", style: "primary" },
      { key: "approve_1h", label: "批准 1 小时（含任意内联代码）", style: "warning" },
      { key: "approve_8h", label: "批准 8 小时（含任意内联代码）", style: "warning" },
      { key: "approve_7d", label: "批准 7 天（含任意内联代码）", style: "warning" },
      { key: "approve_30d", label: "批准 30 天（含任意内联代码）", style: "warning" },
      DENY_ACTION,
    ];
  }
  return [
    { key: "approve_1h", label: "批准 1 小时", style: "primary" },
    { key: "approve_8h", label: "批准 8 小时", style: "neutral" },
    { key: "approve_7d", label: "批准 7 天", style: "neutral" },
    { key: "approve_30d", label: "批准 30 天", style: "neutral" },
    DENY_ACTION,
  ];
}

function actionEmoji(style: string): string {
  if (style === "danger") return "❌";
  if (style === "primary") return "✅";
  if (style === "warning") return "⚠️";
  return "▶️";
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function callbackData(value: string): string {
  if (byteLength(value) > 64) {
    throw new Error(`Telegram callback_data exceeds 64 bytes: ${value.slice(0, 16)}…`);
  }
  return value;
}

function buttonRows(
  buttons: Array<{ text: string; callback_data: string }>,
  perRow = 2,
): TelegramInlineKeyboard {
  const rows: TelegramInlineKeyboard["inline_keyboard"] = [];
  for (let index = 0; index < buttons.length; index += perRow) {
    rows.push(buttons.slice(index, index + perRow));
  }
  return { inline_keyboard: rows };
}

export function buildApprovalKeyboard(card: ApprovalCard): TelegramInlineKeyboard {
  // Inline labels carry their warning, which a half-width button would cut off.
  return buttonRows(approvalActions(card.inline_shell).map((action) => ({
    text: `${actionEmoji(action.style)} ${limit(action.label, 48)}`,
    callback_data: callbackData(`ap:${card.id}:${action.key}`),
  })), card.inline_shell ? 1 : 2);
}

export function buildSightingKeyboard(card: SightingCard): TelegramInlineKeyboard {
  if (!card.inline_grant) {
    return buttonRows([{
      text: `${actionEmoji("danger")} ${limit("立即吊销这套授权", 48)}`,
      callback_data: callbackData(`rv:${card.id}`),
    }]);
  }
  return buttonRows([
    { text: "只撤内联权限", callback_data: callbackData(`ri:${card.id}`) },
    { text: `${actionEmoji("danger")} 全部吊销`, callback_data: callbackData(`rv:${card.id}`) },
  ]);
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

type TelegramMessage = {
  message_id?: unknown;
  from?: { id?: unknown } | null;
  chat?: { id?: unknown } | null;
  text?: unknown;
};

type TelegramUpdate = {
  update_id?: unknown;
  callback_query?: TelegramCallbackQuery | null;
  message?: TelegramMessage | null;
};

type PendingApproval = {
  resolve: (decision: ApprovalDecision) => void;
  timer: ReturnType<typeof setTimeout>;
  inlineShell: boolean;
  /** Message ids of the card currently in the chat, so it can be replaced. */
  messageIds: number[];
  /** Set by the total-window timer before it resolves, so the re-push loop can
   * tell "the Owner never answered" from "the Owner decided". */
  timedOut: boolean;
};

type PendingWrite = {
  resolve: (decision: WriteDecision) => void;
  timer: ReturnType<typeof setTimeout>;
  requestId: string;
};

export type TelegramApproverConfig = {
  botToken: string;
  chatId: string;
  allowedUserIds: number[];
  apiBase?: string;
  /**
   * How many cards one approval window is split into (ADR-0006). Each replaces
   * the one before it, because editing a message produces no push notification
   * and an edited card is one the Owner never learns about.
   */
  approvalCards?: number;
};

export type TelegramApproverHooks = {
  /**
   * Revoke the grants behind a Sighting card by its id, resolved through a
   * DURABLE store (SQLite) so the button keeps working across broker
   * restarts. Returns the number of rows removed, or null when the id cannot
   * be resolved (unknown/expired handle).
   */
  onRevoke: (sightingId: string) => Promise<number | null> | number | null;
  /** Same handle, but clear only the inline permission of those grants. */
  onRevokeInline?: (sightingId: string) => Promise<number | null> | number | null;
  /** Live grants for /grants, one entry per approval, earliest expiry first. */
  listGrants?: () => Promise<GrantListEntry[]> | GrantListEntry[];
  /** Revoke what one approval currently holds: everything, or only its inline permission. */
  revokeApproval?: (approvalId: string, scope: "all" | "inline") => Promise<number> | number;
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
  private readonly approvalCards: number;
  private readonly hooks: TelegramApproverHooks;
  private readonly fetchImpl: typeof fetch;
  private readonly log: (msg: string) => void;
  private readonly now: () => number;

  private readonly pending = new Map<string, PendingApproval>();
  /** Server-generated callback token -> pending write. */
  private readonly pendingWrites = new Map<string, PendingWrite>();
  /** Caller request id -> pending write, used only to reject concurrent reuse. */
  private readonly pendingWriteRequestIds = new Map<string, PendingWrite>();
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
    this.approvalCards = Math.max(1, Math.floor(config.approvalCards ?? 1));
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
      entry.timedOut = true;
      entry.resolve({ approved: false, reason: "timeout" });
      this.pending.delete(id);
    }
    for (const [token, entry] of this.pendingWrites) {
      clearTimeout(entry.timer);
      entry.resolve({ approved: false, reason: "timeout" });
      this.pendingWrites.delete(token);
    }
    this.pendingWriteRequestIds.clear();
  }

  async requestApproval(card: ApprovalCard, timeoutMs: number): Promise<ApprovalDecision> {
    // Park the request and arm the deadline BEFORE sending: a stalled
    // sendMessage must never extend the approval window, and the send itself
    // is bounded so it cannot park the request forever.
    let entry: PendingApproval;
    const decision = new Promise<ApprovalDecision>((resolve) => {
      const timer = setTimeout(() => {
        const parked = this.pending.get(card.id);
        if (parked) parked.timedOut = true;
        this.pending.delete(card.id);
        resolve({ approved: false, reason: "timeout" });
      }, timeoutMs);
      entry = { resolve, timer, inlineShell: card.inline_shell, messageIds: [], timedOut: false };
      this.pending.set(card.id, entry);
    });
    try {
      entry!.messageIds = await this.sendApprovalCard(card, timeoutMs, 1);
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
    // Later cards are best effort and must not delay the caller: the window is
    // already armed, and a failed re-push leaves the previous card standing.
    void this.repushApprovalCard(card, entry!, timeoutMs);
    return decision;
  }

  /**
   * Render and deliver one card. The card renders completely (every item, every
   * mapping, the command) across one or more messages, or buildApprovalMessages
   * throws and the request is rejected. The keyboard rides on the LAST message
   * so the Owner has scrolled past everything the buttons would grant.
   */
  private async sendApprovalCard(
    card: ApprovalCard,
    timeoutMs: number,
    round: number,
  ): Promise<number[]> {
    const texts = buildApprovalMessages(card);
    const sent: number[] = [];
    for (let index = 0; index < texts.length; index++) {
      const first = index === 0;
      const last = index === texts.length - 1;
      const message = await this.api<{ message_id?: unknown }>("sendMessage", {
        chat_id: this.chatId,
        text: first && round > 1 ? `${REPUSH_PREFIX(round)}\n${texts[index]}` : texts[index],
        parse_mode: "HTML",
        disable_web_page_preview: true,
        ...(last ? { reply_markup: buildApprovalKeyboard(card) } : {}),
      }, AbortSignal.timeout(Math.min(timeoutMs, 30_000)));
      if (typeof message?.message_id === "number") sent.push(message.message_id);
    }
    return sent;
  }

  /**
   * Keep exactly one live card in the chat for the life of the window
   * (ADR-0006). Replacing means delete-then-send: `editMessageText` produces no
   * push notification, so an edited card is one the Owner never learns about.
   * The final card is not deleted — it is turned into a record that something
   * was asked and missed, so a chat the Owner comes back to is not silent.
   */
  private async repushApprovalCard(
    card: ApprovalCard,
    entry: PendingApproval,
    timeoutMs: number,
  ): Promise<void> {
    const rounds = this.approvalCards;
    const roundMs = Math.max(1, Math.floor(timeoutMs / rounds));
    const stillParked = () => this.pending.get(card.id) === entry;
    for (let round = 2; round <= rounds; round++) {
      await delay(roundMs);
      if (!stillParked()) break;
      try {
        const next = await this.sendApprovalCard(card, timeoutMs, round);
        const previous = entry.messageIds;
        entry.messageIds = next;
        await this.deleteMessages(previous);
      } catch (error) {
        // Leave the standing card alone: a chat with a stale-looking card beats
        // a chat with none. The window is unaffected either way.
        this.log(`telegram approval re-push failed (card ${round}/${rounds}): ${errorMessage(error)}`);
      }
    }
    // Wait out the tail of the window, then mark the last card abandoned.
    while (stillParked()) await delay(Math.min(roundMs, 5_000));
    if (!entry.timedOut) return;
    const last = entry.messageIds[entry.messageIds.length - 1];
    if (last === undefined) return;
    try {
      await this.api("editMessageReplyMarkup", {
        chat_id: this.chatId,
        message_id: last,
        reply_markup: { inline_keyboard: [] },
      });
      await this.api("sendMessage", {
        chat_id: this.chatId,
        text: GAVE_UP_TEXT,
        parse_mode: "HTML",
        disable_web_page_preview: true,
        reply_to_message_id: last,
        allow_sending_without_reply: true,
      });
    } catch (error) {
      this.log(`telegram approval give-up notice failed: ${errorMessage(error)}`);
    }
  }

  /** Best effort: a card that cannot be deleted is noise, not a failure. */
  private async deleteMessages(messageIds: number[]): Promise<void> {
    for (const messageId of messageIds) {
      try {
        await this.api("deleteMessage", { chat_id: this.chatId, message_id: messageId });
      } catch (error) {
        this.log(`telegram deleteMessage failed: ${errorMessage(error)}`);
      }
    }
  }

  async requestWriteApproval(card: WriteCard, timeoutMs: number): Promise<WriteDecision> {
    // request_id is caller-controlled. Never replace an existing entry: doing
    // so would let the first card's callback resolve a different Write Request.
    if (this.pendingWriteRequestIds.has(card.id)) {
      throw new Error("duplicate pending write request id");
    }
    // Telegram buttons must never carry the caller-controlled request id. A
    // fresh server token keeps an expired card from targeting a later request
    // that reuses that id, while remaining well below callback_data's 64 bytes.
    const callbackToken = crypto.randomUUID();
    // Same shape as requestApproval: park and arm the deadline BEFORE sending,
    // so a stalled sendMessage can never extend the window.
    let entry: PendingWrite;
    const decision = new Promise<WriteDecision>((resolve) => {
      const timer = setTimeout(() => {
        if (this.pendingWrites.get(callbackToken) === entry) {
          this.pendingWrites.delete(callbackToken);
          this.pendingWriteRequestIds.delete(card.id);
        }
        resolve({ approved: false, reason: "timeout" });
      }, timeoutMs);
      entry = { resolve, timer, requestId: card.id };
      this.pendingWrites.set(callbackToken, entry);
      this.pendingWriteRequestIds.set(card.id, entry);
    });
    try {
      const texts = buildWriteMessages(card);
      for (let index = 0; index < texts.length; index++) {
        await this.api("sendMessage", {
          chat_id: this.chatId,
          text: texts[index],
          parse_mode: "HTML",
          disable_web_page_preview: true,
          ...(index === texts.length - 1 ? { reply_markup: buildWriteKeyboard(callbackToken) } : {}),
        }, AbortSignal.timeout(Math.min(timeoutMs, 30_000)));
      }
    } catch (error) {
      if (this.pendingWrites.get(callbackToken) === entry!) {
        clearTimeout(entry!.timer);
        this.pendingWrites.delete(callbackToken);
        this.pendingWriteRequestIds.delete(card.id);
        throw error;
      }
    }
    return decision;
  }

  async notifyWrite(note: WriteNote): Promise<void> {
    try {
      await this.api("sendMessage", {
        chat_id: this.chatId,
        text: buildWriteNoteText(note),
        parse_mode: "HTML",
        disable_web_page_preview: true,
      });
    } catch (error) {
      // Best-effort by contract: an audit note never blocks a write.
      this.log(`telegram write notification failed: ${errorMessage(error)}`);
    }
  }

  async notifySighting(card: SightingCard): Promise<void> {
    try {
      // The revoke button carries only the card id; the id → grant-keys
      // mapping lives in the durable store behind hooks.onRevoke, so the
      // button survives broker restarts.
      //
      // Silent: nothing waits on a Sighting. Only cards that need a tap to
      // proceed may ring, or the ones that do get drowned out.
      const texts = buildSightingMessages(card);
      for (let index = 0; index < texts.length; index++) {
        await this.api("sendMessage", {
          chat_id: this.chatId,
          text: texts[index],
          parse_mode: "HTML",
          disable_web_page_preview: true,
          disable_notification: true,
          ...(index === texts.length - 1 ? { reply_markup: buildSightingKeyboard(card) } : {}),
        });
      }
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
          else if (update.message) await this.handleMessage(update.message);
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
    } else if (data.startsWith("wr:")) {
      await this.handleWriteCallback(data, callbackId, fromId, callback);
    } else if (data.startsWith("rv:")) {
      await this.handleRevokeCallback(data.slice(3), "all", callbackId, fromId, callback);
    } else if (data.startsWith("ri:")) {
      await this.handleRevokeCallback(data.slice(3), "inline", callbackId, fromId, callback);
    } else if (data.startsWith("gp:") || data.startsWith("ga:") || data.startsWith("gi:")) {
      await this.handleGrantsCallback(data, callbackId, fromId, callback);
    }
    // Anything else (unknown callbacks) is ignored.
  }

  /**
   * Plain messages: only `/grants` means anything, and only from the Owner in
   * the configured chat — the bot may sit in other chats, and a listing of
   * what is granted where is itself worth keeping to the Owner.
   */
  private async handleMessage(message: TelegramMessage): Promise<void> {
    const text = typeof message.text === "string" ? message.text.trim() : "";
    if (!/^\/grants(@[A-Za-z0-9_]+)?(\s|$)/.test(text)) return;
    const fromId = typeof message.from?.id === "number" ? message.from.id : NaN;
    if (String(message.chat?.id ?? "") !== this.chatId || !this.allowedUserIds.includes(fromId)) return;
    if (!this.hooks.listGrants) return;
    try {
      const view = buildGrantsPage(await this.hooks.listGrants(), 0);
      await this.api("sendMessage", {
        chat_id: this.chatId,
        text: view.text,
        disable_web_page_preview: true,
        disable_notification: true,
        reply_markup: view.reply_markup,
      });
    } catch (error) {
      this.log(`telegram /grants failed: ${errorMessage(error)}`);
    }
  }

  private async handleGrantsCallback(
    data: string,
    callbackId: string,
    fromId: number,
    callback: TelegramCallbackQuery,
  ): Promise<void> {
    if (!this.allowedUserIds.includes(fromId)) {
      await this.answerCallback(callbackId, "无权操作");
      return;
    }
    const match = /^(gp|ga|gi):(\d{1,4})(?::([A-Za-z0-9_-]{8,80}))?$/.exec(data);
    const [, action, pageText, approvalId] = match ?? [];
    if (!match || (action === "gp") !== (approvalId === undefined) || !this.hooks.listGrants) {
      await this.answerCallback(callbackId, "未知操作");
      return;
    }
    let toast = "";
    if (action !== "gp") {
      if (!this.hooks.revokeApproval) {
        await this.answerCallback(callbackId, "未知操作");
        return;
      }
      try {
        const changed = await this.hooks.revokeApproval(approvalId!, action === "gi" ? "inline" : "all");
        toast = action === "gi" ? `已撤销 ${changed} 行的内联权限` : `已吊销 ${changed} 行`;
      } catch (error) {
        this.log(`telegram grant revoke failed: ${errorMessage(error)}`);
        await this.answerCallback(callbackId, "吊销失败，请检查服务端日志");
        return;
      }
    }
    await this.answerCallback(callbackId, toast);
    // Re-render in place: paging needs no push, and after a revoke the Owner
    // should see the listing as it now stands, not as it was.
    const messageId = callback.message?.message_id;
    const chatId = callback.message?.chat?.id;
    if (messageId === undefined || messageId === null || chatId === undefined || chatId === null) return;
    try {
      const view = buildGrantsPage(await this.hooks.listGrants(), Number(pageText));
      await this.api("editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: view.text,
        disable_web_page_preview: true,
        reply_markup: view.reply_markup,
      });
    } catch (error) {
      this.log(`telegram /grants refresh failed: ${errorMessage(error)}`);
    }
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

  private async handleWriteCallback(
    data: string,
    callbackId: string,
    fromId: number,
    callback: TelegramCallbackQuery,
  ): Promise<void> {
    const parts = data.split(":");
    if (parts.length !== 3) return;
    const [, callbackToken, actionKey] = parts;
    const entry = this.pendingWrites.get(callbackToken);
    if (!entry) {
      await this.answerCallback(callbackId, "已处理");
      return;
    }
    if (!this.allowedUserIds.includes(fromId)) {
      await this.answerCallback(callbackId, "无权审批");
      return;
    }
    if (actionKey !== "apply" && actionKey !== "deny") {
      await this.answerCallback(callbackId, "未知操作");
      return;
    }
    clearTimeout(entry.timer);
    this.pendingWrites.delete(callbackToken);
    this.pendingWriteRequestIds.delete(entry.requestId);
    entry.resolve(
      actionKey === "apply"
        ? { approved: true, decided_by: String(fromId), decided_at: new Date(this.now()).toISOString() }
        : { approved: false, reason: "denied" },
    );
    // This callback records only the Owner's decision. The vault mutation runs
    // after the promise resolves and may still fail, so do not claim success.
    await this.answerCallback(callbackId, actionKey === "apply" ? "已批准，等待写入" : "已拒绝");
    await this.removeKeyboard(callback);
  }

  private async handleRevokeCallback(
    cardId: string,
    scope: "all" | "inline",
    callbackId: string,
    fromId: number,
    callback: TelegramCallbackQuery,
  ): Promise<void> {
    if (!this.allowedUserIds.includes(fromId)) {
      await this.answerCallback(callbackId, "无权审批");
      return;
    }
    const hook = scope === "inline" ? this.hooks.onRevokeInline : this.hooks.onRevoke;
    if (!hook) {
      await this.answerCallback(callbackId, "未知操作");
      return;
    }
    let removed: number | null = null;
    try {
      removed = await hook(cardId);
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
    if (scope === "inline") {
      // The ordinary part is still live, so the full-revoke button must stay
      // usable; only the now-meaningless inline button goes.
      await this.answerCallback(callbackId, `已撤销 ${removed} 行的内联权限`);
      await this.replaceKeyboard(callback, buttonRows([{
        text: `${actionEmoji("danger")} 全部吊销`,
        callback_data: callbackData(`rv:${cardId}`),
      }]));
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
    await this.replaceKeyboard(callback, { inline_keyboard: [] });
  }

  private async replaceKeyboard(callback: TelegramCallbackQuery, markup: TelegramInlineKeyboard): Promise<void> {
    const messageId = callback.message?.message_id;
    const chatId = callback.message?.chat?.id;
    if (messageId === undefined || messageId === null || chatId === undefined || chatId === null) return;
    try {
      await this.api("editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: messageId,
        reply_markup: markup,
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
  // "once" exists only on inline cards; an ordinary card never offered it, so
  // a forged approve_once there is refused rather than silently widened.
  if (actionKey === "approve_once") return inlineShell ? approve("once") : null;
  if (actionKey.startsWith("approve_")) {
    const ttl = actionKey.slice("approve_".length);
    if (isSecretGrantTtl(ttl)) return approve(ttl);
  }
  return null;
}

/** Marks a card as a re-push so the Owner can see it is the same ask, not a new one. */
const REPUSH_PREFIX = (round: number): string => `\u{1F501} <b>\u91cd\u65b0\u63d0\u9192\uff08\u7b2c ${round} \u6b21\uff09</b>`;

const GAVE_UP_TEXT = "\u23f0 <b>\u5df2\u653e\u5f03\uff08\u8d85\u65f6\u672a\u54cd\u5e94\uff09</b>\n\u4e0a\u9762\u8fd9\u5f20\u5361\u7247\u5df2\u5931\u6548\uff0c\u672a\u6388\u4e88\u4efb\u4f55\u6743\u9650\u3002\u9700\u8981\u7684\u8bdd\u8ba9\u8c03\u7528\u65b9\u91cd\u8dd1\u4e00\u6b21\u3002";

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
