// Approver: the channel interface through which the Owner receives Approvals
// and revocations (see CONTEXT.md). One broker uses one Approver at a time.

import type { ApprovalTtl, WireBinding } from "./types.ts";

export type ApprovalCardItem = {
  name: string;
  description?: string;
  bindings: WireBinding[];
};

/** Display-safe context for one pending Approval. Never contains secret values or item ids. */
export type ApprovalCard = {
  /** Request id — used as the callback correlation id. */
  id: string;
  reason: string;
  /** Rendered argv (already truncated/fingerprinted by the caller). */
  command: string;
  inline_shell: boolean;
  items: ApprovalCardItem[];
  repo: string;
  host: string;
  user: string;
  agent?: string;
  client_name: string;
  /** When the pending approval times out, ISO timestamp (display only). */
  expires_at: string;
};

export type ApprovalDecision =
  | { approved: true; ttl: ApprovalTtl; decided_by?: string; decided_at: string }
  | { approved: false; reason: "denied" | "timeout" };

/** Non-blocking Sighting notification with a revoke button. */
export type SightingCard = {
  id: string;
  reason: string;
  command: string;
  items: ApprovalCardItem[];
  repo: string;
  host: string;
  user: string;
  agent?: string;
  client_name: string;
  /** Grant expiry (the earliest unit), ISO timestamp. */
  expires_at: string;
  /** Grant rows the revoke button deletes. */
  grant_keys: string[];
};

export interface Approver extends WriteApprover {
  /**
   * Deliver the card and wait for the Owner's decision. Must resolve
   * `{approved:false, reason:"timeout"}` after timeoutMs (fail closed) and
   * must honor first-decision-wins.
   */
  requestApproval(card: ApprovalCard, timeoutMs: number): Promise<ApprovalDecision>;
  /** Best-effort: failures must be swallowed (log only) — a Sighting never blocks. */
  notifySighting(card: SightingCard): Promise<void>;
  /** Begin any background work (e.g. getUpdates long polling). */
  start(): void;
  stop(): void;
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

/**
 * Which card to render. The Write Operation alone is not enough: what the Owner
 * needs to see depends on whether the thing being changed is a secret — a
 * Description diff can be shown in the clear, a Field value can only ever be a
 * Fingerprint (CONTEXT.md "Fingerprint").
 */
export type WriteCardKind =
  | "create_item"
  | "create_field"
  | "update_value"
  | "update_rename"
  | "update_description"
  | "remove_item"
  | "remove_field";

export type WriteCardLine = {
  label: string;
  value: string;
  /** True when the value is not a credential and may render as prose. */
  plain?: boolean;
};

/** Display-safe context for one pending Write Approval. Never carries a value. */
export type WriteCard = {
  /** Request id — the callback correlation id. */
  id: string;
  kind: WriteCardKind;
  item: string;
  reason: string;
  /** Decision-critical detail, rendered in full or the card fails closed. */
  lines: WriteCardLine[];
  /** Irreversibility and blast radius, rendered immediately above the buttons. */
  warnings: string[];
  repo: string;
  host: string;
  user: string;
  agent?: string;
  client_name: string;
  expires_at: string;
};

/**
 * A Write Approval carries no TTL choice: approving changes the vault once and
 * grants nothing (CONTEXT.md "Approval").
 */
export type WriteDecision =
  | { approved: true; decided_by?: string; decided_at: string }
  | { approved: false; reason: "denied" | "timeout" };

/**
 * Non-blocking record of something that happened to the vault without a
 * blocking Approval: an Entry Form write completing, or its link expiring
 * unused. Nothing may change the vault silently.
 */
export type WriteNote = {
  id: string;
  headline: string;
  lines: WriteCardLine[];
  repo: string;
  host: string;
  user: string;
  agent?: string;
  client_name: string;
};

export interface WriteApprover {
  /** Deliver the card and wait. Must fail closed on timeout, first decision wins. */
  requestWriteApproval(card: WriteCard, timeoutMs: number): Promise<WriteDecision>;
  /** Best-effort: failures must be swallowed (log only). */
  notifyWrite(note: WriteNote): Promise<void>;
}
