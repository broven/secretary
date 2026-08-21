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

export interface Approver {
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
