// Dev-only auto-approver: rubber-stamps every request without a human in the
// loop. It exists so local development does not require a Telegram bot, and it
// is deliberately hard to enable by accident: both the explicit env opt-in and
// a non-production NODE_ENV are required here (defense in depth — main.ts
// gates it again).

import type { ApprovalCard, ApprovalDecision, Approver, SightingCard } from "./approver.ts";

export function createAutoApprover(opts: {
  env: Record<string, string | undefined>;
  log?: (msg: string) => void;
}): Approver {
  if (opts.env.SECRETARY_DEV_AUTO_APPROVE !== "1") {
    throw new Error("auto-approver requires SECRETARY_DEV_AUTO_APPROVE=1");
  }
  if (opts.env.NODE_ENV === "production") {
    throw new Error("auto-approver is forbidden when NODE_ENV=production");
  }
  const log = opts.log ?? ((msg: string) => console.log(msg));
  return {
    async requestApproval(card: ApprovalCard): Promise<ApprovalDecision> {
      // Loud on every single call: this line is the only trace that a request
      // bypassed human review.
      log(`WARNING: dev auto-approver enabled — approving without human review: ${card.id}`);
      return {
        approved: true,
        ttl: card.inline_shell ? "once" : "1h",
        decided_by: "dev-auto-approver",
        decided_at: new Date().toISOString(),
      };
    },
    async notifySighting(card: SightingCard): Promise<void> {
      log(`dev auto-approver: sighting ${card.id} (${card.grant_keys.length} grant rows) — no notification sent`);
    },
    start(): void {},
    stop(): void {},
  };
}
