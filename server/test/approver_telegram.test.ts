import { afterEach, beforeEach, expect, test } from "bun:test";
import type { ApprovalCard, GrantListEntry, SightingCard, WriteCard } from "../src/approver.ts";
import {
  buildApprovalMessages,
  buildGrantsPage,
  buildWriteMessages,
  GRANTS_PAGE_SIZE,
  TELEGRAM_MESSAGE_LIMIT,
  TelegramApprover,
} from "../src/approver_telegram.ts";
import { startFakeTelegram, type FakeTelegram } from "./helpers/fake_telegram.ts";

const ALLOWED_USER = 42;
const OTHER_USER = 999;

let fake: FakeTelegram;
let approver: TelegramApprover;
let revokedCalls: string[];
let inlineRevokedCalls: string[];
// A durable-store stand-in: sighting id -> number of grant rows it deletes.
let revokeHandles: Map<string, number>;
// A grant-store stand-in for /grants: revoking removes the entry (all) or
// strips its inline expiry (inline), like the real store does.
let grantEntries: GrantListEntry[];
let approvalRevocations: Array<[string, "all" | "inline"]>;

beforeEach(async () => {
  fake = await startFakeTelegram();
  revokedCalls = [];
  inlineRevokedCalls = [];
  revokeHandles = new Map();
  grantEntries = [];
  approvalRevocations = [];
  approver = new TelegramApprover(
    { botToken: "TEST_TOKEN", chatId: "555", allowedUserIds: [ALLOWED_USER], apiBase: fake.url },
    {
      onRevoke: (sightingId) => {
        revokedCalls.push(sightingId);
        return revokeHandles.get(sightingId) ?? null;
      },
      onRevokeInline: (sightingId) => {
        inlineRevokedCalls.push(sightingId);
        return revokeHandles.get(sightingId) ?? null;
      },
      listGrants: () => grantEntries,
      revokeApproval: (approvalId, scope) => {
        approvalRevocations.push([approvalId, scope]);
        const before = grantEntries.length;
        grantEntries = scope === "all"
          ? grantEntries.filter((entry) => entry.approval_id !== approvalId)
          : grantEntries.map((entry) => {
            if (entry.approval_id !== approvalId) return entry;
            const { inline_expires_at: _dropped, ...rest } = entry;
            return rest;
          });
        return scope === "all" ? before - grantEntries.length : 1;
      },
    },
    { log: () => {} },
  );
  approver.start();
});

afterEach(() => {
  approver.stop();
  fake.stop();
});

function makeCard(overrides: Partial<ApprovalCard> = {}): ApprovalCard {
  return {
    id: crypto.randomUUID(),
    reason: "deploy pipeline needs the registry token",
    command: "docker login -u ci registry.example.com",
    inline_shell: false,
    items: [{
      name: "Registry Token",
      description: "push access for CI",
      bindings: [{ field: "password", env: "REGISTRY_TOKEN" }],
    }],
    repo: "acme/site",
    host: "buildbox",
    user: "randy",
    agent: "claude-code",
    client_name: "client-abc",
    expires_at: new Date(Date.now() + 300_000).toISOString(),
    ...overrides,
  };
}

function makeSightingCard(overrides: Partial<SightingCard> = {}): SightingCard {
  return {
    id: crypto.randomUUID(),
    reason: "rerun of the deploy",
    command: "docker push registry.example.com/acme/site",
    items: [{
      name: "Registry Token",
      bindings: [{ field: "password", env: "REGISTRY_TOKEN" }],
    }],
    repo: "acme/site",
    host: "buildbox",
    user: "randy",
    client_name: "client-abc",
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    grant_keys: ["grant:a", "grant:b"],
    inline_shell: false,
    inline_grant: false,
    ...overrides,
  };
}

function makeWriteCard(overrides: Partial<WriteCard> = {}): WriteCard {
  return {
    id: crypto.randomUUID(),
    kind: "update_description",
    item: "Registry Token",
    reason: "document why the registry token exists",
    lines: [
      { label: "现描述", value: "old description", plain: true },
      { label: "新描述", value: "new description", plain: true },
    ],
    warnings: [],
    repo: "acme/site",
    host: "buildbox",
    user: "randy",
    agent: "claude-code",
    client_name: "client-abc",
    expires_at: new Date(Date.now() + 300_000).toISOString(),
    ...overrides,
  };
}

async function waitFor(condition: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("waitFor: condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function keyboardButtons(index: number): Array<{ text: string; callback_data: string }> {
  return (fake.sentMessages[index].reply_markup?.inline_keyboard ?? []).flat();
}

test("renders the approval card with escaped command, item name, and 5 buttons", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  const message = fake.sentMessages[0];
  expect(message.chat_id).toBe("555");
  expect(message.text).toContain("docker login -u ci registry.example.com");
  expect(message.text).toContain("Registry Token");
  expect(message.text).toContain("密钥使用审批");
  expect(message.text).toContain("password → REGISTRY_TOKEN");

  const buttons = keyboardButtons(0);
  expect(buttons.length).toBe(5);
  expect(buttons.map((button) => button.callback_data)).toEqual([
    `ap:${card.id}:approve_1h`,
    `ap:${card.id}:approve_8h`,
    `ap:${card.id}:approve_7d`,
    `ap:${card.id}:approve_30d`,
    `ap:${card.id}:deny`,
  ]);
  expect(buttons.map((button) => button.text).join(" ")).toContain("批准 1 小时");

  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  await decision;
});

test("inline shell card keeps approve_once first and offers TTLs that state their scope", async () => {
  const card = makeCard({ inline_shell: true, command: 'sh -c "echo hi"' });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  const buttons = keyboardButtons(0);
  expect(buttons.map((button) => button.callback_data)).toEqual([
    `ap:${card.id}:approve_once`,
    `ap:${card.id}:approve_1h`,
    `ap:${card.id}:approve_8h`,
    `ap:${card.id}:approve_7d`,
    `ap:${card.id}:approve_30d`,
    `ap:${card.id}:deny`,
  ]);
  expect(buttons[0].text).toContain("批准本次执行");
  for (const button of buttons.slice(1, 5)) expect(button.text).toContain("含任意内联代码");
  // One per row: a two-up layout would cut the warning off the label.
  expect(fake.sentMessages[0].reply_markup!.inline_keyboard.every((row) => row.length === 1)).toBe(true);
  // The scope warning sits directly under the title, above the reason.
  const lines = fake.sentMessages[0].text.split("\n");
  expect(lines[1]).toContain("本仓库内任意内联代码可免审使用这些密钥");
  // It rings: an approval card needs a tap to proceed.
  expect(fake.sentMessages[0].disable_notification).toBeUndefined();

  fake.pressButton(`ap:${card.id}:approve_7d`, ALLOWED_USER);
  const result = await decision;
  expect(result).toMatchObject({ approved: true, ttl: "7d", decided_by: String(ALLOWED_USER) });
});

test("approve_once still resolves an inline card as this-run-only", async () => {
  const card = makeCard({ inline_shell: true, command: 'sh -c "echo hi"' });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);
  fake.pressButton(`ap:${card.id}:approve_once`, ALLOWED_USER);
  await expect(decision).resolves.toMatchObject({ approved: true, ttl: "once" });
});

test("a forged approve_once on an ordinary card is refused and leaves it pending", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);
  fake.pressButton(`ap:${card.id}:approve_once`, ALLOWED_USER);
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toBe("未知操作");
  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  await expect(decision).resolves.toEqual({ approved: false, reason: "denied" });
});

test("approve_8h from an allowed user resolves approved with ttl 8h", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  fake.pressButton(`ap:${card.id}:approve_8h`, ALLOWED_USER);
  const result = await decision;
  expect(result.approved).toBe(true);
  if (result.approved) {
    expect(result.ttl).toBe("8h");
    expect(result.decided_by).toBe(String(ALLOWED_USER));
    expect(Date.parse(result.decided_at)).toBeGreaterThan(0);
  }
  // The keyboard is removed after the decision.
  await waitFor(() => fake.editedMarkups.length === 1);
});

test("approve_30d from an allowed user resolves approved with ttl 30d", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  fake.pressButton(`ap:${card.id}:approve_30d`, ALLOWED_USER);
  await expect(decision).resolves.toMatchObject({
    approved: true,
    ttl: "30d",
    decided_by: String(ALLOWED_USER),
  });
});

test("first decision wins: a later deny does not override approve_1h", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  fake.pressButton(`ap:${card.id}:approve_1h`, ALLOWED_USER);
  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  const result = await decision;
  expect(result).toMatchObject({ approved: true, ttl: "1h" });

  // The late press is acknowledged as already handled.
  await waitFor(() => fake.answeredCallbacks.length >= 2);
  expect(fake.answeredCallbacks[1].text).toBe("已处理");
});

test("a disallowed user's press does not resolve; an allowed deny then does", async () => {
  const card = makeCard();
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  fake.pressButton(`ap:${card.id}:approve_7d`, OTHER_USER);
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toBe("无权审批");

  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  const result = await decision;
  expect(result).toEqual({ approved: false, reason: "denied" });
});

test("no press within timeoutMs resolves timeout", async () => {
  const card = makeCard();
  const result = await approver.requestApproval(card, 200);
  expect(result).toEqual({ approved: false, reason: "timeout" });
});

test("a duplicate pending write id is rejected without retargeting the first card", async () => {
  const id = crypto.randomUUID();
  const first = approver.requestWriteApproval(makeWriteCard({ id, item: "Benign Item" }), 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  const duplicate = approver.requestWriteApproval(makeWriteCard({ id, item: "Different Item" }), 200);
  await expect(duplicate).rejects.toThrow("duplicate pending write request id");
  expect(fake.sentMessages).toHaveLength(1);

  fake.pressButton(keyboardButtons(0)[0].callback_data, ALLOWED_USER);
  await expect(first).resolves.toMatchObject({ approved: true, decided_by: String(ALLOWED_USER) });
});

test("a stale write button cannot approve a later request that reuses the caller id", async () => {
  const id = crypto.randomUUID();
  const first = approver.requestWriteApproval(makeWriteCard({ id, item: "First Item" }), 200);
  await waitFor(() => fake.sentMessages.length === 1);
  const staleApply = keyboardButtons(0)[0].callback_data;

  await expect(first).resolves.toEqual({ approved: false, reason: "timeout" });

  const second = approver.requestWriteApproval(makeWriteCard({ id, item: "Second Item" }), 5000);
  await waitFor(() => fake.sentMessages.length === 2);
  const currentButtons = keyboardButtons(1);
  expect(currentButtons.map((button) => button.callback_data)).not.toContain(staleApply);
  for (const button of [...keyboardButtons(0), ...currentButtons]) {
    expect(new TextEncoder().encode(button.callback_data).length).toBeLessThanOrEqual(64);
  }

  fake.pressButton(staleApply, ALLOWED_USER);
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toBe("已处理");

  fake.pressButton(currentButtons[0].callback_data, ALLOWED_USER);
  await expect(second).resolves.toMatchObject({ approved: true });
});

test("approving a write says it is approved, not already applied", async () => {
  const card = makeWriteCard();
  const decision = approver.requestWriteApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);
  // A write approval waits on a tap, so it rings.
  expect(fake.sentMessages[0].disable_notification).toBeUndefined();

  fake.pressButton(keyboardButtons(0)[0].callback_data, ALLOWED_USER);
  await expect(decision).resolves.toMatchObject({ approved: true });
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toBe("已批准，等待写入");
});

test("a write card renders complete maximum-length item names and descriptions", () => {
  const item = `${"I".repeat(499)}Z`;
  const description = `${"D".repeat(999)}Z`;
  const messages = buildWriteMessages(makeWriteCard({
    item,
    lines: [{ label: "新描述", value: description, plain: true }],
  }));
  const combined = messages.join("\n");

  expect(combined).toContain(item);
  expect(combined).toContain(description);
  expect(combined).not.toContain(`${"I".repeat(319)}…`);
  expect(combined).not.toContain(`${"D".repeat(319)}…`);
});

test("complete write details survive worst-case HTML expansion within message limits", () => {
  const messages = buildWriteMessages(makeWriteCard({
    item: "&".repeat(500),
    lines: [{ label: "新描述", value: "<".repeat(1000), plain: true }],
  }));
  const combined = messages.join("\n");

  expect(combined.match(/&amp;/g)).toHaveLength(500);
  expect(combined.match(/&lt;/g)).toHaveLength(1000);
  expect(messages.every((message) => message.length <= TELEGRAM_MESSAGE_LIMIT)).toBe(true);
});

test("notifySighting sends a revoke button and pressing it calls onRevoke by id", async () => {
  const card = makeSightingCard();
  revokeHandles.set(card.id, 2);
  await approver.notifySighting(card);
  expect(fake.sentMessages.length).toBe(1);
  expect(fake.sentMessages[0].text).toContain("密钥免审复用");
  expect(fake.sentMessages[0].text).toContain("授权到期");
  // Nothing waits on a Sighting, so it must not ring.
  expect(fake.sentMessages[0].disable_notification).toBe(true);

  const buttons = keyboardButtons(0);
  expect(buttons.length).toBe(1);
  expect(buttons[0].callback_data).toBe(`rv:${card.id}`);
  expect(buttons[0].text).toContain("立即吊销这套授权");

  fake.pressButton(`rv:${card.id}`, ALLOWED_USER);
  await waitFor(() => revokedCalls.length === 1);
  expect(revokedCalls[0]).toBe(card.id);
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toBe("已吊销 2 行");
});

test("an unresolvable revoke handle answers honestly instead of claiming success (P1-c)", async () => {
  const card = makeSightingCard();
  await approver.notifySighting(card);
  // No entry in the durable store (e.g. it was swept): must NOT say 已吊销.
  fake.pressButton(`rv:${card.id}`, ALLOWED_USER);
  await waitFor(() => fake.answeredCallbacks.length === 1);
  expect(fake.answeredCallbacks[0].text).toContain("无法识别");
  expect(fake.answeredCallbacks[0].text).not.toContain("已吊销");
});

test("the approval card always shows the field mapping before a long description (P1-b)", async () => {
  const card = makeCard({
    items: [{
      name: "Registry Token",
      description: "x".repeat(1000),
      bindings: [{ field: "password", env: "REGISTRY_TOKEN" }],
    }],
  });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);
  const text = fake.sentMessages[0].text;
  expect(text).toContain("password → REGISTRY_TOKEN");
  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  await decision;
});

test("HTML in the command arrives escaped", async () => {
  const card = makeCard({ command: 'echo "<b>bold&stuff</b>"' });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  const text = fake.sentMessages[0].text;
  expect(text).toContain("&lt;b&gt;bold&amp;stuff&lt;/b&gt;");
  expect(text).not.toContain("<b>bold");

  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  await decision;
});

test("a 10-item card renders EVERY item and mapping, keyboard on the last message (P1-i/ii)", async () => {
  const items = Array.from({ length: 10 }, (_, index) => ({
    name: `Item Number ${index} With A Fairly Long Display Name For Padding Purposes`,
    description: "d".repeat(500),
    bindings: [
      { field: `custom_field_number_${index}_${"x".repeat(40)}`, env: `A_RATHER_LONG_ENV_VARIABLE_NAME_${"Y".repeat(80)}_${index}` },
      { field: "password", env: `PASSWORD_ENV_${index}` },
    ],
  }));
  const card = makeCard({ items });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length >= 1);
  // Give the multi-message send a moment to finish.
  await waitFor(() => {
    const last = fake.sentMessages.at(-1);
    return Boolean(last && last.reply_markup);
  });
  const combined = fake.sentMessages.map((message) => message.text).join("\n");
  for (let index = 0; index < 10; index++) {
    expect(combined).toContain(`custom_field_number_${index}_${"x".repeat(40)} → A_RATHER_LONG_ENV_VARIABLE_NAME_${"Y".repeat(80)}_${index}`);
    expect(combined).toContain(`password → PASSWORD_ENV_${index}`);
  }
  expect(combined).toContain("docker login");
  // Keyboard only on the final message.
  for (const message of fake.sentMessages.slice(0, -1)) {
    expect(message.reply_markup).toBeUndefined();
  }
  expect(fake.sentMessages.at(-1)!.reply_markup).toBeDefined();
  expect(fake.sentMessages.length).toBeGreaterThan(1);

  fake.pressButton(`ap:${card.id}:approve_1h`, ALLOWED_USER);
  const result = await decision;
  expect(result).toMatchObject({ approved: true, ttl: "1h" });
});

test("an unrenderable card rejects the request instead of sending a truncated one (P1-iii)", async () => {
  // One block that cannot fit a message even alone: an item whose mapping is
  // pathologically long (10 near-max custom names full of HTML escapables).
  const monstrous = {
    name: "Monster",
    description: "",
    bindings: Array.from({ length: 10 }, (_, index) => ({
      field: `${"&".repeat(60)}${index.toString().padStart(3, "0")}`,
      env: `E${"N".repeat(120)}${index}`,
    })),
  };
  expect(() => buildApprovalMessages(makeCard({ items: [monstrous] })))
    .toThrow("cannot be rendered completely");
  await expect(approver.requestApproval(makeCard({ items: [monstrous] }), 5000))
    .rejects.toThrow("cannot be rendered completely");
  // Nothing was parked or sent.
  expect(fake.sentMessages.length).toBe(0);
});

// -- Re-push: one live card per window (ADR-0006) ----------------------------

function makeRepushApprover(approvalCards: number): TelegramApprover {
  const instance = new TelegramApprover(
    {
      botToken: "TEST_TOKEN",
      chatId: "555",
      allowedUserIds: [ALLOWED_USER],
      apiBase: fake.url,
      approvalCards,
    },
    { onRevoke: () => null },
    { log: () => {} },
  );
  instance.start();
  return instance;
}

test("a window split into cards deletes the standing card and sends a new one", async () => {
  const repusher = makeRepushApprover(3);
  try {
    // 600ms window / 3 cards = a new card roughly every 200ms.
    const decision = repusher.requestApproval(makeCard(), 600);
    // The old card is deleted only after the new one lands, so wait on the
    // delete — waiting on the send alone races the replacement.
    await waitFor(() => fake.deletedMessageIds.length > 0, 2000);

    // The replacement is a fresh send (it pushes), never an edit of the old one.
    expect(fake.sentMessages.length).toBeGreaterThanOrEqual(2);
    expect(fake.sentMessages[1].text).toContain("重新提醒");
    // The buttons ride on the new card too, or the Owner cannot answer it.
    expect((fake.sentMessages[1].reply_markup?.inline_keyboard ?? []).flat().length).toBeGreaterThan(0);

    expect(await decision).toEqual({ approved: false, reason: "timeout" });
  } finally {
    repusher.stop();
  }
});

test("the abandoned window leaves a record instead of an empty chat", async () => {
  const repusher = makeRepushApprover(2);
  try {
    expect(await repusher.requestApproval(makeCard(), 300)).toEqual({ approved: false, reason: "timeout" });
    await waitFor(() => fake.sentMessages.some((message) => message.text.includes("已放弃")), 2000);
    // The dead card's buttons are stripped so a late tap cannot look live.
    expect(fake.editedMarkups.length).toBeGreaterThan(0);
    // Nothing is left to tap, so the record must not ring; the cards did.
    const gaveUp = fake.sentMessages.find((message) => message.text.includes("已放弃"))!;
    expect(gaveUp.disable_notification).toBe(true);
    const cards = fake.sentMessages.filter((message) => message !== gaveUp);
    expect(cards.every((message) => message.disable_notification === undefined)).toBe(true);
  } finally {
    repusher.stop();
  }
});

test("a decision on the standing card stops the re-push", async () => {
  const repusher = makeRepushApprover(5);
  try {
    const card = makeCard();
    const decision = repusher.requestApproval(card, 1000);
    await waitFor(() => fake.sentMessages.length === 1);
    fake.pressButton(`ap:${card.id}:approve_8h`, ALLOWED_USER);
    expect(await decision).toMatchObject({ approved: true, ttl: "8h" });

    const sentAtDecision = fake.sentMessages.length;
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(fake.sentMessages.length).toBe(sentAtDecision);
  } finally {
    repusher.stop();
  }
});

test("a how-to-get change is titled as one, not as a description change", () => {
  // The card kind drives the title. Reusing update_description here would ask
  // the Owner to approve a card headed "改条目描述" whose diff is about
  // something else — exactly what the render-completely contract forbids.
  const text = buildWriteMessages(makeWriteCard({
    kind: "update_how_to_get",
    lines: [
      { label: "现获取方式", value: "（未记录）", plain: true },
      { label: "新获取方式", value: "Settings → Developer → Tokens", plain: true },
    ],
  })).join("\n");
  expect(text).toContain("改获取方式");
  expect(text).not.toContain("改条目描述");
  expect(text).toContain("Settings → Developer → Tokens");
});

// -- Inline permission on Sightings (ADR-0009) --------------------------------

test("a sighting over inline permission offers inline-only and full revoke, silently", async () => {
  const card = makeSightingCard({ inline_shell: true, inline_grant: true, command: 'sh -c "tool --push"' });
  revokeHandles.set(card.id, 1);
  await approver.notifySighting(card);
  expect(fake.sentMessages.every((message) => message.disable_notification === true)).toBe(true);
  expect(fake.sentMessages[0].text).toContain("内联代码免审复用");
  expect(keyboardButtons(fake.sentMessages.length - 1).map((button) => button.callback_data))
    .toEqual([`ri:${card.id}`, `rv:${card.id}`]);

  fake.pressButton(`ri:${card.id}`, ALLOWED_USER);
  await waitFor(() => fake.editedMarkups.length === 1);
  expect(inlineRevokedCalls).toEqual([card.id]);
  expect(revokedCalls).toEqual([]);
  expect(fake.answeredCallbacks[0].text).toContain("内联权限");
  // The ordinary part is still live, so its revoke button must survive.
  const remaining = (fake.editedMarkups[0].reply_markup as { inline_keyboard: Array<Array<{ callback_data: string }>> })
    .inline_keyboard.flat().map((button) => button.callback_data);
  expect(remaining).toEqual([`rv:${card.id}`]);
});

test("an inline sighting shows all of the code even under worst-case escaping", async () => {
  // formatCommandDisplay bounds the display near 900 chars; every one of them
  // expanding to an HTML entity must still arrive whole.
  const code = `sh -c ${"<&".repeat(450)}END`;
  const card = makeSightingCard({ inline_shell: true, inline_grant: true, command: code });
  await approver.notifySighting(card);
  const combined = fake.sentMessages.map((message) => message.text).join("\n");
  // Counted separately: a chunk boundary may fall between the two entities.
  expect(combined.match(/&lt;/g)).toHaveLength(450);
  expect(combined.match(/&amp;/g)).toHaveLength(450);
  expect(combined).toContain("END");
  expect(fake.sentMessages.every((message) => message.text.length <= TELEGRAM_MESSAGE_LIMIT)).toBe(true);
  // Buttons ride on the last message only.
  expect(fake.sentMessages.at(-1)!.reply_markup).toBeDefined();
  for (const message of fake.sentMessages.slice(0, -1)) expect(message.reply_markup).toBeUndefined();
});

// -- /grants ------------------------------------------------------------------

function makeEntry(index: number, overrides: Partial<GrantListEntry> = {}): GrantListEntry {
  return {
    approval_id: crypto.randomUUID(),
    repo: `github.com/acme/repo-${index}`,
    client_name: "client-abc",
    items: [{ name: `Item ${index}`, fields: ["password"] }],
    expires_at: new Date(Date.UTC(2030, 0, 1, index)).toISOString(),
    ...overrides,
  };
}

test("/grants from the Owner in the chat lists grants as plain text, silently", async () => {
  grantEntries = [makeEntry(1), makeEntry(2, { inline_expires_at: "2030-01-02T03:04:05.000Z" })];
  fake.sendText("/grants", ALLOWED_USER, "555");
  await waitFor(() => fake.sentMessages.length === 1);
  const message = fake.sentMessages[0];
  expect(message.parse_mode).toBeUndefined();
  expect(message.disable_notification).toBe(true);
  expect(message.text).toContain("github.com/acme/repo-1");
  expect(message.text).toContain("Item 2（password）");
  expect(message.text).toContain("内联到期：2030-01-02 03:04 UTC");
  const buttons = keyboardButtons(0);
  // Only the entry with inline permission gets the inline-only button.
  expect(buttons.map((button) => button.callback_data)).toEqual([
    `ga:0:${grantEntries[0].approval_id}`,
    `gi:0:${grantEntries[1].approval_id}`,
    `ga:0:${grantEntries[1].approval_id}`,
  ]);
});

test("/grants is ignored from anyone but the Owner, and outside the configured chat", async () => {
  grantEntries = [makeEntry(1)];
  fake.sendText("/grants", OTHER_USER, "555");
  fake.sendText("/grants", ALLOWED_USER, "777");
  // A marker the approver does answer, so we know the two above were processed.
  fake.sendText("/grants@secretary_bot", ALLOWED_USER, "555");
  await waitFor(() => fake.sentMessages.length === 1);
  await new Promise((resolve) => setTimeout(resolve, 100));
  expect(fake.sentMessages).toHaveLength(1);
});

test("/grants pages in place and revokes from the listing", async () => {
  grantEntries = Array.from({ length: GRANTS_PAGE_SIZE * 2 + 3 }, (_, index) =>
    makeEntry(index, { inline_expires_at: "2030-02-01T00:00:00.000Z" }));
  fake.sendText("/grants", ALLOWED_USER, "555");
  await waitFor(() => fake.sentMessages.length === 1);
  expect(fake.sentMessages[0].text).toContain("第 1/3 页");
  const listingId = fake.sentMessages[0].message_id;

  fake.pressButton("gp:2", ALLOWED_USER, listingId);
  await waitFor(() => fake.editedTexts.length === 1);
  expect(fake.editedTexts[0].message_id).toBe(listingId);
  expect(fake.editedTexts[0].text).toContain("第 3/3 页");
  expect(fake.editedTexts[0].text).toContain(`#${GRANTS_PAGE_SIZE * 2 + 3} `);

  const target = grantEntries[GRANTS_PAGE_SIZE * 2];
  fake.pressButton(`gi:2:${target.approval_id}`, ALLOWED_USER, listingId);
  await waitFor(() => fake.editedTexts.length === 2);
  fake.pressButton(`ga:2:${target.approval_id}`, ALLOWED_USER, listingId);
  await waitFor(() => fake.editedTexts.length === 3);
  expect(approvalRevocations).toEqual([[target.approval_id, "inline"], [target.approval_id, "all"]]);
  expect(fake.answeredCallbacks.map((answer) => answer.text)).toContain("已吊销 1 行");
  expect(fake.editedTexts[2].text).not.toContain(target.repo);

  // A stranger cannot revoke through the listing.
  fake.pressButton(`ga:0:${grantEntries[0].approval_id}`, OTHER_USER, listingId);
  await waitFor(() => fake.answeredCallbacks.length === 4);
  expect(fake.answeredCallbacks[3].text).toBe("无权操作");
  expect(approvalRevocations).toHaveLength(2);
});

test("a full page of worst-case entries fits one message and every callback fits 64 bytes", () => {
  const long = "&<".repeat(200);
  const entries = Array.from({ length: GRANTS_PAGE_SIZE }, (_, index) => makeEntry(index, {
    repo: long,
    client_name: long,
    items: Array.from({ length: 10 }, (_, item) => ({ name: `${long}${item}`, fields: ["password", "username"] })),
    inline_expires_at: "2030-02-01T00:00:00.000Z",
  }));
  const view = buildGrantsPage([...entries, ...entries], 0);
  expect(view.text.length).toBeLessThanOrEqual(4096);
  // Plain text: nothing is escaped, so what the Owner sees is the raw string.
  expect(view.text).toContain("&<&<");
  const callbacks = view.reply_markup.inline_keyboard.flat().map((button) => button.callback_data);
  expect(callbacks).toHaveLength(GRANTS_PAGE_SIZE * 2 + 1);
  for (const data of callbacks) expect(new TextEncoder().encode(data).length).toBeLessThanOrEqual(64);
});

test("a write record is sent silently: it asks nothing of the Owner", async () => {
  await approver.notifyWrite({
    id: crypto.randomUUID(),
    headline: "录入完成：Registry Token",
    lines: [{ label: "字段", value: "password" }],
    repo: "acme/site",
    host: "buildbox",
    user: "randy",
    client_name: "client-abc",
  });
  expect(fake.sentMessages).toHaveLength(1);
  expect(fake.sentMessages[0].disable_notification).toBe(true);
});
