import { afterEach, beforeEach, expect, test } from "bun:test";
import type { ApprovalCard, SightingCard } from "../src/approver.ts";
import { buildApprovalMessages, TelegramApprover } from "../src/approver_telegram.ts";
import { startFakeTelegram, type FakeTelegram } from "./helpers/fake_telegram.ts";

const ALLOWED_USER = 42;
const OTHER_USER = 999;

let fake: FakeTelegram;
let approver: TelegramApprover;
let revokedCalls: string[];
// A durable-store stand-in: sighting id -> number of grant rows it deletes.
let revokeHandles: Map<string, number>;

beforeEach(async () => {
  fake = await startFakeTelegram();
  revokedCalls = [];
  revokeHandles = new Map();
  approver = new TelegramApprover(
    { botToken: "TEST_TOKEN", chatId: "555", allowedUserIds: [ALLOWED_USER], apiBase: fake.url },
    {
      onRevoke: (sightingId) => {
        revokedCalls.push(sightingId);
        return revokeHandles.get(sightingId) ?? null;
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

test("renders the approval card with escaped command, item name, and 4 buttons", async () => {
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
  expect(buttons.length).toBe(4);
  expect(buttons.map((button) => button.callback_data)).toEqual([
    `ap:${card.id}:approve_1h`,
    `ap:${card.id}:approve_8h`,
    `ap:${card.id}:approve_7d`,
    `ap:${card.id}:deny`,
  ]);
  expect(buttons.map((button) => button.text).join(" ")).toContain("批准 1 小时");

  fake.pressButton(`ap:${card.id}:deny`, ALLOWED_USER);
  await decision;
});

test("inline shell card gets only approve_once and deny buttons", async () => {
  const card = makeCard({ inline_shell: true, command: 'sh -c "echo hi"' });
  const decision = approver.requestApproval(card, 5000);
  await waitFor(() => fake.sentMessages.length === 1);

  const buttons = keyboardButtons(0);
  expect(buttons.length).toBe(2);
  expect(buttons[0].text).toContain("批准本次执行");
  expect(buttons[0].callback_data).toBe(`ap:${card.id}:approve_once`);
  expect(buttons[1].callback_data).toBe(`ap:${card.id}:deny`);
  expect(fake.sentMessages[0].text).toContain("内联 shell 代码");

  fake.pressButton(`ap:${card.id}:approve_once`, ALLOWED_USER);
  const result = await decision;
  expect(result).toMatchObject({ approved: true, ttl: "once", decided_by: String(ALLOWED_USER) });
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

test("notifySighting sends a revoke button and pressing it calls onRevoke by id", async () => {
  const card = makeSightingCard();
  revokeHandles.set(card.id, 2);
  await approver.notifySighting(card);
  expect(fake.sentMessages.length).toBe(1);
  expect(fake.sentMessages[0].text).toContain("密钥免审复用");
  expect(fake.sentMessages[0].text).toContain("授权到期");

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
