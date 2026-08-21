// Fake Telegram Bot API server for integration tests.
//
// Implements just enough of sendMessage / getUpdates / answerCallbackQuery /
// editMessageReplyMarkup for the TelegramApprover's long-poll loop, including
// offset-based acknowledgement so updates are never redelivered.

export type FakeSentMessage = {
  chat_id: string | number;
  text: string;
  reply_markup?: { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> };
};

export type FakeTelegram = {
  /** Base URL, e.g. http://127.0.0.1:PORT — pass as the approver's apiBase. */
  url: string;
  /** Parsed sendMessage bodies in send order. */
  sentMessages: FakeSentMessage[];
  /** Parsed answerCallbackQuery bodies in order. */
  answeredCallbacks: Array<{ callback_query_id: string; text?: string }>;
  /** Parsed editMessageReplyMarkup bodies in order. */
  editedMarkups: Array<{ chat_id: string | number; message_id: number; reply_markup: unknown }>;
  /** Enqueue a callback_query update, delivered by the pending or next getUpdates call. */
  pressButton(callbackData: string, fromUserId: number): void;
  stop(): void;
};

const HOLD_MS = 1000;

export async function startFakeTelegram(): Promise<FakeTelegram> {
  const sentMessages: FakeSentMessage[] = [];
  const answeredCallbacks: FakeTelegram["answeredCallbacks"] = [];
  const editedMarkups: FakeTelegram["editedMarkups"] = [];

  type Update = {
    update_id: number;
    callback_query: {
      id: string;
      from: { id: number };
      message: { message_id: number; chat: { id: string | number } };
      data: string;
    };
  };

  const queue: Update[] = [];
  let nextUpdateId = 1;
  let nextCallbackId = 1;
  let nextMessageId = 1;
  let lastMessage: { message_id: number; chat_id: string | number } = { message_id: 0, chat_id: 0 };
  let waiter: { resolve: (updates: Update[]) => void; timer: ReturnType<typeof setTimeout> } | null = null;

  function deliverToWaiter(): void {
    if (!waiter || queue.length === 0) return;
    const { resolve, timer } = waiter;
    waiter = null;
    clearTimeout(timer);
    resolve([...queue]);
  }

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const match = url.pathname.match(/^\/bot[^/]+\/([A-Za-z]+)$/);
      if (!match || request.method !== "POST") {
        return Response.json({ ok: false, description: "not found" }, { status: 404 });
      }
      const method = match[1];
      const body = await request.json().catch(() => ({})) as Record<string, unknown>;

      if (method === "sendMessage") {
        const messageId = nextMessageId++;
        lastMessage = { message_id: messageId, chat_id: body.chat_id as string | number };
        sentMessages.push({
          chat_id: body.chat_id as string | number,
          text: String(body.text ?? ""),
          reply_markup: body.reply_markup as FakeSentMessage["reply_markup"],
        });
        return Response.json({ ok: true, result: { message_id: messageId } });
      }

      if (method === "getUpdates") {
        const offset = Number(body.offset ?? 0);
        // Everything below `offset` is acknowledged — drop it for good.
        while (queue.length && queue[0].update_id < offset) queue.shift();
        if (queue.length) return Response.json({ ok: true, result: [...queue] });
        // Long poll: hold until an update arrives or ~1s passes.
        const updates = await new Promise<Update[]>((resolve) => {
          if (waiter) {
            // A second concurrent poll releases the first one empty.
            clearTimeout(waiter.timer);
            waiter.resolve([]);
          }
          const timer = setTimeout(() => {
            waiter = null;
            resolve([]);
          }, HOLD_MS);
          waiter = { resolve, timer };
        });
        return Response.json({ ok: true, result: updates });
      }

      if (method === "answerCallbackQuery") {
        answeredCallbacks.push({
          callback_query_id: String(body.callback_query_id ?? ""),
          text: body.text as string | undefined,
        });
        return Response.json({ ok: true, result: true });
      }

      if (method === "editMessageReplyMarkup") {
        editedMarkups.push({
          chat_id: body.chat_id as string | number,
          message_id: Number(body.message_id),
          reply_markup: body.reply_markup,
        });
        return Response.json({ ok: true, result: true });
      }

      return Response.json({ ok: false, description: `unsupported method: ${method}` }, { status: 400 });
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}`,
    sentMessages,
    answeredCallbacks,
    editedMarkups,
    pressButton(callbackData: string, fromUserId: number): void {
      queue.push({
        update_id: nextUpdateId++,
        callback_query: {
          id: `cb-${nextCallbackId++}`,
          from: { id: fromUserId },
          message: { message_id: lastMessage.message_id, chat: { id: lastMessage.chat_id } },
          data: callbackData,
        },
      });
      deliverToWaiter();
    },
    stop(): void {
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve([]);
        waiter = null;
      }
      server.stop(true);
    },
  };
}
