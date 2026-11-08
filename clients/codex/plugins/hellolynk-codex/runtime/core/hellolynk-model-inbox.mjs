import { readNativeReplyRoute } from "./hellolynk-native-reply-routes.mjs";
import { setTimeout as delay } from "node:timers/promises";
import { readNativeInboxBatchDispatch } from "./hellolynk-native-inbox-runtime.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const READS = new Set(["list", "read", "pending", "count"]);
const fail = code => { throw Object.assign(new Error(code), { code }); };
export function modelInboxCaller(value) {
  if (!value || typeof value !== "object" || !ID.test(value.threadId || "")) fail("model_inbox_context_unavailable");
  // Aliases are supplied by a verified native bridge, never by tool arguments.
  if (value.aliases != null && (!Array.isArray(value.aliases) || value.aliases.length > 2
    || value.aliases.some(id => !ID.test(id)))) fail("model_inbox_context_unavailable");
  return { threadId: value.threadId, ...(value.aliases?.length ? { aliases: [...new Set(value.aliases)] } : {}) };
}

// Request-local only. The dispatcher keeps its original, unscoped operations.
export async function runModelInbox(request, io) {
  const { operation, query = {}, scope = "current" } = request;
  if (![...READS, "claim", "assertReply"].includes(operation)
    || scope !== "current") fail("model_inbox_scope_invalid");
  const caller = modelInboxCaller(request.caller);
  const nativeIds = new Set([caller.threadId, ...(caller.aliases || [])]);
  const assignmentCache = new Map(), messageAssignments = new Map();
  async function preparePage(messages) {
    if (!messages.length) return;
    const rows = await io.assignments(messages.map(message => message.localMessageId));
    for (const message of messages) messageAssignments.set(message.localMessageId, rows[message.localMessageId] ?? null);
  }
  const nativeThread = async assignment => {
    if (!assignment) return null;
    if (assignment.nativeThreadId) return assignment.nativeThreadId;
    if (!assignmentCache.has(assignment.batchId)) {
      assignmentCache.set(assignment.batchId, (await readNativeInboxBatchDispatch(io.nativeScope, assignment.batchId))?.threadId || null);
    }
    return assignmentCache.get(assignment.batchId);
  };
  const targetThread = target => {
    const prefix = io.nativeScope.adapterId === "claude-code" ? "claude-original:" : io.nativeScope.adapterId + "-origin:";
    return typeof target === "string" && target.startsWith(prefix) ? target.slice(prefix.length) : null;
  };
  async function assertAssignment(assignment) {
    if (!assignment) fail("model_inbox_unassigned");
    const deadline = Date.now() + 5_000;
    while (true) {
      const owner = assignment.nativeThreadId || targetThread(assignment.target);
      if (owner) {
        if (!nativeIds.has(owner)) fail("model_inbox_other_conversation");
        return;
      }
      const dispatch = await readNativeInboxBatchDispatch(io.nativeScope, assignment.batchId);
      if (dispatch?.threadId) {
        if (!nativeIds.has(dispatch.threadId)) fail("model_inbox_other_conversation");
        return;
      }
      // Codex creates and prompts atomically: its first claim can precede the
      // create response. Wait only for the authoritative owner, never guess it.
      if (!dispatch?.pending) {
        // Confirm can pin the owner and remove runtime state between our reads.
        const latest = await io.assignment({ batchId: assignment.batchId });
        if (latest?.nativeThreadId) { assignment = latest; continue; }
        fail("model_inbox_unassigned");
      }
      if (Date.now() >= deadline) fail("model_inbox_owner_pending");
      await delay(100);
      assignment = await io.assignment({ batchId: assignment.batchId });
      if (!assignment) fail("model_inbox_unassigned");
    }
  }
  async function owns(message, assert = false) {
    const assignment = messageAssignments.has(message.localMessageId) ? messageAssignments.get(message.localMessageId)
      : await io.assignment({ localMessageId: message.localMessageId });
    if (assignment) {
      if (assert) { await assertAssignment(assignment); return true; }
      const owner = await nativeThread(assignment);
      if (owner) return nativeIds.has(owner);
      // A known original target is immutable. Never infer historical ownership
      // from a carrier that may since have been closed and recreated.
      return nativeIds.has(targetThread(assignment.target));
    }
    if (message.targetConversationId && message.replyToClientMessageId) fail("model_inbox_route_invalid");
    if (message.targetConversationId) return nativeIds.has(message.targetConversationId);
    if (message.replyToClientMessageId) {
      return nativeIds.has((await readNativeReplyRoute(io.nativeScope, message))?.threadId);
    }
    if (assert) fail("model_inbox_unassigned");
    return false; // New, unassigned mail belongs to the backend dispatcher.
  }
  async function assertMessage() {
    const message = await io.metadata(query);
    if (!await owns(message, true)) fail("model_inbox_other_conversation");
    return message;
  }
  async function history({ count = false } = {}) {
    const selected = []; let unread = 0, before = query.before;
    while (true) {
      const page = await io.list(before == null ? {} : { before });
      if (!Array.isArray(page.messages)) fail("model_inbox_response_invalid");
      await preparePage(page.messages);
      for (const message of page.messages) {
        if (await owns(message)) {
          if (count) unread += Number(message.unread === true);
          else selected.push(message);
        }
        if (!count && selected.length === 10) return { messages: selected };
      }
      if (!page.messages.length) return count ? unread : { messages: selected };
      const next = page.messages.at(-1).localMessageId;
      if (!next || next === before) fail("model_inbox_cursor_invalid");
      before = next;
    }
  }
  async function pending({ count = false } = {}) {
    const selected = []; let total = 0, cursor = query.cursor ?? 0;
    while (true) {
      const page = await io.pending({ cursor });
      if (!Array.isArray(page.messages)) fail("model_inbox_response_invalid");
      await preparePage(page.messages);
      for (const message of page.messages) if (await owns(message)) {
        if (count) total++;
        else {
          selected.push(message);
          if (selected.length === 1000) return { messages: selected, nextCursor: message.receiptSeq };
        }
      }
      if (page.nextCursor == null) return count ? total : { messages: selected, nextCursor: null };
      if (!Number.isSafeInteger(page.nextCursor) || page.nextCursor <= cursor) fail("model_inbox_cursor_invalid");
      cursor = page.nextCursor;
    }
  }
  if (operation === "list") return history();
  if (operation === "pending") return pending();
  if (operation === "count") {
    const humanUnreadCount = await history({ count: true });
    const aiPendingCount = await pending({ count: true });
    return { unreadCount: humanUnreadCount, humanUnreadCount, aiPendingCount, scope };
  }
  if (operation === "read") {
    await assertMessage();
    return io.read(query);
  }
  if (operation === "claim") {
    if (query.batchId) {
      const assignment = await io.assignment({ batchId: query.batchId });
      await assertAssignment(assignment);
    } else await assertMessage();
    return io.claim(query);
  }
  await assertMessage(); // Before reply-origin registration as well as send.
  return { allowed: true };
}

const MODEL_TOOLS = Object.freeze({
  hellolynk_get_unread_count: "count", hellolynk_list_authorized_inbox_messages: "list",
  hellolynk_read_authorized_inbox_message: "read", hellolynk_list_pending_messages: "pending",
  hellolynk_claim_message: "claim", hellolynk_reply_authorized_message: "reply",
});
export const isModelInboxTool = name => Object.hasOwn(MODEL_TOOLS, name);
export async function prepareModelInboxInvocation(adapter, { name, args = {}, caller, readEnvelope = false, detailTarget = null }) {
  const operation = MODEL_TOOLS[name];
  if (!operation) return { adapter, args, finish: value => value };
  if (!args || typeof args !== "object" || Array.isArray(args)) fail("model_inbox_scope_invalid");
  if (Object.hasOwn(args, "scope")) fail("model_inbox_scope_invalid");
  const checkedCaller = modelInboxCaller(caller);
  if (typeof adapter?.modelInbox !== "function") fail("model_inbox_unavailable");
  const clean = { ...args };
  const cursor = operation === "pending" ? clean.cursor : undefined;
  if (operation === "pending") {
    if (cursor != null && (!Number.isSafeInteger(cursor) || cursor < 0)) fail("model_inbox_scope_invalid");
    delete clean.cursor;
  }
  let last;
  const call = async (op, query = {}) => {
    last = await adapter.modelInbox({ operation: op, scope: "current", caller: checkedCaller, query });
    return last;
  };
  let assertedReply = null;
  async function assertReply(query) {
    const key = JSON.stringify([query.localMessageId, query.conversationKey]);
    if (assertedReply === key) return;
    await call('assertReply', { localMessageId: query.localMessageId, conversationKey: query.conversationKey });
    assertedReply = key;
  }
  const scoped = { ...adapter,
    assertModelInboxReply: assertReply,
    replyAuthorizedMessage: async query => { await assertReply(query); return adapter.replyAuthorizedMessage(query); },
    readUnreadCount: () => call("count"),
    listAuthorizedInboxMessages: (query = {}) => call("list", query),
    readAuthorizedInboxMessage: async (localMessageId, conversationKey) => {
      const result = await call("read", { localMessageId, conversationKey });
      return readEnvelope ? result : result.message;
    },
    listPendingMessages: (query = {}) => call("pending", { ...(query || {}), ...(cursor == null ? {} : { cursor }) }),
    listPendingAuthorizedInboxMessages: () => call("pending", cursor == null ? {} : { cursor }),
    claimMessage: (localMessageId, conversationKey) => call("claim", { localMessageId, conversationKey }),
    claimAuthorizedInboxMessage: (localMessageId, conversationKey) => call("claim", { localMessageId, conversationKey }),
    claimBatch: batchId => call("claim", { batchId }),
    claimInboxBatch: batchId => call("claim", { batchId }),
  };
  function finish(value) {
    if (!READS.has(operation)) return value;
    if (!value || value.isError || value.ok === false || value.structuredContent?.ok === false) return value;
    const detail = { scope: "current",
      ...(last?.nextCursor != null ? { nextCursor: last.nextCursor } : {}) };
    if (operation === "count" && last) Object.assign(detail, {
      humanUnreadCount: last.humanUnreadCount, aiPendingCount: last.aiPendingCount,
    });
    if (value.structuredContent) {
      const structuredContent = detailTarget && value.structuredContent[detailTarget]
        ? { ...value.structuredContent, [detailTarget]: { ...value.structuredContent[detailTarget], ...detail } }
        : { ...value.structuredContent, ...detail };
      const originalJson = JSON.stringify(value.structuredContent), projected = JSON.stringify(structuredContent);
      let hasProjection = false;
      const content = (value.content || []).map(item => {
        if (item.type !== 'text') return item;
        try {
          if (JSON.stringify(JSON.parse(item.text)) === originalJson) { hasProjection = true; return { ...item, text: projected }; }
        } catch { /* Ordinary result text. */ }
        return item;
      });
      if (operation === 'count') return { ...value, structuredContent, content: [
        { type: 'text', text: '当前对话：人类未读 ' + last.humanUnreadCount + ' 条；AI 待处理 ' + last.aiPendingCount + ' 条。' },
        { type: 'text', text: projected },
      ] };
      if (!hasProjection) content.push({ type: 'text', text: projected });
      return { ...value, structuredContent, content };
    }
    return { ...value, ...detail };
  }
  return { adapter: scoped, args: clean, finish };
}
