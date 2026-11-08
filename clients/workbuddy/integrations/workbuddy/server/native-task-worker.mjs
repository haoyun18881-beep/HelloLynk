import crypto from "node:crypto";
import nativeTaskIndex from "../../../clients/core/hellolynk-native-task-index.cjs";
import { createNativeInboxRuntime } from "../../../clients/core/hellolynk-native-inbox-runtime.mjs";
import { readNativeReplyRoute } from "../../../clients/core/hellolynk-native-reply-routes.mjs";
import { createWorkBuddyNativeTaskClient } from "./native-task-cdp.mjs";
import { createWorkBuddyOriginLedger, importWorkBuddyOriginDrops, markWorkBuddyActiveScope } from "./origin-routes.mjs";

const { createNativeTaskIndex } = nativeTaskIndex;
const digest = value => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
const failure = code => Object.assign(new Error(code), { code });
const REFUSED_TRUST = new Set(["workbuddy_native_mcp_config_mismatch", "workbuddy_native_mcp_disabled", "workbuddy_native_mcp_approval_failed"]);
const unsent = () => Object.assign(failure("workbuddy_native_not_submitted"), { nativeDispatchStarted: false });
const uuidFor = batchId => { const h = digest(batchId); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`; };

// The shared receiver owns batching, immediate delivery receipts and the one
// recovery retry. This bridge retains WorkBuddy's native trust and chat APIs.
export function startWorkBuddyNativeTaskWorker({ adapter, debugEndpoint = process.env.HELLOLYNK_WORKBUDDY_DEBUG_ENDPOINT || "http://127.0.0.1:9337", recoveryMs = 5_000,
  acquireLease, readNoticeLocale, clientFactory = createWorkBuddyNativeTaskClient, storeFactory = openNativeTaskStore,
  originInbox = null, readRoute = readNativeReplyRoute, importOrigins = importWorkBuddyOriginDrops, markScope = markWorkBuddyActiveScope, mcpTrust = null } = {}) {
  if (!adapter || !Number.isSafeInteger(recoveryMs) || recoveryMs < 10) throw failure("workbuddy_native_worker_options_invalid");
  let stopped = false, store, ledger, client, trustSettled = false, status = { status: "starting" };
  // Settle the request once per service process (a new release starts a new
  // one). Approval checks WorkBuddy's exact current entry and approves only
  // if still untrusted, so trust the person gave first also settles it. A
  // refusal (changed, disabled, declined) leaves trust to the person; trust
  // the person withdraws afterwards is never reopened.
  async function settleRequestedTrust(registration) {
    const expected = await mcpTrust.take();
    if (!expected) { trustSettled = true; return registration; }
    if (stopped) return registration;
    let approved;
    try { approved = await client.approveHelloLynkMcp(expected); }
    catch (error) {
      if (REFUSED_TRUST.has(error?.code)) { trustSettled = true; await mcpTrust.settle(); }
      throw error;
    }
    if (approved?.trusted === true) { trustSettled = true; await mcpTrust.settle(); }
    return approved || registration;
  }

  const native = {
    async beforeTick() {
      client ||= clientFactory({ debugEndpoint, ownedSessionIds: [] });
      if ((await client.probe())?.available !== true) throw failure("workbuddy_native_preload_unavailable");
    },
    async configureScope(scope) {
      store = await storeFactory(scope); ledger = createWorkBuddyOriginLedger(scope);
      if (originInbox) await markScope(originInbox, scope).catch(() => {});
    },
    async releaseScope() { await store?.close(); store = ledger = client = null; },
    async legacyDelivery(item) {
      const old = item.replyToClientMessageId ? await ledger.get(item.localMessageId) : store.getDelivery(digest(item.conversationKey), item.localMessageId);
      return old ? /unknown|dispatching|creating/.test(old.status) ? "unknown" : "sent" : null;
    },
    legacyCarrier(key) { const old = store.getConversation(digest(key)); return old?.status === "created" ? old.nativeSessionId : null; },
    async prepare(scope, state) {
      client = clientFactory({ debugEndpoint, ownedSessionIds: [...new Set([...store.listSessions("created"), ...Object.values(state.carriers)])] });
      let registration = await client.mcpRegistrationStatus({ connect: true });
      if (mcpTrust && !trustSettled) registration = await settleRequestedTrust(registration);
      const available = new Set((registration.tools || []).filter(t => t.enabled).map(t => t.name));
      const allowed = registration.trusted === true && registration.enabled === true;
      if (!allowed || !["hellolynk_claim_message", "hellolynk_send_authorized_message", "hellolynk_reply_authorized_message"].every(name => available.has(name)))
        throw failure(allowed && registration.status != null && registration.status !== "ready" ? "workbuddy_native_mcp_not_ready" : "workbuddy_native_mcp_registration_required");
    },
    async listConversations(query = {}) {
      if (query.targetConversationId) {
        const id = query.targetConversationId, valid = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(id);
        const current = valid ? await client.inspectOrigin(id).catch(() => null) : null;
        const state = !valid ? 'deleted' : !current ? 'unavailable' : !current.present ? 'deleted' : current.archived ? 'archived' : current.busy ? 'active' : 'idle';
        return { conversations: [{ targetConversationId: id, title: id, project: '', state }], coverage: 'partial', exactTargetSupported: true };
      }
      return client.listConversations();
    },
    async inspectThread(id) {
      const current = await client.inspectOrigin(id);
      if (typeof current?.present !== "boolean" || typeof current?.busy !== "boolean") throw failure("workbuddy_native_lifecycle_unknown");
      return { state: !current.present ? "deleted" : current.archived ? "archived" : "present", thread: { status: current.busy ? "active" : "idle" } };
    },
    canNotifyOrigin(value) { return value?.state === "present" && value.thread?.status === "idle"; },
    async call(operation, args, context) {
      if (operation === "list_threads") { if ((await client.probe())?.available !== true) throw failure("workbuddy_native_preload_unavailable"); return {}; }
      let id = args.threadId;
      // All preparation precedes prompt submission. A failed create or route
      // save may leave a carrier, but must not consume a native send attempt.
      try {
        if (operation === "create_thread") {
          // WorkBuddy accepts a caller-chosen conversation ID. Recover a lost
          // create receipt by checking this exact ID, without opening a window.
          id = uuidFor(context.batchId);
          let existing;
          try { existing = await client.inspectOrigin(id); } catch { throw unsent(); }
          if (!await context.stillCurrent()) throw unsent();
          if (existing?.present !== true) await client.create({ nativeSessionId: id, title: "HelloLynk" });
          else if (existing.archived) throw Object.assign(failure("workbuddy_native_carrier_closed"),
            { nativeDispatchStarted: false, nativeCarrierClosedBeforeDispatch: true });
          await context.rememberThread(id);
        }
        if (!await context.stillCurrent()) throw unsent();
      } catch (error) {
        if (error?.nativeDispatchStarted === false) throw error;
        throw Object.assign(failure(error?.code || "workbuddy_native_not_submitted"), { nativeDispatchStarted: false });
      }
      const result = await client.sendToIdle({ nativeSessionId: id, clientRequestId: `hellolynk-${context.batchId}`, text: args.prompt });
      if (["busy", "missing", "archived", "lifecycle_unknown"].includes(result?.status)) throw unsent();
      if (!["queued_unconfirmed", "submitted_unconfirmed"].includes(result?.status)) throw failure("workbuddy_native_dispatch_unknown");
      status = { status: "delivered", nativeSessionId: id };
      return { ok: true, threadId: id };
    },
  };
  const runtime = createNativeInboxRuntime({ adapterId: "workbuddy", native, acquireLease, readNoticeLocale, pollMs: recoveryMs,
    adapter: { nativeTaskScope: () => adapter.getNativeTaskScope(), inboxBatch: (...args) => adapter.inboxBatch(...args),
      async listPendingMessages(input) {
        // Import the send-origin hook before grouping replies by destination.
        if (originInbox) await importOrigins(originInbox, await adapter.getNativeTaskScope()).catch(() => {});
        return adapter.listPendingMessages(input);
      } }, readReplyRoute: readRoute, onError: e => { if (e.operation !== "directory") status = { status: "unavailable", errorCode: e.code }; } });
  const tick = () => runtime.tick().catch(error => { status = { status: "unavailable", errorCode: error.code || error.message }; });
  const ready = tick();
  runtime.start();
  return Object.freeze({ ready, tick, get status() { return { ...status }; }, async open(id) {
    if (!client) throw failure("workbuddy_native_task_not_owned"); return client.open(id);
  }, async close() { stopped = true; await runtime.close(); } });
}
export async function openNativeTaskStore(scope) {
  if (scope?.adapterId !== "workbuddy") throw failure("workbuddy_native_scope_invalid");
  return createNativeTaskIndex(scope);
}
