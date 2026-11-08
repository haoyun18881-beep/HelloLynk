import { projectInboxReadState } from "../../../clients/core/hellolynk-inbox-read-state.mjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { createNativeInboxRuntime } from "../../../clients/core/hellolynk-native-inbox-runtime.mjs";
import { readNativeNoticeLocale } from "../../../clients/core/hellolynk-native-notice.mjs";
import { dispatchHelloLynkInbound, resolveHelloLynkInboundRoute } from "./channel-dispatch.mjs";
import { resolveOpenClawOrigin } from "./native-origins.mjs";

const STATE_CONTRACT = "hellolynk-openclaw-authorized-read-state-v1";
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const NATIVE_TARGET_ID = /^[a-z0-9][a-z0-9_-]{0,63}:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

export async function runOpenClawNeutralReadRuntime(options = {}) {
  const runtime = createOpenClawNeutralReadRuntime(options);
  return runtime.run();
}

export function createOpenClawNeutralReadRuntime(options = {}) {
  const adapter = requireAdapter(options.adapter);
  const account = requireAccount(options.account);
  const ctx = options.channelContext || {};
  const dispatch = options.dispatch || dispatchHelloLynkInbound;
  const readNoticeLocale = options.readNoticeLocale || readNativeNoticeLocale;
  const stateStore = options.stateStore || createFileReadStateStore(resolveStatePath(options, adapter, account));
  requireStateStore(stateStore);
  const pollIntervalMs = integer(options.pollIntervalMs, 5_000, 20, 60_000);
  const wait = options.wait || abortableWait;
  const log = options.log || ctx.log;
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.abortSignal?.addEventListener("abort", abort, { once: true });
  if (options.abortSignal?.aborted) abort();
  const origins = new Map(), active = new Set();
  let running, notified = 0, legacySnapshot;
  const legacyRecord = async key => {
    if (!stateStore.snapshot) return stateStore.get(key);
    legacySnapshot ||= stateStore.snapshot();
    return (await legacySnapshot)[key] || null;
  };
  const currentScope = () => {
    if (controller.signal.aborted || ["closed", "dead"].includes(adapter.state)) throw invalid("neutral_read_stopped");
    return adapter.binding;
  };
  const unsent = () => Object.assign(invalid("neutral_read_not_submitted"), { nativeDispatchStarted: false });
  const routeFor = (conversationKey, epoch = 0) => resolveHelloLynkInboundRoute(ctx, account,
    { conversationId: conversationKey, conversationType: "direct" }, ctx.channelRuntime, { sessionEpoch: epoch });
  const readOrigin = async (_scope, summary) => {
    try {
      const origin = await (options.readOrigin || resolveOpenClawOrigin)(ctx, adapter, summary);
      if (origin) origins.set(origin.threadId, origin);
      return origin;
    } catch (error) {
      if (error?.code === "openclaw_reply_origin_unavailable") return null;
      throw error;
    }
  };
  async function inspectThread(id) {
    if (active.has(id)) return { state: "present", thread: { status: "active" } };
    if (options.inspectThread) return options.inspectThread(id);
    const origin = origins.get(id);
    let sessionKey = origin?.sessionKey || id;
    let agentId = origin?.agentId || /^agent:([^:]+):/.exec(id)?.[1];
    // A reserved reply can outlive the pending metadata entry. Resolve only the
    // exact recorded native UUID; never redirect it to the agent's current chat.
    if (!agentId && /^[a-z0-9_-]+:[a-f0-9-]{36}$/.test(id)) {
      if (typeof ctx.hellolynkResolveSessionKeyById !== "function") throw invalid("neutral_read_session_state_unavailable");
      const [agent, sessionId] = id.split(":");
      agentId = agent;
      sessionKey = await ctx.hellolynkResolveSessionKeyById?.({ agentId, sessionId,
        storePath: ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId }) });
      if (!sessionKey) return { state: "deleted" };
      origins.set(id, { threadId: id, agentId, sessionId, sessionKey,
        storePath: ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId }) });
    }
    if (!agentId || typeof ctx.hellolynkGetSessionEntry !== "function") throw invalid("neutral_read_session_state_unavailable");
    const entry = await ctx.hellolynkGetSessionEntry({ agentId, sessionKey,
      storePath: ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId }),
      readConsistency: "latest", hydrateSkillPromptRefs: false });
    if (entry === undefined) return { state: "deleted" };
    if (!entry || typeof entry.sessionId !== "string") throw invalid("neutral_read_session_state_unavailable");
    if (origins.get(id)?.sessionId && entry.sessionId !== origins.get(id).sessionId) return { state: "deleted" };
    if (entry.archivedAt != null) return { state: "archived" };
    if (typeof ctx.hellolynkActiveSessionRun !== "function") throw invalid("neutral_read_session_state_unavailable");
    return { state: "present", sessionKey, nativeThreadId: `${agentId}:${entry.sessionId}`,
      thread: { status: active.has(id) || ctx.hellolynkActiveSessionRun(sessionKey) ? "active" : "idle" } };
  }
  // The SDK's onExecutionStarted / onAgentRunStart acknowledges admission.
  // Keep the native run alive, but don't make delivery wait for its completion.
  function acceptedDispatch(id, message, input = {}) {
    return new Promise((resolve, reject) => {
      let accepted = false, started = false;
      const deadline = setTimeout(() => reject(invalid("neutral_read_acceptance_unknown")), options.acceptanceTimeoutMs || 30_000);
      const onAbort = () => reject(invalid("neutral_read_stopped"));
      controller.signal.addEventListener("abort", onAbort, { once: true });
      active.add(id);
      const work = Promise.resolve().then(() => dispatch(ctx, account, message, {
        adapter, ...input, abortSignal: controller.signal,
        onNativeSubmissionStart() { started = true; },
        onNativeAccepted() {
          if (accepted) return;
          accepted = true; clearTimeout(deadline);
          controller.signal.removeEventListener("abort", onAbort);
          notified++;
          // The SDK has initialized this run's session before this callback.
          // Persist its native UUID, never the reusable route key, as owner.
          Promise.resolve().then(() => input.rememberNativeThread ? input.rememberNativeThread() : id)
            .then(threadId => resolve({ ok: true, threadId }), reject);
        },
      }));
      work.then(() => { if (!accepted) reject(invalid("neutral_read_acceptance_unknown")); }, error => {
        if (!accepted) { if (!started) error.nativeDispatchStarted = false; reject(error); }
        else log?.warn?.(`hellolynk native run ended: ${safeCode(error)}`);
      }).finally(() => {
        active.delete(id); clearTimeout(deadline);
        controller.signal.removeEventListener("abort", onAbort);
      });
    });
  }
  async function contactRequests(scope) {
    // Existing request notifications retain their ledger; ordinary messages no
    // longer read bodies here or wait for claim/finish/task outcomes.
    const result = await adapter.listAuthorizedContactRequests();
    for (const item of result.requests || []) {
      const summary = normalizeSummary("contact_request", item, account);
      const key = processingKey(account.accountId, summary);
      if (await stateStore.get(key)) continue;
      const detail = await adapter.readAuthorizedContactRequest(summary.localId, summary.conversationKey);
      assertDetailMatchesSummary("contact_request", detail, summary);
      const route = routeFor(summary.conversationKey);
      const lifecycle = await inspectThread(route.routeSessionKey);
      if (lifecycle.state !== "deleted" && !(lifecycle.state === "present" && lifecycle.thread?.status === "idle")) continue;
      const noticeLocale = await readNoticeLocale();
      const current = currentScope();
      if (Object.keys(scope).some(key => current[key] !== scope[key])) throw invalid("neutral_read_scope_changed");
      await stateStore.put(key, stateRecord("unknown"));
      try {
        await acceptedDispatch(route.routeSessionKey, projectDispatchMessage("contact_request", detail, summary), { noticeLocale });
        await stateStore.put(key, stateRecord("completed"));
      } catch (error) { log?.warn?.(`hellolynk contact request held: ${safeCode(error)}`); }
    }
  }
  const native = {
    async listConversations(query = {}) {
      if (query.targetConversationId) {
        // Reusable session keys are carriers, not stable first-send addresses.
        // Resolve an exact UUID independently of the full catalog.
        const id = query.targetConversationId;
        const valid = NATIVE_TARGET_ID.test(id);
        const current = valid ? await inspectThread(id).catch(() => null) : null;
        const state = !valid || current?.sessionKey?.includes(":subagent:") ? "deleted"
          : ["archived", "deleted"].includes(current?.state) ? current.state
          : current?.state === "present" ? current.thread?.status : "unavailable";
        return { conversations: [{ targetConversationId: id, title: id, project: "", state }], coverage: "partial", exactTargetSupported: true };
      }
      if (typeof ctx.hellolynkListSessionEntries !== "function") throw invalid("openclaw_native_catalog_unavailable");
      const configured = ctx.cfg?.agents?.list || [];
      const agentIds = [...new Set([ctx.cfg?.agents?.defaults?.id || "main", ...configured.map(agent => agent.id)])];
      const conversations = [];
      for (const agentId of agentIds) {
        if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(agentId)) continue;
        const storePath = ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId });
        const rows = await ctx.hellolynkListSessionEntries({ agentId, storePath, readOnly: true, hydrateSkillPromptRefs: false, readConsistency: "latest" });
        for (const { sessionKey, entry } of rows) {
          if (!sessionKey.startsWith(`agent:${agentId}:`) || sessionKey.includes(":subagent:") || !NATIVE_TARGET_ID.test(`${agentId}:${entry.sessionId}`)) continue;
          conversations.push({ targetConversationId: `${agentId}:${entry.sessionId}`, title: entry.label || entry.displayName || entry.subject || entry.sessionId,
            project: configured.find(agent => agent.id === agentId)?.name || agentId,
            state: entry.archivedAt != null ? "archived" : ctx.hellolynkActiveSessionRun?.(sessionKey) ? "active" : "idle" });
        }
      }
      return { conversations, coverage: "complete", exactTargetSupported: true };
    },
    beforeTick() { currentScope(); legacySnapshot = null; },
    async configureScope() {
      const result = await adapter.activateAuthorizedInbox();
      if (result?.ok !== true || result.active !== true) throw invalid("neutral_read_activation_invalid");
    },
    async legacyDelivery(item) {
      const old = await legacyRecord(processingKey(account.accountId, normalizeSummary("message", item, account)));
      return old && ["inflight", "unknown", "completed"].includes(old.state) ? old.state === "completed" ? "sent" : "unknown" : null;
    },
    async legacyCarrier(key) {
      const old = await legacyRecord(sessionStateKey(account.accountId, { conversationKey: key, localDelegateId: adapterDelegate(account) }));
      return old && Number.isSafeInteger(old.epoch) ? routeFor(key, old.epoch).routeSessionKey : null;
    },
    async prepare(scope) {
      try { await contactRequests(scope); } catch (error) { log?.warn?.(`hellolynk contact request list held: ${safeCode(error)}`); }
    },
    inspectThread,
    canNotifyOrigin(value) { return value?.state === "present" && value.thread?.status === "idle"; },
    async call(operation, args, context) {
      if (operation === "list_threads") {
        if (typeof ctx.hellolynkGetSessionEntry !== "function" && !options.inspectThread) throw invalid("neutral_read_session_state_unavailable");
        // Round trip against the target, not a recent-conversations list.
        await inspectThread(routeFor("hellolynk-connection-probe").routeSessionKey);
        return {};
      }
      let submit;
      try {
        if (!await context.stillCurrent()) throw unsent();
        const original = context.original;
        const conversationKey = original ? context.batchId : context.target.slice("openclaw-conv:".length);
        const epoch = parseInt(crypto.createHash("sha256").update(context.batchId).digest("hex").slice(0, 12), 16);
        let id = args.threadId, createdRoute;
        if (operation === "create_thread") {
          createdRoute = routeFor(conversationKey, epoch);
          id = createdRoute.routeSessionKey;
        } else {
          const state = await inspectThread(id);
          if (state.state !== "present" || state.thread?.status !== "idle") throw unsent();
        }
        if (!await context.stillCurrent()) throw unsent();
        const origin = origins.get(id);
        if (original && !origin) throw unsent();
        submit = () => acceptedDispatch(id, { messageType: "inbox_batch", messageId: context.batchId,
          deliveryId: context.batchId, conversationId: conversationKey, conversationType: "direct",
          text: args.prompt, timestamp: new Date().toISOString(), senderPrincipalDisplayName: "HelloLynk",
          identityProvenanceState: "local_automatic_notice", attachments: [] },
        { origin: original ? origin : undefined, noticeLocale: context.noticeLocale,
          ...(!original ? { routeSessionKey: origin?.sessionKey || id } : {}),
          ...(createdRoute ? { rememberNativeThread: async () => {
            const agentId = createdRoute.agentId, sessionKey = createdRoute.routeSessionKey;
            const storePath = ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId });
            const entry = await ctx.hellolynkGetSessionEntry({ agentId, sessionKey, storePath,
              readConsistency: "latest", hydrateSkillPromptRefs: false });
            const threadId = `${agentId}:${entry?.sessionId}`;
            if (!NATIVE_TARGET_ID.test(threadId) || !await context.stillCurrent()) throw invalid("neutral_read_session_state_unavailable");
            await context.rememberThread(threadId);
            origins.set(threadId, { threadId, agentId, sessionKey, sessionId: entry.sessionId, storePath });
            return threadId;
          } } : {}) });
      } catch (error) {
        // Preparation cannot have submitted a native prompt. Keep the Host's
        // registered ticket reusable; uncertainty starts inside acceptedDispatch.
        throw Object.assign(invalid(safeCode(error)), { nativeDispatchStarted: false });
      }
      return submit();
    },
  };
  const runtime = createNativeInboxRuntime({ adapterId: "openclaw", native, acquireLease: options.acquireLease,
    readNoticeLocale,
    adapter: { nativeTaskScope: currentScope, listPendingMessages: input => adapter.listPendingMessages(input), inboxBatch: (...args) => adapter.inboxBatch(...args) },
    readReplyRoute: readOrigin, onError: event => { if (event.operation !== "directory") log?.warn?.(`hellolynk inbox held: ${event.code}`); } });
  async function cycle() { const before = notified; await runtime.tick(); return { processed: notified - before, empty: notified === before }; }
  async function close() { abort(); await runtime.close(); options.abortSignal?.removeEventListener("abort", abort); }
  async function run() {
    if (running) return running;
    running = (async () => {
      try {
        while (!controller.signal.aborted && !["dead", "closed"].includes(adapter.state)) {
          // Keep the existing cadence while delivery awaits native acceptance;
          // the shared runtime serializes delivery and services only metadata.
          void cycle().catch(error => { if (!controller.signal.aborted) log?.warn?.(`hellolynk inbox held: ${safeCode(error)}`); });
          await wait(pollIntervalMs, controller.signal);
        }
        return adapter.state === "dead" ? "neutral_host_adapter_unavailable" : null;
      } finally { await close(); }
    })();
    return running;
  }
  return Object.freeze({ cycle, run, close });
}

export function createMemoryReadStateStore(seed = {}) {
  const records = new Map(Object.entries(seed));
  const legacyHeld = [...records.values()].some((record) => ["inflight", "unknown"].includes(record?.state));
  return Object.freeze({
    async legacyHeld() { return legacyHeld; },
    async get(key) { return records.get(key) || null; },
    async put(key, value) { records.set(key, structuredClone(value)); },
    async delete(key) { records.delete(key); },
    snapshot() { return Object.fromEntries(records); },
  });
}

export function createFileReadStateStore(filePath) {
  const target = path.resolve(String(filePath || ""));
  let pending = Promise.resolve();
  function enqueue(operation) {
    const result = pending.then(operation);
    pending = result.catch(() => {});
    return result;
  }
  async function read() {
    try {
      const value = JSON.parse(await fs.readFile(target, "utf8"));
      if (value?.contract !== STATE_CONTRACT || !plain(value.records)) throw invalid("neutral_read_state_invalid");
      if (!Object.hasOwn(value, "legacyHeld")) {
        value.legacyHeld = Object.values(value.records).some((record) => ["inflight", "unknown"].includes(record?.state));
      }
      if (typeof value.legacyHeld !== "boolean") throw invalid("neutral_read_state_invalid");
      return value;
    } catch (error) {
      if (error?.code === "ENOENT") return { contract: STATE_CONTRACT, records: {}, legacyHeld: false };
      throw error;
    }
  }
  async function publish(value) {
    await fs.mkdir(path.dirname(target), { recursive: true });
    const temp = `${target}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
    let handle, owned = false;
    try {
      handle = await fs.open(temp, "wx", 0o600);
      owned = true;
      await handle.writeFile(JSON.stringify(value), "utf8");
      await handle.close();
      handle = null;
      await fs.rename(temp, target);
    } finally {
      await handle?.close().catch(() => {});
      // Never sweep other attempts or replace the original publication error.
      if (owned) await fs.unlink(temp).catch(() => {});
    }
  }
  return Object.freeze({
    async snapshot() { await pending; return (await read()).records; },
    async legacyHeld() { await pending; return (await read()).legacyHeld; },
    async get(key) { await pending; return (await read()).records[key] || null; },
    async put(key, record) {
      return enqueue(async () => {
        const value = await read();
        value.records[key] = record;
        await publish(value);
      });
    },
    async delete(key) {
      return enqueue(async () => {
        const value = await read();
        delete value.records[key];
        await publish(value);
      });
    },
  });
}

function normalizeSummary(kind, value, account) {
  if (!plain(value)) throw invalid("neutral_read_summary_invalid");
  const localId = safeId(kind === "message" ? value.localMessageId : value.localRecordId, "neutral_read_local_id_invalid");
  const conversationKey = safeId(value.conversationKey, "neutral_read_conversation_key_invalid");
  const localDelegateId = safeId(value.localDelegateId, "neutral_read_local_delegate_invalid");
  if (localDelegateId !== adapterDelegate(account)) throw invalid("neutral_read_local_delegate_mismatch");
  const peerDelegateId = kind === "message" && value.peerDelegateId != null
    ? safeId(value.peerDelegateId, "neutral_read_peer_delegate_invalid") : null;
  const contactId = kind === "message" && value.contactId != null
    ? safeId(value.contactId, "neutral_read_contact_invalid") : null;
  const replyToClientMessageId = kind === "message" && value.replyToClientMessageId != null
    ? safeId(value.replyToClientMessageId, "neutral_read_reply_origin_invalid") : null;
  return Object.freeze({ kind, localId, conversationKey, localDelegateId, peerDelegateId, contactId, replyToClientMessageId });
}

function assertDetailMatchesSummary(kind, detail, summary) {
  // contactId is mutable contact-book metadata, not the message's route.
  // Deleting/re-adding a saved contact must not revoke access to owned mail.
  // Replies use the latest Host detail and still require send authorization.
  if (!plain(detail)
    || detail[kind === "message" ? "localMessageId" : "localRecordId"] !== summary.localId
    || detail.conversationKey !== summary.conversationKey
    || detail.localDelegateId !== summary.localDelegateId
    || detail.externalContentIsUntrustedData !== true
    || (kind === "message" ? !projectInboxReadState(detail) : detail.readDoesNotMarkRead !== true)
    || detail.source !== (kind === "message" ? "hellolynk_external_message" : "hellolynk_contact_request")
    || (kind === "message" && summary.peerDelegateId && detail.peerDelegateId !== summary.peerDelegateId)
    || (kind === "message" && (detail.replyToClientMessageId ?? null) !== summary.replyToClientMessageId)) {
    throw invalid("neutral_read_detail_binding_invalid");
  }
}

function projectDispatchMessage(kind, detail, summary) {
  const replyTarget = kind === "message"
    && [detail.peerPrincipalId, detail.peerDelegateId, detail.contactId].every((value) => typeof value === "string" && SAFE_ID.test(value))
    ? Object.freeze({
        localMessageId: summary.localId,
        conversationKey: summary.conversationKey,
        localDelegateId: summary.localDelegateId,
        peerPrincipalId: detail.peerPrincipalId,
        peerDelegateId: detail.peerDelegateId,
        contactId: detail.contactId,
      })
    : null;
  const sender = kind === "message" ? {
    principalId: detail.peerPrincipalId,
    delegateId: detail.peerDelegateId || detail.senderDelegateId,
    displayName: detail.displayName,
  } : {
    principalId: detail.sender?.hellolynkId,
    delegateId: detail.peerDelegateId || "hellolynk:unknown-delegate",
    displayName: detail.sender?.verifiedDisplayName,
  };
  return {
    deliveryId: summary.localId,
    messageId: summary.localId,
    conversationId: summary.conversationKey,
    conversationType: "direct",
    messageType: kind === "message" ? (detail.messageType || "text") : "contact_request",
    text: kind === "message" ? String(detail.text ?? "") : String(detail.introText ?? ""),
    timestamp: detail.createdAt || detail.receivedAt,
    senderPrincipalId: safeId(sender.principalId, "neutral_read_sender_principal_invalid"),
    senderDelegateId: safeId(sender.delegateId, "neutral_read_sender_delegate_invalid"),
    senderPrincipalDisplayName: String(sender.displayName || ""),
    senderDelegateDisplayName: kind === "message" ? String(detail.peerInstanceDisplayName || sender.delegateId || "") : "",
    identityProvenanceState: kind === "message" || detail.peerDelegateId
      ? "host_authorized_instance_binding"
      : "host_authorized_principal_delegate_unknown",
    attachments: [],
    raw: { source: detail.source },
    replyTarget,
  };
}

function stateRecord(state, sessionEpoch) {
  return Object.freeze({ state, ...(sessionEpoch !== undefined ? { sessionEpoch } : {}), updatedAt: new Date().toISOString() });
}

function sessionRecord(state, epoch) {
  return Object.freeze({ state, epoch, updatedAt: new Date().toISOString() });
}

function processingKey(accountId, summary) {
  return crypto.createHash("sha256").update(JSON.stringify([
    accountId, summary.localDelegateId, summary.conversationKey, summary.kind, summary.localId,
  ])).digest("hex");
}

function sessionStateKey(accountId, summary) {
  const hash = crypto.createHash("sha256").update(JSON.stringify([
    accountId, summary.localDelegateId, summary.conversationKey,
  ])).digest("hex");
  return `session:${hash}`;
}

function resolveStatePath(options, adapter, account) {
  const explicit = options.statePath || options.channelContext?.hellolynkReadStatePath;
  if (explicit) return explicit;
  const root = String(adapter.binding?.runtimeRoot || "");
  if (!path.isAbsolute(root)) throw invalid("neutral_read_state_path_required");
  const accountHash = crypto.createHash("sha256").update(account.accountId).digest("hex").slice(0, 24);
  return path.join(root, "openclaw", `authorized-read-${accountHash}.json`);
}

function requireAdapter(value) {
  for (const method of ["activateAuthorizedInbox", "listPendingMessages", "inboxBatch", "listAuthorizedContactRequests", "readAuthorizedContactRequest"]) {
    if (typeof value?.[method] !== "function") throw invalid("neutral_read_adapter_invalid");
  }
  return value;
}
function requireStateStore(value) {
  for (const method of ["legacyHeld", "get", "put", "delete"]) {
    if (typeof value?.[method] !== "function") throw invalid("neutral_read_state_store_invalid");
  }
}
function requireAccount(value) {
  if (!value || !safeId(value.accountId, "neutral_read_account_invalid")) throw invalid("neutral_read_account_invalid");
  return value;
}
function adapterDelegate(account) { return safeId(account.localDelegateId || account.delegateId || account.binding?.delegateId || account.__delegateId, "neutral_read_account_delegate_required"); }
function safeId(value, code) { const text = String(value || ""); if (!SAFE_ID.test(text)) throw invalid(code); return text; }
function integer(value, fallback, min, max) { const n = Number(value ?? fallback); if (!Number.isSafeInteger(n) || n < min || n > max) throw invalid("neutral_read_interval_invalid"); return n; }
function plain(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function invalid(code) { const error = new Error(code); error.code = code; return error; }
function safeCode(error) { const code = String(error?.code || "neutral_read_failed"); return /^[a-z][a-z0-9_]{2,127}$/.test(code) ? code : "neutral_read_failed"; }
function isAuthorizationFailure(error) { return /(authorization|authorized|permission|revoked|owner_mismatch|binding_mismatch)/.test(safeCode(error)); }
function abortableWait(ms, signal) {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms); timer.unref?.();
    function done() { clearTimeout(timer); signal?.removeEventListener("abort", done); resolve(); }
    signal?.addEventListener("abort", done, { once: true });
  });
}
