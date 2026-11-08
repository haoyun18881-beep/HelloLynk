import { createNativeDirectoryPublisher, nativeConversationId } from "./hellolynk-native-conversations.mjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { tryAcquireNativeWorkerLease } from "./hellolynk-native-worker-lease.mjs";
import { readNativeNoticeLocale, nativeNoticeText } from "./hellolynk-native-notice.mjs";

const POLL_MS = 5_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const closedBeforeDispatch = record => record?.outcome === "closed" && record.dispatchState === "reserved"
  && !record.threadId && !record.uncertainThreadId;

// One delivery ledger for the native receivers. Host owns body selection and claims;
// client bridges supply only lifecycle reads and immediate native acceptance.
export function createNativeInboxRuntime({ adapter, native, adapterId, acquireLease = tryAcquireNativeWorkerLease,
  pollMs = POLL_MS, timer = setInterval, now = Date.now, onError = reportNativeError, readReplyRoute,
  readNoticeLocale = readNativeNoticeLocale } = {}) {
  if (!adapterId || typeof readReplyRoute !== "function") throw new Error("native_options_invalid");
  const originPrefix = `${adapterId}-origin:`, conversationPrefix = `${adapterId}-conv:`;
  const checkScope = value => validateScope(value, adapterId);
  const publishDirectory = createNativeDirectoryPublisher(native);
  let closed = false;
  let interval;
  let lease;
  let flight;
  let directoryFlight;
  let scope;
  let state;
  let statePath;
  let scannedThreads = new Set();
  let readinessFailure;
  const inspectionFailures = new Map();
  let threadSnapshots = new Map();
  const releaseCurrent = async () => {
    const previous = lease;
    lease = null;
    scope = null;
    state = null;
    statePath = null;
    scannedThreads.clear();
    readinessFailure = null;
    inspectionFailures.clear();
    try { await native.releaseScope?.(); } finally { await previous?.release(); }
  };
  const scopeMatches = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const loadScope = async (nextScope) => {
    await native.ensureTools?.(["create_thread", "send_message_to_thread", "read_thread", "list_archived_threads"]);
    const candidate = await acquireLease(nextScope);
    if (!candidate) return false;
    try {
      if (closed) return false;
      const { hash, filename: nextPath } = nativeTaskStateLocation(nextScope);
      await assertNoReparsePath(nextScope.runtimeRoot);
      const dir = path.join(nextScope.runtimeRoot, "native-tasks");
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
      await assertNoReparsePath(dir);
      let nextState;
      try {
        const stat = await fs.lstat(nextPath);
        if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("native_state_path_unsafe");
        nextState = JSON.parse(await fs.readFile(nextPath, "utf8"));
        validateState(nextState, hash);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        nextState = { version: 1, scopeHash: hash, conversations: {} };
      }
      if (closed) return false;
      // Carry forward only actual native pointers and the old per-message
      // fences. Old unknowns are never silently retried by this format change.
      nextState.batches ||= {};
      nextState.carriers ||= Object.fromEntries(Object.entries(nextState.conversations)
        .filter(([, record]) => record.threadId).map(([key, record]) => [`${conversationPrefix}${key}`, record.threadId]));
      await native.configureScope?.(nextScope, nextState);
      if (closed) return false;
      scope = nextScope;
      lease = candidate;
      statePath = nextPath;
      state = nextState;
      return true;
    } finally {
      if (lease !== candidate) {
        try { await native.releaseScope?.(); } finally { await candidate.release(); }
      }
    }
  };
  const ensureReady = async () => {
    if (closed || !native) return false;
    const nextScope = checkScope(await adapter.nativeTaskScope());
    if (closed) return false;
    if (scope && !scopeMatches(scope, nextScope)) await releaseCurrent();
    try {
      const ready = lease ? true : await loadScope(nextScope);
      readinessFailure = null;
      return ready;
    } catch (error) {
      readinessFailure = { scope: nextScope, failure: { code: safeCode(error), at: now() } };
      throw error;
    }
  };
  const stillCurrent = async () => {
    if (closed || !lease) return false;
    const current = checkScope(await adapter.nativeTaskScope());
    return !closed && Boolean(lease) && scopeMatches(scope, current);
  };
  const tick = async () => {
    if (closed || !native) return;
    // The same timer services metadata even while native delivery is waiting.
    // No second receiver or additional polling loop is introduced.
    if (flight) { await directoryTick(); return flight; }
    flight = (async () => {
      await native.beforeTick?.();
      if (!await ensureReady()) return;
      // Catalog failures cannot stop the existing inbox receiver.
      await directoryTick();
      await native.beforeReceive?.();
      threadSnapshots = new Map(); scannedThreads = new Set();
      // Scan metadata to the end before choosing the newest whole messages.
      // A transport page is not the size of a model batch.
      const groups = new Map();
      let cursor = 0;
      do {
        const page = await adapter.listPendingMessages({ cursor });
        if (!Array.isArray(page?.messages)) throw new Error("native_pending_invalid");
        if (!await stillCurrent()) { await releaseCurrent(); return; }
        for (const item of page.messages) {
          if (item.wakeEligible !== true) continue;
          const key = validId(item.conversationKey), id = validId(item.localMessageId);
          const oldOutcome = state.conversations[key]?.messages?.[id] || await native.legacyDelivery?.(item, scope);
          // Historical per-message outcomes remain replay fences, not current batch failures.
          if (oldOutcome) continue;
          let target;
          if (item.targetConversationId) {
            if (item.replyToClientMessageId) throw new Error("native_target_conflicts_with_reply");
            target = `${originPrefix}${nativeConversationId(item.targetConversationId)}`;
          } else if (item.replyToClientMessageId) {
            const origin = await readReplyRoute(scope, item);
            if (!origin) continue;
            target = `${originPrefix}${validId(origin.threadId)}`;
          } else target = `${conversationPrefix}${key}`;
          if (!groups.has(target)) groups.set(target, []);
          groups.get(target).push(id);
        }
        if (page.nextCursor == null) break;
        if (!Number.isSafeInteger(page.nextCursor) || page.nextCursor <= cursor) throw new Error("native_pending_cursor_invalid");
        cursor = page.nextCursor;
      } while (!closed);
      if (!await stillCurrent()) { await releaseCurrent(); return; }
      // Only unresolved batches belong in the receiver's hot path. Delivered
      // bodies stay in Host for one-time reads, not in every five-second poll.
      const opened = await adapter.inboxBatch("open", { state: "reserved" });
      if (!Array.isArray(opened?.batches)) throw new Error("native_batches_invalid");
      const batches = new Map(opened.batches.map(batch => [batch.batchId, batch]));
      let pruned = false;
      for (const [id, record] of Object.entries(state.batches)) {
        if (record.outcome === "accepted") {
          await adapter.inboxBatch("confirm", { batchId: id, ...(record.threadId ? { nativeThreadId: record.threadId } : {}) });
          delete state.batches[id]; batches.delete(id); pruned = true;
        } else if (!batches.has(id) && !closedBeforeDispatch(record)) {
          // A model claim may have supplied the lost acceptance proof. If its
          // known carrier was already closed, mark that delivered batch read.
          if (record.outcome === "closed" && (record.threadId || record.uncertainThreadId))
            await adapter.inboxBatch("closed", { batchId: id });
          delete state.batches[id]; pruned = true;
        }
      }
      if (pruned) await persist();
      await native.prepare?.(scope, state, groups, batches);
      if (!await stillCurrent()) { await releaseCurrent(); return; }
      const incompleteTargets = new Set();
      let firstError;
      const attempt = async action => {
        try { await action(); return true; } catch (error) { firstError ||= error; onError({ code: safeCode(error), operation: "dispatch" }); return false; }
      };
      // Observe closure even with no new pending mail, using the existing tick.
      for (const [target, threadId] of Object.entries(state.carriers)) {
        if (!await stillCurrent()) { await releaseCurrent(); return; }
        await attempt(async () => {
          const result = await inspectThread(threadId);
          if (["archived", "deleted"].includes(result?.state)) await carrierClosed(target, threadId);
        });
      }
      for (const [target, ids] of groups) if (!await attempt(async () => {
        if (!await stillCurrent() || !await destination(target)) return;
        let batch = [...batches.values()].find(value => value.target === target && value.state === "reserved" && value.attempts === 0);
        const latestFirst = [...new Set(ids)].reverse();
        for (let offset = 0; offset < latestFirst.length; offset += 1000) {
          if (!await stillCurrent()) return;
          const input = { target, candidates: latestFirst.slice(offset, offset + 1000), ...(batch ? { batchId: batch.batchId } : {}) };
          const next = await adapter.inboxBatch("reserve", input);
          if (next.status === "empty") continue;
          batch = next; batches.set(batch.batchId, batch);
        }
      })) incompleteTargets.add(target);
      for (const batch of batches.values()) {
        if (!await stillCurrent()) { await releaseCurrent(); return; }
        if (batch.state === "reserved" && !incompleteTargets.has(batch.target)) await attempt(() => dispatchBatch(batch));
      }
      // Positive native acknowledgements may be waiting only for Host confirm.
      const remaining = await adapter.inboxBatch("open", { state: "reserved" });
      const unknownCount = remaining.batches.filter(batch => batch.attempts > 0
        && state.batches[batch.batchId]?.outcome !== "accepted"
        && !(state.batches[batch.batchId]?.dispatchState === "reserved"
          && state.batches[batch.batchId]?.attempt === 1)).length;
      for (const id of inspectionFailures.keys()) if (!scannedThreads.has(id)) inspectionFailures.delete(id);
      let changed = state.pendingUnknownCount !== unknownCount;
      state.pendingUnknownCount = unknownCount;
      if (!firstError && !inspectionFailures.size && state.deliveryFailure) { delete state.deliveryFailure; changed = true; }
      if (changed) await persist();
      if (firstError) throw firstError;
    })().catch(async error => {
      if (state && lease && state.deliveryFailure?.code !== safeCode(error)) {
        state.deliveryFailure = { code: safeCode(error), at: now() };
        await persist().catch(() => {});
      }
      throw error;
    });
    try { await flight; } finally { flight = null; }
  };
  async function directoryTick() {
    const directoryScope = scope, directoryLease = lease;
    const directoryStillCurrent = async () => {
      if (!directoryScope || !directoryLease || scope !== directoryScope || lease !== directoryLease) return false;
      const current = await stillCurrent();
      return current && scope === directoryScope && lease === directoryLease;
    };
    if (!await directoryStillCurrent()) return;
    if (directoryFlight) return directoryFlight;
    directoryFlight = publishDirectory(directoryScope, directoryStillCurrent).catch(error => onError({ code: safeCode(error), operation: "directory" }));
    try { await directoryFlight; } finally { directoryFlight = null; }
  }
  const persist = async () => {
    const temporary = `${statePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
    try {
      await assertNoReparsePath(path.dirname(statePath));
      const existing = await fs.lstat(statePath).catch((error) => error.code === "ENOENT" ? null : Promise.reject(error));
      if (existing && (!existing.isFile() || existing.isSymbolicLink())) throw new Error("native_state_path_unsafe");
      await fs.writeFile(temporary, JSON.stringify(state), { flag: "wx", mode: 0o600 });
      await fs.rename(temporary, statePath);
    } finally { await fs.unlink(temporary).catch((error) => { if (error.code !== "ENOENT") onError({ code: "native_temp_cleanup_failed", operation: "persist" }); }); }
  };
  const inspectWithBackoff = async (threadId, inspect) => {
    scannedThreads.add(threadId);
    const prior = inspectionFailures.get(threadId);
    if (prior && now() < prior.retryAt) return { state: "unavailable" };
    if (!threadSnapshots.has(threadId)) threadSnapshots.set(threadId, (async () => {
      try {
        const result = await inspect();
        inspectionFailures.delete(threadId);
        return result;
      } catch (error) {
        const attempts = (prior?.attempts || 0) + 1;
        inspectionFailures.set(threadId, { attempts, retryAt: now() + Math.min(300_000, 30_000 * 2 ** Math.min(attempts - 1, 4)) });
        throw error;
      }
    })());
    return threadSnapshots.get(threadId);
  };
  const inspectThread = threadId => inspectWithBackoff(threadId, () => native.inspectThread
    ? native.inspectThread(threadId) : native.call("read_thread", { threadId, turnLimit: 1 }));
  const carrierClosed = async (target, threadId) => {
    const batches = (await adapter.inboxBatch("open", { target, state: "delivered" })).batches;
    for (const batch of batches) {
      // A manually claimed, previously unsent batch never belonged to a later
      // carrier. Keep its small stop record as the existing deduplication fence.
      if (closedBeforeDispatch(state.batches[batch.batchId])) continue;
      // Confirmed batches use the one carrier pointer. An uncertain older
      // attempt may still name a different, already closed carrier.
      const deliveredThread = state.batches[batch.batchId]?.threadId || state.carriers[target];
      if (deliveredThread !== threadId) continue;
      await adapter.inboxBatch("closed", { batchId: batch.batchId });
      delete state.batches[batch.batchId];
    }
    if (state.carriers[target] === threadId) delete state.carriers[target];
    await persist();
  };
  const destination = async target => {
    const original = target.startsWith(originPrefix);
    if (!original && !target.startsWith(conversationPrefix)) throw new Error("native_batch_target_invalid");
    let threadId = original ? target.slice(originPrefix.length) : state.carriers[target];
    if (!original && !threadId) threadId = await native.legacyCarrier?.(target.slice(conversationPrefix.length), scope);
    if (!threadId) return original || native.canCreate === false ? null : { threadId: null, original: false };
    const result = await inspectThread(threadId);
    if (["archived", "deleted"].includes(result?.state)) {
      if (original) return null;
      await carrierClosed(target, threadId);
      return native.canCreate === false ? null : { threadId: null, original: false };
    }
    const canNotify = original ? (native.canNotifyOrigin || canNotifyOrigin)(result)
      : native.canNotifyCarrier ? native.canNotifyCarrier(result) : canNotifyCarrier(result, native.canNotifyOrigin);
    // A host may use a reusable routing key to locate a carrier, while its
    // model tools use a concrete native session ID (OpenClaw). Pin that ID.
    return canNotify ? { threadId: !original && result.nativeThreadId ? validId(result.nativeThreadId) : threadId, original } : null;
  };
  const dispatchBatch = async batch => {
    const id = batch.batchId;
    let record = state.batches[id];
    if (record?.outcome === "accepted") {
      await adapter.inboxBatch("confirm", { batchId: id, nativeThreadId: record.threadId });
      delete state.batches[id]; await persist(); return;
    }
    // A registered but definitely unsent ticket is reusable, including the
    // second ticket. A possibly sent ticket is never reused for native dispatch.
    const registered = record?.dispatchState === "reserved";
    if (record?.outcome === "closed" || (batch.attempts >= 2 && !registered)) return;
    // If a known carrier was closed after an uncertain send, do not redirect
    // that old attempt to a new carrier. New mail still uses destination().
    const uncertainThreadId = registered ? record.uncertainThreadId : record?.threadId;
    if (uncertainThreadId && batch.attempts > 0) {
      const status = await inspectThread(uncertainThreadId);
      if (["archived", "deleted"].includes(status?.state)) {
        record.outcome = "closed"; await persist(); return;
      }
    }
    // Resolve presentation before creating a carrier or consuming a send try.
    const noticeLocale = await readNoticeLocale();
    if (!await stillCurrent()) return;
    const target = await destination(batch.target);
    if (!target || !await stillCurrent()) return;
    if (batch.attempts > 0) {
      // A cheap native round trip proves the connection is usable before the
      // single retry. Reusing the batch id deduplicates the body read, even if
      // Codex cannot deduplicate its native create/send calls.
      await native.call("list_threads", { limit: 1 });
      if (!await stillCurrent()) return;
    }
    if (!registered) record = state.batches[id] = {
      target: batch.target, threadId: target.threadId, outcome: "unknown",
      attemptId: `inattempt_${crypto.randomUUID()}`, attempt: batch.attempts + 1, dispatchState: "reserved",
      uncertainThreadId: record?.threadId ?? null,
    };
    // Persist before POST. An HTTP timeout may leave the original handler live;
    // replay this idempotency ticket instead of spending a new native chance.
    await persist();
    if (!await stillCurrent()) return;
    const attempted = await adapter.inboxBatch("attempt", { batchId: id, attemptId: record.attemptId,
      ...(target.threadId ? { nativeThreadId: target.threadId } : {}) });
    if (!attempted.attempted) return;
    let result, nativeCalled = false;
    try {
      if (!await stillCurrent()) throw new Error("native_scope_changed");
      record.threadId = target.threadId;
      record.dispatchState = "started";
      await persist();
      if (!await stillCurrent()) throw new Error("native_scope_changed");
      const prompt = batchPrompt(batch, noticeLocale);
      // Do not reuse cached idle state for a second batch in the same tick.
      if (target.threadId) threadSnapshots.delete(target.threadId);
      const context = { batchId: id, target: batch.target, original: target.original, stillCurrent, noticeLocale,
        isStopped: () => closed || !lease,
        async rememberThread(threadId) {
          record.threadId = validId(threadId);
          if (!target.original) state.carriers[batch.target] = record.threadId;
          // Keep the created carrier even if its Host owner pin fails before send.
          await persist();
          await adapter.inboxBatch("attempt", { batchId: id, attemptId: record.attemptId, nativeThreadId: record.threadId });
        } };
      nativeCalled = true;
      result = target.threadId
        ? await native.call("send_message_to_thread", { threadId: target.threadId, hostId: "local", prompt }, context)
        : await native.call("create_thread", { target: { type: "projectless", directoryName: "HelloLynk" }, title: nativeNoticeText(noticeLocale, "independentTitle"), prompt }, context);
    } catch (error) {
      // No native write occurred. Reuse only this registered ticket; keeping
      // the batch and its earlier possibly sent ticket preserves uncertainty.
      if (!nativeCalled || error.nativeDispatchStarted === false) {
        record.dispatchState = "reserved";
        // A confirmed closed prebuilt carrier cannot accept this unsent batch.
        // Stop only this batch; no Host confirm/read action occurred.
        if (error.nativeDispatchStarted === false && error.nativeCarrierClosedBeforeDispatch === true) record.outcome = "closed";
        await persist();
      }
      throw error;
    }
    const accepted = target.threadId ? acceptedSend(result) : validIdOrNull(result?.threadId);
    if (!accepted) return;
    record.threadId = target.threadId || result.threadId; record.outcome = "accepted";
    if (!target.original) state.carriers[batch.target] = record.threadId;
    // Save the positive native result before Host confirmation. A lost Host
    // response retries only confirm, never the accepted model notification.
    await persist();
    await adapter.inboxBatch("confirm", { batchId: id, nativeThreadId: record.threadId });
    delete state.batches[id]; await persist();
  };
  return Object.freeze({
    async start() {
      if (closed || !native) return false;
      if (!interval) interval = timer(() => { void tick().catch((error) => onError({ code: safeCode(error), operation: "poll" })); }, pollMs);
      interval.unref?.();
      void tick().catch((error) => onError({ code: safeCode(error), operation: "start" }));
      return true;
    },
    tick,
    async readDeliveryStatus() {
      // Called only with a model tool result, never from a new polling loop.
      // A different MCP process may own the worker lease; read its same state.
      const current = checkScope(await adapter.nativeTaskScope());
      if (readinessFailure && scopeMatches(readinessFailure.scope, current))
        return { failure: readinessFailure.failure, unknownCount: 0 };
      const { hash, filename } = nativeTaskStateLocation(current);
      let snapshot;
      try { snapshot = JSON.parse(await fs.readFile(filename, "utf8")); }
      catch (error) { if (error.code === "ENOENT") return null; throw error; }
      validateState(snapshot, hash);
      if (!scopeMatches(current, checkScope(await adapter.nativeTaskScope()))) return null;
      return {
        failure: snapshot.deliveryFailure ?? null,
        unknownCount: snapshot.pendingUnknownCount ?? 0,
      };
    },
    async close() {
      closed = true;
      if (interval) clearInterval(interval);
      await flight?.catch(() => {});
      await directoryFlight;
      await releaseCurrent();
      await native?.close?.();
    },
  });
}

function nativeTaskStateLocation(scope) {
  const hash = crypto.createHash("sha256").update(JSON.stringify([
    process.platform === "win32" ? path.resolve(scope.runtimeRoot).toLowerCase() : path.resolve(scope.runtimeRoot),
    scope.region, scope.principalId, scope.delegateId, scope.adapterId,
  ])).digest("hex");
  return { hash, filename: path.join(scope.runtimeRoot, "native-tasks", `${hash}.json`) };
}

function validId(value) {
  if (typeof value !== "string" || !ID.test(value)) throw new Error("native_message_id_invalid");
  return value;
}
function validIdOrNull(value) { return typeof value === "string" && ID.test(value); }
function validateScope(value, adapterId) {
  if (!value || typeof value !== "object" || typeof value.runtimeRoot !== "string" || !path.isAbsolute(value.runtimeRoot))
    throw new Error("native_scope_invalid");
  for (const key of ["region", "principalId", "delegateId", "adapterId"])
    if (typeof value[key] !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,240}$/.test(value[key]))
      throw new Error("native_scope_invalid");
  if (value.adapterId !== adapterId) throw new Error("native_scope_adapter_invalid");
  return Object.freeze(Object.fromEntries(["runtimeRoot", "region", "principalId", "delegateId", "adapterId"]
    .map((key) => [key, value[key]])));
}
function statusType(value) {
  const status = value?.thread?.status;
  return status == null ? null : typeof status === "string" ? status : status.type;
}
function isIdle(value) {
  if (value?.state === "unavailable") return false;
  const status = statusType(value);
  if (value?.thread?.status != null) return status === "idle";
  if (!Array.isArray(value?.turns) || value.turns.length === 0) return false;
  const latest = value.turns[0];
  return latest?.status === "completed" && Boolean(latest.completedAt);
}
// The sending session is waiting for this reply, and Codex's own send steers a
// running turn, so a busy origin is notified now. An unloaded one still waits.
function canNotifyOrigin(value) {
  if (value?.state === "unavailable") return false;
  if (isIdle(value)) return true;
  const status = statusType(value);
  if (value?.thread?.status != null) return status === "active";
  return value?.turns?.[0]?.status === "inProgress";
}
// Use the bridge's established notification capability for independent chats
// too. Codex can steer an active turn; bridges that require idle keep that
// restriction. An unloaded carrier may be resumed after a host restart.
function canNotifyCarrier(value, notifyOrigin = canNotifyOrigin) {
  if (value?.state === "unavailable") return false;
  return notifyOrigin(value) || statusType(value) === "notLoaded";
}
function acceptedSend(value) { return value?._nativeToolSuccess === true || value?.threadId || value?.ok === true || value?.status === "sent"; }
function validateState(value, hash) {
  if (value?.version !== 1 || value.scopeHash !== hash || !value.conversations
    || typeof value.conversations !== "object" || Array.isArray(value.conversations))
    throw new Error("native_state_invalid");
  for (const key of ["batches", "carriers"]) {
    if (value[key] != null && (typeof value[key] !== "object" || Array.isArray(value[key])))
      throw new Error("native_state_invalid");
  }
  if (value.deliveryFailure != null && (typeof value.deliveryFailure !== "object"
    || !/^[A-Za-z0-9_:-]{1,100}$/.test(value.deliveryFailure.code)
    || !Number.isSafeInteger(value.deliveryFailure.at) || value.deliveryFailure.at < 0))
    throw new Error("native_state_invalid");
  if (value.pendingUnknownCount != null && (!Number.isSafeInteger(value.pendingUnknownCount) || value.pendingUnknownCount < 0))
    throw new Error("native_state_invalid");
  for (const [id, record] of Object.entries(value.batches || {})) {
    validId(id); validId(record.target);
    if (!["unknown", "accepted", "closed"].includes(record.outcome) || (record.threadId !== null && !validIdOrNull(record.threadId)))
      throw new Error("native_state_invalid");
    if (record.attemptId !== undefined || record.attempt !== undefined || record.dispatchState !== undefined) {
      if (!validIdOrNull(record.attemptId) || !Number.isSafeInteger(record.attempt) || record.attempt < 1 || record.attempt > 2
        || !["reserved", "started"].includes(record.dispatchState)
        || (record.uncertainThreadId != null && !validIdOrNull(record.uncertainThreadId))) throw new Error("native_state_invalid");
    }
  }
  for (const [target, threadId] of Object.entries(value.carriers || {})) { validId(target); validId(threadId); }
  for (const [conversationKey, record] of Object.entries(value.conversations)) {
    validId(conversationKey);
    if (!record || typeof record !== "object" || !record.messages || typeof record.messages !== "object"
      || Array.isArray(record.messages) || (record.threadId !== null && !validIdOrNull(record.threadId))
      || ![null, "unknown"].includes(record.createState)) throw new Error("native_state_invalid");
    if (record.stoppedAt != null && (!Number.isSafeInteger(record.stoppedAt) || record.stoppedAt < 0))
      throw new Error("native_state_invalid");
    if (record.createCaller != null && !validIdOrNull(record.createCaller)) throw new Error("native_state_invalid");
    for (const [localMessageId, outcome] of Object.entries(record.messages)) {
      validId(localMessageId);
      if (!["sent", "unknown"].includes(outcome)) throw new Error("native_state_invalid");
    }
    if (record.messageThreads !== undefined) {
      if (!record.messageThreads || typeof record.messageThreads !== "object" || Array.isArray(record.messageThreads)) throw new Error("native_state_invalid");
      for (const [message, thread] of Object.entries(record.messageThreads))
        if (!Object.hasOwn(record.messages, message) || !validIdOrNull(thread)) throw new Error("native_state_invalid");
    }
  }
}
async function assertNoReparsePath(target) {
  let cursor = path.resolve(target);
  while (true) {
    const stat = await fs.lstat(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("native_state_directory_unsafe");
    const parent = path.dirname(cursor);
    if (parent === cursor) return;
    cursor = parent;
  }
}
function safeCode(error) {
  return /^[A-Za-z0-9_:-]{1,100}$/.test(error?.code || error?.message || "")
    ? String(error.code || error.message) : "native_worker_failed";
}
function reportNativeError(event) {
  process.stderr.write(`${JSON.stringify({ event: "hellolynk_native_task_worker", ...event })}\n`);
}
function batchPrompt(batch, locale) {
  return nativeNoticeText(locale, "batch", { source: nativeNoticeText(locale, "source"), count: batch.count, batchId: batch.batchId });
}

// Only a currently dispatched batch can bridge the short interval before Host
// confirmation saves its native owner. Historical carrier guesses are forbidden.
export async function readNativeInboxBatchDispatch(scope, batchId) {
  validId(batchId);
  const { hash, filename } = nativeTaskStateLocation(scope);
  let source;
  try { source = await fs.readFile(filename, "utf8"); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    if (["EPERM", "EBUSY"].includes(error.code)) return { pending: true, threadId: null };
    throw error;
  }
  const state = JSON.parse(source);
  validateState(state, hash);
  const record = state.batches?.[batchId];
  return record ? { threadId: record.threadId || null, pending: record.dispatchState === "started" } : null;
}
