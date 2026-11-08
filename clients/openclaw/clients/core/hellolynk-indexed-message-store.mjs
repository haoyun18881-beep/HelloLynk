import { nativeConversationId, nativeConversationTitle } from "./hellolynk-native-conversations.mjs";
import crypto from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, open, rename } from "node:fs/promises";
import path from "node:path";
import {
  HelloLynkLocalMessagingError, indexedMessageStoreLegacyInternals as L,
  streamLegacyLocalMessages, replaceLocalStoreFileWithRetry,
} from "./hellolynk-local-messaging.mjs";
import { getMessageConversationBinding, getOutgoingConversationIntent,
  normalizeInstanceConversationBinding, instanceConversationKey } from "./hellolynk-instance-conversation.mjs";
import { HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH } from "../workbench/contract.mjs";

// Local business records are plain JSON payloads. Index columns keep keyed
// hashes so databases converted from the former encrypted format retain every
// identifier; the hash key lives in meta and is not a secret.
export const HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT = "hellolynk-indexed-messages-v2";
const DELETED = "local-deleted";
const INDEX_KEY = /^[a-f0-9]{64}$/;
const MESSAGE_STATUSES = new Set(["received", "fetched", "pending_human_confirmation", "pending", "recipient_offline", "failed_retryable", "failed_permanent", "cancelled", "delivered_to_live_connection", "delivery_state_unknown", "delivery_state_unconfirmed"]);
const SQL = `
CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE, client TEXT NOT NULL, event TEXT, replay TEXT, sender_client TEXT,
 scope TEXT, thread TEXT, route TEXT, delegate TEXT, direction TEXT NOT NULL, status TEXT NOT NULL,
 created TEXT NOT NULL, updated TEXT NOT NULL, receipt INTEGER, deleted INTEGER NOT NULL, admitted INTEGER NOT NULL,
 unread INTEGER NOT NULL, outgoing_protected INTEGER NOT NULL, bytes INTEGER NOT NULL,
 version INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS messages_client ON messages(client,direction);
CREATE INDEX IF NOT EXISTS messages_event ON messages(event);
CREATE INDEX IF NOT EXISTS messages_replay ON messages(replay);
CREATE INDEX IF NOT EXISTS messages_sender_client ON messages(sender_client);
CREATE INDEX IF NOT EXISTS messages_page ON messages(scope,thread,deleted,created,seq);
CREATE INDEX IF NOT EXISTS messages_pending ON messages(delegate,direction,deleted,admitted,receipt);
CREATE INDEX IF NOT EXISTS messages_pending_route ON messages(delegate,route,direction,deleted,admitted,receipt);
CREATE INDEX IF NOT EXISTS messages_outbox ON messages(direction,deleted,status,seq);
CREATE TABLE IF NOT EXISTS claims (id TEXT PRIMARY KEY, message TEXT NOT NULL, delegate TEXT NOT NULL,
 outcome TEXT NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS claims_message ON claims(message);
CREATE INDEX IF NOT EXISTS claims_message_delegate ON claims(message,delegate);
CREATE INDEX IF NOT EXISTS claims_delegate ON claims(delegate);
CREATE TABLE IF NOT EXISTS inbox_batches (id TEXT PRIMARY KEY, delegate TEXT NOT NULL, adapter TEXT NOT NULL,
 target TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS inbox_batches_open ON inbox_batches(delegate,adapter,state,target);
CREATE TABLE IF NOT EXISTS readers (id TEXT PRIMARY KEY, version INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS threads (id TEXT PRIMARY KEY, scope TEXT NOT NULL, updated TEXT NOT NULL,
 archived INTEGER NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL,
 deleted INTEGER NOT NULL, delete_through INTEGER NOT NULL, purge_after INTEGER NOT NULL, purge_pending INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS threads_scope ON threads(scope,updated);
CREATE INDEX IF NOT EXISTS threads_purge ON threads(purge_pending,id);
CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, version INTEGER NOT NULL, payload TEXT NOT NULL);
PRAGMA user_version=2;`;
const INDEX_COLUMNS = ["id", "seq", "client", "event", "replay", "sender_client", "scope", "thread", "route", "delegate", "direction", "status", "created", "updated", "receipt", "deleted", "admitted", "unread", "outgoing_protected", "bytes", "version"];
const fail = (code, options) => { throw new HelloLynkLocalMessagingError(code, options); };
const clone = (value) => structuredClone(value);
const emptyCounts = () => ({ inbox: { total: 0, unread: 0 }, outbox: { total: 0, pending: 0, retryEligible: 0, states: {} } });
function applyCountDelta(counts, index, sign) {
  if (!index || index.deleted) return;
  if (index.direction === "incoming") {
    counts.inbox.total += sign; counts.inbox.unread += sign * index.unread;
  } else {
    counts.outbox.total += sign;
    const publicStatus = index.status === "reply_target_deleted" ? "failed_permanent" : index.status;
    const stateCount = (counts.outbox.states[publicStatus] || 0) + sign;
    if (stateCount) counts.outbox.states[publicStatus] = stateCount;
    else delete counts.outbox.states[publicStatus];
    if (L.BACKGROUND_RETRYABLE_OUTGOING_STATUSES.has(index.status)) counts.outbox.pending += sign;
    if (L.MANUAL_RETRYABLE_OUTGOING_STATUSES.has(index.status)) counts.outbox.retryEligible += sign;
  }
}
function addCounts(target, source) {
  for (const field of ["total", "unread"]) target.inbox[field] += source.inbox[field];
  for (const field of ["total", "pending", "retryEligible"]) target.outbox[field] += source.outbox[field];
  for (const [status, count] of Object.entries(source.outbox.states)) target.outbox.states[status] = (target.outbox.states[status] || 0) + count;
}
const checkedTime = (value) => {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail("local_history_time_invalid");
  return value;
};
// Same derivation as the former encrypted index, so converted rows keep their ids.
function indexToken(key, domain, value) {
  if (!key) fail("local_message_store_not_initialized");
  return crypto.createHmac("sha256", key).update(JSON.stringify([domain, value])).digest("hex");
}
const limitOf = (value, maximum) => {
  const number = value ?? maximum;
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) fail("local_history_limit_invalid");
  return number;
};

export async function createIndexedLocalMessageStore(options = {}) {
  if (options.deferInitialization !== true) return openIndexedLocalMessageStore(options);
  let ready = null, opening = null, stopped = false;
  const facade = { path: options.storePath, archivePath: `${options.storePath}.archive.ndjson`, localHistoryPath: `${options.storePath}.local-history.json`, dbPath: `${options.storePath}.sqlite`,
    async initialize() {
      if (stopped) fail("local_message_store_closed");
      if (ready) return facade;
      opening ||= openIndexedLocalMessageStore({ ...options, deferInitialization: false }).then((store) => { ready = store; return facade; }).catch((error) => { opening = null; throw error; });
      return opening;
    },
    async close() { stopped = true; if (opening) await opening.catch(() => {}); await ready?.close(); },
  };
  for (const name of ["getReceiptHighWater", "getInboxReaderBoundary", "activateInboxReader", "listInboxClaimIds", "claimInboxMessage", "finishInboxClaim", "reserveInboxBatch", "listInboxBatches", "getInboxNativeAssignment", "getInboxNativeAssignments", "attemptInboxBatch", "confirmInboxBatch", "cancelInboxBatch", "expireInboxBatch", "closeInboxBatch", "claimInboxBatch", "readIncomingForModel", "getIncoming", "getOutgoing", "list", "listActive", "queryOutbox", "listPendingInboxCandidates", "getMessageCounts", "addOutgoing", "updateOutgoing", "attachOutgoingE2ee", "claimOutgoingForPreparation", "claimOutgoingForAttempt", "recoverArchivedOutgoingRetryClaim", "recoverAbandonedE2eeOutgoingAttempts", "listPending", "cancelOutgoing", "addIncoming", "findIncomingE2eeReplay", "updateIncoming", "deleteIncoming", "deleteOutgoing", "readWorkbenchSummary", "readWorkbenchRevision", "queryConversationPage", "readLocalHistoryStats", "searchWorkbenchThreads", "configureLocalHistory", "hideLocalConversation", "restoreLocalConversation", "clearLocalConversation", "deleteLocalConversation", "deleteArchivedConversations", "deleteSentLocal", "maintainLocalHistory", "readWorkbenchState", "diagnostics"]) {
    facade[name] = (...args) => { if (!ready) fail("local_message_store_not_initialized"); return ready[name](...args); };
  }
  facade.markIncomingRead = (...args) => { if (!ready) fail("local_message_store_not_initialized"); return ready.markIncomingRead(...args); };
  facade.listInboxMessagesForDelegate = (...args) => { if (!ready) fail("local_message_store_not_initialized"); return ready.listInboxMessagesForDelegate(...args); };
  facade.configureConversationAutoRead = (...args) => { if (!ready) fail("local_message_store_not_initialized"); return ready.configureConversationAutoRead(...args); };
  return facade;
}

// One-time forward conversion of a database written by the former encrypted
// release. All payloads become plain JSON in one transaction; index columns and
// ids embedded in payloads stay valid because the former index key moves into
// meta. A database without encrypted meta is left untouched.
export async function convertEncryptedIndexedMessageDatabase({ storePath, profileId, isEncrypted, decrypt, deriveIndexKey }) {
  const dbPath = `${path.resolve(storePath)}.sqlite`;
  try { if (!(await lstat(dbPath)).isFile()) fail("local_message_store_invalid"); }
  catch (error) { if (error.code === "ENOENT") return { converted: false, rows: 0 }; throw error; }
  const { DatabaseSync } = await import("node:sqlite");
  const db = new DatabaseSync(dbPath, { timeout: 5000 });
  try {
    const metaRow = db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='meta'").get()
      && db.prepare("SELECT * FROM meta WHERE id=1").get();
    if (!metaRow || !isEncrypted(JSON.parse(metaRow.payload))) return { converted: false, rows: 0 };
    const context = (kind, id) => ({ profileId, assetKind: "messages", logicalPath: `messages/${profileId}.sqlite/${kind}/${id}` });
    db.exec("PRAGMA synchronous=FULL; BEGIN IMMEDIATE");
    let rows = 0;
    try {
      const meta = await decrypt(JSON.parse(metaRow.payload), context("meta", "root"));
      if (meta?.contract !== HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT || meta.profileId !== profileId) fail("local_message_index_version_unsupported");
      const key = await deriveIndexKey(context("index", "v1"));
      db.prepare("UPDATE meta SET payload=? WHERE id=1").run(JSON.stringify({ ...meta, indexKey: key.toString("hex") }));
      for (const [table, kind] of [["messages", "message"], ["claims", "claim"], ["readers", "reader"], ["threads", "thread"], ["settings", "setting"]]) {
        const select = db.prepare(`SELECT id,payload FROM ${table} WHERE id>? ORDER BY id LIMIT 256`);
        const update = db.prepare(`UPDATE ${table} SET payload=? WHERE id=?`);
        for (let batch = select.all(""); batch.length; batch = select.all(batch.at(-1).id)) {
          for (const row of batch) {
            const value = await decrypt(JSON.parse(row.payload), context(kind, row.id));
            // A wrong index key would orphan every row; prove it on each id.
            const id = kind === "message" ? indexToken(key, "message", String(value?.message?.localMessageId)) : value?.id;
            if (id !== row.id) fail("local_message_index_invalid");
            update.run(JSON.stringify(value), row.id);
            rows++;
          }
        }
      }
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    return { converted: true, rows };
  } finally { db.close(); }
}

async function openIndexedLocalMessageStore(options = {}) {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 16)) fail("local_message_node_22_16_required");
  if (options.dataProtector != null) fail("local_message_data_protector_unsupported");
  const profileId = L.safeId(options.profileId, "local_message_profile_id_invalid");
  const storePath = path.resolve(options.storePath || "");
  if (!options.storePath || !path.isAbsolute(options.storePath)) fail("local_message_store_path_required");
  const dbPath = `${storePath}.sqlite`, archivePath = `${storePath}.archive.ndjson`, localHistoryPath = `${storePath}.local-history.json`;
  const now = options.now || (() => Date.now());
  let indexKey = null;
  const token = (domain, value) => indexToken(indexKey, domain, String(value));
  const scopeKey = (scope) => token("scope", L.localHistoryScopeKey(L.localHistoryScope(scope)));
  const threadKey = (scope, threadId) => token("thread", `${L.localHistoryScopeKey(L.localHistoryScope(scope))}\0${L.safeId(threadId, "local_history_thread_invalid")}`);
  const ownerScope = options.ownerScope ? L.localHistoryScope({ ...options.ownerScope, delegateId: "legacy-unbound" }) : null;
  function legacyThreadId(message, scope) {
    const peerPrincipalId = message.direction === "incoming" ? (message.peerPrincipalId ?? message.senderPrincipalId) : (message.peerPrincipalId ?? message.recipientPrincipalId);
    const peerHelloLynkId = message.direction === "incoming" ? (message.peerHelloLynkId ?? message.senderHelloLynkId) : (message.recipientHelloLynkId ?? message.peerHelloLynkId);
    if (!peerPrincipalId && !peerHelloLynkId) fail("local_message_legacy_peer_invalid");
    const peer = peerHelloLynkId == null ? `principal:${peerPrincipalId}` : `hellolynk:${peerHelloLynkId}`;
    return `thread_${crypto.createHash("sha256").update(`${scope.region}\0${scope.principalId}\0${peer}`).digest("hex").slice(0, 40)}`;
  }
  function messageOwner(message) {
    const binding = getMessageConversationBinding(message) || getOutgoingConversationIntent(message);
    if (binding) {
      if (ownerScope && (binding.region !== ownerScope.region || binding.localPrincipalId !== ownerScope.principalId)) fail("local_message_scope_mismatch");
      const scope = { region: binding.region, principalId: binding.localPrincipalId, delegateId: binding.localDelegateId };
      return { binding, scope, threadId: instanceConversationKey(binding), legacy: false };
    }
    if (!ownerScope) fail("local_message_legacy_owner_required");
    if (message.direction === "outgoing" && message.senderPrincipalId !== ownerScope.principalId) fail("local_message_legacy_owner_invalid");
    return { binding: null, scope: ownerScope, threadId: legacyThreadId(message, ownerScope), legacy: true };
  }
  function readScopeKeys(input) {
    const scope = L.localHistoryScope(input), values = [scopeKey(scope)];
    if (ownerScope && ownerScope.region === scope.region && ownerScope.principalId === scope.principalId) values.push(scopeKey(ownerScope));
    return [...new Set(values)];
  }
  const metrics = { messageReads: 0, claimReads: 0, recordReads: 0, payloadBytesRead: 0, messageQueries: 0, messageAggregateQueries: 0 };
  let db, identity, closed = false;
  const { DatabaseSync } = await import("node:sqlite");
  const encode = (value) => JSON.stringify(value);
  const decode = (kind, payload) => {
    metrics.recordReads++; metrics.payloadBytesRead += Buffer.byteLength(payload);
    const value = JSON.parse(payload);
    // Synthetic tests observe real message reads to interleave mutations.
    if (kind === "message") { metrics.messageReads++; options.onMessageRead?.(value.message); }
    if (kind === "claim") metrics.claimReads++;
    return value;
  };
  async function assertFiles() {
    await L.assertMessageStoreAccess(dbPath, null, { create: true });
    for (const suffix of ["", "-wal", "-shm", "-journal"]) {
      let stat; try { stat = await lstat(`${dbPath}${suffix}`); } catch (error) { if (error.code === "ENOENT" && suffix) continue; throw error; }
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail("local_message_store_invalid");
      if (!suffix && identity && (stat.dev !== identity.dev || stat.ino !== identity.ino)) fail("local_message_store_replaced");
    }
  }
  function observeRead(sql) {
    if (/\bFROM\s+messages\b/i.test(sql)) {
      metrics.messageQueries++;
      if (/\b(count|sum)\s*\(|\bGROUP BY\b/i.test(sql)) metrics.messageAggregateQueries++;
    }
  }
  const get = (sql, ...params) => { observeRead(sql); return db.prepare(sql).get(...params); };
  const all = (sql, ...params) => { observeRead(sql); return db.prepare(sql).all(...params); };
  const run = (sql, ...params) => db.prepare(sql).run(...params);
  async function readMeta() {
    const row = get("SELECT * FROM meta WHERE id=1");
    if (!row) fail("local_message_index_invalid");
    const value = decode("meta", row.payload);
    if (value?.contract !== HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT || value.profileId !== profileId || value.version !== row.version
      || !Number.isSafeInteger(value.highWater) || value.highWater < 0 || !Number.isSafeInteger(value.sequence) || value.sequence < 0
      || typeof value.migrated !== "boolean" || value.countsVersion !== 1 || !value.globalCounts || !value.scopeCounts
      || typeof value.indexKey !== "string" || !INDEX_KEY.test(value.indexKey)) fail("local_message_index_invalid");
    return value;
  }
  function messageIndex(message, seq, version, claimAnchors = []) {
    L.validateCurrentMessage(message);
    if (!MESSAGE_STATUSES.has(message.status)) fail("local_message_status_invalid");
    const { binding, scope, threadId } = messageOwner(message);
    const deleted = message.messageType === DELETED;
    return {
      id: token("message", message.localMessageId), seq, client: token("client", message.clientMessageId),
      event: message.eventId ? token("event", message.eventId) : null,
      replay: message.senderIdentityKeyId ? token("replay", `${message.senderIdentityKeyId}\0${message.clientMessageId}`) : null,
      sender_client: message.direction === "incoming" ? token("sender-client", `${message.peerPrincipalId}\0${message.clientMessageId}`) : null,
      scope: scopeKey(scope), thread: threadKey(scope, threadId),
      route: binding ? token("route", instanceConversationKey(binding)) : null,
      delegate: binding ? token("delegate", binding.localDelegateId) : (message.direction === "outgoing" ? token("delegate", message.senderDelegateId) : null),
      // A definite deleted-target rejection has the public failed status, but
      // its authenticated index must never count it as a generic retry action.
      direction: message.direction, status: message.status === "failed_permanent" && message.lastErrorCode === "reply_target_deleted" ? "reply_target_deleted" : message.status,
      created: checkedTime(message.createdAt), updated: checkedTime(message.updatedAt),
      receipt: message.receiptSeq ?? null, deleted: Number(deleted), admitted: Number(claimAnchors.length > 0), unread: Number(!deleted && L.localHistoryUnread(message)),
      outgoing_protected: Number(!deleted && message.direction === "outgoing" && !L.localHistorySent(message)),
      bytes: deleted ? 0 : Buffer.byteLength(message.text || "", "utf8"), version,
    };
  }
  async function verifiedMessageIndex(row, record) {
    if (!record || !record.message) fail("local_message_index_invalid");
    const expected = messageIndex(record.message, row.seq, row.version, record.claimAnchors || []);
    if (JSON.stringify(record.index) !== JSON.stringify(expected)) fail("local_message_index_invalid");
    // An authenticated deletion boundary immediately hides the old conversation.
    // Body redaction then proceeds in small, recoverable transactions.
    const threadRow = row.thread && get("SELECT * FROM threads WHERE id=?", row.thread);
    if (row.thread && !threadRow) fail("local_message_index_invalid");
    const thread = threadRow ? await openRecord("thread", threadRow) : null;
    const conversationDeleted = (thread?.deleteThrough ?? 0) >= row.seq;
    if (conversationDeleted) {
      Object.assign(expected, { deleted: 1, unread: 0, outgoing_protected: 0, bytes: 0 });
    }
    if (INDEX_COLUMNS.some((key) => row[key] !== expected[key])) fail("local_message_index_invalid");
    return { ...expected, conversationDeleted };
  }
  async function openMessage(row) {
    if (!row) return null;
    const record = decode("message", row.payload);
    const verified = await verifiedMessageIndex(row, record);
    // The message record owns terminal admission facts. A deleted or
    // misindexed auxiliary claim cannot turn a consumed receipt into new work.
    for (const anchor of record.claimAnchors || []) {
      const claimRow = get("SELECT * FROM claims WHERE id=?", anchor.id);
      if (!claimRow) fail("local_message_claim_anchor_invalid");
      const claim = await openRecord("claim", claimRow);
      if (claim.localMessageId !== record.message.localMessageId || Object.keys(anchor).some((key) => anchor[key] !== claim[key])) fail("local_message_claim_anchor_invalid");
    }
    if (verified.conversationDeleted) return { ...L.localHistoryTombstone(record.message, messageOwner(record.message).scope), conversationDeleted: true };
    if (row.friend_target == null) return record.message;
    const target = JSON.parse(row.friend_target);
    if (target?.heldTargetId != null) return L.validateCurrentMessage({ ...record.message, friendTargetHeld: true,
      targetConversationId: nativeConversationId(target.heldTargetId) });
    // Only a Host with the title lookup can use the saved encryption inputs.
    return L.validateCurrentMessage({ ...record.message, targetConversationTitle: nativeConversationTitle(target?.title),
      e2ee: target.e2ee ?? null, ...(target.preparation ? { e2eePreparation: target.preparation } : {}) });
  }
  async function openRecord(kind, row) {
    if (!row) return null;
    const value = decode(kind, row.payload);
    if (value?.id !== row.id || value.version !== row.version) fail("local_message_index_invalid");
    if (kind === "claim" && (value.outcome !== row.outcome || token("message", value.localMessageId) !== row.message || token("delegate", value.delegateId) !== row.delegate)) fail("local_message_index_invalid");
    if (kind === "batch" && (token("delegate", value.delegateId) !== row.delegate || value.adapterId !== row.adapter || value.target !== row.target || value.state !== row.state)) fail("local_message_index_invalid");
    if (kind === "thread" && (scopeKey(value.scope) !== row.scope || threadKey(value.scope, value.threadId) !== row.id
      || value.updatedAt !== row.updated || Number(value.archived) !== row.archived
      || Number(value.deleted === true) !== row.deleted || (value.deleteThrough ?? 0) !== row.delete_through
      || (value.purgeAfter ?? 0) !== row.purge_after || Number(value.purgePending === true) !== row.purge_pending)) fail("local_message_index_invalid");
    return value;
  }
  async function locked(callback) {
    if (closed) fail("local_message_store_closed");
    return L.withPathMutationQueue(storePath, async () => { await assertFiles(); return callback(await readMeta()); });
  }
  function rawById(id) { return get("SELECT * FROM messages WHERE id=?", token("message", L.safeId(id, "local_message_id_invalid"))); }
  function rawOutgoing(id) { return get("SELECT * FROM messages WHERE client=? AND direction='outgoing'", token("client", L.safeId(id, "client_message_id_invalid"))); }
  async function threadRecord(scope, threadId) {
    return openRecord("thread", get("SELECT * FROM threads WHERE id=?", threadKey(scope, threadId)));
  }
  function selectThreadScope(scope, threadId) {
    if (ownerScope && readScopeKeys(scope).includes(scopeKey(ownerScope)) && get("SELECT 1 FROM threads WHERE id=?", threadKey(ownerScope, threadId))) return ownerScope;
    return L.localHistoryScope(scope);
  }
  // Caller holds the cross-process store lock across asynchronous cryptography.
  // SQLite transactions themselves contain only synchronous prepared operations.
  async function commit(meta, change = {}) {
    const nextMeta = clone({ ...meta, ...(change.meta || {}), version: meta.version + 1 });
    const messages = [], records = [];
    const updatedThreads = new Map();
    const changedMessages = new Map((change.messages || []).map((item) => [item.localMessageId, item]));
    for (const claim of [...(change.claims || []), ...(change.deleteClaims || [])]) {
      if (!changedMessages.has(claim.localMessageId)) {
        const message = await openMessage(rawById(claim.localMessageId));
        if (!message) fail("local_message_claim_anchor_invalid");
        changedMessages.set(claim.localMessageId, message);
      }
    }
    for (const message of changedMessages.values()) {
      const id = token("message", message.localMessageId), previous = get("SELECT * FROM messages WHERE id=?", id);
      const seq = previous?.seq ?? ++nextMeta.sequence;
      const previousRecord = previous ? decode("message", previous.payload) : null;
      const previousIndex = previous ? await verifiedMessageIndex(previous, previousRecord) : null;
      const anchors = new Map((previousRecord?.claimAnchors || []).map((claim) => [claim.id, claim]));
      for (const claim of change.deleteClaims || []) if (claim.localMessageId === message.localMessageId) anchors.delete(claim.id);
      for (const claim of change.claims || []) if (claim.localMessageId === message.localMessageId) anchors.set(claim.id, clone(claim));
      const claimAnchors = [...anchors.values()];
      const { base, friendTarget } = storedMessage(message);
      const index = messageIndex(base, seq, (previous?.version ?? 0) + 1, claimAnchors);
      for (const [record, sign] of [[previousIndex, -1], [index, 1]]) {
        if (!record || record.deleted) continue;
        applyCountDelta(nextMeta.globalCounts, record, sign);
        applyCountDelta(nextMeta.scopeCounts[record.scope] ||= emptyCounts(), record, sign);
      }
      messages.push({ ...index, payload: encode({ message: base, index, claimAnchors }), friend_target: friendTarget,
        previousVersion: previous?.version ?? null });
      const movedThread = previousIndex != null && previousIndex.thread !== index.thread;
      if (movedThread && previousIndex.thread) {
        const oldThread = updatedThreads.get(previousIndex.thread) || await openRecord("thread", get("SELECT * FROM threads WHERE id=?", previousIndex.thread));
        if (!oldThread) fail("local_message_index_invalid");
        updatedThreads.set(oldThread.id, { ...oldThread,
          unreadCount: oldThread.unreadCount - previousIndex.unread,
          outgoingProtectedCount: oldThread.outgoingProtectedCount - previousIndex.outgoing_protected,
          taskProtectedCount: 0 });
      }
      if (index.thread) {
        const { binding, scope, threadId, legacy } = messageOwner(message);
        let thread = updatedThreads.get(index.thread) || await threadRecord(scope, threadId);
        if (!thread) thread = { id: index.thread, version: 0, scope, binding, legacy, threadId,
          peerPrincipalId: binding?.peerPrincipalId ?? message.peerPrincipalId ?? (message.direction === "incoming" ? message.senderPrincipalId : null),
          peerHelloLynkId: message.peerHelloLynkId ?? (message.direction === "incoming" ? message.senderHelloLynkId : message.recipientHelloLynkId) ?? null,
          archived: false, updatedAt: message.updatedAt,
          unreadCount: 0, outgoingProtectedCount: 0, taskProtectedCount: 0 };
        // A new or newly bound message restores the receiving conversation.
        thread = { ...thread, archived: index.deleted || (previous && !movedThread) ? thread.archived : false,
          deleted: index.deleted || (previous && !movedThread) ? thread.deleted : false,
          updatedAt: thread.updatedAt > message.updatedAt ? thread.updatedAt : message.updatedAt,
          unreadCount: thread.unreadCount + index.unread - (movedThread ? 0 : previousIndex?.unread ?? 0),
          outgoingProtectedCount: thread.outgoingProtectedCount + index.outgoing_protected - (movedThread ? 0 : previousIndex?.outgoing_protected ?? 0),
          taskProtectedCount: 0 };
        updatedThreads.set(index.thread, thread);
      }
    }
    for (const thread of change.threads || []) updatedThreads.set(thread.id, thread);
    for (const thread of change.deleteThreads || []) {
      for (const group of all("SELECT direction,status,count(*) AS n,sum(unread) AS unread FROM messages WHERE thread=? AND seq<=? AND deleted=0 GROUP BY direction,status", thread.id, thread.deleteThrough)) {
        for (const counts of [nextMeta.globalCounts, nextMeta.scopeCounts[scopeKey(thread.scope)]]) {
          if (!counts) fail("local_message_index_invalid");
          if (group.direction === "incoming") { counts.inbox.total -= group.n; counts.inbox.unread -= group.unread; }
          else applyCountDelta(counts, { ...group, deleted: 0 }, -group.n);
        }
      }
      updatedThreads.set(thread.id, { ...thread, unreadCount: 0, outgoingProtectedCount: 0, taskProtectedCount: 0 });
    }
    for (const thread of updatedThreads.values()) records.push({ kind: "thread", value: { ...thread, version: thread.version + 1 } });
    for (const value of change.claims || []) records.push({ kind: "claim", value });
    for (const value of change.readers || []) records.push({ kind: "reader", value });
    for (const value of change.settings || []) records.push({ kind: "setting", value });
    for (const value of change.batches || []) records.push({ kind: "batch", value });
    for (const record of records) record.payload = encode(record.value);
    const metaPayload = encode(nextMeta);
    await options.fault?.("before-commit");
    db.exec("BEGIN IMMEDIATE");
    try {
      if (get("SELECT version FROM meta WHERE id=1").version !== meta.version) fail("local_message_store_conflict", { retryable: true });
      for (const thread of change.deleteThreads || []) run("UPDATE messages SET deleted=1,unread=0,outgoing_protected=0,bytes=0 WHERE thread=? AND seq<=?", thread.id, thread.deleteThrough);
      const columns = [...INDEX_COLUMNS, "payload", "friend_target"];
      for (const row of messages) {
        const current = get("SELECT version FROM messages WHERE id=?", row.id);
        if ((current?.version ?? null) !== row.previousVersion) fail("local_message_store_conflict", { retryable: true });
        run(`INSERT INTO messages(${columns.join(",")}) VALUES(${columns.map(() => "?").join(",")}) ON CONFLICT(id) DO UPDATE SET ${columns.filter((key) => key !== "id").map((key) => `${key}=excluded.${key}`).join(",")}`, ...columns.map((key) => row[key]));
      }
      for (const { kind, value, payload } of records) {
        if (kind === "thread") run("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,updated=excluded.updated,archived=excluded.archived,version=excluded.version,payload=excluded.payload,deleted=excluded.deleted,delete_through=excluded.delete_through,purge_after=excluded.purge_after,purge_pending=excluded.purge_pending", value.id, scopeKey(value.scope), value.updatedAt, Number(value.archived), value.version, payload, Number(value.deleted === true), value.deleteThrough ?? 0, value.purgeAfter ?? 0, Number(value.purgePending === true));
        else if (kind === "claim") run("INSERT INTO claims VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET outcome=excluded.outcome,version=excluded.version,payload=excluded.payload", value.id, token("message", value.localMessageId), token("delegate", value.delegateId), value.outcome, value.version, payload);
        else if (kind === "batch") run("INSERT INTO inbox_batches VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,version=excluded.version,payload=excluded.payload", value.id, token("delegate", value.delegateId), value.adapterId, value.target, value.state, value.version, payload);
        else run(`INSERT INTO ${kind === "reader" ? "readers" : "settings"} VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,payload=excluded.payload`, value.id, value.version, payload);
      }
      for (const value of change.deleteClaims || []) run("DELETE FROM claims WHERE id=?", value.id);
      for (const value of change.deleteBatches || []) run("DELETE FROM inbox_batches WHERE id=?", value.id);
      run("UPDATE meta SET version=?,payload=? WHERE id=1", nextMeta.version, metaPayload);
      // Synchronous fault injection exercises rollback without an awaited transaction.
      options.transactionFault?.("before-commit");
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    await options.fault?.("after-commit");
    return nextMeta;
  }

  function storedMessage(message) {
    if (message.targetConversationTitle) {
      L.validateCurrentMessage(message);
      const { targetConversationTitle: title, e2ee, e2eePreparation: preparation, ...base } = message;
      // The previous Host still reads the text, status and peer. It cannot
      // reuse this ciphertext or prepare a send without confirming the title.
      return { base: { ...base, e2ee: null }, friendTarget: encode({ title, e2ee, preparation }) };
    }
    if (message.friendTargetHeld) {
      L.validateCurrentMessage(message);
      const { friendTargetHeld: _held, targetConversationId: heldTargetId, ...base } = message;
      // Old readers use the target ID to authorize a manual read. Leave both
      // that assignment and automatic wake off in the compatible record.
      return { base: { ...base, automaticDeliveryState: "expired" }, friendTarget: encode({ heldTargetId }) };
    }
    return { base: message, friendTarget: null };
  }
  async function initialize() {
    await L.assertMessageStoreAccess(dbPath, null, { create: true });
    let created = false;
    try { const handle = await open(dbPath, "wx", 0o600); await handle.close(); created = true; await options.fault?.("database-created"); } catch (error) { if (error.code !== "EEXIST") throw error; }
    await assertFiles(); identity = await lstat(dbPath);
    db = new DatabaseSync(dbPath, { timeout: 5000 });
    if (get("SELECT 1 FROM sqlite_schema WHERE type='table' LIMIT 1") && get("PRAGMA user_version").user_version !== 2) {
      fail("local_message_index_version_unsupported");
    }
    // Pointer maps must be enabled before the first table exists. Never run a
    // whole-database VACUUM to retrofit an already-created database.
    if (!get("SELECT 1 FROM sqlite_schema WHERE type='table' LIMIT 1")) {
      db.exec("PRAGMA auto_vacuum=INCREMENTAL;");
      if (get("PRAGMA auto_vacuum").auto_vacuum !== 2) fail("local_message_index_vacuum_mode_invalid");
    }
    db.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA trusted_schema=OFF;");
    db.exec(SQL);
    // Keep the previous release's validated message shape and indexes. Its
    // explicit upserts preserve this optional column. Its deletes erase it too.
    if (!all("PRAGMA table_info(messages)").some(column => column.name === "friend_target"))
      db.exec("ALTER TABLE messages ADD COLUMN friend_target TEXT");
    db.exec(`CREATE TRIGGER IF NOT EXISTS message_deleted_friend_target
      AFTER UPDATE OF deleted ON messages WHEN NEW.deleted=1 AND NEW.friend_target IS NOT NULL
      BEGIN UPDATE messages SET friend_target=NULL WHERE id=NEW.id; END;`);
    await options.fault?.("schema-created");
    if (!get("SELECT 1 FROM meta")) {
      if (!created) {
        if (await isLegacyFenced()) fail("local_message_index_metadata_missing");
        // Before the format fence the legacy input is authoritative; a crash
        // can leave an empty DB or a schema-only staging database.
        await L.readStore(storePath, profileId, L.MAX_STORE_BYTES, null);
      }
      const value = { contract: HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT, profileId, version: 0, highWater: 0, sequence: 0, migrated: false,
        countsVersion: 1, globalCounts: emptyCounts(), scopeCounts: {}, indexKey: crypto.randomBytes(32).toString("hex") };
      run("INSERT INTO meta VALUES(1,0,?)", encode(value));
    }
    let meta = await readMeta();
    indexKey = Buffer.from(meta.indexKey, "hex");
    if (!meta.migrated && meta.migrationPrepared === true) {
      const fenced = await isLegacyFenced();
      if (fenced || meta.sourceDigest === await legacySourceDigest()) {
        if (!fenced) await installLegacyFence();
        meta = await commit(meta, { meta: { migrated: true, migrationPrepared: false } });
      }
    }
    if (!meta.migrated) {
      // An interrupted staging import is rebuilt from untouched legacy inputs.
      db.exec("BEGIN IMMEDIATE; DELETE FROM messages; DELETE FROM claims; DELETE FROM readers; DELETE FROM threads; DELETE FROM settings; COMMIT;");
      meta = await commit(meta, { meta: { highWater: 0, sequence: 0, globalCounts: emptyCounts(), scopeCounts: {} } });
      let legacyMetadata, batch = [], previousSource;
      for await (const record of streamLegacyLocalMessages(options)) {
        if (record.kind === "metadata") { legacyMetadata = record; continue; }
        // Materialize the latest archive record before considering main-file
        // retry claims. The old store persisted its unknown claim before
        // removing the archive proof, so that exact interrupted state is safe
        // to recover without attempting delivery.
        if (previousSource === "archive" && record.source !== "archive" && batch.length) {
          meta = await commit(meta, { messages: batch }); batch = [];
        }
        previousSource = record.source;
        let message = record.message;
        if (record.source === "main" && message.direction === "outgoing") {
          const unknown = message.status === "delivery_state_unknown" && message.lastErrorCode === "awaiting_relay_result";
          const interrupted = message.status === "delivery_state_unconfirmed" && message.lastErrorCode === "e2ee_delivery_attempt_interrupted";
          if ((unknown && !L.deliveryAttemptHasLiveOwner(message)) || interrupted) {
            const retained = await openMessage(rawById(message.localMessageId));
            if (retained?.direction === "outgoing" && retained.clientMessageId === message.clientMessageId && retained.status === "failed_permanent") message = retained;
          }
        }
        batch.push(message);
        if (batch.length === 256) { meta = await commit(meta, { messages: batch }); batch = []; await options.fault?.("migration-batch"); }
      }
      if (batch.length) meta = await commit(meta, { messages: batch });
      const old = legacyMetadata?.store || {};
      const claims = (old.inboxClaims || []).map((value) => ({ ...value, id: token("claim", `${value.delegateId}\0${value.localMessageId}`), version: 1 }));
      const readers = (old.inboxReaders || []).map((value) => ({ ...value, id: token("reader", `${value.adapterId}\0${value.delegateId}`), version: 1 }));
      const highest = get("SELECT coalesce(max(receipt),0) AS n FROM messages").n;
      if (highest > (old.receiptHighWater ?? 0)) fail("local_message_receipt_sequence_invalid");
      for (let offset = 0; offset < claims.length; offset += 256) meta = await commit(meta, { claims: claims.slice(offset, offset + 256) });
      meta = await commit(meta, { readers, meta: { highWater: old.receiptHighWater ?? 0 } });
      for (const hidden of legacyMetadata?.history?.hidden || []) {
        const thread = await threadRecord(hidden, hidden.threadId);
        if (thread) {
          const known = new Set(hidden.knownMessageIds.map((id) => token("message", id)));
          const changed = all("SELECT id FROM messages WHERE scope=? AND thread=?", scopeKey(hidden), thread.id).some((row) => !known.has(row.id));
          if (!changed && !thread.unreadCount && !thread.outgoingProtectedCount) meta = await commit(meta, { threads: [{ ...thread, archived: true }] });
        }
      }
      const integrity = get("PRAGMA integrity_check");
      if (Object.values(integrity)[0] !== "ok") fail("local_message_index_invalid");
      meta = await commit(meta, { meta: { migrationPrepared: true, sourceDigest: await legacySourceDigest() } });
      await options.fault?.("migration-before-switch");
      await installLegacyFence();
      await options.fault?.("migration-after-fence");
      meta = await commit(meta, { meta: { migrated: true, migrationPrepared: false } });
    }
    if (!await isLegacyFenced()) fail("local_message_migration_fence_missing");
    await purgeDeletedBatch();
  }

  async function purgeDeletedBatch(threadKeyValue = null) {
    const row = threadKeyValue == null
      ? get("SELECT * FROM threads WHERE purge_pending=1 ORDER BY id LIMIT 1")
      : get("SELECT * FROM threads WHERE id=? AND purge_pending=1", threadKeyValue);
    if (!row) return false;
    const thread = await openRecord("thread", row), meta = await readMeta();
    const rows = all("SELECT * FROM messages WHERE thread=? AND seq>? AND seq<=? ORDER BY seq LIMIT 100", thread.id, thread.purgeAfter ?? 0, thread.deleteThrough);
    const messages = [];
    for (const message of rows) messages.push(await openMessage(message));
    const done = rows.length < 100;
    await commit(meta, { messages, threads: [{ ...thread, purgeAfter: rows.at(-1)?.seq ?? thread.purgeAfter ?? 0, purgePending: !done }] });
    await options.fault?.("conversation-delete-batch");
    return !done;
  }
  async function legacySourceDigest() {
    const hash = crypto.createHash("sha256");
    for (const file of [storePath, archivePath, localHistoryPath]) {
      let stat; try { stat = await lstat(file); } catch (error) { if (error.code === "ENOENT") { hash.update("absent\0"); continue; } throw error; }
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail("local_message_store_invalid");
      hash.update(`${stat.size}\0`);
      for await (const chunk of createReadStream(file)) hash.update(chunk);
    }
    return hash.digest("hex");
  }
  async function isLegacyFenced() {
    try {
      const raw = await readFenceInput(storePath);
      const value = JSON.parse(raw.toString("utf8"));
      return value?.contract === HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT && value.storage === "sqlite" && value.profileId === profileId;
    } catch (error) { if (error.code === "ENOENT") return false; throw error; }
  }
  async function readFenceInput(file) {
    await L.assertMessageStoreAccess(file, null, { create: false });
    const before = await lstat(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > 16 * 1024 * 1024) fail("local_message_store_invalid");
    const handle = await open(file, "r");
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.ino !== before.ino || opened.size !== before.size || (process.platform !== "win32" && opened.dev !== before.dev)) fail("local_message_store_invalid");
      const bytes = await handle.readFile();
      if (bytes.length > 16 * 1024 * 1024) fail("local_message_store_invalid");
      return bytes;
    } finally { await handle.close(); }
  }
  async function installLegacyFence() {
    let raw; try { raw = await readFenceInput(storePath); } catch (error) { if (error.code !== "ENOENT") throw error; }
    if (raw) {
      const current = JSON.parse(raw.toString("utf8"));
      if (current?.contract === HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT && current.storage === "sqlite") return;
      const backup = `${storePath}.pre-indexed.json`;
      let present = false;
      try { if (!(await readFenceInput(backup)).equals(raw)) fail("local_message_migration_backup_conflict"); present = true; }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      if (!present) {
        const staging = migrationTemporary("backup");
        const copy = await open(staging, "wx", 0o600);
        try { await copy.writeFile(raw); await copy.sync(); } finally { await copy.close(); }
        await options.fault?.("migration-backup-staged");
        await rename(staging, backup); await L.syncParentDirectory(backup); await L.syncParentDirectory(staging);
      }
    }
    await writeIndexedFence();
  }
  async function writeIndexedFence() {
    const temporary = migrationTemporary("fence");
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(JSON.stringify({ contract: HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT, storage: "sqlite", profileId })); await handle.sync(); } finally { await handle.close(); }
    await replaceLocalStoreFileWithRetry(temporary, storePath);
    await L.syncParentDirectory(storePath);
  }
  function migrationTemporary(kind) {
    const directory = path.dirname(storePath), parent = path.basename(directory) === "messages" ? path.dirname(directory) : directory;
    return path.join(parent, `.hellolynk-indexed-${profileId}-${kind}-${crypto.randomUUID()}.tmp`);
  }

  try { await L.withPathMutationQueue(storePath, initialize); }
  catch (error) { try { db?.close(); } catch {} throw error; }

  async function mutateMessage(id, outgoing, callback, allowDeleted = false) {
    return locked(async (meta) => {
      const row = outgoing ? rawOutgoing(id) : rawById(id), message = await openMessage(row);
      if (!message || message.direction !== (outgoing ? "outgoing" : "incoming")) fail(outgoing ? "local_outgoing_message_not_found" : "local_incoming_message_not_found");
      if (message.messageType === DELETED && !allowDeleted) throw L.localHistoryFailure("record_not_found");
      const changed = await callback(message);
      if (changed !== false) await commit(meta, { messages: [message] });
      return clone(message);
    });
  }
  function reclaimUnusedPages() {
    // A maintenance tick frees at most 64 freelist pages. Logical UTF-8 body
    // bytes reported by history stats are not a promise of equal disk savings:
    // retained facts, occupied pages and live WAL readers affect reclamation.
    const before = get("PRAGMA freelist_count").freelist_count;
    let checkpointBusy = false;
    db.exec("PRAGMA busy_timeout=0;");
    try {
      if (before > 0) db.exec("PRAGMA incremental_vacuum(64);");
      // With a zero busy timeout this never waits for an active reader/writer;
      // SQLite leaves its durable WAL in place and a later tick retries.
      checkpointBusy = get("PRAGMA wal_checkpoint(TRUNCATE)").busy !== 0;
    } catch (error) {
      if (![5, 6].includes(Number(error.errcode) & 255)) throw error;
      checkpointBusy = true;
    } finally { db.exec("PRAGMA busy_timeout=5000;"); }
    return { reclaimedPageCount: Math.max(0, before - get("PRAGMA freelist_count").freelist_count), checkpointBusy };
  }
  function scopeWhere(scope) { if (!scope) return ["", []]; const keys = readScopeKeys(scope); return [` AND scope IN (${keys.map(() => "?").join(",")})`, keys]; }
  async function readMessages(sql, ...args) {
    const result = [];
    for (const row of all(sql, ...args)) result.push(await openMessage(row));
    return result;
  }
  async function protectedReason(message) {
    if (L.localHistoryUnread(message)) return "unread";
    if (message.direction === "outgoing" && !L.localHistorySent(message)) return "outgoing";
    return null;
  }
  function assertScope(message, scope) {
    scope = L.localHistoryScope(scope);
    if (L.localHistoryBinding(message, scope)) return;
    const owner = messageOwner(message);
    if (owner.legacy && ownerScope && scope.region === ownerScope.region && scope.principalId === ownerScope.principalId) return;
    throw L.localHistoryFailure("record_not_found");
  }
  async function readerBoundary(adapterId, delegateId) {
    L.inboxReaderId(adapterId); L.inboxReaderId(delegateId);
    const id = token("reader", `${adapterId}\0${delegateId}`), record = await openRecord("reader", get("SELECT * FROM readers WHERE id=?", id));
    if (record && (record.adapterId !== adapterId || record.delegateId !== delegateId)) fail("local_message_index_invalid");
    return record;
  }
  async function exposeIncomingToModel(meta, message, authorize) {
    const owner = messageOwner(message);
    const thread = await threadRecord(owner.scope, owner.threadId);
    const automatic = !owner.legacy && !thread?.deleted && thread?.autoReadAfterAi === true;
    const next = automatic && L.localHistoryUnread(message)
      ? { ...message, status: "fetched", updatedAt: new Date(now()).toISOString(), nextRetryAt: null, lastErrorCode: null }
      : message;
    // The human opted in for this exact local instance conversation. Metadata
    // listing, delivery, failed authorization and claim completion never enter
    // this path. Only the exposed body may change its human unread state.
    // Report a human-read transition, not merely an enabled preference. Reading
    // an already-read body must not publish a fresh workbench change event.
    const projected = await authorize(clone(next), meta.highWater, next !== message);
    if (next !== message) await commit(meta, { messages: [next] });
    return projected;
  }
  async function inboxClaim(input, authorize, finish) {
    return locked(async (meta) => {
      const keys = ["adapterId", "conversationKey", "delegateId", "localMessageId", ...(finish ? ["claimId", "outcome"] : [])].sort();
      if (!input || Object.keys(input).sort().join() !== keys.join() || typeof authorize !== "function") fail("local_inbox_claim_invalid");
      for (const key of ["adapterId", "conversationKey", "delegateId", "localMessageId"]) L.inboxReaderId(input[key]);
      if (finish && (!/^inclaim_[a-f0-9]{48}$/.test(input.claimId) || !["completed", "unknown"].includes(input.outcome))) fail("local_inbox_claim_invalid");
      const reader = await readerBoundary(input.adapterId, input.delegateId), message = await openMessage(rawById(input.localMessageId));
      const binding = message && getMessageConversationBinding(message);
      if (!reader || !message || message.direction !== "incoming" || (!finish && message.messageType === DELETED) || !binding
        || binding.localDelegateId !== input.delegateId || instanceConversationKey(binding) !== input.conversationKey
        || !Number.isSafeInteger(message.receiptSeq) || message.receiptSeq <= reader.afterSeq) fail("local_inbox_claim_ineligible");
      await authorize(clone(message), reader.afterSeq, meta.highWater);
      const id = token("claim", `${input.delegateId}\0${input.localMessageId}`);
      const existing = await openRecord("claim", get("SELECT * FROM claims WHERE id=?", id));
      if (finish) {
        if (!existing || existing.adapterId !== input.adapterId || existing.claimId !== input.claimId || existing.conversationKey !== input.conversationKey || existing.receiptSeq !== message.receiptSeq) fail("local_inbox_claim_mismatch");
        if (existing.outcome !== "inflight" && existing.outcome !== input.outcome) fail("local_inbox_claim_terminal");
        const next = { ...existing, outcome: input.outcome, version: existing.version + 1 };
        await commit(meta, { claims: [next] });
        await authorize(clone(message), reader.afterSeq, meta.highWater);
        return { claimId: next.claimId, outcome: next.outcome };
      }
      if (existing) return { claimed: false, claimId: null, message: null };
      const claim = { ...input, id, version: 1, claimId: `inclaim_${crypto.randomBytes(24).toString("hex")}`, receiptSeq: message.receiptSeq, outcome: "inflight" };
      const claimedMeta = await commit(meta, { claims: [claim] });
      await options.fault?.("claim-committed");
      // Keep the durable claim and final authorization check. Human unread is
      // retained by default; its separate per-conversation opt-in is applied
      // only when this claim actually exposes the body.
      const projected = await exposeIncomingToModel(claimedMeta, message,
        (value, highWater, automatic) => authorize(value, reader.afterSeq, highWater, automatic));
      return { claimed: true, claimId: claim.claimId, message: projected };
    });
  }

  const api = {
    path: storePath, dbPath, archivePath, localHistoryPath,
    diagnostics() { return { ...metrics }; },
    async close() { if (closed) return; await L.withPathMutationQueue(storePath, async () => { if (closed) return; closed = true; db.close(); }); },
    async getReceiptHighWater() { return locked((meta) => meta.highWater); },
    async readWorkbenchRevision() { return locked((meta) => `indexed_${meta.version}`); },
    async getInboxReaderBoundary(adapterId, delegateId) { return locked(async () => (await readerBoundary(adapterId, delegateId))?.afterSeq ?? null); },
    async activateInboxReader(adapterId, delegateId) {
      return locked(async (meta) => {
        const existing = await readerBoundary(adapterId, delegateId); if (existing) return existing.afterSeq;
        const reader = { id: token("reader", `${adapterId}\0${delegateId}`), version: 1, adapterId, delegateId, afterSeq: meta.highWater };
        await commit(meta, { readers: [reader] }); return reader.afterSeq;
      });
    },
    async listInboxClaimIds(delegateId) {
      L.inboxReaderId(delegateId);
      return locked(async () => { const result = []; for (const row of all("SELECT * FROM claims WHERE delegate=?", token("delegate", delegateId))) result.push((await openRecord("claim", row)).localMessageId); return result; });
    },
    claimInboxMessage: (input, authorize) => inboxClaim(input, authorize, false),
    finishInboxClaim: (input, authorize) => inboxClaim(input, authorize, true),
    async readIncomingForModel(id, authorize) {
      if (typeof authorize !== "function") fail("local_inbox_read_invalid");
      return locked(async (meta) => {
        const message = await openMessage(rawById(id));
        if (!message || message.direction !== "incoming" || message.messageType === DELETED) throw L.localHistoryFailure("record_not_found");
        return exposeIncomingToModel(meta, message, authorize);
      });
    },
    async getIncoming(id) { return locked(async () => { const message = await openMessage(rawById(id)); return message?.direction === "incoming" ? message : null; }); },
    async getOutgoing(id) { return locked(() => openMessage(rawOutgoing(id))); },
    async list() { return locked(() => readMessages("SELECT * FROM messages WHERE deleted=0 ORDER BY seq")); },
    async listInboxMessagesForDelegate(delegateId, { unreadOnly = false, limit = null, scope = null, before = null } = {}) {
      const delegate = token("delegate", L.safeId(delegateId, "local_inbox_reader_invalid"));
      if (typeof unreadOnly !== "boolean") fail("local_inbox_reader_invalid");
      const bound = limit == null ? null : limitOf(limit, 1000);
      // An older page continues a bounded newest-first window.
      if (before != null && bound == null) fail("local_history_cursor_invalid");
      const beforeId = before == null ? null : L.safeId(before, "local_history_cursor_invalid");
      return locked(() => {
        const [where, args] = scopeWhere(scope);
        let older = "", anchorArgs = [];
        if (beforeId != null) {
          // Any incoming message of this AI and account anchors the page, even one
          // deleted since it was listed, so paging continues from its position.
          const anchor = rawById(beforeId);
          if (!anchor || anchor.delegate !== delegate || anchor.direction !== "incoming"
            || (scope && !readScopeKeys(scope).includes(anchor.scope))) fail("local_history_cursor_invalid");
          older = " AND (created<? OR (created=? AND seq<?))";
          anchorArgs = [anchor.created, anchor.created, anchor.seq];
        }
        return readMessages(`SELECT * FROM messages WHERE delegate=? AND direction='incoming' AND deleted=0${unreadOnly ? " AND unread=1" : ""}${where}${older}
          ORDER BY ${bound == null ? "seq" : "created DESC,seq DESC"}${bound == null ? "" : " LIMIT ?"}`,
        delegate, ...args, ...anchorArgs, ...(bound == null ? [] : [bound]));
      });
    },
    async listActive() { return locked(() => readMessages("SELECT * FROM messages WHERE deleted=0 AND (direction='incoming' AND status NOT IN ('fetched','pending_human_confirmation') OR direction='outgoing' AND status NOT IN ('cancelled','delivered_to_live_connection','delivery_state_unconfirmed','failed_permanent')) ORDER BY seq")); },
    async queryOutbox({ scope = null, limit = 100 } = {}) { return locked(() => { const [where, args] = scopeWhere(scope); return readMessages(`SELECT * FROM messages WHERE deleted=0 AND direction='outgoing' AND status NOT IN ('cancelled','delivered_to_live_connection','delivery_state_unconfirmed')${where} ORDER BY seq DESC LIMIT ?`, ...args, limitOf(limit, 1000)); }); },
    async listPendingInboxCandidates({ delegateId, afterSeq = 0, limit = 1000, cursor = null, conversationKeys = null, receivedSince = null, localMessageId = null, modelPending = false }) {
      L.inboxReaderId(delegateId);
      const boundary = cursor ?? afterSeq;
      if (!Number.isSafeInteger(boundary) || boundary < 0 || typeof modelPending !== "boolean") fail("local_inbox_reader_invalid");
      if (conversationKeys != null && (!Array.isArray(conversationKeys) || conversationKeys.length > 1000)) fail("local_inbox_reader_invalid");
      const cutoff = receivedSince == null ? null : checkedTime(receivedSince);
      // A single-message recheck uses the same pending conditions by primary key.
      const only = localMessageId == null ? null : token("message", L.safeId(localMessageId, "local_inbox_reader_invalid"));
      return locked(async () => {
        if (conversationKeys?.length === 0) return [];
        const accepted = conversationKeys == null ? null : [...new Set(conversationKeys.map((id) => L.safeId(id, "local_inbox_reader_invalid")))];
        const restriction = `${only == null ? "" : " AND m.id=?"}${accepted ? ` AND m.route IN (${accepted.map(() => "?").join(",")})` : ""}`;
        const messages = await readMessages(`SELECT m.* FROM messages m WHERE m.delegate=? AND m.direction='incoming' AND m.deleted=0 AND ${modelPending ? "(m.admitted=0 OR EXISTS (SELECT 1 FROM claims c WHERE c.message=m.id AND c.delegate=m.delegate AND c.outcome IN ('reserved','delivered')))" : "m.admitted=0"} AND m.receipt>?${restriction}${cutoff == null ? "" : " AND m.created>=?"} ORDER BY m.receipt LIMIT ?`, token("delegate", delegateId), boundary, ...(only == null ? [] : [only]), ...(accepted ? accepted.map((id) => token("route", id)) : []), ...(cutoff == null ? [] : [cutoff]), limitOf(limit, 1000));
        if (accepted && messages.some((message) => { const binding = getMessageConversationBinding(message); return !binding || !accepted.includes(instanceConversationKey(binding)); })) fail("local_message_index_invalid");
        return messages;
      });
    },
    async getMessageCounts(scope = null) {
      return locked((meta) => {
        if (scope == null) return clone(meta.globalCounts);
        const result = emptyCounts();
        for (const key of readScopeKeys(scope)) if (meta.scopeCounts[key]) addCounts(result, meta.scopeCounts[key]);
        return result;
      });
    },
  };
  return Object.assign(api, batchApi(), outgoingApi(), historyApi(), incomingApi());

  // Delivery is a transport receipt, not a promise that an AI completed work.
  // The worker owns native routing; this ledger owns selection, admission and
  // the one-retry budget across process restarts. It never resends external mail.
  function batchApi() {
    const describe = (batch) => ({ batchId: batch.id, target: batch.target, state: batch.state,
      count: batch.messageIds.length, expiredCount: batch.expiredCount, full: batch.full,
      highWater: batch.highWater, oldestReceipt: batch.oldestReceipt, attempts: batch.attempts });
    function identity(input) {
      L.inboxReaderId(input?.adapterId); L.inboxReaderId(input?.delegateId);
    }
    async function load(input) {
      identity(input); L.inboxReaderId(input.batchId);
      const batch = await openRecord("batch", get("SELECT * FROM inbox_batches WHERE id=?", input.batchId));
      if (!batch || batch.adapterId !== input.adapterId || batch.delegateId !== input.delegateId) fail("local_inbox_batch_not_found");
      return batch;
    }
    async function assignment(input, batches) {
      identity(input);
      let batchId = input.batchId;
      if (batchId == null) {
        L.inboxReaderId(input.localMessageId);
        const claim = await openRecord('claim', get('SELECT * FROM claims WHERE id=?',
          token('claim', input.delegateId + '\0' + input.localMessageId)));
        if (!claim || claim.adapterId !== input.adapterId || !claim.batchId) return null;
        batchId = claim.batchId;
      }
      if (!batches.has(batchId)) batches.set(batchId, await load({ ...input, batchId }));
      const batch = batches.get(batchId);
      return { batchId: batch.id, target: batch.target, nativeThreadId: batch.nativeThreadId ?? null };
    }
    async function candidates(input, batch, authorize, meta) {
      identity(input);
      if (!Array.isArray(input.candidates) || input.candidates.length > 1000 || typeof authorize !== "function") fail("local_inbox_batch_invalid");
      const reader = await readerBoundary(input.adapterId, input.delegateId);
      if (!reader) fail("local_inbox_claim_ineligible");
      const result = [];
      for (const id of new Set(input.candidates)) {
        const row = rawById(id);
        if (!row || row.deleted) continue;
        const message = await openMessage(row), binding = getMessageConversationBinding(message);
        if (!binding || message.direction !== "incoming" || binding.localDelegateId !== input.delegateId) fail("local_inbox_claim_ineligible");
        if (message.receiptSeq <= reader.afterSeq || row.admitted || (batch && message.receiptSeq > batch.highWater)) continue;
        // A newly resolved target may reveal a gap in an interrupted collection.
        // Keep that newer letter pending; resumption only appends older receipts.
        if (batch && message.receiptSeq >= batch.oldestReceipt) continue;
        await authorize(clone(message), reader.afterSeq, meta.highWater);
        result.push(message);
      }
      return result.sort((a, b) => b.receiptSeq - a.receiptSeq);
    }
    function admission(input, message, batch, outcome) {
      return { id: token("claim", `${input.delegateId}\0${message.localMessageId}`), version: 1,
        adapterId: input.adapterId, delegateId: input.delegateId, localMessageId: message.localMessageId,
        conversationKey: instanceConversationKey(getMessageConversationBinding(message)),
        receiptSeq: message.receiptSeq, batchId: batch.id, outcome };
    }
    async function append(meta, input, batch, messages) {
      if (batch.state !== "reserved" || batch.attempts !== 0) fail("local_inbox_batch_started");
      if (messages.some(message => message.receiptSeq >= batch.oldestReceipt)) fail("local_inbox_batch_order_invalid");
      const claims = [], expired = [];
      for (const message of messages) {
        const length = Array.from(message.text).length;
        batch.full ||= batch.characters + length > 20_000;
        claims.push(admission(input, message, batch, batch.full ? "expired" : "reserved"));
        if (batch.full) {
          batch.expiredCount++;
          expired.push({ ...message, automaticDeliveryState: "expired" });
        } else {
          batch.messageIds.push(message.localMessageId); batch.characters += length;
        }
        batch.oldestReceipt = message.receiptSeq;
      }
      if (messages.length || batch.version === 0) {
        batch.version++;
        await commit(meta, { claims, messages: expired, batches: [batch] });
      }
      return describe(batch);
    }
    return {
      async reserveInboxBatch(input, authorize) {
        return locked(async meta => {
          identity(input); L.inboxReaderId(input.target);
          let batch = input.batchId ? await load(input) : await openRecord("batch", get(
            "SELECT * FROM inbox_batches WHERE delegate=? AND adapter=? AND target=? AND state='reserved' AND json_extract(payload,'$.attempts')=0 LIMIT 1",
            token("delegate", input.delegateId), input.adapterId, input.target));
          if (batch && batch.target !== input.target) fail("local_inbox_batch_not_found");
          const messages = await candidates(input, batch, authorize, meta);
          if (!batch && !messages.length) return { status: "empty" };
          if (!batch) batch = { id: `inbatch_${crypto.randomBytes(24).toString("hex")}`, version: 0,
            adapterId: input.adapterId, delegateId: input.delegateId, target: input.target, state: "reserved",
            messageIds: [], characters: 0, expiredCount: 0, attempts: 0, full: false,
            highWater: messages[0].receiptSeq, oldestReceipt: messages[0].receiptSeq + 1, createdAt: new Date(now()).toISOString() };
          return append(meta, input, batch, messages);
        });
      },
      async expireInboxBatch(input, authorize) {
        return locked(async meta => {
          const batch = await load(input);
          if (!batch.full) fail("local_inbox_batch_not_full");
          return append(meta, input, batch, await candidates(input, batch, authorize, meta));
        });
      },
      // Keep native ownership with the durable batch, not the current carrier.
      // Reading this never claims mail or changes human unread state.
      async getInboxNativeAssignment(input) {
        return locked(() => assignment(input, new Map()));
      },
      async getInboxNativeAssignments(input) {
        return locked(async () => {
          identity(input);
          if (!Array.isArray(input.localMessageIds) || input.localMessageIds.length > 1000) fail('local_inbox_batch_invalid');
          const batches = new Map(), result = {};
          for (const localMessageId of input.localMessageIds) result[localMessageId] = await assignment({ ...input, localMessageId }, batches);
          return result;
        });
      },
      async listInboxBatches(input) {
        identity(input);
        if (input.state != null && !["reserved", "delivered"].includes(input.state)) fail("local_inbox_batch_invalid");
        return locked(async () => {
          const batches = [];
          for (const row of all(`SELECT * FROM inbox_batches WHERE delegate=? AND adapter=? AND ${input.state ? "state=?" : "state!='closed'"}${input.target ? " AND target=?" : ""}`,
            token("delegate", input.delegateId), input.adapterId, ...(input.state ? [input.state] : []), ...(input.target ? [input.target] : []))) {
            const batch = await openRecord("batch", row);
            batches.push(describe(batch));
          }
          return { batches };
        });
      },
      async attemptInboxBatch(input) {
        return locked(async meta => {
          const batch = await load(input);
          if (input.attemptId != null) L.inboxReaderId(input.attemptId);
          let ownerChanged = false;
          if (input.nativeThreadId != null) {
            L.inboxReaderId(input.nativeThreadId);
            if (batch.nativeThreadId && batch.nativeThreadId !== input.nativeThreadId) fail('local_inbox_batch_owner_conflict');
            if (!batch.nativeThreadId) { batch.nativeThreadId = input.nativeThreadId; ownerChanged = true; }
          }
          // Bind the owner and register its attempt in one transaction. A late
          // owner update for the same ticket must not spend another chance.
          const replay = input.attemptId != null && batch.attemptIds?.includes(input.attemptId);
          if (batch.state !== 'reserved' || replay || batch.attempts >= 2) {
            if (ownerChanged) { batch.version++; await commit(meta, { batches: [batch] }); }
            return { ...describe(batch), attempted: batch.state === 'reserved' && Boolean(replay) };
          }
          if (!batch.messageIds.length) {
            batch.state = "closed"; batch.version++;
            await commit(meta, { batches: [batch] });
            return { ...describe(batch), attempted: false };
          }
          batch.attempts++; batch.version++;
          if (input.attemptId != null) batch.attemptIds = [...(batch.attemptIds || []), input.attemptId];
          await commit(meta, { batches: [batch] });
          return { ...describe(batch), attempted: true };
        });
      },
      async confirmInboxBatch(input) {
        return locked(async meta => {
          const batch = await load(input);
          // A fast model may claim before native confirmation. Still retain its
          // carrier, without reopening taken claims or replacing an owner.
          if (input.nativeThreadId != null) {
            L.inboxReaderId(input.nativeThreadId);
            if (batch.nativeThreadId && batch.nativeThreadId !== input.nativeThreadId) fail("local_inbox_batch_owner_conflict");
            if (!batch.nativeThreadId) {
              batch.nativeThreadId = input.nativeThreadId;
              if (batch.state !== "reserved") {
                batch.version++;
                await commit(meta, { batches: [batch] });
              }
            }
          }
          if (batch.state !== "reserved") return describe(batch);
          const claims = [];
          for (const id of batch.messageIds) {
            const claim = await openRecord("claim", get("SELECT * FROM claims WHERE id=?", token("claim", `${input.delegateId}\0${id}`)));
            if (claim?.outcome === "reserved") claims.push({ ...claim, version: claim.version + 1, outcome: "delivered" });
          }
          batch.state = "delivered"; batch.version++;
          await commit(meta, { claims, batches: [batch] });
          return describe(batch);
        });
      },
      async cancelInboxBatch(input) {
        return locked(async meta => {
          const batch = await load(input);
          // A rejection of the second attempt cannot disprove delivery of
          // the first, uncertain one. Keep its original batch/dedup boundary.
          if (batch.state !== "reserved" || batch.attempts > 1) return { ...describe(batch), cancelled: false };
          const claims = [];
          for (const id of batch.messageIds) {
            const claim = await openRecord("claim", get("SELECT * FROM claims WHERE id=?", token("claim", `${input.delegateId}\0${id}`)));
            if (claim?.outcome !== "reserved") return { ...describe(batch), cancelled: false };
            claims.push(claim);
          }
          await commit(meta, { deleteClaims: claims, deleteBatches: [batch] });
          return { ...describe(batch), cancelled: true };
        });
      },
      async claimInboxBatch(input, authorize) {
        return locked(async meta => {
          const batch = await load(input), messages = [], claims = [], read = [];
          if (typeof authorize !== "function") fail("local_inbox_batch_invalid");
          const reader = await readerBoundary(input.adapterId, input.delegateId);
          if (!reader) fail("local_inbox_claim_ineligible");
          if (batch.state !== "closed") for (const id of [...batch.messageIds].reverse()) {
            const claim = await openRecord("claim", get("SELECT * FROM claims WHERE id=?", token("claim", `${input.delegateId}\0${id}`)));
            if (!claim || !["reserved", "delivered"].includes(claim.outcome)) continue;
            const message = await openMessage(rawById(id));
            claims.push({ ...claim, version: claim.version + 1, outcome: "taken" });
            if (!message || message.messageType === DELETED) continue;
            const owner = messageOwner(message), thread = await threadRecord(owner.scope, owner.threadId);
            const automatic = thread?.autoReadAfterAi === true && L.localHistoryUnread(message);
            const next = automatic ? { ...message, status: "fetched", updatedAt: new Date(now()).toISOString(), nextRetryAt: null, lastErrorCode: null } : message;
            messages.push(await authorize(clone(next), reader.afterSeq, meta.highWater, automatic));
            if (automatic) read.push(next);
          }
          if (claims.length) {
            batch.state = "delivered"; batch.version++;
            await commit(meta, { claims, messages: read, batches: [batch] });
          }
          return { claimed: messages.length > 0, messages, expiredCount: batch.expiredCount,
            notice: messages.length ? null : "这批来信已读取，无需重复读取。" };
        });
      },
      async closeInboxBatch(input) {
        return locked(async meta => {
          const batch = await load(input);
          if (batch.state === "closed") return describe(batch);
          if (batch.state !== "delivered") fail("local_inbox_batch_not_delivered");
          const messages = [];
          for (const id of batch.messageIds) {
            const message = await openMessage(rawById(id));
            if (message && message.messageType !== DELETED && L.localHistoryUnread(message)) messages.push({ ...message,
              status: "fetched", updatedAt: new Date(now()).toISOString(), nextRetryAt: null, lastErrorCode: null });
          }
          batch.state = "closed"; batch.version++;
          await commit(meta, { messages, batches: [batch] });
          return describe(batch);
        });
      },
    };
  }

  function outgoingApi() {
    return {
      async addOutgoing(input) {
        const recipient = L.safeId(input.recipientHelloLynkId, "recipient_hellolynk_id_invalid"), client = L.safeId(input.clientMessageId, "client_message_id_invalid");
        const text = L.safeText(input.text), principal = L.safeId(input.senderPrincipalId, "sender_principal_id_invalid"), delegate = L.safeId(input.senderDelegateId, "sender_delegate_id_invalid");
        const e2ee = L.normalizeStoredE2ee(input.e2ee), provenance = L.provenanceFromStoredE2ee(e2ee, principal, delegate);
        const replyToClientMessageId = input.replyToClientMessageId == null ? null : L.safeId(input.replyToClientMessageId, "reply_target_invalid");
        const targetConversationId = input.targetConversationId == null ? null : nativeConversationId(input.targetConversationId);
        const targetConversationTitle = input.targetConversationTitle == null ? null : nativeConversationTitle(input.targetConversationTitle);
        if (targetConversationId && replyToClientMessageId) fail("native_target_conflicts_with_reply");
        if (targetConversationTitle && !targetConversationId) fail("native_target_not_authorized");
        if ((e2ee && (e2ee.envelope.protected.replyToClientMessageId ?? null) !== replyToClientMessageId)
          || replyToClientMessageId === client) fail("reply_target_invalid");
        return locked(async (meta) => {
          if (get("SELECT 1 FROM messages WHERE client=?", token("client", client))) fail("client_message_id_exists");
          const at = new Date(now()).toISOString();
          const message = { localMessageId: `local_message_${crypto.randomUUID()}`, clientMessageId: client, direction: "outgoing", peerHelloLynkId: recipient,
            senderPrincipalId: principal, senderDelegateId: delegate, ...provenance, messageType: "text", text, transportSecurity: e2ee ? L.E2EE_TRANSPORT_SECURITY : "plaintext-v0.1.0", e2ee,
            ...(replyToClientMessageId ? { replyToClientMessageId } : {}),
            ...(targetConversationId ? { targetConversationId } : {}),
            ...(targetConversationTitle ? { targetConversationTitle } : {}),
            ...(input.e2eePreparation ? { e2eePreparation: clone(input.e2eePreparation), deliveryAttemptPid: process.pid, deliveryAttemptInstance: L.PROCESS_INSTANCE_ID, deliveryAttemptStartedAt: at } : {}),
            conversationIntent: normalizeInstanceConversationBinding(input.conversationIntent), status: "pending", attempts: 0, nextRetryAt: null, lastErrorCode: null, createdAt: at, updatedAt: at };
          message.conversationBinding = getMessageConversationBinding(message);
          const changes = [message];
          if (input.resendSourceClientMessageId != null) {
            const originalId = L.safeId(input.resendSourceClientMessageId, "reply_resend_invalid");
            const original = await openMessage(rawOutgoing(originalId));
            const originalBinding = original && (getMessageConversationBinding(original) || getOutgoingConversationIntent(original));
            const newBinding = message.conversationBinding || getOutgoingConversationIntent(message);
            if (!original || original.messageType !== "text" || original.status !== "failed_permanent"
              || original.lastErrorCode !== "reply_target_deleted" || !original.replyToClientMessageId || original.resendClientMessageId
              || original.senderPrincipalId !== principal || original.senderDelegateId !== delegate || original.peerHelloLynkId !== recipient
              || !originalBinding || !newBinding || instanceConversationKey(originalBinding) !== instanceConversationKey(newBinding)
              || original.text !== text || client === originalId || e2ee || replyToClientMessageId
              || input.e2eePreparation?.intentSource !== "human_native_dialog") fail("reply_resend_invalid", { httpStatus: 409 });
            message.resendSourceClientMessageId = originalId;
            original.resendClientMessageId = client; original.updatedAt = at;
            changes.push(original);
          }
          // Reserve the original and create its fixed saved-body copy together.
          // A crash or a second human click cannot create another result copy.
          await commit(meta, { messages: changes }); return clone(message);
        });
      },
      async updateOutgoing(id, patch) {
        return mutateMessage(id, true, (message) => {
          if (message.messageType === DELETED) {
            // Human deletion may win while transport is in flight. Settle its
            // minimal ledger only; never restore content, claims or retry work.
            if (!message.conversationDeleted || message.status !== "delivery_state_unknown"
              || patch.incrementAttempts !== false || !["delivered_to_live_connection", "delivery_state_unconfirmed",
                "failed_permanent", "failed_retryable", "recipient_offline"].includes(patch.status)) {
              throw L.localHistoryFailure("record_not_found");
            }
            message.status = patch.status;
            message.updatedAt = new Date(now()).toISOString();
            return;
          }
          if (patch.preparationOnly && (message.status !== "pending" || message.attempts !== 0)) return false;
          if (patch.beforeTransportClaim && (message.status !== "delivery_state_unknown" || message.lastErrorCode !== "awaiting_relay_result"
            || message.deliveryAttemptPid !== process.pid || message.deliveryAttemptInstance !== L.PROCESS_INSTANCE_ID
            || message.attempts !== patch.beforeTransportClaim.attempts || message.deliveryAttemptStartedAt !== patch.beforeTransportClaim.startedAt)) fail("local_outgoing_attempt_mismatch", { httpStatus: 409 });
          message.status = String(patch.status || message.status); message.attempts = Number(message.attempts || 0) + (patch.incrementAttempts === false ? 0 : 1);
          message.lastErrorCode = patch.lastErrorCode == null ? null : String(patch.lastErrorCode);
          message.deliveryAttemptPid = null; message.deliveryAttemptInstance = null; message.deliveryAttemptStartedAt = null;
          message.nextRetryAt = ["recipient_offline", "failed_retryable"].includes(message.status) ? new Date(now() + Math.min(1000 * 2 ** Math.min(Math.max(message.attempts - 1, 0), 6), 60000)).toISOString() : null;
          message.updatedAt = new Date(now()).toISOString();
        }, patch.settleDelivery === true);
      },
      async attachOutgoingE2ee(id, value) {
        const e2ee = L.normalizeStoredE2ee(value); if (!e2ee) fail("e2ee_required");
        return mutateMessage(id, true, (message) => {
          if (message.status !== "pending" || message.e2ee != null) fail("local_outgoing_e2ee_attach_conflict", { httpStatus: 409 });
          const provenance = L.provenanceFromStoredE2ee(e2ee, message.senderPrincipalId, message.senderDelegateId);
          if ((e2ee.envelope.protected.replyToClientMessageId ?? null) !== (message.replyToClientMessageId ?? null)) fail("reply_target_invalid");
          message.e2ee = e2ee; message.conversationBinding = getMessageConversationBinding(message); Object.assign(message, provenance);
          message.transportSecurity = L.E2EE_TRANSPORT_SECURITY; message.updatedAt = new Date(now()).toISOString();
        });
      },
      async claimOutgoingForPreparation(id, expected) {
        return mutateMessage(id, true, (message) => {
          if (message.senderPrincipalId !== expected.senderPrincipalId || message.senderDelegateId !== expected.senderDelegateId) fail("local_outgoing_identity_mismatch", { httpStatus: 409 });
          if (!L.MANUAL_RETRYABLE_OUTGOING_STATUSES.has(message.status) || message.e2ee || message.attempts !== 0) fail("local_outgoing_message_not_retryable", { httpStatus: 409 });
          if (!message.e2eePreparation) fail("e2ee_preparation_context_missing", { httpStatus: 409 });
          Object.assign(message, { status: "pending", nextRetryAt: null, lastErrorCode: null, deliveryAttemptPid: process.pid, deliveryAttemptInstance: L.PROCESS_INSTANCE_ID, deliveryAttemptStartedAt: new Date(now()).toISOString(), updatedAt: new Date(now()).toISOString() });
        });
      },
      async claimOutgoingForAttempt(id, expected = {}) {
        const principal = L.safeId(expected.senderPrincipalId, "sender_principal_id_invalid"), delegate = L.safeId(expected.senderDelegateId, "sender_delegate_id_invalid");
        return mutateMessage(id, true, (message) => {
          if (!message.senderPrincipalId || !message.senderDelegateId) fail("local_outgoing_identity_unbound", { httpStatus: 409 });
          if (message.senderPrincipalId !== principal || message.senderDelegateId !== delegate) fail("local_outgoing_identity_mismatch", { httpStatus: 409 });
          if (!L.CLAIMABLE_OUTGOING_STATUSES.has(message.status) || message.lastErrorCode === "reply_target_deleted") fail("local_outgoing_message_not_retryable", { httpStatus: 409 });
          Object.assign(message, { status: "delivery_state_unknown", attempts: Number(message.attempts || 0) + 1, lastErrorCode: "awaiting_relay_result", deliveryAttemptPid: process.pid, deliveryAttemptInstance: L.PROCESS_INSTANCE_ID, deliveryAttemptStartedAt: new Date(now()).toISOString(), updatedAt: new Date(now()).toISOString() });
        });
      },
      async recoverArchivedOutgoingRetryClaim() { return null; }, // SQLite has no two-file retry-claim intermediate state.
      async recoverAbandonedE2eeOutgoingAttempts({ clientMessageId = null } = {}) {
        return locked(async (meta) => {
          const messages = clientMessageId ? [await openMessage(rawOutgoing(clientMessageId))].filter(message => message && message.messageType !== DELETED) : await readMessages("SELECT * FROM messages WHERE deleted=0 AND direction='outgoing' AND status IN ('pending','delivery_state_unknown')");
          const changed = L.recoverAbandonedE2eeOutgoingAttempts({ messages }, now, clientMessageId);
          if (changed.length) await commit(meta, { messages: changed }); return changed;
        });
      },
      async listPending() {
        await api.recoverAbandonedE2eeOutgoingAttempts();
        return locked(() => readMessages("SELECT * FROM messages WHERE deleted=0 AND direction='outgoing' AND status IN ('pending','recipient_offline','failed_retryable') ORDER BY seq"));
      },
      async cancelOutgoing(id) {
        return mutateMessage(id, true, (message) => {
          if (!L.BACKGROUND_RETRYABLE_OUTGOING_STATUSES.has(message.status)) fail("local_outgoing_message_not_cancellable", { httpStatus: 409 });
          Object.assign(message, { status: "cancelled", lastErrorCode: null, nextRetryAt: null, deliveryAttemptPid: null, deliveryAttemptInstance: null, deliveryAttemptStartedAt: null, updatedAt: new Date(now()).toISOString() });
        });
      },
    };
  }

  function incomingApi() {
    return {
      async addIncoming(event) {
        const eventId = L.safeId(event?.eventId, "relay_event_id_invalid"), client = L.safeId(event?.clientMessageId, "client_message_id_invalid");
        const principal = L.safeId(event?.senderPrincipalId, "sender_principal_id_invalid"), delegate = L.safeId(event?.senderDelegateId, "sender_delegate_id_invalid");
        const provenance = L.normalizeMessageProvenance(event?.authorizationScope, event?.intentSource, { required: event?.envelopeDigest != null, code: "message_provenance_invalid" });
        const peer = event?.senderHelloLynkId == null ? null : L.safeId(event.senderHelloLynkId, "sender_hellolynk_id_invalid");
        const text = L.safeText(event?.text), digest = event?.envelopeDigest == null ? null : L.safeSha256(event.envelopeDigest);
        const senderKey = event?.senderIdentityKeyId == null ? null : L.safeId(event.senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid");
        const recipientKey = event?.recipientIdentityKeyId == null ? null : L.safeId(event.recipientIdentityKeyId, "e2ee_recipient_identity_key_id_invalid");
        const binding = normalizeInstanceConversationBinding(event?.conversationBinding);
        const replyToClientMessageId = event?.replyToClientMessageId == null ? null : L.safeId(event.replyToClientMessageId, "reply_target_invalid");
        const targetConversationId = event?.targetConversationId == null ? null : nativeConversationId(event.targetConversationId);
        if (targetConversationId && (replyToClientMessageId || !digest || !binding
          || (principal !== binding.localPrincipalId && (provenance.intentSource !== "human_preauthorized_contact"
            || !["direct", "held"].includes(event.friendTarget))))) fail("native_target_not_authorized");
        if (replyToClientMessageId && (!binding || !digest || provenance.intentSource !== "human_preauthorized_contact" || replyToClientMessageId === client)) fail("reply_target_invalid");
        if (binding) { if (!digest) fail("message_provenance_invalid"); getMessageConversationBinding({ ...event, direction: "incoming", conversationBinding: binding, peerHelloLynkId: peer }); }
        const principalName = L.optionalVerifiedDisplayName(event?.senderPrincipalDisplayName, "sender_principal_display_name_invalid");
        const delegateName = L.optionalVerifiedDisplayName(event?.senderDelegateDisplayName, "sender_delegate_display_name_invalid");
        return locked(async (meta) => {
          const candidates = all("SELECT * FROM messages WHERE direction='incoming' AND (event=? OR sender_client=?)", token("event", eventId), token("sender-client", `${principal}\0${client}`));
          if (candidates.length > 1) fail("local_incoming_message_conflict", { httpStatus: 409 });
          const existing = await openMessage(candidates[0]);
          if (existing) {
            const isDeleted = existing.messageType === DELETED;
            const legacyMissing = !Object.hasOwn(existing, "senderPrincipalId") && !Object.hasOwn(existing, "authorizationScope") && !Object.hasOwn(existing, "intentSource");
            // An older Host's deletion can erase the held target's side data.
            // Its unchanged ciphertext digest still fences this replay.
            const deletedHeldReplay = isDeleted && !existing.targetConversationId && targetConversationId && digest
              && principal !== binding?.localPrincipalId;
            if (existing.clientMessageId !== client || existing.peerPrincipalId !== principal || existing.senderDelegateId !== delegate || (existing.peerHelloLynkId || null) !== peer
              || (existing.replyToClientMessageId ?? null) !== replyToClientMessageId
              || (!deletedHeldReplay && (existing.targetConversationId ?? null) !== targetConversationId)
              || (existing.envelopeDigest || null) !== digest || (existing.senderIdentityKeyId || null) !== senderKey || (existing.recipientIdentityKeyId || null) !== recipientKey
              || (isDeleted ? (!existing.conversationBinding || !binding || instanceConversationKey(existing.conversationBinding) !== instanceConversationKey(binding))
                : (existing.messageType !== "text" || existing.text !== text || (existing.conversationBinding && (!binding || instanceConversationKey(existing.conversationBinding) !== instanceConversationKey(binding)))
                  || (!legacyMissing && (existing.senderPrincipalId !== principal || (existing.authorizationScope ?? null) !== provenance.authorizationScope || (existing.intentSource ?? null) !== provenance.intentSource))))) fail("local_incoming_message_conflict", { httpStatus: 409 });
            return { message: clone(existing), duplicate: true };
          }
          if (meta.highWater >= Number.MAX_SAFE_INTEGER) fail("local_message_receipt_sequence_invalid");
          let replyTargetDeleted = false;
          if (replyToClientMessageId) {
            const original = await openMessage(rawOutgoing(replyToClientMessageId));
            const originalBinding = original && (getMessageConversationBinding(original) || getOutgoingConversationIntent(original));
            if (!originalBinding || instanceConversationKey(originalBinding) !== instanceConversationKey(binding)) fail("reply_target_not_found", { httpStatus: 409 });
            replyTargetDeleted = original.conversationDeleted === true;
          }
          const at = new Date(now()).toISOString();
          let message = {
            localMessageId: `local_message_${crypto.randomUUID()}`, eventId, receiptSeq: meta.highWater + 1, clientMessageId: client, direction: "incoming",
            peerPrincipalId: principal, peerHelloLynkId: peer, senderPrincipalId: principal, senderDelegateId: delegate, ...provenance,
            senderPrincipalDisplayName: principalName, senderDelegateDisplayName: delegateName, messageType: "text", text,
            transportSecurity: digest ? L.E2EE_TRANSPORT_SECURITY : "plaintext-v0.1.0", envelopeDigest: digest, senderIdentityKeyId: senderKey, recipientIdentityKeyId: recipientKey,
            conversationBinding: binding, status: "received", attempts: 0, nextRetryAt: null, lastErrorCode: null, createdAt: at, updatedAt: at,
            ...(replyToClientMessageId ? { replyToClientMessageId } : {}),
            ...(targetConversationId ? { targetConversationId } : {}),
            ...(targetConversationId && event.friendTarget === "held" ? { friendTargetHeld: true, automaticDeliveryState: "expired" } : {}),
          };
          if (replyTargetDeleted) message = L.localHistoryTombstone({ ...message, replyTargetDeleted: true, status: "fetched" }, {
            region: binding.region, principalId: binding.localPrincipalId, delegateId: binding.localDelegateId,
          });
          await commit(meta, { messages: [message], meta: { highWater: message.receiptSeq } }); return { message: clone(message), duplicate: false };
        });
      },
      async findIncomingE2eeReplay({ senderIdentityKeyId, clientMessageId, envelopeDigest }) {
        const sender = L.safeId(senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid"), client = L.safeId(clientMessageId, "client_message_id_invalid"), digest = L.safeSha256(envelopeDigest);
        return locked(async () => { const message = await openMessage(get("SELECT * FROM messages WHERE direction='incoming' AND replay=?", token("replay", `${sender}\0${client}`))); if (message && message.envelopeDigest !== digest) fail("e2ee_message_conflict", { httpStatus: 409 }); return message; });
      },
      async updateIncoming(id, patch) {
        return mutateMessage(id, false, (message) => {
          message.status = String(patch.status || message.status);
          if (message.status === "failed_retryable") { message.attempts = Number(message.attempts || 0) + 1; message.nextRetryAt = new Date(now() + Math.min(1000 * 2 ** Math.min(message.attempts - 1, 6), 60000)).toISOString(); message.lastErrorCode = patch.lastErrorCode == null ? "inbound_projection_failed" : String(patch.lastErrorCode); }
          else if (["fetched", "pending_human_confirmation"].includes(message.status)) { message.nextRetryAt = null; message.lastErrorCode = null; }
          message.updatedAt = new Date(now()).toISOString();
        });
      },
      async deleteIncoming(ids) { return deleteIds(ids, false); },
      async deleteOutgoing(ids) { return deleteIds(ids, true); },
    };
  }

  async function deleteIds(input, outgoing) {
    const ids = [...new Set((Array.isArray(input) ? input : []).map((id) => L.safeId(id, outgoing ? "client_message_id_invalid" : "local_message_id_invalid")))];
    if (!ids.length || ids.length > 500) fail(ids.length ? "local_message_delete_capacity_exceeded" : outgoing ? "client_message_ids_required" : "local_message_ids_required");
    return locked(async (meta) => {
      const messages = [], deletedIds = [];
      for (const id of ids) {
        const message = await openMessage(outgoing ? rawOutgoing(id) : rawById(id));
        if (!message || message.direction !== (outgoing ? "outgoing" : "incoming") || message.messageType === DELETED) continue;
        if (await protectedReason(message)) fail(outgoing ? "local_outgoing_message_not_deletable" : "local_incoming_message_not_deletable", { httpStatus: 409 });
        const binding = getMessageConversationBinding(message) || getOutgoingConversationIntent(message);
        const scope = binding ? { region: binding.region, principalId: binding.localPrincipalId, delegateId: binding.localDelegateId } : null;
        messages.push(scope ? L.localHistoryTombstone(message, scope) : { ...message, text: "", e2ee: null, messageType: DELETED });
        deletedIds.push(id);
      }
      if (messages.length) await commit(meta, { messages });
      return { requested: ids.length, deleted: deletedIds.length, deletedIds };
    });
  }

  function historyApi() {
    async function configuration(scope) {
      const id = scopeKey(scope), value = await openRecord("setting", get("SELECT * FROM settings WHERE id=?", id));
      return value || { id, version: 0, scope: L.localHistoryScope(scope), autoArchiveAfterHours: null };
    }
    async function stats(scope, threadId, before) {
      scope = selectThreadScope(scope, threadId);
      const key = threadKey(scope, threadId), values = [scopeKey(scope), key], cutoff = before == null ? "" : " AND m.created<?";
      if (before != null) values.push(checkedTime(before));
      const row = get(`SELECT count(*) AS totalCount,coalesce(sum(bytes),0) AS totalBytes,
        coalesce(sum(CASE WHEN unread=0 AND outgoing_protected=0 THEN 1 ELSE 0 END),0) AS deletableCount,
        coalesce(sum(CASE WHEN unread=0 AND outgoing_protected=0 THEN bytes ELSE 0 END),0) AS deletableBytes,
        coalesce(sum(unread),0) AS retainedUnreadCount,coalesce(sum(outgoing_protected),0) AS retainedOutgoingCount,
        0 AS retainedTaskCount
        FROM messages m WHERE scope=? AND thread=? AND deleted=0${cutoff}`, ...values);
      return { threadId, before: before ?? null, ...row };
    }
    async function archive(input, hidden) {
      const requestedScope = L.localHistoryScope(input), threadId = L.safeId(input.threadId, "local_history_thread_invalid");
      return locked(async (meta) => {
        const scope = selectThreadScope(requestedScope, threadId);
        let thread = await threadRecord(scope, threadId);
        if (thread?.deleted) {
          if (hidden) throw L.localHistoryFailure("record_not_found");
          // A human opening this saved contact starts an empty conversation.
          // The deletion boundary remains: old results cannot enter it.
          await commit(meta, { threads: [{ ...thread, deleted: false, archived: false }] });
          return {};
        }
        if (!thread) {
          if (!hidden) return {};
          // Host supplies this binding only after finding the saved target in
          // the current delegate's contacts. An opaque thread key is not enough.
          const binding = normalizeInstanceConversationBinding(input.conversationBinding);
          if (!binding || binding.region !== scope.region || binding.localPrincipalId !== scope.principalId
            || binding.localDelegateId !== scope.delegateId || instanceConversationKey(binding) !== threadId) {
            throw L.localHistoryFailure("record_not_found");
          }
          const peer = input.peerHelloLynkId == null ? null : L.safeId(input.peerHelloLynkId, "sender_hellolynk_id_invalid");
          thread = { id: threadKey(scope, threadId), version: 0, scope, binding, legacy: false, threadId,
            peerPrincipalId: binding.peerPrincipalId, peerHelloLynkId: peer,
            archived: false, updatedAt: new Date(now()).toISOString(),
            unreadCount: 0, outgoingProtectedCount: 0, taskProtectedCount: 0 };
        }
        // A manual archive changes visibility only. Bodies, unread facts,
        // inflight/unknown claims and send state stay intact. Automatic archive
        // still protects these records in maintainLocalHistory.
        await commit(meta, { threads: [{ ...thread, archived: hidden }] }); return {};
      });
    }
    async function deleteConversations(input, archivedOnly = false) {
      const requestedScope = L.localHistoryScope(input);
      const prepared = await locked(async (meta) => {
        const threads = [];
        if (archivedOnly) {
          const keys = readScopeKeys(requestedScope);
          for (const row of all(`SELECT * FROM threads WHERE scope IN (${keys.map(() => "?").join(",")}) AND archived=1 AND deleted=0`, ...keys)) threads.push(await openRecord("thread", row));
        } else {
          const threadId = L.safeId(input.threadId, "local_history_thread_invalid"), scope = selectThreadScope(requestedScope, threadId);
          let thread = await threadRecord(scope, threadId);
          if (!thread) {
            const binding = normalizeInstanceConversationBinding(input.conversationBinding);
            if (!binding || binding.region !== scope.region || binding.localPrincipalId !== scope.principalId
              || binding.localDelegateId !== scope.delegateId || instanceConversationKey(binding) !== threadId) throw L.localHistoryFailure("record_not_found");
            thread = { id: threadKey(scope, threadId), version: 0, scope, binding, legacy: false, threadId,
              peerPrincipalId: binding.peerPrincipalId, peerHelloLynkId: input.peerHelloLynkId == null ? null : L.safeId(input.peerHelloLynkId, "sender_hellolynk_id_invalid"),
              archived: false, updatedAt: new Date(now()).toISOString(), unreadCount: 0, outgoingProtectedCount: 0, taskProtectedCount: 0 };
          }
          threads.push(thread);
        }
        let deletedCount = 0;
        const changes = [];
        for (const thread of threads) {
          // Resume the original boundary after interruption, including if a new
          // independent message already restored this thread in the meantime.
          if (thread.purgePending || thread.deleted) continue;
          deletedCount += get("SELECT count(*) AS n FROM messages WHERE thread=? AND deleted=0", thread.id).n;
          changes.push({ ...thread, archived: false, deleted: true, deleteThrough: meta.sequence,
            purgeAfter: 0, purgePending: true });
        }
        if (changes.length) await commit(meta, { deleteThreads: changes });
        return { deletedCount, ids: threads.map(thread => thread.id) };
      });
      await options.fault?.("conversation-delete-intent");
      for (const id of prepared.ids) {
        while (await locked(() => purgeDeletedBatch(id))) await new Promise(resolve => setImmediate(resolve));
      }
      return { deletedCount: prepared.deletedCount, retainedUnreadCount: 0, retainedOutgoingCount: 0, retainedTaskCount: 0 };
    }
    return {
      async configureConversationAutoRead({ scope: input, threadId, enabled, conversationBinding, peerHelloLynkId = null }) {
        const scope = L.localHistoryScope(input);
        L.safeId(threadId, "local_history_thread_invalid");
        if (typeof enabled !== "boolean") fail("local_history_configuration_invalid");
        return locked(async (meta) => {
          let thread = await threadRecord(scope, threadId);
          const binding = normalizeInstanceConversationBinding(thread?.binding ?? conversationBinding);
          if (!binding || binding.region !== scope.region || binding.localPrincipalId !== scope.principalId
            || binding.localDelegateId !== scope.delegateId || instanceConversationKey(binding) !== threadId
            || thread?.deleted || thread?.legacy) throw L.localHistoryFailure("record_not_found");
          if (!thread) thread = { id: threadKey(scope, threadId), version: 0, scope, binding, legacy: false, threadId,
            peerPrincipalId: binding.peerPrincipalId,
            peerHelloLynkId: peerHelloLynkId == null ? null : L.safeId(peerHelloLynkId, "sender_hellolynk_id_invalid"),
            archived: false, updatedAt: new Date(now()).toISOString(),
            unreadCount: 0, outgoingProtectedCount: 0, taskProtectedCount: 0 };
          if (thread.autoReadAfterAi !== enabled) await commit(meta, { threads: [{ ...thread, autoReadAfterAi: enabled }] });
          return { threadId, enabled };
        });
      },
      async markIncomingRead({ scope: input, threadId = null, beforeReceiptSeq }) {
        const scope = L.localHistoryScope(input);
        if (!Number.isSafeInteger(beforeReceiptSeq) || beforeReceiptSeq < 0) fail("local_message_receipt_sequence_invalid");
        if (threadId !== null) L.safeId(threadId, "local_history_thread_invalid");
        return locked(async (meta) => {
          if (beforeReceiptSeq > meta.highWater) fail("local_message_receipt_sequence_invalid");
          const keys = readScopeKeys(scope), values = [...keys, beforeReceiptSeq];
          let condition = "";
          if (threadId !== null) {
            const selectedScope = selectThreadScope(scope, threadId);
            condition = " AND thread=?";
            values.push(threadKey(selectedScope, threadId));
          }
          const messages = await readMessages(`SELECT * FROM messages WHERE scope IN (${keys.map(() => "?").join(",")}) AND direction='incoming' AND deleted=0 AND unread=1 AND receipt<=?${condition} ORDER BY receipt`, ...values);
          const at = new Date(now()).toISOString();
          for (const message of messages) {
            assertScope(message, scope);
            Object.assign(message, { status: "fetched", updatedAt: at, nextRetryAt: null, lastErrorCode: null });
          }
          // One durable transaction updates the message rows and unread
          // counts. AI claims/reader boundaries and later arrivals are untouched.
          if (messages.length) await commit(meta, { messages });
          return { markedCount: messages.length };
        });
      },
      async readWorkbenchSummary(input) {
        const scope = L.localHistoryScope(input);
        return locked(async (meta) => {
          const config = await configuration(scope), threads = [], hiddenThreadIds = [];
          const keys = [scopeKey(scope)];
          for (const row of all(`SELECT * FROM threads WHERE scope IN (${keys.map(() => "?").join(",")}) ORDER BY updated DESC,id`, ...keys)) {
            const thread = await openRecord("thread", row);
            if (scopeKey(thread.scope) !== row.scope || thread.updatedAt !== row.updated || Number(thread.archived) !== row.archived) fail("local_message_index_invalid");
            if (thread.legacy) continue;
            if (thread.deleted) { hiddenThreadIds.push(thread.threadId); continue; }
            // Count both directions in the actual conversation, not the outbox
            // page or a search result. Fetch only status columns for the five
            // records, so undisplayed bodies never cross the SQLite boundary.
            const recentMessages = all("SELECT id,direction,status FROM messages WHERE scope=? AND thread=? AND deleted=0 ORDER BY created DESC,seq DESC LIMIT 5", row.scope, row.id);
            const lastMessage = await openMessage(recentMessages.length ? get("SELECT * FROM messages WHERE id=?", recentMessages[0].id) : null);
            const recentSendFailureCount = recentMessages.filter((message) => message.direction === "outgoing"
              && ["recipient_offline", "failed_retryable", "failed_permanent", "reply_target_deleted"].includes(message.status)).length;
            if (lastMessage) assertScope(lastMessage, scope);
            threads.push({ threadId: thread.threadId, binding: thread.binding, legacy: thread.legacy,
              peerPrincipalId: thread.peerPrincipalId, peerHelloLynkId: thread.peerHelloLynkId,
              lastMessage, unreadCount: thread.unreadCount, updatedAt: thread.updatedAt, archived: thread.archived,
              ...(recentSendFailureCount ? { recentSendFailureCount } : {}),
              ...(thread.autoReadAfterAi === true ? { autoReadAfterAi: true } : {}) });
          }
          return { threads, hiddenThreadIds, inboxReadBoundary: meta.highWater, revision: `indexed_${meta.version}`, latestTimestamp: threads.reduce((value, item) => item.updatedAt > value ? item.updatedAt : value, "1970-01-01T00:00:00.000Z"), archivedThreadCount: threads.filter((item) => item.archived).length, autoArchiveAfterHours: config.autoArchiveAfterHours };
        });
      },
      async queryConversationPage({ scope: input, threadId, anchor = null, direction = "before", limit = 20 }) {
        const windowRead = ["from", "older-window", "newer-window"].includes(direction);
        const scope = L.localHistoryScope(input), size = limitOf(limit, windowRead ? 200 : 20);
        if (!["before", "after", "from", "older-window", "newer-window"].includes(direction)) fail("local_history_cursor_invalid");
        return locked(async () => {
          const selectedScope = selectThreadScope(scope, threadId);
          const key = threadKey(selectedScope, threadId), selectedScopeKey = scopeKey(selectedScope);
          let anchorRow = null;
          if (anchor != null) { anchorRow = rawById(anchor.localMessageId); if (!anchorRow || anchorRow.scope !== selectedScopeKey || anchorRow.thread !== key || anchorRow.created !== checkedTime(anchor.createdAt)) fail("local_history_cursor_invalid"); const message = await openMessage(anchorRow); assertScope(message, scope); }
          let selection = direction;
          if (["older-window", "newer-window"].includes(direction)) {
            if (!anchorRow) fail("local_history_cursor_invalid");
            const older = direction === "older-window", op = older ? "<" : ">", order = older ? "DESC" : "ASC";
            // Advance 20 records, then read the complete window under this lock.
            // Its cursors describe real boundaries, even after deletion/arrival.
            const edge = all(`SELECT created,seq FROM messages WHERE scope=? AND thread=? AND deleted=0 AND (created ${op} ? OR (created=? AND seq ${op} ?)) ORDER BY created ${order},seq ${order} LIMIT 20`, selectedScopeKey, key, anchorRow.created, anchorRow.created, anchorRow.seq).at(-1);
            anchorRow = edge ?? anchorRow;
            selection = older ? "from" : "through";
          }
          const values = [selectedScopeKey, key]; let condition = "";
          const descending = ["before", "through"].includes(selection), order = descending ? "DESC" : "ASC";
          if (anchorRow) { const comparator = descending ? "<" : ">", sequenceComparator = ["from", "through"].includes(selection) ? comparator + "=" : comparator; condition = ` AND (created ${comparator} ? OR (created=? AND seq ${sequenceComparator} ?))`; values.push(anchorRow.created, anchorRow.created, anchorRow.seq); }
          let rows = all(`SELECT * FROM messages WHERE scope=? AND thread=? AND deleted=0${condition} ORDER BY created ${order},seq ${order} LIMIT ?`, ...values, size);
          if (descending) rows.reverse();
          if (windowRead && !rows.length) {
            // The page's entire tail may have been deleted since it was shown.
            // Keep the remaining history reachable instead of returning an
            // empty page with neither navigation cursor.
            rows = all("SELECT * FROM messages WHERE scope=? AND thread=? AND deleted=0 ORDER BY created DESC,seq DESC LIMIT ?", selectedScopeKey, key, size).reverse();
          }
          const messages = []; for (const row of rows) { const message = await openMessage(row); assertScope(message, scope); messages.push(message); }
          const first = rows[0], last = rows.at(-1);
          const hasEarlier = first ? !!get("SELECT 1 FROM messages WHERE scope=? AND thread=? AND deleted=0 AND (created<? OR (created=? AND seq<?)) LIMIT 1", selectedScopeKey, key, first.created, first.created, first.seq) : false;
          const hasLater = last ? !!get("SELECT 1 FROM messages WHERE scope=? AND thread=? AND deleted=0 AND (created>? OR (created=? AND seq>?)) LIMIT 1", selectedScopeKey, key, last.created, last.created, last.seq) : false;
          return { messages, hasEarlier, hasLater };
        });
      },
      async readLocalHistoryStats({ scope, threadId, before = null }) { return locked(() => stats(scope, threadId, before)); },
      async searchWorkbenchThreads({ scope: input, query, limit = 500 }) {
        const scope = L.localHistoryScope(input), maximum = limitOf(limit, Number.MAX_SAFE_INTEGER);
        if (typeof query !== "string" || query.length > HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH) fail("local_history_query_invalid");
        const needles = [...new Set(query.normalize("NFKC").trim().toLocaleLowerCase("und").split(/\s+/u).filter(Boolean))]; if (!needles.length) return [];
        const found = new Set(), partial = new Map(); let cursor = 0;
        const keys = readScopeKeys(scope);
        const upper = await locked(() => get(`SELECT coalesce(max(seq),0) AS n FROM messages WHERE scope IN (${keys.map(() => "?").join(",")})`, ...keys).n);
        // Explicit search alone may scan message bodies. Release the store lock
        // between batches so history search never starves live message writes.
        // Fix the scan boundary: a steady receiver must not extend this read
        // forever. The read model retries if its surrounding revision changed.
        for (;;) {
          const batch = await locked(async () => {
            const rows = all(`SELECT * FROM messages WHERE scope IN (${keys.map(() => "?").join(",")}) AND deleted=0 AND seq>? AND seq<=? ORDER BY seq LIMIT 100`, ...keys, cursor, upper);
            const matches = [];
            for (const row of rows) { const message = await openMessage(row); assertScope(message, scope); const thread = messageOwner(message).threadId;
              const text = message.text.normalize("NFKC").toLocaleLowerCase("und"), matched = partial.get(thread) || new Set();
              needles.forEach((needle, index) => { if (text.includes(needle)) matched.add(index); });
              partial.set(thread, matched); if (matched.size === needles.length) matches.push(thread);
            }
            return { cursor: rows.at(-1)?.seq ?? cursor, done: rows.length < 100, matches };
          });
          cursor = batch.cursor; for (const thread of batch.matches) if (thread) found.add(thread);
          if (batch.done || found.size >= maximum) return [...found].slice(0, maximum);
          await new Promise((resolve) => setImmediate(resolve));
        }
      },
      async configureLocalHistory({ scope, autoArchiveAfterHours }) {
        if (autoArchiveAfterHours !== null && autoArchiveAfterHours !== 24) fail("local_history_configuration_invalid");
        return locked(async (meta) => { const current = await configuration(scope); await commit(meta, { settings: [{ ...current, version: current.version + 1, autoArchiveAfterHours }] }); return { autoArchiveAfterHours }; });
      },
      hideLocalConversation: (input) => archive(input, true),
      restoreLocalConversation: (input) => archive(input, false),
      deleteLocalConversation: (input) => deleteConversations(input),
      deleteArchivedConversations: (input) => deleteConversations(input, true),
      async clearLocalConversation(input) {
        const requestedScope = L.localHistoryScope(input), threadId = L.safeId(input.threadId, "local_history_thread_invalid"), before = input.before == null ? null : checkedTime(input.before);
        const scope = await locked(() => selectThreadScope(requestedScope, threadId));
        const result = { deletedCount: 0, retainedUnreadCount: 0, retainedOutgoingCount: 0, retainedTaskCount: 0 };
        const upper = await locked(() => get("SELECT coalesce(max(seq),0) AS n FROM messages WHERE scope=? AND thread=?", scopeKey(scope), threadKey(scope, threadId)).n);
        let cursor = 0;
        for (;;) {
          const batch = await locked(async (meta) => {
            const rows = all(`SELECT * FROM messages WHERE scope=? AND thread=? AND deleted=0 AND seq>? AND seq<=?${before ? " AND created<?" : ""} ORDER BY seq LIMIT 100`, scopeKey(scope), threadKey(scope, threadId), cursor, upper, ...(before ? [before] : []));
            const counts = { deletedCount: 0, retainedUnreadCount: 0, retainedOutgoingCount: 0, retainedTaskCount: 0 }, changes = [];
            for (const row of rows) { const message = await openMessage(row); assertScope(message, scope); const reason = await protectedReason(message);
              if (reason) { counts[reason === "unread" ? "retainedUnreadCount" : reason === "outgoing" ? "retainedOutgoingCount" : "retainedTaskCount"]++; continue; }
              changes.push(L.localHistoryTombstone(message, scope)); counts.deletedCount++;
            }
            if (changes.length) { await commit(meta, { messages: changes }); await options.fault?.("delete-batch-committed"); }
            return { counts, cursor: rows.at(-1)?.seq ?? cursor, done: rows.length < 100 };
          });
          for (const key of Object.keys(result)) result[key] += batch.counts[key]; cursor = batch.cursor;
          if (batch.done) return result;
          await new Promise((resolve) => setImmediate(resolve));
        }
      },
      async deleteSentLocal(input) {
        const scope = L.localHistoryScope(input), ids = input.localMessageIds;
        if (!Array.isArray(ids) || !ids.length || ids.length > 500) throw L.localHistoryFailure("message_invalid");
        return locked(async (meta) => {
          const changes = [];
          for (const id of [...new Set(ids)]) { const message = await openMessage(rawById(id)); if (!message) throw L.localHistoryFailure("record_not_found"); assertScope(message, scope);
            if (message.direction !== "outgoing" || !L.localHistorySent(message) || await protectedReason(message)) throw L.localHistoryFailure("outgoing_protected");
            if (message.messageType !== DELETED) changes.push(L.localHistoryTombstone(message, scope));
          }
          if (changes.length) await commit(meta, { messages: changes }); return { deletedCount: changes.length, retainedUnreadCount: 0, retainedOutgoingCount: 0, retainedTaskCount: 0 };
        });
      },
      async maintainLocalHistory({ limit = 50 } = {}) {
        const size = limitOf(limit, 50);
        return locked(async (meta) => {
          await purgeDeletedBatch(); meta = await readMeta();
          const cursor = meta.maintenanceCursor ?? null, cutoff = new Date(now() - 86400000).toISOString();
          const rows = all(`SELECT * FROM threads WHERE archived=0 AND updated<?${cursor ? " AND (updated>? OR (updated=? AND id>?))" : ""} ORDER BY updated,id LIMIT ?`, cutoff, ...(cursor ? [cursor.updated, cursor.updated, cursor.id] : []), size);
          const changes = [];
          for (const row of rows) {
            const thread = await openRecord("thread", row), config = await configuration(thread.scope);
            if (thread.deleted || thread.legacy || config.autoArchiveAfterHours !== 24) continue;
            if (thread.unreadCount || thread.outgoingProtectedCount) continue;
            changes.push({ ...thread, archived: true });
          }
          const tail = rows.at(-1), maintenanceCursor = rows.length < size ? null : { updated: tail.updated, id: tail.id };
          if (changes.length || cursor || maintenanceCursor) await commit(meta, { threads: changes, meta: { maintenanceCursor } });
          return { archivedCount: changes.length, ...reclaimUnusedPages() };
        });
      },
      async readWorkbenchState(input) {
        const summary = await api.readWorkbenchSummary(input);
        return { messages: await api.list(), hiddenThreadIds: summary.threads.filter((thread) => thread.archived).map((thread) => thread.threadId) };
      },
    };
  }
}
