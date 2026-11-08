import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { nativeConversationId, nativeConversationTitle } from "./hellolynk-native-conversations.mjs";
import crypto from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";
import { assertLocalDataProtectionAccess } from "./hellolynk-local-data-protection.mjs";
import {
  createOutgoingConversationIntent,
  deriveInstanceConversationBinding,
  getMessageConversationBinding,
  getOutgoingConversationIntent,
  instanceConversationKey,
  normalizeInstanceConversationBinding,
} from "./hellolynk-instance-conversation.mjs";
import {
  DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES,
  DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE,
} from "./hellolynk-direct-text-e2ee.mjs";

export const HELLOLYNK_LOCAL_MESSAGE_STORE_CONTRACT = "hellolynk-local-messages-v2";
export const HELLOLYNK_LOCAL_MESSAGE_STORE_SCHEMA_VERSION = 2;
const STORE_SCHEMA_VERSION = HELLOLYNK_LOCAL_MESSAGE_STORE_SCHEMA_VERSION;
const STORE_FIELDS = Object.freeze(["contractId", "messages", "profileId", "schemaVersion"]);
const ARCHIVE_ENVELOPE_FIELDS = Object.freeze([
  "archivedAt",
  "contractId",
  "message",
  "profileId",
  "schemaVersion",
]);
const CURRENT_MESSAGE_FIELDS = new Set([
  "automaticDeliveryState",
  "attempts",
  "authorizationScope",
  "clientMessageId",
  "conversationBinding",
  "conversationIntent",
  "conversationDeleted",
  "replyToClientMessageId",
  "targetConversationId",
  "targetConversationTitle",
  "friendTargetHeld",
  "replyTargetDeleted",
  "resendSourceClientMessageId",
  "resendClientMessageId",
  "createdAt",
  "deliveryAttemptInstance",
  "deliveryAttemptPid",
  "deliveryAttemptStartedAt",
  "direction",
  "e2ee",
  "e2eePreparation",
  "envelopeDigest",
  "eventId",
  "intentSource",
  "lastErrorCode",
  "localMessageId",
  "messageType",
  "nextRetryAt",
  "peerHelloLynkId",
  "peerPrincipalId",
  "recipientHelloLynkId",
  "recipientIdentityKeyId",
  "receiptSeq",
  "senderDelegateDisplayName",
  "senderDelegateId",
  "senderHelloLynkId",
  "senderIdentityKeyId",
  "senderPrincipalDisplayName",
  "senderPrincipalId",
  "status",
  "text",
  "transportSecurity",
  "updatedAt",
]);
const MAX_STORE_BYTES = 8 * 1024 * 1024;
const MAX_TEXT_BYTES = 20 * 1024;
const MAX_JSON_RESPONSE_BYTES = 256 * 1024;
const MAX_SSE_BUFFER_BYTES = 256 * 1024;
const RECEIVER_LOCAL_STORE_CONTRACT = "receiver-local-store-v1";
const RECEIVER_RECEIPT_VERSION = "1";
const E2EE_DIRECT_TEXT_VERSION = "1";
const E2EE_TRANSPORT_SECURITY = "e2ee-direct-text-v1";
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/;
const RETRYABLE_STATUSES = new Set([408, 409, 425, 429]);
const STORE_LOCK_WAIT_MS = 20;
const STORE_LOCK_ATTEMPTS = 100;
const STORE_LOCK_STALE_MS = 5_000;
const MAX_STORE_LOCK_BYTES = 16 * 1024;
const MIN_CONFIGURED_STORE_BYTES = 32 * 1024;
const MAX_ARCHIVE_RECORD_BYTES = 128 * 1024;
const MAX_PROTECTED_ARCHIVE_RECORD_BYTES = MAX_ARCHIVE_RECORD_BYTES * 2;
const RETRYABLE_ATOMIC_REPLACE_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);
const DEFAULT_ATOMIC_REPLACE_RETRY_DELAYS_MS = Object.freeze([10, 25, 50, 100, 200, 400]);
const ARCHIVABLE_OUTGOING_STATUSES = new Set([
  "cancelled",
  "delivered_to_live_connection",
  "delivery_state_unconfirmed",
  "failed_permanent",
]);
const ARCHIVABLE_INCOMING_STATUSES = new Set(["fetched", "pending_human_confirmation"]);
const DELETABLE_OUTGOING_STATUSES = new Set([
  "cancelled",
  "delivered_to_live_connection",
  "delivery_state_unconfirmed",
  "failed_permanent",
  "failed_retryable",
  "recipient_offline",
]);
const MANUAL_RETRYABLE_OUTGOING_STATUSES = new Set([
  "recipient_offline",
  "failed_retryable",
  "failed_permanent",
]);
const BACKGROUND_RETRYABLE_OUTGOING_STATUSES = new Set([
  "pending",
  "recipient_offline",
  "failed_retryable",
]);
const CLAIMABLE_OUTGOING_STATUSES = new Set([
  ...BACKGROUND_RETRYABLE_OUTGOING_STATUSES,
  ...MANUAL_RETRYABLE_OUTGOING_STATUSES,
]);
const PROCESS_INSTANCE_ID = crypto.randomBytes(16).toString("hex");
const pathMutationQueues = new Map();
const LOCAL_HISTORY_CONTRACT = "hellolynk-local-history-v1";
const LOCAL_DELETED_MESSAGE_TYPE = "local-deleted";
const MAX_LOCAL_HISTORY_BYTES = 8 * 1024 * 1024;

function localHistoryFailure(code) {
  return new HelloLynkLocalMessagingError(`local_history_${code}`, { httpStatus: 409 });
}

function localHistoryScope(input) {
  const region = input?.region === "international" ? "intl" : input?.region;
  if (!["intl", "cn"].includes(region)) throw localHistoryFailure("scope_invalid");
  return { region, principalId: safeId(input?.principalId, "local_history_scope_invalid"),
    delegateId: safeId(input?.delegateId, "local_history_scope_invalid") };
}

function localHistoryScopeKey(scope) {
  return `${scope.region}\0${scope.principalId}\0${scope.delegateId}`;
}

function localHistoryBinding(message, scope) {
  try {
    const binding = getMessageConversationBinding(message, scope)
      || getOutgoingConversationIntent(message, scope);
    return binding && binding.region === scope.region && binding.localPrincipalId === scope.principalId
      && binding.localDelegateId === scope.delegateId ? binding : null;
  } catch { return null; }
}

function localHistoryThreadId(message, scope) {
  const binding = localHistoryBinding(message, scope);
  return binding ? instanceConversationKey(binding) : null;
}

function localHistoryUnread(message) {
  return message.direction === "incoming"
    && (typeof message.unread === "boolean" ? message.unread : message.status === "received");
}

function localHistorySent(message) {
  return message.direction === "outgoing" && message.status === "delivered_to_live_connection";
}

function localHistoryTombstone(message, scope) {
  // Keep the original v2 fields and real terminal status. A deleted body must
  // never turn the sending ledger into a missing/retryable message.
  const fields = ["localMessageId", "clientMessageId", "direction", "peerHelloLynkId", "peerPrincipalId",
    "senderPrincipalId", "senderDelegateId", "senderIdentityKeyId", "recipientIdentityKeyId",
    "envelopeDigest", "eventId", "conversationBinding", "conversationIntent", "authorizationScope",
    "intentSource", "status", "createdAt", "updatedAt", "receiptSeq", "conversationDeleted", "replyToClientMessageId", "targetConversationId", "replyTargetDeleted",
    "resendSourceClientMessageId", "resendClientMessageId"];
  return { ...Object.fromEntries(fields.filter((field) => Object.hasOwn(message, field))
    .map((field) => [field, message[field]])), conversationBinding: localHistoryBinding(message, scope),
    messageType: LOCAL_DELETED_MESSAGE_TYPE, text: "" };
}

export class HelloLynkLocalMessagingError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkLocalMessagingError";
    this.code = code;
    this.httpStatus = Number.isInteger(options.httpStatus) ? options.httpStatus : null;
    this.status = this.httpStatus;
    this.retryable = options.retryable === true;
    this.deliveryStatus = options.deliveryStatus || null;
    this.reason = options.reason || null;
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeAtomicReplaceRetryDelays(value) {
  if (value === undefined) return DEFAULT_ATOMIC_REPLACE_RETRY_DELAYS_MS;
  if (!Array.isArray(value) || value.length > 16) {
    throw new TypeError("invalid_atomic_replace_retry_delays");
  }
  const normalized = value.map((item) => Number(item));
  if (normalized.some((item) => !Number.isSafeInteger(item) || item < 0 || item > 1_000)) {
    throw new TypeError("invalid_atomic_replace_retry_delays");
  }
  return normalized;
}

export async function replaceLocalStoreFileWithRetry(sourcePath, targetPath, options = {}) {
  const renameFile = typeof options.renameFile === "function" ? options.renameFile : rename;
  const sleep = typeof options.sleep === "function" ? options.sleep : delay;
  const retryDelaysMs = normalizeAtomicReplaceRetryDelays(options.retryDelaysMs);
  let retryCount = 0;

  while (true) {
    try {
      await renameFile(sourcePath, targetPath);
      return { attempts: retryCount + 1, retries: retryCount };
    } catch (error) {
      const retryable = RETRYABLE_ATOMIC_REPLACE_CODES.has(String(error?.code || ""));
      if (!retryable || retryCount >= retryDelaysMs.length) throw error;
      await sleep(retryDelaysMs[retryCount]);
      retryCount += 1;
    }
  }
}

async function releaseOwnedStoreLock(lockPath, handle, ownershipToken) {
  let ownedBeforeClose = false;
  try {
    const current = JSON.parse(await readFile(lockPath, "utf8"));
    ownedBeforeClose = current?.ownershipToken === ownershipToken;
  } catch {}
  await handle.close().catch(() => {});
  if (!ownedBeforeClose) return false;
  try {
    const current = JSON.parse(await readFile(lockPath, "utf8"));
    if (current?.ownershipToken !== ownershipToken) return false;
    await rm(lockPath);
    return true;
  } catch {
    return false;
  }
}

async function tryRemoveDeadOwnedLock(lockPath, ownershipField) {
  let metadata;
  try {
    metadata = await lstat(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > MAX_STORE_LOCK_BYTES) return false;
  if (Date.now() - metadata.mtimeMs < STORE_LOCK_STALE_MS) return false;

  let current;
  try {
    current = JSON.parse(await readFile(lockPath, "utf8"));
  } catch {
    return false;
  }
  const ownerPid = Number(current?.pid);
  const ownershipToken = current?.[ownershipField];
  if (
    !Number.isSafeInteger(ownerPid) ||
    ownerPid <= 0 ||
    typeof ownershipToken !== "string" ||
    ownershipToken.length < 16 ||
    !Number.isFinite(Number(current?.createdAt)) ||
    processAlive(ownerPid)
  ) return false;

  const stalePath = `${lockPath}.stale.${process.pid}.${crypto.randomBytes(8).toString("hex")}`;
  try {
    await rename(lockPath, stalePath);
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM"].includes(error?.code)) return false;
    throw error;
  }
  await rm(stalePath, { force: true });
  return true;
}

async function tryRecoverDeadStoreLock(lockPath) {
  const recoveryPath = `${lockPath}.recovery`;
  const recoveryToken = crypto.randomBytes(24).toString("hex");
  let recoveryHandle = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      recoveryHandle = await open(recoveryPath, "wx", 0o600);
      await recoveryHandle.writeFile(`${JSON.stringify({
        pid: process.pid,
        ownershipToken: recoveryToken,
        createdAt: Date.now(),
      })}\n`, "utf8");
      await recoveryHandle.sync();
      break;
    } catch (error) {
      await recoveryHandle?.close().catch(() => {});
      recoveryHandle = null;
      if (error?.code !== "EEXIST") throw error;
      if (!(await tryRemoveDeadOwnedLock(recoveryPath, "ownershipToken"))) return false;
    }
  }
  if (!recoveryHandle) return false;

  try {
    return await tryRemoveDeadOwnedLock(lockPath, "ownershipToken");
  } finally {
    await releaseOwnedStoreLock(recoveryPath, recoveryHandle, recoveryToken);
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function deliveryAttemptHasLiveOwner(message) {
  const attemptPid = Number(message?.deliveryAttemptPid);
  const attemptInstance = String(message?.deliveryAttemptInstance || "");
  if (!Number.isSafeInteger(attemptPid) || attemptPid <= 0 || !attemptInstance) return false;
  if (attemptPid === process.pid) return attemptInstance === PROCESS_INSTANCE_ID;
  return processAlive(attemptPid);
}

function recoverAbandonedE2eeOutgoingAttempts(store, now, clientMessageId = null) {
  const recovered = [];
  for (const message of store.messages) {
    if (
      message?.direction !== "outgoing" ||
      !["pending", "delivery_state_unknown"].includes(message.status) ||
      (message.status === "pending" && (message.attempts !== 0 || message.e2eePreparation == null)) ||
      (clientMessageId && message.clientMessageId !== clientMessageId)
    ) continue;

    if (deliveryAttemptHasLiveOwner(message)) continue;

    // Only the current durable preparation phase proves that dispatch has not
    // started. Legacy counters (including zero) cannot thaw an unknown result.
    const interruptedPreparation = message.status === "pending"
      && message.attempts === 0 && message.e2eePreparation != null;
    message.status = interruptedPreparation ? "failed_retryable" : "delivery_state_unconfirmed";
    message.lastErrorCode = interruptedPreparation ? "e2ee_preparation_interrupted" : "e2ee_delivery_attempt_interrupted";
    message.nextRetryAt = null;
    message.deliveryAttemptPid = null;
    message.deliveryAttemptInstance = null;
    message.deliveryAttemptStartedAt = null;
    message.updatedAt = new Date(now()).toISOString();
    recovered.push(structuredClone(message));
  }
  return recovered;
}

async function withCrossProcessStoreLock(storePath, callback) {
  const lockPath = `${storePath}.lock`;
  // Windows may report EEXIST for an exclusive create below a junction even
  // when no lock exists. Validate the directory chain before interpreting
  // EEXIST as lock contention; the callback validates it again before access.
  await assertMessageStoreDirectoryAccess(storePath, { create: true });
  let handle = null;
  let ownershipToken = null;
  for (let attempt = 0; attempt < STORE_LOCK_ATTEMPTS; attempt += 1) {
    try {
      const candidateHandle = await open(lockPath, "wx", 0o600);
      const candidateToken = crypto.randomBytes(24).toString("hex");
      try {
        await candidateHandle.writeFile(`${JSON.stringify({
          pid: process.pid,
          ownershipToken: candidateToken,
          createdAt: Date.now(),
        })}\n`, "utf8");
        await candidateHandle.sync();
      } catch (error) {
        await releaseOwnedStoreLock(lockPath, candidateHandle, candidateToken);
        throw error;
      }
      handle = candidateHandle;
      ownershipToken = candidateToken;
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      await tryRecoverDeadStoreLock(lockPath);
      await delay(STORE_LOCK_WAIT_MS);
    }
  }
  if (!handle) {
    throw new HelloLynkLocalMessagingError("local_message_store_busy", { retryable: true });
  }
  try {
    return await callback();
  } finally {
    await releaseOwnedStoreLock(lockPath, handle, ownershipToken);
  }
}

async function withPathMutationQueue(storePath, callback) {
  const previous = pathMutationQueues.get(storePath) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => gate);
  pathMutationQueues.set(storePath, tail);
  await previous;
  try {
    return await withCrossProcessStoreLock(storePath, callback);
  } finally {
    release();
    if (pathMutationQueues.get(storePath) === tail) pathMutationQueues.delete(storePath);
  }
}

// Reuse the short, cross-process filesystem transaction for native worker
// election. Callers must release it before waiting for a model or a task.
export async function withHelloLynkLocalMutationLock(targetPath, callback) {
  if (typeof targetPath !== "string" || !isAbsolute(targetPath) || typeof callback !== "function") {
    throw new HelloLynkLocalMessagingError("local_mutation_lock_invalid");
  }
  return withPathMutationQueue(targetPath, callback);
}

function safeId(value, code) {
  const normalized = String(value || "").trim();
  if (!SAFE_ID.test(normalized)) throw new HelloLynkLocalMessagingError(code);
  return normalized;
}

function inboxReaderId(value) {
  if (typeof value !== "string" || safeId(value, "local_inbox_reader_invalid") !== value) {
    throw new HelloLynkLocalMessagingError("local_inbox_reader_invalid");
  }
  return value;
}

function safeText(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new HelloLynkLocalMessagingError("local_message_text_required");
  }
  if (Buffer.byteLength(value, "utf8") > MAX_TEXT_BYTES) {
    throw new HelloLynkLocalMessagingError("local_message_text_too_large");
  }
  return value;
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw new HelloLynkLocalMessagingError("e2ee_preparation_cancelled", { retryable: true });
  }
}

function safeLocalErrorCode(error) {
  const code = String(error?.code || "delivery_state_unknown");
  return /^[a-z][a-z0-9_]{1,127}$/.test(code) ? code : "delivery_state_unknown";
}

function normalizeOutgoingRoute(value, e2eeVersion) {
  if (value == null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkLocalMessagingError("e2ee_route_invalid");
  }
  const fields = Object.keys(value);
  if (value.routeKind === "instance_direct") {
    if (fields.length !== 2 || !Object.hasOwn(value, "recipientDelegateId")) {
      throw new HelloLynkLocalMessagingError("e2ee_route_invalid");
    }
    if (String(e2eeVersion || "1") !== "2") {
      throw new HelloLynkLocalMessagingError("e2ee_route_version_unsupported");
    }
    return {
      routeKind: "instance_direct",
      recipientDelegateId: safeId(value.recipientDelegateId, "e2ee_recipient_delegate_invalid"),
    };
  }
  if (value.routeKind !== "owned_delegate") {
    throw new HelloLynkLocalMessagingError("e2ee_route_kind_invalid");
  }
  const allowed = new Set(["routeKind", "recipientDelegateId", "recipientHostId", "recipientDeviceId"]);
  if (
    fields.some((field) => !allowed.has(field))
    || !Object.hasOwn(value, "recipientDelegateId")
    || !Object.hasOwn(value, "recipientHostId")
    || (fields.length !== 3 && fields.length !== 4)
  ) throw new HelloLynkLocalMessagingError("e2ee_route_invalid");
  if (String(e2eeVersion || "1") !== "2") {
    throw new HelloLynkLocalMessagingError("e2ee_route_version_unsupported");
  }
  return {
    routeKind: "owned_delegate",
    recipientDelegateId: safeId(value.recipientDelegateId, "e2ee_recipient_delegate_invalid"),
    recipientHostId: safeId(value.recipientHostId, "e2ee_recipient_host_invalid"),
    ...(value.recipientDeviceId == null ? {} : {
      recipientDeviceId: safeId(value.recipientDeviceId, "e2ee_recipient_device_invalid"),
    }),
  };
}

function optionalVerifiedDisplayName(value, code) {
  if (value == null) return null;
  const normalized = String(value).trim();
  if (
    normalized.length < 1 || [...normalized].length > 80 ||
    /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u.test(normalized)
  ) throw new HelloLynkLocalMessagingError(code);
  return normalized;
}

function normalizeMessageProvenance(authorizationScope, intentSource, options = {}) {
  const scopeMissing = authorizationScope == null;
  const intentMissing = intentSource == null;
  if (scopeMissing && intentMissing && options.required !== true) {
    return { authorizationScope: null, intentSource: null };
  }
  if (
    scopeMissing !== intentMissing
    || authorizationScope !== DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE
    || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(intentSource)
  ) throw new HelloLynkLocalMessagingError(options.code || "message_provenance_invalid");
  return { authorizationScope, intentSource };
}

function provenanceFromStoredE2ee(e2ee, senderPrincipalId, senderDelegateId) {
  if (e2ee == null) return { authorizationScope: null, intentSource: null };
  const protectedMetadata = e2ee.envelope?.protected;
  if (
    !protectedMetadata || typeof protectedMetadata !== "object" || Array.isArray(protectedMetadata)
    || protectedMetadata.senderPrincipalId !== senderPrincipalId
    || protectedMetadata.senderDelegateId !== senderDelegateId
  ) throw new HelloLynkLocalMessagingError("e2ee_outgoing_provenance_invalid");
  return normalizeMessageProvenance(
    protectedMetadata.authorizationScope,
    protectedMetadata.intentSource,
    { required: true, code: "e2ee_outgoing_provenance_invalid" },
  );
}

function safeSha256(value, code = "e2ee_envelope_digest_invalid") {
  const normalized = String(value || "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new HelloLynkLocalMessagingError(code);
  return normalized;
}

function normalizeStoredE2ee(value) {
  if (value == null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkLocalMessagingError("e2ee_outgoing_contract_invalid");
  }
  const claimId = safeId(value.claimId, "e2ee_claim_id_invalid");
  const envelopeDigest = safeSha256(value.envelopeDigest);
  const envelope = value.envelope;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new HelloLynkLocalMessagingError("e2ee_envelope_invalid");
  }
  const serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized, "utf8") > MAX_ARCHIVE_RECORD_BYTES) {
    throw new HelloLynkLocalMessagingError("e2ee_envelope_too_large");
  }
  const calculatedDigest = crypto.createHash("sha256").update(serialized, "utf8").digest("hex");
  if (calculatedDigest !== envelopeDigest) {
    throw new HelloLynkLocalMessagingError("e2ee_envelope_digest_mismatch");
  }
  const version = String(value.version || (
    envelope.schemaVersion === 2 ? "2" : E2EE_DIRECT_TEXT_VERSION
  ));
  if (!["1", "2"].includes(version) || (version === "2" && Number(envelope.schemaVersion) !== 2)) {
    throw new HelloLynkLocalMessagingError("e2ee_version_unsupported");
  }
  if (Object.hasOwn(value, "nativeContentVersion") && (version !== "2" || value.nativeContentVersion !== 1))
    throw new HelloLynkLocalMessagingError("e2ee_outgoing_contract_invalid");
  const route = version === "2" ? {
    routeKind: ["principal_inbox", "owned_delegate", "instance_direct"].includes(value.routeKind)
      ? value.routeKind : (() => { throw new HelloLynkLocalMessagingError("e2ee_route_kind_invalid"); })(),
    recipientDelegateId: safeId(value.recipientDelegateId, "e2ee_recipient_delegate_invalid"),
    recipientHostId: safeId(value.recipientHostId, "e2ee_recipient_host_invalid"),
    recipientDeviceId: safeId(value.recipientDeviceId, "e2ee_recipient_device_invalid"),
  } : {};
  return {
    version,
    ...route,
    ...(value.nativeContentVersion === 1 ? { nativeContentVersion: 1 } : {}),
    claimId,
    envelopeDigest,
    envelope: structuredClone(envelope),
  };
}

function publicRemoteCode(value, fallback) {
  const code = String(value || "");
  return /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : fallback;
}

async function readBoundedText(response, maximum = MAX_JSON_RESPONSE_BYTES) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximum) {
    // Dispose the unread response without delaying or changing the send result.
    try { void Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {}
    throw new HelloLynkLocalMessagingError("relay_response_too_large");
  }
  if (!response.body?.getReader) throw new HelloLynkLocalMessagingError("relay_response_body_missing");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) throw new HelloLynkLocalMessagingError("relay_response_too_large");
      chunks.push(value);
    }
  } catch (error) {
    try { void Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
    throw error;
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

function hasExactFields(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const observed = Object.keys(value).sort();
  return observed.length === expected.length
    && observed.every((field, index) => field === expected[index]);
}

function validateCurrentMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.keys(message).some((field) => !CURRENT_MESSAGE_FIELDS.has(field))) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.hasOwn(message, "automaticDeliveryState") && (message.direction !== "incoming" || message.automaticDeliveryState !== "expired")) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.hasOwn(message, "conversationDeleted") && (message.conversationDeleted !== true || message.messageType !== LOCAL_DELETED_MESSAGE_TYPE)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.hasOwn(message, "targetConversationId")) {
    nativeConversationId(message.targetConversationId);
    if (message.replyToClientMessageId) throw new HelloLynkLocalMessagingError("native_target_conflicts_with_reply");
  }
  if (Object.hasOwn(message, "targetConversationTitle")) {
    if (message.direction !== "outgoing" || !message.targetConversationId) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    nativeConversationTitle(message.targetConversationTitle);
  }
  if (Object.hasOwn(message, "friendTargetHeld") && (message.friendTargetHeld !== true || message.direction !== "incoming"
    || !message.targetConversationId)) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  if (Object.hasOwn(message, "replyToClientMessageId")) {
    safeId(message.replyToClientMessageId, "local_message_store_invalid");
    if (message.replyToClientMessageId === message.clientMessageId) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.hasOwn(message, "replyTargetDeleted") && (message.replyTargetDeleted !== true || !message.replyToClientMessageId
    || message.direction !== "incoming" || message.messageType !== LOCAL_DELETED_MESSAGE_TYPE)) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  for (const field of ["resendSourceClientMessageId", "resendClientMessageId"]) if (Object.hasOwn(message, field)) {
    safeId(message[field], "local_message_store_invalid");
    if (message.direction !== "outgoing" || message[field] === message.clientMessageId) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  safeId(message.localMessageId, "local_message_store_invalid");
  safeId(message.clientMessageId, "local_message_store_invalid");
  if (Object.hasOwn(message, "receiptSeq") && (message.direction !== "incoming"
    || !Number.isSafeInteger(message.receiptSeq) || message.receiptSeq < 1)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (!["incoming", "outgoing"].includes(message.direction)
    || !Object.hasOwn(message, "peerHelloLynkId")) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (message.peerHelloLynkId == null) {
    if (message.direction !== "incoming") {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
  } else {
    safeId(message.peerHelloLynkId, "local_message_store_invalid");
  }
  for (const field of ["recipientHelloLynkId", "senderHelloLynkId"]) {
    if (Object.hasOwn(message, field) && message[field] != null) {
      safeId(message[field], "local_message_store_invalid");
    }
  }
  if (message.conversationBinding != null || message.conversationIntent != null) {
    try {
      if (message.direction !== "outgoing" && message.conversationIntent != null) {
        throw new Error("incoming_conversation_intent_invalid");
      }
      getMessageConversationBinding(message);
    } catch (cause) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid", { cause });
    }
  }
  if (message.e2eePreparation != null) {
    const preparation = message.e2eePreparation;
    if (message.direction !== "outgoing" || !hasExactFields(preparation, ["intentSource", "route"])
      || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(preparation.intentSource)) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    normalizeOutgoingRoute(preparation.route, "2");
  }
  return message;
}

export function assertHelloLynkLocalMessageStore(input, profileId) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (!hasExactFields(input, [...STORE_FIELDS,
    ...(Object.hasOwn(input, "receiptHighWater") ? ["receiptHighWater"] : []),
    ...(Object.hasOwn(input, "inboxReaders") ? ["inboxReaders"] : []),
    ...(Object.hasOwn(input, "inboxClaims") ? ["inboxClaims"] : []),
  ].sort())
    || input.contractId !== HELLOLYNK_LOCAL_MESSAGE_STORE_CONTRACT
    || input.schemaVersion !== STORE_SCHEMA_VERSION
    || input.profileId !== profileId
    || !Array.isArray(input.messages)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  for (const message of input.messages) validateCurrentMessage(message);
  const highWater = Object.hasOwn(input, "receiptHighWater") ? input.receiptHighWater : 0;
  if (!Number.isSafeInteger(highWater) || highWater < 0
    || input.messages.some((message) => message.receiptSeq > highWater)) {
    throw new HelloLynkLocalMessagingError("local_message_store_invalid");
  }
  if (Object.hasOwn(input, "inboxReaders")) {
    if (!Object.hasOwn(input, "receiptHighWater") || !Array.isArray(input.inboxReaders) || input.inboxReaders.length > 1024) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    const seen = new Set();
    for (const reader of input.inboxReaders) {
      if (!hasExactFields(reader, ["adapterId", "afterSeq", "delegateId"])
        || !Number.isSafeInteger(reader.afterSeq) || reader.afterSeq < 0 || reader.afterSeq > highWater) {
        throw new HelloLynkLocalMessagingError("local_message_store_invalid");
      }
      const key = JSON.stringify([inboxReaderId(reader.adapterId), inboxReaderId(reader.delegateId)]);
      if (seen.has(key)) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
      seen.add(key);
    }
  }
  if (Object.hasOwn(input, "inboxClaims")) {
    if (!Array.isArray(input.inboxClaims) || !Array.isArray(input.inboxReaders)) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    const seen = new Set();
    const claimIds = new Set();
    for (const claim of input.inboxClaims) {
      if (!hasExactFields(claim, ["adapterId", "claimId", "conversationKey", "delegateId", "localMessageId", "outcome", "receiptSeq"])
        || !["inflight", "completed", "unknown"].includes(claim.outcome)
        || !Number.isSafeInteger(claim.receiptSeq) || claim.receiptSeq <= 0 || claim.receiptSeq > highWater
        || !/^inclaim_[a-f0-9]{48}$/.test(claim.claimId)) throw new HelloLynkLocalMessagingError("local_message_store_invalid");
      for (const key of ["adapterId", "delegateId", "localMessageId", "conversationKey"]) inboxReaderId(claim[key]);
      const reader = input.inboxReaders.find((item) => item.adapterId === claim.adapterId && item.delegateId === claim.delegateId);
      const key = JSON.stringify([claim.delegateId, claim.localMessageId]);
      if (!reader || claim.receiptSeq <= reader.afterSeq || seen.has(key) || claimIds.has(claim.claimId)) {
        throw new HelloLynkLocalMessagingError("local_message_store_invalid");
      }
      seen.add(key);
      claimIds.add(claim.claimId);
    }
  }
  return input;
}

export function assertHelloLynkLocalMessageArchiveEnvelope(input, profileId) {
  if (!hasExactFields(input, ARCHIVE_ENVELOPE_FIELDS)
    || input.contractId !== HELLOLYNK_LOCAL_MESSAGE_STORE_CONTRACT
    || input.schemaVersion !== STORE_SCHEMA_VERSION
    || input.profileId !== profileId
    || typeof input.archivedAt !== "string"
    || !input.message
    || typeof input.message !== "object"
    || Array.isArray(input.message)) {
    throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
  }
  try {
    validateCurrentMessage(input.message);
  } catch (error) {
    throw new HelloLynkLocalMessagingError("local_message_archive_invalid", { cause: error });
  }
  return input;
}

function emptyStore(profileId) {
  return {
    contractId: HELLOLYNK_LOCAL_MESSAGE_STORE_CONTRACT,
    schemaVersion: STORE_SCHEMA_VERSION,
    profileId,
    messages: [],
  };
}

async function readStore(path, profileId, maximumBytes = MAX_STORE_BYTES, protection = null) {
  let handle;
  try {
    await assertMessageStoreAccess(path, protection, { create: false });
    const physicalMaximum = protectedStoreMaximum(maximumBytes, protection);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > physicalMaximum) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    handle = await open(path, "r");
    const openedMetadata = await handle.stat();
    if (!openedMetadata.isFile() || openedMetadata.size > physicalMaximum
      || (Number.isSafeInteger(metadata.dev) && Number.isSafeInteger(metadata.ino)
        && Number.isSafeInteger(openedMetadata.dev) && Number.isSafeInteger(openedMetadata.ino)
        && ((process.platform !== "win32" && metadata.dev !== openedMetadata.dev) || metadata.ino !== openedMetadata.ino))) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    const stored = JSON.parse(await handle.readFile("utf8"));
    const opened = protection
      ? await protection.protector.openJson(stored, protection.mainContext)
      : stored;
    if (storeByteLength(opened) > maximumBytes) {
      throw new HelloLynkLocalMessagingError("local_message_store_invalid");
    }
    return assertHelloLynkLocalMessageStore(opened, profileId);
  } catch (error) {
    if (error?.code === "ENOENT") return emptyStore(profileId);
    if (error instanceof HelloLynkLocalMessagingError) throw error;
    throw new HelloLynkLocalMessagingError("local_message_store_invalid", { cause: error });
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function syncParentDirectory(path) {
  let handle = null;
  try {
    handle = await open(dirname(path), "r");
    await handle.sync();
  } catch (error) {
    if (!["EBADF", "EINVAL", "EISDIR", "ENOTSUP", "EPERM"].includes(error?.code)) throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function atomicWriteStore(path, store, maximumBytes = MAX_STORE_BYTES, protection = null) {
  await assertMessageStoreAccess(path, protection, { create: true });
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  if (storeByteLength(store) > maximumBytes) {
    throw new HelloLynkLocalMessagingError("local_message_store_too_large");
  }
  const stored = protection
    ? await protection.protector.sealJson(store, protection.mainContext)
    : store;
  const body = `${JSON.stringify(stored, null, 2)}\n`;
  if (Buffer.byteLength(body, "utf8") > protectedStoreMaximum(maximumBytes, protection)) {
    throw new HelloLynkLocalMessagingError("local_message_store_too_large");
  }
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await assertMessageStoreAccess(path, protection, { create: false });
    await replaceLocalStoreFileWithRetry(temporary, path);
    await assertMessageStoreAccess(path, protection, { create: false });
    await syncParentDirectory(path);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

function storeByteLength(store) {
  return Buffer.byteLength(`${JSON.stringify(store, null, 2)}\n`, "utf8");
}

function protectedStoreMaximum(maximumBytes, protection) {
  return protection ? maximumBytes * 2 : maximumBytes;
}

function isArchivableMessage(message) {
  return message?.direction === "outgoing"
    ? ARCHIVABLE_OUTGOING_STATUSES.has(message.status)
    : message?.direction === "incoming" && ARCHIVABLE_INCOMING_STATUSES.has(message.status);
}

async function archiveEnvelope(profileId, message, protection = null) {
  const value = {
    contractId: HELLOLYNK_LOCAL_MESSAGE_STORE_CONTRACT,
    schemaVersion: STORE_SCHEMA_VERSION,
    profileId,
    archivedAt: new Date().toISOString(),
    message,
  };
  return protection
    ? protection.protector.sealArchiveLine(value, protection.archiveContext)
    : JSON.stringify(value);
}

async function parseArchiveEnvelope(line, profileId, protection = null) {
  let parsed;
  try {
    parsed = protection
      ? await protection.protector.openArchiveLine(line, protection.archiveContext)
      : JSON.parse(line);
  } catch (error) {
    throw new HelloLynkLocalMessagingError("local_message_archive_invalid", { cause: error });
  }
  return assertHelloLynkLocalMessageArchiveEnvelope(parsed, profileId).message;
}

async function recoverInterruptedArchiveTail(path, profileId, protection = null) {
  await assertMessageStoreAccess(path, protection, { create: false });
  const handle = await open(path, "r+");
  let changed = false;
  try {
    const metadata = await handle.stat();
    if (metadata.size === 0) return false;
    const lastByte = Buffer.alloc(1);
    await handle.read(lastByte, 0, 1, metadata.size - 1);
    if (lastByte[0] === 0x0a) return false;

    let cursor = metadata.size;
    let lastNewline = -1;
    while (cursor > 0) {
      const start = Math.max(0, cursor - 64 * 1024);
      const chunk = Buffer.alloc(cursor - start);
      await handle.read(chunk, 0, chunk.length, start);
      const offset = chunk.lastIndexOf(0x0a);
      if (offset >= 0) {
        lastNewline = start + offset;
        break;
      }
      cursor = start;
    }

    const tailStart = lastNewline + 1;
    const tailLength = metadata.size - tailStart;
    let completeEnvelope = false;
    const maximumTailBytes = protection
      ? MAX_PROTECTED_ARCHIVE_RECORD_BYTES
      : MAX_ARCHIVE_RECORD_BYTES;
    if (tailLength <= maximumTailBytes) {
      const tail = Buffer.alloc(tailLength);
      await handle.read(tail, 0, tail.length, tailStart);
      const tailText = tail.toString("utf8");
      if (protection) {
        let syntacticallyComplete = false;
        try {
          JSON.parse(tailText);
          syntacticallyComplete = true;
        } catch {
          // A syntactically incomplete final write may be truncated. A complete
          // protected envelope that fails authentication must never be repaired.
        }
        if (syntacticallyComplete) {
          await parseArchiveEnvelope(tailText, profileId, protection);
          completeEnvelope = true;
        }
      } else {
        try {
          await parseArchiveEnvelope(tailText, profileId, null);
          completeEnvelope = true;
        } catch (error) {
          if (!(error instanceof HelloLynkLocalMessagingError)) throw error;
        }
      }
    }

    if (completeEnvelope) {
      await handle.write("\n", metadata.size, "utf8");
    } else {
      await handle.truncate(tailStart);
    }
    await handle.sync();
    changed = true;
  } finally {
    await handle.close();
  }
  if (changed) await syncParentDirectory(path);
  return changed;
}

async function appendArchiveMessages(path, profileId, messages, protection = null) {
  if (messages.length === 0) return;
  await assertMessageStoreAccess(path, protection, { create: true });
  let archiveExists = true;
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    archiveExists = false;
  }
  if (archiveExists) await recoverInterruptedArchiveTail(path, profileId, protection);
  const handle = await open(path, "a", 0o600);
  try {
    const lines = await Promise.all(
      messages.map((message) => archiveEnvelope(profileId, message, protection)),
    );
    await assertMessageStoreAccess(path, protection, { create: false });
    await handle.writeFile(`${lines.join("\n")}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncParentDirectory(path);
}

async function replaceArchiveMessages(path, profileId, messages, protection = null) {
  await assertMessageStoreAccess(path, protection, { create: true });
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  const lines = await Promise.all(
    messages.map((message) => archiveEnvelope(profileId, message, protection)),
  );
  const body = messages.length === 0
    ? ""
    : `${lines.join("\n")}\n`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await assertMessageStoreAccess(path, protection, { create: false });
    await replaceLocalStoreFileWithRetry(temporary, path);
    await assertMessageStoreAccess(path, protection, { create: false });
    await syncParentDirectory(path);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

async function scanArchive(path, profileId, predicate = null, protection = null) {
  try {
    await assertMessageStoreAccess(path, protection, { create: false });
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
    }
  } catch (error) {
    if (error?.code === "ENOENT") return predicate ? null : [];
    throw error;
  }
  await recoverInterruptedArchiveTail(path, profileId, protection);
  await assertMessageStoreAccess(path, protection, { create: false });
  const stream = createReadStream(path, { encoding: "utf8" });
  const reader = createInterface({ input: stream, crlfDelay: Infinity });
  const messages = [];
  let latestMatch = null;
  try {
    for await (const line of reader) {
      if (!line) continue;
      const message = await parseArchiveEnvelope(line, profileId, protection);
      if (predicate) {
        if (predicate(message)) latestMatch = message;
      } else {
        messages.push(message);
      }
    }
  } finally {
    reader.close();
    stream.destroy();
  }
  return predicate
    ? (latestMatch ? structuredClone(latestMatch) : null)
    : structuredClone(messages);
}

async function assertMessageStoreDirectoryAccess(filePath, options = {}) {
  const parent = dirname(resolve(filePath));
  if (options.create === true) await mkdir(parent, { recursive: true, mode: 0o700 });
  const root = parse(parent).root;
  let cursor = root;
  for (const segment of relative(root, parent).split(sep).filter(Boolean)) {
    cursor = join(cursor, segment);
    const metadata = await lstat(cursor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new HelloLynkLocalMessagingError("local_message_store_directory_invalid");
    }
  }
  return parent;
}

async function assertMessageStoreAccess(filePath, protection, options = {}) {
  const parent = await assertMessageStoreDirectoryAccess(filePath, options);
  const dataRoot = ["messages", "contacts", "contact-requests"].includes(basename(parent))
    ? dirname(parent)
    : parent;
  try {
    await assertLocalDataProtectionAccess(dataRoot, protection != null);
  } catch (error) {
    throw new HelloLynkLocalMessagingError(error?.code || "local_message_store_access_invalid", { cause: error });
  }
}

function findLatestIndex(items, predicate) {
  for (let index = items.length - 1; index >= 0; index -= 1) {
    if (predicate(items[index])) return index;
  }
  return -1;
}

function normalizeMessageDataProtection(protector, profileId) {
  if (protector == null) return null;
  if (["sealJson", "openJson", "sealArchiveLine", "openArchiveLine"].some(
    (method) => typeof protector?.[method] !== "function",
  )) {
    throw new HelloLynkLocalMessagingError("local_message_data_protector_invalid");
  }
  return Object.freeze({
    protector,
    mainContext: Object.freeze({
      profileId,
      assetKind: "messages",
      logicalPath: `messages/${profileId}.json`,
    }),
    archiveContext: Object.freeze({
      profileId,
      assetKind: "messages-archive-line",
      logicalPath: `messages/${profileId}.json.archive.ndjson`,
    }),
  });
}

async function compactFinalMessages({
  store,
  archivePath,
  profileId,
  triggerBytes,
  targetBytes,
  protection = null,
}) {
  if (storeByteLength(store) <= triggerBytes) return 0;
  const candidates = store.messages
    .filter(isArchivableMessage)
    .sort((left, right) => String(left.updatedAt || left.createdAt).localeCompare(String(right.updatedAt || right.createdAt)));
  const archived = [];
  const archivedIds = new Set();
  for (const message of candidates) {
    archived.push(message);
    archivedIds.add(message.localMessageId);
    const retained = store.messages.filter((item) => !archivedIds.has(item.localMessageId));
    if (storeByteLength({ ...store, messages: retained }) <= targetBytes) break;
  }
  if (archived.length === 0) return 0;
  await appendArchiveMessages(archivePath, profileId, archived, protection);
  store.messages = store.messages.filter((item) => !archivedIds.has(item.localMessageId));
  return archived.length;
}

export function createLocalMessageStore(options = {}) {
  const profileId = safeId(options.profileId, "local_message_profile_id_invalid");
  const storePath = String(options.storePath || "").trim();
  const archivePath = `${storePath}.archive.ndjson`;
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const configuredMaximum = Number(options.maxStoreBytes);
  const maximumBytes = Number.isSafeInteger(configuredMaximum) && configuredMaximum >= MIN_CONFIGURED_STORE_BYTES
    ? configuredMaximum
    : MAX_STORE_BYTES;
  const compactionTriggerBytes = Math.floor(maximumBytes * 0.75);
  const compactionTargetBytes = Math.floor(maximumBytes * 0.5);
  if (!storePath) throw new HelloLynkLocalMessagingError("local_message_store_path_required");
  const protection = normalizeMessageDataProtection(options.dataProtector, profileId);
  const localHistoryPath = `${storePath}.local-history.json`;
  const historyProtection = protection ? { ...protection, mainContext: Object.freeze({
    profileId, assetKind: "messages", logicalPath: `messages/${profileId}.json.local-history.json`,
  }) } : null;
  let cachedHistory = null;

  function emptyHistory() {
    return { contractId: LOCAL_HISTORY_CONTRACT, schemaVersion: 1, profileId,
      cleanupPending: false, deleted: [], hidden: [] };
  }

  async function readHistory() {
    await assertMessageStoreAccess(localHistoryPath, historyProtection, { create: false });
    let metadata;
    try { metadata = await lstat(localHistoryPath); }
    catch (error) { if (error?.code === "ENOENT") { cachedHistory = null; return emptyHistory(); } throw error; }
    if (!metadata.isFile() || metadata.isSymbolicLink()
      || metadata.size > protectedStoreMaximum(MAX_LOCAL_HISTORY_BYTES, historyProtection)) throw localHistoryFailure("index_invalid");
    const signature = `${metadata.dev}:${metadata.ino}:${metadata.size}:${metadata.mtimeMs}:${metadata.ctimeMs}`;
    if (cachedHistory?.signature === signature) return structuredClone(cachedHistory.value);
    const handle = await open(localHistoryPath, "r");
    let value;
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || (process.platform !== "win32" && opened.dev !== metadata.dev) || opened.ino !== metadata.ino
        || opened.size !== metadata.size) throw localHistoryFailure("index_invalid");
      const stored = JSON.parse(await handle.readFile("utf8"));
      value = historyProtection ? await historyProtection.protector.openJson(stored, historyProtection.mainContext) : stored;
    } catch (cause) { throw localHistoryFailure("index_invalid"); }
    finally { await handle.close(); }
    if (!hasExactFields(value, ["cleanupPending", "contractId", "deleted", "hidden", "profileId", "schemaVersion"])
      || value.contractId !== LOCAL_HISTORY_CONTRACT || value.schemaVersion !== 1 || value.profileId !== profileId
      || typeof value.cleanupPending !== "boolean" || !Array.isArray(value.deleted) || !Array.isArray(value.hidden)
      || storeByteLength(value) > MAX_LOCAL_HISTORY_BYTES) throw localHistoryFailure("index_invalid");
    const ids = new Set();
    for (const item of value.deleted) {
      validateCurrentMessage(item);
      if (item.messageType !== LOCAL_DELETED_MESSAGE_TYPE || item.text !== "" || item.e2ee != null
        || ids.has(item.localMessageId)) throw localHistoryFailure("index_invalid");
      ids.add(item.localMessageId);
    }
    const hiddenKeys = new Set();
    for (const item of value.hidden) {
      if (!hasExactFields(item, ["delegateId", "knownMessageIds", "principalId", "region", "threadId"])) throw localHistoryFailure("index_invalid");
      const scope = localHistoryScope(item);
      safeId(item.threadId, "local_history_index_invalid");
      if (!Array.isArray(item.knownMessageIds)) throw localHistoryFailure("index_invalid");
      for (const id of item.knownMessageIds) safeId(id, "local_history_index_invalid");
      const key = `${localHistoryScopeKey(scope)}\0${item.threadId}`;
      if (hiddenKeys.has(key)) throw localHistoryFailure("index_invalid");
      hiddenKeys.add(key);
    }
    cachedHistory = { signature, value: structuredClone(value) };
    return value;
  }

  async function writeHistory(index) {
    cachedHistory = null;
    await atomicWriteStore(localHistoryPath, index, MAX_LOCAL_HISTORY_BYTES, historyProtection);
  }

  function mergeMessageCopies(store, archived) {
    const byId = new Map();
    for (const item of [...archived, ...store.messages]) {
      // A compacted tombstone always wins over a stale duplicate body.
      if (byId.get(item.localMessageId)?.messageType !== LOCAL_DELETED_MESSAGE_TYPE) byId.set(item.localMessageId, item);
    }
    return [...byId.values()];
  }

  async function applyHistoryCleanup(store, index, archived = null) {
    if (!index.cleanupPending) return store;
    const deletions = new Map(index.deleted.map((item) => [item.localMessageId, item]));
    const archive = archived || await scanArchive(archivePath, profileId, null, protection);
    const scrub = (items) => items.map((item) => deletions.get(item.localMessageId) || item);
    const nextArchived = scrub(archive);
    if (JSON.stringify(nextArchived) !== JSON.stringify(archive)) {
      await replaceArchiveMessages(archivePath, profileId, nextArchived, protection);
    }
    await options.localHistoryFault?.("archive-cleaned");
    const nextMessages = scrub(store.messages);
    if (JSON.stringify(nextMessages) !== JSON.stringify(store.messages)) {
      store.messages = nextMessages;
      await atomicWriteStore(storePath, store, maximumBytes, protection);
    }
    await options.localHistoryFault?.("main-cleaned");
    index.cleanupPending = false;
    await writeHistory(index);
    return store;
  }

  async function readCurrentStore() {
    const store = await readStore(storePath, profileId, maximumBytes, protection);
    const index = await readHistory();
    return applyHistoryCleanup(store, index);
  }

  async function readAdmissionStore() {
    const store = await readCurrentStore();
    const index = await readHistory();
    const archived = await scanArchive(archivePath, profileId, null, protection);
    if ([...index.deleted, ...archived].some((item) => item.receiptSeq > (store.receiptHighWater ?? 0))) {
      throw new HelloLynkLocalMessagingError("local_message_receipt_sequence_invalid");
    }
    return store;
  }

  async function restoreChangedConversations(index, messages) {
    if (index.hidden.length === 0 || messages.length === 0) return;
    const before = index.hidden.length;
    const keyFor = (item) => `${localHistoryScopeKey(item)}\0${item.threadId}`;
    const hidden = new Map(index.hidden.map((item) => [keyFor(item), new Set(item.knownMessageIds)]));
    for (const message of messages) {
      let binding;
      try { binding = getMessageConversationBinding(message) || getOutgoingConversationIntent(message); }
      catch { continue; }
      if (!binding) continue;
      const key = `${localHistoryScopeKey({ region: binding.region, principalId: binding.localPrincipalId,
        delegateId: binding.localDelegateId })}\0${instanceConversationKey(binding)}`;
      const known = hidden.get(key);
      if (known && !known.has(message.localMessageId)) hidden.delete(key);
    }
    index.hidden = index.hidden.filter((item) => hidden.has(keyFor(item)));
    if (index.hidden.length !== before) await writeHistory(index);
  }

  async function localHistoryMutation(input, operation) {
    const scope = localHistoryScope(input);
    const threadId = operation === "delete" ? null : safeId(input.threadId, "local_history_thread_invalid");
    const requestedIds = operation === "delete" ? [...new Set((input.localMessageIds || []).map(
      (id) => safeId(id, "local_history_message_invalid")))] : [];
    if (operation === "delete" && (requestedIds.length === 0 || requestedIds.length > 500)) throw localHistoryFailure("message_invalid");
    return withPathMutationQueue(storePath, async () => {
      const store = await readCurrentStore();
      const index = await readHistory();
      const archived = await scanArchive(archivePath, profileId, null, protection);
      const all = mergeMessageCopies(store, archived);
      const selected = operation === "delete" ? requestedIds.map((id) => {
        const message = all.find((item) => item.localMessageId === id)
          || index.deleted.find((item) => item.localMessageId === id);
        if (!message || message.direction !== "outgoing" || message.senderPrincipalId !== scope.principalId
          || message.senderDelegateId !== scope.delegateId || !localHistoryBinding(message, scope)) throw localHistoryFailure("record_not_found");
        if (!localHistorySent(message)) throw localHistoryFailure("outgoing_protected");
        return message;
      }) : all.filter((message) => localHistoryThreadId(message, scope) === threadId);
      const visible = selected.filter((message) => message.messageType !== LOCAL_DELETED_MESSAGE_TYPE);
      const retainedUnreadCount = visible.filter(localHistoryUnread).length;
      const retainedOutgoingCount = visible.filter((message) => message.direction === "outgoing" && !localHistorySent(message)).length;
      const sameHidden = (item) => localHistoryScopeKey(item) === localHistoryScopeKey(scope) && item.threadId === threadId;
      if (operation === "hide") {
        if (retainedUnreadCount) throw localHistoryFailure("unread_protected");
        if (retainedOutgoingCount) throw localHistoryFailure("outgoing_protected");
        index.hidden = index.hidden.filter((item) => !sameHidden(item));
        index.hidden.push({ ...scope, threadId, knownMessageIds: selected.map((item) => item.localMessageId).sort() });
        await writeHistory(index);
        return {};
      }
      if (operation === "restore") {
        if (index.hidden.some(sameHidden)) { index.hidden = index.hidden.filter((item) => !sameHidden(item)); await writeHistory(index); }
        return {};
      }
      const deletable = visible.filter((message) => message.direction === "incoming" ? !localHistoryUnread(message) : localHistorySent(message));
      if (deletable.length) {
        const tombstones = new Map(index.deleted.map((item) => [item.localMessageId, item]));
        for (const message of deletable) tombstones.set(message.localMessageId, localHistoryTombstone(message, scope));
        index.deleted = [...tombstones.values()];
        index.cleanupPending = true;
        // This durable intent is the visibility commit. Main/archive redaction
        // is recoverable, not a claimed multi-file atomic transaction. Each
        // body replacement preserves its ID and terminal evidence atomically.
        await writeHistory(index);
        await options.localHistoryFault?.("intent-committed");
        await applyHistoryCleanup(store, index, archived);
      }
      return { deletedCount: deletable.length, retainedUnreadCount, retainedOutgoingCount };
    });
  }

  async function mutate(callback, mutationOptions = {}) {
    return withPathMutationQueue(storePath, async () => {
      const store = await readCurrentStore();
      const initialIds = new Set(store.messages.map((item) => item.localMessageId));
      const archived = mutationOptions.scanArchive === true
        ? await scanArchive(archivePath, profileId, null, protection)
        : [];
      const result = await callback(store, archived);
      await compactFinalMessages({
        store,
        archivePath,
        profileId,
        triggerBytes: compactionTriggerBytes,
        targetBytes: compactionTargetBytes,
        protection,
      });
      await atomicWriteStore(storePath, store, maximumBytes, protection);
      const added = store.messages.filter((item) => !initialIds.has(item.localMessageId));
      if (added.length) await restoreChangedConversations(await readHistory(), added);
      return result;
    });
  }

  return {
    path: storePath,
    archivePath,
    localHistoryPath,
    readLegacyHistoryForMigration: readHistory,
    async getReceiptHighWater() {
      return withPathMutationQueue(storePath, async () => (await readAdmissionStore()).receiptHighWater ?? 0);
    },
    async getInboxReaderBoundary(adapterId, delegateId) {
      inboxReaderId(adapterId);
      inboxReaderId(delegateId);
      return withPathMutationQueue(storePath, async () => {
        const store = await readAdmissionStore();
        return store.inboxReaders?.find((item) => item.adapterId === adapterId && item.delegateId === delegateId)?.afterSeq ?? null;
      });
    },
    async activateInboxReader(adapterId, delegateId) {
      inboxReaderId(adapterId);
      inboxReaderId(delegateId);
      return withPathMutationQueue(storePath, async () => {
        const store = await readAdmissionStore();
        const existing = store.inboxReaders?.find((item) => item.adapterId === adapterId && item.delegateId === delegateId);
        if (existing) return existing.afterSeq;
        if ((store.inboxReaders?.length ?? 0) >= 1024) {
          throw new HelloLynkLocalMessagingError("local_inbox_reader_capacity_exceeded");
        }
        store.receiptHighWater ??= 0;
        store.inboxReaders = [...(store.inboxReaders || []), { adapterId, delegateId, afterSeq: store.receiptHighWater }];
        // The durable first activation shares the incoming-record order. Reopen
        // and repeated activation return this same boundary, preserving backlog.
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        return store.receiptHighWater;
      });
    },
    async listInboxClaimIds(delegateId) {
      inboxReaderId(delegateId);
      return withPathMutationQueue(storePath, async () => (await readAdmissionStore()).inboxClaims
        ?.filter((item) => item.delegateId === delegateId).map((item) => item.localMessageId) ?? []);
    },
    async claimInboxMessage(input, authorize) {
      return inboxClaimMutation(input, authorize, false);
    },
    async finishInboxClaim(input, authorize) {
      return inboxClaimMutation(input, authorize, true);
    },
    deleteSentLocal: (input) => localHistoryMutation(input, "delete"),
    hideLocalConversation: (input) => localHistoryMutation(input, "hide"),
    restoreLocalConversation: (input) => localHistoryMutation(input, "restore"),
    clearLocalConversation: (input) => localHistoryMutation(input, "clear"),
    async readWorkbenchState(input) {
      const scope = localHistoryScope(input);
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const archived = await scanArchive(archivePath, profileId, null, protection);
        const index = await readHistory();
        const all = mergeMessageCopies(store, archived);
        await restoreChangedConversations(index, all);
        const deletedIds = new Set(index.deleted.map((item) => item.localMessageId));
        return {
          messages: structuredClone(all.filter((item) => item.messageType !== LOCAL_DELETED_MESSAGE_TYPE && !deletedIds.has(item.localMessageId))),
          hiddenThreadIds: index.hidden.filter((item) => localHistoryScopeKey(item) === localHistoryScopeKey(scope)).map((item) => item.threadId),
        };
      });
    },
    async addOutgoing({ recipientHelloLynkId, clientMessageId, text, senderPrincipalId, senderDelegateId, e2ee, conversationIntent, e2eePreparation, replyToClientMessageId, targetConversationId, resendSourceClientMessageId }) {
      if (targetConversationId != null) throw new HelloLynkLocalMessagingError("native_target_requires_indexed_store");
      if (replyToClientMessageId != null || resendSourceClientMessageId != null || e2ee?.envelope?.protected?.replyToClientMessageId != null) throw new HelloLynkLocalMessagingError("reply_correlation_requires_indexed_store");
      const acceptedRecipient = safeId(recipientHelloLynkId, "recipient_hellolynk_id_invalid");
      const acceptedClientMessageId = safeId(clientMessageId, "client_message_id_invalid");
      const acceptedText = safeText(text);
      const acceptedPrincipalId = safeId(senderPrincipalId, "sender_principal_id_invalid");
      const acceptedDelegateId = safeId(senderDelegateId, "sender_delegate_id_invalid");
      const acceptedE2ee = normalizeStoredE2ee(e2ee);
      const provenance = provenanceFromStoredE2ee(
        acceptedE2ee,
        acceptedPrincipalId,
        acceptedDelegateId,
      );
      return mutate(async (store, archived) => {
        const index = await readHistory();
        if ([...store.messages, ...archived, ...index.deleted].some((item) => item.clientMessageId === acceptedClientMessageId)) {
          throw new HelloLynkLocalMessagingError("client_message_id_exists");
        }
        const at = new Date(now()).toISOString();
        const message = {
          localMessageId: `local_message_${crypto.randomUUID()}`,
          clientMessageId: acceptedClientMessageId,
          direction: "outgoing",
          peerHelloLynkId: acceptedRecipient,
          senderPrincipalId: acceptedPrincipalId,
          senderDelegateId: acceptedDelegateId,
          authorizationScope: provenance.authorizationScope,
          intentSource: provenance.intentSource,
          messageType: "text",
          text: acceptedText,
          transportSecurity: acceptedE2ee ? E2EE_TRANSPORT_SECURITY : "plaintext-v0.1.0",
          e2ee: acceptedE2ee,
          ...(e2eePreparation ? {
            e2eePreparation: structuredClone(e2eePreparation),
            deliveryAttemptPid: process.pid,
            deliveryAttemptInstance: PROCESS_INSTANCE_ID,
            deliveryAttemptStartedAt: at,
          } : {}),
          conversationIntent: normalizeInstanceConversationBinding(conversationIntent),
          status: "pending",
          attempts: 0,
          nextRetryAt: null,
          lastErrorCode: null,
          createdAt: at,
          updatedAt: at,
        };
        message.conversationBinding = getMessageConversationBinding(message);
        store.messages.push(message);
        return structuredClone(message);
      }, { scanArchive: true });
    },
    async updateOutgoing(clientMessageId, patch) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        let archived = null;
        let archivedIndex = -1;
        let message = store.messages.find((item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ));
        if (!message) {
          archived = await scanArchive(archivePath, profileId, null, protection);
          archivedIndex = findLatestIndex(archived, (item) => (
            item.direction === "outgoing" && item.clientMessageId === acceptedId
          ));
          if (archivedIndex >= 0) message = archived[archivedIndex];
        }
        if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
        if (message.messageType === LOCAL_DELETED_MESSAGE_TYPE) throw localHistoryFailure("outgoing_protected");
        if (patch.preparationOnly && (message.status !== "pending" || message.attempts !== 0)) {
          return structuredClone(message);
        }
        if (patch.beforeTransportClaim && (
          message.status !== "delivery_state_unknown" || message.lastErrorCode !== "awaiting_relay_result"
          || message.deliveryAttemptPid !== process.pid || message.deliveryAttemptInstance !== PROCESS_INSTANCE_ID
          || message.attempts !== patch.beforeTransportClaim.attempts
          || message.deliveryAttemptStartedAt !== patch.beforeTransportClaim.startedAt
        )) {
          throw new HelloLynkLocalMessagingError("local_outgoing_attempt_mismatch", { httpStatus: 409 });
        }
        const nextStatus = String(patch.status || message.status);
        if (archived && (message.status !== "failed_permanent" || nextStatus !== "failed_permanent")) {
          throw new HelloLynkLocalMessagingError("local_outgoing_message_not_retryable", { httpStatus: 409 });
        }
        message.status = nextStatus;
        message.attempts = Number(message.attempts || 0) + (patch.incrementAttempts === false ? 0 : 1);
        message.lastErrorCode = patch.lastErrorCode == null ? null : String(patch.lastErrorCode);
        message.deliveryAttemptPid = null;
        message.deliveryAttemptInstance = null;
        message.deliveryAttemptStartedAt = null;
        if (["recipient_offline", "failed_retryable"].includes(nextStatus)) {
          const retryDelayMs = Math.min(1_000 * (2 ** Math.min(Math.max(message.attempts - 1, 0), 6)), 60_000);
          message.nextRetryAt = new Date(now() + retryDelayMs).toISOString();
        } else {
          message.nextRetryAt = null;
        }
        message.updatedAt = new Date(now()).toISOString();
        if (archived) {
          archived[archivedIndex] = message;
          await replaceArchiveMessages(archivePath, profileId, archived, protection);
          return structuredClone(message);
        }
        await compactFinalMessages({
          store,
          archivePath,
          profileId,
          triggerBytes: compactionTriggerBytes,
          targetBytes: compactionTargetBytes,
          protection,
        });
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        return structuredClone(message);
      });
    },
    async attachOutgoingE2ee(clientMessageId, e2ee) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      const acceptedE2ee = normalizeStoredE2ee(e2ee);
      if (!acceptedE2ee) throw new HelloLynkLocalMessagingError("e2ee_required");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const message = store.messages.find((item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ));
        if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
        if (message.status !== "pending" || message.e2ee != null) {
          throw new HelloLynkLocalMessagingError("local_outgoing_e2ee_attach_conflict", { httpStatus: 409 });
        }
        const provenance = provenanceFromStoredE2ee(
          acceptedE2ee,
          message.senderPrincipalId,
          message.senderDelegateId,
        );
        message.e2ee = acceptedE2ee;
        message.conversationBinding = getMessageConversationBinding(message);
        message.authorizationScope = provenance.authorizationScope;
        message.intentSource = provenance.intentSource;
        message.transportSecurity = E2EE_TRANSPORT_SECURITY;
        message.updatedAt = new Date(now()).toISOString();
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        return structuredClone(message);
      });
    },
    async claimOutgoingForPreparation(clientMessageId, expectedIdentity) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      return mutate((store) => {
        const message = store.messages.find((item) => item.direction === "outgoing" && item.clientMessageId === acceptedId);
        if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
        if (message.senderPrincipalId !== expectedIdentity.senderPrincipalId || message.senderDelegateId !== expectedIdentity.senderDelegateId) {
          throw new HelloLynkLocalMessagingError("local_outgoing_identity_mismatch", { httpStatus: 409 });
        }
        if (!MANUAL_RETRYABLE_OUTGOING_STATUSES.has(message.status) || message.e2ee || message.attempts !== 0) {
          throw new HelloLynkLocalMessagingError("local_outgoing_message_not_retryable", { httpStatus: 409 });
        }
        if (!message.e2eePreparation) throw new HelloLynkLocalMessagingError("e2ee_preparation_context_missing", { httpStatus: 409 });
        message.status = "pending";
        message.nextRetryAt = null;
        message.lastErrorCode = null;
        message.deliveryAttemptPid = process.pid;
        message.deliveryAttemptInstance = PROCESS_INSTANCE_ID;
        message.deliveryAttemptStartedAt = new Date(now()).toISOString();
        message.updatedAt = message.deliveryAttemptStartedAt;
        return structuredClone(message);
      });
    },
    async claimOutgoingForAttempt(clientMessageId, expectedIdentity = {}) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      const expectedPrincipalId = safeId(expectedIdentity.senderPrincipalId, "sender_principal_id_invalid");
      const expectedDelegateId = safeId(expectedIdentity.senderDelegateId, "sender_delegate_id_invalid");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        let claimedFromArchive = false;
        let message = store.messages.find((item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ));
        if (!message) {
          const archived = await scanArchive(archivePath, profileId, null, protection);
          const archivedIndex = findLatestIndex(archived, (item) => (
            item.direction === "outgoing" && item.clientMessageId === acceptedId
          ));
          if (archivedIndex >= 0) {
            message = structuredClone(archived[archivedIndex]);
            claimedFromArchive = true;
          }
        }
        if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
        if (!message.senderPrincipalId || !message.senderDelegateId) {
          throw new HelloLynkLocalMessagingError("local_outgoing_identity_unbound", { httpStatus: 409 });
        }
        if (
          message.senderPrincipalId !== expectedPrincipalId ||
          message.senderDelegateId !== expectedDelegateId
        ) {
          throw new HelloLynkLocalMessagingError("local_outgoing_identity_mismatch", { httpStatus: 409 });
        }
        if (!CLAIMABLE_OUTGOING_STATUSES.has(message.status)) {
          throw new HelloLynkLocalMessagingError("local_outgoing_message_not_retryable", { httpStatus: 409 });
        }
        if (claimedFromArchive) store.messages.push(message);
        message.status = "delivery_state_unknown";
        message.attempts = Number(message.attempts || 0) + 1;
        message.lastErrorCode = "awaiting_relay_result";
        message.deliveryAttemptPid = process.pid;
        message.deliveryAttemptInstance = PROCESS_INSTANCE_ID;
        message.deliveryAttemptStartedAt = new Date(now()).toISOString();
        message.updatedAt = new Date(now()).toISOString();
        await compactFinalMessages({
          store,
          archivePath,
          profileId,
          triggerBytes: compactionTriggerBytes,
          targetBytes: compactionTargetBytes,
          protection,
        });
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        const latestArchived = await scanArchive(archivePath, profileId, null, protection);
        if (latestArchived.some((item) => (
          item.direction === "outgoing" &&
          item.clientMessageId === acceptedId &&
          item.localMessageId === message.localMessageId
        ))) {
          // The active unknown claim is durable first, so cleanup failure remains fail-closed before transport.
          await replaceArchiveMessages(
            archivePath,
            profileId,
            latestArchived.filter((item) => (
              item.direction !== "outgoing" ||
              item.clientMessageId !== acceptedId ||
              item.localMessageId !== message.localMessageId
            )),
            protection,
          );
        }
        return structuredClone(message);
      });
    },
    async recoverArchivedOutgoingRetryClaim(options = {}) {
      const acceptedId = safeId(options.clientMessageId, "client_message_id_invalid");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const active = store.messages.find((item) => (
          item.direction === "outgoing" &&
          item.clientMessageId === acceptedId &&
          (
            (item.status === "delivery_state_unknown" && item.lastErrorCode === "awaiting_relay_result") ||
            (
              item.status === "delivery_state_unconfirmed" &&
              item.lastErrorCode === "e2ee_delivery_attempt_interrupted"
            )
          )
        ));
        if (!active) return null;
        const activeUnknown = (
          active.status === "delivery_state_unknown" &&
          active.lastErrorCode === "awaiting_relay_result"
        );
        const interruptedUnconfirmed = (
          active.status === "delivery_state_unconfirmed" &&
          active.lastErrorCode === "e2ee_delivery_attempt_interrupted"
        );
        if (activeUnknown && deliveryAttemptHasLiveOwner(active)) return null;
        if (!activeUnknown && !interruptedUnconfirmed) return null;
        const archived = await scanArchive(archivePath, profileId, null, protection);
        const retainedIndex = findLatestIndex(archived, (item) => (
          item.direction === "outgoing" &&
          item.clientMessageId === acceptedId &&
          item.localMessageId === active.localMessageId
        ));
        const retainedPermanent = retainedIndex >= 0 ? archived[retainedIndex] : null;
        if (retainedPermanent?.status !== "failed_permanent") return null;
        store.messages = store.messages.filter((item) => !(
          item.direction === "outgoing" &&
          item.clientMessageId === acceptedId &&
          item.localMessageId === active.localMessageId
        ));
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        return structuredClone(retainedPermanent);
      });
    },
    async recoverAbandonedE2eeOutgoingAttempts(options = {}) {
      const clientMessageId = options.clientMessageId == null
        ? null
        : safeId(options.clientMessageId, "client_message_id_invalid");
      return mutate((store) => recoverAbandonedE2eeOutgoingAttempts(store, now, clientMessageId));
    },
    async addIncoming(event) {
      if (event?.targetConversationId != null) throw new HelloLynkLocalMessagingError("native_target_requires_indexed_store");
      if (event?.replyToClientMessageId != null) throw new HelloLynkLocalMessagingError("reply_correlation_requires_indexed_store");
      const eventId = safeId(event?.eventId, "relay_event_id_invalid");
      const clientMessageId = safeId(event?.clientMessageId, "client_message_id_invalid");
      const senderPrincipalId = safeId(event?.senderPrincipalId, "sender_principal_id_invalid");
      const senderDelegateId = safeId(event?.senderDelegateId, "sender_delegate_id_invalid");
      const provenance = normalizeMessageProvenance(
        event?.authorizationScope,
        event?.intentSource,
        {
          required: event?.envelopeDigest != null,
          code: "message_provenance_invalid",
        },
      );
      const senderHelloLynkId = event?.senderHelloLynkId == null
        ? null
        : safeId(event.senderHelloLynkId, "sender_hellolynk_id_invalid");
      const senderPrincipalDisplayName = optionalVerifiedDisplayName(
        event?.senderPrincipalDisplayName,
        "sender_principal_display_name_invalid",
      );
      const senderDelegateDisplayName = optionalVerifiedDisplayName(
        event?.senderDelegateDisplayName,
        "sender_delegate_display_name_invalid",
      );
      const text = safeText(event?.text);
      const envelopeDigest = event?.envelopeDigest == null
        ? null
        : safeSha256(event.envelopeDigest);
      const senderIdentityKeyId = event?.senderIdentityKeyId == null
        ? null
        : safeId(event.senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid");
      const recipientIdentityKeyId = event?.recipientIdentityKeyId == null
        ? null
        : safeId(event.recipientIdentityKeyId, "e2ee_recipient_identity_key_id_invalid");
      const conversationBinding = normalizeInstanceConversationBinding(event?.conversationBinding);
      if (conversationBinding) {
        if (!envelopeDigest) throw new HelloLynkLocalMessagingError("message_provenance_invalid");
        getMessageConversationBinding({
          ...event, direction: "incoming", conversationBinding, peerHelloLynkId: senderHelloLynkId,
        });
      }
      return mutate(async (store, archived) => {
        const index = await readHistory();
        const existing = [...index.deleted, ...store.messages, ...archived].find((item) => (
          item.direction === "incoming" && (
            item.eventId === eventId ||
            (item.peerPrincipalId === senderPrincipalId && item.clientMessageId === clientMessageId)
          )
        ));
        if (existing) {
          if (existing.messageType === LOCAL_DELETED_MESSAGE_TYPE) {
            if (existing.direction !== "incoming" || existing.clientMessageId !== clientMessageId
              || existing.peerPrincipalId !== senderPrincipalId || existing.senderDelegateId !== senderDelegateId
              || (existing.peerHelloLynkId || null) !== senderHelloLynkId
              || (existing.envelopeDigest || null) !== envelopeDigest
              || (existing.senderIdentityKeyId || null) !== senderIdentityKeyId
              || (existing.recipientIdentityKeyId || null) !== recipientIdentityKeyId
              || !existing.conversationBinding || !conversationBinding
              || instanceConversationKey(existing.conversationBinding) !== instanceConversationKey(conversationBinding)) {
              throw new HelloLynkLocalMessagingError("local_incoming_message_conflict", { httpStatus: 409 });
            }
            return { message: structuredClone(existing), duplicate: true };
          }
          const legacyProvenanceMissing = !Object.hasOwn(existing, "senderPrincipalId")
            && !Object.hasOwn(existing, "authorizationScope")
            && !Object.hasOwn(existing, "intentSource");
          const exactReplay = (
            existing.clientMessageId === clientMessageId &&
            existing.peerPrincipalId === senderPrincipalId &&
            existing.senderDelegateId === senderDelegateId &&
            (existing.peerHelloLynkId || null) === senderHelloLynkId &&
            existing.messageType === "text" &&
            existing.text === text &&
            (existing.envelopeDigest || null) === envelopeDigest &&
            (existing.senderIdentityKeyId || null) === senderIdentityKeyId &&
            (existing.recipientIdentityKeyId || null) === recipientIdentityKeyId &&
            ((!existing.conversationBinding)
              || (existing.conversationBinding && conversationBinding
                && instanceConversationKey(existing.conversationBinding) === instanceConversationKey(conversationBinding))) &&
            (legacyProvenanceMissing || (
              existing.senderPrincipalId === senderPrincipalId
              && (existing.authorizationScope ?? null) === provenance.authorizationScope
              && (existing.intentSource ?? null) === provenance.intentSource
            ))
          );
          if (!exactReplay) {
            throw new HelloLynkLocalMessagingError("local_incoming_message_conflict", { httpStatus: 409 });
          }
          return { message: structuredClone(existing), duplicate: true };
        }
        const highWater = store.receiptHighWater ?? 0;
        if ([...archived, ...index.deleted].some((item) => item.receiptSeq > highWater)
          || highWater >= Number.MAX_SAFE_INTEGER) {
          throw new HelloLynkLocalMessagingError("local_message_receipt_sequence_invalid");
        }
        const receiptSeq = highWater + 1;
        store.receiptHighWater = receiptSeq;
        const at = new Date(now()).toISOString();
        const message = {
          localMessageId: `local_message_${crypto.randomUUID()}`,
          eventId,
          receiptSeq,
          clientMessageId,
          direction: "incoming",
          peerPrincipalId: senderPrincipalId,
          peerHelloLynkId: senderHelloLynkId,
          senderPrincipalId,
          senderDelegateId,
          authorizationScope: provenance.authorizationScope,
          intentSource: provenance.intentSource,
          senderPrincipalDisplayName,
          senderDelegateDisplayName,
          messageType: "text",
          text,
          transportSecurity: envelopeDigest ? E2EE_TRANSPORT_SECURITY : "plaintext-v0.1.0",
          envelopeDigest,
          senderIdentityKeyId,
          recipientIdentityKeyId,
          conversationBinding,
          status: "received",
          attempts: 0,
          nextRetryAt: null,
          lastErrorCode: null,
          createdAt: at,
          updatedAt: at,
        };
        store.messages.push(message);
        return { message: structuredClone(message), duplicate: false };
      }, { scanArchive: true });
    },
    async findIncomingE2eeReplay({ senderIdentityKeyId, clientMessageId, envelopeDigest }) {
      const acceptedSenderKeyId = safeId(senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid");
      const acceptedClientMessageId = safeId(clientMessageId, "client_message_id_invalid");
      const acceptedDigest = safeSha256(envelopeDigest);
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const archived = await scanArchive(archivePath, profileId, null, protection);
        const index = await readHistory();
        const existing = [...index.deleted, ...store.messages, ...archived].find((item) => (
          item.direction === "incoming" &&
          item.senderIdentityKeyId === acceptedSenderKeyId &&
          item.clientMessageId === acceptedClientMessageId
        ));
        if (!existing) return null;
        if (existing.envelopeDigest !== acceptedDigest) {
          throw new HelloLynkLocalMessagingError("e2ee_message_conflict", { httpStatus: 409 });
        }
        return structuredClone(existing);
      });
    },
    async getOutgoing(clientMessageId) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const index = await readHistory();
        const message = [...index.deleted, ...store.messages].find((item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ));
        if (message) return structuredClone(message);
        return scanArchive(archivePath, profileId, (item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ), protection);
      });
    },
    async updateIncoming(localMessageId, patch) {
      const acceptedId = safeId(localMessageId, "local_message_id_invalid");
      return mutate((store) => {
        const message = store.messages.find((item) => (
          item.direction === "incoming" && item.localMessageId === acceptedId
        ));
        if (!message) throw new HelloLynkLocalMessagingError("local_incoming_message_not_found");
        if (message.messageType === LOCAL_DELETED_MESSAGE_TYPE) throw localHistoryFailure("record_not_found");
        const nextStatus = String(patch.status || message.status);
        message.status = nextStatus;
        if (nextStatus === "failed_retryable") {
          message.attempts = Number(message.attempts || 0) + 1;
          const retryDelayMs = Math.min(1_000 * (2 ** Math.min(message.attempts - 1, 6)), 60_000);
          message.nextRetryAt = new Date(now() + retryDelayMs).toISOString();
          message.lastErrorCode = patch.lastErrorCode == null
            ? "inbound_projection_failed"
            : String(patch.lastErrorCode);
        } else if (["fetched", "pending_human_confirmation"].includes(nextStatus)) {
          message.nextRetryAt = null;
          message.lastErrorCode = null;
        }
        message.updatedAt = new Date(now()).toISOString();
        return structuredClone(message);
      });
    },
    async deleteIncoming(localMessageIds) {
      const acceptedIds = [...new Set(
        (Array.isArray(localMessageIds) ? localMessageIds : [])
          .map((item) => safeId(item, "local_message_id_invalid")),
      )];
      if (acceptedIds.length === 0) {
        throw new HelloLynkLocalMessagingError("local_message_ids_required");
      }
      if (acceptedIds.length > 500) {
        throw new HelloLynkLocalMessagingError("local_message_delete_capacity_exceeded");
      }
      return mutate(async (store, archived) => {
        const requested = new Set(acceptedIds);
        if ([...store.messages, ...archived].some((item) => requested.has(item.localMessageId) && localHistoryUnread(item))) {
          throw new HelloLynkLocalMessagingError("local_incoming_message_not_deletable", { httpStatus: 409 });
        }
        const deletedIds = [...new Set(
          [...store.messages, ...archived]
            .filter((item) => item.direction === "incoming" && item.messageType !== LOCAL_DELETED_MESSAGE_TYPE && requested.has(item.localMessageId))
            .map((item) => item.localMessageId),
        )];
        const deleted = new Set(deletedIds);
        const index = await readHistory();
        const tombstones = new Map(index.deleted.map((item) => [item.localMessageId, item]));
        for (const message of [...store.messages, ...archived]) {
          if (!deleted.has(message.localMessageId) || !message.conversationBinding) continue;
          const binding = message.conversationBinding;
          tombstones.set(message.localMessageId, localHistoryTombstone(message, {
            region: binding.region, principalId: binding.localPrincipalId, delegateId: binding.localDelegateId,
          }));
        }
        if (tombstones.size !== index.deleted.length) {
          index.deleted = [...tombstones.values()];
          index.cleanupPending = true;
          // Preserve the receipt identity before removing the body, so replay
          // after deletion cannot become a fresh automatic wake.
          await writeHistory(index);
        }
        store.messages = store.messages.filter((item) => (
          item.direction !== "incoming" || !deleted.has(item.localMessageId)
        ));
        if (archived.some((item) => (
          item.direction === "incoming" && deleted.has(item.localMessageId)
        ))) {
          await replaceArchiveMessages(
            archivePath,
            profileId,
            archived.filter((item) => (
              item.direction !== "incoming" || !deleted.has(item.localMessageId)
            )),
            protection,
          );
        }
        return {
          requested: acceptedIds.length,
          deleted: deletedIds.length,
          deletedIds: structuredClone(deletedIds),
        };
      }, { scanArchive: true });
    },
    async deleteOutgoing(clientMessageIds) {
      const acceptedIds = [...new Set(
        (Array.isArray(clientMessageIds) ? clientMessageIds : [])
          .map((item) => safeId(item, "client_message_id_invalid")),
      )];
      if (acceptedIds.length === 0) {
        throw new HelloLynkLocalMessagingError("client_message_ids_required");
      }
      if (acceptedIds.length > 500) {
        throw new HelloLynkLocalMessagingError("local_message_delete_capacity_exceeded");
      }
      return mutate(async (store, archived) => {
        const requested = new Set(acceptedIds);
        const selected = [...store.messages, ...archived].filter((item) => (
          item.direction === "outgoing" && requested.has(item.clientMessageId)
        ));
        if (selected.some((item) => item.messageType === LOCAL_DELETED_MESSAGE_TYPE || !DELETABLE_OUTGOING_STATUSES.has(item.status))) {
          throw new HelloLynkLocalMessagingError("local_outgoing_message_not_deletable", { httpStatus: 409 });
        }
        const deletedIds = [...new Set(selected.map((item) => item.clientMessageId))];
        const deleted = new Set(deletedIds);
        store.messages = store.messages.filter((item) => (
          item.direction !== "outgoing" || !deleted.has(item.clientMessageId)
        ));
        if (archived.some((item) => (
          item.direction === "outgoing" && deleted.has(item.clientMessageId)
        ))) {
          await replaceArchiveMessages(
            archivePath,
            profileId,
            archived.filter((item) => (
              item.direction !== "outgoing" || !deleted.has(item.clientMessageId)
            )),
            protection,
          );
        }
        return {
          requested: acceptedIds.length,
          deleted: deletedIds.length,
          deletedIds: structuredClone(deletedIds),
        };
      }, { scanArchive: true });
    },
    async cancelOutgoing(clientMessageId) {
      const acceptedId = safeId(clientMessageId, "client_message_id_invalid");
      return mutate((store) => {
        const message = store.messages.find((item) => (
          item.direction === "outgoing" && item.clientMessageId === acceptedId
        ));
        if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
        if (!["pending", "recipient_offline", "failed_retryable"].includes(message.status)) {
          throw new HelloLynkLocalMessagingError("local_outgoing_message_not_cancellable", { httpStatus: 409 });
        }
        message.status = "cancelled";
        message.lastErrorCode = null;
        message.nextRetryAt = null;
        message.deliveryAttemptPid = null;
        message.deliveryAttemptInstance = null;
        message.deliveryAttemptStartedAt = null;
        message.updatedAt = new Date(now()).toISOString();
        return structuredClone(message);
      });
    },
    async list() {
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const archived = await scanArchive(archivePath, profileId, null, protection);
        return structuredClone(mergeMessageCopies(store, archived).filter((item) => item.messageType !== LOCAL_DELETED_MESSAGE_TYPE));
      });
    },
    async listActive() {
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        return structuredClone(store.messages.filter((item) => item.messageType !== LOCAL_DELETED_MESSAGE_TYPE));
      });
    },
    async getIncoming(localMessageId) {
      const acceptedId = safeId(localMessageId, "local_message_id_invalid");
      return withPathMutationQueue(storePath, async () => {
        const store = await readCurrentStore();
        const index = await readHistory();
        const message = [...index.deleted, ...store.messages].find((item) => (
          item.direction === "incoming" && item.localMessageId === acceptedId
        ));
        if (message) return structuredClone(message);
        return scanArchive(archivePath, profileId, (item) => (
          item.direction === "incoming" && item.localMessageId === acceptedId
        ), protection);
      });
    },
    async listPending() {
      return mutate((store) => {
        recoverAbandonedE2eeOutgoingAttempts(store, now);
        return structuredClone(store.messages.filter((item) => (
          item.direction === "outgoing" &&
          BACKGROUND_RETRYABLE_OUTGOING_STATUSES.has(item.status)
        )));
      });
    },
  };

  async function inboxClaimMutation(input, authorize, finish) {
    const fields = ["adapterId", "conversationKey", "delegateId", "localMessageId",
      ...(finish ? ["claimId", "outcome"] : [])].sort();
    if (!hasExactFields(input, fields) || typeof authorize !== "function") {
      throw new HelloLynkLocalMessagingError("local_inbox_claim_invalid");
    }
    for (const key of ["adapterId", "conversationKey", "delegateId", "localMessageId"]) inboxReaderId(input[key]);
    if (finish && (!/^inclaim_[a-f0-9]{48}$/.test(input.claimId) || !["completed", "unknown"].includes(input.outcome))) {
      throw new HelloLynkLocalMessagingError("local_inbox_claim_invalid");
    }
    return withPathMutationQueue(storePath, async () => {
      const store = await readAdmissionStore();
      const boundary = store.inboxReaders?.find((item) => item.adapterId === input.adapterId && item.delegateId === input.delegateId)?.afterSeq;
      const message = store.messages.find((item) => item.localMessageId === input.localMessageId)
        || await scanArchive(archivePath, profileId, (item) => item.localMessageId === input.localMessageId, protection);
      const binding = message && getMessageConversationBinding(message);
      if (!message || message.direction !== "incoming" || message.messageType === LOCAL_DELETED_MESSAGE_TYPE
        || !binding || binding.localDelegateId !== input.delegateId || instanceConversationKey(binding) !== input.conversationKey
        || !Number.isSafeInteger(boundary) || !Number.isSafeInteger(message.receiptSeq) || message.receiptSeq <= boundary) {
        throw new HelloLynkLocalMessagingError("local_inbox_claim_ineligible");
      }
      // This callback must not acquire the message store lock recursively. It
      // checks current capability and read permission against this snapshot.
      await authorize(structuredClone(message), boundary, store.receiptHighWater);
      const existing = store.inboxClaims?.find((item) => item.delegateId === input.delegateId && item.localMessageId === input.localMessageId);
      if (finish) {
        if (!existing || existing.adapterId !== input.adapterId || existing.claimId !== input.claimId
          || existing.conversationKey !== input.conversationKey || existing.receiptSeq !== message.receiptSeq) {
          throw new HelloLynkLocalMessagingError("local_inbox_claim_mismatch");
        }
        if (existing.outcome !== "inflight" && existing.outcome !== input.outcome) {
          throw new HelloLynkLocalMessagingError("local_inbox_claim_terminal");
        }
        existing.outcome = input.outcome;
        await atomicWriteStore(storePath, store, maximumBytes, protection);
        await authorize(structuredClone(message), boundary, store.receiptHighWater);
        return { claimId: existing.claimId, outcome: existing.outcome };
      }
      // Every persisted state is terminal for automatic admission, including a
      // crash leaving inflight. Never expire, reset, prune or replay a claim.
      if (existing) return { claimed: false, claimId: null, message: null };
      const claim = { ...input, claimId: `inclaim_${crypto.randomBytes(24).toString("hex")}`,
        receiptSeq: message.receiptSeq, outcome: "inflight" };
      store.inboxClaims = [...(store.inboxClaims || []), claim];
      await atomicWriteStore(storePath, store, maximumBytes, protection);
      // If permission changed while committing, withhold the body and retain
      // inflight. A lost response is uncertain, never permission to retry.
      const projected = await authorize(structuredClone(message), boundary, store.receiptHighWater);
      return { claimed: true, claimId: claim.claimId, message: projected };
    });
  }
}

// The caller holds the local mutation lock for the full iteration. Each
// archive record is bounded before decoding, so migration never materializes
// the complete (potentially unbounded) archive in memory.
export async function* streamLegacyLocalMessages(options = {}) {
  const profileId = safeId(options.profileId, "local_message_profile_id_invalid");
  const storePath = String(options.storePath || "").trim();
  if (!storePath) throw new HelloLynkLocalMessagingError("local_message_store_path_required");
  const archivePath = `${storePath}.archive.ndjson`;
  const protection = normalizeMessageDataProtection(options.dataProtector, profileId);
  const legacy = createLocalMessageStore({ storePath, profileId, dataProtector: options.dataProtector });
  const store = await readStore(storePath, profileId, MAX_STORE_BYTES, protection);
  const history = await legacy.readLegacyHistoryForMigration();
  yield {
    kind: "metadata",
    store: {
      ...(Object.hasOwn(store, "receiptHighWater") ? { receiptHighWater: store.receiptHighWater } : {}),
      ...(Object.hasOwn(store, "inboxReaders") ? { inboxReaders: store.inboxReaders } : {}),
      ...(Object.hasOwn(store, "inboxClaims") ? { inboxClaims: store.inboxClaims } : {}),
    },
    history: { cleanupPending: history.cleanupPending, hidden: history.hidden },
  };

  await assertMessageStoreAccess(archivePath, protection, { create: false });
  let metadata;
  try { metadata = await lstat(archivePath); }
  catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (metadata) {
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
    }
    await recoverInterruptedArchiveTail(archivePath, profileId, protection);
    await assertMessageStoreAccess(archivePath, protection, { create: false });
    metadata = await lstat(archivePath);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
    }
    const handle = await open(archivePath, "r");
    const maximumRecordBytes = protection ? MAX_PROTECTED_ARCHIVE_RECORD_BYTES : MAX_ARCHIVE_RECORD_BYTES;
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || (process.platform !== "win32" && opened.dev !== metadata.dev) || opened.ino !== metadata.ino) {
        throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
      }
      let pending = Buffer.alloc(0);
      for await (const chunk of handle.createReadStream({ highWaterMark: 64 * 1024, autoClose: false })) {
        let start = 0;
        for (let newline = chunk.indexOf(0x0a, start); newline >= 0; newline = chunk.indexOf(0x0a, start)) {
          const fragment = chunk.subarray(start, newline);
          if (pending.length + fragment.length > maximumRecordBytes) {
            throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
          }
          const line = pending.length ? Buffer.concat([pending, fragment]) : fragment;
          if (line.length) yield { kind: "message", source: "archive",
            message: await parseArchiveEnvelope(line.toString("utf8"), profileId, protection) };
          pending = Buffer.alloc(0);
          start = newline + 1;
        }
        if (start < chunk.length) {
          const fragment = chunk.subarray(start);
          if (pending.length + fragment.length > maximumRecordBytes) {
            throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
          }
          pending = pending.length ? Buffer.concat([pending, fragment]) : Buffer.from(fragment);
        }
      }
      if (pending.length) {
        throw new HelloLynkLocalMessagingError("local_message_archive_invalid");
      }
    } finally {
      await handle.close();
    }
  }

  for (const message of store.messages) yield { kind: "message", source: "main", message };
  for (const message of history.deleted) yield { kind: "message", source: "deleted", message };
}

export const indexedMessageStoreLegacyInternals = Object.freeze({
  safeId,
  safeText,
  inboxReaderId,
  normalizeStoredE2ee,
  provenanceFromStoredE2ee,
  normalizeMessageProvenance,
  optionalVerifiedDisplayName,
  validateCurrentMessage,
  localHistoryScope,
  localHistoryScopeKey,
  localHistoryBinding,
  localHistoryThreadId,
  localHistoryUnread,
  localHistorySent,
  localHistoryTombstone,
  localHistoryFailure,
  normalizeMessageDataProtection,
  readStore,
  assertMessageStoreAccess,
  syncParentDirectory,
  recoverInterruptedArchiveTail,
  parseArchiveEnvelope,
  withPathMutationQueue,
  recoverAbandonedE2eeOutgoingAttempts,
  deliveryAttemptHasLiveOwner,
  normalizeOutgoingRoute,
  safeSha256,
  PROCESS_INSTANCE_ID,
  MAX_STORE_BYTES,
  MAX_LOCAL_HISTORY_BYTES,
  MAX_ARCHIVE_RECORD_BYTES,
  MAX_PROTECTED_ARCHIVE_RECORD_BYTES,
  LOCAL_HISTORY_CONTRACT,
  LOCAL_DELETED_MESSAGE_TYPE,
  E2EE_DIRECT_TEXT_VERSION,
  E2EE_TRANSPORT_SECURITY,
  ARCHIVABLE_OUTGOING_STATUSES,
  ARCHIVABLE_INCOMING_STATUSES,
  DELETABLE_OUTGOING_STATUSES,
  MANUAL_RETRYABLE_OUTGOING_STATUSES,
  BACKGROUND_RETRYABLE_OUTGOING_STATUSES,
  CLAIMABLE_OUTGOING_STATUSES,
});

function runtimeHeaders(session) {
  const sessionId = safeId(session?.sessionId || session?.id, "runtime_session_id_invalid");
  const sessionSecret = String(session?.sessionSecret || session?.secret || "");
  if (!/^runtime_[a-f0-9]{48}$/.test(sessionSecret)) {
    throw new HelloLynkLocalMessagingError("runtime_session_secret_invalid");
  }
  return {
    "x-hellolynk-runtime-session-id": sessionId,
    "x-hellolynk-runtime-session-secret": sessionSecret,
  };
}

function parseSseBlock(block) {
  let event = "message";
  const data = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith(":")) continue;
    if (line.startsWith("event:")) event = line.slice(6).trim();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (data.length === 0) return null;
  try {
    return { event, data: JSON.parse(data.join("\n")) };
  } catch {
    throw new HelloLynkLocalMessagingError("relay_event_invalid_json");
  }
}

export function createOnlineRelayTransport(options = {}) {
  const baseUrl = normalizeHelloLynkBaseUrl(options.baseUrl, {
    allowLoopbackHttp: options.allowLoopbackHttp === true,
  });
  const fetchImpl = options.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  const sessionProvider = options.sessionProvider;
  const abortSignal = options.abortSignal;
  if (typeof fetchImpl !== "function") throw new HelloLynkLocalMessagingError("fetch_unavailable");
  if (!sessionProvider || typeof sessionProvider.get !== "function") {
    throw new HelloLynkLocalMessagingError("runtime_session_provider_required");
  }

  async function sendText(input) {
    const session = await sessionProvider.get();
    const e2ee = normalizeStoredE2ee(input.e2ee);
    const body = e2ee ? {
      ...(e2ee.version === "2" ? {
        routeKind: e2ee.routeKind,
        recipientDelegateId: e2ee.recipientDelegateId,
        recipientHostId: e2ee.recipientHostId,
        recipientDeviceId: e2ee.recipientDeviceId,
        ...(e2ee.nativeContentVersion === 1 ? { nativeContentVersion: 1 } : {}),
      } : {}),
      recipientHelloLynkId: safeId(input.recipientHelloLynkId, "recipient_hellolynk_id_invalid"),
      clientMessageId: safeId(input.clientMessageId, "client_message_id_invalid"),
      messageType: "text",
      claimId: e2ee.claimId,
      envelopeDigest: e2ee.envelopeDigest,
      e2eeEnvelope: e2ee.envelope,
    } : {
      recipientHelloLynkId: safeId(input.recipientHelloLynkId, "recipient_hellolynk_id_invalid"),
      clientMessageId: safeId(input.clientMessageId, "client_message_id_invalid"),
      messageType: "text",
      text: safeText(input.text),
    };
    const headers = runtimeHeaders(session);
    let response;
    try {
      response = await fetchImpl(`${baseUrl}/api/${e2ee?.version === "2" ? "v2" : "v1"}/relay/messages`, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-hellolynk-relay-contract": RECEIVER_LOCAL_STORE_CONTRACT,
          ...(e2ee ? { "x-hellolynk-e2ee-version": e2ee.version } : {}),
          ...headers,
        },
        body: JSON.stringify(body),
        signal: input.signal || abortSignal,
        redirect: "error",
      });
    } catch (error) {
      throw new HelloLynkLocalMessagingError("relay_transport_error", { cause: error, retryable: true });
    }
    // The edge rejects oversized requests before forwarding, and may return
    // HTML rather than JSON. This status is a definite rejection, not unknown.
    if (response.status === 413) throw new HelloLynkLocalMessagingError("relay_request_body_too_large", { httpStatus: 413 });
    const raw = await readBoundedText(response);
    let data;
    try {
      // An HTTP status with a missing body cannot prove whether relay dispatch
      // happened. Keep it unconfirmed just like other invalid JSON responses.
      data = JSON.parse(raw);
    } catch {
      throw new HelloLynkLocalMessagingError("relay_response_invalid_json");
    }
    if (response.status === 200 && data?.status === "acknowledged_by_recipient_local_store") return data;
    const explicitRelayStatus = String(data?.status || data?.error || "");
    if (e2ee?.nativeContentVersion === 1 && (
      (response.status === 409 && explicitRelayStatus === "native_directory_unavailable")
      || (response.status === 400 && explicitRelayStatus === "e2ee_v2_relay_message_fields_invalid")
    )) throw new HelloLynkLocalMessagingError("native_directory_unavailable", { httpStatus: response.status });
    if (response.status >= 400 && [
      "recipient_offline",
      "relay_unavailable",
      "recipient_ack_capability_unavailable",
      "recipient_e2ee_device_offline",
      "recipient_e2ee_ack_capability_unavailable",
      "receiver_ack_timeout",
      "recipient_disconnected_before_ack",
      "relay_service_stopped_before_ack",
      "relay_ack_capacity_exhausted",
      "delivery_unconfirmed",
      "reply_target_deleted",
    ].includes(explicitRelayStatus)) return { ...data, status: explicitRelayStatus };
    const status = Number(response.status);
    throw new HelloLynkLocalMessagingError(
      publicRemoteCode(data?.error, `relay_http_${status}`),
      { httpStatus: status, retryable: RETRYABLE_STATUSES.has(status) || status >= 500 },
    );
  }

  async function openEventStream() {
    const session = await sessionProvider.get();
    const headers = runtimeHeaders(session);
    const controller = new AbortController();
    const abortFromLifecycle = () => controller.abort(abortSignal?.reason);
    if (abortSignal?.aborted) abortFromLifecycle();
    else abortSignal?.addEventListener?.("abort", abortFromLifecycle, { once: true });
    const releaseLifecycleAbort = () => abortSignal?.removeEventListener?.("abort", abortFromLifecycle);
    let response;
    try {
      const receiveVersion = String(options.e2eeReceiver?.version || E2EE_DIRECT_TEXT_VERSION);
      response = await fetchImpl(`${baseUrl}/api/${receiveVersion === "2" ? "v2" : "v1"}/relay/events`, {
        headers: {
          accept: "text/event-stream",
          "x-hellolynk-relay-receipt-version": RECEIVER_RECEIPT_VERSION,
          ...(options.e2eeReceiver?.identityKeyId ? {
            "x-hellolynk-e2ee-receive-version": receiveVersion,
            "x-hellolynk-e2ee-identity-key-id": safeId(
              options.e2eeReceiver.identityKeyId,
              "e2ee_recipient_identity_key_id_invalid",
            ),
          } : {}),
          ...headers,
        },
        signal: controller.signal,
        redirect: "error",
      });
    } catch (error) {
      releaseLifecycleAbort();
      throw new HelloLynkLocalMessagingError("relay_transport_error", { cause: error, retryable: true });
    }
    if (response.status !== 200 || !String(response.headers.get("content-type") || "").startsWith("text/event-stream")) {
      const raw = await readBoundedText(response).catch(() => "");
      let data = null;
      try { data = raw ? JSON.parse(raw) : null; } catch { /* 使用统一安全错误码。 */ }
      releaseLifecycleAbort();
      controller.abort();
      throw new HelloLynkLocalMessagingError(
        publicRemoteCode(data?.error, `relay_http_${response.status}`),
        { httpStatus: response.status, retryable: RETRYABLE_STATUSES.has(response.status) || response.status >= 500 },
      );
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    async function nextEvent() {
      while (true) {
        const boundary = buffer.indexOf("\n\n");
        if (boundary >= 0) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const event = parseSseBlock(block);
          if (event) return event;
          continue;
        }
        const result = await reader.read();
        if (result.done) throw new HelloLynkLocalMessagingError("relay_event_stream_closed", { retryable: true });
        buffer += decoder.decode(result.value, { stream: true }).replace(/\r\n/g, "\n");
        if (Buffer.byteLength(buffer, "utf8") > MAX_SSE_BUFFER_BYTES) {
          controller.abort();
          await reader.cancel().catch(() => {});
          throw new HelloLynkLocalMessagingError("relay_event_too_large");
        }
      }
    }

    async function acknowledgePersisted(input) {
      const version = String(input?.e2eeVersion || E2EE_DIRECT_TEXT_VERSION);
      const body = {
        deliveryAttemptId: safeId(input?.deliveryAttemptId, "relay_delivery_attempt_id_invalid"),
        eventId: safeId(input?.eventId, "relay_event_id_invalid"),
        clientMessageId: safeId(input?.clientMessageId, "client_message_id_invalid"),
        connectionId: safeId(input?.connectionId, "relay_connection_id_invalid"),
        state: version === "2" && input.replyTargetDeleted === true ? "reply_target_deleted" : "persisted_local",
        ...(input?.envelopeDigest ? {
          envelopeDigest: safeSha256(input.envelopeDigest),
        } : {}),
        ...(version === "2" ? {
          e2eeVersion: 2,
          routeKind: input.routeKind,
          recipientDelegateId: input.recipientDelegateId,
          recipientDelegateAuthorizationVersion: input.recipientDelegateAuthorizationVersion,
          recipientHostId: input.recipientHostId,
          recipientRouteVersion: input.recipientRouteVersion,
          recipientDeviceId: input.recipientDeviceId,
          recipientIdentityKeyId: input.recipientIdentityKeyId,
          recipientPreKeyId: input.recipientPreKeyId,
        } : {}),
      };
      let ackResponse;
      try {
        ackResponse = await fetchImpl(`${baseUrl}/api/${version === "2" ? "v2" : "v1"}/relay/acks`, {
          method: "POST",
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            ...headers,
          },
          body: JSON.stringify(body),
          redirect: "error",
        });
      } catch (error) {
        throw new HelloLynkLocalMessagingError("relay_ack_transport_error", { cause: error, retryable: true });
      }
      const raw = await readBoundedText(ackResponse);
      let data;
      try {
        data = raw ? JSON.parse(raw) : {};
      } catch {
        throw new HelloLynkLocalMessagingError("relay_ack_response_invalid_json", { retryable: true });
      }
      if (
        ackResponse.status === 200 &&
        (data?.status === (body.state === "reply_target_deleted" ? "reply_target_deleted" : "acknowledged_by_recipient_local_store")
          || (body.state === "persisted_local" && data?.status === "recipient_local_store_persisted"))
      ) return data;
      const status = Number(ackResponse.status);
      throw new HelloLynkLocalMessagingError(
        publicRemoteCode(data?.error, `relay_ack_http_${status}`),
        { httpStatus: status, retryable: status === 404 || RETRYABLE_STATUSES.has(status) || status >= 500 },
      );
    }

    return {
      nextEvent,
      acknowledgePersisted,
      async close() {
        releaseLifecycleAbort();
        controller.abort();
        await reader.cancel().catch(() => {});
      },
    };
  }

  return { sendText, openEventStream };
}

export function createLocalMessenger(options = {}) {
  const principalId = safeId(options.principalId, "local_principal_id_invalid");
  const delegateId = safeId(options.delegateId, "local_delegate_id_invalid");
  const e2ee = options.e2ee || null;
  const e2eeMode = String(options.e2eeMode || e2ee?.mode || (e2ee ? "transition" : "disabled"));
  if (!new Set(["disabled", "transition", "required"]).has(e2eeMode)) {
    throw new HelloLynkLocalMessagingError("e2ee_mode_invalid");
  }
  if (e2eeMode === "required" && !e2ee) {
    throw new HelloLynkLocalMessagingError("e2ee_context_required");
  }
  const e2eeIdentityKeyId = e2ee
    ? safeId(e2ee.identityKeyId, "e2ee_identity_key_id_invalid")
    : null;
  const e2eeVersion = String(e2ee?.version || "1");
  const durableBeforeEncryption = options.durableBeforeEncryption === true;
  if (e2ee && (
    typeof e2ee.prepareOutgoing !== "function" ||
    (e2ee.listPreparedOutgoing != null && typeof e2ee.listPreparedOutgoing !== "function") ||
    (e2ee.commitOutgoing != null && typeof e2ee.commitOutgoing !== "function") ||
    (e2ee.ensurePreKeyInventory != null && typeof e2ee.ensurePreKeyInventory !== "function") ||
    (e2ee.replenishPreKeyInventory != null && typeof e2ee.replenishPreKeyInventory !== "function") ||
    typeof e2ee.openIncoming !== "function" ||
    (e2ee.commitIncomingReplay != null && typeof e2ee.commitIncomingReplay !== "function")
  )) throw new HelloLynkLocalMessagingError("e2ee_context_invalid");
  const store = options.store || createLocalMessageStore({
    profileId: options.profileId,
    storePath: options.storePath,
    now: options.now,
  });
  const transport = options.transport || createOnlineRelayTransport({
    ...options,
    e2eeReceiver: e2ee ? { identityKeyId: e2eeIdentityKeyId, version: e2eeVersion } : null,
  });

  let cancelledPreparationRecoveryPending = true;
  async function recoverCancelledPreparations(clientMessageId = null) {
    if (!durableBeforeEncryption || typeof e2ee?.listPreparedOutgoing !== "function"
      || typeof e2ee?.commitOutgoing !== "function") return;
    if (clientMessageId == null) cancelledPreparationRecoveryPending = false;
    try {
      const prepared = await e2ee.listPreparedOutgoing();
      for (const entry of prepared) {
        if (clientMessageId != null && entry.clientMessageId !== clientMessageId) continue;
        const saved = await store.getOutgoing(entry.clientMessageId);
        // Cancellation is terminal, including in a body-deleted tombstone.
        // Missing, retryable and unknown records are not cancellation evidence.
        if (saved?.direction !== "outgoing" || saved.status !== "cancelled"
          || saved.senderPrincipalId !== principalId || saved.senderDelegateId !== delegateId
          || saved.peerHelloLynkId !== entry.recipientHelloLynkId) continue;
        await e2ee.commitOutgoing(entry);
      }
    } catch {
      // Cancellation has already committed. A cleanup failure must neither
      // undo it nor resend; retry cleanup before the next preparation/restart.
      cancelledPreparationRecoveryPending = true;
    }
  }

  async function prepare(message, preparation, signal) {
    throwIfAborted(signal);
    if (cancelledPreparationRecoveryPending) await recoverCancelledPreparations();
    throwIfAborted(signal);
    const sealed = normalizeStoredE2ee(await e2ee.prepareOutgoing({
      recipientHelloLynkId: message.peerHelloLynkId,
      text: message.text,
      clientMessageId: message.clientMessageId,
      senderPrincipalId: principalId,
      senderDelegateId: delegateId,
      intentSource: preparation.intentSource,
      ...(message.replyToClientMessageId ? { replyToClientMessageId: message.replyToClientMessageId } : {}),
      ...(message.targetConversationId ? { targetConversationId: message.targetConversationId } : {}),
      ...(normalizeOutgoingRoute(preparation.route, e2ee.version) || {}),
    }, { signal, persistPrepared: !durableBeforeEncryption }));
    throwIfAborted(signal);
    if (!sealed) throw new HelloLynkLocalMessagingError("e2ee_required", { httpStatus: 426 });
    return sealed;
  }

  async function attempt(clientMessageId, context = {}) {
    const pending = await store.getOutgoing(clientMessageId);
    if (!pending) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
    if (pending.targetConversationTitle) safeId(context.friendTargetConnectionId, "native_target_not_authorized");
    if ((e2eeMode === "required" || pending.e2eePreparation != null) && !pending.e2ee) {
      await store.updateOutgoing(clientMessageId, {
        status: pending.e2eePreparation != null ? "failed_retryable" : "failed_permanent",
        lastErrorCode: "e2ee_required",
        incrementAttempts: false,
      });
      throw new HelloLynkLocalMessagingError("e2ee_required", { httpStatus: 426 });
    }
    const message = await store.claimOutgoingForAttempt(clientMessageId, {
      senderPrincipalId: principalId,
      senderDelegateId: delegateId,
    });
    const relayMessage = {
      recipientHelloLynkId: message.recipientHelloLynkId || message.peerHelloLynkId,
      clientMessageId: message.clientMessageId,
      text: message.text,
      e2ee: message.e2ee || null,
      signal: context.signal,
    };
    try {
      throwIfAborted(context.signal);
      if (message.e2ee && typeof e2ee?.commitOutgoing === "function") {
        await e2ee.commitOutgoing({
          clientMessageId: message.clientMessageId,
          recipientHelloLynkId: message.recipientHelloLynkId || message.peerHelloLynkId,
          envelopeDigest: message.e2ee.envelopeDigest,
        });
      }
      throwIfAborted(context.signal);
    } catch (error) {
      // No transport call has started. Release only our exact durable claim;
      // if that state cannot be persisted, leave it frozen rather than resend.
      await store.updateOutgoing(message.clientMessageId, {
        status: "failed_retryable", lastErrorCode: safeLocalErrorCode(error), incrementAttempts: false,
        beforeTransportClaim: { attempts: message.attempts, startedAt: message.deliveryAttemptStartedAt },
      }).catch(() => {});
      throw error;
    }
    let result;
    try {
      result = await transport.sendText(relayMessage);
    } catch (error) {
      const accepted = error instanceof HelloLynkLocalMessagingError
        ? error
        : new HelloLynkLocalMessagingError("relay_transport_error", { cause: error, retryable: true });
      const acceptedHttpStatus = Number(accepted.httpStatus);
      const definitelyRejected = (
        Number.isInteger(acceptedHttpStatus) &&
        acceptedHttpStatus >= 400 &&
        acceptedHttpStatus < 500 &&
        acceptedHttpStatus !== 408
      );
      const failureStatus = [425, 429].includes(acceptedHttpStatus)
        ? "failed_retryable"
        : definitelyRejected
          ? "failed_permanent"
          : "delivery_state_unconfirmed";
      const updated = await store.updateOutgoing(message.clientMessageId, {
        status: failureStatus,
        lastErrorCode: accepted.code,
        incrementAttempts: false,
        settleDelivery: true,
      });
      if (failureStatus === "failed_permanent") throw accepted;
      return { ok: false, status: updated.status, message: updated, errorCode: accepted.code };
    }

    // Capacity can fail before dispatch or after the recipient has persisted.
    // Retry only when the relay explicitly reports that no attempt was created.
    const rejectedBeforeRelayAttempt = ["relay_unavailable", "relay_ack_capacity_exhausted"].includes(result.status)
      && result.deliveredConnectionCount === 0
      && ["deliveryAttemptId", "eventId", "targetConnectionId", "relayedAt", "ackDeadlineAt"]
        .every((field) => result[field] === null);
    const relayAccepted = ["acknowledged_by_recipient_local_store", "delivered_to_live_connection"].includes(result.status);
    // The queried receiver may have disconnected or downgraded before the
    // write. A receipt from another connection cannot establish delivery.
    const friendReceiptUnconfirmed = message.targetConversationTitle && relayAccepted
      && (result.status !== "acknowledged_by_recipient_local_store" || result.targetConnectionId !== context.friendTargetConnectionId);
    const finalStatus = relayAccepted
      ? friendReceiptUnconfirmed ? "delivery_state_unconfirmed" : "delivered_to_live_connection"
      : result.status === "reply_target_deleted" && message.replyToClientMessageId
        ? "failed_permanent"
      : result.status === "recipient_offline"
        ? "recipient_offline"
        : rejectedBeforeRelayAttempt || [
            "recipient_ack_capability_unavailable",
            "recipient_e2ee_device_offline",
            "recipient_e2ee_ack_capability_unavailable",
          ].includes(result.status)
          ? "failed_retryable"
          : "delivery_state_unconfirmed";
    let updated;
    try {
      updated = await store.updateOutgoing(message.clientMessageId, {
        status: finalStatus,
        lastErrorCode: finalStatus === "delivered_to_live_connection" ? null
          : friendReceiptUnconfirmed ? "native_target_connection_changed" : result.status,
        incrementAttempts: false,
        settleDelivery: true,
      });
    } catch (error) {
      await store.updateOutgoing(message.clientMessageId, {
        status: "delivery_state_unconfirmed",
        lastErrorCode: "local_delivery_state_persist_failed",
        incrementAttempts: false,
        settleDelivery: true,
      }).catch(() => {});
      throw new HelloLynkLocalMessagingError("local_delivery_state_persist_failed", {
        cause: error,
        retryable: false,
        deliveryStatus: result.status,
      });
    }
    return {
      ok: finalStatus === "delivered_to_live_connection",
      status: updated.status,
      message: updated,
      relay: result,
    };
  }

  return {
    principalId,
    delegateId,
    store,
    async sendText({ recipientHelloLynkId, recipientPrincipalId, recipientDelegateId, region, text, clientMessageId, intentSource, route, signal, replyToClientMessageId, targetConversationId, targetConversationTitle, friendTargetConnectionId, resendSourceClientMessageId }) {
      const acceptedClientMessageId = clientMessageId || `hellolynk_local_${crypto.randomUUID()}`;
      const acceptedText = safeText(text);
      const reply = replyToClientMessageId == null ? {} : { replyToClientMessageId: safeId(replyToClientMessageId, "reply_target_invalid") };
      if (targetConversationTitle != null || friendTargetConnectionId != null) {
        if (!targetConversationId || recipientPrincipalId === principalId || route?.routeKind !== "instance_direct")
          throw new HelloLynkLocalMessagingError("native_target_not_authorized");
        safeId(friendTargetConnectionId, "native_target_not_authorized");
        reply.targetConversationTitle = nativeConversationTitle(targetConversationTitle);
      }
      if (targetConversationId != null) {
        if (replyToClientMessageId != null || !e2ee || e2eeVersion !== "2" || (recipientPrincipalId !== principalId && !reply.targetConversationTitle)
          || intentSource !== "human_preauthorized_contact") throw new HelloLynkLocalMessagingError("native_target_not_authorized");
        reply.targetConversationId = nativeConversationId(targetConversationId);
      }
      if (replyToClientMessageId != null && (e2eeVersion !== "2" || !e2ee || intentSource !== "human_preauthorized_contact"
        || !["instance_direct", "owned_delegate"].includes(route?.routeKind))) throw new HelloLynkLocalMessagingError("reply_target_invalid");
      const resend = resendSourceClientMessageId == null ? {} : { resendSourceClientMessageId: safeId(resendSourceClientMessageId, "reply_resend_invalid") };
      if (resendSourceClientMessageId != null && (!durableBeforeEncryption || e2eeVersion !== "2" || !e2ee
        || intentSource !== "human_native_dialog" || replyToClientMessageId != null)) throw new HelloLynkLocalMessagingError("reply_resend_invalid");
      const conversationIntent = createOutgoingConversationIntent({
        region, recipientHelloLynkId, recipientPrincipalId,
        recipientDelegateId: recipientDelegateId ?? route?.recipientDelegateId,
        senderPrincipalId: principalId, senderDelegateId: delegateId,
      });
      let sealed = null;
      let message = null;
      const preparation = e2ee ? {
        intentSource: intentSource == null ? "hellolynk_client_explicit_send" : safeId(intentSource, "e2ee_intent_source_invalid"),
        route: normalizeOutgoingRoute(route, e2ee.version),
      } : null;
      if (preparation && !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(preparation.intentSource)) {
        throw new HelloLynkLocalMessagingError("e2ee_intent_source_invalid");
      }
      if (durableBeforeEncryption) {
        message = await store.addOutgoing({
          recipientHelloLynkId,
          text: acceptedText,
          clientMessageId: acceptedClientMessageId,
          senderPrincipalId: principalId,
          senderDelegateId: delegateId,
          e2ee: null,
          e2eePreparation: preparation,
          ...reply,
          ...resend,
          conversationIntent,
        });
      }
      if (e2ee) {
        try {
          sealed = await prepare(message || {
            peerHelloLynkId: recipientHelloLynkId, text: acceptedText, clientMessageId: acceptedClientMessageId,
            ...reply,
          }, preparation, signal);
          if (durableBeforeEncryption) message = await store.attachOutgoingE2ee(message.clientMessageId, sealed);
        } catch (error) {
          if (message) {
            await store.updateOutgoing(message.clientMessageId, {
              status: "failed_retryable",
              lastErrorCode: safeLocalErrorCode(error),
              incrementAttempts: false,
              preparationOnly: true,
            }).catch(() => {});
            await recoverCancelledPreparations(message.clientMessageId);
          }
          throw error;
        }
      } else if (route != null) {
        throw new HelloLynkLocalMessagingError("e2ee_route_without_e2ee");
      }
      if (e2eeMode === "required" && !sealed) {
        throw new HelloLynkLocalMessagingError("e2ee_required", { httpStatus: 426 });
      }
      if (!message) {
        message = await store.addOutgoing({
          recipientHelloLynkId,
          text: acceptedText,
          clientMessageId: acceptedClientMessageId,
          senderPrincipalId: principalId,
          senderDelegateId: delegateId,
          e2ee: sealed,
          conversationIntent,
          ...reply,
        });
      }
      try {
        throwIfAborted(signal);
      } catch (error) {
        if (durableBeforeEncryption && message) {
          await store.updateOutgoing(message.clientMessageId, {
            status: "failed_retryable",
            lastErrorCode: safeLocalErrorCode(error),
            incrementAttempts: false,
            preparationOnly: true,
          }).catch(() => {});
        }
        throw error;
      }
      return attempt(message.clientMessageId, { signal, friendTargetConnectionId });
    },
    async retry(clientMessageId, { signal, friendTargetConnectionId } = {}) {
      await store.recoverArchivedOutgoingRetryClaim?.({ clientMessageId });
      await store.recoverAbandonedE2eeOutgoingAttempts?.({ clientMessageId });
      const message = await store.getOutgoing(clientMessageId);
      if (!message) throw new HelloLynkLocalMessagingError("local_outgoing_message_not_found");
      if (message.targetConversationTitle) safeId(friendTargetConnectionId, "native_target_not_authorized");
      if (!MANUAL_RETRYABLE_OUTGOING_STATUSES.has(message.status) || message.lastErrorCode === "reply_target_deleted") {
        throw new HelloLynkLocalMessagingError("local_outgoing_message_not_retryable", { httpStatus: 409 });
      }
      if (!message.e2ee && e2ee && message.attempts === 0) {
        const claimed = await store.claimOutgoingForPreparation(clientMessageId, {
          senderPrincipalId: principalId, senderDelegateId: delegateId,
        });
        try {
          const sealed = await prepare(claimed, claimed.e2eePreparation, signal);
          await store.attachOutgoingE2ee(clientMessageId, sealed);
          throwIfAborted(signal);
        } catch (error) {
          await store.updateOutgoing(clientMessageId, {
            status: "failed_retryable", lastErrorCode: safeLocalErrorCode(error),
            incrementAttempts: false, preparationOnly: true,
          }).catch(() => {});
          await recoverCancelledPreparations(clientMessageId);
          throw error;
        }
      }
      throwIfAborted(signal);
      return attempt(clientMessageId, { signal, friendTargetConnectionId });
    },
    async cancel(clientMessageId) {
      const message = await store.cancelOutgoing(clientMessageId);
      await recoverCancelledPreparations(clientMessageId);
      return message;
    },
    async openReceiver() {
      if (typeof e2ee?.ensurePreKeyInventory === "function") {
        await e2ee.ensurePreKeyInventory();
      }
      const stream = await transport.openEventStream();
      let ready;
      try {
        ready = await stream.nextEvent();
      } catch (error) {
        await stream.close().catch(() => {});
        throw error;
      }
      const readyMismatchCode = ready.event !== "ready"
        ? "relay_ready_event_type_mismatch"
        : ready.data?.principalId !== principalId
          ? "relay_ready_principal_mismatch"
          : ready.data?.delegateId !== delegateId
            ? "relay_ready_delegate_mismatch"
            : ready.data?.storage !== "none"
              ? "relay_ready_storage_mode_mismatch"
              : ready.data?.receiverPersistedAckVersion !== 1
                ? "relay_ready_receipt_version_mismatch"
                : e2ee && ready.data?.e2eeDirectTextVersion !== Number(e2eeVersion)
                  ? "relay_ready_e2ee_version_mismatch"
                  : e2ee && ready.data?.identityKeyId !== e2eeIdentityKeyId
                    ? "relay_ready_e2ee_identity_mismatch"
                    : null;
      if (readyMismatchCode) {
        await stream.close().catch(() => {});
        throw new HelloLynkLocalMessagingError(readyMismatchCode);
      }
      return {
        ready: ready.data,
        async nextIncoming() {
          const event = await stream.nextEvent();
          if (event.event === "closed") {
            const reason = [
              "runtime_session_expired",
              "runtime_session_revoked",
              "runtime_session_missing",
              "device_credential_revoked",
              "upstream_authority_inactive",
              "relay_backpressure_limit",
              "relay_connection_unwritable",
              "relay_write_failed",
              "relay_heartbeat_failed",
            ].includes(event.data?.reason) ? event.data.reason : "relay_closed";
            throw new HelloLynkLocalMessagingError(`relay_event_stream_closed_${reason}`, {
              retryable: reason === "runtime_session_expired" || reason.startsWith("relay_"),
              reason,
            });
          }
          if (
            event.event !== "message" ||
            event.data?.recipientPrincipalId !== principalId ||
            event.data?.messageType !== "text"
          ) {
            throw new HelloLynkLocalMessagingError("relay_event_contract_mismatch");
          }
          const ackFields = ["ackContract", "deliveryAttemptId", "targetConnectionId", "ackDeadlineAt"];
          const ackFieldCount = ackFields.filter((field) => Object.hasOwn(event.data, field)).length;
          const legacyContract = ackFieldCount === 0;
          const persistedAckContract = (
            ackFieldCount === ackFields.length &&
            event.data.ackContract === RECEIVER_LOCAL_STORE_CONTRACT &&
            typeof event.data.deliveryAttemptId === "string" &&
            typeof event.data.targetConnectionId === "string" &&
            typeof event.data.ackDeadlineAt === "string" &&
            Number.isFinite(Date.parse(event.data.ackDeadlineAt))
          );
          if (!legacyContract && !persistedAckContract) {
            throw new HelloLynkLocalMessagingError("relay_event_contract_mismatch");
          }
          const hasEnvelope = event.data?.e2eeEnvelope != null;
          const hasPlaintext = event.data?.text != null;
          if (hasEnvelope === hasPlaintext) {
            throw new HelloLynkLocalMessagingError("relay_event_security_contract_mismatch");
          }
          if (!hasEnvelope && e2eeMode === "required") {
            throw new HelloLynkLocalMessagingError("e2ee_plaintext_event_rejected");
          }
          let localEvent = event.data;
          let stored = null;
          let opened = null;
          if (hasEnvelope) {
            if (!e2ee) throw new HelloLynkLocalMessagingError("e2ee_receiver_unavailable");
            const outerDigest = safeSha256(event.data?.envelopeDigest);
            const outerSenderIdentityKeyId = safeId(
              event.data?.senderIdentityKeyId,
              "e2ee_sender_identity_key_id_invalid",
            );
            const replay = typeof store.findIncomingE2eeReplay === "function"
              ? await store.findIncomingE2eeReplay({
                senderIdentityKeyId: outerSenderIdentityKeyId,
                clientMessageId: event.data.clientMessageId,
                envelopeDigest: outerDigest,
              })
              : null;
            if (replay) {
              const replayBinding = getMessageConversationBinding(replay, { principalId });
              if (replayBinding) {
                const eventBinding = deriveInstanceConversationBinding({
                  ...event.data.e2eeEnvelope?.protected, e2eeVersion: 2,
                }, { direction: "incoming", principalId });
                if (replayBinding.localDelegateId !== delegateId
                  || instanceConversationKey(replayBinding) !== instanceConversationKey(eventBinding)) {
                  throw new HelloLynkLocalMessagingError("local_incoming_message_conflict", { httpStatus: 409 });
                }
              }
              stored = { message: replay, duplicate: true };
              localEvent = {
                envelopeDigest: outerDigest,
                senderIdentityKeyId: outerSenderIdentityKeyId,
              };
              if (typeof e2ee.commitIncomingReplay === "function") {
                await e2ee.commitIncomingReplay({
                  event: event.data,
                  storedMessage: replay,
                });
              }
            } else {
              opened = await e2ee.openIncoming({
                event: event.data,
                recipientPrincipalId: principalId,
                recipientDelegateId: delegateId,
              });
              const envelopeDigest = safeSha256(opened?.envelopeDigest || outerDigest);
              if (outerDigest !== envelopeDigest) {
                throw new HelloLynkLocalMessagingError("e2ee_envelope_digest_mismatch");
              }
              localEvent = {
                eventId: event.data.eventId,
                clientMessageId: event.data.clientMessageId,
                messageType: "text",
                senderPrincipalId: opened?.senderPrincipalId,
                senderDelegateId: opened?.senderDelegateId,
                authorizationScope: opened?.authorizationScope,
                intentSource: opened?.intentSource,
                ...(opened?.replyToClientMessageId ? { replyToClientMessageId: opened.replyToClientMessageId } : {}),
                ...(opened?.targetConversationId ? { targetConversationId: opened.targetConversationId } : {}),
                senderHelloLynkId: event.data.senderHelloLynkId,
                senderPrincipalDisplayName: event.data.senderPrincipalDisplayName,
                senderDelegateDisplayName: event.data.senderDelegateDisplayName,
                recipientPrincipalId: event.data.recipientPrincipalId,
                conversationBinding: opened?.e2eeVersion === 2
                  ? deriveInstanceConversationBinding(opened, { direction: "incoming", principalId })
                  : null,
                text: safeText(opened?.text),
                envelopeDigest,
                senderIdentityKeyId: opened?.senderIdentityKeyId || event.data.senderIdentityKeyId,
                recipientIdentityKeyId: opened?.recipientIdentityKeyId || event.data.recipientIdentityKeyId,
              };
            }
          }
          if (!stored) stored = await store.addIncoming(localEvent);
          if (!stored.duplicate && typeof opened?.commit === "function") await opened.commit();
          if (persistedAckContract) {
            await stream.acknowledgePersisted({
              ...(stored.message.replyTargetDeleted ? { replyTargetDeleted: true } : {}),
              deliveryAttemptId: event.data.deliveryAttemptId,
              eventId: event.data.eventId,
              clientMessageId: event.data.clientMessageId,
              connectionId: event.data.targetConnectionId,
              envelopeDigest: hasEnvelope ? localEvent.envelopeDigest : null,
              ...(hasEnvelope && Number(event.data?.schemaVersion) === 2 ? {
                e2eeVersion: 2,
                routeKind: event.data.routeKind,
                recipientDelegateId: event.data.recipientDelegateId,
                recipientDelegateAuthorizationVersion: event.data.recipientDelegateAuthorizationVersion,
                recipientHostId: event.data.recipientHostId,
                recipientRouteVersion: event.data.recipientRouteVersion,
                recipientDeviceId: event.data.recipientDeviceId,
                recipientIdentityKeyId: event.data.recipientIdentityKeyId,
                recipientPreKeyId: event.data.recipientPreKeyId,
              } : {}),
            });
            if (hasEnvelope && typeof e2ee?.replenishPreKeyInventory === "function") {
              void Promise.resolve().then(() => e2ee.replenishPreKeyInventory()).catch(() => {});
            }
          }
          return stored;
        },
        close: () => stream.close(),
      };
    },
  };
}
