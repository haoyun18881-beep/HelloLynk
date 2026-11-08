import crypto from "node:crypto";
import {
  getMessageConversationBinding,
  getOutgoingConversationIntent,
  instanceConversationKey,
  normalizeInstanceConversationBinding,
} from "./hellolynk-instance-conversation.mjs";
import {
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
  HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
  HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH,
} from "../workbench/contract.mjs";

export const HELLOLYNK_NEUTRAL_HOST_WORKBENCH_READ_MODEL_CONTRACT =
  "hellolynk-neutral-host-workbench-read-model-v1";

const THREAD_PAGE_SIZE = 100;
const MESSAGE_PAGE_SIZE = 20;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/;
const HELLOLYNK_ID = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const UNSAFE_TEXT = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const FILTERS = new Set(["all", "unread", "archived"]);
const TRANSPORTS = new Set(["loopback-http", "mcp-app-rpc", "cursor-webview-rpc"]);
const HOST_STATES = new Set(["connecting", "online", "offline", "rebind-required", "error"]);
const RELATIONSHIP_METADATA_STATES = new Set(["loading", "fresh", "stale"]);
const CLIENT_TYPES = new Set(["codex", "cursor", "dsh", "openclaw", "trae-work", "workbuddy", "claude-code", "unknown"]);
const CLIENT_STATES = new Set(["connected", "disconnected", "stale"]);
const CONTACT_REQUEST_STATES = new Set([
  "pending",
  "accepted",
  "rejected",
  "cancelled",
  "blocked",
  "expired",
]);
const MANUAL_RETRYABLE_OUTBOX_STATUSES = new Set([
  "recipient_offline",
  "failed_retryable",
  "failed_permanent",
]);
const MESSAGE_AUTHORIZATION_SCOPE = "relay.text.send";
const MESSAGE_INTENT_SOURCES = new Set([
  "hellolynk_client_explicit_send",
  "human_native_dialog",
  "human_preauthorized_contact",
]);
const DEFAULT_CAPABILITIES = Object.freeze([
  "contacts.read",
  "messages.read",
  "outbox.read",
  "search.local",
  "security.read",
  "threads.read",
]);
const CAPABILITIES = new Set([
  "contact.authorization.manage",
  "contact.delete",
  "contact.save",
  "contact.rename",
  "contact.instances.list",
  "contact.instance.save",
  "contact.instance.rename",
  "contact.instance.delete",
  "contact-request.clear-resolved",
  "contact-request.recover-decision",
  "contact-request.respond",
  "contact-request.cancel",
  "contact-request.send",
  "contacts.read",
  "messages.delete-read",
  "messages.delete-sent",
  "messages.mark-read",
  "messages.mark-all-read",
  "messages.auto-read.manage",
  "messages.read",
  "messages.request-send",
  "outbox.read",
  "outbox.request-retry",
  "principal.search",
  "relationship.end",
  "relationships.read",
  "block.remove",
  "blocks.read",
  "search.local",
  "security.open-account",
  "security.read",
  "threads.read",
  "threads.manage-local",
]);

export class HelloLynkNeutralHostWorkbenchReadModelError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkNeutralHostWorkbenchReadModelError";
    this.code = code;
  }
}

/**
 * Build the single Host-owned read model used by every client transport.
 * Messages use the current indexed store's bounded projections; this
 * module has no write path and never retains a mutable store object.
 */
export function createNeutralHostWorkbenchReadModel(options = {}) {
  exactRecord(options, [
    "subject",
    "localDelegateLabels",
    "hostGeneration",
    "applicationChangeCursor",
    "messageStore",
    "contactStore",
    "contactRequestStore",
    "capabilities",
    "hostStatus",
    "relationshipMetadataState",
    "connectedClients",
    "changeEventTypes",
    "snapshotRequired",
    "now",
  ], "neutral_host_workbench_options_invalid");

  const subject = normalizeSubject(options.subject);
  const localDelegateLabels = new Map();
  for (const item of array(options.localDelegateLabels ?? [], "neutral_host_workbench_local_delegate_labels_invalid")) {
    exactRecord(item, ["principalId", "delegateId", "delegateLabel"], "neutral_host_workbench_local_delegate_label_invalid");
    const principalId = safeId(item.principalId, "neutral_host_workbench_local_delegate_label_invalid");
    const delegateId = safeId(item.delegateId, "neutral_host_workbench_local_delegate_label_invalid");
    const delegateLabel = optionalText(item.delegateLabel, 120, "neutral_host_workbench_local_delegate_label_invalid");
    if (principalId !== subject.principalId || delegateLabel == null) continue;
    if (localDelegateLabels.has(delegateId) && localDelegateLabels.get(delegateId) !== delegateLabel) {
      fail("neutral_host_workbench_local_delegate_label_conflict");
    }
    localDelegateLabels.set(delegateId, delegateLabel);
  }
  const hostGeneration = safeId(options.hostGeneration, "neutral_host_workbench_generation_invalid");
  const applicationChangeCursor = normalizeChangeCursor(options.applicationChangeCursor);
  const indexedMessageStore = options.messageStore;
  if (["readWorkbenchSummary", "readWorkbenchRevision", "queryConversationPage", "readLocalHistoryStats"]
    .some((method) => typeof indexedMessageStore?.[method] !== "function")) {
    fail("neutral_host_workbench_indexed_reader_incomplete");
  }
  const readers = Object.freeze({
    contacts: contactReader(options.contactStore, subject.delegateId),
    contactRequests: contactRequestReader(options.contactRequestStore),
    outbox: outboxReader(indexedMessageStore, subject),
  });
  const capabilities = normalizeCapabilities(options.capabilities);
  const relationshipMetadataFields = Object.hasOwn(options, "relationshipMetadataState") ? {
    relationshipMetadataState: oneOf(options.relationshipMetadataState, RELATIONSHIP_METADATA_STATES,
      "neutral_host_workbench_relationship_metadata_state_invalid"),
  } : {};
  const hostStatus = oneOf(
    options.hostStatus ?? "online",
    HOST_STATES,
    "neutral_host_workbench_host_status_invalid",
  );
  const connectedClients = normalizeConnectedClients(options.connectedClients ?? []);
  const changeEventTypes = normalizeEventTypes(options.changeEventTypes ?? []);
  const snapshotRequired = options.snapshotRequired === true;
  const now = typeof options.now === "function" ? options.now : () => new Date();
  const generationBaseline = isoTimestamp(now(), "neutral_host_workbench_time_invalid");

  async function readSnapshot(request = {}, source) {
    const acceptedRequest = normalizeReadRequest(request);
    const acceptedSource = normalizeSource(source);
    return readIndexedSnapshot(acceptedRequest, acceptedSource);
  }

  async function readIndexedSnapshot(request, source) {
    if (request.messageCursor != null && request.threadId == null) fail("neutral_host_workbench_message_cursor_thread_required");
    if (request.historyBefore !== undefined && request.threadId == null) fail("neutral_host_workbench_thread_id_required");
    const contactRequestRead = readers.contactRequests(Object.hasOwn(request, "contactRequestCursor")
      ? { cursor: request.contactRequestCursor } : {});
    const metadata = await Promise.all([
      contactRequestRead.then(() => readers.contacts()),
      contactRequestRead,
    ]);
    // Each indexed query holds a short store lock; a receiver may write between
    // queries. Fence the complete local projection without holding that lock
    // across a cloud lookup or a history scan. Retry reads only, reusing the
    // relationship result rather than repeating its network/reconciliation work.
    for (let attempt = 0; attempt < 3; attempt++) {
      const revision = safeRevision(await indexedMessageStore.readWorkbenchRevision(),
        "neutral_host_workbench_summary_invalid");
      let snapshot, readError;
      try { snapshot = await buildIndexedSnapshot(request, source, metadata); }
      catch (error) { readError = error; }
      const current = safeRevision(await indexedMessageStore.readWorkbenchRevision(),
        "neutral_host_workbench_summary_invalid");
      if (revision !== current) continue;
      if (readError) throw readError;
      return snapshot;
    }
    fail("neutral_host_workbench_snapshot_busy");
  }

  function validateRelationshipMetadata(value) {
    const state = normalizeContactRequestState(value);
    const requests = normalizeContactRequests(state.requests, subject);
    const projection = {
      contactRequests: requests.filter((item) => item.direction === "incoming"),
      outgoingContactRequests: requests.filter((item) => item.direction === "outgoing"),
      contactRequestNextCursor: state.nextCursor,
      relationships: normalizeRelationships(state.relationships),
      blocks: normalizeBlocks(state.blocks),
    };
    assertNoSensitiveKeys(projection);
    return deepFreeze(projection);
  }

  async function buildIndexedSnapshot(request, source, metadata) {
    const scope = { principalId: subject.principalId, delegateId: subject.delegateId, region: subject.region };
    const [rawContacts, rawContactRequests] = metadata;
    const [rawSummary, rawOutbox, searchThreadIds] = await Promise.all([
      indexedMessageStore.readWorkbenchSummary(scope),
      readers.outbox(),
      request.query ? (typeof indexedMessageStore.searchWorkbenchThreads === "function"
        // Filter and paginate the complete match set below. Truncating it here
        // silently drops older-body matches in later conversations.
        ? indexedMessageStore.searchWorkbenchThreads({ scope, query: request.rawQuery, limit: Number.MAX_SAFE_INTEGER })
        : Promise.reject(new HelloLynkNeutralHostWorkbenchReadModelError("neutral_host_workbench_search_reader_invalid")))
        : Promise.resolve(null),
    ]);
    exactRecord(rawSummary, ["threads", "revision", "latestTimestamp", "archivedThreadCount", "autoArchiveAfterHours", "hiddenThreadIds", "inboxReadBoundary"],
      "neutral_host_workbench_summary_invalid");
    if (Object.hasOwn(rawSummary, "inboxReadBoundary")
      && (!Number.isSafeInteger(rawSummary.inboxReadBoundary) || rawSummary.inboxReadBoundary < 0)) fail("neutral_host_workbench_summary_invalid");
    const summaryRows = array(rawSummary.threads, "neutral_host_workbench_summary_invalid");
    const contacts = normalizeContacts(rawContacts, subject);
    if (contacts.length > 500) fail("neutral_host_workbench_contacts_invalid");
    const aiReadAuthorization = { contactRequests: true };
    const contactByHelloLynkId = new Map(contacts.map((item) => [item.hellolynkId, item]));
    const lastMessages = summaryRows.flatMap((row) => row?.lastMessage == null ? [] : [row.lastMessage]);
    const incoming = normalizeMessages(lastMessages, subject, "messages", localDelegateLabels);
    const outgoing = normalizeMessages(lastMessages, subject, "outbox");
    const projected = buildThreads(deduplicateMessages([...incoming, ...outgoing]), contactByHelloLynkId, subject);
    const threadById = new Map(projected.threads.map((thread) => [thread.threadId, thread]));
    const summaryIds = new Set();
    for (const row of summaryRows) {
      exactRecord(row, ["threadId", "binding", "legacy", "peerPrincipalId", "peerHelloLynkId",
        "lastMessage", "unreadCount", "updatedAt", "archived", "autoReadAfterAi", "recentSendFailureCount"],
        "neutral_host_workbench_summary_invalid");
      const threadId = safeId(row.threadId, "neutral_host_workbench_thread_id_invalid");
      if (summaryIds.has(threadId)) fail("neutral_host_workbench_summary_invalid");
      summaryIds.add(threadId);
      let thread = threadById.get(threadId);
      if (!thread && row.lastMessage == null && row.binding != null) {
        const binding = normalizeInstanceConversationBinding(row.binding,
          { region: subject.region, principalId: subject.principalId });
        if (binding.localDelegateId !== subject.delegateId || instanceConversationKey(binding) !== threadId) {
          fail("neutral_host_workbench_summary_scope_invalid");
        }
        const contact = contacts.find((item) => item.principalId === binding.peerPrincipalId) ?? null;
        const instance = contact?.instances.find((item) => item.delegateId === binding.peerDelegateId) ?? null;
        thread = {
          threadId, conversationKind: "instance", localDelegateId: binding.localDelegateId,
          peerDelegateId: binding.peerDelegateId, contactId: contact?.contactId ?? null,
          peerPrincipalId: binding.peerPrincipalId, peerHelloLynkId: contact?.hellolynkId ?? null,
          displayName: contact?.displayName ?? binding.peerPrincipalId,
          delegateLabel: instance?.displayName ?? null, lastMessage: null,
          unreadCount: 0, updatedAt: row.updatedAt,
        };
        threadById.set(threadId, thread);
      }
      if (!thread && row.lastMessage != null) fail("neutral_host_workbench_summary_scope_invalid");
      if (!thread) continue;
      if (!Number.isSafeInteger(row.unreadCount) || row.unreadCount < 0) fail("neutral_host_workbench_summary_invalid");
      if (typeof row.archived !== "boolean") fail("neutral_host_workbench_summary_invalid");
      thread.unreadCount = row.unreadCount;
      thread.updatedAt = isoTimestamp(row.updatedAt, "neutral_host_workbench_summary_invalid");
      thread.archived = row.archived === true;
      if (Object.hasOwn(row, "recentSendFailureCount")) {
        if (!Number.isSafeInteger(row.recentSendFailureCount) || row.recentSendFailureCount < 0
          || row.recentSendFailureCount > 5) fail("neutral_host_workbench_summary_invalid");
        thread.recentSendFailureCount = row.recentSendFailureCount;
      }
      if (Object.hasOwn(row, "autoReadAfterAi")) {
        if (typeof row.autoReadAfterAi !== "boolean" || row.legacy === true) fail("neutral_host_workbench_summary_invalid");
        thread.autoReadAfterAi = row.autoReadAfterAi;
      }
    }
    const hiddenThreadIds = new Set(array(rawSummary.hiddenThreadIds ?? [], "neutral_host_workbench_summary_invalid")
      .map((id) => safeId(id, "neutral_host_workbench_thread_id_invalid")));
    const canonicalThreads = [...threadById.values()].filter((thread) => thread.conversationKind === "instance"
      && thread.localDelegateId === subject.delegateId && !hiddenThreadIds.has(thread.threadId));
    canonicalThreads.sort((left, right) => compareText(right.updatedAt, left.updatedAt)
      || compareText(left.threadId, right.threadId));
    const { contactRequests, outgoingContactRequests, contactRequestNextCursor, relationships, blocks }
      = validateRelationshipMetadata(rawContactRequests);
    const outbox = normalizeOutbox(rawOutbox, subject);
    const security = { hostStatus, connectedClients };
    // Keep the Host stream cursor captured when this read model was created.
    // Together with hostGeneration it lets the UI recognize notifications
    // already included in a snapshot; it never substitutes for revision checks.
    const changeCursor = applicationChangeCursor;
    const revision = `wbr_${digest(stableJson({
      contractId: HELLOLYNK_NEUTRAL_HOST_WORKBENCH_READ_MODEL_CONTRACT,
      hostGeneration, applicationChangeCursor, subject, capabilities,
      storeRevision: safeRevision(String(rawSummary.revision), "neutral_host_workbench_summary_invalid"),
      contacts, aiReadAuthorization, relationships, ...relationshipMetadataFields,
      blocks, security, changeEventTypes, snapshotRequired,
    })).slice(0, 48)}`;
    const searchMatches = searchThreadIds == null ? null : new Set(array(searchThreadIds,
      "neutral_host_workbench_search_invalid").map((id) => safeId(id, "neutral_host_workbench_thread_id_invalid")));
    const matchingThreads = filterThreads(canonicalThreads, [], request.query, request.filter, searchMatches);
    const selectedThread = request.threadId == null ? null
      : canonicalThreads.find((item) => item.threadId === request.threadId);
    if (request.threadId != null && !selectedThread) fail("neutral_host_workbench_thread_not_found");
    const threadFingerprint = cursorFingerprint({ kind: "threads", hostGeneration, revision,
      query: request.query, filter: request.filter });
    const messageFingerprint = selectedThread ? cursorFingerprint({ kind: "indexed-messages-v1", hostGeneration, subject,
      query: request.query, filter: request.filter, threadId: selectedThread.threadId }) : null;
    const decodedMessageCursor = selectedThread ? decodeIndexedMessageCursor(request.messageCursor, messageFingerprint) : null;
    const windowRead = ["from", "older-window", "newer-window"].includes(decodedMessageCursor?.direction);
    let threadItems;
    let threadNextCursor;
    if (request.messageCursor != null && !windowRead) {
      threadItems = [selectedThread];
      threadNextCursor = null;
    } else {
      const offset = decodeCursor(request.threadCursor, "t", threadFingerprint, matchingThreads.length);
      threadItems = matchingThreads.slice(offset, offset + THREAD_PAGE_SIZE);
      const next = offset + threadItems.length;
      threadNextCursor = next < matchingThreads.length ? encodeCursor("t", next, threadFingerprint) : null;
      if (selectedThread && request.threadCursor == null
        && !threadItems.some((item) => item.threadId === selectedThread.threadId)) threadItems = [...threadItems, selectedThread];
    }
    let messageItems = [];
    let messageNextCursor = null;
    let messagePreviousCursor = null;
    let messageRefreshCursor = null;
    let historySelection = null;
    if (selectedThread) {
      const fingerprint = messageFingerprint;
      const decoded = decodedMessageCursor;
      const messageLimit = windowRead ? 200 : MESSAGE_PAGE_SIZE;
      const page = await indexedMessageStore.queryConversationPage({ scope, threadId: selectedThread.threadId,
        anchor: decoded?.anchor ?? null, direction: decoded?.direction ?? "before", limit: messageLimit });
      exactRecord(page, ["messages", "hasEarlier", "hasLater"], "neutral_host_workbench_message_page_invalid");
      const rawPage = array(page.messages, "neutral_host_workbench_message_page_invalid");
      if (rawPage.length > messageLimit || typeof page.hasEarlier !== "boolean" || typeof page.hasLater !== "boolean") {
        fail("neutral_host_workbench_message_page_invalid");
      }
      const pageMessages = deduplicateMessages([
        ...normalizeMessages(rawPage, subject, "messages", localDelegateLabels),
        ...normalizeMessages(rawPage, subject, "outbox"),
      ]);
      const pageProjected = buildThreads(pageMessages, contactByHelloLynkId, subject).messages;
      const pageKey = (item) => `${item.direction ?? "incoming"}\0${item.localMessageId ?? item.id}\0${item.clientMessageId ?? item.id}`;
      const projectedById = new Map(pageProjected.map((item) => [pageKey(item), item]));
      messageItems = rawPage.map((item) => projectedById.get(pageKey(item)));
      if (messageItems.some((item) => !item || item.threadId !== selectedThread.threadId)) {
        fail("neutral_host_workbench_message_page_scope_invalid");
      }
      if (messageItems.length) {
        messageRefreshCursor = encodeIndexedMessageCursor("from", messageItems[0], fingerprint);
        messageNextCursor = page.hasEarlier ? encodeIndexedMessageCursor("older-window", messageItems[0], fingerprint) : null;
        messagePreviousCursor = page.hasLater
          ? encodeIndexedMessageCursor("newer-window", messageItems.at(-1), fingerprint) : null;
      }
      if (Object.hasOwn(request, "historyBefore")) {
        historySelection = await indexedMessageStore.readLocalHistoryStats({ scope,
          threadId: selectedThread.threadId, before: request.historyBefore });
        if (historySelection?.threadId !== selectedThread.threadId) fail("neutral_host_workbench_history_scope_invalid");
      }
    }
    const latestTimestamp = rawSummary.latestTimestamp == null ? generationBaseline
      : isoTimestamp(rawSummary.latestTimestamp, "neutral_host_workbench_summary_invalid");
    if (!Number.isSafeInteger(rawSummary.archivedThreadCount) || rawSummary.archivedThreadCount < 0
      || (rawSummary.autoArchiveAfterHours !== null && rawSummary.autoArchiveAfterHours !== 24)) {
      fail("neutral_host_workbench_summary_invalid");
    }
    const generatedAt = deterministicGeneratedAt(generationBaseline,
      [{ updatedAt: latestTimestamp }], contacts, relationships, blocks, outbox);
    const snapshot = {
      contractId: HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
      schemaVersion: HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
      compatibility: { minReaderVersion: HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
        commandVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION },
      hostGeneration, commandWindow: null, revision, changeCursor, generatedAt, source,
      ...(Object.hasOwn(rawSummary, "inboxReadBoundary") ? { inboxReadBoundary: rawSummary.inboxReadBoundary } : {}),
      subject, capabilities,
      threads: { items: threadItems, nextCursor: threadNextCursor },
      messages: { threadId: selectedThread?.threadId ?? null, items: messageItems,
        nextCursor: messageNextCursor, previousCursor: messagePreviousCursor, refreshCursor: messageRefreshCursor },
      outbox, contacts, aiReadAuthorization, contactRequests, outgoingContactRequests,
      contactRequestNextCursor, relationships,
      ...relationshipMetadataFields, blocks, security,
      localHistory: { autoArchiveAfterHours: rawSummary.autoArchiveAfterHours,
        archivedThreadCount: rawSummary.archivedThreadCount, selection: historySelection },
      changes: { cursor: changeCursor, snapshotRequired, eventTypes: changeEventTypes },
    };
    assertNoSensitiveKeys(snapshot);
    return deepFreeze(snapshot);
  }

  return Object.freeze({
    contractId: HELLOLYNK_NEUTRAL_HOST_WORKBENCH_READ_MODEL_CONTRACT,
    readSnapshot,
    // Background display refreshes reuse the same projection validation without
    // reading unrelated message, outbox or local-contact stores.
    validateRelationshipMetadata,
  });
}

function normalizeReadRequest(value) {
  exactRecord(
    value,
    ["threadId", "threadCursor", "messageCursor", "contactRequestCursor", "query", "filter", "historyBefore"],
    "neutral_host_workbench_read_request_invalid",
  );
  const rawQuery = value.query ?? "";
  return Object.freeze({
    threadId: value.threadId == null
      ? null
      : safeId(value.threadId, "neutral_host_workbench_thread_id_invalid"),
    threadCursor: value.threadCursor == null
      ? null
      : safeRevision(value.threadCursor, "neutral_host_workbench_thread_cursor_invalid"),
    messageCursor: value.messageCursor == null
      ? null
      : safeMessageCursor(value.messageCursor),
    ...(Object.hasOwn(value, "historyBefore") ? { historyBefore: value.historyBefore == null ? null
      : isoTimestamp(value.historyBefore, "neutral_host_workbench_history_before_invalid") } : {}),
    ...(Object.hasOwn(value, "contactRequestCursor") ? {
      contactRequestCursor: value.contactRequestCursor == null
        ? null
        : contactRequestCursor(
            value.contactRequestCursor,
            "neutral_host_workbench_contact_request_cursor_invalid",
          ),
    } : {}),
    query: normalizeQuery(rawQuery),
    rawQuery,
    filter: oneOf(value.filter ?? "all", FILTERS, "neutral_host_workbench_filter_invalid"),
  });
}

function normalizeSubject(value) {
  exactRecord(value, [
    "region",
    "principalId",
    "principalLabel",
    "hellolynkId",
    "delegateId",
    "delegateLabel",
    "hostInstallationId",
    "authorizationVersion",
  ], "neutral_host_workbench_subject_invalid");
  const authorizationVersion = Number(value.authorizationVersion);
  if (!Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1) {
    fail("neutral_host_workbench_authorization_version_invalid");
  }
  return deepFreeze({
    region: safeId(value.region, "neutral_host_workbench_subject_invalid"),
    principalId: safeId(value.principalId, "neutral_host_workbench_subject_invalid"),
    principalLabel: optionalText(value.principalLabel, 120, "neutral_host_workbench_subject_invalid"),
    hellolynkId: safeHelloLynkId(value.hellolynkId, "neutral_host_workbench_subject_invalid"),
    delegateId: safeId(value.delegateId, "neutral_host_workbench_subject_invalid"),
    delegateLabel: optionalText(value.delegateLabel, 120, "neutral_host_workbench_subject_invalid"),
    hostInstallationId: safeId(value.hostInstallationId, "neutral_host_workbench_subject_invalid"),
    authorizationVersion,
  });
}

function normalizeSource(value) {
  exactRecord(value, ["mode", "transport", "clientId", "clientLabel"], "neutral_host_workbench_source_invalid");
  if (value.mode !== "neutral-host" || !TRANSPORTS.has(value.transport)) {
    fail("neutral_host_workbench_source_invalid");
  }
  return deepFreeze({
    mode: "neutral-host",
    transport: value.transport,
    clientId: safeId(value.clientId, "neutral_host_workbench_source_invalid"),
    clientLabel: text(value.clientLabel, 80, "neutral_host_workbench_source_invalid"),
  });
}

function outboxReader(store, subject) {
  if (typeof store.queryOutbox !== "function") fail("neutral_host_workbench_outbox_reader_invalid");
  return async () => array(await store.queryOutbox({
    scope: { principalId: subject.principalId, delegateId: subject.delegateId, region: subject.region },
    limit: 100, cursor: null,
  }), "neutral_host_workbench_outbox_invalid");
}

function contactReader(store, delegateId) {
  if (!store) fail("neutral_host_workbench_contact_reader_invalid");
  if (typeof store.listForDelegate === "function") {
    return async () => array(
      await store.listForDelegate(delegateId),
      "neutral_host_workbench_contacts_invalid",
    );
  }
  if (typeof store.list === "function") {
    return async () => array(await store.list(), "neutral_host_workbench_contacts_invalid");
  }
  fail("neutral_host_workbench_contact_reader_invalid");
}

function contactRequestReader(store) {
  if (!store || typeof store.listForHuman !== "function") {
    fail("neutral_host_workbench_contact_request_reader_invalid");
  }
  return async (input) => store.listForHuman(input);
}

function normalizeContactRequestState(value) {
  if (Array.isArray(value)) {
    return { requests: value, nextCursor: null, relationships: [], blocks: [] };
  }
  exactRecord(
    value,
    ["requests", "nextCursor", "relationships", "blocks"],
    "neutral_host_workbench_contact_request_state_invalid",
  );
  return {
    requests: array(value.requests, "neutral_host_workbench_contact_requests_invalid"),
    nextCursor: value.nextCursor == null
      ? null
      : contactRequestCursor(
          value.nextCursor,
          "neutral_host_workbench_contact_request_cursor_invalid",
        ),
    relationships: array(
      value.relationships,
      "neutral_host_workbench_relationships_invalid",
    ),
    blocks: array(value.blocks, "neutral_host_workbench_blocks_invalid"),
  };
}

function normalizeMessages(value, subject, origin, localDelegateLabels = null) {
  return array(value, "neutral_host_workbench_messages_invalid")
    .filter((item) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        fail("neutral_host_workbench_message_invalid");
      }
      if (item.messageType === "local-deleted") return false;
      if (origin === "messages") return (item.direction ?? "incoming") === "incoming";
      return (item.direction ?? "outgoing") === "outgoing";
    })
    .filter((item) => origin !== "outbox"
      || item.senderPrincipalId === subject.principalId)
    .map((item) => {
      const direction = origin === "messages" ? "incoming" : "outgoing";
      let conversationBinding = null;
      try {
        const message = { ...item, direction };
        const identityContext = { region: subject.region, principalId: subject.principalId };
        conversationBinding = getMessageConversationBinding(message, identityContext)
          || getOutgoingConversationIntent(message, identityContext);
      } catch {
        // Invalid or contradictory old evidence remains readable only in
        // legacy history. The current Host instance cannot repair its identity.
      }
      const peerPrincipalId = direction === "incoming"
        ? optionalSafeId(item.peerPrincipalId ?? item.senderPrincipalId ?? conversationBinding?.peerPrincipalId)
        : optionalSafeId(item.peerPrincipalId ?? item.recipientPrincipalId ?? conversationBinding?.peerPrincipalId);
      const peerHelloLynkId = direction === "incoming"
        ? optionalHelloLynkId(item.peerHelloLynkId ?? item.senderHelloLynkId)
        : optionalHelloLynkId(item.recipientHelloLynkId ?? item.peerHelloLynkId);
      requirePeer(peerPrincipalId, peerHelloLynkId);
      const senderPrincipalId = optionalSafeId(item.senderPrincipalId);
      const senderDelegateId = optionalSafeId(item.senderDelegateId);
      if (direction === "incoming" && senderPrincipalId != null && peerPrincipalId != null
        && senderPrincipalId !== peerPrincipalId) {
        fail("neutral_host_workbench_message_sender_invalid");
      }
      const provenance = normalizeMessageProvenance(item.authorizationScope, item.intentSource);
      if (provenance.authorizationScope != null
        && (senderPrincipalId == null || senderDelegateId == null)) {
        fail("neutral_host_workbench_message_provenance_invalid");
      }
      const createdAt = isoTimestamp(
        item.createdAt ?? item.receivedAt,
        "neutral_host_workbench_message_time_invalid",
      );
      const updatedAt = isoTimestamp(
        item.updatedAt ?? item.readAt ?? item.receivedAt ?? item.createdAt,
        "neutral_host_workbench_message_time_invalid",
      );
      const unread = direction === "incoming"
        ? (typeof item.unread === "boolean" ? item.unread : item.status === "received")
        : false;
      return {
        localMessageId: safeId(
          item.localMessageId ?? item.id,
          "neutral_host_workbench_message_id_invalid",
        ),
        clientMessageId: safeId(
          item.clientMessageId ?? item.id,
          "neutral_host_workbench_message_id_invalid",
        ),
        direction,
        conversationBinding,
        peerPrincipalId,
        peerHelloLynkId,
        senderPrincipalId,
        senderDelegateId,
        authorizationScope: provenance.authorizationScope,
        intentSource: provenance.intentSource,
        senderPrincipalDisplayName: optionalText(
          item.senderPrincipalDisplayName,
          160,
          "neutral_host_workbench_message_label_invalid",
        ),
        senderDelegateDisplayName: optionalText(
          item.senderDelegateDisplayName,
          120,
          "neutral_host_workbench_message_label_invalid",
        ),
        senderDelegateFallbackLabel: direction === "incoming" && conversationBinding != null
          && senderPrincipalId === subject.principalId
          && conversationBinding.peerPrincipalId === subject.principalId
          && senderDelegateId === conversationBinding.peerDelegateId
          ? localDelegateLabels?.get(senderDelegateId) ?? null : null,
        text: text(item.text ?? "", 64 * 1024, "neutral_host_workbench_message_text_invalid", true),
        ...(direction === "incoming" && item.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}),
        status: errorCode(
          item.status ?? (direction === "incoming" ? (unread ? "received" : "fetched") : "pending"),
          "neutral_host_workbench_message_status_invalid",
        ),
        unread,
        createdAt,
        updatedAt,
      };
    })
    // A verified binding belongs to one local AI. Sharing the principal's
    // physical store must not project that AI's messages into another AI view.
    // Unbound legacy rows stay read-only; current selection is not evidence
    // from which to invent their original recipient.
    .filter((message) => message.conversationBinding == null
      || message.conversationBinding.localDelegateId === subject.delegateId);
}

function deduplicateMessages(messages) {
  const byKey = new Map();
  for (const message of messages) {
    const key = `${message.direction}\0${message.localMessageId}\0${message.clientMessageId}`;
    const previous = byKey.get(key);
    if (previous && stableJson(previous) !== stableJson(message)) {
      fail("neutral_host_workbench_message_conflict");
    }
    byKey.set(key, message);
  }
  return [...byKey.values()];
}

function normalizeContacts(value, subject) {
  const contacts = array(value, "neutral_host_workbench_contacts_invalid").map((item) => {
    record(item, "neutral_host_workbench_contact_invalid");
    const principalId = optionalSafeId(item.principalId);
    const hellolynkId = safeHelloLynkId(item.hellolynkId, "neutral_host_workbench_contact_hellolynk_id_invalid");
    const instances = array(item.instances ?? [], "neutral_host_workbench_contact_instances_invalid").map((instance) => {
      record(instance, "neutral_host_workbench_contact_instance_invalid");
      if (principalId == null) fail("neutral_host_workbench_contact_instance_principal_required");
      const delegateId = safeId(instance.delegateId, "neutral_host_workbench_contact_instance_invalid");
      const region = subject.region === "international" ? "intl" : subject.region;
      const conversationKey = instanceConversationKey(normalizeInstanceConversationBinding({
        schemaVersion: 1, region, localPrincipalId: subject.principalId,
        localDelegateId: subject.delegateId, peerPrincipalId: principalId, peerDelegateId: delegateId,
      }, { region: subject.region, principalId: subject.principalId }));
      return {
        delegateId,
        clientType: oneOf(instance.clientType, CLIENT_TYPES, "neutral_host_workbench_contact_instance_invalid"),
        displayName: text(instance.displayName, 120, "neutral_host_workbench_contact_instance_invalid"),
        createdAt: isoTimestamp(instance.createdAt, "neutral_host_workbench_contact_instance_invalid"),
        updatedAt: isoTimestamp(instance.updatedAt, "neutral_host_workbench_contact_instance_invalid"),
        autonomousSendAuthorized: item.autonomousSendAuthorized === true && instance.autonomousSendAuthorized === true,
        continuousReadAuthorized: true,
        conversationKey,
      };
    }).filter((instance) => principalId !== subject.principalId
      || instance.delegateId !== subject.delegateId);
    return {
      contactId: safeId(item.contactId, "neutral_host_workbench_contact_id_invalid"),
      principalId,
      hellolynkId,
      displayName: text(item.displayName, 160, "neutral_host_workbench_contact_label_invalid"),
      autonomousSendAuthorized: item.autonomousSendAuthorized === true,
      continuousReadAuthorized: true,
      instances,
      updatedAt: isoTimestamp(item.updatedAt, "neutral_host_workbench_contact_time_invalid"),
    };
  });
  contacts.sort((left, right) => compareText(left.displayName, right.displayName)
    || compareText(left.contactId, right.contactId));
  assertUnique(contacts, (item) => item.contactId, "neutral_host_workbench_contact_conflict");
  for (const contact of contacts) assertUnique(contact.instances, (item) => item.delegateId,
    "neutral_host_workbench_contact_instance_conflict");
  return contacts;
}

function normalizeContactRequests(value, subject) {
  const requests = array(value, "neutral_host_workbench_contact_requests_invalid").map((item) => {
    record(item, "neutral_host_workbench_contact_request_invalid");
    if (item.humanOnly !== true || (item.modelVisibility != null && item.modelVisibility !== "none")) {
      fail("neutral_host_workbench_contact_request_visibility_invalid");
    }
    const sender = item.sender && typeof item.sender === "object" ? item.sender : item;
    const direction = oneOf(
      item.direction ?? "incoming",
      new Set(["incoming", "outgoing"]),
      "neutral_host_workbench_contact_request_direction_invalid",
    );
    const other = item.otherPrincipal && typeof item.otherPrincipal === "object"
      ? item.otherPrincipal
      : sender;
    const state = oneOf(
      item.state ?? item.status,
      CONTACT_REQUEST_STATES,
      "neutral_host_workbench_contact_request_state_invalid",
    );
    const hasDecisionOutcome = Object.hasOwn(item, "decisionOutcome");
    const hasDecisionAction = Object.hasOwn(item, "decisionAction");
    if (hasDecisionOutcome !== hasDecisionAction) {
      fail("neutral_host_workbench_contact_request_decision_invalid");
    }
    const decisionOutcome = hasDecisionOutcome
      ? item.decisionOutcome
      : null;
    const decisionAction = hasDecisionAction ? item.decisionAction : null;
    const actionReady = hasDecisionOutcome ? item.actionReady === true : false;
    if ((hasDecisionOutcome && typeof item.actionReady !== "boolean")
      || !new Set([null, "unknown", "recovery-required"]).has(decisionOutcome)
      || (decisionAction != null && !new Set(["accept", "reject", "block"]).has(decisionAction))
      || (actionReady && (state !== "pending"
        || decisionOutcome != null
        || decisionAction != null))
      || (state !== "pending" && actionReady)
      || ((decisionOutcome === "unknown") !== (decisionAction != null))
      || (decisionOutcome != null && (state !== "pending" || actionReady))
    ) {
      fail("neutral_host_workbench_contact_request_decision_invalid");
    }
    return {
      requestId: safeId(
        item.serverContactRequestId ?? item.requestId ?? item.localRecordId,
        "neutral_host_workbench_contact_request_id_invalid",
      ),
      senderHelloLynkId: safeHelloLynkId(
        direction === "incoming"
          ? (sender.hellolynkId ?? item.senderHelloLynkId ?? other.hellolynkId)
          : subject.hellolynkId,
        "neutral_host_workbench_contact_request_sender_invalid",
      ),
      senderLabel: optionalText(
        direction === "incoming"
          ? (sender.verifiedDisplayName ?? item.senderLabel
            ?? item.senderPrincipalDisplayName ?? other.displayName)
          : subject.principalLabel,
        160,
        "neutral_host_workbench_contact_request_label_invalid",
      ),
      direction,
      otherHelloLynkId: safeHelloLynkId(
        other.hellolynkId ?? item.otherHelloLynkId ?? item.senderHelloLynkId,
        "neutral_host_workbench_contact_request_sender_invalid",
      ),
      otherLabel: optionalText(
        other.displayName ?? other.verifiedDisplayName ?? item.otherLabel
          ?? item.senderLabel ?? item.senderPrincipalDisplayName,
        160,
        "neutral_host_workbench_contact_request_label_invalid",
      ),
      state,
      actionReady,
      decisionOutcome,
      decisionAction,
      humanOnly: true,
      ...(item.introText == null ? {} : {
        introText: text(item.introText, 80, "neutral_host_workbench_contact_request_intro_invalid", true),
      }),
      receivedAt: isoTimestamp(
        item.receivedAt ?? item.createdAt,
        "neutral_host_workbench_contact_request_time_invalid",
      ),
    };
  });
  requests.sort((left, right) => compareText(right.receivedAt, left.receivedAt)
    || compareText(left.requestId, right.requestId));
  assertUnique(requests, (item) => item.requestId, "neutral_host_workbench_contact_request_conflict");
  return requests;
}

function normalizeRelationships(value) {
  const relationships = array(value, "neutral_host_workbench_relationships_invalid")
    .map((item) => {
      record(item, "neutral_host_workbench_relationship_invalid");
      const other = record(
        item.otherPrincipal,
        "neutral_host_workbench_relationship_invalid",
      );
      const status = oneOf(
        item.status,
        new Set(["active", "ended"]),
        "neutral_host_workbench_relationship_status_invalid",
      );
      const endedAt = item.endedAt == null
        ? null
        : isoTimestamp(item.endedAt, "neutral_host_workbench_relationship_time_invalid");
      if ((status === "active") !== (endedAt == null)) {
        fail("neutral_host_workbench_relationship_status_invalid");
      }
      return {
        relationshipId: safeId(
          item.relationshipId,
          "neutral_host_workbench_relationship_id_invalid",
        ),
        otherHelloLynkId: safeHelloLynkId(
          other.hellolynkId,
          "neutral_host_workbench_relationship_peer_invalid",
        ),
        otherLabel: optionalText(
          other.displayName,
          160,
          "neutral_host_workbench_relationship_peer_invalid",
        ),
        status,
        createdAt: isoTimestamp(
          item.createdAt,
          "neutral_host_workbench_relationship_time_invalid",
        ),
        updatedAt: isoTimestamp(
          item.updatedAt,
          "neutral_host_workbench_relationship_time_invalid",
        ),
        endedAt,
      };
    });
  relationships.sort((left, right) => compareText(right.updatedAt, left.updatedAt)
    || compareText(left.relationshipId, right.relationshipId));
  assertUnique(
    relationships,
    (item) => item.relationshipId,
    "neutral_host_workbench_relationship_conflict",
  );
  return relationships;
}

function normalizeBlocks(value) {
  const blocks = array(value, "neutral_host_workbench_blocks_invalid").map((item) => {
    record(item, "neutral_host_workbench_block_invalid");
    const other = record(item.otherPrincipal, "neutral_host_workbench_block_invalid");
    if (item.status !== "active") fail("neutral_host_workbench_block_status_invalid");
    return {
      blockId: safeId(item.blockId, "neutral_host_workbench_block_id_invalid"),
      otherHelloLynkId: safeHelloLynkId(
        other.hellolynkId,
        "neutral_host_workbench_block_peer_invalid",
      ),
      otherLabel: optionalText(
        other.displayName,
        160,
        "neutral_host_workbench_block_peer_invalid",
      ),
      status: "active",
      createdAt: isoTimestamp(item.createdAt, "neutral_host_workbench_block_time_invalid"),
    };
  });
  blocks.sort((left, right) => compareText(right.createdAt, left.createdAt)
    || compareText(left.blockId, right.blockId));
  assertUnique(blocks, (item) => item.blockId, "neutral_host_workbench_block_conflict");
  return blocks;
}

function normalizeOutbox(value, subject) {
  const rawByMessageKey = new Map();
  for (const item of array(value, "neutral_host_workbench_outbox_invalid")) {
    if (!item || typeof item !== "object" || Array.isArray(item)
      || (item.direction ?? "outgoing") !== "outgoing") continue;
    if (item.senderPrincipalId !== subject.principalId) continue;
    const localMessageId = safeId(
      item.localMessageId ?? item.id,
      "neutral_host_workbench_message_id_invalid",
    );
    const clientMessageId = safeId(
      item.clientMessageId ?? item.id,
      "neutral_host_workbench_message_id_invalid",
    );
    rawByMessageKey.set(`${localMessageId}\0${clientMessageId}`, item);
  }
  const outbox = normalizeMessages(value, subject, "outbox").map((message) => {
    const raw = rawByMessageKey.get(`${message.localMessageId}\0${message.clientMessageId}`);
    if (!raw) fail("neutral_host_workbench_outbox_invalid");
    const status = message.status;
    const unknown = status === "delivery_state_unknown" || status === "unknown";
    const retryAllowed = !unknown
      && message.conversationBinding != null
      && message.conversationBinding.localDelegateId === subject.delegateId
      && MANUAL_RETRYABLE_OUTBOX_STATUSES.has(status)
      && raw.senderPrincipalId === subject.principalId
      && raw.senderDelegateId === subject.delegateId
      && raw.lastErrorCode !== "reply_target_deleted"
      && raw.retryAllowed !== false;
    return {
      clientMessageId: message.clientMessageId,
      threadId: messageThreadId(subject, message),
      recipientHelloLynkId: message.peerHelloLynkId,
      localDelegateId: message.conversationBinding?.localDelegateId ?? null,
      recipientDelegateId: message.conversationBinding?.peerDelegateId ?? null,
      text: message.text,
      status,
      retryAllowed,
      errorCategory: raw.lastErrorCode === "reply_target_deleted" && raw.resendClientMessageId
        ? "reply_target_deleted_resent" : redactErrorCategory(raw?.errorCategory ?? raw?.lastErrorCode, status),
      createdAt: message.createdAt,
      updatedAt: message.updatedAt,
    };
  });
  outbox.sort((left, right) => compareText(right.updatedAt, left.updatedAt)
    || compareText(left.clientMessageId, right.clientMessageId));
  assertUnique(outbox, (item) => item.clientMessageId, "neutral_host_workbench_outbox_conflict");
  return outbox;
}

function buildThreads(messages, contactByHelloLynkId, subject) {
  const threadMap = new Map();
  const fallbackLabels = new Map();
  const projectedMessages = [];
  for (const message of messages) {
    const binding = message.conversationBinding;
    const threadId = messageThreadId(subject, message);
    if (message.senderDelegateFallbackLabel != null) {
      fallbackLabels.set(threadId, message.senderDelegateFallbackLabel);
    }
    const candidateContact = message.peerHelloLynkId == null ? null : contactByHelloLynkId.get(message.peerHelloLynkId) ?? null;
    const contact = binding && candidateContact?.principalId != null
      && candidateContact.principalId !== binding.peerPrincipalId ? null : candidateContact;
    const instance = binding == null ? null : contact?.instances.find((item) => item.delegateId === binding.peerDelegateId);
    let thread = threadMap.get(threadId);
    if (!thread) {
      thread = {
        threadId,
        conversationKind: binding == null ? "legacy" : "instance",
        localDelegateId: binding?.localDelegateId ?? null,
        peerDelegateId: binding?.peerDelegateId ?? null,
        contactId: contact?.contactId ?? null,
        peerPrincipalId: message.peerPrincipalId,
        peerHelloLynkId: message.peerHelloLynkId,
        displayName: contact?.displayName
          ?? (message.direction === "incoming" ? message.senderPrincipalDisplayName : null)
          ?? message.peerHelloLynkId
          ?? message.peerPrincipalId,
        delegateLabel: instance?.displayName ?? (message.direction === "incoming" ? message.senderDelegateDisplayName : null),
        lastMessage: null,
        unreadCount: 0,
        updatedAt: message.updatedAt,
      };
      threadMap.set(threadId, thread);
    } else {
      mergePeerIdentity(thread, message);
      if (thread.contactId == null && contact) {
        thread.contactId = contact.contactId;
        thread.displayName = contact.displayName;
      }
      if (thread.delegateLabel == null && message.direction === "incoming" && message.senderDelegateDisplayName != null) {
        thread.delegateLabel = message.senderDelegateDisplayName;
      }
    }
    if (message.direction === "incoming" && message.unread) thread.unreadCount += 1;
    const candidate = {
      text: message.text,
      direction: message.direction,
      status: message.status,
      createdAt: message.createdAt,
    };
    if (!thread.lastMessage
      || compareText(candidate.createdAt, thread.lastMessage.createdAt) > 0
      || (candidate.createdAt === thread.lastMessage.createdAt
        && compareText(message.localMessageId, thread.lastMessageId) > 0)) {
      thread.lastMessage = candidate;
      thread.lastMessageId = message.localMessageId;
    }
    if (compareText(message.updatedAt, thread.updatedAt) > 0) thread.updatedAt = message.updatedAt;
    projectedMessages.push({
      localMessageId: message.localMessageId,
      clientMessageId: message.clientMessageId,
      threadId,
      direction: message.direction,
      senderPrincipalId: message.senderPrincipalId,
      senderDelegateId: message.senderDelegateId,
      intentSource: message.intentSource,
      authorizationScope: message.authorizationScope,
      text: message.text,
      status: message.status,
      ...(message.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}),
      unread: message.unread,
      createdAt: message.createdAt,
      updatedAt: message.updatedAt,
    });
  }
  // Saved target instances are selectable before the first message. This
  // explicit current selection never supplies missing identities to old rows.
  for (const contact of contactByHelloLynkId.values()) {
    if (contact.principalId == null) continue;
    const region = subject.region === "international" ? "intl" : subject.region;
    if (contact.hellolynkId.split(":")[1] !== region) continue;
    for (const instance of contact.instances) {
      const binding = normalizeInstanceConversationBinding({
        schemaVersion: 1,
        region,
        localPrincipalId: subject.principalId,
        localDelegateId: subject.delegateId,
        peerPrincipalId: contact.principalId,
        peerDelegateId: instance.delegateId,
      }, { region: subject.region, principalId: subject.principalId });
      const threadId = instanceConversationKey(binding);
      if (threadMap.has(threadId)) continue;
      threadMap.set(threadId, {
        threadId,
        conversationKind: "instance",
        localDelegateId: binding.localDelegateId,
        peerDelegateId: binding.peerDelegateId,
        contactId: contact.contactId,
        peerPrincipalId: contact.principalId,
        peerHelloLynkId: contact.hellolynkId,
        displayName: contact.displayName,
        delegateLabel: instance.displayName,
        lastMessage: null,
        unreadCount: 0,
        updatedAt: instance.updatedAt,
      });
    }
  }
  const threads = [...threadMap.values()].map(({ lastMessageId: _ignored, ...thread }) => ({
    ...thread,
    // Apply local display metadata only after inspecting all stored messages,
    // so an earlier missing label never overrides a later sender-provided name.
    delegateLabel: thread.delegateLabel ?? fallbackLabels.get(thread.threadId) ?? null,
  }));
  threads.sort((left, right) => compareText(right.updatedAt, left.updatedAt)
    || compareText(left.threadId, right.threadId));
  projectedMessages.sort((left, right) => compareText(left.createdAt, right.createdAt)
    || compareText(left.localMessageId, right.localMessageId));
  return { threads, messages: projectedMessages };
}

function mergePeerIdentity(thread, message) {
  if (thread.peerPrincipalId != null && message.peerPrincipalId != null
    && thread.peerPrincipalId !== message.peerPrincipalId) {
    fail("neutral_host_workbench_thread_identity_conflict");
  }
  if (thread.peerHelloLynkId != null && message.peerHelloLynkId != null
    && thread.peerHelloLynkId !== message.peerHelloLynkId) {
    fail("neutral_host_workbench_thread_identity_conflict");
  }
  thread.peerPrincipalId ??= message.peerPrincipalId;
  thread.peerHelloLynkId ??= message.peerHelloLynkId;
}

function stableThreadId(subject, peerPrincipalId, peerHelloLynkId) {
  requirePeer(peerPrincipalId, peerHelloLynkId);
  const peerKey = peerHelloLynkId == null ? `principal:${peerPrincipalId}` : `hellolynk:${peerHelloLynkId}`;
  const region = subject.region === "international" ? "intl" : subject.region;
  return `thread_${digest(`${region}\0${subject.principalId}\0${peerKey}`).slice(0, 40)}`;
}

function messageThreadId(subject, message) {
  return message.conversationBinding == null
    ? stableThreadId(subject, message.peerPrincipalId, message.peerHelloLynkId)
    : instanceConversationKey(message.conversationBinding);
}

function filterThreads(threads, messages, query, filter, indexedMatches = null) {
  const tokens = query.split(/\s+/u).filter(Boolean);
  const textByThread = new Map();
  for (const message of messages) {
    const values = textByThread.get(message.threadId) ?? [];
    values.push(message.text);
    textByThread.set(message.threadId, values);
  }
  return threads.filter((thread) => {
    if (filter === "archived" ? thread.archived !== true : thread.archived === true) return false;
    if (filter === "unread" && thread.unreadCount === 0) return false;
    if (tokens.length === 0) return true;
    if (indexedMatches?.has(thread.threadId)) return true;
    const haystack = normalizeSearchText([
      thread.displayName,
      thread.peerPrincipalId ?? "",
      thread.peerHelloLynkId ?? "",
      thread.delegateLabel ?? "",
      thread.lastMessage?.text ?? "",
      ...(textByThread.get(thread.threadId) ?? []),
    ].join("\n"));
    return tokens.every((token) => haystack.includes(token));
  });
}

function encodeIndexedMessageCursor(direction, message, fingerprint) {
  const anchor = Buffer.from(JSON.stringify({ createdAt: message.createdAt,
    localMessageId: message.localMessageId }), "utf8").toString("base64url");
  return `wbc3.m.${direction}.${anchor}.${fingerprint}`;
}

function decodeIndexedMessageCursor(value, fingerprint) {
  if (value == null) return null;
  const match = /^wbc3\.m\.(before|after|from|older-window|newer-window)\.([A-Za-z0-9_-]{8,512})\.([a-f0-9]{24})$/.exec(value);
  if (!match || match[3] !== fingerprint) fail("neutral_host_workbench_cursor_invalid");
  let anchor;
  try { anchor = JSON.parse(Buffer.from(match[2], "base64url").toString("utf8")); }
  catch { fail("neutral_host_workbench_cursor_invalid"); }
  exactRecord(anchor, ["createdAt", "localMessageId"], "neutral_host_workbench_cursor_invalid");
  return { direction: match[1], anchor: {
    createdAt: isoTimestamp(anchor.createdAt, "neutral_host_workbench_cursor_invalid"),
    localMessageId: safeId(anchor.localMessageId, "neutral_host_workbench_cursor_invalid"),
  } };
}

function normalizeQuery(value) {
  if (typeof value !== "string" || value.length > HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH || UNSAFE_TEXT.test(value)) {
    fail("neutral_host_workbench_query_invalid");
  }
  return normalizeSearchText(value).replace(/\s+/gu, " ");
}

function normalizeSearchText(value) {
  return String(value).normalize("NFKC").trim().toLocaleLowerCase("und");
}

function encodeCursor(kind, offset, fingerprint) {
  return `wbc1.${kind}.${offset}.${fingerprint}`;
}

function decodeCursor(value, kind, fingerprint, maximum) {
  if (value == null) return 0;
  const match = /^wbc1\.([tm])\.(0|[1-9][0-9]{0,8})\.([a-f0-9]{24})$/.exec(value);
  if (!match || match[1] !== kind || match[3] !== fingerprint) {
    fail("neutral_host_workbench_cursor_invalid");
  }
  const offset = Number(match[2]);
  if (!Number.isSafeInteger(offset) || offset <= 0 || offset >= maximum) {
    fail("neutral_host_workbench_cursor_invalid");
  }
  return offset;
}

function cursorFingerprint(value) {
  return digest(stableJson(value)).slice(0, 24);
}

function normalizeCapabilities(value) {
  const input = value == null ? DEFAULT_CAPABILITIES : array(value, "neutral_host_workbench_capabilities_invalid");
  const normalized = [...new Set(input.map((item) => {
    if (typeof item !== "string" || !CAPABILITIES.has(item)) {
      fail("neutral_host_workbench_capability_invalid");
    }
    return item;
  }))].sort();
  return deepFreeze(normalized);
}

function normalizeConnectedClients(value) {
  const clients = array(value, "neutral_host_workbench_clients_invalid").map((item) => {
    exactRecord(
      item,
      ["clientId", "clientType", "state"],
      "neutral_host_workbench_client_invalid",
    );
    return {
      clientId: safeId(item.clientId, "neutral_host_workbench_client_invalid"),
      clientType: oneOf(item.clientType, CLIENT_TYPES, "neutral_host_workbench_client_invalid"),
      state: oneOf(item.state, CLIENT_STATES, "neutral_host_workbench_client_invalid"),
    };
  });
  clients.sort((left, right) => compareText(left.clientId, right.clientId));
  assertUnique(clients, (item) => item.clientId, "neutral_host_workbench_client_conflict");
  return clients;
}

function normalizeEventTypes(value) {
  const result = [...new Set(array(value, "neutral_host_workbench_event_types_invalid")
    .map((item) => errorCode(item, "neutral_host_workbench_event_type_invalid")))].sort();
  if (result.length > 64) fail("neutral_host_workbench_event_types_invalid");
  return result;
}

function normalizeChangeCursor(value) {
  const result = String(value ?? "0");
  if (!SAFE_REVISION.test(result)) fail("neutral_host_workbench_change_cursor_invalid");
  return result;
}

function deterministicGeneratedAt(baseline, ...collections) {
  let latest = baseline;
  for (const collection of collections) {
    for (const item of collection) {
      const candidate = item.updatedAt ?? item.receivedAt ?? item.createdAt;
      if (candidate != null && compareText(candidate, latest) > 0) latest = candidate;
    }
  }
  return latest;
}

function redactErrorCategory(value, status) {
  if (value === "reply_target_deleted") return "reply_target_deleted";
  if (["e2ee_envelope_expired", "e2ee_created_at_in_future"].includes(value)) return "message_time";
  if (value === "e2ee_peer_identity_pin_mismatch") return "device_identity_changed";
  if (value === "e2ee_recipient_external_contact_disabled") return "external_contact_disabled";
  const normalized = `${String(value || "")} ${status}`.trim().toLocaleLowerCase("und");
  if (!normalized) return null;
  if (/e2ee_request_timeout|e2ee_transport_error/u.test(normalized)) return "connectivity";
  if (/e2ee|encrypt|decrypt|key/u.test(normalized)) return "encryption";
  if (/auth|scope|permission|forbid/u.test(normalized)) return "authorization";
  if (/rate|thrott/u.test(normalized)) return "rate_limit";
  if (/offline|network|timeout|unavailable|connect/u.test(normalized)) return "connectivity";
  if (/input|invalid|payload|recipient|not_found/u.test(normalized)) return "validation";
  return "delivery";
}

function requirePeer(principalId, hellolynkId) {
  if (principalId == null && hellolynkId == null) fail("neutral_host_workbench_peer_identity_missing");
}

function optionalSafeId(value) {
  return value == null ? null : safeId(value, "neutral_host_workbench_id_invalid");
}

function normalizeMessageProvenance(authorizationScope, intentSource) {
  if (authorizationScope == null && intentSource == null) {
    return { authorizationScope: null, intentSource: null };
  }
  if (
    authorizationScope !== MESSAGE_AUTHORIZATION_SCOPE
    || !MESSAGE_INTENT_SOURCES.has(intentSource)
  ) fail("neutral_host_workbench_message_provenance_invalid");
  return { authorizationScope, intentSource };
}

function optionalHelloLynkId(value) {
  return value == null ? null : safeHelloLynkId(value, "neutral_host_workbench_hellolynk_id_invalid");
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function safeRevision(value, code) {
  if (typeof value !== "string" || !SAFE_REVISION.test(value)) fail(code);
  return value;
}

function safeMessageCursor(value) {
  if (typeof value !== "string" || value.length > 800 || !/^[A-Za-z0-9._-]+$/.test(value)) {
    fail("neutral_host_workbench_message_cursor_invalid");
  }
  return value;
}

function contactRequestCursor(value, code) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{20,512}$/.test(value)) fail(code);
  return value;
}

function safeHelloLynkId(value, code) {
  if (typeof value !== "string" || !HELLOLYNK_ID.test(value)) fail(code);
  return value;
}

function text(value, maximum, code, emptyAllowed = false) {
  if (typeof value !== "string" || (!emptyAllowed && !value)
    || [...value].length > maximum || value.includes("\u0000")) {
    fail(code);
  }
  return value;
}

function optionalText(value, maximum, code) {
  return value == null ? null : text(value, maximum, code);
}

function errorCode(value, code) {
  const normalized = String(value || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,126}$/.test(normalized)) fail(code);
  return normalized;
}

function isoTimestamp(value, code) {
  const time = value instanceof Date ? value.getTime() : Date.parse(String(value || ""));
  if (!Number.isFinite(time)) fail(code);
  return new Date(time).toISOString();
}

function exactRecord(value, allowedKeys, code) {
  record(value, code);
  const keys = Object.keys(value).sort();
  const accepted = [...allowedKeys].sort();
  if (keys.some((key) => !accepted.includes(key))) fail(code);
  return value;
}

function record(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value;
}

function array(value, code) {
  if (!Array.isArray(value)) fail(code);
  return value;
}

function oneOf(value, allowed, code) {
  if (!allowed.has(value)) fail(code);
  return value;
}

function assertUnique(items, keyOf, code) {
  const seen = new Set();
  for (const item of items) {
    const key = keyOf(item);
    if (seen.has(key)) fail(code);
    seen.add(key);
  }
}

function assertNoSensitiveKeys(value, seen = new Set(), path = []) {
  if (!value || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  for (const [key, nested] of Object.entries(value)) {
    const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
    const exactMessageAuthorizationScope = key === "authorizationScope"
      && path.length === 3
      && path[0] === "messages"
      && path[1] === "items"
      && /^(0|[1-9][0-9]*)$/.test(path[2])
      && (nested == null || nested === MESSAGE_AUTHORIZATION_SCOPE);
    if (!exactMessageAuthorizationScope && (
      (normalized.startsWith("authorization") && normalized !== "authorizationversion")
      || /(bearer|cookie|password|privatekey|secret|token|credential)/u.test(normalized)
    )) {
      fail("neutral_host_workbench_sensitive_field_forbidden");
    }
    assertNoSensitiveKeys(nested, seen, [...path, key]);
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function compareText(left, right) {
  return String(left).localeCompare(String(right), "und");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function fail(code) {
  throw new HelloLynkNeutralHostWorkbenchReadModelError(code);
}
