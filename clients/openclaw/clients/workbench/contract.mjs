export const HELLOLYNK_WORKBENCH_LEGACY_SNAPSHOT_CONTRACT = "hellolynk-workbench-snapshot-v1";
export const HELLOLYNK_WORKBENCH_SNAPSHOT_V2_CONTRACT = "hellolynk-workbench-snapshot-v2";
export const HELLOLYNK_WORKBENCH_SNAPSHOT_V3_CONTRACT = "hellolynk-workbench-snapshot-v3";
export const HELLOLYNK_WORKBENCH_SNAPSHOT_V4_CONTRACT = "hellolynk-workbench-snapshot-v4";
export const HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT = "hellolynk-workbench-snapshot-v12";
export const HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION = 12;
export const HELLOLYNK_WORKBENCH_COMMAND_CONTRACT = "hellolynk-workbench-command-v6";
export const HELLOLYNK_WORKBENCH_RESULT_CONTRACT = "hellolynk-workbench-command-result-v6";
export const HELLOLYNK_WORKBENCH_READ_REQUEST_CONTRACT = "hellolynk-workbench-read-request-v1";
export const HELLOLYNK_WORKBENCH_SCHEMA_VERSION = 6;
export const HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH = 512;

export const HELLOLYNK_WORKBENCH_TRANSPORTS = Object.freeze([
  "loopback-http",
  "mcp-app-rpc",
  "cursor-webview-rpc",
  "synthetic-memory",
]);

export const HELLOLYNK_WORKBENCH_CAPABILITIES = Object.freeze([
  "block.remove",
  "blocks.read",
  "contact.authorization.manage",
  "contact.delete",
  "contact.instance.delete",
  "contact.instance.rename",
  "contact.instance.save",
  "contact.instances.list",
  "contact.save",
  "contact.rename",
  "contact-request.cancel",
  "contact-request.clear-resolved",
  "contact-request.recover-decision",
  "contact-request.respond",
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
  "search.local",
  "security.open-account",
  "security.read",
  "threads.manage-local",
  "threads.read",
]);

export const HELLOLYNK_WORKBENCH_COMMAND_TYPES = Object.freeze({
  requestSend: "message.request-send",
  getSendStatus: "message.send-status",
  markRead: "message.mark-read",
  markAllRead: "messages.mark-all-read",
  setAutoRead: "thread.set-auto-read",
  deleteRead: "message.delete-read",
  deleteSent: "message.delete-sent",
  hideThread: "thread.hide",
  restoreThread: "thread.restore",
  clearThread: "thread.clear-local",
  deleteThread: "thread.delete-local",
  deleteArchivedThreads: "thread.delete-archived-local",
  configureHistory: "history.configure",
  requestRetry: "outbox.request-retry",
  resendDeletedReply: "outbox.resend-deleted-reply",
  saveContact: "contact.save",
  renameContact: "contact.rename",
  deleteContact: "contact.delete",
  listContactInstances: "contact.instances.list",
  saveContactInstance: "contact.instance.save",
  renameContactInstance: "contact.instance.rename",
  deleteContactInstance: "contact.instance.delete",
  clearResolvedContactRequests: "contact-request.clear-resolved",
  recoverContactRequestDecision: "contact-request.recover-decision",
  respondContactRequest: "contact-request.respond",
  searchPrincipal: "principal.search",
  sendContactRequest: "contact-request.send",
  cancelContactRequest: "contact-request.cancel",
  setContactAuthorization: "contact.authorization.set",
  endRelationship: "relationship.end",
  removeBlock: "block.remove",
  openAccount: "security.open-account",
});

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/;
const COMMAND_WINDOW = /^wb5\.[a-f0-9]{32}\.([1-9][0-9]{0,15})$/;
const CAPABILITY_SET = new Set(HELLOLYNK_WORKBENCH_CAPABILITIES);
const TRANSPORT_SET = new Set(HELLOLYNK_WORKBENCH_TRANSPORTS);
const COMMAND_SET = new Set(Object.values(HELLOLYNK_WORKBENCH_COMMAND_TYPES));
const MESSAGE_DIRECTIONS = new Set(["incoming", "outgoing"]);
const HOST_STATES = new Set(["connecting", "online", "offline", "rebind-required", "error"]);
const CLIENT_STATES = new Set(["connected", "disconnected", "stale"]);
const READ_FILTERS = new Set(["all", "unread", "archived"]);
const MESSAGE_AUTHORIZATION_SCOPE = "relay.text.send";
const MESSAGE_INTENT_SOURCES = new Set([
  "hellolynk_client_explicit_send",
  "human_native_dialog",
  "human_preauthorized_contact",
]);
const MAX_SNAPSHOT_MESSAGE_ITEMS = 50_000;
const MAX_LEGACY_SNAPSHOT_MESSAGE_ITEMS = 2_000;
const SNAPSHOT_VERSION_BY_CONTRACT = new Map([
  [HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT, HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION],
]);

export class HelloLynkWorkbenchContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkWorkbenchContractError";
    this.code = code;
  }
}

export function validateWorkbenchSnapshot(value) {
  const input = record(value, "workbench_snapshot_invalid");
  assertNoSensitiveKeys(input);
  const snapshotSchemaVersion = SNAPSHOT_VERSION_BY_CONTRACT.get(input.contractId);
  if (snapshotSchemaVersion == null) fail("workbench_snapshot_contract_unsupported");
  const baseFields = [
    "contractId", "schemaVersion", "compatibility", "hostGeneration", "commandWindow", "revision", "changeCursor",
    "generatedAt", "source", "subject", "capabilities", "threads", "messages", "outbox",
    "contacts", "contactRequests", "aiReadAuthorization", "security", "changes",
  ];
  const requiredFields = snapshotSchemaVersion >= 4
    ? [...baseFields, "contactRequestNextCursor", "outgoingContactRequests", "relationships", "blocks"]
    : baseFields;
  exactOptionalKeys(input, [...requiredFields, "relationshipMetadataState", "localHistory", "inboxReadBoundary"], requiredFields,
    "workbench_snapshot_fields_invalid");
  if (input.schemaVersion !== snapshotSchemaVersion) fail("workbench_snapshot_version_unsupported");

  const compatibility = record(input.compatibility, "workbench_snapshot_compatibility_invalid");
  const source = record(input.source, "workbench_snapshot_source_invalid");
  exactKeys(compatibility, ["minReaderVersion", "commandVersion"], "workbench_snapshot_compatibility_invalid");
  exactKeys(source, ["mode", "transport", "clientId", "clientLabel"], "workbench_snapshot_source_invalid");
  const mode = oneOf(source.mode, ["neutral-host", "synthetic-preview"], "workbench_snapshot_source_invalid");
  const transport = oneOf(source.transport, HELLOLYNK_WORKBENCH_TRANSPORTS, "workbench_snapshot_transport_invalid");
  if ((mode === "synthetic-preview") !== (transport === "synthetic-memory")) {
    fail("workbench_snapshot_source_transport_mismatch");
  }
  const inputMinReaderVersion = positiveInteger(
    compatibility.minReaderVersion,
    "workbench_snapshot_compatibility_invalid",
  );
  const inputCommandVersion = positiveInteger(
    compatibility.commandVersion,
    "workbench_snapshot_compatibility_invalid",
  );
  if (inputMinReaderVersion !== snapshotSchemaVersion
    || inputCommandVersion !== HELLOLYNK_WORKBENCH_SCHEMA_VERSION) {
    fail("workbench_snapshot_compatibility_unsupported");
  }

  const snapshot = {
    contractId: HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
    compatibility: {
      minReaderVersion: HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
      commandVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    },
    hostGeneration: safeId(input.hostGeneration, "workbench_snapshot_host_generation_invalid"),
    commandWindow: input.commandWindow === null ? null : validateWorkbenchCommandWindow(input.commandWindow),
    revision: safeRevision(input.revision),
    changeCursor: safeRevision(input.changeCursor),
    generatedAt: timestamp(input.generatedAt, "workbench_snapshot_generated_at_invalid"),
    ...(Object.hasOwn(input, "inboxReadBoundary") ? { inboxReadBoundary:
      nonNegativeInteger(input.inboxReadBoundary, "workbench_snapshot_inbox_boundary_invalid") } : {}),
    source: {
      mode,
      transport,
      clientId: safeId(source.clientId, "workbench_snapshot_client_id_invalid"),
      clientLabel: text(source.clientLabel, 80, "workbench_snapshot_client_label_invalid"),
    },
    subject: validateSubject(input.subject),
    capabilities: validateCapabilities(input.capabilities),
    threads: validateThreadPage(input.threads),
    messages: validateMessagePage(input.messages, snapshotSchemaVersion),
    ...(Object.hasOwn(input, "localHistory") ? { localHistory: validateLocalHistory(input.localHistory) } : {}),
    outbox: validateOutbox(input.outbox),
    contacts: list(input.contacts, 1_000, "workbench_snapshot_contacts_invalid").map(validateContact),
    aiReadAuthorization: validateAiReadAuthorization(input.aiReadAuthorization),
    contactRequests: list(input.contactRequests, 1_000, "workbench_snapshot_contact_requests_invalid")
      .map((item) => validateContactRequest(item, snapshotSchemaVersion)),
    outgoingContactRequests: snapshotSchemaVersion >= 4
      ? list(
          input.outgoingContactRequests,
          1_000,
          "workbench_snapshot_contact_requests_invalid",
        ).map((item) => validateContactRequest(item, snapshotSchemaVersion))
      : [],
    contactRequestNextCursor: snapshotSchemaVersion >= 4 && input.contactRequestNextCursor != null
      ? contactRequestCursor(input.contactRequestNextCursor)
      : null,
    relationships: snapshotSchemaVersion >= 4
      ? list(input.relationships, 1_000, "workbench_snapshot_relationships_invalid")
        .map(validateRelationship)
      : [],
    ...(Object.hasOwn(input, "relationshipMetadataState") ? {
      relationshipMetadataState: oneOf(input.relationshipMetadataState, ["loading", "fresh", "stale"],
        "workbench_snapshot_relationship_metadata_state_invalid"),
    } : {}),
    blocks: snapshotSchemaVersion >= 4
      ? list(input.blocks, 1_000, "workbench_snapshot_blocks_invalid").map(validateBlock)
      : [],
    security: validateSecurity(input.security),
    changes: validateChanges(input.changes),
  };

  if (snapshot.contactRequests.some((item) => item.direction !== "incoming")
    || snapshot.outgoingContactRequests.some((item) => item.direction !== "outgoing")) {
    fail("workbench_snapshot_contact_request_direction_invalid");
  }

  if (snapshot.messages.threadId != null
    && !snapshot.threads.items.some((item) => item.threadId === snapshot.messages.threadId)) {
    fail("workbench_snapshot_selected_thread_missing");
  }
  if (snapshot.localHistory?.selection != null
    && snapshot.localHistory.selection.threadId !== snapshot.messages.threadId) {
    fail("workbench_history_selection_thread_mismatch");
  }
  if (snapshot.changes.cursor !== snapshot.changeCursor) fail("workbench_snapshot_cursor_mismatch");
  return deepFreeze(snapshot);
}

export function validateWorkbenchReadRequest(value = {}) {
  const input = record(value, "workbench_read_request_invalid");
  exactOptionalKeys(
    input,
    ["threadId", "threadCursor", "messageCursor", "contactRequestCursor", "query", "filter", "historyBefore"],
    [],
    "workbench_read_request_fields_invalid",
  );
  if (Object.hasOwn(input, "historyBefore") && input.threadId == null) fail("workbench_read_history_thread_required");
  return deepFreeze({
    threadId: input.threadId == null ? null : safeId(input.threadId, "workbench_read_thread_id_invalid"),
    ...(Object.hasOwn(input, "historyBefore") ? {
      historyBefore: input.historyBefore == null ? null : timestamp(input.historyBefore, "workbench_read_history_before_invalid"),
    } : {}),
    threadCursor: input.threadCursor == null ? null : safeRevision(input.threadCursor),
    messageCursor: input.messageCursor == null ? null : messagePageCursor(input.messageCursor),
    ...(Object.hasOwn(input, "contactRequestCursor") ? {
      contactRequestCursor: input.contactRequestCursor == null
        ? null
        : contactRequestCursor(input.contactRequestCursor),
    } : {}),
    query: input.query == null ? "" : searchText(input.query),
    filter: input.filter == null ? "all" : oneOf(input.filter, [...READ_FILTERS], "workbench_read_filter_invalid"),
  });
}

export function createWorkbenchCommand(type, payload, options = {}) {
  const commandType = oneOf(type, [...COMMAND_SET], "workbench_command_type_invalid");
  const command = {
    contractId: HELLOLYNK_WORKBENCH_COMMAND_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    command: commandType,
    requestId: safeId(options.requestId, "workbench_command_request_id_invalid"),
    idempotencyKey: workbenchIdempotencyKey(options.idempotencyKey),
    expectedRevision: options.expectedRevision == null ? null : safeRevision(options.expectedRevision),
    payload: validateCommandPayload(commandType, payload),
  };
  return deepFreeze(command);
}

// A new key is created only for a new human intent. Transports must forward the
// complete key unchanged, including after a refresh, timeout or Host restart.
export function createWorkbenchIdempotencyKey(commandWindow, nonce) {
  return workbenchIdempotencyKey(`${validateWorkbenchCommandWindow(commandWindow)}.${safeId(nonce, "workbench_command_nonce_invalid")}`);
}

export function validateWorkbenchCommandWindow(value) {
  const match = typeof value === "string" ? COMMAND_WINDOW.exec(value) : null;
  if (!match || !Number.isSafeInteger(Number(match[1]))) fail("workbench_command_window_invalid");
  return value;
}

export function workbenchCommandWindowFromKey(value) {
  const key = safeId(value, "workbench_command_idempotency_key_invalid");
  const parts = key.split(".");
  validateWorkbenchCommandWindow(parts.slice(0, 3).join("."));
  safeId(parts.slice(3).join("."), "workbench_command_nonce_invalid");
  return parts.slice(0, 3).join(".");
}

function workbenchIdempotencyKey(value) {
  workbenchCommandWindowFromKey(value);
  return value;
}

export function validateWorkbenchCommand(value) {
  const input = record(value, "workbench_command_invalid");
  assertNoSensitiveKeys(input);
  exactKeys(input, [
    "contractId",
    "schemaVersion",
    "command",
    "requestId",
    "idempotencyKey",
    "expectedRevision",
    "payload",
  ], "workbench_command_fields_invalid");
  if (input.contractId !== HELLOLYNK_WORKBENCH_COMMAND_CONTRACT) fail("workbench_command_contract_unsupported");
  if (input.schemaVersion !== HELLOLYNK_WORKBENCH_SCHEMA_VERSION) fail("workbench_command_version_unsupported");
  return createWorkbenchCommand(input.command, input.payload, {
    requestId: input.requestId,
    idempotencyKey: input.idempotencyKey,
    expectedRevision: input.expectedRevision,
  });
}

export function validateWorkbenchCommandResult(value, expectedCommand = null) {
  const input = record(value, "workbench_command_result_invalid");
  assertNoSensitiveKeys(input);
  if (input.contractId !== HELLOLYNK_WORKBENCH_RESULT_CONTRACT) fail("workbench_result_contract_unsupported");
  if (input.schemaVersion !== HELLOLYNK_WORKBENCH_SCHEMA_VERSION) fail("workbench_result_version_unsupported");
  if (typeof input.ok !== "boolean") fail("workbench_command_result_invalid");
  exactKeys(
    input,
    input.ok
      ? ["contractId", "schemaVersion", "ok", "requestId", "revision", "changeCursor", "result"]
      : ["contractId", "schemaVersion", "ok", "requestId", "revision", "changeCursor", "error"],
    "workbench_command_result_fields_invalid",
  );

  const result = {
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: input.ok,
    requestId: safeId(input.requestId, "workbench_result_request_id_invalid"),
    revision: input.revision == null ? null : safeRevision(input.revision),
    changeCursor: input.changeCursor == null ? null : safeRevision(input.changeCursor),
  };
  if (input.ok) {
    result.result = validateCommandSuccessResult(input.result, expectedCommand);
  } else {
    const error = record(input.error, "workbench_command_error_invalid");
    exactKeys(error, ["code", "retryable", "outcome", "retryAfterMs", "currentRevision"], "workbench_command_error_invalid");
    result.error = {
      code: errorCode(error.code),
      retryable: boolean(error.retryable, "workbench_command_error_invalid"),
      outcome: oneOf(error.outcome, ["known-failed", "unknown"], "workbench_command_error_invalid"),
      retryAfterMs: error.retryAfterMs == null
        ? null
        : nonNegativeInteger(error.retryAfterMs, "workbench_command_error_invalid"),
      currentRevision: error.currentRevision == null ? null : safeRevision(error.currentRevision),
    };
    if (result.error.outcome === "unknown" && result.error.retryable) {
      fail("workbench_unknown_outcome_cannot_auto_retry");
    }
  }
  if (expectedCommand != null) {
    const command = oneOf(expectedCommand, [...COMMAND_SET], "workbench_command_type_invalid");
    if (result.ok) {
      const expectedKind = command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead ? "messages-marked-read"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead ? "conversation-auto-read"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply ? "deleted-reply-resend"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend
        || command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus
        ? "message-send"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances
        ? "contact-instances"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal
        ? "principal-search"
        : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest
          ? "contact-request-send"
          : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests
            ? "contact-request-clear-resolved"
              : command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent
                || command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread
                || command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread
                || command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads
                ? "local-history"
              : null;
      const actualKind = result.result.kind ?? null;
      const legacyEmptySend = command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend
        && Object.keys(result.result).length === 0;
      if (!legacyEmptySend && actualKind !== expectedKind) fail("workbench_command_result_type_mismatch");
    }
  }
  return deepFreeze(result);
}

export function hasWorkbenchCapability(snapshot, capability) {
  const validated = validateWorkbenchSnapshot(snapshot);
  return validated.capabilities.includes(String(capability));
}

function validateSubject(value) {
  const input = record(value, "workbench_snapshot_subject_invalid");
  exactKeys(input, ["region", "principalId", "principalLabel", "hellolynkId", "delegateId", "delegateLabel", "hostInstallationId", "authorizationVersion"], "workbench_snapshot_subject_invalid");
  return {
    region: safeId(input.region, "workbench_snapshot_region_invalid"),
    principalId: safeId(input.principalId, "workbench_snapshot_principal_id_invalid"),
    principalLabel: optionalText(input.principalLabel, 120, "workbench_snapshot_principal_label_invalid"),
    hellolynkId: text(input.hellolynkId, 200, "workbench_snapshot_hellolynk_id_invalid"),
    delegateId: safeId(input.delegateId, "workbench_snapshot_delegate_id_invalid"),
    delegateLabel: optionalText(input.delegateLabel, 120, "workbench_snapshot_delegate_label_invalid"),
    hostInstallationId: safeId(input.hostInstallationId, "workbench_snapshot_host_installation_id_invalid"),
    authorizationVersion: positiveInteger(input.authorizationVersion, "workbench_snapshot_authorization_version_invalid"),
  };
}

function validateCapabilities(value) {
  const capabilities = list(value, HELLOLYNK_WORKBENCH_CAPABILITIES.length, "workbench_snapshot_capabilities_invalid")
    .map((item) => {
      if (typeof item !== "string") fail("workbench_snapshot_capability_invalid");
      return item;
    });
  if (capabilities.some((item) => !CAPABILITY_SET.has(item))) fail("workbench_snapshot_capability_unknown");
  const canonical = [...new Set(capabilities)].sort();
  if (canonical.length !== capabilities.length || canonical.some((item, index) => item !== capabilities[index])) {
    fail("workbench_snapshot_capabilities_noncanonical");
  }
  return canonical;
}

function validateThreadPage(value) {
  const input = record(value, "workbench_snapshot_threads_invalid");
  exactKeys(input, ["items", "nextCursor"], "workbench_snapshot_threads_invalid");
  return {
    items: list(input.items, 1_000, "workbench_snapshot_threads_invalid").map(validateThread),
    nextCursor: input.nextCursor == null ? null : safeRevision(input.nextCursor),
  };
}

function validateThread(value) {
  const input = record(value, "workbench_snapshot_thread_invalid");
  const fields = ["threadId", "conversationKind", "localDelegateId", "peerDelegateId", "contactId", "peerPrincipalId", "peerHelloLynkId", "displayName", "delegateLabel", "lastMessage", "unreadCount", "updatedAt"];
  exactOptionalKeys(input, [...fields, "archived", "autoReadAfterAi", "recentSendFailureCount"], fields, "workbench_snapshot_thread_invalid");
  const lastMessage = input.lastMessage == null ? null : record(input.lastMessage, "workbench_snapshot_thread_invalid");
  if (lastMessage) exactKeys(lastMessage, ["text", "direction", "status", "createdAt"], "workbench_snapshot_thread_invalid");
  const thread = {
    threadId: safeId(input.threadId, "workbench_snapshot_thread_id_invalid"),
    conversationKind: oneOf(input.conversationKind, ["instance", "legacy"], "workbench_snapshot_conversation_kind_invalid"),
    localDelegateId: input.localDelegateId == null ? null : safeId(input.localDelegateId, "workbench_snapshot_delegate_id_invalid"),
    peerDelegateId: input.peerDelegateId == null ? null : safeId(input.peerDelegateId, "workbench_snapshot_delegate_id_invalid"),
    contactId: input.contactId == null ? null : safeId(input.contactId, "workbench_snapshot_contact_id_invalid"),
    peerPrincipalId: input.peerPrincipalId == null
      ? null
      : safeId(input.peerPrincipalId, "workbench_snapshot_peer_id_invalid"),
    peerHelloLynkId: input.peerHelloLynkId == null
      ? null
      : text(input.peerHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    displayName: text(input.displayName, 160, "workbench_snapshot_display_name_invalid"),
    delegateLabel: optionalText(input.delegateLabel, 120, "workbench_snapshot_delegate_label_invalid"),
    lastMessage: lastMessage == null ? null : {
      text: text(lastMessage.text, 20_480, "workbench_snapshot_message_text_invalid", true),
      direction: oneOf(lastMessage.direction, [...MESSAGE_DIRECTIONS], "workbench_snapshot_message_direction_invalid"),
      status: errorCode(lastMessage.status),
      createdAt: timestamp(lastMessage.createdAt, "workbench_snapshot_message_time_invalid"),
    },
    unreadCount: nonNegativeInteger(input.unreadCount, "workbench_snapshot_unread_count_invalid"),
    ...(Object.hasOwn(input, "recentSendFailureCount") ? { recentSendFailureCount:
      nonNegativeInteger(input.recentSendFailureCount, "workbench_snapshot_recent_failure_count_invalid") } : {}),
    ...(Object.hasOwn(input, "archived") ? { archived: boolean(input.archived, "workbench_snapshot_archived_invalid") } : {}),
    ...(Object.hasOwn(input, "autoReadAfterAi") ? { autoReadAfterAi: boolean(input.autoReadAfterAi, "workbench_snapshot_auto_read_invalid") } : {}),
    updatedAt: timestamp(input.updatedAt, "workbench_snapshot_thread_time_invalid"),
  };
  if (thread.peerPrincipalId == null && thread.peerHelloLynkId == null) {
    fail("workbench_snapshot_peer_identity_missing");
  }
  if (thread.conversationKind === "instance"
    ? !thread.localDelegateId || !thread.peerDelegateId || !thread.peerPrincipalId
    : thread.localDelegateId != null || thread.peerDelegateId != null) {
    fail("workbench_snapshot_conversation_binding_invalid");
  }
  if (thread.autoReadAfterAi === true && thread.conversationKind !== "instance") fail("workbench_snapshot_auto_read_invalid");
  if (thread.recentSendFailureCount > 5) fail("workbench_snapshot_recent_failure_count_invalid");
  return thread;
}

function validateMessagePage(value, snapshotSchemaVersion) {
  const input = record(value, "workbench_snapshot_messages_invalid");
  exactOptionalKeys(input, ["threadId", "items", "nextCursor", "previousCursor", "refreshCursor"],
    ["threadId", "items", "nextCursor"], "workbench_snapshot_messages_invalid");
  const threadId = input.threadId == null ? null : safeId(input.threadId, "workbench_snapshot_thread_id_invalid");
  const maximumItems = snapshotSchemaVersion >= 3
    ? MAX_SNAPSHOT_MESSAGE_ITEMS
    : MAX_LEGACY_SNAPSHOT_MESSAGE_ITEMS;
  const items = list(input.items, maximumItems, "workbench_snapshot_messages_invalid")
    .map((item) => validateMessage(item, snapshotSchemaVersion));
  if (threadId == null && items.length) fail("workbench_snapshot_message_thread_missing");
  if (threadId != null && items.some((item) => item.threadId !== threadId)) fail("workbench_snapshot_message_thread_mismatch");
  return { threadId, items, nextCursor: input.nextCursor == null ? null : messagePageCursor(input.nextCursor),
    ...(Object.hasOwn(input, "previousCursor") ? {
      previousCursor: input.previousCursor == null ? null : messagePageCursor(input.previousCursor),
    } : {}),
    ...(Object.hasOwn(input, "refreshCursor") ? {
      refreshCursor: input.refreshCursor == null ? null : messagePageCursor(input.refreshCursor),
    } : {}) };
}

function validateLocalHistory(value) {
  const input = record(value, "workbench_history_invalid");
  exactKeys(input, ["autoArchiveAfterHours", "archivedThreadCount", "selection"], "workbench_history_invalid");
  if (input.autoArchiveAfterHours !== null && input.autoArchiveAfterHours !== 24) fail("workbench_history_setting_invalid");
  let selection = null;
  if (input.selection != null) {
    const fields = ["totalCount", "totalBytes", "deletableCount", "deletableBytes", "retainedUnreadCount", "retainedOutgoingCount", "retainedTaskCount"];
    const source = record(input.selection, "workbench_history_selection_invalid");
    exactKeys(source, ["threadId", "before", ...fields], "workbench_history_selection_invalid");
    selection = {
      threadId: safeId(source.threadId, "workbench_history_thread_invalid"),
      before: source.before == null ? null : timestamp(source.before, "workbench_history_before_invalid"),
      ...Object.fromEntries(fields.map((field) => [field, nonNegativeInteger(source[field], "workbench_history_count_invalid")])),
    };
    if (selection.deletableCount > selection.totalCount || selection.deletableBytes > selection.totalBytes) fail("workbench_history_count_invalid");
  }
  return { autoArchiveAfterHours: input.autoArchiveAfterHours,
    archivedThreadCount: nonNegativeInteger(input.archivedThreadCount, "workbench_history_count_invalid"), selection };
}

function messagePageCursor(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{1,800}$/.test(value)) fail("workbench_message_cursor_invalid");
  return value;
}

function validateMessage(value, snapshotSchemaVersion) {
  const input = record(value, "workbench_snapshot_message_invalid");
  const legacyKeys = [
    "localMessageId", "clientMessageId", "threadId", "direction", "senderPrincipalId",
    "senderDelegateId", "text", "status", "unread", "createdAt", "updatedAt",
  ];
  if (Object.hasOwn(input, "automaticDeliveryState")) {
    if (input.direction !== "incoming" || input.automaticDeliveryState !== "expired") fail("workbench_snapshot_message_invalid");
    legacyKeys.push("automaticDeliveryState");
  }
  exactKeys(
    input,
    snapshotSchemaVersion >= 3
      ? [...legacyKeys, "intentSource", "authorizationScope"]
      : legacyKeys,
    "workbench_snapshot_message_invalid",
  );
  const authorizationScope = snapshotSchemaVersion >= 3 ? input.authorizationScope : null;
  const intentSource = snapshotSchemaVersion >= 3 ? input.intentSource : null;
  if (
    (authorizationScope == null) !== (intentSource == null)
    || (authorizationScope != null && authorizationScope !== MESSAGE_AUTHORIZATION_SCOPE)
    || (intentSource != null && !MESSAGE_INTENT_SOURCES.has(intentSource))
  ) fail("workbench_snapshot_message_provenance_invalid");
  const senderPrincipalId = snapshotSchemaVersion >= 3 && input.senderPrincipalId == null
    ? null
    : safeId(input.senderPrincipalId, "workbench_snapshot_sender_id_invalid");
  const senderDelegateId = input.senderDelegateId == null
    ? null
    : safeId(input.senderDelegateId, "workbench_snapshot_sender_delegate_id_invalid");
  if (authorizationScope != null && (senderPrincipalId == null || senderDelegateId == null)) {
    fail("workbench_snapshot_message_provenance_invalid");
  }
  return {
    localMessageId: safeId(input.localMessageId, "workbench_snapshot_message_id_invalid"),
    clientMessageId: safeId(input.clientMessageId, "workbench_snapshot_client_message_id_invalid"),
    threadId: safeId(input.threadId, "workbench_snapshot_thread_id_invalid"),
    direction: oneOf(input.direction, [...MESSAGE_DIRECTIONS], "workbench_snapshot_message_direction_invalid"),
    senderPrincipalId,
    senderDelegateId,
    intentSource,
    authorizationScope,
    text: text(input.text, 64 * 1024, "workbench_snapshot_message_text_invalid", true),
    ...(input.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}),
    status: errorCode(input.status),
    unread: boolean(input.unread, "workbench_snapshot_message_unread_invalid"),
    createdAt: timestamp(input.createdAt, "workbench_snapshot_message_time_invalid"),
    updatedAt: timestamp(input.updatedAt, "workbench_snapshot_message_time_invalid"),
  };
}

function validateOutbox(value) {
  return list(value, 2_000, "workbench_snapshot_outbox_invalid").map((item) => {
    const input = record(item, "workbench_snapshot_outbox_item_invalid");
    exactKeys(input, ["clientMessageId", "threadId", "localDelegateId", "recipientDelegateId", "recipientHelloLynkId", "text", "status", "errorCategory", "retryAllowed", "createdAt", "updatedAt"], "workbench_snapshot_outbox_item_invalid");
    return {
      clientMessageId: safeId(input.clientMessageId, "workbench_snapshot_client_message_id_invalid"),
      threadId: input.threadId == null ? null : safeId(input.threadId, "workbench_snapshot_thread_id_invalid"),
      localDelegateId: input.localDelegateId == null ? null : safeId(input.localDelegateId, "workbench_snapshot_delegate_id_invalid"),
      recipientDelegateId: input.recipientDelegateId == null ? null : safeId(input.recipientDelegateId, "workbench_snapshot_delegate_id_invalid"),
      recipientHelloLynkId: text(input.recipientHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
      text: text(input.text, 20_480, "workbench_snapshot_message_text_invalid", true),
      status: errorCode(input.status),
      errorCategory: input.errorCategory == null ? null : errorCode(input.errorCategory),
      retryAllowed: boolean(input.retryAllowed, "workbench_snapshot_outbox_retry_invalid"),
      createdAt: timestamp(input.createdAt, "workbench_snapshot_message_time_invalid"),
      updatedAt: timestamp(input.updatedAt, "workbench_snapshot_message_time_invalid"),
    };
  });
}

function validateAiReadAuthorization(value) {
  const input = record(value, "workbench_snapshot_ai_read_authorization_invalid");
  exactKeys(input, ["contactRequests"], "workbench_snapshot_ai_read_authorization_invalid");
  return {
    contactRequests: boolean(input.contactRequests, "workbench_snapshot_ai_read_authorization_invalid"),
  };
}

function validateContact(value) {
  const input = record(value, "workbench_snapshot_contact_invalid");
  exactOptionalKeys(input, ["contactId", "principalId", "hellolynkId", "displayName", "autonomousSendAuthorized", "continuousReadAuthorized", "updatedAt", "instances"], ["contactId", "hellolynkId", "displayName", "autonomousSendAuthorized", "continuousReadAuthorized", "updatedAt", "instances"], "workbench_snapshot_contact_invalid");
  return {
    contactId: safeId(input.contactId, "workbench_snapshot_contact_id_invalid"),
    principalId: input.principalId == null
      ? null
      : safeId(input.principalId, "workbench_snapshot_peer_id_invalid"),
    hellolynkId: text(input.hellolynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    displayName: text(input.displayName, 160, "workbench_snapshot_display_name_invalid"),
    autonomousSendAuthorized: boolean(input.autonomousSendAuthorized, "workbench_snapshot_contact_authorization_invalid"),
    continuousReadAuthorized: boolean(input.continuousReadAuthorized, "workbench_snapshot_ai_read_authorization_invalid"),
    instances: validateContactInstances(input.instances),
    updatedAt: timestamp(input.updatedAt, "workbench_snapshot_contact_time_invalid"),
  };
}

function validateContactInstances(value) {
  const instances = list(value, 1_000, "workbench_snapshot_contact_instances_invalid").map((value) => {
    const item = record(value, "workbench_snapshot_contact_instance_invalid");
    exactKeys(item, ["delegateId", "clientType", "displayName", "createdAt", "updatedAt", "autonomousSendAuthorized", "continuousReadAuthorized", "conversationKey"], "workbench_snapshot_contact_instance_invalid");
    return {
      delegateId: safeId(item.delegateId, "workbench_snapshot_delegate_id_invalid"),
      clientType: text(item.clientType, 80, "workbench_snapshot_client_type_invalid"),
      displayName: text(item.displayName, 160, "workbench_snapshot_display_name_invalid"),
      createdAt: timestamp(item.createdAt, "workbench_snapshot_contact_time_invalid"),
      updatedAt: timestamp(item.updatedAt, "workbench_snapshot_contact_time_invalid"),
      autonomousSendAuthorized: boolean(item.autonomousSendAuthorized, "workbench_snapshot_contact_authorization_invalid"),
      continuousReadAuthorized: boolean(item.continuousReadAuthorized, "workbench_snapshot_ai_read_authorization_invalid"),
      conversationKey: safeId(item.conversationKey, "workbench_snapshot_conversation_key_invalid"),
    };
  });
  if (new Set(instances.map((item) => item.delegateId)).size !== instances.length) fail("workbench_snapshot_contact_instances_duplicate");
  return instances;
}

function validateContactRequest(value, snapshotSchemaVersion) {
  const input = record(value, "workbench_snapshot_contact_request_invalid");
  const legacyKeys = [
    "requestId", "senderHelloLynkId", "senderLabel", "state", "humanOnly", "receivedAt",
  ];
  const decisionKeys = ["actionReady", "decisionOutcome", "decisionAction"];
  const lifecycleKeys = ["direction", "otherHelloLynkId", "otherLabel"];
  const hasDecisionFields = snapshotSchemaVersion >= 2;
  const hasLifecycleFields = snapshotSchemaVersion >= 4;
  exactOptionalKeys(
    input,
    [
      ...legacyKeys,
      ...(hasDecisionFields ? decisionKeys : []),
      ...(hasLifecycleFields ? lifecycleKeys : []),
      "introText",
    ],
    [
      ...legacyKeys,
      ...(hasDecisionFields ? decisionKeys : []),
      ...(hasLifecycleFields ? lifecycleKeys : []),
    ],
    "workbench_snapshot_contact_request_invalid",
  );
  const state = oneOf(input.state, [
    "pending", "accepted", "rejected", "cancelled", "blocked", "expired",
  ], "workbench_snapshot_contact_request_state_invalid");
  const decisionOutcome = hasDecisionFields
    ? (input.decisionOutcome === null
        ? null
        : oneOf(
            input.decisionOutcome,
            ["unknown", "recovery-required"],
            "workbench_snapshot_contact_request_decision_invalid",
          ))
    : null;
  const decisionAction = hasDecisionFields
    ? (input.decisionAction === null
        ? null
        : oneOf(
            input.decisionAction,
            ["accept", "reject", "block"],
            "workbench_snapshot_contact_request_decision_invalid",
          ))
    : null;
  const actionReady = hasDecisionFields
    ? boolean(
        input.actionReady,
        "workbench_snapshot_contact_request_decision_invalid",
      )
    : false;
  if ((actionReady && (state !== "pending"
    || decisionOutcome != null
    || decisionAction != null))
    || (state !== "pending" && actionReady)
    || ((decisionOutcome === "unknown") !== (decisionAction != null))
    || (decisionOutcome != null && (state !== "pending" || actionReady))
  ) {
    fail("workbench_snapshot_contact_request_decision_invalid");
  }
  return {
    requestId: safeId(input.requestId, "workbench_snapshot_contact_request_id_invalid"),
    direction: hasLifecycleFields
      ? oneOf(
          input.direction,
          ["incoming", "outgoing"],
          "workbench_snapshot_contact_request_direction_invalid",
        )
      : "incoming",
    otherHelloLynkId: hasLifecycleFields
      ? text(input.otherHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid")
      : text(input.senderHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    otherLabel: hasLifecycleFields
      ? optionalText(input.otherLabel, 160, "workbench_snapshot_display_name_invalid")
      : optionalText(input.senderLabel, 160, "workbench_snapshot_display_name_invalid"),
    senderHelloLynkId: text(input.senderHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    senderLabel: optionalText(input.senderLabel, 160, "workbench_snapshot_display_name_invalid"),
    state,
    actionReady,
    decisionOutcome,
    decisionAction,
    humanOnly: boolean(input.humanOnly, "workbench_snapshot_contact_request_visibility_invalid"),
    ...(Object.hasOwn(input, "introText") ? {
      introText: text(input.introText, 80, "workbench_snapshot_contact_request_intro_invalid", true),
    } : {}),
    receivedAt: timestamp(input.receivedAt, "workbench_snapshot_contact_request_time_invalid"),
  };

}

function validateRelationship(value) {
  const input = record(value, "workbench_snapshot_relationship_invalid");
  exactKeys(input, [
    "relationshipId", "otherHelloLynkId", "otherLabel", "status", "createdAt", "updatedAt", "endedAt",
  ], "workbench_snapshot_relationship_invalid");
  const status = oneOf(
    input.status,
    ["active", "ended"],
    "workbench_snapshot_relationship_status_invalid",
  );
  const endedAt = input.endedAt == null
    ? null
    : timestamp(input.endedAt, "workbench_snapshot_relationship_time_invalid");
  if ((status === "active") !== (endedAt == null)) {
    fail("workbench_snapshot_relationship_status_invalid");
  }
  return {
    relationshipId: safeId(input.relationshipId, "workbench_snapshot_relationship_id_invalid"),
    otherHelloLynkId: text(input.otherHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    otherLabel: optionalText(input.otherLabel, 160, "workbench_snapshot_display_name_invalid"),
    status,
    createdAt: timestamp(input.createdAt, "workbench_snapshot_relationship_time_invalid"),
    updatedAt: timestamp(input.updatedAt, "workbench_snapshot_relationship_time_invalid"),
    endedAt,
  };
}

function validateBlock(value) {
  const input = record(value, "workbench_snapshot_block_invalid");
  exactKeys(input, [
    "blockId", "otherHelloLynkId", "otherLabel", "status", "createdAt",
  ], "workbench_snapshot_block_invalid");
  return {
    blockId: safeId(input.blockId, "workbench_snapshot_block_id_invalid"),
    otherHelloLynkId: text(input.otherHelloLynkId, 200, "workbench_snapshot_peer_hellolynk_id_invalid"),
    otherLabel: optionalText(input.otherLabel, 160, "workbench_snapshot_display_name_invalid"),
    status: oneOf(input.status, ["active"], "workbench_snapshot_block_status_invalid"),
    createdAt: timestamp(input.createdAt, "workbench_snapshot_block_time_invalid"),
  };
}

function validateSecurity(value) {
  const input = record(value, "workbench_snapshot_security_invalid");
  exactKeys(input, ["hostStatus", "connectedClients"], "workbench_snapshot_security_invalid");
  return {
    hostStatus: oneOf(input.hostStatus, [...HOST_STATES], "workbench_snapshot_host_status_invalid"),
    connectedClients: list(input.connectedClients, 32, "workbench_snapshot_clients_invalid").map((item) => {
      const client = record(item, "workbench_snapshot_client_invalid");
      exactKeys(client, ["clientId", "clientType", "state"], "workbench_snapshot_client_invalid");
      return {
        clientId: safeId(client.clientId, "workbench_snapshot_client_id_invalid"),
        clientType: oneOf(client.clientType, ["codex", "cursor", "dsh", "openclaw", "trae-work", "workbuddy", "claude-code", "unknown"], "workbench_snapshot_client_type_invalid"),
        state: oneOf(client.state, [...CLIENT_STATES], "workbench_snapshot_client_state_invalid"),
      };
    }),
  };
}

function validateChanges(value) {
  const input = record(value, "workbench_snapshot_changes_invalid");
  exactKeys(input, ["cursor", "snapshotRequired", "eventTypes"], "workbench_snapshot_changes_invalid");
  return {
    cursor: safeRevision(input.cursor),
    snapshotRequired: boolean(input.snapshotRequired, "workbench_snapshot_changes_invalid"),
    eventTypes: list(input.eventTypes, 64, "workbench_snapshot_changes_invalid").map(errorCode),
  };
}

function validateCommandPayload(type, value) {
  const input = record(value, "workbench_command_payload_invalid");
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal) {
    exactKeys(input, ["mode", "query"], "workbench_command_payload_fields_invalid");
    const mode = oneOf(input.mode, ["hellolynk_id", "nickname"], "workbench_command_principal_search_mode_invalid");
    const query = text(input.query, 200, "workbench_command_principal_search_query_invalid");
    if (mode === "hellolynk_id" && !/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(query)) {
      fail("workbench_command_principal_search_query_invalid");
    }
    return { mode, query };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest) {
    exactKeys(input, ["targetRef", "introText"], "workbench_command_payload_fields_invalid");
    return {
      targetRef: safeId(input.targetRef, "workbench_command_contact_target_invalid"),
      introText: validateWorkbenchContactRequestIntro(input.introText),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend) {
    exactKeys(input, ["clientMessageId", "recipientHelloLynkId", "recipientDelegateId", "text"], "workbench_command_payload_fields_invalid");
    const message = text(input.text, 20_480, "workbench_command_text_invalid");
    if (new TextEncoder().encode(message).byteLength > 20_480) fail("workbench_command_text_invalid");
    return {
      clientMessageId: safeId(input.clientMessageId, "workbench_command_client_message_id_invalid"),
      recipientHelloLynkId: text(input.recipientHelloLynkId, 200, "workbench_command_recipient_invalid"),
      recipientDelegateId: safeId(input.recipientDelegateId, "workbench_command_recipient_delegate_invalid"),
      text: message,
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
    exactKeys(input, ["actionId"], "workbench_command_payload_fields_invalid");
    return { actionId: safeId(input.actionId, "workbench_command_action_id_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead) {
    exactKeys(input, ["localMessageId"], "workbench_command_payload_fields_invalid");
    return { localMessageId: safeId(input.localMessageId, "workbench_command_message_id_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead) {
    exactKeys(input, ["threadId", "beforeReceiptSeq"], "workbench_command_payload_fields_invalid");
    return { threadId: input.threadId === null ? null : safeId(input.threadId, "workbench_command_thread_id_invalid"),
      beforeReceiptSeq: nonNegativeInteger(input.beforeReceiptSeq, "workbench_command_inbox_boundary_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead) {
    exactKeys(input, ["threadId", "enabled"], "workbench_command_payload_fields_invalid");
    return { threadId: safeId(input.threadId, "workbench_command_thread_id_invalid"),
      enabled: boolean(input.enabled, "workbench_command_auto_read_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead
    || type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent) {
    exactKeys(input, ["localMessageIds"], "workbench_command_payload_fields_invalid");
    if (!Array.isArray(input.localMessageIds) || input.localMessageIds.length === 0) {
      fail("workbench_command_message_ids_invalid");
    }
    return {
      localMessageIds: list(input.localMessageIds, 500, "workbench_command_message_ids_invalid")
        .map((item) => safeId(item, "workbench_command_message_id_invalid")),
    };
  }
  if ([HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread,
    HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread,
    HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread].includes(type)) {
    exactOptionalKeys(input, type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread ? ["threadId", "before"] : ["threadId"],
      ["threadId"], "workbench_command_payload_fields_invalid");
    return { threadId: safeId(input.threadId, "workbench_command_thread_id_invalid"),
      ...(Object.hasOwn(input, "before") ? {
        before: input.before == null ? null : timestamp(input.before, "workbench_command_history_before_invalid"),
      } : {}) };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads) {
    exactKeys(input, [], "workbench_command_payload_fields_invalid"); return {};
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory) {
    exactKeys(input, ["autoArchiveAfterHours"], "workbench_command_payload_fields_invalid");
    if (input.autoArchiveAfterHours !== null && input.autoArchiveAfterHours !== 24) fail("workbench_history_setting_invalid");
    return { autoArchiveAfterHours: input.autoArchiveAfterHours };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry || type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply) {
    exactKeys(input, ["clientMessageId"], "workbench_command_payload_fields_invalid");
    return { clientMessageId: safeId(input.clientMessageId, "workbench_command_client_message_id_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact) {
    exactOptionalKeys(
      input,
      ["contactId", "hellolynkId", "displayName"],
      ["hellolynkId", "displayName"],
      "workbench_command_payload_fields_invalid",
    );
    const contactId = input.contactId == null ? null : safeId(input.contactId, "workbench_command_contact_id_invalid");
    return {
      contactId,
      hellolynkId: text(input.hellolynkId, 200, "workbench_command_recipient_invalid"),
      displayName: text(input.displayName, 160, "workbench_command_contact_name_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact) {
    exactKeys(input, ["contactId", "displayName", "expectedDisplayName", "expectedHelloLynkId"], "workbench_command_payload_fields_invalid");
    return {
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      displayName: text(input.displayName, 160, "workbench_command_contact_name_invalid"),
      expectedDisplayName: text(input.expectedDisplayName, 160, "workbench_command_contact_name_invalid"),
      expectedHelloLynkId: text(input.expectedHelloLynkId, 200, "workbench_command_recipient_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances
    || type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact) {
    exactKeys(input, ["contactId"], "workbench_command_payload_fields_invalid");
    return { contactId: safeId(input.contactId, "workbench_command_contact_id_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance) {
    exactOptionalKeys(input, ["contactId", "recipientDelegateId", "displayName"], ["contactId", "recipientDelegateId"], "workbench_command_payload_fields_invalid");
    const accepted = {
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      recipientDelegateId: safeId(input.recipientDelegateId, "workbench_command_recipient_delegate_invalid"),
    };
    if (input.displayName !== "" && Object.hasOwn(input, "displayName")) {
      accepted.displayName = text(input.displayName, 80, "workbench_command_contact_name_invalid");
    }
    return accepted;
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance) {
    exactKeys(input, ["contactId", "recipientDelegateId", "displayName", "expectedDisplayName", "expectedHelloLynkId", "expectedPrincipalId"], "workbench_command_payload_fields_invalid");
    return {
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      recipientDelegateId: safeId(input.recipientDelegateId, "workbench_command_recipient_delegate_invalid"),
      displayName: text(input.displayName, 80, "workbench_command_contact_name_invalid"),
      expectedDisplayName: text(input.expectedDisplayName, 80, "workbench_command_contact_name_invalid"),
      expectedHelloLynkId: text(input.expectedHelloLynkId, 200, "workbench_command_recipient_invalid"),
      expectedPrincipalId: safeId(input.expectedPrincipalId, "workbench_command_principal_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance) {
    exactKeys(input, ["contactId", "recipientDelegateId"], "workbench_command_payload_fields_invalid");
    return {
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      recipientDelegateId: safeId(input.recipientDelegateId, "workbench_command_recipient_delegate_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests) {
    exactKeys(input, [], "workbench_command_payload_fields_invalid");
    return {};
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision) {
    exactKeys(input, ["requestId"], "workbench_command_payload_fields_invalid");
    return {
      requestId: safeId(input.requestId, "workbench_command_contact_request_id_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest) {
    exactKeys(input, ["requestId", "decision"], "workbench_command_payload_fields_invalid");
    return {
      requestId: safeId(input.requestId, "workbench_command_contact_request_id_invalid"),
      decision: oneOf(input.decision, ["accept", "reject", "block"], "workbench_command_contact_request_decision_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest) {
    exactKeys(input, ["requestId"], "workbench_command_payload_fields_invalid");
    return {
      requestId: safeId(input.requestId, "workbench_command_contact_request_id_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization) {
    exactKeys(input, ["contactId", "recipientDelegateId", "enabled"], "workbench_command_payload_fields_invalid");
    if (typeof input.enabled !== "boolean") fail("workbench_command_authorization_enabled_invalid");
    return {
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      recipientDelegateId: safeId(input.recipientDelegateId, "workbench_command_recipient_delegate_invalid"),
      enabled: input.enabled,
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship) {
    exactKeys(input, ["relationshipId"], "workbench_command_payload_fields_invalid");
    return {
      relationshipId: safeId(input.relationshipId, "workbench_command_relationship_id_invalid"),
    };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock) {
    exactKeys(input, ["blockId"], "workbench_command_payload_fields_invalid");
    return { blockId: safeId(input.blockId, "workbench_command_block_id_invalid") };
  }
  if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.openAccount) {
    exactKeys(input, ["target"], "workbench_command_payload_fields_invalid");
    return { target: oneOf(input.target, ["account", "devices", "keys"], "workbench_command_account_target_invalid") };
  }
  fail("workbench_command_type_invalid");
}

function validateCommandSuccessResult(value, expectedCommand) {
  const input = record(value, "workbench_command_result_invalid");
  if (Object.keys(input).length === 0) {
    // Older Hosts returned an empty success body after admitting request-send.
    // Keep parsing that result so upgraded clients can treat it as unknown,
    // while the new status command always requires an authoritative state.
    if (expectedCommand === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
      fail("workbench_command_result_type_mismatch");
    }
    return {};
  }
  if (expectedCommand == null) fail("workbench_command_result_type_required");
  if (input.kind === "messages-marked-read") {
    exactKeys(input, ["kind", "markedCount", "threadId", "beforeReceiptSeq"], "workbench_command_result_fields_invalid");
    return { kind: input.kind,
      markedCount: nonNegativeInteger(input.markedCount, "workbench_command_read_count_invalid"),
      threadId: input.threadId === null ? null : safeId(input.threadId, "workbench_command_thread_id_invalid"),
      beforeReceiptSeq: nonNegativeInteger(input.beforeReceiptSeq, "workbench_command_inbox_boundary_invalid") };
  }
  if (input.kind === "conversation-auto-read") {
    exactKeys(input, ["kind", "threadId", "enabled"], "workbench_command_result_fields_invalid");
    return { kind: input.kind, threadId: safeId(input.threadId, "workbench_command_thread_id_invalid"),
      enabled: boolean(input.enabled, "workbench_command_auto_read_invalid") };
  }
  if (input.kind === "deleted-reply-resend") {
    exactKeys(input, ["kind", "originalClientMessageId", "clientMessageId", "status"], "workbench_command_result_invalid");
    return { kind: input.kind, originalClientMessageId: safeId(input.originalClientMessageId, "workbench_command_result_invalid"),
      clientMessageId: safeId(input.clientMessageId, "workbench_command_result_invalid"),
      status: oneOf(input.status, ["sent", "not-delivered", "unknown"], "workbench_command_result_invalid") };
  }
  if (input.kind === "local-history") {
    exactOptionalKeys(input, ["kind", "deletedCount", "retainedUnreadCount", "retainedOutgoingCount", "retainedTaskCount", "deletedBytes"],
      ["kind", "deletedCount", "retainedUnreadCount", "retainedOutgoingCount"],
      "workbench_command_result_fields_invalid");
    return {
      kind: "local-history",
      deletedCount: nonNegativeInteger(input.deletedCount, "workbench_command_local_history_count_invalid"),
      retainedUnreadCount: nonNegativeInteger(input.retainedUnreadCount, "workbench_command_local_history_count_invalid"),
      retainedOutgoingCount: nonNegativeInteger(input.retainedOutgoingCount, "workbench_command_local_history_count_invalid"),
      ...Object.fromEntries(["retainedTaskCount", "deletedBytes"].filter((field) => Object.hasOwn(input, field))
        .map((field) => [field, nonNegativeInteger(input[field], "workbench_command_local_history_count_invalid")])),
    };
  }
  if (input.kind === "message-send") {
    exactKeys(input, ["kind", "actionId", "state", "code", "createdAtMs", "expiresAtMs"], "workbench_command_result_fields_invalid");
    const state = oneOf(input.state, [
      "pending", "consuming", "approved", "cancelled", "expired", "failed", "invalidated",
    ], "workbench_command_send_state_invalid");
    const code = input.code == null ? null : errorCode(input.code);
    if ((["pending", "consuming", "approved"].includes(state) && code !== null)
      || (["cancelled", "expired", "failed", "invalidated"].includes(state)
        && (code === null || !/^human_confirmation_[a-z0-9_]{1,100}$/.test(code)))) {
      fail("workbench_command_send_state_invalid");
    }
    const createdAtMs = nonNegativeInteger(input.createdAtMs, "workbench_command_send_time_invalid");
    const expiresAtMs = nonNegativeInteger(input.expiresAtMs, "workbench_command_send_time_invalid");
    if (expiresAtMs <= createdAtMs) fail("workbench_command_send_time_invalid");
    return {
      kind: "message-send",
      actionId: safeId(input.actionId, "workbench_command_action_id_invalid"),
      state,
      code,
      createdAtMs,
      expiresAtMs,
    };
  }
  if (input.kind === "contact-instances") {
    exactKeys(input, ["kind", "contactId", "principalId", "hellolynkId", "instances"], "workbench_command_result_fields_invalid");
    const instances = list(input.instances, 1_000, "workbench_command_contact_instances_invalid").map((value) => {
      const item = record(value, "workbench_command_contact_instance_invalid");
      exactOptionalKeys(item, ["delegateId", "displayName", "clientType", "status", "createdAt"],
        ["delegateId", "displayName", "clientType", "status"], "workbench_command_contact_instance_invalid");
      return {
        delegateId: safeId(item.delegateId, "workbench_command_recipient_delegate_invalid"),
        displayName: text(item.displayName, 160, "workbench_command_contact_name_invalid"),
        clientType: text(item.clientType, 80, "workbench_command_client_type_invalid"),
        status: oneOf(item.status, ["active"], "workbench_command_contact_instance_status_invalid"),
        ...(item.createdAt === undefined ? {} : { createdAt: timestamp(item.createdAt, "workbench_command_contact_instance_invalid") }),
      };
    });
    if (new Set(instances.map((item) => item.delegateId)).size !== instances.length) fail("workbench_command_contact_instances_duplicate");
    return {
      kind: "contact-instances",
      contactId: safeId(input.contactId, "workbench_command_contact_id_invalid"),
      principalId: safeId(input.principalId, "workbench_snapshot_principal_id_invalid"),
      hellolynkId: text(input.hellolynkId, 200, "workbench_command_recipient_invalid"),
      instances,
    };
  }
  if (input.kind === "principal-search") {
    exactKeys(input, ["kind", "mode", "results", "quota", "exactMatchOnly", "modelCalls"], "workbench_command_result_fields_invalid");
    const quota = record(input.quota, "workbench_command_search_quota_invalid");
    exactKeys(quota, ["limit", "remaining", "resetsAt"], "workbench_command_search_quota_invalid");
    if (input.exactMatchOnly !== true || input.modelCalls !== 0) fail("workbench_command_result_invalid");
    const acceptedQuota = {
      limit: nonNegativeInteger(quota.limit, "workbench_command_search_quota_invalid"),
      remaining: nonNegativeInteger(quota.remaining, "workbench_command_search_quota_invalid"),
      resetsAt: timestamp(quota.resetsAt, "workbench_command_search_quota_invalid"),
    };
    if (acceptedQuota.limit !== 30 || acceptedQuota.remaining > acceptedQuota.limit) {
      fail("workbench_command_search_quota_invalid");
    }
    const mode = oneOf(input.mode, ["hellolynk_id", "nickname"], "workbench_command_principal_search_mode_invalid");
    const results = list(input.results, 32, "workbench_command_search_results_invalid").map((value) => {
      const item = record(value, "workbench_command_search_result_invalid");
      exactKeys(item, ["targetRef", "displayName", "hellolynkId", "expiresAt"], "workbench_command_search_result_invalid");
      return {
        targetRef: safeId(item.targetRef, "workbench_command_contact_target_invalid"),
        displayName: optionalText(item.displayName, 160, "workbench_command_search_result_invalid"),
        hellolynkId: item.hellolynkId == null ? null : searchResultHelloLynkId(item.hellolynkId),
        expiresAt: timestamp(item.expiresAt, "workbench_command_search_result_invalid"),
      };
    });
    if (mode === "nickname" && results.some((item) => item.hellolynkId != null)) {
      fail("workbench_command_search_result_privacy_invalid");
    }
    return {
      kind: "principal-search",
      mode,
      results,
      quota: acceptedQuota,
      exactMatchOnly: true,
      modelCalls: 0,
    };
  }
  if (input.kind === "contact-request-send") {
    exactKeys(input, ["kind", "status", "quota", "serverStoredIntro", "serverStoredCiphertext", "modelCalls"], "workbench_command_result_fields_invalid");
    if (input.serverStoredIntro !== false
      || (input.serverStoredCiphertext !== null && typeof input.serverStoredCiphertext !== "boolean") || input.modelCalls !== 0) {
      fail("workbench_command_result_invalid");
    }
    let quota = null;
    if (input.quota != null) {
      const rawQuota = record(input.quota, "workbench_command_contact_request_quota_invalid");
      exactKeys(rawQuota, ["limit", "used", "remaining", "nextResetAt"], "workbench_command_contact_request_quota_invalid");
      quota = {
        limit: nonNegativeInteger(rawQuota.limit, "workbench_command_contact_request_quota_invalid"),
        used: nonNegativeInteger(rawQuota.used, "workbench_command_contact_request_quota_invalid"),
        remaining: nonNegativeInteger(rawQuota.remaining, "workbench_command_contact_request_quota_invalid"),
        nextResetAt: timestamp(rawQuota.nextResetAt, "workbench_command_contact_request_quota_invalid"),
      };
      if (quota.limit !== 3 || quota.used > quota.limit || quota.remaining > quota.limit
        || quota.used + quota.remaining !== quota.limit) {
        fail("workbench_command_contact_request_quota_invalid");
      }
    }
    return {
      kind: "contact-request-send",
      status: oneOf(input.status, ["submitted", "delivery_unknown"], "workbench_command_contact_request_status_invalid"),
      quota,
      serverStoredIntro: false,
      serverStoredCiphertext: input.serverStoredCiphertext,
      modelCalls: 0,
    };
  }
  if (input.kind === "contact-request-clear-resolved") {
    exactKeys(input, ["kind", "deletedCount", "inboundResume", "localOnly", "modelCalls"], "workbench_command_result_fields_invalid");
    if (input.localOnly !== true || input.modelCalls !== 0) fail("workbench_command_result_invalid");
    return {
      kind: "contact-request-clear-resolved",
      deletedCount: nonNegativeInteger(input.deletedCount, "workbench_command_clear_resolved_count_invalid"),
      inboundResume: oneOf(input.inboundResume, ["not_applicable", "resume_scheduled", "resume_attempted", "retry_required"], "workbench_command_clear_resolved_resume_invalid"),
      localOnly: true,
      modelCalls: 0,
    };
  }
  fail("workbench_command_result_fields_invalid");
}

export function validateWorkbenchContactRequestIntro(value) {
  if (typeof value !== "string") {
    fail("contact_request_intro_invalid");
  }
  if (value.length > 80 || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value)) {
    fail(value.length > 80 ? "contact_request_intro_too_long" : "contact_request_intro_forbidden_character");
  }
  if (/^\p{Zs}*$/u.test(value)) return "";
  let weight = 0;
  for (const codePoint of value) {
    const scalar = codePoint.codePointAt(0);
    weight += scalar >= 0x20 && scalar <= 0x7e ? 1 : 2;
    if (weight > 40) fail("contact_request_intro_too_long");
  }
  const candidate = value.normalize("NFKC").replace(/[\u3002\uFF0E\uFF61]/gu, ".");
  if (/\b(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:[/\\]|(?:https?|ftps?|wss?|file|mailto|tel|sms|data|javascript|vbscript|blob|about|intent|magnet|urn|hellolynk):\S)/iu.test(candidate)
    || /[\p{L}\p{N}\p{M}.!#$%&'*+/=?^_`{|}~-]+@[\p{L}\p{N}\p{M}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?(?:\.[\p{L}\p{N}\p{M}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?)*/iu.test(candidate)
    || /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?=$|[^a-z0-9-])/iu.test(candidate)
    || /(?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.)+(?=[\p{L}\p{N}\p{M}-]{2,63}(?=$|[^\p{L}\p{N}\p{M}-]))\p{L}(?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?(?=$|[^\p{L}\p{N}\p{M}-])/iu.test(candidate)
    || /\bwww\s*\./iu.test(candidate)
    || /(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?=$|[^0-9])/u.test(candidate)) {
    fail("contact_request_intro_link_forbidden");
  }
  return value;
}

function searchResultHelloLynkId(value) {
  const accepted = text(value, 200, "workbench_command_search_result_invalid");
  if (!/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(accepted)) {
    fail("workbench_command_search_result_invalid");
  }
  return accepted;
}

function record(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value;
}

function list(value, maximum, code) {
  if (!Array.isArray(value) || value.length > maximum) fail(code);
  return value;
}

function exactKeys(value, keys, code) {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail(code);
}

function exactOptionalKeys(value, allowed, required, code) {
  const actual = Object.keys(value);
  if (actual.some((key) => !allowed.includes(key)) || required.some((key) => !Object.hasOwn(value, key))) fail(code);
}

function assertNoSensitiveKeys(value, seen = new WeakSet(), depth = 0, path = []) {
  if (!value || typeof value !== "object") return;
  if (depth > 32 || seen.has(value)) fail("workbench_sensitive_field_invalid");
  seen.add(value);
  const forbiddenExact = new Set([
    "apikey",
    "authorization",
    "bearer",
    "bindingkey",
    "capabilitysecret",
    "cookie",
    "password",
    "privatekey",
    "secret",
    "token",
  ]);
  for (const [key, nested] of Object.entries(value)) {
    const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
    const exactMessageAuthorizationScope = key === "authorizationScope"
      && path.length === 3
      && path[0] === "messages"
      && path[1] === "items"
      && /^(0|[1-9][0-9]*)$/.test(path[2])
      && (nested == null || nested === MESSAGE_AUTHORIZATION_SCOPE);
    if (!exactMessageAuthorizationScope && (forbiddenExact.has(normalized)
      || (normalized.startsWith("authorization") && normalized !== "authorizationversion")
      || /(token|cookie|password|privatekey|bindingkey|capabilitysecret|apikey|bearer|credential)/.test(normalized))) {
      fail("workbench_sensitive_field_invalid");
    }
    assertNoSensitiveKeys(nested, seen, depth + 1, [...path, key]);
  }
}

function text(value, maximum, code, allowEmpty = false) {
  if (typeof value !== "string" || (!allowEmpty && !value.trim()) || value.length > maximum || value.includes("\u0000")) fail(code);
  return value;
}

function optionalText(value, maximum, code) {
  if (value == null || value === "") return null;
  return text(value, maximum, code);
}

function searchText(value) {
  if (typeof value !== "string" || value.length > HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH || value.includes("\u0000")) {
    fail("workbench_read_query_invalid");
  }
  // Keep Unicode unexpanded across transport validation. NFKC/lowercase can
  // expand it; downstream guards must not count that as extra user input.
  return value.trim().replace(/\s+/gu, " ");
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function safeRevision(value) {
  if (typeof value !== "string" || !SAFE_REVISION.test(value)) fail("workbench_revision_invalid");
  return value;
}

function contactRequestCursor(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{20,512}$/.test(value)) {
    fail("workbench_contact_request_cursor_invalid");
  }
  return value;
}

function errorCode(value) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_.:-]{1,126}$/.test(value)) fail("workbench_error_code_invalid");
  return value;
}

function timestamp(value, code) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) fail(code);
  return value;
}

function nonNegativeInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) fail(code);
  return value;
}

function positiveInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) fail(code);
  return value;
}

function boolean(value, code) {
  if (typeof value !== "boolean") fail(code);
  return value;
}

function oneOf(value, allowed, code) {
  if (!allowed.includes(value)) fail(code);
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function fail(code) {
  throw new HelloLynkWorkbenchContractError(code);
}
