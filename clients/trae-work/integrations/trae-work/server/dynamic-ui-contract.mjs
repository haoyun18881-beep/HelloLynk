import crypto from "node:crypto";

export const TRAE_DYNAMIC_UI_CONTRACT = "hellolynk-trae-dynamic-ui-v1";
export const TRAE_DYNAMIC_UI_VERSION = 1;
export const TRAE_DYNAMIC_UI_RENDERER = "HelloLynkTraeLocalWebV18";

const VIEWS = new Set([
  "status", "inbox", "message", "contacts", "contact", "outbox", "send", "action", "error",
]);
const STATES = new Set(["ready", "empty", "pending", "blocked"]);
const EXPOSURES = new Set(["aggregate-only", "metadata-only", "selected-record", "selected-content"]);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const HELLOLYNK_ID = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype", "html", "innerHTML", "script"]);

export function createDynamicUiEnvelope(view, state, data, options = {}) {
  if (!VIEWS.has(view)) throw codeError("trae_dynamic_ui_view_invalid");
  if (!STATES.has(state)) throw codeError("trae_dynamic_ui_state_invalid");
  const exposure = options.exposure || "metadata-only";
  if (!EXPOSURES.has(exposure)) throw codeError("trae_dynamic_ui_exposure_invalid");
  const envelope = {
    contract: TRAE_DYNAMIC_UI_CONTRACT,
    version: TRAE_DYNAMIC_UI_VERSION,
    renderer: TRAE_DYNAMIC_UI_RENDERER,
    view,
    state,
    exposure,
    component: componentFor(view),
    data: sanitizeWidgetValue({ ...data, actions: componentActions(view) }, widgetLimits(view, data, options.privateText !== true)),
  };
  return Object.freeze(envelope);
}

export function validateDynamicUiEnvelope(value) {
  if (!isPlainObject(value)) throw codeError("trae_dynamic_ui_envelope_invalid");
  assertExactKeys(value, ["contract", "version", "renderer", "view", "state", "exposure", "component", "data"]);
  if (value.contract !== TRAE_DYNAMIC_UI_CONTRACT || value.version !== TRAE_DYNAMIC_UI_VERSION
    || value.renderer !== TRAE_DYNAMIC_UI_RENDERER || !VIEWS.has(value.view)
    || !STATES.has(value.state) || !EXPOSURES.has(value.exposure)) {
    throw codeError("trae_dynamic_ui_envelope_invalid");
  }
  validateComponent(value.component, value.view);
  sanitizeWidgetValue(value.data, widgetLimits(value.view, value.data));
  return value;
}

export function sanitizeWidgetText(value, maximumBytes = 20_000) {
  return normalizeWidgetText(value, maximumBytes)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function maskHelloLynkId(value) {
  const hellolynkId = safeHelloLynkId(value);
  const region = hellolynkId.split(":")[1];
  const digest = crypto.createHash("sha256").update(hellolynkId).digest("hex").slice(0, 8);
  return `hellolynk:${region}:masked-${digest}`;
}

export function projectInboxView(raw) {
  const messages = safeArray(raw?.messages, "trae_inbox_contract_invalid");
  const items = messages.map((message) => {
    const item = plain(message, "trae_inbox_contract_invalid");
    return {
      localMessageId: safeId(item.localMessageId, "trae_inbox_contract_invalid"),
      senderPrincipalDisplayName: optionalWidgetText(item.senderPrincipalDisplayName, 320),
      senderDelegateDisplayName: optionalWidgetText(item.senderDelegateDisplayName, 320),
      peerHelloLynkIdMasked: item.peerHelloLynkId == null ? null : maskHelloLynkId(item.peerHelloLynkId),
      messageType: safeId(item.messageType, "trae_inbox_contract_invalid"),
      unread: boolean(item.unread, "trae_inbox_contract_invalid"),
      createdAt: safeTimestamp(item.createdAt, "trae_inbox_contract_invalid"),
      updatedAt: safeTimestamp(item.updatedAt, "trae_inbox_contract_invalid"),
      bodyAvailable: true,
    };
  });
  const unreadCount = items.filter((item) => item.unread).length;
  return createDynamicUiEnvelope("inbox", items.length ? "ready" : "empty", {
    counts: { total: items.length, unread: unreadCount },
    items,
    controls: {
      readMessageTool: "hellolynk_read_inbox_message",
      markReadTool: "hellolynk_mark_inbox_message_read",
      deleteReadTool: "hellolynk_delete_read_inbox_messages",
    },
  }, { exposure: "metadata-only" });
}

function componentFor(view) {
  return view === "send" ? "message-form" : view === "action" ? "message-confirm"
    : view === "status" || view === "error" ? "status-card" : "messenger-inbox";
}
function componentActions(view) {
  if (view === "inbox") return [{ id: "refresh", label: "刷新消息", type: "tool-call", tool: "hellolynk_render_inbox", params: {} }, { id: "open-detail", label: "打开消息", type: "tool-call", tool: "hellolynk_read_inbox_message", params: {} }];
  if (view === "contacts") return [{ id: "refresh-contacts", label: "刷新联系人", type: "tool-call", tool: "hellolynk_render_contacts", params: {} }];
  if (view === "outbox") return [{ id: "refresh-outbox", label: "刷新发出记录", type: "tool-call", tool: "hellolynk_render_outbox", params: {} }];
  return [];
}
function validateComponent(value, view) {
  if (value !== componentFor(view)) throw codeError("trae_dynamic_ui_envelope_invalid");
}

// Private-only dashboard payload. It is deliberately never used as
// structuredContent: internal contract tests use this model-safe projection.
// Production TRAE exposes only open/status tools; the fixed local Web UI reads
// private data directly from the neutral Host adapter over the loopback server.
export function projectPrivateInboxDashboard(inboxRaw, contactsRaw, requestsRaw, outboxRaw) {
  const messages = safeArray(inboxRaw?.messages, "trae_inbox_contract_invalid").map((item) => ({
    localMessageId: safeId(item?.localMessageId, "trae_inbox_contract_invalid"),
    peerHelloLynkId: safeHelloLynkId(item?.peerHelloLynkId),
    senderPrincipalDisplayName: optionalWidgetText(item?.senderPrincipalDisplayName, 320),
    senderDelegateDisplayName: optionalWidgetText(item?.senderDelegateDisplayName, 320),
    messageType: safeId(item?.messageType, "trae_inbox_contract_invalid"),
    text: checkedWidgetText(item?.text, 64 * 1024), unread: boolean(item?.unread, "trae_inbox_contract_invalid"),
    createdAt: safeTimestamp(item?.createdAt, "trae_inbox_contract_invalid"),
  }));
  const contacts = safeArray(contactsRaw?.contacts, "trae_contacts_contract_invalid").map((item) => ({
    contactId: safeId(item?.contactId, "trae_contacts_contract_invalid"), hellolynkId: safeHelloLynkId(item?.hellolynkId),
    displayName: checkedWidgetText(item?.displayName, 320),
    updatedAt: safeTimestamp(item?.updatedAt, "trae_contacts_contract_invalid"),
  }));
  const contactRequests = safeArray(requestsRaw?.requests, "trae_contact_requests_contract_invalid").map((item) => {
    if (item?.humanOnly !== true || item?.modelVisibility !== "none") throw codeError("trae_contact_requests_contract_invalid");
    return {
      localRecordId: safeId(item?.localRecordId, "trae_contact_requests_contract_invalid"),
      state: safeId(item?.state, "trae_contact_requests_contract_invalid"),
      introText: item?.introText == null ? null : checkedWidgetText(item.introText, 20_000),
      senderHelloLynkId: item?.sender?.hellolynkId == null ? null : safeHelloLynkId(item.sender.hellolynkId),
      senderDisplayName: item?.sender?.verifiedDisplayName == null ? null : checkedWidgetText(item.sender.verifiedDisplayName, 320),
    };
  });
  const outbox = safeArray(outboxRaw?.messages, "trae_outbox_contract_invalid").map((item) => ({
    clientMessageId: safeId(item?.clientMessageId, "trae_outbox_contract_invalid"), recipientHelloLynkId: safeHelloLynkId(item?.recipientHelloLynkId),
    text: checkedWidgetText(item?.text, 64 * 1024), status: safeId(item?.status, "trae_outbox_contract_invalid"),
    retryAllowed: boolean(item?.retryAllowed, "trae_outbox_contract_invalid"), createdAt: safeTimestamp(item?.createdAt, "trae_outbox_contract_invalid"),
  }));
  return createDynamicUiEnvelope("inbox", messages.length ? "ready" : "empty", {
    dashboard: { messages, contacts, contactRequests, outbox },
    controls: { markReadTool: "hellolynk_mark_inbox_message_read", deleteReadTool: "hellolynk_delete_read_inbox_messages", retryTool: "hellolynk_retry_outbox_message", submitTool: "hellolynk_request_human_send", saveContactTool: "hellolynk_save_contact", deleteContactTool: "hellolynk_delete_contact" },
  }, { exposure: "selected-content", privateText: true });
}

export function projectSelectedMessage(raw, localMessageId) {
  const messages = safeArray(raw?.messages, "trae_inbox_contract_invalid");
  const selected = messages.find((item) => item?.localMessageId === localMessageId);
  if (!selected) throw codeError("host_app_record_not_found");
  return createDynamicUiEnvelope("message", "ready", {
    localMessageId: safeId(selected.localMessageId, "trae_inbox_contract_invalid"),
    senderPrincipalDisplayName: optionalWidgetText(selected.senderPrincipalDisplayName, 320),
    senderDelegateDisplayName: optionalWidgetText(selected.senderDelegateDisplayName, 320),
    peerHelloLynkIdMasked: selected.peerHelloLynkId == null ? null : maskHelloLynkId(selected.peerHelloLynkId),
    messageType: safeId(selected.messageType, "trae_inbox_contract_invalid"),
    text: checkedWidgetText(selected.text, 64 * 1024),
    unread: boolean(selected.unread, "trae_inbox_contract_invalid"),
    createdAt: safeTimestamp(selected.createdAt, "trae_inbox_contract_invalid"),
    controls: { markReadTool: "hellolynk_mark_inbox_message_read" },
  }, { exposure: "selected-content", privateText: true });
}

export function projectSelectedMessageMetadata(raw, localMessageId) {
  const messages = safeArray(raw?.messages, "trae_inbox_contract_invalid");
  const selected = messages.find((item) => item?.localMessageId === localMessageId);
  if (!selected) throw codeError("host_app_record_not_found");
  return createDynamicUiEnvelope("message", "ready", {
    localMessageId: safeId(selected.localMessageId, "trae_inbox_contract_invalid"),
    senderPrincipalDisplayName: optionalWidgetText(selected.senderPrincipalDisplayName, 320),
    senderDelegateDisplayName: optionalWidgetText(selected.senderDelegateDisplayName, 320),
    peerHelloLynkIdMasked: selected.peerHelloLynkId == null ? null : maskHelloLynkId(selected.peerHelloLynkId),
    messageType: safeId(selected.messageType, "trae_inbox_contract_invalid"),
    unread: boolean(selected.unread, "trae_inbox_contract_invalid"),
    createdAt: safeTimestamp(selected.createdAt, "trae_inbox_contract_invalid"),
    bodyAvailableInPrivateUi: true,
    bodyExcludedFromModelResult: true,
  }, { exposure: "selected-record" });
}

export function projectContactsView(contactsRaw, requestsRaw) {
  const contacts = safeArray(contactsRaw?.contacts, "trae_contacts_contract_invalid").map((contact) => ({
    contactId: safeId(contact?.contactId, "trae_contacts_contract_invalid"),
    displayName: checkedWidgetText(contact?.displayName, 320),
    hellolynkIdMasked: maskHelloLynkId(contact?.hellolynkId),
    updatedAt: safeTimestamp(contact?.updatedAt, "trae_contacts_contract_invalid"),
  }));
  const requests = safeArray(requestsRaw?.requests, "trae_contact_requests_contract_invalid");
  const requestCounts = Object.create(null);
  for (const request of requests) {
    if (request?.modelVisibility !== "none" || request?.humanOnly !== true) {
      throw codeError("trae_contact_requests_contract_invalid");
    }
    const state = safeId(request.state, "trae_contact_requests_contract_invalid");
    requestCounts[state] = (requestCounts[state] || 0) + 1;
  }
  return createDynamicUiEnvelope("contacts", contacts.length || requests.length ? "ready" : "empty", {
    counts: { contacts: contacts.length, contactRequests: requests.length },
    contacts,
    contactRequests: {
      countsByState: requestCounts,
      detailsWithheld: true,
      reason: "host_model_visibility_none",
    },
    controls: {
      contactDetailTool: "hellolynk_get_contact_detail",
      saveContactTool: "hellolynk_save_contact",
      deleteContactTool: "hellolynk_delete_contact",
    },
  }, { exposure: "metadata-only" });
}

export function projectContactDetail(raw, contactId) {
  const contact = safeArray(raw?.contacts, "trae_contacts_contract_invalid")
    .find((item) => item?.contactId === contactId);
  if (!contact) throw codeError("host_app_record_not_found");
  return createDynamicUiEnvelope("contact", "ready", {
    contactId: safeId(contact.contactId, "trae_contacts_contract_invalid"),
    displayName: checkedWidgetText(contact.displayName, 320),
    hellolynkId: safeHelloLynkId(contact.hellolynkId),
    updatedAt: safeTimestamp(contact.updatedAt, "trae_contacts_contract_invalid"),
    controls: { saveContactTool: "hellolynk_save_contact", deleteContactTool: "hellolynk_delete_contact" },
  }, { exposure: "selected-record" });
}

export function projectOutboxView(raw) {
  const messages = safeArray(raw?.messages, "trae_outbox_contract_invalid").map((message) => ({
    clientMessageId: safeId(message?.clientMessageId, "trae_outbox_contract_invalid"),
    recipientHelloLynkIdMasked: maskHelloLynkId(message?.recipientHelloLynkId),
    messageType: safeId(message?.messageType, "trae_outbox_contract_invalid"),
    status: safeId(message?.status, "trae_outbox_contract_invalid"),
    retryAllowed: boolean(message?.retryAllowed, "trae_outbox_contract_invalid"),
    createdAt: safeTimestamp(message?.createdAt, "trae_outbox_contract_invalid"),
    updatedAt: safeTimestamp(message?.updatedAt, "trae_outbox_contract_invalid"),
  }));
  return createDynamicUiEnvelope("outbox", messages.length ? "ready" : "empty", {
    counts: {
      total: messages.length,
      retryable: messages.filter((item) => item.retryAllowed).length,
    },
    items: messages,
    controls: { retryTool: "hellolynk_retry_outbox_message" },
  }, { exposure: "metadata-only" });
}

export function projectSendForm(contactsRaw) {
  const contacts = safeArray(contactsRaw?.contacts, "trae_contacts_contract_invalid").map((contact) => ({
    contactId: safeId(contact?.contactId, "trae_contacts_contract_invalid"),
    displayName: checkedWidgetText(contact?.displayName, 320),
    hellolynkIdMasked: maskHelloLynkId(contact?.hellolynkId),
  }));
  return createDynamicUiEnvelope("send", "ready", {
    contacts,
    fields: [
      { name: "contactId", type: "contact-select", required: false },
      { name: "recipientHelloLynkId", type: "hellolynk-id", required: false },
      { name: "text", type: "multiline-text", required: true, maximumLength: 20_000 },
    ],
    controls: {
      submitTool: "hellolynk_request_human_send",
      submitRequiresExplicitConfirmation: true,
      hostNativeConfirmationStillRequired: true,
    },
  }, { exposure: "metadata-only" });
}

export function projectActionView(value, message) {
  const state = String(value?.state || "");
  if (!/^(pending|approved|cancelled|consuming|expired|failed|invalidated)$/.test(state)) {
    throw codeError("human_action_status_invalid");
  }
  const createdAtMs = safeInteger(value?.createdAtMs, "human_action_status_invalid");
  const expiresAtMs = safeInteger(value?.expiresAtMs, "human_action_status_invalid");
  if (expiresAtMs < createdAtMs || (value?.code != null
    && !/^human_confirmation_[a-z0-9_]{1,100}$/.test(String(value.code)))) {
    throw codeError("human_action_status_invalid");
  }
  return createDynamicUiEnvelope("action", state === "pending" ? "pending" : "ready", {
    message: checkedWidgetText(message, 500),
    actionId: safeId(value?.actionId, "human_action_status_invalid"),
    state,
    createdAtMs,
    expiresAtMs,
    ...(typeof value?.idempotent === "boolean" ? { idempotent: value.idempotent } : {}),
    ...(value?.code == null ? {} : { code: value.code }),
  }, { exposure: "aggregate-only" });
}

export function projectErrorView(errorCode) {
  return createDynamicUiEnvelope("error", "blocked", {
    errorCode: safeId(errorCode, "trae_dynamic_ui_error_invalid"),
  }, { exposure: "aggregate-only" });
}

function widgetLimits(view, data, escapeHtml = false) {
  return {
    maximumDepth: 8, maximumItems: 500, escapeHtml,
    // The Host contract counts authorized instance routes, not unique contacts.
    // Only this root array gets its 1,000-row budget, in both encode and validate.
    maximumAuthorizedContacts: view === "status" && Array.isArray(data?.authorizedContacts) ? 1_000 : 500,
  };
}

function sanitizeWidgetValue(value, limits, depth = 0, seen = new Set(), field = "") {
  if (value == null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw codeError("trae_dynamic_ui_value_invalid");
    return value;
  }
  if (typeof value === "string") return limits.escapeHtml
    ? sanitizeWidgetText(value, 64 * 1024)
    : normalizeWidgetText(value, 64 * 1024);
  if (typeof value !== "object" || seen.has(value) || depth >= limits.maximumDepth) {
    throw codeError("trae_dynamic_ui_value_invalid");
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const maximum = depth === 1 && field === "authorizedContacts" ? limits.maximumAuthorizedContacts : limits.maximumItems;
      if (value.length > maximum) throw codeError("trae_dynamic_ui_value_invalid");
      return value.map((item) => sanitizeWidgetValue(item, limits, depth + 1, seen));
    }
    if (!isPlainObject(value)) throw codeError("trae_dynamic_ui_value_invalid");
    const entries = Object.entries(value);
    if (entries.length > limits.maximumItems) throw codeError("trae_dynamic_ui_value_invalid");
    const result = {};
    for (const [key, nested] of entries) {
      if (!/^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(key) || FORBIDDEN_KEYS.has(key)) {
        throw codeError("trae_dynamic_ui_key_invalid");
      }
      result[key] = sanitizeWidgetValue(nested, limits, depth + 1, seen, key);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function normalizeWidgetText(value, maximumBytes) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maximumBytes || value.includes("\0")) {
    throw codeError("trae_dynamic_ui_text_invalid");
  }
  return value.replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "");
}

function safeArray(value, code) {
  if (!Array.isArray(value) || value.length > 1_000) throw codeError(code);
  return value;
}
function plain(value, code) { if (!isPlainObject(value)) throw codeError(code); return value; }
function safeId(value, code) { const text = String(value || ""); if (!ID.test(text)) throw codeError(code); return text; }
function safeHelloLynkId(value) { const text = String(value || ""); if (!HELLOLYNK_ID.test(text)) throw codeError("trae_hellolynk_id_invalid"); return text; }
function safeTimestamp(value, code) {
  const text = String(value || "");
  if (!ISO_TIMESTAMP.test(text) || new Date(text).toISOString() !== text) throw codeError(code);
  return text;
}
function safeInteger(value, code) { const number = Number(value); if (!Number.isSafeInteger(number) || number < 0) throw codeError(code); return number; }
function boolean(value, code) { if (typeof value !== "boolean") throw codeError(code); return value; }
function checkedWidgetText(value, maximumBytes) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maximumBytes || value.includes("\0")) {
    throw codeError("trae_dynamic_ui_text_invalid");
  }
  return value;
}
function optionalWidgetText(value, maximumBytes) { return value == null ? null : checkedWidgetText(value, maximumBytes); }
function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError("trae_dynamic_ui_envelope_invalid");
  }
}
function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value); return proto === Object.prototype || proto === null;
}
function codeError(code) { const error = new Error(code); error.code = code; return error; }
