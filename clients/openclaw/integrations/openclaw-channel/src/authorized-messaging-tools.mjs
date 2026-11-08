import { prepareModelInboxInvocation, isModelInboxTool } from "../../../clients/core/hellolynk-model-inbox.mjs";
import { openClawModelInboxCaller } from "./native-origins.mjs";
import { nativeTool, optionalTarget, nativeAddressingError, replyHint, firstSendReceipt, paramText, resultText, sendArgumentKeys, sendRecipient, findContacts, writeFailure, failureText } from "../../../clients/core/hellolynk-native-addressing-tools.cjs";
import { withHelloLynkModelNotices } from "../../../clients/core/hellolynk-model-notices.cjs";
import { projectInboxReadState } from "../../../clients/core/hellolynk-inbox-read-state.mjs";
import { rememberOpenClawOrigin } from "./native-origins.mjs";
// Host owns the selected batch and every reply target / authorization check.

const WRITE_ID = Object.freeze({ type: "string", minLength: 3, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$" });
const WRITE_ID_PATTERN = new RegExp(WRITE_ID.pattern);
const CLIENT_MESSAGE_ID = Object.freeze({ ...WRITE_ID, examples: ["msg-a1b2c3-01"], description: paramText.clientMessageId });
const MESSAGE_TEXT = Object.freeze({ type: "string", minLength: 1, maxLength: 20000, description: paramText.text });

// nativeTool adds the titles and descriptions every client shares; the agent tools below pass on only the description.
export const OPENCLAW_AUTHORIZED_MESSAGING_TOOLS = Object.freeze([
  Object.freeze({
    name: "hellolynk_open_inbox",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "hellolynk_get_unread_count",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "hellolynk_list_authorized_contacts",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "hellolynk_send_authorized_message",
    inputSchema: Object.freeze({
      type: "object", additionalProperties: false,
      required: ["clientMessageId", "text"],
      properties: Object.freeze({
        contactId: Object.freeze({ type: "string", minLength: 3, maxLength: 200 }),
        recipientDelegateId: Object.freeze({ type: "string", minLength: 3, maxLength: 200 }),
        clientMessageId: CLIENT_MESSAGE_ID,
        text: MESSAGE_TEXT,
      }),
    }),
  }),
  Object.freeze({
    name: "hellolynk_list_authorized_inbox_messages",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: Object.freeze({
      before: Object.freeze({ type: "string", minLength: 3, maxLength: 240, description: paramText.before }),
    }) }),
  }),
  Object.freeze({
    name: "hellolynk_read_authorized_inbox_message",
    inputSchema: strictConversationSchema("localMessageId"),
  }),
  Object.freeze({
    name: "hellolynk_list_authorized_contact_requests",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "hellolynk_read_authorized_contact_request",
    inputSchema: strictConversationSchema("localRecordId"),
  }),
  Object.freeze({
    name: "hellolynk_list_pending_messages",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "hellolynk_claim_message",
    inputSchema: pendingClaimSchema(),
  }),
  Object.freeze({
    name: "hellolynk_reply_authorized_message",
    inputSchema: { type: "object", additionalProperties: false, required: ["localMessageId", "conversationKey", "clientMessageId", "text"], properties: {
      localMessageId: { ...WRITE_ID, description: paramText.localMessageId }, conversationKey: { ...WRITE_ID, description: paramText.conversationKey },
      clientMessageId: CLIENT_MESSAGE_ID, text: MESSAGE_TEXT,
    } },
  }),
].map(nativeTool));

export function createOpenClawAuthorizedMessagingToolHandlers(options = {}) {
  const original = createUnscopedMessagingToolHandlers(options);
  return Object.freeze(Object.fromEntries(Object.entries(original).map(([name, handler]) => [name,
    !isModelInboxTool(name) ? handler : async (args = {}, attempt) => {
      const adapter = await options.adapterProvider();
      const invocation = await prepareModelInboxInvocation(adapter, { name, args,
        caller: openClawModelInboxCaller(options.toolContext) });
      const handlers = createUnscopedMessagingToolHandlers({ ...options, adapterProvider: async () => invocation.adapter });
      return invocation.finish(await handlers[name](invocation.args, attempt));
    },
  ])));
}

function createUnscopedMessagingToolHandlers(options = {}) {
  if (typeof options.adapterProvider !== "function") throw codeError("authorized_messaging_adapter_provider_required");
  // Manual single-message claim: the model names one message by its two ids.
  async function claimSingle(args) {
    assertExact(args, ["localMessageId", "conversationKey"]);
    for (const key of ["localMessageId", "conversationKey"]) {
      if (typeof args[key] !== "string" || !PENDING_ID.test(args[key])) throw codeError("arguments_invalid");
    }
    const adapter = await options.adapterProvider();
    const result = await adapter.claimMessage(args.localMessageId, args.conversationKey);
    if (result?.claimed === false && result.claimId === null && result.message === null) {
      return { claimed: false, claimId: null, message: null, notice: "此来信已被领取或处理。" };
    }
    if (result?.claimed !== true || typeof result.claimId !== "string" || !/^inclaim_[a-f0-9]{48}$/.test(result.claimId)) throw codeError("host_app_response_invalid");
    const message = projectRead(result.message);
    if (message.localMessageId !== args.localMessageId || message.conversationKey !== args.conversationKey
      || result.message?.wakeEligible !== true) throw codeError("host_app_response_invalid");
    return { claimed: true, claimId: result.claimId, message: { ...message, wakeEligible: true } };
  }
  return Object.freeze({
    async hellolynk_list_pending_messages(args = {}) {
      assertEmpty(args);
      const adapter = await options.adapterProvider();
      return { messages: projectPendingMessages(await adapter.listPendingMessages()) };
    },
    async hellolynk_claim_message(args = {}) {
      if (!!args && typeof args === "object" && !Array.isArray(args) && !Object.hasOwn(args, "batchId")) return claimSingle(args);
      assertExact(args, ["batchId"]);
      if (!/^inbatch_[a-f0-9]{48}$/.test(args.batchId || "")) throw codeError("arguments_invalid");
      const adapter = await options.adapterProvider();
      const result = await adapter.claimBatch(args.batchId);
      if (!Array.isArray(result?.messages) || result.claimed !== (result.messages.length > 0)
        || !Number.isSafeInteger(result.expiredCount) || result.expiredCount < 0) throw codeError("host_app_response_invalid");
      const messages = result.messages.map(projectRead);
      if (messages.reduce((total, message) => total + [...message.text].length, 0) > 20_000) throw codeError("host_app_response_invalid");
      return { batchId: args.batchId, claimed: result.claimed, messages, expiredCount: result.expiredCount,
        ...(result.claimed ? {} : { notice: "这批来信已读取，无需重复读取。" }) };
    },
    async hellolynk_reply_authorized_message(args = {}, attempt = { phase: "input_validation" }) {
      assertExact(args, ["localMessageId", "conversationKey", "clientMessageId", "text"]);
      for (const key of ["localMessageId", "conversationKey", "clientMessageId"]) {
        if (typeof args[key] !== "string" || !WRITE_ID_PATTERN.test(args[key])) throw codeError("arguments_invalid");
      }
      const input = { ...args, text: safeBody(args.text, 20_000, true) };
      attempt.clientMessageId = input.clientMessageId;
      attempt.phase = "preparation";
      const adapter = await options.adapterProvider();
      await adapter.assertModelInboxReply(input);
      options.toolContext?.assertInvocationCurrent?.();
      attempt.phase = "adapter_call";
      const result = await adapter.replyAuthorizedMessage(input);
      attempt.phase = "response_validation";
      if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist"
        || result.clientMessageId !== input.clientMessageId
        || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) throw codeError("host_app_send_result_unknown");
      // Route registration follows successful send and cannot cause a replay.
      const originRegistered = await rememberOpenClawOrigin(adapter, options.toolContext, input);
      return { accepted: true, contactId: result.contactId, clientMessageId: result.clientMessageId, status: result.status, originRegistered };
    },
    async hellolynk_open_inbox(args = {}) {
      assertEmpty(args);
      return {
        controlUiId: "hellolynk-inbox",
        label: "HelloLynk 通讯",
        action: "open_sidebar_control",
      };
    },
    async hellolynk_list_authorized_contacts(args = {}) {
      const adapter = await options.adapterProvider();
      const result = await findContacts(args, query => adapter.listAuthorizedContacts(query));
      return { contacts: safeContactList(result?.contacts), ...(result?.nativeConversations ? { nativeConversations: result.nativeConversations } : {}) };
    },
    async hellolynk_send_authorized_message(args = {}, attempt = { phase: "input_validation" }) {
      assertExact(args, sendArgumentKeys(args));
      if (Object.values(args).some(value => typeof value !== "string")) throw codeError("arguments_invalid");
      if (!Object.hasOwn(args, "contact")) {
        safeText(args.contactId, "contact_id_invalid", 200);
        safeText(args.recipientDelegateId, "recipient_delegate_id_invalid", 200);
      }
      optionalTarget(args);
      if (!WRITE_ID_PATTERN.test(args.clientMessageId)) throw codeError("client_message_id_invalid");
      attempt.clientMessageId = args.clientMessageId;
      const text = safeBody(args.text, 20_000, true);
      attempt.phase = "preparation";
      const adapter = await options.adapterProvider();
      const { contactId, recipientDelegateId } = await sendRecipient(args, query => adapter.listAuthorizedContacts(query));
      const input = {
        ...optionalTarget(args),
        contactId: safeText(contactId, "contact_id_invalid", 200),
        recipientDelegateId: safeText(recipientDelegateId, "recipient_delegate_id_invalid", 200),
        clientMessageId: safeText(args.clientMessageId, "client_message_id_invalid", 200),
        text,
      };
      const originRegistered = await rememberOpenClawOrigin(adapter, options.toolContext, input);
      options.toolContext?.assertInvocationCurrent?.();
      attempt.phase = "adapter_call";
      const result = await adapter.sendAuthorizedMessage(input);
      attempt.phase = "response_validation";
      if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist"
        || result.contactId !== input.contactId || result.clientMessageId !== input.clientMessageId
        || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) throw codeError("host_app_send_result_unknown");
      return {
        accepted: true,
        contactId: result.contactId,
        recipientDelegateId: input.recipientDelegateId,
        clientMessageId: result.clientMessageId,
        status: result.status,
        destination: firstSendReceipt(input, result.status).destination,
        originRegistered,
      };
    },
    async hellolynk_get_unread_count(args = {}) {
      assertEmpty(args);
      const result = await (await options.adapterProvider()).readUnreadCount();
      if (!Number.isSafeInteger(result?.unreadCount) || result.unreadCount < 0) throw codeError("authorized_inbox_response_invalid");
      return { unreadCount: result.unreadCount };
    },
    async hellolynk_list_authorized_inbox_messages(args = {}) {
      const older = !!args && typeof args === "object" && Object.hasOwn(args, "before");
      if (older) assertExact(args, ["before"]); else assertEmpty(args);
      const adapter = await options.adapterProvider();
      const result = await adapter.listAuthorizedInboxMessages(older
        ? { before: safeText(args.before, "authorized_inbox_message_id_invalid", 240) } : {});
      return { messages: (result?.messages || []).map(value => ({ ...projectMetadata(value), ...replyHint(value) })) };
    },
    async hellolynk_read_authorized_inbox_message(args = {}) {
      assertExact(args, ["conversationKey", "localMessageId"]);
      const adapter = await options.adapterProvider();
      return projectRead(await adapter.readAuthorizedInboxMessage(
        safeText(args.localMessageId, "authorized_inbox_message_id_invalid", 240),
        safeText(args.conversationKey, "authorized_inbox_conversation_key_invalid", 240),
      ));
    },
    async hellolynk_list_authorized_contact_requests(args = {}) {
      assertEmpty(args);
      const adapter = await options.adapterProvider();
      const result = await adapter.listAuthorizedContactRequests();
      return { requests: (result?.requests || []).map(projectContactRequestMetadata) };
    },
    async hellolynk_read_authorized_contact_request(args = {}) {
      assertExact(args, ["conversationKey", "localRecordId"]);
      const adapter = await options.adapterProvider();
      return projectContactRequestRead(await adapter.readAuthorizedContactRequest(
        safeText(args.localRecordId, "authorized_contact_request_id_invalid", 240),
        safeText(args.conversationKey, "authorized_contact_request_conversation_key_invalid", 240),
      ));
    },
  });
}

export function createOpenClawAuthorizedMessagingAgentTools(options = {}) {
  const handlers = createOpenClawAuthorizedMessagingToolHandlers(options);
  // OpenClaw wraps registered tools with a policy Proxy that replaces
  // `execute`. Freezing each tool makes that Proxy violate the JavaScript
  // invariant for a non-configurable, read-only data property. Keep the array
  // immutable while leaving its runtime tool records proxy-compatible.
  return Object.freeze(OPENCLAW_AUTHORIZED_MESSAGING_TOOLS.map((definition) => ({
    name: definition.name,
    description: definition.description,
    parameters: definition.inputSchema,
    async execute(_toolCallId, params = {}) {
      return withHelloLynkModelNotices(async () => {
      const attempt = ["hellolynk_send_authorized_message", "hellolynk_reply_authorized_message"].includes(definition.name) ? { phase: "input_validation" } : null;
      try {
        const result = await handlers[definition.name](params, attempt);
        return {
          content: renderToolResult(definition.name, result, params).map((text) => ({ type: "text", text })),
          details: result,
        };
      } catch (error) {
        const nativeError = nativeAddressingError(error, attempt);
        if (nativeError) return { content: nativeError.content, details: nativeError.structuredContent, isError: true };
        const code = safeErrorCode(error);
        if (!attempt) return { content: [{ type: "text", text: failureText(code) }], details: { ok: false, errorCode: code }, isError: true };
        // Phase and retry policy come only from this invocation, never from an adapter error.
        const { text, ...outcome } = writeFailure(code, attempt.phase);
        return { content: [{ type: "text", text }], details: { ok: false, errorCode: code, ...outcome, phase: attempt.phase,
          ...(attempt.clientMessageId ? { clientMessageId: attempt.clientMessageId } : {}) }, isError: true };
      }
      });
    },
  })));
}

// The sentence comes first; tools that return records follow it with the records as JSON.
function renderToolResult(name, result, params) {
  if (name === "hellolynk_get_unread_count") return [`当前对话：人类未读 ${result.humanUnreadCount} 条；AI 待处理 ${result.aiPendingCount} 条。`, JSON.stringify(result)];
  if (name === "hellolynk_open_inbox") return ["HelloLynk 已就绪，在左侧打开“HelloLynk 通讯”。"];
  if (name === "hellolynk_list_authorized_contacts") return [resultText.contacts(result.contacts.length),
    JSON.stringify({ contacts: result.contacts, ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}) })];
  if (name === "hellolynk_list_authorized_inbox_messages") return [resultText.inbox(result.messages.length, Object.hasOwn(params, "before")), JSON.stringify(result)];
  if (name === "hellolynk_list_pending_messages") return [resultText.pending(result.messages.length), JSON.stringify(result)];
  if (name === "hellolynk_claim_message") return result.claimed ? [resultText.claimed(result.messages?.length ?? 1, result.expiredCount), JSON.stringify(result)] : [JSON.stringify(result)];
  if (name === "hellolynk_read_authorized_inbox_message") return ["已读取来信。", JSON.stringify(result)];
  if (name === "hellolynk_read_authorized_contact_request") return ["已读取联系申请。", JSON.stringify(result)];
  if (name === "hellolynk_list_authorized_contact_requests") return [`联系申请 ${result.requests.length} 条。`, JSON.stringify({ requests: result.requests })];
  return [resultText.sent(result.status, result.clientMessageId)];
}

function safeContactList(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => ({
    contactId: safeText(item?.contactId, "contact_id_invalid", 200),
    displayName: safeText(item?.displayName, "contact_display_name_invalid", 160),
    recipientDelegateId: safeText(item?.recipientDelegateId, "recipient_delegate_id_invalid", 200),
    instanceDisplayName: safeText(item?.instanceDisplayName, "instance_display_name_invalid", 160),
  }));
}

function projectMetadata(value) {
  const result = {
    localMessageId: safeText(value?.localMessageId, "authorized_inbox_message_id_invalid", 240),
    conversationKey: safeText(value?.conversationKey, "authorized_inbox_conversation_key_invalid", 240),
    localDelegateId: safeText(value?.localDelegateId, "authorized_inbox_local_delegate_invalid", 200),
    peerDelegateId: safeText(value?.peerDelegateId, "authorized_inbox_peer_delegate_invalid", 200),
    messageType: safeText(value?.messageType || "text", "authorized_inbox_message_type_invalid", 80),
    unread: value?.unread === true,
  };
  for (const key of ["contactId", "displayName", "peerInstanceDisplayName", "clientMessageId", "createdAt", "updatedAt"]) {
    if (value?.[key] != null) result[key] = safeText(value[key], `authorized_inbox_${key}_invalid`, 240);
  }
  return result;
}

function projectRead(value) {
  if (!projectInboxReadState(value) || value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid");
  return {
    ...projectMetadata(value), peerPrincipalId: safeText(value?.peerPrincipalId, "authorized_inbox_peer_principal_invalid", 200), text: safeBody(value?.text, 65536),
    ...(value?.automationStatus === "expired" ? { automationStatus: "expired" } : {}),
    source: requireSource(value?.source, "hellolynk_external_message"),
    ...projectInboxReadState(value), ...replyHint(value),
  };
}

function projectContactRequestMetadata(value) {
  return {
    localRecordId: safeText(value?.localRecordId, "authorized_contact_request_id_invalid", 240),
    conversationKey: safeText(value?.conversationKey, "authorized_contact_request_conversation_key_invalid", 240),
    localDelegateId: safeText(value?.localDelegateId, "authorized_contact_request_local_delegate_invalid", 200),
    sender: {
      hellolynkId: safeText(value?.sender?.hellolynkId, "authorized_contact_request_sender_invalid", 200),
      verifiedDisplayName: safeText(value?.sender?.verifiedDisplayName, "authorized_contact_request_sender_name_invalid", 160),
    },
    state: safeText(value?.state, "authorized_contact_request_state_invalid", 80),
    receivedAt: safeText(value?.receivedAt, "authorized_contact_request_time_invalid", 80),
  };
}

function projectContactRequestRead(value) {
  return {
    ...projectContactRequestMetadata(value), introText: safeContactRequestIntro(value?.introText),
    source: requireSource(value?.source, "hellolynk_contact_request"),
    readDoesNotMarkRead: value?.readDoesNotMarkRead === true,
  };
}

const PENDING_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;

// Keep the model-facing schema flat across providers. The handler enforces
// batchId OR the exact localMessageId + conversationKey pair before the Host.
function pendingClaimSchema() {
  return { type: "object", additionalProperties: false,
    properties: { batchId: { type: "string", pattern: "^inbatch_[a-f0-9]{48}$", description: paramText.batchId },
      localMessageId: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$", description: paramText.localMessageId },
      conversationKey: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$", description: paramText.conversationKey } } };
}

function projectPendingMessages(result) {
  if (!Array.isArray(result?.messages) || result.messages.length > 1000) throw codeError("host_app_response_invalid");
  return result.messages.map((value) => {
    const ids = [value?.localMessageId, value?.conversationKey, value?.localDelegateId, value?.peerDelegateId, ...(value?.contactId === null ? [] : [value?.contactId])];
    if (value?.wakeEligible !== true || typeof value.unread !== "boolean" || ids.some((id) => typeof id !== "string" || !PENDING_ID.test(id))
      || typeof value.displayName !== "string" || !value.displayName || value.displayName.length > 160 || /[\r\n\0]/.test(value.displayName)
      || typeof value.createdAt !== "string" || value.createdAt.length > 80 || !Number.isFinite(Date.parse(value.createdAt))) throw codeError("host_app_response_invalid");
    return { ...Object.fromEntries(["localMessageId", "conversationKey", "localDelegateId", "peerDelegateId", "contactId", "displayName", "unread", "createdAt", "wakeEligible"].map((key) => [key, value[key]])),
      ...(value.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeText(value.peerInstanceDisplayName, "instance_display_name_invalid", 160) }) };
  });
}

function strictConversationSchema(id) {
  const message = id === "localMessageId";
  return Object.freeze({ type: "object", additionalProperties: false, required: Object.freeze([id, "conversationKey"]), properties: Object.freeze({
    [id]: Object.freeze({ type: "string", minLength: 3, maxLength: 240, ...(message ? { description: paramText.localMessageId } : {}) }),
    conversationKey: Object.freeze({ type: "string", minLength: 3, maxLength: 240, ...(message ? { description: paramText.conversationKey } : {}) }),
  }) });
}

function requireSource(value, expected) {
  if (value !== expected) throw codeError("external_content_source_invalid");
  return expected;
}

function safeContactRequestIntro(value) {
  return value === "" ? "" : safeBody(value);
}

function safeBody(value, maximum = 20_000, countCodePoints = false) {
  const text = String(value ?? "");
  if (!text || text.includes("\u0000") || (countCodePoints ? [...text].length : text.length) > maximum || Buffer.byteLength(text, "utf8") > (maximum === 20_000 ? 20 * 1024 : maximum)) {
    throw codeError("message_text_invalid");
  }
  return text;
}

function safeText(value, code, maximum) {
  const text = String(value ?? "").trim();
  if (!text || text.length > maximum || /[\r\n\u0000-\u001f\u007f]/.test(text)) throw codeError(code);
  return text;
}

function assertEmpty(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length) {
    throw codeError("arguments_invalid");
  }
}

function assertExact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("arguments_invalid");
  const actual = Object.keys(value || {}).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw codeError("arguments_invalid");
  }
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function safeErrorCode(error) {
  const code = String(error?.code || error?.message || "hellolynk_operation_failed").trim();
  return /^[a-z0-9_:-]{1,120}$/i.test(code) ? code : "hellolynk_operation_failed";
}
