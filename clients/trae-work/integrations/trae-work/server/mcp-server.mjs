#!/usr/bin/env node
import { prepareModelInboxInvocation, isModelInboxTool } from "../../../runtime/core/hellolynk-model-inbox.mjs";
import { nativeTool, optionalTarget, nativeAddressingError, replyHint, conversationGuidance, replyHintSchema, firstSendReceipt, paramText, resultText, sendArgumentKeys, sendRecipient, findContacts, writeFailure, failureText } from "../../../runtime/core/hellolynk-native-addressing-tools.cjs";
import { withHelloLynkModelNotices } from "../../../runtime/core/hellolynk-model-notices.cjs";

import path from "node:path";
import { rememberNativeReplyRoute } from "../../../runtime/core/hellolynk-native-reply-routes.mjs";
import { projectInboxReadState } from "../../../runtime/core/hellolynk-inbox-read-state.mjs";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import packageMetadata from "../package.json" with { type: "json" };
import {
  createDynamicUiEnvelope, projectActionView, projectContactDetail, projectContactsView, projectPrivateInboxDashboard,
  projectErrorView, projectInboxView, projectOutboxView, projectSelectedMessage,
  projectSelectedMessageMetadata, projectSendForm,
  TRAE_DYNAMIC_UI_CONTRACT,
} from "./dynamic-ui-contract.mjs";
import {
  createPrivateUiMeta,
  createTraeUiActionGate,
} from "./ui-action-gate.mjs";

if (packageMetadata.name !== "@hellolynk-ai/trae-work-mcp"
  || typeof packageMetadata.version !== "string" || !/^\d+\.\d+\.\d+$/.test(packageMetadata.version)) {
  throw codeError("trae_work_package_metadata_invalid");
}

export const TRAE_WORK_MCP_PROTOCOL_VERSION = "2025-11-25";
export const TRAE_WORK_MCP_SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([TRAE_WORK_MCP_PROTOCOL_VERSION, "2025-06-18"]);
export const TRAE_WORK_MCP_MAX_FRAME_BYTES = 64 * 1024;

const READ_ONLY = Object.freeze({ readOnlyHint: true, openWorldHint: false, destructiveHint: false, idempotentHint: true });
const LOCAL_WRITE = Object.freeze({ readOnlyHint: false, openWorldHint: false, destructiveHint: false, idempotentHint: false });
const LOCAL_DELETE = Object.freeze({ readOnlyHint: false, openWorldHint: false, destructiveHint: true, idempotentHint: false });
const REQUEST_WRITE = Object.freeze({ readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: false });
const AUTHORIZED_SEND = Object.freeze({ readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: false });
const COMMON_PUBLIC_ERROR_CODES = new Set([
  "native_addressing_arguments_invalid",
  "native_directory_cursor_invalid", "native_directory_query_invalid", "native_conversation_id_invalid",
  "action_id_invalid", "client_message_id_invalid", "confirmation_required", "contact_display_name_invalid",
  "contact_id_invalid", "contact_recipient_not_found", "host_app_native_broker_unavailable",
  "host_native_inbox_upgrade_required", "host_app_record_not_found", "host_app_state_conflict", "host_app_unavailable",
  "host_app_reply_target_deleted", "host_app_authorization_required",
  "hellolynk_node_22_16_required",
  "host_attachment_ambiguous", "host_attachment_not_found", "host_capability_scope_denied",
  "host_not_running", "host_request_replayed", "host_request_unauthorized", "human_action_status_invalid",
  "invalid_params", "local_message_id_invalid", "local_message_ids_invalid", "message_text_invalid",
  "method_not_found", "neutral_capability_binding_invalid", "neutral_capability_inactive",
  "neutral_capability_owner_mismatch", "neutral_capability_provider_required", "neutral_capability_scopes_mismatch",
  "neutral_capability_version_mismatch", "neutral_host_adapter_closed", "neutral_host_discovery_generation_mismatch",
  "neutral_host_discovery_owner_mismatch", "neutral_host_discovery_stale", "neutral_host_heartbeat_failed",
  "neutral_host_launcher_unavailable", "neutral_host_not_running", "neutral_host_release_superseded",
  "outbox_message_id_invalid", "powershell7_missing", "recipient_invalid",
  "recipient_selection_invalid", "unknown_tool",
  "trae_ui_action_authorization_expired", "trae_ui_action_authorization_invalid",
  "trae_ui_action_authorization_required", "trae_ui_action_scope_mismatch",
  "trae_local_web_adapter_required", "trae_local_web_launch_invalid", "trae_local_web_launch_unavailable", "trae_local_web_payload_invalid",
]);

const EMPTY_SCHEMA = Object.freeze({ type: "object", additionalProperties: false, properties: Object.freeze({}) });
const CONFIRM = Object.freeze({ type: "boolean", const: true, description: "必须来自人类在当前 UI 中的明确操作。" });
const ID_SCHEMA = Object.freeze({ type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$" });
const HISTORY_SCHEMA = Object.freeze({ type: "object", additionalProperties: false, properties: Object.freeze({
  before: Object.freeze({ ...ID_SCHEMA, description: paramText.before }),
}) });
const MESSAGE_TEXT = Object.freeze({ type: "string", minLength: 1, maxLength: 20000, description: paramText.text });
// JSON Schema uses an unflagged ECMA-262 pattern; keep the portable anchors.
const WRITE_ID = Object.freeze({ type: "string", minLength: 3, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$" });
const WRITE_ID_PATTERN = new RegExp(WRITE_ID.pattern);
const CLIENT_MESSAGE_ID = Object.freeze({ ...WRITE_ID, examples: ["msg-a1b2c3-01"], description: paramText.clientMessageId });

const HELLOLYNK_ID_SCHEMA = Object.freeze({ type: "string", pattern: "^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$" });
const UI_ACTION_TOKEN_SCHEMA = Object.freeze({ type: "string", pattern: "^hellolynkui_[A-Za-z0-9_-]{43}$" });
const DEFAULT_UI_ACTION_GATE = createTraeUiActionGate();
const NOTICES_SCHEMA = Object.freeze({ type: "array", items: { type: "string" } });
const OUTPUT_SCHEMA = Object.freeze({
  type: "object", additionalProperties: false,
  required: Object.freeze(["contract", "version", "renderer", "view", "state", "exposure", "component", "data"]),
  properties: Object.freeze({
    contract: Object.freeze({ type: "string", const: TRAE_DYNAMIC_UI_CONTRACT }),
    version: Object.freeze({ type: "integer", const: 1 }), renderer: Object.freeze({ type: "string", const: "HelloLynkTraeLocalWebV18" }),
    view: Object.freeze({ type: "string" }), state: Object.freeze({ type: "string" }), exposure: Object.freeze({ type: "string" }), component: Object.freeze({ type: "string", enum: ["messenger-inbox", "message-form", "status-card", "message-confirm"] }),
    data: Object.freeze({ type: "object" }), notices: NOTICES_SCHEMA,
  }),
});
const PENDING_MESSAGE_SCHEMA = Object.freeze({
  type: "object", additionalProperties: false,
  required: ["localMessageId", "conversationKey", "localDelegateId", "peerDelegateId", "contactId", "displayName", "unread", "createdAt", "wakeEligible"],
  properties: {
    localMessageId: ID_SCHEMA, conversationKey: ID_SCHEMA, localDelegateId: ID_SCHEMA,
    peerDelegateId: ID_SCHEMA, contactId: { anyOf: [ID_SCHEMA, { type: "null" }] }, displayName: { type: "string" }, peerInstanceDisplayName: { type: "string" },
    unread: { type: "boolean" }, createdAt: { type: "string" }, wakeEligible: { type: "boolean", const: true },
  },
});
const CLAIM_ID_SCHEMA = Object.freeze({ type: "string", pattern: "^inclaim_[a-f0-9]{48}$" });
const PENDING_OUTPUT_SCHEMAS = Object.freeze({
  hellolynk_list_pending_messages: {
    type: "object", additionalProperties: false, required: ["messages"],
    properties: { messages: { type: "array", maxItems: 1000, items: PENDING_MESSAGE_SCHEMA }, notices: NOTICES_SCHEMA },
  },
  hellolynk_claim_message: { type: "object", oneOf: [{
    type: "object", additionalProperties: false, required: ["claimed", "claimId", "message"],
    properties: { claimed: { type: "boolean" }, claimId: { type: ["string", "null"] }, message: { type: ["object", "null"] }, notices: NOTICES_SCHEMA },
    oneOf: [
      { properties: { claimed: { const: false }, claimId: { type: "null" }, message: { type: "null" } } },
      { properties: { claimed: { const: true }, claimId: CLAIM_ID_SCHEMA, message: {
        type: "object", additionalProperties: false,
        required: [...PENDING_MESSAGE_SCHEMA.required, "peerPrincipalId", "messageType", "text", "source", "readDoesNotMarkRead"],
        properties: {
          ...PENDING_MESSAGE_SCHEMA.properties, peerPrincipalId: ID_SCHEMA, messageType: ID_SCHEMA,
          text: { type: "string", minLength: 1 }, source: { type: "string", const: "hellolynk_external_message" },
          readDoesNotMarkRead: { type: "boolean" }, humanReadAutomatically: { type: "boolean", const: true }, reply: replyHintSchema,
        },
      } } },
    ],
  }, { type: "object", additionalProperties: false, required: ["claimed", "messages", "expiredCount", "notice"],
      properties: { claimed: { type: "boolean" }, messages: { type: "array", items: { type: "object" } }, expiredCount: { type: "integer", minimum: 0 }, notice: { type: ["string", "null"] }, notices: NOTICES_SCHEMA } }] },

});
const tool = (name, inputSchema, annotations, text = {}) => Object.freeze({
  name, ...text, inputSchema, outputSchema: PENDING_OUTPUT_SCHEMAS[name] || OUTPUT_SCHEMA, annotations,
});

// nativeTool adds the titles and descriptions every client shares.
export const TRAE_WORK_INTERNAL_TOOLS = Object.freeze([
  tool("hellolynk_open_inbox", EMPTY_SCHEMA, READ_ONLY),
  tool("hellolynk_host_status", EMPTY_SCHEMA, READ_ONLY),
  tool("hellolynk_get_unread_count", EMPTY_SCHEMA, READ_ONLY),
  tool("hellolynk_list_authorized_contacts", EMPTY_SCHEMA, READ_ONLY),
  tool("hellolynk_list_authorized_inbox_messages", HISTORY_SCHEMA, READ_ONLY),
  tool("hellolynk_read_authorized_inbox_message", strictConversationSchema("localMessageId"), READ_ONLY),
  tool("hellolynk_list_authorized_contact_requests", EMPTY_SCHEMA, READ_ONLY),
  tool("hellolynk_read_authorized_contact_request", strictConversationSchema("localRecordId"), READ_ONLY),
  tool("hellolynk_send_authorized_message", {
    type: "object", additionalProperties: false, required: ["clientMessageId", "text"], properties: {
      clientMessageId: CLIENT_MESSAGE_ID, contactId: ID_SCHEMA, recipientDelegateId: ID_SCHEMA, text: MESSAGE_TEXT,
    },
  }, AUTHORIZED_SEND),
  tool("hellolynk_reply_authorized_message", {
    type: "object", additionalProperties: false, required: ["localMessageId", "conversationKey", "clientMessageId", "text"], properties: {
      localMessageId: { ...ID_SCHEMA, description: paramText.localMessageId }, conversationKey: { ...ID_SCHEMA, description: paramText.conversationKey },
      clientMessageId: CLIENT_MESSAGE_ID, text: MESSAGE_TEXT,
    },
  }, AUTHORIZED_SEND),
  tool("hellolynk_render_inbox", EMPTY_SCHEMA, READ_ONLY, { title: "显示 HelloLynk 消息", description: "显示本机消息列表，不含正文。" }),
  tool("hellolynk_read_inbox_message", {
    type: "object", additionalProperties: false, required: ["localMessageId"], properties: { localMessageId: ID_SCHEMA },
  }, READ_ONLY, { title: "查看一条HelloLynk消息", description: "返回所选消息的元数据，不含正文。" }),
  tool("hellolynk_mark_inbox_message_read", {
    type: "object", additionalProperties: false, required: ["localMessageId", "confirm", "uiActionToken"],
    properties: { localMessageId: ID_SCHEMA, confirm: CONFIRM, uiActionToken: UI_ACTION_TOKEN_SCHEMA },
  }, LOCAL_WRITE, { title: "把一条HelloLynk消息标为已读", description: "把所选消息标为已读，需要本人在界面确认。" }),
  tool("hellolynk_delete_read_inbox_messages", {
    type: "object", additionalProperties: false, required: ["localMessageIds", "confirm", "uiActionToken"],
    properties: { localMessageIds: { type: "array", minItems: 1, maxItems: 500, uniqueItems: true, items: ID_SCHEMA }, confirm: CONFIRM, uiActionToken: UI_ACTION_TOKEN_SCHEMA },
  }, LOCAL_DELETE, { title: "删除已读HelloLynk消息", description: "删除所选的已读消息，需要本人在界面确认。" }),
  tool("hellolynk_render_contacts", EMPTY_SCHEMA, READ_ONLY, { title: "显示HelloLynk联系人", description: "显示联系人列表。" }),
  tool("hellolynk_get_contact_detail", {
    type: "object", additionalProperties: false, required: ["contactId"], properties: { contactId: ID_SCHEMA },
  }, READ_ONLY, { title: "查看一个HelloLynk联系人", description: "返回所选联系人的详情。" }),
  tool("hellolynk_save_contact", {
    type: "object", additionalProperties: false, required: ["hellolynkId", "displayName", "confirm", "uiActionToken"],
    properties: { contactId: ID_SCHEMA, hellolynkId: HELLOLYNK_ID_SCHEMA, displayName: { type: "string", minLength: 1, maxLength: 80 }, confirm: CONFIRM, uiActionToken: UI_ACTION_TOKEN_SCHEMA },
  }, LOCAL_WRITE, { title: "保存HelloLynk联系人", description: "保存联系人，需要本人在界面确认。" }),
  tool("hellolynk_delete_contact", {
    type: "object", additionalProperties: false, required: ["contactId", "confirm", "uiActionToken"],
    properties: { contactId: ID_SCHEMA, confirm: CONFIRM, uiActionToken: UI_ACTION_TOKEN_SCHEMA },
  }, LOCAL_DELETE, { title: "删除HelloLynk联系人", description: "删除联系人，需要本人在界面确认。" }),
  tool("hellolynk_render_outbox", EMPTY_SCHEMA, READ_ONLY, { title: "显示 HelloLynk 发出记录", description: "显示发出记录，不含正文。" }),
  tool("hellolynk_retry_outbox_message", {
    type: "object", additionalProperties: false, required: ["clientMessageId", "confirm", "uiActionToken"],
    properties: { clientMessageId: ID_SCHEMA, confirm: CONFIRM, uiActionToken: UI_ACTION_TOKEN_SCHEMA },
  }, REQUEST_WRITE, { title: "重试一条发件记录", description: "重试一条发出失败的消息，需要本人在界面确认。" }),
  tool("hellolynk_render_send_form", EMPTY_SCHEMA, READ_ONLY, { title: "显示HelloLynk发信表单", description: "显示发信表单。" }),
  tool("hellolynk_request_human_send", {
    type: "object", additionalProperties: false, required: ["clientMessageId", "text", "confirm", "uiActionToken"],
    oneOf: [
      { required: ["contactId"], not: { required: ["recipientHelloLynkId"] } },
      { required: ["recipientHelloLynkId"], not: { required: ["contactId"] } },
    ],
    properties: {
      clientMessageId: ID_SCHEMA, contactId: ID_SCHEMA, recipientHelloLynkId: HELLOLYNK_ID_SCHEMA,
      text: MESSAGE_TEXT, confirm: CONFIRM,
      uiActionToken: UI_ACTION_TOKEN_SCHEMA,
    },
  }, REQUEST_WRITE, { title: "请求人类确认发送HelloLynk", description: "请本人在 HelloLynk 里确认发送；本工具不直接发送。" }),
  tool("hellolynk_get_human_send_status", {
    type: "object", additionalProperties: false, required: ["actionId"], properties: { actionId: ID_SCHEMA },
  }, READ_ONLY, { title: "查看人类确认请求状态", description: "查看确认请求的状态。" }),
].map(nativeTool));

// Public model tools expose projected metadata and explicitly authorized content.
// Host checks still control reads, claims, and sends; human UI data stays private.
export const TRAE_WORK_TOOLS = Object.freeze([
  nativeTool(tool("hellolynk_list_pending_messages", EMPTY_SCHEMA, { readOnlyHint: false, openWorldHint: false, destructiveHint: false, idempotentHint: true })),
  nativeTool(tool("hellolynk_claim_message", pendingSchema(), { readOnlyHint: false, openWorldHint: false, destructiveHint: false, idempotentHint: false })),
  TRAE_WORK_INTERNAL_TOOLS[0], TRAE_WORK_INTERNAL_TOOLS[1],
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_get_unread_count"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_list_authorized_contacts"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_list_authorized_inbox_messages"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_read_authorized_inbox_message"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_list_authorized_contact_requests"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_read_authorized_contact_request"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_send_authorized_message"),
  TRAE_WORK_INTERNAL_TOOLS.find((item) => item.name === "hellolynk_reply_authorized_message"),
]);

export function createRestrictedStdioMcpSurface(options = {}) {
  const publicErrorCodes = new Set([...COMMON_PUBLIC_ERROR_CODES, ...(options.publicErrorCodes || [])]);
  const serverInfo = Object.freeze({
    name: safeSurfaceText(options.name, "restricted_surface_name_invalid"),
    title: safeSurfaceText(options.title, "restricted_surface_title_invalid"),
    version: safeSurfaceText(options.version || packageMetadata.version, "restricted_surface_version_invalid"),
  });
  if (!Array.isArray(options.tools) || options.tools.length < 1 || options.tools.length > 32) throw codeError("restricted_surface_tools_invalid");
  return Object.freeze({
    protocolVersion: options.protocolVersion || TRAE_WORK_MCP_PROTOCOL_VERSION,
    supportedProtocolVersions: Object.freeze(options.supportedProtocolVersions || [...TRAE_WORK_MCP_SUPPORTED_PROTOCOL_VERSIONS]),
    serverInfo, instructions: safeSurfaceText(options.instructions, "restricted_surface_instructions_invalid", 1_000),
    tools: Object.freeze([...options.tools]), isPublicErrorCode: (code) => publicErrorCodes.has(code),
  });
}

export const TRAE_WORK_MCP_SURFACE = createRestrictedStdioMcpSurface({
  name: "hellolynk-trae-work", title: "HelloLynk 通讯", version: packageMetadata.version, tools: TRAE_WORK_TOOLS,
  instructions: conversationGuidance + "“打开 HelloLynk”调用 hellolynk_open_inbox 一次，再用 OpenPreview 打开返回地址。",
  publicErrorCodes: [
    "neutral_trae_work_binding_configuration_required", "neutral_trae_work_binding_invalid",
    "neutral_trae_work_capability_ambiguous", "neutral_trae_work_capability_binding_mismatch",
    "neutral_trae_work_capability_missing",
  ],
});

export async function runTraeWorkStdioMcpServer(options = {}) {
  const adapter = options.adapter; if (!adapter) throw codeError("neutral_host_adapter_required");
  const uiActionGate = options.uiActionGate || createTraeUiActionGate();
  const input = options.input || process.stdin; const output = options.output || process.stdout;
  const rl = readline.createInterface({ input, crlfDelay: Number.POSITIVE_INFINITY });
  const stop = () => rl.close(); process.once("SIGINT", stop); process.once("SIGTERM", stop);
  try {
    for await (const line of rl) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line, "utf8") > TRAE_WORK_MCP_MAX_FRAME_BYTES) { write(output, jsonRpcError(null, -32600, "frame_too_large")); continue; }
      await handleTraeWorkMcpLine(line, output, {
        adapter, surface: options.surface || TRAE_WORK_MCP_SURFACE, uiActionGate,
        openInbox: options.openInbox,
        privateUiEnabled: options.privateUiEnabled === true,
      });
    }
  } finally { process.removeListener("SIGINT", stop); process.removeListener("SIGTERM", stop); }
}
export async function handleTraeWorkMcpLine(line, output, runtime) {
  let message; try { message = JSON.parse(line); } catch { write(output, jsonRpcError(null, -32700, "parse_error")); return; }
  const response = await handleTraeWorkJsonRpcMessage(message, runtime); if (response) write(output, response);
}
export async function handleTraeWorkJsonRpcMessage(message, runtime = {}) {
  const surface = runtime.surface || TRAE_WORK_MCP_SURFACE;
  const id = isPlainObject(message) && Object.hasOwn(message, "id") ? message.id : null;
  if (!isPlainObject(message) || !exactKeysAllowed(message, ["id", "jsonrpc", "method", "params"])
    || message.jsonrpc !== "2.0" || typeof message.method !== "string"
    || (Object.hasOwn(message, "id") && !validId(message.id))) return jsonRpcError(id, -32600, "invalid_request");
  if (!Object.hasOwn(message, "id")) return null;
  try { return { jsonrpc: "2.0", id: message.id, result: await dispatchTraeWorkMcp(message.method, message.params, { ...runtime, surface }) }; }
  catch (error) {
    const code = toRestrictedStdioPublicErrorCode(error, surface);
    return jsonRpcError(message.id, code === "method_not_found" ? -32601 : code === "invalid_params" ? -32602 : -32603, code);
  }
}
export async function dispatchTraeWorkMcp(method, params, runtime = {}) {
  const run = () => dispatchWithoutModelNotices(method, params, runtime);
  return method === "tools/call" ? withHelloLynkModelNotices(run) : run();
}

async function dispatchWithoutModelNotices(method, params, runtime = {}) {
  const surface = runtime.surface || TRAE_WORK_MCP_SURFACE;
  if (method === "initialize") return {
    protocolVersion: negotiateInitializeProtocolVersion(params, surface), capabilities: { tools: { listChanged: false } },
    serverInfo: surface.serverInfo, instructions: surface.instructions,
  };
  if (method === "ping") { assertEmptyParams(params); return {}; }
  if (method === "tools/list") { assertEmptyParams(params); return { tools: surface.tools }; }
  if (method === "tools/call") return callTool(
    params,
    runtime.adapter,
    surface,
    runtime.uiActionGate || DEFAULT_UI_ACTION_GATE,
    runtime.openInbox,
    runtime.privateUiEnabled === true,
  );
  throw codeError("method_not_found");
}

async function callTool(params, adapter, surface, uiActionGate, openInbox, privateUiEnabled) {
  if (!isModelInboxTool(params?.name)) return callToolWithoutInboxScope(params, adapter, surface, uiActionGate, openInbox, privateUiEnabled);
  try {
    const invocation = await prepareModelInboxInvocation(adapter, { name: params.name, args: params.arguments || {}, readEnvelope: true, detailTarget: "data",
      caller: params._meta?.chatSessionId ? { threadId: params._meta.chatSessionId } : undefined });
    return invocation.finish(await callToolWithoutInboxScope({ ...params, arguments: invocation.args },
      invocation.adapter, surface, uiActionGate, openInbox, privateUiEnabled));
  } catch (error) {
    if (params.name === 'hellolynk_reply_authorized_message') return authorizedMessagingFailure(error, surface,
      { phase: error?.code === 'model_inbox_scope_invalid' ? 'input_validation' : 'preparation' });
    return failure(error, surface);
  }
}

async function callToolWithoutInboxScope(params, adapter, surface, uiActionGate, openInbox, privateUiEnabled) {
  if (!isPlainObject(params) || !exactKeysAllowed(params, ["_meta", "arguments", "name"])
    || typeof params.name !== "string"
    || (Object.hasOwn(params, "_meta") && !isPlainObject(params._meta))
    || (Object.hasOwn(params, "arguments") && !isPlainObject(params.arguments))) throw codeError("invalid_params");
  // MCP defines CallToolRequestParams.arguments as optional. TRAE omits it for
  // parameterless tools and may add protocol _meta; neither changes tool input.
  const args = Object.hasOwn(params, "arguments") ? params.arguments : {};
  const writeAttempt = ["hellolynk_send_authorized_message", "hellolynk_reply_authorized_message"].includes(params.name) ? { phase: "input_validation" } : null;
  try {
    if (!surface.tools.some((item) => item.name === params.name) && privateUiEnabled !== true) {
      throw codeError("unknown_tool");
    }
    if (params.name === "hellolynk_open_inbox") {
      assertArguments(args, []);
      if (typeof openInbox !== "function") throw codeError("trae_local_web_launch_unavailable");
      const launched = await openInbox();
      if (launched?.launched !== true || !/^http:\/\/127\.0\.0\.1:\d{1,5}\/inbox$/.test(String(launched.cleanUrl || ""))) {
        throw codeError("trae_local_web_launch_invalid");
      }
      return success(resultText.ready(launched.cleanUrl), createDynamicUiEnvelope("action", "ready", {
        message: "HelloLynk 已就绪。",
        actionId: "trae-inbox-browser-open",
        state: "ready",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 120_000,
        url: launched.cleanUrl,
      }, { exposure: "aggregate-only" }));
    }
    const pending = await pendingTool(params.name, args, adapter);
    if (pending) return pending;
    if (params.name === "hellolynk_host_status") {
      assertArguments(args, []); const status = projectStatus(await adapter.hostStatus());
      return success("本机 HelloLynk 已连接。", createDynamicUiEnvelope("status", "ready", status, { exposure: "aggregate-only" }));
    }
    if (params.name === "hellolynk_get_unread_count") {
      assertArguments(args, []);
      const unread = (await adapter.readUnreadCount())?.unreadCount;
      if (!Number.isSafeInteger(unread) || unread < 0) throw codeError("host_app_response_invalid");
      return success(resultText.unread(unread), createDynamicUiEnvelope("status", "ready", { counts: { unread } }, { exposure: "aggregate-only" }));
    }
    if (params.name === "hellolynk_list_authorized_contacts") {
      const result = await findContacts(args, (query) => adapter.listAuthorizedContacts(query));
      const contacts = (Array.isArray(result?.contacts) ? result.contacts : []).map((item) => ({
        contactId: safeId(item?.contactId, "contact_id_invalid", 198),
        displayName: safeDisplayName(item?.displayName, "contact_display_name_invalid"),
        recipientDelegateId: safeId(item?.recipientDelegateId, "recipient_delegate_id_invalid", 198),
        instanceDisplayName: safeDisplayName(item?.instanceDisplayName, "instance_display_name_invalid"),
      }));
      return success(resultText.contacts(contacts.length), createDynamicUiEnvelope("status", "ready", {
        authorizedContacts: contacts, ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}),
      }, { exposure: "aggregate-only" }));
    }
    if (params.name === "hellolynk_list_authorized_inbox_messages") {
      const older = isPlainObject(args) && Object.hasOwn(args, "before");
      assertArguments(args, older ? ["before"] : []);
      const result = await adapter.listAuthorizedInboxMessages(older ? { before: safeId(args.before, "local_message_id_invalid", 198) } : {});
      const messages = (Array.isArray(result?.messages) ? result.messages : []).map((item) => ({
        localMessageId: safeId(item?.localMessageId, "local_message_id_invalid", 198),
        conversationKey: safeId(item?.conversationKey, "conversation_key_invalid", 240),
        localDelegateId: safeId(item?.localDelegateId, "local_delegate_id_invalid", 198),
        peerDelegateId: safeId(item?.peerDelegateId, "peer_delegate_id_invalid", 198),
        contactId: item?.contactId === null ? null : safeId(item?.contactId, "contact_id_invalid", 198),
        displayName: safeDisplayName(item?.displayName, "contact_display_name_invalid"),
        ...(item.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeDisplayName(item.peerInstanceDisplayName, "instance_display_name_invalid") }),
        unread: item?.unread === true,
        createdAt: safeText(item?.createdAt || "", "timestamp_invalid", 80), ...replyHint(item),
      }));
      return success(resultText.inbox(messages.length, older), createDynamicUiEnvelope("status", "ready", {
        authorizedMessages: messages,
      }, { exposure: "metadata-only" }));
    }
    if (params.name === "hellolynk_read_authorized_inbox_message") {
      assertArguments(args, ["localMessageId", "conversationKey"]);
      const result = await adapter.readAuthorizedInboxMessage(safeId(args.localMessageId, "local_message_id_invalid", 198), safeId(args.conversationKey, "conversation_key_invalid", 240));
      return success("已读取来信。", createDynamicUiEnvelope("message", "ready", { message: projectExternalMessage(result?.message ?? result) }, { exposure: "selected-content" }));
    }
    if (params.name === "hellolynk_list_authorized_contact_requests") {
      assertArguments(args, []); const result = await adapter.listAuthorizedContactRequests();
      const requests = (result?.requests || []).map(projectRequestMetadata);
      return success(`联系申请 ${requests.length} 条。`, createDynamicUiEnvelope("status", "ready", { authorizedContactRequests: requests }, { exposure: "metadata-only" }));
    }
    if (params.name === "hellolynk_read_authorized_contact_request") {
      assertArguments(args, ["localRecordId", "conversationKey"]);
      const result = await adapter.readAuthorizedContactRequest(safeId(args.localRecordId, "local_record_id_invalid", 198), safeId(args.conversationKey, "conversation_key_invalid", 240));
      return success("已读取联系申请。", createDynamicUiEnvelope("message", "ready", { request: projectExternalRequest(result?.request ?? result) }, { exposure: "selected-content" }));
    }
    if (params.name === "hellolynk_send_authorized_message") {
      assertArguments(args, sendArgumentKeys(args));
      if (Object.values(args).some((value) => typeof value !== "string")) throw codeError("invalid_params");
      if (!Object.hasOwn(args, "contact")) {
        safeId(args.contactId, "contact_id_invalid", 198); safeId(args.recipientDelegateId, "recipient_delegate_id_invalid", 198);
      }
      optionalTarget(args);
      writeAttempt.clientMessageId = authorizedWriteId(args.clientMessageId);
      const text = safeText(args.text, "message_text_invalid", 20_000, 20 * 1024, true);
      try {
        writeAttempt.phase = "preparation";
        const recipient = await sendRecipient(args, (query) => adapter.listAuthorizedContacts(query));
        const input = {
          ...optionalTarget(args),
          clientMessageId: writeAttempt.clientMessageId,
          contactId: safeId(recipient.contactId, "contact_id_invalid", 198),
          recipientDelegateId: safeId(recipient.recipientDelegateId, "recipient_delegate_id_invalid", 198),
          text,
        };
        const originRegistered = await rememberToolOrigin(adapter, params._meta, input);
        writeAttempt.phase = "adapter_call";
        const result = await adapter.sendAuthorizedMessage(input);
        writeAttempt.phase = "response_validation";
        if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist"
          || result.clientMessageId !== input.clientMessageId || result.contactId !== input.contactId
          || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) throw codeError("host_app_response_invalid");
        const receipt = firstSendReceipt(input, result.status);
        return success(receipt.text, createDynamicUiEnvelope("action", "ready", {
          accepted: true, operation: "authorized_send", contactId: input.contactId, clientMessageId: input.clientMessageId,
          recipientDelegateId: input.recipientDelegateId, originRegistered,
          destination: receipt.destination,
          status: result.status,
        }, { exposure: "aggregate-only" }));
      } catch (error) {
        return authorizedMessagingFailure(error, surface, writeAttempt);
      }
    }
    if (params.name === "hellolynk_reply_authorized_message") {
      assertArguments(args, ["localMessageId", "conversationKey", "clientMessageId", "text"]);
      if ([args.localMessageId, args.conversationKey, args.clientMessageId, args.text].some((value) => typeof value !== "string")) throw codeError("invalid_params");
      writeAttempt.clientMessageId = authorizedWriteId(args.clientMessageId);
      const input = {
        localMessageId: safeId(args.localMessageId, "local_message_id_invalid", 198),
        conversationKey: safeId(args.conversationKey, "conversation_key_invalid", 240),
        clientMessageId: writeAttempt.clientMessageId,
        text: safeText(args.text, "message_text_invalid", 20_000, 20 * 1024, true),
      };
      try {
        writeAttempt.phase = "preparation";
        await adapter.assertModelInboxReply(input);
        const originRegistered = await rememberToolOrigin(adapter, params._meta, input);
        writeAttempt.phase = "adapter_call";
        const result = await adapter.replyAuthorizedMessage(input);
        writeAttempt.phase = "response_validation";
        if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist"
          || result.clientMessageId !== input.clientMessageId
          || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) throw codeError("host_app_response_invalid");
        const status = safeText(result.status, "human_action_status_invalid", 80);
        return success(resultText.sent(status, input.clientMessageId), createDynamicUiEnvelope("action", "ready", {
          accepted: true, operation: "authorized_reply", localMessageId: input.localMessageId,
          clientMessageId: input.clientMessageId, originRegistered,
          contactId: safeId(result.contactId, "contact_id_invalid", 198),
          status,
        }, { exposure: "aggregate-only" }));
      } catch (error) {
        return authorizedMessagingFailure(error, surface, writeAttempt);
      }
    }
    if (params.name === "hellolynk_render_inbox") {
      assertArguments(args, []); const [raw, contacts, requests, outbox] = await Promise.all([
        adapter.readInbox(), adapter.listContacts(), adapter.listContactRequests(), adapter.readOutbox(),
      ]); const envelope = projectInboxView(raw);
      const allIds = raw.messages.map((item) => safeId(item.localMessageId, "local_message_id_invalid", 198));
      const readIds = raw.messages.filter((item) => item.unread === false)
        .map((item) => safeId(item.localMessageId, "local_message_id_invalid", 198));
      const grants = privateUiEnabled ? [
        ...(allIds.length ? [uiActionGate.issue({ toolName: "hellolynk_mark_inbox_message_read", mode: "subset", allowedIds: allIds })] : []),
        ...(readIds.length ? [uiActionGate.issue({ toolName: "hellolynk_delete_read_inbox_messages", mode: "subset", allowedIds: readIds })] : []),
        ...(outbox.messages.filter((item) => item.retryAllowed === true).length ? [uiActionGate.issue({ toolName: "hellolynk_retry_outbox_message", mode: "subset", allowedIds: outbox.messages.filter((item) => item.retryAllowed === true).map((item) => safeId(item.clientMessageId, "outbox_message_id_invalid", 198)) })] : []),
        ...(contacts.contacts.length ? [uiActionGate.issue({ toolName: "hellolynk_save_contact", mode: "subset", allowedIds: contacts.contacts.map((item) => safeId(item.contactId, "contact_id_invalid", 198)) }), uiActionGate.issue({ toolName: "hellolynk_delete_contact", mode: "subset", allowedIds: contacts.contacts.map((item) => safeId(item.contactId, "contact_id_invalid", 198)) })] : []),
        uiActionGate.issue({ toolName: "hellolynk_save_contact", mode: "new-contact", allowedIds: [] }),
        uiActionGate.issue({ toolName: "hellolynk_request_human_send", mode: "send-form", allowedIds: contacts.contacts.map((item) => safeId(item.contactId, "contact_id_invalid", 198)) }),
      ] : [];
      return success("HelloLynk message metadata is available to the installed TRAE extension.", envelope, privateUiEnabled
        ? createPrivateUiMeta(projectPrivateInboxDashboard(raw, contacts, requests, outbox), grants)
        : null);
    }
    if (params.name === "hellolynk_read_inbox_message") {
      assertArguments(args, ["localMessageId"]); const id = safeId(args.localMessageId, "local_message_id_invalid", 198);
      const raw = await adapter.readInbox();
      const modelEnvelope = projectSelectedMessageMetadata(raw, id);
      let privateMeta = null;
      if (privateUiEnabled) {
        const privateEnvelope = projectSelectedMessage(raw, id);
        const selected = raw.messages.find((item) => item.localMessageId === id);
        const toolName = selected.unread === true ? "hellolynk_mark_inbox_message_read" : "hellolynk_delete_read_inbox_messages";
        const grant = uiActionGate.issue({ toolName, mode: "exact", allowedIds: [id] });
        privateMeta = createPrivateUiMeta(privateEnvelope, [grant]);
      }
      return success(
        "One user-selected message is available only to the private HelloLynk TRAE extension bridge.",
        modelEnvelope,
        privateMeta,
      );
    }
    if (params.name === "hellolynk_mark_inbox_message_read") {
      assertArguments(args, ["confirm", "localMessageId", "uiActionToken"]); assertConfirmed(args.confirm);
      const id = safeId(args.localMessageId, "local_message_id_invalid", 198);
      uiActionGate.consume(args.uiActionToken, { toolName: params.name, targetIds: [id] });
      const raw = await adapter.markInboxMessageRead(id);
      return success("The selected local message was marked read.", localAction("message_marked_read", { localMessageId: safeId(raw.localMessageId, "local_message_id_invalid", 198), unread: raw.unread }));
    }
    if (params.name === "hellolynk_delete_read_inbox_messages") {
      assertArguments(args, ["confirm", "localMessageIds", "uiActionToken"]); assertConfirmed(args.confirm);
      const ids = safeIdArray(args.localMessageIds, "local_message_ids_invalid", 500);
      uiActionGate.consume(args.uiActionToken, { toolName: params.name, targetIds: ids });
      const raw = await adapter.deleteReadInboxMessages(ids);
      return success("The Host deleted only the selected local read messages.", localAction("read_messages_deleted", { deletedCount: safeInteger(raw.deletedCount, "local_message_ids_invalid") }));
    }
    if (params.name === "hellolynk_render_contacts") {
      assertArguments(args, []); const [contacts, requests] = await Promise.all([adapter.listContacts(), adapter.listContactRequests()]);
      const envelope = projectContactsView(contacts, requests);
      const privateMeta = privateUiEnabled ? createPrivateUiMeta(envelope, [
        uiActionGate.issue({ toolName: "hellolynk_save_contact", mode: "new-contact", allowedIds: [] }),
      ]) : null;
      return success("Contact metadata and model-safe request counts are available to the installed HelloLynk TRAE extension.", envelope, privateMeta);
    }
    if (params.name === "hellolynk_get_contact_detail") {
      assertArguments(args, ["contactId"]); const id = safeId(args.contactId, "contact_id_invalid", 198);
      const envelope = projectContactDetail(await adapter.listContacts(), id);
      const grants = privateUiEnabled ? [
        uiActionGate.issue({ toolName: "hellolynk_save_contact", mode: "exact", allowedIds: [id] }),
        uiActionGate.issue({ toolName: "hellolynk_delete_contact", mode: "exact", allowedIds: [id] }),
      ] : [];
      return success("One user-selected contact is available to the private HelloLynk TRAE extension bridge.", envelope,
        privateUiEnabled ? createPrivateUiMeta(envelope, grants) : null);
    }
    if (params.name === "hellolynk_save_contact") {
      assertArgumentsAllowed(
        args,
        ["confirm", "contactId", "displayName", "hellolynkId", "uiActionToken"],
        ["confirm", "displayName", "hellolynkId", "uiActionToken"],
      );
      assertConfirmed(args.confirm);
      const targetIds = args.contactId == null ? [] : [safeId(args.contactId, "contact_id_invalid", 198)];
      uiActionGate.consume(args.uiActionToken, { toolName: params.name, targetIds });
      const raw = await adapter.saveContact({
        ...(targetIds.length ? { contactId: targetIds[0] } : {}),
        hellolynkId: safeHelloLynkId(args.hellolynkId), displayName: safeDisplayName(args.displayName, "contact_display_name_invalid"),
      });
      return success("The contact was saved by HelloLynk on this computer.", createDynamicUiEnvelope("action", "ready", {
        operation: "contact_saved", contactId: safeId(raw.contact?.contactId, "contact_id_invalid", 198),
        displayName: safeDisplayName(raw.contact?.displayName, "contact_display_name_invalid"),
      }, { exposure: "aggregate-only" }));
    }
    if (params.name === "hellolynk_delete_contact") {
      assertArguments(args, ["confirm", "contactId", "uiActionToken"]); assertConfirmed(args.confirm);
      const id = safeId(args.contactId, "contact_id_invalid", 198);
      uiActionGate.consume(args.uiActionToken, { toolName: params.name, targetIds: [id] });
      const raw = await adapter.deleteContact(id);
      return success("The selected local contact record was deleted.", localAction("contact_deleted", { contactId: id, removed: raw.removed === true }));
    }
    if (params.name === "hellolynk_render_outbox") {
      assertArguments(args, []); const raw = await adapter.readOutbox(); const envelope = projectOutboxView(raw);
      const retryableIds = raw.messages.filter((item) => item.retryAllowed === true)
        .map((item) => safeId(item.clientMessageId, "outbox_message_id_invalid", 198));
      const grants = privateUiEnabled && retryableIds.length
        ? [uiActionGate.issue({ toolName: "hellolynk_retry_outbox_message", mode: "subset", allowedIds: retryableIds })]
        : [];
      return success("HelloLynk sent-message status metadata is available to the installed TRAE extension.", envelope,
        privateUiEnabled ? createPrivateUiMeta(envelope, grants) : null);
    }
    if (params.name === "hellolynk_retry_outbox_message") {
      assertArguments(args, ["clientMessageId", "confirm", "uiActionToken"]); assertConfirmed(args.confirm);
      const id = safeId(args.clientMessageId, "outbox_message_id_invalid", 198);
      uiActionGate.consume(args.uiActionToken, { toolName: params.name, targetIds: [id] });
      const grant = await adapter.issueOutboxRetryGrant(id);
      const raw = await adapter.retryOutboxMessage(id, grant.retryGrant); const message = raw.message;
      return success("The Host processed the explicit retry request.", localAction("outbox_retry_requested", {
        clientMessageId: safeId(message?.clientMessageId, "outbox_message_id_invalid", 198),
        status: safeId(message?.status, "human_action_status_invalid", 198), retryAllowed: message?.retryAllowed === true,
      }));
    }
    if (params.name === "hellolynk_render_send_form") {
      assertArguments(args, []); const contacts = await adapter.listContacts(); const envelope = projectSendForm(contacts);
      const privateMeta = privateUiEnabled ? createPrivateUiMeta(envelope, [uiActionGate.issue({
        toolName: "hellolynk_request_human_send", mode: "send-form",
        allowedIds: contacts.contacts.map((item) => safeId(item.contactId, "contact_id_invalid", 198)),
      })]) : null;
      return success("The human-confirmed send form is available to the private HelloLynk TRAE extension bridge.", envelope, privateMeta);
    }
    if (params.name === "hellolynk_request_human_send") {
      assertArgumentsAllowed(
        args,
        ["clientMessageId", "confirm", "contactId", "recipientHelloLynkId", "text", "uiActionToken"],
        ["clientMessageId", "confirm", "text", "uiActionToken"],
      );
      assertConfirmed(args.confirm);
      const hasContact = Object.hasOwn(args, "contactId"); const hasRecipient = Object.hasOwn(args, "recipientHelloLynkId");
      if (hasContact === hasRecipient) throw codeError("recipient_selection_invalid");
      let recipientHelloLynkId;
      if (hasContact) {
        const contactId = safeId(args.contactId, "contact_id_invalid", 198);
        uiActionGate.consume(args.uiActionToken, {
          toolName: params.name, targetIds: [contactId], recipientKind: "contact",
        });
        const contacts = await adapter.listContacts();
        const contact = contacts.contacts?.find((item) => item.contactId === contactId);
        if (!contact) throw codeError("contact_recipient_not_found");
        recipientHelloLynkId = safeHelloLynkId(contact.hellolynkId);
      } else {
        recipientHelloLynkId = safeHelloLynkId(args.recipientHelloLynkId);
        uiActionGate.consume(args.uiActionToken, {
          toolName: params.name, targetIds: [], recipientKind: "typed",
        });
      }
      const input = {
        clientMessageId: safeId(args.clientMessageId, "client_message_id_invalid", 198), recipientHelloLynkId,
        text: safeText(args.text, "message_text_invalid", 20_000, 20 * 1024, true),
      };
      const raw = await adapter.requestHumanSend(input); assertNoSensitiveProjection(raw, [input.recipientHelloLynkId, input.text]);
      return success("Native human confirmation was requested; this tool did not approve or send the message.", projectActionView(raw, "等待本机 HelloLynk 原生确认"));
    }
    if (params.name === "hellolynk_get_human_send_status") {
      assertArguments(args, ["actionId"]); const id = safeId(args.actionId, "action_id_invalid", 198);
      return success("Native confirmation status is available to the installed HelloLynk TRAE extension.", projectActionView(await adapter.getHumanSendStatus(id), "本机 HelloLynk 原生确认状态"));
    }
    throw codeError("unknown_tool");
  } catch (error) { return writeAttempt ? authorizedMessagingFailure(error, surface, writeAttempt) : failure(error, surface); }
}

async function rememberToolOrigin(adapter, meta, input) {
  // TRAE's native MCP executor supplies chatSessionId outside tool arguments.
  // Registration failure never changes the message's single send attempt.
  const threadId = meta?.chatSessionId;
  if (typeof threadId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(threadId)) return false;
  try {
    await rememberNativeReplyRoute(await adapter.getNativeTaskScope(), {
      threadId, clientMessageId: input.clientMessageId,
      ...(input.recipientDelegateId ? { peerDelegateId: input.recipientDelegateId }
        : { conversationKey: input.conversationKey }),
    });
    return true;
  } catch { return false; }
}

function localAction(operation, fields) { return createDynamicUiEnvelope("action", "ready", { operation, ...fields }, { exposure: "aggregate-only" }); }
function projectStatus(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["configured", "ok", "status"]) || value.ok !== true || value.configured !== true || value.status !== "attached") throw codeError("neutral_host_status_invalid");
  return { connected: true, configured: true, status: "attached" };
}
function success(text, structuredContent, privateMeta = null) {
  return {
    // MCP clients that only pass content to the model need the same projected
    // result. Never serialize the whole response: _meta belongs to private UI.
    content: [{ type: "text", text }, { type: "text", text: JSON.stringify(structuredContent) }],
    structuredContent,
    ...(privateMeta ? { _meta: privateMeta } : {}),
    isError: false,
  };
}
function failure(error, surface) {
  const nativeError = nativeAddressingError(error);
  if (nativeError) return nativeFailureEnvelope(nativeError);
  const code = toRestrictedStdioPublicErrorCode(error, surface);
  return { ...success(failureText(code), projectErrorView(code)), isError: true };
}
function authorizedMessagingFailure(error, surface, attempt) {
  const nativeError = nativeAddressingError(error, attempt);
  if (nativeError) return nativeFailureEnvelope(nativeError);
  const code = toRestrictedStdioPublicErrorCode(error, surface);
  // Phase and retry policy come only from this invocation, never from an adapter error.
  const { text, ...outcome } = writeFailure(code, attempt.phase);
  const envelope = createDynamicUiEnvelope("error", "blocked", { errorCode: code, ...outcome, phase: attempt.phase,
    ...(attempt.clientMessageId ? { clientMessageId: attempt.clientMessageId } : {}) }, { exposure: "aggregate-only" });
  return { ...success(text, envelope), isError: true };
}
function nativeFailureEnvelope(result) {
  const { ok: _ok, ...fields } = result.structuredContent;
  const envelope = createDynamicUiEnvelope("error", "blocked", fields, { exposure: "aggregate-only" });
  return { ...success(result.content[0].text, envelope), isError: true };
}
function negotiateInitializeProtocolVersion(value, surface) {
  if (!isPlainObject(value) || !exactKeysAllowed(value, ["_meta", "capabilities", "clientInfo", "protocolVersion"])
    || !Object.hasOwn(value, "capabilities") || !Object.hasOwn(value, "clientInfo") || !Object.hasOwn(value, "protocolVersion")
    || typeof value.protocolVersion !== "string" || value.protocolVersion.length > 64 || !isPlainObject(value.capabilities)
    || !isPlainObject(value.clientInfo) || (Object.hasOwn(value, "_meta") && !isPlainObject(value._meta))) throw codeError("invalid_params");
  return surface.supportedProtocolVersions.includes(value.protocolVersion) ? value.protocolVersion : surface.protocolVersion;
}
function assertEmptyParams(value) { if (value == null) return; if (!isPlainObject(value) || Object.keys(value).length) throw codeError("invalid_params"); }
function assertArguments(value, keys) { if (!isPlainObject(value) || !exactKeys(value, keys)) throw codeError("invalid_params"); }
function assertArgumentsAllowed(value, allowed, required) {
  if (!isPlainObject(value) || !exactKeysAllowed(value, allowed) || required.some((key) => !Object.hasOwn(value, key))) throw codeError("invalid_params");
}
function assertConfirmed(value) { if (value !== true) throw codeError("confirmation_required"); }
function assertNoSensitiveProjection(value, sensitive) { const serialized = JSON.stringify(value); if (sensitive.some((item) => item && serialized.includes(item))) throw codeError("human_action_status_invalid"); }
function safeHelloLynkId(value) { const text = String(value || ""); if (!/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(text)) throw codeError("recipient_invalid"); return text; }
function safeContactRequestIntro(value) { return value === "" ? "" : safeText(value, "intro_text_invalid", 20000, 20 * 1024); }
function safeText(value, code, maximum, maximumBytes = maximum, countCodePoints = false) { const text = String(value ?? ""); if (!text || (countCodePoints ? Array.from(text).length : text.length) > maximum || Buffer.byteLength(text, "utf8") > maximumBytes || text.includes("\0")) throw codeError(code); return text; }
// 80 Unicode code points can occupy 160 UTF-16 units and 320 UTF-8 bytes.
function safeDisplayName(value, code) {
  if (typeof value !== "string") throw codeError(code);
  const name = safeText(value, code, 80 * 2, 80 * 4);
  if ([...name].length > 80) throw codeError(code);
  return name;
}
function authorizedWriteId(value) { if (typeof value !== "string" || !WRITE_ID_PATTERN.test(value)) throw codeError("client_message_id_invalid"); return value; }
function safeId(value, code, maximum) { const text = String(value || ""); if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(text) || text.length > maximum) throw codeError(code); return text; }
function safeIdArray(value, code, maximum) { if (!Array.isArray(value) || !value.length || value.length > maximum) throw codeError(code); const ids = value.map((item) => safeId(item, code, 198)); if (new Set(ids).size !== ids.length) throw codeError(code); return ids; }
function strictConversationSchema(id) {
  const message = id === "localMessageId";
  return Object.freeze({ type: "object", additionalProperties: false, required: [id, "conversationKey"], properties: Object.freeze({
    [id]: message ? { ...ID_SCHEMA, description: paramText.localMessageId } : ID_SCHEMA,
    conversationKey: message ? { ...ID_SCHEMA, description: paramText.conversationKey } : ID_SCHEMA }) });
}
function projectExternalMessage(value) { if (!projectInboxReadState(value) || value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid"); return { localMessageId: safeId(value?.localMessageId, "local_message_id_invalid", 198), conversationKey: safeId(value?.conversationKey, "conversation_key_invalid", 240), localDelegateId: safeId(value?.localDelegateId, "local_delegate_id_invalid", 198), peerDelegateId: safeId(value?.peerDelegateId, "peer_delegate_id_invalid", 198), peerPrincipalId: safeId(value?.peerPrincipalId, "peer_principal_id_invalid", 198), contactId: value?.contactId === null ? null : safeId(value?.contactId, "contact_id_invalid", 198), displayName: safeDisplayName(value?.displayName, "contact_display_name_invalid"), ...(value.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeDisplayName(value.peerInstanceDisplayName, "instance_display_name_invalid") }), messageType: safeId(value?.messageType || "text", "message_type_invalid", 80), unread: value?.unread === true, createdAt: safeText(value?.createdAt, "timestamp_invalid", 80), text: safeText(value?.text, "message_text_invalid", 20000, 20 * 1024, true), source: requireSource(value?.source, "hellolynk_external_message"), ...(value.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}), ...projectInboxReadState(value), ...replyHint(value) }; }
function projectRequestMetadata(value) { return { localRecordId: safeId(value?.localRecordId, "local_record_id_invalid", 198), conversationKey: safeId(value?.conversationKey, "conversation_key_invalid", 240), localDelegateId: safeId(value?.localDelegateId, "local_delegate_id_invalid", 198), sender: { hellolynkId: safeText(value?.sender?.hellolynkId, "sender_hellolynk_id_invalid", 200), verifiedDisplayName: safeText(value?.sender?.verifiedDisplayName, "sender_display_name_invalid", 160) }, state: safeId(value?.state, "request_state_invalid", 80), receivedAt: safeText(value?.receivedAt, "timestamp_invalid", 80) }; }
function projectExternalRequest(value) { if (value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid"); return { ...projectRequestMetadata(value), introText: safeContactRequestIntro(value?.introText), source: requireSource(value?.source, "hellolynk_contact_request"), readDoesNotMarkRead: value?.readDoesNotMarkRead === true }; }
function requireSource(value, expected) { if (value !== expected) throw codeError("external_content_source_invalid"); return expected; }
function safeInteger(value, code) { const number = Number(value); if (!Number.isSafeInteger(number) || number < 0) throw codeError(code); return number; }
export function toTraeWorkPublicErrorCode(error) { return toRestrictedStdioPublicErrorCode(error, TRAE_WORK_MCP_SURFACE); }
export function toRestrictedStdioPublicErrorCode(error, surface = TRAE_WORK_MCP_SURFACE) { const code = typeof error?.code === "string" ? error.code : ""; return surface.isPublicErrorCode(code) ? code : "hellolynk_operation_failed"; }
function safeSurfaceText(value, code, maximum = 120) { const text = String(value || ""); if (!text || text.length > maximum || /[\r\n\0]/.test(text)) throw codeError(code); return text; }
function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function exactKeysAllowed(value, allowed) { const set = new Set(allowed); return Object.keys(value).every((key) => set.has(key)); }
function isPlainObject(value) { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const proto = Object.getPrototypeOf(value); return proto === Object.prototype || proto === null; }
function validId(value) { return value === null || typeof value === "string" || Number.isSafeInteger(value); }
function jsonRpcError(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }
function write(output, value) { output.write(`${JSON.stringify(value)}\n`); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) { process.stderr.write(`${JSON.stringify({ ok: false, error: "trae_work_mcp_proxy_required" })}\n`); process.exitCode = 1; }

function pendingInput(args, finish = false) {
  const keys = finish ? ["localMessageId", "conversationKey", "claimId", "outcome"] : ["localMessageId", "conversationKey"];
  if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).length !== keys.length
    || keys.some((key) => !Object.hasOwn(args, key))
    || [args.localMessageId, args.conversationKey].some((value) => typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(value))
    || (finish && (typeof args.claimId !== "string" || !/^inclaim_[a-f0-9]{48}$/.test(args.claimId) || !["completed", "unknown"].includes(args.outcome)))) throw codeError("invalid_params");
  return args;
}
function pendingSchema() {
  return { type: "object", additionalProperties: false,
    properties: { batchId: { type: "string", pattern: "^inbatch_[a-f0-9]{48}$", description: paramText.batchId },
      localMessageId: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$", description: paramText.localMessageId },
      conversationKey: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$", description: paramText.conversationKey } },
    oneOf: [{ required: ["batchId"], not: { anyOf: [{ required: ["localMessageId"] }, { required: ["conversationKey"] }] } },
      { required: ["localMessageId", "conversationKey"], not: { required: ["batchId"] } }] };
}
export function projectPendingMessages(result) {
  if (!Array.isArray(result?.messages) || result.messages.length > 1000) throw codeError("host_app_response_invalid");
  return result.messages.map((value) => {
    pendingInput({ localMessageId: value?.localMessageId, conversationKey: value?.conversationKey });
    if (value?.wakeEligible !== true || typeof value.unread !== "boolean"
      || [...(value.contactId === null ? [] : [value.contactId]), value.localDelegateId, value.peerDelegateId].some((id) => typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(id))
      || typeof value.displayName !== "string" || !value.displayName || value.displayName.length > 160 || /[\r\n\0]/.test(value.displayName)
      || typeof value.createdAt !== "string" || value.createdAt.length > 80 || !Number.isFinite(Date.parse(value.createdAt))) throw codeError("host_app_response_invalid");
    return { ...Object.fromEntries(["localMessageId", "conversationKey", "localDelegateId", "peerDelegateId", "contactId", "displayName", "unread", "createdAt", "wakeEligible"].map((key) => [key, value[key]])),
      ...(value.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeDisplayName(value.peerInstanceDisplayName, "instance_display_name_invalid") }) };
  });
}
async function pendingTool(name, args, adapter) {
  if (name === "hellolynk_list_pending_messages") {
    if (Object.keys(args).length) throw codeError("invalid_params");
    const messages = projectPendingMessages(await adapter.listPendingMessages());
    return success(resultText.pending(messages.length), { messages });
  }
  if (name === "hellolynk_claim_message") {
    if (Object.hasOwn(args, "batchId")) {
      if (Object.keys(args).length !== 1 || !/^inbatch_[a-f0-9]{48}$/.test(args.batchId || "")) throw codeError("invalid_params");
      const result = await adapter.claimBatch(args.batchId);
      if (!Array.isArray(result?.messages) || result.claimed !== (result.messages.length > 0)
        || !Number.isSafeInteger(result.expiredCount) || result.expiredCount < 0) throw codeError("host_app_response_invalid");
      const messages = result.messages.map(projectExternalMessage);
      if (messages.reduce((count, m) => count + Array.from(m.text).length, 0) > 20000) throw codeError("host_app_response_invalid");
      const notice = result.claimed ? (result.expiredCount ? `另有 ${result.expiredCount} 条较早来信超出单次读取上限，未处理。` : null) : "这批来信已读取，无需重复读取。";
      return success(result.claimed ? resultText.claimed(messages.length, result.expiredCount) : notice, { claimed: result.claimed, messages, expiredCount: result.expiredCount, notice });
    }
    pendingInput(args);
    const result = await adapter.claimMessage(args.localMessageId, args.conversationKey);
    if (result?.claimed === false && result.claimId === null && result.message === null) return success("此来信已被领取或处理。", { claimed: false, claimId: null, message: null });
    if (result?.claimed !== true || typeof result.claimId !== "string" || !/^inclaim_[a-f0-9]{48}$/.test(result.claimId)) throw codeError("host_app_response_invalid");
    const message = projectExternalMessage(result.message);
    if (message.localMessageId !== args.localMessageId || message.conversationKey !== args.conversationKey
      || !projectInboxReadState(message) || result.message?.wakeEligible !== true) throw codeError("host_app_response_invalid");
    return success(resultText.claimed(1), { claimed: true, claimId: result.claimId, message: { ...message, wakeEligible: true } });
  }

  return null;
}
