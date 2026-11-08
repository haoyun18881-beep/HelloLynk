#!/usr/bin/env node
import { rememberNativeReplyRoute } from "../../../clients/core/hellolynk-native-reply-routes.mjs";
import { prepareModelInboxInvocation, isModelInboxTool } from "../../../clients/core/hellolynk-model-inbox.mjs";
import { nativeTool, optionalTarget, nativeAddressingError, replyHint, conversationGuidance, firstSendReceipt, paramText, resultText, sendArgumentKeys, sendRecipient, findContacts, writeFailure, failureText } from "../../../clients/core/hellolynk-native-addressing-tools.cjs";
import { withHelloLynkModelNotices } from "../../../clients/core/hellolynk-model-notices.cjs";

import path from "node:path";
import { projectInboxReadState } from "../../../clients/core/hellolynk-inbox-read-state.mjs";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import packageMetadata from "../package.json" with { type: "json" };

if (packageMetadata.name !== "@hellolynk-ai/workbuddy-mcp"
  || typeof packageMetadata.version !== "string" || !/^\d+\.\d+\.\d+$/.test(packageMetadata.version)) {
  throw codeError("workbuddy_package_metadata_invalid");
}

export const WORKBUDDY_MCP_PROTOCOL_VERSION = "2025-06-18";
export const WORKBUDDY_MCP_MAX_FRAME_BYTES = 64 * 1024;

const READ = Object.freeze({ readOnlyHint: true, openWorldHint: false, destructiveHint: false, idempotentHint: true });
const SEND = Object.freeze({ readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: false });

// JSON Schema uses an unflagged ECMA-262 pattern; keep the portable anchors.
const WRITE_ID = Object.freeze({ type: "string", minLength: 3, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$" });
const WRITE_ID_PATTERN = new RegExp(WRITE_ID.pattern);
const CLIENT_MESSAGE_ID = Object.freeze({ ...WRITE_ID, examples: ["msg-a1b2c3-01"], description: paramText.clientMessageId });
const MESSAGE_TEXT = Object.freeze({ type: "string", minLength: 1, maxLength: 20000, description: paramText.text });

// Human writes belong to the same-origin shared Workbench -> Host command pair,
// never to an MCP App resource or an integration-owned action grant.
// nativeTool adds the titles and descriptions every client shares.
export const WORKBUDDY_TOOLS = Object.freeze([
  tool("hellolynk_reply_authorized_message", { type: "object", additionalProperties: false, required: ["localMessageId", "conversationKey", "clientMessageId", "text"], properties: { localMessageId: { ...WRITE_ID, description: paramText.localMessageId }, conversationKey: { ...WRITE_ID, description: paramText.conversationKey }, clientMessageId: CLIENT_MESSAGE_ID, text: MESSAGE_TEXT } }, SEND),
  tool("hellolynk_list_pending_messages", emptySchema(), { readOnlyHint: false, openWorldHint: false, destructiveHint: false, idempotentHint: true }),
  tool("hellolynk_claim_message", pendingSchema(), { readOnlyHint: false, openWorldHint: false, destructiveHint: false, idempotentHint: false }),
  tool("hellolynk_host_status", emptySchema(), READ),
  tool("hellolynk_open_inbox", emptySchema(), READ),
  tool("hellolynk_get_unread_count", emptySchema(), READ),
  tool("hellolynk_list_authorized_contacts", emptySchema(), READ),
  tool("hellolynk_send_authorized_message", authorizedSendSchema(), SEND),
  tool("hellolynk_list_authorized_inbox_messages", historySchema(), READ),
  tool("hellolynk_read_authorized_inbox_message", strictConversationSchema("localMessageId"), READ),
  tool("hellolynk_list_authorized_contact_requests", emptySchema(), READ),
  tool("hellolynk_read_authorized_contact_request", strictConversationSchema("localRecordId"), READ),
].map(nativeTool));

export const WORKBUDDY_MCP_SURFACE = Object.freeze({
  name: "hellolynk-workbuddy", title: "HelloLynk 通讯", version: packageMetadata.version, tools: WORKBUDDY_TOOLS,
});

export async function runWorkBuddyStdioMcpServer(options = {}) {
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const rl = readline.createInterface({ input, crlfDelay: Number.POSITIVE_INFINITY });
  for await (const line of rl) {
    if (!line.trim()) continue;
    if (Buffer.byteLength(line, "utf8") > WORKBUDDY_MCP_MAX_FRAME_BYTES) {
      write(output, rpcError(null, -32600, "frame_too_large"));
      continue;
    }
    await handleWorkBuddyMcpLine(line, output, { adapter: options.adapter, openLocalWeb: options.openLocalWeb, nativeTaskStatus: options.nativeTaskStatus, getModelInboxCaller: options.getModelInboxCaller });
  }
}

export async function handleWorkBuddyMcpLine(line, output, runtime = {}) {
  let message;
  try { message = JSON.parse(line); }
  catch { write(output, rpcError(null, -32700, "parse_error")); return; }
  const result = await handleWorkBuddyJsonRpcMessage(message, runtime);
  if (result) write(output, result);
}

export async function handleWorkBuddyJsonRpcMessage(message, runtime = {}) {
  if (!plain(message) || message.jsonrpc !== "2.0" || typeof message.method !== "string") return rpcError(message?.id ?? null, -32600, "invalid_request");
  if (message.method.startsWith("notifications/")) return null;
  try {
    const result = await dispatchWorkBuddyMcp(message.method, message.params || {}, runtime);
    return message.id === undefined ? null : { jsonrpc: "2.0", id: message.id, result };
  } catch (error) {
    return message.id === undefined ? null : rpcError(message.id, -32603, safeErrorCode(error));
  }
}

export async function dispatchWorkBuddyMcp(method, params, runtime = {}) {
  const run = () => dispatchWithoutModelNotices(method, params, runtime);
  return method === "tools/call" ? withHelloLynkModelNotices(run) : run();
}

async function dispatchWithoutModelNotices(method, params, runtime = {}) {
  if (method === "initialize") return {
    protocolVersion: WORKBUDDY_MCP_PROTOCOL_VERSION,
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: WORKBUDDY_MCP_SURFACE.name, title: WORKBUDDY_MCP_SURFACE.title, version: WORKBUDDY_MCP_SURFACE.version },
    instructions: conversationGuidance + "“打开 HelloLynk”调用 hellolynk_open_inbox 一次，再用内置浏览器打开返回地址。",
  };
  if (method === "ping") return {};
  if (method === "tools/list") return { tools: WORKBUDDY_TOOLS };
  if (method === "tools/call") return callTool(params, requireAdapter(runtime.adapter), runtime.openLocalWeb, runtime.nativeTaskStatus, runtime.getModelInboxCaller);
  if (method === "resources/list") return { resources: [] };
  if (method === "resources/templates/list") return { resourceTemplates: [] };
  if (method === "resources/read") throw codeError("resource_not_found");
  throw codeError("method_not_found");
}

async function callTool(params, adapter, openLocalWeb, nativeTaskStatus, getModelInboxCaller) {
  if (!isModelInboxTool(params?.name)) return callToolWithoutInboxScope(params, adapter, openLocalWeb, nativeTaskStatus);
  try {
    const caller = await getModelInboxCaller?.(params._meta, params.name, params.arguments || {});
    const invocation = await prepareModelInboxInvocation(adapter, { name: params.name, args: params.arguments || {}, caller, readEnvelope: true });
    return invocation.finish(await callToolWithoutInboxScope({ ...params, arguments: invocation.args },
      invocation.adapter, openLocalWeb, nativeTaskStatus, caller));
  } catch (error) {
    if (params.name === 'hellolynk_reply_authorized_message') return authorizedWriteFailure(error,
      { phase: error?.code === 'model_inbox_scope_invalid' ? 'input_validation' : 'preparation' });
    return failure(error);
  }
}

async function callToolWithoutInboxScope(params, adapter, openLocalWeb, nativeTaskStatus, caller) {
  if (!plain(params) || typeof params.name !== "string" || (Object.hasOwn(params, "arguments") && !plain(params.arguments))) throw codeError("invalid_params");
  const args = params.arguments || {};
  const writeAttempt = ["hellolynk_send_authorized_message", "hellolynk_reply_authorized_message"].includes(params.name) ? { phase: "input_validation" } : null;
  try {
    const pending = await pendingTool(params.name, args, adapter);
    if (pending) return pending;
    if (params.name === "hellolynk_host_status") {
      exactArgs(args, []);
      const status = await adapter.hostStatus();
      const native = nativeTaskStatus?.();
      const nativeTasks = native ? { status: /^[a-z_]{1,60}$/.test(native.status) ? native.status : "unavailable", ...(typeof native.errorCode === "string" && /^[a-z_]{1,120}$/.test(native.errorCode) ? { errorCode: native.errorCode } : {}) } : undefined;
      return success("本机 HelloLynk 已连接。", { ok: true, configured: true, status: "attached", startedByWorkBuddy: status.startedHost === true, ...(nativeTasks ? { nativeTasks } : {}) });
    }
    if (params.name === "hellolynk_open_inbox") {
      exactArgs(args, []);
      if (typeof openLocalWeb !== "function") throw codeError("workbuddy_local_web_launch_unavailable");
      const launched = await openLocalWeb();
      if (!/^http:\/\/127\.0\.0\.1:\d{1,5}\/inbox$/.test(String(launched?.cleanUrl || ""))) throw codeError("workbuddy_local_web_launch_invalid");
      return success(resultText.ready(launched.cleanUrl), {
        ok: true, configured: true, status: "ready_for_browser_navigation", url: launched.cleanUrl,
      });
    }
    if (params.name === "hellolynk_get_unread_count") {
      exactArgs(args, []);
      const unread = (await adapter.readUnreadCount())?.unreadCount;
      if (!Number.isSafeInteger(unread) || unread < 0) throw codeError("widget_bundle_invalid");
      return success(resultText.unread(unread), { ok: true, configured: true, status: "running", counts: { unread } });
    }
    if (params.name === "hellolynk_list_authorized_contacts") {
      const result = await findContacts(args, (query) => adapter.listAuthorizedContacts(query));
      const contacts = Array.isArray(result?.contacts) ? result.contacts.map((item) => ({
        contactId: safeId(item?.contactId, 80), displayName: safeString(item?.displayName, 160),
        recipientDelegateId: safeId(item?.recipientDelegateId, 198),
        instanceDisplayName: safeString(item?.instanceDisplayName, 160),
      })) : [];
      return success(resultText.contacts(contacts.length), {
        ok: true, authorizedContacts: contacts, ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}),
      });
    }
    if (params.name === "hellolynk_list_authorized_inbox_messages") {
      const older = Object.hasOwn(args, "before");
      exactArgs(args, older ? ["before"] : []);
      const result = await adapter.listAuthorizedInboxMessages(older ? { before: safeId(args.before, 198) } : {});
      const messages = Array.isArray(result?.messages) ? result.messages.map((item) => ({
        localMessageId: safeId(item?.localMessageId, 198), contactId: item?.contactId === null ? null : safeId(item?.contactId, 80),
        conversationKey: safeId(item?.conversationKey, 240),
        localDelegateId: safeId(item?.localDelegateId, 198), peerDelegateId: safeId(item?.peerDelegateId, 198),
        displayName: safeString(item?.displayName, 160), ...(item.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeString(item.peerInstanceDisplayName, 160) }), unread: item?.unread === true,
        createdAt: safeString(item?.createdAt || "", 80, true), ...replyHint(item),
      })) : [];
      return success(resultText.inbox(messages.length, older), { ok: true, authorizedMessages: messages });
    }
    if (params.name === "hellolynk_reply_authorized_message") {
      exactArgs(args, ["localMessageId", "conversationKey", "clientMessageId", "text"]);
      if (Object.values(args).some(value => typeof value !== "string")) throw codeError("invalid_params");
      const input = { localMessageId: authorizedWriteId(args.localMessageId), conversationKey: authorizedWriteId(args.conversationKey), clientMessageId: authorizedWriteId(args.clientMessageId) };
      writeAttempt.clientMessageId = input.clientMessageId;
      input.text = safeBody(args.text, 20 * 1024, true);
      writeAttempt.phase = "preparation";
      await adapter.assertModelInboxReply(input);
      // Ownership was checked before this
      // best-effort origin registration; never register a denied reply.
      if (caller?.threadId) void (async () => {
        await rememberNativeReplyRoute(await adapter.getNativeTaskScope(), {
          threadId: caller.threadId, clientMessageId: input.clientMessageId, conversationKey: input.conversationKey,
        });
      })().catch(() => {});
      writeAttempt.phase = "adapter_call";
      const result = await adapter.replyAuthorizedMessage(input);
      writeAttempt.phase = "response_validation";
      if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist" || result.clientMessageId !== input.clientMessageId
        || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) throw codeError("host_app_send_result_unknown");
      return success(resultText.sent(result.status, input.clientMessageId), { accepted: true,
        localMessageId: input.localMessageId, conversationKey: input.conversationKey,
        clientMessageId: input.clientMessageId, contactId: safeId(result.contactId, 198), status: result.status });
    }
    if (params.name === "hellolynk_send_authorized_message") {
      exactArgs(args, sendArgumentKeys(args));
      if (Object.values(args).some((value) => typeof value !== "string")) throw codeError("invalid_params");
      if (!Object.hasOwn(args, "contact")) { authorizedWriteId(args.contactId); authorizedWriteId(args.recipientDelegateId); }
      optionalTarget(args);
      const clientMessageId = authorizedWriteId(args.clientMessageId);
      writeAttempt.clientMessageId = clientMessageId;
      const text = safeBody(args.text, 20 * 1024, true);
      writeAttempt.phase = "preparation";
      const { contactId, recipientDelegateId } = await sendRecipient(args, (query) => adapter.listAuthorizedContacts(query));
      writeAttempt.phase = "adapter_call";
      const result = await adapter.sendAuthorizedMessage({ contactId, recipientDelegateId, clientMessageId, text, ...optionalTarget(args) });
      writeAttempt.phase = "response_validation";
      if (result?.accepted !== true || result.ok === false || result.authorization !== "contact_delegate_allowlist"
        || result.contactId !== contactId || result.clientMessageId !== clientMessageId
        || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result.status)) {
        throw codeError("host_app_send_result_unknown");
      }
      const status = safeId(result.status, 80);
      const receipt = firstSendReceipt(args, status);
      return success(receipt.text, {
        accepted: true, clientMessageId, contactId, recipientDelegateId, status, destination: receipt.destination,
      });
    }
    if (params.name === "hellolynk_read_authorized_inbox_message") {
      exactArgs(args, ["localMessageId", "conversationKey"]);
      const result = await adapter.readAuthorizedInboxMessage(safeId(args.localMessageId, 198), safeId(args.conversationKey, 240));
      return success("已读取来信。", { ok: true, message: projectExternalMessage(result?.message ?? result) });
    }
    if (params.name === "hellolynk_list_authorized_contact_requests") {
      exactArgs(args, []); const result = await adapter.listAuthorizedContactRequests();
      const requests = (result?.requests || []).map(projectRequestMetadata);
      return success(`联系申请 ${requests.length} 条。`, { ok: true, authorizedContactRequests: requests });
    }
    if (params.name === "hellolynk_read_authorized_contact_request") {
      exactArgs(args, ["localRecordId", "conversationKey"]);
      const result = await adapter.readAuthorizedContactRequest(safeId(args.localRecordId, 198), safeId(args.conversationKey, 240));
      return success("已读取联系申请。", { ok: true, request: projectExternalRequest(result?.request ?? result) });
    }
    throw codeError("unknown_tool");
  } catch (error) {
    return writeAttempt ? authorizedWriteFailure(error, writeAttempt) : failure(error);
  }
}

function authorizedWriteId(value) { if (typeof value !== "string" || !WRITE_ID_PATTERN.test(value)) throw codeError("identifier_invalid"); return value; }
function authorizedWriteFailure(error, attempt) {
  const nativeError = nativeAddressingError(error, attempt);
  if (nativeError) return nativeError;
  const errorCode = attempt.phase === "input_validation" && error?.code === "external_content_text_invalid" ? error.code : safeErrorCode(error);
  // Phase and retry policy come only from this invocation, never from an adapter error.
  const { text, ...outcome } = writeFailure(errorCode, attempt.phase);
  return { content: [{ type: "text", text }], structuredContent: { ok: false, configured: true, errorCode, ...outcome,
    phase: attempt.phase, ...(attempt.clientMessageId ? { clientMessageId: attempt.clientMessageId } : {}) }, isError: true };
}

function success(text, structuredContent) { return { content: [{ type: "text", text }, { type: "text", text: JSON.stringify(structuredContent) }], structuredContent, isError: false }; }
function failure(error) {
  const nativeError = nativeAddressingError(error);
  if (nativeError) return nativeError;
  const errorCode = safeErrorCode(error);
  const deleted = errorCode === "host_app_reply_target_deleted";
  return { content: [{ type: "text", text: failureText(errorCode) }], structuredContent: { ok: false, configured: true,
    status: deleted ? "not_delivered" : "blocked", errorCode, ...(deleted ? { automaticRetryAllowed: false } : {}) }, isError: true };
}

export function toWorkBuddyPublicErrorCode(error) { return safeErrorCode(error); }
function requireAdapter(value) { if (!value) throw codeError("neutral_host_adapter_unavailable"); return value; }
function tool(name, inputSchema, annotations) { return Object.freeze({ name, inputSchema, annotations }); }
function emptySchema() { return { type: "object", additionalProperties: false, properties: {} }; }
function historySchema() { return { type: "object", additionalProperties: false, properties: { before: { type: "string", minLength: 3, maxLength: 198, description: paramText.before } } }; }
function authorizedSendSchema() { return { type: "object", additionalProperties: false, required: ["clientMessageId", "text"], properties: { contactId: WRITE_ID, recipientDelegateId: WRITE_ID, clientMessageId: CLIENT_MESSAGE_ID, text: MESSAGE_TEXT } }; }
function strictConversationSchema(id) {
  const message = id === "localMessageId";
  return { type: "object", additionalProperties: false, required: [id, "conversationKey"], properties: {
    [id]: { type: "string", minLength: 3, maxLength: 198, ...(message ? { description: paramText.localMessageId } : {}) },
    conversationKey: { type: "string", minLength: 3, maxLength: 240, ...(message ? { description: paramText.conversationKey } : {}) } } };
}
function exactArgs(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw codeError("invalid_params"); }
function safeId(value, maximum) { const result = String(value || ""); if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(result) || result.length > maximum) throw codeError("identifier_invalid"); return result; }
function safeString(value, maximum, empty = false) { const result = String(value ?? ""); if ((!empty && !result) || result.length > maximum || /[\r\n\0]/.test(result)) throw codeError("string_invalid"); return result; }
function safeContactRequestIntro(value) { return value === "" ? "" : safeBody(value); }
function safeBody(value, maximumBytes = 20 * 1024, countCodePoints = false) { const result = String(value ?? ""); if (!result || (countCodePoints ? Array.from(result).length : result.length) > 20000 || Buffer.byteLength(result, "utf8") > maximumBytes || result.includes("\0")) throw codeError("external_content_text_invalid"); return result; }
function projectExternalMessage(value) { if (!projectInboxReadState(value) || value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid"); return { localMessageId: safeId(value?.localMessageId, 198), conversationKey: safeId(value?.conversationKey, 240), localDelegateId: safeId(value?.localDelegateId, 198), peerDelegateId: safeId(value?.peerDelegateId, 198), peerPrincipalId: safeId(value?.peerPrincipalId, 198), contactId: value?.contactId === null ? null : safeId(value?.contactId, 198), displayName: safeString(value?.displayName, 160), ...(value.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeString(value.peerInstanceDisplayName, 160) }), messageType: safeId(value?.messageType || "text", 80), unread: value?.unread === true, createdAt: safeString(value?.createdAt, 80), text: safeBody(value?.text, 20 * 1024, true), source: requireSource(value?.source, "hellolynk_external_message"), ...(value.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}), ...projectInboxReadState(value), ...replyHint(value) }; }
function projectRequestMetadata(value) { return { localRecordId: safeId(value?.localRecordId, 198), conversationKey: safeId(value?.conversationKey, 240), localDelegateId: safeId(value?.localDelegateId, 198), sender: { hellolynkId: safeString(value?.sender?.hellolynkId, 200), verifiedDisplayName: safeString(value?.sender?.verifiedDisplayName, 160) }, state: safeId(value?.state, 80), receivedAt: safeString(value?.receivedAt, 80) }; }
function projectExternalRequest(value) { if (value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid"); return { ...projectRequestMetadata(value), introText: safeContactRequestIntro(value?.introText), source: requireSource(value?.source, "hellolynk_contact_request"), readDoesNotMarkRead: value?.readDoesNotMarkRead === true }; }
function requireSource(value, expected) { if (value !== expected) throw codeError("external_content_source_invalid"); return expected; }
function safeErrorCode(error) {
  const value = String(error?.code || error?.message || "hellolynk_operation_failed");
  if (["host_native_inbox_upgrade_required", "hellolynk_node_22_16_required", "powershell7_missing"].includes(value)) return value;
  if (["native_addressing_arguments_invalid", "native_directory_cursor_invalid", "native_directory_query_invalid", "native_conversation_id_invalid"].includes(value)) return value;
  return /^(neutral_(?:host|workbuddy)_[a-z0-9_]{1,100}|host_app_[a-z0-9_]{1,100}|workbuddy_local_web_launch_[a-z0-9_]{1,100}|workbuddy_page_(?:task|service)_[a-z0-9_]{1,100}|resource_not_found|method_not_found|unknown_tool|invalid_params|identifier_invalid|string_invalid|widget_bundle_invalid)$/.test(value) ? value : "hellolynk_operation_failed";
}
function rpcError(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }
function write(output, value) { output.write(`${JSON.stringify(value)}\n`); }
function plain(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: "workbuddy_mcp_proxy_required" })}\n`);
  process.exitCode = 1;
}

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
      ...(value.peerInstanceDisplayName == null ? {} : { peerInstanceDisplayName: safeString(value.peerInstanceDisplayName, 160) }) };
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
      if (!result.claimed) return success(safeString(result.notice ?? "这批来信已读取，无需重复读取。", 200), { claimed: false, messages: [], expiredCount: result.expiredCount });
      const messages = result.messages.map(projectExternalMessage);
      if (messages.reduce((count, m) => count + Array.from(m.text).length, 0) > 20000) throw codeError("host_app_response_invalid");
      return success(resultText.claimed(messages.length, result.expiredCount), { claimed: true, messages, expiredCount: result.expiredCount });
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
