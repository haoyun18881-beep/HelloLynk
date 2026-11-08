#!/usr/bin/env node
import { prepareModelInboxInvocation, isModelInboxTool } from "../runtime/core/hellolynk-model-inbox.mjs";
import { inspectCodexExecutorMetadata } from "./native-task-client.mjs";
import { nativeTool, optionalTarget, nativeAddressingError, replyHint, conversationGuidance, firstSendReceipt, paramText, resultText, sendArgumentKeys, sendRecipient, findContacts, writeFailure, failureText } from "../runtime/core/hellolynk-native-addressing-tools.cjs";
import { withHelloLynkModelNotices, captureHelloLynkNativeDeliveryStatus } from "../runtime/core/hellolynk-model-notices.cjs";

import readline from "node:readline";
import { projectInboxReadState } from "../runtime/core/hellolynk-inbox-read-state.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CODEX_WORKBENCH_RESOURCE_META } from "./workbench-runtime.mjs";
import packageMetadata from "../package.json" with { type: "json" };

if (packageMetadata.name !== "@hellolynk-ai/codex-plugin"
  || typeof packageMetadata.version !== "string" || !/^\d+\.\d+\.\d+$/.test(packageMetadata.version)) {
  throw codeError("codex_package_metadata_invalid");
}

const WRITE_ID = Object.freeze({ type: "string", minLength: 3, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$" });
const WRITE_ID_PATTERN = new RegExp(WRITE_ID.pattern);
const CLIENT_MESSAGE_ID = Object.freeze({ ...WRITE_ID, examples: ["msg-a1b2c3-01"], description: paramText.clientMessageId });
const MESSAGE_TEXT = Object.freeze({ type: "string", minLength: 1, maxLength: 20000, description: paramText.text });

const PROTOCOL_VERSION = "2025-06-18";
const VERSIONED_WORKBENCH_URI_RE = /^ui:\/\/hellolynk\/workbench-codex-[a-f0-9]{64}\.html$/;

const TOOL_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  openWorldHint: false,
  destructiveHint: false,
  idempotentHint: true,
});
const LOCAL_WRITE_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  openWorldHint: false,
  destructiveHint: false,
  idempotentHint: true,
});
const WORKBENCH_COMMAND_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  openWorldHint: true,
  destructiveHint: true,
  idempotentHint: false,
});
const SEND_ANNOTATIONS = Object.freeze({
  readOnlyHint: false,
  openWorldHint: true,
  destructiveHint: false,
  idempotentHint: false,
});
const WORKBENCH_CONNECT_TOOL = "hellolynk_workbench_connect";
const WORKBENCH_SNAPSHOT_TOOL = "hellolynk_workbench_snapshot";
const WORKBENCH_CHANGES_TOOL = "hellolynk_workbench_changes";
const WORKBENCH_ACTION_GRANT_TOOL = "hellolynk_workbench_action_grant";
const WORKBENCH_COMMAND_TOOL = "hellolynk_workbench_command";
const OPEN_HELLOLYNK_TOOL = "hellolynk_open";

// nativeTool adds the titles and descriptions every client shares.
const neutralTools = [
  {
    name: OPEN_HELLOLYNK_TOOL,
    title: "打开 HelloLynk",
    description: "在聊天里显示 HelloLynk 卡片。",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: TOOL_ANNOTATIONS,
  },
  {
    name: "hellolynk_get_unread_count",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: TOOL_ANNOTATIONS,
  },
  {
    name: "hellolynk_list_authorized_contacts",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: TOOL_ANNOTATIONS,
  },
  {
    name: "hellolynk_send_authorized_message",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["clientMessageId", "text"],
      properties: {
        contactId: WRITE_ID,
        recipientDelegateId: WRITE_ID,
        clientMessageId: CLIENT_MESSAGE_ID,
        text: MESSAGE_TEXT,
      },
    },
    annotations: SEND_ANNOTATIONS,
  },
  {
    name: "hellolynk_list_authorized_inbox_messages",
    inputSchema: { type: "object", additionalProperties: false, properties: {
      before: { type: "string", minLength: 3, maxLength: 198, description: paramText.before },
    } },
    annotations: TOOL_ANNOTATIONS,
  },
  {
    name: "hellolynk_read_authorized_inbox_message",
    inputSchema: strictConversationSchema("localMessageId"), annotations: TOOL_ANNOTATIONS,
  },
  { name: "hellolynk_list_pending_messages",
    inputSchema: { type: "object", additionalProperties: false, properties: {} }, annotations: LOCAL_WRITE_ANNOTATIONS },
  { name: "hellolynk_claim_message",
    inputSchema: { type: "object", additionalProperties: false, properties: {
      batchId: { type: "string", minLength: 3, maxLength: 128, description: paramText.batchId },
      localMessageId: { type: "string", minLength: 3, maxLength: 240, description: paramText.localMessageId },
      conversationKey: { type: "string", minLength: 3, maxLength: 240, description: paramText.conversationKey },
    }, oneOf: [{ required: ["batchId"] }, { required: ["localMessageId", "conversationKey"] }] }, annotations: LOCAL_WRITE_ANNOTATIONS },
  { name: "hellolynk_reply_authorized_message",
    inputSchema: { type: "object", additionalProperties: false, required: ["localMessageId", "conversationKey", "clientMessageId", "text"], properties: {
      localMessageId: { ...WRITE_ID, description: paramText.localMessageId },
      conversationKey: { ...WRITE_ID, description: paramText.conversationKey },
      clientMessageId: CLIENT_MESSAGE_ID, text: MESSAGE_TEXT,
    } }, annotations: SEND_ANNOTATIONS },
  {
    name: "hellolynk_list_authorized_contact_requests",
    inputSchema: { type: "object", additionalProperties: false, properties: {} }, annotations: TOOL_ANNOTATIONS,
  },
  {
    name: "hellolynk_read_authorized_contact_request",
    inputSchema: strictConversationSchema("localRecordId"), annotations: TOOL_ANNOTATIONS,
  },

].map(nativeTool);

export async function runStdioMcpServer(options = {}) {
  const neutralAdapter = options.neutralAdapter || null;
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const rl = readline.createInterface({
    input,
    crlfDelay: Number.POSITIVE_INFINITY,
  });
  const stopMcp = () => {
    rl.close();
  };
  process.once("SIGINT", stopMcp);
  process.once("SIGTERM", stopMcp);
  let commands = Promise.resolve();
  let appReads = Promise.resolve();
  let failure;
  let protocolWarmupStarted = false;
  const serve = async (line) => {
    const { message: handled, response } = await handleLine(line, output, {
        neutralAdapter,
        prepareAuthorizedWrite: options.prepareAuthorizedWrite,
        readNativeDeliveryStatus: options.readNativeDeliveryStatus,
        ...(options.workbenchCandidate === undefined ? {} : { workbenchCandidate: options.workbenchCandidate }),
      }) || {};
      if (!protocolWarmupStarted && response?.result
        && ["initialize", "tools/list"].includes(handled?.method)
        && typeof options.onProtocolReady === "function") {
        // Codex may cache tools/list entirely. Start once after a successful
        // handshake (or catalog response), never on an invalid request and
        // never in the response's critical path. Real calls can retry failure.
        protocolWarmupStarted = true;
        Promise.resolve()
          .then(() => options.onProtocolReady())
          .catch(() => {});
      }
      if (handled?.method === "tools/call"
        && !(WORKBENCH_READ_TOOLS.has(handled.params?.name) && handled.params?.name !== OPEN_HELLOLYNK_TOOL)
        && typeof options.onExecutorToolCall === "function") {
        // Only the executor-owned MCP request envelope can identify the
        // current Codex task. App-only polling is not a model turn and must
        // not retarget its receiver while a different model turn is sending.
        // The model-visible open tool still registers its executor context.
        // External tool arguments are never inspected.
        Promise.resolve()
          .then(() => options.onExecutorToolCall(handled.params?._meta))
          .catch(() => {});
      }
  };
  try {
    for await (const line of rl) {
      if (!line.trim()) continue;
      let message;
      try { message = JSON.parse(line); } catch { /* handleLine reports parse_error */ }
      const method = message?.method;
      // HTML and protocol responses do not wait for Host startup. They remain
      // available while a Host operation is waiting, so the UI can display its
      // own bounded wait/error state. Business calls retain their original order;
      // an unknown write result must never cause replay or concurrent execution.
      if (method === undefined || STATIC_MCP_METHODS.has(method) || method?.startsWith?.("notifications/")) {
        await serve(line);
      } else if (method === "tools/call" && WORKBENCH_READ_TOOLS.has(message.params?.name)) {
        // The card's read-only account/snapshot/change queries need not wait
        // for a model send or verification. Keep reads ordered in their own
        // lane; dispatch still checks account revision before and after reads,
        // and Host snapshots retain their authorization/coherence checks.
        appReads = appReads.then(() => failure ? undefined : serve(line)).catch((error) => {
          failure = error;
          stopMcp();
        });
      } else {
        commands = commands.then(() => failure ? undefined : serve(line)).catch((error) => {
          failure = error;
          stopMcp();
        });
      }
    }
    await Promise.all([commands, appReads]);
    if (failure) throw failure;
  } finally {
    process.removeListener("SIGINT", stopMcp);
    process.removeListener("SIGTERM", stopMcp);
  }
}

const STATIC_MCP_METHODS = new Set([
  "initialize", "ping", "tools/list", "resources/list", "resources/templates/list", "resources/read",
]);
const WORKBENCH_READ_TOOLS = new Set([
  OPEN_HELLOLYNK_TOOL,
  "hellolynk_workbench_account", WORKBENCH_SNAPSHOT_TOOL, WORKBENCH_CHANGES_TOOL,
]);

async function handleLine(line, output = process.stdout, runtime = {}) {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    write(jsonRpcError(null, -32700, "parse_error"), output);
    return null;
  }
  const response = await handleJsonRpcMessage(message, runtime);
  if (response) write(response, output);
  return { message, response };
}

export async function handleJsonRpcMessage(message, runtime = {}) {
  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return jsonRpcError(message?.id ?? null, -32600, "invalid_request");
  }
  if (message.method.startsWith("notifications/")) return null;
  try {
    const result = await dispatch(message.method, message.params || {}, { ...runtime,
      executorMetadata: message.params?._meta });
    return message.id === undefined ? null : { jsonrpc: "2.0", id: message.id, result };
  } catch (error) {
    return message.id === undefined
      ? null
      : jsonRpcError(message.id, -32603, safeErrorCode(error));
  }
}

export async function dispatch(method, params, runtime = {}) {
  const run = async () => {
    const result = await dispatchWithoutModelNotices(method, params, runtime);
    if (method === "tools/call" && !isOpenHelloLynkToolName(params.name)
      && neutralTools.some(tool => tool.name === params.name)) {
      // Do not delay UI refreshes or change a send result if diagnostics fail.
      try { captureHelloLynkNativeDeliveryStatus(await runtime.readNativeDeliveryStatus?.()); } catch {}
    }
    return result;
  };
  return method === "tools/call" ? withHelloLynkModelNotices(run) : run();
}

async function dispatchWithoutModelNotices(method, params, runtime = {}) {
  const workbenchCandidate = runtimeWorkbenchCandidate(runtime);
  const workbenchUnavailable = !workbenchCandidate;
  if (method === "initialize") {
    return {
      // This server implements one protocol version; unknown offers receive
      // that supported counteroffer instead of an arbitrary string echo.
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
      },
      serverInfo: {
        name: "hellolynk-codex-inbox",
        title: "HelloLynk 通讯",
        version: packageMetadata.version,
      },
      instructions: conversationGuidance + "“打开 HelloLynk”时请用户点 Codex 左侧栏的 HelloLynk；要在聊天里显示卡片时调用 hellolynk_open。",
    };
  }
  if (method === "ping") return {};
  if (method === "tools/list") {
    const tools = neutralTools.map((tool) => isOpenHelloLynkToolName(tool.name)
      ? workbenchCandidate ? workbenchOpenTool(tool, workbenchCandidate) : unavailableWorkbenchOpenTool(tool)
      : tool);
    return {
      tools: workbenchCandidate
        ? [
            ...tools,
            workbenchCandidateTool(workbenchCandidate),
            ...(typeof workbenchCandidate.readChanges === "function" ? [workbenchChangesToolDefinition(workbenchCandidate)] : []),
            ...(typeof workbenchCandidate.connectAccount === "function" ? [workbenchConnectTool()] : []),
            ...(workbenchCandidate.connectAccount?.readAccountState ? [workbenchAccountTool(false), workbenchAccountTool(true)] : []),
            ...(typeof workbenchCandidate.executeCommand === "function"
              ? [workbenchActionGrantTool(workbenchCandidate), workbenchCommandTool(workbenchCandidate)]
              : []),
          ].map((tool) => withAccountRevision(tool, workbenchCandidate))
        : tools,
    };
  }
  if (method === "tools/call") return callTool(params, runtime);
  if (method === "resources/list") {
    return {
      resources: workbenchCandidate ? [{
        uri: workbenchCandidate.resourceUri,
        name: "HelloLynk 通讯界面",
        title: "HelloLynk 通讯",
        description: typeof workbenchCandidate.executeCommand === "function"
          ? "阶段 F MCP App；只显示本机 HelloLynk 报告的真实能力，缺失能力由界面隐藏或由本机 HelloLynk 拒绝。"
          : "阶段 F 共享 HelloLynk 通讯只读 MCP App。",
        mimeType: "text/html;profile=mcp-app",
      }] : [],
    };
  }
  if (method === "resources/templates/list") return { resourceTemplates: [] };
  if (method === "resources/read") {
    if (workbenchCandidate) {
      // Codex may retain a previous invocation's URI after a plugin upgrade.
      // Keep advertising the current content hash for cache refresh, but serve
      // the installed UI for this same entry's older hashes. No old UI is read.
      const retainedWorkbenchEntry = typeof params.uri === "string"
        && VERSIONED_WORKBENCH_URI_RE.test(params.uri)
        && VERSIONED_WORKBENCH_URI_RE.test(workbenchCandidate.resourceUri);
      if (params.uri !== workbenchCandidate.resourceUri && !retainedWorkbenchEntry) throw codeError("resource_not_found");
      return {
        contents: [{
          uri: params.uri,
          mimeType: "text/html;profile=mcp-app",
          text: workbenchCandidate.html,
          _meta: CODEX_WORKBENCH_RESOURCE_META,
        }],
      };
    }
    throw codeError("resource_not_found");
  }
  throw codeError("method_not_found");
}

async function callTool(params, runtime = {}) {
  if (!runtime.neutralAdapter || !isModelInboxTool(params?.name)) return callToolWithoutInboxScope(params, runtime);
  try {
    const source = inspectCodexExecutorMetadata(runtime.executorMetadata);
    const invocation = await prepareModelInboxInvocation(runtime.neutralAdapter, {
      name: params.name, args: params.arguments || {},
      caller: !source.conflict && source.threadId ? { threadId: source.threadId } : undefined,
    });
    return invocation.finish(await callToolWithoutInboxScope({ ...params, arguments: invocation.args },
      { ...runtime, neutralAdapter: invocation.adapter }));
  } catch (error) {
    if (params.name === 'hellolynk_reply_authorized_message') return authorizedWriteToolError(error, undefined,
      'authorized_reply_result_unknown', error?.code === 'model_inbox_scope_invalid' ? 'input_validation' : 'preparation');
    return nativeAddressingError(error) || toolError(safeErrorCode(error));
  }
}

async function callToolWithoutInboxScope(params, runtime = {}) {
  const name = String(params?.name || "");
  const workbenchCandidate = runtimeWorkbenchCandidate(runtime);
  const workbenchUnavailable = !workbenchCandidate;
  const accounts = workbenchCandidate?.connectAccount;
  const surfaceError = name === WORKBENCH_CHANGES_TOOL ? workbenchChangesError : workbenchSurfaceToolError;
  if (accounts?.readAccountState && ["hellolynk_workbench_account", "hellolynk_workbench_disconnect"].includes(name)) {
    try {
      const disconnect = name === "hellolynk_workbench_disconnect";
      assertExactArgumentKeys(params?.arguments, disconnect ? ["revision"] : []);
      const result = disconnect ? await accounts.disconnectAccount(params.arguments) : accounts.readAccountState();
      return { content: [], structuredContent: { ok: true }, _meta: { hellolynkWorkbench: { [disconnect ? "disconnection" : "account"]: result } }, isError: false };
    } catch (error) { return workbenchSurfaceToolError(error?.code || "workbench_account_unavailable", "账号操作"); }
  }
  const revision = params?.arguments?._hellolynkAccountRevision;
  if (accounts?.readAccountState && [WORKBENCH_CONNECT_TOOL, WORKBENCH_SNAPSHOT_TOOL, WORKBENCH_CHANGES_TOOL, WORKBENCH_ACTION_GRANT_TOOL, WORKBENCH_COMMAND_TOOL].includes(name)) {
    try { accounts.assertRevision(revision); }
    catch (error) { return surfaceError(error.code, "账号检查"); }
    const args = { ...params.arguments }; delete args._hellolynkAccountRevision;
    params = { ...params, arguments: args };
  }
  const accountOperation = async (operation, mutation = false) => {
    try {
      if (!accounts?.readAccountState) return await operation();
      if (mutation) return await accounts.runForAccount(revision, operation);
      accounts.assertRevision(revision);
      const result = await operation();
      accounts.assertRevision(revision);
      return result;
    } catch (error) { return surfaceError(error?.code || "workbench_account_unavailable", "账号检查"); }
  };
  if (workbenchUnavailable && isOpenHelloLynkToolName(name)) {
    return workbenchSurfaceToolError("workbench_unavailable", "启动");
  }
  if (workbenchCandidate && isOpenHelloLynkToolName(name)) {
    return workbenchOpenToolCall(params?.arguments);
  }
  if (workbenchCandidate && name === WORKBENCH_CONNECT_TOOL && typeof workbenchCandidate.connectAccount === "function") {
    try {
      assertExactArgumentKeys(params?.arguments, ["hellolynkId", "instanceName"]);
      const connection = await workbenchCandidate.connectAccount(params.arguments, revision);
      return { content: [], structuredContent: { ok: true }, _meta: { hellolynkWorkbench: { connection } }, isError: false };
    } catch (error) { return workbenchSurfaceToolError(error?.code || "workbench_connect_failed", "连接"); }
  }
  if (workbenchCandidate && name === WORKBENCH_SNAPSHOT_TOOL) {
    return accountOperation(() => workbenchSnapshotTool(params?.arguments, workbenchCandidate));
  }
  if (name === WORKBENCH_CHANGES_TOOL) {
    if (typeof workbenchCandidate?.readChanges !== "function") return workbenchChangesError("workbench_changes_unavailable");
    return accountOperation(() => workbenchChangesToolCall(params?.arguments, workbenchCandidate));
  }
  if (workbenchCandidate && name === WORKBENCH_ACTION_GRANT_TOOL
    && typeof workbenchCandidate.issueActionGrant === "function") {
    return accountOperation(() => workbenchActionGrantToolCall(params?.arguments, workbenchCandidate), true);
  }
  if (workbenchCandidate && name === WORKBENCH_COMMAND_TOOL
    && typeof workbenchCandidate.executeCommand === "function") {
    return accountOperation(() => workbenchCommandToolCall(params?.arguments, workbenchCandidate), true);
  }
  if (name === WORKBENCH_ACTION_GRANT_TOOL || name === WORKBENCH_COMMAND_TOOL) {
    return workbenchSurfaceToolError("workbench_action_grant_unavailable", "通讯操作");
  }
  const neutral = runtime.neutralAdapter;
  if (neutral) {
    if (name === "hellolynk_list_authorized_contacts") return neutralListAuthorizedContactsTool(params?.arguments, neutral);
    if (name === "hellolynk_send_authorized_message") return neutralSendAuthorizedMessageTool(params?.arguments, neutral, runtime);
    if (name === "hellolynk_list_authorized_inbox_messages") return neutralListAuthorizedInboxMessagesTool(params?.arguments, neutral);
    if (name === "hellolynk_read_authorized_inbox_message") return neutralReadAuthorizedInboxMessageTool(params?.arguments, neutral);
    if (name === "hellolynk_list_pending_messages") return neutralListPendingMessagesTool(params?.arguments, neutral);
    if (name === "hellolynk_claim_message") return neutralClaimMessageTool(params?.arguments, neutral);
    if (name === "hellolynk_reply_authorized_message") return neutralReplyAuthorizedMessageTool(params?.arguments, neutral, runtime);
    if (name === "hellolynk_list_authorized_contact_requests") return neutralListAuthorizedContactRequestsTool(params?.arguments, neutral);
    if (name === "hellolynk_read_authorized_contact_request") return neutralReadAuthorizedContactRequestTool(params?.arguments, neutral);
    if (![OPEN_HELLOLYNK_TOOL, "hellolynk_get_unread_count"].includes(name)) return toolError("unknown_tool");
  }
  if (![OPEN_HELLOLYNK_TOOL, "hellolynk_get_unread_count"].includes(name)) return toolError("unknown_tool");
  if (!plainEmptyObject(params?.arguments)) return toolError("arguments_not_allowed");
  try {
    if (name === "hellolynk_get_unread_count") return neutralGetUnreadCountTool(neutral);
    if (!neutral) return toolError("neutral_adapter_unavailable");
    return workbenchUnavailable
      ? workbenchSurfaceToolError("workbench_unavailable", "启动")
      : workbenchOpenToolCall(params?.arguments);
  } catch (error) {
    return toolError(safeErrorCode(error));
  }
}

function runtimeWorkbenchCandidate(runtime) {
  const value = runtime?.workbenchCandidate;
  if (value === undefined) return null;
  const keys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).filter((key) => !["connectAccount", "readChanges"].includes(key)).sort().join(",")
    : "";
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![
      "html,readSnapshot,resourceUri,validateReadRequest,validateSnapshot",
      "commandContractId,commandSchemaVersion,commandTypes,executeCommand,html,issueActionGrant,readSnapshot,resourceUri,resultContractId,resultSchemaVersion,snapshotContractId,snapshotSchemaVersion,validateCommand,validateCommandResult,validateReadRequest,validateSnapshot",
    ].includes(keys)
    || typeof value.html !== "string" || value.html.length < 500 || value.html.length > 2_000_000
    || (Object.hasOwn(value, "connectAccount") && typeof value.connectAccount !== "function")
    || (Object.hasOwn(value, "readChanges") && typeof value.readChanges !== "function")
    || typeof value.readSnapshot !== "function"
    || typeof value.validateReadRequest !== "function"
    || typeof value.validateSnapshot !== "function"
    || (Object.hasOwn(value, "executeCommand") && typeof value.executeCommand !== "function")
    || (Object.hasOwn(value, "executeCommand") && typeof value.issueActionGrant !== "function")
    || (Object.hasOwn(value, "executeCommand") && value.executeCommand.length < 2)
    || (Object.hasOwn(value, "executeCommand") && value.issueActionGrant.length < 1)
    || (Object.hasOwn(value, "executeCommand") && typeof value.validateCommand !== "function")
    || (Object.hasOwn(value, "executeCommand") && typeof value.validateCommandResult !== "function")
    || (Object.hasOwn(value, "executeCommand")
      && (value.snapshotContractId !== "hellolynk-workbench-snapshot-v12"
        || value.snapshotSchemaVersion !== 12
        || value.commandContractId !== "hellolynk-workbench-command-v6"
        || value.commandSchemaVersion !== 6
        || value.resultContractId !== "hellolynk-workbench-command-result-v6"
        || value.resultSchemaVersion !== 6))
    || (Object.hasOwn(value, "executeCommand") && !validWorkbenchCommandTypes(value.commandTypes))
    || !/^ui:\/\/hellolynk\/[a-z0-9][a-z0-9._/-]{1,120}\.html$/.test(String(value.resourceUri || ""))) {
    throw codeError("workbench_candidate_runtime_invalid");
  }
  return value;
}

function validWorkbenchCommandTypes(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 100
    && new Set(value).size === value.length
    && value.every((item) => typeof item === "string"
      && /^[a-z][a-z0-9.-]{2,80}$/.test(item));
}

function workbenchOpenTool(baseTool, candidate) {
  return {
    ...baseTool,
    _meta: {
      ...baseTool._meta,
      ui: {
        ...(baseTool._meta?.ui || {}),
        visibility: ["model", "app"],
        resourceUri: candidate.resourceUri,
      },
      "openai/ui": { entrypoints: [{ type: "global" }] },
      "openai/outputTemplate": candidate.resourceUri,
      "openai/toolInvocation/invoking": "正在打开 HelloLynk 通讯",
      "openai/toolInvocation/invoked": "HelloLynk 通讯已打开",
    },
  };
}

function workbenchOpenToolCall(args) {
  if (!plainEmptyObject(args)) return workbenchSurfaceToolError("arguments_not_allowed", "通讯启动");
  return {
    content: [{
      type: "text",
      text: "HelloLynk 卡片已就绪。",
    }],
    structuredContent: { ok: true, status: "ready" },
    isError: false,
  };
}

function unavailableWorkbenchOpenTool(baseTool) {
  const {
    "openai/outputTemplate": _legacyTemplate,
    "openai/toolInvocation/invoking": _legacyInvoking,
    "openai/toolInvocation/invoked": _legacyInvoked,
    ...remainingMeta
  } = baseTool._meta || {};
  const safeMeta = {
    ...remainingMeta,
    ui: { visibility: ["model", "app"] },
  };
  return { ...baseTool, _meta: safeMeta };
}

function isOpenHelloLynkToolName(name) {
  return name === OPEN_HELLOLYNK_TOOL;
}

function workbenchSurfaceToolError(code, operation) {
  const safe = safeErrorCode({ code });
  return {
    content: [{ type: "text", text: safe === "neutral_host_release_superseded" ? failureText(safe) : `HelloLynk${operation}失败：${safe}。` }],
    structuredContent: {
      ok: false,
      status: "blocked",
      errorCode: safe,
    },
    isError: true,
  };
}

function workbenchConnectTool() {
  return {
    name: WORKBENCH_CONNECT_TOOL, title: "连接 HelloLynk",
    description: "由 HelloLynk 聊天卡片发起首次连接；返回官网确认入口。确认账号设备后才建立连接。",
    inputSchema: { type: "object", additionalProperties: false, required: ["hellolynkId", "instanceName"], properties: {
      hellolynkId: { type: "string", pattern: "^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$" },
      instanceName: { type: "string", maxLength: 80 },
    } },
    annotations: { readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: true },
    _meta: { ui: { visibility: ["app"] } },
  };
}

function workbenchAccountTool(disconnect) {
  return {
    name: disconnect ? "hellolynk_workbench_disconnect" : "hellolynk_workbench_account",
    title: disconnect ? "解除设备连接" : "读取当前客户端连接状态",
    description: "仅供 HelloLynk 聊天卡片使用。解除只影响当前客户端，保留旧账号资料。",
    inputSchema: { type: "object", additionalProperties: false, required: disconnect ? ["revision"] : [],
      properties: disconnect ? { revision: { type: "string", pattern: "^(initial|[a-f0-9]{32})$" } } : {} },
    annotations: { readOnlyHint: !disconnect, openWorldHint: false, destructiveHint: disconnect, idempotentHint: true },
    _meta: { ui: { visibility: ["app"] } },
  };
}

function withAccountRevision(tool, candidate) {
  if (!candidate.connectAccount?.readAccountState
    || ![WORKBENCH_CONNECT_TOOL, WORKBENCH_SNAPSHOT_TOOL, WORKBENCH_CHANGES_TOOL, WORKBENCH_ACTION_GRANT_TOOL, WORKBENCH_COMMAND_TOOL].includes(tool.name)) return tool;
  return { ...tool, inputSchema: { ...tool.inputSchema,
    required: [...(tool.inputSchema.required || []), "_hellolynkAccountRevision"],
    properties: { ...tool.inputSchema.properties, _hellolynkAccountRevision: { type: "string", pattern: "^(initial|[a-f0-9]{32})$" } } } };
}

function workbenchChangesToolDefinition(candidate) {
  return {
    name: WORKBENCH_CHANGES_TOOL,
    title: "读取HelloLynk界面变化游标",
    description: "仅供 HelloLynk MCP App 静默检查本机变化；不返回正文或事件身份，不触发模型轮次。",
    inputSchema: { type: "object", additionalProperties: false, required: ["afterCursor"],
      properties: { afterCursor: { type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER } } },
    annotations: TOOL_ANNOTATIONS,
    _meta: { ui: { resourceUri: candidate.resourceUri, visibility: ["app"] } },
  };
}

function workbenchChangesError(code) {
  return { content: [], structuredContent: { ok: true },
    _meta: { hellolynkWorkbench: { changeError: { code: safeErrorCode({ code }) } } }, isError: true };
}

async function workbenchChangesToolCall(args, candidate) {
  try {
    assertExactArgumentKeys(args, ["afterCursor"]);
    if (!Number.isSafeInteger(args?.afterCursor) || args.afterCursor < 0) throw codeError("host_app_change_cursor_invalid");
    const batch = await candidate.readChanges({ afterCursor: args.afterCursor });
    if (!batch || !Number.isSafeInteger(batch.cursor) || batch.cursor < 0
      || !/^[a-f0-9]{48}$/.test(batch.hostGeneration)
      || typeof batch.snapshotRequired !== "boolean" || !Array.isArray(batch.events) || batch.events.length > 256) {
      throw codeError("workbench_changes_invalid");
    }
    return { content: [], structuredContent: { ok: true }, _meta: { hellolynkWorkbench: { changes: {
      cursor: batch.cursor, hostGeneration: batch.hostGeneration,
      snapshotRequired: batch.snapshotRequired, changed: batch.events.length > 0,
    } } }, isError: false };
  } catch (error) { return workbenchChangesError(error?.code || "workbench_changes_failed"); }
}

function workbenchCandidateTool(candidate) {
  return {
    name: WORKBENCH_SNAPSHOT_TOOL,
    title: "读取HelloLynk通讯快照",
    description: "供HelloLynk共享 MCP App 读取本机 HelloLynk 的只读快照；消息正文和联系申请正文不会进入模型可见结果，原始设备核验值不得进入 Codex 结果。",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        threadId: {
          type: "string",
          minLength: 2,
          maxLength: 199,
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$",
        },
        threadCursor: {
          type: "string",
          minLength: 1,
          maxLength: 255,
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$",
        },
        messageCursor: {
          type: "string",
          minLength: 1,
          maxLength: 800,
          pattern: "^[A-Za-z0-9._-]{1,800}$",
        },
        contactRequestCursor: {
          anyOf: [
            { type: "null" },
            { type: "string", minLength: 20, maxLength: 512, pattern: "^[A-Za-z0-9_-]{20,512}$" },
          ],
        },
        historyBefore: { type: ["string", "null"], maxLength: 30 },
        query: { type: "string", maxLength: 512, pattern: "^[^\\u0000]*$" },
        filter: { type: "string", enum: ["all", "unread", "archived"] },
      },
    },
    annotations: TOOL_ANNOTATIONS,
    _meta: {
      ui: { resourceUri: candidate.resourceUri, visibility: ["app"] },
      "openai/outputTemplate": candidate.resourceUri,
    },
  };
}

function workbenchCommandTool(candidate) {
  return {
    name: WORKBENCH_COMMAND_TOOL,
    title: "执行HelloLynk通讯操作",
    description: "仅供HelloLynk MCP App 转交人类界面操作；写操作携带本机 HelloLynk 已签发的一次性私有授权，只读发送状态查询不签发授权，命令正文和完整结果不会进入普通工具结果。",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["command"],
      properties: {
        command: workbenchCommandDtoSchema(candidate),
        _hellolynkUiActionGrant: opaqueWorkbenchActionGrantSchema(),
      },
    },
    annotations: WORKBENCH_COMMAND_ANNOTATIONS,
    _meta: { ui: { resourceUri: candidate.resourceUri, visibility: ["app"] } },
  };
}

function workbenchActionGrantTool(candidate) {
  return {
    name: WORKBENCH_ACTION_GRANT_TOOL,
    title: "准备HelloLynk通讯操作授权",
    description: "仅供HelloLynk MCP App 把当前人类界面操作交给本机 HelloLynk 审核并准备一次性私有授权；授权只返回应用私有元数据。",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["command"],
      properties: { command: workbenchCommandDtoSchema(candidate) },
    },
    annotations: LOCAL_WRITE_ANNOTATIONS,
    _meta: { ui: { resourceUri: candidate.resourceUri, visibility: ["app"] } },
  };
}

function workbenchCommandDtoSchema(candidate) {
  return {
    type: "object",
    additionalProperties: false,
    required: [
      "contractId", "schemaVersion", "command", "requestId",
      "idempotencyKey", "expectedRevision", "payload",
    ],
    properties: {
      contractId: { const: candidate.commandContractId },
      schemaVersion: { const: candidate.commandSchemaVersion },
      command: { type: "string", enum: [...candidate.commandTypes] },
      requestId: { type: "string", minLength: 2, maxLength: 199 },
      idempotencyKey: {
        type: "string", maxLength: 199,
        pattern: "^wb5\\.[a-f0-9]{32}\\.[1-9][0-9]{0,15}\\.[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$",
      },
      expectedRevision: {
        anyOf: [
          { type: "null" },
          { type: "string", minLength: 1, maxLength: 255 },
        ],
      },
      payload: { type: "object" },
    },
  };
}

function opaqueWorkbenchActionGrantSchema() {
  return {
    type: "string",
    minLength: 32,
    maxLength: 512,
    pattern: "^[A-Za-z0-9._~-]{32,512}$",
  };
}

// Preserve only established public read errors. A code-shaped private detail
// is not safe merely because safeErrorCode can normalize it.
const WORKBENCH_SNAPSHOT_READ_ERRORS = new Set([
  "workbench_snapshot_timeout", "workbench_connection_required", "workbench_account_changed",
  "host_request_unauthorized", "host_request_replayed", "host_adapter_route_forbidden",
  "host_nonce_capability_cache_full", "host_nonce_cache_full",
  "host_app_authorization_required", "host_capability_scope_denied",
  "host_capability_human_surface_required", "host_capability_inactive",
  "host_capability_invalid", "host_capability_id_mismatch", "host_capability_resolver_required",
  "host_attachment_not_found", "host_attachment_expired", "host_attachment_ambiguous",
  "neutral_host_discovery_generation_mismatch", "neutral_host_discovery_stale",
  "neutral_host_discovery_invalid", "neutral_host_discovery_owner_mismatch",
  "neutral_host_discovery_unsafe_path", "neutral_host_not_found",
  "neutral_host_launcher_unavailable", "neutral_host_adapter_unavailable", "neutral_adapter_closed",
  "neutral_codex_binding_invalid", "neutral_codex_capability_binding_mismatch",
  "neutral_codex_discovery_timeout", "neutral_codex_launch_failed", "neutral_codex_launch_lock_timeout",
  "neutral_codex_runner_integrity_invalid", "neutral_codex_runner_unavailable",
  "host_not_running", "host_app_unavailable", "host_app_action_failed", "host_app_response_invalid",
  "host_app_workbench_snapshot_failed", "host_app_workbench_thread_not_found",
  "host_app_workbench_cursor_invalid", "host_app_workbench_read_invalid", "host_app_state_conflict",
  "host_app_relationship_status_unavailable", "neutral_host_release_superseded",
]);

function workbenchSnapshotReadError(error) {
  const code = error?.code;
  if (WORKBENCH_SNAPSHOT_READ_ERRORS.has(code)) return code;
  if (code === "neutral_host_http_401") return "host_request_unauthorized";
  if (code === "neutral_host_http_403") return "host_app_authorization_required";
  const networkCode = code ?? error?.cause?.code;
  if (networkCode === "ECONNREFUSED") return "neutral_host_connection_refused";
  if (networkCode === "ECONNRESET") return "neutral_host_connection_reset";
  return "workbench_snapshot_unavailable";
}

async function workbenchSnapshotTool(args, candidate) {
  const input = args ?? {};
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return workbenchSurfaceToolError("invalid_params", "通讯读取");
  }
  let readRequest;
  try {
    readRequest = candidate.validateReadRequest(input);
  } catch {
    return workbenchSurfaceToolError("invalid_params", "通讯读取");
  }
  let rawSnapshot;
  try {
    rawSnapshot = await candidate.readSnapshot(readRequest);
  } catch (error) {
    return workbenchSurfaceToolError(workbenchSnapshotReadError(error), "通讯读取");
  }
  let snapshot;
  try {
    snapshot = candidate.validateSnapshot(rawSnapshot);
    assertNoRawSafetyCodeFields(snapshot);
    if (snapshot.source.mode !== "neutral-host" || snapshot.source.transport !== "mcp-app-rpc") {
      throw codeError("workbench_snapshot_invalid");
    }
  } catch {
    return workbenchSurfaceToolError("workbench_snapshot_invalid", "通讯读取");
  }
  return {
    content: [],
    structuredContent: { ok: true },
    _meta: { hellolynkWorkbench: { snapshot } },
    isError: false,
  };
}

async function workbenchActionGrantToolCall(args, candidate) {
  try {
    assertExactArgumentKeys(args, ["command"]);
    const command = candidate.validateCommand(args.command);
    if (command.command === "message.send-status") throw codeError("workbench_action_grant_invalid");
    const issued = await candidate.issueActionGrant(command);
    assertExactArgumentKeys(issued, ["actionGrant"]);
    const actionGrant = safeOpaqueWorkbenchActionGrant(issued.actionGrant);
    return {
      content: [],
      structuredContent: { ok: true },
      _meta: { hellolynkWorkbench: { actionGrant } },
      isError: false,
    };
  } catch (error) {
    return workbenchSurfaceToolError(
      error?.code === "workbench_action_grant_timeout"
        ? error.code
        : "workbench_action_grant_invalid",
      "通讯授权准备",
    );
  }
}

async function workbenchCommandToolCall(args, candidate) {
  try {
    const command = candidate.validateCommand(args.command);
    const statusRead = command.command === "message.send-status";
    assertExactArgumentKeys(args, statusRead ? ["command"] : ["command", "_hellolynkUiActionGrant"]);
    const actionGrant = statusRead ? null : safeOpaqueWorkbenchActionGrant(args._hellolynkUiActionGrant);
    const result = candidate.validateCommandResult(
      await candidate.executeCommand(command, statusRead ? {} : { actionGrant }),
      command.command,
    );
    assertNoRawSafetyCodeFields(result);
    if (result.requestId !== command.requestId) throw codeError("workbench_candidate_command_result_invalid");
    return {
      content: [],
      structuredContent: { ok: true },
      _meta: { hellolynkWorkbench: { commandResult: result } },
      isError: false,
    };
  } catch {
    return workbenchSurfaceToolError("workbench_command_invalid", "通讯操作");
  }
}

async function neutralGetUnreadCountTool(adapter) {
  if (!adapter || typeof adapter.readUnreadCount !== "function") {
    return toolError("neutral_adapter_unavailable");
  }
  try {
    const result = await adapter.readUnreadCount();
    const unreadCount = result?.unreadCount;
    if (!Number.isSafeInteger(unreadCount) || unreadCount < 0) {
      return toolError("neutral_unread_count_invalid");
    }
    const unreadMessages = unreadCount;
    return {
      content: [{ type: "text", text: resultText.unread(unreadMessages) }],
      structuredContent: {
        ok: true,
        configured: true,
        status: "running",
        counts: { unreadMessages },
      },
      isError: false,
    };
  } catch (error) {
    return toolError(safeErrorCode(error));
  }
}

async function neutralListAuthorizedContactsTool(args, adapter) {
  try {
    const result = await findContacts(args, query => adapter.listAuthorizedContacts(query));
    const contacts = Array.isArray(result?.contacts) ? result.contacts.map((contact) => ({
      contactId: safeIdentifier(contact?.contactId, "contact_id_invalid", 200),
      displayName: safeIdentifier(contact?.displayName, "contact_display_name_invalid", 160),
      recipientDelegateId: safeIdentifier(contact?.recipientDelegateId, "recipient_delegate_id_invalid", 200),
      instanceDisplayName: safeIdentifier(contact?.instanceDisplayName, "instance_display_name_invalid", 160),
    })) : [];
    return {
      content: [{ type: "text", text: resultText.contacts(contacts.length) }],
      structuredContent: { contacts, ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}) },
      isError: false,
    };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralSendAuthorizedMessageTool(args, adapter, runtime) {
  let clientMessageId;
  let phase = "input_validation";
  try {
    if (!args || typeof args !== "object" || Array.isArray(args)) throw codeError("arguments_invalid");
    assertExactArgumentKeys(args, sendArgumentKeys(args));
    if (Object.values(args).some((value) => typeof value !== "string")) throw codeError("arguments_invalid");
    if (!Object.hasOwn(args, "contact")) {
      authorizedWriteIdentifier(args.contactId, "contact_id_invalid");
      authorizedWriteIdentifier(args.recipientDelegateId, "recipient_delegate_id_invalid");
    }
    optionalTarget(args);
    clientMessageId = authorizedWriteIdentifier(args.clientMessageId, "client_message_id_invalid");
    const text = args.text;
    if (!text || text.includes("\u0000") || [...text].length > 20_000 || Buffer.byteLength(text, "utf8") > 20 * 1024) {
      throw codeError("message_text_invalid");
    }
    phase = "preparation";
    const { contactId, recipientDelegateId } = await sendRecipient(args, query => adapter.listAuthorizedContacts(query));
    await runtime?.prepareAuthorizedWrite?.(runtime.executorMetadata, { clientMessageId, peerDelegateId: recipientDelegateId });
    phase = "adapter_call";
    const result = await adapter.sendAuthorizedMessage({ contactId, recipientDelegateId, clientMessageId, text, ...optionalTarget(args) });
    phase = "response_validation";
    if (result?.accepted !== true || result?.ok === false || result?.authorization !== "contact_delegate_allowlist"
      || result?.clientMessageId !== clientMessageId || result?.contactId !== contactId
      || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result?.status)) throw codeError("send_result_invalid");
    const receipt = firstSendReceipt(args, result.status);
    return {
      content: [{ type: "text", text: receipt.text }],
      structuredContent: {
        accepted: true,
        clientMessageId,
        contactId,
        recipientDelegateId,
        status: result.status,
        destination: receipt.destination,
      },
      isError: false,
    };
  } catch (error) { return authorizedWriteToolError(error, clientMessageId, "authorized_send_result_unknown", phase); }
}
async function neutralListAuthorizedInboxMessagesTool(args, adapter) {
  const older = args != null && typeof args === "object" && !Array.isArray(args) && Object.hasOwn(args, "before");
  if (!older && !plainEmptyObject(args)) return toolError("arguments_not_allowed");
  try {
    if (older) assertExactArgumentKeys(args, ["before"]);
    const result = await adapter.listAuthorizedInboxMessages(older
      ? { before: safeIdentifier(args.before, "authorized_inbox_message_id_invalid", 240) } : {});
    const messages = Array.isArray(result?.messages)
      ? result.messages.map(value => ({ ...projectAuthorizedInboxMetadata(value), ...replyHint(value) }))
      : [];
    return {
      content: [{ type: "text", text: resultText.inbox(messages.length, older) }],
      structuredContent: { messages },
      isError: false,
    };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralReadAuthorizedInboxMessageTool(args, adapter) {
  try {
    assertExactArgumentKeys(args, ["localMessageId", "conversationKey"]);
    const message = projectAuthorizedInboxRead(await adapter.readAuthorizedInboxMessage(
      safeIdentifier(args.localMessageId, "authorized_inbox_message_id_invalid", 240),
      safeIdentifier(args.conversationKey, "authorized_inbox_conversation_key_invalid", 240),
    ));
    return { content: [{ type: "text", text: JSON.stringify(message) }], structuredContent: message, isError: false };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralListPendingMessagesTool(args, adapter) {
  if (!plainEmptyObject(args)) return toolError("arguments_not_allowed");
  try {
    const result = await adapter.listPendingMessages();
    if (!Array.isArray(result?.messages) || result.messages.length > 1000) throw codeError("pending_messages_invalid");
    const messages = result.messages.map((value) => {
      if (value?.wakeEligible !== true) throw codeError("pending_message_ineligible");
      return projectAuthorizedInboxMetadata(value);
    });
    return { content: [{ type: "text", text: resultText.pending(messages.length) }], structuredContent: { messages }, isError: false };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralClaimMessageTool(args, adapter) {
  try {
    if (args?.batchId != null) {
      assertExactArgumentKeys(args, ["batchId"]);
      const batchId = safeIdentifier(args.batchId, "authorized_inbox_batch_id_invalid", 128);
      const result = await adapter.claimBatch(batchId);
      if (!Array.isArray(result?.messages) || result.claimed !== (result.messages.length > 0)
        || !Number.isSafeInteger(result.expiredCount) || result.expiredCount < 0) throw codeError("claim_result_invalid");
      const messages = result.messages.map(projectAuthorizedInboxRead);
      if (messages.reduce((n, m) => n + Array.from(m.text).length, 0) > 20000) throw codeError("claim_result_invalid");
      const output = { claimed: result.claimed, messages, expiredCount: result.expiredCount,
        notice: result.claimed ? (result.expiredCount ? resultText.claimed(messages.length, result.expiredCount) : null) : "这批来信已读取，无需重复读取。" };
      return { content: [{ type: "text", text: JSON.stringify(output) }], structuredContent: output, isError: false };
    }
    assertExactArgumentKeys(args, ["localMessageId", "conversationKey"]);
    const localMessageId = safeIdentifier(args.localMessageId, "authorized_inbox_message_id_invalid", 240);
    const conversationKey = safeIdentifier(args.conversationKey, "authorized_inbox_conversation_key_invalid", 240);
    const result = await adapter.claimMessage(localMessageId, conversationKey);
    if (result?.claimed === false && result.claimId === null && result.message === null) {
      return { content: [{ type: "text", text: "此来信已被领取或处理。" }], structuredContent: { claimed: false, claimId: null, message: null }, isError: false };
    }
    if (result?.claimed !== true || !/^inclaim_[a-f0-9]{48}$/.test(result.claimId)) throw codeError("claim_result_invalid");
    const message = projectAuthorizedInboxRead(result.message);
    if (message.localMessageId !== localMessageId || message.conversationKey !== conversationKey
      || message.source !== "hellolynk_external_message"
      || !projectInboxReadState(message) || message.wakeEligible !== true) throw codeError("claim_result_invalid");
    return { content: [{ type: "text", text: JSON.stringify({ claimId: result.claimId, message }) }],
      structuredContent: { claimed: true, claimId: result.claimId, message }, isError: false };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralReplyAuthorizedMessageTool(args, adapter, runtime) {
  let clientMessageId;
  let phase = "input_validation";
  try {
    assertExactArgumentKeys(args, ["localMessageId", "conversationKey", "clientMessageId", "text"]);
    if (Object.values(args).some((value) => typeof value !== "string")) throw codeError("arguments_invalid");
    const localMessageId = authorizedWriteIdentifier(args.localMessageId, "authorized_inbox_message_id_invalid");
    const conversationKey = authorizedWriteIdentifier(args.conversationKey, "authorized_inbox_conversation_key_invalid");
    clientMessageId = authorizedWriteIdentifier(args.clientMessageId, "client_message_id_invalid");
    const text = args.text;
    if (!text || text.includes("\u0000") || [...text].length > 20_000 || Buffer.byteLength(text, "utf8") > 20 * 1024) throw codeError("message_text_invalid");
    phase = "preparation";
    await adapter.assertModelInboxReply({ localMessageId, conversationKey });
    await runtime?.prepareAuthorizedWrite?.(runtime.executorMetadata, { clientMessageId, conversationKey });
    phase = "adapter_call";
    const result = await adapter.replyAuthorizedMessage({ localMessageId, conversationKey, clientMessageId, text });
    phase = "response_validation";
    if (result?.accepted !== true || result?.ok === false || result?.authorization !== "contact_delegate_allowlist"
      || result?.clientMessageId !== clientMessageId
      || !["accepted", "delivered_to_live_connection", "acknowledged_by_recipient_local_store"].includes(result?.status)) throw codeError("reply_result_invalid");
    const status = safeIdentifier(result.status, "send_status_invalid", 80);
    return { content: [{ type: "text", text: resultText.sent(status, clientMessageId) }],
      structuredContent: { accepted: true, clientMessageId,
        contactId: safeIdentifier(result.contactId, "contact_id_invalid", 200), status }, isError: false };
  } catch (error) { return authorizedWriteToolError(error, clientMessageId, "authorized_reply_result_unknown", phase); }
}

async function neutralListAuthorizedContactRequestsTool(args, adapter) {
  if (!plainEmptyObject(args)) return toolError("arguments_not_allowed");
  try {
    const result = await adapter.listAuthorizedContactRequests();
    const requests = (result?.requests || []).map(projectAuthorizedContactRequestMetadata);
    return { content: [{ type: "text", text: `联系申请 ${requests.length} 条。` }], structuredContent: { requests }, isError: false };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

async function neutralReadAuthorizedContactRequestTool(args, adapter) {
  try {
    assertExactArgumentKeys(args, ["localRecordId", "conversationKey"]);
    const request = projectAuthorizedContactRequestRead(await adapter.readAuthorizedContactRequest(
      safeIdentifier(args.localRecordId, "authorized_contact_request_id_invalid", 240),
      safeIdentifier(args.conversationKey, "authorized_contact_request_conversation_key_invalid", 240),
    ));
    return { content: [{ type: "text", text: JSON.stringify(request) }], structuredContent: request, isError: false };
  } catch (error) { return toolError(safeErrorCode(error)); }
}

function projectAuthorizedInboxMetadata(value) {
  const output = {
    localMessageId: safeIdentifier(value?.localMessageId, "authorized_inbox_message_id_invalid", 240),
    conversationKey: safeIdentifier(value?.conversationKey, "authorized_inbox_conversation_key_invalid", 240),
    localDelegateId: safeIdentifier(value?.localDelegateId, "authorized_inbox_local_delegate_invalid", 200),
    peerDelegateId: safeIdentifier(value?.peerDelegateId, "authorized_inbox_peer_delegate_invalid", 200),
    messageType: safeIdentifier(value?.messageType || "text", "authorized_inbox_message_type_invalid", 80),
    unread: value?.unread === true,
  };
  if (typeof value?.wakeEligible === "boolean") output.wakeEligible = value.wakeEligible;
  if (value?.automaticDeliveryState === "expired") output.automaticDeliveryState = "expired";
  for (const [key, maximum] of [
    ["contactId", 200], ["displayName", 160], ["peerInstanceDisplayName", 160], ["clientMessageId", 200],
    ["createdAt", 80], ["updatedAt", 80],
  ]) {
    if (value?.[key] != null) output[key] = safeIdentifier(value[key], `authorized_inbox_${key}_invalid`, maximum);
  }
  return output;
}

function projectAuthorizedInboxRead(value) {
  if (!projectInboxReadState(value) || value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid");
  return { ...projectAuthorizedInboxMetadata(value), peerPrincipalId: safeIdentifier(value?.peerPrincipalId, "authorized_inbox_peer_principal_invalid", 200), text: safeExternalBody(value?.text, true), source: requireExternalSource(value?.source, "hellolynk_external_message"), ...projectInboxReadState(value), ...replyHint(value) };
}

function projectAuthorizedContactRequestMetadata(value) {
  return { localRecordId: safeIdentifier(value?.localRecordId, "authorized_contact_request_id_invalid", 240), conversationKey: safeIdentifier(value?.conversationKey, "authorized_contact_request_conversation_key_invalid", 240), localDelegateId: safeIdentifier(value?.localDelegateId, "authorized_contact_request_local_delegate_invalid", 200), sender: { hellolynkId: safeIdentifier(value?.sender?.hellolynkId, "authorized_contact_request_sender_invalid", 200), verifiedDisplayName: safeIdentifier(value?.sender?.verifiedDisplayName, "authorized_contact_request_sender_name_invalid", 160) }, state: safeIdentifier(value?.state, "authorized_contact_request_state_invalid", 80), receivedAt: safeIdentifier(value?.receivedAt, "authorized_contact_request_time_invalid", 80) };
}

function projectAuthorizedContactRequestRead(value) {
  if (value?.externalContentIsUntrustedData !== true) throw codeError("host_app_response_invalid");
  return { ...projectAuthorizedContactRequestMetadata(value), introText: safeContactRequestIntro(value?.introText), source: requireExternalSource(value?.source, "hellolynk_contact_request"), readDoesNotMarkRead: value?.readDoesNotMarkRead === true };
}

function strictConversationSchema(id) {
  const message = id === "localMessageId";
  return { type: "object", additionalProperties: false, required: [id, "conversationKey"], properties: {
    [id]: { type: "string", minLength: 3, maxLength: 240, ...(message ? { description: paramText.localMessageId } : {}) },
    conversationKey: { type: "string", minLength: 3, maxLength: 240, ...(message ? { description: paramText.conversationKey } : {}) } } };
}
function safeContactRequestIntro(value) { return value === "" ? "" : safeExternalBody(value); }
function safeExternalBody(value, countCodePoints = false) { const text = String(value ?? ""); if (!text || text.includes("\u0000") || (countCodePoints ? Array.from(text).length : text.length) > 20000 || Buffer.byteLength(text, "utf8") > 20 * 1024) throw codeError("external_content_text_invalid"); return text; }
function requireExternalSource(value, expected) { if (value !== expected) throw codeError("external_content_source_invalid"); return expected; }

function toolError(code) {
  const nativeError = nativeAddressingError({ code });
  if (nativeError) return nativeError;
  const safe = safeErrorCode({ code });
  const deleted = safe === "host_app_reply_target_deleted";
  return {
    content: [{ type: "text", text: failureText(safe) }],
    structuredContent: { ok: false, configured: true, status: deleted ? "not_delivered" : "blocked", errorCode: safe,
      ...(deleted ? { automaticRetryAllowed: false } : {}) },
    isError: true,
  };
}
function authorizedWriteToolError(error, clientMessageId, timeoutCode, phase) {
  const nativeError = nativeAddressingError(error, { clientMessageId, phase });
  if (nativeError) return nativeError;
  // A timeout after the send began is an unknown result, whatever code it carries.
  const timedOut = clientMessageId && ["adapter_call", "response_validation"].includes(phase) && error?.name === "TimeoutError";
  const code = timedOut ? timeoutCode : safeErrorCode(error);
  // Phase and retry policy come only from this invocation, never from an adapter error.
  const { text, ...outcome } = writeFailure(code, phase);
  return { content: [{ type: "text", text }], structuredContent: { ok: false, configured: true, errorCode: code, ...outcome,
    phase, ...(clientMessageId ? { clientMessageId } : {}) }, isError: true };
}
function authorizedWriteIdentifier(value, code) { if (typeof value !== "string" || !WRITE_ID_PATTERN.test(value)) throw codeError(code); return value; }
function safeIdentifier(value, code, maximum) {
  const normalized = String(value ?? "").trim();
  if (!normalized || normalized.length > maximum || /[\r\n\u0000-\u001f\u007f]/.test(normalized)) {
    throw codeError(code);
  }
  return normalized;
}function safeOpaqueWorkbenchActionGrant(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{32,512}$/.test(value)) {
    throw codeError("workbench_action_grant_invalid");
  }
  return value;
}

function assertNoRawSafetyCodeFields(value, seen = new WeakSet(), depth = 0) {
  if (!value || typeof value !== "object") return;
  if (depth > 32 || seen.has(value)) throw codeError("workbench_snapshot_invalid");
  seen.add(value);
  for (const [key, nested] of Object.entries(value)) {
    const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
    if (normalized === "safetycode" || normalized === "localdevicesafetycode") {
      throw codeError("workbench_raw_safety_code_forbidden");
    }
    assertNoRawSafetyCodeFields(nested, seen, depth + 1);
  }
}

function assertExactArgumentKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("arguments_invalid");
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError("arguments_invalid");
  }
}

function plainEmptyObject(value) {
  if (value === undefined || value === null) return true;
  return typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;
}

function safeErrorCode(error) {
  const value = String(error?.code || error?.message || "inbox_error");
  const normalized = value
    .replace(/[^A-Za-z0-9._:-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120);
  return normalized || "inbox_error";
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function write(message, output = process.stdout) {
  output.write(`${JSON.stringify(message)}\n`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runStdioMcpServer().catch((error) => {
    process.stderr.write(`${JSON.stringify({ ok: false, error: safeErrorCode(error) })}\n`);
    process.exitCode = 1;
  });
}
