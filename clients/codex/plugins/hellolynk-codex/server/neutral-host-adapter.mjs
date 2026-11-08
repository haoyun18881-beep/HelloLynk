import { queryArgs, optionalTarget } from "../runtime/core/hellolynk-native-addressing-tools.cjs";
import { captureHelloLynkModelNotices } from "../runtime/core/hellolynk-model-notices.cjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { loadCodexWorkbenchContract } from "./workbench-runtime.mjs";

export const HELLOLYNK_CODEX_NEUTRAL_ADAPTER_CONTRACT = "hellolynk-codex-neutral-adapter-v3";
export const HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT = "hellolynk-neutral-host-discovery-v1";

const FROZEN_WORKBENCH_ACTION_GRANT_PATH = "/host/v1/app/workbench/action-grants";
const FROZEN_WORKBENCH_COMMAND_PATH = "/host/v1/app/workbench/commands";

export const NEUTRAL_HOST_PATHS = Object.freeze({
  health: "/host/v1/health",
  attach: "/host/v1/attachments",
  heartbeat: "/host/v1/attachments/heartbeat",
  detach: "/host/v1/attachments/detach",
  unread: "/host/v1/app/inbox/unread-count",
  authorizedContacts: "/host/v1/app/authorized-contacts",
  authorizedInboxMessages: "/host/v1/app/authorized-inbox/messages",
  authorizedInboxRead: "/host/v1/app/authorized-inbox/read",
  authorizedInboxActivate: "/host/v1/app/authorized-inbox/activate",
  authorizedInboxPending: "/host/v1/app/authorized-inbox/pending",
  authorizedInboxClaim: "/host/v1/app/authorized-inbox/claim",
  authorizedInboxBatch: "/host/v1/app/authorized-inbox/batch/",
  authorizedContactRequests: "/host/v1/app/authorized-contact-requests",
  authorizedContactRequestRead: "/host/v1/app/authorized-contact-requests/read",
  authorizedSend: "/host/v1/app/authorized-actions/send-text",
  authorizedReply: "/host/v1/app/authorized-actions/reply-text",
  workbenchSnapshot: "/host/v1/app/workbench/snapshot",
  workbenchChanges: "/host/v1/app/changes/subscribe",
  appWorkbenchActionGrant: FROZEN_WORKBENCH_ACTION_GRANT_PATH,
  appWorkbenchCommand: FROZEN_WORKBENCH_COMMAND_PATH,
});

export const CODEX_NEUTRAL_EXACT_SCOPES = Object.freeze([
  "app-data:authorized-messaging",
  "app-data:changes-read",
  "app-data:contact-requests-read",
  "app-data:contacts-manage",
  "app-data:contacts-read",
  "app-data:human-send-request",
  "app-data:inbox-manage",
  "app-data:inbox-read",
  "app-data:outbox-read",
  "app-data:outbox-retry",
  "attachments:manage",
  "surface:human-ui",
  "ui:launch",
].sort());

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
// Another client, or a newer release, is starting the Host: wait for it instead of failing.
const LAUNCH_YIELD_ERRORS = new Set(["neutral_host_already_running", "neutral_host_release_superseded"]);
// A release handover is on hold: wait for the newer Host like already_running, report "switching" only if none appears.
const RELEASE_SUPERSEDED = "neutral_host_release_superseded";
const TERMINAL_HOST_ERRORS = new Set([
  "neutral_host_discovery_generation_mismatch", "neutral_host_discovery_stale",
  "neutral_host_not_found", "host_not_running", "host_request_unauthorized",
  "host_attachment_not_found", "host_attachment_expired", "ECONNREFUSED",
]);

export function isCodexNeutralHostUnavailable(error) {
  return TERMINAL_HOST_ERRORS.has(error?.code) || TERMINAL_HOST_ERRORS.has(error?.cause?.code);
}

export function resolveHelloLynkHostMode(env = process.env) {
  const value = String(env.HELLOLYNK_HOST_MODE || "neutral");
  if (value === "legacy") throw codeError("hellolynk_host_mode_legacy_unsupported");
  if (value !== "neutral") throw codeError("hellolynk_host_mode_invalid");
  return "neutral";
}

export async function createCodexNeutralHostAdapter(options = {}) {
  const provider = options.capabilityProvider;
  if (typeof provider !== "function") throw codeError("neutral_capability_provider_required");
  const supplied = await provider();
  const binding = validateProtectedBinding(supplied);
  const discover = options.discoverHost || discoverNeutralHost;
  const request = options.requestHost || requestNeutralHost;
  // The Host module ships beside this adapter and loads once a running Host has been found.
  const requestHandover = options.requestHostHandover
    || (async (input) => (await import("../runtime/core/hellolynk-neutral-host-process.mjs")).requestHelloLynkNeutralHostHandover(input));
  const discoverInput = {
    runtimeRoot: binding.runtimeRoot,
    region: binding.region,
    principalId: binding.principalId,
    hostInstallationId: binding.hostInstallationId,
    fetchImpl: options.fetchImpl,
  };
  let discovery = await discoverAvailableHost(discover, discoverInput);
  // A Host of an earlier release is asked to make room, and this client's release starts in its place.
  if (discovery && typeof options.hostLauncher === "function"
    && await earlierHostLeft(requestHandover, binding, integer(options.handoverWaitMs, 5_000, 0, 30_000))) {
    discovery = await discoverAvailableHost(discover, discoverInput);
  }
  if (!discovery) {
    if (typeof options.hostLauncher !== "function") {
      throw codeError("neutral_host_launcher_unavailable");
    }
    // Another client may have started the shared Host a moment ago: wait for it instead of failing.
    let superseded = false;
    try { await options.hostLauncher(publicBinding(binding)); }
    catch (error) {
      if (!LAUNCH_YIELD_ERRORS.has(error?.code)) throw error;
      superseded = error.code === RELEASE_SUPERSEDED;
    }
    discovery = await waitForDiscovery(discover, binding, options);
    if (!discovery && superseded) throw codeError(RELEASE_SUPERSEDED);
  }
  if (!discovery) throw codeError("neutral_host_not_found");
  assertDiscoveryBinding(discovery, binding);

  const adapterInstanceId = safeId(
    options.adapterInstanceId || `codex-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
    "neutral_adapter_instance_invalid",
  );
  const callRaw = async (method, pathname, body = null, requestOptions = {}) => captureHelloLynkModelNotices(await request({
    discovery,
    capability: binding.capability,
    method,
    pathname,
    body,
    fetchImpl: options.fetchImpl,
    ...requestOptions,
  }));
  const attached = requireOk(await callRaw("POST", NEUTRAL_HOST_PATHS.attach, { adapterInstanceId }));

  let closed = false;
  let deadCode = null;
  let inboxActivation = null;
  let leaseExpiresAt = Number(attached.leaseExpiresAt) || Date.now() + 30_000;
  let heartbeatBusy = false;
  const markDead = (error) => {
    deadCode ||= String(error?.code || error?.cause?.code || "host_attachment_expired");
    clearInterval(heartbeat);
  };
  const call = async (method, pathname, body = null, requestOptions = {}) => {
    if (closed) throw codeError("neutral_adapter_closed");
    if (deadCode) throw codeError(deadCode);
    try {
      const result = await callRaw(method, pathname, body, requestOptions);
      if (isCodexNeutralHostUnavailable({ code: result?.body?.error })) {
        throw codeError(result.body.error);
      }
      return result;
    } catch (error) {
      if (isCodexNeutralHostUnavailable(error)) markDead(error);
      throw error;
    }
  };
  // A Host without the native inbox routes is of an earlier release: ask it to make room, once; the error is unchanged.
  let handoverAsked = false;
  async function callNativeInbox(method, pathname, body) {
    const result = await call(method, pathname, body);
    if (isMissingNativeInboxRoute(result) && !handoverAsked) {
      handoverAsked = true;
      try {
        await requestHandover({ runtimeRoot: binding.runtimeRoot, hostInstallationId: binding.hostInstallationId,
          publishedAt: new Date().toISOString(), waitMs: 0 });
      } catch {}
    }
    return result;
  }
  const heartbeatMs = integer(options.heartbeatMs, 10_000, 100, 30_000);
  const heartbeat = setInterval(async () => {
    if (closed || deadCode || heartbeatBusy) return;
    heartbeatBusy = true;
    try {
      const result = requireOk(await call("POST", NEUTRAL_HOST_PATHS.heartbeat, { adapterInstanceId }));
      leaseExpiresAt = Number(result.leaseExpiresAt) || Date.now() + 30_000;
    } catch (error) {
      if (isCodexNeutralHostUnavailable(error)) markDead(error);
      else if (Date.now() >= leaseExpiresAt) markDead(codeError("host_attachment_expired"));
    } finally {
      heartbeatBusy = false;
    }
  }, heartbeatMs);
  heartbeat.unref?.();

  async function close() {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    try {
      if (!deadCode) await callRaw("POST", NEUTRAL_HOST_PATHS.detach, { adapterInstanceId }).catch(() => {});
    } finally { binding.capability.secretBuffer.fill(0); }
  }

  return Object.freeze({
    mode: "neutral",
    get state() { return closed ? "closed" : deadCode ? "dead" : "attached"; },
    binding: publicBinding(binding),
    nativeTaskScope() { return Object.freeze({
      runtimeRoot: binding.runtimeRoot, region: binding.region,
      principalId: binding.principalId, delegateId: binding.delegateId, adapterId: binding.adapterId,
    }); },
    discovery: publicDiscovery(discovery),
    adapterInstanceId,
    async modelInbox(input) { return requireOk(await call("POST", "/host/v1/app/model-inbox", input)); },
    async readUnreadCount() {
      const result = requireOk(await call("GET", NEUTRAL_HOST_PATHS.unread));
      const unreadCount = result.unreadCount;
      if (!Number.isSafeInteger(unreadCount) || unreadCount < 0) {
        throw codeError("neutral_unread_count_invalid");
      }
      return Object.freeze({ unreadCount });
    },
    async readWorkbenchSnapshot(input = {}) {
      const result = await requireOk(await call("POST", NEUTRAL_HOST_PATHS.workbenchSnapshot, input));
      return result.snapshot;
    },
    async readWorkbenchChanges({ afterCursor = 0 } = {}) {
      if (!Number.isSafeInteger(afterCursor) || afterCursor < 0) throw codeError("host_app_change_cursor_invalid");
      const result = requireOk(await call("POST", NEUTRAL_HOST_PATHS.workbenchChanges, { afterCursor }));
      return { ...result, hostGeneration: discovery.hostGeneration };
    },
    async issueWorkbenchActionGrant(command) {
      const { validateWorkbenchCommand } = await loadCodexWorkbenchContract();
      const request = validateWorkbenchCommand(command);
      return requireWorkbenchActionGrant(await call("POST", NEUTRAL_HOST_PATHS.appWorkbenchActionGrant, {
        adapterInstanceId,
        request,
      }));
    },
    async executeWorkbenchCommand(command, context) {
      const { validateWorkbenchCommand, validateWorkbenchCommandResult } = await loadCodexWorkbenchContract();
      const request = validateWorkbenchCommand(command);
      const statusRead = request.command === "message.send-status";
      const actionGrant = statusRead ? noWorkbenchActionGrantContext(context) : workbenchActionGrantContext(context);
      const result = requireWorkbenchCommandResult(await call("POST", NEUTRAL_HOST_PATHS.appWorkbenchCommand, {
        adapterInstanceId,
        request,
        ...(statusRead ? {} : { actionGrant }),
      }));
      return validateWorkbenchCommandResult(result, request.command);
    },
    async listAuthorizedContacts(input = {}) {
      const query = queryArgs(input);
      const result = await requireOk(await call(Object.keys(query).length ? "POST" : "GET", NEUTRAL_HOST_PATHS.authorizedContacts, Object.keys(query).length ? query : undefined, { timeoutMs: 25_000 }));
      return Object.freeze({ ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}), contacts: Object.freeze([...(result.contacts || [])]) });
    },
    async listAuthorizedInboxMessages({ before } = {}) {
      const result = await requireOk(before === undefined ? await call("GET", NEUTRAL_HOST_PATHS.authorizedInboxMessages)
        : await call("POST", NEUTRAL_HOST_PATHS.authorizedInboxMessages, { before: safeId(before, "neutral_authorized_inbox_message_id_invalid") }));
      return Object.freeze({ messages: Object.freeze([...(result.messages || [])]) });
    },
    async readAuthorizedInboxMessage(localMessageId, conversationKey) {
      const result = await requireOk(await call("POST", NEUTRAL_HOST_PATHS.authorizedInboxRead, {
        localMessageId: safeId(localMessageId, "neutral_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(conversationKey, "neutral_authorized_inbox_conversation_key_invalid"),
      }));
      return result.message;
    },
    async listPendingMessages(target = null) {
      // The durable reader boundary belongs to this fixed identity/connection.
      // Pending GETs still validate the current Host capability on every call.
      inboxActivation ??= call("POST", NEUTRAL_HOST_PATHS.authorizedInboxActivate)
        .then(response => {
          if (requireOk(response).active !== true) throw codeError("neutral_inbox_activation_invalid");
        })
        .catch(error => { inboxActivation = null; throw error; });
      await inboxActivation;
      if (target?.cursor != null && (!Number.isSafeInteger(target.cursor) || target.cursor < 0)) throw codeError("neutral_pending_cursor_invalid");
      const body = target == null ? null : target.cursor != null ? { cursor: target.cursor } : {
        localMessageId: safeId(target.localMessageId, "neutral_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(target.conversationKey, "neutral_authorized_inbox_conversation_key_invalid"),
      };
      const result = requireNativeInboxOk(await callNativeInbox(body ? "POST" : "GET", NEUTRAL_HOST_PATHS.authorizedInboxPending, body));
      if (!Array.isArray(result.messages)) throw codeError("neutral_pending_response_invalid");
      return { messages: result.messages, ...(result.nextCursor == null ? {} : { nextCursor: result.nextCursor }) };
    },
    async claimMessage(localMessageId, conversationKey) {
      return requireNativeInboxOk(await callNativeInbox("POST", NEUTRAL_HOST_PATHS.authorizedInboxClaim, {
        localMessageId: safeId(localMessageId, "neutral_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(conversationKey, "neutral_authorized_inbox_conversation_key_invalid"),
      }));
    },
    async claimBatch(batchId) {
      return requireNativeInboxOk(await callNativeInbox("POST", NEUTRAL_HOST_PATHS.authorizedInboxClaim,
        { batchId: safeId(batchId, "neutral_inbox_batch_id_invalid") }));
    },
    async inboxBatch(operation, input = {}) {
      if (!["reserve", "open", "attempt", "confirm", "cancel", "expire", "closed"].includes(operation))
        throw codeError("neutral_inbox_batch_operation_invalid");
      return requireNativeInboxOk(await callNativeInbox("POST", NEUTRAL_HOST_PATHS.authorizedInboxBatch + operation, input));
    },
    async listAuthorizedContactRequests() {
      const result = await requireOk(await call("GET", NEUTRAL_HOST_PATHS.authorizedContactRequests));
      return Object.freeze({ requests: Object.freeze([...(result.requests || [])]) });
    },
    async readAuthorizedContactRequest(localRecordId, conversationKey) {
      const result = await requireOk(await call("POST", NEUTRAL_HOST_PATHS.authorizedContactRequestRead, {
        localRecordId: safeId(localRecordId, "neutral_authorized_contact_request_id_invalid"),
        conversationKey: safeId(conversationKey, "neutral_authorized_contact_request_conversation_key_invalid"),
      }));
      return result.request;
    },
    async sendAuthorizedMessage(input) {
      return requireOk(await call("POST", NEUTRAL_HOST_PATHS.authorizedSend, authorizedSendInput(input)));
    },
    async replyAuthorizedMessage(input) {
      if (!input || typeof input !== "object" || Array.isArray(input)
        || Object.keys(input).sort().join("|") !== "clientMessageId|conversationKey|localMessageId|text") {
        throw codeError("authorized_reply_input_invalid");
      }
      const text = String(input.text ?? "");
      if (!text || text.includes("\u0000") || Buffer.byteLength(text, "utf8") > 20 * 1024) throw codeError("message_text_invalid");
      return requireOk(await call("POST", NEUTRAL_HOST_PATHS.authorizedReply, {
        localMessageId: safeId(input.localMessageId, "neutral_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(input.conversationKey, "neutral_authorized_inbox_conversation_key_invalid"),
        clientMessageId: safeId(input.clientMessageId, "neutral_client_message_id_invalid"), text,
      }));
    },
    close,
  });
}

export function validateProtectedBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("neutral_capability_binding_invalid");
  }
  const capability = value.capability;
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw codeError("neutral_capability_invalid");
  }
  const region = safeId(value.region, "neutral_region_invalid");
  const principalId = safeId(value.principalId, "neutral_principal_invalid");
  const delegateId = safeId(value.delegateId, "neutral_delegate_invalid");
  const hostInstallationId = safeId(value.hostInstallationId, "neutral_host_installation_invalid");
  const adapterId = safeId(value.adapterId, "neutral_adapter_invalid");
  if (adapterId !== "codex") throw codeError("neutral_adapter_mismatch");
  if (!value.runtimeRoot || !path.isAbsolute(String(value.runtimeRoot))) {
    throw codeError("neutral_runtime_root_invalid");
  }
  if (capability.principalId !== principalId || capability.delegateId !== delegateId
    || capability.hostInstallationId !== hostInstallationId || capability.adapterId !== adapterId) {
    throw codeError("neutral_capability_owner_mismatch");
  }
  const scopes = [...new Set((capability.scopes || []).map(String))].sort();
  if (JSON.stringify(scopes) !== JSON.stringify(CODEX_NEUTRAL_EXACT_SCOPES)) {
    throw codeError("neutral_capability_scopes_mismatch");
  }
  const secretBuffer = Buffer.isBuffer(capability.secretBuffer)
    ? Buffer.from(capability.secretBuffer)
    : capability.secretBuffer instanceof Uint8Array ? Buffer.from(capability.secretBuffer) : null;
  if (!secretBuffer || secretBuffer.length < 32 || secretBuffer.length > 128) {
    throw codeError("neutral_capability_secret_invalid");
  }
  const version = Number(capability.version);
  if (version !== 2) {
    throw codeError("neutral_capability_version_mismatch");
  }
  if (capability.state !== "active") {
    throw codeError("neutral_capability_inactive");
  }
  return Object.freeze({
    region, principalId, delegateId, hostInstallationId, adapterId,
    runtimeRoot: String(value.runtimeRoot || ""),
    capability: Object.freeze({
      contract: String(capability.contract || ""),
      capabilityId: safeId(capability.capabilityId, "neutral_capability_id_invalid"),
      adapterId, delegateId, principalId, hostInstallationId,
      version, state: "active", scopes,
      issuedAt: Number(capability.issuedAt),
      revokedAt: capability.revokedAt ?? null,
      region,
      secretBuffer,
    }),
  });
}

export async function discoverNeutralHost(options = {}) {
  if (typeof options.discoveryProvider === "function") {
    return options.discoveryProvider(options);
  }
  const runtimeRoot = path.resolve(String(options.runtimeRoot || ""));
  if (!options.runtimeRoot) throw codeError("neutral_runtime_root_required");
  const key = sha256(String(options.hostInstallationId || ""));
  const discoveryDirectory = path.join(runtimeRoot, "neutral-host");
  const discoveryPath = path.join(discoveryDirectory, `${key}.json`);
  let raw;
  try {
    await assertNoReparsePath(runtimeRoot);
    await assertNoReparsePath(discoveryDirectory);
    const stat = await fs.lstat(discoveryPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024) {
      throw codeError("neutral_host_discovery_invalid");
    }
    raw = await fs.readFile(discoveryPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  let record;
  try { record = JSON.parse(raw); } catch { throw codeError("neutral_host_discovery_invalid"); }
  if (record.region !== options.region || record.principalId !== options.principalId
    || record.hostInstallationId !== options.hostInstallationId) {
    throw codeError("neutral_host_discovery_owner_mismatch");
  }
  assertDiscoveryBinding(record, options);
  const fetchImpl = options.fetchImpl || fetch;
  const health = await fetchImpl(`http://${record.host}:${record.port}${NEUTRAL_HOST_PATHS.health}`, {
    redirect: "error",
    signal: AbortSignal.timeout(2_000),
  }).catch(() => null);
  if (!health || health.status !== 200) throw codeError("neutral_host_discovery_stale");
  const body = await health.json().catch(() => null);
  if (body?.hostGeneration !== record.hostGeneration || body?.status !== "running") {
    throw codeError("neutral_host_discovery_generation_mismatch");
  }
  return Object.freeze(structuredClone(record));
}

async function assertNoReparsePath(target) {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  const relative = path.relative(parsed.root, resolved);
  let cursor = parsed.root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const stat = await fs.lstat(cursor);
    if (stat.isSymbolicLink()) throw codeError("neutral_host_discovery_unsafe_path");
  }
}

export async function requestNeutralHost(options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  const discovery = options.discovery;
  const capability = options.capability;
  const method = String(options.method || "GET").toUpperCase();
  const pathname = String(options.pathname || "");
  // Workbench commands perform Host-owned validation and return the resulting
  // snapshot. Contact writes can therefore wait behind two full Host reads.
  // Authorized writes can also perform several durable E2EE steps before Host
  // replies. Keep both below the MCP app's 60-second ceiling; ordinary RPC remains short.
  const snapshotRead = method === "POST" && pathname === NEUTRAL_HOST_PATHS.workbenchSnapshot;
  const actionGrant = method === "POST" && pathname === NEUTRAL_HOST_PATHS.appWorkbenchActionGrant;
  const workbenchCommand = method === "POST" && pathname === NEUTRAL_HOST_PATHS.appWorkbenchCommand;
  const authorizedSend = method === "POST" && pathname === NEUTRAL_HOST_PATHS.authorizedSend;
  const authorizedReply = method === "POST" && pathname === NEUTRAL_HOST_PATHS.authorizedReply;
  const authorizedWrite = authorizedSend || authorizedReply;
  const nativeDirectoryQuery = method === "POST" && pathname === NEUTRAL_HOST_PATHS.authorizedContacts;
  const principalSearch = workbenchCommand && options.body?.request?.command === "principal.search";
  const rawBody = options.body == null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(options.body));
  const timestampMs = Date.now();
  const nonce = crypto.randomBytes(24).toString("base64url");
  const bodySha256 = sha256(rawBody);
  const message = [
    "hellolynk-host-request-v1", capability.capabilityId, capability.adapterId, method, pathname,
    discovery.hostGeneration, String(timestampMs), nonce, bodySha256,
  ].join("\n");
  const proof = crypto.createHmac("sha256", capability.secretBuffer).update(message, "utf8").digest("hex");
  const signal = AbortSignal.timeout(workbenchCommand || authorizedWrite ? 55_000 : nativeDirectoryQuery ? 25_000 : snapshotRead || actionGrant ? 30_000 : 8_000);
  try {
    const response = await fetchImpl(`http://${discovery.host}:${discovery.port}${pathname}`, {
      method,
      headers: {
        "content-type": "application/json",
        "x-hellolynk-host-capability-id": capability.capabilityId,
        "x-hellolynk-host-adapter-id": capability.adapterId,
        "x-hellolynk-host-generation": discovery.hostGeneration,
        "x-hellolynk-host-timestamp": String(timestampMs),
        "x-hellolynk-host-nonce": nonce,
        "x-hellolynk-host-proof": proof,
      },
      body: rawBody.length ? rawBody : undefined,
      redirect: "error",
      signal,
    });
    return { status: response.status, body: await response.json().catch((error) => {
      if ((authorizedWrite || snapshotRead || nativeDirectoryQuery)
        && (error?.name === "TimeoutError" || (error?.name === "AbortError" && signal.reason?.name === "TimeoutError"))) {
        throw error;
      }
      return {};
    }) };
  } catch (error) {
    const timedOut = error?.name === "TimeoutError"
      || (error?.name === "AbortError" && signal.reason?.name === "TimeoutError");
    if (authorizedSend && timedOut) throw codeError("authorized_send_result_unknown");
    if (authorizedReply && timedOut) throw codeError("authorized_reply_result_unknown");
    if (nativeDirectoryQuery && timedOut) throw codeError("native_directory_unavailable");
    if (snapshotRead && timedOut) throw codeError("workbench_snapshot_timeout");
    if (principalSearch && error?.name === "TimeoutError") throw codeError("workbench_principal_search_timeout");
    if (workbenchCommand && error?.name === "TimeoutError") throw codeError("workbench_command_timeout");
    if (actionGrant && error?.name === "TimeoutError") throw codeError("workbench_action_grant_timeout");
    throw error;
  }
}

function assertDiscoveryBinding(record, binding) {
  if (!record || record.contractId !== HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT
    || record.region !== binding.region || record.principalId !== binding.principalId
    || record.hostInstallationId !== binding.hostInstallationId || record.host !== "127.0.0.1"
    || !Number.isSafeInteger(record.port) || record.port < 1 || record.port > 65_535
    || !/^[a-f0-9]{48}$/.test(String(record.hostGeneration || ""))) {
    throw codeError("neutral_host_discovery_owner_mismatch");
  }
}

function isMissingNativeInboxRoute(result) {
  return result?.body?.error === "host_route_not_found" || (result?.status === 404 && !result?.body?.error);
}

function requireNativeInboxOk(result) {
  if (isMissingNativeInboxRoute(result)) throw codeError("host_native_inbox_upgrade_required");
  return requireOk(result);
}

function requireOk(result) {
  if (!result || result.status !== 200 || result.body?.ok !== true) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return result.body;
}

function requireWorkbenchCommandResult(result) {
  if (!result || result.status !== 200 || !result.body
    || typeof result.body !== "object" || Array.isArray(result.body)) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return result.body;
}

function requireWorkbenchActionGrant(result) {
  const value = result?.body;
  if (!result || result.status !== 200 || !value
    || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join("|") !== "actionGrant|expiresAtMs|ok"
    || value.ok !== true
    || !Number.isSafeInteger(value.expiresAtMs) || value.expiresAtMs <= Date.now()) {
    throw codeError(String(value?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return Object.freeze({ actionGrant: opaqueWorkbenchActionGrant(value.actionGrant) });
}

function workbenchActionGrantContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join("|") !== "actionGrant") {
    throw codeError("workbench_action_grant_required");
  }
  return opaqueWorkbenchActionGrant(value.actionGrant);
}

function noWorkbenchActionGrantContext(value) {
  if (value != null && (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== 0)) {
    throw codeError("workbench_action_grant_forbidden");
  }
  return null;
}

function opaqueWorkbenchActionGrant(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{32,512}$/.test(value)) {
    throw codeError("workbench_action_grant_invalid");
  }
  return value;
}

function authorizedSendInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).filter(key => key !== "targetConversationId" && key !== "targetConversationTitle").sort().join("|") !== "clientMessageId|contactId|recipientDelegateId|text") {
    throw codeError("authorized_send_input_invalid");
  }
  const text = String(value.text ?? "");
  if (!text || text.includes("\u0000") || Buffer.byteLength(text, "utf8") > 20 * 1024) {
    throw codeError("message_text_invalid");
  }
  return {
    ...optionalTarget(value),
    clientMessageId: safeId(value.clientMessageId, "neutral_client_message_id_invalid"),
    contactId: safeId(value.contactId, "neutral_contact_id_invalid"),
    recipientDelegateId: safeId(value.recipientDelegateId, "recipient_delegate_id_invalid"),
    text,
  };
}

function publicBinding(value) {
  return Object.freeze({
    region: value.region, principalId: value.principalId, delegateId: value.delegateId,
    hostInstallationId: value.hostInstallationId, adapterId: value.adapterId,
    capabilityVersion: value.capability.version, scopes: [...value.capability.scopes],
  });
}

function publicDiscovery(value) {
  return Object.freeze({
    contractId: value.contractId, region: value.region, principalId: value.principalId,
    hostInstallationId: value.hostInstallationId, host: value.host, port: value.port,
    hostGeneration: value.hostGeneration, startedAt: value.startedAt || null,
  });
}

// The same or a higher release answers "current" and nothing is written. An earlier one finishes
// its admitted work and leaves; while it is busy it keeps serving and this client attaches to it.
async function earlierHostLeft(requestHandover, binding, waitMs) {
  try {
    const { status } = await requestHandover({ runtimeRoot: binding.runtimeRoot,
      hostInstallationId: binding.hostInstallationId, publishedAt: new Date().toISOString(), waitMs, untilStopped: true });
    return ["stopped", "restarted", "no_host"].includes(status);
  } catch { return false; }
}
async function waitForDiscovery(discover, binding, options) {
  const timeoutMs = integer(options.launchTimeoutMs, 7_000, 100, 30_000);
  const deadline = Date.now() + timeoutMs;
  const wait = options.wait || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  let lastError = null;
  while (Date.now() < deadline) {
    await wait(50);
    try {
      const record = await discoverAvailableHost(discover, {
        runtimeRoot: binding.runtimeRoot,
        region: binding.region,
        principalId: binding.principalId,
        hostInstallationId: binding.hostInstallationId,
        fetchImpl: options.fetchImpl,
      });
      if (record) return record;
    } catch (error) { lastError = error; }
  }
  if (lastError) throw lastError;
  return null;
}

async function discoverAvailableHost(discover, options) {
  try {
    return await discover(options);
  } catch (error) {
    if (["neutral_host_discovery_stale", "neutral_host_discovery_generation_mismatch"].includes(error?.code)) {
      return null;
    }
    throw error;
  }
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function safeId(value, code) {
  const text = String(value || "");
  if (!SAFE_ID.test(text)) throw codeError(code);
  return text;
}
function integer(value, fallback, minimum, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw codeError("neutral_limit_invalid");
  return number;
}
function codeError(code) { const error = new Error(code); error.code = code; return error; }
