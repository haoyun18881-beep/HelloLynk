#!/usr/bin/env node

import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { readClientAccount } from "../../../clients/core/hellolynk-client-account.mjs";
import { workbenchConnectionError, isWorkbenchConnectionRequired } from "../../../clients/core/hellolynk-workbench-connection.mjs";
import { fileURLToPath } from "node:url";
import { startInstalledClientUpdate } from "../../../clients/core/hellolynk-client-update-entry.mjs";
import {
  createWorkBuddyNeutralHostAdapter,
  createWorkBuddyProtectedBindingProvider,
  validateWorkBuddyProtectedBinding,
} from "./neutral-host-adapter.mjs";
import {
  runWorkBuddyStdioMcpServer,
  toWorkBuddyPublicErrorCode,
  projectPendingMessages,
} from "./mcp-server.mjs";
import { launchWorkBuddyNeutralHost } from "./host-lifecycle.mjs";
import { startWorkBuddyNativeTaskWorker } from "./native-task-worker.mjs";
import { prepareWorkBuddyOriginHook, workBuddyOriginInbox, markWorkBuddyActiveScope } from "./origin-routes.mjs";
import { readWorkBuddyModelCaller } from "./model-call-origin.mjs";
import { nativeReplyRouteLocation } from "../../../clients/core/hellolynk-native-reply-routes.mjs";
import { defaultNeutralHostStoreRoot } from "../../../clients/core/hellolynk-neutral-host-installation-store.mjs";
import { startRecordedWorkBuddyNativeService, workBuddyMcpTrustRequests } from "./native-task-service-registration.mjs";
import { closeWorkBuddyWorkbench, launchWorkBuddyWorkbench } from "./workbench-candidate.mjs";
import { serveWorkBuddyWorkbench, serveWorkBuddyWorkbenchService } from "./workbench-process.mjs";
export { launchDetachedWorkBuddyWorkbench, handoffWorkBuddyWorkbench, configureWorkBuddyNativeTaskService } from "./workbench-process.mjs";
export { registerWorkBuddyNativeMcp } from "./native-task-mcp-registration.mjs";

function createProxyAdapter(options) {
  if (options.adapter) return options.adapter;
  const updating = options.createAdapter ? Promise.resolve(null) : startInstalledClientUpdate({
    client: "workbuddy", packageRoot: fileURLToPath(new URL("../../../", import.meta.url)), storeRoot: options.storeRoot,
  });
  const connect = async () => {
    await updating;
    const connected = await (options.createAdapter || createWorkBuddyNeutralHostAdapter)({
    capabilityProvider: options.capabilityProvider || createWorkBuddyProtectedBindingProvider(options),
    discoverHost: options.discoverHost,
    requestHost: options.requestHost,
    hostLauncher: options.hostLauncher || ((binding) => launchWorkBuddyNeutralHost(binding, {
      storeRoot: path.dirname(binding.runtimeRoot),
      ...(options.spawnRunner ? { spawnRunner: options.spawnRunner } : {}),
    })),
    adapterInstanceId: options.adapterInstanceId,
    heartbeatMs: options.heartbeatMs,
    });
    try { await markWorkBuddyActiveScope(workBuddyOriginInbox(options.storeRoot || defaultNeutralHostStoreRoot()), await connected.getNativeTaskScope()); }
    catch { /* Model calls still require matching current-account hook evidence. */ }
    return connected;
  };
  const adapter = recoveringAdapter(connect, toWorkBuddyPublicErrorCode, [
    "hostStatus", "getNativeTaskScope", "readBundle", "readUnreadCount", "markMessageRead", "deleteRead", "saveContact",
    "deleteContact", "setAutonomousSendAuthorization", "listAuthorizedContacts", "listAuthorizedInboxMessages", "modelInbox", "listPendingMessages", "claimMessage", "claimBatch", "inboxBatch", "readAuthorizedInboxMessage", "listAuthorizedContactRequests", "readAuthorizedContactRequest", "sendAuthorizedMessage", "replyAuthorizedMessage",
    "issueRetryGrant", "retryOutgoing", "requestHumanSend", "getHumanSendStatus",
    "readWorkbenchSnapshot", "readWorkbenchChanges", "issueWorkbenchActionGrant", "executeWorkbenchCommand",
  ], () => readClientAccount("workbuddy", options.storeRoot).revision);
  // Opening the page is owned by its separate service. Do not cold-start the
  // Host inside WorkBuddy's short-lived conversation Job just for discovery.
  return adapter;
}

export async function runWorkBuddyWorkbenchProcess(options = {}) {
  return serveWorkBuddyWorkbench({ ...options, adapter: createProxyAdapter(options) });
}
export async function runWorkBuddyWorkbenchService(options = {}) {
  return serveWorkBuddyWorkbenchService({ ...options, adapter: createProxyAdapter(options) });
}

// Installed outside WorkBuddy's conversation Job. No AI task has to remain
// running to receive the next message; this is an ordinary program listener.
export async function runWorkBuddyNativeTaskService(options = {}) {
  if (!process.env.HELLOLYNK_WORKBUDDY_DEBUG_ENDPOINT && !options.nativeTaskOptions?.debugEndpoint) throw codeError("workbuddy_native_debug_enable_required");
  const adapter = createProxyAdapter(options);
  // Only the installed service (package bootstrap) registers the hook that
  // records which conversation sent each message; tests opt in explicitly.
  const origin = options.originHook ? await prepareWorkBuddyOriginHook({
    storeRoot: options.storeRoot || defaultNeutralHostStoreRoot(), ...(options.originHook === true ? {} : options.originHook) }) : null;
  // The installed service approves the trust request its own release's
  // update left; a service without a pinned release approves nothing.
  const mcpTrust = options.root && options.expectedManifestSha256 ? workBuddyMcpTrustRequests({ storeRoot: options.storeRoot,
    root: options.root, expectedManifestSha256: options.expectedManifestSha256 }) : null;
  const worker = startWorkBuddyNativeTaskWorker({ adapter, ...(origin ? { originInbox: origin.inbox } : {}), mcpTrust, ...options.nativeTaskOptions });
  const keepAlive = setInterval(() => {}, 60_000);
  const stop = () => { void worker.close(); };
  options.signal?.addEventListener("abort", stop, { once: true });
  if (options.signal?.aborted) stop();
  try {
    await worker.ready;
    if (!options.signal?.aborted) await new Promise((resolve) => options.signal?.addEventListener("abort", resolve, { once: true }));
  } finally { options.signal?.removeEventListener("abort", stop); clearInterval(keepAlive); await worker.close(); await adapter.close(); }
}

// Called only by a native background shell in a dedicated HelloLynk task.
// This process performs no model calls and emits no message content or identity.
export async function waitForWorkBuddyPending(options = {}) {
  if (options.signal?.aborted) return { pending: false, cancelled: true };
  const adapter = options.adapter || await (options.createAdapter || createWorkBuddyNeutralHostAdapter)({
    capabilityProvider: options.capabilityProvider || createWorkBuddyProtectedBindingProvider(options),
    discoverHost: options.discoverHost, requestHost: options.requestHost,
    hostLauncher: options.hostLauncher || ((binding) => launchWorkBuddyNeutralHost(binding, { storeRoot: path.dirname(binding.runtimeRoot) })),
  });
  try {
    while (!options.signal?.aborted) {
      const messages = projectPendingMessages(await adapter.listPendingMessages());
      if (options.signal?.aborted) break;
      if (messages.length) {
        (options.output || process.stdout).write("HELLOLYNK_INBOX_PENDING\n");
        return { pending: true };
      }
      try { await (options.wait || delay)(5000, undefined, { signal: options.signal }); }
      catch (error) { if (options.signal?.aborted && error?.name === "AbortError") break; throw error; }
    }
    return { pending: false, cancelled: true };
  } finally { await adapter.close(); }
}

export async function runWorkBuddyMcpProxy(options = {}) {
  const capabilityProvider = options.capabilityProvider || (!options.adapter && !options.createAdapter
    ? createWorkBuddyProtectedBindingProvider(options) : null);
  const adapter = createProxyAdapter({ ...options, ...(capabilityProvider ? { capabilityProvider } : {}) });
  const originInbox = workBuddyOriginInbox(options.storeRoot || defaultNeutralHostStoreRoot());
  // Publish the account before tools become available and their PreToolUse hook
  // runs. Reading the protected binding does not start a Host or receiver.
  try {
    const binding = capabilityProvider ? validateWorkBuddyProtectedBinding(await capabilityProvider()) : null;
    const scope = binding ? { runtimeRoot: binding.runtimeRoot, adapterId: "workbuddy", region: binding.region,
      principalId: binding.principalId, delegateId: binding.delegateId } : await options.adapter?.getNativeTaskScope?.();
    if (scope) await markWorkBuddyActiveScope(originInbox, scope);
  } catch { /* Unconnected discovery remains available; scoped calls fail closed. */ }
  let recordedService = { configured: false, status: "not_installed" };
  if (options.nativeTasks !== false) {
    try { recordedService = await (options.startRecordedNativeService || startRecordedWorkBuddyNativeService)({ storeRoot: options.storeRoot }); }
    catch (error) {
      recordedService = { configured: true, status: "unavailable", errorCode: /^workbuddy_[a-z_]{1,100}$/.test(error?.code || "") ? error.code : "workbuddy_native_service_start_failed" };
    }
  }
  // CDP must be explicitly enabled for this desktop profile. Existing MCP
  // discovery alone must not cold-start a Host in a short-lived native Job.
  const nativeEnabled = !recordedService.configured && options.nativeTasks !== false && Boolean(options.nativeTaskOptions?.debugEndpoint || process.env.HELLOLYNK_WORKBUDDY_DEBUG_ENDPOINT);
  const nativeTasks = nativeEnabled ? startWorkBuddyNativeTaskWorker({ adapter, ...options.nativeTaskOptions }) : null;
  try {
    return await (options.runServer || runWorkBuddyStdioMcpServer)({
      adapter,
      getModelInboxCaller: options.getModelInboxCaller || (async (meta, name, args) => {
        const scope = await adapter.getNativeTaskScope();
        await markWorkBuddyActiveScope(originInbox, scope);
        return readWorkBuddyModelCaller(originInbox,
          meta, name, args, nativeReplyRouteLocation(scope).scopeHash);
      }),
      nativeTaskStatus: () => nativeTasks?.status || (recordedService.configured ? { status: recordedService.status, ...(recordedService.errorCode ? { errorCode: recordedService.errorCode } : {}) } : { status: "disabled", errorCode: "workbuddy_native_debug_enable_required" }),
      // The resulting MCP response contains only a clean loopback URL. The
      // one explicit top-level navigation receives a short local session.
      openLocalWeb: options.openLocalWeb || (() => launchWorkBuddyWorkbench({ adapter })),
      input: options.input || process.stdin,
      output: options.output || process.stdout,
    });
  } finally {
    try { await nativeTasks?.close(); await closeWorkBuddyWorkbench(); }
    finally { await adapter.close(); }
  }
}

function recoveringAdapter(connectAdapter, publicCode, methods, accountRevision = () => null) {
  let current = null;
  let pending = null;
  let closed = false;
  let revision = accountRevision();
  let accountReset = null;
  async function connect() {
    if (closed) throw codeError("neutral_host_adapter_closed");
    const nextRevision = accountRevision();
    if (!accountReset && revision !== nextRevision) {
      const old = current, previousFlight = pending;
      current = null; pending = null; revision = nextRevision;
      accountReset = Promise.resolve().then(async () => {
        const previous = await previousFlight?.catch(() => null);
        await (previous || old)?.close?.().catch(() => {});
      }).finally(() => { accountReset = null; });
    }
    if (accountReset) await accountReset;
    if (revision !== accountRevision()) throw codeError("workbench_account_changed");
    if (current && current.state !== "dead" && current.state !== "closed") return current;
    if (current) await current.close().catch(() => {});
    current = null;
    if (!pending) {
      const generation = revision;
      const flight = Promise.resolve().then(connectAdapter).then(async (value) => {
        if (closed || generation !== accountRevision()) {
          await value?.close?.().catch(() => {});
          throw codeError("neutral_host_adapter_closed");
        }
        current = value;
        return value;
      }, (error) => { throw isWorkbenchConnectionRequired(error) ? workbenchConnectionError(error) : codeError(publicCode(error)); }).finally(() => { if (pending === flight) pending = null; });
      pending = flight;
    }
    return pending;
  }
  const facade = {
    async close() {
      if (closed) return;
      closed = true;
      const value = current;
      current = null;
      await value?.close?.().catch(() => {});
    },
  };
  const workbenchPair = methods.includes("issueWorkbenchActionGrant")
    && methods.includes("executeWorkbenchCommand");
  for (const method of methods) {
    if (workbenchPair && ["issueWorkbenchActionGrant", "executeWorkbenchCommand"].includes(method)) continue;
    facade[method] = async (...args) => (await connect())[method](...args);
  }
  if (workbenchPair) {
    const issueWorkbenchActionGrant = async function issueWorkbenchActionGrant(command) {
      const target = await connect();
      requireWorkbenchPair(target);
      return target.issueWorkbenchActionGrant(command);
    };
    facade.executeWorkbenchCommand = async function executeWorkbenchCommand(command, context) {
      const target = await connect();
      requireWorkbenchPair(target);
      return target.executeWorkbenchCommand(command, context);
    };
    Object.defineProperty(facade, "issueWorkbenchActionGrant", {
      enumerable: true,
      get() { return !current || hasWorkbenchPair(current) ? issueWorkbenchActionGrant : undefined; },
    });
  }
  return Object.freeze(facade);

  function requireWorkbenchPair(value) {
    if (!hasWorkbenchPair(value)) throw codeError("neutral_host_workbench_action_grant_unavailable");
  }

  function hasWorkbenchPair(value) {
    return typeof value?.issueWorkbenchActionGrant === "function"
      && value.issueWorkbenchActionGrant.length >= 1
      && typeof value.executeWorkbenchCommand === "function"
      && value.executeWorkbenchCommand.length >= 2;
  }
}

export function formatWorkBuddyProxyError(error) {
  return `${JSON.stringify({ ok: false, error: toWorkBuddyPublicErrorCode(error) })}\n`;
}

function codeError(code) { const error = new Error(code); error.code = code; return error; }

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runWorkBuddyMcpProxy().catch((error) => {
    process.stderr.write(formatWorkBuddyProxyError(error));
    process.exitCode = 1;
  });
}
