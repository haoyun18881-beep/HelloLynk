#!/usr/bin/env node

import path from "node:path";
import { createClientAccountActions } from "../runtime/core/hellolynk-client-account.mjs";
import { createWorkbenchConnection, workbenchConnectionError } from "../runtime/core/hellolynk-workbench-connection.mjs";
import { fileURLToPath } from "node:url";
import { runStdioMcpServer } from "./mcp-server.mjs";
import {
  createCodexNeutralHostAdapter,
  isCodexNeutralHostUnavailable,
  resolveHelloLynkHostMode,
} from "./neutral-host-adapter.mjs";
import { createCodexNeutralProduction } from "./codex-neutral-production.mjs";
import { bootstrapCodexWorkbenchRuntime } from "./workbench-runtime.mjs";
import { createNativeTaskRuntime } from "./native-task-runtime.mjs";
import { createNativeTaskClient, inspectCodexExecutorMetadata } from "./native-task-client.mjs";
import { rememberNativeReplyRoute, rememberNativeCaller, readNativeCaller } from "./native-reply-routes.mjs";


export async function runMcpProxy(options = {}) {
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const mode = options.mode == null
    ? resolveHelloLynkHostMode(options.env || process.env)
    : resolveHelloLynkHostMode({ HELLOLYNK_HOST_MODE: options.mode });
  if (mode === "neutral") {
    // Codex builds the optional MCP tool catalog on a short deadline. Resolving the
    // protected binding and cold-starting the Host before `initialize` can exceed
    // that deadline, causing an otherwise healthy plugin to be omitted for the
    // whole task. Keep protocol discovery immediate, then warm the Host after
    // the handshake response even when Codex reuses its cached tool catalog.
    const neutralAdapter = options.neutralAdapter || createLazyNeutralAdapter(options);
    const nativeTasksEnabled = (options.nativeTaskClient !== undefined || options.createNativeTaskClient ||
      (!options.capabilityProvider && !options.createNeutralAdapter && !options.neutralAdapter
        && !options.createNeutralProduction && !options.hostLauncher && !options.discoverNeutralHost
        && !options.requestNeutralHost));
    let nativeTasks = null;
    let nativeCallerThreadId = null;
    let proxyClosed = false;
    let nativeTransition = Promise.resolve();
    const startNativeTasks = async (executorMetadata = null) => {
      if (proxyClosed || !nativeTasksEnabled) return;
      const context = inspectCodexExecutorMetadata(executorMetadata);
      if (context.conflict) return;
      const observedThreadId = context.threadId;
      let registeredCallerThreadId = null;
      if (observedThreadId || !nativeTasks) {
        try {
          const scope = await neutralAdapter.nativeTaskScope?.();
          if (scope && observedThreadId) await rememberNativeCaller(scope, observedThreadId);
          else if (scope) registeredCallerThreadId = await readNativeCaller(scope);
        } catch (error) {
          // Persistence is optional for a live executor. Keep its existing
          // receive path usable, while leaving a bounded diagnostic on stderr.
          process.stderr.write(`${JSON.stringify({ operation: "native_caller_cache", error: safeCode(error) })}\n`);
        }
      }
      if (nativeCallerThreadId && observedThreadId && nativeCallerThreadId !== observedThreadId) {
        // A long-lived MCP process may serve several legitimate Codex tasks.
        // Finish the old worker before adopting the next executor-owned context.
        await nativeTasks?.close();
        nativeTasks = null;
        nativeCallerThreadId = null;
      }
      if (proxyClosed) return;
      if (!nativeTasks) {
        const client = options.nativeTaskClient === undefined
          ? (options.createNativeTaskClient || createNativeTaskClient)({ env: options.env || process.env, executorMetadata, registeredCallerThreadId })
          : options.nativeTaskClient;
        if (!client) return;
        nativeCallerThreadId = observedThreadId || client.callerThreadId;
        nativeTasks = (options.createNativeTaskRuntime || createNativeTaskRuntime)({ adapter: neutralAdapter, native: client });
      }
      await nativeTasks.start();
    };
    const queueNativeStart = (metadata) => {
      const transition = nativeTransition.then(() => startNativeTasks(metadata));
      nativeTransition = transition.catch(() => {});
      return transition;
    };
    const workbenchCandidate = await optionalWorkbenchCandidate(options, neutralAdapter);
    try {
      return await runStdioMcpServer({
        input,
        output,
        neutralAdapter,
        readNativeDeliveryStatus: () => nativeTasks?.readDeliveryStatus?.(),
        async prepareAuthorizedWrite(metadata, message) {
          const context = inspectCodexExecutorMetadata(metadata);
          // A shared MCP process's inherited thread may be stale. Registration
          // needs the exact current executor envelope, never its environment.
          if (!nativeTasksEnabled || context.conflict || !context.threadId) return;
          const scope = await neutralAdapter.nativeTaskScope();
          await rememberNativeReplyRoute(scope, { ...message, threadId: context.threadId });
        },
        onProtocolReady: async () => {
          await neutralAdapter.prewarm();
          await queueNativeStart().catch(() => {});
        },
        onExecutorToolCall: (metadata) => queueNativeStart(metadata),
        ...(workbenchCandidate ? { workbenchCandidate } : {}),
      });
    } finally {
      proxyClosed = true;
      await nativeTransition;
      await nativeTasks?.close();
      await neutralAdapter.close();
    }
  }
}

export function createLazyNeutralAdapter(options = {}) {
  let adapterPromise = null;
  let currentAdapter = null;
  let closePromise = null;
  let closed = false;
  const adapterCloses = new WeakMap();
  const retiring = new Set();
  const accounts = createClientAccountActions({ ...options, client: "codex" });
  let accountRevision = accounts.readAccountState().revision;
  let accountReset = null;

  const closeAdapter = (adapter) => {
    if (!adapterCloses.has(adapter)) {
      const operation = Promise.resolve().then(() => adapter.close?.());
      adapterCloses.set(adapter, operation);
      retiring.add(operation);
      void operation.then(() => retiring.delete(operation), () => retiring.delete(operation));
    }
    return adapterCloses.get(adapter);
  };
  const retireAdapter = async (adapter, pendingAdapter) => {
    if (adapterPromise === pendingAdapter) { adapterPromise = null; currentAdapter = null; }
    await closeAdapter(adapter).catch(() => {});
  };

  const resolveAdapter = async (allowCachedRecovery = true) => {
    const nextRevision = accounts.readAccountState().revision;
    if (!accountReset && accountRevision !== nextRevision) {
      const previousFlight = adapterPromise;
      adapterPromise = null; currentAdapter = null; accountRevision = nextRevision;
      accountReset = Promise.resolve().then(async () => {
        const previous = await previousFlight?.catch(() => null);
        if (previous) await closeAdapter(previous).catch(() => {});
      }).finally(() => { accountReset = null; });
    }
    if (accountReset) await accountReset;
    const generation = accountRevision;
    if (generation !== accounts.readAccountState().revision) throw codeError("workbench_account_changed");
    if (!adapterPromise && retiring.size) await Promise.allSettled([...retiring]);
    if (closed) throw codeError("neutral_adapter_closed");
    const cachedAdapter = currentAdapter;
    if (!adapterPromise) adapterPromise = initializeNeutralAdapter(options);
    const pendingAdapter = adapterPromise;
    let adapter;
    try {
      adapter = await pendingAdapter;
    } catch (error) {
      // Keep concurrent first calls single-flight, but do not retain a rejected
      // initialization forever. The failing call remains fail-closed; only a
      // later tool call may start a fresh initialization attempt.
      if (adapterPromise === pendingAdapter) adapterPromise = null;
      throw workbenchConnectionError(error);
    }
    if (closed || generation !== accounts.readAccountState().revision) {
      await retireAdapter(adapter, pendingAdapter);
      throw codeError("neutral_adapter_closed");
    }
    if (adapter?.state === "dead" || adapter?.state === "closed") {
      await retireAdapter(adapter, pendingAdapter);
      // Only an already usable cached attachment gets one replacement. A new
      // attachment that is dead on arrival fails this operation without a loop.
      if (allowCachedRecovery && adapter === cachedAdapter) return resolveAdapter(false);
      throw codeError("neutral_host_adapter_unavailable");
    }
    if (adapterPromise === pendingAdapter) currentAdapter = adapter;
    return { adapter, pendingAdapter };
  };

  const invoke = async (method, args, minimumArity = 0) => {
    const { adapter, pendingAdapter } = await resolveAdapter();
    if (typeof adapter?.[method] !== "function" || adapter[method].length < minimumArity) {
      throw codeError("neutral_adapter_invalid");
    }
    try { return await adapter[method](...args); }
    catch (error) {
      if (adapter.state === "dead" || isCodexNeutralHostUnavailable(error)) {
        await retireAdapter(adapter, pendingAdapter);
      }
      // A failed command is never replayed. Only a later operation reconnects.
      throw error;
    }
  };
  const forward = (method) => (...args) => invoke(method, args);

  return Object.freeze({
    mode: "neutral",
    prewarm() {
      // Discovery must stay immediate. Start privileged initialization only in a
      // later microtask, and deliberately absorb a warm-up failure: an explicit
      // tool call still goes through resolveAdapter(), which clears a rejected
      // attempt and can retry normally.
      return Promise.resolve()
        .then(() => resolveAdapter())
        .then(() => undefined, () => undefined);
    },
    modelInbox: forward("modelInbox"),
    readUnreadCount: forward("readUnreadCount"),
    listAuthorizedContacts: forward("listAuthorizedContacts"),
    listAuthorizedInboxMessages: forward("listAuthorizedInboxMessages"),
    readAuthorizedInboxMessage: forward("readAuthorizedInboxMessage"),
    listPendingMessages: forward("listPendingMessages"),
    nativeTaskScope: forward("nativeTaskScope"),
    claimMessage: forward("claimMessage"),
    claimBatch: forward("claimBatch"),
    inboxBatch: forward("inboxBatch"),
    replyAuthorizedMessage: forward("replyAuthorizedMessage"),
    listAuthorizedContactRequests: forward("listAuthorizedContactRequests"),
    readAuthorizedContactRequest: forward("readAuthorizedContactRequest"),
    sendAuthorizedMessage: forward("sendAuthorizedMessage"),
    readWorkbenchSnapshot: forward("readWorkbenchSnapshot"),
    readWorkbenchChanges: forward("readWorkbenchChanges"),
    async issueWorkbenchActionGrant(command) {
      return invoke("issueWorkbenchActionGrant", [command], 1);
    },
    async executeWorkbenchCommand(command, context) {
      return invoke("executeWorkbenchCommand", [command, context], 2);
    },
    async close() {
      if (closed) return closePromise;
      closed = true;
      const pendingAdapter = adapterPromise;
      const pendingReset = accountReset;
      adapterPromise = null;
      currentAdapter = null;
      closePromise = (async () => {
        // Account reset owns any initialization it detached from adapterPromise.
        // Shutdown must also wait for that flight and its eventual retirement.
        await pendingReset?.catch(() => {});
        const adapter = await pendingAdapter?.catch(() => null);
        if (adapter) await closeAdapter(adapter);
        await Promise.allSettled([...retiring]);
      })();
      return closePromise;
    },
  });
}

async function optionalWorkbenchCandidate(options, neutralAdapter) {
  if (options.workbenchCandidate === null) return null;
  if (options.workbenchCandidate !== undefined) return options.workbenchCandidate;
  const bootstrap = options.bootstrapWorkbenchCandidate || bootstrapCodexWorkbenchRuntime;
  if (typeof bootstrap !== "function") return null;
  try {
    return await bootstrap({ adapter: neutralAdapter, connectAccount: options.connectAccount || createWorkbenchConnection({
      client: "codex", releaseRoot: path.dirname(path.dirname(fileURLToPath(import.meta.url))), env: options.env || process.env,
    }) });
  } catch {
    // Discovery stays available when the shared bundle is missing, but the MCP
    // server must fail that UI surface closed instead of restoring the retired
    // UI. Independent neutral model tools remain available.
    return null;
  }
}

async function initializeNeutralAdapter(options) {
  const production = options.capabilityProvider || options.hostLauncher
    ? null
    : await (options.createNeutralProduction || createCodexNeutralProduction)({
        env: options.env || process.env,
      });
  const createAdapter = options.createNeutralAdapter || createCodexNeutralHostAdapter;
  return createAdapter({
    capabilityProvider: options.capabilityProvider || production?.capabilityProvider,
    discoverHost: options.discoverNeutralHost,
    hostLauncher: options.hostLauncher || production?.hostLauncher,
    requestHost: options.requestNeutralHost,
    fetchImpl: options.fetchImpl,
    adapterInstanceId: options.adapterInstanceId,
    heartbeatMs: options.heartbeatMs,
    wait: options.wait,
  });
}

function safeCode(error) {
  const value = String(error?.code || error?.message || "single_host_unavailable")
    .replace(/[^A-Za-z0-9._:-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120);
  return value || "single_host_unavailable";
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runMcpProxy().catch((error) => {
    process.stderr.write(`${JSON.stringify({ ok: false, error: safeCode(error) })}\n`);
    process.exitCode = 1;
  });
}
