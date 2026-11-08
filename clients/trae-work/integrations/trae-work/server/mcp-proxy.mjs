#!/usr/bin/env node

import path from "node:path";
import { readClientAccount } from "../../../runtime/core/hellolynk-client-account.mjs";
import { workbenchConnectionError, isWorkbenchConnectionRequired } from "../../../runtime/core/hellolynk-workbench-connection.mjs";
import { fileURLToPath } from "node:url";
import { startInstalledClientUpdate } from "../../../runtime/core/hellolynk-client-update-entry.mjs";
import {
  createTraeWorkNeutralHostAdapter,
  createTraeWorkProtectedBindingProvider,
} from "./neutral-host-adapter.mjs";
import {
  runTraeWorkStdioMcpServer,
  toTraeWorkPublicErrorCode,
} from "./mcp-server.mjs";
import { createCurrentTraeWorkNeutralProduction } from "./trae-neutral-production.mjs";
import { closeTraeWorkInbox, openTraeWorkInbox } from "./trae-ui-launch.mjs";
import { readTraeNativeTaskWorkerConfig, startTraeNativeTaskWorker } from "./native-task-worker.mjs";

export async function runTraeWorkMcpProxy(options = {}) {
  let adapter = options.adapter || null;
  if (!adapter) {
    const updating = options.createAdapter ? Promise.resolve(null) : startInstalledClientUpdate({
      client: "trae-work", packageRoot: fileURLToPath(new URL("../../../", import.meta.url)), storeRoot: options.storeRoot,
    });
    const createProduction = options.createProduction || (options.createAdapter ? null : createCurrentTraeWorkNeutralProduction);
    const connect = async () => {
      // A startup install finishes first. After that the protected binding names the
      // release to use, and a background update can move it while this process stays open.
      await updating;
      const production = options.production || (createProduction ? await createProduction({
        ...(options.storeRoot ? { storeRoot: options.storeRoot } : {}),
      }) : null);
      return (options.createAdapter || createTraeWorkNeutralHostAdapter)({
        capabilityProvider: options.capabilityProvider || production?.capabilityProvider || createTraeWorkProtectedBindingProvider(options),
        discoverHost: options.discoverHost,
        requestHost: options.requestHost,
        hostLauncher: options.hostLauncher || production?.hostLauncher,
        adapterInstanceId: options.adapterInstanceId,
        heartbeatMs: options.heartbeatMs,
      });
    };
    adapter = recoveringAdapter(connect, toTraeWorkPublicErrorCode, [
      "hostStatus", "getNativeTaskScope", "readInbox", "readUnreadCount", "markInboxMessageRead", "deleteReadInboxMessages",
      "listContacts", "saveContact", "deleteContact", "listContactRequests",
      "setAutonomousSendAuthorization", "listAuthorizedContacts", "listAuthorizedInboxMessages", "modelInbox", "listPendingMessages", "claimMessage", "claimBatch", "inboxBatch", "readAuthorizedInboxMessage", "listAuthorizedContactRequests", "readAuthorizedContactRequest", "sendAuthorizedMessage", "replyAuthorizedMessage",
      "readOutbox", "issueOutboxRetryGrant", "retryOutboxMessage", "readChangesSnapshot",
      "readWorkbenchSnapshot", "readWorkbenchChanges", "issueWorkbenchActionGrant", "executeWorkbenchCommand",
      "requestHumanSend", "getHumanSendStatus",
    ], () => readClientAccount("trae-work", options.storeRoot).revision);
    adapter.start();
  }
  let nativeTasks = null;
  try {
    const debugEndpoint = options.nativeTasks === false ? null : options.nativeTaskOptions?.debugEndpoint
      || process.env.HELLOLYNK_TRAE_DEBUG_ENDPOINT || await readTraeNativeTaskWorkerConfig(options.storeRoot);
    nativeTasks = debugEndpoint ? startTraeNativeTaskWorker({ adapter, ...options.nativeTaskOptions, debugEndpoint }) : null;
    return await (options.runServer || runTraeWorkStdioMcpServer)({
      adapter,
      input: options.input || process.stdin,
      output: options.output || process.stdout,
      openInbox: options.openInbox || (() => openTraeWorkInbox({ adapter })),
      privateUiEnabled: options.privateUiEnabled === true,
    });
  } finally {
    try { await nativeTasks?.close(); await closeTraeWorkInbox(); }
    finally { await adapter.close(); }
  }
}

function recoveringAdapter(connectAdapter, publicCode, methods, accountRevision = () => null) {
  let current = null;
  let pending = null;
  let closed = false;
  let closePromise = null;
  const adapterCloses = new WeakMap();
  let revision = accountRevision();
  let accountReset = null;
  function closeAdapter(value) {
    if (!value) return Promise.resolve();
    if (!adapterCloses.has(value)) adapterCloses.set(value, Promise.resolve().then(() => value.close?.()));
    return adapterCloses.get(value);
  }
  async function connect() {
    if (closed) throw codeError("neutral_host_adapter_closed");
    const nextRevision = accountRevision();
    if (!accountReset && revision !== nextRevision) {
      const old = current, previousFlight = pending;
      current = null; pending = null; revision = nextRevision;
      accountReset = Promise.resolve().then(async () => {
        const previous = await previousFlight?.catch(() => null);
        await closeAdapter(previous || old).catch(() => {});
      }).finally(() => { accountReset = null; });
    }
    if (accountReset) await accountReset;
    if (closed) throw codeError("neutral_host_adapter_closed");
    if (revision !== accountRevision()) throw codeError("workbench_account_changed");
    if (current && current.state !== "dead" && current.state !== "closed") return current;
    if (current) await closeAdapter(current).catch(() => {});
    current = null;
    if (closed) throw codeError("neutral_host_adapter_closed");
    if (!pending) {
      const generation = revision;
      const flight = Promise.resolve().then(connectAdapter).then(async (value) => {
        if (closed || generation !== accountRevision()) {
          await closeAdapter(value).catch(() => {});
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
    start() {
      const started = connect();
      started.catch(() => {});
      return started;
    },
    async close() {
      if (closed) return closePromise;
      closed = true;
      const value = current;
      current = null;
      // Both the current flight and a reset-detached flight remain owned until
      // their late adapter has been retired. Repeated callers share the drain.
      closePromise = Promise.allSettled([pending, accountReset, closeAdapter(value)]).then(() => undefined);
      return closePromise;
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

export function formatTraeWorkProxyError(error) {
  return `${JSON.stringify({ ok: false, error: toTraeWorkPublicErrorCode(error) })}\n`;
}

function codeError(code) { const error = new Error(code); error.code = code; return error; }

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runTraeWorkMcpProxy().catch((error) => {
    process.stderr.write(formatTraeWorkProxyError(error));
    process.exitCode = 1;
  });
}
