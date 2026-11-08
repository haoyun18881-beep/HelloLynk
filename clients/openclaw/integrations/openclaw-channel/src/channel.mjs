import {
  createChatChannelPlugin,
  defineChannelPluginEntry,
} from "openclaw/plugin-sdk/channel-core";
import { createChannelMessageAdapterFromOutbound } from "openclaw/plugin-sdk/channel-outbound";
import { getReplyFromConfig } from "openclaw/plugin-sdk/reply-runtime";
import { getSessionEntry, listSessionEntries, resolveTranscriptSessionKeyBySessionId } from "openclaw/plugin-sdk/session-store-runtime";
import { readAgentRunTerminalOutcome } from "openclaw/plugin-sdk/channel-inbound";
import { resolveActiveEmbeddedRunSessionId } from "openclaw/plugin-sdk/agent-harness-runtime";
import { HELLOLYNK_CHANNEL_CONFIG_SCHEMA_DESCRIPTOR } from "./config-schema.mjs";
import {
  createOpenClawWorkbenchRuntime,
  registerHelloLynkWorkbenchControlUi,
  resolveOpenClawWorkbenchParentOrigin,
} from "./control-ui.mjs";
import { createOpenClawAuthorizedMessagingAgentTools, OPENCLAW_AUTHORIZED_MESSAGING_TOOLS } from "./authorized-messaging-tools.mjs";
import { observeHelloLynkModelCall } from "./channel-dispatch.mjs";
import { runOpenClawNeutralReadRuntime } from "./neutral-read-runtime.mjs";
import { createWorkbenchConnection, isWorkbenchConnectionRequired } from "../../../clients/core/hellolynk-workbench-connection.mjs";
import { readClientAccount } from "../../../clients/core/hellolynk-client-account.mjs";
import { startInstalledClientUpdate } from "../../../clients/core/hellolynk-client-update-entry.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { launchPinnedNeutralHost } from "../../../clients/core/hellolynk-neutral-host-launcher.mjs";
import {
  createOpenClawNeutralHostAdapter,
  createOpenClawProtectedBindingProvider,
  isOpenClawNeutralHostUnavailable,
} from "./neutral-host-adapter.mjs";

const CHANNEL_ID = "hellolynk";
const DEFAULT_ACCOUNT_ID = "default";

// OpenClaw can run this module from a temporary copy of its imports, while each
// registration names the installed plugin directory. Files outside the module
// graph (Host helper, package metadata, workbench runtime) come from that root.
let registeredReleaseRoot = "";
let registeredAgentRuntime;

function openClawReleaseRoot() {
  return registeredReleaseRoot || fileURLToPath(new URL("../../../", import.meta.url));
}

function channelConfig(cfg) {
  return cfg?.channels?.hellolynk || cfg?.hellolynk || {};
}

function accountConfig(cfg, accountId = DEFAULT_ACCOUNT_ID) {
  const root = channelConfig(cfg);
  const account = root.accounts?.[accountId] || {};
  rejectLegacyFields(root);
  rejectLegacyFields(account);
  const hostMode = account.hostMode ?? root.hostMode;
  const bindingRef = account.bindingRef ?? root.bindingRef;
  const adapterInstanceId = account.adapterInstanceId ?? root.adapterInstanceId;
  return Object.freeze({
    accountId,
    name: account.name || root.name || "HelloLynk 通讯",
    enabled: account.enabled ?? root.enabled ?? false,
    configured: hostMode === "neutral" && bindingRef === "protected-store:openclaw",
    hostMode: hostMode || "",
    bindingRef: bindingRef || "",
    adapterInstanceId: adapterInstanceId || "",
    nativeModel: account.nativeModel ?? root.nativeModel,
  });
}

function rejectLegacyFields(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  for (const key of [
    "baseUrl", "principalId", "hellolynkId", "delegateId", "deviceId", "deviceCredential",
    "runtimeSessionId", "runtimeSessionSecret", "pollIntervalMs", "hellolynkAgentId",
    "openclawAgentId", "devTrustedSenderPrincipalIds", "knownTargets", "defaultTo",
  ]) {
    if (Object.hasOwn(value, key)) throw codeError("neutral_openclaw_legacy_config_rejected");
  }
}

function listAccountIds(cfg) {
  const accounts = channelConfig(cfg).accounts;
  const ids = accounts && typeof accounts === "object" ? Object.keys(accounts) : [];
  return ids.length ? ids : [DEFAULT_ACCOUNT_ID];
}

function resolveDefaultAccountId(cfg) {
  return channelConfig(cfg).defaultAccount || listAccountIds(cfg)[0] || DEFAULT_ACCOUNT_ID;
}

const failDirectSend = async () => { throw codeError("neutral_openclaw_direct_send_unavailable"); };
export const hellolynkNeutralOutbound = Object.freeze({
  deliveryMode: "direct",
  resolveTarget: () => ({ ok: false, error: codeError("neutral_openclaw_direct_send_unavailable") }),
  sendText: failDirectSend,
  sendMedia: failDirectSend,
  sendPayload: failDirectSend,
});
const message = createChannelMessageAdapterFromOutbound({ id: CHANNEL_ID, outbound: hellolynkNeutralOutbound });

async function startHelloLynkGatewayAccount(ctx) {
  const account = accountConfig(ctx.cfg, ctx.account?.accountId || ctx.accountId || DEFAULT_ACCOUNT_ID);
  if (!account.enabled) throw codeError("neutral_openclaw_disabled");
  if (!account.configured) throw codeError("neutral_openclaw_binding_configuration_required");
  const adapter = await createOpenClawAdapter(ctx, account);
  ctx.setStatus?.({
    accountId: account.accountId,
    running: true,
    configured: true,
    enabled: true,
    mode: "neutral_host",
  });
  const readController = new AbortController();
  const abortRead = () => readController.abort();
  ctx.abortSignal?.addEventListener("abort", abortRead, { once: true });
  if (ctx.abortSignal?.aborted) readController.abort();
  const readRuntime = runOpenClawNeutralReadRuntime({
    adapter,
    account: { ...account, delegateId: adapter.binding?.delegateId },
    channelContext: { ...ctx, hellolynkGetReplyFromConfig: getReplyFromConfig, hellolynkGetSessionEntry: getSessionEntry, hellolynkListSessionEntries: listSessionEntries,
      hellolynkResolveSessionKeyById: resolveTranscriptSessionKeyBySessionId,
      hellolynkActiveSessionRun: resolveActiveEmbeddedRunSessionId,
      hellolynkAgentRuntime: registeredAgentRuntime, hellolynkReadRunOutcome: readAgentRunTerminalOutcome },
    abortSignal: readController.signal,
    ...(ctx.hellolynkAcquireNativeWorkerLease ? { acquireLease: ctx.hellolynkAcquireNativeWorkerLease } : {}),
  });
  try {
    const reason = await Promise.race([adapter.done, readRuntime]);
    if (adapter.state === "dead" && !ctx.abortSignal?.aborted) throw codeError(reason);
  } finally {
    readController.abort();
    await readRuntime.catch(() => {});
    ctx.abortSignal?.removeEventListener("abort", abortRead);
    await adapter.close();
    ctx.setStatus?.({
      accountId: account.accountId,
      running: false,
      configured: true,
      enabled: true,
      mode: "neutral_host",
    });
  }
}

async function createOpenClawAdapter(ctx, account) {
  if (!ctx?.hellolynkNeutralAdapterFactory) {
    await startInstalledClientUpdate({ client: "openclaw", packageRoot: openClawReleaseRoot() });
  }
  const createAdapter = ctx?.hellolynkNeutralAdapterFactory || createOpenClawNeutralHostAdapter;
  return createAdapter({
    bindingRef: account.bindingRef,
    ...(account.adapterInstanceId ? { adapterInstanceId: account.adapterInstanceId } : {}),
    capabilityProvider: ctx?.hellolynkNeutralCapabilityProvider
      || createOpenClawProtectedBindingProvider({
        helperPath: path.join(openClawReleaseRoot(), "clients", "platform", "windows", "hellolynk-host-protected-store.ps1"),
      }),
    hostLauncher: ctx?.hellolynkNeutralHostLauncher
      || ((binding) => launchPinnedNeutralHost(binding)),
  });
}

// The workbench retains this facade for its lifetime. Its underlying attachment
// can be retired without replaying the operation that discovered the failure.
export function createRecoveringOpenClawAdapter(factory) {
  let pending = null;
  let current = null;
  let epoch = 0;
  let closing = null;
  const closes = new WeakMap();
  const retiring = new Set();
  let accountRevision = readClientAccount("openclaw").revision;
  let accountReset = null;
  const closeAdapter = (adapter) => {
    if (!closes.has(adapter)) {
      const operation = Promise.resolve().then(() => adapter.close?.());
      closes.set(adapter, operation);
      retiring.add(operation);
      void operation.then(() => retiring.delete(operation), () => retiring.delete(operation));
    }
    return closes.get(adapter);
  };
  const retire = async (adapter, flight) => {
    if (pending === flight) { pending = null; current = null; }
    await closeAdapter(adapter).catch(() => {});
  };
  const resolve = async (allowCachedRecovery = true) => {
    const nextRevision = readClientAccount("openclaw").revision;
    if (!accountReset && nextRevision !== accountRevision) {
      const previousFlight = pending;
      pending = null; current = null; accountRevision = nextRevision;
      accountReset = Promise.resolve().then(async () => {
        const previous = await previousFlight?.catch(() => null);
        if (previous) await closeAdapter(previous).catch(() => {});
      }).finally(() => { accountReset = null; });
    }
    if (accountReset) await accountReset;
    const selectedAccount = accountRevision;
    if (selectedAccount !== readClientAccount("openclaw").revision) throw codeError("workbench_account_changed");
    if (closing) await closing;
    if (!pending && retiring.size) await Promise.allSettled([...retiring]);
    const generation = epoch;
    const cachedAdapter = current;
    const flight = pending ||= Promise.resolve().then(factory);
    let adapter;
    try { adapter = await flight; }
    catch (error) { if (pending === flight) pending = null; throw error; }
    if (epoch !== generation || selectedAccount !== readClientAccount("openclaw").revision) {
      await closeAdapter(adapter).catch(() => {});
      throw codeError("neutral_host_adapter_closed");
    }
    if (adapter.state === "dead" || adapter.state === "closed") {
      await retire(adapter, flight);
      // A dead cached attachment may be replaced once. A fresh dead result must
      // reject instead of continuously creating attachments in this operation.
      if (allowCachedRecovery && adapter === cachedAdapter) return resolve(false);
      throw codeError("neutral_host_adapter_unavailable");
    }
    if (pending === flight) current = adapter;
    return { adapter, flight };
  };
  const invoke = async (method, args, minimumArity = 0) => {
    const { adapter, flight } = await resolve();
    if (typeof adapter[method] !== "function" || adapter[method].length < minimumArity) {
      throw codeError("neutral_openclaw_adapter_invalid");
    }
    try { return await adapter[method](...args); }
    catch (error) {
      if (adapter.state === "dead" || isOpenClawNeutralHostUnavailable(error)) await retire(adapter, flight);
      throw error;
    }
  };
  const methods = Object.fromEntries([
    "readBundle", "readWorkbenchSnapshot", "readWorkbenchChanges", "markRead", "deleteRead", "saveContact", "deleteContact",
    "setAutonomousSendAuthorization", "listAuthorizedContacts", "activateAuthorizedInbox", "listAuthorizedInboxMessages", "modelInbox",
    "readAuthorizedInboxMessage", "listAuthorizedContactRequests", "readAuthorizedContactRequest", "listPendingMessages", "claimMessage", "claimBatch", "inboxBatch",
    "sendAuthorizedMessage", "replyAuthorizedMessage", "issueRetryGrant", "retryOutgoing",
    "deleteOutgoing", "requestHumanSend", "getHumanSendStatus",
  ].map((method) => [method, (...args) => invoke(method, args)]));
  return Object.freeze({
    ...methods,
    async ready() { await resolve(); },
    get binding() { return current?.binding; },
    async issueWorkbenchActionGrant(command) { return invoke("issueWorkbenchActionGrant", [command], 1); },
    async executeWorkbenchCommand(command, context) { return invoke("executeWorkbenchCommand", [command, context], 2); },
    async close() {
      if (closing) return closing;
      epoch += 1;
      const flight = pending;
      pending = null;
      current = null;
      const operation = (async () => {
        const adapter = await flight?.catch(() => null);
        if (adapter) await closeAdapter(adapter);
        await Promise.allSettled([...retiring]);
      })();
      closing = operation;
      try { await operation; }
      finally { if (closing === operation) closing = null; }
    },
  });
}

export const hellolynkChannelPlugin = createChatChannelPlugin({
  base: {
    id: CHANNEL_ID,
    meta: {
      id: CHANNEL_ID,
      label: "HelloLynk 通讯",
      selectionLabel: "HelloLynk 通讯",
      detailLabel: "HelloLynk 通讯 · 本机 Host",
      docsPath: "/channels/hellolynk",
      blurb: "HelloLynk Messaging attached to the local neutral HelloLynk Host.",
    },
    capabilities: { chatTypes: ["direct"], media: false, threads: false, blockStreaming: true },
    reload: { configPrefixes: ["channels.hellolynk"] },
    configSchema: HELLOLYNK_CHANNEL_CONFIG_SCHEMA_DESCRIPTOR,
    config: {
      listAccountIds,
      resolveAccount: (cfg, accountId) => accountConfig(cfg, accountId),
      defaultAccountId: resolveDefaultAccountId,
      isConfigured: (account) => account.configured,
      resolveAllowFrom: () => [],
      resolveDefaultTo: () => undefined,
    },
    messaging: {
      targetPrefixes: ["hellolynk"],
      normalizeTarget: () => null,
      inferTargetChatType: () => "direct",
    },
    directory: { listPeers: async () => [] },
    message,
    actions: { describeMessageTool: () => ({ actions: [] }) },
    gateway: { startAccount: startHelloLynkGatewayAccount },
  },
  outbound: hellolynkNeutralOutbound,
});

// Discovery and the active Gateway expose the same Host-backed tools.
function registerMessagingTools(api, account) {
  let recoveringAdapter;
  const adapterProvider = async () => {
    recoveringAdapter ||= createRecoveringOpenClawAdapter(() => (
      typeof api.hellolynkNeutralAdapterProvider === "function"
        ? api.hellolynkNeutralAdapterProvider()
        : createOpenClawAdapter(api, account)
    ));
    await recoveringAdapter.ready().catch((error) => { if (!isWorkbenchConnectionRequired(error)) throw error; });
    return recoveringAdapter;
  };
  api.registerTool((toolContext) => createOpenClawAuthorizedMessagingAgentTools({ adapterProvider, toolContext }),
    { names: OPENCLAW_AUTHORIZED_MESSAGING_TOOLS.map((tool) => tool.name) });
  return adapterProvider;
}

const channelEntry = defineChannelPluginEntry({
  id: CHANNEL_ID,
  name: "HelloLynk 通讯",
  description: "HelloLynk Messaging: linked replies return to their exact originating conversation with explicit source attribution; new mail uses a dedicated conversation.",
  plugin: hellolynkChannelPlugin,
  registerFull: (api) => {
    if (api.registrationMode !== "full" && api.registrationMode !== "tool-discovery") return;
    const account = accountConfig(api.config, resolveDefaultAccountId(api.config));
    if (!account.enabled) return;
    if (api.registrationMode === "full" && typeof api.registerService !== "function") {
      throw codeError("openclaw_workbench_service_api_unavailable");
    }
    if (api.registrationMode === "full") registeredAgentRuntime = api.runtime?.agent;
    const adapterProvider = registerMessagingTools(api, account);
    if (api.registrationMode === "full") {
      if (typeof api.on === "function") {
        api.on("model_call_started", (event) => observeHelloLynkModelCall(event, "started"));
        api.on("model_call_ended", (event) => observeHelloLynkModelCall(event, "ended"));
        api.on("llm_output", (event) => observeHelloLynkModelCall(event, "llm_output"));
      }
      const workbenchRuntime = createOpenClawWorkbenchRuntime({
        adapterProvider,
        releaseRoot: openClawReleaseRoot(),
        connectAccount: createWorkbenchConnection({ client: "openclaw", releaseRoot: openClawReleaseRoot(),
          helperPath: path.join(openClawReleaseRoot(), "clients", "platform", "windows", "hellolynk-host-protected-store.ps1"),
        }),
        trustedParentOrigin: resolveOpenClawWorkbenchParentOrigin(api.config),
      });
      registerHelloLynkWorkbenchControlUi(api, {
        workbenchProvider: workbenchRuntime.workbenchProvider,
      });
      api.registerService(workbenchRuntime.service);
    }
  },
  registerCapabilities: (api) => {
    if (api.registrationMode !== "discovery") return;
    const account = accountConfig(api.config, resolveDefaultAccountId(api.config));
    if (account.enabled) registerMessagingTools(api, account);
  },
});

// Every registration mode receives api.rootDir, before the gateway can start an
// account from this registry.
export const hellolynkChannelEntry = {
  ...channelEntry,
  register(api) {
    if (path.isAbsolute(String(api?.rootDir || ""))) registeredReleaseRoot = path.resolve(api.rootDir, "..", "..");
    return channelEntry.register(api);
  },
};

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
