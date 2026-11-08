import { queryArgs, optionalTarget } from "../../../clients/core/hellolynk-native-addressing-tools.cjs";
import { captureHelloLynkModelNotices } from "../../../clients/core/hellolynk-model-notices.cjs";
import crypto from "node:crypto";
import path from "node:path";

import { HELLOLYNK_HOST_CAPABILITY_CONTRACT } from "../../../clients/core/hellolynk-host-auth.mjs";
import { createHostProtectedStore } from "../../../clients/core/hellolynk-host-protected-store.mjs";
import { discoverHelloLynkNeutralHost, requestHelloLynkNeutralHost, requestHelloLynkNeutralHostHandover } from "../../../clients/core/hellolynk-neutral-host-process.mjs";
import { HELLOLYNK_HOST_PATHS } from "../../../clients/core/hellolynk-host.mjs";
import {
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
} from "../../../clients/workbench/contract.mjs";

export const HELLOLYNK_WORKBUDDY_NEUTRAL_ADAPTER_CONTRACT = "hellolynk-workbuddy-neutral-adapter-v3";
export const HELLOLYNK_WORKBUDDY_NEUTRAL_BINDING_CONTRACT = "hellolynk-workbuddy-neutral-binding-v1";
export const WORKBUDDY_HEARTBEAT_MS = 10_000;

// Exact-match, human-UI-only capability. A general agent send capability is not included.
export const WORKBUDDY_NEUTRAL_EXACT_SCOPES = Object.freeze([
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
  "status:read",
  "surface:human-ui",
  "ui:launch",
].sort());

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;
const FROZEN_WORKBENCH_ACTION_GRANT_PATH = "/host/v1/app/workbench/action-grants";
if (HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant !== undefined
  && HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant !== FROZEN_WORKBENCH_ACTION_GRANT_PATH) {
  throw codeError("neutral_host_workbench_action_grant_path_mismatch");
}
const WORKBENCH_ACTION_GRANT_PATH = HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant
  ?? FROZEN_WORKBENCH_ACTION_GRANT_PATH;
const SAFE_DISCOVERY_ERRORS = new Set([
  "ENOENT", "neutral_host_discovery_stale", "neutral_host_discovery_generation_mismatch",
]);
// Another client, or a newer release, is starting the Host: wait for it instead of failing.
const LAUNCH_YIELD_ERRORS = new Set(["neutral_host_already_running", "neutral_host_release_superseded"]);
// A release handover is on hold: wait for the newer Host like already_running, report "switching" only if none appears.
const RELEASE_SUPERSEDED = "neutral_host_release_superseded";
const NON_TERMINAL_HOST_APP_ERRORS = new Set([
  "host_app_authorization_required", "host_app_record_not_found", "host_app_state_conflict",
  "host_app_reply_target_deleted",
]);

export function createWorkBuddyProtectedBindingProvider(options = {}) {
  const store = options.protectedStore || createHostProtectedStore({
    ...(options.storeRoot ? { root: options.storeRoot } : {}),
    ...(options.installationStore ? { installationStore: options.installationStore } : {}),
  });
  return () => store.resolveWorkBuddyNeutralBinding(options.bindingQuery || {});
}

export async function createWorkBuddyNeutralHostAdapter(options = {}) {
  if (typeof options.capabilityProvider !== "function") throw codeError("neutral_capability_provider_required");
  const binding = validateWorkBuddyProtectedBinding(await options.capabilityProvider());
  const discover = options.discoverHost || discoverHelloLynkNeutralHost;
  const request = options.requestHost || requestHelloLynkNeutralHost;
  const requestHandover = options.requestHostHandover || requestHelloLynkNeutralHostHandover;
  const discoverInput = publicBinding(binding);
  let discovery = await safeDiscover(discover, discoverInput);
  // A Host of an earlier release is asked to make room, and this client's release starts in its place.
  if (discovery && typeof options.hostLauncher === "function"
    && await earlierHostLeft(requestHandover, binding, integer(options.handoverWaitMs, 5_000, 0, 30_000))) {
    discovery = await safeDiscover(discover, discoverInput);
  }
  let startedHost = false;
  if (!discovery) {
    if (typeof options.hostLauncher !== "function") throw codeError("neutral_host_launcher_unavailable");
    // Another client may have started the shared Host a moment ago: wait for it instead of failing.
    let superseded = false;
    try { await options.hostLauncher(launchBinding(binding)); startedHost = true; }
    catch (error) {
      if (!LAUNCH_YIELD_ERRORS.has(error?.code)) throw error;
      superseded = error.code === RELEASE_SUPERSEDED;
    }
    discovery = await waitForDiscovery(discover, discoverInput, options);
    if (!discovery && superseded) throw codeError(RELEASE_SUPERSEDED);
  }
  if (!discovery) throw codeError("neutral_host_not_found");
  assertDiscovery(discovery, binding);

  const adapterInstanceId = safeId(
    options.adapterInstanceId || `workbuddy-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
    "neutral_host_adapter_instance_invalid",
  );
  const callRaw = async (method, pathname, body = null, requestOptions = {}) => captureHelloLynkModelNotices(await request({
    discovery, capability: binding.capability, method, pathname, body, ...requestOptions,
  }));
  await requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentAttach, { adapterInstanceId }));

  let closed = false;
  let deadCode = null;
  let inboxActivation = null;
  let heartbeatBusy = false;
  const heartbeatMs = integer(options.heartbeatMs, WORKBUDDY_HEARTBEAT_MS, 10, 30_000);
  const heartbeat = setInterval(async () => {
    if (closed || deadCode || heartbeatBusy) return;
    heartbeatBusy = true;
    try { await requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentHeartbeat, { adapterInstanceId })); }
    catch (error) {
      deadCode = /^(?:host|neutral_host)_[a-z0-9_]{1,100}$/.test(error?.code || "")
        ? error.code : "neutral_host_heartbeat_failed";
      clearInterval(heartbeat);
    }
    finally { heartbeatBusy = false; }
  }, heartbeatMs);
  heartbeat.unref?.();

  function assertLive() {
    if (closed) throw codeError("neutral_host_adapter_closed");
    if (deadCode) throw codeError(deadCode);
  }
  // A Host without the native inbox routes is of an earlier release: ask it to make room, then fail as before.
  async function askHostToHandOver() {
    try {
      await requestHandover({ runtimeRoot: binding.runtimeRoot, hostInstallationId: binding.hostInstallationId,
        publishedAt: new Date().toISOString(), waitMs: 0 });
    } catch {}
  }
  async function call(method, pathname, body = null, accepted = false, requestOptions = {}) {
    assertLive();
    try {
      const result = await callRaw(method, pathname, body, requestOptions);
      if (([HELLOLYNK_HOST_PATHS.appAuthorizedInboxPending,
        HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim].includes(pathname) || pathname.startsWith("/host/v1/app/authorized-inbox/batch/"))
        && (result?.body?.error === "host_route_not_found" || (result?.status === 404 && !result?.body?.error))) {
        await askHostToHandOver();
        throw codeError("host_native_inbox_upgrade_required");
      }
      return accepted ? requireAccepted(result) : requireOk(result);
    } catch (error) {
      if (isTerminalHostError(error)) {
        deadCode = safeCode(error);
        clearInterval(heartbeat);
      }
      throw error;
    }
  }
  async function readBundle() {
    const [inbox, unread, contacts, contactRequests, outbox, changes] = await Promise.all([
      call("GET", HELLOLYNK_HOST_PATHS.appInboxMessages),
      call("GET", HELLOLYNK_HOST_PATHS.appInboxUnreadCount),
      call("GET", HELLOLYNK_HOST_PATHS.appContacts),
      call("GET", HELLOLYNK_HOST_PATHS.appContactRequests),
      call("GET", HELLOLYNK_HOST_PATHS.appOutboxMessages),
      call("GET", HELLOLYNK_HOST_PATHS.appChangesSnapshot),
    ]);
    return projectWidgetBundle({ inbox, unread, contacts, contactRequests, outbox, changes });
  }
  async function close() {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    if (!deadCode) await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentDetach, { adapterInstanceId }).catch(() => {});
  }

  return Object.freeze({
    contract: HELLOLYNK_WORKBUDDY_NEUTRAL_ADAPTER_CONTRACT,
    mode: "neutral",
    startedHost,
    get state() { return closed ? "closed" : deadCode ? "dead" : "attached"; },
    async getNativeTaskScope() {
      assertLive();
      return Object.freeze({ runtimeRoot: binding.runtimeRoot, adapterId: "workbuddy", region: binding.region, principalId: binding.principalId, delegateId: binding.delegateId });
    },
    async hostStatus() {
      const value = await call("GET", HELLOLYNK_HOST_PATHS.status);
      if (value.status !== "running") throw codeError("neutral_host_not_running");
      return Object.freeze({ ok: true, configured: true, status: "attached", startedHost });
    },
    readBundle,
    async modelInbox(input) { return call("POST", HELLOLYNK_HOST_PATHS.appModelInbox, input); },
    async readUnreadCount() {
      return call("GET", HELLOLYNK_HOST_PATHS.appInboxUnreadCount);
    },
    async readWorkbenchChanges({ afterCursor = 0 } = {}) {
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appChangesSubscribe, { afterCursor }, false, { timeoutMs: 8_000 });
      return { ...result, hostGeneration: discovery.hostGeneration };
    },
    async readWorkbenchSnapshot(input = {}) {
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appWorkbenchSnapshot, input);
      return result.snapshot;
    },
    async issueWorkbenchActionGrant(command) {
      const validated = validateWorkbenchCommand(command);
      assertLive();
      try {
        return requireWorkbenchActionGrantResult(await callRaw(
          "POST",
          WORKBENCH_ACTION_GRANT_PATH,
          { adapterInstanceId, request: validated },
        ));
      } catch (error) {
        if (isTerminalHostError(error)) {
          deadCode = safeCode(error);
          clearInterval(heartbeat);
        }
        throw error;
      }
    },
    async executeWorkbenchCommand(command, context) {
      const validated = validateWorkbenchCommand(command);
      const statusRead = validated.command === "message.send-status";
      const actionGrant = statusRead ? noWorkbenchActionGrantContext(context) : requireWorkbenchActionGrantContext(context);
      assertLive();
      try {
        return requireWorkbenchCommandResult(await callRaw(
          "POST",
          HELLOLYNK_HOST_PATHS.appWorkbenchCommand,
          { adapterInstanceId, request: validated, ...(statusRead ? {} : { actionGrant }) },
          {},
        ), validated.command);
      } catch (error) {
        if (isTerminalHostError(error)) {
          deadCode = safeCode(error);
          clearInterval(heartbeat);
        }
        throw error;
      }
    },
    async markMessageRead(localMessageId) {
      await call("POST", HELLOLYNK_HOST_PATHS.appInboxMarkRead, { localMessageId: safeId(localMessageId, "local_message_id_invalid") });
      return readBundle();
    },
    async deleteRead(localMessageIds) {
      const ids = uniqueIds(localMessageIds, "local_message_ids_invalid", 500);
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appInboxDeleteRead, { localMessageIds: ids });
      return Object.freeze({ deletedCount: nonNegative(result.deletedCount), bundle: await readBundle() });
    },
    async saveContact(input) {
      await call("POST", HELLOLYNK_HOST_PATHS.appContactsUpsert, contactInput(input));
      return readBundle();
    },
    async deleteContact(contactId) {
      await call("POST", HELLOLYNK_HOST_PATHS.appContactsRemove, { contactId: safeId(contactId, "contact_id_invalid") });
      return readBundle();
    },
    async setAutonomousSendAuthorization(contactId, recipientDelegateId, enabled) {
      await call("POST", HELLOLYNK_HOST_PATHS.appContactAutonomousSendAuthorization, {
        contactId: safeId(contactId, "contact_id_invalid"),
        recipientDelegateId: safeId(recipientDelegateId, "recipient_delegate_id_invalid"),
        enabled: enabled === true,
      });
      return readBundle();
    },
    async listAuthorizedContacts(input = {}) {
      const query = queryArgs(input);
      const result = await call(Object.keys(query).length ? "POST" : "GET", HELLOLYNK_HOST_PATHS.appAuthorizedContacts, Object.keys(query).length ? query : undefined, false, { timeoutMs: 25_000 });
      return Object.freeze({ ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}), contacts: Object.freeze([...(result.contacts || [])]) });
    },
    async listPendingMessages(query = null) {
      assertLive();
      // Reuse only successful activation within this fixed Host connection.
      // Each pending GET still validates permission; failures may activate again.
      inboxActivation ??= call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxActivate)
        .then(activated => { if (activated.active !== true) throw codeError("host_app_response_invalid"); })
        .catch(error => { inboxActivation = null; throw error; });
      await inboxActivation;
      const result = await call(query == null ? "GET" : "POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxPending, query);
      if (!Array.isArray(result.messages)) throw codeError("host_app_response_invalid");
      return { messages: result.messages, ...(result.nextCursor == null ? {} : { nextCursor: result.nextCursor }) };
    },
    async claimMessage(localMessageId, conversationKey) {
      if (typeof localMessageId !== "string" || typeof conversationKey !== "string") throw codeError("invalid_params");
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim, {
        localMessageId: safeId(localMessageId, "local_message_id_invalid"),
        conversationKey: safeId(conversationKey, "conversation_key_invalid"),
      });
    },
    async claimBatch(batchId) {
      if (!/^inbatch_[a-f0-9]{48}$/.test(batchId || "")) throw codeError("invalid_params");
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim, { batchId });
    },
    async inboxBatch(operation, input = {}) {
      if (!["reserve", "open", "attempt", "confirm", "cancel", "expire", "closed"].includes(operation)) throw codeError("invalid_params");
      return call("POST", `/host/v1/app/authorized-inbox/batch/${operation}`, input);
    },
    async listAuthorizedInboxMessages({ before } = {}) {
      const result = before === undefined ? await call("GET", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages)
        : await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages, { before: safeId(before, "local_message_id_invalid") });
      return Object.freeze({ messages: Object.freeze([...(result.messages || [])]) });
    },
    async readAuthorizedInboxMessage(localMessageId, conversationKey) {
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxRead, {
        localMessageId: safeId(localMessageId, "local_message_id_invalid"),
        conversationKey: safeId(conversationKey, "conversation_key_invalid"),
      });
      return Object.freeze({ message: structuredClone(result.message) });
    },
    async listAuthorizedContactRequests() {
      const result = await call("GET", HELLOLYNK_HOST_PATHS.appAuthorizedContactRequests);
      return Object.freeze({ requests: Object.freeze([...(result.requests || [])]) });
    },
    async readAuthorizedContactRequest(localRecordId, conversationKey) {
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedContactRequestRead, { localRecordId: safeId(localRecordId, "local_record_id_invalid"), conversationKey: safeId(conversationKey, "conversation_key_invalid") });
      return Object.freeze({ request: structuredClone(result.request) });
    },
    async sendAuthorizedMessage(input) {
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedSend, authorizedSendInput(input));
    },
    async replyAuthorizedMessage(input) {
      if (!isPlainObject(input) || !exactKeys(input, ["localMessageId", "conversationKey", "clientMessageId", "text"])) throw codeError("invalid_params");
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedReply, {
        localMessageId: safeId(input.localMessageId, "local_message_id_invalid"),
        conversationKey: safeId(input.conversationKey, "conversation_key_invalid"),
        clientMessageId: safeId(input.clientMessageId, "client_message_id_invalid"),
        text: text(input.text, "message_text_invalid", 20_000, false, true),
      });
    },
    async issueRetryGrant(clientMessageId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetryGrant, {
        adapterInstanceId,
        clientMessageId: safeId(clientMessageId, "client_message_id_invalid"),
      });
    },
    async retryOutgoing(clientMessageId, retryGrant) {
      const result = await call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetry, {
        adapterInstanceId,
        clientMessageId: safeId(clientMessageId, "client_message_id_invalid"),
        retryGrant: String(retryGrant || ""),
      });
      return Object.freeze({ delivered: result.message?.status === "delivered_to_live_connection", bundle: await readBundle() });
    },
    async requestHumanSend(input) {
      return call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequests, {
        adapterInstanceId,
        request: humanSendInput(input),
      }, true);
    },
    async getHumanSendStatus(actionId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequestStatus, {
        adapterInstanceId,
        request: { actionId: safeId(actionId, "action_id_invalid") },
      });
    },
    async getHumanSendStatus(actionId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequestStatus, {
        adapterInstanceId,
        request: { actionId: safeId(actionId, "action_id_invalid") },
      });
    },
    close,
  });
}

export function validateWorkBuddyProtectedBinding(value) {
  if (!isPlainObject(value)) throw codeError("neutral_workbuddy_binding_invalid");
  const allowedBindingKeys = new Set([
    "adapterId", "capability", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version", "releaseRoot",
    "releaseManifestSha256", "runnerRelativePath", "profileManifestPath",
  ]);
  if (Object.keys(value).some((key) => !allowedBindingKeys.has(key))) throw codeError("neutral_workbuddy_binding_invalid");
  const scopes = canonicalScopes(value.scopes);
  if (value.contract !== HELLOLYNK_WORKBUDDY_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "workbuddy" || Number(value.version) !== 2
    || !sameStrings(scopes, WORKBUDDY_NEUTRAL_EXACT_SCOPES)) {
    throw codeError("neutral_workbuddy_binding_migration_required");
  }
  const capability = value.capability;
  if (!isPlainObject(capability)) throw codeError("neutral_workbuddy_capability_invalid");
  const capabilityKeys = [
    "adapterId", "capabilityId", "contract", "delegateId", "hostInstallationId", "issuedAt",
    "principalId", "region", "revokedAt", "scopes", "secretBuffer", "state", "version",
  ].sort();
  if (!sameStrings(Object.keys(capability).sort(), capabilityKeys)) {
    throw codeError("neutral_workbuddy_capability_invalid");
  }
  const capabilityScopes = canonicalScopes(capability.scopes);
  const binding = {
    contract: value.contract,
    region: safeId(value.region, "neutral_workbuddy_binding_invalid"),
    principalId: safeId(value.principalId, "neutral_workbuddy_binding_invalid"),
    delegateId: safeId(value.delegateId, "neutral_workbuddy_binding_invalid"),
    hostInstallationId: safeId(value.hostInstallationId, "neutral_workbuddy_binding_invalid"),
    profileId: safeId(value.profileId, "neutral_workbuddy_binding_invalid"),
    adapterId: "workbuddy", version: 2, scopes: Object.freeze(scopes),
    runtimeRoot: absolutePath(value.runtimeRoot, "neutral_workbuddy_binding_invalid"),
  };
  if (capability.contract !== HELLOLYNK_HOST_CAPABILITY_CONTRACT
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "workbuddy" || Number(capability.version) !== 2
    || capability.state !== "active" || capability.revokedAt !== null
    || !sameStrings(capabilityScopes, WORKBUDDY_NEUTRAL_EXACT_SCOPES)) {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
  const secretBuffer = Buffer.isBuffer(capability.secretBuffer)
    ? Buffer.from(capability.secretBuffer)
    : capability.secretBuffer instanceof Uint8Array ? Buffer.from(capability.secretBuffer) : null;
  if (!secretBuffer || secretBuffer.length < 32 || secretBuffer.length > 128) {
    throw codeError("neutral_workbuddy_capability_secret_invalid");
  }
  const releaseKeys = ["releaseRoot", "releaseManifestSha256", "runnerRelativePath", "profileManifestPath"];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value, key)).length;
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) throw codeError("neutral_workbuddy_launch_configuration_invalid");
  return Object.freeze({
    ...binding,
    ...(releaseCount === 0 ? {} : {
      releaseRoot: absolutePath(value.releaseRoot, "neutral_workbuddy_launch_configuration_invalid"),
      releaseManifestSha256: hash(value.releaseManifestSha256, "neutral_workbuddy_launch_configuration_invalid"),
      runnerRelativePath: value.runnerRelativePath === "runtime/neutral-host-bootstrap.mjs"
        ? value.runnerRelativePath : fail("neutral_workbuddy_launch_configuration_invalid"),
      profileManifestPath: absolutePath(value.profileManifestPath, "neutral_workbuddy_launch_configuration_invalid"),
    }),
    capability: Object.freeze({
      contract: HELLOLYNK_HOST_CAPABILITY_CONTRACT,
      capabilityId: safeId(capability.capabilityId, "neutral_workbuddy_capability_invalid"),
      region: binding.region, principalId: binding.principalId, delegateId: binding.delegateId,
      hostInstallationId: binding.hostInstallationId, adapterId: "workbuddy", version: 2,
      state: "active", scopes: Object.freeze(capabilityScopes), issuedAt: nonNegative(capability.issuedAt),
      revokedAt: null, secretBuffer,
    }),
  });
}

function publicBinding(value) {
  return Object.freeze({ region: value.region, principalId: value.principalId, hostInstallationId: value.hostInstallationId, runtimeRoot: value.runtimeRoot });
}
function launchBinding(value) {
  return Object.freeze({
    ...publicBinding(value), delegateId: value.delegateId, profileId: value.profileId,
    adapterId: "workbuddy", version: 2, scopes: Object.freeze([...value.scopes]),
    ...(value.releaseRoot ? {
      releaseRoot: value.releaseRoot, releaseManifestSha256: value.releaseManifestSha256,
      runnerRelativePath: value.runnerRelativePath, profileManifestPath: value.profileManifestPath,
    } : {}),
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
async function safeDiscover(discover, input) {
  try { return await discover(input); }
  catch (error) { if (SAFE_DISCOVERY_ERRORS.has(error?.code)) return null; throw error; }
}
async function waitForDiscovery(discover, input, options) {
  const wait = options.wait || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const timeoutMs = integer(options.discoveryWaitMs, 75_000, 10, 120_000);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await safeDiscover(discover, input);
    if (value) return value;
    await wait(Math.min(50, Math.max(1, deadline - Date.now())));
  }
  return null;
}
function assertDiscovery(value, binding) {
  if (!isPlainObject(value) || value.contractId !== "hellolynk-neutral-host-discovery-v1"
    || value.region !== binding.region || value.principalId !== binding.principalId
    || value.hostInstallationId !== binding.hostInstallationId || value.host !== "127.0.0.1"
    || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65_535
    || !/^[a-f0-9]{48}$/.test(String(value.hostGeneration || ""))) {
    throw codeError("neutral_host_discovery_owner_mismatch");
  }
}

function projectWidgetBundle(value) {
  const inbox = array(value.inbox?.messages).map((item) => pick(item, [
    "localMessageId", "clientMessageId", "peerPrincipalId", "peerHelloLynkId", "senderDelegateId",
    "senderPrincipalDisplayName", "senderDelegateDisplayName", "messageType", "text", "unread", "createdAt", "updatedAt",
  ]));
  const contacts = array(value.contacts?.contacts).map((item) => pick(item, [
    "contactId", "hellolynkId", "displayName", "autonomousSendAuthorized", "createdAt", "updatedAt",
  ]));
  const contactRequests = array(value.contactRequests?.requests).map((item) => pick(item, [
    "actionReady", "humanOnly", "introText", "introWeight", "localRecordId", "modelVisibility",
    "receivedAt", "sender", "serverContactRequestId", "serverUpdatedAt", "state",
  ]));
  const outbox = array(value.outbox?.messages).map((item) => pick(item, [
    "localMessageId", "clientMessageId", "recipientHelloLynkId", "messageType", "text", "textSha256",
    "status", "retryAllowed", "createdAt", "updatedAt",
  ]));
  return Object.freeze({
    contract: "hellolynk-workbuddy-widget-bundle-v1", status: "running",
    counts: Object.freeze({
      inbox: inbox.length, unread: nonNegative(value.unread?.unreadCount), contacts: contacts.length,
      contactRequests: contactRequests.length,
      pendingContactRequests: contactRequests.filter((item) => item.state === "pending").length,
      outbox: outbox.length, failedOutbox: outbox.filter((item) => item.retryAllowed === true).length,
    }),
    inbox: Object.freeze(inbox), contacts: Object.freeze(contacts),
    contactRequests: Object.freeze(contactRequests), outbox: Object.freeze(outbox),
    changeCursor: Number.isSafeInteger(value.changes?.cursor) ? value.changes.cursor : 0,
  });
}

function contactInput(value) {
  if (!isPlainObject(value)
    || !exactKeys(value, value.contactId == null
      ? ["hellolynkId", "displayName"]
      : ["contactId", "hellolynkId", "displayName"])) {
    throw codeError("contact_input_invalid");
  }
  const result = {
    hellolynkId: text(value.hellolynkId, "contact_hellolynk_id_invalid", 200),
    displayName: text(value.displayName, "contact_display_name_invalid", 160),
  };
  if (value.contactId != null) result.contactId = safeId(value.contactId, "contact_id_invalid");
  return result;
}
function humanSendInput(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["clientMessageId", "recipientHelloLynkId", "recipientDelegateId", "text"])) throw codeError("human_send_input_invalid");
  const recipientHelloLynkId = String(value.recipientHelloLynkId || "");
  if (!/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(recipientHelloLynkId)) throw codeError("recipient_invalid");
  const messageText = text(value.text, "message_text_invalid", 20_000, false, true);
  if (Buffer.byteLength(messageText, "utf8") > 20 * 1024) throw codeError("message_text_invalid");
  return {
    clientMessageId: safeId(value.clientMessageId, "client_message_id_invalid"), recipientHelloLynkId,
    recipientDelegateId: safeId(value.recipientDelegateId, "recipient_delegate_id_invalid"),
    text: messageText,
  };
}
function authorizedSendInput(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["clientMessageId", "contactId", "recipientDelegateId", "text", ...Object.keys(optionalTarget(value))])) {
    throw codeError("authorized_send_input_invalid");
  }
  const messageText = text(value.text, "message_text_invalid", 20_000, false, true);
  if (Buffer.byteLength(messageText, "utf8") > 20 * 1024) throw codeError("message_text_invalid");
  return {
    ...optionalTarget(value),
    clientMessageId: safeId(value.clientMessageId, "client_message_id_invalid"),
    contactId: safeId(value.contactId, "contact_id_invalid"),
    recipientDelegateId: safeId(value.recipientDelegateId, "recipient_delegate_id_invalid"),
    text: messageText,
  };
}
function requireOk(result) {
  if (!result || result.status !== 200 || result.body?.ok !== true) throw codeError(publicHostCode(result));
  return result.body;
}
function requireWorkbenchCommandResult(result, expectedCommand) {
  if (!result || result.status !== 200) throw codeError(publicHostCode(result));
  try {
    return validateWorkbenchCommandResult(result.body, expectedCommand);
  } catch {
    throw codeError("neutral_host_workbench_command_response_invalid");
  }
}
function requireWorkbenchActionGrantResult(result) {
  if (!result || result.status !== 200 || !isPlainObject(result.body)) {
    throw codeError(publicHostCode(result));
  }
  if (!exactKeys(result.body, ["ok", "actionGrant", "expiresAtMs"])
    || result.body.ok !== true || typeof result.body.actionGrant !== "string"
    || !ACTION_GRANT.test(result.body.actionGrant)
    || !Number.isSafeInteger(result.body.expiresAtMs) || result.body.expiresAtMs <= Date.now()) {
    throw codeError("neutral_host_workbench_action_grant_response_invalid");
  }
  return Object.freeze({ actionGrant: result.body.actionGrant });
}
function requireWorkbenchActionGrantContext(value) {
  if (!isPlainObject(value) || !exactKeys(value, ["actionGrant"])
    || typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError("neutral_host_workbench_action_grant_required");
  }
  return value.actionGrant;
}

function noWorkbenchActionGrantContext(value) {
  if (value != null && (!isPlainObject(value) || Object.keys(value).length !== 0)) {
    throw codeError("neutral_host_workbench_action_grant_forbidden");
  }
  return null;
}
function requireAccepted(result) {
  if (!result || result.status !== 202 || result.body?.ok !== true) throw codeError(publicHostCode(result));
  return result.body;
}
function publicHostCode(result) {
  const value = String(result?.body?.error || `neutral_host_http_${result?.status || 0}`);
  return /^[a-z][a-z0-9_]{1,127}$/.test(value) ? value : "neutral_host_operation_failed";
}
function isTerminalHostError(error) {
  const code = safeCode(error);
  if (NON_TERMINAL_HOST_APP_ERRORS.has(code)) return false;
  return error instanceof TypeError || code.startsWith("neutral_host_") || code.startsWith("host_");
}
function safeCode(error) {
  const value = String(error?.code || error?.message || "neutral_host_request_failed")
    .replace(/[^A-Za-z0-9._:-]+/g, "_").slice(0, 120);
  return value || "neutral_host_request_failed";
}
function pick(value, keys) {
  if (!isPlainObject(value)) throw codeError("neutral_host_response_invalid");
  return Object.freeze(Object.fromEntries(
    keys.filter((key) => Object.hasOwn(value, key)).map((key) => [key, structuredClone(value[key])]),
  ));
}
function array(value) { if (!Array.isArray(value)) throw codeError("neutral_host_response_invalid"); return value; }
function uniqueIds(value, code, maximum) {
  if (!Array.isArray(value) || value.length < 1 || value.length > maximum) throw codeError(code);
  const ids = value.map((item) => safeId(item, code));
  if (new Set(ids).size !== ids.length) throw codeError(code);
  return ids;
}
function text(value, code, maximum, empty = false, countCodePoints = false) {
  const result = String(value ?? "");
  if ((!empty && !result) || (countCodePoints ? Array.from(result).length : result.length) > maximum || Buffer.byteLength(result, "utf8") > maximum * 4 || /[\u0000]/.test(result)) throw codeError(code);
  return result;
}
function canonicalScopes(value) {
  if (!Array.isArray(value)) throw codeError("neutral_workbuddy_capability_scopes_mismatch");
  const scopes = [...new Set(value.map(String))].sort();
  if (scopes.length !== value.length) throw codeError("neutral_workbuddy_capability_scopes_mismatch");
  return scopes;
}
function sameStrings(left, right) { return left.length === right.length && left.every((item, index) => item === right[index]); }
function exactKeys(value, expected) {
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}
function safeId(value, code) { const result = String(value || ""); if (!SAFE_ID.test(result)) throw codeError(code); return result; }
function nonNegative(value) { const result = Number(value); if (!Number.isSafeInteger(result) || result < 0) throw codeError("neutral_host_response_invalid"); return result; }
function absolutePath(value, code) { const result = String(value || ""); if (!path.isAbsolute(result) || path.resolve(result) !== result) throw codeError(code); return result; }
function hash(value, code) { const result = String(value || ""); if (!/^[a-f0-9]{64}$/.test(result)) throw codeError(code); return result; }
function integer(value, fallback, minimum, maximum) { const result = Number(value ?? fallback); if (!Number.isSafeInteger(result) || result < minimum || result > maximum) throw codeError("neutral_limit_invalid"); return result; }
function isPlainObject(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function fail(code) { throw codeError(code); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
