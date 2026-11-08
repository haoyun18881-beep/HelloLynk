import { queryArgs, optionalTarget } from "../../../runtime/core/hellolynk-native-addressing-tools.cjs";
import { captureHelloLynkModelNotices } from "../../../runtime/core/hellolynk-model-notices.cjs";
import crypto from "node:crypto";
import path from "node:path";
import { HELLOLYNK_HOST_CAPABILITY_CONTRACT } from "../../../runtime/core/hellolynk-host-auth.mjs";
import {
  createHostProtectedStore,
} from "../../../runtime/core/hellolynk-host-protected-store.mjs";
import {
  discoverHelloLynkNeutralHost,
  HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT,
  requestHelloLynkNeutralHost,
  requestHelloLynkNeutralHostHandover,
} from "../../../runtime/core/hellolynk-neutral-host-process.mjs";
import { HELLOLYNK_HOST_PATHS } from "../../../runtime/core/hellolynk-host.mjs";
import {
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
} from "../../../runtime/workbench/contract.mjs";

export const HELLOLYNK_TRAE_WORK_NEUTRAL_ADAPTER_CONTRACT = "hellolynk-trae-work-neutral-adapter-v2";
export const TRAE_WORK_HEARTBEAT_MS = 10_000;
export const TRAE_WORK_NEUTRAL_EXACT_SCOPES = Object.freeze([
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
]);

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;
const FROZEN_WORKBENCH_ACTION_GRANT_PATH = "/host/v1/app/workbench/action-grants";
if (HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant !== undefined
  && HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant !== FROZEN_WORKBENCH_ACTION_GRANT_PATH) {
  fail("neutral_host_workbench_action_grant_path_mismatch");
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

export function createTraeWorkProtectedBindingProvider(options = {}) {
  const store = options.protectedStore || createHostProtectedStore({
    ...(options.storeRoot ? { root: options.storeRoot } : {}),
    ...(options.installationStore ? { installationStore: options.installationStore } : {}),
  });
  return () => store.resolveTraeWorkNeutralBinding(options.bindingQuery || {});
}

export async function createTraeWorkNeutralHostAdapter(options = {}) {
  return createRestrictedNeutralHostAdapter({
    ...options,
    adapterContract: HELLOLYNK_TRAE_WORK_NEUTRAL_ADAPTER_CONTRACT,
    adapterInstancePrefix: "trae-work",
    validateBinding: validateTraeWorkProtectedBinding,
  });
}

export async function createRestrictedNeutralHostAdapter(options = {}) {
  if (typeof options.capabilityProvider !== "function") {
    throw codeError("neutral_capability_provider_required");
  }
  if (typeof options.validateBinding !== "function") {
    throw codeError("neutral_capability_binding_validator_required");
  }
  const adapterContract = safeId(options.adapterContract, "neutral_adapter_contract_invalid");
  const adapterInstancePrefix = safeId(options.adapterInstancePrefix, "neutral_adapter_prefix_invalid");
  const binding = options.validateBinding(await options.capabilityProvider());
  const discover = options.discoverHost || discoverHelloLynkNeutralHost;
  const request = options.requestHost || requestHelloLynkNeutralHost;
  const requestHandover = options.requestHostHandover || requestHelloLynkNeutralHostHandover;
  const discoveryInput = publicBinding(binding);
  let discovery = await safeDiscover(discover, discoveryInput);
  // A Host of an earlier release is asked to make room, and this client's release starts in its place.
  if (discovery && typeof options.hostLauncher === "function"
    && await earlierHostLeft(requestHandover, binding, integer(options.handoverWaitMs, 5_000, 0, 30_000))) {
    discovery = await safeDiscover(discover, discoveryInput);
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
    discovery = await waitForDiscovery(discover, discoveryInput, options);
    if (!discovery && superseded) throw codeError(RELEASE_SUPERSEDED);
  }
  if (!discovery) throw codeError("neutral_host_not_found");
  assertDiscovery(discovery, binding);

  const adapterInstanceId = safeId(
    options.adapterInstanceId || `${adapterInstancePrefix}-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
    "neutral_host_adapter_instance_invalid",
  );
  const callRaw = async (method, pathname, body = null, requestOptions = {}) => captureHelloLynkModelNotices(await request({
    discovery,
    capability: binding.capability,
    method,
    pathname,
    body,
    ...requestOptions,
  }));
  await requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentAttach, { adapterInstanceId }));

  let closed = false;
  let deadCode = null;
  let inboxActivation = null;
  let heartbeatBusy = false;
  const heartbeatMs = integer(options.heartbeatMs, TRAE_WORK_HEARTBEAT_MS, 10, 30_000);
  const heartbeat = setInterval(async () => {
    if (closed || deadCode || heartbeatBusy) return;
    heartbeatBusy = true;
    try {
      await requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentHeartbeat, { adapterInstanceId }));
    } catch {
      deadCode = "neutral_host_heartbeat_failed";
      clearInterval(heartbeat);
    } finally {
      heartbeatBusy = false;
    }
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

  async function close() {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    if (!deadCode) {
      await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentDetach, { adapterInstanceId }).catch(() => {});
    }
  }

  return Object.freeze({
    contract: adapterContract,
    mode: "neutral",
    startedHost,
    get state() { return closed ? "closed" : deadCode ? "dead" : "attached"; },
    async getNativeTaskScope() {
      assertLive();
      return Object.freeze({ runtimeRoot: binding.runtimeRoot, adapterId: binding.adapterId,
        region: binding.region, principalId: binding.principalId, delegateId: binding.delegateId });
    },
    async hostStatus() {
      const result = await call("GET", HELLOLYNK_HOST_PATHS.status);
      if (result.status !== "running") throw codeError("neutral_host_not_running");
      return Object.freeze({ ok: true, configured: true, status: "attached" });
    },
    async requestHumanSend(input) {
      return call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequests, { adapterInstanceId, request: input }, true);
    },
    async getHumanSendStatus(actionId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequestStatus, {
        adapterInstanceId,
        request: { actionId },
      });
    },
    async readInbox() {
      return call("GET", HELLOLYNK_HOST_PATHS.appInboxMessages);
    },
    async modelInbox(input) { return call("POST", HELLOLYNK_HOST_PATHS.appModelInbox, input); },
    async readUnreadCount() {
      return call("GET", HELLOLYNK_HOST_PATHS.appInboxUnreadCount);
    },
    async markInboxMessageRead(localMessageId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appInboxMarkRead, { localMessageId });
    },
    async deleteReadInboxMessages(localMessageIds) {
      return call("POST", HELLOLYNK_HOST_PATHS.appInboxDeleteRead, { localMessageIds });
    },
    async listContacts() {
      return projectContactsResponse(await call("GET", HELLOLYNK_HOST_PATHS.appContacts));
    },
    async saveContact(input) {
      return projectContactMutationResponse(await call(
        "POST",
        HELLOLYNK_HOST_PATHS.appContactsUpsert,
        contactWriteInput(input),
      ));
    },
    async deleteContact(contactId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appContactsRemove, { contactId });
    },
    async setAutonomousSendAuthorization(contactId, recipientDelegateId, enabled) {
      return projectContactMutationResponse(await call("POST", HELLOLYNK_HOST_PATHS.appContactAutonomousSendAuthorization, {
        contactId,
        recipientDelegateId: safeId(recipientDelegateId, "recipient_delegate_id_invalid"),
        enabled: enabled === true,
      }));
    },
    async listAuthorizedContacts(input = {}) {
      const query = queryArgs(input);
      const value = await call(Object.keys(query).length ? "POST" : "GET", HELLOLYNK_HOST_PATHS.appAuthorizedContacts, Object.keys(query).length ? query : undefined, false, { timeoutMs: 25_000 });
      return Object.freeze({
        ...(value.nativeConversations ? { nativeConversations: value.nativeConversations } : {}),
        contacts: Object.freeze((Array.isArray(value?.contacts) ? value.contacts : [])
          .map((contact) => projectContact(contact, ["contactId", "displayName", "recipientDelegateId", "instanceDisplayName"]))),
      });
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
      return before === undefined ? call("GET", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages)
        : call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages, { before: safeId(before, "local_message_id_invalid") });
    },
    async readAuthorizedInboxMessage(localMessageId, conversationKey) {
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxRead, {
        localMessageId: safeId(localMessageId, "local_message_id_invalid"),
        conversationKey: safeId(conversationKey, "conversation_key_invalid"),
      });
    },
    async listAuthorizedContactRequests() { return call("GET", HELLOLYNK_HOST_PATHS.appAuthorizedContactRequests); },
    async readAuthorizedContactRequest(localRecordId, conversationKey) {
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedContactRequestRead, { localRecordId: safeId(localRecordId, "local_record_id_invalid"), conversationKey: safeId(conversationKey, "conversation_key_invalid") });
    },
    async sendAuthorizedMessage(input) {
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedSend, authorizedSendInput(input));
    },
    async replyAuthorizedMessage(input) {
      return call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedReply, authorizedReplyInput(input));
    },
    async listContactRequests() {
      return call("GET", HELLOLYNK_HOST_PATHS.appContactRequests);
    },
    async readOutbox() {
      return call("GET", HELLOLYNK_HOST_PATHS.appOutboxMessages);
    },
    async issueOutboxRetryGrant(clientMessageId) {
      return call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetryGrant, { adapterInstanceId, clientMessageId });
    },
    async retryOutboxMessage(clientMessageId, retryGrant) {
      return call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetry, { adapterInstanceId, clientMessageId, retryGrant });
    },
    async readChangesSnapshot() {
      return call("GET", HELLOLYNK_HOST_PATHS.appChangesSnapshot);
    },
    async readWorkbenchChanges({ afterCursor = 0 } = {}) {
      assertLive();
      const result = requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.appChangesSubscribe, { afterCursor }, { timeoutMs: 8_000 }));
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
    close,
  });
}

export function validateTraeWorkProtectedBinding(value) {
  return validateRestrictedProtectedBinding(value, {
    adapterId: "trae-work",
    bindingContract: "hellolynk-trae-work-neutral-binding-v1",
    exactScopes: TRAE_WORK_NEUTRAL_EXACT_SCOPES,
  });
}

export function validateRestrictedProtectedBinding(value, policy = {}) {
  const adapterId = safeId(policy.adapterId, "neutral_adapter_mismatch");
  const bindingContract = safeId(policy.bindingContract, "neutral_capability_binding_invalid");
  const exactScopes = Object.freeze([...(policy.exactScopes || [])].map(String).sort());
  if (!exactScopes.length || !sameStrings(exactScopes, policy.exactScopes || [])) {
    throw codeError("neutral_capability_scopes_mismatch");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("neutral_capability_binding_invalid");
  }
  const releaseKeys = ["releaseRoot", "releaseManifestSha256", "runnerRelativePath", "profileManifestPath"];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value, key)).length;
  assertExactKeys(value, [
    "adapterId", "capability", "contract", "delegateId", "hostInstallationId",
    "principalId", "profileId", "region", "runtimeRoot", "scopes", "version",
    ...(releaseCount ? releaseKeys : []),
  ], "neutral_capability_binding_invalid");
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) {
    throw codeError("neutral_trae_work_launch_configuration_invalid");
  }
  const capability = value.capability;
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw codeError("neutral_capability_invalid");
  }
  assertExactKeys(capability, [
    "adapterId", "capabilityId", "contract", "delegateId", "hostInstallationId",
    "issuedAt", "principalId", "region", "revokedAt", "scopes", "secretBuffer", "state", "version",
  ], "neutral_capability_invalid");
  const binding = {
    region: safeId(value.region, "neutral_region_invalid"),
    principalId: safeId(value.principalId, "neutral_principal_invalid"),
    delegateId: safeId(value.delegateId, "neutral_delegate_invalid"),
    hostInstallationId: safeId(value.hostInstallationId, "neutral_host_installation_invalid"),
    profileId: safeId(value.profileId, "neutral_profile_invalid"),
    adapterId: safeId(value.adapterId, "neutral_adapter_invalid"),
    runtimeRoot: String(value.runtimeRoot || ""),
  };
  const bindingScopes = [...new Set((value.scopes || []).map(String))].sort();
  if (value.contract !== bindingContract || Number(value.version) !== 2
    || !sameStrings(bindingScopes, exactScopes)) {
    throw codeError("neutral_capability_binding_invalid");
  }
  if (binding.adapterId !== adapterId) throw codeError("neutral_adapter_mismatch");
  if (!binding.runtimeRoot || !path.isAbsolute(binding.runtimeRoot)
    || path.resolve(binding.runtimeRoot) !== binding.runtimeRoot) {
    throw codeError("neutral_runtime_root_invalid");
  }
  if (capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== binding.adapterId) {
    throw codeError("neutral_capability_owner_mismatch");
  }
  const scopes = [...new Set((capability.scopes || []).map(String))].sort();
  if (!sameStrings(scopes, exactScopes)) {
    throw codeError("neutral_capability_scopes_mismatch");
  }
  const secretBuffer = Buffer.isBuffer(capability.secretBuffer)
    ? Buffer.from(capability.secretBuffer)
    : capability.secretBuffer instanceof Uint8Array ? Buffer.from(capability.secretBuffer) : null;
  if (!secretBuffer || secretBuffer.length < 32 || secretBuffer.length > 128) {
    throw codeError("neutral_capability_secret_invalid");
  }
  if (Number(capability.version) !== 2) throw codeError("neutral_capability_version_mismatch");
  if (capability.state !== "active") throw codeError("neutral_capability_inactive");
  if (capability.contract !== HELLOLYNK_HOST_CAPABILITY_CONTRACT || capability.revokedAt !== null) {
    throw codeError("neutral_capability_binding_invalid");
  }
  return Object.freeze({
    ...binding,
    scopes: Object.freeze(bindingScopes),
    ...(releaseCount === 0 ? {} : {
      releaseRoot: absolutePath(value.releaseRoot, "neutral_trae_work_launch_configuration_invalid"),
      releaseManifestSha256: sha256(value.releaseManifestSha256, "neutral_trae_work_launch_configuration_invalid"),
      runnerRelativePath: value.runnerRelativePath === "runtime/neutral-host-bootstrap.mjs"
        ? value.runnerRelativePath : fail("neutral_trae_work_launch_configuration_invalid"),
      profileManifestPath: absolutePath(value.profileManifestPath, "neutral_trae_work_launch_configuration_invalid"),
    }),
    capability: Object.freeze({
      contract: HELLOLYNK_HOST_CAPABILITY_CONTRACT,
      capabilityId: safeId(capability.capabilityId, "neutral_capability_id_invalid"),
      region: binding.region,
      principalId: binding.principalId,
      delegateId: binding.delegateId,
      hostInstallationId: binding.hostInstallationId,
      adapterId,
      version: 2,
      state: "active",
      scopes: Object.freeze(scopes),
      issuedAt: integer(capability.issuedAt, undefined, 0, Number.MAX_SAFE_INTEGER),
      revokedAt: null,
      secretBuffer,
    }),
  });
}

function publicBinding(value) {
  return {
    region: value.region,
    principalId: value.principalId,
    hostInstallationId: value.hostInstallationId,
    runtimeRoot: value.runtimeRoot,
  };
}

function launchBinding(value) {
  return Object.freeze({
    ...publicBinding(value), delegateId: value.delegateId, profileId: value.profileId,
    adapterId: "trae-work", version: 2, scopes: Object.freeze([...value.scopes]),
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
  const timeoutMs = integer(options.discoveryWaitMs, 120_000, 10, 120_000);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await safeDiscover(discover, input);
    if (value) return value;
    await wait(Math.min(50, Math.max(1, deadline - Date.now())));
  }
  return null;
}

function assertDiscovery(value, binding) {
  if (!value || value.contractId !== HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT
    || value.region !== binding.region || value.principalId !== binding.principalId
    || value.hostInstallationId !== binding.hostInstallationId || value.host !== "127.0.0.1"
    || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65_535
    || !/^[a-f0-9]{48}$/.test(String(value.hostGeneration || ""))) {
    throw codeError("neutral_host_discovery_owner_mismatch");
  }
}

function requireOk(result) {
  if (!result || result.status !== 200 || result.body?.ok !== true) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return result.body;
}

function requireWorkbenchCommandResult(result, expectedCommand) {
  if (!result || result.status !== 200) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  try {
    return validateWorkbenchCommandResult(result.body, expectedCommand);
  } catch {
    throw codeError("neutral_host_workbench_command_response_invalid");
  }
}

function requireWorkbenchActionGrantResult(result) {
  if (!result || result.status !== 200 || !result.body || typeof result.body !== "object"
    || Array.isArray(result.body)) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  assertExactKeys(
    result.body,
    ["ok", "actionGrant", "expiresAtMs"],
    "neutral_host_workbench_action_grant_response_invalid",
  );
  if (result.body.ok !== true || typeof result.body.actionGrant !== "string"
    || !ACTION_GRANT.test(result.body.actionGrant)
    || !Number.isSafeInteger(result.body.expiresAtMs) || result.body.expiresAtMs <= Date.now()) {
    throw codeError("neutral_host_workbench_action_grant_response_invalid");
  }
  return Object.freeze({ actionGrant: result.body.actionGrant });
}

function requireWorkbenchActionGrantContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw codeError("neutral_host_workbench_action_grant_required");
  }
  assertExactKeys(value, ["actionGrant"], "neutral_host_workbench_action_grant_required");
  if (typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError("neutral_host_workbench_action_grant_required");
  }
  return value.actionGrant;
}

function requireAccepted(result) {
  if (!result || result.status !== 202 || result.body?.ok !== true) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return result.body;
}

function isTerminalHostError(error) {
  const code = safeCode(error);
  if (NON_TERMINAL_HOST_APP_ERRORS.has(code)) return false;
  return code.startsWith("neutral_host_") || code.startsWith("host_");
}

function noWorkbenchActionGrantContext(value) {
  if (value != null && (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== 0)) {
    throw codeError("neutral_host_workbench_action_grant_forbidden");
  }
  return null;
}

function safeId(value, code) {
  const text = String(value || "");
  if (!SAFE_ID.test(text)) throw codeError(code);
  return text;
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
    clientMessageId: safeId(value.clientMessageId, "client_message_id_invalid"),
    contactId: safeId(value.contactId, "contact_id_invalid"),
    recipientDelegateId: safeId(value.recipientDelegateId, "recipient_delegate_id_invalid"),
    text,
  };
}

function authorizedReplyInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join("|") !== "clientMessageId|conversationKey|localMessageId|text"
    || [value.localMessageId, value.conversationKey, value.clientMessageId, value.text].some((item) => typeof item !== "string")) {
    throw codeError("authorized_reply_input_invalid");
  }
  const text = value.text;
  if (!text || text.includes("\u0000") || Buffer.byteLength(text, "utf8") > 20 * 1024) {
    throw codeError("message_text_invalid");
  }
  return {
    localMessageId: safeId(value.localMessageId, "local_message_id_invalid"),
    conversationKey: safeId(value.conversationKey, "conversation_key_invalid"),
    clientMessageId: safeId(value.clientMessageId, "client_message_id_invalid"),
    text,
  };
}

function contactWriteInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("contact_input_invalid");
  }
  const expected = value.contactId == null
    ? ["displayName", "hellolynkId"]
    : ["contactId", "displayName", "hellolynkId"];
  assertExactKeys(value, expected, "contact_input_invalid");
  return {
    ...(value.contactId == null ? {} : { contactId: safeId(value.contactId, "contact_id_invalid") }),
    hellolynkId: String(value.hellolynkId || ""),
    displayName: String(value.displayName || ""),
  };
}

function projectContactsResponse(value) {
  if (!Array.isArray(value?.contacts)) throw codeError("neutral_host_response_invalid");
  return Object.freeze({
    contacts: Object.freeze(value.contacts.map((contact) => projectContact(contact, [
      "contactId", "hellolynkId", "displayName",
      "autonomousSendAuthorized", "createdAt", "updatedAt",
    ]))),
  });
}

function projectContactMutationResponse(value) {
  if (!value?.contact || typeof value.contact !== "object" || Array.isArray(value.contact)) {
    throw codeError("neutral_host_response_invalid");
  }
  return Object.freeze({
    contact: projectContact(value.contact, [
      "contactId", "hellolynkId", "displayName",
      "autonomousSendAuthorized", "createdAt", "updatedAt",
    ]),
  });
}

function projectContact(value, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("neutral_host_response_invalid");
  }
  const result = {};
  for (const key of allowed) if (Object.hasOwn(value, key)) result[key] = structuredClone(value[key]);
  return Object.freeze(result);
}

function absolutePath(value, code) {
  const text = String(value || "");
  if (!path.isAbsolute(text) || path.resolve(text) !== text) throw codeError(code);
  return text;
}

function sha256(value, code) {
  const text = String(value || "");
  if (!/^[a-f0-9]{64}$/.test(text)) throw codeError(code);
  return text;
}

function integer(value, fallback, minimum, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw codeError("neutral_limit_invalid");
  }
  return number;
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function assertExactKeys(value, expected, code) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError(code);
  }
}

function safeCode(error) {
  return String(error?.code || error?.message || "neutral_host_unavailable")
    .replace(/[^A-Za-z0-9._:-]+/g, "_").slice(0, 120) || "neutral_host_unavailable";
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
function fail(code) { throw codeError(code); }
