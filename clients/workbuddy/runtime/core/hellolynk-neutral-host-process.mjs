import { nativeConversationId, nativeConversationQuery, nativeDirectoryResult, queryLocalNativeConversations } from "./hellolynk-native-conversations.mjs";
import { DIRECT_TEXT_E2EE_MAX_TTL_MS } from "./hellolynk-direct-text-e2ee.mjs";
import { runModelInbox } from "./hellolynk-model-inbox.mjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { withLocalProcessLock, inspectProcessIdentity } from "./hellolynk-local-process-lock.mjs";
import {
  createHostRequestAuth,
  createHostNonce,
} from "./hellolynk-host-auth.mjs";
import {
  createHelloLynkHostCore,
  HELLOLYNK_HOST_PATHS,
} from "./hellolynk-host.mjs";
import { createNeutralHostWorkbenchReadModel } from "./hellolynk-neutral-host-workbench-read-model.mjs";
import {
  deriveInstanceConversationBinding,
  getMessageConversationBinding,
  getOutgoingConversationIntent,
  instanceConversationKey,
} from "./hellolynk-instance-conversation.mjs";
import {
  HELLOLYNK_WORKBENCH_CAPABILITIES,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES,
  HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  validateWorkbenchSnapshot,
} from "../workbench/contract.mjs";
import { createHelloLynkWorkbenchService } from "../workbench/service.mjs";

export const HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT = "hellolynk-neutral-host-process-v1";
export const HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT = "hellolynk-neutral-host-discovery-v1";
// Raised with every release batch, together with the six client versions. A Host reports it
// in its health; the higher release stays and the lower one makes room.
export const HELLOLYNK_HOST_RELEASE_ORDINAL = 10;

const INSTALLATION_LOCK_CONTRACT = "hellolynk-neutral-host-installation-lock-v2";
const INSTALLATION_LOCK_MAX_BYTES = 4 * 1024;
const INSTALLATION_LOCK_STARTUP_GRACE_MS = 30_000;
const PROCESS_START_REUSE_TOLERANCE_MS = 2_000;
// An installer that has published new bindings asks a Host of a lower release
// to make room; the Host leaves through its normal drain once nothing is in flight.
const HANDOVER_REQUEST_CONTRACT = "hellolynk-neutral-host-handover-request-v1";
const HANDOVER_REQUEST_MAX_BYTES = 1024;
// Whoever asks for the handover also records its release and the time, and the Host that
// leaves stamps the time again as it frees the slot. For a short hold after that a Host of a
// lower release does not start, so the newer release gets the slot; then the record no
// longer blocks, and a client that has not updated yet still gets a Host.
const EXPECTED_RELEASE_CONTRACT = "hellolynk-neutral-host-expected-release-v1";
const EXPECTED_RELEASE_MAX_BYTES = 1024;
const EXPECTED_RELEASE_HOLD_MS = 60_000;
const HANDOVER_CHECK_EVERY_MS = 1_000;
// The native confirmation TTL: a bounded wait so an open window is not closed.
const HANDOVER_NATIVE_CONFIRMATION_QUIET_MS = 120_000;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const APPLICATION_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const HELLOLYNK_ID = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const LOOPBACK_HOST = "127.0.0.1";
const MAX_REQUEST_BYTES = 64 * 1024;
const APPLICATION_CHANGE_CAPACITY = 256;
// AI history browsing returns one page of the newest incoming metadata. Older
// pages are explicit `before` requests; the pending queue has no such window.
const AUTHORIZED_INBOX_HISTORY_LIMIT = 10;
const MANUAL_RETRYABLE_STATUSES = new Set(["recipient_offline", "failed_retryable", "failed_permanent"]);
const CONTACT_REQUEST_STATES = new Set(["pending", "accepted", "rejected", "cancelled", "blocked", "expired"]);
const WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND = "contact-request.clear-resolved";
const WORKBENCH_LEGACY_LIFECYCLE_ROUTES_UNAVAILABLE =
  "neutral_host_workbench_legacy_lifecycle_routes_unavailable";
const WORKBENCH_LOCAL_ONLY_CAPABILITIES = new Set([
  "contact.authorization.manage", "contact.delete", "contact.instance.delete",
  "messages.mark-read", "messages.delete-read", "contact-request.clear-resolved",
  "messages.mark-all-read",
  "messages.auto-read.manage",
  "contact.instance.rename",
  "contact.rename",
  "messages.delete-sent", "threads.manage-local",
  "contacts.read", "messages.read", "outbox.read", "search.local", "security.read", "threads.read",
]);
const WORKBENCH_LIFECYCLE_DEPENDENT_CAPABILITIES = new Set([
  "block.remove",
  "blocks.read",
  "contact.save",
  "contact.instance.save",
  "relationship.end",
  "relationships.read",
]);
const WORKBENCH_RELATIONSHIP_METADATA_CAPABILITIES = new Set([
  ...WORKBENCH_LIFECYCLE_DEPENDENT_CAPABILITIES,
  "contact.instances.list", "contact-request.respond",
  "contact-request.cancel", "contact-request.send",
  "contact-request.recover-decision", "principal.search",
]);
const WORKBENCH_RELATIONSHIP_METADATA_REFRESH_MS = 15_000;
const PREKEY_REFILL_RETRY_MIN_MS = 1_000;
const PREKEY_REFILL_RETRY_MAX_MS = 60_000;
const RELAY_RETRY_MIN_MS = 1_000;
const RELAY_RETRY_MAX_MS = 60_000;
const RELAY_AUTHORITY_DENIAL_CODES = new Set([
  "host_transport_host_revoked", "host_transport_credential_revoked", "host_transport_credential_inactive",
  "device_credential_invalid", "device_credential_revoked", "delegate_revoked", "delegate_inactive",
]);
const MESSAGE_LOCAL_CAPACITY_CODES = new Set(["local_message_store_too_large"]);
const CONTACT_REQUEST_LOCAL_CAPACITY_CODES = new Set([
  "contact_request_local_capacity_exceeded",
  "contact_request_local_store_too_large",
]);
const KNOWN_CONTACT_REQUEST_SEND_FAILURE_CODES = new Set([
  "contact_request_recipient_prekey_unavailable",
  "contact_request_recipient_endpoint_ambiguous",
]);
const INBOUND_LOCAL_CAPACITY_CODES = new Set([
  ...MESSAGE_LOCAL_CAPACITY_CODES,
  ...CONTACT_REQUEST_LOCAL_CAPACITY_CODES,
]);
const WORKBENCH_COMMAND_CAPABILITIES = Object.freeze({
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend]: "messages.request-send",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus]: "messages.request-send",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead]: "messages.mark-read",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead]: "messages.mark-all-read",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead]: "messages.auto-read.manage",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead]: "messages.delete-read",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent]: "messages.delete-sent",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory]: "threads.manage-local",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry]: "outbox.request-retry",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply]: "outbox.request-retry",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact]: "contact.save",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact]: "contact.rename",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact]: "contact.delete",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances]: "contact.instances.list",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance]: "contact.instance.save",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance]: "contact.instance.rename",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance]: "contact.instance.delete",
  [WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND]:
    WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision]: "contact-request.recover-decision",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest]: "contact-request.respond",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest]: "contact-request.cancel",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal]: "principal.search",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest]: "contact-request.send",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization]: "contact.authorization.manage",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship]: "relationship.end",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock]: "block.remove",
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.openAccount]: "security.open-account",
});

/**
 * Starts the process-owning neutral Host. This is intentionally dependency
 * injected: P5a proves lifecycle and ordering, not a production migration of
 * the existing local stores or the Codex/OpenClaw adapters.
 */
export async function startHelloLynkNeutralHostProcess(options = {}) {
  const tuple = normalizeTuple(options);
  const stableRegion = tuple.region === "international" ? "intl" : tuple.region;
  const runtimeRoot = path.resolve(String(options.runtimeRoot || ""));
  if (!options.runtimeRoot) throw failure("neutral_host_runtime_root_required");
  requireInterface(options.transport, ["registerEndpoint", "openEventStream", "acknowledge"], "neutral_host_transport_invalid");
  requireInterface(options.localStore, ["persistIncomingRecoverable"], "neutral_host_local_store_invalid");
  requireInterface(options.contactStore, ["persistIncomingRecoverable"], "neutral_host_contact_store_invalid");
  requireInterface(options.outbox, ["persistBeforeEncryption", "markUnknown", "markResult", "freezeUnknown"], "neutral_host_outbox_invalid");
  if (typeof options.capabilityResolver !== "function") throw failure("neutral_host_capability_resolver_required");
  if (options.nativeHumanConfirmationBrokerFactory != null
    && typeof options.nativeHumanConfirmationBrokerFactory !== "function") {
    throw failure("neutral_host_native_broker_factory_invalid");
  }
  if (options.changeSink != null && typeof options.changeSink !== "function") throw failure("neutral_host_change_sink_invalid");
  if (options.prepareLocalData != null && typeof options.prepareLocalData !== "function") {
    throw failure("neutral_host_local_data_preparer_invalid");
  }
  if (options.sameHostDeliveryRegistrar != null && typeof options.sameHostDeliveryRegistrar !== "function") {
    throw failure("neutral_host_same_host_delivery_registrar_invalid");
  }
  if (options.humanRelationships != null) {
    requireInterface(
      options.humanRelationships,
      ["search", "send", "list", "decide", "clearResolved"],
      "neutral_host_human_relationships_invalid",
    );
  }
  if (options.accountLauncher != null && typeof options.accountLauncher !== "function") {
    throw failure("neutral_host_account_launcher_invalid");
  }

  const endpoints = normalizeEndpoints(options.endpoints, tuple);
  const handoverCheckEveryMs = integerInRange(options.handoverCheckEveryMs, HANDOVER_CHECK_EVERY_MS, 25, 60_000);
  // Only a test can report a lower release than this code.
  const releaseOrdinal = integerInRange(options.releaseOrdinal, HELLOLYNK_HOST_RELEASE_ORDINAL, 0, HELLOLYNK_HOST_RELEASE_ORDINAL);
  const directoryPending = new Map();
  const friendTargets = new Map();
  const layout = discoveryLayout(runtimeRoot, tuple.hostInstallationId);
  await ensureSafeRuntimeDirectory(runtimeRoot, layout.directory);
  await assertHelloLynkNeutralHostReleaseCurrent({ runtimeRoot, hostInstallationId: tuple.hostInstallationId, releaseOrdinal });
  const lockHandle = await claimInstallationLock(layout.lockPath, layout.discoveryPath, tuple).catch(async (error) => {
    // A Host of a lower release in the slot is asked to make room, as an installer would.
    if (error?.code === "neutral_host_already_running") {
      await requestHelloLynkNeutralHostHandover({ runtimeRoot, hostInstallationId: tuple.hostInstallationId, releaseOrdinal,
        publishedAt: new Date().toISOString(), waitMs: 0 }).catch(() => {});
    }
    throw error;
  });
  try {
    await options.prepareLocalData?.(Object.freeze({
      ...tuple,
      lockHeld: true,
    }));
  } catch (error) {
    await lockHandle.release().catch(() => {});
    throw error;
  }
  const hostGeneration = crypto.randomBytes(24).toString("hex");
  const hostStartedAt = new Date(nowMs(options.clock)).toISOString();
  const pendingOperations = new Set();
  const changeSink = options.changeSink || (() => undefined);
  const applicationInboxStore = options.inboxStore || options.localStore;
  const applicationInbox = normalizeApplicationInbox(applicationInboxStore);
  const applicationContacts = normalizeApplicationContacts(options.contacts || options.contactDirectory);
  const applicationContactRequests = normalizeApplicationContactRequests(
    options.contactRequests || options.contactRequestStore || options.contactStore,
  );
  const applicationOutbox = normalizeApplicationOutbox(options.applicationOutbox, options.outbox, options.messenger);
  const sharedApplicationMessageStore = typeof applicationInboxStore?.list === "function"
    && applicationInboxStore === (options.applicationOutbox || options.outbox);
  const applicationChanges = [];
  const workbenchServices = new Map();
  const workbenchRelationshipTargets = new Map();
  let applicationChangeCursor = 0;
  let applicationMutationTail = Promise.resolve();
  const clock = options.clock || undefined;
  let lifecycle = "starting";
  let failureCode = null;
  let discovery = null;
  let inboundCapacityWarningActive = false;
  let contactRequestNoticeRead = null;
  let inboundPaused = false;
  let inboundPauseCode = null;
  let inboundResumeTask = null;
  let server = null;
  let stream = null;
  let receiveTask = null;
  let relayConnectTask = null;
  let receiverState = null;
  const relayAbortController = new AbortController();
  const relayProvisionedEndpoints = new Set();
  const relayState = { status: "connecting", failureCount: 0, nextAttemptAtMs: 0, errorCode: null };
  const rejectedInboundTimes = new WeakSet();
  let lastRejectedInbound = null;
  let maintenanceTimer = null;
  let historyMaintenanceAt = -Infinity;
  let historyMaintenanceTask = null;
  const preKeyRefillStates = new Map();
  const preKeyRefillQueue = new Set();
  const preKeyRefillAbortController = new AbortController();
  let preKeyRefillTask = null;
  let stopPromise = null;
  let handoverRequested = false;
  let handoverCheckedAt = -Infinity;
  let nativeConfirmationAt = -Infinity;
  let ownsDiscovery = false;
  let modelCalls = 0;
  let nativeBroker = null;
  let relationshipRefreshInFlight = null;
  // Display projection only. Authority checks always use the original controller.
  // The enclosing Host owns this cache; no account/generation survives a restart.
  let workbenchRelationshipMetadata = null;
  let workbenchRelationshipMetadataState = "loading";
  let workbenchRelationshipMetadataAttemptAt = -Infinity;
  let workbenchRelationshipMetadataEpoch = 0;
  let workbenchRelationshipMetadataRefresh = null;
  let workbenchRelationshipMetadataReadContext = null;
  for (const endpoint of endpoints.values()) {
    const initial = endpoint.e2ee?.preKeyInventoryStatus;
    if (initial?.status !== "retrying") continue;
    const state = preKeyRefillState(endpoint.delegateId);
    state.failureCount = 1;
    state.nextAttemptAtMs = Math.max(nowMs(clock), retryAtTimestamp(initial.retryAt) || 0);
    state.errorCode = safeCode(
      { code: initial.errorCode },
      "e2ee_local_prekey_capacity_exceeded",
    );
  }
  try {
    nativeBroker = options.nativeHumanConfirmationBrokerFactory
      ? await options.nativeHumanConfirmationBrokerFactory({
          hostGeneration,
          onApproved: handleNativeApproval,
        })
      : null;
    if (nativeBroker && ["request", "status", "detachAdapter", "close"].some(
      (method) => typeof nativeBroker[method] !== "function",
    )) throw failure("neutral_host_native_broker_invalid");
  } catch (error) {
    await nativeBroker?.close?.().catch(() => {});
    await lockHandle.release().catch(() => {});
    throw error;
  }

  const workbenchCapabilities = resolveWorkbenchCapabilities({
    transport: options.transport,
    applicationInbox,
    applicationContacts,
    applicationContactRequests,
    applicationOutbox,
    nativeBroker,
    humanRelationships: options.humanRelationships,
    accountLauncher: options.accountLauncher,
  });

  const core = createHelloLynkHostCore({
    readModelNotices: async () => {
      // Read only on the first use or after contact-request changes, never scan messages
      // or wait for the cloud to add a short notice to an existing local response.
      contactRequestNoticeRead ??= (async () => {
        const records = await applicationContactRequests?.listForHuman({ states: ["pending"] });
        return records?.filter(record => record.state === "pending" && record.decisionOutcome == null).length ?? 0;
      })().catch(() => null);
      const noticeRead = contactRequestNoticeRead;
      const pendingContactRequests = await noticeRead;
      if (pendingContactRequests == null && contactRequestNoticeRead === noticeRead) contactRequestNoticeRead = null;
      return { pendingContactRequests, localStorageFull: inboundPaused || inboundCapacityWarningActive };
    },
    hostGeneration,
    clock,
    capabilityResolver: async (capabilityId) => {
      const capability = await options.capabilityResolver(capabilityId);
      if (capability?.region !== tuple.region
        || capability?.principalId !== tuple.principalId
        || capability?.hostInstallationId !== tuple.hostInstallationId) {
        throw failure("neutral_host_capability_owner_mismatch");
      }
      return capability;
    },
    actionHandlers: {
      localPeerExchange: (context) => {
        if (typeof options.localPeerExchange !== "function") throw failure("neutral_host_local_peer_unavailable");
        return trackOperation(options.localPeerExchange(context), pendingOperations);
      },
      localIdentityProof: (context) => {
        if (typeof options.localIdentityProof !== "function") throw failure("neutral_host_local_identity_unavailable");
        return trackOperation(options.localIdentityProof(context), pendingOperations);
      },
      detach: (context) => nativeBroker?.detachAdapter({
        capabilityId: context.capabilityId,
        adapterInstanceId: context.adapterInstanceId,
      }),
      appInboxMessages: (context) => applicationInboxMessages(context),
      appInboxUnreadCount: (context) => applicationInboxUnreadCount(context),
      appInboxMarkRead: (context) => trackApplicationMutation(() => applicationInboxMarkRead(context)),
      appInboxDeleteRead: (context) => trackApplicationMutation(() => applicationInboxDeleteRead(context)),
      appContactsList: (context) => applicationContactsList(context),
      appContactsUpsert: (context) => trackApplicationMutation(() => applicationContactsUpsert(context)),
      appContactsRemove: (context) => trackApplicationMutation(() => applicationContactsRemove(context)),
      appContactAutonomousSendAuthorization: (context) => trackApplicationMutation(
        () => applicationContactAutonomousSendAuthorization(context),
      ),
      appAuthorizedContactsList: (context) => applicationAuthorizedContactsList(context),
      appModelInbox: (context) => trackOperation(applicationModelInbox(context), pendingOperations),
      appAuthorizedInboxMessages: (context) => applicationAuthorizedInboxMessages(context),
      appAuthorizedInboxRead: (context) => applicationAuthorizedInboxRead(context),
      appAuthorizedInboxActivate: (context) => applicationAuthorizedInboxActivate(context),
      appAuthorizedInboxPending: (context) => applicationAuthorizedInboxMessages(context, true),
      appAuthorizedInboxPendingQuery: (context) => applicationAuthorizedInboxMessages(context, true, context.request),
      appAuthorizedInboxClaim: (context) => trackOperation(context.request.batchId
        ? applicationAuthorizedInboxBatch(context, "Claim") : applicationAuthorizedInboxClaim(context), pendingOperations),
      appAuthorizedInboxBatchReserve: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Reserve"), pendingOperations),
      appAuthorizedInboxBatchOpen: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Open"), pendingOperations),
      appAuthorizedInboxBatchAttempt: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Attempt"), pendingOperations),
      appAuthorizedInboxBatchConfirm: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Confirm"), pendingOperations),
      appAuthorizedInboxBatchCancel: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Cancel"), pendingOperations),
      appAuthorizedInboxBatchExpire: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Expire"), pendingOperations),
      appAuthorizedInboxBatchClosed: (context) => trackOperation(applicationAuthorizedInboxBatch(context, "Closed"), pendingOperations),
      appAuthorizedInboxFinish: (context) => trackOperation(applicationAuthorizedInboxClaim(context, true), pendingOperations),
      appAuthorizedContactRequestsList: (context) => applicationAuthorizedContactRequestsList(context),
      appAuthorizedContactRequestRead: (context) => applicationAuthorizedContactRequestRead(context),
      // Contact admission is locked by the store; keep slow delivery outside the
      // application mutation queue so human revocations can complete meanwhile.
      appAuthorizedSend: (context) => trackOperation(applicationAuthorizedSend(context), pendingOperations),
      appAuthorizedReply: (context) => trackOperation(applicationAuthorizedReply(context), pendingOperations),
      appContactRequestsList: () => applicationContactRequestsList(),
      appOutboxMessages: (context) => applicationOutboxMessages(context),
      appOutboxRetry: (context) => trackOperation(applicationOutboxRetry(context), pendingOperations),
      appHumanSendRequest: (context) => nativeHumanSendRequest(context),
      appHumanSendRequestStatus: (context) => nativeHumanSendRequestStatus(context),
      appChangesSnapshot: (context) => applicationChangesSnapshot(context),
      appChangesSubscribe: (context) => applicationChangesSubscribe(context),
      appWorkbenchSnapshot: (context) => applicationWorkbenchSnapshot(context),
      appWorkbenchActionGrant: (context) => assertWorkbenchLegacyLifecycleCapabilityAvailable(
        WORKBENCH_COMMAND_CAPABILITIES[context.request?.command],
      ),
      appWorkbenchCommand: (context) => trackOperation(applicationWorkbenchCommand(context), pendingOperations),
      idleShutdown: () => beginDrain("last_attachment_lease_ended"),
    },
  });

  function trackApplicationMutation(operation) {
    const current = applicationMutationTail.then(() => operation());
    applicationMutationTail = current.catch(() => undefined);
    return trackOperation(current, pendingOperations);
  }

  async function nativeHumanSendRequest(context) {
    if (!nativeBroker) throw hostApplicationFailure("host_app_native_broker_unavailable");
    const nativeAuthority = context.nativeAuthority;
    if (typeof nativeAuthority?.assertCurrent !== "function" || typeof nativeAuthority?.revalidate !== "function") {
      throw hostApplicationFailure("human_confirmation_authority_invalidated");
    }
    nativeAuthority.assertCurrent();
    const target = await resolveSavedInstance(context.request, context.delegateId);
    await nativeAuthority.revalidate();
    nativeAuthority.assertCurrent();
    nativeConfirmationAt = nowMs(clock);
    const result = await nativeBroker.request({
      capabilityId: context.capabilityId,
      principalId: context.principalId,
      delegateId: context.delegateId,
      hostInstallationId: context.hostInstallationId,
      adapterId: context.adapterId,
      adapterInstanceId: context.adapterInstanceId,
      hostGeneration,
      recipientHelloLynkId: context.request.recipientHelloLynkId,
      recipientDelegateId: target.recipientDelegateId,
      recipientInstanceDisplayName: target.instance.displayName,
      clientMessageId: context.request.clientMessageId,
      text: context.request.text,
    }, { nativeAuthority });
    return result.body;
  }

  async function nativeHumanSendRequestStatus(context) {
    if (!nativeBroker) throw hostApplicationFailure("host_app_native_broker_unavailable");
    const result = await nativeBroker.status({
      capabilityId: context.capabilityId,
      adapterInstanceId: context.adapterInstanceId,
      actionId: context.request.actionId,
    });
    return result.body;
  }

  async function handleNativeApproval(approval, approvalContext = {}) {
    if (lifecycle !== "running") throw failure("human_confirmation_broker_closed");
    const nativeAuthority = approvalContext.nativeAuthority;
    if (typeof nativeAuthority?.assertCurrent !== "function" || typeof nativeAuthority?.revalidate !== "function") {
      throw failure("human_confirmation_authority_invalidated");
    }
    nativeAuthority.assertCurrent();
    if (approval.principalId !== tuple.principalId
      || approval.hostInstallationId !== tuple.hostInstallationId
      || approval.hostGeneration !== hostGeneration
      || approval.intentSource !== "human_native_dialog") {
      throw failure("human_confirmation_binding_mismatch");
    }
    const endpoint = endpoints.get(approval.delegateId);
    if (!endpoint?.outbound || typeof endpoint.outbound.send !== "function") {
      throw failure("human_confirmation_approval_handler_missing");
    }
    // Approval binds the stable target. Re-read the saved entry after the
    // native dialog; deleting/replacing an entry cannot retarget this action.
    const target = await resolveSavedInstance(approval, approval.delegateId);
    await nativeAuthority.revalidate();
    // No await between this final lifetime check and outbound admission. Once
    // admitted, keep the actual result; detach must not make it safe to resend.
    nativeAuthority.assertCurrent();
    // The approval arrives outside an HTTP request; a drain must still wait for it.
    const result = await trackOperation(sendOutboundOnce({
      endpoint,
      delegateId: approval.delegateId,
      clientMessageId: approval.clientMessageId,
      input: {
        recipientHelloLynkId: approval.recipientHelloLynkId,
        recipientPrincipalId: target.principalId,
        recipientDelegateId: target.recipientDelegateId,
        region: tuple.region,
        route: savedInstanceRoute(target),
        text: approval.text,
        clientMessageId: approval.clientMessageId,
        intentSource: approval.intentSource,
        signal: approvalContext.signal,
      },
    }), pendingOperations);
    return result;
  }

  try {
    await options.outbox.freezeUnknown();
    server = http.createServer(handleHttp);
    server.on("clientError", (_error, socket) => socket.destroy());
    await listenLoopback(server, Number(options.port || 0));
    discovery = Object.freeze({
      contractId: HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT,
      processContractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
      region: tuple.region,
      principalId: tuple.principalId,
      hostInstallationId: tuple.hostInstallationId,
      tupleDigest: digestTuple(tuple),
      host: LOOPBACK_HOST,
      port: server.address().port,
      pid: process.pid,
      hostGeneration,
      startedAt: new Date(nowMs(clock)).toISOString(),
    });
    await atomicWriteJson(layout.discoveryPath, discovery);
    ownsDiscovery = true;
    lifecycle = "running";
    // Local identity, data and authenticated IPC are ready independently of the
    // relay. Cloud setup/recovery must never hold local discovery hostage.
    void connectRelay();
    const maintenanceEveryMs = integerInRange(options.maintenanceEveryMs, 250, 25, 10_000);
    maintenanceTimer = setInterval(() => void runMaintenance().catch(() => undefined), maintenanceEveryMs);
    maintenanceTimer.unref?.();
  } catch (error) {
    try { await cleanupAfterFailedStart(); }
    catch (cleanupError) {
      // Keep the startup failure authoritative, even if its Error is frozen.
      try { error.cleanupErrorCode = safeCode(cleanupError, "neutral_host_startup_cleanup_failed"); }
      catch {}
    }
    throw error;
  }

  async function handleHttp(request, response) {
    if (!isLoopbackAddress(request.socket.remoteAddress)) {
      writeJson(response, 403, { ok: false, error: "neutral_host_loopback_required" });
      return;
    }
    let requestUrl;
    try { requestUrl = new URL(request.url || "/", "http://127.0.0.1"); }
    catch {
      writeJson(response, 400, { ok: false, error: "neutral_host_request_target_invalid" });
      return;
    }
    const pathname = requestUrl.pathname;
    if (requestUrl.search !== "" || requestUrl.hash !== "" || request.url !== pathname) {
      writeJson(response, 400, { ok: false, error: "neutral_host_request_target_invalid" });
      return;
    }
    if (lifecycle !== "running") {
      if (request.method === "GET" && pathname === HELLOLYNK_HOST_PATHS.health) {
        writeJson(response, 200, wrapperHealth());
      } else {
        writeJson(response, 503, { ok: false, error: "neutral_host_draining" });
      }
      return;
    }
    const rawBody = await readBody(request, MAX_REQUEST_BYTES).catch((error) => {
      writeJson(response, error?.code === "neutral_host_request_too_large" ? 413 : 400, {
        ok: false,
        error: safeCode(error, "neutral_host_request_invalid"),
      });
      return null;
    });
    if (rawBody == null) return;
    if (lifecycle !== "running") {
      writeJson(response, 503, { ok: false, error: "neutral_host_draining" });
      return;
    }
    if (request.method === "GET" && pathname === HELLOLYNK_HOST_PATHS.health) {
      const result = await trackOperation(core.dispatch({
        method: request.method,
        pathname,
        rawBody,
        headers: request.headers,
      }), pendingOperations);
      writeJson(response, result.status, result.status === 200 ? runningHealth(result.body) : result.body);
      return;
    }
    const result = await trackOperation(core.dispatch({
      method: request.method,
      pathname,
      rawBody,
      headers: request.headers,
    }), pendingOperations);
    writeJson(response, result.status, result.body);
  }

  async function receiveLoop() {
    let inboundFailed = false;
    try {
      for await (const item of stream.events) {
        if (lifecycle !== "running") return;
        if (!item || item.event === "ready" || item.event === "heartbeat") continue;
        // A relay closure is a transport control, not an encrypted message.
        // Temporary closures reconnect below; explicit revocation still drains.
        if (item.event === "host_transport_closed") {
          throw failure(safeCode({ code: item.data?.reason }, "neutral_host_transport_stream_closed"));
        }
        const operation = trackOperation(handleInbound(item), pendingOperations);
        try {
          await operation;
          lastRejectedInbound = null;
        } catch (error) {
          // These errors were raised before persistence/prekey consumption.
          // Do not ACK or retry this frame; let the relay expire it while later
          // valid frames continue. Disk/commit/ACK failures still drain below.
          if (rejectedInboundTimes.has(error)) {
            lastRejectedInbound = { errorCode: error.code };
            continue;
          }
          if (!isInboundLocalCapacityError(error)) {
            inboundFailed = true;
            throw error;
          }
          await pauseInboundForLocalCapacity(error);
          return;
        }
      }
      if (lifecycle === "running") throw failure("neutral_host_transport_stream_closed");
    } catch (error) {
      if (lifecycle !== "running") return;
      // Preserve fail-closed persistence/ACK and other malformed-inbound errors.
      if (inboundFailed || RELAY_AUTHORITY_DENIAL_CODES.has(error?.code)) throw error;
      await stream?.close?.().catch(() => {});
      stream = null;
      scheduleRelayRetry(error);
      if (error?.code === "host_transport_session_rotation") void connectRelay();
    }
  }

  function scheduleRelayRetry(error) {
    relayState.status = "retrying";
    relayState.errorCode = safeCode(error, "neutral_host_relay_unavailable");
    relayState.failureCount = Math.min(relayState.failureCount + 1, 31);
    const delay = error?.code === "host_transport_session_rotation" ? 0
      : Math.min(RELAY_RETRY_MAX_MS, RELAY_RETRY_MIN_MS * 2 ** Math.min(relayState.failureCount - 1, 16));
    relayState.nextAttemptAtMs = nowMs(clock) + delay;
  }

  function connectRelay() {
    if (relayConnectTask || lifecycle !== "running" || inboundPaused || relayState.status === "ready") {
      return relayConnectTask;
    }
    relayState.status = "connecting";
    const signal = relayAbortController.signal;
    const task = (async () => {
      let connected = null;
      try {
        const registrations = await Promise.allSettled([...endpoints.values()].map(async (endpoint) => {
          if (endpoint.e2ee?.preKeyInventoryStatus?.status === "deferred"
            && !relayProvisionedEndpoints.has(endpoint.delegateId)) {
            try {
              await endpoint.e2ee.ensurePreKeyInventory({ signal });
            } catch (error) {
              if (error?.code !== "e2ee_local_prekey_capacity_exceeded") throw error;
              const state = preKeyRefillState(endpoint.delegateId);
              state.failureCount = 1;
              state.nextAttemptAtMs = Math.max(nowMs(clock) + PREKEY_REFILL_RETRY_MIN_MS, retryAtTimestamp(error.retryAt) || 0);
              state.errorCode = error.code;
            }
            relayProvisionedEndpoints.add(endpoint.delegateId);
          }
          if (signal.aborted || lifecycle !== "running") return;
          await options.transport.registerEndpoint({
            delegateId: endpoint.delegateId, identityKeyId: endpoint.identityKeyId,
            runtimeHeaders: endpoint.runtimeHeaders, signal,
          });
        }));
        if (signal.aborted || lifecycle !== "running") return;
        const failed = registrations.find((result) => result.status === "rejected"
          && RELAY_AUTHORITY_DENIAL_CODES.has(result.reason?.code))
          || registrations.find((result) => result.status === "rejected");
        if (failed) throw failed.reason;
        connected = await openRelayStream(signal);
        if (!connected?.events || typeof connected.events[Symbol.asyncIterator] !== "function") {
          throw failure("neutral_host_transport_stream_invalid");
        }
        if (signal.aborted || lifecycle !== "running") {
          await connected.close?.().catch(() => {});
          return;
        }
        stream = connected;
        Object.assign(relayState, { status: "ready", failureCount: 0, nextAttemptAtMs: 0, errorCode: null });
        startReceiveTask();
      } catch (error) {
        await connected?.close?.().catch(() => {});
        if (signal.aborted || lifecycle !== "running") return;
        // An explicit revocation of this Host still fences local access. A
        // timeout/expired cloud session alone is not a local revocation.
        if (RELAY_AUTHORITY_DENIAL_CODES.has(error?.code)) {
          // Failure is exposed as host.status/failureCode to the release entry.
          void beginDrain(error.code).catch(() => {});
          return;
        }
        scheduleRelayRetry(error);
      }
    })();
    // Relay setup is cancellable connection work, not a message persist/ACK
    // unit. Its late completion is fenced above and must not hold the local
    // shutdown lock after the caller has aborted it.
    relayConnectTask = task;
    relayConnectTask.finally(() => { relayConnectTask = null; });
    return relayConnectTask;
  }

  async function openRelayStream(signal) {
    signal.throwIfAborted();
    // The installation lock is held for this Host's entire lifetime. Persist
    // before sending, so a crash cannot reuse an accepted attempt number.
    // Drain tracks this local write before releasing ownership to a successor.
    const receiverAttempt = await trackOperation((async () => {
      if (!receiverState) {
        await assertSafePath(layout.receiverStatePath, { mustExist: false, directory: false });
        let saved;
        try { saved = JSON.parse(await fs.readFile(layout.receiverStatePath, "utf8")); }
        catch (error) { if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error; }
        receiverState = saved;
      }
      // This is disposable receive bookkeeping, not an account credential.
      // A fresh ID cannot reuse an old attempt or displace another receiver.
      if (!receiverState || typeof receiverState !== "object" || Array.isArray(receiverState)
        || receiverState.contract !== "hellolynk-host-receiver-state-v1" || receiverState.tupleDigest !== digestTuple(tuple)
        || typeof receiverState.receiverId !== "string" || !SAFE_ID.test(receiverState.receiverId)
        || !Number.isSafeInteger(receiverState.sequence) || receiverState.sequence < 0 || receiverState.sequence >= Number.MAX_SAFE_INTEGER) {
        receiverState = { contract: "hellolynk-host-receiver-state-v1", tupleDigest: digestTuple(tuple), receiverId: crypto.randomUUID(), sequence: 0 };
      }
      const next = { ...receiverState, sequence: receiverState.sequence + 1 };
      await atomicWriteJson(layout.receiverStatePath, next);
      receiverState = next;
      return { receiverId: next.receiverId, sequence: next.sequence };
    })(), pendingOperations);
    signal.throwIfAborted();
    if (lifecycle !== "running") throw failure("neutral_host_draining");
    return options.transport.openEventStream({ signal, receiverAttempt });
  }

  async function handleInbound(item) {
    const event = assertPlainRecord(item.data, "neutral_host_inbound_event_invalid");
    if (event.recipientPrincipalId !== tuple.principalId || event.recipientHostId !== tuple.hostInstallationId) {
      throw failure("neutral_host_inbound_owner_mismatch");
    }
    const endpoint = endpoints.get(safeId(event.recipientDelegateId, "neutral_host_inbound_delegate_invalid"));
    if (!endpoint) throw failure("neutral_host_inbound_endpoint_unknown");
    const isContactRequest = item.event === "contact_request";
    if (!isContactRequest && item.event !== "message") throw failure("neutral_host_inbound_kind_invalid");
    const decryptor = isContactRequest ? endpoint.contactE2ee : endpoint.e2ee;
    let opened;
    try {
      opened = await decryptor.openIncoming({
        event,
        recipientPrincipalId: tuple.principalId,
        recipientDelegateId: endpoint.delegateId,
      });
    } catch (error) {
      if (["e2ee_envelope_expired", "e2ee_created_at_in_future",
        "contact_request_envelope_expired", "contact_request_created_at_in_future"].includes(error?.code)) {
        rejectedInboundTimes.add(error);
      }
      throw error;
    }
    if (!opened || typeof opened.text !== "string" || typeof opened.commit !== "function") {
      throw failure("neutral_host_inbound_decrypt_invalid");
    }
    if (!isContactRequest && opened.rejectedNativeContent) return consumeNativeFrame(event, opened, endpoint, item.localDelivery === true);
    if (!isContactRequest && opened.nativeDirectory) return handleNativeDirectory(event, opened, endpoint, item.localDelivery === true);
    if (opened.targetConversationId && (opened.replyToClientMessageId
      || (opened.senderPrincipalId !== tuple.principalId && !isFriendTargetFrame(opened, item.localDelivery))))
      return consumeNativeFrame(event, opened, endpoint, item.localDelivery === true);
    const friendTarget = opened.targetConversationId && opened.senderPrincipalId !== tuple.principalId
      ? admitFriendTarget(opened, endpoint, event.clientMessageId) : null;
    const store = isContactRequest ? options.contactStore : options.localStore;
    // The persistence coordinator orders business-record durability before
    // prekey commit and journals recovery. It is not a cross-store transaction.
    const persisted = await store.persistIncomingRecoverable({
      event,
      text: opened.text,
      envelopeDigest: opened.envelopeDigest || event.envelopeDigest,
      ...(isContactRequest ? { introDigestSalt: opened.introDigestSalt } : {
        senderPrincipalId: opened.senderPrincipalId,
        senderDelegateId: opened.senderDelegateId,
        authorizationScope: opened.authorizationScope,
        intentSource: opened.intentSource,
        ...(opened.replyToClientMessageId ? { replyToClientMessageId: opened.replyToClientMessageId } : {}),
        ...(opened.targetConversationId ? { targetConversationId: opened.targetConversationId } : {}),
        ...(friendTarget ? { friendTarget } : {}),
        conversationBinding: opened.e2eeVersion === 2 ? deriveInstanceConversationBinding(opened, {
          direction: "incoming", region: tuple.region, principalId: tuple.principalId,
        }) : null,
      }),
      commitPrekey: opened.commit,
      humanOnly: isContactRequest,
      modelVisibility: "none",
    });
    // The record and prekey commit are durable now. Refresh the application
    // before network ACK can delay visibility.
    await publishApplicationChange(
      isContactRequest ? "contact_requests_changed" : "inbox_changed",
      persisted.localRecordId || event.eventId,
    );
    let acknowledged = true;
    if (item.localDelivery !== true) {
      try {
        await options.transport.acknowledge({ event, kind: item.event, persisted });
      } catch (error) {
        const deadline = typeof event.ackDeadlineAt === "string" ? Date.parse(event.ackDeadlineAt) : NaN;
        if (isContactRequest || error?.code !== "relay_ack_delivery_attempt_not_found" || error?.httpStatus !== 409
          || !Number.isFinite(deadline) || new Date(deadline).toISOString() !== event.ackDeadlineAt
          || nowMs(clock) < deadline) throw error;
        // The relay already removed this expired attempt. Keep the durable
        // message and receiver, without claiming a cloud ACK or retrying a send.
        acknowledged = false;
      }
    }
    if (acknowledged && item.localDelivery !== true && !persisted.duplicate
      && preKeyRefillMethod(endpoint)) {
      // A consumed one-time prekey must remain retained for replay protection.
      // Refill only after its ACK has made the server inventory authoritative;
      // a refill error must never roll back an acknowledged local record or stop
      // the Host receiver.
      requestPreKeyRefill(endpoint);
    }
    const change = Object.freeze({
      contractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
      type: isContactRequest ? "contact_requests_changed" : "inbox_changed",
      eventId: event.eventId,
      duplicate: persisted.duplicate === true,
      ...(acknowledged ? {} : { acknowledged: false }),
      modelVisibility: "none",
    });
    assertNoSensitiveEventFields(change);
    await changeSink(change);
    return Object.freeze({
      localRecordId: persisted.localRecordId,
      duplicate: persisted.duplicate === true,
      acknowledged,
      ...(persisted.replyTargetDeleted ? { replyTargetDeleted: true } : {}),
    });
  }

  options.sameHostDeliveryRegistrar?.((item) => {
    if (lifecycle !== "running") throw failure("neutral_host_same_host_delivery_unavailable");
    if (item?.localDelivery !== true || item?.event !== "message") {
      throw failure("neutral_host_same_host_delivery_invalid");
    }
    return trackOperation(handleInbound(item), pendingOperations);
  });

  async function reportInboundCapacity() {
    const change = Object.freeze({
      contractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
      type: "local_storage_full",
      modelVisibility: "none",
    });
    assertNoSensitiveEventFields(change);
    await publishChange(change, "local-storage-capacity");
    inboundCapacityWarningActive = true;
  }

  function startReceiveTask() {
    receiveTask = receiveLoop().catch((error) => {
      if (lifecycle === "running") {
        // Do not turn a terminal drain failure into an unhandled process abort.
        void beginDrain(safeCode(error, "neutral_host_receive_failed")).catch(() => {});
      }
    });
  }

  function requestPreKeyRefill(endpoint) {
    const state = preKeyRefillState(endpoint.delegateId);
    if (state.failureCount === 0) state.nextAttemptAtMs = 0;
    preKeyRefillQueue.add(endpoint.delegateId);
    if (preKeyRefillTask) return preKeyRefillTask;
    const task = trackOperation(runPreKeyRefillQueue(), pendingOperations);
    preKeyRefillTask = task;
    task.then(
      () => { if (preKeyRefillTask === task) preKeyRefillTask = null; },
      () => { if (preKeyRefillTask === task) preKeyRefillTask = null; },
    );
    return task;
  }

  async function runPreKeyRefillQueue() {
    while (preKeyRefillQueue.size > 0 && lifecycle === "running") {
      const delegateId = preKeyRefillQueue.values().next().value;
      preKeyRefillQueue.delete(delegateId);
      const endpoint = endpoints.get(delegateId);
      const refill = preKeyRefillMethod(endpoint);
      if (!refill) continue;
      const state = preKeyRefillState(delegateId);
      const attemptedAtMs = nowMs(clock);
      if (attemptedAtMs < state.nextAttemptAtMs) continue;
      try {
        await refill.call(endpoint.e2ee, { signal: preKeyRefillAbortController.signal });
        state.failureCount = 0;
        state.nextAttemptAtMs = 0;
        state.errorCode = null;
      } catch (error) {
        if (preKeyRefillAbortController.signal.aborted || lifecycle !== "running") return;
        state.failureCount = Math.min(state.failureCount + 1, 31);
        const exponent = Math.min(state.failureCount - 1, 16);
        const backoffMs = Math.min(
          PREKEY_REFILL_RETRY_MAX_MS,
          PREKEY_REFILL_RETRY_MIN_MS * (2 ** exponent),
        );
        state.nextAttemptAtMs = Math.max(
          attemptedAtMs + backoffMs,
          retryAtTimestamp(error?.retryAt) || 0,
        );
        state.errorCode = safeCode(error, "e2ee_prekey_refill_failed");
      }
    }
  }

  function preKeyRefillMethod(endpoint) {
    if (typeof endpoint?.e2ee?.ensurePreKeyInventory === "function") {
      return endpoint.e2ee.ensurePreKeyInventory;
    }
    return typeof endpoint?.e2ee?.replenishPreKeyInventory === "function"
      ? endpoint.e2ee.replenishPreKeyInventory
      : null;
  }

  function preKeyRefillState(delegateId) {
    let state = preKeyRefillStates.get(delegateId);
    if (!state) {
      state = { failureCount: 0, nextAttemptAtMs: 0, errorCode: null };
      preKeyRefillStates.set(delegateId, state);
    }
    return state;
  }

  function preKeyInventoryHealth() {
    const failures = [...preKeyRefillStates.values()].filter((state) => state.failureCount > 0);
    if (failures.length === 0) return { status: "ready", failedEndpointCount: 0 };
    const next = failures.reduce((selected, state) => (
      !selected || state.nextAttemptAtMs < selected.nextAttemptAtMs ? state : selected
    ), null);
    return {
      status: "retrying",
      failedEndpointCount: failures.length,
      retryAt: new Date(next.nextAttemptAtMs).toISOString(),
      errorCode: next.errorCode,
    };
  }

  async function runMaintenance() {
    const health = await core.runMaintenance();
    if (lifecycle !== "running") return health;
    const now = nowMs(clock);
    if (await handOverWhenQuiet(now)) return health;
    if (relayState.status === "retrying" && now >= relayState.nextAttemptAtMs) void connectRelay();
    if (typeof applicationInbox?.maintainLocalHistory === "function" && !historyMaintenanceTask
      && now - historyMaintenanceAt >= 60_000) {
      historyMaintenanceAt = now;
      // Bounded local bookkeeping only; it does not call or schedule AI work.
      historyMaintenanceTask = trackOperation(Promise.resolve().then(async () => {
        const result = await applicationInbox.maintainLocalHistory({ limit: 50 });
        if (result?.archivedCount > 0 && lifecycle === "running") {
          await publishApplicationChange("inbox_changed", "local_history_maintenance");
        }
      }), pendingOperations).catch(() => undefined).finally(() => { historyMaintenanceTask = null; });
    }
    for (const [delegateId, state] of preKeyRefillStates) {
      if (state.failureCount > 0 && state.nextAttemptAtMs <= now) preKeyRefillQueue.add(delegateId);
    }
    if (preKeyRefillQueue.size > 0) {
      const endpoint = endpoints.get(preKeyRefillQueue.values().next().value);
      if (endpoint) await requestPreKeyRefill(endpoint);
    }
    return runningHealth(health);
  }

  async function handOverWhenQuiet(now) {
    if (!handoverRequested && now - handoverCheckedAt >= handoverCheckEveryMs) {
      handoverCheckedAt = now;
      const request = await readHandoverRequest(layout.handoverPath).catch(() => null);
      handoverRequested = request?.hostGeneration === hostGeneration;
    }
    // Sends, receipts, prekey refills and verifications are all pendingOperations.
    if (!handoverRequested || lifecycle !== "running" || pendingOperations.size > 0
      || nowMs(clock) - nativeConfirmationAt < HANDOVER_NATIVE_CONFIRMATION_QUIET_MS) return false;
    // The idle-stop drain: admitted work finishes, discovery and lock are
    // released, and adapters reconnect to the release now bound on disk.
    void beginDrain("release_handover_requested").catch(() => undefined);
    return true;
  }

  async function pauseInboundForLocalCapacity(error) {
    if (inboundPaused) return;
    inboundPaused = true;
    inboundPauseCode = String(error?.code || "");
    await stream?.close?.().catch(() => {});
    if (!inboundCapacityWarningActive) await reportInboundCapacity().catch(() => undefined);
  }

  async function resumeInboundAfterHumanCleanup(acceptedCapacityCodes) {
    if (!inboundPaused || lifecycle !== "running") return false;
    if (!acceptedCapacityCodes?.has(inboundPauseCode)) return false;
    if (inboundResumeTask) return inboundResumeTask;
    inboundResumeTask = (async () => {
      try {
        const resumed = await openRelayStream(relayAbortController.signal);
        if (!resumed?.events || typeof resumed.events[Symbol.asyncIterator] !== "function") {
          throw failure("neutral_host_transport_stream_invalid");
        }
        if (lifecycle !== "running") {
          await resumed.close?.().catch(() => {});
          return false;
        }
        stream = resumed;
        inboundPaused = false;
        inboundPauseCode = null;
        inboundCapacityWarningActive = false;
        Object.assign(relayState, { status: "ready", failureCount: 0, nextAttemptAtMs: 0, errorCode: null });
        startReceiveTask();
        return true;
      } catch {
        return false;
      } finally {
        inboundResumeTask = null;
      }
    })();
    return inboundResumeTask;
  }

  async function sendOutboundOnce({ endpoint, delegateId, clientMessageId, input }) {
    try {
      const result = await endpoint.outbound.send(input);
      if (result?.message?.lastErrorCode === "reply_target_deleted" || result?.relay?.status === "reply_target_deleted") {
        throw hostApplicationFailure("host_app_reply_target_deleted");
      }
      const status = String(result?.status || "");
      const delivered = [
        "acknowledged_by_recipient_local_store",
        "delivered_to_live_connection",
      ].includes(status);
      if (result?.ok === false
        || (status && !delivered)
        || (!status && result?.ok !== true)) {
        throw failure("neutral_host_outbound_delivery_failed");
      }
      await publishOutboxChange(clientMessageId, delegateId);
      return result;
    } catch (error) {
      // The production messenger persists the failed/unknown outbox state before
      // throwing. Publish that durable state and return the failure to the caller.
      // This path never calls retry and never schedules another send attempt.
      await publishOutboxChange(clientMessageId, delegateId).catch(() => undefined);
      throw error;
    }
  }

  async function publishOutboxChange(clientMessageId, delegateId) {
    const change = Object.freeze({
      contractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
      type: "outbox_changed",
      clientMessageId,
      modelVisibility: "none",
    });
    assertNoSensitiveEventFields(change);
    await publishChange(change, clientMessageId, delegateId);
  }

  async function applicationInboxMessages(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    const messages = await applicationInbox.list();
    return {
      messages: messages
        .filter((message) => message?.direction === "incoming")
        .map((message) => projectInboxMessage(message, tuple)),
    };
  }

  async function applicationInboxUnreadCount(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    if (typeof applicationInbox.getMessageCounts !== "function") throw hostApplicationFailure("host_app_unavailable");
    // The protected index updates these counts with every message mutation.
    // A badge needs no bodies and must not include another AI's conversations.
    const counts = await applicationInbox.getMessageCounts(localHistoryScope(context));
    if (!Number.isSafeInteger(counts?.inbox?.unread) || counts.inbox.unread < 0) {
      throw hostApplicationFailure("host_app_response_invalid");
    }
    return { unreadCount: counts.inbox.unread };
  }

  async function applicationInboxMarkRead(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    const localMessageId = context.request.localMessageId;
    const message = await applicationInbox.getIncoming(localMessageId);
    if (!message) throw hostApplicationFailure("host_app_record_not_found");
    if (message.direction !== "incoming") throw hostApplicationFailure("host_app_record_not_found");
    if (!isUnreadIncoming(message)) {
      scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
      return { localMessageId, unread: false };
    }
    const updated = await applicationInbox.markRead(localMessageId);
    if (!updated || isUnreadIncoming(updated)) throw hostApplicationFailure("host_app_action_failed");
    await publishApplicationChange("inbox_changed", localMessageId);
    scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
    return { localMessageId, unread: false };
  }

  async function applicationInboxMarkAllRead(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    if (typeof applicationInbox.markIncomingRead !== "function") throw hostApplicationFailure("host_app_capability_unavailable");
    const { threadId, beforeReceiptSeq } = context.request;
    if (threadId !== null) await requireLocalConversation(context, threadId);
    const { markedCount } = await applicationInbox.markIncomingRead({ scope: localHistoryScope(context), threadId, beforeReceiptSeq });
    if (markedCount > 0) await publishApplicationChange("inbox_changed", threadId || context.delegateId, context.delegateId);
    scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
    return { kind: "messages-marked-read", markedCount, threadId, beforeReceiptSeq };
  }
  async function applicationConversationAutoRead(context) {
    if (typeof applicationInbox?.configureConversationAutoRead !== "function") throw hostApplicationFailure("host_app_capability_unavailable");
    const { threadId, enabled } = context.request;
    const conversation = await requireLocalConversation(context, threadId);
    if (!conversation?.binding) throw hostApplicationFailure("host_app_record_not_found");
    const result = await applicationInbox.configureConversationAutoRead({ scope: localHistoryScope(context),
      threadId, enabled, conversationBinding: conversation.binding, peerHelloLynkId: conversation.peerHelloLynkId });
    await publishApplicationChange("inbox_changed", threadId, context.delegateId);
    return { kind: "conversation-auto-read", ...result };
  }

  async function applicationInboxDeleteRead(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    const localMessageIds = context.request.localMessageIds;
    const selected = await Promise.all(localMessageIds.map((id) => applicationInbox.getIncoming(id)));
    if (selected.some((message) => !message || message.direction !== "incoming")) {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    if (selected.some(isUnreadIncoming)) throw hostApplicationFailure("host_app_state_conflict");
    const result = await applicationInbox.deleteRead(localMessageIds);
    const deletedIds = result?.deletedIds;
    if (!Array.isArray(deletedIds) || new Set(deletedIds).size !== deletedIds.length
      || deletedIds.some((id) => !localMessageIds.includes(id))) {
      throw hostApplicationFailure("host_app_action_failed");
    }
    // Earlier or concurrent cleanup may have left only deletion tombstones.
    // The store's committed result is authoritative; report the actual count
    // instead of turning successful cleanup into a server error.
    for (const localMessageId of deletedIds) await publishApplicationChange("inbox_changed", localMessageId);
    scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
    return { deletedCount: deletedIds.length, deletedIds };
  }

  function localHistoryScope(context) {
    return { principalId: tuple.principalId, delegateId: context.delegateId, region: tuple.region };
  }

  function resumeAfterLocalHistoryCleanup(result) {
    if (result.deletedCount > 0) scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
  }

  function scheduleInboundResumeAfterHumanCleanup(acceptedCapacityCodes) {
    if (!inboundPaused || lifecycle !== "running" || !acceptedCapacityCodes.has(inboundPauseCode)) return false;
    // The completed local cleanup never waits for reconnecting the receive
    // stream. Track that separate recovery so Host shutdown can drain it.
    void trackOperation(Promise.resolve().then(() => resumeInboundAfterHumanCleanup(acceptedCapacityCodes)),
      pendingOperations).catch(() => {});
    return true;
  }

  async function requireLocalConversation(context, threadId) {
    const scope = localHistoryScope(context);
    const summary = typeof applicationInbox.readWorkbenchSummary === "function"
      ? await applicationInbox.readWorkbenchSummary(scope) : null;
    // The indexed summary is authenticated and restricted to this scope (or
    // this principal's unbound legacy history). Local housekeeping grants no
    // messaging or execution authority to those legacy records.
    const savedThread = summary?.threads.find((thread) => thread.threadId === threadId
      && (thread.binding || thread.legacy === true));
    if (savedThread) return savedThread;
    const state = summary ? { messages: [], hiddenThreadIds: [] }
      : await applicationInbox.readWorkbenchState(scope);
    if (state.hiddenThreadIds.includes(threadId)) return;
    if (state.messages.some((message) => {
      try {
        const binding = getMessageConversationBinding(message, tuple) || getOutgoingConversationIntent(message, tuple);
        return binding?.localDelegateId === context.delegateId && instanceConversationKey(binding) === threadId;
      } catch {
        // Contradictory old evidence stays in read-only legacy history. It
        // neither authorizes this operation nor blocks a different valid route.
        return false;
      }
    })) return;
    const contacts = await applicationContacts.listForDelegate(context.delegateId);
    for (const contact of contacts) {
      if (!contact.principalId || contact.hellolynkId?.split(":")[1] !== stableRegion) continue;
      for (const instance of contact.instances || []) {
        const binding = { schemaVersion: 1, region: stableRegion,
          localPrincipalId: tuple.principalId, localDelegateId: context.delegateId,
          peerPrincipalId: contact.principalId, peerDelegateId: instance.delegateId };
        if (instanceConversationKey(binding) === threadId) return { binding, peerHelloLynkId: contact.hellolynkId };
      }
    }
    throw hostApplicationFailure("host_app_record_not_found");
  }

  async function applicationLocalHistory(command, context) {
    const scope = localHistoryScope(context);
    const type = command.command;
    if ([HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads].includes(type)) {
      const allArchived = type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads;
      const conversation = allArchived ? null : await requireLocalConversation(context, command.payload.threadId);
      const method = allArchived ? "deleteArchivedConversations" : "deleteLocalConversation";
      if (typeof applicationInbox[method] !== "function") throw hostApplicationFailure("host_app_capability_unavailable");
      const result = await applicationInbox[method]({ ...scope, ...command.payload,
        ...(conversation?.binding ? { conversationBinding: conversation.binding, peerHelloLynkId: conversation.peerHelloLynkId } : {}) });
      resumeAfterLocalHistoryCleanup(result);
      await publishApplicationChange("inbox_changed", command.payload.threadId || "archived_conversations", context.delegateId);
      await publishApplicationChange("outbox_changed", command.payload.threadId || "archived_conversations", context.delegateId);
      return { kind: "local-history", ...result };
    }
    if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory) {
      if (typeof applicationInbox.configureLocalHistory !== "function") throw hostApplicationFailure("host_app_capability_unavailable");
      await applicationInbox.configureLocalHistory({ scope, ...command.payload });
      await publishApplicationChange("inbox_changed", "local_history_preferences", context.delegateId);
      historyMaintenanceAt = -Infinity;
      return {};
    }
    if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent) {
      const result = await applicationInbox.deleteSentLocal({ ...scope, ...command.payload });
      resumeAfterLocalHistoryCleanup(result);
      for (const id of command.payload.localMessageIds) await publishApplicationChange("outbox_changed", id, context.delegateId);
      return { kind: "local-history", deletedCount: result.deletedCount,
        retainedUnreadCount: result.retainedUnreadCount, retainedOutgoingCount: result.retainedOutgoingCount,
        ...(result.retainedTaskCount != null ? { retainedTaskCount: result.retainedTaskCount } : {}),
        ...(result.deletedBytes != null ? { deletedBytes: result.deletedBytes } : {}) };
    }
    const { threadId } = command.payload;
    // The opaque key is never authority: require a saved instance, a scoped
    // history row, or this delegate's persisted hidden entry, all read locally.
    const conversation = await requireLocalConversation(context, threadId);
    if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread) {
      await applicationInbox.hideLocalConversation({ ...scope, threadId,
        ...(conversation?.binding ? { conversationBinding: conversation.binding, peerHelloLynkId: conversation.peerHelloLynkId } : {}) });
    } else if (type === HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread) {
      await applicationInbox.restoreLocalConversation({ ...scope, threadId });
    } else {
      const result = await applicationInbox.clearLocalConversation({ ...scope, threadId,
        ...(Object.hasOwn(command.payload, "before") ? { before: command.payload.before } : {}) });
      resumeAfterLocalHistoryCleanup(result);
      await publishApplicationChange("inbox_changed", threadId, context.delegateId);
      await publishApplicationChange("outbox_changed", threadId, context.delegateId);
      return { kind: "local-history", deletedCount: result.deletedCount,
        retainedUnreadCount: result.retainedUnreadCount, retainedOutgoingCount: result.retainedOutgoingCount,
        ...(result.retainedTaskCount != null ? { retainedTaskCount: result.retainedTaskCount } : {}),
        ...(result.deletedBytes != null ? { deletedBytes: result.deletedBytes } : {}) };
    }
    await publishApplicationChange("inbox_changed", threadId, context.delegateId);
    return {};
  }

  async function applicationContactsList(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    return {
      contacts: (await applicationContacts.listForDelegate(context.delegateId)).map(projectContact),
    };
  }

  async function readContactInstances(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof options.transport.listAgentInstances !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const contact = (await applicationContacts.listForDelegate(context.delegateId))
      .find((item) => item.contactId === context.request.contactId);
    if (!contact) throw hostApplicationFailure("host_app_record_not_found");
    if (!contact.hellolynkId.startsWith(`hellolynk:${stableRegion}:`)) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    const directory = await options.transport.listAgentInstances({ hellolynkId: contact.hellolynkId });
    if (directory.hellolynkId !== contact.hellolynkId
      || (contact.principalId && directory.principalId !== contact.principalId)
      || (contact.hellolynkId === endpoints.get(context.delegateId)?.hellolynkId
        && directory.principalId !== tuple.principalId)
      || !Array.isArray(directory.instances)) {
      throw hostApplicationFailure("host_app_instance_directory_invalid");
    }
    const principalId = safeId(directory.principalId, "host_app_instance_directory_invalid");
    const seen = new Set();
    const instances = directory.instances.map((item) => {
      const delegateId = safeId(item.delegateId, "host_app_instance_directory_invalid");
      if (seen.has(delegateId) || item.status !== "active"
        || !["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh", "claude-code"].includes(item.clientType)) {
        throw hostApplicationFailure("host_app_instance_directory_invalid");
      }
      seen.add(delegateId);
      const createdAtMs = typeof item.createdAt === "string" && item.createdAt.length <= 64 ? Date.parse(item.createdAt) : NaN;
      return { delegateId, displayName: safeDisplayName(item.displayName, "host_app_instance_directory_invalid"),
        clientType: item.clientType, status: "active",
        ...(Number.isFinite(createdAtMs) ? { createdAt: new Date(createdAtMs).toISOString() } : {}) };
    }).filter((item) => principalId !== tuple.principalId || item.delegateId !== context.delegateId);
    return { kind: "contact-instances", contactId: contact.contactId,
      principalId, hellolynkId: contact.hellolynkId, instances };
  }

  async function saveContactInstance(context) {
    const directory = await readContactInstances(context);
    const instance = directory.instances.find((item) => item.delegateId === context.request.recipientDelegateId);
    if (!instance || typeof applicationContacts.upsertInstance !== "function") {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    const storedContact = (await applicationContacts.listForDelegate(context.delegateId))
      .find((item) => item.contactId === directory.contactId);
    const storedInstance = storedContact?.instances?.find((item) => item.delegateId === instance.delegateId);
    const displayName = context.request.displayName
      ?? storedInstance?.displayName
      ?? instance.displayName;
    await applicationContacts.upsertInstance(directory.contactId, {
      principalId: directory.principalId, delegateId: instance.delegateId,
      clientType: instance.clientType,
      displayName: safeDisplayName(displayName, "host_app_instance_display_name_invalid"),
    });
    await publishApplicationChange("contacts_changed", directory.contactId);
  }

  async function renameContact(context) {
    if (typeof applicationContacts?.rename !== "function") throw hostApplicationFailure("host_app_capability_unavailable");
    const { contactId, displayName, expectedDisplayName, expectedHelloLynkId } = context.request;
    if (!expectedHelloLynkId.startsWith(`hellolynk:${stableRegion}:`)) throw hostApplicationFailure("host_app_authorization_required");
    try {
      await applicationContacts.rename(contactId, { displayName, expectedDisplayName, expectedHelloLynkId });
    } catch (error) {
      if (error?.code === "contact_name_conflict") throw hostApplicationFailure("host_app_revision_conflict");
      if (/^contact_(?:display_name|hellolynk_id|id)_/.test(String(error?.code || ""))) {
        throw hostApplicationFailure("host_app_input_invalid");
      }
      throw error;
    }
    await publishApplicationChange("contacts_changed", contactId);
  }

  async function renameContactInstance(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof applicationContacts.renameInstance !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const request = context.request;
    if (!request.expectedHelloLynkId.startsWith(`hellolynk:${stableRegion}:`)
      || request.recipientDelegateId === context.delegateId
      || (request.expectedHelloLynkId === endpoints.get(context.delegateId)?.hellolynkId
        && request.expectedPrincipalId !== tuple.principalId)) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    try {
      await applicationContacts.renameInstance(request.contactId, {
        delegateId: request.recipientDelegateId,
        displayName: request.displayName,
        expectedDisplayName: request.expectedDisplayName,
        expectedHelloLynkId: request.expectedHelloLynkId,
        expectedPrincipalId: request.expectedPrincipalId,
      });
    } catch (error) {
      if (error?.code === "contact_instance_name_conflict") throw hostApplicationFailure("host_app_revision_conflict");
      if (/^contact_(?:display_name|hellolynk_id|delegate|id)_/.test(String(error?.code || ""))) {
        throw hostApplicationFailure("host_app_input_invalid");
      }
      throw error;
    }
    await publishApplicationChange("contacts_changed", request.contactId);
  }

  async function deleteContactInstance(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof applicationContacts.removeInstance !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    await applicationContacts.removeInstance(context.request.contactId, context.request.recipientDelegateId);
    await publishApplicationChange("contacts_changed", context.request.contactId);
  }

  async function resolveSavedInstance(input, delegateId) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (!endpoints.has(delegateId) || typeof applicationContacts.resolveInstance !== "function") {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    const recipientDelegateId = safeId(input.recipientDelegateId, "host_app_recipient_delegate_invalid");
    if (recipientDelegateId === delegateId) throw hostApplicationFailure("host_app_authorization_required");
    const contact = (await applicationContacts.listForDelegate(delegateId)).find((item) => (
      input.contactId ? item.contactId === input.contactId : item.hellolynkId === input.recipientHelloLynkId
    ));
    if (!contact || (input.recipientHelloLynkId && contact.hellolynkId !== input.recipientHelloLynkId)
      || !contact.hellolynkId.startsWith(`hellolynk:${stableRegion}:`)) {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    try {
      return await applicationContacts.resolveInstance(contact.contactId, recipientDelegateId);
    } catch (error) {
      if (["contact_not_found", "contact_instance_not_found"].includes(error?.code)) {
        throw hostApplicationFailure("host_app_record_not_found");
      }
      throw error;
    }
  }

  function savedInstanceRoute(target) {
    if (target.principalId !== tuple.principalId || !endpoints.has(target.recipientDelegateId)) {
      return { routeKind: "instance_direct", recipientDelegateId: target.recipientDelegateId };
    }
    return { routeKind: "owned_delegate", recipientDelegateId: target.recipientDelegateId,
      recipientHostId: tuple.hostInstallationId };
  }


  async function applicationContactsUpsert(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    const contactWriteKeys = Object.keys(context.request || {}).sort();
    const allowedContactWriteKeys = Object.hasOwn(context.request || {}, "contactId")
      ? ["contactId", "displayName", "hellolynkId"]
      : ["displayName", "hellolynkId"];
    if (contactWriteKeys.length !== allowedContactWriteKeys.length
      || contactWriteKeys.some((key, index) => key !== allowedContactWriteKeys[index])) {
      // Contact edits must not inject internal E2EE identity fingerprints.
      // Neither the direct application route nor Workbench may transport one.
      throw hostApplicationFailure("host_app_input_invalid");
    }
    const ownHelloLynkId = endpoints.get(context.delegateId)?.hellolynkId;
    if (!ownHelloLynkId || context.request.hellolynkId !== ownHelloLynkId) {
      if (!options.humanRelationships
        || typeof options.humanRelationships.assertActiveRelationship !== "function") {
        throw hostApplicationFailure("host_app_relationship_status_unavailable");
      }
      try {
        await options.humanRelationships.assertActiveRelationship({
          hellolynkId: context.request.hellolynkId,
        });
      } catch (error) {
        if (error?.code === "human_relationship_active_relationship_required") {
          throw hostApplicationFailure("host_app_contact_relationship_not_active");
        }
        throw hostApplicationFailure("host_app_relationship_status_unavailable");
      }
    }
    let stored;
    try {
      stored = await applicationContacts.upsert(context.request);
    } catch (error) {
      if (/^contact_(?:display_name|hellolynk_id|safety_code|id|capacity)/.test(String(error?.code || ""))) {
        throw hostApplicationFailure("host_app_input_invalid");
      }
      throw error;
    }
    const contact = projectContactMutation(stored);
    await publishApplicationChange("contacts_changed", contact.contactId);
    return { contact };
  }

  async function applicationContactsRemove(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    const contactId = context.request.contactId;
    const removed = await applicationContacts.remove(contactId);
    if (removed) await publishApplicationChange("contacts_changed", contactId);
    return { contactId, removed: Boolean(removed) };
  }

  async function applicationContactAutonomousSendAuthorization(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    let stored;
    try {
      stored = await applicationContacts.setAutonomousSendAuthorization(
        context.request.contactId,
        context.delegateId,
        context.request.enabled,
        context.request.recipientDelegateId,
      );
    } catch (error) {
      if (["contact_not_found", "contact_instance_not_found"].includes(error?.code)) throw hostApplicationFailure("host_app_record_not_found");
      if (/^contact_(?:authorization|delegate)/.test(String(error?.code || ""))) {
        throw hostApplicationFailure("host_app_input_invalid");
      }
      throw error;
    }
    const contact = projectContactAuthorizationMutation(stored);
    await publishApplicationChange("contacts_changed", contact.contactId, context.delegateId);
    return { contact };
  }


  async function applicationContactRequestsClearResolved() {
    if (!options.humanRelationships
      || typeof options.humanRelationships.clearResolved !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const result = await options.humanRelationships.clearResolved();
    if (!Number.isSafeInteger(result?.deletedCount) || result.deletedCount < 0
      || result.localOnly !== true) {
      throw hostApplicationFailure("host_app_contact_request_clear_response_invalid");
    }
    if (result.deletedCount > 0) {
      await publishApplicationChange("contact_requests_changed", "resolved-contact-requests");
    }
    const resumeScheduled = scheduleInboundResumeAfterHumanCleanup(CONTACT_REQUEST_LOCAL_CAPACITY_CODES);
    return {
      deletedCount: result.deletedCount,
      localOnly: result.localOnly === true,
      inboundResume: resumeScheduled ? "resume_scheduled" : "not_applicable",
      modelCalls: 0,
    };
  }

  async function applicationAuthorizedContactsList(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    const contacts = (await applicationContacts.listAuthorizedForDelegate(context.delegateId)).map(projectAuthorizedContact);
    if (!context.request?.recipientDelegateId) return { contacts };
    const authorization = await resolveAuthorizedSendRequest(context);
    const { contactId: _contact, recipientDelegateId: _recipient, ...query } = context.request;
    const nativeConversations = await queryOwnNativeDirectory(context.delegateId, authorization, query);
    await context.revalidateCapability();
    await resolveAuthorizedSendRequest(context);
    return { contacts, nativeConversations };
  }

  async function localNativeDirectory(endpoint, query) {
    if (!endpoint?.nativeDirectoryAdapterId) return nativeDirectoryResult({ conversations: [], coverage: "unavailable",
      available: false, exactTargetSupported: false, reason: "native_directory_unavailable" });
    try {
      await endpoint.assertNativeDirectoryCurrent?.();
      const result = await queryLocalNativeConversations({ runtimeRoot, region: tuple.region, principalId: tuple.principalId,
        delegateId: endpoint.delegateId, adapterId: endpoint.nativeDirectoryAdapterId }, query);
      await endpoint.assertNativeDirectoryCurrent?.();
      return result;
    } catch (error) {
      if (error?.code === "native_directory_cursor_invalid") throw error;
      throw hostApplicationFailure("native_directory_unavailable");
    }
  }

  async function queryOwnNativeDirectory(delegateId, authorization, query) {
    if (authorization.principalId !== tuple.principalId) throw hostApplicationFailure("native_directory_own_ai_only");
    query = nativeConversationQuery(query);
    const local = endpoints.get(authorization.recipientDelegateId);
    if (local) return localNativeDirectory(local, query);
    return queryPeerNativeDirectory(delegateId, authorization, { kind: "request", query });
  }

  async function queryPeerNativeDirectory(delegateId, authorization, request) {
    const sender = endpoints.get(delegateId);
    if (!sender?.outbound?.sendDirectory) throw hostApplicationFailure("native_directory_unavailable");
    const friend = request.kind === "friend_target_request";
    const unavailable = friend ? null : nativeDirectoryResult({ conversations: [], coverage: "unavailable",
      available: false, exactTargetSupported: false, reason: "native_directory_unavailable" });
    const requestId = "directory_" + crypto.randomUUID();
    let timer;
    const response = new Promise(resolve => {
      timer = setTimeout(() => resolve(unavailable), 12_000);
      directoryPending.set(requestId, { delegateId, peerDelegateId: authorization.recipientDelegateId,
        peerPrincipalId: authorization.principalId, peerHelloLynkId: authorization.hellolynkId, friend, resolve });
    });
    try {
      const sent = await sender.outbound.sendDirectory({ clientMessageId: "hellolynk_local_" + crypto.randomUUID(), recipientHelloLynkId: authorization.hellolynkId,
        recipientPrincipalId: authorization.principalId, route: savedInstanceRoute(authorization),
        nativeDirectory: { ...request, requestId } });
      if (["recipient_e2ee_device_offline", "recipient_offline"].includes(sent?.status))
        throw hostApplicationFailure("recipient_e2ee_device_offline");
      if (friend && (sent?.status !== "acknowledged_by_recipient_local_store"
        || typeof sent.targetConnectionId !== "string" || !SAFE_ID.test(sent.targetConnectionId))) return unavailable;
      if (!["acknowledged_by_recipient_local_store", "delivered_to_live_connection"].includes(sent?.status)) return unavailable;
      const result = await response;
      return friend && result ? { ...result, friendTargetConnectionId: sent.targetConnectionId } : result;
    } catch (error) {
      if (friend && ["ordinary_message_not_permitted", "e2ee_recipient_external_contact_disabled"].includes(error?.code))
        throw hostApplicationFailure("host_app_authorization_required");
      if (["e2ee_peer_identity_pin_mismatch",
        "recipient_e2ee_device_offline", "e2ee_prekey_claim_rate_limited"].includes(error?.code)) throw hostApplicationFailure(error.code);
      throw hostApplicationFailure("native_directory_unavailable");
    } finally { clearTimeout(timer); directoryPending.delete(requestId); }
  }

  function isFriendTargetFrame(opened, localDelivery) {
    // The authenticated relay checks the active friendship, blocks and exact
    // exposed AI on both the key claim and the write. Local delivery is for
    // one account only. Receiving doesn't require saving the sender's AI.
    return localDelivery !== true && opened.e2eeVersion === 2 && opened.routeKind === "instance_direct"
      && opened.intentSource === "human_preauthorized_contact";
  }

  function friendTargetKey(opened, endpoint, clientMessageId, targetConversationId) {
    return JSON.stringify([opened.senderPrincipalId, opened.senderDelegateId, opened.senderIdentityKeyId,
      endpoint.delegateId, clientMessageId, targetConversationId]);
  }

  function admitFriendTarget(opened, endpoint, clientMessageId) {
    const key = friendTargetKey(opened, endpoint, clientMessageId, opened.targetConversationId);
    const expires = friendTargets.get(key) ?? 0;
    // The store keeps the first disposition on replay, even after a restart.
    return expires > nowMs(clock) ? "direct" : "held";
  }

  function rememberFriendTarget(opened, endpoint, clientMessageId, targetConversationId) {
    const now = nowMs(clock);
    for (const [key, expires] of friendTargets) {
      if (expires <= now) friendTargets.delete(key);
    }
    const key = friendTargetKey(opened, endpoint, clientMessageId, targetConversationId);
    if (!friendTargets.has(key) && friendTargets.size >= 1024) return false;
    // Allow time to prepare a ciphertext after the lookup. An unused grant is
    // tied to this message, sending key and local AI for its entire lifetime.
    friendTargets.set(key, now + DIRECT_TEXT_E2EE_MAX_TTL_MS + 90_000);
    return true;
  }

  function uniqueTitleTarget(catalog) {
    const [row] = catalog.conversations;
    return catalog.available && catalog.exactTargetSupported && catalog.conversations.length === 1
      && ["idle", "active", "notLoaded"].includes(row?.state) ? row.targetConversationId : null;
  }

  async function queryFriendTarget(delegateId, authorization, title, clientMessageId) {
    const result = await queryPeerNativeDirectory(delegateId, authorization, { kind: "friend_target_request", title, clientMessageId });
    if (!result) throw hostApplicationFailure("native_target_unsupported_or_unavailable");
    if (!result.targetConversationId) throw hostApplicationFailure("native_target_title_not_unique");
    return { ...result, targetConversationTitle: title };
  }

  async function consumeNativeFrame(event, opened, endpoint, localDelivery) {
    // A reserved protocol frame is never a chat message. A malformed or
    // unauthorized frame cannot stop the Host or be sent to a model as text.
    // Storage/commit errors still propagate; only validated content is dropped.
    await opened.commit();
    let acknowledged = true;
    if (!localDelivery) try { await options.transport.acknowledge({ event, kind: "message", persisted: {} }); }
    catch (error) {
      const deadline = typeof event.ackDeadlineAt === "string" ? Date.parse(event.ackDeadlineAt) : NaN;
      if (error?.code !== "relay_ack_delivery_attempt_not_found" || error?.httpStatus !== 409
        || !Number.isFinite(deadline) || new Date(deadline).toISOString() !== event.ackDeadlineAt
        || nowMs(clock) < deadline) throw error;
      acknowledged = false;
    }
    if (acknowledged && !localDelivery && preKeyRefillMethod(endpoint)) requestPreKeyRefill(endpoint);
    return { acknowledged, duplicate: false };
  }

  async function handleNativeDirectory(event, opened, endpoint, localDelivery) {
    const control = opened.nativeDirectory;
    const friend = control.kind === "friend_target_request" || control.kind === "friend_target_response";
    if (opened.replyToClientMessageId || opened.targetConversationId || opened.e2eeVersion !== 2
      || (friend ? opened.senderPrincipalId === tuple.principalId || !isFriendTargetFrame(opened, localDelivery)
        : opened.senderPrincipalId !== tuple.principalId)) return consumeNativeFrame(event, opened, endpoint, localDelivery);
    // Read-only control traffic has no human unread state and never reaches a
    // model. Consume its authenticated prekey before acknowledging transport.
    const consumed = await consumeNativeFrame(event, opened, endpoint, localDelivery);
    if (control.kind === "response" || control.kind === "friend_target_response") {
      const pending = directoryPending.get(control.requestId);
      if (pending?.delegateId === endpoint.delegateId && pending.peerDelegateId === opened.senderDelegateId
        && pending.peerPrincipalId === opened.senderPrincipalId && pending.peerHelloLynkId === opened.senderHelloLynkId
        && pending.friend === friend) pending.resolve(friend
        ? { targetConversationId: control.targetConversationId } : nativeDirectoryResult(control.result));
    } else {
      // Do not await the response on the inbound event stream: two simultaneous
      // queries must not wait for each other's receiver to process an ACK.
      void (async () => {
        const query = friend ? { title: control.title, exactTitle: true } : control.query;
        let result;
        try { result = await localNativeDirectory(endpoint, query); }
        catch { result = nativeDirectoryResult({ conversations: [], coverage: "unavailable", available: false,
          exactTargetSupported: false, reason: "native_directory_unavailable" }); }
        let response = { kind: "response", requestId: control.requestId, result };
        if (friend) {
          const target = uniqueTitleTarget(result);
          response = { kind: "friend_target_response", requestId: control.requestId,
            targetConversationId: target && rememberFriendTarget(opened, endpoint, control.clientMessageId, target) ? target : null };
        }
        await endpoint.outbound.sendDirectory({ clientMessageId: "hellolynk_local_" + crypto.randomUUID(),
          recipientHelloLynkId: opened.senderHelloLynkId, recipientPrincipalId: opened.senderPrincipalId,
          route: { routeKind: "instance_direct", recipientDelegateId: opened.senderDelegateId },
          nativeDirectory: response });
      })().catch(() => {}); // The caller times out; control queries never resend user messages.
    }
    return consumed;
  }

  async function applicationAuthorizedInboxActivate(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    if (typeof applicationInbox.activateInboxReader !== "function") {
      throw hostApplicationFailure("host_app_unavailable");
    }
    await context.revalidateCapability();
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof applicationContacts.listReadableRoutesForDelegate !== "function") throw hostApplicationFailure("host_app_unavailable");
    // Activation records the owner's durable inbox boundary, not a contact
    // grant. It needs no contact labels and must not reread them on idle polls.
    await applicationInbox.activateInboxReader(context.adapterId, context.delegateId);
    await context.revalidateCapability();
    return { active: true };
  }

  async function applicationModelInbox(context) {
    const identity = { adapterId: context.adapterId, delegateId: context.delegateId };
    const child = (query, extra = {}) => ({ ...context, request: query, ...extra });
    await context.revalidateCapability();
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    if (typeof applicationInbox.getInboxNativeAssignment !== "function") throw hostApplicationFailure("host_app_unavailable");
    return runModelInbox(context.request, {
      nativeScope: { runtimeRoot, region: tuple.region, principalId: tuple.principalId, ...identity },
      assignment: query => applicationInbox.getInboxNativeAssignment({ ...identity, ...query }),
      assignments: localMessageIds => applicationInbox.getInboxNativeAssignments({ ...identity, localMessageIds }),
      metadata: async query => {
        const message = await applicationInbox.getIncoming(query.localMessageId);
        const binding = message && getMessageConversationBinding(message, tuple);
        if (!message || message.friendTargetHeld || message.messageType === "local-deleted")
          throw hostApplicationFailure("host_app_record_not_found");
        if (!binding || binding.localDelegateId !== context.delegateId || query.conversationKey !== instanceConversationKey(binding)) {
          throw hostApplicationFailure("host_app_authorization_required");
        }
        return projectAuthorizedInboxMetadata(message, null, binding);
      },
      list: query => applicationAuthorizedInboxMessages(child(query, { modelInbox: true })),
      pending: query => applicationAuthorizedInboxMessages(child(query, { modelInbox: true }), true, query),
      read: query => applicationAuthorizedInboxRead(child(query)),
      claim: query => query.batchId ? applicationAuthorizedInboxBatch(child(query), "Claim") : applicationAuthorizedInboxClaim(child(query)),
    });
  }

  async function inboxWakeBoundary(context) {
    return await applicationInbox.getInboxReaderBoundary?.(context.adapterId, context.delegateId) ?? null;
  }

  async function applicationAuthorizedInboxMessages(context, pendingOnly = false, query = null) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof applicationContacts.listReadableRoutesForDelegate !== "function") return query ? { messages: [], nextCursor: null } : { messages: [] };
    await context.revalidateCapability();
    const indexedPending = pendingOnly && typeof applicationInbox.listPendingInboxCandidates === "function";
    if (pendingOnly && !indexedPending && (query || typeof applicationInbox.listInboxClaimIds !== "function")) throw hostApplicationFailure("host_app_unavailable");
    const afterSeq = await inboxWakeBoundary(context);
    if (pendingOnly && afterSeq == null) return query ? { messages: [], nextCursor: null } : { messages: [] };
    const target = query?.localMessageId == null ? null : query;
    let nextCursor = null;
    const consumed = pendingOnly && !indexedPending ? new Set(await applicationInbox.listInboxClaimIds(context.delegateId)) : null;
    let storedMessages;
    const before = pendingOnly ? null : context.request?.before ?? null;
    const indexedHistory = !pendingOnly && typeof applicationInbox.listInboxMessagesForDelegate === "function";
    if (before != null && !indexedHistory) throw hostApplicationFailure("host_app_unavailable");
    if (!pendingOnly && context.request?.unreadOnly === true) {
      if (typeof applicationInbox.listInboxMessagesForDelegate !== "function") throw hostApplicationFailure("host_app_unavailable");
      storedMessages = await applicationInbox.listInboxMessagesForDelegate(context.delegateId, {
        unreadOnly: true, limit: context.request.limit, scope: localHistoryScope(context),
      });
    } else if (indexedPending) {
      // GET is always the first page. Receivers scan later pages with their
      // own cursor or recheck one message; the Host keeps no shared position.
      storedMessages = await applicationInbox.listPendingInboxCandidates({
        delegateId: context.delegateId, afterSeq: Math.max(afterSeq, query?.cursor ?? 0),
        limit: target ? 1 : 1000, modelPending: context.modelInbox === true, ...(target ? { localMessageId: target.localMessageId } : {}),
      });
      // Ownership is checked below; contact membership does not control access
      // to already received data. Pages follow stored rows, not visible results.
      if (!target && storedMessages.length === 1000) nextCursor = storedMessages.at(-1).receiptSeq;
    } else if (indexedHistory) {
      try {
        storedMessages = await applicationInbox.listInboxMessagesForDelegate(context.delegateId, {
          limit: context.modelInbox ? 1000 : AUTHORIZED_INBOX_HISTORY_LIMIT, scope: localHistoryScope(context), ...(before == null ? {} : { before }),
        });
      } catch (error) {
        // The page anchor must be an incoming message of this AI and account.
        if (error?.code === "local_history_cursor_invalid") throw hostApplicationFailure("host_app_record_not_found");
        throw error;
      }
    } else storedMessages = typeof applicationInbox.listInboxMessagesForDelegate === "function"
      ? await applicationInbox.listInboxMessagesForDelegate(context.delegateId, {})
      : await applicationInbox.list();
    // Contacts only label records in this response. Empty indexed pages are
    // common while waiting for mail; don't read/parse every contact for them.
    // Nonempty pages still get fresh labels, without a cross-request cache.
    const authorized = new Map((storedMessages.length === 0 ? []
      : await applicationContacts.listReadableRoutesForDelegate(context.delegateId))
      .map((contact) => [JSON.stringify([contact.hellolynkId, contact.recipientDelegateId]), contact]));
    const messages = [];
    if (pendingOnly) storedMessages.sort((left, right) => (left.receiptSeq ?? 0) - (right.receiptSeq ?? 0));
    for (const message of storedMessages) {
      if (message?.direction !== "incoming" || message.friendTargetHeld) continue;
      const binding = getMessageConversationBinding(message, tuple);
      if (!binding || binding.localDelegateId !== context.delegateId) continue;
      const contact = authorized.get(JSON.stringify([
        message.peerHelloLynkId || message.senderHelloLynkId, binding.peerDelegateId,
      ]));
      const label = contact?.principalId === binding.peerPrincipalId ? contact : null;
      const metadata = projectAuthorizedInboxMetadata(message, label, binding, afterSeq);
      if (pendingOnly && (!metadata.wakeEligible
        || consumed?.has(metadata.localMessageId) || (target && metadata.conversationKey !== target.conversationKey))) continue;
      messages.push(context.modelInbox && pendingOnly ? { ...metadata, receiptSeq: message.receiptSeq } : metadata);
      if (pendingOnly && messages.length === 1000) break;
    }
    await context.revalidateCapability();
    if (query) return { messages, nextCursor };
    return {
      // History browsing is a recent context window, separate from the durable
      // automatic wake window. Older unhandled messages remain manually claimable.
      // The index already orders newest first; keeping that order lets the next
      // explicit page start exactly after this page's last message.
      messages: pendingOnly ? messages : (indexedHistory ? messages : messages.sort((left, right) =>
        String(right.createdAt).localeCompare(String(left.createdAt)))).slice(0, context.modelInbox ? 1000 : AUTHORIZED_INBOX_HISTORY_LIMIT),
    };
  }

  async function applicationAuthorizedInboxRead(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    const afterSeq = await inboxWakeBoundary(context);
    if (typeof applicationInbox.readIncomingForModel !== "function") throw hostApplicationFailure("host_app_unavailable");
    const message = await applicationInbox.readIncomingForModel(context.request.localMessageId,
      (value, highWater, automatic) => authorizeInboxMessage(context, value, afterSeq, highWater, false, false, automatic));
    if (message.humanReadAutomatically === true) {
      await publishApplicationChange("inbox_changed", context.request.localMessageId, context.delegateId).catch(() => undefined);
      scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
    }
    return { message };
  }

  async function authorizeInboxMessage(context, message, afterSeq, highWater, requireWake = false, finish = false, automatic = false) {
    await context.revalidateCapability();
    if (!message || message.direction !== "incoming" || message.friendTargetHeld || (message.messageType === "local-deleted" && !finish)) {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    const binding = getMessageConversationBinding(message, tuple);
    if (!binding || binding.localDelegateId !== context.delegateId
      || context.request.conversationKey !== instanceConversationKey(binding)) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    const contacts = await applicationContacts.listReadableRoutesForDelegate(context.delegateId);
    const contact = contacts.find((candidate) => candidate.principalId === binding.peerPrincipalId
      && candidate.recipientDelegateId === binding.peerDelegateId
      && candidate.hellolynkId === (message.peerHelloLynkId || message.senderHelloLynkId)) || null;
    if (finish && message.messageType === "local-deleted") {
      await context.revalidateCapability();
      return {}; // Completing the existing claim exposes no erased body.
    }
    const projected = projectAuthorizedInboxMessage(message, contact, binding, afterSeq, automatic);
    if (requireWake && !projected.wakeEligible) throw hostApplicationFailure("host_app_authorization_required");
    await context.revalidateCapability();
    return projected;
  }

  async function applicationAuthorizedInboxBatch(context, operation) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    await context.revalidateCapability();
    const method = ({ Reserve: "reserveInboxBatch", Open: "listInboxBatches", Attempt: "attemptInboxBatch",
      Confirm: "confirmInboxBatch", Cancel: "cancelInboxBatch", Expire: "expireInboxBatch",
      Closed: "closeInboxBatch", Claim: "claimInboxBatch" })[operation];
    if (typeof applicationInbox[method] !== "function") throw hostApplicationFailure("host_app_unavailable");
    // Labels are read once for the whole batch. Ownership is checked per record;
    // a removed contact never revokes access to this AI's already received mail.
    const contacts = operation === "Claim"
      ? await applicationContacts.listReadableRoutesForDelegate(context.delegateId) : [];
    const labels = new Map(contacts.map(contact => [JSON.stringify([contact.hellolynkId, contact.recipientDelegateId]), contact]));
    const authorize = (message, afterSeq, highWater, automatic = false) => {
      if (message.friendTargetHeld) throw hostApplicationFailure("host_app_record_not_found");
      const binding = getMessageConversationBinding(message, tuple);
      if (!binding || binding.localDelegateId !== context.delegateId || message.direction !== "incoming") {
        throw hostApplicationFailure("host_app_authorization_required");
      }
      if (operation !== "Claim") return null;
      const label = labels.get(JSON.stringify([message.peerHelloLynkId || message.senderHelloLynkId, binding.peerDelegateId]));
      return projectAuthorizedInboxMessage(message, label?.principalId === binding.peerPrincipalId ? label : null, binding, afterSeq, automatic);
    };
    const result = await applicationInbox[method]({ ...context.request, adapterId: context.adapterId, delegateId: context.delegateId }, authorize);
    await context.revalidateCapability();
    if (["Reserve", "Expire", "Claim", "Closed"].includes(operation)) {
      await publishApplicationChange("inbox_changed", context.delegateId, context.delegateId).catch(() => undefined);
    }
    if (operation === "Closed" || result.messages?.some(message => message.humanReadAutomatically === true)) {
      scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
    }
    return result;
  }

  async function applicationAuthorizedInboxClaim(context, finish = false) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    const method = finish ? "finishInboxClaim" : "claimInboxMessage";
    if (typeof applicationInbox[method] !== "function") throw hostApplicationFailure("host_app_unavailable");
    try {
      const result = await applicationInbox[method]({ ...context.request, adapterId: context.adapterId, delegateId: context.delegateId },
        (message, afterSeq, highWater, automatic) => authorizeInboxMessage(context, message, afterSeq, highWater, true, finish, automatic));
      if (result.claimed === true) await publishApplicationChange("inbox_changed", context.request.localMessageId).catch(() => undefined);
      if (result.message?.humanReadAutomatically === true) scheduleInboundResumeAfterHumanCleanup(MESSAGE_LOCAL_CAPACITY_CODES);
      return result;
    } catch (error) {
      if (error?.code === "local_inbox_claim_ineligible") throw hostApplicationFailure("host_app_authorization_required");
      if (["local_inbox_claim_mismatch", "local_inbox_claim_terminal"].includes(error?.code)) {
        throw hostApplicationFailure("host_app_state_conflict");
      }
      throw error;
    }
  }

  function contactRequestConversationKey(delegateId) {
    return `requests_${crypto.createHash("sha256")
      .update("hellolynk-contact-request-conversation-v1\n")
      .update(JSON.stringify([stableRegion, tuple.principalId, delegateId]))
      .digest("hex").slice(0, 40)}`;
  }

  function projectAuthorizedContactRequestMetadata(record, context) {
    const request = projectContactRequest(record);
    return {
      localRecordId: request.localRecordId,
      conversationKey: contactRequestConversationKey(context.delegateId),
      localDelegateId: context.delegateId,
      sender: request.sender,
      state: request.state,
      receivedAt: request.receivedAt,
    };
  }

  async function applicationAuthorizedContactRequestsList(context) {
    requireApplicationStore(applicationContactRequests, "neutral_host_app_contact_requests_unavailable");
    await context.revalidateCapability();
    const requests = await applicationContactRequests.listForHuman();
    await context.revalidateCapability();
    return { requests: requests.map((record) => projectAuthorizedContactRequestMetadata(record, context)) };
  }

  async function applicationAuthorizedContactRequestRead(context) {
    requireApplicationStore(applicationContactRequests, "neutral_host_app_contact_requests_unavailable");
    await context.revalidateCapability();
    if (context.request.conversationKey !== contactRequestConversationKey(context.delegateId)) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    const requests = await applicationContactRequests.listForHuman();
    const record = requests.find((item) => item.localRecordId === context.request.localRecordId);
    if (!record) throw hostApplicationFailure("host_app_record_not_found");
    await context.revalidateCapability();
    return { request: {
      ...projectAuthorizedContactRequestMetadata(record, context),
      introText: projectContactRequest(record).introText,
      source: "hellolynk_contact_request",
      externalContentIsUntrustedData: true,
      readDoesNotMarkRead: true,
    } };
  }

  async function applicationAuthorizedSend(context) {
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    let authorization = await resolveAuthorizedSendRequest(context);
    const { targetConversationId, targetConversationTitle, clientMessageId } = context.request;
    let target = {};
    if (targetConversationTitle || targetConversationId) {
      if (authorization.principalId !== tuple.principalId) {
        if (!targetConversationTitle) throw hostApplicationFailure("native_target_title_required");
        target = await queryFriendTarget(context.delegateId, authorization, targetConversationTitle, clientMessageId);
      } else {
        const query = targetConversationTitle ? { title: targetConversationTitle, exactTitle: true } : { targetConversationId };
        const catalog = await queryOwnNativeDirectory(context.delegateId, authorization, query);
        if (!catalog.exactTargetSupported) throw hostApplicationFailure("native_target_unsupported_or_unavailable");
        if (targetConversationTitle) {
          const resolved = uniqueTitleTarget(catalog);
          if (!resolved) throw hostApplicationFailure("native_target_title_not_unique");
          target = { targetConversationId: resolved };
        } else {
          if (catalog.conversations.some(row => row.targetConversationId === targetConversationId && ["archived", "deleted"].includes(row.state)))
            throw hostApplicationFailure("native_target_unavailable");
          target = { targetConversationId };
        }
      }
      await context.revalidateCapability();
      authorization = await recheckTargetRecipient(context, authorization);
    }
    return sendAuthorizedContactText(context, authorization, null, target);
  }

  async function recheckTargetRecipient(context, original) {
    const current = await resolveAuthorizedSendRequest(context);
    if (current.principalId !== original.principalId || current.hellolynkId !== original.hellolynkId
      || current.recipientDelegateId !== original.recipientDelegateId) throw hostApplicationFailure("host_app_authorization_required");
    return current;
  }

  async function resolveAuthorizedSendRequest(context) {
    let authorization;
    try {
      authorization = await applicationContacts.resolveAuthorizedSend(
        context.request.contactId,
        context.delegateId,
        context.request.recipientDelegateId,
      );
    } catch (error) {
      if (["contact_not_found", "contact_instance_not_found"].includes(error?.code)) throw hostApplicationFailure("host_app_record_not_found");
      if (error?.code === "contact_autonomous_send_not_authorized") {
        throw hostApplicationFailure("host_app_authorization_required");
      }
      throw error;
    }
    return authorization;
  }

  async function applicationAuthorizedReply(context) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    if (typeof applicationContacts.resolveAuthorizedReply !== "function") {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    const message = await applicationInbox.getIncoming(context.request.localMessageId);
    if (!message || message.direction !== "incoming" || message.friendTargetHeld || message.messageType === "local-deleted") {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    const binding = getMessageConversationBinding(message, tuple);
    if (!binding || binding.localDelegateId !== context.delegateId
      || context.request.conversationKey !== instanceConversationKey(binding)) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    let authorization;
    try {
      authorization = await applicationContacts.resolveAuthorizedReply(
        message.peerHelloLynkId || message.senderHelloLynkId, context.delegateId, binding.peerDelegateId,
      );
    } catch (error) {
      if (["contact_not_found", "contact_instance_not_found", "contact_continuous_read_not_authorized",
        "contact_autonomous_send_not_authorized"].includes(error?.code)) {
        throw hostApplicationFailure("host_app_authorization_required");
      }
      throw error;
    }
    if (authorization.principalId !== binding.peerPrincipalId) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    return sendAuthorizedContactText(context, authorization, message.clientMessageId);
  }

  async function sendAuthorizedContactText(context, authorization, replyToClientMessageId = null, target = {}) {
    const endpoint = endpoints.get(context.delegateId);
    if (!endpoint?.outbound || typeof endpoint.outbound.send !== "function") {
      throw hostApplicationFailure("host_app_unavailable");
    }
    let result;
    try {
      result = await sendOutboundOnce({
        endpoint,
        delegateId: context.delegateId,
        clientMessageId: context.request.clientMessageId,
        input: {
          clientMessageId: context.request.clientMessageId,
          recipientHelloLynkId: authorization.hellolynkId,
          recipientPrincipalId: authorization.principalId,
          recipientDelegateId: authorization.recipientDelegateId,
          region: tuple.region,
          route: savedInstanceRoute(authorization),
          text: context.request.text,
          intentSource: "human_preauthorized_contact",
          ...(replyToClientMessageId ? { replyToClientMessageId } : {}),
          ...target,
        },
      });
    } catch (error) {
      if (error?.code === "host_app_reply_target_deleted" || error?.code === "reply_target_deleted") throw hostApplicationFailure("host_app_reply_target_deleted");
      if (["native_directory_unavailable", "e2ee_peer_identity_pin_mismatch",
        "recipient_e2ee_device_offline", "e2ee_prekey_claim_rate_limited", "relay_request_body_too_large"].includes(error?.code)) throw hostApplicationFailure(error.code);
      throw hostApplicationFailure("host_app_send_failed");
    }
    return {
      accepted: true,
      authorization: authorization.authorization,
      clientMessageId: context.request.clientMessageId,
      contactId: authorization.contactId,
      // Keep the recipient-store receipt when this call actually received one.
      // The durable outbox intentionally retains its coarser delivery status;
      // neither status means the human read it or the model executed it.
      status: safeId(result?.relay?.status === "acknowledged_by_recipient_local_store"
        ? result.relay.status : result?.status || "accepted", "neutral_host_app_outbox_record_invalid"),
    };
  }

  async function applicationContactRequestsList() {
    requireApplicationStore(applicationContactRequests, "neutral_host_app_contact_requests_unavailable");
    // Remote reconciliation is best-effort for a local-first human UI. A cloud
    // outage must not hide already authenticated and locally persisted requests;
    // each local record is still validated below and any malformed record keeps
    // the endpoint fail-closed.
    await refreshHumanRelationshipsBestEffort();
    return {
      requests: (await applicationContactRequests.listForHuman())
        .map(projectContactRequest),
    };
  }

  async function applicationContactRequestRespond(context) {
    requireApplicationStore(
      applicationContactRequests,
      "neutral_host_app_contact_requests_unavailable",
    );
    if (!options.humanRelationships || typeof options.humanRelationships.decide !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const requestId = context.request.requestId;
    const local = (await applicationContactRequests.listForHuman()).find((record) => (
      record?.humanOnly === true
      && record?.modelVisibility === "none"
      && record?.serverContactRequestId === requestId
    ));
    if (!local) throw hostApplicationFailure("host_app_record_not_found");
    if (!Object.hasOwn(local, "decisionOutcome")
      || !Object.hasOwn(local, "decisionAction")
      || local.decisionOutcome != null) {
      throw hostApplicationFailure("host_app_contact_request_decision_unresolved");
    }
    if (local.state !== "pending" || local.actionReady !== true
      || local.decisionOutcome != null || local.decisionAction != null) {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    await options.humanRelationships.decide({
      requestId,
      action: context.request.decision,
    });
    await publishApplicationChange(
      "contact_requests_changed",
      safeApplicationId(local.localRecordId, "neutral_host_app_contact_request_record_invalid"),
    );
  }

  async function applicationContactRequestRecover(context) {
    requireApplicationStore(
      applicationContactRequests,
      "neutral_host_app_contact_requests_unavailable",
    );
    if (!options.humanRelationships
      || typeof options.humanRelationships.recoverDecision !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const requestId = context.request.requestId;
    const local = (await applicationContactRequests.listForHuman()).find((record) => (
      record?.humanOnly === true
      && record?.modelVisibility === "none"
      && record?.serverContactRequestId === requestId
    ));
    if (!local) throw hostApplicationFailure("host_app_record_not_found");
    const recoverable = local.state === "pending"
      && local.actionReady === false
      && ((local.decisionOutcome === "unknown"
          && ["accept", "reject", "block"].includes(local.decisionAction))
        || (local.decisionOutcome === "recovery-required" && local.decisionAction == null));
    if (!recoverable) {
      throw hostApplicationFailure("host_app_contact_request_recovery_not_required");
    }
    await options.humanRelationships.recoverDecision({ requestId });
    await publishApplicationChange(
      "contact_requests_changed",
      safeApplicationId(local.localRecordId, "neutral_host_app_contact_request_record_invalid"),
    );
  }

  async function applicationContactRequestCancel(context) {
    if (!options.humanRelationships
      || typeof options.humanRelationships.cancel !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const result = await options.humanRelationships.cancel({
      requestId: context.request.requestId,
    });
    await publishApplicationChange("contact_requests_changed", result.requestId);
  }

  async function applicationRelationshipEnd(context) {
    if (!options.humanRelationships
      || typeof options.humanRelationships.endRelationship !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const result = await options.humanRelationships.endRelationship({
      relationshipId: context.request.relationshipId,
    });
    if (result.localHistoryDeleted !== false) {
      throw hostApplicationFailure("host_app_relationship_history_invariant_failed");
    }
    await publishApplicationChange("relationships_changed", result.relationship.relationshipId);
  }

  async function applicationBlockRemove(context) {
    if (!options.humanRelationships
      || typeof options.humanRelationships.removeBlock !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const result = await options.humanRelationships.removeBlock({
      blockId: context.request.blockId,
    });
    if (result.relationshipRestored !== false || result.authorizationRestored !== false) {
      throw hostApplicationFailure("host_app_block_remove_invariant_failed");
    }
    await publishApplicationChange("blocks_changed", result.block.blockId);
  }

  async function applicationAccountOpen(context) {
    if (typeof options.accountLauncher !== "function") {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    const result = await options.accountLauncher(Object.freeze({
      target: context.request.target,
    }));
    if (result && !Array.isArray(result) && typeof result === "object"
      && Object.keys(result).length === 1 && result.opened === true) return;
    if (result && !Array.isArray(result) && typeof result === "object"
      && Object.keys(result).length === 1 && result.opened === false) {
      throw hostApplicationFailure("host_app_account_open_failed");
    }
    throw failure("neutral_host_account_launcher_response_invalid");
  }

  async function refreshHumanRelationshipsBestEffort() {
    if (!options.humanRelationships) return;
    relationshipRefreshInFlight ||= Promise.resolve()
      .then(() => options.humanRelationships.list())
      .catch(() => undefined)
      .finally(() => { relationshipRefreshInFlight = null; });
    let timeout;
    await Promise.race([
      relationshipRefreshInFlight,
      new Promise((resolve) => {
        timeout = setTimeout(resolve, 1_500);
        timeout.unref?.();
      }),
    ]);
    clearTimeout(timeout);
  }

  async function applicationOutboxMessages(context) {
    requireApplicationStore(applicationOutbox, "neutral_host_app_outbox_unavailable");
    const messages = await applicationOutbox.list();
    return {
      messages: messages
        .filter((message) => message?.direction === "outgoing")
        .filter((message) => message.senderPrincipalId === tuple.principalId)
        .filter((message) => message.senderDelegateId === context.delegateId)
        .map(projectOutboxMessage),
    };
  }

  async function applicationResendDeletedReply(context) {
    if (context.workbenchRetryAuthorized !== true) throw hostApplicationFailure("host_app_outbox_retry_grant_invalid");
    requireApplicationStore(applicationOutbox, "neutral_host_app_outbox_unavailable");
    const original = await applicationOutbox.get(context.request.clientMessageId);
    if (!original || original.direction !== "outgoing" || original.messageType !== "text"
      || original.senderPrincipalId !== tuple.principalId || original.senderDelegateId !== context.delegateId
      || original.status !== "failed_permanent" || original.lastErrorCode !== "reply_target_deleted" || !original.replyToClientMessageId) {
      throw hostApplicationFailure("host_app_state_conflict");
    }
    const clientMessageId = `human_resend_${crypto.createHash("sha256").update(JSON.stringify([
      tuple.region, tuple.principalId, context.delegateId, original.clientMessageId,
    ])).digest("hex")}`;
    const readResult = async () => {
      const saved = await applicationOutbox.get(clientMessageId);
      if (!saved || saved.resendSourceClientMessageId !== original.clientMessageId
        || saved.senderPrincipalId !== tuple.principalId || saved.senderDelegateId !== context.delegateId) {
        throw hostApplicationFailure("host_app_workbench_outcome_unknown");
      }
      return { kind: "deleted-reply-resend", originalClientMessageId: original.clientMessageId, clientMessageId,
        status: saved.status === "delivered_to_live_connection" ? "sent"
          : ["failed_retryable", "failed_permanent", "recipient_offline", "cancelled"].includes(saved.status) ? "not-delivered" : "unknown" };
    };
    if (original.resendClientMessageId) {
      if (original.resendClientMessageId !== clientMessageId) throw hostApplicationFailure("host_app_state_conflict");
      return readResult();
    }
    const binding = getMessageConversationBinding(original, tuple) || getOutgoingConversationIntent(original, tuple);
    if (!binding || binding.localDelegateId !== context.delegateId) throw hostApplicationFailure("host_app_state_conflict");
    const target = await resolveSavedInstance({ recipientHelloLynkId: original.peerHelloLynkId,
      recipientDelegateId: binding.peerDelegateId }, context.delegateId);
    if (target.principalId !== binding.peerPrincipalId) throw hostApplicationFailure("host_app_state_conflict");
    const endpoint = endpoints.get(context.delegateId);
    if (typeof endpoint?.outbound?.send !== "function") throw hostApplicationFailure("host_app_unavailable");
    await context.revalidateCapability?.();
    try {
      await sendOutboundOnce({ endpoint, delegateId: context.delegateId, clientMessageId, input: {
        clientMessageId, recipientHelloLynkId: original.peerHelloLynkId, recipientPrincipalId: binding.peerPrincipalId,
        recipientDelegateId: binding.peerDelegateId, region: tuple.region, route: savedInstanceRoute(target),
        text: original.text, intentSource: "human_native_dialog", resendSourceClientMessageId: original.clientMessageId,
      } });
    } catch (error) {
      // Inspect the one reserved copy; never start another send or task here.
      if (!(await applicationOutbox.get(clientMessageId))) {
        if (error?.code === "reply_resend_invalid") throw hostApplicationFailure("host_app_state_conflict");
        throw error;
      }
    }
    return readResult();
  }

  async function applicationOutboxRetry(context) {
    requireApplicationStore(applicationOutbox, "neutral_host_app_outbox_unavailable");
    const clientMessageId = context.request.clientMessageId;
    const current = await applicationOutbox.get(clientMessageId);
    if (!current || current.direction !== "outgoing"
      || current.senderPrincipalId !== tuple.principalId
      || current.senderDelegateId !== context.delegateId) {
      throw hostApplicationFailure("host_app_record_not_found");
    }
    if (!MANUAL_RETRYABLE_STATUSES.has(current.status) || current.lastErrorCode === "reply_target_deleted") {
      throw hostApplicationFailure("host_app_state_conflict");
    }
    const binding = getMessageConversationBinding(current, tuple) || getOutgoingConversationIntent(current, tuple);
    if (!binding || binding.localDelegateId !== context.delegateId) {
      throw hostApplicationFailure("host_app_state_conflict");
    }
    const target = await resolveSavedInstance({
      recipientHelloLynkId: current.peerHelloLynkId || current.recipientHelloLynkId,
      recipientDelegateId: binding.peerDelegateId,
    }, context.delegateId);
    if (target.principalId !== binding.peerPrincipalId) throw hostApplicationFailure("host_app_state_conflict");
    let retryOptions;
    if (current.targetConversationId && binding.peerPrincipalId !== tuple.principalId) {
      if (!current.targetConversationTitle) throw hostApplicationFailure("native_target_unsupported_or_unavailable");
      const authorizationContext = { delegateId: context.delegateId, request: target };
      const authorization = await recheckTargetRecipient(authorizationContext, target);
      const verified = await queryFriendTarget(context.delegateId, authorization, current.targetConversationTitle, clientMessageId);
      if (verified.targetConversationId !== current.targetConversationId) throw hostApplicationFailure("native_target_unavailable");
      await recheckTargetRecipient(authorizationContext, authorization);
      await context.nativeAuthority.revalidate();
      retryOptions = { friendTargetConnectionId: verified.friendTargetConnectionId };
    }
    try {
      await applicationOutbox.retry(clientMessageId, context.delegateId, retryOptions);
    } catch (error) {
      // Another admitted retry may already have claimed the same message.
      // Report the state conflict without retrying or adopting its result.
      if (error?.code === "local_outgoing_message_not_retryable") {
        throw hostApplicationFailure("host_app_state_conflict");
      }
      // LocalMessenger persists a definite recipient rejection before reporting
      // it as an error. Project that completed state to the human, but never
      // turn an unrelated retry/lock/E2EE failure into a successful mutation.
      const updated = await applicationOutbox.get(clientMessageId);
      const sameAttempt = (
        updated?.clientMessageId === current.clientMessageId
        && updated?.localMessageId === current.localMessageId
        && updated.direction === "outgoing"
        && updated.senderPrincipalId === tuple.principalId
        && updated.senderDelegateId === context.delegateId
        && Number.isSafeInteger(Number(current.attempts))
        && Number.isSafeInteger(Number(updated.attempts))
        && Number(updated.attempts) === Number(current.attempts) + 1
      );
      if (sameAttempt && updated.status === "failed_permanent") {
        await publishApplicationChange("outbox_changed", clientMessageId, context.delegateId);
        return { message: projectOutboxMutation(updated) };
      }
      if (sameAttempt && ["delivery_state_unknown", "delivery_state_unconfirmed"].includes(updated.status)) {
        await publishApplicationChange("outbox_changed", clientMessageId, context.delegateId);
      }
      throw error;
    }
    const updated = await applicationOutbox.get(clientMessageId);
    if (!updated || updated.senderPrincipalId !== tuple.principalId
      || updated.senderDelegateId !== context.delegateId) {
      throw hostApplicationFailure("host_app_action_failed");
    }
    await publishApplicationChange("outbox_changed", clientMessageId, context.delegateId);
    return { message: projectOutboxMutation(updated) };
  }

  async function applicationChangesSnapshot(context) {
    if (typeof applicationInbox?.getMessageCounts !== "function" || !sharedApplicationMessageStore) {
      throw hostApplicationFailure("host_app_unavailable");
    }
    const [counts, contacts] = await Promise.all([
      applicationInbox.getMessageCounts(localHistoryScope(context)),
      applicationContacts ? applicationContacts.list() : [],
    ]);
    return {
      cursor: applicationChangeCursor,
      inbox: counts.inbox,
      contacts: { total: contacts.length },
      outbox: { total: counts.outbox.total, retryEligible: counts.outbox.retryEligible },
      modelVisibility: "none",
    };
  }

  async function applicationChangesSubscribe(context) {
    // Existing UI change polling also refreshes display metadata when due. This
    // never adds a snapshot or network wait to the cheap changes response.
    const metadataRead = workbenchRelationshipMetadataReadContext;
    if (metadataRead && nowMs(clock) >= workbenchRelationshipMetadataAttemptAt + WORKBENCH_RELATIONSHIP_METADATA_REFRESH_MS) {
      startWorkbenchRelationshipMetadataRefresh(metadataRead.createReadModel);
    }
    const afterCursor = context.request.afterCursor;
    const oldestCursor = applicationChanges[0]?.cursor ?? applicationChangeCursor;
    // The counter belongs to this Host process. A page can retain the previous
    // process's cursor across reconnects; this read needs a fresh snapshot, not
    // a write-conflict error. Existing command/revision checks are unaffected.
    const snapshotRequired = afterCursor > applicationChangeCursor
      || (applicationChanges.length > 0 && afterCursor < oldestCursor - 1);
    return {
      cursor: applicationChangeCursor,
      snapshotRequired,
      events: snapshotRequired
        ? []
        : applicationChanges
          .filter((event) => event.cursor > afterCursor)
          .filter((event) => event.audienceDelegateId == null || event.audienceDelegateId === context.delegateId)
          .map(projectApplicationChange),
    };
  }

  async function applicationWorkbenchSnapshot(context) {
    const source = workbenchSource(context.adapterId);
    const resolved = await workbenchServiceFor(context, { initialRequest: context.request, source });
    return {
      snapshot: await resolved.service.readSnapshot(context.request, {
        source,
        authority: context,
      }),
    };
  }

  async function applicationWorkbenchCommand(context) {
    const { service } = await workbenchServiceFor(context);
    return service.executeCommand(context.request, {
      source: workbenchSource(context.adapterId),
      authority: context,
    });
  }

  async function workbenchServiceFor(context, initialization = {}) {
    const delegateId = safeId(context.delegateId, "neutral_host_workbench_delegate_invalid");
    let pending = workbenchServices.get(delegateId);
    if (pending) {
      const resolved = await pending;
      return { service: resolved.service };
    }
    const initialRequest = initialization.initialRequest || {};
    const initialSource = initialization.source || workbenchSource(context.adapterId);
    pending = (async () => {
      // Validate the real delegate projection before exposing any service
      // result, including a refusal of a foreign/retired command window.
      const initial = validateWorkbenchSnapshot(
        await buildApplicationWorkbenchSnapshot(context, initialRequest, initialSource),
      );
      let seedSnapshot = Object.hasOwn(initialization, "initialRequest") ? initial : null;
      const service = createHelloLynkWorkbenchService({
        hostGeneration,
        writerRegistrationKey: `${hostGeneration}:${delegateId}`,
        refreshBeforeCommand: true,
        revision: initial.revision,
        changeCursor: initial.changeCursor,
        runCommandOperation(_command, operation) {
          // Take the global queue only after this delegate's service turn, and
          // keep the fresh revision check and admission in the same turn.
          // The service detaches retry completion after admission, so its
          // network wait holds neither this queue nor the delegate's queue.
          return trackApplicationMutation(operation);
        },
        async readSnapshot(request, serviceContext) {
          const authority = requireWorkbenchAuthority(serviceContext.authority, delegateId);
          const useSeed = seedSnapshot && request === initialRequest && authority === context
            && Object.keys(initialSource).every((key) => serviceContext.source[key] === initialSource[key]);
          const snapshot = useSeed ? seedSnapshot : null;
          seedSnapshot = null;
          if (snapshot) return snapshot;
          return buildApplicationWorkbenchSnapshot(authority, request, serviceContext.source,
            { authoritativeMetadata: serviceContext.beforeCommand === true
              && WORKBENCH_RELATIONSHIP_METADATA_CAPABILITIES.has(WORKBENCH_COMMAND_CAPABILITIES[serviceContext.commandType]) });
        },
        async executeCommand(command, serviceContext) {
          const authority = requireWorkbenchAuthority(serviceContext.authority, delegateId);
          return executeAuthoritativeWorkbenchCommand(command, authority, serviceContext.source, serviceContext);
        },
      });
      return Object.freeze({ service });
    })();
    workbenchServices.set(delegateId, pending);
    try {
      const resolved = await pending;
      return {
        service: resolved.service,
      };
    } catch (error) {
      if (workbenchServices.get(delegateId) === pending) workbenchServices.delete(delegateId);
      throw error;
    }
  }

  function requireWorkbenchAuthority(value, delegateId) {
    if (!value || value.delegateId !== delegateId || value.hostGeneration !== hostGeneration) {
      throw hostApplicationFailure("host_app_authorization_required");
    }
    return value;
  }

  async function assertWorkbenchCommandCapabilityAvailable(command) {
    const requiredCapability = WORKBENCH_COMMAND_CAPABILITIES[command?.command];
    if (!requiredCapability || !workbenchCapabilities.includes(requiredCapability)) {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    await assertWorkbenchLegacyLifecycleCapabilityAvailable(requiredCapability);
  }

  async function assertWorkbenchLegacyLifecycleCapabilityAvailable(requiredCapability) {
    if (!WORKBENCH_LIFECYCLE_DEPENDENT_CAPABILITIES.has(requiredCapability)) return;
    if (!hasRemoteWorkbenchLifecycle()) {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    try {
      await readRemoteWorkbenchLifecyclePages();
    } catch {
      // A lifecycle-dependent mutation must never rely on a stale successful
      // snapshot. Any probe failure closes both grant issuance and execution.
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
  }

  async function executeAuthoritativeWorkbenchCommand(command, context, source, serviceContext) {
    try {
      await assertWorkbenchCommandCapabilityAvailable(command);
      let publicResult = {};
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal) {
        if (!options.humanRelationships || typeof options.humanRelationships.search !== "function") {
          throw hostApplicationFailure("host_app_capability_unavailable");
        }
        const found = await options.humanRelationships.search(command.payload);
        publicResult = {
          kind: "principal-search",
          mode: command.payload.mode,
          ...found,
        };
        bindWorkbenchRelationshipTargets(found.results, context);
        // Directory search does not change the local snapshot. Return its
        // authority-bound results without making unrelated cloud lists a
        // second condition for a successful read.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest) {
        if (!options.humanRelationships || typeof options.humanRelationships.send !== "function") {
          throw hostApplicationFailure("host_app_capability_unavailable");
        }
        requireWorkbenchRelationshipTarget(command.payload.targetRef, context);
        publicResult = {
          kind: "contact-request-send",
          ...(await options.humanRelationships.send(command.payload)),
        };
        // The controller result is the authoritative submission outcome. Do not
        // let an unrelated relationship-list refresh replace it after the cloud
        // has already admitted or frozen this exact request attempt.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend) {
        publicResult = projectHumanSendStatus(
          await nativeHumanSendRequest({ ...context, request: command.payload }),
        );
        // The broker has admitted this exact saved peer and returns its action
        // state, not a delivery acknowledgement. An unrelated cloud refresh
        // must not hide that action after its confirmation has already started.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
        publicResult = projectHumanSendStatus(
          await nativeHumanSendRequestStatus({ ...context, request: command.payload }),
        );
        // The broker is the authority for this action. Do not make an unrelated
        // cloud/relationship snapshot a second condition for observing it.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead) {
        await applicationInboxMarkRead({ ...context, request: command.payload });
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead) {
        publicResult = await applicationInboxMarkAllRead({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead) {
        publicResult = await applicationConversationAutoRead({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead) {
        await applicationInboxDeleteRead({ ...context, request: command.payload });
      } else if ([HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent, HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread,
        HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread, HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread,
        HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads,
        HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory].includes(command.command)) {
        publicResult = await applicationLocalHistory(command, context);
        // Durable local completion is the acknowledgement. A later independent
        // snapshot refresh must not turn the completed operation into unknown.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply) {
        publicResult = await applicationResendDeletedReply({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry) {
        if (context.workbenchRetryAuthorized !== true) {
          throw hostApplicationFailure("host_app_outbox_retry_grant_invalid");
        }
        await applicationOutboxRetry({ ...context, request: command.payload });
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact) {
        // This is deliberately the same Host-owned path as the application API:
        // the workbench never writes the local contact file on its own.
        await applicationContactsUpsert({ ...context, request: command.payload });
        // The durable local write is the acknowledgement boundary. An unrelated
        // cloud-list refresh must not turn a committed edit into an unknown
        // outcome. Keep the checked command baseline; the contacts_changed event
        // and the UI's separate read refresh the snapshot before the next edit.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact) {
        await renameContact({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances) {
        publicResult = await readContactInstances({ ...context, request: command.payload });
        // Directory reads do not change the snapshot. Return the checked
        // result without a second, unrelated cloud metadata refresh.
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance) {
        await saveContactInstance({ ...context, request: command.payload });
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance) {
        await renameContactInstance({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance) {
        await deleteContactInstance({ ...context, request: command.payload });
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact) {
        // Deletion removes the local relationship only. Any later autonomous
        // action still re-resolves the contact and therefore fails closed.
        await applicationContactsRemove({ ...context, request: command.payload });
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization) {
        await applicationContactAutonomousSendAuthorization({ ...context, request: command.payload });
      } else if (command.command === WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND) {
        publicResult = {
          kind: "contact-request-clear-resolved",
          ...(await applicationContactRequestsClearResolved()),
        };
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision) {
        await applicationContactRequestRecover({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest) {
        await applicationContactRequestRespond({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest) {
        await applicationContactRequestCancel({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship) {
        await applicationRelationshipEnd({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock) {
        await applicationBlockRemove({ ...context, request: command.payload });
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      } else if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.openAccount) {
        await applicationAccountOpen({ ...context, request: command.payload });
      } else {
        throw hostApplicationFailure("host_app_workbench_command_not_enabled");
      }
      if (WORKBENCH_LOCAL_ONLY_CAPABILITIES.has(WORKBENCH_COMMAND_CAPABILITIES[command.command])) {
        return workbenchSuccess(command.requestId, serviceContext, publicResult);
      }
      const snapshot = await buildApplicationWorkbenchSnapshot(context, {}, source, {
        authoritativeMetadata: WORKBENCH_RELATIONSHIP_METADATA_CAPABILITIES.has(WORKBENCH_COMMAND_CAPABILITIES[command.command]),
      });
      return workbenchSuccess(command.requestId, snapshot, publicResult);
    } catch (error) {
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal) {
        const code = String(error?.code || "");
        if (code === "directory_search_rate_limited" && error.httpStatus === 429) {
          return workbenchFailure(command.requestId, code, serviceContext, "known-failed");
        }
        const safeCode = /^(?:host_app|host_transport|human_relationship)_[a-z0-9_]{1,100}$/.test(code)
          ? code : "host_app_principal_search_failed";
        // A timed-out search may already have consumed its cloud quota. Keep
        // that uncertainty and never replay it, but retain the useful code.
        const refusedBeforeSearch = safeCode.startsWith("host_app_") && safeCode !== "host_app_principal_search_failed";
        return workbenchFailure(command.requestId, safeCode, refusedBeforeSearch ? serviceContext : null,
          refusedBeforeSearch ? "known-failed" : "unknown");
      }
      // A contact-request refusal is already authoritative. Refreshing unrelated
      // lists here can hide that known failure behind the browser's timeout.
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock
        || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances) {
        const knownCode = knownWorkbenchCommandFailure(error);
        return workbenchFailure(
          command.requestId,
          knownCode || "host_app_workbench_outcome_unknown",
          knownCode ? serviceContext : null,
          knownCode ? "known-failed" : "unknown",
        );
      }
      const knownCode = knownWorkbenchCommandFailure(error);
      if (WORKBENCH_LOCAL_ONLY_CAPABILITIES.has(WORKBENCH_COMMAND_CAPABILITIES[command.command])) {
        // The local CAS already determined whether this edit was rejected.
        // Cloud metadata cannot improve that answer or acknowledge a failed write.
        return workbenchFailure(command.requestId, knownCode || "host_app_workbench_outcome_unknown",
          knownCode ? serviceContext : null, knownCode ? "known-failed" : "unknown");
      }
      if (knownCode) {
        const snapshot = await buildApplicationWorkbenchSnapshot(context, {}, source, {
          authoritativeMetadata: WORKBENCH_RELATIONSHIP_METADATA_CAPABILITIES.has(WORKBENCH_COMMAND_CAPABILITIES[command.command]),
        }).catch(() => null);
        return workbenchFailure(command.requestId, knownCode, snapshot, "known-failed");
      }
      return workbenchFailure(command.requestId, "host_app_workbench_outcome_unknown", null, "unknown");
    }
  }

  function bindWorkbenchRelationshipTargets(results, context) {
    const now = nowMs(clock);
    for (const [targetRef, binding] of workbenchRelationshipTargets) {
      if (binding.expiresAtMs <= now) workbenchRelationshipTargets.delete(targetRef);
    }
    for (const result of results) {
      const expiresAtMs = Date.parse(result.expiresAt);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now) {
        throw hostApplicationFailure("host_app_contact_target_expired");
      }
      workbenchRelationshipTargets.set(result.targetRef, Object.freeze({
        delegateId: context.delegateId,
        capabilityId: context.capabilityId,
        adapterInstanceId: context.adapterInstanceId,
        hostGeneration,
        expiresAtMs,
      }));
    }
    while (workbenchRelationshipTargets.size > 64) {
      workbenchRelationshipTargets.delete(workbenchRelationshipTargets.keys().next().value);
    }
  }

  function requireWorkbenchRelationshipTarget(targetRef, context) {
    const binding = workbenchRelationshipTargets.get(targetRef);
    if (binding?.expiresAtMs <= nowMs(clock)) workbenchRelationshipTargets.delete(targetRef);
    if (!binding || binding.expiresAtMs <= nowMs(clock)
      || binding.delegateId !== context.delegateId
      || binding.capabilityId !== context.capabilityId
      || binding.adapterInstanceId !== context.adapterInstanceId
      || binding.hostGeneration !== hostGeneration) {
      throw hostApplicationFailure("host_app_contact_target_expired");
    }
  }

  async function buildApplicationWorkbenchSnapshot(context, request, source, behavior = {}) {
    requireApplicationStore(applicationInbox, "neutral_host_app_inbox_unavailable");
    requireApplicationStore(applicationContacts, "neutral_host_app_contacts_unavailable");
    requireApplicationStore(applicationContactRequests, "neutral_host_app_contact_requests_unavailable");
    requireApplicationStore(applicationOutbox, "neutral_host_app_outbox_unavailable");
    const endpoint = endpoints.get(context.delegateId);
    if (!endpoint?.hellolynkId || !Number.isSafeInteger(endpoint.authorizationVersion)) {
      throw hostApplicationFailure("host_app_workbench_subject_unavailable");
    }
    const remoteMetadata = hasRemoteWorkbenchLifecycle();
    let observedMetadata = null;
    const createReadModel = ({ capabilities, legacyLifecycleFallback = false, localOnly = false,
      metadata, metadataState }) => (
      createNeutralHostWorkbenchReadModel({
        subject: {
          region: tuple.region,
          principalId: tuple.principalId,
          principalLabel: endpoint.principalLabel ?? null,
          hellolynkId: endpoint.hellolynkId,
          delegateId: endpoint.delegateId,
          delegateLabel: endpoint.delegateLabel ?? null,
          hostInstallationId: tuple.hostInstallationId,
          authorizationVersion: endpoint.authorizationVersion,
        },
        hostGeneration,
        applicationChangeCursor: String(applicationChangeCursor),
        messageStore: applicationInbox,
        contactStore: applicationContacts,
        contactRequestStore: {
          async listForHuman(input) {
            if (metadata) return projectLocalWorkbenchRelationshipMetadata(metadata);
            if (localOnly) return { requests: [], nextCursor: null, relationships: [], blocks: [] };
            observedMetadata = await applicationWorkbenchRelationshipState(input, { legacyLifecycleFallback });
            return observedMetadata;
          },
        },
        localDelegateLabels: [...endpoints.values()].map((item) => ({
          principalId: item.principalId,
          delegateId: item.delegateId,
          delegateLabel: item.delegateLabel ?? null,
        })),
        capabilities,
        ...(metadataState ? { relationshipMetadataState: metadataState } : {}),
        hostStatus: !localOnly && lifecycle === "running" ? "online" : "offline",
        connectedClients: core.connectedClients(),
        changeEventTypes: [...new Set(applicationChanges.map((item) => item.type))].sort(),
        snapshotRequired: false,
        now: () => new Date(hostStartedAt),
      })
    );
    if (remoteMetadata) workbenchRelationshipMetadataReadContext = { createReadModel };
    if (remoteMetadata && behavior.authoritativeMetadata !== true && !Object.hasOwn(request, "contactRequestCursor")) {
      const now = nowMs(clock);
      // Never put the network task on the service's serialized read/write tail.
      // Capture this projection before starting it so a cold read is coherent.
      const metadataState = workbenchRelationshipMetadataState;
      const metadata = workbenchRelationshipMetadata || { requests: [], nextCursor: null, relationships: [], blocks: [] };
      if (now >= workbenchRelationshipMetadataAttemptAt + WORKBENCH_RELATIONSHIP_METADATA_REFRESH_MS) {
        startWorkbenchRelationshipMetadataRefresh(createReadModel);
      }
      return createReadModel({ metadata, metadataState,
        capabilities: metadataState === "fresh" ? workbenchCapabilities
          : workbenchCapabilities.filter((capability) => !WORKBENCH_RELATIONSHIP_METADATA_CAPABILITIES.has(capability)
            // Starting a new relationship does not depend on the cached list
            // of existing relationships. Keep the discovery form available;
            // request submission still performs its authoritative preflight.
            || capability === "principal.search" || capability === "contact-request.send"),
      }).readSnapshot(request, source);
    }
    // A newer authoritative read supersedes any older background projection,
    // including when only the server observed a relationship change.
    const metadataEpoch = remoteMetadata ? ++workbenchRelationshipMetadataEpoch : workbenchRelationshipMetadataEpoch;
    try {
      const snapshot = await createReadModel({ capabilities: workbenchCapabilities,
        ...(remoteMetadata ? { metadataState: "fresh" } : {}) })
        .readSnapshot(request, source);
      if (remoteMetadata && request.contactRequestCursor == null && observedMetadata) {
        await commitWorkbenchRelationshipMetadata(observedMetadata, metadataEpoch, false);
      }
      return { ...snapshot };
    } catch (error) {
      if (remoteMetadata && metadataEpoch === workbenchRelationshipMetadataEpoch) {
        workbenchRelationshipMetadataState = "stale";
      }
      if (isTransientWorkbenchCloudFailure(error)
        || error?.code === "host_transport_account_authorization_required") {
        // Local history does not need a successful cloud metadata read. Do not
        // present empty remote lists as authoritative. Local records and local
        // send settings remain usable without a successful remote metadata read.
        return { ...(await createReadModel({
          capabilities: workbenchCapabilities.filter((capability) => WORKBENCH_LOCAL_ONLY_CAPABILITIES.has(capability)),
          localOnly: true,
        }).readSnapshot(request, source)) };
      }
      if (error?.code !== WORKBENCH_LEGACY_LIFECYCLE_ROUTES_UNAVAILABLE) throw error;
      const degradedCapabilities = workbenchCapabilities.filter(
        (capability) => !WORKBENCH_LIFECYCLE_DEPENDENT_CAPABILITIES.has(capability),
      );
      return {
        ...(await createReadModel({
          capabilities: degradedCapabilities,
          legacyLifecycleFallback: true,
        }).readSnapshot(request, source)),
      };
    }
  }

  async function commitWorkbenchRelationshipMetadata(metadata, epoch, notify = true) {
    if (lifecycle !== "running" || epoch !== workbenchRelationshipMetadataEpoch) return;
    // Keep only validated relationship display metadata. Local intro text,
    // receipts and decision state are reread from the protected store below.
    metadata = workbenchRelationshipMetadataProjection(metadata);
    const changed = workbenchRelationshipMetadataState !== "fresh"
      || JSON.stringify(metadata) !== JSON.stringify(workbenchRelationshipMetadata);
    workbenchRelationshipMetadata = structuredClone(metadata);
    workbenchRelationshipMetadataState = "fresh";
    workbenchRelationshipMetadataAttemptAt = nowMs(clock);
    if (changed && notify) await publishApplicationChange("contacts_changed", "relationship-metadata");
  }

  function workbenchRelationshipMetadataProjection(metadata) {
    return { ...metadata, requests: metadata.requests.map((request) => ({
      requestId: request.serverContactRequestId ?? request.requestId ?? request.localRecordId,
      direction: request.direction ?? "incoming", status: request.state ?? request.status,
      otherPrincipal: request.otherPrincipal ?? {
        displayName: request.sender?.verifiedDisplayName ?? null, hellolynkId: request.sender?.hellolynkId,
      },
      createdAt: request.receivedAt ?? request.createdAt,
      humanOnly: true, modelVisibility: "none",
    })) };
  }

  async function projectLocalWorkbenchRelationshipMetadata(metadata) {
    const local = await applicationContactRequests.listForHuman();
    const byId = new Map(local.map((request) => [request.serverContactRequestId ?? request.localRecordId, request]));
    const requests = metadata.requests.map((remote) => {
      const current = remote.direction === "incoming" ? byId.get(remote.requestId) : null;
      byId.delete(remote.requestId);
      if (!current) return { ...remote, actionReady: false, decisionOutcome: null, decisionAction: null };
      const state = current.state === "pending" && current.decisionOutcome != null
        ? "pending" : remote.status === "pending" ? current.state : remote.status;
      const consistent = state === current.state;
      return { ...remote, ...current, state,
        actionReady: consistent && current.actionReady === true,
        decisionOutcome: consistent ? current.decisionOutcome : null,
        decisionAction: consistent ? current.decisionAction : null,
      };
    });
    return { ...structuredClone(metadata), requests: [...requests, ...byId.values()] };
  }

  function startWorkbenchRelationshipMetadataRefresh(createReadModel) {
    if (lifecycle !== "running" || workbenchRelationshipMetadataRefresh) return;
    const epoch = workbenchRelationshipMetadataEpoch;
    workbenchRelationshipMetadataAttemptAt = nowMs(clock);
    const task = Promise.resolve().then(async () => {
      try {
        // Refreshing unchanged display data is not a business change. Keep the
        // last successful projection while this read is pending; real failures
        // and relationship events still mark it stale. Commands keep their
        // authoritative preflight and never rely on this display cache.
        const metadata = await applicationWorkbenchRelationshipState();
        if (lifecycle !== "running" || epoch !== workbenchRelationshipMetadataEpoch) return;
        // Validate the same relationship projection used by snapshots. Building
        // a complete local snapshot here would reread unrelated chat history.
        createReadModel({ capabilities: workbenchCapabilities, metadataState: "fresh" })
          .validateRelationshipMetadata(metadata);
        await commitWorkbenchRelationshipMetadata(metadata, epoch);
      } catch {
        if (lifecycle !== "running" || epoch !== workbenchRelationshipMetadataEpoch) return;
        const changed = workbenchRelationshipMetadataState !== "stale";
        workbenchRelationshipMetadataState = "stale";
        if (changed) await publishApplicationChange("contacts_changed", "relationship-metadata");
      }
    }).finally(() => {
      if (workbenchRelationshipMetadataRefresh === task) workbenchRelationshipMetadataRefresh = null;
    });
    workbenchRelationshipMetadataRefresh = task;
    trackOperation(task, pendingOperations);
  }

  async function applicationWorkbenchRelationshipState(input = {}, behavior = {}) {
    const cursor = input?.cursor ?? null;
    const hasRemoteLifecycle = hasRemoteWorkbenchLifecycle();
    if (hasRemoteLifecycle) {
      if (behavior.legacyLifecycleFallback === true) {
        const contactRequestPage = await options.humanRelationships.list(
          cursor == null ? {} : { cursor },
        );
        return {
          requests: contactRequestPage.requests,
          nextCursor: contactRequestPage.nextCursor,
          relationships: [],
          blocks: [],
        };
      }
      // The lifecycle lists are authoritative as one read surface. Never
      // turn a remote failure into an incomplete page or empty arrays while
      // advertising the corresponding read and mutation capabilities.
      // These snapshot reads are independent. Starting all three together
      // also shares the transport's in-flight protected session resolution.
      // Settle every read before choosing an error; a failed page must never
      // be exposed as an authoritative empty list.
      const [lifecycleResult, contactRequestResult] = await Promise.allSettled([
        readRemoteWorkbenchLifecyclePages(),
        Promise.resolve().then(() => options.humanRelationships.list(cursor == null ? {} : { cursor })),
      ]);
      if (contactRequestResult.status === "rejected"
        && !isTransientWorkbenchCloudFailure(contactRequestResult.reason)
        && contactRequestResult.reason?.code !== "host_transport_account_authorization_required") {
        throw contactRequestResult.reason;
      }
      if (lifecycleResult.status === "rejected") throw lifecycleResult.reason;
      if (contactRequestResult.status === "rejected") throw contactRequestResult.reason;
      const { relationshipPage, blockPage } = lifecycleResult.value;
      const contactRequestPage = contactRequestResult.value;
      return {
        requests: contactRequestPage.requests,
        nextCursor: contactRequestPage.nextCursor,
        relationships: relationshipPage.relationships,
        blocks: blockPage.blocks,
      };
    } else if (cursor != null) {
      throw hostApplicationFailure("host_app_capability_unavailable");
    }
    return {
      requests: await applicationContactRequests.listForHuman(),
      nextCursor: null,
      relationships: [],
      blocks: [],
    };
  }

  function hasRemoteWorkbenchLifecycle() {
    return Boolean(options.humanRelationships
      && typeof options.humanRelationships.list === "function"
      && typeof options.humanRelationships.listRelationships === "function"
      && typeof options.humanRelationships.listBlocks === "function");
  }

  async function readRemoteWorkbenchLifecyclePages() {
    const [relationshipResult, blockResult] = await Promise.allSettled([
      options.humanRelationships.listRelationships(),
      options.humanRelationships.listBlocks(),
    ]);
    if (relationshipResult.status === "rejected" || blockResult.status === "rejected") {
      if (relationshipResult.status === "rejected"
        && blockResult.status === "rejected"
        && isMissingLegacyLifecycleRoute(relationshipResult.reason)
        && isMissingLegacyLifecycleRoute(blockResult.reason)) {
        throw failure(WORKBENCH_LEGACY_LIFECYCLE_ROUTES_UNAVAILABLE);
      }
      const permanentFailure = [relationshipResult, blockResult].find(
        (result) => result.status === "rejected"
          && !isMissingLegacyLifecycleRoute(result.reason)
          && !isTransientWorkbenchCloudFailure(result.reason)
          && result.reason?.code !== "host_transport_account_authorization_required",
      );
      const nonMissingRouteFailure = [relationshipResult, blockResult].find(
        (result) => result.status === "rejected" && !isMissingLegacyLifecycleRoute(result.reason),
      );
      const firstFailure = permanentFailure || nonMissingRouteFailure
        || [relationshipResult, blockResult].find((result) => result.status === "rejected");
      throw firstFailure.reason;
    }
    return {
      relationshipPage: relationshipResult.value,
      blockPage: blockResult.value,
    };
  }

  async function publishChange(change, entityId, audienceDelegateId = null) {
    assertNoSensitiveEventFields(change);
    await changeSink(change);
    await publishApplicationChange(change.type, entityId, audienceDelegateId);
  }

  async function publishApplicationChange(type, entityId, audienceDelegateId = null) {
    if (type === "contacts_changed" && entityId === "relationship-metadata") contactRequestNoticeRead = null;
    if (["contact_requests_changed", "relationships_changed", "blocks_changed"].includes(type)) {
      contactRequestNoticeRead = null;
      workbenchRelationshipMetadataEpoch += 1;
      workbenchRelationshipMetadataAttemptAt = -Infinity;
      workbenchRelationshipMetadataState = workbenchRelationshipMetadata ? "stale" : "loading";
    }
    const event = Object.freeze({
      cursor: ++applicationChangeCursor,
      type: safeId(type, "neutral_host_change_type_invalid"),
      entityId: safeApplicationId(entityId, "neutral_host_change_entity_invalid"),
      changedAt: new Date(nowMs(clock)).toISOString(),
      modelVisibility: "none",
      audienceDelegateId,
    });
    assertNoSensitiveEventFields(event);
    applicationChanges.push(event);
    if (applicationChanges.length > APPLICATION_CHANGE_CAPACITY) applicationChanges.shift();
  }

  async function beginDrain(reason = "stop_requested") {
    if (stopPromise) return stopPromise;
    lifecycle = "draining";
    workbenchRelationshipMetadataEpoch += 1;
    workbenchRelationshipMetadata = null;
    workbenchRelationshipMetadataReadContext = null;
    workbenchRelationshipMetadataState = "loading";
    stopPromise = (async () => {
      if (maintenanceTimer) clearInterval(maintenanceTimer);
      maintenanceTimer = null;
      preKeyRefillAbortController.abort();
      relayAbortController.abort();
      // A confirmation-window cleanup failure must not retain the Host's
      // transport, listener or installation lock after a requested stop.
      try { await nativeBroker?.close(); } catch {}
      // Fence new callbacks before waiting. Anything already in pendingOperations
      // crossed the running gate and is allowed to finish its persist/ACK unit.
      await stream?.close?.().catch(() => {});
      const drainTimeoutMs = integerInRange(options.drainTimeoutMs, 5_000, 100, 60_000);
      // Give admitted persist/ACK units a bounded grace period. After that,
      // closing the transport cancels slow cloud work; the second wait still
      // protects all admitted local writes before releasing ownership.
      // Close belongs here, not only in assembly.stop: idle/revocation also use
      // this path, and the installation lock is still owned at this point.
      try { await waitForOperations(pendingOperations, drainTimeoutMs); }
      catch (error) {
        if (error?.code !== "neutral_host_drain_timeout") throw error;
      }
      finally {
        const transportDrain = options.transport.close?.();
        if (transportDrain) trackOperation(transportDrain, pendingOperations);
      }
      await waitForOperations(pendingOperations, drainTimeoutMs);
      if (server) await closeServer(server);
      await receiveTask?.catch(() => {});
      if (ownsDiscovery) await removeOwnedDiscovery(layout.discoveryPath, hostGeneration);
      // The same generation check clears a handover request addressed to this Host.
      await removeOwnedDiscovery(layout.handoverPath, hostGeneration);
      if (handoverRequested) await restampExpectedRelease(layout, releaseOrdinal).catch(() => {});
      await lockHandle.release();
      lifecycle = "stopped";
      return { ok: true, reason, status: lifecycle };
    })().catch(async (error) => {
      failureCode = safeCode(error, "neutral_host_stop_failed");
      // A failed drain is terminal. Keep the lock while this process is alive,
      // close its listener, and let the owning release entry exit with failure.
      // Never leave a live, unusable Host indefinitely advertising "draining".
      try { options.transport.close?.()?.catch(() => {}); } catch {}
      if (server) {
        const closing = closeServer(server);
        server.closeAllConnections?.();
        await closing.catch(() => {});
      }
      lifecycle = "failed";
      throw error;
    });
    return stopPromise;
  }

  async function cleanupAfterFailedStart() {
    if (maintenanceTimer) clearInterval(maintenanceTimer);
    preKeyRefillAbortController.abort();
    relayAbortController.abort();
    await nativeBroker?.close().catch(() => {});
    await stream?.close?.().catch(() => {});
    try {
      if (options.transport.close) {
        trackOperation(options.transport.close(), pendingOperations);
        await waitForOperations(pendingOperations, integerInRange(options.drainTimeoutMs, 5_000, 100, 60_000));
      }
    } finally {
      // A failed local drain must retain ownership, but not an unusable listener.
      if (server) await closeServer(server).catch(() => {});
    }
    await lockHandle.release().catch(() => {});
  }

  return Object.freeze({
    contractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
    tuple,
    discovery,
    core,
    stop: beginDrain,
    runMaintenance,
    get status() { return lifecycle; },
    get failureCode() { return failureCode; },
    get modelCalls() { return modelCalls; },
    get pendingOperationCount() { return pendingOperations.size; },
  });

  function wrapperHealth() {
    return {
      ok: lifecycle === "running",
      contractId: HELLOLYNK_NEUTRAL_HOST_PROCESS_CONTRACT,
      hostGeneration,
      status: lifecycle,
      releaseOrdinal,
      receive: receiveHealth(),
    };
  }

  function runningHealth(health = core.publicHealth()) {
    return {
      ...health,
      releaseOrdinal,
      receive: receiveHealth(),
    };
  }

  function receiveHealth() {
    const preKeyInventory = preKeyInventoryHealth();
    return {
      status: inboundPaused
        ? "paused"
        : preKeyInventory.status === "ready" && relayState.status === "ready" && !lastRejectedInbound ? "ready" : "degraded",
      ...(lastRejectedInbound ? { lastRejectedInbound } : {}),
      preKeyInventory,
      relay: {
        status: relayState.status,
        ...(relayState.errorCode ? { errorCode: relayState.errorCode } : {}),
        ...(relayState.status === "retrying" ? { retryAt: new Date(relayState.nextAttemptAtMs).toISOString() } : {}),
      },
    };
  }
}

export async function discoverHelloLynkNeutralHost(options = {}) {
  const tuple = normalizeTuple(options);
  const runtimeRoot = path.resolve(String(options.runtimeRoot || ""));
  if (!options.runtimeRoot) throw failure("neutral_host_runtime_root_required");
  const layout = discoveryLayout(runtimeRoot, tuple.hostInstallationId);
  await assertNoReparseAncestors(runtimeRoot);
  await assertSafePath(runtimeRoot, { mustExist: true, directory: true });
  await assertSafePath(layout.directory, { mustExist: true, directory: true });
  await assertSafePath(layout.discoveryPath, { mustExist: true, directory: false });
  let record;
  try {
    record = JSON.parse(await fs.readFile(layout.discoveryPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw failure("neutral_host_discovery_invalid", error);
  }
  validateDiscovery(record);
  if (record.tupleDigest !== digestTuple(tuple)
    || record.region !== tuple.region
    || record.principalId !== tuple.principalId
    || record.hostInstallationId !== tuple.hostInstallationId) {
    throw failure("neutral_host_discovery_owner_mismatch");
  }
  const health = await fetch(`http://${record.host}:${record.port}${HELLOLYNK_HOST_PATHS.health}`, {
    redirect: "error",
    signal: AbortSignal.timeout(2_000),
  }).catch(() => null);
  if (!health || health.status !== 200) throw failure("neutral_host_discovery_stale");
  const body = await health.json().catch(() => null);
  if (body?.hostGeneration !== record.hostGeneration || body?.status !== "running") {
    throw failure("neutral_host_discovery_generation_mismatch");
  }
  return Object.freeze(structuredClone(record));
}

export async function attachHelloLynkNeutralHost(options = {}) {
  const record = options.discovery || await discoverHelloLynkNeutralHost(options);
  if (!record) throw failure("neutral_host_not_found");
  return requestHelloLynkNeutralHost({
    ...options,
    discovery: record,
    method: "POST",
    pathname: HELLOLYNK_HOST_PATHS.attachmentAttach,
    body: { adapterInstanceId: safeId(options.adapterInstanceId, "neutral_host_adapter_instance_invalid") },
  });
}

// For installers, after new bindings are committed, for adapters that find a running Host
// or one without a route they need, and for a Host start that finds the slot taken. A Host
// of a lower release is asked to hand over; one of the same or a higher release is
// "current" and left alone. Only a different, healthy generation is "restarted", which
// still says nothing about its release; a removed discovery is "stopped"; anything
// unobservable stays pending/unconfirmed. Never an install failure.
export async function requestHelloLynkNeutralHostHandover(options = {}) {
  if (!options.runtimeRoot) throw failure("neutral_host_runtime_root_required");
  const runtimeRoot = path.resolve(String(options.runtimeRoot));
  const hostInstallationId = safeId(options.hostInstallationId, "neutral_host_installation_invalid");
  const publishedAtMs = Date.parse(String(options.publishedAt || ""));
  if (!Number.isFinite(publishedAtMs)) throw failure("neutral_host_handover_published_at_invalid");
  const waitMs = integerInRange(options.waitMs, 5_000, 0, 30_000);
  // Only a test can ask for a lower release than this code.
  const releaseOrdinal = integerInRange(options.releaseOrdinal, HELLOLYNK_HOST_RELEASE_ORDINAL, 0, HELLOLYNK_HOST_RELEASE_ORDINAL);
  // An adapter starts its own release's Host next, so it stops waiting once the slot is free.
  const untilStopped = options.untilStopped === true;
  const layout = discoveryLayout(runtimeRoot, hostInstallationId);
  try {
    const record = await readDiscoveryRecord(layout.discoveryPath);
    if (record === null) return Object.freeze({ status: "no_host" });
    const health = await discoveryHealth(record);
    if (!health) return Object.freeze({ status: "unconfirmed" });
    if (releaseOrdinalOf(health) >= releaseOrdinal) {
      return Object.freeze({ status: "current", hostGeneration: record.hostGeneration });
    }
    // A failed write only loses the hold; the request still goes out.
    await recordExpectedRelease(runtimeRoot, layout, releaseOrdinal).catch(() => {});
    await atomicWriteJson(layout.handoverPath, {
      contract: HANDOVER_REQUEST_CONTRACT,
      hostGeneration: record.hostGeneration,
      publishedAt: new Date(publishedAtMs).toISOString(),
    });
    let stopped = false;
    for (const deadline = Date.now() + waitMs; Date.now() < deadline;) {
      await new Promise((resolve) => setTimeout(resolve, 250));
      const current = await readDiscoveryRecord(layout.discoveryPath).catch(() => undefined);
      if (current === null) { stopped = true; if (untilStopped) break; continue; }
      if (current && current.hostGeneration !== record.hostGeneration && await discoveryRunning(current)) {
        return Object.freeze({ status: "restarted", previousHostGeneration: record.hostGeneration,
          hostGeneration: current.hostGeneration });
      }
    }
    return Object.freeze(stopped
      ? { status: "stopped", previousHostGeneration: record.hostGeneration }
      : { status: "pending", requestWritten: true, hostGeneration: record.hostGeneration });
  } catch {
    return Object.freeze({ status: "unconfirmed" });
  }
}

// While a newer release is taking over (a fresh record of a higher release), a Host of a lower
// release leaves the start to it. A stale or unreadable record never blocks a start. Read-only
// and cheap, so the assembly calls it before it reads profiles, credentials and keys.
export async function assertHelloLynkNeutralHostReleaseCurrent(options = {}) {
  if (!options.runtimeRoot) throw failure("neutral_host_runtime_root_required");
  const runtimeRoot = path.resolve(String(options.runtimeRoot));
  const hostInstallationId = safeId(options.hostInstallationId, "neutral_host_installation_invalid");
  // Only a test can report a lower release than this code.
  const releaseOrdinal = integerInRange(options.releaseOrdinal, HELLOLYNK_HOST_RELEASE_ORDINAL, 0, HELLOLYNK_HOST_RELEASE_ORDINAL);
  const recorded = await readExpectedRelease(discoveryLayout(runtimeRoot, hostInstallationId).expectedReleasePath)
    .catch(() => null);
  if (recorded && recorded.releaseOrdinal > releaseOrdinal && expectedReleaseHolds(recorded)) {
    throw failure("neutral_host_release_superseded");
  }
}

// For an explicit restore to an earlier release: a record this release wrote would hold the
// restored release back. A higher release's record or another format stays; none is fine.
export async function removeHelloLynkNeutralHostExpectedRelease(options = {}) {
  if (!options.runtimeRoot) throw failure("neutral_host_runtime_root_required");
  const runtimeRoot = path.resolve(String(options.runtimeRoot));
  const hostInstallationId = safeId(options.hostInstallationId, "neutral_host_installation_invalid");
  const layout = discoveryLayout(runtimeRoot, hostInstallationId);
  await assertNoReparseAncestors(layout.expectedReleasePath);
  await assertSafePath(layout.expectedReleasePath, { mustExist: false, directory: false });
  let text;
  try {
    const metadata = await fs.lstat(layout.expectedReleasePath);
    text = metadata.size > EXPECTED_RELEASE_MAX_BYTES ? "" : await fs.readFile(layout.expectedReleasePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return Object.freeze({ removed: false });
    throw error;
  }
  let recorded = null;
  try { recorded = JSON.parse(text); } catch {}
  if (recorded && typeof recorded === "object" && recorded.contract !== EXPECTED_RELEASE_CONTRACT) {
    return Object.freeze({ removed: false });
  }
  if (Number.isSafeInteger(recorded?.releaseOrdinal) && recorded.releaseOrdinal > HELLOLYNK_HOST_RELEASE_ORDINAL) {
    return Object.freeze({ removed: false, releaseOrdinal: recorded.releaseOrdinal });
  }
  await unlinkWithWindowsRetry(layout.expectedReleasePath);
  return Object.freeze({ removed: true });
}

// Records the asking release before a handover request. A fresh record of a higher release stays.
async function recordExpectedRelease(runtimeRoot, layout, releaseOrdinal) {
  await ensureSafeRuntimeDirectory(runtimeRoot, layout.directory);
  const recorded = await readExpectedRelease(layout.expectedReleasePath).catch(() => null);
  if (recorded && recorded.releaseOrdinal > releaseOrdinal && expectedReleaseHolds(recorded)) return;
  await atomicWriteJson(layout.expectedReleasePath, {
    contract: EXPECTED_RELEASE_CONTRACT,
    releaseOrdinal,
    publishedAt: new Date().toISOString(),
  });
}

// The Host that was asked to leave stamps the time again as it frees the slot: admitted work
// and an open native confirmation can keep it running past a hold counted from the request.
async function restampExpectedRelease(layout, releaseOrdinal) {
  const recorded = await readExpectedRelease(layout.expectedReleasePath);
  if (!recorded || recorded.releaseOrdinal <= releaseOrdinal) return;
  await atomicWriteJson(layout.expectedReleasePath, {
    contract: EXPECTED_RELEASE_CONTRACT,
    releaseOrdinal: recorded.releaseOrdinal,
    publishedAt: new Date().toISOString(),
  });
}

function expectedReleaseHolds(record) {
  return Math.abs(Date.now() - Date.parse(String(record.publishedAt || ""))) < EXPECTED_RELEASE_HOLD_MS;
}

export async function requestHelloLynkNeutralHost(options = {}) {
  const record = options.discovery;
  validateDiscovery(record);
  const capability = options.capability;
  if (!capability || typeof capability !== "object") throw failure("neutral_host_capability_required");
  const method = String(options.method || "GET").toUpperCase();
  const pathname = String(options.pathname || "");
  const rawBody = options.body == null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(options.body));
  const auth = createHostRequestAuth({
    capabilityId: capability.capabilityId,
    adapterId: capability.adapterId,
    hostGeneration: record.hostGeneration,
    method,
    pathname,
    timestampMs: Number(options.timestampMs ?? Date.now()),
    nonce: options.nonce || createHostNonce(),
    rawBody,
    secretBuffer: capability.secretBuffer,
  });
  const timeoutMs = options.timeoutMs == null ? null : Number(options.timeoutMs);
  if (timeoutMs != null && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100
    || timeoutMs > 30_000)) {
    throw failure("neutral_host_request_timeout_invalid");
  }

  const response = await fetch(`http://${record.host}:${record.port}${pathname}`, {
    method,
    headers: { "content-type": "application/json", ...auth.headers, ...(options.extraHeaders || {}) },
    body: rawBody.length ? rawBody : undefined,
    redirect: "error",
    ...((timeoutMs == null && !options.signal) ? {} : { signal: AbortSignal.any([
      ...(timeoutMs == null ? [] : [AbortSignal.timeout(timeoutMs)]), ...(options.signal ? [options.signal] : []),
    ]) }),
  });
  const body = await response.json().catch(() => ({}));
  return Object.freeze({ status: response.status, body });
}

export async function probeLegacyStoresReadOnly(paths = []) {
  const results = [];
  for (const candidate of paths) {
    const resolved = path.resolve(String(candidate || ""));
    if (!candidate) continue;
    try {
      const stat = await fs.stat(resolved);
      results.push(Object.freeze({ path: resolved, exists: true, kind: stat.isFile() ? "file" : "other" }));
    } catch (error) {
      if (error?.code === "ENOENT") results.push(Object.freeze({ path: resolved, exists: false, kind: "missing" }));
      else throw failure("neutral_host_legacy_probe_failed", error);
    }
  }
  return Object.freeze(results);
}

function normalizeApplicationInbox(value) {
  if (!value) return null;
  const localHistory = Object.fromEntries([
    "readWorkbenchState", "deleteSentLocal", "hideLocalConversation", "restoreLocalConversation", "clearLocalConversation", "deleteLocalConversation", "deleteArchivedConversations",
    "getReceiptHighWater", "getInboxReaderBoundary", "activateInboxReader",
    "listInboxClaimIds", "claimInboxMessage", "finishInboxClaim", "readIncomingForModel",
    "reserveInboxBatch", "listInboxBatches", "getInboxNativeAssignment", "getInboxNativeAssignments", "attemptInboxBatch", "confirmInboxBatch",
    "cancelInboxBatch", "expireInboxBatch", "closeInboxBatch", "claimInboxBatch",
    "readWorkbenchSummary", "readWorkbenchRevision", "queryConversationPage", "readLocalHistoryStats", "queryOutbox", "searchWorkbenchThreads", "markIncomingRead", "configureConversationAutoRead",
    "configureLocalHistory", "maintainLocalHistory", "listPendingInboxCandidates", "listInboxMessagesForDelegate", "getMessageCounts",
  ].filter((name) => typeof value[name] === "function").map((name) => [name, (...args) => value[name](...args)]));
  if (typeof value.list === "function" && typeof value.getIncoming === "function"
    && typeof value.updateIncoming === "function" && typeof value.deleteIncoming === "function") {
    return Object.freeze({
      ...localHistory,
      list: () => value.list(),
      getIncoming: (id) => value.getIncoming(id),
      markRead: (id) => value.updateIncoming(id, { status: "fetched" }),
      deleteRead: (ids) => value.deleteIncoming(ids),
    });
  }
  return null;
}

function normalizeApplicationContacts(value) {
  if (!value) return null;
  const list = typeof value.list === "function" ? () => value.list() : null;
  const upsert = typeof value.save === "function" ? (input) => value.save(input)
    : typeof value.upsert === "function" ? (input) => value.upsert(input) : null;
  const remove = typeof value.delete === "function" ? (id) => value.delete(id)
    : typeof value.remove === "function" ? (id) => value.remove(id) : null;
  const listForDelegate = typeof value.listForDelegate === "function"
    ? (delegateId) => value.listForDelegate(delegateId) : null;
  const listAuthorizedForDelegate = typeof value.listAuthorizedForDelegate === "function"
    ? (delegateId) => value.listAuthorizedForDelegate(delegateId) : null;
  const resolveAuthorizedSend = typeof value.resolveAuthorizedSend === "function"
    ? (contactId, delegateId, peerDelegateId) => value.resolveAuthorizedSend(contactId, delegateId, peerDelegateId) : null;
  const setAutonomousSendAuthorization = typeof value.setAutonomousSendAuthorization === "function"
    ? (contactId, delegateId, enabled, peerDelegateId) => value.setAutonomousSendAuthorization(contactId, delegateId, enabled, peerDelegateId)
    : null;
  return list && upsert && remove && listForDelegate && listAuthorizedForDelegate
    && resolveAuthorizedSend && setAutonomousSendAuthorization
    ? Object.freeze({
        list,
        upsert,
        remove,
        listForDelegate,
        listAuthorizedForDelegate,
        resolveAuthorizedSend,
        setAutonomousSendAuthorization,
        ...Object.fromEntries([
          "listReadableRoutesForDelegate",
          "resolveAuthorizedReply",
        ].filter((name) => typeof value[name] === "function")
          .map((name) => [name, (...args) => value[name](...args)])),
        ...(typeof value.resolveInstance === "function" ? { resolveInstance: (...args) => value.resolveInstance(...args) } : {}),
        ...(typeof value.upsertInstance === "function" ? { upsertInstance: (...args) => value.upsertInstance(...args) } : {}),
        ...(typeof value.renameInstance === "function" ? { renameInstance: (...args) => value.renameInstance(...args) } : {}),
        ...(typeof value.rename === "function" ? { rename: (...args) => value.rename(...args) } : {}),
        ...(typeof value.removeInstance === "function" ? { removeInstance: (...args) => value.removeInstance(...args) } : {}),
      })
    : null;
}

function normalizeApplicationContactRequests(value) {
  if (!value || typeof value.listForHuman !== "function") return null;
  return Object.freeze({ listForHuman: (input) => value.listForHuman(input) });
}

function resolveWorkbenchCapabilities(dependencies) {
  const {
    transport,
    applicationInbox,
    applicationContacts,
    applicationContactRequests,
    applicationOutbox,
    nativeBroker,
    humanRelationships,
    accountLauncher,
  } = dependencies;
  // A snapshot currently reads all four local projections atomically. Do not
  // advertise a partial surface that cannot produce the snapshot containing
  // its controls.
  if (!applicationInbox || !applicationContacts
    || !applicationContactRequests || !applicationOutbox) return Object.freeze([]);
  const capabilities = new Set([
    "contacts.read",
    "messages.read",
    "outbox.read",
    "search.local",
    "security.read",
    "threads.read",
    "messages.mark-read",
    "messages.delete-read",
    "outbox.request-retry",
    "contact.delete",
    "contact.authorization.manage",
  ]);
  if (typeof applicationInbox.deleteSentLocal === "function") capabilities.add("messages.delete-sent");
  if (typeof applicationInbox.markIncomingRead === "function") capabilities.add("messages.mark-all-read");
  if (typeof applicationInbox.configureConversationAutoRead === "function") capabilities.add("messages.auto-read.manage");
  if (["readWorkbenchState", "hideLocalConversation", "restoreLocalConversation", "clearLocalConversation"]
    .every((name) => typeof applicationInbox[name] === "function")) capabilities.add("threads.manage-local");
  if (humanRelationships && typeof humanRelationships.assertActiveRelationship === "function") {
    capabilities.add("contact.save");
  }
  if (typeof transport?.listAgentInstances === "function") {
    capabilities.add("contact.instances.list");
    if (typeof applicationContacts.upsertInstance === "function") capabilities.add("contact.instance.save");
  }
  if (typeof applicationContacts.removeInstance === "function") capabilities.add("contact.instance.delete");
  if (typeof applicationContacts.renameInstance === "function") capabilities.add("contact.instance.rename");
  if (typeof applicationContacts.rename === "function") capabilities.add("contact.rename");
  if (nativeBroker) capabilities.add("messages.request-send");
  if (humanRelationships && typeof humanRelationships.decide === "function") {
    capabilities.add("contact-request.respond");
  }
  if (humanRelationships && typeof humanRelationships.search === "function") {
    capabilities.add("principal.search");
  }
  if (humanRelationships && typeof humanRelationships.send === "function") {
    capabilities.add("contact-request.send");
  }
  if (humanRelationships && typeof humanRelationships.recoverDecision === "function") {
    capabilities.add("contact-request.recover-decision");
  }
  if (humanRelationships && typeof humanRelationships.clearResolved === "function"
    && HELLOLYNK_WORKBENCH_CAPABILITIES.includes(
      WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND,
    )) {
    capabilities.add(WORKBENCH_CLEAR_RESOLVED_CONTACT_REQUESTS_COMMAND);
  }
  if (humanRelationships && typeof humanRelationships.cancel === "function") {
    capabilities.add("contact-request.cancel");
  }
  if (humanRelationships && typeof humanRelationships.listRelationships === "function") {
    capabilities.add("relationships.read");
  }
  if (humanRelationships && typeof humanRelationships.endRelationship === "function") {
    capabilities.add("relationship.end");
  }
  if (humanRelationships && typeof humanRelationships.listBlocks === "function") {
    capabilities.add("blocks.read");
  }
  if (humanRelationships && typeof humanRelationships.removeBlock === "function") {
    capabilities.add("block.remove");
  }
  if (typeof accountLauncher === "function") capabilities.add("security.open-account");
  return Object.freeze([...capabilities].sort());
}

function normalizeApplicationOutbox(explicit, store, messenger) {
  const value = explicit || store;
  if (!value) return null;
  const list = typeof value.list === "function" ? () => value.list() : null;
  const get = typeof value.get === "function" ? (id) => value.get(id)
    : typeof value.getOutgoing === "function" ? (id) => value.getOutgoing(id)
    : list ? async (id) => (await list()).find((message) => message.clientMessageId === id) || null : null;
  const retry = typeof value.retry === "function" ? (id, delegateId, options) => value.retry(id, delegateId, options)
    : typeof messenger?.retry === "function" ? (id, _delegateId, options) => messenger.retry(id, options) : null;
  return list && get && retry ? Object.freeze({ list, get, retry,
    ...(typeof value.queryOutbox === "function" ? { queryOutbox: (input) => value.queryOutbox(input) } : {}),
  }) : null;
}

function projectInboxMessage(message, owner) {
  const localMessageId = safeApplicationId(message.localMessageId || message.id, "neutral_host_app_inbox_record_invalid");
  const binding = getMessageConversationBinding(message, owner);
  return {
    localMessageId,
    clientMessageId: safeApplicationId(message.clientMessageId || message.id, "neutral_host_app_inbox_record_invalid"),
    peerPrincipalId: optionalSafeId(message.peerPrincipalId || message.senderPrincipalId),
    peerHelloLynkId: optionalHelloLynkId(message.peerHelloLynkId || message.senderHelloLynkId),
    senderDelegateId: safeId(message.senderDelegateId, "neutral_host_app_inbox_record_invalid"),
    conversationKey: binding ? instanceConversationKey(binding) : null,
    localDelegateId: binding?.localDelegateId ?? null,
    peerDelegateId: binding?.peerDelegateId ?? null,
    senderPrincipalDisplayName: optionalDisplayName(message.senderPrincipalDisplayName),
    senderDelegateDisplayName: optionalDisplayName(message.senderDelegateDisplayName),
    messageType: safeId(message.messageType || "text", "neutral_host_app_inbox_record_invalid"),
    text: safeStoredText(message.text),
    unread: isUnreadIncoming(message),
    createdAt: safeIsoTimestamp(message.createdAt || message.receivedAt),
    updatedAt: safeIsoTimestamp(message.updatedAt || message.readAt || message.receivedAt || message.createdAt),
  };
}

function projectContact(contact) {
  return {
    contactId: safeApplicationId(contact.contactId, "neutral_host_app_contact_record_invalid"),
    hellolynkId: safeHelloLynkId(contact.hellolynkId, "neutral_host_app_contact_record_invalid"),
    displayName: safeDisplayName(contact.displayName, "neutral_host_app_contact_record_invalid"),
    autonomousSendAuthorized: contact.autonomousSendAuthorized === true,
    createdAt: safeIsoTimestamp(contact.createdAt),
    updatedAt: safeIsoTimestamp(contact.updatedAt),
  };
}

function projectContactAuthorizationMutation(contact) {
  return {
    contactId: safeApplicationId(contact.contactId, "neutral_host_app_contact_record_invalid"),
    autonomousSendAuthorized: contact.autonomousSendAuthorized === true,
    updatedAt: safeIsoTimestamp(contact.updatedAt),
  };
}

function projectAuthorizedContact(contact) {
  return {
    contactId: safeApplicationId(contact.contactId, "neutral_host_app_contact_record_invalid"),
    displayName: safeDisplayName(contact.displayName, "neutral_host_app_contact_record_invalid"),
    recipientDelegateId: safeId(contact.recipientDelegateId, "neutral_host_app_contact_record_invalid"),
    instanceDisplayName: safeDisplayName(contact.instanceDisplayName, "neutral_host_app_contact_record_invalid"),
  };
}

function projectAuthorizedInboxMetadata(message, contact, binding, activationAfterSeq = null) {
  // First activation and durable claims prevent history from becoming new work.
  const wakeEligible = message.messageType !== "local-deleted"
    && message.automaticDeliveryState !== "expired"
    && Number.isSafeInteger(activationAfterSeq) && activationAfterSeq >= 0
    && Number.isSafeInteger(message.receiptSeq) && message.receiptSeq > 0
    && message.receiptSeq > activationAfterSeq;
  return {
    localMessageId: safeApplicationId(message.localMessageId || message.id, "neutral_host_app_inbox_record_invalid"),
    contactId: contact ? safeApplicationId(contact.contactId, "neutral_host_app_contact_record_invalid") : null,
    displayName: safeDisplayName(contact?.displayName || (message.peerHelloLynkId
      || message.senderHelloLynkId || binding.peerPrincipalId).slice(0, 80), "neutral_host_app_contact_record_invalid"),
    // The contact name identifies the person; the saved instance label identifies
    // their AI. Neither label is an authority or a substitute for the bound IDs.
    ...(contact?.instanceDisplayName ? {
      peerInstanceDisplayName: safeDisplayName(contact.instanceDisplayName, "neutral_host_app_contact_record_invalid"),
    } : {}),
    conversationKey: instanceConversationKey(binding),
    localDelegateId: binding.localDelegateId,
    peerDelegateId: binding.peerDelegateId,
    // Already verified against the encrypted envelope and original local send
    // by the indexed store. This is a correlation identifier, never a body or
    // a caller-supplied native session destination.
    ...(message.replyToClientMessageId ? { replyToClientMessageId: safeApplicationId(message.replyToClientMessageId, "neutral_host_app_inbox_record_invalid") } : {}),
    ...(message.targetConversationId ? { targetConversationId: nativeConversationId(message.targetConversationId) } : {}),
    unread: isUnreadIncoming(message),
    ...(message.automaticDeliveryState === "expired" ? { automaticDeliveryState: "expired" } : {}),
    wakeEligible,
    createdAt: safeIsoTimestamp(message.createdAt || message.receivedAt),
  };
}

function projectAuthorizedInboxMessage(message, contact, binding, activationAfterSeq = null, automatic = false) {
  return {
    ...projectAuthorizedInboxMetadata(message, contact, binding, activationAfterSeq),
    peerPrincipalId: binding.peerPrincipalId,
    text: safeStoredText(message.text),
    source: "hellolynk_external_message",
    externalContentIsUntrustedData: true,
    readDoesNotMarkRead: automatic !== true,
    ...(automatic === true ? { humanReadAutomatically: true } : {}),
  };
}

function projectContactMutation(contact) {
  return {
    contactId: safeApplicationId(contact.contactId, "neutral_host_app_contact_record_invalid"),
    hellolynkId: safeHelloLynkId(contact.hellolynkId, "neutral_host_app_contact_record_invalid"),
    displayName: safeDisplayName(contact.displayName, "neutral_host_app_contact_record_invalid"),
    updatedAt: safeIsoTimestamp(contact.updatedAt),
  };
}

function projectContactRequest(record) {
  if (record?.humanOnly !== true || record?.modelVisibility !== "none") {
    throw failure("neutral_host_app_contact_request_record_invalid");
  }
  const introText = safeStoredText(record.introText);
  const introWeight = record.introWeight;
  const state = safeId(record.state, "neutral_host_app_contact_request_record_invalid");
  const serverContactRequestId = record.serverContactRequestId == null
    ? null : safeApplicationId(
      record.serverContactRequestId,
      "neutral_host_app_contact_request_record_invalid",
    );
  const hasDecisionOutcome = Object.hasOwn(record, "decisionOutcome");
  const hasDecisionAction = Object.hasOwn(record, "decisionAction");
  if (hasDecisionOutcome !== hasDecisionAction) {
    throw failure("neutral_host_app_contact_request_record_invalid");
  }
  const decisionOutcome = hasDecisionOutcome
    ? record.decisionOutcome
    : null;
  const decisionAction = hasDecisionAction ? record.decisionAction : null;
  const actionReady = hasDecisionOutcome ? record.actionReady : false;
  if (typeof record.introText !== "string" || Buffer.byteLength(introText, "utf8") > 256
    || !Number.isSafeInteger(introWeight) || introWeight < 0 || introWeight > 40
    || !CONTACT_REQUEST_STATES.has(state)
    || typeof record.actionReady !== "boolean"
    || !new Set([null, "unknown", "recovery-required"]).has(decisionOutcome)
    || (decisionAction != null && !new Set(["accept", "reject", "block"]).has(decisionAction))
    || (actionReady && (serverContactRequestId == null
      || state !== "pending"
      || decisionOutcome != null
      || decisionAction != null))
    || (state !== "pending" && actionReady)
    || ((decisionOutcome === "unknown") !== (decisionAction != null))
    || (decisionOutcome != null && (state !== "pending" || actionReady))) {
    throw failure("neutral_host_app_contact_request_record_invalid");
  }
  return {
    humanOnly: true,
    modelVisibility: "none",
    localRecordId: safeApplicationId(
      record.localRecordId,
      "neutral_host_app_contact_request_record_invalid",
    ),
    serverContactRequestId,
    state,
    actionReady,
    decisionOutcome,
    decisionAction,
    introText,
    introWeight,
    sender: {
      hellolynkId: safeHelloLynkId(record.sender?.hellolynkId, "neutral_host_app_contact_request_record_invalid"),
      verifiedDisplayName: optionalDisplayName(record.sender?.verifiedDisplayName),
    },
    receivedAt: safeIsoTimestamp(record.receivedAt),
    serverUpdatedAt: record.serverUpdatedAt == null ? null : safeIsoTimestamp(record.serverUpdatedAt),
  };
}

function projectOutboxMessage(message) {
  const text = safeStoredText(message.text);
  const status = safeId(message.status || message.rawStatus, "neutral_host_app_outbox_record_invalid");
  return {
    localMessageId: safeApplicationId(message.localMessageId, "neutral_host_app_outbox_record_invalid"),
    clientMessageId: safeApplicationId(message.clientMessageId, "neutral_host_app_outbox_record_invalid"),
    recipientHelloLynkId: safeHelloLynkId(message.recipientHelloLynkId || message.peerHelloLynkId, "neutral_host_app_outbox_record_invalid"),
    messageType: safeId(message.messageType || "text", "neutral_host_app_outbox_record_invalid"),
    text,
    textSha256: crypto.createHash("sha256").update(text, "utf8").digest("hex"),
    status,
    retryAllowed: message.lastErrorCode !== "reply_target_deleted" && MANUAL_RETRYABLE_STATUSES.has(status),
    createdAt: safeIsoTimestamp(message.createdAt),
    updatedAt: safeIsoTimestamp(message.updatedAt || message.createdAt),
  };
}

function projectOutboxMutation(message) {
  const status = safeId(message.status || message.rawStatus, "neutral_host_app_outbox_record_invalid");
  return {
    clientMessageId: safeApplicationId(message.clientMessageId, "neutral_host_app_outbox_record_invalid"),
    status,
    retryAllowed: message.lastErrorCode !== "reply_target_deleted" && MANUAL_RETRYABLE_STATUSES.has(status),
    updatedAt: safeIsoTimestamp(message.updatedAt || message.createdAt),
  };
}

function projectApplicationChange(event) {
  return {
    cursor: event.cursor,
    type: event.type,
    entityId: event.entityId,
    changedAt: event.changedAt,
    modelVisibility: "none",
  };
}

function isUnreadIncoming(message) {
  if (typeof message?.unread === "boolean") return message.unread;
  return message?.status === "received";
}

function requireApplicationStore(value, code) {
  if (!value) throw hostApplicationFailure("host_app_unavailable", code);
}

function optionalSafeId(value) {
  return value == null ? null : safeId(value, "neutral_host_app_record_invalid");
}

function optionalHelloLynkId(value) {
  return value == null ? null : safeHelloLynkId(value, "neutral_host_app_record_invalid");
}

function optionalDisplayName(value) {
  return value == null ? null : safeDisplayName(value, "neutral_host_app_record_invalid");
}

function safeHelloLynkId(value, code) {
  const normalized = String(value || "");
  if (!HELLOLYNK_ID.test(normalized)) throw failure(code);
  return normalized;
}

function safeApplicationId(value, code) {
  const normalized = String(value || "");
  if (!APPLICATION_ID.test(normalized)) throw failure(code);
  return normalized;
}

function safeDisplayName(value, code) {
  const normalized = String(value ?? "");
  if (!normalized || [...normalized].length > 80 || /[\u0000-\u001F\u007F-\u009F]/u.test(normalized)) {
    throw failure(code);
  }
  return normalized;
}

function projectHumanSendStatus(value) {
  const status = assertPlainRecord(value, "neutral_host_human_send_status_invalid");
  return {
    kind: "message-send",
    actionId: status.actionId,
    state: status.state,
    code: status.code ?? null,
    createdAtMs: status.createdAtMs,
    expiresAtMs: status.expiresAtMs,
  };
}

function safeStoredText(value) {
  const text = String(value ?? "");
  if (Buffer.byteLength(text, "utf8") > 64 * 1024 || text.includes("\u0000")) {
    throw failure("neutral_host_app_record_invalid");
  }
  return text;
}

function safeIsoTimestamp(value) {
  const timestamp = Date.parse(String(value || ""));
  if (!Number.isFinite(timestamp)) throw failure("neutral_host_app_record_invalid");
  return new Date(timestamp).toISOString();
}

function hostApplicationFailure(code, causeCode) {
  const error = new Error(code);
  error.code = code;
  if (causeCode) error.causeCode = causeCode;
  return error;
}

async function claimInstallationLock(lockPath, discoveryPath, tuple, staleAudit = true) {
  return withLocalProcessLock(lockPath, () => claimInstallationLockUnderGuard(lockPath, discoveryPath, tuple, staleAudit));
}

async function claimInstallationLockUnderGuard(lockPath, discoveryPath, tuple, staleAudit = true) {
  const token = crypto.randomBytes(32).toString("hex");
  const candidate = `${lockPath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.candidate`;
  const ownerProcess = await inspectProcessIdentity(process.pid);
  const candidateRecord = Object.freeze({
    contract: INSTALLATION_LOCK_CONTRACT,
    tupleDigest: digestTuple(tuple),
    pid: process.pid,
    ownerIdentity: ownerProcess?.identity || null,
    claimedAtMs: Date.now(),
    token,
  });
  let candidateHandle;
  try {
    await assertSafePath(lockPath, { mustExist: false, directory: false });
    candidateHandle = await fs.open(candidate, "wx", 0o600);
    await candidateHandle.writeFile(`${JSON.stringify(candidateRecord)}\n`, "utf8");
    await candidateHandle.sync();
    await candidateHandle.close();
    candidateHandle = null;
    await linkWithWindowsRetry(candidate, lockPath);
    // Publication already succeeded. A leftover candidate is harmless; it
    // must not turn this successful claim into an ownerless rejected promise.
    await fs.unlink(candidate).catch(() => {});
    return Object.freeze({
      token,
      async release() {
        return withLocalProcessLock(lockPath, async () => {
          let current;
          try {
            current = (await readInstallationLock(lockPath)).record;
          } catch (error) {
            if (error?.code === "ENOENT") return;
            throw failure("neutral_host_singleton_lock_invalid", error);
          }
          if (current?.token !== token || current?.pid !== process.pid) {
            throw failure("neutral_host_singleton_lock_ownership_lost");
          }
          await unlinkWithWindowsRetry(lockPath);
        });
      },
    });
  } catch (error) {
    await candidateHandle?.close().catch(() => {});
    await fs.unlink(candidate).catch(() => {});
    if (error?.code !== "EEXIST") throw failure("neutral_host_singleton_claim_failed", error);
    let lockSnapshot;
    try {
      lockSnapshot = await readInstallationLock(lockPath);
    } catch { throw failure("neutral_host_singleton_lock_invalid"); }
    const existing = lockSnapshot.record;
    validateLockRecord(existing);
    if (existing?.tupleDigest !== digestTuple(tuple)) throw failure("neutral_host_singleton_owner_mismatch");
    if (staleAudit) {
      const discoveryHealthy = await discoveryRecordHealthy(
        discoveryPath,
        existing.tupleDigest,
        existing.pid,
      );
      if (discoveryHealthy) throw failure("neutral_host_already_running");
      const alive = processAlive(existing.pid);
      if (alive === null) throw failure("neutral_host_singleton_owner_unknown");
      if (!alive) return reclaimInstallationLock(lockPath, discoveryPath, tuple, lockSnapshot);

      const observedOwner = await inspectProcessIdentity(existing.pid);
      if (existing.contract === INSTALLATION_LOCK_CONTRACT
        && existing.ownerIdentity && observedOwner?.identity === existing.ownerIdentity) {
        // A matching process-birth identity is authoritative during the interval
        // before discovery becomes healthy. PID liveness alone is never enough.
        throw failure("neutral_host_already_running");
      }
      if (existing.contract === INSTALLATION_LOCK_CONTRACT
        && existing.ownerIdentity && observedOwner?.identity
        && observedOwner.identity !== existing.ownerIdentity) {
        return reclaimInstallationLock(lockPath, discoveryPath, tuple, lockSnapshot);
      }

      const aliveAfterInspection = processAlive(existing.pid);
      if (aliveAfterInspection === false) {
        return reclaimInstallationLock(lockPath, discoveryPath, tuple, lockSnapshot);
      }
      if (aliveAfterInspection === null) throw failure("neutral_host_singleton_owner_unknown");

      // Legacy locks did not persist a process-birth marker. A current process
      // born after the lock is conclusive PID-reuse evidence; otherwise retain a
      // short startup grace and fail safely instead of risking split ownership.
      if (observedOwner?.startedAtMs != null
        && observedOwner.startedAtMs > lockSnapshot.mtimeMs + PROCESS_START_REUSE_TOLERANCE_MS) {
        return reclaimInstallationLock(lockPath, discoveryPath, tuple, lockSnapshot);
      }
      if (Date.now() - lockSnapshot.mtimeMs <= INSTALLATION_LOCK_STARTUP_GRACE_MS) {
        throw failure("neutral_host_already_running");
      }
      throw failure("neutral_host_singleton_owner_unknown");
    }
    throw failure("neutral_host_already_running");
  }
}

function validateLockRecord(value) {
  const legacy = value?.contract == null;
  const expectedKeys = legacy
    ? ["pid", "token", "tupleDigest"]
    : ["claimedAtMs", "contract", "ownerIdentity", "pid", "token", "tupleDigest"];
  const actualKeys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  if (!value || actualKeys.length !== expectedKeys.length
    || actualKeys.some((item, index) => item !== expectedKeys[index])
    || (!legacy && value.contract !== INSTALLATION_LOCK_CONTRACT)
    || !/^[a-f0-9]{64}$/.test(String(value.tupleDigest || ""))
    || !Number.isSafeInteger(value.pid) || value.pid < 1
    || (!legacy && (!Number.isSafeInteger(value.claimedAtMs) || value.claimedAtMs < 1))
    || (!legacy && value.ownerIdentity != null
      && !/^[A-Za-z0-9][A-Za-z0-9:._-]{7,198}$/.test(String(value.ownerIdentity)))
    || !/^[a-f0-9]{64}$/.test(String(value.token || ""))) {
    throw failure("neutral_host_singleton_lock_invalid");
  }
}

async function readInstallationLock(lockPath) {
  await assertSafePath(lockPath, { mustExist: true, directory: false });
  const metadata = await fs.lstat(lockPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > INSTALLATION_LOCK_MAX_BYTES) {
    throw failure("neutral_host_singleton_lock_invalid");
  }
  const text = await fs.readFile(lockPath, "utf8");
  let record;
  try { record = JSON.parse(text); } catch { throw failure("neutral_host_singleton_lock_invalid"); }
  validateLockRecord(record);
  return Object.freeze({ record, text, mtimeMs: metadata.mtimeMs });
}

async function reclaimInstallationLock(lockPath, discoveryPath, tuple, snapshot) {
  await new Promise((resolve) => setTimeout(resolve, 25));
  let second;
  try { second = await readInstallationLock(lockPath); } catch {
    throw failure("neutral_host_singleton_lock_changed");
  }
  if (second.text !== snapshot.text) throw failure("neutral_host_singleton_lock_changed");
  const quarantine = `${lockPath}.stale.${Date.now()}.${crypto.randomBytes(8).toString("hex")}`;
  try { await fs.rename(lockPath, quarantine); } catch (renameError) {
    throw failure("neutral_host_singleton_stale_quarantine_failed", renameError);
  }
  try {
    return await claimInstallationLockUnderGuard(lockPath, discoveryPath, tuple, false);
  } finally {
    await fs.unlink(quarantine).catch(() => {});
  }
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    return null;
  }
}

async function discoveryRecordHealthy(discoveryPath, tupleDigest, expectedPid) {
  let record;
  try {
    await assertSafePath(discoveryPath, { mustExist: true, directory: false });
    record = JSON.parse(await fs.readFile(discoveryPath, "utf8"));
    validateDiscovery(record);
  } catch { return false; }
  if (record.tupleDigest !== tupleDigest || record.pid !== expectedPid) return false;
  const response = await fetch(`http://${record.host}:${record.port}${HELLOLYNK_HOST_PATHS.health}`, {
    redirect: "error",
    signal: AbortSignal.timeout(500),
  }).catch(() => null);
  if (!response?.ok) return false;
  const body = await response.json().catch(() => null);
  return body?.status === "running" && body?.hostGeneration === record.hostGeneration;
}

async function linkWithWindowsRetry(candidate, target) {
  let last;
  for (const delayMs of [0, 10, 25, 50, 100, 200]) {
    if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
    try { await fs.link(candidate, target); return; } catch (error) {
      if (error?.code === "EEXIST") throw error;
      last = error;
      if (!isWindowsTransientFsError(error)) break;
    }
  }
  throw last;
}

async function unlinkWithWindowsRetry(target) {
  let last;
  for (const delayMs of [0, 10, 25, 50, 100, 200]) {
    if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
    try { await fs.unlink(target); return; } catch (error) {
      if (error?.code === "ENOENT") return;
      last = error;
      if (!isWindowsTransientFsError(error)) break;
    }
  }
  throw last;
}

function discoveryLayout(runtimeRoot, hostInstallationId) {
  const key = crypto.createHash("sha256").update(hostInstallationId).digest("hex");
  const directory = path.join(runtimeRoot, "neutral-host");
  return {
    directory,
    lockPath: path.join(directory, `${key}.lock`),
    discoveryPath: path.join(directory, `${key}.json`),
    receiverStatePath: path.join(directory, `${key}.receiver.json`),
    handoverPath: path.join(directory, `${key}.handover.json`),
    expectedReleasePath: path.join(directory, `${key}.expected-release.json`),
  };
}

async function readHandoverRequest(target) {
  const metadata = await fs.lstat(target);
  if (!metadata.isFile() || metadata.size > HANDOVER_REQUEST_MAX_BYTES) return null;
  const record = JSON.parse(await fs.readFile(target, "utf8"));
  return record?.contract === HANDOVER_REQUEST_CONTRACT ? record : null;
}

async function readExpectedRelease(target) {
  const metadata = await fs.lstat(target);
  if (!metadata.isFile() || metadata.size > EXPECTED_RELEASE_MAX_BYTES) return null;
  const record = JSON.parse(await fs.readFile(target, "utf8"));
  return record?.contract === EXPECTED_RELEASE_CONTRACT && Number.isSafeInteger(record.releaseOrdinal)
    && record.releaseOrdinal >= 0 ? record : null;
}

// A Host without the field is older than every release that has an ordinal.
function releaseOrdinalOf(health) {
  return Number.isSafeInteger(health?.releaseOrdinal) && health.releaseOrdinal > 0 ? health.releaseOrdinal : 0;
}

// null only when there is no discovery record; an unreadable one throws.
async function readDiscoveryRecord(discoveryPath) {
  let text;
  try { text = await fs.readFile(discoveryPath, "utf8"); }
  catch (error) { if (error?.code === "ENOENT") return null; throw error; }
  const record = JSON.parse(text);
  validateDiscovery(record);
  return record;
}

// The health body when the recorded generation is running, otherwise null.
async function discoveryHealth(record) {
  const health = await fetch(`http://${record.host}:${record.port}${HELLOLYNK_HOST_PATHS.health}`, {
    redirect: "error",
    signal: AbortSignal.timeout(2_000),
  }).catch(() => null);
  const body = health?.status === 200 ? await health.json().catch(() => null) : null;
  return body?.hostGeneration === record.hostGeneration && body?.status === "running" ? body : null;
}

async function discoveryRunning(record) {
  return await discoveryHealth(record) !== null;
}

async function atomicWriteJson(target, value) {
  await assertSafePath(target, { mustExist: false, directory: false });
  const temporary = `${target}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  try { await fs.rename(temporary, target); } catch (error) { await fs.unlink(temporary).catch(() => {}); throw error; }
}

async function removeOwnedDiscovery(target, generation) {
  let current;
  try {
    await assertSafePath(target, { mustExist: true, directory: false });
    current = JSON.parse(await fs.readFile(target, "utf8"));
  } catch { return; }
  if (current?.hostGeneration === generation) await unlinkWithWindowsRetry(target).catch(() => {});
}

async function ensureSafeRuntimeDirectory(runtimeRoot, hostDirectory) {
  await assertNoReparseAncestors(path.dirname(runtimeRoot));
  await fs.mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  await assertNoReparseAncestors(runtimeRoot);
  await assertSafePath(runtimeRoot, { mustExist: true, directory: true });
  await fs.mkdir(hostDirectory, { recursive: true, mode: 0o700 });
  await assertSafePath(hostDirectory, { mustExist: true, directory: true });
}

async function assertNoReparseAncestors(target) {
  let current = path.resolve(target);
  while (true) {
    let stat;
    try { stat = await fs.lstat(current); } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      current = path.dirname(current);
      continue;
    }
    if (stat.isSymbolicLink()) throw failure("neutral_host_unsafe_reparse_path");
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function assertSafePath(target, options) {
  let stat;
  try { stat = await fs.lstat(target); } catch (error) {
    if (error?.code === "ENOENT" && options.mustExist === false) return;
    throw error;
  }
  if (stat.isSymbolicLink()) throw failure("neutral_host_unsafe_reparse_path");
  if (options.directory === true && !stat.isDirectory()) throw failure("neutral_host_runtime_path_invalid");
  if (options.directory === false && !stat.isFile()) throw failure("neutral_host_runtime_path_invalid");
}

function isWindowsTransientFsError(error) {
  return process.platform === "win32" && ["EPERM", "EACCES", "EBUSY"].includes(error?.code);
}

function normalizeTuple(options) {
  return Object.freeze({
    region: safeId(options.region, "neutral_host_region_invalid"),
    principalId: safeId(options.principalId, "neutral_host_principal_invalid"),
    hostInstallationId: safeId(options.hostInstallationId, "neutral_host_installation_invalid"),
  });
}

function normalizeEndpoints(value, tuple) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) throw failure("neutral_host_endpoints_invalid");
  const map = new Map();
  for (const item of value) {
    const delegateId = safeId(item?.delegateId, "neutral_host_delegate_invalid");
    if (item?.principalId !== tuple.principalId || item?.hostInstallationId !== tuple.hostInstallationId) {
      throw failure("neutral_host_endpoint_owner_mismatch");
    }
    if (!item.e2ee || typeof item.e2ee.openIncoming !== "function") throw failure("neutral_host_endpoint_e2ee_invalid");
    if (!item.contactE2ee || typeof item.contactE2ee.openIncoming !== "function") {
      throw failure("neutral_host_endpoint_contact_e2ee_invalid");
    }
    if (map.has(delegateId)) throw failure("neutral_host_endpoint_duplicate");
    map.set(delegateId, Object.freeze({ ...item, delegateId }));
  }
  return map;
}

function workbenchSource(adapterId) {
  const id = safeId(adapterId, "neutral_host_workbench_adapter_invalid");
  const clients = {
    codex: ["mcp-app-rpc", "Codex"],
    cursor: ["cursor-webview-rpc", "Cursor"],
    openclaw: ["loopback-http", "OpenClaw"],
    "trae-work": ["loopback-http", "TRAE Work"],
    workbuddy: ["loopback-http", "WorkBuddy"],
  };
  const [transport, clientLabel] = clients[id] || ["loopback-http", id];
  return Object.freeze({
    mode: "neutral-host",
    transport,
    clientId: id,
    clientLabel,
  });
}

function workbenchSuccess(requestId, snapshot, result = {}) {
  return {
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: true,
    requestId,
    revision: snapshot.revision,
    changeCursor: snapshot.changeCursor,
    result,
  };
}

function workbenchFailure(requestId, code, snapshot, outcome) {
  const known = outcome === "known-failed";
  return {
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: false,
    requestId,
    revision: known ? snapshot?.revision ?? null : null,
    changeCursor: known ? snapshot?.changeCursor ?? null : null,
    error: {
      code,
      retryable: false,
      outcome,
      retryAfterMs: null,
      currentRevision: known ? snapshot?.revision ?? null : null,
    },
  };
}

function knownWorkbenchCommandFailure(error) {
  const code = String(error?.code || "");
  if (new Set([
    "human_relationship_decision_outcome_unknown",
    "human_relationship_cancel_outcome_unknown",
    "human_relationship_cancel_response_invalid",
    "human_relationship_relationship_end_outcome_unknown",
    "human_relationship_relationship_end_response_invalid",
    "human_relationship_block_remove_outcome_unknown",
    "human_relationship_block_remove_response_invalid",
    // The cloud write has already succeeded before these local/invariant
    // checks fail. They cannot prove rejection or permit another submission.
    "human_relationship_local_authorization_revoke_failed",
    "host_app_relationship_history_invariant_failed",
    "host_app_block_remove_invariant_failed",
  ]).has(code)) return null;
  if (code === "human_relationship_cancel_known_failed") {
    return "host_app_contact_request_cancel_failed";
  }
  if (code === "human_relationship_relationship_end_known_failed") {
    return "host_app_relationship_end_failed";
  }
  if (code === "human_relationship_block_remove_known_failed") {
    return "host_app_block_remove_failed";
  }
  if (code === "human_relationship_decision_known_failed") {
    return "host_app_contact_request_decision_failed";
  }
  if (code === "human_relationship_decision_not_applied") {
    return "host_app_contact_request_decision_not_applied";
  }
  if (code === "human_relationship_target_expired") return "host_app_contact_target_expired";
  if (code === "human_relationship_retry_input_conflict") return "host_app_contact_request_input_conflict";
  if (code === "contact_identity_mismatch") return "host_app_authorization_required";
  if (["local_history_unread_protected", "local_history_outgoing_protected", "local_history_task_protected"].includes(code)) return `host_app_${code}`;
  if (code === "local_history_record_not_found") return "host_app_record_not_found";
  if (["local_history_scope_invalid", "local_history_thread_invalid", "local_history_message_invalid"].includes(code)) {
    return "host_app_input_invalid";
  }
  if (["contact_not_found", "contact_instance_not_found"].includes(code)) return "host_app_record_not_found";
  if (/^contact_(?:authorization|delegate)/.test(code)) return "host_app_input_invalid";
  if (/^contact_request_intro_[a-z0-9_]{1,80}$/.test(code)) return code;
  if (error?.httpStatus === 409 && KNOWN_CONTACT_REQUEST_SEND_FAILURE_CODES.has(code)) return code;
  if (/^human_relationship_[a-z0-9_]{1,100}$/.test(code)) return "host_app_contact_request_failed";
  if (/^host_app_[a-z0-9_]{1,100}$/.test(code)) return code;
  if (/^human_confirmation_[a-z0-9_]{1,100}$/.test(code)) return code;
  return null;
}

function validateDiscovery(record) {
  if (!record || record.contractId !== HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT
    || record.host !== LOOPBACK_HOST || !Number.isInteger(record.port) || record.port < 1 || record.port > 65535
    || !/^[a-f0-9]{48}$/.test(String(record.hostGeneration || ""))
    || !/^[a-f0-9]{64}$/.test(String(record.tupleDigest || ""))) {
    throw failure("neutral_host_discovery_invalid");
  }
}

function digestTuple(tuple) {
  return crypto.createHash("sha256")
    .update(`${tuple.region}\0${tuple.principalId}\0${tuple.hostInstallationId}`)
    .digest("hex");
}

function requireInterface(value, methods, code) {
  if (!value || methods.some((method) => typeof value[method] !== "function")) throw failure(code);
}

function trackOperation(promise, set) {
  const tracked = Promise.resolve(promise);
  set.add(tracked);
  tracked.finally(() => set.delete(tracked)).catch(() => {});
  return tracked;
}

async function waitForOperations(set, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (set.size > 0) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw failure("neutral_host_drain_timeout");
    await Promise.race([Promise.allSettled([...set]), new Promise((resolve) => setTimeout(resolve, Math.min(remaining, 25)))]);
  }
}

function listenLoopback(server, port) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw failure("neutral_host_port_invalid");
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, LOOPBACK_HOST, () => { server.off("error", reject); resolve(); });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function readBody(request, maximum) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximum) { reject(failure("neutral_host_request_too_large")); request.destroy(); return; }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function writeJson(response, status, body) {
  const raw = Buffer.from(JSON.stringify(body));
  response.writeHead(status, { "content-type": "application/json", "content-length": raw.length, "cache-control": "no-store" });
  response.end(raw);
}

function isLoopbackAddress(value) {
  return value === "127.0.0.1" || value === "::1" || value === "::ffff:127.0.0.1";
}

function assertNoSensitiveEventFields(value) {
  for (const key of Object.keys(value)) {
    if (/text|body|content|secret|token|credential|envelope|prekey/i.test(key)) throw failure("neutral_host_change_event_sensitive");
  }
}

function isInboundLocalCapacityError(error) {
  return INBOUND_LOCAL_CAPACITY_CODES.has(String(error?.code || ""));
}

function safeId(value, code) {
  const normalized = String(value || "");
  if (!SAFE_ID.test(normalized)) throw failure(code);
  return normalized;
}

function assertPlainRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw failure(code);
  return value;
}

function integerInRange(value, fallback, minimum, maximum) {
  const normalized = Number(value ?? fallback);
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) throw failure("neutral_host_limit_invalid");
  return normalized;
}

function nowMs(clock) {
  return typeof clock === "function" ? clock() : typeof clock?.now === "function" ? clock.now() : Date.now();
}

function retryAtTimestamp(value) {
  if (value == null || value === "") return null;
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function safeCode(error, fallback) {
  const code = String(error?.code || fallback);
  return /^[a-z][a-z0-9_]{1,127}$/.test(code) ? code : fallback;
}

function isTransientWorkbenchCloudFailure(error) {
  return new Set(["host_transport_request_timeout", "host_transport_request_failed"]).has(error?.code)
    || (Number.isInteger(error?.httpStatus) && error.httpStatus >= 500 && error.httpStatus <= 599);
}

function isMissingLegacyLifecycleRoute(error) {
  return error?.code === "host_transport_http_error" && error?.httpStatus === 404;
}

function failure(code, cause) {
  const error = new Error(code, cause ? { cause } : undefined);
  error.code = code;
  return error;
}
