import { nativeConversationId, nativeConversationTitle, nativeConversationQuery, nativeDirectoryResult } from "./hellolynk-native-conversations.mjs";
import { modelInboxCaller } from "./hellolynk-model-inbox.mjs";
import crypto from "node:crypto";
import { projectInboxReadState } from "./hellolynk-inbox-read-state.mjs";
import { LOCAL_IDENTITY_PROOF_PATH, validateLocalIdentityProofRequest, signLocalIdentityProof } from "./hellolynk-local-identity-trust.mjs";
import { LOCAL_PEER_EXCHANGE_PATH, validateLocalPeerRequest, signLocalPeerResult } from "./hellolynk-local-peer-transport.mjs";
import {
  asRawBody,
  assertCapabilityRecord,
  assertHostGeneration,
  assertIdentifier,
  assertMethod,
  assertPathname,
  assertRequestFresh,
  createNonceReplayGuard,
  hostRequestAuthMatches,
  HELLOLYNK_HOST_AUTH_HEADERS,
  HELLOLYNK_HOST_REQUEST_MAX_SKEW_MS,
} from "./hellolynk-host-auth.mjs";
import {
  HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES,
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
  validateWorkbenchReadRequest,
  validateWorkbenchSnapshot,
} from "../workbench/contract.mjs";
import {
  createHelloLynkWorkbenchActionGrantRegistry,
  rejectConsumedHelloLynkWorkbenchActionGrant,
  revokeHelloLynkWorkbenchActionGrants,
} from "./hellolynk-workbench-action-grants.mjs";

export const HELLOLYNK_HOST_CONTRACT = "hellolynk-host-v2";
export const HELLOLYNK_HOST_ATTACHMENT_HEARTBEAT_MS = 10_000;
export const HELLOLYNK_HOST_ATTACHMENT_LEASE_MS = 30_000;
export const HELLOLYNK_HOST_IDLE_SHUTDOWN_GRACE_MS = 10_000;

export const HELLOLYNK_HOST_SCOPES = Object.freeze({
  statusRead: "status:read",
  attachmentsManage: "attachments:manage",
  uiLaunch: "ui:launch",
  agentMessagesSend: "agent-messages:send",
  humanUiSurface: "surface:human-ui",
  appInboxRead: "app-data:inbox-read",
  appInboxManage: "app-data:inbox-manage",
  appContactsRead: "app-data:contacts-read",
  appContactsManage: "app-data:contacts-manage",
  appAuthorizedMessaging: "app-data:authorized-messaging",
  appContactRequestsRead: "app-data:contact-requests-read",
  appOutboxRead: "app-data:outbox-read",
  appOutboxRetry: "app-data:outbox-retry",
  appHumanSendRequest: "app-data:human-send-request",
  appChangesRead: "app-data:changes-read",
});

export const HELLOLYNK_HOST_PATHS = Object.freeze({
  health: "/host/v1/health",
  status: "/host/v1/status",
  localIdentityProof: LOCAL_IDENTITY_PROOF_PATH,
  localPeerExchange: LOCAL_PEER_EXCHANGE_PATH,
  attachmentAttach: "/host/v1/attachments",
  attachmentHeartbeat: "/host/v1/attachments/heartbeat",
  attachmentDetach: "/host/v1/attachments/detach",
  agentMessages: "/host/v1/agent-messages",
  appInboxMessages: "/host/v1/app/inbox/messages",
  appInboxUnreadCount: "/host/v1/app/inbox/unread-count",
  appInboxMarkRead: "/host/v1/app/inbox/mark-read",
  appInboxDeleteRead: "/host/v1/app/inbox/delete-read",
  appContacts: "/host/v1/app/contacts",
  appContactsUpsert: "/host/v1/app/contacts/upsert",
  appContactsRemove: "/host/v1/app/contacts/remove",
  appContactAutonomousSendAuthorization: "/host/v1/app/contacts/autonomous-send-authorization",
  appAuthorizedContacts: "/host/v1/app/authorized-contacts",
  appModelInbox: "/host/v1/app/model-inbox",
  appAuthorizedInboxMessages: "/host/v1/app/authorized-inbox/messages",
  appAuthorizedInboxRead: "/host/v1/app/authorized-inbox/read",
  appAuthorizedInboxActivate: "/host/v1/app/authorized-inbox/activate",
  appAuthorizedInboxPending: "/host/v1/app/authorized-inbox/pending",
  appAuthorizedInboxClaim: "/host/v1/app/authorized-inbox/claim",
  appAuthorizedInboxFinish: "/host/v1/app/authorized-inbox/finish",
  appAuthorizedInboxBatchReserve: "/host/v1/app/authorized-inbox/batch/reserve",
  appAuthorizedInboxBatchOpen: "/host/v1/app/authorized-inbox/batch/open",
  appAuthorizedInboxBatchAttempt: "/host/v1/app/authorized-inbox/batch/attempt",
  appAuthorizedInboxBatchConfirm: "/host/v1/app/authorized-inbox/batch/confirm",
  appAuthorizedInboxBatchCancel: "/host/v1/app/authorized-inbox/batch/cancel",
  appAuthorizedInboxBatchExpire: "/host/v1/app/authorized-inbox/batch/expire",
  appAuthorizedInboxBatchClosed: "/host/v1/app/authorized-inbox/batch/closed",
  appAuthorizedContactRequests: "/host/v1/app/authorized-contact-requests",
  appAuthorizedContactRequestRead: "/host/v1/app/authorized-contact-requests/read",
  appContactRequests: "/host/v1/app/contact-requests",
  appOutboxMessages: "/host/v1/app/outbox/messages",
  appOutboxRetryGrant: "/host/v1/app/outbox/retry-grants",
  appOutboxRetry: "/host/v1/app/outbox/retry",
  appHumanSendRequests: "/host/v1/app/human-actions/send-requests",
  appHumanSendRequestStatus: "/host/v1/app/human-actions/send-requests/status",
  appAuthorizedSend: "/host/v1/app/authorized-actions/send-text",
  appAuthorizedReply: "/host/v1/app/authorized-actions/reply-text",
  appChangesSnapshot: "/host/v1/app/changes/snapshot",
  appChangesSubscribe: "/host/v1/app/changes/subscribe",
  appWorkbenchSnapshot: "/host/v1/app/workbench/snapshot",
  appWorkbenchActionGrant: "/host/v1/app/workbench/action-grants",
  appWorkbenchCommand: "/host/v1/app/workbench/commands",
});

const WORKBENCH_SNAPSHOT_SCOPES = Object.freeze([
  HELLOLYNK_HOST_SCOPES.appInboxRead,
  HELLOLYNK_HOST_SCOPES.appContactsRead,
  HELLOLYNK_HOST_SCOPES.appContactRequestsRead,
  HELLOLYNK_HOST_SCOPES.appOutboxRead,
  HELLOLYNK_HOST_SCOPES.appChangesRead,
]);
const WORKBENCH_COMMAND_SCOPES = Object.freeze({
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend]: HELLOLYNK_HOST_SCOPES.appHumanSendRequest,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus]: HELLOLYNK_HOST_SCOPES.appHumanSendRequest,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead]: HELLOLYNK_HOST_SCOPES.appInboxManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead]: HELLOLYNK_HOST_SCOPES.appInboxManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead]: HELLOLYNK_HOST_SCOPES.appInboxManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead]: HELLOLYNK_HOST_SCOPES.appInboxManage,
  // Local history management requires both existing mutation authorities plus
  // the human surface and the exact per-command grant; retry alone is insufficient.
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory]: [HELLOLYNK_HOST_SCOPES.appInboxManage, HELLOLYNK_HOST_SCOPES.appOutboxRetry],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry]: HELLOLYNK_HOST_SCOPES.appOutboxRetry,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply]: HELLOLYNK_HOST_SCOPES.appOutboxRetry,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances]: HELLOLYNK_HOST_SCOPES.appContactsRead,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  "contact-request.clear-resolved": HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock]: HELLOLYNK_HOST_SCOPES.appContactsManage,
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.openAccount]: HELLOLYNK_HOST_SCOPES.uiLaunch,
});
const WORKBENCH_READ_ONLY_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal,
]);

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const OUTBOX_RETRY_GRANT_TTL_MS = 90_000;
const OUTBOX_RETRY_GRANT_CAPACITY = 512;
const OUTBOX_RETRY_GRANT_PATTERN = /^hretry_[A-Za-z0-9_-]{43}$/;
const HELLOLYNK_ID_PATTERN = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const APPLICATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,198}$/;
const CONTACT_REQUEST_STATES = new Set(["pending", "accepted", "rejected", "cancelled", "blocked", "expired"]);
const RESERVED_MESSAGE_IDENTITY_KEYS = new Set([
  "adapterid",
  "agentid",
  "capabilityid",
  "delegateid",
  "from",
  "hostid",
  "principalid",
  "sender",
  "senderagentid",
  "senderdelegateid",
  "senderdeviceid",
  "senderhostid",
  "senderid",
  "senderidentity",
  "senderidentitykeyid",
  "senderhellolynkid",
  "senderprincipalid",
]);

const ROUTES = new Map([
  [`POST ${HELLOLYNK_HOST_PATHS.localPeerExchange}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    body: "localPeerExchange",
    action: "localPeerExchange",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.localIdentityProof}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactsRead,
    body: "localIdentityProof",
    action: "localIdentityProof",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.status}`, {
    scope: HELLOLYNK_HOST_SCOPES.statusRead,
    body: "empty",
    action: "status",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.attachmentAttach}`, {
    scope: HELLOLYNK_HOST_SCOPES.attachmentsManage,
    body: "attachment",
    action: "attach",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.attachmentHeartbeat}`, {
    scope: HELLOLYNK_HOST_SCOPES.attachmentsManage,
    body: "attachment",
    action: "heartbeat",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.attachmentDetach}`, {
    scope: HELLOLYNK_HOST_SCOPES.attachmentsManage,
    body: "attachment",
    action: "detach",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.agentMessages}`, {
    scope: HELLOLYNK_HOST_SCOPES.agentMessagesSend,
    body: "agentMessage",
    action: "agentMessage",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appInboxMessages}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxRead,
    body: "empty",
    action: "appInboxMessages",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appInboxUnreadCount}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxRead,
    body: "empty",
    action: "appInboxUnreadCount",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appInboxMarkRead}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxManage,
    body: "appInboxId",
    action: "appInboxMarkRead",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appInboxDeleteRead}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxManage,
    body: "appInboxIds",
    action: "appInboxDeleteRead",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appContacts}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactsRead,
    body: "empty",
    action: "appContactsList",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appContactsUpsert}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactsManage,
    body: "appContactUpsert",
    action: "appContactsUpsert",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appContactsRemove}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactsManage,
    body: "appContactRemove",
    action: "appContactsRemove",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appContactAutonomousSendAuthorization}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactsManage,
    body: "appContactAutonomousSendAuthorization",
    action: "appContactAutonomousSendAuthorization",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedContacts}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging, capabilityVersion: 2,
    body: "appNativeConversationQuery", action: "appAuthorizedContactsList",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appAuthorizedContacts}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "empty",
    action: "appAuthorizedContactsList",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appModelInbox}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging, capabilityVersion: 2,
    body: "appModelInbox", action: "appModelInbox",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "empty",
    action: "appAuthorizedInboxMessages",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "appAuthorizedInboxPreview",
    action: "appAuthorizedInboxMessages",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedInboxActivate}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "empty",
    action: "appAuthorizedInboxActivate",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedInboxRead}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "appAuthorizedInboxRead",
    action: "appAuthorizedInboxRead",
  }],
  ...[ ["GET", "appAuthorizedInboxPending", "empty"],
    ["POST", "appAuthorizedInboxClaim", "appAuthorizedInboxClaim"],
    ["POST", "appAuthorizedInboxFinish", "appAuthorizedInboxFinish"]
  ].map(([method, action, body]) => [`${method} ${HELLOLYNK_HOST_PATHS[action]}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging, capabilityVersion: 2, body, action,
  }]),
  ...["appAuthorizedInboxBatchReserve", "appAuthorizedInboxBatchOpen", "appAuthorizedInboxBatchAttempt", "appAuthorizedInboxBatchConfirm", "appAuthorizedInboxBatchCancel", "appAuthorizedInboxBatchExpire", "appAuthorizedInboxBatchClosed"].map(action => [`POST ${HELLOLYNK_HOST_PATHS[action]}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging, capabilityVersion: 2, body: action, action,
  }]),
  // GET returns the first page for model tools. A receiver scans further pages
  // with its own cursor, or rechecks one message, without any shared state.
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedInboxPending}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging, capabilityVersion: 2,
    body: "appAuthorizedInboxPendingQuery", action: "appAuthorizedInboxPendingQuery",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appAuthorizedContactRequests}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "empty",
    action: "appAuthorizedContactRequestsList",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedContactRequestRead}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "appAuthorizedContactRequestRead",
    action: "appAuthorizedContactRequestRead",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appContactRequests}`, {
    scope: HELLOLYNK_HOST_SCOPES.appContactRequestsRead,
    body: "empty",
    action: "appContactRequestsList",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appOutboxMessages}`, {
    scope: HELLOLYNK_HOST_SCOPES.appOutboxRead,
    body: "empty",
    action: "appOutboxMessages",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appOutboxRetryGrant}`, {
    scope: HELLOLYNK_HOST_SCOPES.appOutboxRetry,
    body: "appOutboxRetryGrant",
    action: "appOutboxRetryGrant",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appOutboxRetry}`, {
    scope: HELLOLYNK_HOST_SCOPES.appOutboxRetry,
    body: "appOutboxRetry",
    action: "appOutboxRetry",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appHumanSendRequests}`, {
    scope: HELLOLYNK_HOST_SCOPES.appHumanSendRequest,
    capabilityVersion: 2,
    body: "appHumanSendRequest",
    action: "appHumanSendRequest",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appHumanSendRequestStatus}`, {
    scope: HELLOLYNK_HOST_SCOPES.appHumanSendRequest,
    capabilityVersion: 2,
    body: "appHumanSendRequestStatus",
    action: "appHumanSendRequestStatus",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedSend}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "appAuthorizedSend",
    action: "appAuthorizedSend",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appAuthorizedReply}`, {
    scope: HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging,
    capabilityVersion: 2,
    body: "appAuthorizedReply",
    action: "appAuthorizedReply",
  }],
  [`GET ${HELLOLYNK_HOST_PATHS.appChangesSnapshot}`, {
    scope: HELLOLYNK_HOST_SCOPES.appChangesRead,
    body: "empty",
    action: "appChangesSnapshot",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appChangesSubscribe}`, {
    scope: HELLOLYNK_HOST_SCOPES.appChangesRead,
    body: "appChangesSubscribe",
    action: "appChangesSubscribe",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appWorkbenchSnapshot}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxRead,
    scopes: WORKBENCH_SNAPSHOT_SCOPES,
    body: "appWorkbenchRead",
    action: "appWorkbenchSnapshot",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxRead,
    scopes: WORKBENCH_SNAPSHOT_SCOPES,
    capabilityVersion: 2,
    body: "appWorkbenchActionGrant",
    action: "appWorkbenchActionGrant",
  }],
  [`POST ${HELLOLYNK_HOST_PATHS.appWorkbenchCommand}`, {
    scope: HELLOLYNK_HOST_SCOPES.appInboxRead,
    scopes: WORKBENCH_SNAPSHOT_SCOPES,
    capabilityVersion: 2,
    body: "appWorkbenchCommand",
    action: "appWorkbenchCommand",
  }],
]);

export function createHelloLynkHostCore(options = {}) {
  if (typeof options.capabilityResolver !== "function") {
    throw codeError("host_capability_resolver_required");
  }
  const capabilityResolver = options.capabilityResolver;
  const legacyCompatEnabled = options.legacyCompatEnabled === true;
  const handlers = normalizeHandlers(options.actionHandlers);
  const clock = normalizeClock(options.clock);
  const hostGeneration = assertHostGeneration(options.hostGeneration || randomGeneration());
  const maxBodyBytes = normalizeLimit(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, 1_024, 1_048_576);
  const maxSkewMs = normalizeLimit(
    options.maxSkewMs,
    HELLOLYNK_HOST_REQUEST_MAX_SKEW_MS,
    1_000,
    300_000,
  );
  const minimumNonceTtlMs = (2 * maxSkewMs) + 1;
  const nonceTtlMs = normalizeLimit(
    options.nonceTtlMs,
    Math.max(90_000, minimumNonceTtlMs),
    1_000,
    1_800_001,
  );
  if (nonceTtlMs < minimumNonceTtlMs) throw codeError("host_nonce_ttl_too_short");
  const replayGuard = createNonceReplayGuard({
    clock,
    ttlMs: nonceTtlMs,
    maxEntries: options.maxNonceEntries,
    maxEntriesPerCapability: options.maxNoncesPerCapability,
  });
  const capabilityBindings = new Map();
  const attachments = new Map();
  const outboxRetryGrants = new Map();
  const workbenchActionGrants = createHelloLynkWorkbenchActionGrantRegistry({
    clock,
    ...(options.workbenchActionGrantTtlMs == null
      ? {}
      : { ttlMs: options.workbenchActionGrantTtlMs }),
    ...(options.workbenchActionGrantCapacity == null
      ? {}
      : { capacity: options.workbenchActionGrantCapacity }),
  });
  let lifecycleState = "running";
  let idleShutdownAt = null;
  let hasEverAttached = false;
  let shutdownPromise = null;

  async function dispatch(request = {}) {
    let mayReadModelNotices = false;
    try {
      const method = assertMethod(request.method);
      const pathname = assertPathname(request.pathname);
      const rawBody = asRawBody(request.rawBody);
      if (rawBody.length > maxBodyBytes) throw codeError("host_request_too_large");

      if (method === "GET" && pathname === HELLOLYNK_HOST_PATHS.health) {
        if (rawBody.length !== 0) throw codeError("host_request_body_forbidden");
        return response(200, publicHealth());
      }
      if (isHumanOrRootPath(pathname)) throw codeError("host_adapter_route_forbidden");

      const route = ROUTES.get(`${method} ${pathname}`);
      if (!route) throw codeError("host_route_not_found");
      if (!legacyCompatEnabled && isLegacySendRoute(pathname)) throw codeError("host_route_not_found");
      if (lifecycleState !== "running") throw codeError("host_not_running");

      const authenticated = await authenticateRequest({ method, pathname, rawBody, headers: request.headers });
      if (route.capabilityVersion != null
        && authenticated.capability.version !== route.capabilityVersion) {
        throw codeError("host_request_unauthorized");
      }
      if (route.action.startsWith("app")
        && !authenticated.capability.scopes.includes(HELLOLYNK_HOST_SCOPES.humanUiSurface)) {
        throw codeError("host_capability_human_surface_required");
      }
      const requiredScopes = route.scopes || [route.scope];
      if (requiredScopes.some((scope) => !authenticated.capability.scopes.includes(scope))) {
        throw codeError("host_capability_scope_denied");
      }
      mayReadModelNotices = (route.action === "status" || route.action.startsWith("appAuthorized")
        || route.action === "appInboxUnreadCount")
        && authenticated.capability.scopes.includes(HELLOLYNK_HOST_SCOPES.appAuthorizedMessaging);
      const body = parseAndValidateBody(route.body, rawBody);
      if (route.action === "appWorkbenchActionGrant" || route.action === "appWorkbenchCommand") {
        const commandScope = WORKBENCH_COMMAND_SCOPES[body.request.command];
        if (!commandScope || (Array.isArray(commandScope) ? commandScope : [commandScope])
          .some((scope) => !authenticated.capability.scopes.includes(scope))) {
          throw codeError("host_capability_scope_denied");
        }
        if ((body.request.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal
          || body.request.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest)
          && !authenticated.capability.scopes.includes(HELLOLYNK_HOST_SCOPES.humanUiSurface)) {
          throw codeError("host_capability_human_surface_required");
        }
        if (route.action === "appWorkbenchActionGrant"
          && body.request.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
          throw codeError("host_app_workbench_command_invalid");
        }
      }
      const prepared = prepareAction(route.action, authenticated.capability, body);

      // Consuming the nonce is deliberately last: unknown/inactive capabilities,
      // bad HMAC, stale timestamps, wrong generation/scope/delegate, and invalid
      // bodies cannot pollute the bounded replay cache or trigger an action.
      if (!replayGuard.consume(
        authenticated.capability.capabilityId,
        authenticated.nonce,
        authenticated.timestampMs,
      )) {
        if (route.action === "appWorkbenchCommand") {
          if (prepared?.workbenchActionGrantConsumed) {
            rejectConsumedHelloLynkWorkbenchActionGrant(
              workbenchActionGrants,
              body.actionGrant,
            );
          }
          if (prepared?.workbenchActionGrantConsumed
            || prepared?.workbenchActionGrantFailureOutcome) {
            return response(200, workbenchActionGrantFailure(
              body.request,
              prepared.workbenchActionGrantFailureOutcome || "known-failed",
            ));
          }
        }
        throw codeError("host_request_replayed");
      }
      return await withModelNotices(await executeAction(route.action, authenticated.capability, body, prepared));
    } catch (error) {
      return withModelNotices(errorResponse(error));
    }

    async function withModelNotices(result) {
      if (!mayReadModelNotices || result.status === 401
        || typeof options.readModelNotices !== "function") return result;
      try {
        const state = await options.readModelNotices();
        return { ...result, body: { ...result.body, modelNotices: {
          ...(Number.isSafeInteger(state?.pendingContactRequests) && state.pendingContactRequests >= 0
            ? { pendingContactRequests: state.pendingContactRequests } : {}),
          localStorageFull: state?.localStorageFull === true,
        } } };
      } catch { return result; } // Notices must never replace the actual action outcome.
    }
  }

  async function authenticateRequest({ method, pathname, rawBody, headers }) {
    const capabilityId = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.capabilityId);
    const adapterId = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.adapterId);
    const generation = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.hostGeneration);
    const timestampValue = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.timestampMs);
    const nonce = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.nonce);
    const proof = requiredHeader(headers, HELLOLYNK_HOST_AUTH_HEADERS.proof);

    const capability = await resolvePinnedCapability(capabilityId);
    if (capability.adapterId !== adapterId || generation !== hostGeneration) {
      throw codeError("host_request_unauthorized");
    }
    const timestampMs = parseTimestampHeader(timestampValue);
    try {
      assertRequestFresh(timestampMs, clock.now(), maxSkewMs);
    } catch {
      throw codeError("host_request_unauthorized");
    }
    if (!hostRequestAuthMatches({
      secretBuffer: capability.secretBuffer,
      capabilityId,
      adapterId,
      method,
      pathname,
      hostGeneration,
      timestampMs,
      nonce,
      rawBody,
      proof,
    })) {
      throw codeError("host_request_unauthorized");
    }
    return { capability, timestampMs, nonce };
  }

  async function resolvePinnedCapability(capabilityId) {
    if (capabilityBindings.get(capabilityId)?.state === "invalidated") {
      throw codeError("host_request_unauthorized");
    }
    let capability;
    try {
      capability = assertCapabilityRecord(await capabilityResolver(capabilityId));
      if (capability.capabilityId !== capabilityId) throw codeError("host_capability_id_mismatch");
    } catch {
      if (capabilityBindings.has(capabilityId)) {
        revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
          hostGeneration,
          capabilityId,
        });
        capabilityBindings.set(capabilityId, Object.freeze({ state: "invalidated" }));
      }
      throw codeError("host_request_unauthorized");
    }
    const tuple = immutableCapabilityTuple(capability);
    const current = capabilityBindings.get(capabilityId);
    if (current?.state === "invalidated") throw codeError("host_request_unauthorized");
    if (!current) {
      capabilityBindings.set(capabilityId, Object.freeze({ state: "active", tuple }));
    } else if (!immutableCapabilityTupleMatches(current.tuple, tuple)) {
      revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
        hostGeneration,
        capabilityId,
      });
      capabilityBindings.set(capabilityId, Object.freeze({ state: "invalidated" }));
      throw codeError("host_request_unauthorized");
    }
    return capability;
  }

  function prepareAction(action, capability, body) {
    const now = clock.now();
    if (["localIdentityProof", "localPeerExchange"].includes(action) && (body.target.delegateId !== capability.delegateId
      || body.target.hostInstallationId !== capability.hostInstallationId
      || body.owner.principalId !== capability.principalId)) throw codeError("host_request_unauthorized");
    if (action === "heartbeat" || action === "detach") {
      return exactActiveAttachment(capability, body.adapterInstanceId, now);
    }
    if (action === "appHumanSendRequest" || action === "appHumanSendRequestStatus") {
      return { attachment: exactActiveAttachment(capability, body.adapterInstanceId, now).attachment };
    }
    if (action === "appOutboxRetryGrant") {
      return { attachment: exactActiveAttachment(capability, body.adapterInstanceId, now).attachment };
    }
    if (action === "appWorkbenchActionGrant") {
      return { attachment: exactActiveAttachment(capability, body.adapterInstanceId, now).attachment };
    }
    if (action === "appWorkbenchCommand") {
      const grantRequired = !WORKBENCH_READ_ONLY_COMMANDS.has(body.request.command);
      let workbenchActionGrantConsumed = false;
      if (grantRequired || body.actionGrant != null) {
        try {
          workbenchActionGrants.consume(workbenchActionGrantBinding(
            capability,
            body.adapterInstanceId,
            body.request,
            body.actionGrant,
          ));
          workbenchActionGrantConsumed = true;
        } catch (error) {
          return {
            workbenchActionGrantFailureOutcome:
              error?.outcome === "unknown" ? "unknown" : "known-failed",
          };
        }
      }
      let attachment;
      try {
        attachment = exactActiveAttachment(capability, body.adapterInstanceId, now).attachment;
      } catch (error) {
        if (grantRequired || body.actionGrant != null) {
          if (workbenchActionGrantConsumed) {
            rejectConsumedHelloLynkWorkbenchActionGrant(
              workbenchActionGrants,
              body.actionGrant,
            );
          }
          return { workbenchActionGrantFailureOutcome: "known-failed" };
        }
        throw error;
      }
      return {
        attachment,
        workbenchActionGrantConsumed,
        workbenchRetryAuthorized:
          [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry, HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply].includes(body.request.command),
      };
    }
    if (action === "appOutboxRetry") {
      const { attachment } = exactActiveAttachment(capability, body.adapterInstanceId, now);
      pruneOutboxRetryGrants(now);
      const digest = crypto.createHash("sha256").update(body.retryGrant, "utf8").digest("hex");
      const grant = outboxRetryGrants.get(digest);
      if (!grant || grant.expiresAt <= now
        || grant.capabilityId !== capability.capabilityId
        || grant.adapterId !== capability.adapterId
        || grant.delegateId !== capability.delegateId
        || grant.adapterInstanceId !== body.adapterInstanceId
        || grant.authorityEpoch !== attachment.authorityEpoch
        || grant.clientMessageId !== body.clientMessageId) {
        throw codeError("host_app_outbox_retry_grant_invalid");
      }
      return { retryGrantDigest: digest, grant, attachment };
    }
    return null;
  }

  async function executeAction(action, capability, body, prepared) {
    const now = clock.now();
    if (action === "localPeerExchange") {
      const result = await invokeHandler(handlers.localPeerExchange,
        publicActionContext(capability, { hostGeneration, request: body }));
      await resolvePinnedCapability(capability.capabilityId);
      return response(200, signLocalPeerResult({ request: body, hostGeneration,
        capabilityId: capability.capabilityId, result, secretBuffer: capability.secretBuffer }));
    }
    if (action === "localIdentityProof") {
      const identity = await invokeHandler(handlers.localIdentityProof,
        publicActionContext(capability, { hostGeneration, request: body }));
      // Re-resolve after the callback: disconnect/revocation during proof
      // calculation must not leave a successfully signed stale response.
      await resolvePinnedCapability(capability.capabilityId);
      return response(200, signLocalIdentityProof({ request: body, hostGeneration,
        capabilityId: capability.capabilityId, identity, secretBuffer: capability.secretBuffer }));
    }
    if (action === "status") {
      await invokeHandler(handlers.status, publicCapability(capability));
      return response(200, {
        ok: true,
        contractId: HELLOLYNK_HOST_CONTRACT,
        hostGeneration,
        status: lifecycleState,
        attachmentCount: activeAttachmentCount(now),
        idleShutdownAt,
        adapter: publicCapability(capability),
      });
    }
    if (action === "attach") {
      const key = attachmentKey(capability.capabilityId, body.adapterInstanceId);
      const existing = attachments.get(key);
      if (existing && existing.expiresAt <= now) {
        revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
          hostGeneration,
          capabilityId: capability.capabilityId,
          adapterInstanceId: body.adapterInstanceId,
        });
      }
      const attachedAt = existing?.attachedAt ?? now;
      const attachment = Object.freeze({
        authorityEpoch: existing && existing.expiresAt > now ? existing.authorityEpoch : Symbol("attachment"),
        adapterInstanceId: body.adapterInstanceId,
        capabilityId: capability.capabilityId,
        adapterId: capability.adapterId,
        delegateId: capability.delegateId,
        capabilityVersion: capability.version,
        attachedAt,
        lastHeartbeatAt: now,
        expiresAt: now + HELLOLYNK_HOST_ATTACHMENT_LEASE_MS,
      });
      attachments.set(key, attachment);
      hasEverAttached = true;
      idleShutdownAt = null;
      await invokeHandler(existing ? handlers.heartbeat : handlers.attach,
        publicActionContext(capability, { hostGeneration, adapterInstanceId: body.adapterInstanceId }),
      );
      return response(200, attachmentResponse(attachment, Boolean(existing)));
    }
    if (action === "heartbeat") {
      const attachment = Object.freeze({
        ...prepared.attachment,
        lastHeartbeatAt: now,
        expiresAt: now + HELLOLYNK_HOST_ATTACHMENT_LEASE_MS,
      });
      attachments.set(prepared.key, attachment);
      idleShutdownAt = null;
      await invokeHandler(handlers.heartbeat,
        publicActionContext(capability, { hostGeneration, adapterInstanceId: body.adapterInstanceId }),
      );
      return response(200, attachmentResponse(attachment, false));
    }
    if (action === "detach") {
      attachments.delete(prepared.key);
      revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
        hostGeneration,
        capabilityId: capability.capabilityId,
        adapterInstanceId: body.adapterInstanceId,
      });
      scheduleIdleShutdownIfEmpty(now);
      await invokeHandler(handlers.detach,
        publicActionContext(capability, {
          hostGeneration,
          capabilityId: capability.capabilityId,
          adapterInstanceId: body.adapterInstanceId,
        }),
      );
      return response(200, {
        ok: true,
        detached: true,
        adapterInstanceId: body.adapterInstanceId,
        attachmentCount: activeAttachmentCount(now),
        idleShutdownAt,
      });
    }
    if (action === "agentMessage") {
      await invokeHandler(
        handlers.agentMessage,
        publicActionContext(capability, { hostGeneration, message: body }),
      );
      return response(200, { ok: true, accepted: true });
    }
    if (action === "appOutboxRetryGrant") {
      const issued = issueOutboxRetryGrant(
        capability,
        prepared.attachment,
        body.clientMessageId,
        now,
      );
      return response(200, { ok: true, retryGrant: issued.retryGrant, expiresAt: issued.expiresAt });
    }
    if (action === "appWorkbenchActionGrant") {
      await invokeApplicationHandler(
        handlers.appWorkbenchActionGrant,
        publicActionContext(capability, {
          hostGeneration,
          capabilityId: capability.capabilityId,
          adapterInstanceId: prepared.attachment.adapterInstanceId,
          request: body.request,
        }),
      );
      const currentCapability = await resolvePinnedCapability(capability.capabilityId);
      if (lifecycleState !== "running") throw codeError("host_not_running");
      const currentAttachment = exactActiveAttachment(
        currentCapability, prepared.attachment.adapterInstanceId, clock.now(),
      ).attachment;
      if (currentAttachment.authorityEpoch !== prepared.attachment.authorityEpoch) {
        throw codeError("host_request_unauthorized");
      }
      // The handler and capability lookup may outlive this attachment. Keep the
      // final lifetime check and token issuance synchronous so reattachment
      // cannot give an older request fresh authority.
      const issued = workbenchActionGrants.issue(workbenchActionGrantBinding(
        currentCapability,
        prepared.attachment.adapterInstanceId,
        body.request,
      ));
      return response(200, {
        ok: true,
        actionGrant: issued.actionGrant,
        expiresAtMs: issued.expiresAtMs,
      });
    }
    if (action === "appWorkbenchCommand" && prepared?.workbenchActionGrantFailureOutcome) {
      return response(200, workbenchActionGrantFailure(
        body.request,
        prepared.workbenchActionGrantFailureOutcome,
      ));
    }
    if (action.startsWith("app")) {
      const applicationRequest = (action === "appHumanSendRequest"
        || action === "appHumanSendRequestStatus"
        || action === "appWorkbenchCommand") ? body.request : body;
      if (action === "appOutboxRetry") {
        outboxRetryGrants.delete(prepared.retryGrantDigest);
      }
      const result = await invokeApplicationHandler(
        handlers[action],
        publicActionContext(capability, {
          hostGeneration,
          ...((action === "appHumanSendRequest" || action === "appHumanSendRequestStatus"
            || action === "appWorkbenchCommand")
            ? { capabilityId: capability.capabilityId }
            : {}),
          ...(prepared?.attachment ? { adapterInstanceId: prepared.attachment.adapterInstanceId } : {}),
          ...(prepared?.workbenchRetryAuthorized ? { workbenchRetryAuthorized: true } : {}),
          request: applicationRequest,
          ...((action === "appHumanSendRequest" || action === "appOutboxRetry"
            || (action === "appWorkbenchCommand"
              && [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend, HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry]
                .includes(applicationRequest.command))) ? {
            nativeAuthority: createNativeAttachmentAuthority(capability, prepared.attachment),
          } : {}),
          ...((action === "appModelInbox" || action === "appAuthorizedContactsList" || action === "appAuthorizedSend" || action.startsWith("appAuthorizedInbox")
            || action === "appAuthorizedContactRequestsList"
            || action === "appAuthorizedContactRequestRead") ? {
            // A queued/durable admission must not rely on authentication taken
            // before it waited. Reuse pinned identity and current revocation.
            revalidateCapability: () => resolvePinnedCapability(capability.capabilityId),
          } : {}),
        }),
      );
      return response(
        action === "appHumanSendRequest" ? 202 : 200,
        applicationResponse(action, result, applicationRequest),
      );
    }
    throw codeError("host_action_invalid");
  }

  function issueOutboxRetryGrant(capability, attachment, clientMessageId, now) {
    pruneOutboxRetryGrants(now);
    if (outboxRetryGrants.size >= OUTBOX_RETRY_GRANT_CAPACITY) {
      throw codeError("host_app_outbox_retry_grant_capacity_exceeded");
    }
    const retryGrant = `hretry_${crypto.randomBytes(32).toString("base64url")}`;
    if (!OUTBOX_RETRY_GRANT_PATTERN.test(retryGrant)) {
      throw codeError("host_app_outbox_retry_grant_generation_failed");
    }
    const digest = crypto.createHash("sha256").update(retryGrant, "utf8").digest("hex");
    const expiresAt = now + OUTBOX_RETRY_GRANT_TTL_MS;
    outboxRetryGrants.set(digest, Object.freeze({
      capabilityId: capability.capabilityId,
      adapterId: capability.adapterId,
      delegateId: capability.delegateId,
      adapterInstanceId: attachment.adapterInstanceId,
      authorityEpoch: attachment.authorityEpoch,
      clientMessageId,
      expiresAt,
    }));
    return { retryGrant, digest, expiresAt };
  }

  function workbenchActionGrantBinding(capability, adapterInstanceId, command, actionGrant) {
    const targetDigest = crypto.createHash("sha256")
      .update(JSON.stringify({ command: command.command, payload: command.payload }), "utf8")
      .digest("hex");
    return {
      hostGeneration,
      principalId: capability.principalId,
      capabilityId: capability.capabilityId,
      adapterId: capability.adapterId,
      delegateId: capability.delegateId,
      adapterInstanceId,
      tool: command.command,
      target: `workbench:${targetDigest}`,
      // The registry canonicalizes this complete, already validated DTO. Thus
      // requestId, contract/schema, idempotency, revision, tool and payload are
      // all cryptographically bound without retaining the raw command.
      payload: command,
      expectedRevision: command.expectedRevision,
      idempotencyKey: command.idempotencyKey,
      ...(actionGrant === undefined ? {} : { actionGrant }),
    };
  }

  async function runMaintenance() {
    if (lifecycleState !== "running") return publicHealth();
    const now = clock.now();
    let lastExpiredAt = null;
    for (const [key, attachment] of attachments) {
      if (attachment.expiresAt <= now) {
        attachments.delete(key);
        revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
          hostGeneration,
          capabilityId: attachment.capabilityId,
          adapterInstanceId: attachment.adapterInstanceId,
        });
        lastExpiredAt = Math.max(lastExpiredAt ?? 0, attachment.expiresAt);
      }
    }
    if (attachments.size === 0 && hasEverAttached && idleShutdownAt == null) {
      idleShutdownAt = (lastExpiredAt ?? now) + HELLOLYNK_HOST_IDLE_SHUTDOWN_GRACE_MS;
    }
    if (idleShutdownAt != null && now >= idleShutdownAt) await shutDownForIdle();
    replayGuard.prune(now);
    pruneOutboxRetryGrants(now);
    try {
      workbenchActionGrants.prune();
    } catch (error) {
      // The registry has already cleared every grant before reporting a clock
      // rollback. Maintenance must remain stable because its process timer is
      // fire-and-forget; issuance/consumption still surface their fail-closed
      // errors to the authenticated request that triggered them.
      if (error?.code !== "host_workbench_action_grant_clock_invalid") throw error;
    }
    return publicHealth();
  }

  function pruneOutboxRetryGrants(now = clock.now()) {
    for (const [digest, grant] of outboxRetryGrants) {
      if (grant.expiresAt <= now) outboxRetryGrants.delete(digest);
    }
  }

  async function shutDownForIdle() {
    if (shutdownPromise) return shutdownPromise;
    lifecycleState = "stopping";
    shutdownPromise = Promise.resolve()
      .then(() => invokeHandler(handlers.idleShutdown, {
        contractId: HELLOLYNK_HOST_CONTRACT,
        hostGeneration,
        reason: "no_adapter_attachments",
      }))
      .finally(() => {
        lifecycleState = "stopped";
      });
    return shutdownPromise;
  }

  function activeAttachmentCount(now = clock.now()) {
    let count = 0;
    for (const attachment of attachments.values()) {
      if (attachment.expiresAt > now) count += 1;
    }
    return count;
  }

  function connectedClients(now = clock.now()) {
    const types = new Set();
    for (const attachment of attachments.values()) {
      if (attachment.expiresAt > now) types.add(workbenchClientType(attachment.adapterId));
    }
    return Object.freeze([...types]
      .sort((left, right) => left.localeCompare(right, "en"))
      .map((clientType) => Object.freeze({
        clientId: clientType,
        clientType,
        state: "connected",
      })));
  }

  function scheduleIdleShutdownIfEmpty(now) {
    if (attachments.size === 0 && hasEverAttached && idleShutdownAt == null) {
      idleShutdownAt = now + HELLOLYNK_HOST_IDLE_SHUTDOWN_GRACE_MS;
    }
  }

  function exactActiveAttachment(capability, adapterInstanceId, now) {
    const key = attachmentKey(capability.capabilityId, adapterInstanceId);
    const attachment = attachments.get(key);
    if (!attachment || !attachmentMatchesCapability(attachment, capability) || attachment.expiresAt <= now) {
      if (attachment) {
        attachments.delete(key);
        revokeHelloLynkWorkbenchActionGrants(workbenchActionGrants, {
          hostGeneration,
          capabilityId: capability.capabilityId,
          adapterInstanceId,
        });
      }
      throw codeError("host_attachment_not_found");
    }
    return { key, attachment };
  }

  function publicHealth() {
    return {
      ok: lifecycleState === "running",
      contractId: HELLOLYNK_HOST_CONTRACT,
      hostGeneration,
      status: lifecycleState,
    };
  }

  function createNativeAttachmentAuthority(capability, original) {
    function assertCurrent() {
      if (lifecycleState !== "running" || capabilityBindings.get(capability.capabilityId)?.state !== "active") {
        throw codeError("host_request_unauthorized");
      }
      const current = attachments.get(attachmentKey(capability.capabilityId, original.adapterInstanceId));
      if (!current || !attachmentMatchesCapability(current, capability)
        || current.expiresAt <= clock.now() || current.authorityEpoch !== original.authorityEpoch) {
        throw codeError("host_request_unauthorized");
      }
    }
    return Object.freeze({
      assertCurrent,
      async revalidate() {
        await resolvePinnedCapability(capability.capabilityId);
        assertCurrent();
      },
    });
  }

  // Internal native-action guard; never serialized in an application response.
  // A detach/re-attach of the same adapter name is a new authority lifetime.
  async function captureNativeAuthority(context) {
    async function currentAttachment() {
      if (context.hostGeneration !== hostGeneration || lifecycleState !== "running") {
        throw codeError("host_request_unauthorized");
      }
      const capability = await resolvePinnedCapability(context.capabilityId);
      for (const field of ["principalId", "delegateId", "hostInstallationId", "adapterId"]) {
        if (capability[field] !== context[field]) throw codeError("host_request_unauthorized");
      }
      return exactActiveAttachment(capability, context.adapterInstanceId, clock.now()).attachment;
    }
    const original = await currentAttachment();
    return async () => {
      const current = await currentAttachment();
      if (current.authorityEpoch !== original.authorityEpoch) throw codeError("host_request_unauthorized");
    };
  }

  return Object.freeze({
    dispatch,
    runMaintenance,
    publicHealth,
    captureNativeAuthority,
    get hostGeneration() {
      return hostGeneration;
    },
    get attachmentCount() {
      return activeAttachmentCount();
    },
    connectedClients,
    get idleShutdownAt() {
      return idleShutdownAt;
    },
  });
}

function parseAndValidateBody(kind, rawBody) {
  if (kind === "empty") {
    if (rawBody.length !== 0) throw codeError("host_request_body_forbidden");
    return null;
  }
  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw codeError("host_request_json_invalid");
  }
  if (!isPlainObject(body)) throw codeError("host_request_body_invalid");
  if (kind === "localIdentityProof") return validateLocalIdentityProofRequest(body);
  if (kind === "localPeerExchange") return validateLocalPeerRequest(body);
  if (kind === "attachment") {
    assertExactKeys(body, ["adapterInstanceId"]);
    return { adapterInstanceId: assertIdentifier(body.adapterInstanceId, "host_adapter_instance_id_invalid") };
  }
  if (kind === "agentMessage") {
    assertNoSenderIdentity(body);
    if (Object.keys(body).length === 0) throw codeError("host_agent_message_invalid");
  }
  if (kind === "appModelInbox") {
    assertExactKeys(body, ["operation", "scope", "query", ...(Object.hasOwn(body, "caller") ? ["caller"] : [])]);
    if (body.scope !== "current") throw codeError("model_inbox_scope_invalid");
    if (!isPlainObject(body.query)) throw codeError("host_request_body_invalid");
    const kinds = { list: "appAuthorizedInboxPreview", read: "appAuthorizedInboxRead",
      pending: "appAuthorizedInboxPendingQuery", claim: "appAuthorizedInboxClaim",
      assertReply: "appAuthorizedInboxRead" };
    let query;
    if (["count", "list", "pending"].includes(body.operation) && Object.keys(body.query).length === 0) query = {};
    else if (Object.hasOwn(kinds, body.operation)) query = parseAndValidateBody(kinds[body.operation], Buffer.from(JSON.stringify(body.query)));
    else throw codeError("host_request_body_invalid");
    const caller = modelInboxCaller(body.caller);
    return { operation: body.operation, scope: body.scope, query, caller };
  }
  if (kind === "appInboxId") {
    assertExactKeys(body, ["localMessageId"]);
    return { localMessageId: assertApplicationId(body.localMessageId, "host_app_local_message_id_invalid") };
  }
  if (kind === "appAuthorizedInboxClaim" && Object.hasOwn(body, "batchId")) {
    assertExactKeys(body, ["batchId"]);
    return { batchId: assertIdentifier(body.batchId, "host_request_body_invalid") };
  }
  if (kind.startsWith("appAuthorizedInboxBatch")) {
    const operation = kind.slice("appAuthorizedInboxBatch".length);
    const fields = operation === "Reserve" ? ["target", "candidates", ...(Object.hasOwn(body, "batchId") ? ["batchId"] : [])]
      : operation === "Expire" ? ["batchId", "candidates"]
      : operation === "Attempt" ? ["batchId", ...["attemptId", "nativeThreadId"].filter(key => Object.hasOwn(body, key))]
      : operation === "Open" ? ["target", "state"].filter(key => Object.hasOwn(body, key))
      : operation === "Confirm" && Object.hasOwn(body, "nativeThreadId") ? ["batchId", "nativeThreadId"] : ["batchId"];
    assertExactKeys(body, fields);
    const result = {};
    for (const field of fields) {
      if (field === "candidates") {
        if (!Array.isArray(body.candidates) || body.candidates.length > 1000) throw codeError("host_request_body_invalid");
        result.candidates = body.candidates.map(id => assertApplicationId(id, "host_app_local_message_id_invalid"));
      } else if (field === "state") {
        if (!["reserved", "delivered"].includes(body.state)) throw codeError("host_request_body_invalid");
        result.state = body.state;
      } else result[field] = assertIdentifier(body[field], "host_request_body_invalid");
    }
    return result;
  }
  if (kind === "appAuthorizedInboxRead" || kind === "appAuthorizedInboxClaim") {
    assertExactKeys(body, ["localMessageId", "conversationKey"]);
    return {
      localMessageId: assertApplicationId(body.localMessageId, "host_app_local_message_id_invalid"),
      conversationKey: assertIdentifier(body.conversationKey, "host_app_conversation_key_invalid"),
    };
  }
  if (kind === "appAuthorizedInboxPendingQuery") {
    if (Object.hasOwn(body, "cursor")) {
      assertExactKeys(body, ["cursor"]);
      if (!Number.isSafeInteger(body.cursor) || body.cursor < 0) throw codeError("host_request_body_invalid");
      return { cursor: body.cursor };
    }
    assertExactKeys(body, ["localMessageId", "conversationKey"]);
    return {
      localMessageId: assertApplicationId(body.localMessageId, "host_app_local_message_id_invalid"),
      conversationKey: assertIdentifier(body.conversationKey, "host_app_conversation_key_invalid"),
    };
  }
  if (kind === "appAuthorizedInboxFinish") {
    assertExactKeys(body, ["localMessageId", "conversationKey", "claimId", "outcome"]);
    if (!["completed", "unknown"].includes(body.outcome)) throw codeError("host_request_body_invalid");
    return {
      localMessageId: assertApplicationId(body.localMessageId, "host_app_local_message_id_invalid"),
      conversationKey: assertIdentifier(body.conversationKey, "host_app_conversation_key_invalid"),
      claimId: assertIdentifier(body.claimId, "host_request_body_invalid"),
      outcome: body.outcome,
    };
  }
  if (kind === "appAuthorizedContactRequestRead") {
    assertExactKeys(body, ["localRecordId", "conversationKey"]);
    return {
      localRecordId: assertApplicationId(body.localRecordId, "host_app_local_record_id_invalid"),
      conversationKey: assertIdentifier(body.conversationKey, "host_app_conversation_key_invalid"),
    };
  }
  if (kind === "appInboxIds") {
    assertExactKeys(body, ["localMessageIds"]);
    return { localMessageIds: assertApplicationIdArray(body.localMessageIds, "host_app_local_message_ids_invalid") };
  }
  if (kind === "appContactUpsert") {
    assertAllowedKeys(body, ["contactId", "hellolynkId", "displayName"]);
    if (!Object.hasOwn(body, "hellolynkId") || !Object.hasOwn(body, "displayName")) {
      throw codeError("host_request_body_invalid");
    }
    return {
      ...(body.contactId == null ? {} : {
        contactId: assertApplicationId(body.contactId, "host_app_contact_id_invalid"),
      }),
      hellolynkId: assertHelloLynkId(body.hellolynkId, "host_app_contact_hellolynk_id_invalid"),
      displayName: assertApplicationDisplayName(body.displayName, "host_app_contact_display_name_invalid"),
    };
  }
  if (kind === "appContactRemove") {
    assertExactKeys(body, ["contactId"]);
    return { contactId: assertApplicationId(body.contactId, "host_app_contact_id_invalid") };
  }
  if (kind === "appContactAutonomousSendAuthorization") {
    assertExactKeys(body, ["contactId", "recipientDelegateId", "enabled"]);
    if (typeof body.enabled !== "boolean") throw codeError("host_request_body_invalid");
    return {
      contactId: assertApplicationId(body.contactId, "host_app_contact_id_invalid"),
      recipientDelegateId: assertIdentifier(body.recipientDelegateId, "host_app_recipient_delegate_invalid"),
      enabled: body.enabled,
    };
  }
  if (kind === "appOutboxRetryGrant") {
    assertExactKeys(body, ["adapterInstanceId", "clientMessageId"]);
    return {
      adapterInstanceId: assertIdentifier(body.adapterInstanceId, "host_adapter_instance_id_invalid"),
      clientMessageId: assertApplicationId(body.clientMessageId, "host_app_client_message_id_invalid"),
    };
  }
  if (kind === "appOutboxRetry") {
    assertExactKeys(body, ["adapterInstanceId", "clientMessageId", "retryGrant"]);
    const retryGrant = String(body.retryGrant || "");
    if (!OUTBOX_RETRY_GRANT_PATTERN.test(retryGrant)) {
      throw codeError("host_app_outbox_retry_grant_required");
    }
    return {
      adapterInstanceId: assertIdentifier(body.adapterInstanceId, "host_adapter_instance_id_invalid"),
      clientMessageId: assertApplicationId(body.clientMessageId, "host_app_client_message_id_invalid"),
      retryGrant,
    };
  }
  if (kind === "appHumanSendRequest") {
    assertExactKeys(body, ["adapterInstanceId", "request"]);
    if (!isPlainObject(body.request)) throw codeError("host_request_body_invalid");
    assertExactKeys(body.request, ["clientMessageId", "recipientHelloLynkId", "recipientDelegateId", "text"]);
    return {
      adapterInstanceId: assertIdentifier(body.adapterInstanceId, "host_adapter_instance_id_invalid"),
      request: {
        clientMessageId: assertApplicationId(body.request.clientMessageId, "host_app_client_message_id_invalid"),
        recipientHelloLynkId: assertHelloLynkId(body.request.recipientHelloLynkId, "host_app_recipient_hellolynk_id_invalid"),
        recipientDelegateId: assertIdentifier(body.request.recipientDelegateId, "host_app_recipient_delegate_invalid"),
        // The native human-confirmation broker has a deliberately smaller input
        // boundary. Admit the same UTF-8 byte budget here so every client gets a
        // recoverable validation response before a native child is started.
        text: assertApplicationString(body.request.text, "host_app_human_send_text_too_large", 20 * 1024),
      },
    };
  }
  if (kind === "appHumanSendRequestStatus") {
    assertExactKeys(body, ["adapterInstanceId", "request"]);
    if (!isPlainObject(body.request)) throw codeError("host_request_body_invalid");
    assertExactKeys(body.request, ["actionId"]);
    return {
      adapterInstanceId: assertIdentifier(body.adapterInstanceId, "host_adapter_instance_id_invalid"),
      request: { actionId: assertApplicationId(body.request.actionId, "host_app_action_id_invalid") },
    };
  }
  if (kind === "appNativeConversationQuery") {
    const { contactId, recipientDelegateId, ...query } = body;
    if (Object.hasOwn(query, "exactTitle")) throw codeError("native_directory_query_invalid");
    return { contactId: assertApplicationId(contactId, "host_app_contact_id_invalid"),
      recipientDelegateId: assertIdentifier(recipientDelegateId, "host_app_recipient_delegate_invalid"),
      ...nativeConversationQuery(query) };
  }
  if (kind === "appAuthorizedSend") {
    const targets = ["targetConversationId", "targetConversationTitle"].filter(key => Object.hasOwn(body, key));
    assertExactKeys(body, ["clientMessageId", "contactId", "recipientDelegateId", "text", ...targets]);
    if (targets.length > 1) throw codeError("host_request_body_invalid");
    return {
      ...(Object.hasOwn(body, "targetConversationId") ? { targetConversationId: nativeConversationId(body.targetConversationId) } : {}),
      ...(Object.hasOwn(body, "targetConversationTitle") ? { targetConversationTitle: nativeConversationTitle(body.targetConversationTitle) } : {}),
      clientMessageId: assertApplicationId(body.clientMessageId, "host_app_client_message_id_invalid"),
      contactId: assertApplicationId(body.contactId, "host_app_contact_id_invalid"),
      recipientDelegateId: assertIdentifier(body.recipientDelegateId, "host_app_recipient_delegate_invalid"),
      text: assertApplicationString(body.text, "host_app_text_invalid", 64 * 1024),
    };
  }
  if (kind === "appAuthorizedReply") {
    assertExactKeys(body, ["localMessageId", "conversationKey", "clientMessageId", "text"]);
    return {
      localMessageId: assertApplicationId(body.localMessageId, "host_app_local_message_id_invalid"),
      conversationKey: assertIdentifier(body.conversationKey, "host_app_conversation_key_invalid"),
      clientMessageId: assertApplicationId(body.clientMessageId, "host_app_client_message_id_invalid"),
      text: assertApplicationString(body.text, "host_app_text_invalid", 64 * 1024),
    };
  }
  if (kind === "appChangesSubscribe") {
    assertExactKeys(body, ["afterCursor"]);
    const afterCursor = Number(body.afterCursor);
    if (!Number.isSafeInteger(afterCursor) || afterCursor < 0) {
      throw codeError("host_app_change_cursor_invalid");
    }
    return { afterCursor };
  }
  if (kind === "appAuthorizedInboxPreview") {
    // An explicit older history page names the last message already listed.
    if (Object.keys(body).length === 1 && Object.hasOwn(body, "before")) {
      return { before: assertApplicationId(body.before, "host_app_local_message_id_invalid") };
    }
    assertExactKeys(body, ["unreadOnly", "limit"]);
    if (body.unreadOnly !== true || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > 3) {
      throw codeError("host_request_body_invalid");
    }
    return { unreadOnly: true, limit: body.limit };
  }
  if (kind === "appWorkbenchRead") {
    try {
      return validateWorkbenchReadRequest(body);
    } catch {
      throw codeError("host_app_workbench_read_invalid");
    }
  }
  if (kind === "appWorkbenchActionGrant") {
    assertExactKeys(body, ["adapterInstanceId", "request"]);
    if (!isPlainObject(body.request)) throw codeError("host_request_body_invalid");
    const adapterInstanceId = assertIdentifier(
      body.adapterInstanceId,
      "host_adapter_instance_id_invalid",
    );
    try {
      const request = validateWorkbenchCommand(body.request);
      assertWorkbenchRawSafetyCodeForbidden(request);
      return {
        adapterInstanceId,
        request,
      };
    } catch {
      throw codeError("host_app_workbench_command_invalid");
    }
  }
  if (kind === "appWorkbenchCommand") {
    assertAllowedKeys(body, ["actionGrant", "adapterInstanceId", "request"]);
    if (!Object.hasOwn(body, "adapterInstanceId") || !Object.hasOwn(body, "request")) {
      throw codeError("host_app_workbench_command_invalid");
    }
    if (!isPlainObject(body.request)) throw codeError("host_request_body_invalid");
    const adapterInstanceId = assertIdentifier(
      body.adapterInstanceId,
      "host_adapter_instance_id_invalid",
    );
    try {
      const request = validateWorkbenchCommand(body.request);
      assertWorkbenchRawSafetyCodeForbidden(request);
      const readOnlyStatus = request.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus;
      if ((!readOnlyStatus && !Object.hasOwn(body, "actionGrant"))
        || (readOnlyStatus && Object.hasOwn(body, "actionGrant") && body.actionGrant != null)) {
        throw codeError("host_app_workbench_command_invalid");
      }
      return {
        adapterInstanceId,
        request,
        ...(Object.hasOwn(body, "actionGrant") ? { actionGrant: body.actionGrant } : {}),
      };
    } catch {
      throw codeError("host_app_workbench_command_invalid");
    }
  }
  return body;
}

function assertWorkbenchRawSafetyCodeForbidden(command) {
  if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact
    && Object.hasOwn(command.payload, "safetyCode")) {
    throw codeError("host_app_workbench_command_invalid");
  }
}

function assertNoSenderIdentity(value, seen = new Set()) {
  if (value == null || typeof value !== "object") return;
  if (seen.has(value)) throw codeError("host_agent_message_invalid");
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertNoSenderIdentity(item, seen);
    return;
  }
  if (!isPlainObject(value)) throw codeError("host_agent_message_invalid");
  for (const [key, nested] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (RESERVED_MESSAGE_IDENTITY_KEYS.has(normalized)) {
      throw codeError("host_agent_sender_identity_forbidden");
    }
    assertNoSenderIdentity(nested, seen);
  }
}

function normalizeHandlers(value = {}) {
  const handlers = value && typeof value === "object" ? value : {};
  return Object.freeze({
    status: functionOrDefault(handlers.status, () => null),
    localIdentityProof: functionOrDefault(handlers.localIdentityProof, unavailableApplicationHandler),
    localPeerExchange: functionOrDefault(handlers.localPeerExchange, unavailableApplicationHandler),
    attach: functionOrDefault(handlers.attach, () => null),
    heartbeat: functionOrDefault(handlers.heartbeat, () => null),
    detach: functionOrDefault(handlers.detach, () => null),
    agentMessage: functionOrDefault(handlers.agentMessage, () => ({ accepted: true })),
    appInboxMessages: functionOrDefault(handlers.appInboxMessages, unavailableApplicationHandler),
    appInboxUnreadCount: functionOrDefault(handlers.appInboxUnreadCount, unavailableApplicationHandler),
    appInboxMarkRead: functionOrDefault(handlers.appInboxMarkRead, unavailableApplicationHandler),
    appInboxDeleteRead: functionOrDefault(handlers.appInboxDeleteRead, unavailableApplicationHandler),
    appContactsList: functionOrDefault(handlers.appContactsList, unavailableApplicationHandler),
    appContactsUpsert: functionOrDefault(handlers.appContactsUpsert, unavailableApplicationHandler),
    appContactsRemove: functionOrDefault(handlers.appContactsRemove, unavailableApplicationHandler),
    appContactAutonomousSendAuthorization: functionOrDefault(
      handlers.appContactAutonomousSendAuthorization,
      unavailableApplicationHandler,
    ),
    appAuthorizedContactsList: functionOrDefault(
      handlers.appAuthorizedContactsList,
      unavailableApplicationHandler,
    ),
    appModelInbox: functionOrDefault(handlers.appModelInbox, unavailableApplicationHandler),
    appAuthorizedInboxMessages: functionOrDefault(
      handlers.appAuthorizedInboxMessages,
      unavailableApplicationHandler,
    ),
    appAuthorizedInboxActivate: functionOrDefault(
      handlers.appAuthorizedInboxActivate,
      unavailableApplicationHandler,
    ),
    appAuthorizedInboxRead: functionOrDefault(
      handlers.appAuthorizedInboxRead,
      unavailableApplicationHandler,
    ),
    ...Object.fromEntries(["appAuthorizedInboxPending", "appAuthorizedInboxPendingQuery", "appAuthorizedInboxClaim", "appAuthorizedInboxFinish", "appAuthorizedInboxBatchReserve", "appAuthorizedInboxBatchOpen", "appAuthorizedInboxBatchAttempt", "appAuthorizedInboxBatchConfirm", "appAuthorizedInboxBatchCancel", "appAuthorizedInboxBatchExpire", "appAuthorizedInboxBatchClosed"]
      .map((name) => [name, functionOrDefault(handlers[name], unavailableApplicationHandler)])),
    appAuthorizedContactRequestsList: functionOrDefault(
      handlers.appAuthorizedContactRequestsList,
      unavailableApplicationHandler,
    ),
    appAuthorizedContactRequestRead: functionOrDefault(
      handlers.appAuthorizedContactRequestRead,
      unavailableApplicationHandler,
    ),
    appAuthorizedSend: functionOrDefault(handlers.appAuthorizedSend, unavailableApplicationHandler),
    appAuthorizedReply: functionOrDefault(handlers.appAuthorizedReply, unavailableApplicationHandler),
    appContactRequestsList: functionOrDefault(handlers.appContactRequestsList, unavailableApplicationHandler),
    appOutboxMessages: functionOrDefault(handlers.appOutboxMessages, unavailableApplicationHandler),
    appOutboxRetry: functionOrDefault(handlers.appOutboxRetry, unavailableApplicationHandler),
    appHumanSendRequest: functionOrDefault(handlers.appHumanSendRequest, unavailableNativeBrokerHandler),
    appHumanSendRequestStatus: functionOrDefault(handlers.appHumanSendRequestStatus, unavailableNativeBrokerHandler),
    appChangesSnapshot: functionOrDefault(handlers.appChangesSnapshot, unavailableApplicationHandler),
    appChangesSubscribe: functionOrDefault(handlers.appChangesSubscribe, unavailableApplicationHandler),
    appWorkbenchSnapshot: functionOrDefault(handlers.appWorkbenchSnapshot, unavailableApplicationHandler),
    appWorkbenchActionGrant: functionOrDefault(handlers.appWorkbenchActionGrant, () => null),
    appWorkbenchCommand: functionOrDefault(handlers.appWorkbenchCommand, unavailableApplicationHandler),
    idleShutdown: functionOrDefault(handlers.idleShutdown, () => null),
  });
}

function immutableCapabilityTuple(capability) {
  return Object.freeze({
    contract: capability.contract,
    capabilityId: capability.capabilityId,
    region: capability.region,
    principalId: capability.principalId,
    delegateId: capability.delegateId,
    hostInstallationId: capability.hostInstallationId,
    adapterId: capability.adapterId,
    version: capability.version,
    state: capability.state,
    scopes: Object.freeze([...capability.scopes]),
    issuedAt: capability.issuedAt,
    revokedAt: capability.revokedAt,
    secretDigest: crypto.createHash("sha256").update(capability.secretBuffer).digest("hex"),
  });
}

function immutableCapabilityTupleMatches(left, right) {
  return left.contract === right.contract
    && left.capabilityId === right.capabilityId
    && left.region === right.region
    && left.principalId === right.principalId
    && left.delegateId === right.delegateId
    && left.hostInstallationId === right.hostInstallationId
    && left.adapterId === right.adapterId
    && left.version === right.version
    && left.state === right.state
    && left.issuedAt === right.issuedAt
    && left.revokedAt === right.revokedAt
    && left.secretDigest === right.secretDigest
    && left.scopes.length === right.scopes.length
    && left.scopes.every((scope, index) => scope === right.scopes[index]);
}

function publicCapability(capability) {
  return {
    region: capability.region,
    principalId: capability.principalId,
    hostInstallationId: capability.hostInstallationId,
    adapterId: capability.adapterId,
    delegateId: capability.delegateId,
    capabilityVersion: capability.version,
    scopes: [...capability.scopes],
  };
}

function publicActionContext(capability, fields) {
  return Object.freeze({
    ...fields,
    contractId: HELLOLYNK_HOST_CONTRACT,
    hostGeneration: fields.hostGeneration,
    region: capability.region,
    principalId: capability.principalId,
    hostInstallationId: capability.hostInstallationId,
    adapterId: capability.adapterId,
    delegateId: capability.delegateId,
    capabilityVersion: capability.version,
  });
}

function attachmentResponse(attachment, alreadyAttached) {
  return {
    ok: true,
    attached: true,
    alreadyAttached,
    adapterInstanceId: attachment.adapterInstanceId,
    adapterId: attachment.adapterId,
    delegateId: attachment.delegateId,
    heartbeatAfterMs: HELLOLYNK_HOST_ATTACHMENT_HEARTBEAT_MS,
    leaseExpiresAt: attachment.expiresAt,
  };
}

function attachmentMatchesCapability(attachment, capability) {
  return attachment.capabilityId === capability.capabilityId
    && attachment.adapterId === capability.adapterId
    && attachment.delegateId === capability.delegateId
    && attachment.capabilityVersion === capability.version;
}

function attachmentKey(capabilityId, adapterInstanceId) {
  return `${capabilityId}\0${adapterInstanceId}`;
}

function workbenchClientType(adapterId) {
  const value = String(adapterId || "").toLowerCase();
  if (value === "codex") return "codex";
  if (value === "cursor") return "cursor";
  if (value === "dsh") return "dsh";
  if (value === "claude-code") return "claude-code";
  if (value === "openclaw") return "openclaw";
  if (["trae-work", "trae_work", "traework"].includes(value)) return "trae-work";
  if (["workbuddy", "work-buddy"].includes(value)) return "workbuddy";
  return "unknown";
}

function requiredHeader(headers, name) {
  let value;
  if (typeof headers?.get === "function") value = headers.get(name);
  else if (headers instanceof Map) value = headers.get(name) ?? headers.get(name.toLowerCase());
  else if (headers && typeof headers === "object") {
    const matching = Object.keys(headers).filter((key) => key.toLowerCase() === name);
    if (matching.length !== 1) throw codeError("host_request_unauthorized");
    value = headers[matching[0]];
  }
  if (Array.isArray(value) || typeof value !== "string" || value.length === 0 || value.includes(",")) {
    throw codeError("host_request_unauthorized");
  }
  return value;
}

function parseTimestampHeader(value) {
  if (!/^(?:0|[1-9][0-9]{0,15})$/.test(value)) throw codeError("host_request_unauthorized");
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp)) throw codeError("host_request_unauthorized");
  return timestamp;
}

function isHumanOrRootPath(pathname) {
  return pathname === "/human-api"
    || pathname.startsWith("/human-api/")
    || pathname === "/root"
    || pathname.startsWith("/root/");
}

async function invokeHandler(handler, input) {
  try {
    return await handler(input);
  } catch {
    throw codeError("host_action_failed");
  }
}

const applicationDeliveryErrorStatus = Object.freeze({
  e2ee_peer_identity_pin_mismatch: 409,
  recipient_e2ee_device_offline: 503,
  e2ee_prekey_claim_rate_limited: 429,
  relay_request_body_too_large: 413,
});

async function invokeApplicationHandler(handler, input) {
  try {
    return await handler(input);
  } catch (error) {
    const code = safeErrorCode(error);
    if (Object.hasOwn(applicationDeliveryErrorStatus, code) || /^native_(?:directory|target|conversation|content)_/.test(code)
      || code.startsWith("model_inbox_") || code.startsWith("host_app_") || code.startsWith("human_confirmation_")
      || code === "host_request_unauthorized") {
      throw codeError(code);
    }
    const workbenchCode = mapWorkbenchApplicationError(error?.code);
    if (workbenchCode) throw codeError(workbenchCode);
    throw codeError("host_app_action_failed");
  }
}

function mapWorkbenchApplicationError(value) {
  const code = String(value || "");
  if (!/^neutral_host_workbench_[a-z0-9_]{1,100}$/.test(code)) return null;
  if (code === "neutral_host_workbench_snapshot_busy") return "host_app_workbench_snapshot_busy";
  if (code === "neutral_host_workbench_thread_not_found"
    || code === "neutral_host_workbench_thread_not_in_page") {
    return "host_app_workbench_thread_not_found";
  }
  if (code === "neutral_host_workbench_cursor_invalid"
    || code === "neutral_host_workbench_thread_cursor_invalid"
    || code === "neutral_host_workbench_message_cursor_invalid") {
    return "host_app_workbench_cursor_invalid";
  }
  if (code === "neutral_host_workbench_message_cursor_thread_required"
    || code === "neutral_host_workbench_filter_invalid"
    || code === "neutral_host_workbench_query_invalid"
    || code === "neutral_host_workbench_read_request_invalid") {
    return "host_app_workbench_read_invalid";
  }
  return "host_app_workbench_snapshot_failed";
}

function applicationResponse(action, value, requestBody = null) {
  if (!isPlainObject(value)) throw codeError("host_app_response_invalid");
  if (action === "appModelInbox") {
    const operation = requestBody.operation;
    if (operation === "count") {
      assertExactKeys(value, ["unreadCount", "humanUnreadCount", "aiPendingCount", "scope"]);
      if (value.scope !== requestBody.scope || value.unreadCount !== value.humanUnreadCount) throw codeError("host_app_response_invalid");
      return { ok: true, scope: value.scope, unreadCount: assertNonNegativeInteger(value.unreadCount),
        humanUnreadCount: assertNonNegativeInteger(value.humanUnreadCount), aiPendingCount: assertNonNegativeInteger(value.aiPendingCount) };
    }
    if (operation === "assertReply") {
      assertExactKeys(value, ["allowed"]);
      if (value.allowed !== true) throw codeError("host_app_response_invalid");
      return { ok: true, allowed: true };
    }
    if (operation === "pending") {
      return applicationResponse("appAuthorizedInboxPendingQuery", { messages: value.messages.map(({ receiptSeq, ...message }) => message),
        nextCursor: value.nextCursor ?? null }, {});
    }
    const actions = { list: "appAuthorizedInboxMessages", read: "appAuthorizedInboxRead", claim: "appAuthorizedInboxClaim" };
    return applicationResponse(actions[operation], value, requestBody.query);
  }
  if (action === "appInboxMessages") {
    assertExactKeys(value, ["messages"]);
    if (!Array.isArray(value.messages) || value.messages.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, messages: value.messages.map(validateInboxMessageDto) };
  }
  if (action === "appInboxUnreadCount") {
    assertExactKeys(value, ["unreadCount"]);
    return { ok: true, unreadCount: assertNonNegativeInteger(value.unreadCount) };
  }
  if (action === "appInboxMarkRead") {
    assertExactKeys(value, ["localMessageId", "unread"]);
    if (value.unread !== false) throw codeError("host_app_response_invalid");
    return {
      ok: true,
      localMessageId: assertApplicationId(value.localMessageId, "host_app_response_invalid"),
      unread: false,
    };
  }
  if (action === "appInboxDeleteRead") {
    assertExactKeys(value, ["deletedCount", "deletedIds"]);
    const deletedIds = assertApplicationIdArray(value.deletedIds, "host_app_response_invalid", 0);
    if (assertNonNegativeInteger(value.deletedCount) !== deletedIds.length) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, deletedCount: deletedIds.length, deletedIds };
  }
  if (action === "appContactsList") {
    assertExactKeys(value, ["contacts"]);
    if (!Array.isArray(value.contacts) || value.contacts.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, contacts: value.contacts.map(validateContactDto) };
  }
  if (action === "appContactsUpsert") {
    assertExactKeys(value, ["contact"]);
    return { ok: true, contact: validateContactMutationDto(value.contact) };
  }
  if (action === "appContactsRemove") {
    assertExactKeys(value, ["contactId", "removed"]);
    if (typeof value.removed !== "boolean") throw codeError("host_app_response_invalid");
    return {
      ok: true,
      contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
      removed: value.removed,
    };
  }
  if (action === "appContactAutonomousSendAuthorization") {
    assertExactKeys(value, ["contact"]);
    return { ok: true, contact: validateContactAuthorizationMutationDto(value.contact) };
  }
  if (action === "appAuthorizedContactsList") {
    assertExactKeys(value, ["contacts", ...(Object.hasOwn(value, "nativeConversations") ? ["nativeConversations"] : [])]);
    if (!Array.isArray(value.contacts) || value.contacts.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, contacts: value.contacts.map(validateAuthorizedContactDto),
      ...(value.nativeConversations ? { nativeConversations: nativeDirectoryResult(value.nativeConversations) } : {}) };
  }
  if (action === "appAuthorizedInboxMessages" || action === "appAuthorizedInboxPending") {
    assertExactKeys(value, ["messages"]);
    if (!Array.isArray(value.messages) || value.messages.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, messages: value.messages.map(validateAuthorizedInboxMetadataDto) };
  }
  if (action === "appAuthorizedInboxPendingQuery") {
    assertExactKeys(value, ["messages", "nextCursor"]);
    const target = requestBody?.localMessageId != null;
    if (!Array.isArray(value.messages) || value.messages.length > (target ? 1 : 1_000)
      || (value.nextCursor !== null && (target || !Number.isSafeInteger(value.nextCursor) || value.nextCursor <= 0))) {
      throw codeError("host_app_response_invalid");
    }
    const messages = value.messages.map(validateAuthorizedInboxMetadataDto);
    if (target && messages.some((item) => item.localMessageId !== requestBody.localMessageId
      || item.conversationKey !== requestBody.conversationKey)) throw codeError("host_app_response_invalid");
    return { ok: true, messages, nextCursor: value.nextCursor };
  }
  if (action === "appAuthorizedInboxActivate") {
    assertExactKeys(value, ["active"]);
    if (value.active !== true) throw codeError("host_app_response_invalid");
    return { ok: true, active: true };
  }
  if (action === "appAuthorizedInboxRead") {
    assertExactKeys(value, ["message"]);
    return { ok: true, message: validateAuthorizedInboxMessageDto(value.message) };
  }
  if (action.startsWith("appAuthorizedInboxBatch")) {
    const operation = action.slice("appAuthorizedInboxBatch".length);
    if (operation === "Open") {
      assertExactKeys(value, ["batches"]);
      if (!Array.isArray(value.batches)) throw codeError("host_app_response_invalid");
      return { ok: true, batches: value.batches.map(item => validateInboxBatchDto(item)) };
    }
    if (operation === "Reserve" && value.status === "empty") {
      assertExactKeys(value, ["status"]); return { ok: true, status: "empty" };
    }
    return { ok: true, ...validateInboxBatchDto(value, operation) };
  }
  if (action === "appAuthorizedInboxClaim" && requestBody?.batchId) {
    assertExactKeys(value, ["claimed", "messages", "expiredCount", "notice"]);
    if (!Array.isArray(value.messages) || typeof value.claimed !== "boolean" || value.claimed !== (value.messages.length > 0)
      || !Number.isSafeInteger(value.expiredCount) || value.expiredCount < 0 || (value.notice !== null && typeof value.notice !== "string")) throw codeError("host_app_response_invalid");
    const messages = value.messages.map(validateAuthorizedInboxMessageDto);
    if (messages.reduce((n, m) => n + Array.from(m.text).length, 0) > 20000) throw codeError("host_app_response_invalid");
    return { ok: true, ...value, messages };
  }
  if (action === "appAuthorizedInboxClaim") {
    assertExactKeys(value, ["claimed", "claimId", "message"]);
    if (value.claimed === false && value.claimId === null && value.message === null) {
      return { ok: true, claimed: false, claimId: null, message: null };
    }
    if (value.claimed !== true) throw codeError("host_app_response_invalid");
    return { ok: true, claimed: true,
      claimId: assertIdentifier(value.claimId, "host_app_response_invalid"),
      message: validateAuthorizedInboxMessageDto(value.message) };
  }
  if (action === "appAuthorizedInboxFinish") {
    assertExactKeys(value, ["claimId", "outcome"]);
    if (!["completed", "unknown"].includes(value.outcome)) throw codeError("host_app_response_invalid");
    return { ok: true, claimId: assertIdentifier(value.claimId, "host_app_response_invalid"), outcome: value.outcome };
  }
  if (action === "appAuthorizedContactRequestsList") {
    assertExactKeys(value, ["requests"]);
    if (!Array.isArray(value.requests) || value.requests.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, requests: value.requests.map(validateAuthorizedContactRequestMetadataDto) };
  }
  if (action === "appAuthorizedContactRequestRead") {
    assertExactKeys(value, ["request"]);
    return { ok: true, request: validateAuthorizedContactRequestDto(value.request) };
  }
  if (action === "appContactRequestsList") {
    assertExactKeys(value, ["requests"]);
    if (!Array.isArray(value.requests) || value.requests.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, requests: value.requests.map(validateContactRequestDto) };
  }
  if (action === "appOutboxMessages") {
    assertExactKeys(value, ["messages"]);
    if (!Array.isArray(value.messages) || value.messages.length > 1_000) {
      throw codeError("host_app_response_invalid");
    }
    return { ok: true, messages: value.messages.map(validateOutboxMessageDto) };
  }
  if (action === "appOutboxRetry") {
    assertExactKeys(value, ["message"]);
    return { ok: true, message: validateOutboxMutationDto(value.message) };
  }
  if (action === "appHumanSendRequest" || action === "appHumanSendRequestStatus") {
    assertAllowedKeys(value, [
      "actionId", "code", "contract", "createdAtMs", "expiresAtMs", "idempotent", "state",
    ]);
    for (const required of ["actionId", "createdAtMs", "expiresAtMs", "state"]) {
      if (!Object.hasOwn(value, required)) throw codeError("host_app_response_invalid");
    }
    if (Object.hasOwn(value, "idempotent") && typeof value.idempotent !== "boolean") {
      throw codeError("host_app_response_invalid");
    }
    if (Object.hasOwn(value, "code") && value.code != null
      && !/^human_confirmation_[a-z0-9_]{1,100}$/.test(String(value.code))) {
      throw codeError("host_app_response_invalid");
    }
    const createdAtMs = assertNonNegativeInteger(value.createdAtMs);
    const expiresAtMs = assertNonNegativeInteger(value.expiresAtMs);
    if (expiresAtMs < createdAtMs) throw codeError("host_app_response_invalid");
    return {
      ok: true,
      actionId: assertApplicationId(value.actionId, "host_app_response_invalid"),
      state: assertHumanActionState(value.state),
      ...(value.code == null ? {} : { code: value.code }),
      createdAtMs,
      expiresAtMs,
      ...(Object.hasOwn(value, "idempotent") ? { idempotent: value.idempotent } : {}),
    };
  }
  if (action === "appAuthorizedSend" || action === "appAuthorizedReply") {
    assertExactKeys(value, ["accepted", "authorization", "clientMessageId", "contactId", "status"]);
    if (value.accepted !== true || value.authorization !== "contact_delegate_allowlist") {
      throw codeError("host_app_response_invalid");
    }
    return {
      ok: true,
      accepted: true,
      authorization: value.authorization,
      clientMessageId: assertApplicationId(value.clientMessageId, "host_app_response_invalid"),
      contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
      status: assertApplicationId(value.status, "host_app_response_invalid"),
    };
  }
  if (action === "appChangesSnapshot") return validateChangeSnapshot(value);
  if (action === "appChangesSubscribe") return validateChangeSubscription(value);
  if (action === "appWorkbenchSnapshot") {
    assertExactKeys(value, ["snapshot"]);
    return { ok: true, snapshot: validateWorkbenchSnapshot(value.snapshot) };
  }
  if (action === "appWorkbenchCommand") {
    return validateWorkbenchCommandResult(value, requestBody?.command);
  }
  throw codeError("host_app_response_invalid");
}

function validateInboxMessageDto(value) {
  assertExactKeys(value, [
    "localMessageId", "clientMessageId", "peerPrincipalId", "peerHelloLynkId", "senderDelegateId",
    "senderPrincipalDisplayName", "senderDelegateDisplayName", "messageType", "text", "unread",
    "createdAt", "updatedAt", "conversationKey", "localDelegateId", "peerDelegateId",
  ]);
  if (typeof value.unread !== "boolean") throw codeError("host_app_response_invalid");
  return {
    localMessageId: assertApplicationId(value.localMessageId, "host_app_response_invalid"),
    clientMessageId: assertApplicationId(value.clientMessageId, "host_app_response_invalid"),
    peerPrincipalId: optionalApplicationIdentifier(value.peerPrincipalId),
    peerHelloLynkId: value.peerHelloLynkId == null ? null : assertHelloLynkId(value.peerHelloLynkId, "host_app_response_invalid"),
    senderDelegateId: assertIdentifier(value.senderDelegateId, "host_app_response_invalid"),
    conversationKey: optionalApplicationIdentifier(value.conversationKey),
    localDelegateId: optionalApplicationIdentifier(value.localDelegateId),
    peerDelegateId: optionalApplicationIdentifier(value.peerDelegateId),
    senderPrincipalDisplayName: optionalApplicationString(value.senderPrincipalDisplayName, 80),
    senderDelegateDisplayName: optionalApplicationString(value.senderDelegateDisplayName, 80),
    messageType: assertIdentifier(value.messageType, "host_app_response_invalid"),
    text: assertApplicationString(value.text, "host_app_response_invalid", 64 * 1024, true),
    unread: value.unread,
    createdAt: assertIsoTimestamp(value.createdAt),
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateContactDto(value) {
  assertExactKeys(value, [
    "contactId", "hellolynkId", "displayName",
    "autonomousSendAuthorized", "createdAt", "updatedAt",
  ]);
  if (typeof value.autonomousSendAuthorized !== "boolean") throw codeError("host_app_response_invalid");
  return {
    contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
    hellolynkId: assertHelloLynkId(value.hellolynkId, "host_app_response_invalid"),
    displayName: assertApplicationDisplayName(value.displayName, "host_app_response_invalid"),
    autonomousSendAuthorized: value.autonomousSendAuthorized,
    createdAt: assertIsoTimestamp(value.createdAt),
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateContactAuthorizationMutationDto(value) {
  assertExactKeys(value, ["contactId", "autonomousSendAuthorized", "updatedAt"]);
  if (typeof value.autonomousSendAuthorized !== "boolean") throw codeError("host_app_response_invalid");
  return {
    contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
    autonomousSendAuthorized: value.autonomousSendAuthorized,
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateAuthorizedContactDto(value) {
  assertExactKeys(value, ["contactId", "displayName", "recipientDelegateId", "instanceDisplayName"]);
  return {
    contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
    displayName: assertApplicationDisplayName(value.displayName, "host_app_response_invalid"),
    recipientDelegateId: assertIdentifier(value.recipientDelegateId, "host_app_response_invalid"),
    instanceDisplayName: assertApplicationDisplayName(value.instanceDisplayName, "host_app_response_invalid"),
  };
}

function validateInboxBatchDto(value, operation = "") {
  const extra = operation === "Attempt" ? ["attempted"] : operation === "Cancel" ? ["cancelled"] : [];
  assertExactKeys(value, ["batchId", "target", "state", "count", "expiredCount", "full", "highWater", "oldestReceipt", "attempts", ...extra]);
  for (const field of ["count", "expiredCount", "highWater", "oldestReceipt", "attempts"])
    if (!Number.isSafeInteger(value[field]) || value[field] < 0) throw codeError("host_app_response_invalid");
  if (!["reserved", "delivered", "closed"].includes(value.state) || typeof value.full !== "boolean" || value.attempts > 2
    || extra.some(field => typeof value[field] !== "boolean")) throw codeError("host_app_response_invalid");
  assertIdentifier(value.batchId, "host_app_response_invalid"); assertIdentifier(value.target, "host_app_response_invalid");
  return value;
}

function validateAuthorizedInboxMetadataDto(value) {
  const hasReply = Object.hasOwn(value, "replyToClientMessageId");
  const hasTarget = Object.hasOwn(value, "targetConversationId");
  const hasInstanceName = Object.hasOwn(value, "peerInstanceDisplayName");
  const hasExpiry = Object.hasOwn(value, "automaticDeliveryState");
  if (hasExpiry && value.automaticDeliveryState !== "expired") throw codeError("host_app_response_invalid");
  assertExactKeys(value, ["localMessageId", "contactId", "displayName", "unread", "createdAt", "conversationKey", "localDelegateId", "peerDelegateId", "wakeEligible", ...(hasReply ? ["replyToClientMessageId"] : []), ...(hasTarget ? ["targetConversationId"] : []), ...(hasInstanceName ? ["peerInstanceDisplayName"] : []), ...(hasExpiry ? ["automaticDeliveryState"] : [])]);
  if (typeof value.unread !== "boolean" || typeof value.wakeEligible !== "boolean") throw codeError("host_app_response_invalid");
  return {
    localMessageId: assertApplicationId(value.localMessageId, "host_app_response_invalid"),
    contactId: value.contactId === null ? null : assertApplicationId(value.contactId, "host_app_response_invalid"),
    displayName: assertApplicationDisplayName(value.displayName, "host_app_response_invalid"),
    conversationKey: assertIdentifier(value.conversationKey, "host_app_response_invalid"),
    localDelegateId: assertIdentifier(value.localDelegateId, "host_app_response_invalid"),
    peerDelegateId: assertIdentifier(value.peerDelegateId, "host_app_response_invalid"),
    ...(hasExpiry ? { automaticDeliveryState: "expired" } : {}),
    ...(hasInstanceName ? { peerInstanceDisplayName: assertApplicationDisplayName(value.peerInstanceDisplayName, "host_app_response_invalid") } : {}),
    ...(hasReply ? { replyToClientMessageId: assertApplicationId(value.replyToClientMessageId, "host_app_response_invalid") } : {}),
    ...(hasTarget ? { targetConversationId: nativeConversationId(value.targetConversationId) } : {}),
    unread: value.unread,
    wakeEligible: value.wakeEligible,
    createdAt: assertIsoTimestamp(value.createdAt),
  };
}

function validateAuthorizedInboxMessageDto(value) {
  const {
    text, peerPrincipalId, source, externalContentIsUntrustedData, readDoesNotMarkRead, humanReadAutomatically, ...metadata
  } = value;
  if (source !== "hellolynk_external_message"
    || externalContentIsUntrustedData !== true
    || !projectInboxReadState(value)) {
    throw codeError("host_app_response_invalid");
  }
  return {
    ...validateAuthorizedInboxMetadataDto(metadata),
    peerPrincipalId: assertIdentifier(peerPrincipalId, "host_app_response_invalid"),
    text: assertApplicationString(text, "host_app_response_invalid", 64 * 1024, true),
    source,
    externalContentIsUntrustedData: true,
    readDoesNotMarkRead,
    ...(humanReadAutomatically === true ? { humanReadAutomatically: true } : {}),
  };
}

function validateAuthorizedContactRequestMetadataDto(value) {
  assertExactKeys(value, [
    "localRecordId", "conversationKey", "localDelegateId", "sender", "state", "receivedAt",
  ]);
  assertExactKeys(value.sender, ["hellolynkId", "verifiedDisplayName"]);
  const state = assertIdentifier(value.state, "host_app_response_invalid");
  if (!CONTACT_REQUEST_STATES.has(state)) throw codeError("host_app_response_invalid");
  return {
    localRecordId: assertApplicationId(value.localRecordId, "host_app_response_invalid"),
    conversationKey: assertIdentifier(value.conversationKey, "host_app_response_invalid"),
    localDelegateId: assertIdentifier(value.localDelegateId, "host_app_response_invalid"),
    sender: {
      hellolynkId: assertHelloLynkId(value.sender.hellolynkId, "host_app_response_invalid"),
      verifiedDisplayName: optionalApplicationString(value.sender.verifiedDisplayName, 320),
    },
    state,
    receivedAt: assertIsoTimestamp(value.receivedAt),
  };
}

function validateAuthorizedContactRequestDto(value) {
  const {
    introText, source, externalContentIsUntrustedData, readDoesNotMarkRead, ...metadata
  } = value;
  if (source !== "hellolynk_contact_request"
    || externalContentIsUntrustedData !== true
    || readDoesNotMarkRead !== true) {
    throw codeError("host_app_response_invalid");
  }
  return {
    ...validateAuthorizedContactRequestMetadataDto(metadata),
    introText: assertApplicationString(introText, "host_app_response_invalid", 256, true),
    source,
    externalContentIsUntrustedData: true,
    readDoesNotMarkRead: true,
  };
}

function validateContactMutationDto(value) {
  assertExactKeys(value, ["contactId", "hellolynkId", "displayName", "updatedAt"]);
  return {
    contactId: assertApplicationId(value.contactId, "host_app_response_invalid"),
    hellolynkId: assertHelloLynkId(value.hellolynkId, "host_app_response_invalid"),
    displayName: assertApplicationDisplayName(value.displayName, "host_app_response_invalid"),
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateOutboxMessageDto(value) {
  assertExactKeys(value, [
    "localMessageId", "clientMessageId", "recipientHelloLynkId", "messageType", "text", "textSha256",
    "status", "retryAllowed", "createdAt", "updatedAt",
  ]);
  if (typeof value.retryAllowed !== "boolean" || !/^[a-f0-9]{64}$/.test(String(value.textSha256 || ""))) {
    throw codeError("host_app_response_invalid");
  }
  return {
    localMessageId: assertApplicationId(value.localMessageId, "host_app_response_invalid"),
    clientMessageId: assertApplicationId(value.clientMessageId, "host_app_response_invalid"),
    recipientHelloLynkId: assertHelloLynkId(value.recipientHelloLynkId, "host_app_response_invalid"),
    messageType: assertIdentifier(value.messageType, "host_app_response_invalid"),
    text: assertApplicationString(value.text, "host_app_response_invalid", 64 * 1024, true),
    textSha256: value.textSha256,
    status: assertIdentifier(value.status, "host_app_response_invalid"),
    retryAllowed: value.retryAllowed,
    createdAt: assertIsoTimestamp(value.createdAt),
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateOutboxMutationDto(value) {
  assertExactKeys(value, ["clientMessageId", "status", "retryAllowed", "updatedAt"]);
  if (typeof value.retryAllowed !== "boolean") throw codeError("host_app_response_invalid");
  return {
    clientMessageId: assertApplicationId(value.clientMessageId, "host_app_response_invalid"),
    status: assertIdentifier(value.status, "host_app_response_invalid"),
    retryAllowed: value.retryAllowed,
    updatedAt: assertIsoTimestamp(value.updatedAt),
  };
}

function validateContactRequestDto(value) {
  const legacyKeys = [
    "actionReady", "humanOnly", "introText", "introWeight", "localRecordId",
    "modelVisibility", "receivedAt", "sender", "serverContactRequestId",
    "serverUpdatedAt", "state",
  ];
  const decisionKeys = ["decisionOutcome", "decisionAction"];
  const hasDecisionOutcome = Object.hasOwn(value, "decisionOutcome");
  const hasDecisionAction = Object.hasOwn(value, "decisionAction");
  if (hasDecisionOutcome !== hasDecisionAction) throw codeError("host_app_response_invalid");
  assertExactKeys(value, hasDecisionOutcome ? [...legacyKeys, ...decisionKeys] : legacyKeys);
  assertExactKeys(value.sender, ["hellolynkId", "verifiedDisplayName"]);
  if (value.humanOnly !== true || value.modelVisibility !== "none"
    || typeof value.actionReady !== "boolean") {
    throw codeError("host_app_response_invalid");
  }
  const introWeight = assertNonNegativeInteger(value.introWeight);
  if (!Number.isSafeInteger(value.introWeight) || introWeight > 40) throw codeError("host_app_response_invalid");
  const serverContactRequestId = optionalApplicationIdentifier(value.serverContactRequestId);
  const state = assertIdentifier(value.state, "host_app_response_invalid");
  const decisionOutcome = hasDecisionOutcome ? value.decisionOutcome : null;
  const decisionAction = hasDecisionAction ? value.decisionAction : null;
  const actionReady = hasDecisionOutcome ? value.actionReady : false;
  if (!CONTACT_REQUEST_STATES.has(state)
    || !new Set([null, "unknown", "recovery-required"]).has(decisionOutcome)
    || (decisionAction != null && !new Set(["accept", "reject", "block"]).has(decisionAction))
    || (actionReady && (serverContactRequestId == null
      || state !== "pending"
      || decisionOutcome != null
      || decisionAction != null))
    || (state !== "pending" && actionReady)
    || ((decisionOutcome === "unknown") !== (decisionAction != null))
    || (decisionOutcome != null && (state !== "pending" || actionReady))) {
    throw codeError("host_app_response_invalid");
  }
  return {
    humanOnly: true,
    modelVisibility: "none",
    localRecordId: assertApplicationId(value.localRecordId, "host_app_response_invalid"),
    serverContactRequestId,
    state,
    actionReady,
    decisionOutcome,
    decisionAction,
    introText: assertApplicationString(value.introText, "host_app_response_invalid", 256, true),
    introWeight,
    sender: {
      hellolynkId: assertHelloLynkId(value.sender.hellolynkId, "host_app_response_invalid"),
      verifiedDisplayName: optionalApplicationString(value.sender.verifiedDisplayName, 320),
    },
    receivedAt: assertIsoTimestamp(value.receivedAt),
    serverUpdatedAt: value.serverUpdatedAt == null ? null : assertIsoTimestamp(value.serverUpdatedAt),
  };
}

function validateChangeSnapshot(value) {
  assertExactKeys(value, ["cursor", "inbox", "contacts", "outbox", "modelVisibility"]);
  if (value.modelVisibility !== "none") throw codeError("host_app_response_invalid");
  assertExactKeys(value.inbox, ["total", "unread"]);
  assertExactKeys(value.contacts, ["total"]);
  assertExactKeys(value.outbox, ["total", "retryEligible"]);
  return {
    ok: true,
    cursor: assertNonNegativeInteger(value.cursor),
    inbox: {
      total: assertNonNegativeInteger(value.inbox.total),
      unread: assertNonNegativeInteger(value.inbox.unread),
    },
    contacts: { total: assertNonNegativeInteger(value.contacts.total) },
    outbox: {
      total: assertNonNegativeInteger(value.outbox.total),
      retryEligible: assertNonNegativeInteger(value.outbox.retryEligible),
    },
    modelVisibility: "none",
  };
}

function validateChangeSubscription(value) {
  assertExactKeys(value, ["cursor", "snapshotRequired", "events"]);
  if (typeof value.snapshotRequired !== "boolean" || !Array.isArray(value.events) || value.events.length > 256) {
    throw codeError("host_app_response_invalid");
  }
  return {
    ok: true,
    cursor: assertNonNegativeInteger(value.cursor),
    snapshotRequired: value.snapshotRequired,
    events: value.events.map((event) => {
      assertExactKeys(event, ["cursor", "type", "entityId", "changedAt", "modelVisibility"]);
      if (event.modelVisibility !== "none") throw codeError("host_app_response_invalid");
      return {
        cursor: assertNonNegativeInteger(event.cursor),
        type: assertIdentifier(event.type, "host_app_response_invalid"),
        entityId: assertApplicationId(event.entityId, "host_app_response_invalid"),
        changedAt: assertIsoTimestamp(event.changedAt),
        modelVisibility: "none",
      };
    }),
  };
}

function response(status, body) {
  return { status, body };
}

function workbenchActionGrantFailure(command, outcome) {
  const acceptedOutcome = outcome === "unknown" ? "unknown" : "known-failed";
  return validateWorkbenchCommandResult({
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: false,
    requestId: command.requestId,
    revision: null,
    changeCursor: null,
    error: {
      code: "host_workbench_action_grant_invalid",
      retryable: false,
      outcome: acceptedOutcome,
      retryAfterMs: null,
      currentRevision: null,
    },
  }, command.command);
}

function errorResponse(error) {
  const code = safeErrorCode(error);
  return response(errorStatus(code), { ok: false, error: code });
}

function errorStatus(code) {
  if (Object.hasOwn(applicationDeliveryErrorStatus, code)) return applicationDeliveryErrorStatus[code];
  if (code === "native_directory_own_ai_only" || code === "native_target_not_authorized") return 403;
  if (code === "native_directory_unavailable" || code === "native_target_unsupported_or_unavailable") return 503;
  if (["native_target_unavailable", "native_target_title_not_unique", "native_target_title_required"].includes(code)) return 409;
  if (code === "host_route_not_found") return 404;
  if (code === "host_app_record_not_found") return 404;
  if (code === "host_app_workbench_thread_not_found") return 404;
  if (code === "human_confirmation_not_found") return 404;
  if (code === "host_adapter_route_forbidden" || code === "host_capability_scope_denied"
    || code === "host_capability_human_surface_required"
    || code === "host_app_authorization_required") return 403;
  if (code === "host_request_unauthorized") return 401;
  if (code === "host_request_replayed" || code === "host_attachment_not_found"
    || code === "host_attachment_ambiguous" || code === "host_app_state_conflict"
    || code === "host_app_send_failed"
    || code === "host_app_reply_target_deleted"
    || code === "host_app_contact_relationship_not_active"
    || code === "human_confirmation_pending_conflict"
    || code === "human_confirmation_host_generation_mismatch"
    || code === "human_confirmation_authority_invalidated"
    || code === "human_confirmation_binding_mismatch") return 409;
  if (code === "human_confirmation_timed_out") return 408;
  if (code === "human_confirmation_rate_limited") return 429;
  if (code === "host_request_too_large" || code === "host_app_human_send_text_too_large") return 413;
  if (code === "host_not_running" || code === "host_app_unavailable"
    || code === "host_app_workbench_snapshot_busy"
    || code === "host_app_native_broker_unavailable"
    || code === "host_app_relationship_status_unavailable"
    || code === "host_workbench_action_grant_capacity_exceeded"
    || code === "human_confirmation_ledger_unavailable"
    || code === "human_confirmation_broker_closed") return 503;
  if (code.startsWith("host_action_") || code === "host_app_action_failed"
    || code === "host_app_response_invalid" || code === "host_app_workbench_snapshot_failed"
    || code === "host_workbench_action_grant_binding_invalid"
    || code === "host_workbench_action_grant_clock_invalid"
    || code === "host_workbench_action_grant_generation_failed"
    || code === "host_workbench_action_grant_random_source_invalid"
    || code === "host_workbench_action_grant_registry_invalid") return 500;
  if (code.startsWith("human_confirmation_")) {
    if (/_(?:invalid|malformed)$/.test(code)
      || code === "human_confirmation_cancelled"
      || code === "human_confirmation_proof_invalid") return 400;
    return 500;
  }
  return 400;
}

function safeErrorCode(error) {
  const code = String(error?.code || "host_action_failed");
  return Object.hasOwn(applicationDeliveryErrorStatus, code) || /^(?:host|human_confirmation|native_directory|native_target|native_conversation|native_content|model_inbox)_[a-z0-9_]{1,100}$/.test(code)
    ? code : "host_action_failed";
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError("host_request_body_invalid");
  }
}

function assertAllowedKeys(value, allowed) {
  const actual = Object.keys(value);
  if (actual.some((key) => !allowed.includes(key))) throw codeError("host_request_body_invalid");
}

function assertApplicationIdArray(value, code, minimumLength = 1) {
  if (!Array.isArray(value) || value.length < minimumLength || value.length > 500) throw codeError(code);
  const identifiers = value.map((item) => assertApplicationId(item, code));
  if (new Set(identifiers).size !== identifiers.length) throw codeError(code);
  return identifiers;
}

function assertApplicationId(value, code) {
  const identifier = String(value || "");
  if (!APPLICATION_ID_PATTERN.test(identifier)) throw codeError(code);
  return identifier;
}

function assertApplicationString(value, code, maximumBytes, allowEmpty = false) {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)
    || Buffer.byteLength(value, "utf8") > maximumBytes || value.includes("\u0000")) {
    throw codeError(code);
  }
  return value;
}

function assertApplicationDisplayName(value, code) {
  // The local contact store permits 80 Unicode code points, up to 320 UTF-8 bytes.
  const name = assertApplicationString(value, code, 80 * 4);
  if ([...name].length > 80) throw codeError(code);
  return name;
}

function optionalApplicationString(value, maximumBytes) {
  if (value == null) return null;
  return assertApplicationString(value, "host_app_response_invalid", maximumBytes, true);
}

function optionalApplicationIdentifier(value) {
  if (value == null) return null;
  return assertIdentifier(value, "host_app_response_invalid");
}

function assertHelloLynkId(value, code) {
  const hellolynkId = String(value || "");
  if (!HELLOLYNK_ID_PATTERN.test(hellolynkId)) throw codeError(code);
  return hellolynkId;
}

function assertIsoTimestamp(value) {
  if (typeof value !== "string") throw codeError("host_app_response_invalid");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw codeError("host_app_response_invalid");
  }
  return value;
}

function assertNonNegativeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw codeError("host_app_response_invalid");
  return number;
}

function assertHumanActionState(value) {
  const state = String(value || "");
  if (!new Set(["approved", "cancelled", "consuming", "expired", "failed", "invalidated", "pending"])
    .has(state)) throw codeError("host_app_response_invalid");
  return state;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeClock(value) {
  if (value == null) return Object.freeze({ now: () => Date.now() });
  if (typeof value === "function") return Object.freeze({ now: value });
  if (typeof value?.now === "function") return Object.freeze({ now: () => value.now() });
  throw codeError("host_clock_invalid");
}

function normalizeLimit(value, fallback, minimum, maximum) {
  const normalized = Number(value ?? fallback);
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw codeError("host_limit_invalid");
  }
  return normalized;
}

function functionOrDefault(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "function") throw codeError("host_action_handler_invalid");
  return value;
}

function unavailableApplicationHandler() {
  throw codeError("host_app_unavailable");
}

function unavailableNativeBrokerHandler() {
  throw codeError("host_app_native_broker_unavailable");
}

function isLegacySendRoute(pathname) {
  return pathname === HELLOLYNK_HOST_PATHS.agentMessages;
}

function randomGeneration() {
  return crypto.randomBytes(24).toString("hex");
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
