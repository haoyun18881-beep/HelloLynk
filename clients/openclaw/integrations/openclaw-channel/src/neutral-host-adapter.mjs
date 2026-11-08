import { queryArgs, optionalTarget } from "../../../clients/core/hellolynk-native-addressing-tools.cjs";
import { captureHelloLynkModelNotices } from "../../../clients/core/hellolynk-model-notices.cjs";
import crypto from "node:crypto";
import path from "node:path";
import { HELLOLYNK_HOST_CAPABILITY_CONTRACT } from "../../../clients/core/hellolynk-host-auth.mjs";
import {
  createHostProtectedStore,
  HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES,
} from "../../../clients/core/hellolynk-host-protected-store.mjs";
import { HELLOLYNK_HOST_PATHS } from "../../../clients/core/hellolynk-host.mjs";
import {
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
} from "../../../clients/workbench/contract.mjs";

export const HELLOLYNK_OPENCLAW_NEUTRAL_ADAPTER_CONTRACT = "hellolynk-openclaw-neutral-adapter-v3";
export const OPENCLAW_NEUTRAL_EXACT_SCOPES = Object.freeze([
  ...HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES,
]);

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;
const FROZEN_WORKBENCH_ACTION_GRANT_PATH = "/host/v1/app/workbench/action-grants";
const WORKBENCH_ACTION_GRANT_PATH = Object.hasOwn(HELLOLYNK_HOST_PATHS, "appWorkbenchActionGrant")
  ? HELLOLYNK_HOST_PATHS.appWorkbenchActionGrant
  : FROZEN_WORKBENCH_ACTION_GRANT_PATH;
if (WORKBENCH_ACTION_GRANT_PATH !== FROZEN_WORKBENCH_ACTION_GRANT_PATH) {
  throw codeError("neutral_host_workbench_action_grant_path_mismatch");
}
const BINDING_REF = "protected-store:openclaw";
const SAFE_DISCOVERY_ERRORS = new Set([
  "ENOENT", "neutral_host_discovery_stale", "neutral_host_discovery_generation_mismatch",
]);
// Another client, or a newer release, is starting the Host: wait for it instead of failing.
const LAUNCH_YIELD_ERRORS = new Set(["neutral_host_already_running", "neutral_host_release_superseded"]);
// A release handover is on hold: wait for the newer Host like already_running, report "switching" only if none appears.
const RELEASE_SUPERSEDED = "neutral_host_release_superseded";
const TERMINAL_HOST_ERRORS = new Set([
  "neutral_host_discovery_generation_mismatch", "neutral_host_discovery_stale",
  "neutral_host_not_found", "host_not_running", "host_request_unauthorized",
  "host_attachment_not_found", "host_attachment_expired", "ECONNREFUSED",
]);
export function isOpenClawNeutralHostUnavailable(error) {
  return TERMINAL_HOST_ERRORS.has(error?.code) || TERMINAL_HOST_ERRORS.has(error?.cause?.code);
}

export function createOpenClawProtectedBindingProvider(options = {}) {
  const store = options.protectedStore || createHostProtectedStore({
    ...(options.storeRoot ? { root: options.storeRoot } : {}),
    ...(options.installationStore ? { installationStore: options.installationStore } : {}),
    ...(options.helperPath ? { helperPath: options.helperPath } : {}),
  });
  return async function resolveOpenClawBinding() {
    return store.resolveOpenClawNeutralBinding(options.bindingQuery || {});
  };
}

export async function probeOpenClawLegacyStoresReadOnly(paths = []) {
  try {
    const { probeLegacyStoresReadOnly } = await loadNeutralHostProcess();
    return await probeLegacyStoresReadOnly(paths);
  } catch (error) {
    throw codeError(error?.code || "neutral_host_legacy_probe_failed");
  }
}

export async function createOpenClawNeutralHostAdapter(options = {}) {
  if (options.bindingRef != null && options.bindingRef !== BINDING_REF) {
    throw codeError("neutral_openclaw_binding_ref_invalid");
  }
  if (typeof options.capabilityProvider !== "function") {
    throw codeError("neutral_capability_provider_required");
  }
  const hostRuntime = await loadNeutralHostProcess();
  const binding = validateOpenClawProtectedBinding(await options.capabilityProvider());
  const discover = options.discoverHost || hostRuntime.discoverHelloLynkNeutralHost;
  const request = options.requestHost || hostRuntime.requestHelloLynkNeutralHost;
  const requestHandover = options.requestHostHandover || hostRuntime.requestHelloLynkNeutralHostHandover;
  const readTimeoutMs = integer(options.readTimeoutMs, 8_000, 100, 15_000);
  const optionalReadTimeoutMs = integer(options.optionalReadTimeoutMs, 4_000, 100, 10_000);
  const cacheTtlMs = integer(options.cacheTtlMs, 10_000, 100, 60_000);
  const now = typeof options.clock === "function" ? options.clock : Date.now;
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
  assertDiscovery(
    discovery,
    binding,
    hostRuntime.HELLOLYNK_NEUTRAL_HOST_DISCOVERY_CONTRACT,
  );

  const adapterInstanceId = safeId(
    options.adapterInstanceId || `openclaw-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
    "neutral_host_adapter_instance_invalid",
  );
  const callRaw = async (method, pathname, body = null, requestOptions = {}) => captureHelloLynkModelNotices(await request({
    discovery,
    capability: binding.capability,
    method,
    pathname,
    body,
    timeoutMs: readTimeoutMs,
    ...requestOptions,
  }));
  const attached = requireOk(await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentAttach, { adapterInstanceId }));

  let closed = false;
  let deadCode = null;
  let leaseExpiresAt = Number(attached.leaseExpiresAt) || Date.now() + 30_000;
  let finish;
  const done = new Promise((resolve) => { finish = resolve; });
  let heartbeatBusy = false;
  const markDead = (error) => {
    deadCode ||= String(error?.code || error?.cause?.code || "host_attachment_expired");
    clearInterval(heartbeat);
    finish(deadCode);
  };
  function assertLive() {
    if (closed) throw codeError("neutral_host_adapter_closed");
    if (deadCode) throw codeError(deadCode);
  }
  // A Host without the native inbox routes is of an earlier release: ask it to make room, once; the error is unchanged.
  let handoverAsked = false;
  async function call(method, pathname, body = null, requestOptions = {}) {
    assertLive();
    try {
      const result = await callRaw(method, pathname, body, requestOptions);
      if (isOpenClawNeutralHostUnavailable({ code: result?.body?.error })) {
        throw codeError(result.body.error);
      }
      if (!handoverAsked && isMissingNativeInboxRoute(pathname, result)) {
        handoverAsked = true;
        try {
          await requestHandover({ runtimeRoot: binding.runtimeRoot, hostInstallationId: binding.hostInstallationId,
            publishedAt: new Date().toISOString(), waitMs: 0 });
        } catch {}
      }
      return result;
    } catch (error) {
      if (isOpenClawNeutralHostUnavailable(error)) markDead(error);
      throw error;
    }
  }
  const heartbeatMs = integer(options.heartbeatMs, 10_000, 100, 30_000);
  const heartbeat = setInterval(async () => {
    if (closed || deadCode || heartbeatBusy) return;
    heartbeatBusy = true;
    try {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.attachmentHeartbeat, { adapterInstanceId }));
      leaseExpiresAt = Number(result.leaseExpiresAt) || Date.now() + 30_000;
    } catch (error) {
      if (isOpenClawNeutralHostUnavailable(error)) markDead(error);
      else if (Date.now() >= leaseExpiresAt) markDead(codeError("host_attachment_expired"));
    } finally {
      heartbeatBusy = false;
    }
  }, heartbeatMs);
  heartbeat.unref?.();

  const resourceCache = new Map([
    ["inbox", { value: null, expiresAt: 0, flight: null, generation: 0 }],
    ["contacts", { value: null, expiresAt: 0, flight: null, generation: 0 }],
    ["contactRequests", { value: null, expiresAt: 0, flight: null, generation: 0 }],
    ["outbox", { value: null, expiresAt: 0, flight: null, generation: 0 }],
  ]);

  function invalidateResources(...names) {
    for (const name of names) {
      const entry = resourceCache.get(name);
      if (!entry) continue;
      entry.value = null;
      entry.expiresAt = 0;
      entry.flight = null;
      entry.generation += 1;
    }
  }

  function refreshResource(name, loader) {
    const entry = resourceCache.get(name);
    if (entry.flight) return entry.flight;
    const generation = entry.generation;
    const flight = Promise.resolve()
      .then(loader)
      .then((value) => {
        if (entry.generation === generation) {
          entry.value = value;
          entry.expiresAt = now() + cacheTtlMs;
        }
        return value;
      });
    entry.flight = flight;
    void flight.then(
      () => { if (entry.flight === flight) entry.flight = null; },
      () => { if (entry.flight === flight) entry.flight = null; },
    );
    return flight;
  }

  async function readResource(name, loader, forceRefresh) {
    const entry = resourceCache.get(name);
    const current = now();
    if (!forceRefresh && entry.value && entry.expiresAt > current) return entry.value;
    if (!forceRefresh && entry.value) {
      void refreshResource(name, loader).catch(() => {});
      return entry.value;
    }
    return refreshResource(name, loader);
  }

  async function readBundle(input = {}) {
    assertLive();
    const includeContacts = input.includeContacts === true;
    const includeContactRequests = input.includeContactRequests === true;
    const includeOutbox = input.includeOutbox === true;
    const forceRefresh = input.refresh === true;
    const [inbox, contacts, contactRequests, outbox] = await Promise.all([
      readResource("inbox", () => readRequired(HELLOLYNK_HOST_PATHS.appInboxMessages), forceRefresh),
      includeContacts
        ? readResource(
          "contacts",
          () => readOptional(HELLOLYNK_HOST_PATHS.appContacts, { contacts: [] }),
          forceRefresh,
        )
        : { available: false, contacts: [] },
      includeContactRequests
        ? readResource(
          "contactRequests",
          () => readOptional(HELLOLYNK_HOST_PATHS.appContactRequests, { requests: [] }),
          forceRefresh,
        )
        : { available: false, requests: [] },
      includeOutbox
        ? readResource(
          "outbox",
          () => readOptional(HELLOLYNK_HOST_PATHS.appOutboxMessages, { messages: [] }),
          forceRefresh,
        )
        : { available: false, messages: [] },
    ]);
    assertLive();
    const messages = Object.freeze([...(inbox.messages || [])]);
    return Object.freeze({
      source: "neutral_host",
      inbox: Object.freeze({
        messages,
        unreadCount: messages.filter((message) => message?.unread !== false).length,
      }),
      contacts: Object.freeze({
        available: contacts.available,
        contacts: Object.freeze((contacts.contacts || []).map(projectSecurityStateOnly)),
      }),
      contactRequests: Object.freeze({
        available: contactRequests.available,
        requests: Object.freeze([...(contactRequests.requests || [])]),
      }),
      outbox: Object.freeze({
        available: outbox.available,
        messages: Object.freeze([...(outbox.messages || [])]),
      }),
      changes: Object.freeze({ available: false, cursor: null, modelVisibility: "none" }),
    });
  }

  async function readRequired(pathname) {
    return withReadTimeout(
      call("GET", pathname, null, { timeoutMs: readTimeoutMs }),
      readTimeoutMs,
      "neutral_host_read_timeout",
    ).then(requireOk);
  }

  async function readOptional(pathname, fallback) {
    try {
      const value = requireOk(await withReadTimeout(
        call("GET", pathname, null, { timeoutMs: optionalReadTimeoutMs }),
        optionalReadTimeoutMs,
        "neutral_host_optional_read_timeout",
      ));
      return Object.freeze({ ...value, available: true });
    } catch {
      return Object.freeze({ ...fallback, available: false });
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    finish(null);
    try {
      if (!deadCode) await callRaw("POST", HELLOLYNK_HOST_PATHS.attachmentDetach, { adapterInstanceId }).catch(() => {});
    } finally {
      invalidateResources(...resourceCache.keys());
      binding.capability.secretBuffer.fill(0);
    }
  }

  return Object.freeze({
    contract: HELLOLYNK_OPENCLAW_NEUTRAL_ADAPTER_CONTRACT,
    mode: "neutral",
    get state() { return closed ? "closed" : deadCode ? "dead" : "attached"; },
    done,
    startedHost,
    binding: publicBinding(binding),
    discovery: publicDiscovery(discovery),
    adapterInstanceId,
    readBundle,
    async modelInbox(input) { return requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appModelInbox, input, { timeoutMs: 15_000 })); },
    async readWorkbenchChanges({ afterCursor = 0 } = {}) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appChangesSubscribe, { afterCursor }));
      return { ...result, hostGeneration: discovery.hostGeneration };
    },
    async readWorkbenchSnapshot(input = {}) {
      try {
        // Workbench reads can wait behind an earlier read for this delegate.
        // Keep the deadline below the page's 30 seconds; other calls stay unchanged.
        const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appWorkbenchSnapshot, input, { timeoutMs: 25_000 }));
        return result.snapshot;
      } catch (error) {
        if (error?.name === "TimeoutError") throw codeError("workbench_snapshot_timeout");
        throw error;
      }
    },
    async issueWorkbenchActionGrant(command) {
      const validated = validateWorkbenchCommand(command);
      return requireWorkbenchActionGrant(requireOk(await call(
        "POST",
        WORKBENCH_ACTION_GRANT_PATH,
        { adapterInstanceId, request: validated },
      )));
    },
    async executeWorkbenchCommand(command, context) {
      // The Host is the sole grant issuer and writer. OpenClaw forwards each
      // exact envelope once and never interprets, stores, retries, or changes it.
      const validated = validateWorkbenchCommand(command);
      const statusRead = validated.command === "message.send-status";
      const actionGrant = statusRead ? noActionGrantContext(context) : requireActionGrantContext(context);
      return requireWorkbenchCommandResult(await call(
        "POST",
        HELLOLYNK_HOST_PATHS.appWorkbenchCommand,
        { adapterInstanceId, request: validated, ...(statusRead ? {} : { actionGrant: actionGrant.actionGrant }) },
        {},
      ), validated.command);
    },
    async markRead(localMessageId) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appInboxMarkRead, {
        localMessageId: safeId(localMessageId, "host_app_local_message_id_invalid"),
      }));
      invalidateResources("inbox");
      return result;
    },
    async deleteRead(localMessageIds) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appInboxDeleteRead, {
        localMessageIds: localMessageIds.map((value) => safeId(value, "host_app_local_message_id_invalid")),
      }));
      invalidateResources("inbox");
      return result;
    },
    async saveContact(input) {
      const result = requireOk(await call(
        "POST",
        HELLOLYNK_HOST_PATHS.appContactsUpsert,
        exactLegacyContactWrite(input),
      ));
      invalidateResources("contacts");
      return projectSecurityStateOnly(result);
    },
    async deleteContact(contactId) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appContactsRemove, {
        contactId: safeId(contactId, "host_app_contact_id_invalid"),
      }));
      invalidateResources("contacts");
      return result;
    },
    async setAutonomousSendAuthorization(contactId, recipientDelegateId, enabled) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appContactAutonomousSendAuthorization, {
        contactId: safeId(contactId, "host_app_contact_id_invalid"),
        recipientDelegateId: safeId(recipientDelegateId, "recipient_delegate_id_invalid"),
        enabled: enabled === true,
      }));
      invalidateResources("contacts");
      return result;
    },
    async listAuthorizedContacts(input = {}) {
      const query = queryArgs(input);
      const result = await requireOk(await call(Object.keys(query).length ? "POST" : "GET", HELLOLYNK_HOST_PATHS.appAuthorizedContacts, Object.keys(query).length ? query : undefined, { timeoutMs: 25_000 }));
      return Object.freeze({
        ...(result.nativeConversations ? { nativeConversations: result.nativeConversations } : {}), contacts: Object.freeze((result.contacts || []).map(projectSecurityStateOnly)),
      });
    },
    async listAuthorizedInboxMessages({ before } = {}) {
      const result = await requireOk(await (before === undefined ? call("GET", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages)
        : call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxMessages, { before: safeId(before, "host_app_authorized_inbox_message_id_invalid") })));
      return Object.freeze({ messages: Object.freeze([...(result.messages || [])]) });
    },
    async listPendingMessages(query = null) {
      const result = await requireOk(await call(query == null ? "GET" : "POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxPending, query));
      return Object.freeze({ messages: Object.freeze([...(result.messages || [])]), ...(result.nextCursor == null ? {} : { nextCursor: result.nextCursor }) });
    },
    async claimMessage(localMessageId, conversationKey) {
      return requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim, {
        localMessageId: safeId(localMessageId, "host_app_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(conversationKey, "host_app_authorized_inbox_conversation_key_invalid"),
      }));
    },
    async claimBatch(batchId) {
      return requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim, { batchId }));
    },
    async inboxBatch(action, input = {}) {
      if (!["reserve", "open", "attempt", "confirm", "cancel", "expire", "closed"].includes(action)) throw codeError("native_batch_action_invalid");
      return requireOk(await call("POST", `/host/v1/app/authorized-inbox/batch/${action}`, input));
    },
    async activateAuthorizedInbox() {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxActivate));
      if (result.active !== true) throw codeError("neutral_authorized_inbox_activation_invalid");
      return Object.freeze({ ok: true, active: true });
    },
    async readAuthorizedInboxMessage(localMessageId, conversationKey) {
      const result = await requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedInboxRead, {
        localMessageId: safeId(localMessageId, "host_app_authorized_inbox_message_id_invalid"),
        conversationKey: safeId(conversationKey, "host_app_authorized_inbox_conversation_key_invalid"),
      }));
      return result.message;
    },
    async listAuthorizedContactRequests() {
      const result = await requireOk(await call("GET", "/host/v1/app/authorized-contact-requests"));
      return Object.freeze({ requests: Object.freeze([...(result.requests || [])]) });
    },
    async readAuthorizedContactRequest(localRecordId, conversationKey) {
      const result = await requireOk(await call("POST", "/host/v1/app/authorized-contact-requests/read", {
        localRecordId: safeId(localRecordId, "host_app_authorized_contact_request_id_invalid"),
        conversationKey: safeId(conversationKey, "host_app_authorized_contact_request_conversation_key_invalid"),
      }));
      return result.request;
    },
    async sendAuthorizedMessage(input) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedSend, authorizedSendInput(input),
        input.targetConversationTitle ? { timeoutMs: 55_000 } : input.targetConversationId ? { timeoutMs: 30_000 } : {}));
      invalidateResources("outbox");
      return result;
    },
    async replyAuthorizedMessage(input) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appAuthorizedReply, authorizedReplyInput(input)));
      invalidateResources("outbox");
      return Object.freeze({
        accepted: result.accepted,
        authorization: result.authorization,
        contactId: result.contactId,
        clientMessageId: result.clientMessageId,
        status: result.status,
      });
    },
    async issueRetryGrant(clientMessageId) {
      return requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetryGrant, {
        adapterInstanceId,
        clientMessageId: safeId(clientMessageId, "host_app_client_message_id_invalid"),
      }));
    },
    async retryOutgoing(clientMessageId, retryGrant) {
      const result = requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appOutboxRetry, {
        adapterInstanceId,
        clientMessageId: safeId(clientMessageId, "host_app_client_message_id_invalid"),
        retryGrant: String(retryGrant || ""),
      }));
      invalidateResources("outbox");
      return result;
    },
    async deleteOutgoing() {
      throw codeError("neutral_outbox_delete_route_unavailable");
    },
    async requestHumanSend(input) {
      const result = requireAccepted(await call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequests, {
        adapterInstanceId,
        request: input,
      }));
      invalidateResources("outbox");
      return result;
    },
    async getHumanSendStatus(actionId) {
      return requireOk(await call("POST", HELLOLYNK_HOST_PATHS.appHumanSendRequestStatus, {
        adapterInstanceId,
        request: { actionId: safeId(actionId, "host_app_action_id_invalid") },
      }));
    },
    close,
  });
}

export function validateOpenClawProtectedBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("neutral_capability_binding_invalid");
  }
  const capability = value.capability;
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw codeError("neutral_capability_invalid");
  }
  const binding = {
    region: safeId(value.region, "neutral_region_invalid"),
    principalId: safeId(value.principalId, "neutral_principal_invalid"),
    delegateId: safeId(value.delegateId, "neutral_delegate_invalid"),
    hostInstallationId: safeId(value.hostInstallationId, "neutral_host_installation_invalid"),
    profileId: safeId(value.profileId, "neutral_profile_invalid"),
    adapterId: safeId(value.adapterId, "neutral_adapter_invalid"),
    runtimeRoot: String(value.runtimeRoot || ""),
    releaseRoot: String(value.releaseRoot || ""),
    releaseManifestSha256: String(value.releaseManifestSha256 || ""),
    runnerRelativePath: String(value.runnerRelativePath || ""),
    profileManifestPath: String(value.profileManifestPath || ""),
  };
  if (binding.adapterId !== "openclaw") throw codeError("neutral_adapter_mismatch");
  if (!binding.runtimeRoot || !path.isAbsolute(binding.runtimeRoot)) throw codeError("neutral_runtime_root_invalid");
  if (!binding.releaseRoot || !path.isAbsolute(binding.releaseRoot)
    || !binding.profileManifestPath || !path.isAbsolute(binding.profileManifestPath)
    || !/^[a-f0-9]{64}$/.test(binding.releaseManifestSha256)
    || binding.runnerRelativePath !== "runtime/neutral-host-bootstrap.mjs") {
    throw codeError("neutral_openclaw_launch_configuration_invalid");
  }
  if (capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== binding.adapterId) {
    throw codeError("neutral_capability_owner_mismatch");
  }
  const scopes = [...new Set((capability.scopes || []).map(String))].sort();
  if (!sameStrings(scopes, OPENCLAW_NEUTRAL_EXACT_SCOPES)) {
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
  if (capability.contract !== HELLOLYNK_HOST_CAPABILITY_CONTRACT) throw codeError("neutral_capability_binding_invalid");
  const capabilityId = safeId(capability.capabilityId, "neutral_capability_id_invalid");
  const issuedAt = Number(capability.issuedAt);
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 1 || capability.revokedAt != null) {
    throw codeError("neutral_capability_binding_invalid");
  }
  return Object.freeze({
    ...binding,
    capability: Object.freeze({
      contract: HELLOLYNK_HOST_CAPABILITY_CONTRACT,
      capabilityId,
      region: binding.region,
      principalId: binding.principalId,
      delegateId: binding.delegateId,
      hostInstallationId: binding.hostInstallationId,
      adapterId: "openclaw",
      version: 2,
      state: "active",
      issuedAt,
      revokedAt: null,
      scopes: Object.freeze(scopes),
      secretBuffer,
    }),
  });
}

function assertDiscovery(discovery, binding, discoveryContract) {
  if (!discovery || discovery.contractId !== discoveryContract
    || discovery.region !== binding.region
    || discovery.principalId !== binding.principalId
    || discovery.hostInstallationId !== binding.hostInstallationId
    || discovery.host !== "127.0.0.1"
    || !Number.isSafeInteger(discovery.port) || discovery.port < 1 || discovery.port > 65_535
    || !/^[a-f0-9]{48}$/.test(String(discovery.hostGeneration || ""))) {
    throw codeError("neutral_host_discovery_owner_mismatch");
  }
}

function isMissingNativeInboxRoute(pathname, result) {
  return (pathname === HELLOLYNK_HOST_PATHS.appAuthorizedInboxPending || pathname === HELLOLYNK_HOST_PATHS.appAuthorizedInboxClaim
    || pathname.startsWith("/host/v1/app/authorized-inbox/batch/"))
    && (result?.body?.error === "host_route_not_found" || (result?.status === 404 && !result?.body?.error));
}

function requireOk(result) {
  if (!result || result.status !== 200 || result.body?.ok !== true) {
    throw codeError(String(result?.body?.error || `neutral_host_http_${result?.status || 0}`));
  }
  return result.body;
}

function requireAccepted(result) {
  if (!result || result.status !== 202 || result.body?.ok !== true) {
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

function requireWorkbenchActionGrant(value) {
  if (!isPlainRecord(value)
    || Object.keys(value).sort().join(",") !== "actionGrant,expiresAtMs,ok"
    || value.ok !== true
    || typeof value.actionGrant !== "string"
    || !ACTION_GRANT.test(value.actionGrant)
    || !Number.isSafeInteger(value.expiresAtMs)
    || value.expiresAtMs <= Date.now()) {
    throw codeError("neutral_host_workbench_action_grant_response_invalid");
  }
  return Object.freeze({ actionGrant: value.actionGrant });
}

function requireActionGrantContext(value) {
  if (!isPlainRecord(value)
    || Object.keys(value).length !== 1
    || !Object.hasOwn(value, "actionGrant")
    || typeof value.actionGrant !== "string"
    || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError("neutral_host_workbench_action_grant_required");
  }
  return Object.freeze({ actionGrant: value.actionGrant });
}

function noActionGrantContext(value) {
  if (value != null && (!isPlainRecord(value) || Object.keys(value).length !== 0)) {
    throw codeError("neutral_host_workbench_action_grant_forbidden");
  }
  return null;
}

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function projectSecurityStateOnly(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(projectSecurityStateOnly));
  if (!isPlainRecord(value)) return value;
  const projected = {};
  for (const key of Object.keys(value)) {
    const normalizedKey = key.replace(/[-_]/g, "").toLowerCase();
    if (normalizedKey === "safetycode" || normalizedKey === "localdevicesafetycode") {
      throw codeError("neutral_host_raw_safety_code_rejected");
    }
    projected[key] = projectSecurityStateOnly(value[key]);
  }
  return Object.freeze(projected);
}

function exactLegacyContactWrite(value) {
  if (!isPlainRecord(value)) throw codeError("neutral_host_contact_fields_invalid");
  const actual = Object.keys(value).sort().join(",");
  if (actual !== "displayName,hellolynkId" && actual !== "contactId,displayName,hellolynkId") {
    throw codeError("neutral_host_contact_fields_invalid");
  }
  return Object.freeze({
    ...(Object.hasOwn(value, "contactId") ? { contactId: value.contactId } : {}),
    displayName: value.displayName,
    hellolynkId: value.hellolynkId,
  });
}

function publicBinding(value) {
  return Object.freeze({
    region: value.region,
    principalId: value.principalId,
    delegateId: value.delegateId,
    hostInstallationId: value.hostInstallationId,
    profileId: value.profileId,
    adapterId: "openclaw",
    capabilityVersion: 2,
    scopes: Object.freeze([...value.capability.scopes]),
    runtimeRoot: value.runtimeRoot,
  });
}

function launchBinding(value) {
  return Object.freeze({
    ...publicBinding(value),
    delegateId: value.delegateId,
    profileId: value.profileId,
    adapterId: "openclaw",
    version: 2,
    scopes: Object.freeze([...value.capability.scopes]),
    releaseRoot: value.releaseRoot,
    releaseManifestSha256: value.releaseManifestSha256,
    runnerRelativePath: value.runnerRelativePath,
    profileManifestPath: value.profileManifestPath,
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

function publicDiscovery(value) {
  return Object.freeze({
    region: value.region,
    principalId: value.principalId,
    hostInstallationId: value.hostInstallationId,
    host: value.host,
    port: value.port,
    hostGeneration: value.hostGeneration,
    startedAt: value.startedAt || null,
  });
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
    clientMessageId: safeId(value.clientMessageId, "host_app_client_message_id_invalid"),
    contactId: safeId(value.contactId, "host_app_contact_id_invalid"),
    recipientDelegateId: safeId(value.recipientDelegateId, "recipient_delegate_id_invalid"),
    text,
  };
}

function authorizedReplyInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join("|") !== "clientMessageId|conversationKey|localMessageId|text") {
    throw codeError("authorized_reply_input_invalid");
  }
  if (typeof value.text !== "string" || !value.text || value.text.includes("\u0000")
    || Buffer.byteLength(value.text, "utf8") > 20 * 1024) {
    throw codeError("message_text_invalid");
  }
  return {
    localMessageId: safeId(value.localMessageId, "host_app_local_message_id_invalid"),
    conversationKey: safeId(value.conversationKey, "host_app_conversation_key_invalid"),
    clientMessageId: safeId(value.clientMessageId, "host_app_client_message_id_invalid"),
    text: value.text,
  };
}

function integer(value, fallback, minimum, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw codeError("neutral_limit_invalid");
  }
  return number;
}

function withReadTimeout(operation, timeoutMs, code) {
  let timeout;
  const expiry = new Promise((_, reject) => {
    timeout = setTimeout(() => reject(codeError(code)), timeoutMs);
    timeout.unref?.();
  });
  return Promise.race([operation, expiry]).finally(() => clearTimeout(timeout));
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function loadNeutralHostProcess() {
  // OpenClaw captures plugin dependencies before running channel callbacks.
  // Keep the lazy import literal so that capture can include the shared core.
  return import("../../../clients/core/hellolynk-neutral-host-process.mjs");
}
