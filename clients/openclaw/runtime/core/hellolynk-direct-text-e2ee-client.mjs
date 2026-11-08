import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { encodeNativeContent, decodeNativeContent } from "./hellolynk-native-conversations.mjs";
import { createHash } from "node:crypto";

import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";
import { createPlatformCredentialStore } from "./hellolynk-platform-credential-store.mjs";
import { sealContactRequestIntroEnvelope } from "./hellolynk-contact-request-e2ee.mjs";
import {
  DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE,
  DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES,
  DIRECT_TEXT_E2EE_MAX_TTL_MS,
  createDirectTextDeviceKeyBundle,
  createOneTimePreKey,
  digestDirectTextEnvelope,
  digestDirectTextEnvelopeV2,
  openDirectTextEnvelope,
  openDirectTextEnvelopeV2,
  publicDirectTextDeviceIdentity,
  publicOneTimePreKey,
  sealDirectTextEnvelope,
  sealDirectTextEnvelopeV2,
  verifyDeviceIdentityRegistration,
  verifyOneTimePreKeyRegistration,
} from "./hellolynk-direct-text-e2ee.mjs";

export const DIRECT_TEXT_E2EE_PRIVATE_STATE_SCHEMA_VERSION = 7;
const STATE_SCHEMA_VERSION = DIRECT_TEXT_E2EE_PRIVATE_STATE_SCHEMA_VERSION;
const DEFAULT_PREKEY_COUNT = 8;
const MAX_PREKEY_COUNT = 8;
const MAX_LOCAL_PREKEYS = 64;
const MAX_PEER_PINS = 128;
const MAX_PEER_AUTHORIZATIONS = 128;
const MAX_PENDING_PEER_CLAIMS = 32;
const MAX_CONSUMED_RECORDS = 512;
const MAX_PREPARED_OUTGOING = 64;
const MAX_JSON_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const SAFE_DIGEST = /^[a-f0-9]{64}$/;
const SAFETY_CODE = /^[A-F0-9]{4}(?:-[A-F0-9]{4}){11}$/;
const OUTER_PROTECTED_BINDINGS = Object.freeze([
  ["clientMessageId", "clientMessageId"],
  ["senderPrincipalId", "senderPrincipalId"],
  ["senderHelloLynkId", "senderHelloLynkId"],
  ["senderAgentId", "senderAgentId"],
  ["senderDelegateId", "senderDelegateId"],
  ["senderDeviceId", "senderDeviceId"],
  ["senderIdentityKeyId", "senderIdentityKeyId"],
  ["recipientPrincipalId", "recipientPrincipalId"],
  ["recipientHelloLynkId", "recipientHelloLynkId"],
  ["recipientDeviceId", "recipientDeviceId"],
  ["recipientIdentityKeyId", "recipientIdentityKeyId"],
  ["recipientPreKeyId", "recipientPreKeyId"],
  ["messageType", "messageType"],
]);
const OUTER_PROTECTED_BINDINGS_V2 = Object.freeze([
  ["clientMessageId", "clientMessageId"], ["routeKind", "routeKind"],
  ["senderPrincipalId", "senderPrincipalId"], ["senderHelloLynkId", "senderHelloLynkId"],
  ["senderAgentId", "senderAgentId"], ["senderDelegateId", "senderDelegateId"],
  ["senderDelegateAuthorizationVersion", "senderDelegateAuthorizationVersion"],
  ["senderHostId", "senderHostId"], ["senderDeviceId", "senderDeviceId"],
  ["senderIdentityKeyId", "senderIdentityKeyId"],
  ["recipientPrincipalId", "recipientPrincipalId"], ["recipientHelloLynkId", "recipientHelloLynkId"],
  ["recipientDelegateId", "recipientDelegateId"],
  ["recipientDelegateAuthorizationVersion", "recipientDelegateAuthorizationVersion"],
  ["recipientHostId", "recipientHostId"], ["recipientRouteVersion", "recipientRouteVersion"],
  ["recipientDeviceId", "recipientDeviceId"], ["recipientIdentityKeyId", "recipientIdentityKeyId"],
  ["recipientPreKeyId", "recipientPreKeyId"], ["messageType", "messageType"],
]);

export class HelloLynkDirectTextE2eeClientError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkDirectTextE2eeClientError";
    this.code = code;
    this.httpStatus = Number.isInteger(options.httpStatus) ? options.httpStatus : null;
    this.retryable = options.retryable === true;
    this.retryAt = options.retryAt || null;
    this.peerIdentityVerification = options.peerIdentityVerification
      ? Object.freeze({ ...options.peerIdentityVerification })
      : null;
  }
}

export function normalizeDirectTextSafetyCode(value) {
  const normalized = String(value || "").trim().toUpperCase().replace(/[\s:]+/gu, "-");
  if (!SAFETY_CODE.test(normalized)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_safety_code_invalid");
  }
  return normalized;
}

export function directTextDeviceSafetyCode(input) {
  assertPlainObject(input, "e2ee_peer_identity_invalid");
  const canonical = JSON.stringify({
    domain: "hellolynk/direct-text/device-safety-code/v1",
    hellolynkId: safeId(input.hellolynkId, "e2ee_peer_hellolynk_id_invalid"),
    deviceId: safeId(input.deviceId, "e2ee_peer_device_id_invalid"),
    identityKeyId: safeId(input.identityKeyId, "e2ee_peer_identity_key_id_invalid"),
    publicKey: String(input.publicKey || ""),
  });
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, 48).toUpperCase();
  return digest.match(/.{4}/g).join("-");
}

export async function createDirectTextE2eeClientContext(options = {}) {
  assertPlainObject(options, "e2ee_client_options_invalid");
  const profileId = safeProfileId(options.profileId);
  const e2eeVersion = options.e2eeVersion == null ? 1 : Number(options.e2eeVersion);
  if (![1, 2].includes(e2eeVersion)) throw new HelloLynkDirectTextE2eeClientError("e2ee_version_unsupported");
  const owner = Object.freeze({
    principalId: safeId(options.principalId, "e2ee_owner_principal_invalid"),
    hellolynkId: safeId(options.hellolynkId, "e2ee_owner_hellolynk_id_invalid"),
    agentId: safeId(options.agentId, "e2ee_owner_agent_invalid"),
    delegateId: safeId(options.delegateId, "e2ee_owner_delegate_invalid"),
    deviceId: safeId(options.deviceId, "e2ee_owner_device_invalid"),
    ...(e2eeVersion === 2 ? {
      hostId: safeId(options.hostId, "e2ee_owner_host_invalid"),
      authorizationVersion: Number(options.authorizationVersion),
    } : {}),
  });
  if (owner.principalId === owner.agentId || owner.principalId === owner.delegateId) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_owner_identity_collapsed");
  }
  if (e2eeVersion === 2 && (
    !Number.isSafeInteger(owner.authorizationVersion) || owner.authorizationVersion < 1
  )) throw new HelloLynkDirectTextE2eeClientError("e2ee_owner_route_context_required");
  if (e2eeVersion === 1 && (options.hostId != null || options.authorizationVersion != null)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_owner_route_context_unexpected");
  }
  const baseUrl = normalizeHelloLynkBaseUrl(options.baseUrl, {
    allowLoopbackHttp: options.allowLoopbackHttp === true,
  }).replace(/\/api\/v1$/, "");
  const fetchImpl = options.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  const sessionProvider = options.sessionProvider;
  const credentialStore = options.credentialStore || createPlatformCredentialStore(options.credentialStoreOptions);
  const privateKeys = credentialStore?.directTextPrivateKeys;
  const stateLock = credentialStore?.runtimeSessions;
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const sameHostClaimProvider = options.sameHostClaimProvider;
  const preKeyCount = options.preKeyCount == null ? DEFAULT_PREKEY_COUNT : Number(options.preKeyCount);
  const requestTimeoutMs = options.requestTimeoutMs == null ? DEFAULT_REQUEST_TIMEOUT_MS : Number(options.requestTimeoutMs);
  const localClaimTimeoutMs = options.localClaimTimeoutMs ?? requestTimeoutMs;
  if (!Number.isSafeInteger(localClaimTimeoutMs) || localClaimTimeoutMs < 1 || localClaimTimeoutMs > 30_000) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_local_claim_timeout_invalid");
  }
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 10_000) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_request_timeout_invalid");
  }
  if (typeof fetchImpl !== "function") throw new HelloLynkDirectTextE2eeClientError("e2ee_fetch_unavailable");
  if (!sessionProvider || typeof sessionProvider.get !== "function") {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_runtime_session_provider_required");
  }
  if (!privateKeys || typeof privateKeys.load !== "function" || typeof privateKeys.save !== "function") {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_key_store_unavailable");
  }
  if (!stateLock || typeof stateLock.withLock !== "function") {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_cross_process_lock_unavailable");
  }

  if (sameHostClaimProvider != null && typeof sameHostClaimProvider !== "function") {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_same_host_claim_provider_invalid");
  }
  if (!Number.isSafeInteger(preKeyCount) || preKeyCount < 1 || preKeyCount > MAX_PREKEY_COUNT) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_count_invalid");
  }

  const withState = (operation, signal) => withRequestSignal(() => stateLock.withLock(profileId, async () => {
    assertRequestActive(signal);
    let state;
    try {
      state = await privateKeys.load(profileId);
    } catch (error) {
      throw clientFailure(error, "e2ee_private_key_load_failed");
    }
    assertRequestActive(signal);
    const save = async () => {
      assertRequestActive(signal);
      // An atomic save already in progress keeps the physical profile lock
      // until it settles, even if the caller has stopped waiting after abort.
      await saveState(privateKeys, profileId, state);
      assertRequestActive(signal);
    };
    if (state == null) {
      state = createInitialState(profileId, owner, preKeyCount, now());
      await save();
    } else {
      const normalized = normalizeState(state, profileId, owner);
      state = normalized.state;
      if (normalized.migrated) await save();
    }
    const result = await operation(state, save);
    assertRequestActive(signal);
    return result;
  }), signal);

  function assertRequestActive(signal) {
    if (signal?.aborted) throw new HelloLynkDirectTextE2eeClientError(
      signal.reason?.name === "TimeoutError" || signal.reason?.code === "e2ee_request_timeout"
        ? "e2ee_request_timeout" : "e2ee_request_cancelled",
      { retryable: true },
    );
  }

  async function withRequestSignal(operation, signal) {
    assertRequestActive(signal);
    if (!signal) return operation();
    let onAbort;
    const interrupted = new Promise((_, reject) => {
      onAbort = () => { try { assertRequestActive(signal); } catch (error) { reject(error); } };
      signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      return await Promise.race([Promise.resolve().then(() => {
        assertRequestActive(signal);
        return operation();
      }), interrupted]);
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  }

  async function runtimeHeaders() {
    let session;
    try {
      session = await sessionProvider.get({
        expectedPrincipalId: owner.principalId,
        expectedAgentId: owner.agentId,
      });
    } catch (error) {
      throw clientFailure(error, "e2ee_runtime_session_unavailable");
    }
    if (
      safeId(session?.principalId, "e2ee_runtime_session_identity_invalid") !== owner.principalId
      || safeId(session?.agentId, "e2ee_runtime_session_identity_invalid") !== owner.agentId
      || safeId(session?.deviceId, "e2ee_runtime_session_identity_invalid") !== owner.deviceId
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_runtime_session_identity_mismatch");
    if (e2eeVersion === 2 && (
      safeId(session?.delegateId, "e2ee_runtime_session_identity_invalid") !== owner.delegateId
      || safeId(session?.hostId, "e2ee_runtime_session_identity_invalid") !== owner.hostId
      || Number(session?.authorizationVersion) !== owner.authorizationVersion
    )) throw new HelloLynkDirectTextE2eeClientError("e2ee_runtime_session_route_mismatch");
    const sessionId = safeId(session?.sessionId || session?.id, "e2ee_runtime_session_invalid");
    const secret = String(session?.sessionSecret || session?.secret || "");
    if (!/^runtime_[a-f0-9]{48}$/.test(secret)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_runtime_session_invalid");
    }
    return {
      "x-hellolynk-runtime-session-id": sessionId,
      "x-hellolynk-runtime-session-secret": secret,
      ...(e2eeVersion === 2 ? { "x-hellolynk-e2ee-version": "2" } : {}),
    };
  }

  async function requestJson(path, method, body, acceptedStatuses, authorizedHeaders = null, signal) {
    let response;
    const controller = new AbortController();
    const abort = () => controller.abort(new HelloLynkDirectTextE2eeClientError(
      signal?.reason?.name === "TimeoutError" ? "e2ee_request_timeout" : "e2ee_request_cancelled",
      { retryable: true },
    ));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const timer = setTimeout(() => controller.abort(new HelloLynkDirectTextE2eeClientError("e2ee_request_timeout", { retryable: true })), requestTimeoutMs);
    let onAbort;
    const interrupted = new Promise((_, reject) => {
      onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", onAbort, { once: true });
      if (controller.signal.aborted) onAbort();
    });
    void interrupted.catch(() => {});
    try {
      if (controller.signal.aborted) throw controller.signal.reason;
      response = await Promise.race([fetchImpl(`${baseUrl}${path}`, {
        method,
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          ...(authorizedHeaders || await runtimeHeaders()),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: "error",
        signal: controller.signal,
      }), interrupted]);
      const data = await Promise.race([readBoundedJson(response), interrupted]);
      if (!acceptedStatuses.has(response.status)) {
        const code = /^[a-z][a-z0-9_]{0,63}$/.test(String(data?.error || ""))
          ? data.error : `e2ee_http_${response.status}`;
        throw new HelloLynkDirectTextE2eeClientError(code, {
          httpStatus: response.status,
          retryable: response.status >= 500 || [408, 425, 429].includes(response.status),
        });
      }
      return data;
    } catch (error) {
      if (error instanceof HelloLynkDirectTextE2eeClientError) throw error;
      throw new HelloLynkDirectTextE2eeClientError("e2ee_transport_error", { cause: error, retryable: true });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      controller.signal.removeEventListener("abort", onAbort);
      if (controller.signal.aborted) {
        try { void response?.body?.cancel?.().catch(() => {}); } catch {}
      }
    }
  }

  async function registerState(state, save, authorizedHeaders, signal) {
    const identity = publicDirectTextDeviceIdentity(state.deviceKeyBundle);
    const identityResult = await requestJson(
      "/api/v1/e2ee/device-identity",
      "PUT",
      { identity },
      new Set([200, 201]),
      authorizedHeaders,
      signal,
    );
    requireExactFields(identityResult, ["ok", "identity", "deviceId", "state", "idempotent"], "e2ee_identity_response_invalid");
    if (
      identityResult.ok !== true || identityResult.state !== "active"
      || identityResult.deviceId !== owner.deviceId
      || JSON.stringify(identityResult.identity) !== JSON.stringify(identity)
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_identity_response_mismatch");

    const pending = state.preKeys.filter((item) => item.state === "pending_registration");
    if (pending.length > 0) {
      const oneTimePreKeys = pending.map((item) => publicOneTimePreKey(item.privateKeyBundle, state.deviceKeyBundle));
      const result = await requestJson(
        "/api/v1/e2ee/one-time-prekeys",
        "POST",
        { identityKeyId: state.deviceKeyBundle.keyId, oneTimePreKeys },
        new Set([200]),
        authorizedHeaders,
        signal,
      );
      requireExactFields(result, ["ok", "identityKeyId", "inserted", "idempotent", "available"], "e2ee_prekey_response_invalid");
      if (
        result.ok !== true || result.identityKeyId !== state.deviceKeyBundle.keyId
        || !Number.isSafeInteger(result.inserted) || !Number.isSafeInteger(result.idempotent)
        || result.inserted + result.idempotent !== pending.length || !Number.isSafeInteger(result.available)
      ) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_response_mismatch");
      const registeredAt = new Date(now()).toISOString();
      for (const item of pending) {
        item.state = "registered";
        item.registeredAt = registeredAt;
      }
      await save();
    }
  }

  async function ensurePreKeyInventoryWithHeaders(authorizedHeaders, signal) {
    return withState(async (state, save) => {
      // Bound the whole network sequence as well as each request: several slow
      // successful stages must not keep this profile locked past the lock wait.
      const inventorySignal = AbortSignal.any([
        AbortSignal.timeout(Math.min(requestTimeoutMs * 2, 10_000)),
        ...(signal ? [signal] : []),
      ]);
      await registerState(state, save, authorizedHeaders, inventorySignal);
      const inventory = validateInventoryResponse(await requestJson(
        "/api/v1/e2ee/one-time-prekeys",
        "GET",
        undefined,
        new Set([200]),
        authorizedHeaders,
        inventorySignal,
      ), now());
      const result = reconcilePreKeyInventory(state, inventory, preKeyCount, now());
      if (result.changed) await save();
      if (result.generated > 0) await registerState(state, save, authorizedHeaders, inventorySignal);
      return Object.freeze({
        available: result.available + result.generated,
        generated: result.generated,
        retainedUsed: result.retainedUsed,
      });
    });
  }

  async function ensurePreKeyInventory({ signal } = {}) {
    return ensurePreKeyInventoryWithHeaders(await runtimeHeaders(), signal);
  }

  // The neutral Host can initialize its protected local identity while offline.
  // It provisions relay keys before registering its cloud receive endpoint.
  let preKeyInventoryStatus = Object.freeze({ status: "deferred" });
  if (options.deferCloudRegistration !== true) {
    preKeyInventoryStatus = Object.freeze({ status: "ready" });
    try {
      await ensurePreKeyInventory({ signal: options.signal });
    } catch (error) {
      // Retained used keys can temporarily fill the pool. Keep the receiver
      // available for maintenance after expiry.
      if (error?.code !== "e2ee_local_prekey_capacity_exceeded") throw error;
      preKeyInventoryStatus = Object.freeze({ status: "retrying", errorCode: error.code, retryAt: error.retryAt });
    }
  }
  const { identityKeyId, localDeviceSafetyCode } = await withState(async (state) => ({
    identityKeyId: state.deviceKeyBundle.keyId,
    localDeviceSafetyCode: directTextDeviceSafetyCode({
      hellolynkId: owner.hellolynkId,
      deviceId: owner.deviceId,
      identityKeyId: state.deviceKeyBundle.keyId,
      publicKey: state.deviceKeyBundle.publicKey,
    }),
  }));


  async function prepareOutgoing(input, { signal, persistPrepared = true } = {}) {
    if (e2eeVersion === 2) return prepareOutgoingV2(input, { signal, persistPrepared });
    requireExactFields(input, [
      "recipientHelloLynkId", "text", "clientMessageId", "senderPrincipalId", "senderDelegateId", "intentSource",
    ], "e2ee_prepare_input_invalid");
    const recipientHelloLynkId = safeId(input.recipientHelloLynkId, "e2ee_recipient_hellolynk_id_invalid");
    const clientMessageId = safeId(input.clientMessageId, "e2ee_client_message_id_invalid");
    if (
      input.senderPrincipalId !== owner.principalId || input.senderDelegateId !== owner.delegateId
      || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(input.intentSource)
      || typeof input.text !== "string"
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_prepare_identity_mismatch");
    const requestDigest = digestRequest({ ...input, recipientHelloLynkId, clientMessageId });
    const authorizedHeaders = await runtimeHeaders();
    return withState(async (state, save) => {
      const prunedPendingClaims = pruneExpiredPendingPeerClaims(state, now());
      const existing = state.preparedOutgoing.find((item) => (
        item.clientMessageId === clientMessageId && item.recipientHelloLynkId === recipientHelloLynkId
      ));
      if (existing) {
        if (existing.requestDigest !== requestDigest) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
        }
        requirePreparedPeerTrust(state, existing);
        if (prunedPendingClaims) await save();
        return publicPrepared(existing);
      }
      if (state.preparedOutgoing.some((item) => item.clientMessageId === clientMessageId)) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
      }
      if (state.preparedOutgoing.length >= MAX_PREPARED_OUTGOING) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_capacity_exceeded");
      }
      if (state.pendingPeerClaims.some((item) => (
        item.clientMessageId === clientMessageId && item.recipientHelloLynkId !== recipientHelloLynkId
      ))) throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
      const pendingClaim = state.pendingPeerClaims.find((item) => (
        item.recipientHelloLynkId === recipientHelloLynkId && item.clientMessageId === clientMessageId
      ));
      const claim = pendingClaim?.claim || validateClaimResponse(await requestJson(
          "/api/v1/e2ee/one-time-prekeys/claim",
          "POST",
          { recipientHelloLynkId, clientMessageId },
          new Set([200]),
          authorizedHeaders,
          signal,
        ), recipientHelloLynkId, now());
      observePeerIdentity(state, {
        peerHelloLynkId: claim.recipientHelloLynkId,
        peerPrincipalId: claim.recipientPrincipalId,
        peerDeviceId: claim.recipientDeviceId,
        identity: claim.identity,
        observedAt: claim.claimedAt,
      }, now());
      if (pendingClaim) {
        state.pendingPeerClaims.splice(state.pendingPeerClaims.indexOf(pendingClaim), 1);
      }
      const createdAtMs = now();
      const expiresAtMs = Math.min(createdAtMs + DIRECT_TEXT_E2EE_MAX_TTL_MS, Date.parse(claim.expiresAt));
      if (expiresAtMs <= createdAtMs) throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_expired");
      const envelope = sealDirectTextEnvelope({
        protectedMetadata: {
          clientMessageId,
          senderPrincipalId: owner.principalId,
          senderHelloLynkId: owner.hellolynkId,
          senderAgentId: owner.agentId,
          senderDelegateId: owner.delegateId,
          senderDeviceId: owner.deviceId,
          senderIdentityKeyId: state.deviceKeyBundle.keyId,
          recipientPrincipalId: claim.recipientPrincipalId,
          recipientHelloLynkId: recipientHelloLynkId,
          recipientDeviceId: claim.recipientDeviceId,
          recipientIdentityKeyId: claim.identity.keyId,
          recipientPreKeyId: claim.oneTimePreKey.preKeyId,
          authorizationScope: DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE,
          intentSource: input.intentSource,
          messageType: "text",
          createdAt: new Date(createdAtMs).toISOString(),
          expiresAt: new Date(expiresAtMs).toISOString(),
        },
        recipientDeviceIdentity: claim.identity,
        recipientOneTimePreKey: claim.oneTimePreKey,
        senderDeviceKeyBundle: state.deviceKeyBundle,
        text: input.text,
      }, { nowMs: createdAtMs });
      const record = {
        e2eeVersion: 1,
        clientMessageId,
        recipientHelloLynkId,
        requestDigest,
        claimId: claim.claimId,
        envelope,
        envelopeDigest: digestDirectTextEnvelope(envelope),
      };
      state.preparedOutgoing.push(record);
      await save();
      return publicPrepared(record);
    });
  }

  async function prepareOutgoingV2(input, { signal, persistPrepared = true } = {}) {
    assertPlainObject(input, "e2ee_prepare_input_invalid");
    const routeKind = input.routeKind == null ? "principal_inbox" : String(input.routeKind);
    const baseFields = [
      "recipientHelloLynkId", "text", "clientMessageId", "senderPrincipalId", "senderDelegateId", "intentSource",
      ...(Object.hasOwn(input, "replyToClientMessageId") ? ["replyToClientMessageId"] : []),
      ...["targetConversationId", "nativeDirectory"].filter(key => Object.hasOwn(input, key)),
    ];
    if (routeKind === "principal_inbox") {
      requireExactFields(input, input.routeKind == null ? baseFields : [...baseFields, "routeKind"], "e2ee_prepare_input_invalid");
    } else if (routeKind === "owned_delegate") {
      const fields = [...baseFields, "routeKind", "recipientDelegateId", "recipientHostId"];
      if (input.recipientDeviceId != null) fields.push("recipientDeviceId");
      requireExactFields(input, fields, "e2ee_prepare_input_invalid");
    } else if (routeKind === "instance_direct") {
      requireExactFields(input, [...baseFields, "routeKind", "recipientDelegateId"], "e2ee_prepare_input_invalid");
    } else throw new HelloLynkDirectTextE2eeClientError("e2ee_route_kind_invalid");
    const recipientHelloLynkId = safeId(input.recipientHelloLynkId, "e2ee_recipient_hellolynk_id_invalid");
    const clientMessageId = safeId(input.clientMessageId, "e2ee_client_message_id_invalid");
    const replyToClientMessageId = Object.hasOwn(input, "replyToClientMessageId")
      ? safeId(input.replyToClientMessageId, "e2ee_reply_target_invalid") : null;
    if (replyToClientMessageId && (routeKind === "principal_inbox" || input.intentSource !== "human_preauthorized_contact"
      || replyToClientMessageId === clientMessageId)) throw new HelloLynkDirectTextE2eeClientError("e2ee_reply_target_invalid");
    if (
      input.senderPrincipalId !== owner.principalId || input.senderDelegateId !== owner.delegateId
      || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(input.intentSource)
      || typeof input.text !== "string"
      || (routeKind === "owned_delegate" && recipientHelloLynkId !== owner.hellolynkId)
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_prepare_identity_mismatch");
    const sealedContent = encodeNativeContent(input);
    const nativeContentVersion = sealedContent !== input.text ? 1 : null;
    const routeTarget = routeKind === "owned_delegate" ? {
      recipientDelegateId: safeId(input.recipientDelegateId, "e2ee_recipient_delegate_invalid"),
      recipientHostId: safeId(input.recipientHostId, "e2ee_recipient_host_invalid"),
      recipientDeviceId: input.recipientDeviceId == null
        ? null : safeId(input.recipientDeviceId, "e2ee_recipient_device_invalid"),
    } : {
      recipientDelegateId: routeKind === "instance_direct"
        ? safeId(input.recipientDelegateId, "e2ee_recipient_delegate_invalid") : null,
      recipientHostId: null,
      recipientDeviceId: null,
    };
    if (["owned_delegate", "instance_direct"].includes(routeKind)
      && routeTarget.recipientDelegateId === owner.delegateId) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_route_semantics_invalid");
    }
    const requestDigest = digestRequestV2({
      ...input, routeKind, recipientHelloLynkId, clientMessageId, ...routeTarget,
    });
    const directoryOnly = persistPrepared === false && input.nativeDirectory != null
      && recipientHelloLynkId === owner.hellolynkId && ["owned_delegate", "instance_direct"].includes(routeKind);
    // Directory preparations never hold a user message. Their digest identifies
    // an unused directory claim, rather than a transient query/requestId. Keep
    // the existing pending-record shape readable by the installed prior release.
    const directoryClaimDigest = item => createHash("sha256").update(JSON.stringify([
      "hellolynk/native-directory/pending-claim/v1", owner.delegateId, item.clientMessageId,
      item.recipientHelloLynkId, item.routeKind, item.recipientDelegateId, item.recipientHostId, item.recipientDeviceId,
    ])).digest("hex");
    const reusableDirectoryClaim = item => directoryOnly && item.e2eeVersion === 2
      && item.requestDigest === directoryClaimDigest(item) && item.recipientHelloLynkId === recipientHelloLynkId
      && item.routeKind === routeKind && item.recipientDelegateId === routeTarget.recipientDelegateId
      && (routeKind !== "owned_delegate" || (item.recipientHostId === routeTarget.recipientHostId
        && (!routeTarget.recipientDeviceId || item.recipientDeviceId === routeTarget.recipientDeviceId)));
    const usesSameHostProvider = ["owned_delegate", "instance_direct"].includes(routeKind)
      && recipientHelloLynkId === owner.hellolynkId && sameHostClaimProvider;
    const claimBody = routeKind === "principal_inbox"
      ? { routeKind, recipientHelloLynkId, clientMessageId }
      : routeKind === "instance_direct"
        ? { routeKind, recipientHelloLynkId, recipientDelegateId: routeTarget.recipientDelegateId, clientMessageId }
        : {
          routeKind,
          recipientDelegateId: routeTarget.recipientDelegateId,
          recipientHostId: routeTarget.recipientHostId,
          ...(routeTarget.recipientDeviceId ? { recipientDeviceId: routeTarget.recipientDeviceId } : {}),
          clientMessageId,
        };
    const inspectOutgoing = async (state, save) => {
      const prunedPendingClaims = pruneExpiredPendingPeerClaims(state, now());
      const existing = state.preparedOutgoing.find((item) => (
        item.clientMessageId === clientMessageId && item.recipientHelloLynkId === recipientHelloLynkId
      ));
      if (existing) {
        if (existing.e2eeVersion !== 2 || existing.requestDigest !== requestDigest) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
        }
        requirePreparedPeerTrust(state, existing);
        if (prunedPendingClaims) await save();
        return { prepared: publicPrepared(existing), pendingClaim: null };
      }
      if (state.preparedOutgoing.some((item) => item.clientMessageId === clientMessageId)) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
      }
      if (state.preparedOutgoing.length >= MAX_PREPARED_OUTGOING) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_capacity_exceeded");
      }
      const pendingClaim = state.pendingPeerClaims.find((item) => (
        item.e2eeVersion === 2 && item.recipientHelloLynkId === recipientHelloLynkId
        && item.clientMessageId === clientMessageId
      )) || state.pendingPeerClaims.find(reusableDirectoryClaim);
      if (pendingClaim && !reusableDirectoryClaim(pendingClaim) && pendingClaim.requestDigest !== requestDigest) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_message_conflict");
      }
      return { prepared: null, pendingClaim, prunedPendingClaims };
    };
    let sameHostClaim = null;
    if (usesSameHostProvider) {
      const inspected = await withState(inspectOutgoing, signal);
      if (inspected.prepared) return inspected.prepared;
      if (!inspected.pendingClaim) {
        // The receiver takes its own profile lock. Never call it while holding
        // this sender's lock: simultaneous A->B and B->A must not lock each other.
        // Bound the claim request, not the sender's surrounding private-state
        // I/O as well. Windows credential helpers make those separate stages
        // expensive; caller cancellation still applies to the entire prepare.
        const claimSignal = AbortSignal.any([
          AbortSignal.timeout(localClaimTimeoutMs), ...(signal ? [signal] : []),
        ]);
        sameHostClaim = await withRequestSignal(() => sameHostClaimProvider(Object.freeze({
          ...claimBody,
          // Old local peers reject this field before claiming or receiving a
          // message. Never probe protocol support with a chat control frame.
          ...(nativeContentVersion ? { nativeContentVersion } : {}),
          senderPrincipalId: owner.principalId,
          senderDelegateId: owner.delegateId,
          senderDelegateAuthorizationVersion: owner.authorizationVersion,
        }), { signal: claimSignal }), claimSignal);
      }
    }
    return withState(async (state, save) => {
      // Another caller can commit while the sender lock is released. Recheck
      // the exact request and retain any already persisted claim before writing.
      const { prepared, pendingClaim, prunedPendingClaims } = await inspectOutgoing(state, save);
      if (prepared) return prepared;
      // A directory query has no durable outgoing message and may be retried
      // with a new requestId after identity verification. Reuse only its still
      // unused claim, under this lock, with the claim's original wire ID.
      const wireClientMessageId = reusableDirectoryClaim(pendingClaim || {}) ? pendingClaim.clientMessageId : clientMessageId;
      let rawClaim = pendingClaim?.claim || sameHostClaim;
      if (!rawClaim) {
        try {
          // Old relays reject this optional field before claiming a prekey;
          // no chat probe or plaintext fallback is used to discover support.
          rawClaim = await requestJson("/api/v2/e2ee/one-time-prekeys/claim", "POST",
            { ...claimBody, ...(nativeContentVersion ? { nativeContentVersion } : {}) }, new Set([200]), undefined, signal);
          if (nativeContentVersion && rawClaim?.nativeContentVersion !== nativeContentVersion)
            throw new HelloLynkDirectTextE2eeClientError("native_directory_unavailable");
        } catch (error) {
          if (!nativeContentVersion || !["request_fields_forbidden", "unexpected_fields", "e2ee_route_v2_disabled"].includes(error?.code)) throw error;
          throw new HelloLynkDirectTextE2eeClientError("native_directory_unavailable", { cause: error });
        }
      }
      const claim = validateClaimResponseV2(rawClaim, {
        recipientHelloLynkId, routeKind, ...routeTarget,
        senderDelegateAuthorizationVersion: owner.authorizationVersion,
      }, now());
      const trust = observePeerIdentity(state, {
        peerHelloLynkId: claim.recipientHelloLynkId,
        peerPrincipalId: claim.recipientPrincipalId,
        peerDeviceId: claim.recipientDeviceId,
        identity: claim.identity,
        observedAt: claim.claimedAt,
      }, now());
      if (pendingClaim) state.pendingPeerClaims.splice(state.pendingPeerClaims.indexOf(pendingClaim), 1);
      const createdAtMs = now();
      const expiresAtMs = Math.min(createdAtMs + DIRECT_TEXT_E2EE_MAX_TTL_MS, Date.parse(claim.expiresAt));
      if (expiresAtMs <= createdAtMs) throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_expired");
      const envelope = sealDirectTextEnvelopeV2({
        protectedMetadata: {
          clientMessageId: wireClientMessageId, routeKind,
          senderPrincipalId: owner.principalId, senderHelloLynkId: owner.hellolynkId,
          senderAgentId: owner.agentId, senderDelegateId: owner.delegateId,
          senderDelegateAuthorizationVersion: owner.authorizationVersion,
          senderHostId: owner.hostId, senderDeviceId: owner.deviceId,
          senderIdentityKeyId: state.deviceKeyBundle.keyId,
          recipientPrincipalId: claim.recipientPrincipalId,
          recipientHelloLynkId: claim.recipientHelloLynkId,
          recipientDelegateId: claim.recipientDelegateId,
          recipientDelegateAuthorizationVersion: claim.recipientDelegateAuthorizationVersion,
          recipientHostId: claim.recipientHostId,
          recipientRouteVersion: claim.recipientRouteVersion,
          recipientDeviceId: claim.recipientDeviceId,
          recipientIdentityKeyId: claim.identity.keyId,
          recipientPreKeyId: claim.oneTimePreKey.preKeyId,
          authorizationScope: DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE,
          intentSource: input.intentSource,
          messageType: "text",
          createdAt: new Date(createdAtMs).toISOString(),
          expiresAt: new Date(expiresAtMs).toISOString(),
          ...(replyToClientMessageId ? { replyToClientMessageId } : {}),
        },
        recipientDeviceIdentity: claim.identity,
        recipientOneTimePreKey: claim.oneTimePreKey,
        senderDeviceKeyBundle: state.deviceKeyBundle,
        text: sealedContent,
      }, { nowMs: createdAtMs });
      const record = {
        e2eeVersion: 2, clientMessageId: wireClientMessageId, recipientHelloLynkId,
        requestDigest: wireClientMessageId === clientMessageId ? requestDigest : digestRequestV2({
          ...input, routeKind, recipientHelloLynkId, clientMessageId: wireClientMessageId, ...routeTarget,
        }),
        ...(nativeContentVersion ? { nativeContentVersion } : {}),
        routeKind, recipientDelegateId: claim.recipientDelegateId,
        recipientHostId: claim.recipientHostId, recipientDeviceId: claim.recipientDeviceId,
        claimId: claim.claimId, envelope, envelopeDigest: digestDirectTextEnvelopeV2(envelope),
      };
      if (persistPrepared !== false) state.preparedOutgoing.push(record);
      // The durable outbox owns preparation/recovery when its plaintext row
      // already exists. It attaches this exact envelope before any dispatch,
      // so a second encrypted crash-window copy adds two private-key writes.
      // Identity/claim changes still need their own durable checkpoint.
      if (persistPrepared !== false || trust.changed || pendingClaim || prunedPendingClaims) await save();
      return publicPrepared(record);
    }, signal);
  }

  async function openIncoming(input) {
    if (e2eeVersion === 2) return openIncomingV2(input);
    requireExactFields(input, ["event", "recipientPrincipalId", "recipientDelegateId"], "e2ee_open_client_input_invalid");
    if (input.recipientPrincipalId !== owner.principalId || input.recipientDelegateId !== owner.delegateId) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_context_mismatch");
    }
    const event = validateIncomingEvent(input.event, owner);
    return withState(async (state, save) => {
      if (event.recipientIdentityKeyId !== state.deviceKeyBundle.keyId) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_identity_mismatch");
      }
      const preKey = state.preKeys.find((item) => (
        ["registered", "used"].includes(item.state)
        && item.privateKeyBundle.preKeyId === event.recipientPreKeyId
      ));
      if (!preKey) throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_prekey_unavailable");
      if (preKey.state === "used" && (
        (preKey.usedClientMessageId != null && preKey.usedClientMessageId !== event.clientMessageId)
        || (preKey.usedEnvelopeDigest != null && preKey.usedEnvelopeDigest !== event.envelopeDigest)
      )) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
      const trust = observePeerIdentity(state, {
        peerHelloLynkId: event.senderHelloLynkId,
        peerPrincipalId: event.senderPrincipalId,
        peerDeviceId: event.senderDeviceId,
        identity: event.senderIdentity,
        observedAt: event.relayedAt,
      }, now());
      const opened = openDirectTextEnvelope({
        envelope: event.e2eeEnvelope,
        senderDeviceIdentity: event.senderIdentity,
        recipientDeviceKeyBundle: state.deviceKeyBundle,
        recipientOneTimePreKey: preKey.privateKeyBundle,
        expectedRecipient: {
          principalId: owner.principalId,
          hellolynkId: owner.hellolynkId,
          deviceId: owner.deviceId,
        },
      }, { nowMs: now() });
      if (opened.envelopeDigest !== event.envelopeDigest) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_envelope_mismatch");
      }
      for (const [outerField, protectedField] of OUTER_PROTECTED_BINDINGS) {
        if (opened.protectedMetadata[protectedField] !== event[outerField]) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
        }
      }
      if (trust.changed) await save();
      let commitStarted = false;
      return {
        text: opened.text,
        envelopeDigest: opened.envelopeDigest,
        senderIdentityKeyId: event.senderIdentityKeyId,
        recipientIdentityKeyId: event.recipientIdentityKeyId,
        senderPrincipalId: opened.protectedMetadata.senderPrincipalId,
        senderDelegateId: opened.protectedMetadata.senderDelegateId,
        intentSource: opened.protectedMetadata.intentSource,
        authorizationScope: opened.protectedMetadata.authorizationScope,
        async commit() {
          if (commitStarted) return;
          commitStarted = true;
          try {
            await withState(async (latest, saveLatest) => {
              consumePreKey(
                latest,
                event.recipientPreKeyId,
                event.clientMessageId,
                event.envelopeDigest,
                event.e2eeEnvelope.protected.expiresAt,
                now(),
              );
              await saveLatest();
            });
          } catch (error) {
            commitStarted = false;
            throw error;
          }
        },
      };
    });
  }

  async function openIncomingV2(input) {
    requireExactFields(input, ["event", "recipientPrincipalId", "recipientDelegateId"], "e2ee_open_client_input_invalid");
    if (input.recipientPrincipalId !== owner.principalId || input.recipientDelegateId !== owner.delegateId) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_context_mismatch");
    }
    const event = validateIncomingEventV2(input.event, owner);
    const openFromState = async (state, save) => {
      if (event.recipientIdentityKeyId !== state.deviceKeyBundle.keyId) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_identity_mismatch");
      }
      const persistedPreKey = state.preKeys.find((item) => (
        ["registered", "used"].includes(item.state)
        && item.privateKeyBundle.preKeyId === event.recipientPreKeyId
      ));
      const localPreKey = state.sameHostPreKeys.find((item) => (
        item.privateKeyBundle.preKeyId === event.recipientPreKeyId
      )) || null;
      const preKey = persistedPreKey || localPreKey;
      if (!preKey) throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_prekey_unavailable");
      if (localPreKey && (
        localPreKey.clientMessageId !== event.clientMessageId
        || localPreKey.senderDelegateId !== event.senderDelegateId
      )) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
      if (preKey.state === "used" && (
        (preKey.usedClientMessageId != null && preKey.usedClientMessageId !== event.clientMessageId)
        || (preKey.usedEnvelopeDigest != null && preKey.usedEnvelopeDigest !== event.envelopeDigest)
      )) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
      const trust = observePeerIdentity(state, {
        peerHelloLynkId: event.senderHelloLynkId,
        peerPrincipalId: event.senderPrincipalId,
        peerDeviceId: event.senderDeviceId,
        identity: event.senderIdentity,
        observedAt: event.relayedAt,
      }, now());
      const opened = openDirectTextEnvelopeV2({
        envelope: event.e2eeEnvelope,
        senderDeviceIdentity: event.senderIdentity,
        recipientDeviceKeyBundle: state.deviceKeyBundle,
        recipientOneTimePreKey: preKey.privateKeyBundle,
        expectedRecipient: {
          principalId: owner.principalId,
          hellolynkId: owner.hellolynkId,
          delegateId: owner.delegateId,
          hostId: owner.hostId,
          deviceId: owner.deviceId,
        },
      }, { nowMs: now() });
      if (
        opened.protectedMetadata.recipientDelegateAuthorizationVersion !== owner.authorizationVersion
      ) throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_authorization_version_mismatch");
      if (opened.envelopeDigest !== event.envelopeDigest) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_envelope_mismatch");
      }
      for (const [outerField, protectedField] of OUTER_PROTECTED_BINDINGS_V2) {
        if (opened.protectedMetadata[protectedField] !== event[outerField]) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
        }
      }
      if (trust.changed) await save();
      let commitStarted = false;
      return {
        e2eeVersion: 2,
        ...decodeNativeContent(opened.text),
        ...(opened.protectedMetadata.replyToClientMessageId ? { replyToClientMessageId: opened.protectedMetadata.replyToClientMessageId } : {}),
        envelopeDigest: opened.envelopeDigest,
        senderIdentityKeyId: event.senderIdentityKeyId,
        recipientIdentityKeyId: event.recipientIdentityKeyId,
        senderPrincipalId: opened.protectedMetadata.senderPrincipalId,
        senderDelegateId: opened.protectedMetadata.senderDelegateId,
        senderHelloLynkId: opened.protectedMetadata.senderHelloLynkId,
        recipientPrincipalId: opened.protectedMetadata.recipientPrincipalId,
        recipientDelegateId: opened.protectedMetadata.recipientDelegateId,
        recipientHelloLynkId: opened.protectedMetadata.recipientHelloLynkId,
        routeKind: opened.protectedMetadata.routeKind,
        intentSource: opened.protectedMetadata.intentSource,
        authorizationScope: opened.protectedMetadata.authorizationScope,
        async commit() {
          if (commitStarted) return;
          commitStarted = true;
          try {
            await withState(async (latest, saveLatest) => {
              const sameHostPreKey = latest.sameHostPreKeys.find((item) => (
                item.privateKeyBundle.preKeyId === event.recipientPreKeyId
              ));
              if (sameHostPreKey) {
                if (sameHostPreKey.clientMessageId !== event.clientMessageId
                  || (sameHostPreKey.usedEnvelopeDigest != null
                    && sameHostPreKey.usedEnvelopeDigest !== event.envelopeDigest)) {
                  throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
                }
                sameHostPreKey.state = "used";
                sameHostPreKey.usedEnvelopeDigest = event.envelopeDigest;
                await saveLatest();
                return;
              }
              consumePreKey(
                latest, event.recipientPreKeyId, event.clientMessageId,
                event.envelopeDigest, event.e2eeEnvelope.protected.expiresAt, now(),
              );
              await saveLatest();
            });
          } catch (error) {
            commitStarted = false;
            throw error;
          }
        },
      };
    };
    // An already verified identity can be checked and decrypted under the same
    // lock and state load. Nothing is cached across operations or lock releases.
    const opened = await withState((state, save) => {
      const verified = state.peerIdentityPins.some((pin) => (
        pin.peerHelloLynkId === event.senderHelloLynkId
        && pin.peerPrincipalId === event.senderPrincipalId
        && pin.peerDeviceId === event.senderDeviceId
        && pin.identityKeyId === event.senderIdentity.keyId
        && pin.publicKey === event.senderIdentity.publicKey
      ));
      return verified ? openFromState(state, save) : null;
    });
    if (opened) return opened;
    // Reload an unseen identity under the lock before checking and pinning the
    // authenticated relay identity; never retain a trust decision across locks.
    return withState((state, save) => openFromState(state, save));
  }

  async function listPreparedOutgoing() {
    // Internal reconciliation metadata only: never export an envelope, body or
    // key. The caller still needs the durable outbox's cancellation evidence.
    return withState(async (state) => state.preparedOutgoing.map((item) => ({
      clientMessageId: item.clientMessageId,
      recipientHelloLynkId: item.recipientHelloLynkId,
      envelopeDigest: item.envelopeDigest,
    })));
  }

  async function commitOutgoing(input) {
    requireExactFields(
      input,
      ["clientMessageId", "recipientHelloLynkId", "envelopeDigest"],
      "e2ee_outgoing_commit_input_invalid",
    );
    const clientMessageId = safeId(input.clientMessageId, "e2ee_client_message_id_invalid");
    const recipientHelloLynkId = safeId(input.recipientHelloLynkId, "e2ee_recipient_hellolynk_id_invalid");
    const envelopeDigest = String(input.envelopeDigest || "");
    if (!SAFE_DIGEST.test(envelopeDigest)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_outgoing_digest_invalid");
    }
    return withState(async (state, save) => {
      const index = state.preparedOutgoing.findIndex((item) => (
        item.clientMessageId === clientMessageId && item.recipientHelloLynkId === recipientHelloLynkId
      ));
      if (index < 0) return { committed: true, idempotent: true };
      if (state.preparedOutgoing[index].envelopeDigest !== envelopeDigest) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_outgoing_commit_binding_mismatch");
      }
      state.preparedOutgoing.splice(index, 1);
      await save();
      return { committed: true, idempotent: false };
    });
  }

  async function commitIncomingReplay(input) {
    requireExactFields(input, ["event", "storedMessage"], "e2ee_replay_commit_input_invalid");
    const event = e2eeVersion === 2
      ? validateIncomingEventV2(input.event, owner)
      : validateIncomingEvent(input.event, owner);
    const stored = input.storedMessage;
    if (
      !stored || typeof stored !== "object" || stored.clientMessageId !== event.clientMessageId
      || stored.envelopeDigest !== event.envelopeDigest
      || stored.recipientIdentityKeyId !== event.recipientIdentityKeyId
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_replay_commit_binding_mismatch");
    const protectedMetadata = event.e2eeEnvelope.protected;
    const hasStoredProtectedProvenance = [
      "senderPrincipalId",
      "authorizationScope",
      "intentSource",
    ].some((field) => Object.hasOwn(stored, field));
    if (hasStoredProtectedProvenance && (
      stored.senderPrincipalId !== protectedMetadata.senderPrincipalId
      || stored.senderDelegateId !== protectedMetadata.senderDelegateId
      || stored.intentSource !== protectedMetadata.intentSource
      || stored.authorizationScope !== protectedMetadata.authorizationScope
    )) throw new HelloLynkDirectTextE2eeClientError("e2ee_replay_commit_binding_mismatch");
    return withState(async (state, save) => {
      observePeerIdentity(state, {
        peerHelloLynkId: event.senderHelloLynkId,
        peerPrincipalId: event.senderPrincipalId,
        peerDeviceId: event.senderDeviceId,
        identity: event.senderIdentity,
        observedAt: event.relayedAt,
      }, now());
      consumePreKey(
        state,
        event.recipientPreKeyId,
        event.clientMessageId,
        event.envelopeDigest,
        event.e2eeEnvelope.protected.expiresAt,
        now(),
      );
      await save();
      return { committed: true, idempotent: true };
    });
  }

  async function createSameHostClaim(input, { signal } = {}) {
    if (e2eeVersion !== 2) throw new HelloLynkDirectTextE2eeClientError("e2ee_same_host_v2_required");
    requireExactFields(input, [
      "routeKind", "recipientDelegateId", "recipientHostId", "clientMessageId",
      "senderPrincipalId", "senderDelegateId", "senderDelegateAuthorizationVersion",
    ], "e2ee_same_host_claim_input_invalid");
    if (!["owned_delegate", "instance_direct"].includes(input.routeKind)
      || input.senderPrincipalId !== owner.principalId
      || input.senderDelegateId === owner.delegateId
      || input.recipientDelegateId !== owner.delegateId
      || input.recipientHostId !== owner.hostId
      || !Number.isSafeInteger(input.senderDelegateAuthorizationVersion)
      || input.senderDelegateAuthorizationVersion < 1) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_same_host_route_mismatch");
    }
    const clientMessageId = safeId(input.clientMessageId, "e2ee_client_message_id_invalid");
    return withState(async (state, save) => {
      const claimedAtMs = now();
      const expiresAtMs = claimedAtMs + Math.min(DIRECT_TEXT_E2EE_MAX_TTL_MS, 5 * 60 * 1000);
      state.sameHostPreKeys = state.sameHostPreKeys.filter((item) => (
        Date.parse(item.expiresAt) > claimedAtMs
      ));
      let preKey = state.sameHostPreKeys.find((item) => (
        item.clientMessageId === clientMessageId && item.senderDelegateId === input.senderDelegateId
      ));
      if (!preKey) {
        if (state.sameHostPreKeys.length >= MAX_LOCAL_PREKEYS) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_same_host_prekey_capacity_exceeded");
        }
        preKey = {
          state: "registered",
          privateKeyBundle: createOneTimePreKey({ nowMs: claimedAtMs }),
          clientMessageId,
          senderDelegateId: input.senderDelegateId,
          expiresAt: new Date(expiresAtMs).toISOString(),
          usedEnvelopeDigest: null,
        };
        state.sameHostPreKeys.push(preKey);
      }
      await save();
      return Object.freeze({
        ok: true,
        e2eeVersion: 2,
        routeKind: input.routeKind,
        claimId: `same_host_${createHash("sha256").update(`${owner.hostId}\0${owner.delegateId}\0${clientMessageId}`).digest("hex").slice(0, 32)}`,
        senderDelegateAuthorizationVersion: input.senderDelegateAuthorizationVersion,
        recipientPrincipalId: owner.principalId,
        recipientHelloLynkId: owner.hellolynkId,
        recipientDelegateId: owner.delegateId,
        recipientDelegateAuthorizationVersion: owner.authorizationVersion,
        recipientHostId: owner.hostId,
        recipientRouteVersion: 0,
        recipientDeviceId: owner.deviceId,
        identity: publicDirectTextDeviceIdentity(state.deviceKeyBundle),
        oneTimePreKey: publicOneTimePreKey(preKey.privateKeyBundle, state.deviceKeyBundle),
        claimedAt: new Date(claimedAtMs).toISOString(),
        expiresAt: preKey.expiresAt,
      });
    }, signal);
  }

  async function authorizePeerIdentity(input, { assertCurrentAuthority } = {}) {
    const targeted = Object.hasOwn(input ?? {}, "peerDeviceId") || Object.hasOwn(input ?? {}, "identityKeyId");
    requireExactFields(input, targeted
      ? ["peerHelloLynkId", "safetyCode", "peerDeviceId", "identityKeyId"]
      : ["peerHelloLynkId", "safetyCode"], "e2ee_peer_authorization_input_invalid");
    const peerHelloLynkId = safeId(input.peerHelloLynkId, "e2ee_peer_hellolynk_id_invalid");
    const safetyCode = normalizeDirectTextSafetyCode(input.safetyCode);
    const peerDeviceId = targeted ? safeId(input.peerDeviceId, "e2ee_peer_device_id_invalid") : null;
    const expectedKeyId = targeted ? safeId(input.identityKeyId, "e2ee_peer_identity_key_id_invalid") : null;
    return withState(async (state, save) => {
      // The native dialog selects an already observed device. Recheck its key
      // and code under the state lock before creating any authorization.
      if (targeted && !state.peerIdentityPins.some((pin) => (
        pin.peerHelloLynkId === peerHelloLynkId && pin.peerDeviceId === peerDeviceId
        && pin.identityKeyId === expectedKeyId && pin.safetyCode === safetyCode
      ))) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_identity_authorization_mismatch");
      }
      if (assertCurrentAuthority != null) await assertCurrentAuthority();
      const timestamp = new Date(now()).toISOString();
      let authorization = state.peerIdentityAuthorizations.find((item) => (
        item.peerHelloLynkId === peerHelloLynkId && item.safetyCode === safetyCode
      ));
      if (!authorization) {
        if (state.peerIdentityAuthorizations.length >= MAX_PEER_AUTHORIZATIONS) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_authorization_capacity_exceeded");
        }
        authorization = { peerHelloLynkId, safetyCode, authorizedAt: timestamp };
        state.peerIdentityAuthorizations.push(authorization);
      }
      const verified = [];
      for (const pin of state.peerIdentityPins) {
        if (pin.peerHelloLynkId !== peerHelloLynkId || pin.safetyCode !== safetyCode) continue;
        if (targeted && (pin.peerDeviceId !== peerDeviceId || pin.identityKeyId !== expectedKeyId)) continue;
        if (pin.verificationState !== "verified") {
          pin.verificationState = "verified";
          pin.verifiedAt = timestamp;
        }
        verified.push(publicPeerIdentityPin(pin));
      }
      try {
        await save();
      } catch {
        // A credential helper may replace the durable file before losing its
        // acknowledgement. No storage error may masquerade as a pre-write
        // identity mismatch; retain the established identity and do not replay.
        throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_authorization_outcome_unknown");
      }
      return Object.freeze({
        authorized: true,
        peerHelloLynkId,
        safetyCode,
        observedIdentitiesVerified: verified.length,
        identities: verified,
      });
    });
  }

  async function listPeerIdentityVerifications() {
    return withState(async (state) => Object.freeze({
      localDevice: Object.freeze({
        hellolynkId: owner.hellolynkId,
        deviceId: owner.deviceId,
        identityKeyId: state.deviceKeyBundle.keyId,
        safetyCode: localDeviceSafetyCode,
      }),
      peers: state.peerIdentityPins.map(publicPeerIdentityPin),
      authorizations: state.peerIdentityAuthorizations.map((item) => Object.freeze({ ...item })),
    }));
  }

  async function sealContactRequestIntro(input = {}) {
    assertPlainObject(input, "contact_request_e2ee_seal_input_invalid");
    requireExactFields(input, [
      "protectedMetadata", "recipientDeviceIdentity", "recipientOneTimePreKey", "introText", "introDigestSalt",
    ], "contact_request_e2ee_seal_input_invalid");
    const metadata = input.protectedMetadata;
    assertPlainObject(metadata, "contact_request_protected_metadata_invalid");
    return withState(async (state) => {
      if (metadata.senderPrincipalId !== owner.principalId
        || metadata.senderHelloLynkId !== owner.hellolynkId
        || metadata.senderDeviceId !== owner.deviceId
        || metadata.senderIdentityKeyId !== state.deviceKeyBundle.keyId) {
        throw new HelloLynkDirectTextE2eeClientError("contact_request_sender_owner_mismatch");
      }
      try {
        return sealContactRequestIntroEnvelope({
          ...input,
          senderDeviceKeyBundle: state.deviceKeyBundle,
        }, { nowMs: now() });
      } catch (error) {
        throw clientFailure(error, "contact_request_encryption_failed");
      }
    });
  }

  return Object.freeze({
    mode: "required",
    version: String(e2eeVersion),
    identityKeyId,
    localDeviceSafetyCode,
    authorizePeerIdentity,
    listPeerIdentityVerifications,
    sealContactRequestIntro,
    prepareOutgoing,
    listPreparedOutgoing,
    preKeyInventoryStatus,
    commitOutgoing,
    ensurePreKeyInventory,
    replenishPreKeyInventory: ensurePreKeyInventory,
    openIncoming,
    commitIncomingReplay,
    createSameHostClaim,
    publicDeviceIdentity: () => withState(async (state) => publicDirectTextDeviceIdentity(state.deviceKeyBundle)),
  });
}

function createInitialState(profileId, owner, preKeyCount, nowMs) {
  const deviceKeyBundle = createDirectTextDeviceKeyBundle({ nowMs });
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    profileId,
    owner: { ...owner },
    deviceKeyBundle,
    preKeys: Array.from({ length: preKeyCount }, (_, index) => (
      createLocalPreKey(nowMs + index)
    )),
    peerIdentityPins: [],
    peerIdentityAuthorizations: [],
    pendingPeerClaims: [],
    preparedOutgoing: [],
    consumedPreKeys: [],
    sameHostPreKeys: [],
  };
}

function normalizeState(state, profileId, owner) {
  if (state?.schemaVersion === 6) {
    requireExactFields(state, [
      "schemaVersion", "profileId", "owner", "deviceKeyBundle", "preKeys",
      "peerIdentityPins", "peerIdentityAuthorizations", "pendingPeerClaims",
      "preparedOutgoing", "consumedPreKeys",
    ], "e2ee_private_state_invalid");
    const migrated = structuredClone(state);
    migrated.schemaVersion = STATE_SCHEMA_VERSION;
    migrated.sameHostPreKeys = [];
    return { state: validateState(migrated, profileId, owner), migrated: true };
  }
  return { state: validateState(state, profileId, owner), migrated: false };
}

function validateState(state, profileId, owner) {
  requireExactFields(state, [
    "schemaVersion", "profileId", "owner", "deviceKeyBundle", "preKeys",
    "peerIdentityPins", "peerIdentityAuthorizations", "pendingPeerClaims",
    "preparedOutgoing", "consumedPreKeys", "sameHostPreKeys",
  ], "e2ee_private_state_invalid");
  if (state.schemaVersion !== STATE_SCHEMA_VERSION || state.profileId !== profileId) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  requireExactFields(state.owner, Object.hasOwn(owner, "hostId")
    ? ["principalId", "hellolynkId", "agentId", "delegateId", "deviceId", "hostId", "authorizationVersion"]
    : ["principalId", "hellolynkId", "agentId", "delegateId", "deviceId"], "e2ee_private_state_invalid");
  if (JSON.stringify(state.owner) !== JSON.stringify(owner)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_owner_mismatch");
  }
  publicDirectTextDeviceIdentity(state.deviceKeyBundle);
  if (!Array.isArray(state.preKeys) || state.preKeys.length > MAX_LOCAL_PREKEYS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  for (const item of state.preKeys) {
    requireExactFields(item, [
      "state", "privateKeyBundle", "registeredAt", "claimExpiresAt",
      "usedClientMessageId", "usedEnvelopeDigest",
    ], "e2ee_private_state_invalid");
    if (!["pending_registration", "registered", "used"].includes(item.state)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    publicOneTimePreKey(item.privateKeyBundle, state.deviceKeyBundle);
    if (item.registeredAt != null) iso(item.registeredAt, "e2ee_private_state_invalid");
    if (item.claimExpiresAt != null) iso(item.claimExpiresAt, "e2ee_private_state_invalid");
    if (item.state === "pending_registration" && (
      item.registeredAt != null || item.claimExpiresAt != null
      || item.usedClientMessageId != null || item.usedEnvelopeDigest != null
    )) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    if (item.state === "used") {
      if (item.claimExpiresAt == null) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
      if ((item.usedClientMessageId == null) !== (item.usedEnvelopeDigest == null)) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
      }
      if (item.usedClientMessageId != null) {
        safeId(item.usedClientMessageId, "e2ee_private_state_invalid");
        if (!SAFE_DIGEST.test(String(item.usedEnvelopeDigest || ""))) {
          throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
        }
      }
    } else if (item.usedClientMessageId != null || item.usedEnvelopeDigest != null) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
  }
  if (!Array.isArray(state.sameHostPreKeys) || state.sameHostPreKeys.length > MAX_LOCAL_PREKEYS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  const sameHostPreKeyIds = new Set();
  const sameHostClaimKeys = new Set();
  for (const item of state.sameHostPreKeys) {
    requireExactFields(item, [
      "state", "privateKeyBundle", "clientMessageId", "senderDelegateId", "expiresAt", "usedEnvelopeDigest",
    ], "e2ee_private_state_invalid");
    if (!["registered", "used"].includes(item.state)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    publicOneTimePreKey(item.privateKeyBundle, state.deviceKeyBundle);
    safeId(item.clientMessageId, "e2ee_private_state_invalid");
    safeId(item.senderDelegateId, "e2ee_private_state_invalid");
    const sameHostExpiry = iso(item.expiresAt, "e2ee_private_state_invalid");
    if (Date.parse(sameHostExpiry) > Date.now() + DIRECT_TEXT_E2EE_MAX_TTL_MS) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    const preKeyId = item.privateKeyBundle.preKeyId;
    const claimKey = `${item.senderDelegateId}\0${item.clientMessageId}`;
    if (sameHostPreKeyIds.has(preKeyId) || sameHostClaimKeys.has(claimKey)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    sameHostPreKeyIds.add(preKeyId);
    sameHostClaimKeys.add(claimKey);
    if (item.state === "used") {
      if (!SAFE_DIGEST.test(String(item.usedEnvelopeDigest || ""))) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
      }
    } else if (item.usedEnvelopeDigest != null) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
  }
  if (!Array.isArray(state.peerIdentityPins) || state.peerIdentityPins.length > MAX_PEER_PINS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  for (const pin of state.peerIdentityPins) {
    requireExactFields(pin, [
      "peerHelloLynkId", "peerPrincipalId", "peerDeviceId", "identityKeyId", "publicKey",
      "firstSeenAt", "safetyCode", "verificationState", "verifiedAt",
    ], "e2ee_private_state_invalid");
    safeId(pin.peerHelloLynkId, "e2ee_private_state_invalid");
    safeId(pin.peerPrincipalId, "e2ee_private_state_invalid");
    safeId(pin.peerDeviceId, "e2ee_private_state_invalid");
    safeId(pin.identityKeyId, "e2ee_private_state_invalid");
    iso(pin.firstSeenAt, "e2ee_private_state_invalid");
    if (pin.safetyCode !== directTextDeviceSafetyCode({
      hellolynkId: pin.peerHelloLynkId,
      deviceId: pin.peerDeviceId,
      identityKeyId: pin.identityKeyId,
      publicKey: pin.publicKey,
    })) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    if (!["pending", "verified"].includes(pin.verificationState)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    if (pin.verificationState === "verified") iso(pin.verifiedAt, "e2ee_private_state_invalid");
    else if (pin.verifiedAt != null) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  if (
    !Array.isArray(state.peerIdentityAuthorizations)
    || state.peerIdentityAuthorizations.length > MAX_PEER_AUTHORIZATIONS
  ) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  for (const authorization of state.peerIdentityAuthorizations) {
    requireExactFields(authorization, ["peerHelloLynkId", "safetyCode", "authorizedAt"], "e2ee_private_state_invalid");
    safeId(authorization.peerHelloLynkId, "e2ee_private_state_invalid");
    normalizeDirectTextSafetyCode(authorization.safetyCode);
    iso(authorization.authorizedAt, "e2ee_private_state_invalid");
  }
  if (!Array.isArray(state.pendingPeerClaims) || state.pendingPeerClaims.length > MAX_PENDING_PEER_CLAIMS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  for (const pending of state.pendingPeerClaims) {
    requireExactFields(pending, pending.e2eeVersion === 2
      ? [
          "e2eeVersion", "recipientHelloLynkId", "clientMessageId", "requestDigest", "routeKind",
          "recipientDelegateId", "recipientHostId", "recipientDeviceId", "claim", "storedAt",
        ]
      : ["e2eeVersion", "recipientHelloLynkId", "clientMessageId", "claim", "storedAt"],
    "e2ee_private_state_invalid");
    const recipientHelloLynkId = safeId(pending.recipientHelloLynkId, "e2ee_private_state_invalid");
    if (![1, 2].includes(pending.e2eeVersion)) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    if (pending.e2eeVersion === 2 && !SAFE_DIGEST.test(String(pending.requestDigest || ""))) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    safeId(pending.clientMessageId, "e2ee_private_state_invalid");
    iso(pending.storedAt, "e2ee_private_state_invalid");
    const claim = validateStoredClaim(
      pending.claim,
      recipientHelloLynkId,
      pending.e2eeVersion === 2 ? owner.authorizationVersion : null,
    );
    if (pending.e2eeVersion === 2 && (
      pending.routeKind !== claim.routeKind
      || pending.recipientDelegateId !== claim.recipientDelegateId
      || pending.recipientHostId !== claim.recipientHostId
      || pending.recipientDeviceId !== claim.recipientDeviceId
    )) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  if (!Array.isArray(state.preparedOutgoing) || state.preparedOutgoing.length > MAX_PREPARED_OUTGOING) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  const preparedKeys = new Set();
  for (const record of state.preparedOutgoing) {
    const version = record?.e2eeVersion;
    requireExactFields(record, version === 2 ? [
      "e2eeVersion", "clientMessageId", "recipientHelloLynkId", "requestDigest",
      "routeKind", "recipientDelegateId", "recipientHostId", "recipientDeviceId",
      "claimId", "envelope", "envelopeDigest",
      ...(Object.hasOwn(record, "nativeContentVersion") ? ["nativeContentVersion"] : []),
    ] : [
      "e2eeVersion", "clientMessageId", "recipientHelloLynkId", "requestDigest",
      "claimId", "envelope", "envelopeDigest",
    ], "e2ee_private_state_invalid");
    if (![1, 2].includes(version)) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    if (Object.hasOwn(record, "nativeContentVersion") && record.nativeContentVersion !== 1)
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    const clientMessageId = safeId(record.clientMessageId, "e2ee_private_state_invalid");
    const recipientHelloLynkId = safeId(record.recipientHelloLynkId, "e2ee_private_state_invalid");
    safeId(record.claimId, "e2ee_private_state_invalid");
    if (!SAFE_DIGEST.test(String(record.requestDigest || ""))) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    let envelopeDigest;
    try {
      envelopeDigest = version === 2
        ? digestDirectTextEnvelopeV2(record.envelope)
        : digestDirectTextEnvelope(record.envelope);
    } catch (error) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid", { cause: error });
    }
    if (record.envelopeDigest !== envelopeDigest) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    const protectedMetadata = record.envelope?.protected;
    if (
      protectedMetadata?.clientMessageId !== clientMessageId
      || protectedMetadata?.recipientHelloLynkId !== recipientHelloLynkId
      || protectedMetadata?.senderPrincipalId !== owner.principalId
      || protectedMetadata?.senderHelloLynkId !== owner.hellolynkId
      || protectedMetadata?.senderAgentId !== owner.agentId
      || protectedMetadata?.senderDelegateId !== owner.delegateId
      || protectedMetadata?.senderDeviceId !== owner.deviceId
      || protectedMetadata?.senderIdentityKeyId !== state.deviceKeyBundle.keyId
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    if (version === 2) {
      if (
        !Object.hasOwn(owner, "hostId")
        || !["principal_inbox", "owned_delegate", "instance_direct"].includes(record.routeKind)
        || record.routeKind !== protectedMetadata.routeKind
        || safeId(record.recipientDelegateId, "e2ee_private_state_invalid") !== protectedMetadata.recipientDelegateId
        || safeId(record.recipientHostId, "e2ee_private_state_invalid") !== protectedMetadata.recipientHostId
        || safeId(record.recipientDeviceId, "e2ee_private_state_invalid") !== protectedMetadata.recipientDeviceId
        || protectedMetadata.senderHostId !== owner.hostId
        || protectedMetadata.senderDelegateAuthorizationVersion !== owner.authorizationVersion
      ) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    const key = clientMessageId;
    if (preparedKeys.has(key)) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    preparedKeys.add(key);
  }
  if (!Array.isArray(state.consumedPreKeys) || state.consumedPreKeys.length > MAX_CONSUMED_RECORDS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  const consumedIds = new Set();
  for (const record of state.consumedPreKeys) {
    requireExactFields(
      record,
      ["preKeyId", "clientMessageId", "envelopeDigest", "consumedAt"],
      "e2ee_private_state_invalid",
    );
    const preKeyId = safeId(record.preKeyId, "e2ee_private_state_invalid");
    const clientMessageId = safeId(record.clientMessageId, "e2ee_private_state_invalid");
    if (!SAFE_DIGEST.test(String(record.envelopeDigest || ""))) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    }
    iso(record.consumedAt, "e2ee_private_state_invalid");
    if (consumedIds.has(preKeyId)) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
    consumedIds.add(preKeyId);
    const preKey = state.preKeys.find((item) => item.privateKeyBundle.preKeyId === preKeyId);
    if (preKey && (
      preKey.state !== "used"
      || preKey.usedClientMessageId !== clientMessageId
      || preKey.usedEnvelopeDigest !== record.envelopeDigest
    )) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  for (const preKey of state.preKeys) {
    if (preKey.state !== "used" || preKey.usedClientMessageId == null) continue;
    if (!state.consumedPreKeys.some((record) => (
      record.preKeyId === preKey.privateKeyBundle.preKeyId
      && record.clientMessageId === preKey.usedClientMessageId
      && record.envelopeDigest === preKey.usedEnvelopeDigest
    ))) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  }
  return state;
}

function e2eeOwnerBaseIdentity(owner) {
  return JSON.stringify({
    principalId: owner?.principalId,
    hellolynkId: owner?.hellolynkId,
    agentId: owner?.agentId,
    delegateId: owner?.delegateId,
    deviceId: owner?.deviceId,
  });
}

function observePeerIdentity(state, observation, nowMs = Date.now()) {
  if (!verifyDeviceIdentityRegistration(observation.identity)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_identity_signature_invalid");
  }
  let pin = state.peerIdentityPins.find((candidate) => (
    candidate.peerHelloLynkId === observation.peerHelloLynkId && candidate.peerDeviceId === observation.peerDeviceId
  ));
  let changed = false;
  if (pin) {
    if (
      pin.peerPrincipalId !== observation.peerPrincipalId
      || pin.identityKeyId !== observation.identity.keyId
      || pin.publicKey !== observation.identity.publicKey
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_identity_pin_mismatch");
  } else {
    if (state.peerIdentityPins.length >= MAX_PEER_PINS) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_peer_identity_pin_capacity_exceeded");
    }
    pin = {
      peerHelloLynkId: observation.peerHelloLynkId,
      peerPrincipalId: observation.peerPrincipalId,
      peerDeviceId: observation.peerDeviceId,
      identityKeyId: observation.identity.keyId,
      publicKey: observation.identity.publicKey,
      firstSeenAt: iso(observation.observedAt, "e2ee_peer_identity_observed_at_invalid"),
      safetyCode: directTextDeviceSafetyCode({
        hellolynkId: observation.peerHelloLynkId,
        deviceId: observation.peerDeviceId,
        identityKeyId: observation.identity.keyId,
        publicKey: observation.identity.publicKey,
      }),
      verificationState: "pending",
      verifiedAt: null,
    };
    state.peerIdentityPins.push(pin);
    changed = true;
  }
  // Historical manual verification fields remain unchanged. The authenticated
  // directory identity, signature and exact pin binding decide whether it is usable.
  return { changed };
}

function publicPeerIdentityPin(pin) {
  return Object.freeze({
    peerHelloLynkId: pin.peerHelloLynkId,
    peerPrincipalId: pin.peerPrincipalId,
    peerDeviceId: pin.peerDeviceId,
    identityKeyId: pin.identityKeyId,
    safetyCode: pin.safetyCode,
    verificationState: pin.verificationState,
    firstSeenAt: pin.firstSeenAt,
    verifiedAt: pin.verifiedAt,
  });
}

function requirePreparedPeerTrust(state, record) {
  const protectedMetadata = record?.envelope?.protected;
  const pin = state.peerIdentityPins.find((item) => (
    item.peerHelloLynkId === record.recipientHelloLynkId
    && item.peerDeviceId === protectedMetadata?.recipientDeviceId
    && item.identityKeyId === protectedMetadata?.recipientIdentityKeyId
  ));
  if (!pin) throw new HelloLynkDirectTextE2eeClientError("e2ee_prepared_peer_identity_pin_missing");
}

function pruneExpiredPendingPeerClaims(state, nowMs) {
  const retained = state.pendingPeerClaims.filter((item) => Date.parse(item.claim.expiresAt) > nowMs);
  if (retained.length === state.pendingPeerClaims.length) return false;
  state.pendingPeerClaims = retained;
  return true;
}

function validateStoredClaim(value, recipientHelloLynkId, senderDelegateAuthorizationVersion = null) {
  const claimedAt = Date.parse(value?.claimedAt || "");
  if (!Number.isFinite(claimedAt)) throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid");
  try {
    return value?.e2eeVersion === 2
      ? validateClaimResponseV2(value, {
          recipientHelloLynkId,
          routeKind: value.routeKind,
          recipientDelegateId: value.recipientDelegateId,
          recipientHostId: value.recipientHostId,
          recipientDeviceId: value.recipientDeviceId,
          senderDelegateAuthorizationVersion,
        }, claimedAt - 1)
      : validateClaimResponse(value, recipientHelloLynkId, claimedAt - 1);
  } catch (error) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_private_state_invalid", { cause: error });
  }
}

function validateClaimResponse(value, recipientHelloLynkId, nowMs) {
  requireExactFields(value, [
    "ok", "claimId", "recipientPrincipalId", "recipientHelloLynkId", "recipientDeviceId",
    "identity", "oneTimePreKey", "claimedAt", "expiresAt",
  ], "e2ee_claim_response_invalid");
  if (value.ok !== true || value.recipientHelloLynkId !== recipientHelloLynkId) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_response_mismatch");
  }
  safeId(value.claimId, "e2ee_claim_response_invalid");
  safeId(value.recipientPrincipalId, "e2ee_claim_response_invalid");
  safeId(value.recipientDeviceId, "e2ee_claim_response_invalid");
  if (!verifyDeviceIdentityRegistration(value.identity)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({ identity: value.identity, oneTimePreKey: value.oneTimePreKey })) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_prekey_signature_invalid");
  }
  const claimedAt = iso(value.claimedAt, "e2ee_claim_response_invalid");
  const expiresAt = iso(value.expiresAt, "e2ee_claim_response_invalid");
  if (Date.parse(expiresAt) <= nowMs || Date.parse(expiresAt) - Date.parse(claimedAt) > DIRECT_TEXT_E2EE_MAX_TTL_MS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_expired");
  }
  return value;
}

function validateClaimResponseV2(value, expected, nowMs) {
  requireExactFields(value, [
    "ok", "e2eeVersion", "routeKind", "claimId", "senderDelegateAuthorizationVersion",
    "recipientPrincipalId", "recipientHelloLynkId", "recipientDelegateId",
    "recipientDelegateAuthorizationVersion", "recipientHostId", "recipientRouteVersion",
    "recipientDeviceId", "identity", "oneTimePreKey", "claimedAt", "expiresAt",
    ...(Object.hasOwn(value || {}, "nativeContentVersion") ? ["nativeContentVersion"] : []),
  ], "e2ee_claim_response_invalid");
  if (Object.hasOwn(value, "nativeContentVersion") && value.nativeContentVersion !== 1)
    throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_response_invalid");
  if (
    value.ok !== true || value.e2eeVersion !== 2 || value.routeKind !== expected.routeKind
    || value.senderDelegateAuthorizationVersion !== expected.senderDelegateAuthorizationVersion
    || value.recipientHelloLynkId !== expected.recipientHelloLynkId
    || (expected.routeKind === "owned_delegate" && (
      value.recipientDelegateId !== expected.recipientDelegateId
      || value.recipientHostId !== expected.recipientHostId
      || (expected.recipientDeviceId != null && value.recipientDeviceId !== expected.recipientDeviceId)
    ))
    || (expected.routeKind === "instance_direct" && value.recipientDelegateId !== expected.recipientDelegateId)
    || !Number.isSafeInteger(value.senderDelegateAuthorizationVersion)
    || value.senderDelegateAuthorizationVersion < 1
    || !Number.isSafeInteger(value.recipientDelegateAuthorizationVersion)
    || value.recipientDelegateAuthorizationVersion < 1
    || !Number.isSafeInteger(value.recipientRouteVersion)
    || (value.routeKind === "principal_inbox" && value.recipientRouteVersion < 1)
    || (value.routeKind === "owned_delegate" && value.recipientRouteVersion !== 0)
    || (value.routeKind === "instance_direct" && value.recipientRouteVersion !== 0)
  ) throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_response_mismatch");
  for (const field of [
    "claimId", "recipientPrincipalId", "recipientDelegateId", "recipientHostId", "recipientDeviceId",
  ]) safeId(value[field], "e2ee_claim_response_invalid");
  if (!verifyDeviceIdentityRegistration(value.identity)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({ identity: value.identity, oneTimePreKey: value.oneTimePreKey })) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_recipient_prekey_signature_invalid");
  }
  const claimedAt = iso(value.claimedAt, "e2ee_claim_response_invalid");
  const expiresAt = iso(value.expiresAt, "e2ee_claim_response_invalid");
  if (Date.parse(expiresAt) <= nowMs || Date.parse(expiresAt) - Date.parse(claimedAt) > DIRECT_TEXT_E2EE_MAX_TTL_MS) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_claim_expired");
  }
  return value;
}

function validateInventoryResponse(value, nowMs) {
  requireExactFields(value, ["ok", "oneTimePreKeys"], "e2ee_inventory_response_invalid");
  if (value.ok !== true || !Array.isArray(value.oneTimePreKeys) || value.oneTimePreKeys.length > 1000) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_response_invalid");
  }
  const seen = new Set();
  const inventory = value.oneTimePreKeys.map((item) => {
    requireExactFields(item, ["preKeyId", "state", "claimExpiresAt"], "e2ee_inventory_response_invalid");
    const preKeyId = safeId(item.preKeyId, "e2ee_inventory_response_invalid");
    if (seen.has(preKeyId) || !["available", "claimed", "used"].includes(item.state)) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_response_invalid");
    }
    seen.add(preKeyId);
    if (item.state === "available") {
      if (item.claimExpiresAt != null) throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_response_invalid");
      return { preKeyId, state: item.state, claimExpiresAt: null };
    }
    const claimExpiresAt = iso(item.claimExpiresAt, "e2ee_inventory_response_invalid");
    if (Date.parse(claimExpiresAt) <= nowMs) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_response_invalid");
    }
    return { preKeyId, state: item.state, claimExpiresAt };
  });
  return inventory;
}

function reconcilePreKeyInventory(state, inventory, targetAvailable, nowMs) {
  const byId = new Map(inventory.map((item) => [item.preKeyId, item]));
  const localById = new Map(state.preKeys.map((item) => [item.privateKeyBundle.preKeyId, item]));
  for (const item of inventory) {
    if (localById.has(item.preKeyId)) continue;
    const legacyConsumed = item.state === "used" && state.consumedPreKeys.some((record) => (
      record.preKeyId === item.preKeyId
    ));
    if (!legacyConsumed) throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_private_key_missing");
  }

  let changed = false;
  const retained = [];
  for (const local of state.preKeys) {
    if (local.state === "pending_registration") {
      retained.push(local);
      continue;
    }
    const server = byId.get(local.privateKeyBundle.preKeyId);
    if (!server) {
      if (local.state === "used" && Date.parse(local.claimExpiresAt || "") > nowMs) {
        throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_used_record_missing");
      }
      changed = true;
      continue;
    }
    if (local.state === "used" && server.state !== "used") {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_inventory_used_state_regressed");
    }
    if (server.state === "used") {
      if (local.state !== "used" || local.claimExpiresAt !== server.claimExpiresAt) changed = true;
      local.state = "used";
      local.claimExpiresAt = server.claimExpiresAt;
    } else {
      if (local.state !== "registered" || local.claimExpiresAt !== server.claimExpiresAt) changed = true;
      local.state = "registered";
      local.claimExpiresAt = server.claimExpiresAt;
      local.usedClientMessageId = null;
      local.usedEnvelopeDigest = null;
    }
    retained.push(local);
  }
  if (retained.length !== state.preKeys.length) state.preKeys = retained;

  const retainedUsed = state.preKeys.filter((item) => item.state === "used").length;
  const available = inventory.filter((item) => item.state === "available").length;
  const generated = Math.max(0, targetAvailable - available);
  if (state.preKeys.length + generated > MAX_LOCAL_PREKEYS) {
    const expiries = state.preKeys.filter((item) => item.state === "used")
      .map((item) => Date.parse(item.claimExpiresAt)).filter((value) => value > nowMs);
    throw new HelloLynkDirectTextE2eeClientError("e2ee_local_prekey_capacity_exceeded", {
      retryable: true,
      retryAt: expiries.length ? new Date(Math.min(...expiries)).toISOString() : null,
    });
  }
  for (let index = 0; index < generated; index += 1) {
    state.preKeys.push(createLocalPreKey(nowMs + index + 1));
  }
  if (generated > 0) changed = true;
  return { changed, available, generated, retainedUsed };
}

function validateIncomingEvent(event, owner) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_invalid");
  }
  if (Object.hasOwn(event, "authorizationScope") || Object.hasOwn(event, "intentSource")) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
  }
  const requiredIds = OUTER_PROTECTED_BINDINGS
    .map(([outerField]) => outerField)
    .filter((field) => field !== "messageType");
  for (const field of requiredIds) safeId(event[field], "e2ee_incoming_event_invalid");
  if (
    event.messageType !== "text" || event.recipientPrincipalId !== owner.principalId
    || event.recipientHelloLynkId !== owner.hellolynkId || event.recipientDeviceId !== owner.deviceId
    || event.senderIdentity?.keyId !== event.senderIdentityKeyId
  ) throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
  if (!verifyDeviceIdentityRegistration(event.senderIdentity)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_sender_identity_signature_invalid");
  }
  const envelopeDigest = digestDirectTextEnvelope(event.e2eeEnvelope);
  if (!SAFE_DIGEST.test(String(event.envelopeDigest || "")) || envelopeDigest !== event.envelopeDigest) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_digest_mismatch");
  }
  for (const [outerField, protectedField] of OUTER_PROTECTED_BINDINGS) {
    if (event.e2eeEnvelope.protected[protectedField] !== event[outerField]) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
    }
  }
  return event;
}

function validateIncomingEventV2(event, owner) {
  if (!event || typeof event !== "object" || Array.isArray(event) || event.schemaVersion !== 2) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_invalid");
  }
  if (Object.hasOwn(event, "authorizationScope") || Object.hasOwn(event, "intentSource")) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
  }
  for (const [outerField] of OUTER_PROTECTED_BINDINGS_V2) {
    if ([
      "senderDelegateAuthorizationVersion", "recipientDelegateAuthorizationVersion", "recipientRouteVersion",
    ].includes(outerField)) continue;
    if (outerField !== "messageType" && outerField !== "routeKind") {
      safeId(event[outerField], "e2ee_incoming_event_invalid");
    }
  }
  if (
    !["principal_inbox", "owned_delegate", "instance_direct"].includes(event.routeKind)
    || event.messageType !== "text" || event.recipientPrincipalId !== owner.principalId
    || event.recipientHelloLynkId !== owner.hellolynkId || event.recipientDelegateId !== owner.delegateId
    || event.recipientHostId !== owner.hostId || event.recipientDeviceId !== owner.deviceId
    || event.recipientDelegateAuthorizationVersion !== owner.authorizationVersion
    || !Number.isSafeInteger(event.recipientRouteVersion)
    || event.senderIdentity?.keyId !== event.senderIdentityKeyId
  ) throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
  if (!verifyDeviceIdentityRegistration(event.senderIdentity)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_sender_identity_signature_invalid");
  }
  const envelopeDigest = digestDirectTextEnvelopeV2(event.e2eeEnvelope);
  if (!SAFE_DIGEST.test(String(event.envelopeDigest || "")) || envelopeDigest !== event.envelopeDigest) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_digest_mismatch");
  }
  for (const [outerField, protectedField] of OUTER_PROTECTED_BINDINGS_V2) {
    if (event.e2eeEnvelope.protected[protectedField] !== event[outerField]) {
      throw new HelloLynkDirectTextE2eeClientError("e2ee_incoming_event_binding_mismatch");
    }
  }
  return event;
}

function consumePreKey(state, preKeyId, clientMessageId, envelopeDigest, claimExpiresAt, nowMs) {
  const consumed = state.consumedPreKeys.find((item) => item.preKeyId === preKeyId);
  const index = state.preKeys.findIndex((item) => item.privateKeyBundle.preKeyId === preKeyId);
  if (consumed && (consumed.clientMessageId !== clientMessageId || consumed.envelopeDigest !== envelopeDigest)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
  }
  if (index < 0) {
    if (consumed) return false;
    throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_record_missing");
  }
  const preKey = state.preKeys[index];
  if (consumed) {
    if (
      preKey.state !== "used"
      || preKey.usedClientMessageId !== clientMessageId
      || preKey.usedEnvelopeDigest !== envelopeDigest
    ) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
    return false;
  }
  const acceptedExpiry = iso(claimExpiresAt, "e2ee_prekey_claim_expiry_invalid");
  if (Date.parse(acceptedExpiry) <= nowMs) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_claim_expired");
  }
  if (preKey.state === "used" && (
    (preKey.usedClientMessageId != null && preKey.usedClientMessageId !== clientMessageId)
    || (preKey.usedEnvelopeDigest != null && preKey.usedEnvelopeDigest !== envelopeDigest)
  )) throw new HelloLynkDirectTextE2eeClientError("e2ee_prekey_consumption_conflict");
  preKey.state = "used";
  preKey.claimExpiresAt = new Date(Math.max(
    Date.parse(preKey.claimExpiresAt || acceptedExpiry),
    Date.parse(acceptedExpiry),
  )).toISOString();
  preKey.usedClientMessageId = clientMessageId;
  preKey.usedEnvelopeDigest = envelopeDigest;
  if (state.consumedPreKeys.length >= MAX_CONSUMED_RECORDS) state.consumedPreKeys.shift();
  state.consumedPreKeys.push({
    preKeyId,
    clientMessageId,
    envelopeDigest,
    consumedAt: new Date(nowMs).toISOString(),
  });
  return true;
}

function createLocalPreKey(nowMs) {
  return {
    state: "pending_registration",
    privateKeyBundle: createOneTimePreKey({ nowMs }),
    registeredAt: null,
    claimExpiresAt: null,
    usedClientMessageId: null,
    usedEnvelopeDigest: null,
  };
}

function publicPrepared(record) {
  return {
    ...(record.e2eeVersion === 2 ? {
      version: "2",
      routeKind: record.routeKind,
      recipientDelegateId: record.recipientDelegateId,
      recipientHostId: record.recipientHostId,
      recipientDeviceId: record.recipientDeviceId,
      ...(record.nativeContentVersion === 1 ? { nativeContentVersion: 1 } : {}),
    } : {}),
    claimId: record.claimId,
    envelope: structuredClone(record.envelope),
    envelopeDigest: record.envelopeDigest,
  };
}

function digestRequestV2(input) {
  return createHash("sha256").update(JSON.stringify({
    e2eeVersion: 2,
    clientMessageId: input.clientMessageId,
    routeKind: input.routeKind,
    recipientHelloLynkId: input.recipientHelloLynkId,
    recipientDelegateId: input.recipientDelegateId,
    recipientHostId: input.recipientHostId,
    recipientDeviceId: input.recipientDeviceId,
    senderPrincipalId: input.senderPrincipalId,
    senderDelegateId: input.senderDelegateId,
    intentSource: input.intentSource,
    text: input.text,
    ...(input.replyToClientMessageId ? { replyToClientMessageId: input.replyToClientMessageId } : {}),
    ...(input.targetConversationId ? { targetConversationId: input.targetConversationId } : {}),
    ...(input.nativeDirectory ? { nativeDirectory: input.nativeDirectory } : {}),
  }), "utf8").digest("hex");
}

function digestRequest(input) {
  return createHash("sha256").update(JSON.stringify({
    clientMessageId: input.clientMessageId,
    recipientHelloLynkId: input.recipientHelloLynkId,
    senderPrincipalId: input.senderPrincipalId,
    senderDelegateId: input.senderDelegateId,
    intentSource: input.intentSource,
    text: input.text,
  }), "utf8").digest("hex");
}

async function saveState(privateKeys, profileId, state) {
  try {
    await privateKeys.save(profileId, state);
  } catch (error) {
    throw clientFailure(error, "e2ee_private_key_save_failed");
  }
}

async function readBoundedJson(response) {
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > MAX_JSON_RESPONSE_BYTES) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_response_too_large");
  }
  const raw = await response.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_JSON_RESPONSE_BYTES) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_response_too_large");
  }
  try {
    return raw ? JSON.parse(raw) : {};
  } catch (error) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_response_invalid_json", { cause: error });
  }
}

function safeProfileId(value) {
  const text = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/.test(text)) {
    throw new HelloLynkDirectTextE2eeClientError("e2ee_profile_id_invalid");
  }
  return text;
}

function safeId(value, code) {
  const text = String(value || "").trim();
  if (!SAFE_ID.test(text)) throw new HelloLynkDirectTextE2eeClientError(code);
  return text;
}

function iso(value, code) {
  const text = String(value || "");
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== text) {
    throw new HelloLynkDirectTextE2eeClientError(code);
  }
  return text;
}

function requireExactFields(value, fields, code) {
  assertPlainObject(value, code);
  const actual = Object.keys(value);
  if (actual.length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new HelloLynkDirectTextE2eeClientError(code);
  }
}

function assertPlainObject(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkDirectTextE2eeClientError(code);
  }
}

function clientFailure(error, fallback) {
  if (error instanceof HelloLynkDirectTextE2eeClientError) return error;
  const code = /^[a-z][a-z0-9_]{0,63}$/.test(String(error?.code || "")) ? error.code : fallback;
  return new HelloLynkDirectTextE2eeClientError(code, { cause: error });
}
