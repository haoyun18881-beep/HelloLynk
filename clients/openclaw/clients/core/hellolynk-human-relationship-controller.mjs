import crypto from "node:crypto";

import {
  CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE,
  CONTACT_REQUEST_E2EE_INTENT_SOURCE,
  CONTACT_REQUEST_E2EE_MESSAGE_TYPE,
  createContactRequestIntroCommitment,
  createContactRequestRecordDigest,
  digestContactRequestIntroEnvelope,
  validateContactRequestIntro,
} from "./hellolynk-contact-request-e2ee.mjs";

export const HELLOLYNK_HUMAN_RELATIONSHIP_CONTROLLER_CONTRACT =
  "hellolynk-human-relationship-controller-v2";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const HELLOLYNK_ID = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const TARGET_CAPACITY = 64;
const DECISION_TARGET_STATES = Object.freeze({
  accept: "accepted",
  reject: "rejected",
  block: "blocked",
});
const DECISION_TERMINAL_STATES = new Set([
  "accepted",
  "rejected",
  "cancelled",
  "blocked",
  "expired",
]);

export class HelloLynkHumanRelationshipControllerError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkHumanRelationshipControllerError";
    this.code = code;
    this.httpStatus = Number.isInteger(options.httpStatus) ? options.httpStatus : null;
  }
}

export function createHelloLynkHumanRelationshipController(options = {}) {
  const cloud = requireMethods(options.cloud, [
    "searchDirectory", "reserveContactRequest", "relayContactRequest",
    "listContactRequests", "decideContactRequest", "getContactRequestDecisionState",
  ], "human_relationship_cloud_invalid");
  const e2ee = requireMethods(
    options.e2ee,
    ["sealContactRequestIntro"],
    "human_relationship_e2ee_invalid",
  );
  const localStore = requireMethods(options.localStore, [
    "listForHuman", "listPendingAckReceipts", "projectServerState",
    "beginDecision", "abortDecision", "resolveDecision", "recoverDecision",
    "listUnresolvedDecisions",
    "clearResolvedForHuman",
  ], "human_relationship_local_store_invalid");
  const contactAuthorizationStore = options.contactAuthorizationStore == null
    ? null
    : requireMethods(
        options.contactAuthorizationStore,
        ["revokeAutonomousMessagingByHelloLynkId"],
        "human_relationship_contact_authorization_store_invalid",
      );
  if (typeof options.runtimeHeaders !== "function") {
    throw failure("human_relationship_runtime_headers_required");
  }
  const owner = Object.freeze({
    principalId: safeId(options.principalId, "human_relationship_owner_invalid"),
    hellolynkId: safeHelloLynkId(options.hellolynkId, "human_relationship_owner_invalid"),
    deviceId: safeId(options.deviceId, "human_relationship_owner_invalid"),
    identityKeyId: safeId(options.identityKeyId, "human_relationship_owner_invalid"),
  });
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const targets = new Map();
  const sendAttempts = new Map();

  async function search(input = {}) {
    exactKeys(input, ["mode", "query"], "human_relationship_search_invalid");
    const mode = String(input.mode || "");
    if (!new Set(["hellolynk_id", "nickname"]).has(mode)) {
      throw failure("human_relationship_search_mode_invalid");
    }
    const query = String(input.query || "");
    if (!query || query.length > 200 || (mode === "hellolynk_id" && !HELLOLYNK_ID.test(query))) {
      throw failure("human_relationship_search_query_invalid");
    }
    pruneTargets();
    const result = await cloud.searchDirectory({
      clientSearchId: `human_search_${crypto.randomBytes(18).toString("hex")}`,
      mode,
      query,
    });
    const publicResults = [];
    for (const item of array(result?.results, "human_relationship_search_response_invalid")) {
      const binding = record(item?.hostTarget, "human_relationship_search_response_invalid");
      const expiresAtMs = Date.parse(String(binding.expiresAt || ""));
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now()) {
        throw failure("human_relationship_search_response_invalid");
      }
      const targetRef = `human_target_${crypto.randomBytes(24).toString("hex")}`;
      targets.set(targetRef, Object.freeze({
        targetRef,
        cloudTargetRef: nonEmpty(item.directoryTargetRef, "human_relationship_search_response_invalid"),
        principalId: safeId(binding.principalId, "human_relationship_search_response_invalid"),
        hellolynkId: safeHelloLynkId(binding.hellolynkId, "human_relationship_search_response_invalid"),
        expiresAtMs,
      }));
      publicResults.push(Object.freeze({
        targetRef,
        displayName: safeDisplayName(item.displayName),
        hellolynkId: mode === "hellolynk_id" ? safeHelloLynkId(item.hellolynkId, "human_relationship_search_response_invalid") : null,
        expiresAt: new Date(expiresAtMs).toISOString(),
      }));
    }
    trimTargets();
    return Object.freeze({
      results: Object.freeze(publicResults),
      quota: publicDirectoryQuota(result?.quota),
      exactMatchOnly: true,
      modelCalls: 0,
    });
  }

  async function send(input = {}) {
    exactKeys(input, ["targetRef", "introText"], "human_relationship_send_invalid");
    const targetRef = String(input.targetRef || "");
    pruneTargets();
    const target = targets.get(targetRef);
    if (!target) throw failure("human_relationship_target_expired");
    let attempt = sendAttempts.get(targetRef);
    if (attempt?.result) return attempt.result;
    const finish = (status, quota = null, serverStoredCiphertext = false) => {
      attempt.phase = status;
      attempt.result = publicSendResult(status, quota, serverStoredCiphertext);
      return attempt.result;
    };
    const accepted = validateIntro(input.introText);
    if (!attempt) {
      const commitment = createContactRequestIntroCommitment(accepted.text);
      attempt = {
        phase: "prepared",
        clientRequestId: `human_contact_${crypto.randomBytes(18).toString("hex")}`,
        commitment,
        requestDigest: createContactRequestRecordDigest({
          recipientPrincipalId: target.principalId,
          introDigest: commitment.introDigest,
          introWeight: commitment.introWeight,
        }),
      };
      sendAttempts.set(targetRef, attempt);
    } else {
      const repeated = createContactRequestIntroCommitment(accepted.text, {
        introDigestSalt: attempt.commitment.introDigestSalt,
      });
      if (repeated.introDigest !== attempt.commitment.introDigest) {
        throw failure("human_relationship_retry_input_conflict");
      }
    }

    // Concurrent callers for this exact attempt share its result and envelope.
    // Publish the promise before invoking cloud or crypto dependencies.
    if (attempt.pending) return attempt.pending;
    attempt.pending = Promise.resolve().then(sendPreparedAttempt).finally(() => {
      attempt.pending = null;
    });
    return attempt.pending;

    async function sendPreparedAttempt() {
      const common = {
        directoryTargetRef: target.cloudTargetRef,
        clientRequestId: attempt.clientRequestId,
        introDigest: attempt.commitment.introDigest,
        introWeight: attempt.commitment.introWeight,
        requestDigest: attempt.requestDigest,
      };
      let reserved;
      try {
        reserved = await cloud.reserveContactRequest({
          ...common,
          runtimeHeaders: options.runtimeHeaders,
        });
      } catch (error) {
        if (error?.httpStatus === 409
          && (error?.code === "contact_request_recipient_prekey_unavailable"
            || error?.code === "contact_request_recipient_endpoint_ambiguous")) {
          if (sendAttempts.get(targetRef) === attempt) sendAttempts.delete(targetRef);
          throw error;
        }
        if (!Number.isInteger(error?.httpStatus) || error.httpStatus >= 500) {
          return finish("delivery_unknown");
        }
        throw error;
      }
      const handoff = reserved?.handoff;
      if (!handoff) {
        return finish("delivery_unknown", reserved?.quota);
      }
      validateHandoff(handoff, owner, target, e2ee.identityKeyId || owner.identityKeyId);
      const createdAtMs = now();
      const createdAt = new Date(createdAtMs).toISOString();
      const expiresAt = new Date(Math.min(
        createdAtMs + 7 * 24 * 60 * 60 * 1000,
        Date.parse(String(handoff.claimExpiresAt || "")),
      )).toISOString();
      if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= createdAtMs) {
        throw failure("human_relationship_contact_handoff_expired");
      }
      const protectedMetadata = {
        attemptId: safeId(reserved.attempt?.attemptId, "human_relationship_contact_handoff_invalid"),
        clientRequestId: attempt.clientRequestId,
        requestDigest: attempt.requestDigest,
        introDigest: attempt.commitment.introDigest,
        introWeight: attempt.commitment.introWeight,
        senderPrincipalId: owner.principalId,
        senderHelloLynkId: owner.hellolynkId,
        senderDeviceId: owner.deviceId,
        senderIdentityKeyId: owner.identityKeyId,
        recipientPrincipalId: target.principalId,
        recipientHelloLynkId: target.hellolynkId,
        recipientDeviceId: safeId(handoff.recipient.deviceId, "human_relationship_contact_handoff_invalid"),
        recipientIdentityKeyId: safeId(handoff.recipient.identity?.keyId, "human_relationship_contact_handoff_invalid"),
        recipientPreKeyId: safeId(handoff.recipient.oneTimePreKey?.preKeyId, "human_relationship_contact_handoff_invalid"),
        authorizationScope: CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE,
        intentSource: CONTACT_REQUEST_E2EE_INTENT_SOURCE,
        messageType: CONTACT_REQUEST_E2EE_MESSAGE_TYPE,
        createdAt,
        expiresAt,
      };
      const envelope = await e2ee.sealContactRequestIntro({
        protectedMetadata,
        introDigestSalt: attempt.commitment.introDigestSalt,
        recipientDeviceIdentity: handoff.recipient.identity,
        recipientOneTimePreKey: handoff.recipient.oneTimePreKey,
        introText: accepted.text,
      });
      attempt.phase = "relay_started";
      try {
        const relayed = await cloud.relayContactRequest({
          attemptId: protectedMetadata.attemptId,
          ...common,
          claimId: safeId(handoff.claimId, "human_relationship_contact_handoff_invalid"),
          envelopeDigest: digestContactRequestIntroEnvelope(envelope),
          e2eeEnvelope: envelope,
          runtimeHeaders: options.runtimeHeaders,
        });
        const status = new Set([
          "contact_request_acknowledged",
          "contact_request_queued",
        ]).has(relayed.status)
          ? "submitted"
          : "delivery_unknown";
        // Ciphertext retention is distinct from plaintext storage and delivery.
        // A missing receipt field is unknown, never evidence of non-storage.
        return finish(status, reserved?.quota,
          typeof relayed.serverStoredCiphertext === "boolean" ? relayed.serverStoredCiphertext : null);
      } catch (error) {
        if (!Number.isInteger(error?.httpStatus) || error.httpStatus >= 500) {
          return finish("delivery_unknown", reserved?.quota, null);
        }
        attempt.phase = "prepared";
        throw error;
      }
    }
  }

  async function list(input = {}) {
    record(input, "human_relationship_list_invalid");
    if (Object.keys(input).some((key) => key !== "cursor")) {
      throw failure("human_relationship_list_invalid");
    }
    const cursor = optionalCursor(input.cursor);
    const cloudList = await cloud.listContactRequests(cursor == null ? {} : { cursor });
    const cloudRequests = array(cloudList?.requests, "human_relationship_list_response_invalid");
    const hasMore = cloudList?.hasMore == null ? false : cloudList.hasMore;
    if (typeof hasMore !== "boolean") throw failure("human_relationship_list_response_invalid");
    const nextCursor = optionalCursor(cloudList?.nextCursor);
    if (hasMore !== (nextCursor != null)) {
      throw failure("human_relationship_list_response_invalid");
    }
    const reconciledByRequestId = await reconcileUnresolvedDecisions();
    const pending = await localStore.listPendingAckReceipts();
    const cloudByAttempt = new Map(cloudRequests
      .filter((item) => item.direction === "incoming" && item.hostBinding?.deliveryAttemptId)
      .map((item) => [item.hostBinding.deliveryAttemptId, item]));
    for (const receipt of pending) {
      const remote = cloudByAttempt.get(receipt.attemptId);
      if (!remote) continue;
      await localStore.projectServerState({
        localRecordId: receipt.localRecordId,
        expectedLocalRecordDigest: receipt.localRecordDigest,
        serverContactRequestId: safeId(remote.requestId, "human_relationship_list_response_invalid"),
        state: publicState(remote.status),
        serverUpdatedAt: safeTimestamp(remote.decidedAt || remote.createdAt),
      });
    }
    const boundPending = await localStore.listForHuman();
    const cloudByRequestId = new Map();
    for (const item of cloudRequests) {
      const requestId = safeId(item.requestId, "human_relationship_list_response_invalid");
      const direction = oneOf(
        item.direction,
        ["incoming", "outgoing"],
        "human_relationship_list_response_invalid",
      );
      const status = publicState(item.status);
      if (direction !== "incoming") continue;
      if (cloudByRequestId.has(requestId)) {
        throw failure("human_relationship_list_response_invalid");
      }
      cloudByRequestId.set(requestId, { item, status });
    }
    for (const localRecord of boundPending) {
      if (localRecord.serverContactRequestId == null
        || localRecord.state !== "pending"
        || localRecord.actionReady !== true
        || localRecord.decisionOutcome != null
        || localRecord.decisionAction != null) continue;
      const remote = cloudByRequestId.get(localRecord.serverContactRequestId);
      if (!remote || remote.status === "pending") continue;
      let serverUpdatedAt;
      try {
        serverUpdatedAt = safeTimestamp(remote.item.decidedAt);
      } catch {
        throw failure("human_relationship_list_response_invalid");
      }
      try {
        await localStore.projectServerState({
          localRecordId: localRecord.localRecordId,
          expectedLocalRecordDigest: localRecord.localRecordDigest,
          serverContactRequestId: localRecord.serverContactRequestId,
          state: remote.status,
          serverUpdatedAt,
        });
      } catch (error) {
        // A human decision may have acquired its durable marker after this
        // list snapshot. In that race the marker wins and only the exact
        // point-read path may settle it; never use the broad page as a receipt.
        if (!new Set([
          "contact_request_local_decision_unresolved",
          "contact_request_local_decision_recovery_required",
          "contact_request_local_state_conflict",
        ]).has(error?.code)) throw error;
      }
    }
    const local = await localStore.listForHuman();
    const localByServerId = new Map(local
      .filter((item) => item.serverContactRequestId)
      .map((item) => [item.serverContactRequestId, item]));
    const publicRequests = cloudRequests.map((item) => {
      const requestId = safeId(item.requestId, "human_relationship_list_response_invalid");
      const direction = oneOf(item.direction, ["incoming", "outgoing"], "human_relationship_list_response_invalid");
      const cloudStatus = publicState(item.status);
      const localRecord = localByServerId.get(requestId);
      const reconciliation = reconciledByRequestId.get(requestId) || null;
      const status = reconciledCloudState({
        cloudStatus,
        localRecord,
        reconciliation,
      });
      const localDecisionFields = decisionFieldsForCloudRecord({
        direction,
        status,
        localRecord,
      });
      return Object.freeze({
        requestId,
        direction,
        status,
        ...localDecisionFields,
        otherPrincipal: Object.freeze({
          displayName: safeDisplayName(item.otherPrincipal?.displayName),
          hellolynkId: safeOptionalHelloLynkId(item.otherPrincipal?.hellolynkId),
        }),
        introText: direction === "incoming" && localRecord ? localRecord.introText : null,
        introWeight: direction === "incoming" && localRecord ? localRecord.introWeight : null,
        createdAt: safeTimestamp(item.createdAt),
        decidedAt: reconciliation?.decidedAt
          ?? (item.decidedAt == null ? null : safeTimestamp(item.decidedAt)),
        humanOnly: true,
        modelVisibility: "none",
      });
    });
    for (const request of publicRequests) {
      if (request.direction === "incoming" && request.status === "blocked") {
        await revokeContactAutonomy(request.otherPrincipal.hellolynkId);
      }
    }
    return Object.freeze({
      requests: Object.freeze(publicRequests),
      hasMore,
      nextCursor,
      serverStoredIntro: false,
      serverStoredCiphertext: false,
      modelCalls: 0,
    });
  }

  async function decide(input = {}) {
    exactKeys(input, ["requestId", "action"], "human_relationship_decision_invalid");
    const requestId = safeId(input.requestId, "human_relationship_decision_invalid");
    const action = oneOf(
      input.action,
      ["accept", "reject", "block"],
      "human_relationship_decision_invalid",
    );
    const before = await localStore.listForHuman();
    const local = before.find((item) => item.serverContactRequestId === requestId) || null;
    if (!local || local.state !== "pending" || local.actionReady !== true
      || local.decisionOutcome != null) {
      throw failure("human_relationship_decision_known_failed");
    }
    let decisionAttempt;
    try {
      decisionAttempt = await localStore.beginDecision({
        localRecordId: local.localRecordId,
        expectedLocalRecordDigest: local.localRecordDigest,
        serverContactRequestId: requestId,
        action,
      });
    } catch (error) {
      throw failure("human_relationship_decision_known_failed", {
        cause: error,
        httpStatus: error?.status,
      });
    }

    let result;
    try {
      result = await cloud.decideContactRequest({ requestId, action });
    } catch (error) {
      const reconciliation = await reconcileDecisionAttempt(decisionAttempt);
      if (reconciliation.outcome === "applied") {
        return publicDecisionResult(requestId, action, reconciliation);
      }
      if (reconciliation.outcome === "not_applied") {
        throw failure("human_relationship_decision_not_applied", {
          cause: error,
          httpStatus: error?.httpStatus,
        });
      }
      if (reconciliation.outcome === "pending" && isKnownRemoteFailure(error)) {
        try {
          await abortDecisionAttempt(decisionAttempt);
        } catch (abortError) {
          throw failure("human_relationship_decision_outcome_unknown", { cause: abortError });
        }
        throw failure("human_relationship_decision_known_failed", {
          cause: error,
          httpStatus: error.httpStatus,
        });
      }
      throw failure("human_relationship_decision_outcome_unknown", { cause: error });
    }

    let authoritative;
    try {
      authoritative = normalizeDecisionSuccess(result, requestId, action);
    } catch (error) {
      const reconciliation = await reconcileDecisionAttempt(decisionAttempt);
      if (reconciliation.outcome === "applied") {
        return publicDecisionResult(requestId, action, reconciliation);
      }
      if (reconciliation.outcome === "not_applied") {
        throw failure("human_relationship_decision_not_applied", { cause: error });
      }
      throw failure("human_relationship_decision_outcome_unknown", { cause: error });
    }
    try {
      await localStore.resolveDecision({
        localRecordId: decisionAttempt.localRecordId,
        expectedLocalRecordDigest: decisionAttempt.localRecordDigest,
        serverContactRequestId: decisionAttempt.serverContactRequestId,
        decisionId: decisionAttempt.decisionId,
        state: authoritative.state,
        serverUpdatedAt: authoritative.decidedAt,
      });
    } catch (error) {
      // A concurrent background point-read may have committed this same
      // terminal receipt while the original cloud response was in flight.
      // Accept only that exact durable result; never resend or reinterpret a
      // different decision, missing record or failed local write as success.
      const settled = error?.code === "contact_request_local_decision_cas_conflict"
        ? (await localStore.listForHuman().catch(() => [])).find((item) => (
          item.localRecordId === decisionAttempt.localRecordId
          && item.localRecordDigest === decisionAttempt.localRecordDigest
          && item.serverContactRequestId === requestId
          && item.state === authoritative.state
          && item.serverUpdatedAt === authoritative.decidedAt
          && item.decisionOutcome == null && item.decisionAction == null
        )) : null;
      if (!settled) throw failure("human_relationship_decision_outcome_unknown", { cause: error });
    }
    if (action === "block") {
      await revokeContactAutonomy(local.sender?.hellolynkId);
    }
    return publicDecisionResult(requestId, action, {
      state: authoritative.state,
      relationshipStatus: authoritative.relationshipStatus,
    });
  }

  async function reconcileUnresolvedDecisions() {
    const unresolved = array(
      await localStore.listUnresolvedDecisions(),
      "human_relationship_local_decision_list_invalid",
    );
    const reconciled = new Map();
    for (const decisionAttempt of unresolved) {
      const result = await reconcileDecisionAttempt(decisionAttempt);
      if (result.state != null) {
        reconciled.set(decisionAttempt.serverContactRequestId, result);
      }
    }
    return reconciled;
  }

  async function reconcileDecisionAttempt(decisionAttempt) {
    let authoritative;
    try {
      authoritative = normalizeDecisionPointState(
        await cloud.getContactRequestDecisionState({
          requestId: decisionAttempt.serverContactRequestId,
        }),
        decisionAttempt.serverContactRequestId,
      );
    } catch {
      return Object.freeze({
        outcome: "unknown", state: null, relationshipStatus: null, decidedAt: null,
      });
    }
    const actualState = authoritative.state;
    if (actualState === "pending") {
      return Object.freeze({
        outcome: "pending", state: "pending", relationshipStatus: null, decidedAt: null,
      });
    }
    if (!DECISION_TERMINAL_STATES.has(actualState)) {
      return Object.freeze({
        outcome: "unknown", state: null, relationshipStatus: null, decidedAt: null,
      });
    }
    try {
      await finalizeDecisionAttempt(decisionAttempt, authoritative);
    } catch {
      return Object.freeze({
        outcome: "unknown", state: null, relationshipStatus: null, decidedAt: null,
      });
    }
    if (actualState === "blocked") {
      await revokeBlockedRequestAutonomy(decisionAttempt.serverContactRequestId);
    }
    return Object.freeze({
      outcome: actualState === DECISION_TARGET_STATES[decisionAttempt.action]
        && (decisionAttempt.action !== "block"
          || authoritative.requestDecisionAction === "block")
        ? "applied"
        : "not_applied",
      state: actualState,
      relationshipStatus: authoritative.relationshipStatus,
      decidedAt: authoritative.decidedAt || authoritative.observedAt,
    });
  }

  async function finalizeDecisionAttempt(decisionAttempt, authoritative) {
    const common = {
      localRecordId: decisionAttempt.localRecordId,
      expectedLocalRecordDigest: decisionAttempt.localRecordDigest,
      serverContactRequestId: decisionAttempt.serverContactRequestId,
      state: authoritative.state,
      serverUpdatedAt: authoritative.decidedAt || authoritative.observedAt,
    };
    if (decisionAttempt.recoveryRequired === true) {
      return localStore.projectServerState(common);
    }
    return localStore.resolveDecision({
      ...common,
      decisionId: decisionAttempt.decisionId,
    });
  }

  async function abortDecisionAttempt(decisionAttempt) {
    return localStore.abortDecision({
      localRecordId: decisionAttempt.localRecordId,
      expectedLocalRecordDigest: decisionAttempt.localRecordDigest,
      serverContactRequestId: decisionAttempt.serverContactRequestId,
      decisionId: decisionAttempt.decisionId,
    });
  }

  async function recoverDecision(input = {}) {
    exactKeys(input, ["requestId"], "human_relationship_decision_recovery_invalid");
    const requestId = safeId(input.requestId, "human_relationship_decision_recovery_invalid");
    const local = (await localStore.listForHuman())
      .find((item) => item.serverContactRequestId === requestId) || null;
    if (!local || local.state !== "pending"
      || !new Set(["unknown", "recovery-required"]).has(local.decisionOutcome)) {
      throw failure("human_relationship_decision_recovery_not_required");
    }
    const decisionAttempt = (await localStore.listUnresolvedDecisions())
      .find((item) => item.serverContactRequestId === requestId) || null;
    if (!decisionAttempt) {
      throw failure("human_relationship_decision_outcome_unknown");
    }
    let authoritative;
    try {
      authoritative = normalizeDecisionPointState(
        await cloud.getContactRequestDecisionState({ requestId }),
        requestId,
      );
    } catch (error) {
      throw failure("human_relationship_decision_outcome_unknown", { cause: error });
    }
    if (authoritative.state !== "pending") {
      try {
        await finalizeDecisionAttempt(decisionAttempt, authoritative);
      } catch (error) {
        throw failure("human_relationship_decision_outcome_unknown", { cause: error });
      }
      if (authoritative.state === "blocked") {
        await revokeBlockedRequestAutonomy(decisionAttempt.serverContactRequestId);
      }
      return publicRecoveryResult(requestId, authoritative.state, false);
    }
    try {
      await localStore.recoverDecision({
        localRecordId: decisionAttempt.localRecordId,
        expectedLocalRecordDigest: decisionAttempt.localRecordDigest,
        serverContactRequestId: decisionAttempt.serverContactRequestId,
        decisionId: decisionAttempt.decisionId,
      });
    } catch (error) {
      throw failure("human_relationship_decision_outcome_unknown", { cause: error });
    }
    return publicRecoveryResult(requestId, "pending", true);
  }

  async function clearResolved() {
    const result = await localStore.clearResolvedForHuman();
    const deletedCount = Number(result?.deletedCount);
    if (!Number.isSafeInteger(deletedCount) || deletedCount < 0) {
      throw failure("human_relationship_local_cleanup_invalid");
    }
    return Object.freeze({
      deletedCount,
      localOnly: true,
      modelCalls: 0,
    });
  }

  async function cancel(input = {}) {
    requireMethods(cloud, ["cancelContactRequest"], "human_relationship_cancel_unavailable");
    exactKeys(input, ["requestId"], "human_relationship_cancel_invalid");
    const requestId = safeId(input.requestId, "human_relationship_cancel_invalid");
    let result;
    try {
      result = await cloud.cancelContactRequest({ requestId });
    } catch (error) {
      if (isKnownRemoteFailure(error)) {
        throw failure("human_relationship_cancel_known_failed", {
          cause: error,
          httpStatus: error.httpStatus,
        });
      }
      throw failure("human_relationship_cancel_outcome_unknown", { cause: error });
    }
    const normalized = normalizeCancelSuccess(result, requestId);
    return Object.freeze({ ...normalized, modelCalls: 0 });
  }

  async function listRelationships() {
    return readRelationships({ revokeEndedAuthorization: true });
  }

  async function readRelationships({ revokeEndedAuthorization }) {
    requireMethods(cloud, ["listRelationships"], "human_relationship_relationship_list_unavailable");
    const result = record(
      await cloud.listRelationships(),
      "human_relationship_relationship_list_response_invalid",
    );
    exactKeys(result, ["ok", "relationships"], "human_relationship_relationship_list_response_invalid");
    if (result.ok !== true) throw failure("human_relationship_relationship_list_response_invalid");
    const relationships = array(
        result.relationships,
        "human_relationship_relationship_list_response_invalid",
      ).map(normalizeRelationship);
    if (revokeEndedAuthorization) {
      for (const relationship of relationships) {
        if (relationship.status === "ended") {
          await revokeContactAutonomy(relationship.otherPrincipal.hellolynkId);
        }
      }
      if (typeof contactAuthorizationStore?.synchronizeRelationships === "function") {
        await contactAuthorizationStore.synchronizeRelationships({
          principalId: owner.principalId,
          hellolynkId: owner.hellolynkId,
          relationships,
        });
      }
    }
    return Object.freeze({
      relationships: Object.freeze(relationships),
      modelCalls: 0,
    });
  }

  async function assertActiveRelationship(input = {}) {
    exactKeys(input, ["hellolynkId"], "human_relationship_active_relationship_check_invalid");
    const hellolynkId = safeHelloLynkId(
      input.hellolynkId,
      "human_relationship_active_relationship_check_invalid",
    );
    let relationshipsResult;
    let blocksResult;
    try {
      relationshipsResult = await readRelationships({ revokeEndedAuthorization: false });
      // Read blocks second so an active relationship snapshot can never be
      // accepted on the basis of an older, concurrently completed block page.
      blocksResult = await listBlocks();
    } catch (error) {
      throw failure("human_relationship_active_relationship_check_unavailable", { cause: error });
    }
    const active = relationshipsResult.relationships.some((relationship) => (
      relationship.status === "active"
      && relationship.otherPrincipal.hellolynkId === hellolynkId
    ));
    const blocked = blocksResult.blocks.some((block) => (
      block.status === "active"
      && block.otherPrincipal.hellolynkId === hellolynkId
    ));
    if (!active || blocked) {
      throw failure("human_relationship_active_relationship_required");
    }
    return Object.freeze({ active: true, modelCalls: 0 });
  }

  async function endRelationship(input = {}) {
    requireMethods(cloud, ["endRelationship"], "human_relationship_relationship_end_unavailable");
    exactKeys(input, ["relationshipId"], "human_relationship_relationship_end_invalid");
    const relationshipId = safeId(
      input.relationshipId,
      "human_relationship_relationship_end_invalid",
    );
    let cloudResult;
    try {
      cloudResult = await cloud.endRelationship({ relationshipId });
    } catch (error) {
      if (isKnownRemoteFailure(error)) {
        throw failure("human_relationship_relationship_end_known_failed", {
          cause: error,
          httpStatus: error.httpStatus,
        });
      }
      throw failure("human_relationship_relationship_end_outcome_unknown", { cause: error });
    }
    const result = record(cloudResult, "human_relationship_relationship_end_response_invalid");
    exactKeys(result, ["ok", "relationship"], "human_relationship_relationship_end_response_invalid");
    if (result.ok !== true) throw failure("human_relationship_relationship_end_response_invalid");
    const relationship = normalizeRelationship(result.relationship);
    if (relationship.relationshipId !== relationshipId || relationship.status !== "ended") {
      throw failure("human_relationship_relationship_end_response_invalid");
    }
    await revokeContactAutonomy(relationship.otherPrincipal.hellolynkId);
    return Object.freeze({ relationship, localHistoryDeleted: false, modelCalls: 0 });
  }

  async function listBlocks() {
    requireMethods(cloud, ["listBlocks"], "human_relationship_block_list_unavailable");
    const result = record(await cloud.listBlocks(), "human_relationship_block_list_response_invalid");
    exactKeys(result, ["ok", "blocks"], "human_relationship_block_list_response_invalid");
    if (result.ok !== true) throw failure("human_relationship_block_list_response_invalid");
    const blocks = array(
      result.blocks,
      "human_relationship_block_list_response_invalid",
    ).map((item) => normalizeBlock(item, "active"));
    for (const block of blocks) {
      // The cloud list is authoritative and may reflect a block created on a
      // different device or before this Host restarted. Repair any stale local
      // delegate authorization before returning the visible block state.
      await revokeContactAutonomy(block.otherPrincipal.hellolynkId);
    }
    return Object.freeze({
      blocks: Object.freeze(blocks),
      modelCalls: 0,
    });
  }

  async function removeBlock(input = {}) {
    requireMethods(cloud, ["removeBlock"], "human_relationship_block_remove_unavailable");
    exactKeys(input, ["blockId"], "human_relationship_block_remove_invalid");
    const blockId = safeId(input.blockId, "human_relationship_block_remove_invalid");
    let cloudResult;
    try {
      cloudResult = await cloud.removeBlock({ blockId });
    } catch (error) {
      if (isKnownRemoteFailure(error)) {
        throw failure("human_relationship_block_remove_known_failed", {
          cause: error,
          httpStatus: error.httpStatus,
        });
      }
      throw failure("human_relationship_block_remove_outcome_unknown", { cause: error });
    }
    const result = record(cloudResult, "human_relationship_block_remove_response_invalid");
    exactKeys(result, ["ok", "block"], "human_relationship_block_remove_response_invalid");
    if (result.ok !== true) throw failure("human_relationship_block_remove_response_invalid");
    const block = normalizeBlock(result.block, "removed");
    if (block.blockId !== blockId) throw failure("human_relationship_block_remove_response_invalid");
    return Object.freeze({
      block,
      relationshipRestored: false,
      authorizationRestored: false,
      modelCalls: 0,
    });
  }

  return Object.freeze({
    contractId: HELLOLYNK_HUMAN_RELATIONSHIP_CONTROLLER_CONTRACT,
    search,
    send,
    list,
    decide,
    recoverDecision,
    clearResolved,
    cancel,
    listRelationships,
    assertActiveRelationship,
    endRelationship,
    listBlocks,
    removeBlock,
  });

  async function revokeBlockedRequestAutonomy(requestId) {
    if (!contactAuthorizationStore) return;
    const local = (await localStore.listForHuman())
      .find((item) => item.serverContactRequestId === requestId) || null;
    await revokeContactAutonomy(local?.sender?.hellolynkId);
  }

  async function revokeContactAutonomy(hellolynkId) {
    if (!contactAuthorizationStore || hellolynkId == null) return;
    const acceptedHelloLynkId = safeHelloLynkId(
      hellolynkId,
      "human_relationship_contact_authorization_identity_invalid",
    );
    try {
      await contactAuthorizationStore.revokeAutonomousMessagingByHelloLynkId(
        acceptedHelloLynkId,
      );
    } catch (error) {
      throw failure("human_relationship_local_authorization_revoke_failed", { cause: error });
    }
  }

  function pruneTargets() {
    const observedAt = now();
    for (const [key, value] of targets) {
      if (value.expiresAtMs <= observedAt) {
        targets.delete(key);
        sendAttempts.delete(key);
      }
    }
  }

  function trimTargets() {
    while (targets.size > TARGET_CAPACITY) {
      const oldest = targets.keys().next().value;
      targets.delete(oldest);
      sendAttempts.delete(oldest);
    }
  }
}

function validateHandoff(handoff, owner, target, identityKeyId) {
  record(handoff.sender, "human_relationship_contact_handoff_invalid");
  record(handoff.recipient, "human_relationship_contact_handoff_invalid");
  if (handoff.sender.principalId !== owner.principalId
    || handoff.sender.hellolynkId !== owner.hellolynkId
    || handoff.sender.deviceId !== owner.deviceId
    || handoff.sender.identity?.keyId !== identityKeyId
    || handoff.recipient.principalId !== target.principalId
    || handoff.recipient.hellolynkId !== target.hellolynkId) {
    throw failure("human_relationship_contact_handoff_mismatch");
  }
}

function publicSendResult(status, quota = null, serverStoredCiphertext = false) {
  return Object.freeze({
    status,
    quota: quota ? Object.freeze({
      limit: Number(quota.limit),
      used: Number(quota.used),
      remaining: Number(quota.remaining),
      nextResetAt: String(quota.nextResetAt || ""),
    }) : null,
    serverStoredIntro: false,
    serverStoredCiphertext,
    modelCalls: 0,
  });
}

function publicDirectoryQuota(value) {
  const quota = record(value?.directorySearch, "human_relationship_search_response_invalid");
  return Object.freeze({
    limit: Number(quota.limit),
    remaining: Number(quota.remaining),
    resetsAt: safeTimestamp(quota.resetsAt),
  });
}

function normalizeDecisionSuccess(value, requestId, action) {
  const result = record(value?.result, "human_relationship_decision_response_invalid");
  const required = new Set(["requestId", "action", "status", "idempotent", "decidedAt"]);
  const allowed = new Set(required);
  if (action === "accept") allowed.add("relationshipStatus");
  if (action === "block") allowed.add("blockStatus");
  if (Object.keys(result).some((key) => !allowed.has(key))
    || [...required].some((key) => !Object.hasOwn(result, key))) {
    throw failure("human_relationship_decision_response_invalid");
  }
  if (safeId(result.requestId, "human_relationship_decision_response_invalid") !== requestId
    || oneOf(result.action, ["accept", "reject", "block"], "human_relationship_decision_response_invalid") !== action
    || publicState(result.status) !== DECISION_TARGET_STATES[action]
    || typeof result.idempotent !== "boolean") {
    throw failure("human_relationship_decision_response_invalid");
  }
  const relationshipStatus = action === "accept"
    ? oneOf(result.relationshipStatus, ["active"], "human_relationship_decision_response_invalid")
    : null;
  if (action === "block"
    && oneOf(result.blockStatus, ["active"], "human_relationship_decision_response_invalid") !== "active") {
    throw failure("human_relationship_decision_response_invalid");
  }
  return Object.freeze({
    state: DECISION_TARGET_STATES[action],
    decidedAt: safeTimestamp(result.decidedAt),
    relationshipStatus,
  });
}

function normalizeCancelSuccess(value, requestId) {
  const result = record(value?.result, "human_relationship_cancel_response_invalid");
  exactKeys(result, [
    "requestId", "action", "status", "idempotent", "decidedAt",
  ], "human_relationship_cancel_response_invalid");
  if (safeId(result.requestId, "human_relationship_cancel_response_invalid") !== requestId
    || result.action !== "cancel"
    || result.status !== "cancelled"
    || typeof result.idempotent !== "boolean") {
    throw failure("human_relationship_cancel_response_invalid");
  }
  return Object.freeze({
    requestId,
    status: "cancelled",
    idempotent: result.idempotent,
    decidedAt: safeTimestamp(result.decidedAt),
  });
}

function normalizeRelationship(value) {
  const relationship = record(value, "human_relationship_relationship_response_invalid");
  exactKeys(relationship, [
    "relationshipId", "otherPrincipal", "status", "createdAt", "updatedAt", "endedAt",
  ], "human_relationship_relationship_response_invalid");
  return Object.freeze({
    relationshipId: safeId(
      relationship.relationshipId,
      "human_relationship_relationship_response_invalid",
    ),
    otherPrincipal: normalizeOtherPrincipal(
      relationship.otherPrincipal,
      "human_relationship_relationship_response_invalid",
    ),
    status: oneOf(
      relationship.status,
      ["active", "ended"],
      "human_relationship_relationship_response_invalid",
    ),
    createdAt: safeTimestamp(relationship.createdAt),
    updatedAt: safeTimestamp(relationship.updatedAt),
    endedAt: relationship.endedAt == null ? null : safeTimestamp(relationship.endedAt),
  });
}

function normalizeBlock(value, expectedStatus) {
  const block = record(value, "human_relationship_block_response_invalid");
  const keys = expectedStatus === "removed"
    ? ["blockId", "otherPrincipal", "status", "createdAt", "removedAt"]
    : ["blockId", "otherPrincipal", "status", "createdAt"];
  exactKeys(block, keys, "human_relationship_block_response_invalid");
  if (block.status !== expectedStatus) throw failure("human_relationship_block_response_invalid");
  return Object.freeze({
    blockId: safeId(block.blockId, "human_relationship_block_response_invalid"),
    otherPrincipal: normalizeOtherPrincipal(
      block.otherPrincipal,
      "human_relationship_block_response_invalid",
    ),
    status: expectedStatus,
    createdAt: safeTimestamp(block.createdAt),
    ...(expectedStatus === "removed" ? { removedAt: safeTimestamp(block.removedAt) } : {}),
  });
}

function normalizeOtherPrincipal(value, code) {
  const principal = record(value, code);
  exactKeys(principal, ["displayName", "hellolynkId", "hellolynkIdPurpose"], code);
  if (principal.hellolynkIdPurpose !== "human_identity_verification_only") throw failure(code);
  return Object.freeze({
    displayName: safeDisplayName(principal.displayName),
    hellolynkId: safeHelloLynkId(principal.hellolynkId, code),
  });
}

function normalizeDecisionPointState(value, requestId) {
  const result = record(value, "human_relationship_decision_state_invalid");
  exactKeys(result, [
    "ok",
    "requestId",
    "status",
    "decidedAt",
    "requestDecisionAction",
    "viewerBlockStatus",
    "relationshipStatus",
    "observedAt",
  ], "human_relationship_decision_state_invalid");
  if (result.ok !== true
    || safeId(result.requestId, "human_relationship_decision_state_invalid") !== requestId) {
    throw failure("human_relationship_decision_state_invalid");
  }
  const state = publicState(result.status);
  const requestDecisionAction = result.requestDecisionAction == null
    ? null
    : oneOf(
        result.requestDecisionAction,
        ["block"],
        "human_relationship_decision_state_invalid",
      );
  if ((state === "blocked") !== (requestDecisionAction === "block")) {
    throw failure("human_relationship_decision_state_invalid");
  }
  const decidedAt = result.decidedAt == null ? null : safeTimestamp(result.decidedAt);
  if (state !== "pending" && decidedAt == null) {
    throw failure("human_relationship_decision_state_invalid");
  }
  return Object.freeze({
    state,
    decidedAt,
    requestDecisionAction,
    viewerBlockStatus: oneOf(
      result.viewerBlockStatus,
      ["active", "none"],
      "human_relationship_decision_state_invalid",
    ),
    relationshipStatus: result.relationshipStatus == null
      ? null
      : oneOf(result.relationshipStatus, ["active", "ended"], "human_relationship_decision_state_invalid"),
    observedAt: safeTimestamp(result.observedAt),
  });
}

function publicDecisionResult(requestId, action, result) {
  return Object.freeze({
    requestId,
    action,
    status: result.state,
    relationshipStatus: result.relationshipStatus === "active" ? "active" : null,
    modelCalls: 0,
  });
}

function publicRecoveryResult(requestId, status, recovered) {
  return Object.freeze({
    requestId,
    status,
    recovered,
    requiresNewDecision: recovered,
    remoteDecisionWrites: 0,
    modelCalls: 0,
  });
}

function isKnownRemoteFailure(error) {
  return Number.isInteger(error?.httpStatus)
    && error.httpStatus >= 400
    && error.httpStatus < 500;
}

function validateIntro(value) {
  try {
    return validateContactRequestIntro(value);
  } catch (error) {
    throw failure(String(error?.code || "contact_request_intro_invalid"), { cause: error });
  }
}

function publicState(value) {
  const state = String(value || "");
  if (state === "cancelled_by_block") return "cancelled";
  if (state === "cancelled_by_sender" || state === "superseded") {
    return "cancelled";
  }
  return oneOf(state, ["pending", "accepted", "rejected", "cancelled", "blocked", "expired"],
    "human_relationship_state_invalid");
}

function reconciledCloudState({ cloudStatus, localRecord, reconciliation }) {
  if (reconciliation?.state != null) return reconciliation.state;
  if (localRecord?.state === "pending"
    && new Set(["unknown", "recovery-required"]).has(localRecord.decisionOutcome)) {
    return "pending";
  }
  if (cloudStatus === "pending" && localRecord?.state != null
    && localRecord.state !== "pending") return localRecord.state;
  return cloudStatus;
}

function decisionFieldsForCloudRecord({ direction, status, localRecord }) {
  if (direction !== "incoming") {
    return Object.freeze({
      actionReady: false,
      decisionOutcome: null,
      decisionAction: null,
    });
  }
  const consistent = localRecord
    && localRecord.state === status
    && typeof localRecord.actionReady === "boolean"
    && new Set([null, "unknown", "recovery-required"]).has(localRecord.decisionOutcome)
    && (localRecord.decisionAction == null
      || new Set(["accept", "reject", "block"]).has(localRecord.decisionAction))
    && ((localRecord.decisionOutcome === "unknown")
      === (localRecord.decisionAction != null));
  if (!consistent) {
    return Object.freeze({
      actionReady: false,
      decisionOutcome: null,
      decisionAction: null,
    });
  }
  const actionReady = status === "pending"
    && localRecord.actionReady === true
    && localRecord.decisionOutcome == null
    && localRecord.decisionAction == null;
  const decisionOutcome = localRecord.decisionOutcome;
  const decisionAction = decisionOutcome === "unknown" ? localRecord.decisionAction : null;
  if ((decisionOutcome === "unknown") !== (decisionAction != null)
    || (decisionOutcome === "recovery-required" && decisionAction != null)) {
    return Object.freeze({
      actionReady: false,
      decisionOutcome: null,
      decisionAction: null,
    });
  }
  return Object.freeze({ actionReady, decisionOutcome, decisionAction });
}

function requireMethods(value, methods, code) {
  if (!value || methods.some((method) => typeof value[method] !== "function")) throw failure(code);
  return value;
}

function exactKeys(value, keys, code) {
  record(value, code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw failure(code);
  }
}

function record(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure(code);
  return value;
}

function array(value, code) {
  if (!Array.isArray(value)) throw failure(code);
  return value;
}

function safeId(value, code) {
  const text = String(value || "");
  if (!SAFE_ID.test(text)) throw failure(code);
  return text;
}

function safeHelloLynkId(value, code) {
  const text = String(value || "");
  if (!HELLOLYNK_ID.test(text)) throw failure(code);
  return text;
}

function safeOptionalHelloLynkId(value) {
  return value == null ? null : safeHelloLynkId(value, "human_relationship_list_response_invalid");
}

function safeDisplayName(value) {
  if (value == null) return null;
  const text = String(value);
  if (!text || text.length > 80 || /[\u0000-\u001f\u007f-\u009f]/u.test(text)) {
    throw failure("human_relationship_display_name_invalid");
  }
  return text;
}

function safeTimestamp(value) {
  const text = String(value || "");
  if (!Number.isFinite(Date.parse(text))) throw failure("human_relationship_timestamp_invalid");
  return text;
}

function optionalCursor(value) {
  if (value == null) return null;
  const cursor = String(value);
  if (!/^[A-Za-z0-9_-]{20,512}$/.test(cursor)) {
    throw failure("human_relationship_list_response_invalid");
  }
  return cursor;
}

function nonEmpty(value, code) {
  const text = String(value || "");
  if (!text || text.length > 4_096) throw failure(code);
  return text;
}

function oneOf(value, allowed, code) {
  const text = String(value || "");
  if (!allowed.includes(text)) throw failure(code);
  return text;
}

function failure(code, options = {}) {
  return new HelloLynkHumanRelationshipControllerError(code, options);
}
