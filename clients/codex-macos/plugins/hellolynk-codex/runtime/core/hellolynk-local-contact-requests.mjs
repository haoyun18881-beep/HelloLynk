import crypto from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";

import { defaultHelloLynkClientRoot } from "./hellolynk-client-profile.mjs";
import {
  CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE,
  CONTACT_REQUEST_E2EE_INTENT_SOURCE,
  CONTACT_REQUEST_E2EE_MAX_TTL_MS,
  CONTACT_REQUEST_E2EE_MESSAGE_TYPE,
  contactRequestIntroReplayKey,
  createContactRequestIntroCommitment,
  createContactRequestRecordDigest,
  validateContactRequestIntro,
} from "./hellolynk-contact-request-e2ee.mjs";
import { assertLocalDataProtectionAccess } from "./hellolynk-local-data-protection.mjs";

export const LOCAL_CONTACT_REQUEST_STORE_CONTRACT = "hellolynk-contact-request-local-store-v2";

const STORE_SCHEMA_VERSION = 2;
const LEGACY_STORE_SCHEMA_VERSION = 1;
const STORE_DIRECTORY_NAME = "contact-requests";
const DEFAULT_MAX_STORE_BYTES = 2 * 1024 * 1024;
const MIN_MAX_STORE_BYTES = 4 * 1024;
const DEFAULT_MAX_RECORDS = 500;
const MAX_CONFIGURED_RECORDS = 2_000;
const MAX_LOCK_BYTES = 16 * 1024;
const LOCK_WAIT_MS = 20;
const LOCK_ATTEMPTS = 100;
const LOCK_STALE_MS = 5_000;
const WINDOWS_TRANSIENT_FS_CODES = new Set(["EACCES", "EBUSY", "EPERM"]);
const WINDOWS_TRANSIENT_FS_RETRY_MS = Object.freeze([0, 5, 10, 25, 50, 100, 200]);
const MAX_RELAY_CLOCK_SKEW_MS = 5 * 60_000;
const MAX_ENVELOPE_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_ACK_WINDOW_MS = 60_000;
const LOCAL_RECORD_DIGEST_DOMAIN = "hellolynk/contact-request/local-record/v2\0";
const PROFILE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/;
const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,199}$/;
const LOCAL_RECORD_ID_RE = /^local_contact_request_[a-f0-9-]{36}$/;
const HELLOLYNK_ID_RE = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const BASE64URL_16_RE = /^[A-Za-z0-9_-]{22}$/;
const UNSAFE_DISPLAY_RE = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const STORE_KEYS = Object.freeze(["schemaVersion", "contractId", "profileId", "records"]);
const INCOMING_KEYS = Object.freeze([
  "eventId",
  "attemptId",
  "clientRequestId",
  "connectionId",
  "claimId",
  "replayKey",
  "envelopeDigest",
  "requestDigest",
  "introDigest",
  "introDigestSalt",
  "introWeight",
  "introText",
  "senderPrincipalId",
  "senderHelloLynkId",
  "senderPrincipalDisplayName",
  "senderDeviceId",
  "senderIdentityKeyId",
  "recipientPrincipalId",
  "recipientHelloLynkId",
  "recipientDeviceId",
  "recipientIdentityKeyId",
  "recipientPreKeyId",
  "createdAt",
  "expiresAt",
  "relayedAt",
  "ackDeadlineAt",
]);
const RECORD_KEYS = Object.freeze([
  "localRecordId",
  "localRecordDigest",
  ...INCOMING_KEYS,
  "state",
  "serverContactRequestId",
  "serverUpdatedAt",
  "decisionAttempt",
  "decisionRecoveryRequired",
  "receivedAt",
  "updatedAt",
]);
const LEGACY_RECORD_KEYS = Object.freeze(RECORD_KEYS.filter((key) => (
  key !== "decisionAttempt" && key !== "decisionRecoveryRequired"
)));
const PROJECTION_KEYS = Object.freeze([
  "localRecordId",
  "expectedLocalRecordDigest",
  "serverContactRequestId",
  "state",
  "serverUpdatedAt",
]);
const HUMAN_LIST_OPTION_KEYS = Object.freeze(["states", "limit"]);
const PROJECTION_STATES = new Set([
  "pending", "accepted", "rejected", "cancelled", "blocked", "expired",
]);
const FINAL_PROJECTION_STATES = new Set([
  "accepted", "rejected", "cancelled", "blocked", "expired",
]);
const DECISION_ACTIONS = new Set(["accept", "reject", "block"]);
const DECISION_ATTEMPT_KEYS = Object.freeze(["decisionId", "action", "startedAt"]);
const BEGIN_DECISION_KEYS = Object.freeze([
  "localRecordId",
  "expectedLocalRecordDigest",
  "serverContactRequestId",
  "action",
]);
const ABORT_DECISION_KEYS = Object.freeze([
  "localRecordId",
  "expectedLocalRecordDigest",
  "serverContactRequestId",
  "decisionId",
]);
const RECOVER_DECISION_KEYS = ABORT_DECISION_KEYS;
const RESOLVE_DECISION_KEYS = Object.freeze([
  "localRecordId",
  "expectedLocalRecordDigest",
  "serverContactRequestId",
  "decisionId",
  "state",
  "serverUpdatedAt",
]);
const pathMutationQueues = new Map();

export class HelloLynkLocalContactRequestsError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkLocalContactRequestsError";
    this.code = code;
    this.status = Number.isInteger(options.status) ? options.status : null;
    this.retryable = options.retryable === true;
  }
}

export function resolveLocalContactRequestsPath(options = {}) {
  assertPlainRecord(options, "contact_request_store_options_invalid");
  assertOnlyKnownFields(options, ["profileId", "root"], "contact_request_store_options_invalid");
  const profileId = normalizeProfileId(options.profileId);
  const root = path.resolve(options.root || defaultHelloLynkClientRoot());
  return path.join(root, STORE_DIRECTORY_NAME, `${profileId}.json`);
}

export function createLocalContactRequestStore(options = {}) {
  assertPlainRecord(options, "contact_request_store_options_invalid");
  assertOnlyKnownFields(
    options,
    ["profileId", "root", "storePath", "now", "maxStoreBytes", "maxRecords", "dataProtector"],
    "contact_request_store_options_invalid",
  );
  const profileId = normalizeProfileId(options.profileId);
  if (options.root != null && options.storePath != null) {
    throw new HelloLynkLocalContactRequestsError("contact_request_store_path_options_conflict");
  }
  const storePath = path.resolve(options.storePath || resolveLocalContactRequestsPath({
    profileId,
    root: options.root,
  }));
  const layout = resolveStoreLayout(storePath, profileId);
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const maximumBytes = normalizeMaximumBytes(options.maxStoreBytes);
  const maximumRecords = normalizeMaximumRecords(options.maxRecords);
  const protection = normalizeContactRequestDataProtection(options.dataProtector, profileId);

  async function mutate(callback) {
    return withPathMutationQueue(storePath, async () => {
      const store = await readStore(layout, profileId, maximumBytes, maximumRecords, protection);
      const result = await callback(store);
      await atomicWriteStore(layout, store, maximumBytes, protection);
      return result;
    });
  }

  async function persistIncoming(input) {
    const accepted = normalizeIncoming(input);
    const receivedAt = normalizeCurrentTimestamp(now());
    assertCurrentReceiveWindow(accepted, Date.parse(receivedAt));
    return mutate((store) => {
      const replay = store.records.find((record) => record.replayKey === accepted.replayKey);
      if (replay) {
        if (replay.envelopeDigest !== accepted.envelopeDigest) {
          throw new HelloLynkLocalContactRequestsError("contact_request_local_replay_conflict", {
            status: 409,
          });
        }
        return acknowledgementReceipt(replay, true);
      }
      const conflictingOuterIdentity = store.records.find((record) => (
        record.eventId === accepted.eventId
        || record.attemptId === accepted.attemptId
        || (
          record.senderPrincipalId === accepted.senderPrincipalId
          && record.clientRequestId === accepted.clientRequestId
        )
      ));
      if (conflictingOuterIdentity) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_identity_conflict", {
          status: 409,
        });
      }
      if (store.records.length >= maximumRecords) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_capacity_exceeded", {
          status: 507,
        });
      }
      const localRecordId = `local_contact_request_${crypto.randomUUID()}`;
      const record = {
        localRecordId,
        localRecordDigest: "",
        ...accepted,
        state: "pending",
        serverContactRequestId: null,
        serverUpdatedAt: null,
        decisionAttempt: null,
        decisionRecoveryRequired: false,
        receivedAt,
        updatedAt: receivedAt,
      };
      record.localRecordDigest = digestImmutableRecord(record);
      store.records.push(record);
      return acknowledgementReceipt(record, false);
    });
  }

  async function projectServerState(input) {
    const projection = normalizeProjection(input);
    return mutate((store) => {
      const record = store.records.find((item) => item.localRecordId === projection.localRecordId);
      if (!record) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_record_not_found", {
          status: 404,
        });
      }
      if (record.localRecordDigest !== projection.expectedLocalRecordDigest) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_record_digest_mismatch", {
          status: 409,
        });
      }
      if (
        record.serverContactRequestId != null
        && record.serverContactRequestId !== projection.serverContactRequestId
      ) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_server_id_conflict", {
          status: 409,
        });
      }
      if (record.decisionAttempt != null) {
        if (record.state === "pending" && projection.state === "pending") {
          return projectionReceipt(record, true);
        }
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_unresolved", {
          status: 409,
        });
      }
      if (record.decisionRecoveryRequired) {
        if (record.state === "pending" && projection.state === "pending") {
          return projectionReceipt(record, true);
        }
        if (!FINAL_PROJECTION_STATES.has(projection.state)) {
          throw new HelloLynkLocalContactRequestsError(
            "contact_request_local_decision_recovery_required",
            { status: 409 },
          );
        }
      }
      if (record.state === projection.state) {
        if (record.serverContactRequestId == null) {
          record.serverContactRequestId = projection.serverContactRequestId;
          record.serverUpdatedAt = projection.serverUpdatedAt;
          record.updatedAt = normalizeCurrentTimestamp(now());
          return projectionReceipt(record, false);
        }
        return projectionReceipt(record, true);
      }
      const transitionAllowed = (
        (record.state === "pending" && FINAL_PROJECTION_STATES.has(projection.state))
        || (record.state !== "blocked" && projection.state === "blocked")
      );
      if (!transitionAllowed) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_state_conflict", {
          status: 409,
        });
      }
      record.serverContactRequestId = projection.serverContactRequestId;
      record.state = projection.state;
      record.serverUpdatedAt = projection.serverUpdatedAt;
      record.decisionRecoveryRequired = false;
      record.updatedAt = normalizeCurrentTimestamp(now());
      return projectionReceipt(record, false);
    });
  }

  async function beginDecision(input) {
    const accepted = normalizeBeginDecision(input);
    return mutate((store) => {
      const record = requireDecisionRecord(store, accepted);
      if (record.state !== "pending" || record.serverContactRequestId == null) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_not_pending", {
          status: 409,
        });
      }
      if (record.decisionRecoveryRequired) {
        throw new HelloLynkLocalContactRequestsError(
          "contact_request_local_decision_recovery_required",
          { status: 409 },
        );
      }
      if (record.decisionAttempt != null) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_unresolved", {
          status: 409,
        });
      }
      const decisionAttempt = {
        decisionId: `contact_decision_${crypto.randomUUID()}`,
        action: accepted.action,
        startedAt: normalizeCurrentTimestamp(now()),
      };
      record.decisionAttempt = decisionAttempt;
      record.updatedAt = decisionAttempt.startedAt;
      return decisionAttemptReceipt(record);
    });
  }

  async function abortDecision(input) {
    const accepted = normalizeAbortDecision(input);
    return mutate((store) => {
      const record = requireDecisionRecord(store, accepted);
      assertDecisionCas(record, accepted.decisionId);
      if (record.state !== "pending") {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_not_pending", {
          status: 409,
        });
      }
      record.decisionAttempt = null;
      record.decisionRecoveryRequired = false;
      record.updatedAt = normalizeCurrentTimestamp(now());
      return decisionAttemptReceipt(record);
    });
  }

  async function resolveDecision(input) {
    const accepted = normalizeResolveDecision(input);
    return mutate((store) => {
      const record = requireDecisionRecord(store, accepted);
      assertDecisionCas(record, accepted.decisionId);
      if (record.state !== "pending") {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_not_pending", {
          status: 409,
        });
      }
      record.state = accepted.state;
      record.serverUpdatedAt = accepted.serverUpdatedAt;
      record.decisionAttempt = null;
      record.decisionRecoveryRequired = false;
      record.updatedAt = normalizeCurrentTimestamp(now());
      return projectionReceipt(record, false);
    });
  }

  async function recoverDecision(input) {
    const accepted = normalizeRecoverDecision(input);
    return mutate((store) => {
      const record = requireDecisionRecord(store, accepted);
      if (record.state !== "pending" || record.serverContactRequestId == null) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_not_pending", {
          status: 409,
        });
      }
      if (record.decisionRecoveryRequired) {
        if (accepted.decisionId !== null || record.decisionAttempt != null) {
          throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_cas_conflict", {
            status: 409,
          });
        }
      } else if (record.decisionAttempt != null) {
        assertDecisionCas(record, accepted.decisionId);
      } else {
        throw new HelloLynkLocalContactRequestsError(
          "contact_request_local_decision_recovery_not_required",
          { status: 409 },
        );
      }
      record.decisionAttempt = null;
      record.decisionRecoveryRequired = false;
      record.updatedAt = normalizeCurrentTimestamp(now());
      return decisionAttemptReceipt(record);
    });
  }

  async function listUnresolvedDecisions() {
    const store = await readStore(layout, profileId, maximumBytes, maximumRecords, protection);
    return store.records
      .filter((record) => record.decisionAttempt != null || record.decisionRecoveryRequired)
      .sort((left, right) => left.receivedAt.localeCompare(right.receivedAt))
      .map(unresolvedDecisionProjection);
  }

  async function listForHuman(input = {}) {
    assertPlainRecord(input, "contact_request_human_list_options_invalid");
    assertOnlyKnownFields(input, HUMAN_LIST_OPTION_KEYS, "contact_request_human_list_options_invalid");
    const states = normalizeHumanStates(input.states);
    const limit = normalizeHumanLimit(input.limit, maximumRecords);
    const store = await readStore(layout, profileId, maximumBytes, maximumRecords, protection);
    return store.records
      .filter((record) => states.has(record.state))
      .sort((left, right) => right.receivedAt.localeCompare(left.receivedAt))
      .slice(0, limit)
      .map(humanProjection);
  }

  async function snapshotMetadata() {
    const store = await readStore(layout, profileId, maximumBytes, maximumRecords, protection);
    const counts = Object.fromEntries([...PROJECTION_STATES].map((state) => [state, 0]));
    for (const record of store.records) counts[record.state] += 1;
    return Object.freeze({
      schemaVersion: STORE_SCHEMA_VERSION,
      contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
      profileId,
      count: store.records.length,
      counts: Object.freeze(counts),
      storage: "local_file",
      humanOnly: true,
      modelVisibility: "none",
    });
  }

  async function clearResolvedForHuman() {
    return mutate((store) => {
      const retained = store.records.filter((record) => !(
        FINAL_PROJECTION_STATES.has(record.state)
        && record.serverContactRequestId != null
      ));
      const deletedCount = store.records.length - retained.length;
      store.records = retained;
      return Object.freeze({ deletedCount });
    });
  }

  return Object.freeze({
    schemaVersion: STORE_SCHEMA_VERSION,
    contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
    profileId,
    path: storePath,
    persistIncoming,
    projectServerState,
    beginDecision,
    abortDecision,
    resolveDecision,
    recoverDecision,
    listUnresolvedDecisions,
    listForHuman,
    listPendingForHuman: () => listForHuman({ states: ["pending"] }),
    listPendingAckReceipts: async () => {
      const store = await readStore(layout, profileId, maximumBytes, maximumRecords, protection);
      return store.records
        .filter((record) => record.serverContactRequestId == null)
        .sort((left, right) => left.receivedAt.localeCompare(right.receivedAt))
        .map((record) => acknowledgementReceipt(record, true));
    },
    snapshotMetadata,
    clearResolvedForHuman,
  });
}

function emptyStore(profileId) {
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
    profileId,
    records: [],
  };
}

function normalizeIncoming(input) {
  assertExactFields(input, INCOMING_KEYS, "contact_request_local_input_invalid");
  let acceptedIntro;
  try {
    acceptedIntro = validateContactRequestIntro(input.introText);
  } catch (error) {
    throw new HelloLynkLocalContactRequestsError(
      String(error?.code || "contact_request_intro_invalid"),
      { cause: error },
    );
  }
  const introDigestSalt = normalizeDigestSalt(input.introDigestSalt);
  let commitment;
  try {
    commitment = createContactRequestIntroCommitment(acceptedIntro.text, { introDigestSalt });
  } catch (error) {
    throw new HelloLynkLocalContactRequestsError(
      String(error?.code || "contact_request_local_intro_commitment_invalid"),
      { cause: error },
    );
  }
  const introDigest = normalizeDigest(input.introDigest, "contact_request_intro_digest_invalid");
  const introWeight = input.introWeight;
  if (commitment.introDigest !== introDigest || commitment.introWeight !== introWeight) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_intro_commitment_mismatch", {
      status: 409,
    });
  }
  const recipientPrincipalId = normalizeId(
    input.recipientPrincipalId,
    "contact_request_recipient_principal_invalid",
  );
  const requestDigest = normalizeDigest(input.requestDigest, "contact_request_request_digest_invalid");
  let expectedRequestDigest;
  try {
    expectedRequestDigest = createContactRequestRecordDigest({
      recipientPrincipalId,
      introDigest,
      introWeight,
    });
  } catch (error) {
    throw new HelloLynkLocalContactRequestsError(
      String(error?.code || "contact_request_local_request_digest_invalid"),
      { cause: error },
    );
  }
  if (expectedRequestDigest !== requestDigest) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_request_digest_mismatch", {
      status: 409,
    });
  }
  const accepted = {
    eventId: normalizeId(input.eventId, "contact_request_event_id_invalid"),
    attemptId: normalizeId(input.attemptId, "contact_request_attempt_id_invalid"),
    clientRequestId: normalizeId(input.clientRequestId, "contact_request_client_id_invalid"),
    connectionId: normalizeId(
      input.connectionId,
      "contact_request_connection_id_invalid",
    ),
    claimId: normalizeId(input.claimId, "contact_request_claim_id_invalid"),
    replayKey: normalizeDigest(input.replayKey, "contact_request_replay_key_invalid"),
    envelopeDigest: normalizeDigest(
      input.envelopeDigest,
      "contact_request_envelope_digest_invalid",
    ),
    requestDigest,
    introDigest,
    introDigestSalt,
    introWeight,
    introText: acceptedIntro.text,
    senderPrincipalId: normalizeId(
      input.senderPrincipalId,
      "contact_request_sender_principal_invalid",
    ),
    senderHelloLynkId: normalizeHelloLynkId(input.senderHelloLynkId, "contact_request_sender_hellolynk_id_invalid"),
    senderPrincipalDisplayName: normalizeOptionalDisplayName(input.senderPrincipalDisplayName),
    senderDeviceId: normalizeId(input.senderDeviceId, "contact_request_sender_device_invalid"),
    senderIdentityKeyId: normalizeId(
      input.senderIdentityKeyId,
      "contact_request_sender_identity_invalid",
    ),
    recipientPrincipalId,
    recipientHelloLynkId: normalizeHelloLynkId(
      input.recipientHelloLynkId,
      "contact_request_recipient_hellolynk_id_invalid",
    ),
    recipientDeviceId: normalizeId(
      input.recipientDeviceId,
      "contact_request_recipient_device_invalid",
    ),
    recipientIdentityKeyId: normalizeId(
      input.recipientIdentityKeyId,
      "contact_request_recipient_identity_invalid",
    ),
    recipientPreKeyId: normalizeId(
      input.recipientPreKeyId,
      "contact_request_recipient_prekey_invalid",
    ),
    createdAt: normalizeTimestamp(input.createdAt, "contact_request_created_at_invalid"),
    expiresAt: normalizeTimestamp(input.expiresAt, "contact_request_expires_at_invalid"),
    relayedAt: normalizeTimestamp(input.relayedAt, "contact_request_relayed_at_invalid"),
    ackDeadlineAt: normalizeTimestamp(
      input.ackDeadlineAt,
      "contact_request_ack_deadline_invalid",
    ),
  };
  if (accepted.senderPrincipalId === accepted.recipientPrincipalId) {
    throw new HelloLynkLocalContactRequestsError("contact_request_self_target_invalid");
  }
  const createdAtMs = Date.parse(accepted.createdAt);
  const expiresAtMs = Date.parse(accepted.expiresAt);
  const relayedAtMs = Date.parse(accepted.relayedAt);
  const ackDeadlineAtMs = Date.parse(accepted.ackDeadlineAt);
  if (
    expiresAtMs <= createdAtMs
    || expiresAtMs - createdAtMs > CONTACT_REQUEST_E2EE_MAX_TTL_MS
    || relayedAtMs < createdAtMs - MAX_RELAY_CLOCK_SKEW_MS
    || relayedAtMs >= expiresAtMs
    || ackDeadlineAtMs <= relayedAtMs
    || ackDeadlineAtMs - relayedAtMs > MAX_ACK_WINDOW_MS
  ) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_timestamp_order_invalid");
  }
  let expectedReplayKey;
  try {
    expectedReplayKey = contactRequestIntroReplayKey({
      attemptId: accepted.attemptId,
      clientRequestId: accepted.clientRequestId,
      requestDigest: accepted.requestDigest,
      introDigest: accepted.introDigest,
      introWeight: accepted.introWeight,
      senderPrincipalId: accepted.senderPrincipalId,
      senderHelloLynkId: accepted.senderHelloLynkId,
      senderDeviceId: accepted.senderDeviceId,
      senderIdentityKeyId: accepted.senderIdentityKeyId,
      recipientPrincipalId: accepted.recipientPrincipalId,
      recipientHelloLynkId: accepted.recipientHelloLynkId,
      recipientDeviceId: accepted.recipientDeviceId,
      recipientIdentityKeyId: accepted.recipientIdentityKeyId,
      recipientPreKeyId: accepted.recipientPreKeyId,
      authorizationScope: CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE,
      intentSource: CONTACT_REQUEST_E2EE_INTENT_SOURCE,
      messageType: CONTACT_REQUEST_E2EE_MESSAGE_TYPE,
      createdAt: accepted.createdAt,
      expiresAt: accepted.expiresAt,
    });
  } catch (error) {
    throw new HelloLynkLocalContactRequestsError(
      String(error?.code || "contact_request_local_replay_key_invalid"),
      { cause: error },
    );
  }
  if (!constantTimeDigestEqual(expectedReplayKey, accepted.replayKey)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_replay_key_mismatch", {
      status: 409,
    });
  }
  return Object.freeze(accepted);
}

function assertCurrentReceiveWindow(incoming, nowMs) {
  // The relay ACK deadline only ends the synchronous wait. A delivery_unknown attempt may still
  // be durably persisted and late-ACKed while its signed E2EE envelope remains unexpired.
  if (Date.parse(incoming.expiresAt) <= nowMs) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_envelope_expired", {
      status: 409,
    });
  }
  if (
    Date.parse(incoming.createdAt) > nowMs + MAX_ENVELOPE_CLOCK_SKEW_MS
    || Date.parse(incoming.relayedAt) > nowMs + MAX_ENVELOPE_CLOCK_SKEW_MS
  ) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_timestamp_in_future", {
      status: 409,
    });
  }
}

function normalizeStoredRecord(input, schemaVersion) {
  assertExactFields(
    input,
    schemaVersion === LEGACY_STORE_SCHEMA_VERSION ? LEGACY_RECORD_KEYS : RECORD_KEYS,
    "contact_request_local_store_invalid",
  );
  const immutable = normalizeIncoming(Object.fromEntries(
    INCOMING_KEYS.map((key) => [key, input[key]]),
  ));
  const record = {
    localRecordId: normalizeLocalRecordId(input.localRecordId),
    localRecordDigest: normalizeDigest(
      input.localRecordDigest,
      "contact_request_local_record_digest_invalid",
    ),
    ...immutable,
    state: normalizeProjectionState(input.state),
    serverContactRequestId: input.serverContactRequestId == null
      ? null
      : normalizeId(
          input.serverContactRequestId,
          "contact_request_server_request_id_invalid",
        ),
    serverUpdatedAt: input.serverUpdatedAt == null
      ? null
      : normalizeTimestamp(
          input.serverUpdatedAt,
          "contact_request_server_updated_at_invalid",
        ),
    decisionAttempt: schemaVersion === LEGACY_STORE_SCHEMA_VERSION
      ? null
      : normalizeDecisionAttempt(input.decisionAttempt),
    decisionRecoveryRequired: schemaVersion === LEGACY_STORE_SCHEMA_VERSION
      ? false
      : normalizeStoredBoolean(
          input.decisionRecoveryRequired,
          "contact_request_local_decision_recovery_invalid",
        ),
    receivedAt: normalizeTimestamp(input.receivedAt, "contact_request_received_at_invalid"),
    updatedAt: normalizeTimestamp(input.updatedAt, "contact_request_updated_at_invalid"),
  };
  if ((record.serverContactRequestId == null) !== (record.serverUpdatedAt == null)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  if (record.state !== "pending" && record.serverContactRequestId == null) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  if (record.decisionAttempt != null
    && (record.state !== "pending" || record.serverContactRequestId == null)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  if (schemaVersion === LEGACY_STORE_SCHEMA_VERSION
    && record.state === "pending"
    && record.serverContactRequestId != null) {
    record.decisionRecoveryRequired = true;
  }
  if (record.decisionRecoveryRequired
    && (record.state !== "pending"
      || record.serverContactRequestId == null
      || record.decisionAttempt != null)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  // Local wall-clock timestamps are observations, not an ordering guarantee:
  // automatic clock correction must not make durable requests unreadable.
  // State transitions, immutable digests and replay IDs remain authoritative.
  const expectedDigest = digestImmutableRecord(record);
  if (!constantTimeDigestEqual(expectedDigest, record.localRecordDigest)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_digest_invalid");
  }
  return record;
}

function digestImmutableRecord(record) {
  const immutable = {
    localRecordId: record.localRecordId,
    ...Object.fromEntries(INCOMING_KEYS.map((key) => [key, record[key]])),
    receivedAt: record.receivedAt,
  };
  return crypto.createHash("sha256")
    .update(`${LOCAL_RECORD_DIGEST_DOMAIN}${JSON.stringify(immutable)}`, "utf8")
    .digest("hex");
}

function acknowledgementReceipt(record, duplicate) {
  return Object.freeze({
    contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
    ackState: "persisted_local",
    localRecordId: record.localRecordId,
    localRecordDigest: record.localRecordDigest,
    attemptId: record.attemptId,
    eventId: record.eventId,
    clientRequestId: record.clientRequestId,
    connectionId: record.connectionId,
    recipientPrincipalId: record.recipientPrincipalId,
    recipientEndpointId: record.recipientDeviceId,
    replayKey: record.replayKey,
    envelopeDigest: record.envelopeDigest,
    claimId: record.claimId,
    ackDeadlineAt: record.ackDeadlineAt,
    duplicate,
  });
}

function projectionReceipt(record, duplicate) {
  return Object.freeze({
    contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
    localRecordId: record.localRecordId,
    localRecordDigest: record.localRecordDigest,
    serverContactRequestId: record.serverContactRequestId,
    state: record.state,
    duplicate,
  });
}

function decisionAttemptReceipt(record) {
  return Object.freeze({
    contractId: LOCAL_CONTACT_REQUEST_STORE_CONTRACT,
    localRecordId: record.localRecordId,
    localRecordDigest: record.localRecordDigest,
    serverContactRequestId: record.serverContactRequestId,
    state: record.state,
    decisionId: record.decisionAttempt?.decisionId ?? null,
    action: record.decisionAttempt?.action ?? null,
    startedAt: record.decisionAttempt?.startedAt ?? null,
  });
}

function unresolvedDecisionProjection(record) {
  return Object.freeze({
    localRecordId: record.localRecordId,
    localRecordDigest: record.localRecordDigest,
    serverContactRequestId: record.serverContactRequestId,
    state: record.state,
    decisionId: record.decisionAttempt?.decisionId ?? null,
    action: record.decisionAttempt?.action ?? null,
    startedAt: record.decisionAttempt?.startedAt ?? null,
    recoveryRequired: record.decisionRecoveryRequired,
  });
}

function humanProjection(record) {
  return Object.freeze({
    humanOnly: true,
    modelVisibility: "none",
    localRecordId: record.localRecordId,
    localRecordDigest: record.localRecordDigest,
    serverContactRequestId: record.serverContactRequestId,
    state: record.state,
    actionReady: record.serverContactRequestId != null
      && record.state === "pending"
      && record.decisionAttempt == null
      && !record.decisionRecoveryRequired,
    decisionOutcome: record.decisionRecoveryRequired
      ? "recovery-required"
      : record.decisionAttempt == null ? null : "unknown",
    decisionAction: record.decisionAttempt?.action ?? null,
    introText: record.introText,
    introWeight: record.introWeight,
    sender: Object.freeze({
      principalId: record.senderPrincipalId,
      hellolynkId: record.senderHelloLynkId,
      verifiedDisplayName: record.senderPrincipalDisplayName,
      deviceId: record.senderDeviceId,
      identityKeyId: record.senderIdentityKeyId,
    }),
    recipient: Object.freeze({
      principalId: record.recipientPrincipalId,
      hellolynkId: record.recipientHelloLynkId,
      deviceId: record.recipientDeviceId,
      identityKeyId: record.recipientIdentityKeyId,
    }),
    receivedAt: record.receivedAt,
    serverUpdatedAt: record.serverUpdatedAt,
  });
}

function normalizeProjection(input) {
  assertExactFields(input, PROJECTION_KEYS, "contact_request_local_projection_invalid");
  return Object.freeze({
    localRecordId: normalizeLocalRecordId(input.localRecordId),
    expectedLocalRecordDigest: normalizeDigest(
      input.expectedLocalRecordDigest,
      "contact_request_local_record_digest_invalid",
    ),
    serverContactRequestId: normalizeId(
      input.serverContactRequestId,
      "contact_request_server_request_id_invalid",
    ),
    state: normalizeProjectionState(input.state),
    serverUpdatedAt: normalizeTimestamp(
      input.serverUpdatedAt,
      "contact_request_server_updated_at_invalid",
    ),
  });
}

function normalizeBeginDecision(input) {
  assertExactFields(input, BEGIN_DECISION_KEYS, "contact_request_local_decision_input_invalid");
  return Object.freeze({
    ...normalizeDecisionRecordIdentity(input),
    action: normalizeDecisionAction(input.action),
  });
}

function normalizeAbortDecision(input) {
  assertExactFields(input, ABORT_DECISION_KEYS, "contact_request_local_decision_input_invalid");
  return Object.freeze({
    ...normalizeDecisionRecordIdentity(input),
    decisionId: normalizeDecisionId(input.decisionId, false),
  });
}

function normalizeRecoverDecision(input) {
  assertExactFields(input, RECOVER_DECISION_KEYS, "contact_request_local_decision_input_invalid");
  return Object.freeze({
    ...normalizeDecisionRecordIdentity(input),
    decisionId: normalizeDecisionId(input.decisionId, true),
  });
}

function normalizeResolveDecision(input) {
  assertExactFields(input, RESOLVE_DECISION_KEYS, "contact_request_local_decision_input_invalid");
  const state = normalizeProjectionState(input.state);
  if (!FINAL_PROJECTION_STATES.has(state)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_state_invalid");
  }
  return Object.freeze({
    ...normalizeDecisionRecordIdentity(input),
    decisionId: normalizeDecisionId(input.decisionId, false),
    state,
    serverUpdatedAt: normalizeTimestamp(
      input.serverUpdatedAt,
      "contact_request_server_updated_at_invalid",
    ),
  });
}

function normalizeDecisionRecordIdentity(input) {
  return {
    localRecordId: normalizeLocalRecordId(input.localRecordId),
    expectedLocalRecordDigest: normalizeDigest(
      input.expectedLocalRecordDigest,
      "contact_request_local_record_digest_invalid",
    ),
    serverContactRequestId: normalizeId(
      input.serverContactRequestId,
      "contact_request_server_request_id_invalid",
    ),
  };
}

function requireDecisionRecord(store, accepted) {
  const record = store.records.find((item) => item.localRecordId === accepted.localRecordId);
  if (!record) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_record_not_found", {
      status: 404,
    });
  }
  if (record.localRecordDigest !== accepted.expectedLocalRecordDigest) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_record_digest_mismatch", {
      status: 409,
    });
  }
  if (record.serverContactRequestId !== accepted.serverContactRequestId) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_server_id_conflict", {
      status: 409,
    });
  }
  return record;
}

function assertDecisionCas(record, decisionId) {
  if (record.decisionAttempt == null || record.decisionAttempt.decisionId !== decisionId) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_cas_conflict", {
      status: 409,
    });
  }
}

function normalizeHumanStates(value) {
  if (value == null) return new Set(PROJECTION_STATES);
  if (!Array.isArray(value) || value.length < 1 || value.length > PROJECTION_STATES.size) {
    throw new HelloLynkLocalContactRequestsError("contact_request_human_states_invalid");
  }
  const states = new Set(value.map(normalizeProjectionState));
  if (states.size !== value.length) {
    throw new HelloLynkLocalContactRequestsError("contact_request_human_states_invalid");
  }
  return states;
}

function normalizeHumanLimit(value, maximumRecords) {
  if (value == null) return maximumRecords;
  const limit = Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximumRecords) {
    throw new HelloLynkLocalContactRequestsError("contact_request_human_limit_invalid");
  }
  return limit;
}

function normalizeProjectionState(value) {
  const state = String(value || "");
  if (!PROJECTION_STATES.has(state)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_state_invalid");
  }
  return state;
}

function normalizeDecisionAttempt(value) {
  if (value == null) return null;
  assertExactFields(value, DECISION_ATTEMPT_KEYS, "contact_request_local_decision_attempt_invalid");
  return Object.freeze({
    decisionId: normalizeDecisionId(value.decisionId, false),
    action: normalizeDecisionAction(value.action),
    startedAt: normalizeTimestamp(
      value.startedAt,
      "contact_request_local_decision_started_at_invalid",
    ),
  });
}

function normalizeDecisionAction(value) {
  const action = String(value || "");
  if (!DECISION_ACTIONS.has(action)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_decision_action_invalid");
  }
  return action;
}

function normalizeDecisionId(value, nullable) {
  if (nullable && value == null) return null;
  return normalizeId(value, "contact_request_local_decision_id_invalid");
}

function normalizeStoredBoolean(value, code) {
  if (typeof value !== "boolean") {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  return value;
}

function normalizeContactRequestDataProtection(protector, profileId) {
  if (protector == null) return null;
  if (["sealJson", "openJson"].some((method) => typeof protector?.[method] !== "function")) {
    throw new HelloLynkLocalContactRequestsError("contact_request_data_protector_invalid");
  }
  return Object.freeze({
    protector,
    context: Object.freeze({
      profileId,
      assetKind: "contact-requests",
      logicalPath: `contact-requests/${profileId}.json`,
    }),
  });
}

async function readStore(layout, profileId, maximumBytes, maximumRecords, protection = null) {
  await assertContactRequestStoreAccess(layout, protection);
  const layoutExists = await assertSafeStoreLayout(layout, { create: false });
  if (!layoutExists) return emptyStore(profileId);
  const physicalMaximum = protectedStoreMaximum(maximumBytes, protection);
  let metadata;
  try {
    metadata = await lstat(layout.storePath);
  } catch (error) {
    if (error?.code === "ENOENT") return emptyStore(profileId);
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_read_failed", {
      cause: error,
    });
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > physicalMaximum) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  let handle;
  let parsed;
  try {
    const noFollow = Number(fsConstants.O_NOFOLLOW || 0);
    handle = await open(layout.storePath, fsConstants.O_RDONLY | noFollow);
    const openedMetadata = await handle.stat();
    const windowsUnreportedDevice = process.platform === "win32"
      && (metadata.dev === 0 || openedMetadata.dev === 0);
    if (
      !openedMetadata.isFile()
      || openedMetadata.size > physicalMaximum
      || (windowsUnreportedDevice && metadata.ino !== openedMetadata.ino)
      || (
        Number.isSafeInteger(metadata.dev)
        && Number.isSafeInteger(metadata.ino)
        && Number.isSafeInteger(openedMetadata.dev)
        && Number.isSafeInteger(openedMetadata.ino)
        && (metadata.ino !== openedMetadata.ino
          || (metadata.dev !== openedMetadata.dev
            && !windowsUnreportedDevice))
      )
    ) {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
    }
    const stored = JSON.parse(await handle.readFile("utf8"));
    parsed = protection
      ? await protection.protector.openJson(stored, protection.context)
      : stored;
    if (serializedStoreBytes(parsed) > maximumBytes) {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
    }
  } catch (error) {
    if (error instanceof HelloLynkLocalContactRequestsError) throw error;
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid", { cause: error });
  } finally {
    await handle?.close().catch(() => {});
  }
  assertExactFields(parsed, STORE_KEYS, "contact_request_local_store_invalid");
  if (
    !new Set([LEGACY_STORE_SCHEMA_VERSION, STORE_SCHEMA_VERSION]).has(parsed.schemaVersion)
    || parsed.contractId !== LOCAL_CONTACT_REQUEST_STORE_CONTRACT
    || parsed.profileId !== profileId
    || !Array.isArray(parsed.records)
    || parsed.records.length > maximumRecords
  ) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
  }
  const records = parsed.records.map((record) => normalizeStoredRecord(
    record,
    parsed.schemaVersion,
  ));
  assertUniqueRecords(records);
  await applyBestEffortPrivateMode(layout.storePath);
  return { ...emptyStore(profileId), records };
}

function assertUniqueRecords(records) {
  for (const key of ["localRecordId", "replayKey", "eventId", "attemptId"]) {
    const seen = new Set();
    for (const record of records) {
      if (seen.has(record[key])) {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
      }
      seen.add(record[key]);
    }
  }
  const senderClientPairs = new Set();
  for (const record of records) {
    const pair = `${record.senderPrincipalId}\0${record.clientRequestId}`;
    if (senderClientPairs.has(pair)) {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
    }
    senderClientPairs.add(pair);
  }
}

async function atomicWriteStore(layout, store, maximumBytes, protection = null) {
  await assertContactRequestStoreAccess(layout, protection);
  await assertSafeStoreLayout(layout, { create: true });
  try {
    const current = await lstat(layout.storePath);
    if (current.isSymbolicLink() || !current.isFile()) {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_invalid");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (serializedStoreBytes(store) > maximumBytes) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_too_large", {
      status: 507,
    });
  }
  const stored = protection
    ? await protection.protector.sealJson(store, protection.context)
    : store;
  const body = `${JSON.stringify(stored, null, 2)}\n`;
  if (Buffer.byteLength(body, "utf8") > protectedStoreMaximum(maximumBytes, protection)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_too_large", {
      status: 507,
    });
  }
  const temporary = `${layout.storePath}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_write_failed", {
      cause: error,
    });
  } finally {
    await handle?.close().catch(() => {});
  }
  try {
    await assertContactRequestStoreAccess(layout, protection);
    await assertSafeStoreLayout(layout, { create: false });
    await replaceFileWithRetry(temporary, layout.storePath);
    await applyBestEffortPrivateMode(layout.storePath);
    await syncDirectory(layout.directoryPath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    if (error instanceof HelloLynkLocalContactRequestsError) throw error;
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_write_failed", {
      cause: error,
    });
  }
}

async function assertContactRequestStoreAccess(layout, protection) {
  try {
    await assertLocalDataProtectionAccess(layout.rootPath, protection != null);
  } catch (error) {
    if (error instanceof HelloLynkLocalContactRequestsError) throw error;
    throw new HelloLynkLocalContactRequestsError(
      error?.code || "contact_request_local_store_access_invalid",
      { cause: error },
    );
  }
}

function serializedStoreBytes(store) {
  return Buffer.byteLength(`${JSON.stringify(store, null, 2)}\n`, "utf8");
}

function protectedStoreMaximum(maximumBytes, protection) {
  return protection ? maximumBytes * 2 : maximumBytes;
}

async function replaceFileWithRetry(sourcePath, targetPath) {
  let lastError;
  for (const wait of [0, 10, 25, 75, 200, 400]) {
    if (wait > 0) await delay(wait);
    try {
      await rename(sourcePath, targetPath);
      return;
    } catch (error) {
      lastError = error;
      if (!["EACCES", "EPERM", "EBUSY"].includes(error?.code)) throw error;
    }
  }
  throw lastError;
}

async function syncDirectory(directoryPath) {
  let handle;
  try {
    handle = await open(directoryPath, "r");
    await handle.sync();
  } catch (error) {
    if (!["EBADF", "EINVAL", "EISDIR", "ENOTSUP", "EPERM"].includes(error?.code)) {
      throw error;
    }
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function applyBestEffortPrivateMode(filePath) {
  try {
    await chmod(filePath, 0o600);
  } catch (error) {
    if (!["EACCES", "EPERM", "ENOTSUP", "EINVAL"].includes(error?.code)) throw error;
  }
}

async function withPathMutationQueue(storePath, callback) {
  const previous = pathMutationQueues.get(storePath) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => gate);
  pathMutationQueues.set(storePath, tail);
  await previous;
  try {
    return await withCrossProcessLock(storePath, callback);
  } finally {
    release();
    if (pathMutationQueues.get(storePath) === tail) pathMutationQueues.delete(storePath);
  }
}

async function withCrossProcessLock(storePath, callback) {
  const layout = resolveStoreLayoutFromPath(storePath);
  await assertSafeStoreLayout(layout, { create: true });
  const lockPath = `${storePath}.lock`;
  const recoveryPath = `${lockPath}.recovery`;
  let ownershipToken = null;
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    if (await pathExists(recoveryPath)) {
      await removeDeadOwnedLock(recoveryPath);
      await delay(LOCK_WAIT_MS);
      continue;
    }
    try {
      ({ ownershipToken } = await publishOwnedLock(lockPath));
      break;
    } catch (error) {
      ownershipToken = null;
      if (error?.code !== "EEXIST") {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_lock_failed", {
          cause: error,
        });
      }
      await recoverDeadLock(lockPath);
      await delay(LOCK_WAIT_MS);
    }
  }
  if (!ownershipToken) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_busy", {
      status: 503,
      retryable: true,
    });
  }
  try {
    return await callback();
  } finally {
    await releaseOwnedLock(lockPath, null, ownershipToken);
  }
}

async function recoverDeadLock(lockPath) {
  const recoveryPath = `${lockPath}.recovery`;
  let recoveryToken = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      ({ ownershipToken: recoveryToken } = await publishOwnedLock(recoveryPath));
      break;
    } catch (error) {
      recoveryToken = null;
      if (error?.code !== "EEXIST") throw error;
      if (!(await removeDeadOwnedLock(recoveryPath))) return false;
    }
  }
  if (!recoveryToken) return false;
  try {
    return await removeDeadOwnedLock(lockPath);
  } finally {
    await releaseOwnedLock(recoveryPath, null, recoveryToken);
  }
}

async function publishOwnedLock(lockPath) {
  const ownershipToken = crypto.randomBytes(24).toString("hex");
  const candidatePath = `${lockPath}.candidate.${process.pid}.${crypto.randomUUID()}`;
  let candidateHandle = null;
  let published = false;
  let failure = null;
  try {
    candidateHandle = await retryWindowsTransientFs(() => open(candidatePath, "wx", 0o600));
    await candidateHandle.writeFile(`${JSON.stringify({
      pid: process.pid,
      ownershipToken,
      createdAt: Date.now(),
    })}\n`, "utf8");
    await candidateHandle.sync();
    await candidateHandle.close();
    candidateHandle = null;

    // Publish a fully written inode without ever exposing an empty/partial
    // authoritative lock file. link() is atomic and refuses to overwrite an
    // existing owner, so a paused creator cannot later enter the critical
    // section after another process has acquired the same lock.
    for (let attempt = 0; attempt < WINDOWS_TRANSIENT_FS_RETRY_MS.length; attempt += 1) {
      const wait = WINDOWS_TRANSIENT_FS_RETRY_MS[attempt];
      if (wait > 0) await delay(wait);
      try {
        await link(candidatePath, lockPath);
        published = true;
        break;
      } catch (error) {
        if (error?.code === "EEXIST") throw error;
        if (!isWindowsTransientFsError(error)) throw error;
        if (await pathExists(lockPath)) throw lockAlreadyOwnedError(error);
        if (attempt === WINDOWS_TRANSIENT_FS_RETRY_MS.length - 1) throw error;
      }
    }
    if (!published) throw new Error("contact_request_local_lock_publish_failed");
  } catch (error) {
    failure = error;
  } finally {
    await candidateHandle?.close().catch(() => {});
    try {
      await removeWithWindowsRetry(candidatePath);
    } catch (error) {
      failure ||= error;
    }
  }
  if (failure) {
    if (published) await releaseOwnedLock(lockPath, null, ownershipToken).catch(() => {});
    throw failure;
  }
  return { ownershipToken };
}

async function removeDeadOwnedLock(lockPath) {
  const first = await readLockSnapshot(lockPath);
  if (!first || !lockSnapshotEligibleForRecovery(first)) return false;
  await delay(LOCK_WAIT_MS);
  const second = await readLockSnapshot(lockPath);
  if (
    !second
    || !lockSnapshotEligibleForRecovery(second)
    || !sameLockSnapshot(first, second)
  ) return false;
  const stalePath = `${lockPath}.stale.${process.pid}.${crypto.randomBytes(8).toString("hex")}`;
  try {
    await rename(lockPath, stalePath);
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM", "EBUSY"].includes(error?.code)) return false;
    throw error;
  }
  const quarantined = await readLockSnapshot(stalePath);
  if (!quarantined || !sameLockSnapshot(second, quarantined)) {
    try {
      await rename(stalePath, lockPath);
    } catch {}
    return false;
  }
  await rm(stalePath, { force: true });
  return true;
}

async function readLockSnapshot(lockPath) {
  let metadata;
  try {
    metadata = await retryWindowsTransientFs(() => lstat(lockPath));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > MAX_LOCK_BYTES) return null;
  let body;
  try {
    body = await retryWindowsTransientFs(() => readFile(lockPath));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (body.length !== metadata.size) return null;
  return { metadata, body };
}

function lockSnapshotEligibleForRecovery(snapshot) {
  if (Date.now() - snapshot.metadata.mtimeMs < LOCK_STALE_MS) return false;
  let record = null;
  try {
    record = JSON.parse(snapshot.body.toString("utf8"));
  } catch {}
  const pid = Number(record?.pid);
  if (
    Number.isSafeInteger(pid)
    && pid > 0
    && typeof record?.ownershipToken === "string"
    && record.ownershipToken.length >= 16
    && Number.isFinite(Number(record?.createdAt))
  ) return !processAlive(pid);
  return true;
}

function sameLockSnapshot(left, right) {
  const leftMetadata = left.metadata;
  const rightMetadata = right.metadata;
  const identitiesComparable = (
    Number.isSafeInteger(leftMetadata.dev)
    && Number.isSafeInteger(leftMetadata.ino)
    && Number.isSafeInteger(rightMetadata.dev)
    && Number.isSafeInteger(rightMetadata.ino)
  );
  return (
    (!identitiesComparable || (
      leftMetadata.dev === rightMetadata.dev
      && leftMetadata.ino === rightMetadata.ino
    ))
    && leftMetadata.size === rightMetadata.size
    && leftMetadata.mtimeMs === rightMetadata.mtimeMs
    && left.body.length === right.body.length
    && crypto.timingSafeEqual(left.body, right.body)
  );
}

async function pathExists(candidatePath) {
  try {
    await retryWindowsTransientFs(() => lstat(candidatePath));
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function releaseOwnedLock(lockPath, handle, ownershipToken) {
  await handle?.close().catch(() => {});
  try {
    const current = JSON.parse(await retryWindowsTransientFs(() => readFile(lockPath, "utf8")));
    if (current?.ownershipToken === ownershipToken) await removeWithWindowsRetry(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT" || error instanceof SyntaxError) return;
    throw new HelloLynkLocalContactRequestsError("contact_request_local_lock_failed", {
      cause: error,
    });
  }
}

async function removeWithWindowsRetry(filePath) {
  return retryWindowsTransientFs(async () => {
    try {
      await rm(filePath, { force: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
  });
}

async function retryWindowsTransientFs(operation) {
  let lastError = null;
  for (const wait of WINDOWS_TRANSIENT_FS_RETRY_MS) {
    if (wait > 0) await delay(wait);
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!isWindowsTransientFsError(error)) throw error;
    }
  }
  throw lastError;
}

function isWindowsTransientFsError(error) {
  return process.platform === "win32" && WINDOWS_TRANSIENT_FS_CODES.has(error?.code);
}

function lockAlreadyOwnedError(cause) {
  const error = new Error("contact_request_local_lock_exists", { cause });
  error.code = "EEXIST";
  return error;
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function resolveStoreLayout(storePath, profileId) {
  const resolved = path.resolve(storePath);
  const directoryPath = path.dirname(resolved);
  const rootPath = path.dirname(directoryPath);
  if (
    path.basename(directoryPath) !== STORE_DIRECTORY_NAME
    || path.basename(resolved) !== `${profileId}.json`
    || rootPath === directoryPath
  ) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_path_invalid");
  }
  return { rootPath, directoryPath, storePath: resolved };
}

function resolveStoreLayoutFromPath(storePath) {
  const resolved = path.resolve(storePath);
  const profileId = path.basename(resolved, ".json");
  return resolveStoreLayout(resolved, profileId);
}

async function assertSafeStoreLayout(layout, options = {}) {
  const create = options.create === true;
  await assertNoSymlinkAncestors(layout.rootPath);
  const rootExists = await assertSafeDirectory(layout.rootPath, {
    create,
    recursive: true,
  });
  if (!rootExists) return false;
  await assertNoSymlinkAncestors(layout.rootPath);
  const directoryExists = await assertSafeDirectory(layout.directoryPath, {
    create,
    recursive: false,
  });
  return directoryExists;
}

async function assertNoSymlinkAncestors(targetPath) {
  const resolved = path.resolve(targetPath);
  const root = path.parse(resolved).root;
  let current = root;
  for (const segment of path.relative(root, resolved).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid", {
        cause: error,
      });
    }
    if (metadata.isSymbolicLink()) {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid");
    }
  }
}

async function assertSafeDirectory(directoryPath, options = {}) {
  let metadata;
  try {
    metadata = await lstat(directoryPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid", {
        cause: error,
      });
    }
    if (!options.create) return false;
    try {
      await mkdir(directoryPath, { recursive: options.recursive === true, mode: 0o700 });
      metadata = await lstat(directoryPath);
    } catch (createError) {
      if (createError?.code === "EEXIST") {
        try {
          metadata = await lstat(directoryPath);
        } catch (raceError) {
          throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid", {
            cause: raceError,
          });
        }
      } else {
        throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid", {
          cause: createError,
        });
      }
    }
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_store_directory_invalid");
  }
  return true;
}

function normalizeProfileId(value) {
  const profileId = String(value || "").trim();
  if (!PROFILE_ID_RE.test(profileId)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_profile_id_invalid");
  }
  return profileId;
}

function normalizeLocalRecordId(value) {
  const localRecordId = String(value || "");
  if (!LOCAL_RECORD_ID_RE.test(localRecordId)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_record_id_invalid");
  }
  return localRecordId;
}

function normalizeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID_RE.test(value)) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  return value;
}

function normalizeHelloLynkId(value, code) {
  if (typeof value !== "string" || !HELLOLYNK_ID_RE.test(value)) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  return value;
}

function normalizeDigest(value, code) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  return value;
}

function normalizeDigestSalt(value) {
  if (typeof value !== "string" || !BASE64URL_16_RE.test(value)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_intro_digest_salt_invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 16 || decoded.toString("base64url") !== value) {
    throw new HelloLynkLocalContactRequestsError("contact_request_intro_digest_salt_invalid");
  }
  return value;
}

function normalizeOptionalDisplayName(value) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new HelloLynkLocalContactRequestsError("contact_request_sender_display_name_invalid");
  }
  const normalized = value.normalize("NFKC").trim().replace(/\s+/gu, " ");
  if (!normalized || [...normalized].length > 80 || UNSAFE_DISPLAY_RE.test(normalized)) {
    throw new HelloLynkLocalContactRequestsError("contact_request_sender_display_name_invalid");
  }
  return normalized;
}

function normalizeTimestamp(value, code) {
  if (typeof value !== "string") throw new HelloLynkLocalContactRequestsError(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  return value;
}

function normalizeCurrentTimestamp(value) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.valueOf())) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_clock_invalid");
  }
  return parsed.toISOString();
}

function normalizeMaximumBytes(value) {
  if (value == null) return DEFAULT_MAX_STORE_BYTES;
  const maximum = Number(value);
  if (
    !Number.isSafeInteger(maximum)
    || maximum < MIN_MAX_STORE_BYTES
    || maximum > DEFAULT_MAX_STORE_BYTES
  ) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_max_store_bytes_invalid");
  }
  return maximum;
}

function normalizeMaximumRecords(value) {
  if (value == null) return DEFAULT_MAX_RECORDS;
  const maximum = Number(value);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_CONFIGURED_RECORDS) {
    throw new HelloLynkLocalContactRequestsError("contact_request_local_max_records_invalid");
  }
  return maximum;
}

function constantTimeDigestEqual(left, right) {
  return timingSafeBufferEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function timingSafeBufferEqual(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function assertPlainRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
}

function assertOnlyKnownFields(value, expectedFields, code) {
  if (Object.keys(value).some((field) => !expectedFields.includes(field))) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
}

function assertExactFields(value, expectedFields, code) {
  assertPlainRecord(value, code);
  const actualFields = Object.keys(value);
  if (
    actualFields.length !== expectedFields.length
    || expectedFields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new HelloLynkLocalContactRequestsError(code);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
