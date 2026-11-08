import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { contactRequestIntroReplayKey } from "./hellolynk-contact-request-e2ee.mjs";
import {
  DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES,
  DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE,
} from "./hellolynk-direct-text-e2ee.mjs";
import { assertLocalDataProtectionAccess } from "./hellolynk-local-data-protection.mjs";
import {
  createOutgoingConversationIntent,
  deriveInstanceConversationBinding,
  instanceConversationKey,
  normalizeInstanceConversationBinding,
} from "./hellolynk-instance-conversation.mjs";

export const HELLOLYNK_NEUTRAL_HOST_RECOVERY_CONTRACT = "hellolynk-neutral-host-recovery-v1";

const MAX_JOURNAL_BYTES = 4 * 1024 * 1024;
const queues = new Map();

export function createNeutralHostStoreAdapters(options = {}) {
  const messageStore = requireMethods(options.messageStore, [
    "addIncoming", "addOutgoing", "claimOutgoingForAttempt", "updateOutgoing", "list", "getOutgoing",
  ], "neutral_host_message_store_invalid");
  const contactRequestStore = requireMethods(options.contactRequestStore, [
    "persistIncoming", "listForHuman",
  ], "neutral_host_contact_store_invalid");
  const principalId = safeId(options.principalId, "neutral_host_store_principal_invalid");
  const journal = createRecoveryJournal({
    journalPath: options.journalPath,
    principalId,
    profileId: options.profileId,
    dataProtector: options.dataProtector,
    maximumBytes: options.recoveryJournalMaximumBytes,
  });

  async function persistIncomingMessageRecoverable(input = {}) {
      validatePersistenceInput(input, false);
      const event = input.event;
      if ((input.replyToClientMessageId ?? null) !== (event.e2eeEnvelope?.protected?.replyToClientMessageId ?? null)) {
        throw failure("neutral_host_persistence_binding_mismatch");
      }
      const conversationBinding = normalizeInstanceConversationBinding(input.conversationBinding, { principalId });
      if (conversationBinding) {
        // Opening the envelope is the caller's responsibility. Here the already
        // verified tuple must also agree with every corresponding event field.
        const eventBinding = deriveInstanceConversationBinding({ ...event, e2eeVersion: 2 }, {
          direction: "incoming", principalId,
        });
        if (instanceConversationKey(conversationBinding) !== instanceConversationKey(eventBinding)
          || input.senderPrincipalId !== conversationBinding.peerPrincipalId
          || input.senderDelegateId !== conversationBinding.peerDelegateId) {
          throw failure("neutral_host_persistence_binding_mismatch");
        }
      }
      const identity = eventIdentity("message", event, input.envelopeDigest);
      return journal.coordinate(identity, async (current, checkpoint, recovery) => {
        if (current.stage === "committed") {
          const stored = typeof messageStore.getIncoming === "function"
            ? await messageStore.getIncoming(current.localRecordId)
            : (await messageStore.list()).find((item) => item.localMessageId === current.localRecordId);
          if (stored?.conversationBinding && (!conversationBinding
            || instanceConversationKey(stored.conversationBinding) !== instanceConversationKey(conversationBinding))) {
            throw failure("neutral_host_persistence_binding_mismatch");
          }
          if (!stored) throw failure("neutral_host_persistence_record_missing");
          return persistenceReceipt(current, true, stored);
        }
        const stored = await messageStore.addIncoming({
          eventId: event.eventId,
          clientMessageId: event.clientMessageId,
          senderPrincipalId: input.senderPrincipalId,
          senderDelegateId: input.senderDelegateId,
          authorizationScope: input.authorizationScope,
          intentSource: input.intentSource,
          ...(input.replyToClientMessageId ? { replyToClientMessageId: input.replyToClientMessageId } : {}),
          ...(input.targetConversationId ? { targetConversationId: input.targetConversationId } : {}),
          ...(input.friendTarget ? { friendTarget: input.friendTarget } : {}),
          senderHelloLynkId: event.senderHelloLynkId ?? null,
          senderPrincipalDisplayName: event.senderPrincipalDisplayName ?? null,
          senderDelegateDisplayName: event.senderDelegateDisplayName ?? null,
          text: input.text,
          envelopeDigest: input.envelopeDigest,
          senderIdentityKeyId: event.senderIdentityKeyId,
          recipientIdentityKeyId: event.recipientIdentityKeyId,
          conversationBinding,
        });
        const record = await checkpoint({
          stage: "recorded",
          localRecordId: stored.message.localMessageId,
          localRecordDigest: null,
        });
        await input.commitPrekey();
        const committed = await checkpoint({ ...record, stage: "committed" });
        if (recovery.createdHere && stored.duplicate === true) {
          const replaced = await recovery.replaceDuplicate({
            eventId: stored.message.eventId,
            localRecordId: stored.message.localMessageId,
          });
          if (!replaced) await recovery.discard();
        }
        return persistenceReceipt(committed, stored.duplicate === true, stored.message);
      });
  }
  const localStore = Object.freeze({
    ...messageStore,
    persistIncomingRecoverable: persistIncomingMessageRecoverable,
    // Historical compatibility alias. This is a recoverable ordered journal,
    // not a transaction spanning the business store and encrypted key store.
    persistIncomingAtomic: persistIncomingMessageRecoverable,
  });

  async function persistIncomingContactRecoverable(input = {}) {
      validatePersistenceInput(input, true);
      const event = input.event;
      const identity = eventIdentity("contact_request", event, input.envelopeDigest);
      return journal.coordinate(identity, async (current, checkpoint, recovery) => {
        if (current.stage === "committed") return contactPersistenceReceipt(current, event, principalId, true);
        const stored = await contactRequestStore.persistIncoming({
          eventId: event.eventId,
          attemptId: event.attemptId,
          clientRequestId: event.clientRequestId,
          connectionId: event.targetConnectionId,
          claimId: event.claimId,
          replayKey: contactRequestIntroReplayKey({
            attemptId: event.attemptId,
            clientRequestId: event.clientRequestId,
            requestDigest: event.requestDigest,
            introDigest: event.introDigest,
            introWeight: event.introWeight,
            senderPrincipalId: event.senderPrincipalId,
            senderHelloLynkId: event.senderHelloLynkId,
            senderDeviceId: event.senderDeviceId,
            senderIdentityKeyId: event.senderIdentityKeyId,
            recipientPrincipalId: event.recipientPrincipalId,
            recipientHelloLynkId: event.recipientHelloLynkId,
            recipientDeviceId: event.recipientDeviceId,
            recipientIdentityKeyId: event.recipientIdentityKeyId,
            recipientPreKeyId: event.recipientPreKeyId,
            authorizationScope: "contact.request.send",
            intentSource: "hellolynk_host_explicit_human_ui",
            messageType: "contact_request_intro",
            createdAt: event.createdAt,
            expiresAt: event.expiresAt,
          }),
          envelopeDigest: input.envelopeDigest,
          requestDigest: event.requestDigest,
          introDigest: event.introDigest,
          introDigestSalt: input.introDigestSalt,
          introWeight: event.introWeight,
          introText: input.text,
          senderPrincipalId: event.senderPrincipalId,
          senderHelloLynkId: event.senderHelloLynkId,
          senderPrincipalDisplayName: event.senderPrincipalDisplayName ?? null,
          senderDeviceId: event.senderDeviceId,
          senderIdentityKeyId: event.senderIdentityKeyId,
          recipientPrincipalId: event.recipientPrincipalId,
          recipientHelloLynkId: event.recipientHelloLynkId,
          recipientDeviceId: event.recipientDeviceId,
          recipientIdentityKeyId: event.recipientIdentityKeyId,
          recipientPreKeyId: event.recipientPreKeyId,
          createdAt: event.createdAt,
          expiresAt: event.expiresAt,
          relayedAt: event.relayedAt,
          ackDeadlineAt: event.ackDeadlineAt,
        });
        const record = await checkpoint({
          stage: "recorded",
          localRecordId: stored.localRecordId,
          localRecordDigest: stored.localRecordDigest,
        });
        await input.commitPrekey();
        const committed = await checkpoint({ ...record, stage: "committed" });
        if (recovery.createdHere && stored.duplicate === true) {
          const replaced = await recovery.replaceDuplicate({
            eventId: stored.eventId,
            localRecordId: stored.localRecordId,
          });
          if (!replaced) await recovery.discard();
        }
        return contactPersistenceReceipt(committed, event, principalId, stored.duplicate === true);
      });
  }
  const contactStore = Object.freeze({
    ...contactRequestStore,
    persistIncomingRecoverable: persistIncomingContactRecoverable,
    // Historical compatibility alias; see the message adapter note above.
    persistIncomingAtomic: persistIncomingContactRecoverable,
  });

  const outbox = Object.freeze({
    ...messageStore,
    async persistBeforeEncryption(input = {}) {
      const created = await messageStore.addOutgoing({
        recipientHelloLynkId: input.recipientHelloLynkId,
        clientMessageId: input.clientMessageId,
        text: input.text,
        senderPrincipalId: input.senderPrincipalId,
        senderDelegateId: input.senderDelegateId,
        e2ee: null,
        conversationIntent: createOutgoingConversationIntent(input),
      });
      return messageStore.claimOutgoingForAttempt(created.clientMessageId, {
        senderPrincipalId: input.senderPrincipalId,
        senderDelegateId: input.senderDelegateId,
      });
    },
    async markUnknown(input = {}) {
      return messageStore.updateOutgoing(input.clientMessageId, {
        status: "delivery_state_unknown",
        lastErrorCode: String(input.errorCode || "neutral_host_delivery_unknown"),
        incrementAttempts: false,
      });
    },
    async markResult(input = {}) {
      const status = String(input.result?.status || "delivery_state_unknown");
      return messageStore.updateOutgoing(input.clientMessageId, {
        status,
        lastErrorCode: input.result?.errorCode ?? null,
        incrementAttempts: false,
      });
    },
    async freezeUnknown() {
      // Unknown is already a durable status. Startup only reports its count;
      // loading every message body here delays opening the Host listener.
      if (typeof messageStore.getMessageCounts === "function") {
        const states = (await messageStore.getMessageCounts()).outbox.states;
        return Object.freeze({ frozen: (states.delivery_state_unknown ?? 0) + (states.delivery_state_unconfirmed ?? 0) });
      }
      const records = await messageStore.list();
      return Object.freeze({
        frozen: records.filter((item) => item.direction === "outgoing"
          && ["delivery_state_unknown", "delivery_state_unconfirmed"].includes(item.status)).length,
      });
    },
    get: (clientMessageId) => messageStore.getOutgoing(clientMessageId),
    retry: async () => { throw failure("neutral_host_native_human_broker_unavailable"); },
  });

  return Object.freeze({ localStore, contactStore, outbox, journal });
}

export function createRecoveryJournal(options = {}) {
  const journalPath = path.resolve(String(options.journalPath || ""));
  const principalId = safeId(options.principalId, "neutral_host_store_principal_invalid");
  if (!options.journalPath) throw failure("neutral_host_recovery_journal_path_required");
  const protection = normalizeRecoveryDataProtection(options.dataProtector, options.profileId);
  const maximumBytes = normalizeRecoveryJournalMaximumBytes(options.maximumBytes);

  async function coordinate(identity, operation) {
    return queued(journalPath, async () => {
      const state = await readJournal(journalPath, principalId, protection, maximumBytes);
      let current = state.operations.find((item) => item.key === identity.key);
      if (current && current.eventDigest !== identity.eventDigest) {
        throw failure("neutral_host_recovery_event_conflict");
      }
      const reclaimed = reclaimCompletedOperations(state, identity.key);
      current = state.operations.find((item) => item.key === identity.key);
      let createdHere = false;
      if (!current) {
        current = {
          key: identity.key,
          kind: identity.kind,
          eventDigest: identity.eventDigest,
          stage: "intent",
          localRecordId: null,
          localRecordDigest: null,
        };
        state.operations.push(current);
        createdHere = true;
        await atomicWriteJson(journalPath, state, protection, maximumBytes);
      } else if (reclaimed) {
        await atomicWriteJson(journalPath, state, protection, maximumBytes);
      }
      const checkpoint = async (patch) => {
        current = { ...current, ...patch };
        state.operations[state.operations.findIndex((item) => item.key === current.key)] = current;
        await atomicWriteJson(journalPath, state, protection, maximumBytes);
        return current;
      };
      const discard = async () => {
        const index = state.operations.findIndex((item) => item.key === current.key);
        if (index < 0) throw failure("neutral_host_recovery_operation_missing");
        state.operations.splice(index, 1);
        await atomicWriteJson(journalPath, state, protection, maximumBytes);
      };
      const replaceDuplicate = async (input = {}) => {
        const sourceEventId = safeId(input.eventId, "neutral_host_recovery_duplicate_event_invalid");
        const sourceLocalRecordId = safeId(
          input.localRecordId,
          "neutral_host_recovery_duplicate_record_invalid",
        );
        const index = state.operations.findIndex((item) => (
          item.key === `${identity.kind}:${sourceEventId}`
          && item.key !== current.key
        ));
        if (index < 0) return false;
        const previous = state.operations[index];
        if (previous.localRecordId != null && previous.localRecordId !== sourceLocalRecordId) {
          throw failure("neutral_host_recovery_duplicate_record_conflict");
        }
        state.operations.splice(index, 1);
        await atomicWriteJson(journalPath, state, protection, maximumBytes);
        return true;
      };
      return operation(structuredClone(current), checkpoint, Object.freeze({
        createdHere,
        discard,
        replaceDuplicate,
      }));
    });
  }

  async function snapshot() {
    return queued(
      journalPath,
      async () => structuredClone(await readJournal(journalPath, principalId, protection, maximumBytes)),
    );
  }

  return Object.freeze({ path: journalPath, coordinate, snapshot });
}

function validatePersistenceInput(input, contact) {
  requireRecord(input, "neutral_host_persistence_input_invalid");
  if (!input.event || typeof input.text !== "string" || typeof input.commitPrekey !== "function") {
    throw failure("neutral_host_persistence_input_invalid");
  }
  if (input.modelVisibility !== "none" || Boolean(input.humanOnly) !== contact) {
    throw failure("neutral_host_persistence_visibility_invalid");
  }
  if (!contact && (
    !safeId(input.senderPrincipalId, "neutral_host_persistence_provenance_invalid")
    || !safeId(input.senderDelegateId, "neutral_host_persistence_provenance_invalid")
    || input.authorizationScope !== DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE
    || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(input.intentSource)
  )) throw failure("neutral_host_persistence_provenance_invalid");
}

function eventIdentity(kind, event, envelopeDigest) {
  requireRecord(event, "neutral_host_persistence_event_invalid");
  const eventId = safeId(event.eventId, "neutral_host_persistence_event_invalid");
  const digest = safeDigest(envelopeDigest, "neutral_host_persistence_event_invalid");
  const immutableFields = kind === "message" ? [
    "eventId", "clientMessageId", "senderPrincipalId", "senderHelloLynkId", "senderAgentId",
    "senderDelegateId", "senderDelegateAuthorizationVersion", "senderHostId", "senderDeviceId",
    "senderIdentityKeyId", "recipientPrincipalId", "recipientHelloLynkId", "recipientDelegateId",
    "recipientDelegateAuthorizationVersion", "recipientHostId", "recipientRouteVersion",
    "recipientDeviceId", "recipientIdentityKeyId", "recipientPreKeyId", "claimId", "routeKind",
  ] : [
    "eventId", "attemptId", "clientRequestId", "requestDigest", "introDigest",
    "introWeight", "senderPrincipalId", "senderHelloLynkId", "senderDeviceId", "senderIdentityKeyId",
    "recipientPrincipalId", "recipientHelloLynkId", "recipientDeviceId", "recipientIdentityKeyId",
    "recipientPreKeyId", "claimId", "createdAt", "expiresAt",
  ];
  const immutable = Object.fromEntries(immutableFields.map((field) => [field, event[field] ?? null]));
  return Object.freeze({
    key: `${kind}:${eventId}`,
    kind,
    eventDigest: crypto.createHash("sha256")
      .update(JSON.stringify({ kind, envelopeDigest: digest, immutable }), "utf8")
      .digest("hex"),
  });
}

function persistenceReceipt(item, duplicate, message) {
  return Object.freeze({ localRecordId: item.localRecordId, duplicate,
    ...(message?.replyTargetDeleted === true ? { replyTargetDeleted: true } : {}) });
}

function contactPersistenceReceipt(item, event, principalId, duplicate) {
  const proofInput = {
    attemptId: event.attemptId,
    eventId: event.eventId,
    clientRequestId: event.clientRequestId,
    recipientPrincipalId: principalId,
    recipientEndpointId: event.recipientDeviceId,
    envelopeDigest: event.envelopeDigest,
    claimId: event.claimId,
    localRecordDigest: item.localRecordDigest,
  };
  return Object.freeze({
    localRecordId: item.localRecordId,
    localRecordDigest: item.localRecordDigest,
    ackProofDigest: crypto.createHash("sha256")
      .update(`hellolynk/contact-request/ack-proof/v1\0${JSON.stringify(proofInput)}`, "utf8")
      .digest("hex"),
    duplicate,
  });
}

function normalizeRecoveryDataProtection(protector, profileId) {
  if (protector == null) return null;
  if (["sealJson", "openJson"].some((method) => typeof protector?.[method] !== "function")) {
    throw failure("neutral_host_recovery_data_protector_invalid");
  }
  const acceptedProfileId = safeId(profileId, "neutral_host_recovery_profile_invalid");
  return Object.freeze({
    protector,
    context: Object.freeze({
      profileId: acceptedProfileId,
      assetKind: "neutral-host-recovery",
      logicalPath: "neutral-host-recovery-v1.json",
    }),
  });
}

function normalizeRecoveryJournalMaximumBytes(value) {
  if (value == null) return MAX_JOURNAL_BYTES;
  if (!Number.isSafeInteger(value) || value < 1024 || value > MAX_JOURNAL_BYTES) {
    throw failure("neutral_host_recovery_journal_maximum_invalid");
  }
  return value;
}

function reclaimCompletedOperations(state, currentKey) {
  // The business record and prekey commit are already durable. Replay evidence
  // lives in their stores. Retain unfinished work and the current replay entry.
  const retained = state.operations.filter((item) => item?.stage !== "committed" || item.key === currentKey);
  const removed = state.operations.length - retained.length;
  if (removed) state.operations = retained;
  return removed;
}

async function readJournal(journalPath, principalId, protection = null, maximumBytes = MAX_JOURNAL_BYTES) {
  let body;
  let handle;
  const physicalMaximum = protection ? maximumBytes * 2 : maximumBytes;
  try {
    await assertRecoveryJournalAccess(journalPath, protection, { create: false });
    const metadata = await fs.lstat(journalPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > physicalMaximum) {
      throw failure("neutral_host_recovery_journal_invalid");
    }
    handle = await fs.open(journalPath, "r");
    const openedMetadata = await handle.stat();
    const windowsUnreportedDevice = process.platform === "win32"
      && (metadata.dev === 0 || openedMetadata.dev === 0);
    if (!openedMetadata.isFile() || openedMetadata.size > physicalMaximum
      || (windowsUnreportedDevice && metadata.ino !== openedMetadata.ino)
      || (Number.isSafeInteger(metadata.dev) && Number.isSafeInteger(metadata.ino)
        && Number.isSafeInteger(openedMetadata.dev) && Number.isSafeInteger(openedMetadata.ino)
        && (metadata.ino !== openedMetadata.ino
          || (metadata.dev !== openedMetadata.dev
            && !windowsUnreportedDevice)))) {
      throw failure("neutral_host_recovery_journal_invalid");
    }
    body = await handle.readFile("utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { contract: HELLOLYNK_NEUTRAL_HOST_RECOVERY_CONTRACT, principalId, operations: [] };
    }
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
  let value;
  try {
    const stored = JSON.parse(body);
    value = protection
      ? await protection.protector.openJson(stored, protection.context)
      : stored;
    if (serializedJournalBytes(value) > maximumBytes) {
      throw failure("neutral_host_recovery_journal_invalid");
    }
  } catch {
    throw failure("neutral_host_recovery_journal_invalid");
  }
  if (value?.contract !== HELLOLYNK_NEUTRAL_HOST_RECOVERY_CONTRACT
    || value?.principalId !== principalId || !Array.isArray(value.operations)) {
    throw failure("neutral_host_recovery_journal_invalid");
  }
  return value;
}

async function atomicWriteJson(target, value, protection = null, maximumBytes = MAX_JOURNAL_BYTES) {
  const directory = path.dirname(target);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await assertRecoveryJournalAccess(target, protection, { create: false });
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  if (serializedJournalBytes(value) > maximumBytes) {
    throw failure("neutral_host_recovery_journal_full");
  }
  const stored = protection
    ? await protection.protector.sealJson(value, protection.context)
    : value;
  const body = `${JSON.stringify(stored, null, 2)}\n`;
  const physicalMaximum = protection ? maximumBytes * 2 : maximumBytes;
  if (Buffer.byteLength(body, "utf8") > physicalMaximum) throw failure("neutral_host_recovery_journal_full");
  const handle = await fs.open(temporary, "wx", 0o600);
  try { await handle.writeFile(body, "utf8"); await handle.sync(); } finally { await handle.close(); }
  try {
    await assertRecoveryJournalAccess(target, protection, { create: false });
    await fs.rename(temporary, target);
    await assertRecoveryJournalAccess(target, protection, { create: false });
  } catch (error) { await fs.rm(temporary, { force: true }); throw error; }
}

function serializedJournalBytes(value) {
  return Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function assertRecoveryJournalAccess(target, protection, options = {}) {
  const root = path.dirname(path.resolve(target));
  if (options.create === true) await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const parsed = path.parse(root);
  let cursor = parsed.root;
  for (const segment of path.relative(parsed.root, root).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const metadata = await fs.lstat(cursor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw failure("neutral_host_recovery_journal_directory_invalid");
    }
  }
  await assertLocalDataProtectionAccess(root, protection != null);
}

async function queued(key, operation) {
  const previous = queues.get(key) || Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  queues.set(key, current);
  try { return await current; } finally { if (queues.get(key) === current) queues.delete(key); }
}

function requireMethods(value, methods, code) {
  if (!value || methods.some((method) => typeof value[method] !== "function")) throw failure(code);
  return value;
}

function requireRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure(code);
  return value;
}

function safeId(value, code) {
  const normalized = String(value || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,199}$/.test(normalized)) throw failure(code);
  return normalized;
}

function safeDigest(value, code) {
  const normalized = String(value || "");
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw failure(code);
  return normalized;
}

function failure(code) { const error = new Error(code); error.code = code; return error; }
