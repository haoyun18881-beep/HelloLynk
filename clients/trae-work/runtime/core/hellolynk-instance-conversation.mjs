import crypto from "node:crypto";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const BINDING_FIELDS = Object.freeze([
  "schemaVersion", "region", "localPrincipalId", "localDelegateId", "peerPrincipalId", "peerDelegateId",
]);
const ID_FIELDS = BINDING_FIELDS.slice(2);
const METADATA_FIELDS = Object.freeze([
  "senderPrincipalId", "senderDelegateId", "senderHelloLynkId",
  "recipientPrincipalId", "recipientDelegateId", "recipientHelloLynkId",
]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/;

function invalid(code = "instance_conversation_binding_invalid") {
  const error = new Error(code);
  error.code = code;
  return error;
}

function contextRegion(value) {
  if (value == null) return null;
  if (value === "international") return "intl";
  if (value !== "intl" && value !== "cn") throw invalid();
  return value;
}

function stableIdRegion(value) {
  const identity = runtimeSafety.classifyHelloLynkStableId(value);
  if (!identity) throw invalid("instance_conversation_metadata_invalid");
  return identity.region;
}

export function normalizeInstanceConversationBinding(value, options = {}) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== BINDING_FIELDS.length
    || BINDING_FIELDS.some((field) => !Object.hasOwn(value, field))
    || value.schemaVersion !== 1 || !["intl", "cn"].includes(value.region)
    || ID_FIELDS.some((field) => typeof value[field] !== "string" || !SAFE_ID.test(value[field]))) {
    throw invalid();
  }
  const region = contextRegion(options.region);
  if ((region != null && region !== value.region)
    || (options.principalId != null && options.principalId !== value.localPrincipalId)) {
    throw invalid("instance_conversation_owner_mismatch");
  }
  return Object.freeze(Object.fromEntries(BINDING_FIELDS.map((field) => [field, value[field]])));
}

// The caller supplies metadata only after opening and verifying v2 ciphertext,
// or from its own previously sealed, durably saved outgoing envelope.
export function deriveInstanceConversationBinding(metadata, options = {}) {
  if (!metadata || typeof metadata !== "object" || metadata.e2eeVersion !== 2
    || !["incoming", "outgoing"].includes(options.direction)
    || METADATA_FIELDS.some((field) => typeof metadata[field] !== "string" || !SAFE_ID.test(metadata[field]))) {
    throw invalid("instance_conversation_metadata_invalid");
  }
  const region = stableIdRegion(metadata.senderHelloLynkId);
  if (region !== stableIdRegion(metadata.recipientHelloLynkId)) {
    throw invalid("instance_conversation_region_mismatch");
  }
  const local = options.direction === "incoming" ? "recipient" : "sender";
  const peer = options.direction === "incoming" ? "sender" : "recipient";
  return normalizeInstanceConversationBinding({
    schemaVersion: 1,
    region,
    localPrincipalId: metadata[`${local}PrincipalId`],
    localDelegateId: metadata[`${local}DelegateId`],
    peerPrincipalId: metadata[`${peer}PrincipalId`],
    peerDelegateId: metadata[`${peer}DelegateId`],
  }, options);
}

function assertMessageMatchesBinding(message, binding) {
  const incoming = message.direction === "incoming";
  const senderPrincipalId = incoming ? binding.peerPrincipalId : binding.localPrincipalId;
  const senderDelegateId = incoming ? binding.peerDelegateId : binding.localDelegateId;
  const recipientPrincipalId = incoming ? binding.localPrincipalId : binding.peerPrincipalId;
  const recipientDelegateId = incoming ? binding.localDelegateId : binding.peerDelegateId;
  const expectations = {
    senderPrincipalId, senderDelegateId, recipientPrincipalId, recipientDelegateId,
    peerPrincipalId: binding.peerPrincipalId,
  };
  for (const [field, expected] of Object.entries(expectations)) {
    if (message[field] != null && message[field] !== expected) {
      throw invalid("instance_conversation_message_mismatch");
    }
  }
  for (const field of ["peerHelloLynkId", "senderHelloLynkId", "recipientHelloLynkId"]) {
    if (message[field] != null && stableIdRegion(message[field]) !== binding.region) {
      throw invalid("instance_conversation_region_mismatch");
    }
  }
}

export function getMessageConversationBinding(message, options = {}) {
  if (!message || !["incoming", "outgoing"].includes(message.direction)) throw invalid();
  const persisted = normalizeInstanceConversationBinding(message.conversationBinding, options);
  if (persisted) assertMessageMatchesBinding(message, persisted);
  if (message.direction === "incoming") return persisted;
  const intent = getOutgoingConversationIntent(message, options);
  if (persisted && intent && instanceConversationKey(persisted) !== instanceConversationKey(intent)) {
    throw invalid("instance_conversation_message_mismatch");
  }

  const envelope = message.e2ee?.envelope;
  const metadata = envelope?.protected;
  // Incomplete historical records stay readable as legacy. Current endpoint
  // selection and contact labels are never evidence of their missing recipient.
  if (envelope?.schemaVersion !== 2 || !metadata
    || METADATA_FIELDS.some((field) => metadata[field] == null)) return persisted;
  if (message.e2ee.envelopeDigest == null) {
    if (persisted) throw invalid("instance_conversation_metadata_invalid");
    return null;
  }
  if (message.e2ee.version != null && String(message.e2ee.version) !== "2"
    || message.e2ee.envelopeDigest !== crypto.createHash("sha256").update(JSON.stringify(envelope), "utf8").digest("hex")) {
    throw invalid("instance_conversation_metadata_invalid");
  }
  const derived = deriveInstanceConversationBinding({ ...metadata, e2eeVersion: 2 }, {
    ...options, direction: "outgoing",
  });
  assertMessageMatchesBinding(message, derived);
  if (message.e2ee.recipientDelegateId != null
    && message.e2ee.recipientDelegateId !== metadata.recipientDelegateId) {
    throw invalid("instance_conversation_message_mismatch");
  }
  if (message.peerHelloLynkId != null && message.peerHelloLynkId !== metadata.recipientHelloLynkId) {
    throw invalid("instance_conversation_message_mismatch");
  }
  for (const field of ["senderHelloLynkId", "recipientHelloLynkId"]) {
    if (message[field] != null && message[field] !== metadata[field]) {
      throw invalid("instance_conversation_message_mismatch");
    }
  }
  if (persisted && instanceConversationKey(persisted) !== instanceConversationKey(derived)) {
    throw invalid("instance_conversation_message_mismatch");
  }
  if (intent && instanceConversationKey(intent) !== instanceConversationKey(derived)) {
    throw invalid("instance_conversation_message_mismatch");
  }
  return persisted || derived;
}

// An explicit outgoing target is useful before encryption, but is never used
// as verified evidence for an incoming message or to recover historical IDs.
export function getOutgoingConversationIntent(message, options = {}) {
  if (!message || message.direction !== "outgoing") return null;
  const intent = normalizeInstanceConversationBinding(message.conversationIntent, options);
  if (intent) {
    if (message.senderPrincipalId !== intent.localPrincipalId
      || message.senderDelegateId !== intent.localDelegateId
      || stableIdRegion(message.peerHelloLynkId) !== intent.region) {
      throw invalid("instance_conversation_message_mismatch");
    }
    assertMessageMatchesBinding(message, intent);
  }
  return intent;
}

export function createOutgoingConversationIntent(input = {}) {
  if (input.region == null && input.recipientPrincipalId == null) return null;
  const intent = normalizeInstanceConversationBinding({
    schemaVersion: 1,
    region: contextRegion(input.region),
    localPrincipalId: input.senderPrincipalId,
    localDelegateId: input.senderDelegateId,
    peerPrincipalId: input.recipientPrincipalId,
    peerDelegateId: input.recipientDelegateId,
  });
  return getOutgoingConversationIntent({
    direction: "outgoing", conversationIntent: intent,
    senderPrincipalId: input.senderPrincipalId, senderDelegateId: input.senderDelegateId,
    peerHelloLynkId: input.recipientHelloLynkId,
  });
}

export function instanceConversationKey(value) {
  const binding = normalizeInstanceConversationBinding(value);
  if (!binding) throw invalid();
  const tuple = [binding.region, ...ID_FIELDS.map((field) => binding[field])];
  return `thread_${crypto.createHash("sha256")
    .update("hellolynk-instance-conversation-v1\n", "utf8")
    .update(JSON.stringify(tuple), "utf8").digest("hex").slice(0, 40)}`;
}
