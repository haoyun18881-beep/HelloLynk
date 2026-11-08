import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import {
  DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION,
  publicDirectTextDeviceIdentity,
  publicOneTimePreKey,
  verifyDeviceIdentityRegistration,
  verifyOneTimePreKeyRegistration,
} from "./hellolynk-direct-text-e2ee.mjs";

export const CONTACT_REQUEST_E2EE_SCHEMA_VERSION = 3;
export const CONTACT_REQUEST_E2EE_PROTOCOL = "hellolynk_contact_request_intro_e2ee_v3";
export const CONTACT_REQUEST_E2EE_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM-Ed25519";
export const CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE = "contact.request.send";
export const CONTACT_REQUEST_E2EE_INTENT_SOURCE = "hellolynk_host_explicit_human_ui";
export const CONTACT_REQUEST_E2EE_MESSAGE_TYPE = "contact_request_intro";
export const CONTACT_REQUEST_E2EE_MAX_WEIGHT = 40;
export const CONTACT_REQUEST_E2EE_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const INTRO_DIGEST_SALT_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = INTRO_DIGEST_SALT_BYTES + 80;
// Keep the local record commitment stable. Its random salt is private in v3,
// carried only inside the encrypted payload, never in relay metadata.
const INTRO_DIGEST_DOMAIN = Buffer.from("hellolynk/contact-request/intro-digest/v2\0", "utf8");
const ENVELOPE_SIGNATURE_DOMAIN = "hellolynk/contact-request/envelope-signature/v3\0";
const ENVELOPE_AAD_DOMAIN = "hellolynk/contact-request/envelope-aad/v3\0";
// Replay identity is independent of the wire encryption version. Preserve
// existing local deduplication records when the envelope format changes.
const REPLAY_KEY_DOMAIN = "hellolynk/contact-request/replay-key/v2\0";
const HKDF_INFO = Buffer.from("hellolynk/contact-request/e2ee/v3/aes-256-gcm", "utf8");
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const PROTECTED_FIELDS = Object.freeze([
  "attemptId",
  "clientRequestId",
  "requestDigest",
  "introDigest",
  "introWeight",
  "senderPrincipalId",
  "senderHelloLynkId",
  "senderDeviceId",
  "senderIdentityKeyId",
  "recipientPrincipalId",
  "recipientHelloLynkId",
  "recipientDeviceId",
  "recipientIdentityKeyId",
  "recipientPreKeyId",
  "authorizationScope",
  "intentSource",
  "messageType",
  "createdAt",
  "expiresAt",
]);
const ENVELOPE_FIELDS = Object.freeze([
  "schemaVersion",
  "protocol",
  "algorithm",
  "protected",
  "ephemeralPublicKey",
  "kdfSalt",
  "iv",
  "ciphertext",
  "authenticationTag",
  "signature",
]);
const EXPECTED_ROUTE_FIELDS = Object.freeze(["principalId", "hellolynkId", "deviceId"]);
const COMMITMENT_OPTION_FIELDS = Object.freeze(["introDigestSalt"]);
const PUBLIC_VERIFICATION_INPUT_FIELDS = Object.freeze([
  "envelope",
  "senderDeviceIdentity",
  "recipientDeviceIdentity",
  "recipientOneTimePreKey",
  "expectedSender",
  "expectedRecipient",
]);

const FORBIDDEN_CODE_POINT = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
// A colon in a name or sentence is not itself a link (for example Alice:你好).
const URI_SCHEME = /\b(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:[/\\]|(?:https?|ftps?|wss?|file|mailto|tel|sms|data|javascript|vbscript|blob|about|intent|magnet|urn|hellolynk):\S)/iu;
const EMAIL_ADDRESS = /[\p{L}\p{N}\p{M}.!#$%&'*+/=?^_`{|}~-]+@[\p{L}\p{N}\p{M}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?(?:\.[\p{L}\p{N}\p{M}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?)*/iu;
const ASCII_DOMAIN = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?=$|[^a-z0-9-])/iu;
const UNICODE_DOMAIN = /(?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.)+(?=[\p{L}\p{N}\p{M}-]{2,63}(?=$|[^\p{L}\p{N}\p{M}-]))\p{L}(?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?(?=$|[^\p{L}\p{N}\p{M}-])/iu;
const WWW_LINK = /\bwww\s*\./iu;
const IPV4_LINK = /(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?=$|[^0-9])/u;

export class HelloLynkContactRequestE2eeError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkContactRequestE2eeError";
    this.code = code;
  }
}

export function validateContactRequestIntro(value) {
  if (typeof value !== "string") {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_invalid");
  }
  if (value.length > CONTACT_REQUEST_E2EE_MAX_WEIGHT * 2) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_too_long");
  }
  if (FORBIDDEN_CODE_POINT.test(value)) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_forbidden_character");
  }
  if (/^\p{Zs}*$/u.test(value)) return Object.freeze({ text: "", introWeight: 0 });
  let introWeight = 0;
  for (const codePoint of value) {
    const scalar = codePoint.codePointAt(0);
    introWeight += scalar >= 0x20 && scalar <= 0x7e ? 1 : 2;
    if (introWeight > CONTACT_REQUEST_E2EE_MAX_WEIGHT) {
      throw new HelloLynkContactRequestE2eeError("contact_request_intro_too_long");
    }
  }
  const linkCandidate = value.normalize("NFKC").replace(/[\u3002\uFF0E\uFF61]/gu, ".");
  if (
    URI_SCHEME.test(linkCandidate)
    || EMAIL_ADDRESS.test(linkCandidate)
    || ASCII_DOMAIN.test(linkCandidate)
    || UNICODE_DOMAIN.test(linkCandidate)
    || WWW_LINK.test(linkCandidate)
    || IPV4_LINK.test(linkCandidate)
  ) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_link_forbidden");
  }
  return Object.freeze({ text: value, introWeight });
}

export function createContactRequestIntroCommitment(text, options = {}) {
  assertPlainRecord(options, "contact_request_intro_commitment_options_invalid");
  assertOnlyKnownFields(options, COMMITMENT_OPTION_FIELDS, "contact_request_intro_commitment_options_invalid");
  const accepted = validateContactRequestIntro(text);
  const salt = Object.hasOwn(options, "introDigestSalt")
    ? decodeBase64Url(
        options.introDigestSalt,
        INTRO_DIGEST_SALT_BYTES,
        "contact_request_intro_digest_salt_invalid",
      )
    : randomBytes(INTRO_DIGEST_SALT_BYTES);
  const introDigestSalt = salt.toString("base64url");
  const introDigest = contactRequestIntroDigest(accepted.text, salt);
  salt.fill(0);
  return Object.freeze({
    introDigest,
    introDigestSalt,
    introWeight: accepted.introWeight,
  });
}

export function createContactRequestRecordDigest(input) {
  assertExactFields(
    input,
    ["recipientPrincipalId", "introDigest", "introWeight"],
    "contact_request_record_digest_input_invalid",
  );
  const recipientPrincipalId = assertSafeId(
    input.recipientPrincipalId,
    "contact_request_recipient_principal_id_invalid",
  );
  const introDigest = assertDigest(input.introDigest, "contact_request_intro_digest_invalid");
  const introWeight = input.introWeight;
  if (!Number.isSafeInteger(introWeight)
    || introWeight < 0
    || introWeight > CONTACT_REQUEST_E2EE_MAX_WEIGHT) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_weight_invalid");
  }
  return createHash("sha256")
    .update(
      `hellolynk-contact-request-record-v2\0${recipientPrincipalId}\0${introDigest}\0${introWeight}`,
      "utf8",
    )
    .digest("hex");
}

export function sealContactRequestIntroEnvelope(input, options = {}) {
  assertExactFields(input, [
    "protectedMetadata",
    "recipientDeviceIdentity",
    "recipientOneTimePreKey",
    "senderDeviceKeyBundle",
    "introText",
    "introDigestSalt",
  ], "contact_request_e2ee_seal_input_invalid");
  const nowMs = normalizeNowOptions(options, "contact_request_e2ee_seal_options_invalid");
  const protectedMetadata = canonicalProtectedMetadata(input.protectedMetadata);
  assertEnvelopeTime(protectedMetadata, nowMs);

  const senderIdentity = publicIdentityFromPrivateBundle(input.senderDeviceKeyBundle);
  const recipientIdentity = canonicalDeviceIdentity(input.recipientDeviceIdentity);
  const recipientPreKey = canonicalPublicPreKey(input.recipientOneTimePreKey);
  if (!verifyDeviceIdentityRegistration(recipientIdentity)) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({
    identity: recipientIdentity,
    oneTimePreKey: recipientPreKey,
  })) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_prekey_signature_invalid");
  }
  if (protectedMetadata.senderIdentityKeyId !== senderIdentity.keyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientIdentity.keyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_prekey_mismatch");
  }

  const acceptedIntro = validateContactRequestIntro(input.introText);
  verifyIntroCommitment(protectedMetadata, acceptedIntro, input.introDigestSalt);
  const privateSalt = decodeBase64Url(input.introDigestSalt, INTRO_DIGEST_SALT_BYTES,
    "contact_request_intro_digest_salt_invalid");
  const plaintext = Buffer.concat([privateSalt, Buffer.from(acceptedIntro.text, "utf8")]);
  privateSalt.fill(0);
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPairSync("x25519");
  const ephemeralPublicKeyValue = ephemeralPublicKey
    .export({ format: "der", type: "spki" })
    .toString("base64url");
  const kdfSalt = randomBytes(32);
  const iv = randomBytes(12);
  const header = Object.freeze({
    protected: protectedMetadata,
    ephemeralPublicKey: ephemeralPublicKeyValue,
    kdfSalt: kdfSalt.toString("base64url"),
    iv: iv.toString("base64url"),
  });
  const aad = domainSeparatedBytes(ENVELOPE_AAD_DOMAIN, header);
  const recipientPublicKey = importPublicDer(
    recipientPreKey.publicKey,
    "x25519",
    "contact_request_recipient_prekey_public_invalid",
  );
  let sharedSecret;
  let aesKey;
  try {
    sharedSecret = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey: recipientPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, kdfSalt, HKDF_INFO, 32));
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const unsignedEnvelope = canonicalUnsignedEnvelope({
      schemaVersion: CONTACT_REQUEST_E2EE_SCHEMA_VERSION,
      protocol: CONTACT_REQUEST_E2EE_PROTOCOL,
      algorithm: CONTACT_REQUEST_E2EE_ALGORITHM,
      protected: protectedMetadata,
      ephemeralPublicKey: header.ephemeralPublicKey,
      kdfSalt: header.kdfSalt,
      iv: header.iv,
      ciphertext: ciphertext.toString("base64url"),
      authenticationTag: cipher.getAuthTag().toString("base64url"),
    });
    const signingPrivateKey = privateIdentityKey(input.senderDeviceKeyBundle);
    return Object.freeze({
      ...unsignedEnvelope,
      signature: sign(
        null,
        domainSeparatedBytes(ENVELOPE_SIGNATURE_DOMAIN, unsignedEnvelope),
        signingPrivateKey,
      ).toString("base64url"),
    });
  } catch (error) {
    if (error instanceof HelloLynkContactRequestE2eeError) throw error;
    throw new HelloLynkContactRequestE2eeError("contact_request_encryption_failed");
  } finally {
    plaintext.fill(0);
    kdfSalt.fill(0);
    iv.fill(0);
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
}

export function openContactRequestIntroEnvelope(input, options = {}) {
  assertExactFields(input, [
    "envelope",
    "senderDeviceIdentity",
    "recipientDeviceKeyBundle",
    "recipientOneTimePreKey",
    "expectedSender",
    "expectedRecipient",
  ], "contact_request_e2ee_open_input_invalid");
  const nowMs = normalizeNowOptions(options, "contact_request_e2ee_open_options_invalid");
  const recipientIdentity = publicIdentityFromPrivateBundle(input.recipientDeviceKeyBundle);
  const recipientPreKey = privatePreKeyFromBundle(
    input.recipientOneTimePreKey,
    input.recipientDeviceKeyBundle,
  );
  const verified = verifyContactRequestIntroEnvelopePublicBinding({
    envelope: input.envelope,
    senderDeviceIdentity: input.senderDeviceIdentity,
    recipientDeviceIdentity: recipientIdentity,
    recipientOneTimePreKey: recipientPreKey.publicPreKey,
    expectedSender: input.expectedSender,
    expectedRecipient: input.expectedRecipient,
  }, { nowMs });
  const { envelope, protectedMetadata } = verified;

  const ephemeralPublicKey = importPublicDer(
    envelope.ephemeralPublicKey,
    "x25519",
    "contact_request_ephemeral_public_key_invalid",
  );
  const recipientPrivateKey = importPrivateDer(
    recipientPreKey.privateKey,
    "x25519",
    "contact_request_recipient_prekey_private_invalid",
  );
  const kdfSalt = decodeBase64Url(envelope.kdfSalt, 32, "contact_request_kdf_salt_invalid");
  const iv = decodeBase64Url(envelope.iv, 12, "contact_request_iv_invalid");
  const ciphertext = decodeBase64Url(
    envelope.ciphertext,
    null,
    "contact_request_ciphertext_invalid",
    { minimumBytes: INTRO_DIGEST_SALT_BYTES, maximumBytes: MAX_CIPHERTEXT_BYTES },
  );
  const authenticationTag = decodeBase64Url(
    envelope.authenticationTag,
    16,
    "contact_request_authentication_tag_invalid",
  );
  const aad = domainSeparatedBytes(ENVELOPE_AAD_DOMAIN, {
    protected: protectedMetadata,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    kdfSalt: envelope.kdfSalt,
    iv: envelope.iv,
  });
  let sharedSecret;
  let aesKey;
  let plaintext;
  try {
    sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, kdfSalt, HKDF_INFO, 32));
    const decipher = createDecipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(authenticationTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new HelloLynkContactRequestE2eeError("contact_request_decryption_failed");
  } finally {
    kdfSalt.fill(0);
    iv.fill(0);
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }

  try {
    const introDigestSalt = plaintext.subarray(0, INTRO_DIGEST_SALT_BYTES).toString("base64url");
    let introText;
    try {
      introText = textDecoder.decode(plaintext.subarray(INTRO_DIGEST_SALT_BYTES));
    } catch {
      throw new HelloLynkContactRequestE2eeError("contact_request_plaintext_invalid");
    }
    const acceptedIntro = validateContactRequestIntro(introText);
    verifyIntroCommitment(protectedMetadata, acceptedIntro, introDigestSalt);
    return Object.freeze({
      introText: acceptedIntro.text,
      introDigestSalt,
      protectedMetadata,
      envelopeDigest: digestContactRequestIntroEnvelope(envelope),
      replayKey: contactRequestIntroReplayKey(protectedMetadata),
    });
  } finally {
    plaintext.fill(0);
  }
}

export function verifyContactRequestIntroEnvelopePublicBinding(input, options = {}) {
  assertExactFields(
    input,
    PUBLIC_VERIFICATION_INPUT_FIELDS,
    "contact_request_e2ee_public_verification_input_invalid",
  );
  const nowMs = normalizeNowOptions(
    options,
    "contact_request_e2ee_public_verification_options_invalid",
  );
  const envelope = canonicalEnvelope(input.envelope);
  const senderIdentity = canonicalDeviceIdentity(input.senderDeviceIdentity);
  const recipientIdentity = canonicalDeviceIdentity(input.recipientDeviceIdentity);
  const recipientPreKey = canonicalPublicPreKey(input.recipientOneTimePreKey);
  if (!verifyDeviceIdentityRegistration(senderIdentity)) {
    throw new HelloLynkContactRequestE2eeError("contact_request_sender_identity_signature_invalid");
  }
  if (!verifyDeviceIdentityRegistration(recipientIdentity)) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({
    identity: recipientIdentity,
    oneTimePreKey: recipientPreKey,
  })) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_prekey_signature_invalid");
  }
  const expectedSender = canonicalExpectedRoute(input.expectedSender);
  const expectedRecipient = canonicalExpectedRoute(input.expectedRecipient);
  const protectedMetadata = envelope.protected;
  if (protectedMetadata.senderIdentityKeyId !== senderIdentity.keyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientIdentity.keyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_recipient_prekey_mismatch");
  }
  assertExpectedRoute(protectedMetadata, "sender", expectedSender);
  assertExpectedRoute(protectedMetadata, "recipient", expectedRecipient);
  const unsignedEnvelope = canonicalUnsignedEnvelope(envelope);
  const senderPublicKey = importPublicDer(
    senderIdentity.publicKey,
    "ed25519",
    "contact_request_sender_public_key_invalid",
  );
  if (!verify(
    null,
    domainSeparatedBytes(ENVELOPE_SIGNATURE_DOMAIN, unsignedEnvelope),
    senderPublicKey,
    decodeBase64Url(
      envelope.signature,
      64,
      "contact_request_envelope_signature_invalid",
    ),
  )) {
    throw new HelloLynkContactRequestE2eeError("contact_request_envelope_signature_invalid");
  }
  assertEnvelopeTime(protectedMetadata, nowMs);
  importPublicDer(
    envelope.ephemeralPublicKey,
    "x25519",
    "contact_request_ephemeral_public_key_invalid",
  );
  return Object.freeze({
    envelope: Object.freeze(envelope),
    protectedMetadata,
    envelopeDigest: digestContactRequestIntroEnvelope(envelope),
    replayKey: contactRequestIntroReplayKey(protectedMetadata),
  });
}

export function digestContactRequestIntroEnvelope(envelope) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalEnvelope(envelope)), "utf8")
    .digest("hex");
}

export function contactRequestIntroReplayKey(protectedMetadata) {
  const accepted = canonicalProtectedMetadata(protectedMetadata);
  return createHash("sha256")
    .update(
      `${REPLAY_KEY_DOMAIN}${accepted.senderPrincipalId}\0${accepted.attemptId}\0${accepted.clientRequestId}`,
      "utf8",
    )
    .digest("hex");
}

export function classifyContactRequestIntroReplay(input) {
  assertExactFields(
    input,
    ["replayKey", "envelopeDigest", "existingEnvelopeDigest"],
    "contact_request_replay_input_invalid",
  );
  const replayKey = assertDigest(input.replayKey, "contact_request_replay_key_invalid");
  const envelopeDigest = assertDigest(input.envelopeDigest, "contact_request_envelope_digest_invalid");
  const existingEnvelopeDigest = input.existingEnvelopeDigest == null
    ? null
    : assertDigest(
        input.existingEnvelopeDigest,
        "contact_request_existing_envelope_digest_invalid",
      );
  if (existingEnvelopeDigest == null) {
    return Object.freeze({ decision: "accept_new", replayKey, envelopeDigest });
  }
  const same = timingSafeEqual(
    Buffer.from(envelopeDigest, "hex"),
    Buffer.from(existingEnvelopeDigest, "hex"),
  );
  return Object.freeze({
    decision: same ? "idempotent_replay" : "conflicting_replay",
    replayKey,
    envelopeDigest,
  });
}

function verifyIntroCommitment(protectedMetadata, acceptedIntro, introDigestSalt) {
  if (acceptedIntro.introWeight !== protectedMetadata.introWeight) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_weight_mismatch");
  }
  const salt = decodeBase64Url(
    introDigestSalt,
    INTRO_DIGEST_SALT_BYTES,
    "contact_request_intro_digest_salt_invalid",
  );
  const expectedDigest = contactRequestIntroDigest(acceptedIntro.text, salt);
  salt.fill(0);
  if (!timingSafeEqual(
    Buffer.from(expectedDigest, "hex"),
    Buffer.from(protectedMetadata.introDigest, "hex"),
  )) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_digest_mismatch");
  }
}

function contactRequestIntroDigest(text, salt) {
  return createHash("sha256")
    .update(INTRO_DIGEST_DOMAIN)
    .update(salt)
    .update(Buffer.from(text, "utf8"))
    .digest("hex");
}

function canonicalProtectedMetadata(input) {
  assertExactFields(input, PROTECTED_FIELDS, "contact_request_protected_metadata_invalid");
  const accepted = {
    attemptId: assertSafeId(input.attemptId, "contact_request_attempt_id_invalid"),
    clientRequestId: assertSafeId(input.clientRequestId, "contact_request_client_request_id_invalid"),
    requestDigest: assertDigest(input.requestDigest, "contact_request_request_digest_invalid"),
    introDigest: assertDigest(input.introDigest, "contact_request_intro_digest_invalid"),
    introWeight: input.introWeight,
    senderPrincipalId: assertSafeId(input.senderPrincipalId, "contact_request_sender_principal_id_invalid"),
    senderHelloLynkId: assertHelloLynkId(input.senderHelloLynkId, "contact_request_sender_hellolynk_id_invalid"),
    senderDeviceId: assertSafeId(input.senderDeviceId, "contact_request_sender_device_id_invalid"),
    senderIdentityKeyId: assertSafeId(input.senderIdentityKeyId, "contact_request_sender_identity_key_id_invalid"),
    recipientPrincipalId: assertSafeId(input.recipientPrincipalId, "contact_request_recipient_principal_id_invalid"),
    recipientHelloLynkId: assertHelloLynkId(input.recipientHelloLynkId, "contact_request_recipient_hellolynk_id_invalid"),
    recipientDeviceId: assertSafeId(input.recipientDeviceId, "contact_request_recipient_device_id_invalid"),
    recipientIdentityKeyId: assertSafeId(input.recipientIdentityKeyId, "contact_request_recipient_identity_key_id_invalid"),
    recipientPreKeyId: assertSafeId(input.recipientPreKeyId, "contact_request_recipient_prekey_id_invalid"),
    authorizationScope: input.authorizationScope,
    intentSource: input.intentSource,
    messageType: input.messageType,
    createdAt: assertIsoTimestamp(input.createdAt, "contact_request_created_at_invalid"),
    expiresAt: assertIsoTimestamp(input.expiresAt, "contact_request_expires_at_invalid"),
  };
  if (!Number.isSafeInteger(accepted.introWeight)
    || accepted.introWeight < 0
    || accepted.introWeight > CONTACT_REQUEST_E2EE_MAX_WEIGHT) {
    throw new HelloLynkContactRequestE2eeError("contact_request_intro_weight_invalid");
  }
  if (
    accepted.authorizationScope !== CONTACT_REQUEST_E2EE_AUTHORIZATION_SCOPE
    || accepted.intentSource !== CONTACT_REQUEST_E2EE_INTENT_SOURCE
    || accepted.messageType !== CONTACT_REQUEST_E2EE_MESSAGE_TYPE
  ) {
    throw new HelloLynkContactRequestE2eeError("contact_request_protected_metadata_invalid");
  }
  if (accepted.senderPrincipalId === accepted.recipientPrincipalId) {
    throw new HelloLynkContactRequestE2eeError("contact_request_self_target_invalid");
  }
  const expectedRequestDigest = createContactRequestRecordDigest({
    recipientPrincipalId: accepted.recipientPrincipalId,
    introDigest: accepted.introDigest,
    introWeight: accepted.introWeight,
  });
  if (!timingSafeEqual(
    Buffer.from(accepted.requestDigest, "hex"),
    Buffer.from(expectedRequestDigest, "hex"),
  )) {
    throw new HelloLynkContactRequestE2eeError("contact_request_request_digest_mismatch");
  }
  const createdAtMs = Date.parse(accepted.createdAt);
  const expiresAtMs = Date.parse(accepted.expiresAt);
  if (
    expiresAtMs <= createdAtMs
    || expiresAtMs - createdAtMs > CONTACT_REQUEST_E2EE_MAX_TTL_MS
  ) {
    throw new HelloLynkContactRequestE2eeError("contact_request_expiry_window_invalid");
  }
  return Object.freeze(accepted);
}

function canonicalUnsignedEnvelope(input) {
  const unsignedFields = ENVELOPE_FIELDS.slice(0, -1);
  const source = Object.hasOwn(input, "signature")
    ? {
        schemaVersion: input.schemaVersion,
        protocol: input.protocol,
        algorithm: input.algorithm,
        protected: input.protected,
        ephemeralPublicKey: input.ephemeralPublicKey,
        kdfSalt: input.kdfSalt,
        iv: input.iv,
        ciphertext: input.ciphertext,
        authenticationTag: input.authenticationTag,
      }
    : input;
  assertExactFields(source, unsignedFields, "contact_request_envelope_invalid");
  if (
    source.schemaVersion !== CONTACT_REQUEST_E2EE_SCHEMA_VERSION
    || source.protocol !== CONTACT_REQUEST_E2EE_PROTOCOL
    || source.algorithm !== CONTACT_REQUEST_E2EE_ALGORITHM
  ) {
    throw new HelloLynkContactRequestE2eeError("contact_request_envelope_algorithm_invalid");
  }
  return {
    schemaVersion: source.schemaVersion,
    protocol: source.protocol,
    algorithm: source.algorithm,
    protected: canonicalProtectedMetadata(source.protected),
    ephemeralPublicKey: canonicalBase64Url(
      source.ephemeralPublicKey,
      44,
      "contact_request_ephemeral_public_key_invalid",
    ),
    kdfSalt: canonicalBase64Url(source.kdfSalt, 32, "contact_request_kdf_salt_invalid"),
    iv: canonicalBase64Url(source.iv, 12, "contact_request_iv_invalid"),
    ciphertext: canonicalBase64Url(
      source.ciphertext,
      null,
      "contact_request_ciphertext_invalid",
      { minimumBytes: INTRO_DIGEST_SALT_BYTES, maximumBytes: MAX_CIPHERTEXT_BYTES },
    ),
    authenticationTag: canonicalBase64Url(
      source.authenticationTag,
      16,
      "contact_request_authentication_tag_invalid",
    ),
  };
}

function canonicalEnvelope(input) {
  assertExactFields(input, ENVELOPE_FIELDS, "contact_request_envelope_invalid");
  const unsigned = canonicalUnsignedEnvelope(input);
  return {
    ...unsigned,
    signature: canonicalBase64Url(
      input.signature,
      64,
      "contact_request_envelope_signature_invalid",
    ),
  };
}

function canonicalExpectedRoute(input) {
  assertExactFields(input, EXPECTED_ROUTE_FIELDS, "contact_request_expected_route_invalid");
  return {
    principalId: assertSafeId(input.principalId, "contact_request_expected_route_invalid"),
    hellolynkId: assertHelloLynkId(input.hellolynkId, "contact_request_expected_route_invalid"),
    deviceId: assertSafeId(input.deviceId, "contact_request_expected_route_invalid"),
  };
}

function assertExpectedRoute(protectedMetadata, prefix, expected) {
  if (
    protectedMetadata[`${prefix}PrincipalId`] !== expected.principalId
    || protectedMetadata[`${prefix}HelloLynkId`] !== expected.hellolynkId
    || protectedMetadata[`${prefix}DeviceId`] !== expected.deviceId
  ) {
    throw new HelloLynkContactRequestE2eeError(`contact_request_${prefix}_route_mismatch`);
  }
}

function canonicalDeviceIdentity(input) {
  assertExactFields(
    input,
    ["schemaVersion", "keyId", "algorithm", "publicKey", "createdAt", "ownershipSignature"],
    "contact_request_device_identity_invalid",
  );
  if (input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION || input.algorithm !== "Ed25519") {
    throw new HelloLynkContactRequestE2eeError("contact_request_device_identity_invalid");
  }
  canonicalBase64Url(input.publicKey, 44, "contact_request_device_public_key_invalid");
  canonicalBase64Url(input.ownershipSignature, 64, "contact_request_identity_signature_invalid");
  return Object.freeze({
    schemaVersion: input.schemaVersion,
    keyId: assertSafeId(input.keyId, "contact_request_identity_key_id_invalid"),
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: assertIsoTimestamp(input.createdAt, "contact_request_identity_created_at_invalid"),
    ownershipSignature: input.ownershipSignature,
  });
}

function canonicalPublicPreKey(input) {
  assertExactFields(
    input,
    ["schemaVersion", "preKeyId", "identityKeyId", "algorithm", "publicKey", "createdAt", "signature"],
    "contact_request_public_prekey_invalid",
  );
  if (input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION || input.algorithm !== "X25519") {
    throw new HelloLynkContactRequestE2eeError("contact_request_public_prekey_invalid");
  }
  canonicalBase64Url(input.publicKey, 44, "contact_request_prekey_public_invalid");
  canonicalBase64Url(input.signature, 64, "contact_request_prekey_signature_invalid");
  return Object.freeze({
    schemaVersion: input.schemaVersion,
    preKeyId: assertSafeId(input.preKeyId, "contact_request_prekey_id_invalid"),
    identityKeyId: assertSafeId(input.identityKeyId, "contact_request_identity_key_id_invalid"),
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: assertIsoTimestamp(input.createdAt, "contact_request_prekey_created_at_invalid"),
    signature: input.signature,
  });
}

function publicIdentityFromPrivateBundle(bundle) {
  try {
    return publicDirectTextDeviceIdentity(bundle);
  } catch {
    throw new HelloLynkContactRequestE2eeError("contact_request_device_key_bundle_invalid");
  }
}

function privateIdentityKey(bundle) {
  publicIdentityFromPrivateBundle(bundle);
  return importPrivateDer(
    bundle.privateKey,
    "ed25519",
    "contact_request_sender_private_key_invalid",
  );
}

function privatePreKeyFromBundle(preKeyBundle, deviceKeyBundle) {
  let publicPreKey;
  try {
    publicPreKey = publicOneTimePreKey(preKeyBundle, deviceKeyBundle);
  } catch {
    throw new HelloLynkContactRequestE2eeError("contact_request_private_prekey_invalid");
  }
  return {
    preKeyId: publicPreKey.preKeyId,
    identityKeyId: publicPreKey.identityKeyId,
    privateKey: preKeyBundle.privateKey,
    publicPreKey,
  };
}

function assertEnvelopeTime(protectedMetadata, nowMs) {
  const createdAtMs = Date.parse(protectedMetadata.createdAt);
  const expiresAtMs = Date.parse(protectedMetadata.expiresAt);
  if (createdAtMs > nowMs + MAX_CLOCK_SKEW_MS) {
    throw new HelloLynkContactRequestE2eeError("contact_request_created_at_in_future");
  }
  if (expiresAtMs <= nowMs) {
    throw new HelloLynkContactRequestE2eeError("contact_request_envelope_expired");
  }
}

function normalizeNowOptions(options, code) {
  assertPlainRecord(options, code);
  assertOnlyKnownFields(options, ["nowMs"], code);
  const nowMs = options.nowMs == null ? Date.now() : Number(options.nowMs);
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return nowMs;
}

function assertIsoTimestamp(value, code) {
  if (typeof value !== "string") throw new HelloLynkContactRequestE2eeError(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return value;
}

function assertSafeId(value, code) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,199}$/.test(value)) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return value;
}

function assertHelloLynkId(value, code) {
  if (typeof value !== "string" || !/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(value)) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return value;
}

function assertDigest(value, code) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return value;
}

function assertPlainRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
}

function assertOnlyKnownFields(value, expectedFields, code) {
  if (Object.keys(value).some((field) => !expectedFields.includes(field))) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
}

function assertExactFields(value, expectedFields, code) {
  assertPlainRecord(value, code);
  const actualFields = Object.keys(value);
  if (
    actualFields.length !== expectedFields.length
    || expectedFields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
}

function canonicalBase64Url(value, expectedBytes, code, limits = {}) {
  return decodeBase64Url(value, expectedBytes, code, limits).toString("base64url");
}

function decodeBase64Url(value, expectedBytes, code, limits = {}) {
  if (typeof value !== "string"
    || (!/^[A-Za-z0-9_-]+$/.test(value) && !(value === "" && limits.minimumBytes === 0))) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new HelloLynkContactRequestE2eeError(code);
  if (expectedBytes != null && decoded.length !== expectedBytes) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  if (limits.minimumBytes != null && decoded.length < limits.minimumBytes) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  if (limits.maximumBytes != null && decoded.length > limits.maximumBytes) {
    throw new HelloLynkContactRequestE2eeError(code);
  }
  return decoded;
}

function importPrivateDer(value, asymmetricKeyType, code) {
  try {
    const der = decodeBase64Url(value, 48, code);
    const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    if (key.asymmetricKeyType !== asymmetricKeyType) throw new Error("type");
    return key;
  } catch (error) {
    if (error instanceof HelloLynkContactRequestE2eeError) throw error;
    throw new HelloLynkContactRequestE2eeError(code);
  }
}

function importPublicDer(value, asymmetricKeyType, code) {
  try {
    const der = decodeBase64Url(value, 44, code);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== asymmetricKeyType) throw new Error("type");
    return key;
  } catch (error) {
    if (error instanceof HelloLynkContactRequestE2eeError) throw error;
    throw new HelloLynkContactRequestE2eeError(code);
  }
}

function domainSeparatedBytes(domain, value) {
  return Buffer.from(`${domain}${JSON.stringify(value)}`, "utf8");
}
