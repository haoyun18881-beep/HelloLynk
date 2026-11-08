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

export const DIRECT_TEXT_E2EE_SCHEMA_VERSION = 1;
export const DIRECT_TEXT_E2EE_PROTOCOL = "hellolynk_direct_text_e2ee_v1";
export const DIRECT_TEXT_E2EE_V2_SCHEMA_VERSION = 2;
export const DIRECT_TEXT_E2EE_V2_PROTOCOL = "hellolynk_direct_text_e2ee_v2";
export const DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION = 2;
export const DIRECT_TEXT_E2EE_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM-Ed25519";
export const DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE = "relay.text.send";
export const DIRECT_TEXT_E2EE_INTENT_SOURCE = "hellolynk_client_explicit_send";
export const DIRECT_TEXT_E2EE_NATIVE_HUMAN_INTENT_SOURCE = "human_native_dialog";
export const DIRECT_TEXT_E2EE_PREAUTHORIZED_CONTACT_INTENT_SOURCE = "human_preauthorized_contact";
export const DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES = Object.freeze([
  DIRECT_TEXT_E2EE_INTENT_SOURCE,
  DIRECT_TEXT_E2EE_NATIVE_HUMAN_INTENT_SOURCE,
  DIRECT_TEXT_E2EE_PREAUTHORIZED_CONTACT_INTENT_SOURCE,
]);
export const DIRECT_TEXT_E2EE_MAX_TTL_MS = 5 * 60 * 1000;
export const DIRECT_TEXT_E2EE_MAX_TEXT_UTF8_BYTES = 64 * 1024;

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_CIPHERTEXT_BYTES = DIRECT_TEXT_E2EE_MAX_TEXT_UTF8_BYTES;
const DEVICE_KEY_PURPOSE = "hellolynk_direct_text_device_identity_v2";
const PRE_KEY_PURPOSE = "hellolynk_direct_text_one_time_prekey_v2";
const DEVICE_IDENTITY_REGISTRATION_DOMAIN = "hellolynk/direct-text/device-identity-registration/v2\0";
const PRE_KEY_REGISTRATION_DOMAIN = "hellolynk/direct-text/one-time-prekey-registration/v2\0";
const ENVELOPE_SIGNATURE_DOMAIN = "hellolynk/direct-text/envelope-signature/v1\0";
const ENVELOPE_AAD_DOMAIN = "hellolynk/direct-text/envelope-aad/v1\0";
const HKDF_INFO = Buffer.from("hellolynk/direct-text/e2ee/v1/aes-256-gcm", "utf8");
const ENVELOPE_V2_SIGNATURE_DOMAIN = "hellolynk/direct-text/envelope-signature/v2\0";
const ENVELOPE_V2_AAD_DOMAIN = "hellolynk/direct-text/envelope-aad/v2\0";
const HKDF_V2_INFO = Buffer.from("hellolynk/direct-text/e2ee/v2/aes-256-gcm", "utf8");
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const DEVICE_PRIVATE_FIELDS = Object.freeze([
  "schemaVersion", "purpose", "keyId", "algorithm", "publicKey", "privateKey", "createdAt",
]);
const DEVICE_PUBLIC_UNSIGNED_FIELDS = Object.freeze([
  "schemaVersion", "keyId", "algorithm", "publicKey", "createdAt",
]);
const DEVICE_PUBLIC_FIELDS = Object.freeze([
  ...DEVICE_PUBLIC_UNSIGNED_FIELDS, "ownershipSignature",
]);
const PRE_KEY_PRIVATE_FIELDS = Object.freeze([
  "schemaVersion", "purpose", "preKeyId", "algorithm", "publicKey", "privateKey", "createdAt",
]);
const PRE_KEY_PUBLIC_UNSIGNED_FIELDS = Object.freeze([
  "schemaVersion", "preKeyId", "identityKeyId", "algorithm", "publicKey", "createdAt",
]);
const PRE_KEY_PUBLIC_FIELDS = Object.freeze([
  ...PRE_KEY_PUBLIC_UNSIGNED_FIELDS, "signature",
]);
const PROTECTED_FIELDS = Object.freeze([
  "clientMessageId",
  "senderPrincipalId",
  "senderHelloLynkId",
  "senderAgentId",
  "senderDelegateId",
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
const PROTECTED_V2_FIELDS = Object.freeze([
  "clientMessageId",
  "routeKind",
  "senderPrincipalId",
  "senderHelloLynkId",
  "senderAgentId",
  "senderDelegateId",
  "senderDelegateAuthorizationVersion",
  "senderHostId",
  "senderDeviceId",
  "senderIdentityKeyId",
  "recipientPrincipalId",
  "recipientHelloLynkId",
  "recipientDelegateId",
  "recipientDelegateAuthorizationVersion",
  "recipientHostId",
  "recipientRouteVersion",
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
  "salt",
  "iv",
  "ciphertext",
  "authenticationTag",
  "signature",
]);
const EXPECTED_RECIPIENT_FIELDS = Object.freeze(["principalId", "hellolynkId", "deviceId"]);
const EXPECTED_RECIPIENT_V2_FIELDS = Object.freeze([
  "principalId", "hellolynkId", "delegateId", "hostId", "deviceId",
]);

export class HelloLynkDirectTextE2eeError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkDirectTextE2eeError";
    this.code = code;
  }
}

export function createDirectTextDeviceKeyBundle(options = {}) {
  const nowMs = normalizeNowOptions(options, "e2ee_key_generation_options_invalid");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  return Object.freeze({
    schemaVersion: DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION,
    purpose: DEVICE_KEY_PURPOSE,
    keyId: keyIdForPublicDer("e2ee_id_", publicDer),
    algorithm: "Ed25519",
    publicKey: publicDer.toString("base64url"),
    privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
    createdAt: new Date(nowMs).toISOString(),
  });
}

export function publicDirectTextDeviceIdentity(deviceKeyBundle) {
  const bundle = canonicalDevicePrivateBundle(deviceKeyBundle);
  const unsigned = canonicalDeviceIdentityUnsigned({
    schemaVersion: bundle.schemaVersion,
    keyId: bundle.keyId,
    algorithm: bundle.algorithm,
    publicKey: bundle.publicKey,
    createdAt: bundle.createdAt,
  });
  const privateKey = importPrivateDer(bundle.privateKey, "ed25519", "e2ee_device_private_key_invalid");
  return Object.freeze({
    ...unsigned,
    ownershipSignature: sign(
      null,
      domainSeparatedBytes(DEVICE_IDENTITY_REGISTRATION_DOMAIN, unsigned),
      privateKey,
    ).toString("base64url"),
  });
}

export function verifyDeviceIdentityRegistration(identity) {
  try {
    const accepted = canonicalDeviceIdentity(identity);
    const publicKey = importPublicDer(accepted.publicKey, "ed25519", "e2ee_device_public_key_invalid");
    return verify(
      null,
      domainSeparatedBytes(
        DEVICE_IDENTITY_REGISTRATION_DOMAIN,
        canonicalDeviceIdentityUnsigned(accepted),
      ),
      publicKey,
      decodeBase64Url(accepted.ownershipSignature, 64, "e2ee_identity_signature_invalid"),
    );
  } catch {
    return false;
  }
}

export function createOneTimePreKey(options = {}) {
  const nowMs = normalizeNowOptions(options, "e2ee_prekey_generation_options_invalid");
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  return Object.freeze({
    schemaVersion: DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION,
    purpose: PRE_KEY_PURPOSE,
    preKeyId: keyIdForPublicDer("e2ee_pre_", publicDer),
    algorithm: "X25519",
    publicKey: publicDer.toString("base64url"),
    privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
    createdAt: new Date(nowMs).toISOString(),
  });
}

export function publicOneTimePreKey(oneTimePreKey, deviceKeyBundle) {
  const preKey = canonicalPrivatePreKey(oneTimePreKey);
  const bundle = canonicalDevicePrivateBundle(deviceKeyBundle);
  const unsigned = canonicalPublicPreKeyUnsigned({
    schemaVersion: preKey.schemaVersion,
    preKeyId: preKey.preKeyId,
    identityKeyId: bundle.keyId,
    algorithm: preKey.algorithm,
    publicKey: preKey.publicKey,
    createdAt: preKey.createdAt,
  });
  const privateKey = importPrivateDer(bundle.privateKey, "ed25519", "e2ee_device_private_key_invalid");
  return Object.freeze({
    ...unsigned,
    signature: sign(
      null,
      domainSeparatedBytes(PRE_KEY_REGISTRATION_DOMAIN, unsigned),
      privateKey,
    ).toString("base64url"),
  });
}

export function verifyOneTimePreKeyRegistration(input) {
  try {
    assertExactFields(input, ["identity", "oneTimePreKey"], "e2ee_prekey_verification_input_invalid");
    const identity = canonicalDeviceIdentity(input.identity);
    const preKey = canonicalPublicPreKey(input.oneTimePreKey);
    if (!verifyDeviceIdentityRegistration(identity) || preKey.identityKeyId !== identity.keyId) return false;
    const publicKey = importPublicDer(identity.publicKey, "ed25519", "e2ee_device_public_key_invalid");
    return verify(
      null,
      domainSeparatedBytes(
        PRE_KEY_REGISTRATION_DOMAIN,
        canonicalPublicPreKeyUnsigned(preKey),
      ),
      publicKey,
      decodeBase64Url(preKey.signature, 64, "e2ee_prekey_signature_invalid"),
    );
  } catch {
    return false;
  }
}

export function sealDirectTextEnvelope(input, options = {}) {
  assertExactFields(input, [
    "protectedMetadata",
    "recipientDeviceIdentity",
    "recipientOneTimePreKey",
    "senderDeviceKeyBundle",
    "text",
  ], "e2ee_seal_input_invalid");
  const nowMs = normalizeNowOptions(options, "e2ee_seal_options_invalid");
  const protectedMetadata = canonicalProtectedMetadata(input.protectedMetadata);
  assertEnvelopeTime(protectedMetadata, nowMs);
  const senderBundle = canonicalDevicePrivateBundle(input.senderDeviceKeyBundle);
  const recipientIdentity = canonicalDeviceIdentity(input.recipientDeviceIdentity);
  const recipientPreKey = canonicalPublicPreKey(input.recipientOneTimePreKey);
  if (!verifyDeviceIdentityRegistration(recipientIdentity)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({ identity: recipientIdentity, oneTimePreKey: recipientPreKey })) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_signature_invalid");
  }
  if (protectedMetadata.senderIdentityKeyId !== senderBundle.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientIdentity.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_mismatch");
  }
  const textValue = assertText(input.text);
  const plaintext = Buffer.from(textValue, "utf8");
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPairSync("x25519");
  const ephemeralPublicDer = ephemeralPublicKey.export({ format: "der", type: "spki" });
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const header = {
    protected: protectedMetadata,
    ephemeralPublicKey: ephemeralPublicDer.toString("base64url"),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
  };
  const aad = domainSeparatedBytes(ENVELOPE_AAD_DOMAIN, header);
  const recipientPublicKey = importPublicDer(
    recipientPreKey.publicKey,
    "x25519",
    "e2ee_recipient_prekey_public_invalid",
  );
  let sharedSecret;
  let aesKey;
  try {
    sharedSecret = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey: recipientPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const unsignedEnvelope = canonicalUnsignedEnvelope({
      schemaVersion: DIRECT_TEXT_E2EE_SCHEMA_VERSION,
      protocol: DIRECT_TEXT_E2EE_PROTOCOL,
      algorithm: DIRECT_TEXT_E2EE_ALGORITHM,
      protected: protectedMetadata,
      ephemeralPublicKey: header.ephemeralPublicKey,
      salt: header.salt,
      iv: header.iv,
      ciphertext: ciphertext.toString("base64url"),
      authenticationTag: cipher.getAuthTag().toString("base64url"),
    });
    const signingPrivateKey = importPrivateDer(
      senderBundle.privateKey,
      "ed25519",
      "e2ee_sender_private_key_invalid",
    );
    return Object.freeze({
      ...unsignedEnvelope,
      signature: sign(
        null,
        domainSeparatedBytes(ENVELOPE_SIGNATURE_DOMAIN, unsignedEnvelope),
        signingPrivateKey,
      ).toString("base64url"),
    });
  } catch (error) {
    if (error instanceof HelloLynkDirectTextE2eeError) throw error;
    throw new HelloLynkDirectTextE2eeError("e2ee_encryption_failed");
  } finally {
    plaintext.fill(0);
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
}

export function openDirectTextEnvelope(input, options = {}) {
  assertExactFields(input, [
    "envelope",
    "senderDeviceIdentity",
    "recipientDeviceKeyBundle",
    "recipientOneTimePreKey",
    "expectedRecipient",
  ], "e2ee_open_input_invalid");
  const nowMs = normalizeNowOptions(options, "e2ee_open_options_invalid");
  const envelope = canonicalEnvelope(input.envelope);
  const senderIdentity = canonicalDeviceIdentity(input.senderDeviceIdentity);
  if (!verifyDeviceIdentityRegistration(senderIdentity)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_signature_invalid");
  }
  const recipientBundle = canonicalDevicePrivateBundle(input.recipientDeviceKeyBundle);
  const recipientPreKey = canonicalPrivatePreKey(input.recipientOneTimePreKey);
  const expectedRecipient = canonicalExpectedRecipient(input.expectedRecipient);
  const protectedMetadata = envelope.protected;
  if (protectedMetadata.senderIdentityKeyId !== senderIdentity.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientBundle.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_mismatch");
  }
  if (
    protectedMetadata.recipientPrincipalId !== expectedRecipient.principalId
    || protectedMetadata.recipientHelloLynkId !== expectedRecipient.hellolynkId
    || protectedMetadata.recipientDeviceId !== expectedRecipient.deviceId
  ) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_route_mismatch");
  }
  const unsignedEnvelope = canonicalUnsignedEnvelope(envelope);
  const senderPublicKey = importPublicDer(
    senderIdentity.publicKey,
    "ed25519",
    "e2ee_sender_public_key_invalid",
  );
  if (!verify(
    null,
    domainSeparatedBytes(ENVELOPE_SIGNATURE_DOMAIN, unsignedEnvelope),
    senderPublicKey,
    decodeBase64Url(envelope.signature, 64, "e2ee_envelope_signature_invalid"),
  )) {
    throw new HelloLynkDirectTextE2eeError("e2ee_envelope_signature_invalid");
  }
  assertEnvelopeTime(protectedMetadata, nowMs);
  const ephemeralPublicKey = importPublicDer(
    envelope.ephemeralPublicKey,
    "x25519",
    "e2ee_ephemeral_public_key_invalid",
  );
  const recipientPrivateKey = importPrivateDer(
    recipientPreKey.privateKey,
    "x25519",
    "e2ee_recipient_prekey_private_invalid",
  );
  const salt = decodeBase64Url(envelope.salt, 32, "e2ee_envelope_salt_invalid");
  const iv = decodeBase64Url(envelope.iv, 12, "e2ee_envelope_iv_invalid");
  const ciphertext = decodeBase64Url(
    envelope.ciphertext,
    null,
    "e2ee_envelope_ciphertext_invalid",
    { minimumBytes: 1, maximumBytes: MAX_CIPHERTEXT_BYTES },
  );
  const authenticationTag = decodeBase64Url(
    envelope.authenticationTag,
    16,
    "e2ee_envelope_authentication_tag_invalid",
  );
  const header = {
    protected: protectedMetadata,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    salt: envelope.salt,
    iv: envelope.iv,
  };
  const aad = domainSeparatedBytes(ENVELOPE_AAD_DOMAIN, header);
  let sharedSecret;
  let aesKey;
  let plaintext;
  try {
    sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
    const decipher = createDecipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(authenticationTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new HelloLynkDirectTextE2eeError("e2ee_decryption_failed");
  } finally {
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
  try {
    let text;
    try {
      text = textDecoder.decode(plaintext);
    } catch {
      throw new HelloLynkDirectTextE2eeError("e2ee_plaintext_invalid");
    }
    assertText(text);
    return Object.freeze({
      text,
      protectedMetadata,
      envelopeDigest: digestDirectTextEnvelope(envelope),
    });
  } finally {
    plaintext.fill(0);
  }
}

export function digestDirectTextEnvelope(envelope) {
  const canonical = canonicalEnvelope(envelope);
  return createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}

export function sealDirectTextEnvelopeV2(input, options = {}) {
  assertExactFields(input, [
    "protectedMetadata",
    "recipientDeviceIdentity",
    "recipientOneTimePreKey",
    "senderDeviceKeyBundle",
    "text",
  ], "e2ee_v2_seal_input_invalid");
  const nowMs = normalizeNowOptions(options, "e2ee_v2_seal_options_invalid");
  const protectedMetadata = canonicalProtectedMetadataV2(input.protectedMetadata);
  assertEnvelopeTime(protectedMetadata, nowMs);
  const senderBundle = canonicalDevicePrivateBundle(input.senderDeviceKeyBundle);
  const recipientIdentity = canonicalDeviceIdentity(input.recipientDeviceIdentity);
  const recipientPreKey = canonicalPublicPreKey(input.recipientOneTimePreKey);
  if (!verifyDeviceIdentityRegistration(recipientIdentity)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_signature_invalid");
  }
  if (!verifyOneTimePreKeyRegistration({ identity: recipientIdentity, oneTimePreKey: recipientPreKey })) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_signature_invalid");
  }
  if (protectedMetadata.senderIdentityKeyId !== senderBundle.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientIdentity.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_mismatch");
  }
  const textValue = assertText(input.text);
  const plaintext = Buffer.from(textValue, "utf8");
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPairSync("x25519");
  const ephemeralPublicDer = ephemeralPublicKey.export({ format: "der", type: "spki" });
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const header = {
    protected: protectedMetadata,
    ephemeralPublicKey: ephemeralPublicDer.toString("base64url"),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
  };
  const aad = domainSeparatedBytes(ENVELOPE_V2_AAD_DOMAIN, header);
  const recipientPublicKey = importPublicDer(
    recipientPreKey.publicKey,
    "x25519",
    "e2ee_recipient_prekey_public_invalid",
  );
  let sharedSecret;
  let aesKey;
  try {
    sharedSecret = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey: recipientPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_V2_INFO, 32));
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const unsignedEnvelope = canonicalUnsignedEnvelopeV2({
      schemaVersion: DIRECT_TEXT_E2EE_V2_SCHEMA_VERSION,
      protocol: DIRECT_TEXT_E2EE_V2_PROTOCOL,
      algorithm: DIRECT_TEXT_E2EE_ALGORITHM,
      protected: protectedMetadata,
      ephemeralPublicKey: header.ephemeralPublicKey,
      salt: header.salt,
      iv: header.iv,
      ciphertext: ciphertext.toString("base64url"),
      authenticationTag: cipher.getAuthTag().toString("base64url"),
    });
    const signingPrivateKey = importPrivateDer(
      senderBundle.privateKey,
      "ed25519",
      "e2ee_sender_private_key_invalid",
    );
    return Object.freeze({
      ...unsignedEnvelope,
      signature: sign(
        null,
        domainSeparatedBytes(ENVELOPE_V2_SIGNATURE_DOMAIN, unsignedEnvelope),
        signingPrivateKey,
      ).toString("base64url"),
    });
  } catch (error) {
    if (error instanceof HelloLynkDirectTextE2eeError) throw error;
    throw new HelloLynkDirectTextE2eeError("e2ee_encryption_failed");
  } finally {
    plaintext.fill(0);
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
}

export function openDirectTextEnvelopeV2(input, options = {}) {
  assertExactFields(input, [
    "envelope",
    "senderDeviceIdentity",
    "recipientDeviceKeyBundle",
    "recipientOneTimePreKey",
    "expectedRecipient",
  ], "e2ee_v2_open_input_invalid");
  const nowMs = normalizeNowOptions(options, "e2ee_v2_open_options_invalid");
  const envelope = canonicalEnvelopeV2(input.envelope);
  const senderIdentity = canonicalDeviceIdentity(input.senderDeviceIdentity);
  if (!verifyDeviceIdentityRegistration(senderIdentity)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_signature_invalid");
  }
  const recipientBundle = canonicalDevicePrivateBundle(input.recipientDeviceKeyBundle);
  const recipientPreKey = canonicalPrivatePreKey(input.recipientOneTimePreKey);
  const expectedRecipient = canonicalExpectedRecipientV2(input.expectedRecipient);
  const protectedMetadata = envelope.protected;
  if (protectedMetadata.senderIdentityKeyId !== senderIdentity.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_key_mismatch");
  }
  if (protectedMetadata.recipientIdentityKeyId !== recipientBundle.keyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_identity_key_mismatch");
  }
  if (protectedMetadata.recipientPreKeyId !== recipientPreKey.preKeyId) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_prekey_mismatch");
  }
  if (
    protectedMetadata.recipientPrincipalId !== expectedRecipient.principalId
    || protectedMetadata.recipientHelloLynkId !== expectedRecipient.hellolynkId
    || protectedMetadata.recipientDelegateId !== expectedRecipient.delegateId
    || protectedMetadata.recipientHostId !== expectedRecipient.hostId
    || protectedMetadata.recipientDeviceId !== expectedRecipient.deviceId
  ) {
    throw new HelloLynkDirectTextE2eeError("e2ee_recipient_route_mismatch");
  }
  const unsignedEnvelope = canonicalUnsignedEnvelopeV2(envelope);
  const senderPublicKey = importPublicDer(
    senderIdentity.publicKey,
    "ed25519",
    "e2ee_sender_public_key_invalid",
  );
  if (!verify(
    null,
    domainSeparatedBytes(ENVELOPE_V2_SIGNATURE_DOMAIN, unsignedEnvelope),
    senderPublicKey,
    decodeBase64Url(envelope.signature, 64, "e2ee_envelope_signature_invalid"),
  )) {
    throw new HelloLynkDirectTextE2eeError("e2ee_envelope_signature_invalid");
  }
  assertEnvelopeTime(protectedMetadata, nowMs);
  const ephemeralPublicKey = importPublicDer(
    envelope.ephemeralPublicKey,
    "x25519",
    "e2ee_ephemeral_public_key_invalid",
  );
  const recipientPrivateKey = importPrivateDer(
    recipientPreKey.privateKey,
    "x25519",
    "e2ee_recipient_prekey_private_invalid",
  );
  const salt = decodeBase64Url(envelope.salt, 32, "e2ee_envelope_salt_invalid");
  const iv = decodeBase64Url(envelope.iv, 12, "e2ee_envelope_iv_invalid");
  const ciphertext = decodeBase64Url(
    envelope.ciphertext,
    null,
    "e2ee_envelope_ciphertext_invalid",
    { minimumBytes: 1, maximumBytes: MAX_CIPHERTEXT_BYTES },
  );
  const authenticationTag = decodeBase64Url(
    envelope.authenticationTag,
    16,
    "e2ee_envelope_authentication_tag_invalid",
  );
  const header = {
    protected: protectedMetadata,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    salt: envelope.salt,
    iv: envelope.iv,
  };
  const aad = domainSeparatedBytes(ENVELOPE_V2_AAD_DOMAIN, header);
  let sharedSecret;
  let aesKey;
  let plaintext;
  try {
    sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublicKey });
    aesKey = Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_V2_INFO, 32));
    const decipher = createDecipheriv("aes-256-gcm", aesKey, iv, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(authenticationTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new HelloLynkDirectTextE2eeError("e2ee_decryption_failed");
  } finally {
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }
  try {
    let text;
    try {
      text = textDecoder.decode(plaintext);
    } catch {
      throw new HelloLynkDirectTextE2eeError("e2ee_plaintext_invalid");
    }
    assertText(text);
    return Object.freeze({
      text,
      protectedMetadata,
      envelopeDigest: digestDirectTextEnvelopeV2(envelope),
    });
  } finally {
    plaintext.fill(0);
  }
}

export function verifyDirectTextEnvelopeSignatureV2(input, options = {}) {
  try {
    assertExactFields(input, [
      "envelope",
      "senderDeviceIdentity",
    ], "e2ee_v2_verify_input_invalid");
    const nowMs = normalizeNowOptions(options, "e2ee_v2_verify_options_invalid");
    const envelope = canonicalEnvelopeV2(input.envelope);
    const senderIdentity = canonicalDeviceIdentity(input.senderDeviceIdentity);
    if (!verifyDeviceIdentityRegistration(senderIdentity)) return false;
    if (envelope.protected.senderIdentityKeyId !== senderIdentity.keyId) return false;
    const senderPublicKey = importPublicDer(
      senderIdentity.publicKey,
      "ed25519",
      "e2ee_sender_public_key_invalid",
    );
    if (!verify(
      null,
      domainSeparatedBytes(ENVELOPE_V2_SIGNATURE_DOMAIN, canonicalUnsignedEnvelopeV2(envelope)),
      senderPublicKey,
      decodeBase64Url(envelope.signature, 64, "e2ee_envelope_signature_invalid"),
    )) return false;
    assertEnvelopeTime(envelope.protected, nowMs);
    return true;
  } catch {
    return false;
  }
}

export function digestDirectTextEnvelopeV2(envelope) {
  const canonical = canonicalEnvelopeV2(envelope);
  return createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}

export function classifyDirectTextEnvelopeReplay(input) {
  assertExactFields(
    input,
    ["clientMessageId", "envelopeDigest", "existingEnvelopeDigest"],
    "e2ee_replay_input_invalid",
  );
  const clientMessageId = assertSafeId(input.clientMessageId, "e2ee_client_message_id_invalid");
  const envelopeDigest = assertDigest(input.envelopeDigest);
  const existingEnvelopeDigest = input.existingEnvelopeDigest == null
    ? null
    : assertDigest(input.existingEnvelopeDigest);
  if (existingEnvelopeDigest == null) {
    return Object.freeze({ decision: "accept_new", clientMessageId, envelopeDigest });
  }
  const same = timingSafeEqual(Buffer.from(envelopeDigest, "hex"), Buffer.from(existingEnvelopeDigest, "hex"));
  return Object.freeze({
    decision: same ? "idempotent_replay" : "conflicting_replay",
    clientMessageId,
    envelopeDigest,
  });
}

function canonicalDevicePrivateBundle(input) {
  assertExactFields(input, DEVICE_PRIVATE_FIELDS, "e2ee_device_key_bundle_invalid");
  if (
    input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION
    || input.purpose !== DEVICE_KEY_PURPOSE
    || input.algorithm !== "Ed25519"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_device_key_bundle_invalid");
  const publicDer = decodeBase64Url(input.publicKey, 44, "e2ee_device_public_key_invalid");
  const privateKey = importPrivateDer(input.privateKey, "ed25519", "e2ee_device_private_key_invalid");
  const derivedPublicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  if (!timingSafeEqual(publicDer, derivedPublicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_device_key_pair_mismatch");
  }
  const keyId = assertSafeId(input.keyId, "e2ee_identity_key_id_invalid");
  if (keyId !== keyIdForPublicDer("e2ee_id_", publicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_identity_key_id_invalid");
  }
  return {
    schemaVersion: input.schemaVersion,
    purpose: input.purpose,
    keyId,
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    privateKey: input.privateKey,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_identity_created_at_invalid"),
  };
}

function canonicalDeviceIdentityUnsigned(input) {
  const allowed = DEVICE_PUBLIC_FIELDS.includes("ownershipSignature") && Object.hasOwn(input, "ownershipSignature")
    ? DEVICE_PUBLIC_FIELDS
    : DEVICE_PUBLIC_UNSIGNED_FIELDS;
  assertExactFields(input, allowed, "e2ee_device_identity_invalid");
  if (
    input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION
    || input.algorithm !== "Ed25519"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_device_identity_invalid");
  const publicDer = decodeBase64Url(input.publicKey, 44, "e2ee_device_public_key_invalid");
  const keyId = assertSafeId(input.keyId, "e2ee_identity_key_id_invalid");
  if (keyId !== keyIdForPublicDer("e2ee_id_", publicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_identity_key_id_invalid");
  }
  return {
    schemaVersion: input.schemaVersion,
    keyId,
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_identity_created_at_invalid"),
  };
}

function canonicalDeviceIdentity(input) {
  assertExactFields(input, DEVICE_PUBLIC_FIELDS, "e2ee_device_identity_invalid");
  const unsigned = canonicalDeviceIdentityUnsigned({
    schemaVersion: input.schemaVersion,
    keyId: input.keyId,
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: input.createdAt,
  });
  decodeBase64Url(input.ownershipSignature, 64, "e2ee_identity_signature_invalid");
  return { ...unsigned, ownershipSignature: input.ownershipSignature };
}

function canonicalPrivatePreKey(input) {
  assertExactFields(input, PRE_KEY_PRIVATE_FIELDS, "e2ee_private_prekey_invalid");
  if (
    input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION
    || input.purpose !== PRE_KEY_PURPOSE
    || input.algorithm !== "X25519"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_private_prekey_invalid");
  const publicDer = decodeBase64Url(input.publicKey, 44, "e2ee_prekey_public_invalid");
  const privateKey = importPrivateDer(input.privateKey, "x25519", "e2ee_prekey_private_invalid");
  const derivedPublicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  if (!timingSafeEqual(publicDer, derivedPublicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_prekey_pair_mismatch");
  }
  const preKeyId = assertSafeId(input.preKeyId, "e2ee_prekey_id_invalid");
  if (preKeyId !== keyIdForPublicDer("e2ee_pre_", publicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_prekey_id_invalid");
  }
  return {
    schemaVersion: input.schemaVersion,
    purpose: input.purpose,
    preKeyId,
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    privateKey: input.privateKey,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_prekey_created_at_invalid"),
  };
}

function canonicalPublicPreKeyUnsigned(input) {
  const allowed = PRE_KEY_PUBLIC_FIELDS.includes("signature") && Object.hasOwn(input, "signature")
    ? PRE_KEY_PUBLIC_FIELDS
    : PRE_KEY_PUBLIC_UNSIGNED_FIELDS;
  assertExactFields(input, allowed, "e2ee_public_prekey_invalid");
  if (
    input.schemaVersion !== DIRECT_TEXT_E2EE_KEY_SCHEMA_VERSION
    || input.algorithm !== "X25519"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_public_prekey_invalid");
  const publicDer = decodeBase64Url(input.publicKey, 44, "e2ee_prekey_public_invalid");
  const preKeyId = assertSafeId(input.preKeyId, "e2ee_prekey_id_invalid");
  if (preKeyId !== keyIdForPublicDer("e2ee_pre_", publicDer)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_prekey_id_invalid");
  }
  return {
    schemaVersion: input.schemaVersion,
    preKeyId,
    identityKeyId: assertSafeId(input.identityKeyId, "e2ee_identity_key_id_invalid"),
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_prekey_created_at_invalid"),
  };
}

function canonicalPublicPreKey(input) {
  assertExactFields(input, PRE_KEY_PUBLIC_FIELDS, "e2ee_public_prekey_invalid");
  const unsigned = canonicalPublicPreKeyUnsigned({
    schemaVersion: input.schemaVersion,
    preKeyId: input.preKeyId,
    identityKeyId: input.identityKeyId,
    algorithm: input.algorithm,
    publicKey: input.publicKey,
    createdAt: input.createdAt,
  });
  decodeBase64Url(input.signature, 64, "e2ee_prekey_signature_invalid");
  return { ...unsigned, signature: input.signature };
}

function canonicalProtectedMetadata(input) {
  assertExactFields(input, PROTECTED_FIELDS, "e2ee_protected_metadata_invalid");
  const accepted = {
    clientMessageId: assertSafeId(input.clientMessageId, "e2ee_client_message_id_invalid"),
    senderPrincipalId: assertSafeId(input.senderPrincipalId, "e2ee_sender_principal_id_invalid"),
    senderHelloLynkId: assertSafeId(input.senderHelloLynkId, "e2ee_sender_hellolynk_id_invalid"),
    senderAgentId: assertSafeId(input.senderAgentId, "e2ee_sender_agent_id_invalid"),
    senderDelegateId: assertSafeId(input.senderDelegateId, "e2ee_sender_delegate_id_invalid"),
    senderDeviceId: assertSafeId(input.senderDeviceId, "e2ee_sender_device_id_invalid"),
    senderIdentityKeyId: assertSafeId(input.senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid"),
    recipientPrincipalId: assertSafeId(input.recipientPrincipalId, "e2ee_recipient_principal_id_invalid"),
    recipientHelloLynkId: assertSafeId(input.recipientHelloLynkId, "e2ee_recipient_hellolynk_id_invalid"),
    recipientDeviceId: assertSafeId(input.recipientDeviceId, "e2ee_recipient_device_id_invalid"),
    recipientIdentityKeyId: assertSafeId(input.recipientIdentityKeyId, "e2ee_recipient_identity_key_id_invalid"),
    recipientPreKeyId: assertSafeId(input.recipientPreKeyId, "e2ee_recipient_prekey_id_invalid"),
    authorizationScope: input.authorizationScope,
    intentSource: input.intentSource,
    messageType: input.messageType,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_created_at_invalid"),
    expiresAt: assertIsoTimestamp(input.expiresAt, "e2ee_expires_at_invalid"),
  };
  if (
    accepted.authorizationScope !== DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE
    || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(accepted.intentSource)
    || accepted.messageType !== "text"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_protected_metadata_invalid");
  if (
    accepted.senderPrincipalId === accepted.senderAgentId
    || accepted.senderPrincipalId === accepted.senderDelegateId
  ) throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_collapsed");
  const createdAtMs = Date.parse(accepted.createdAt);
  const expiresAtMs = Date.parse(accepted.expiresAt);
  if (expiresAtMs <= createdAtMs || expiresAtMs - createdAtMs > DIRECT_TEXT_E2EE_MAX_TTL_MS) {
    throw new HelloLynkDirectTextE2eeError("e2ee_expiry_window_invalid");
  }
  return Object.freeze(accepted);
}

function canonicalProtectedMetadataV2(input) {
  const replyFields = Object.hasOwn(input || {}, "replyToClientMessageId") ? ["replyToClientMessageId"] : [];
  assertExactFields(input, [...PROTECTED_V2_FIELDS, ...replyFields], "e2ee_v2_protected_metadata_invalid");
  const routeKind = String(input.routeKind || "");
  if (!new Set(["principal_inbox", "owned_delegate", "instance_direct"]).has(routeKind)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_route_kind_invalid");
  }
  const senderDelegateAuthorizationVersion = assertPositiveInteger(
    input.senderDelegateAuthorizationVersion,
    "e2ee_sender_delegate_authorization_version_invalid",
  );
  const recipientDelegateAuthorizationVersion = assertPositiveInteger(
    input.recipientDelegateAuthorizationVersion,
    "e2ee_recipient_delegate_authorization_version_invalid",
  );
  const recipientRouteVersion = assertNonNegativeInteger(
    input.recipientRouteVersion,
    "e2ee_recipient_route_version_invalid",
  );
  const accepted = {
    clientMessageId: assertSafeId(input.clientMessageId, "e2ee_client_message_id_invalid"),
    routeKind,
    senderPrincipalId: assertSafeId(input.senderPrincipalId, "e2ee_sender_principal_id_invalid"),
    senderHelloLynkId: assertSafeId(input.senderHelloLynkId, "e2ee_sender_hellolynk_id_invalid"),
    senderAgentId: assertSafeId(input.senderAgentId, "e2ee_sender_agent_id_invalid"),
    senderDelegateId: assertSafeId(input.senderDelegateId, "e2ee_sender_delegate_id_invalid"),
    senderDelegateAuthorizationVersion,
    senderHostId: assertSafeId(input.senderHostId, "e2ee_sender_host_id_invalid"),
    senderDeviceId: assertSafeId(input.senderDeviceId, "e2ee_sender_device_id_invalid"),
    senderIdentityKeyId: assertSafeId(input.senderIdentityKeyId, "e2ee_sender_identity_key_id_invalid"),
    recipientPrincipalId: assertSafeId(input.recipientPrincipalId, "e2ee_recipient_principal_id_invalid"),
    recipientHelloLynkId: assertSafeId(input.recipientHelloLynkId, "e2ee_recipient_hellolynk_id_invalid"),
    recipientDelegateId: assertSafeId(input.recipientDelegateId, "e2ee_recipient_delegate_id_invalid"),
    recipientDelegateAuthorizationVersion,
    recipientHostId: assertSafeId(input.recipientHostId, "e2ee_recipient_host_id_invalid"),
    recipientRouteVersion,
    recipientDeviceId: assertSafeId(input.recipientDeviceId, "e2ee_recipient_device_id_invalid"),
    recipientIdentityKeyId: assertSafeId(input.recipientIdentityKeyId, "e2ee_recipient_identity_key_id_invalid"),
    recipientPreKeyId: assertSafeId(input.recipientPreKeyId, "e2ee_recipient_prekey_id_invalid"),
    authorizationScope: input.authorizationScope,
    intentSource: input.intentSource,
    messageType: input.messageType,
    createdAt: assertIsoTimestamp(input.createdAt, "e2ee_created_at_invalid"),
    expiresAt: assertIsoTimestamp(input.expiresAt, "e2ee_expires_at_invalid"),
    ...(replyFields.length ? { replyToClientMessageId: assertSafeId(input.replyToClientMessageId, "e2ee_reply_target_invalid") } : {}),
  };
  if (replyFields.length && (routeKind === "principal_inbox" || accepted.intentSource !== "human_preauthorized_contact"
    || accepted.replyToClientMessageId === accepted.clientMessageId)) throw new HelloLynkDirectTextE2eeError("e2ee_reply_target_invalid");
  if (
    accepted.authorizationScope !== DIRECT_TEXT_E2EE_AUTHORIZATION_SCOPE
    || !DIRECT_TEXT_E2EE_ALLOWED_INTENT_SOURCES.includes(accepted.intentSource)
    || accepted.messageType !== "text"
  ) throw new HelloLynkDirectTextE2eeError("e2ee_v2_protected_metadata_invalid");
  if (
    accepted.senderPrincipalId === accepted.senderAgentId
    || accepted.senderPrincipalId === accepted.senderDelegateId
  ) throw new HelloLynkDirectTextE2eeError("e2ee_sender_identity_collapsed");
  if (
    (accepted.senderPrincipalId === accepted.recipientPrincipalId)
      !== (accepted.senderHelloLynkId === accepted.recipientHelloLynkId)
  ) throw new HelloLynkDirectTextE2eeError("e2ee_route_semantics_invalid");
  if (
    (routeKind === "principal_inbox" && (
      accepted.senderPrincipalId === accepted.recipientPrincipalId
      || accepted.recipientRouteVersion < 1
    ))
    || (routeKind === "owned_delegate" && (
      accepted.senderPrincipalId !== accepted.recipientPrincipalId
      || accepted.senderDelegateId === accepted.recipientDelegateId
      || accepted.recipientRouteVersion !== 0
    ))
    || (routeKind === "instance_direct" && (
      accepted.senderDelegateId === accepted.recipientDelegateId
      || accepted.recipientRouteVersion !== 0
    ))
  ) throw new HelloLynkDirectTextE2eeError("e2ee_route_semantics_invalid");
  const createdAtMs = Date.parse(accepted.createdAt);
  const expiresAtMs = Date.parse(accepted.expiresAt);
  if (expiresAtMs <= createdAtMs || expiresAtMs - createdAtMs > DIRECT_TEXT_E2EE_MAX_TTL_MS) {
    throw new HelloLynkDirectTextE2eeError("e2ee_expiry_window_invalid");
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
        salt: input.salt,
        iv: input.iv,
        ciphertext: input.ciphertext,
        authenticationTag: input.authenticationTag,
      }
    : input;
  assertExactFields(source, unsignedFields, "e2ee_envelope_invalid");
  if (
    source.schemaVersion !== DIRECT_TEXT_E2EE_SCHEMA_VERSION
    || source.protocol !== DIRECT_TEXT_E2EE_PROTOCOL
    || source.algorithm !== DIRECT_TEXT_E2EE_ALGORITHM
  ) throw new HelloLynkDirectTextE2eeError("e2ee_envelope_algorithm_invalid");
  decodeBase64Url(source.ephemeralPublicKey, 44, "e2ee_ephemeral_public_key_invalid");
  decodeBase64Url(source.salt, 32, "e2ee_envelope_salt_invalid");
  decodeBase64Url(source.iv, 12, "e2ee_envelope_iv_invalid");
  decodeBase64Url(source.ciphertext, null, "e2ee_envelope_ciphertext_invalid", {
    minimumBytes: 1,
    maximumBytes: MAX_CIPHERTEXT_BYTES,
  });
  decodeBase64Url(source.authenticationTag, 16, "e2ee_envelope_authentication_tag_invalid");
  return {
    schemaVersion: source.schemaVersion,
    protocol: source.protocol,
    algorithm: source.algorithm,
    protected: canonicalProtectedMetadata(source.protected),
    ephemeralPublicKey: source.ephemeralPublicKey,
    salt: source.salt,
    iv: source.iv,
    ciphertext: source.ciphertext,
    authenticationTag: source.authenticationTag,
  };
}

function canonicalUnsignedEnvelopeV2(input) {
  const unsignedFields = ENVELOPE_FIELDS.slice(0, -1);
  const source = Object.hasOwn(input, "signature")
    ? {
        schemaVersion: input.schemaVersion,
        protocol: input.protocol,
        algorithm: input.algorithm,
        protected: input.protected,
        ephemeralPublicKey: input.ephemeralPublicKey,
        salt: input.salt,
        iv: input.iv,
        ciphertext: input.ciphertext,
        authenticationTag: input.authenticationTag,
      }
    : input;
  assertExactFields(source, unsignedFields, "e2ee_v2_envelope_invalid");
  if (
    source.schemaVersion !== DIRECT_TEXT_E2EE_V2_SCHEMA_VERSION
    || source.protocol !== DIRECT_TEXT_E2EE_V2_PROTOCOL
    || source.algorithm !== DIRECT_TEXT_E2EE_ALGORITHM
  ) throw new HelloLynkDirectTextE2eeError("e2ee_v2_envelope_algorithm_invalid");
  decodeBase64Url(source.ephemeralPublicKey, 44, "e2ee_ephemeral_public_key_invalid");
  decodeBase64Url(source.salt, 32, "e2ee_envelope_salt_invalid");
  decodeBase64Url(source.iv, 12, "e2ee_envelope_iv_invalid");
  decodeBase64Url(source.ciphertext, null, "e2ee_envelope_ciphertext_invalid", {
    minimumBytes: 1,
    maximumBytes: MAX_CIPHERTEXT_BYTES,
  });
  decodeBase64Url(source.authenticationTag, 16, "e2ee_envelope_authentication_tag_invalid");
  return {
    schemaVersion: source.schemaVersion,
    protocol: source.protocol,
    algorithm: source.algorithm,
    protected: canonicalProtectedMetadataV2(source.protected),
    ephemeralPublicKey: source.ephemeralPublicKey,
    salt: source.salt,
    iv: source.iv,
    ciphertext: source.ciphertext,
    authenticationTag: source.authenticationTag,
  };
}

function canonicalEnvelope(input) {
  assertExactFields(input, ENVELOPE_FIELDS, "e2ee_envelope_invalid");
  const unsigned = canonicalUnsignedEnvelope(input);
  decodeBase64Url(input.signature, 64, "e2ee_envelope_signature_invalid");
  return { ...unsigned, signature: input.signature };
}

function canonicalEnvelopeV2(input) {
  assertExactFields(input, ENVELOPE_FIELDS, "e2ee_v2_envelope_invalid");
  const unsigned = canonicalUnsignedEnvelopeV2(input);
  decodeBase64Url(input.signature, 64, "e2ee_envelope_signature_invalid");
  return { ...unsigned, signature: input.signature };
}

function canonicalExpectedRecipient(input) {
  assertExactFields(input, EXPECTED_RECIPIENT_FIELDS, "e2ee_expected_recipient_invalid");
  return {
    principalId: assertSafeId(input.principalId, "e2ee_expected_recipient_invalid"),
    hellolynkId: assertSafeId(input.hellolynkId, "e2ee_expected_recipient_invalid"),
    deviceId: assertSafeId(input.deviceId, "e2ee_expected_recipient_invalid"),
  };
}

function canonicalExpectedRecipientV2(input) {
  assertExactFields(input, EXPECTED_RECIPIENT_V2_FIELDS, "e2ee_v2_expected_recipient_invalid");
  return {
    principalId: assertSafeId(input.principalId, "e2ee_v2_expected_recipient_invalid"),
    hellolynkId: assertSafeId(input.hellolynkId, "e2ee_v2_expected_recipient_invalid"),
    delegateId: assertSafeId(input.delegateId, "e2ee_v2_expected_recipient_invalid"),
    hostId: assertSafeId(input.hostId, "e2ee_v2_expected_recipient_invalid"),
    deviceId: assertSafeId(input.deviceId, "e2ee_v2_expected_recipient_invalid"),
  };
}

function assertEnvelopeTime(protectedMetadata, nowMs) {
  const createdAtMs = Date.parse(protectedMetadata.createdAt);
  const expiresAtMs = Date.parse(protectedMetadata.expiresAt);
  if (createdAtMs > nowMs + MAX_CLOCK_SKEW_MS) {
    throw new HelloLynkDirectTextE2eeError("e2ee_created_at_in_future");
  }
  if (expiresAtMs <= nowMs) throw new HelloLynkDirectTextE2eeError("e2ee_envelope_expired");
}

function assertText(value) {
  if (typeof value !== "string") throw new HelloLynkDirectTextE2eeError("e2ee_text_invalid");
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < 1 || bytes > DIRECT_TEXT_E2EE_MAX_TEXT_UTF8_BYTES) {
    throw new HelloLynkDirectTextE2eeError("e2ee_text_invalid");
  }
  return value;
}

function normalizeNowOptions(options, code) {
  assertPlainRecord(options, code);
  const keys = Object.keys(options);
  if (keys.some((key) => key !== "nowMs")) throw new HelloLynkDirectTextE2eeError(code);
  const nowMs = options.nowMs == null ? Date.now() : Number(options.nowMs);
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) throw new HelloLynkDirectTextE2eeError(code);
  return nowMs;
}

function assertIsoTimestamp(value, code) {
  if (typeof value !== "string") throw new HelloLynkDirectTextE2eeError(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new HelloLynkDirectTextE2eeError(code);
  }
  return value;
}

function assertSafeId(value, code) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(value)) {
    throw new HelloLynkDirectTextE2eeError(code);
  }
  return value;
}

function assertPositiveInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) throw new HelloLynkDirectTextE2eeError(code);
  return value;
}

function assertNonNegativeInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) throw new HelloLynkDirectTextE2eeError(code);
  return value;
}

function assertDigest(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new HelloLynkDirectTextE2eeError("e2ee_envelope_digest_invalid");
  }
  return value;
}

function assertPlainRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkDirectTextE2eeError(code);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new HelloLynkDirectTextE2eeError(code);
}

function assertExactFields(value, expectedFields, code) {
  assertPlainRecord(value, code);
  const actualFields = Object.keys(value);
  if (
    actualFields.length !== expectedFields.length
    || expectedFields.some((field) => !Object.hasOwn(value, field))
  ) throw new HelloLynkDirectTextE2eeError(code);
}

function decodeBase64Url(value, expectedBytes, code, limits = {}) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new HelloLynkDirectTextE2eeError(code);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new HelloLynkDirectTextE2eeError(code);
  if (expectedBytes != null && decoded.length !== expectedBytes) throw new HelloLynkDirectTextE2eeError(code);
  if (limits.minimumBytes != null && decoded.length < limits.minimumBytes) {
    throw new HelloLynkDirectTextE2eeError(code);
  }
  if (limits.maximumBytes != null && decoded.length > limits.maximumBytes) {
    throw new HelloLynkDirectTextE2eeError(code);
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
    if (error instanceof HelloLynkDirectTextE2eeError) throw error;
    throw new HelloLynkDirectTextE2eeError(code);
  }
}

function importPublicDer(value, asymmetricKeyType, code) {
  try {
    const der = decodeBase64Url(value, 44, code);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== asymmetricKeyType) throw new Error("type");
    return key;
  } catch (error) {
    if (error instanceof HelloLynkDirectTextE2eeError) throw error;
    throw new HelloLynkDirectTextE2eeError(code);
  }
}

function keyIdForPublicDer(prefix, publicDer) {
  return `${prefix}${createHash("sha256").update(publicDer).digest("base64url")}`;
}

function domainSeparatedBytes(domain, value) {
  return Buffer.from(`${domain}${JSON.stringify(value)}`, "utf8");
}
