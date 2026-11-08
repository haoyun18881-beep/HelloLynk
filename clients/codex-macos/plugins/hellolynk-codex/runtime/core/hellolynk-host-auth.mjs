import crypto from "node:crypto";

export const HELLOLYNK_HOST_REQUEST_AUTH_DOMAIN = "hellolynk-host-request-v1";
export const HELLOLYNK_HOST_REQUEST_MAX_SKEW_MS = 30_000;
export const HELLOLYNK_HOST_NONCE_TTL_MS = 90_000;
export const HELLOLYNK_HOST_NONCE_CACHE_MAX_ENTRIES = 4_096;
// One installed capability is shared by every open conversation, receiver and
// card. Its replay history may use the existing Host-wide budget; a smaller
// default quota throttles ordinary reads and then rejects unrelated new sends.
export const HELLOLYNK_HOST_NONCE_CACHE_MAX_ENTRIES_PER_CAPABILITY = HELLOLYNK_HOST_NONCE_CACHE_MAX_ENTRIES;
export const HELLOLYNK_HOST_CAPABILITY_CONTRACT = "hellolynk-host-capability-v1";

export const HELLOLYNK_HOST_AUTH_HEADERS = Object.freeze({
  capabilityId: "x-hellolynk-host-capability-id",
  adapterId: "x-hellolynk-host-adapter-id",
  hostGeneration: "x-hellolynk-host-generation",
  timestampMs: "x-hellolynk-host-timestamp",
  nonce: "x-hellolynk-host-nonce",
  proof: "x-hellolynk-host-proof",
});

const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/;
const GENERATION_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,126}[A-Za-z0-9])?$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const PROOF_PATTERN = /^[a-f0-9]{64}$/;

export function sha256RawBody(rawBody) {
  return crypto.createHash("sha256").update(asRawBody(rawBody)).digest("hex");
}

export function createHostRequestAuth(input) {
  const normalized = normalizeRequestAuthInput(input);
  const proof = crypto
    .createHmac("sha256", normalized.secretBuffer)
    .update(normalized.message, "utf8")
    .digest("hex");
  return {
    capabilityId: normalized.capabilityId,
    adapterId: normalized.adapterId,
    hostGeneration: normalized.hostGeneration,
    timestampMs: normalized.timestampMs,
    nonce: normalized.nonce,
    bodySha256: normalized.bodySha256,
    proof,
    headers: {
      [HELLOLYNK_HOST_AUTH_HEADERS.capabilityId]: normalized.capabilityId,
      [HELLOLYNK_HOST_AUTH_HEADERS.adapterId]: normalized.adapterId,
      [HELLOLYNK_HOST_AUTH_HEADERS.hostGeneration]: normalized.hostGeneration,
      [HELLOLYNK_HOST_AUTH_HEADERS.timestampMs]: String(normalized.timestampMs),
      [HELLOLYNK_HOST_AUTH_HEADERS.nonce]: normalized.nonce,
      [HELLOLYNK_HOST_AUTH_HEADERS.proof]: proof,
    },
  };
}

export function hostRequestAuthMatches(input) {
  try {
    const expected = createHostRequestAuth(input).proof;
    const candidate = String(input?.proof || "").toLowerCase();
    if (!PROOF_PATTERN.test(candidate)) return false;
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(candidate, "hex"));
  } catch {
    return false;
  }
}

export function canonicalHostRequestMessage(input) {
  return normalizeRequestAuthInput(input).message;
}

export function createHostNonce(bytes = 24) {
  if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 64) {
    throw codeError("host_nonce_size_invalid");
  }
  return crypto.randomBytes(bytes).toString("base64url");
}

export function createNonceReplayGuard(options = {}) {
  const now = normalizeNow(options.clock);
  const ttlMs = normalizePositiveInteger(options.ttlMs, HELLOLYNK_HOST_NONCE_TTL_MS, 1_000, 1_800_001);
  const maxEntries = normalizePositiveInteger(
    options.maxEntries,
    HELLOLYNK_HOST_NONCE_CACHE_MAX_ENTRIES,
    1,
    65_536,
  );
  const maxEntriesPerCapability = normalizePositiveInteger(
    options.maxEntriesPerCapability,
    Math.min(HELLOLYNK_HOST_NONCE_CACHE_MAX_ENTRIES_PER_CAPABILITY, maxEntries),
    1,
    maxEntries,
  );
  const entries = new Map();
  const capabilityEntryCounts = new Map();

  function consume(capabilityId, nonce, timestampMs) {
    const normalizedCapabilityId = assertIdentifier(capabilityId, "host_capability_id_invalid");
    const normalizedNonce = assertNonce(nonce);
    const normalizedTimestamp = assertTimestamp(timestampMs);
    const current = assertTimestamp(now());
    prune(current);
    const key = `${normalizedCapabilityId}\0${normalizedNonce}`;
    if (entries.has(key)) return false;
    const capabilityEntryCount = capabilityEntryCounts.get(normalizedCapabilityId) || 0;
    if (capabilityEntryCount >= maxEntriesPerCapability) {
      throw codeError("host_nonce_capability_cache_full");
    }
    if (entries.size >= maxEntries) throw codeError("host_nonce_cache_full");
    entries.set(key, {
      capabilityId: normalizedCapabilityId,
      expiresAt: Math.max(current, normalizedTimestamp) + ttlMs,
    });
    capabilityEntryCounts.set(normalizedCapabilityId, capabilityEntryCount + 1);
    return true;
  }

  function prune(current = assertTimestamp(now())) {
    for (const [key, entry] of entries) {
      if (entry.expiresAt <= current) {
        entries.delete(key);
        const count = capabilityEntryCounts.get(entry.capabilityId) || 0;
        if (count <= 1) capabilityEntryCounts.delete(entry.capabilityId);
        else capabilityEntryCounts.set(entry.capabilityId, count - 1);
      }
    }
  }

  return {
    consume,
    prune,
    get size() {
      prune();
      return entries.size;
    },
    sizeForCapability(capabilityId) {
      prune();
      return capabilityEntryCounts.get(assertIdentifier(capabilityId, "host_capability_id_invalid")) || 0;
    },
  };
}

export function assertRequestFresh(timestampMs, nowMs, maxSkewMs = HELLOLYNK_HOST_REQUEST_MAX_SKEW_MS) {
  const timestamp = assertTimestamp(timestampMs);
  const current = assertTimestamp(nowMs);
  const allowedSkew = normalizePositiveInteger(maxSkewMs, HELLOLYNK_HOST_REQUEST_MAX_SKEW_MS, 1, 300_000);
  if (Math.abs(current - timestamp) > allowedSkew) throw codeError("host_request_stale");
  return timestamp;
}

export function assertCapabilityRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("host_capability_invalid");
  }
  const expectedKeys = [
    "adapterId",
    "capabilityId",
    "contract",
    "delegateId",
    "hostInstallationId",
    "issuedAt",
    "principalId",
    "region",
    "revokedAt",
    "scopes",
    "secretBuffer",
    "state",
    "version",
  ];
  const actualKeys = Object.keys(value).sort();
  if (
    actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw codeError("host_capability_fields_invalid");
  }
  if (value.contract !== HELLOLYNK_HOST_CAPABILITY_CONTRACT) {
    throw codeError("host_capability_contract_invalid");
  }
  const capabilityId = assertIdentifier(value.capabilityId, "host_capability_id_invalid");
  const region = assertIdentifier(value.region, "host_capability_region_invalid");
  const principalId = assertIdentifier(value.principalId, "host_principal_id_invalid");
  const adapterId = assertIdentifier(value.adapterId, "host_adapter_id_invalid");
  const delegateId = assertIdentifier(value.delegateId, "host_delegate_id_invalid");
  const hostInstallationId = assertIdentifier(
    value.hostInstallationId,
    "host_installation_id_invalid",
  );
  const version = Number(value.version);
  if (!Number.isSafeInteger(version) || version < 1) throw codeError("host_capability_version_invalid");
  if (value.state !== "active") throw codeError("host_capability_inactive");
  const issuedAt = assertTimestamp(value.issuedAt);
  if (value.revokedAt !== null) throw codeError("host_capability_revoked_at_invalid");
  if (!Array.isArray(value.scopes) || value.scopes.length > 64) {
    throw codeError("host_capability_scopes_invalid");
  }
  const scopes = value.scopes.map((scope) => (
    assertIdentifier(scope, "host_capability_scope_invalid")
  ));
  const canonicalScopes = [...new Set(scopes)].sort();
  if (
    canonicalScopes.length !== scopes.length
    || canonicalScopes.some((scope, index) => scope !== scopes[index])
  ) {
    throw codeError("host_capability_scopes_noncanonical");
  }
  const secretBuffer = assertSecretBuffer(value.secretBuffer);
  return Object.freeze({
    contract: HELLOLYNK_HOST_CAPABILITY_CONTRACT,
    capabilityId,
    region,
    principalId,
    delegateId,
    hostInstallationId,
    adapterId,
    version,
    state: "active",
    scopes: Object.freeze(scopes),
    issuedAt,
    revokedAt: null,
    secretBuffer,
  });
}

export function assertIdentifier(value, errorCode = "host_identifier_invalid") {
  const identifier = String(value || "");
  if (!IDENTIFIER_PATTERN.test(identifier)) throw codeError(errorCode);
  return identifier;
}

export function assertHostGeneration(value) {
  const generation = String(value || "");
  if (!GENERATION_PATTERN.test(generation)) throw codeError("host_generation_invalid");
  return generation;
}

export function assertNonce(value) {
  const nonce = String(value || "");
  if (!NONCE_PATTERN.test(nonce)) throw codeError("host_nonce_invalid");
  return nonce;
}

export function assertPathname(value) {
  const pathname = String(value || "");
  if (
    !pathname.startsWith("/")
    || pathname.length > 512
    || pathname.includes("?")
    || pathname.includes("#")
    || pathname.includes("\r")
    || pathname.includes("\n")
    || pathname.includes("\\")
  ) {
    throw codeError("host_pathname_invalid");
  }
  return pathname;
}

export function assertMethod(value) {
  const method = String(value || "");
  if (!/^[A-Z]{3,12}$/.test(method)) throw codeError("host_method_invalid");
  return method;
}

export function asRawBody(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value == null) return Buffer.alloc(0);
  throw codeError("host_raw_body_invalid");
}

function normalizeRequestAuthInput(input = {}) {
  const capabilityId = assertIdentifier(input.capabilityId, "host_capability_id_invalid");
  const adapterId = assertIdentifier(input.adapterId, "host_adapter_id_invalid");
  const method = assertMethod(input.method);
  const pathname = assertPathname(input.pathname);
  const hostGeneration = assertHostGeneration(input.hostGeneration);
  const timestampMs = assertTimestamp(input.timestampMs);
  const nonce = assertNonce(input.nonce);
  const secretBuffer = assertSecretBuffer(input.secretBuffer);
  const bodySha256 = sha256RawBody(input.rawBody);
  const message = [
    HELLOLYNK_HOST_REQUEST_AUTH_DOMAIN,
    capabilityId,
    adapterId,
    method,
    pathname,
    hostGeneration,
    String(timestampMs),
    nonce,
    bodySha256,
  ].join("\n");
  return {
    capabilityId,
    adapterId,
    method,
    pathname,
    hostGeneration,
    timestampMs,
    nonce,
    secretBuffer,
    bodySha256,
    message,
  };
}

function assertSecretBuffer(value) {
  const secret = Buffer.isBuffer(value)
    ? Buffer.from(value)
    : value instanceof Uint8Array
      ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
      : null;
  if (!secret || secret.length < 32 || secret.length > 128) {
    throw codeError("host_capability_secret_invalid");
  }
  return secret;
}

function assertTimestamp(value) {
  if (typeof value !== "number" && !/^(?:0|[1-9][0-9]{0,15})$/.test(String(value || ""))) {
    throw codeError("host_timestamp_invalid");
  }
  const timestamp = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw codeError("host_timestamp_invalid");
  return timestamp;
}

function normalizeNow(clock) {
  if (clock == null) return () => Date.now();
  if (typeof clock === "function") return clock;
  if (typeof clock?.now === "function") return () => clock.now();
  throw codeError("host_clock_invalid");
}

function normalizePositiveInteger(value, fallback, minimum, maximum) {
  const normalized = Number(value ?? fallback);
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw codeError("host_limit_invalid");
  }
  return normalized;
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
