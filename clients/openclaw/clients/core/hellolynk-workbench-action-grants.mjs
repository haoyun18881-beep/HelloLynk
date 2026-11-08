import crypto from "node:crypto";

export const HELLOLYNK_WORKBENCH_ACTION_GRANT_TTL_MS = 60_000;
export const HELLOLYNK_WORKBENCH_ACTION_GRANT_CAPACITY = 1_024;

const MIN_TTL_MS = 30_000;
const MAX_TTL_MS = 90_000;
const MAX_CAPACITY = 4_096;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_TARGET_BYTES = 1_024;
const MAX_PAYLOAD_BYTES = 256 * 1_024;
const MAX_PAYLOAD_DEPTH = 64;
const TOKEN_BYTES = 32;
const TOKEN_PREFIX = "hwag_";
const TOKEN_PATTERN = /^hwag_[A-Za-z0-9_-]{43}$/;
const ISSUE_KEYS = Object.freeze([
  "adapterId",
  "adapterInstanceId",
  "capabilityId",
  "delegateId",
  "expectedRevision",
  "hostGeneration",
  "idempotencyKey",
  "payload",
  "principalId",
  "target",
  "tool",
]);
const CONSUME_KEYS = Object.freeze([...ISSUE_KEYS, "actionGrant"].sort());
const BINDING_FIELDS = Object.freeze([
  "hostGeneration",
  "principalId",
  "capabilityId",
  "adapterId",
  "delegateId",
  "adapterInstanceId",
  "tool",
  "target",
  "payloadDigest",
  "expectedRevision",
  "idempotencyKey",
]);
const AUTHORIZED_RESULT = Object.freeze({ authorized: true });
const KNOWN_FAILED_OUTCOME = "known-failed";
const UNKNOWN_OUTCOME = "unknown";
const REGISTRY_INTERNALS = new WeakMap();

export class HelloLynkWorkbenchActionGrantError extends Error {
  constructor(code, statusCode, outcome = null) {
    super(code);
    this.name = "HelloLynkWorkbenchActionGrantError";
    this.code = code;
    this.statusCode = statusCode;
    if (outcome != null) this.outcome = outcome;
  }
}

/*
 * This registry is deliberately process-local. Recreating the Host creates an
 * empty registry, so a grant can never survive a Host restart. The raw token and
 * original payload are never retained: the Map key is SHA-256(token), while the
 * record contains only normalized authority bindings and a payload digest.
 */
export function createHelloLynkWorkbenchActionGrantRegistry(options = {}) {
  const clock = normalizeClock(options.clock);
  const randomBytes = normalizeRandomBytes(options.randomBytes);
  const ttlMs = normalizeTtl(options.ttlMs);
  const capacity = normalizeCapacity(options.capacity);
  const grants = new Map();
  const tombstones = new Map();
  let lastObservedNowMs = null;

  function issue(value) {
    const binding = normalizeBinding(value, ISSUE_KEYS, "issue");
    const nowMs = monotonicNow();
    pruneExpired(nowMs);
    if (grants.size >= capacity) {
      throw failure("host_workbench_action_grant_capacity_exceeded", 503);
    }

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const tokenBytes = readRandomBytes(randomBytes);
      const actionGrant = `${TOKEN_PREFIX}${tokenBytes.toString("base64url")}`;
      if (!TOKEN_PATTERN.test(actionGrant)) continue;
      const tokenDigest = digestText(actionGrant);
      if (grants.has(tokenDigest) || tombstones.has(tokenDigest)) continue;

      const expiresAtMs = nowMs + ttlMs;
      if (!Number.isSafeInteger(expiresAtMs)) {
        throw failure("host_workbench_action_grant_clock_invalid", 500);
      }
      grants.set(tokenDigest, Object.freeze({ ...binding, expiresAtMs }));
      return Object.freeze({ actionGrant, expiresAtMs });
    }

    throw failure("host_workbench_action_grant_generation_failed", 500);
  }

  function consume(value) {
    // Extract and burn a well-formed, known token before validating any other
    // field. A malformed binding therefore cannot be retried with the same grant.
    // A successful burn becomes an outcome-unknown tombstone synchronously,
    // before the caller can enter an attachment check or an async handler.
    const rawToken = ownDataProperty(value, "actionGrant");
    const tokenDigest = typeof rawToken === "string" && TOKEN_PATTERN.test(rawToken)
      ? digestText(rawToken)
      : null;
    if (!tokenDigest) throw invalidGrant(KNOWN_FAILED_OUTCOME);

    const record = grants.get(tokenDigest);
    if (!record) {
      const tombstone = tombstones.get(tokenDigest);
      // A syntactically valid but unrecognized token may be a consumed token
      // whose bounded tombstone has expired or been evicted. We cannot prove
      // that its write never started, so the safe public outcome is unknown.
      throw invalidGrant(tombstone?.outcome ?? UNKNOWN_OUTCOME);
    }
    grants.delete(tokenDigest);

    let binding;
    try {
      binding = normalizeBinding(value, CONSUME_KEYS, "consume");
    } catch {
      rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, record.expiresAtMs);
      throw invalidGrant(KNOWN_FAILED_OUTCOME);
    }

    let nowMs;
    try {
      nowMs = monotonicNow();
    } catch {
      // This record was still active and has not crossed the Host execution
      // boundary, so a clock failure can be classified as known-failed.
      rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, record.expiresAtMs);
      throw invalidGrant(KNOWN_FAILED_OUTCOME);
    }
    if (record.expiresAtMs <= nowMs) {
      rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, nowMs + ttlMs);
      throw invalidGrant(KNOWN_FAILED_OUTCOME);
    }
    for (const field of BINDING_FIELDS) {
      if (record[field] !== binding[field]) {
        rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, nowMs + ttlMs);
        throw invalidGrant(KNOWN_FAILED_OUTCOME);
      }
    }
    rememberTombstone(tokenDigest, UNKNOWN_OUTCOME, nowMs + ttlMs);
    return AUTHORIZED_RESULT;
  }

  function prune() {
    return pruneExpired(monotonicNow());
  }

  function monotonicNow() {
    let nowMs;
    try {
      nowMs = readNow(clock);
    } catch (error) {
      failClosedActiveGrants();
      throw error;
    }
    if (lastObservedNowMs != null && nowMs < lastObservedNowMs) {
      // Keep the high-water mark: the registry remains fail-closed until the
      // clock catches up, instead of silently extending outstanding TTLs.
      failClosedActiveGrants();
      throw failure("host_workbench_action_grant_clock_invalid", 500);
    }
    lastObservedNowMs = nowMs;
    return nowMs;
  }

  function pruneExpired(nowMs) {
    let pruned = 0;
    for (const [tokenDigest, grant] of grants) {
      if (grant.expiresAtMs <= nowMs) {
        grants.delete(tokenDigest);
        rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, nowMs + ttlMs);
        pruned += 1;
      }
    }
    for (const [tokenDigest, tombstone] of tombstones) {
      if (tombstone.expiresAtMs <= nowMs) {
        tombstones.delete(tokenDigest);
        pruned += 1;
      }
    }
    return pruned;
  }

  function failClosedActiveGrants() {
    const fallbackExpiry = (lastObservedNowMs ?? 0) + ttlMs;
    for (const [tokenDigest, grant] of grants) {
      rememberTombstone(
        tokenDigest,
        KNOWN_FAILED_OUTCOME,
        Math.max(grant.expiresAtMs, fallbackExpiry),
      );
    }
    grants.clear();
  }

  function rememberTombstone(tokenDigest, outcome, expiresAtMs) {
    if (tombstones.has(tokenDigest)) tombstones.delete(tokenDigest);
    while (tombstones.size >= capacity) {
      tombstones.delete(tombstones.keys().next().value);
    }
    tombstones.set(tokenDigest, Object.freeze({ outcome, expiresAtMs }));
  }

  const registry = Object.freeze({
    issue,
    consume,
    prune,
    get size() {
      pruneExpired(monotonicNow());
      return grants.size;
    },
    get capacity() {
      return capacity;
    },
    get ttlMs() {
      return ttlMs;
    },
  });
  REGISTRY_INTERNALS.set(registry, Object.freeze({ grants, rememberTombstone, tombstones }));
  return registry;
}

export function rejectConsumedHelloLynkWorkbenchActionGrant(registry, actionGrant) {
  const internal = REGISTRY_INTERNALS.get(registry);
  if (!internal) throw failure("host_workbench_action_grant_registry_invalid", 500);
  if (typeof actionGrant !== "string" || !TOKEN_PATTERN.test(actionGrant)) return false;
  const tokenDigest = digestText(actionGrant);
  const tombstone = internal.tombstones.get(tokenDigest);
  if (!tombstone || tombstone.outcome !== UNKNOWN_OUTCOME) return false;
  internal.rememberTombstone(tokenDigest, KNOWN_FAILED_OUTCOME, tombstone.expiresAtMs);
  return true;
}

export function revokeHelloLynkWorkbenchActionGrants(registry, value) {
  const internal = REGISTRY_INTERNALS.get(registry);
  if (!internal) throw failure("host_workbench_action_grant_registry_invalid", 500);
  const hasAttachment = value && Object.hasOwn(value, "adapterInstanceId");
  try {
    assertExactObject(
      value,
      hasAttachment
        ? ["adapterInstanceId", "capabilityId", "hostGeneration"]
        : ["capabilityId", "hostGeneration"],
    );
    const authority = {
      hostGeneration: boundedString(value.hostGeneration, MAX_IDENTIFIER_BYTES),
      capabilityId: boundedString(value.capabilityId, MAX_IDENTIFIER_BYTES),
      ...(hasAttachment ? {
        adapterInstanceId: boundedString(value.adapterInstanceId, MAX_IDENTIFIER_BYTES),
      } : {}),
    };
    let revoked = 0;
    for (const [tokenDigest, grant] of internal.grants) {
      if (grant.hostGeneration === authority.hostGeneration
        && grant.capabilityId === authority.capabilityId
        && (!hasAttachment || grant.adapterInstanceId === authority.adapterInstanceId)) {
        internal.grants.delete(tokenDigest);
        internal.rememberTombstone(
          tokenDigest,
          KNOWN_FAILED_OUTCOME,
          grant.expiresAtMs,
        );
        revoked += 1;
      }
    }
    return revoked;
  } catch (error) {
    if (error instanceof HelloLynkWorkbenchActionGrantError) throw error;
    throw failure("host_workbench_action_grant_binding_invalid", 400);
  }
}

function normalizeBinding(value, expectedKeys, operation) {
  try {
    assertExactObject(value, expectedKeys);
    return Object.freeze({
      hostGeneration: boundedString(value.hostGeneration, MAX_IDENTIFIER_BYTES),
      principalId: boundedString(value.principalId, MAX_IDENTIFIER_BYTES),
      capabilityId: boundedString(value.capabilityId, MAX_IDENTIFIER_BYTES),
      adapterId: boundedString(value.adapterId, MAX_IDENTIFIER_BYTES),
      delegateId: boundedString(value.delegateId, MAX_IDENTIFIER_BYTES),
      adapterInstanceId: boundedString(value.adapterInstanceId, MAX_IDENTIFIER_BYTES),
      tool: boundedString(value.tool, MAX_IDENTIFIER_BYTES),
      target: boundedString(value.target, MAX_TARGET_BYTES),
      payloadDigest: digestPayload(value.payload),
      expectedRevision: value.expectedRevision == null
        ? null
        : boundedString(value.expectedRevision, MAX_IDENTIFIER_BYTES),
      idempotencyKey: boundedString(value.idempotencyKey, MAX_IDENTIFIER_BYTES),
    });
  } catch {
    if (operation === "consume") throw invalidGrant();
    throw failure("host_workbench_action_grant_binding_invalid", 400);
  }
}

function assertExactObject(value, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("invalid");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError("invalid");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError("invalid");
  const actual = Object.keys(value).sort();
  if (actual.length !== expectedKeys.length) throw new TypeError("invalid");
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (actual[index] !== expectedKeys[index]) throw new TypeError("invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, actual[index]);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new TypeError("invalid");
  }
  if (Object.getOwnPropertyNames(value).length !== actual.length) throw new TypeError("invalid");
}

function boundedString(value, maxBytes) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new TypeError("invalid");
  }
  if (Buffer.byteLength(value, "utf8") > maxBytes) throw new TypeError("invalid");
  return value;
}

function digestPayload(value) {
  const canonical = canonicalJson(value, new Set(), 0);
  if (Buffer.byteLength(canonical, "utf8") > MAX_PAYLOAD_BYTES) throw new TypeError("invalid");
  return digestText(canonical);
}

function canonicalJson(value, ancestors, depth) {
  if (depth > MAX_PAYLOAD_DEPTH) throw new TypeError("invalid");
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("invalid");
    return JSON.stringify(value);
  }
  if (!value || typeof value !== "object") throw new TypeError("invalid");
  if (ancestors.has(value)) throw new TypeError("invalid");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError("invalid");

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.keys(value).length !== value.length) throw new TypeError("invalid");
      if (Object.getOwnPropertyNames(value).length !== value.length + 1) {
        throw new TypeError("invalid");
      }
      const entries = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError("invalid");
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
          throw new TypeError("invalid");
        }
        entries.push(canonicalJson(value[index], ancestors, depth + 1));
      }
      return `[${entries.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("invalid");
    const keys = Object.keys(value).sort();
    if (Object.getOwnPropertyNames(value).length !== keys.length) throw new TypeError("invalid");
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
        throw new TypeError("invalid");
      }
    }
    const entries = keys.map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key], ancestors, depth + 1)}`
    ));
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function ownDataProperty(value, key) {
  if (!value || typeof value !== "object") return null;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : null;
  } catch {
    return null;
  }
}

function normalizeClock(value) {
  if (value == null) return Object.freeze({ now: () => Date.now() });
  if (!value || typeof value.now !== "function") {
    throw failure("host_workbench_action_grant_clock_invalid", 500);
  }
  return value;
}

function normalizeRandomBytes(value) {
  if (value == null) return crypto.randomBytes;
  if (typeof value !== "function") {
    throw failure("host_workbench_action_grant_random_source_invalid", 500);
  }
  return value;
}

function normalizeTtl(value) {
  const ttlMs = value ?? HELLOLYNK_WORKBENCH_ACTION_GRANT_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
    throw failure("host_workbench_action_grant_ttl_invalid", 500);
  }
  return ttlMs;
}

function normalizeCapacity(value) {
  const capacity = value ?? HELLOLYNK_WORKBENCH_ACTION_GRANT_CAPACITY;
  if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > MAX_CAPACITY) {
    throw failure("host_workbench_action_grant_capacity_invalid", 500);
  }
  return capacity;
}

function readNow(clock) {
  const nowMs = clock.now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw failure("host_workbench_action_grant_clock_invalid", 500);
  }
  return nowMs;
}

function readRandomBytes(randomBytes) {
  let value;
  try {
    value = randomBytes(TOKEN_BYTES);
  } catch {
    throw failure("host_workbench_action_grant_generation_failed", 500);
  }
  if (!(value instanceof Uint8Array) || value.byteLength !== TOKEN_BYTES) {
    throw failure("host_workbench_action_grant_generation_failed", 500);
  }
  return Buffer.from(value);
}

function digestText(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function invalidGrant(outcome) {
  return failure("host_workbench_action_grant_invalid", 403, outcome);
}

function failure(code, statusCode, outcome = null) {
  return new HelloLynkWorkbenchActionGrantError(code, statusCode, outcome);
}
