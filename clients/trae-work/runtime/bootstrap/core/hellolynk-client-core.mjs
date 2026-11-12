import { createHash } from "node:crypto";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_JSON_RESPONSE_BYTES = 256 * 1024;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const DEVICE_RUNTIME_TTL_MS = 20 * 60 * 1000;
const DEVICE_RUNTIME_RECOVERY_WINDOW_MS = 120_000;
const DEVICE_CREDENTIAL_RECHECK_MS = 60 * 60_000;
const DEVICE_RUNTIME_SCOPES = Object.freeze([
  "relay.text.receive",
  "relay.text.send",
  "runtime.session.refresh",
  "runtime.session.revoke",
]);
export const RECEIVE_ONLY_RUNTIME_SCOPES = Object.freeze(["relay.text.receive"]);
const INVALIDATING_RUNTIME_SESSION_REASONS = new Set([
  "runtime_session_expired",
  "runtime_session_revoked",
  "runtime_session_superseded",
  "runtime_session_missing",
  "runtime_session_invalid",
  "runtime_session_not_found",
  "invalid_runtime_session_handle",
]);

export class HelloLynkClientError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkClientError";
    this.code = code;
    this.httpStatus = options.httpStatus || null;
    this.retryable = options.retryable === true;
  }
}

export function normalizeHelloLynkBaseUrl(value, options = {}) {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    throw new HelloLynkClientError("invalid_hellolynk_base_url");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new HelloLynkClientError("unsafe_hellolynk_base_url");
  }
  const loopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(options.allowLoopbackHttp === true && loopback && url.protocol === "http:")) {
    throw new HelloLynkClientError("https_required");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}

function assertBindingKey(value) {
  const key = String(value || "");
  if (!/^hellolynk_bind_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$/.test(key)) {
    throw new HelloLynkClientError("invalid_binding_key_format");
  }
  return key;
}

function assertDeviceId(value) {
  const deviceId = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(deviceId)) {
    throw new HelloLynkClientError("invalid_device_id");
  }
  return deviceId;
}

function assertDeviceCredential(value) {
  const credential = String(value || "");
  if (!/^hellolynk_device_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$/.test(credential)) {
    throw new HelloLynkClientError("invalid_device_credential_format");
  }
  return credential;
}

function assertSafeId(value, code) {
  const normalized = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(normalized)) {
    throw new HelloLynkClientError(code);
  }
  return normalized;
}

async function safeJson(response) {
  try {
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_JSON_RESPONSE_BYTES) {
      // We own this unread body. Initiate disposal without waiting for a
      // transport's cancellation to finish or replacing the diagnostic.
      try { void Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {}
      return null;
    }
    if (!response.body || typeof response.body.getReader !== "function") return null;
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    let complete = false;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) { complete = true; break; }
        total += value.byteLength;
        if (total > MAX_JSON_RESPONSE_BYTES) return null;
        chunks.push(value);
      }
    } finally {
      if (!complete) {
        try { void Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
      }
      reader.releaseLock();
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(body));
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return null;
  }
}

function safeRemoteErrorCode(value) {
  const code = String(value || "");
  return /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "binding_key_redeem_failed";
}

function safeDeviceRuntimeErrorCode(value) {
  const code = String(value || "");
  return /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "device_runtime_session_issue_failed";
}

function normalizeRequestedRuntimeScopes(value) {
  if (value == null) return DEVICE_RUNTIME_SCOPES;
  if (
    !Array.isArray(value) ||
    value.length !== RECEIVE_ONLY_RUNTIME_SCOPES.length ||
    !RECEIVE_ONLY_RUNTIME_SCOPES.every((scope, index) => value[index] === scope)
  ) throw new HelloLynkClientError("invalid_requested_runtime_scopes");
  return RECEIVE_ONLY_RUNTIME_SCOPES;
}

function exactRuntimeScopes(actual, expected) {
  return actual.length === expected.length && expected.every((scope, index) => actual[index] === scope);
}

function assertRuntimeSessionHandle(
  value,
  expectedAgentId,
  expectedPrincipalId,
  nowMs = Date.now(),
  expectedScopes = DEVICE_RUNTIME_SCOPES,
) {
  const sessionId = assertSafeId(value?.sessionId, "invalid_runtime_session_handle");
  const runtimeId = assertSafeId(value?.runtimeId, "invalid_runtime_session_handle");
  const principalId = assertSafeId(value?.principalId, "invalid_runtime_session_handle");
  const agentId = assertSafeId(value?.agentId, "invalid_runtime_session_handle");
  const delegateId = value?.delegateId == null ? null
    : assertSafeId(value.delegateId, "invalid_runtime_session_handle");
  const hostId = value?.hostId == null ? null
    : assertSafeId(value.hostId, "invalid_runtime_session_handle");
  const authorizationVersion = value?.authorizationVersion == null ? null : Number(value.authorizationVersion);
  const routeFieldCount = [delegateId, hostId, authorizationVersion].filter((item) => item != null).length;
  const deviceId = assertSafeId(value?.deviceId, "invalid_runtime_session_handle");
  const sessionSecret = String(value?.sessionSecret || "");
  const expiresAtMs = Number(value?.expiresAtMs);
  const allowedScopes = Array.isArray(value?.allowedScopes) ? value.allowedScopes.map(String) : [];
  const exactScopes = exactRuntimeScopes(allowedScopes, expectedScopes);
  if (
    !/^runtime_[a-f0-9]{48}$/.test(sessionSecret) ||
    principalId !== expectedPrincipalId ||
    agentId !== expectedAgentId ||
    !exactScopes ||
    (routeFieldCount !== 0 && routeFieldCount !== 3) ||
    (routeFieldCount === 3 && (!Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1)) ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= nowMs
  ) throw new HelloLynkClientError("invalid_runtime_session_handle");
  return {
    sessionId,
    sessionSecret,
    runtimeId,
    principalId,
    agentId,
    delegateId,
    hostId,
    authorizationVersion,
    deviceId,
    allowedScopes: [...allowedScopes],
    expiresAtMs,
  };
}

// A recently expired predecessor is only a recovery proof for the issue endpoint.
// Keep ordinary session validation strict so this cannot authorize business calls.
function assertRuntimeRecoveryProof(value, expectedAgentId, expectedPrincipalId, nowMs, expectedScopes) {
  return assertRuntimeSessionHandle(
    value, expectedAgentId, expectedPrincipalId,
    nowMs - DEVICE_RUNTIME_RECOVERY_WINDOW_MS, expectedScopes,
  );
}

export function shouldInvalidateDeviceRuntimeSession(error) {
  const candidates = [error?.reason, error?.code]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return candidates.some((value) => {
    if (INVALIDATING_RUNTIME_SESSION_REASONS.has(value)) return true;
    const wrapped = value.match(
      /^relay_event_stream_closed_(runtime_session_(?:expired|revoked|superseded|missing|invalid|not_found))$/,
    );
    return Boolean(wrapped && INVALIDATING_RUNTIME_SESSION_REASONS.has(wrapped[1]));
  });
}

async function boundedJsonFetch(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { ...options, signal: controller.signal });
    const result = await safeJson(response);
    return { response, result };
  } catch (error) {
    if (error?.name === "AbortError") throw new HelloLynkClientError("request_timeout", { retryable: true });
    throw new HelloLynkClientError(runtimeSafety.helloLynkNetworkErrorCode(error), { cause: error, retryable: true });
  } finally {
    clearTimeout(timer);
  }
}

export async function redeemAgentBindingKey(options) {
  const baseUrl = normalizeHelloLynkBaseUrl(options?.baseUrl, {
    allowLoopbackHttp: options?.allowLoopbackHttp === true,
  });
  const bindingKey = assertBindingKey(options?.bindingKey);
  const deviceId = assertDeviceId(options?.deviceId);
  const hostInstallationId = assertSafeId(
    options?.hostInstallationId,
    "invalid_host_installation_id",
  );
  const fetchImpl = options?.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  if (typeof fetchImpl !== "function") throw new HelloLynkClientError("fetch_unavailable");
  const timeoutMs = Math.min(Math.max(Number(options?.timeoutMs) || DEFAULT_TIMEOUT_MS, 1_000), 30_000);
  const endpoint = `${baseUrl}/api/v1/public-preview/agent-binding-keys/redeem`;
  const { response, result } = await boundedJsonFetch(fetchImpl, endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      bindingKey,
      deviceId,
      hostInstallationId,
      ...(options?.bootstrapHostTransport === true ? { bootstrapHostTransport: true } : {}),
    }),
    redirect: "error",
  }, timeoutMs);
  if (!response.ok) {
    throw new HelloLynkClientError(safeRemoteErrorCode(result?.error), { httpStatus: response.status });
  }
  if (
    typeof result?.deviceCredential !== "string" ||
    typeof result?.deviceCredentialId !== "string" ||
    typeof result?.hellolynkId !== "string" ||
    typeof result?.delegateId !== "string" ||
    result.deviceId !== deviceId ||
    result.credentialReturnedOnce !== true
  ) {
    throw new HelloLynkClientError("invalid_redeem_response");
  }
  const redeemRouteFieldCount = [result.hostId, result.authorizationVersion]
    .filter((value) => value != null).length;
  if (redeemRouteFieldCount !== 0 && redeemRouteFieldCount !== 2) {
    throw new HelloLynkClientError("invalid_redeem_response");
  }
  const hostId = redeemRouteFieldCount === 2
    ? assertSafeId(result.hostId, "invalid_redeem_response") : null;
  const authorizationVersion = redeemRouteFieldCount === 2
    ? Number(result.authorizationVersion) : null;
  if (redeemRouteFieldCount === 2 && (
    !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1
  )) throw new HelloLynkClientError("invalid_redeem_response");
  const bootstrapHostTransportCredential = result.bootstrapHostTransportCredential == null
    ? null : normalizeBootstrapHostTransportCredential(
      result.bootstrapHostTransportCredential,
      hostId,
      result.bootstrapHostTransportCredentialReturnedOnce,
    );
  return {
    credential: result.deviceCredential,
    credentialId: result.deviceCredentialId,
    principalId: result.principalId,
    hellolynkId: assertSafeId(result.hellolynkId, "invalid_redeem_response"),
    agentId: result.agentId,
    delegateId: assertSafeId(result.delegateId, "invalid_redeem_response"),
    hostId,
    authorizationVersion,
    deviceId: result.deviceId,
    region: result.region,
    allowedScopes: Array.isArray(result.allowedScopes) ? [...result.allowedScopes] : [],
    bootstrapHostTransportCredential,
  };
}

function normalizeBootstrapHostTransportCredential(value, hostId, returnedOnce) {
  if (!hostId || returnedOnce !== true || !value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "createdAt,credential,credentialId,expiresAt,hostId") {
    throw new HelloLynkClientError("invalid_redeem_response");
  }
  const credentialId = assertSafeId(value.credentialId, "invalid_redeem_response");
  const credential = String(value.credential || "");
  const createdAt = String(value.createdAt || "");
  const expiresAt = String(value.expiresAt || "");
  if (value.hostId !== hostId
    || !new RegExp(`^hellolynk_host_transport_v1_${credentialId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.[A-Za-z0-9_-]{32,}$`).test(credential)
    || !Number.isFinite(Date.parse(createdAt)) || !Number.isFinite(Date.parse(expiresAt))
    || Date.parse(expiresAt) <= Date.parse(createdAt)) {
    throw new HelloLynkClientError("invalid_redeem_response");
  }
  return Object.freeze({ credentialId, hostId, credential, createdAt, expiresAt });
}

export async function issueDeviceRuntimeSession(options) {
  const baseUrl = normalizeHelloLynkBaseUrl(options?.baseUrl, {
    allowLoopbackHttp: options?.allowLoopbackHttp === true,
  });
  const deviceCredential = assertDeviceCredential(options?.deviceCredential);
  const expectedPrincipalId = assertSafeId(options?.expectedPrincipalId, "invalid_expected_principal_id");
  const expectedAgentId = assertSafeId(options?.expectedAgentId, "invalid_expected_agent_id");
  const expectsRoute = options?.expectedDelegateId != null || options?.expectedHostId != null
    || options?.expectedAuthorizationVersion != null;
  if (expectsRoute && (
    options?.expectedDelegateId == null || options?.expectedHostId == null
    || options?.expectedAuthorizationVersion == null
  )) throw new HelloLynkClientError("invalid_expected_runtime_route");
  const expectedDelegateId = expectsRoute
    ? assertSafeId(options.expectedDelegateId, "invalid_expected_runtime_route") : null;
  const expectedHostId = expectsRoute
    ? assertSafeId(options.expectedHostId, "invalid_expected_runtime_route") : null;
  const expectedAuthorizationVersion = expectsRoute ? Number(options.expectedAuthorizationVersion) : null;
  if (expectsRoute && (!Number.isSafeInteger(expectedAuthorizationVersion) || expectedAuthorizationVersion < 1)) {
    throw new HelloLynkClientError("invalid_expected_runtime_route");
  }
  const expectedRuntimeType = assertSafeId(
    options?.expectedRuntimeType || "hellolynk_client",
    "invalid_expected_runtime_type",
  );
  const requestedScopes = normalizeRequestedRuntimeScopes(options?.requestedScopes);
  const fetchImpl = options?.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  if (typeof fetchImpl !== "function") throw new HelloLynkClientError("fetch_unavailable");
  const timeoutMs = Math.min(Math.max(Number(options?.timeoutMs) || DEFAULT_TIMEOUT_MS, 1_000), 30_000);
  const endpoint = `${baseUrl}/api/v1/public-preview/device-credentials/runtime-sessions`;
  const requestedAt = Date.now();
  const previous = options.previousSession == null ? null : assertRuntimeRecoveryProof(
    options.previousSession, expectedAgentId, expectedPrincipalId, requestedAt, requestedScopes,
  );
  if (previous && expectsRoute && (previous.delegateId !== expectedDelegateId
    || previous.hostId !== expectedHostId || previous.authorizationVersion !== expectedAuthorizationVersion)) {
    throw new HelloLynkClientError("invalid_expected_runtime_route");
  }
  const explicitReceiveOnly = requestedScopes === RECEIVE_ONLY_RUNTIME_SCOPES;
  const { response, result } = await boundedJsonFetch(fetchImpl, endpoint, {
    method: "POST",
    headers: {
      accept: "application/json",
      ...(explicitReceiveOnly ? { "content-type": "application/json" } : {}),
      "x-hellolynk-device-credential": deviceCredential,
      ...(previous ? {
        "x-hellolynk-runtime-session-id": previous.sessionId,
        "x-hellolynk-runtime-session-secret": previous.sessionSecret,
      } : {}),
    },
    ...(explicitReceiveOnly ? { body: JSON.stringify({ allowedScopes: [...requestedScopes] }) } : {}),
    redirect: "error",
  }, timeoutMs);
  if (!response.ok) {
    // The authenticated server has confirmed that this instance has no active
    // lease. One fresh session request still passes its clone/conflict checks.
    // A lost response, an ordinary 401 or an active successor never takes this path.
    if (previous && response.status === 401 && result?.error === "runtime_session_recovery_unneeded") {
      const fresh = await issueDeviceRuntimeSession({ ...options, previousSession: null });
      if (fresh.deviceId !== previous.deviceId || fresh.delegateId !== previous.delegateId
        || fresh.hostId !== previous.hostId || fresh.authorizationVersion !== previous.authorizationVersion) {
        throw new HelloLynkClientError("invalid_device_runtime_response");
      }
      return fresh;
    }
    const code = response.status === 401 && result?.error === "device_credential_invalid"
      && result?.reason === "device_credential_revoked" ? result.reason : safeDeviceRuntimeErrorCode(result?.error);
    throw new HelloLynkClientError(code, {
      httpStatus: response.status,
      retryable: response.status === 408 || response.status === 425 || response.status === 429 || response.status >= 500,
    });
  }

  const session = result?.runtimeSession;
  const sessionId = assertSafeId(session?.id, "invalid_device_runtime_response");
  const runtimeId = assertSafeId(session?.runtimeId, "invalid_device_runtime_response");
  const principalId = assertSafeId(session?.principalId, "invalid_device_runtime_response");
  const agentId = assertSafeId(session?.agentId, "invalid_device_runtime_response");
  const deviceId = assertSafeId(session?.deviceId, "invalid_device_runtime_response");
  const routeFieldCount = [session?.delegateId, session?.hostId, session?.authorizationVersion]
    .filter((value) => value != null).length;
  if (routeFieldCount !== 0 && routeFieldCount !== 3) throw new HelloLynkClientError("invalid_device_runtime_response");
  const delegateId = routeFieldCount === 3
    ? assertSafeId(session.delegateId, "invalid_device_runtime_response") : null;
  const hostId = routeFieldCount === 3
    ? assertSafeId(session.hostId, "invalid_device_runtime_response") : null;
  const authorizationVersion = routeFieldCount === 3 ? Number(session.authorizationVersion) : null;
  const secret = String(result?.runtimeSessionSecret || "");
  const expiresAtMs = Date.parse(String(session?.expiresAt || ""));
  const scopes = Array.isArray(session?.allowedScopes) ? session.allowedScopes.map(String) : [];
  const exactScopes = exactRuntimeScopes(scopes, requestedScopes);
  const recoverableRotation = result?.secretReturnedOnce === false
    && result?.recoveryWindowMs === DEVICE_RUNTIME_RECOVERY_WINDOW_MS;
  const recoveredCreatedAtMs = expiresAtMs - DEVICE_RUNTIME_TTL_MS;
  const validSecretDelivery = recoverableRotation
    ? previous != null && routeFieldCount === 3 && previous.delegateId != null
      && recoveredCreatedAtMs > requestedAt - DEVICE_RUNTIME_RECOVERY_WINDOW_MS - 5 * 60_000
      && recoveredCreatedAtMs <= previous.expiresAtMs
    // An active device credential can receive a fresh session even when its
    // previous proof has expired (for example without an instance lease).
    // This is a new authenticated issue, not recovery of an old secret. The
    // exact owner, device, route, scopes and lifetime are still checked below.
    : result?.secretReturnedOnce === true && result?.recoveryWindowMs == null;
  if (
    !/^runtime_[a-f0-9]{48}$/.test(secret) ||
    !validSecretDelivery ||
    result?.previewOnly !== true ||
    result?.expiresInMs !== DEVICE_RUNTIME_TTL_MS ||
    session?.sessionState !== "active" ||
    session?.runtimeType !== expectedRuntimeType ||
    session?.executionMode !== "receive_only" ||
    session?.signatureRequired !== false ||
    !exactScopes ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= requestedAt ||
    expiresAtMs > requestedAt + DEVICE_RUNTIME_TTL_MS + 5 * 60_000 ||
    principalId !== expectedPrincipalId ||
    agentId !== expectedAgentId ||
    (previous && (
      deviceId !== previous.deviceId || delegateId !== previous.delegateId
      || hostId !== previous.hostId || authorizationVersion !== previous.authorizationVersion
    )) ||
    (routeFieldCount === 3 && (!Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1)) ||
    (expectsRoute && (
      delegateId !== expectedDelegateId || hostId !== expectedHostId
      || authorizationVersion !== expectedAuthorizationVersion
    ))
  ) {
    throw new HelloLynkClientError("invalid_device_runtime_response");
  }

  return {
    sessionId,
    sessionSecret: secret,
    runtimeId,
    runtimeType: expectedRuntimeType,
    principalId,
    agentId,
    delegateId,
    hostId,
    authorizationVersion,
    deviceId,
    allowedScopes: [...scopes],
    expiresAt: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
  };
}

export async function preflightDeviceRuntimeSession(options) {
  const baseUrl = normalizeHelloLynkBaseUrl(options?.baseUrl, {
    allowLoopbackHttp: options?.allowLoopbackHttp === true,
  });
  const expectedPrincipalId = assertSafeId(options?.expectedPrincipalId, "invalid_expected_principal_id");
  const expectedAgentId = assertSafeId(options?.expectedAgentId, "invalid_expected_agent_id");
  const expectsRoute = options?.expectedDelegateId != null || options?.expectedHostId != null
    || options?.expectedAuthorizationVersion != null;
  if (expectsRoute && (
    options?.expectedDelegateId == null || options?.expectedHostId == null
    || options?.expectedAuthorizationVersion == null
  )) throw new HelloLynkClientError("invalid_expected_runtime_route");
  const expectedDelegateId = expectsRoute
    ? assertSafeId(options.expectedDelegateId, "invalid_expected_runtime_route") : null;
  const expectedHostId = expectsRoute
    ? assertSafeId(options.expectedHostId, "invalid_expected_runtime_route") : null;
  const expectedAuthorizationVersion = expectsRoute ? Number(options.expectedAuthorizationVersion) : null;
  const requestedScopes = normalizeRequestedRuntimeScopes(options?.requestedScopes);
  const session = assertRuntimeSessionHandle(
    options?.session,
    expectedAgentId,
    expectedPrincipalId,
    Date.now(),
    requestedScopes,
  );
  const fetchImpl = options?.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  if (typeof fetchImpl !== "function") throw new HelloLynkClientError("fetch_unavailable");
  const timeoutMs = Math.min(Math.max(Number(options?.timeoutMs) || DEFAULT_TIMEOUT_MS, 1_000), 30_000);
  const { response, result } = await boundedJsonFetch(fetchImpl, `${baseUrl}/api/v1/runtime/session`, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-hellolynk-runtime-session-id": session.sessionId,
      "x-hellolynk-runtime-session-secret": session.sessionSecret,
    },
    redirect: "error",
  }, timeoutMs);
  if (!response.ok) {
    throw new HelloLynkClientError(safeDeviceRuntimeErrorCode(result?.error), {
      httpStatus: response.status,
      retryable: response.status === 408 || response.status === 425 || response.status === 429 || response.status >= 500,
    });
  }
  const remoteSession = result?.runtimeSession;
  const remoteScopes = Array.isArray(remoteSession?.allowedScopes)
    ? remoteSession.allowedScopes.map(String) : [];
  const remoteRouteFieldCount = [
    remoteSession?.delegateId, remoteSession?.hostId, remoteSession?.authorizationVersion,
  ].filter((value) => value != null).length;
  const localRouteFieldCount = [session.delegateId, session.hostId, session.authorizationVersion]
    .filter((value) => value != null).length;
  const remoteAuthorizationVersion = remoteRouteFieldCount === 3
    ? Number(remoteSession.authorizationVersion) : null;
  const remoteRouteValid = remoteRouteFieldCount !== 3 || (
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(String(remoteSession.delegateId || "").trim())
    && /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(String(remoteSession.hostId || "").trim())
    && Number.isSafeInteger(remoteAuthorizationVersion)
    && remoteAuthorizationVersion >= 1
  );
  if (
    remoteSession?.id !== session.sessionId ||
    remoteSession?.runtimeId !== session.runtimeId ||
    remoteSession?.principalId !== expectedPrincipalId ||
    remoteSession?.agentId !== expectedAgentId ||
    remoteSession?.deviceId !== session.deviceId ||
    !exactRuntimeScopes(remoteScopes, requestedScopes) ||
    remoteRouteFieldCount !== localRouteFieldCount ||
    !remoteRouteValid ||
    (remoteRouteFieldCount === 3 && (
      remoteSession.delegateId !== session.delegateId
      || remoteSession.hostId !== session.hostId
      || remoteAuthorizationVersion !== session.authorizationVersion
    )) ||
    (expectsRoute && (
      remoteSession?.delegateId !== expectedDelegateId || remoteSession?.hostId !== expectedHostId
      || Number(remoteSession?.authorizationVersion) !== expectedAuthorizationVersion
      || session.delegateId !== expectedDelegateId || session.hostId !== expectedHostId
      || session.authorizationVersion !== expectedAuthorizationVersion
    )) ||
    remoteSession?.sessionState !== "active" ||
    (remoteRouteFieldCount !== 0 && remoteRouteFieldCount !== 3) ||
    result?.runtime?.id !== session.runtimeId ||
    result?.agent?.id !== expectedAgentId
  ) throw new HelloLynkClientError("invalid_runtime_session_preflight_response");
  return {
    ok: true,
    principalId: expectedPrincipalId,
    agentId: expectedAgentId,
    ...(expectsRoute ? {
      delegateId: expectedDelegateId,
      hostId: expectedHostId,
      authorizationVersion: expectedAuthorizationVersion,
    } : {}),
    expiresAt: new Date(session.expiresAtMs).toISOString(),
  };
}

export function createDeviceRuntimeSessionManager(options = {}) {
  const issue = options.issue || issueDeviceRuntimeSession;
  const now = options.now || (() => Date.now());
  const sessionStore = options.sessionStore || null;
  const credentialRejections = sessionStore?.credentialRejections;
  const sessionKey = options.sessionKey == null ? null : String(options.sessionKey);
  if (sessionStore && (
    !sessionKey ||
    typeof sessionStore.load !== "function" ||
    typeof sessionStore.save !== "function" ||
    typeof sessionStore.remove !== "function" ||
    typeof sessionStore.withLock !== "function"
  )) throw new HelloLynkClientError("invalid_runtime_session_store");
  const minimumRemainingMs = Math.min(
    Math.max(Number(options.minimumRemainingMs) || 2 * 60 * 1000, 30_000),
    5 * 60 * 1000,
  );
  let current = null;
  let rejectedCredential = null;
  const revokedFingerprints = new Set();
  let localIssueTail = Promise.resolve();

  const routeMatches = (session, input) => {
    const expectedValues = [
      input?.expectedDelegateId, input?.expectedHostId, input?.expectedAuthorizationVersion,
    ];
    const expectedCount = expectedValues.filter((value) => value != null).length;
    if (expectedCount === 0) return true;
    if (expectedCount !== 3) throw new HelloLynkClientError("invalid_expected_runtime_route");
    return session.delegateId === String(input.expectedDelegateId)
      && session.hostId === String(input.expectedHostId)
      && session.authorizationVersion === Number(input.expectedAuthorizationVersion);
  };

  const scopesMatch = (session, input) => {
    const expectedScopes = normalizeRequestedRuntimeScopes(input?.requestedScopes);
    return exactRuntimeScopes(session.allowedScopes, expectedScopes);
  };

  const reusable = (candidate, input, remainingMs = minimumRemainingMs) => {
    try {
      if (!candidate) return null;
      const normalized = assertRuntimeSessionHandle(
        candidate,
        input?.expectedAgentId == null
          ? candidate.agentId : assertSafeId(input.expectedAgentId, "invalid_expected_agent_id"),
        input?.expectedPrincipalId == null
          ? candidate.principalId : assertSafeId(input.expectedPrincipalId, "invalid_expected_principal_id"),
        now(),
        normalizeRequestedRuntimeScopes(input?.requestedScopes),
      );
      return normalized.expiresAtMs - now() > remainingMs
        && routeMatches(normalized, input) && scopesMatch(normalized, input)
        ? normalized : null;
    } catch (error) {
      if (error?.code === "invalid_runtime_session_handle") return null;
      throw error;
    }
  };

  const recoveryProof = (candidate, input) => {
    if (!candidate) return null;
    try {
      const normalized = assertRuntimeRecoveryProof(
        candidate,
        input?.expectedAgentId == null
          ? candidate.agentId : assertSafeId(input.expectedAgentId, "invalid_expected_agent_id"),
        input?.expectedPrincipalId == null
          ? candidate.principalId : assertSafeId(input.expectedPrincipalId, "invalid_expected_principal_id"),
        now(), normalizeRequestedRuntimeScopes(input?.requestedScopes),
      );
      return routeMatches(normalized, input) && scopesMatch(normalized, input) ? normalized : null;
    } catch (error) {
      if (error?.code === "invalid_runtime_session_handle") return null;
      throw error;
    }
  };

  const loadPersisted = async (input) => {
    let persisted;
    try {
      persisted = await sessionStore.load(sessionKey);
    } catch (error) {
      if (error?.code !== "invalid_runtime_session_handle") throw error;
      await sessionStore.remove(sessionKey);
      return null;
    }
    if (!persisted) return null;
    const proof = recoveryProof(persisted, input);
    if (!proof) await sessionStore.remove(sessionKey);
    return proof;
  };

  const issueSession = async (input, previousSession) => {
    const request = { ...input, previousSession };
    if (options.loadDeviceCredential) request.deviceCredential = await options.loadDeviceCredential();
    const fingerprint = request.deviceCredential && request.baseUrl
      ? createHash("sha256").update(JSON.stringify([
        normalizeHelloLynkBaseUrl(request.baseUrl, { allowLoopbackHttp: request.allowLoopbackHttp === true }),
        request.deviceCredential,
      ])).digest("hex")
      : null;
    // The production caller holds the existing session lock, including across
    // Host processes. An authority denial may drain the current Host.
    const revocationKey = fingerprint && `revoked-${fingerprint}`;
    if (fingerprint) {
      // An older process may update or clear its temporary rejection for the
      // profile. Keep permanent revocation under the credential's own key.
      if (revokedFingerprints.has(fingerprint)
        || (await credentialRejections?.load(revocationKey).catch(() => null))?.fingerprint === fingerprint) {
        revokedFingerprints.add(fingerprint);
        throw new HelloLynkClientError("device_credential_revoked", { httpStatus: 401 });
      }
      const isCoolingDown = (rejection) => {
        if (rejection?.fingerprint !== fingerprint) return false;
        const age = now() - rejection.rejectedAtMs;
        return age >= 0 && age < DEVICE_CREDENTIAL_RECHECK_MS;
      };
      // A generic denial may clear after a server-side repair, without a new
      // credential. The lock permits one recheck once the cooldown ends.
      if (isCoolingDown(rejectedCredential)
        || isCoolingDown(await credentialRejections?.load(sessionKey).catch(() => null))) {
        throw new HelloLynkClientError("device_credential_invalid", { httpStatus: 401 });
      }
    }
    let session;
    try {
      session = reusable(await issue(request), input);
    } catch (error) {
      if (fingerprint && error?.httpStatus === 401) {
        if (error.code === "device_credential_revoked") {
          revokedFingerprints.add(fingerprint);
          await credentialRejections?.save(revocationKey, { fingerprint, rejectedAtMs: now() }).catch(() => {});
        } else if (error.code === "device_credential_invalid") {
          rejectedCredential = { fingerprint, rejectedAtMs: now() };
          await credentialRejections?.save(sessionKey, rejectedCredential).catch(() => {});
        }
      }
      throw error;
    }
    if (session && fingerprint) {
      rejectedCredential = null;
      await credentialRejections?.remove(sessionKey).catch(() => {});
    }
    return session;
  };

  return {
    async get(input) {
      if (!sessionStore) {
        const result = localIssueTail.then(async () => {
          if (
            current && current.expiresAtMs - now() > minimumRemainingMs
            && routeMatches(current, input)
            && scopesMatch(current, input)
            && (input?.expectedAgentId == null || input.expectedAgentId === current.agentId)
            && (input?.expectedPrincipalId == null || input.expectedPrincipalId === current.principalId)
          ) return current;
          const reusableCurrent = reusable(current, input);
          if (reusableCurrent) return reusableCurrent;
          current = await issueSession(input, recoveryProof(current, input));
          if (!current) throw new HelloLynkClientError("invalid_runtime_session_handle");
          return current;
        });
        localIssueTail = result.catch(() => {});
        return result;
      }
      const inMemory = reusable(current, input);
      if (inMemory) return inMemory;
      current = null;
      return sessionStore.withLock(sessionKey, async () => {
        const persisted = await loadPersisted(input);
        if (persisted && reusable(persisted, input)) {
          current = persisted;
          return current;
        }
        const issued = await issueSession(input, persisted);
        if (!issued) throw new HelloLynkClientError("invalid_runtime_session_handle");
        await sessionStore.save(sessionKey, issued);
        current = issued;
        return current;
      });
    },
    async clear(error) {
      if (error !== undefined && !shouldInvalidateDeviceRuntimeSession(error)) return false;
      const invalidatedSessionId = current?.sessionId || null;
      current = null;
      if (!sessionStore) return true;
      return sessionStore.withLock(sessionKey, async () => {
        let persisted = null;
        try {
          persisted = await sessionStore.load(sessionKey);
        } catch (loadError) {
          if (loadError?.code !== "invalid_runtime_session_handle") throw loadError;
        }
        if (invalidatedSessionId && persisted?.sessionId && persisted.sessionId !== invalidatedSessionId) {
          return false;
        }
        await sessionStore.remove(sessionKey);
        return true;
      });
    },
    status() {
      return current ? {
        ready: current.expiresAtMs > now(),
        expiresAt: new Date(current.expiresAtMs).toISOString(),
      } : { ready: false, expiresAt: null };
    },
  };
}

export async function runSanitizedDoctor(options) {
  const credentialPresent = Boolean(options?.credentialPresent);
  let baseUrl;
  try {
    baseUrl = normalizeHelloLynkBaseUrl(options?.baseUrl, {
      allowLoopbackHttp: options?.allowLoopbackHttp === true,
    });
  } catch (error) {
    return {
      ok: false,
      serviceReachable: false,
      credentialPresent,
      platform: String(options?.platform || process.platform),
      errorCode: error.code || "invalid_hellolynk_base_url",
    };
  }
  const fetchImpl = options?.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  if (typeof fetchImpl !== "function") {
    return {
      ok: false,
      serviceReachable: false,
      credentialPresent,
      platform: String(options?.platform || process.platform),
      errorCode: "fetch_unavailable",
    };
  }
  try {
    const { response, result } = await boundedJsonFetch(fetchImpl, `${baseUrl}/api/v1/health`, {
      method: "GET",
      headers: { accept: "application/json" },
      redirect: "error",
    }, Math.min(Math.max(Number(options?.timeoutMs) || 5_000, 1_000), 15_000));
    return {
      ok: response.ok && result?.ok === true && credentialPresent,
      serviceReachable: response.ok,
      credentialPresent,
      platform: String(options?.platform || process.platform),
      serviceName: typeof result?.name === "string" ? result.name : null,
      securityLevel: typeof result?.securityLevel === "string" ? result.securityLevel : null,
      errorCode: !response.ok || result?.ok !== true
        ? "health_check_failed"
        : credentialPresent
          ? null
          : "device_credential_unavailable",
    };
  } catch (error) {
    return {
      ok: false,
      serviceReachable: false,
      credentialPresent,
      platform: String(options?.platform || process.platform),
      errorCode: error.code || "network_request_failed",
    };
  }
}
