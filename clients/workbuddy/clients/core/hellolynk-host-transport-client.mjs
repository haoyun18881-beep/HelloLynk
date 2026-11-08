import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { randomUUID } from "node:crypto";
import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const MAX_SSE_BUFFER_BYTES = 256 * 1024;
const DEFAULT_SESSION_ROTATION_LEAD_MS = 30_000;
const DEFAULT_JSON_REQUEST_TIMEOUT_MS = 8_000;
const MAX_JSON_REQUEST_TIMEOUT_MS = 120_000;
// The relay sends byte-level keepalives every 20 seconds by default.
const DEFAULT_STREAM_IDLE_TIMEOUT_MS = 90_000;
const MAX_STREAM_IDLE_TIMEOUT_MS = 300_000;

export class HelloLynkHostTransportClientError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkHostTransportClientError";
    this.code = code;
    this.httpStatus = Number.isInteger(options.httpStatus) ? options.httpStatus : null;
  }
}

export function createHelloLynkHostTransportClient(options = {}) {
  const baseUrl = normalizeHelloLynkBaseUrl(options.baseUrl, {
    allowLoopbackHttp: options.allowLoopbackHttp === true,
  }).replace(/\/api\/v1$/, "");
  const fetchImpl = options.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  const credentialProvider = options.credentialProvider;
  const sessionProvider = options.sessionProvider;
  const runtimeHeadersForDelegate = options.runtimeHeadersForDelegate;
  const jsonRequestTimeoutMs = positiveInteger(
    options.requestTimeoutMs ?? DEFAULT_JSON_REQUEST_TIMEOUT_MS,
    "host_transport_request_timeout_invalid",
  );
  if (jsonRequestTimeoutMs > MAX_JSON_REQUEST_TIMEOUT_MS) {
    throw failure("host_transport_request_timeout_invalid");
  }
  const streamIdleTimeoutMs = positiveInteger(
    options.streamIdleTimeoutMs ?? DEFAULT_STREAM_IDLE_TIMEOUT_MS,
    "host_transport_stream_idle_timeout_invalid",
  );
  if (streamIdleTimeoutMs > MAX_STREAM_IDLE_TIMEOUT_MS) {
    throw failure("host_transport_stream_idle_timeout_invalid");
  }
  const owner = Object.freeze({
    principalId: safeId(options.expectedPrincipalId, "host_transport_principal_invalid"),
    hostId: safeId(options.expectedHostId, "host_transport_host_invalid"),
  });
  const registeredEndpoints = new Map();
  const lifetime = new AbortController();
  // Standalone transports keep their own identity. The process-owning Host
  // supplies a durable attempt only after taking its installation lock.
  const receiverId = randomUUID();
  let receiverSequence = 0;
  let activeStream = null;
  let activeSessionPending = null;
  let issuedSessionPending = null;
  let sessionPersistencePending = null;
  let cachedSession = null;
  let latestSessionId = null;
  let staleSessionId = null;
  let rotateBeforeNextStreamSessionId = null;
  let sessionGeneration = 0;
  if (typeof fetchImpl !== "function") throw failure("host_transport_fetch_unavailable");
  if (!credentialProvider || typeof credentialProvider.get !== "function") {
    throw failure("host_transport_credential_provider_required");
  }
  if (!sessionProvider || typeof sessionProvider.get !== "function"
    || typeof sessionProvider.save !== "function") {
    throw failure("host_transport_session_provider_required");
  }

  async function issueSession(signal) {
    assertUsable(signal);
    if (!issuedSessionPending) {
      cachedSession = null;
      sessionGeneration += 1;
      const pending = mintSession();
      issuedSessionPending = pending;
      pending.finally(() => {
        if (issuedSessionPending === pending) issuedSessionPending = null;
      }).catch(() => {});
    }
    return waitForSession(issuedSessionPending, signal);
  }

  async function mintSession() {
    const credential = String(await credentialProvider.get() || "");
    assertUsable();
    if (!credential) throw failure("host_transport_credential_required");
    const result = await jsonRequest("/api/v2/host-transport/sessions", {
      method: "POST",
      headers: { "x-hellolynk-host-transport-credential": credential },
      body: {},
    });
    const session = validateSession({
      sessionId: safeId(result.hostTransportSessionId, "host_transport_session_invalid"),
      sessionSecret: String(result.hostTransportSessionSecret || ""),
      principalId: safeId(result.principalId, "host_transport_principal_invalid"),
      hostId: safeId(result.hostId, "host_transport_host_invalid"),
      expiresAt: String(result.expiresAt || ""),
    }, owner);
    // A stopped transport must not publish a late cloud response into the
    // protected slot now used by the replacement Host.
    assertUsable();
    const persistence = Promise.resolve(sessionProvider.save(session));
    sessionPersistencePending = persistence;
    try { await persistence; }
    finally { if (sessionPersistencePending === persistence) sessionPersistencePending = null; }
    assertUsable();
    cachedSession = session;
    latestSessionId = session.sessionId;
    staleSessionId = null;
    return session;
  }

  async function registerEndpoint(input = {}) {
    assertUsable(input.signal);
    const session = await activeSession(input.signal);
    assertUsable(input.signal);
    const runtimeHeaders = await requiredRuntimeHeaders(input.runtimeHeaders);
    assertUsable(input.signal);
    const result = await jsonRequest("/api/v2/host-transport/endpoints", {
      method: "POST",
      headers: {
        ...hostSessionHeaders(session),
        ...runtimeHeaders,
      },
      body: { identityKeyId: safeId(input.identityKeyId, "host_transport_identity_invalid") },
      signal: input.signal,
    });
    input.signal?.throwIfAborted();
    const endpoint = validateEndpointResult(result, owner);
    if (input.delegateId != null && endpoint.delegateId !== input.delegateId) {
      throw failure("host_transport_endpoint_response_mismatch");
    }
    registeredEndpoints.set(endpointRouteKey(endpoint.deviceId, endpoint.identityKeyId), endpoint);
    return result;
  }

  async function openEventStream(input = {}) {
    assertUsable(input.signal);
    if (activeStream) throw failure("host_transport_stream_already_open");
    const slot = {};
    activeStream = slot;
    try {
      return await openOwnedEventStream(input, slot);
    } catch (error) {
      if (activeStream === slot) activeStream = null;
      throw error;
    }
  }

  async function openOwnedEventStream(input, slot) {
    let attempt;
    if (input.receiverAttempt !== undefined) {
      requireExactFields(input.receiverAttempt, ["receiverId", "sequence"], "host_transport_receiver_invalid");
      attempt = { receiverId: safeId(input.receiverAttempt.receiverId, "host_transport_receiver_invalid"),
        sequence: positiveInteger(input.receiverAttempt.sequence, "host_transport_receiver_invalid") };
    } else {
      attempt = { receiverId, sequence: positiveInteger(++receiverSequence, "host_transport_receiver_invalid") };
    }
    const rotationLeadMs = Math.min(
      Math.max(Number(input.rotationLeadMs) || DEFAULT_SESSION_ROTATION_LEAD_MS, 25),
      120_000,
    );
    if (rotateBeforeNextStreamSessionId) {
      invalidateSession(rotateBeforeNextStreamSessionId);
      rotateBeforeNextStreamSessionId = null;
    }
    const session = await activeSession(input.signal);
    assertUsable(input.signal);
    const requestSignal = input.signal ? AbortSignal.any([input.signal, lifetime.signal]) : lifetime.signal;
    const controller = new AbortController();
    let response;
    let rotationTimer;
    const cleanup = () => {
      clearTimeout(rotationTimer);
      requestSignal.removeEventListener("abort", abortFromCaller);
      if (activeStream === slot) activeStream = null;
    };
    const abortFromCaller = () => controller.abort(requestSignal.reason);
    controller.signal.addEventListener("abort", () => {
      cleanup();
      // A reader may already own the body; readSseBytes cancels that reader.
      void response?.body?.cancel().catch(() => {});
    }, { once: true });
    if (requestSignal.aborted) abortFromCaller();
    else requestSignal.addEventListener("abort", abortFromCaller, { once: true });
    let handshakeTimer;
    let rejectAbortedHandshake;
    const handshakeDeadline = new Promise((_, reject) => {
      rejectAbortedHandshake = () => reject(controller.signal.reason);
      if (controller.signal.aborted) rejectAbortedHandshake();
      else controller.signal.addEventListener("abort", rejectAbortedHandshake, { once: true });
      handshakeTimer = setTimeout(() => controller.abort(failure("host_transport_request_timeout")), jsonRequestTimeoutMs);
    });
    const handshake = (async () => {
      if (controller.signal.aborted) throw controller.signal.reason;
      try {
        response = await fetchImpl(`${baseUrl}/api/v2/host-transport/events`, {
          method: "GET",
          headers: {
            accept: "text/event-stream",
            "x-hellolynk-host-transport-version": "1",
            "x-hellolynk-instance-direct-version": "1",
            "x-hellolynk-native-content-version": "1",
            "x-hellolynk-host-receiver-id": attempt.receiverId,
            "x-hellolynk-host-receiver-sequence": String(attempt.sequence),
            ...hostSessionHeaders(session),
          },
          signal: controller.signal,
        });
      } catch (error) {
        throw failure(runtimeSafety.helloLynkNetworkErrorCode(error, "host_transport_request_failed"), { cause: error });
      }
      // Also release a late response from a fetch implementation that ignores abort.
      if (controller.signal.aborted) {
        await response.body?.cancel().catch(() => {});
        throw controller.signal.reason;
      }
      if (response.status !== 200
        || !String(response.headers.get("content-type") || "").startsWith("text/event-stream")
        || !response.body) {
        const error = await responseFailure(response, controller);
        if (controller.signal.aborted) throw controller.signal.reason;
        invalidateRejectedSession(error, hostSessionHeaders(session));
        throw error;
      }
    })();
    try {
      await Promise.race([handshake, handshakeDeadline]);
    } catch (error) {
      controller.abort();
      cleanup();
      throw error;
    } finally {
      clearTimeout(handshakeTimer);
      controller.signal.removeEventListener("abort", rejectAbortedHandshake);
    }
    if (controller.signal.aborted) throw controller.signal.reason;
    let rotationRequested = false;
    rotationTimer = setTimeout(() => {
      rotationRequested = true;
      // Persisting a received contact request may still need to ACK this SSE session.
      if (latestSessionId === session.sessionId) rotateBeforeNextStreamSessionId = session.sessionId;
      controller.abort();
    }, Math.max(1, Date.parse(session.expiresAt) - Date.now() - rotationLeadMs));
    rotationTimer.unref?.();
    const events = (async function* rotateSessionEvents() {
      try {
        const bytes = readSseBytes(response.body, controller, streamIdleTimeoutMs);
        for await (const item of routeSseEvents(parseSse(bytes), registeredEndpoints, owner)) {
          if (item.event === "host_transport_closed" && [
            "host_transport_session_expired", "host_transport_session_revoked",
            "host_transport_credential_inactive", "host_transport_credential_revoked", "host_transport_host_revoked",
          ].includes(item.data?.reason)) invalidateSession(session.sessionId);
          yield item;
        }
        if (rotationRequested) throw failure("host_transport_session_rotation");
      } catch (error) {
        if (rotationRequested) throw failure("host_transport_session_rotation", { cause: error });
        throw error;
      } finally {
        cleanup();
        controller.abort();
      }
    })();
    return Object.freeze({
      response,
      events,
      principalId: session.principalId,
      hostId: session.hostId,
      async close() {
        cleanup();
        controller.abort();
        await response.body.cancel().catch(() => {});
      },
    });
  }

  async function acknowledge(input = {}) {
    requireExactFields(input, ["event", "kind", "persisted"], "host_transport_ack_input_invalid");
    const event = requireRecord(input.event, "host_transport_ack_event_invalid");
    const persisted = requireRecord(input.persisted, "host_transport_ack_persistence_invalid");
    const kind = String(input.kind || "");
    if (!new Set(["message", "contact_request"]).has(kind)) {
      throw failure("host_transport_ack_kind_invalid");
    }
    const delegateId = safeId(event.recipientDelegateId, "host_transport_ack_delegate_invalid");
    if (typeof runtimeHeadersForDelegate !== "function") {
      throw failure("host_transport_runtime_resolver_required");
    }
    const session = await activeSession();
    const runtimeHeaders = await requiredRuntimeHeaders(
      await runtimeHeadersForDelegate(delegateId, { kind, event }),
    );
    const request = kind === "message"
      ? messageAcknowledgement(event, persisted)
      : contactAcknowledgement(event, persisted);
    return jsonRequest(request.pathname, {
      method: "POST",
      headers: { ...hostSessionHeaders(session), ...runtimeHeaders },
      body: request.body,
    });
  }

  async function searchDirectory(input = {}) {
    const session = await activeSession();
    return jsonRequest("/api/v2/host-transport/directory/search", {
      method: "POST",
      headers: hostSessionHeaders(session),
      body: input,
    });
  }

  async function reserveContactRequest(input = {}) {
    const { runtimeHeaders: suppliedRuntimeHeaders, ...body } = input;
    const session = await activeSession();
    const runtimeHeaders = await requiredRuntimeHeaders(suppliedRuntimeHeaders);
    return jsonRequest("/api/v2/host-transport/contact-request-attempts", {
      method: "POST",
      headers: { ...hostSessionHeaders(session), ...runtimeHeaders },
      body,
    });
  }

  async function relayContactRequest(input = {}) {
    const attemptId = safeId(input.attemptId, "host_transport_contact_attempt_invalid");
    const { runtimeHeaders: suppliedRuntimeHeaders, attemptId: _attemptId, ...body } = input;
    const session = await activeSession();
    const runtimeHeaders = await requiredRuntimeHeaders(suppliedRuntimeHeaders);
    return jsonRequest(
      `/api/v2/host-transport/contact-request-attempts/${encodeURIComponent(attemptId)}/relay`,
      {
        method: "POST",
        headers: { ...hostSessionHeaders(session), ...runtimeHeaders },
        body,
      },
    );
  }

  async function listContactRequests(input = {}) {
    if (!input || typeof input !== "object" || Array.isArray(input)
      || Object.keys(input).some((key) => key !== "cursor")) {
      throw failure("host_transport_contact_list_invalid");
    }
    const session = await activeSession();
    const cursor = optionalCursor(input.cursor, "host_transport_contact_cursor_invalid");
    const target = cursor == null
      ? "/api/v2/host-transport/contact-requests"
      : `/api/v2/host-transport/contact-requests?cursor=${encodeURIComponent(cursor)}`;
    return jsonRequest(target, {
      method: "GET",
      headers: hostSessionHeaders(session),
    });
  }

  async function decideContactRequest(input = {}) {
    const requestId = safeId(input.requestId, "host_transport_contact_request_invalid");
    const action = String(input.action || "");
    if (!new Set(["accept", "reject", "block"]).has(action)) {
      throw failure("host_transport_contact_decision_invalid");
    }
    const session = await activeSession();
    return jsonRequest(
      `/api/v2/host-transport/contact-requests/${encodeURIComponent(requestId)}/${action}`,
      { method: "POST", headers: hostSessionHeaders(session), body: {} },
    );
  }

  async function getContactRequestDecisionState(input = {}) {
    if (!input || typeof input !== "object" || Array.isArray(input)
      || Object.keys(input).length !== 1 || !Object.hasOwn(input, "requestId")) {
      throw failure("host_transport_contact_request_invalid");
    }
    const requestId = safeId(input.requestId, "host_transport_contact_request_invalid");
    const session = await activeSession();
    return jsonRequest(
      `/api/v2/host-transport/contact-requests/${encodeURIComponent(requestId)}/decision-state`,
      { method: "GET", headers: hostSessionHeaders(session), body: undefined },
    );
  }

  async function cancelContactRequest(input = {}) {
    requireExactFields(input, ["requestId"], "host_transport_contact_request_invalid");
    const requestId = safeId(input.requestId, "host_transport_contact_request_invalid");
    const session = await activeSession();
    return jsonRequest(
      `/api/v2/host-transport/contact-requests/${encodeURIComponent(requestId)}/cancel`,
      { method: "POST", headers: hostSessionHeaders(session), body: {} },
    );
  }

  async function listRelationships() {
    const session = await activeSession();
    return jsonRequest("/api/v2/host-transport/relationships", {
      method: "GET",
      headers: hostSessionHeaders(session),
    });
  }

  async function endRelationship(input = {}) {
    requireExactFields(input, ["relationshipId"], "host_transport_relationship_invalid");
    const relationshipId = safeId(input.relationshipId, "host_transport_relationship_invalid");
    const session = await activeSession();
    return jsonRequest(
      `/api/v2/host-transport/relationships/${encodeURIComponent(relationshipId)}/end`,
      { method: "POST", headers: hostSessionHeaders(session), body: {} },
    );
  }

  async function listBlocks() {
    const session = await activeSession();
    return jsonRequest("/api/v2/host-transport/blocks", {
      method: "GET",
      headers: hostSessionHeaders(session),
    });
  }

  async function removeBlock(input = {}) {
    requireExactFields(input, ["blockId"], "host_transport_block_invalid");
    const blockId = safeId(input.blockId, "host_transport_block_invalid");
    const session = await activeSession();
    return jsonRequest(
      `/api/v2/host-transport/blocks/${encodeURIComponent(blockId)}/remove`,
      { method: "POST", headers: hostSessionHeaders(session), body: {} },
    );
  }

  async function activeSession(signal) {
    assertUsable(signal);
    if (issuedSessionPending) return waitForSession(issuedSessionPending, signal);
    if (cachedSession && Date.parse(cachedSession.expiresAt) > Date.now() + DEFAULT_SESSION_ROTATION_LEAD_MS) {
      return cachedSession;
    }
    if (activeSessionPending) return waitForSession(activeSessionPending, signal);
    const generation = sessionGeneration;
    const pending = (async () => {
      let session;
      try {
        session = validateSession(await sessionProvider.get(), owner);
      } catch (error) {
        assertUsable();
        if (generation !== sessionGeneration) return currentSessionOrIssue();
        if (error?.code !== "host_transport_session_invalid"
          && error?.code !== "host_transport_session_expired"
          && error?.code !== "host_transport_session_owner_mismatch") throw error;
        return issueSession();
      }
      assertUsable();
      // An explicit rotation wins over a provider read that started earlier.
      if (generation !== sessionGeneration) return currentSessionOrIssue();
      if (session.sessionId === staleSessionId
        || Date.parse(session.expiresAt) <= Date.now()) return issueSession();
      cachedSession = session;
      latestSessionId = session.sessionId;
      return session;
    })();
    activeSessionPending = pending;
    pending.finally(() => {
      if (activeSessionPending === pending) activeSessionPending = null;
    }).catch(() => {});
    return waitForSession(pending, signal);
  }

  function currentSessionOrIssue() {
    return issuedSessionPending || cachedSession || issueSession();
  }

  async function waitForSession(pending, signal) {
    // Session lookup/issuance belongs to the transport, not its first caller.
    // Canceling one waiter cannot cancel another admitted receive unit's ACK.
    const waitSignal = signal ? AbortSignal.any([signal, lifetime.signal]) : lifetime.signal;
    waitSignal.throwIfAborted();
    let rejectAborted;
    try {
      return await Promise.race([pending, new Promise((_, reject) => {
        rejectAborted = () => reject(waitSignal.reason);
        waitSignal.addEventListener("abort", rejectAborted, { once: true });
      })]);
    } finally {
      waitSignal.removeEventListener("abort", rejectAborted);
    }
  }

  function invalidateRejectedSession(error, headers) {
    if (error.httpStatus !== 401 && error.httpStatus !== 403) return;
    const sessionId = headers?.["x-hellolynk-host-transport-session-id"];
    if (!sessionId || latestSessionId !== sessionId) return;
    cachedSession = null;
    // A relationship/runtime denial does not revoke the transport session used by the live SSE receiver.
    if (/^host_transport_(session|credential)_/.test(error.code)
      || error.code === "host_transport_http_error") staleSessionId = sessionId;
  }

  function invalidateSession(sessionId) {
    // A delayed rejection of an old request must not discard a newer session.
    if (!sessionId || latestSessionId !== sessionId) return;
    cachedSession = null;
    staleSessionId = sessionId;
  }

  async function listAgentInstances(input = {}) {
    requireExactFields(input, ["hellolynkId"], "host_transport_instance_directory_invalid");
    const hellolynkId = input.hellolynkId;
    if (typeof hellolynkId !== "string" || !/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(hellolynkId)) {
      throw failure("host_transport_instance_directory_invalid");
    }
    const session = await activeSession();
    const result = await jsonRequest("/api/v2/host-transport/instances/list", {
      method: "POST", headers: { ...hostSessionHeaders(session),
        "X-HelloLynk-Client-Types": "codex,openclaw,trae-work,workbuddy,cursor,dsh,claude-code",
      }, body: { hellolynkId },
    });
    if (result?.ok !== true || result.hellolynkId !== hellolynkId
      || !Array.isArray(result.instances) || result.instances.length > 512) {
      throw failure("host_transport_instance_directory_response_invalid");
    }
    if (typeof result.principalId !== "string") throw failure("host_transport_instance_directory_response_invalid");
    const principalId = safeId(result.principalId, "host_transport_instance_directory_response_invalid");
    const ids = new Set();
    const instances = result.instances.map((item) => {
      if (!item || typeof item.delegateId !== "string") throw failure("host_transport_instance_directory_response_invalid");
      const delegateId = safeId(item?.delegateId, "host_transport_instance_directory_response_invalid");
      if (ids.has(delegateId) || item.status !== "active"
        || !["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh", "claude-code"].includes(item.clientType)
        || typeof item.displayName !== "string" || !item.displayName.trim() || item.displayName.length > 80) {
        throw failure("host_transport_instance_directory_response_invalid");
      }
      ids.add(delegateId);
      // createdAt is display-only. An older relay omits it, and a malformed
      // value is dropped instead of hiding the whole directory.
      const createdAtMs = typeof item.createdAt === "string" && item.createdAt.length <= 64 ? Date.parse(item.createdAt) : NaN;
      return { delegateId, displayName: item.displayName, clientType: item.clientType, status: "active",
        ...(Number.isFinite(createdAtMs) ? { createdAt: new Date(createdAtMs).toISOString() } : {}) };
    });
    return { principalId, hellolynkId, instances };
  }

  async function jsonRequest(pathname, input) {
    assertUsable(input.signal);
    const requestSignal = input.signal ? AbortSignal.any([input.signal, lifetime.signal]) : lifetime.signal;
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort(requestSignal.reason);
    requestSignal.addEventListener("abort", abortFromCaller, { once: true });
    if (requestSignal.aborted) abortFromCaller();
    let timedOut = false;
    let timeoutHandle;
    const deadline = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(failure("host_transport_request_timeout"));
      }, jsonRequestTimeoutMs);
    });
    const request = (async () => {
      let response;
      try {
        controller.signal.throwIfAborted();
        response = await fetchImpl(`${baseUrl}${pathname}`, {
          method: input.method,
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            ...input.headers,
          },
          body: JSON.stringify(input.body),
          signal: controller.signal,
        });
      } catch (error) {
        if (timedOut) throw failure("host_transport_request_timeout", { cause: error });
        throw failure(runtimeSafety.helloLynkNetworkErrorCode(error, "host_transport_request_failed"), { cause: error });
      }
      assertUsable(input.signal);
      if (!response.ok) {
        const error = await responseFailure(response);
        invalidateRejectedSession(error, input.headers);
        throw error;
      }
      let result;
      try {
        result = await response.json();
      } catch (error) {
        if (timedOut) throw failure("host_transport_request_timeout", { cause: error });
        throw failure("host_transport_response_invalid", { cause: error });
      }
      assertUsable(input.signal);
      return result;
    })();
    try {
      return await Promise.race([request, deadline]);
    } finally {
      clearTimeout(timeoutHandle);
      requestSignal.removeEventListener("abort", abortFromCaller);
    }
  }

  function assertUsable(signal) {
    lifetime.signal.throwIfAborted();
    signal?.throwIfAborted();
  }

  return Object.freeze({
    async close() {
      lifetime.abort(failure("host_transport_closed"));
      cachedSession = null;
      registeredEndpoints.clear();
      // Cloud requests may ignore abort. Only the already admitted local write
      // must settle before this Host gives up its installation lock.
      await sessionPersistencePending?.catch(() => {});
    },
    issueSession,
    registerEndpoint,
    openEventStream,
    acknowledge,
    searchDirectory,
    reserveContactRequest,
    relayContactRequest,
    listContactRequests,
    decideContactRequest,
    getContactRequestDecisionState,
    cancelContactRequest,
    listRelationships,
    listAgentInstances,
    endRelationship,
    listBlocks,
    removeBlock,
  });
}

async function* routeSseEvents(events, endpoints, owner) {
  for await (const item of events) {
    if (item?.event === "host_transport_ready") {
      yield Object.freeze({ ...item, event: "ready" });
      continue;
    }
    if (!item || !["message", "contact_request"].includes(item.event)) {
      yield item;
      continue;
    }
    const event = requireRecord(item.data, "host_transport_event_invalid");
    const endpoint = endpoints.get(endpointRouteKey(event.recipientDeviceId, event.recipientIdentityKeyId));
    if (!endpoint) throw failure("host_transport_event_endpoint_unknown");
    if (item.event === "message") {
      if (event.recipientDelegateId !== endpoint.delegateId || event.recipientHostId !== owner.hostId) {
        throw failure("host_transport_event_endpoint_mismatch");
      }
      yield item;
      continue;
    }
    if (Object.hasOwn(event, "recipientDelegateId") || Object.hasOwn(event, "recipientHostId")) {
      throw failure("host_transport_contact_route_ambiguous");
    }
    yield Object.freeze({
      event: item.event,
      data: Object.freeze({
        ...event,
        recipientDelegateId: endpoint.delegateId,
        recipientHostId: owner.hostId,
      }),
    });
  }
}

function validateEndpointResult(value, owner) {
  requireExactFields(value, ["ok", "endpoint"], "host_transport_endpoint_response_invalid");
  if (value.ok !== true) throw failure("host_transport_endpoint_response_invalid");
  requireExactFields(value.endpoint, [
    "endpointId", "principalId", "hostId", "delegateId", "delegateAuthorizationVersion",
    "deviceId", "identityKeyId",
  ], "host_transport_endpoint_response_invalid");
  const endpoint = Object.freeze({
    endpointId: safeId(value.endpoint.endpointId, "host_transport_endpoint_response_invalid"),
    principalId: safeId(value.endpoint.principalId, "host_transport_endpoint_response_invalid"),
    hostId: safeId(value.endpoint.hostId, "host_transport_endpoint_response_invalid"),
    delegateId: safeId(value.endpoint.delegateId, "host_transport_endpoint_response_invalid"),
    delegateAuthorizationVersion: positiveInteger(
      value.endpoint.delegateAuthorizationVersion,
      "host_transport_endpoint_response_invalid",
    ),
    deviceId: safeId(value.endpoint.deviceId, "host_transport_endpoint_response_invalid"),
    identityKeyId: safeId(value.endpoint.identityKeyId, "host_transport_endpoint_response_invalid"),
  });
  if (endpoint.principalId !== owner.principalId || endpoint.hostId !== owner.hostId) {
    throw failure("host_transport_endpoint_response_mismatch");
  }
  return endpoint;
}

function endpointRouteKey(deviceId, identityKeyId) {
  return `${safeId(deviceId, "host_transport_event_endpoint_invalid")}\0${safeId(identityKeyId, "host_transport_event_endpoint_invalid")}`;
}

function messageAcknowledgement(event, persisted) {
  rejectPersistedRouteFields(persisted);
  if (Object.hasOwn(persisted, "replyTargetDeleted") && (persisted.replyTargetDeleted !== true
    || !event.e2eeEnvelope?.protected?.replyToClientMessageId)) throw failure("host_transport_ack_persistence_invalid");
  const eventE2eeVersion = Number(event.e2eeVersion ?? event.schemaVersion);
  if (eventE2eeVersion !== 2) throw failure("host_transport_ack_event_invalid");
  const routeKind = oneOf(event.routeKind, ["principal_inbox", "owned_delegate", "instance_direct"], "host_transport_ack_event_invalid");
  const recipientRouteVersion = event.recipientRouteVersion;
  if (!Number.isSafeInteger(recipientRouteVersion)
    || (routeKind === "principal_inbox" ? recipientRouteVersion < 1 : recipientRouteVersion !== 0)) {
    throw failure("host_transport_ack_event_invalid");
  }
  return Object.freeze({
    pathname: "/api/v2/relay/acks",
    body: {
      deliveryAttemptId: safeId(event.deliveryAttemptId, "host_transport_ack_event_invalid"),
      eventId: safeId(event.eventId, "host_transport_ack_event_invalid"),
      clientMessageId: safeId(event.clientMessageId, "host_transport_ack_event_invalid"),
      connectionId: safeId(event.targetConnectionId, "host_transport_ack_event_invalid"),
      state: persisted.replyTargetDeleted === true ? "reply_target_deleted" : "persisted_local",
      envelopeDigest: safeDigest(event.envelopeDigest, "host_transport_ack_event_invalid"),
      e2eeVersion: eventE2eeVersion,
      routeKind,
      recipientDelegateId: safeId(event.recipientDelegateId, "host_transport_ack_event_invalid"),
      recipientDelegateAuthorizationVersion: positiveInteger(
        event.recipientDelegateAuthorizationVersion,
        "host_transport_ack_event_invalid",
      ),
      recipientHostId: safeId(event.recipientHostId, "host_transport_ack_event_invalid"),
      recipientRouteVersion,
      recipientDeviceId: safeId(event.recipientDeviceId, "host_transport_ack_event_invalid"),
      recipientIdentityKeyId: safeId(event.recipientIdentityKeyId, "host_transport_ack_event_invalid"),
      recipientPreKeyId: safeId(event.recipientPreKeyId, "host_transport_ack_event_invalid"),
    },
  });
}

function contactAcknowledgement(event, persisted) {
  rejectPersistedRouteFields(persisted);
  return Object.freeze({
    pathname: "/api/v2/contact-request-acks",
    body: {
      attemptId: safeId(event.attemptId, "host_transport_ack_event_invalid"),
      eventId: safeId(event.eventId, "host_transport_ack_event_invalid"),
      clientRequestId: safeId(event.clientRequestId, "host_transport_ack_event_invalid"),
      connectionId: safeId(event.targetConnectionId, "host_transport_ack_event_invalid"),
      recipientEndpointId: safeId(event.recipientDeviceId, "host_transport_ack_event_invalid"),
      envelopeDigest: safeDigest(event.envelopeDigest, "host_transport_ack_event_invalid"),
      claimId: safeId(event.claimId, "host_transport_ack_event_invalid"),
      state: "persisted_local",
      localRecordDigest: safeDigest(persisted.localRecordDigest, "host_transport_ack_persistence_invalid"),
      ackProofDigest: safeDigest(persisted.ackProofDigest, "host_transport_ack_persistence_invalid"),
    },
  });
}

function rejectPersistedRouteFields(value) {
  const forbidden = [
    "deliveryAttemptId", "attemptId", "eventId", "clientMessageId", "clientRequestId",
    "connectionId", "targetConnectionId", "envelopeDigest", "e2eeVersion", "routeKind",
    "recipientDelegateId", "recipientDelegateAuthorizationVersion", "recipientHostId",
    "recipientRouteVersion", "recipientDeviceId", "recipientEndpointId", "recipientIdentityKeyId",
    "recipientPreKeyId", "claimId", "state",
  ];
  if (forbidden.some((field) => Object.hasOwn(value, field))) {
    throw failure("host_transport_ack_persistence_route_forbidden");
  }
}

async function requiredRuntimeHeaders(provider) {
  const headers = typeof provider === "function" ? await provider() : provider;
  const sessionId = String(headers?.["x-hellolynk-runtime-session-id"] || "");
  const sessionSecret = String(headers?.["x-hellolynk-runtime-session-secret"] || "");
  if (!sessionId || !sessionSecret) throw failure("host_transport_runtime_session_required");
  return {
    "x-hellolynk-runtime-session-id": sessionId,
    "x-hellolynk-runtime-session-secret": sessionSecret,
  };
}

function hostSessionHeaders(session) {
  return {
    "x-hellolynk-host-transport-session-id": session.sessionId,
    "x-hellolynk-host-transport-session-secret": session.sessionSecret,
  };
}

async function responseFailure(response, streamController = null) {
  let code = "host_transport_http_error";
  try {
    let body;
    if (streamController && response.body) {
      const decoder = new TextDecoder();
      let text = "";
      let size = 0;
      // Keep an error response under the same cancellable handshake as its headers.
      for await (const chunk of readSseBytes(response.body, streamController, DEFAULT_STREAM_IDLE_TIMEOUT_MS)) {
        size += chunk.byteLength;
        if (size > MAX_SSE_BUFFER_BYTES) throw failure("host_transport_response_invalid");
        text += decoder.decode(chunk, { stream: true });
      }
      body = JSON.parse(text + decoder.decode());
    } else body = await response.json();
    if (/^[a-z][a-z0-9_]{0,127}$/.test(String(body?.error || ""))) code = body.error;
  } catch {}
  return failure(code, { httpStatus: response.status });
}

async function* readSseBytes(body, controller, idleTimeoutMs) {
  const reader = body.getReader();
  const signal = controller.signal;
  const cancelRead = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancelRead, { once: true });
  let idleTimer;
  try {
    while (true) {
      if (signal.aborted) throw signal.reason;
      // Count comments and partial frames as activity. Time only a pending
      // network read, not the caller's local persist/ACK processing of an event.
      idleTimer = setTimeout(() => {
        controller.abort(failure("host_transport_stream_idle_timeout"));
      }, idleTimeoutMs);
      let next;
      try {
        do {
          next = await reader.read();
          if (signal.aborted) throw signal.reason;
        } while (!next.done && !next.value?.byteLength);
      } finally {
        clearTimeout(idleTimer);
      }
      if (next.done) return;
      yield next.value;
    }
  } finally {
    clearTimeout(idleTimer);
    signal.removeEventListener("abort", cancelRead);
    cancelRead();
    reader.releaseLock();
  }
}

async function* parseSse(body) {
  const decoder = new TextDecoder();
  let buffered = "";
  for await (const chunk of body) {
    buffered += decoder.decode(chunk, { stream: true }).replace(/\r\n/g, "\n");
    if (new TextEncoder().encode(buffered).byteLength > MAX_SSE_BUFFER_BYTES) {
      throw failure("host_transport_sse_too_large");
    }
    while (buffered.includes("\n\n")) {
      const index = buffered.indexOf("\n\n");
      const block = buffered.slice(0, index);
      buffered = buffered.slice(index + 2);
      const event = parseSseBlock(block);
      if (event) yield event;
    }
  }
  buffered += decoder.decode();
  const event = parseSseBlock(buffered);
  if (event) yield event;
}

function parseSseBlock(block) {
  let event = "message";
  const data = [];
  for (const line of String(block || "").split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (data.length === 0) return null;
  try {
    return Object.freeze({ event, data: JSON.parse(data.join("\n")) });
  } catch (error) {
    throw failure("host_transport_sse_invalid", { cause: error });
  }
}

function safeId(value, code) {
  const normalized = String(value || "");
  if (!SAFE_ID.test(normalized)) throw failure(code);
  return normalized;
}

function safeDigest(value, code) {
  const normalized = String(value || "");
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw failure(code);
  return normalized;
}

function optionalCursor(value, code) {
  if (value == null) return null;
  const cursor = String(value);
  if (!/^[A-Za-z0-9_-]{20,512}$/.test(cursor)) throw failure(code);
  return cursor;
}

function positiveInteger(value, code) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) throw failure(code);
  return normalized;
}

function oneOf(value, allowed, code) {
  if (!allowed.includes(value)) throw failure(code);
  return value;
}

function requireRecord(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure(code);
  return value;
}

function requireExactFields(value, fields, code) {
  requireRecord(value, code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw failure(code);
  }
}

function validateSession(value, owner) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw failure("host_transport_session_invalid");
  }
  const actual = Object.keys(value).sort();
  const expected = ["expiresAt", "hostId", "principalId", "sessionId", "sessionSecret"].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw failure("host_transport_session_invalid");
  }
  const session = Object.freeze({
    sessionId: safeId(value.sessionId, "host_transport_session_invalid"),
    sessionSecret: String(value.sessionSecret || ""),
    principalId: safeId(value.principalId, "host_transport_session_invalid"),
    hostId: safeId(value.hostId, "host_transport_session_invalid"),
    expiresAt: String(value.expiresAt || ""),
  });
  if (!/^hosttransportsession_[A-Za-z0-9_-]{16,}$/.test(session.sessionId)
    || !/^hostsession_[a-f0-9]{48}$/.test(session.sessionSecret)
    || !Number.isFinite(Date.parse(session.expiresAt))) {
    throw failure("host_transport_session_invalid");
  }
  if (session.principalId !== owner.principalId || session.hostId !== owner.hostId) {
    throw failure("host_transport_session_owner_mismatch");
  }
  return session;
}

function failure(code, options = {}) {
  return new HelloLynkHostTransportClientError(code, options);
}
