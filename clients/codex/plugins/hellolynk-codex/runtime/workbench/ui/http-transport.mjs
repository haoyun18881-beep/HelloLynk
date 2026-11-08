export function createWorkbenchHttpTransport(options = {}) {
  const requestTimeoutMs = positiveTimeout(options.requestTimeoutMs, 10_000);
  // Contact-request admission performs three bounded Host stages: an
  // authoritative metadata preflight, reserve, and (when admitted) relay.
  // Keep explicit test/embedding overrides inherited from requestTimeoutMs.
  const contactRequestTimeoutMs = positiveTimeout(
    options.contactRequestTimeoutMs ?? options.requestTimeoutMs,
    30_000,
  );
  // Page remounts can queue behind an earlier Host read, so snapshots have a
  // separate longer deadline. Ordinary commands keep the base request budget;
  // contact-request admission uses the bounded exception above.
  const snapshotTimeoutMs = positiveTimeout(options.snapshotTimeoutMs ?? options.requestTimeoutMs, 30_000);
  // A first Windows Host launch may take up to 75 seconds before discovery.
  // Once data has loaded, keep the shorter ordinary read deadline.
  const initialSnapshotTimeoutMs = positiveTimeout(options.initialSnapshotTimeoutMs
    ?? options.snapshotTimeoutMs ?? options.requestTimeoutMs, 90_000);
  const initialSourceMode = options?.initialSourceMode == null
    ? null
    : String(options.initialSourceMode);
  if (initialSourceMode !== null && initialSourceMode !== "synthetic-preview") {
    throw new Error("workbench_http_transport_initial_source_mode_invalid");
  }
  let csrf = null;
  let accountRevision = null;
  let snapshotLoaded = false;

  async function request(path, options = {}, { knownFailureOnHttpError = false, timeoutMs = requestTimeoutMs } = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(path, {
        credentials: "same-origin",
        ...options,
        headers: { ...(options.headers || {}), ...(accountRevision ? { "x-hellolynk-account-revision": accountRevision } : {}) },
        signal: controller.signal,
      });
      let body;
      try {
        body = await response.json();
      } catch (error) {
        if (controller.signal.aborted) throw error;
        if (response.ok) throw codeError("workbench_loopback_response_invalid");
        body = {};
      }
      if (!response.ok) {
        const error = codeError(publicCode(body?.error, "workbench_loopback_failed"));
        if (knownFailureOnHttpError || knownPreMutationError(error.code)) error.outcome = "known-failed";
        throw error;
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) throw codeError("workbench_loopback_response_invalid");
      return body;
    } catch (error) {
      if (controller.signal.aborted) {
        const timeoutError = new Error("workbench_loopback_timeout");
        timeoutError.code = "workbench_loopback_timeout";
        if (knownFailureOnHttpError) timeoutError.outcome = "known-failed";
        throw timeoutError;
      }
      if (error instanceof TypeError && !error.code) throw codeError("workbench_loopback_unreachable");
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }
  return Object.freeze({
    mode: "loopback-http",
    ...(initialSourceMode ? { initialSourceMode } : {}),
    actionGrantMode: "host-single-use-v1",
    async readAccountState() {
      const value = await request("/api/v1/account");
      if (accountRevision !== value.revision) snapshotLoaded = false;
      accountRevision = value.revision;
      return value;
    },
    async disconnectAccount(input) {
      csrf = (await request("/api/v1/csrf")).csrf;
      const value = await request("/api/v1/disconnect", { method: "POST",
        headers: { "content-type": "application/json", "x-hellolynk-csrf": csrf }, body: JSON.stringify(input),
      }, { timeoutMs: 60_000 });
      accountRevision = value.revision;
      snapshotLoaded = false;
      return value;
    },
    async readSnapshot(input = {}) {
      const query = new URLSearchParams();
      for (const key of ["threadId", "threadCursor", "messageCursor", "contactRequestCursor", "query", "filter", "historyBefore"]) {
        if (!Object.hasOwn(input, key) || input[key] === "") continue;
        if (input[key] === null) {
          if (key === "contactRequestCursor" || key === "historyBefore") query.set(key, "");
          continue;
        }
        query.set(key, input[key]);
      }
      const suffix = query.size ? `?${query}` : "";
      const revision = accountRevision;
      const body = await request(`/api/v1/snapshot${suffix}`, {}, {
        timeoutMs: snapshotLoaded ? snapshotTimeoutMs : initialSnapshotTimeoutMs,
      });
      if (!body.snapshot || typeof body.snapshot !== "object" || Array.isArray(body.snapshot)) {
        throw codeError("workbench_loopback_response_invalid");
      }
      if (revision === accountRevision) snapshotLoaded = true;
      return body.snapshot;
    },
    async connectAccount(input) {
      csrf = (await request("/api/v1/csrf")).csrf;
      return request("/api/v1/connect", { method: "POST",
        headers: { "content-type": "application/json", "x-hellolynk-csrf": csrf },
        body: JSON.stringify(input),
      }, { timeoutMs: 160_000 });
    },
    async openAccount(url) {
      csrf = (await request("/api/v1/csrf")).csrf;
      return request("/api/v1/open-account", { method: "POST",
        headers: { "content-type": "application/json", "x-hellolynk-csrf": csrf },
        body: JSON.stringify({ url }),
      }, { timeoutMs: 15_000 });
    },
    async executeCommand(command) {
      let prepared = false;
      try {
        if (!csrf) csrf = (await request("/api/v1/csrf", {}, { knownFailureOnHttpError: true })).csrf;
        const headers = {
          "content-type": "application/json",
          "x-hellolynk-csrf": csrf,
        };
        let actionGrant;
        if (command.command !== "message.send-status") {
          const grantResponse = await request("/api/v1/action-grants", {
            method: "POST",
            headers,
            body: JSON.stringify({ command }),
          }, { knownFailureOnHttpError: true });
          actionGrant = privateActionGrant(grantResponse.actionGrant);
        }
        prepared = true;
        return (await request("/api/v1/command", {
          method: "POST",
          headers,
          body: JSON.stringify({ command, ...(actionGrant ? { actionGrant } : {}) }),
        }, {
          timeoutMs: command.command === "contact-request.send"
            ? contactRequestTimeoutMs
            : requestTimeoutMs,
        })).result;
      } catch (error) {
        if (!prepared && error && typeof error === "object" && error.outcome == null) error.outcome = "known-failed";
        throw error;
      }
    },
    subscribe(onChange, onError, onReconnect) {
      const events = new EventSource("/api/v1/events");
      let stopped = false;
      let reconnecting = false;
      let sourceFailed = false;
      let sourceReady = false;
      let keepAliveTimer;
      const recovered = () => {
        if (stopped || sourceFailed || !reconnecting) return;
        reconnecting = false;
        onReconnect?.();
      };
      const failed = (error) => {
        if (stopped) return;
        reconnecting = true;
        onError?.(error);
      };
      const keepSessionAlive = async () => {
        try {
          await request("/api/v1/session", {}, { knownFailureOnHttpError: true });
          if (events.readyState === EventSource.OPEN) recovered();
        } catch (error) {
          failed(error);
          if (error?.code === "workbench_surface_session_invalid") {
            stopped = true;
            events.close();
          }
        } finally {
          if (!stopped) keepAliveTimer = setTimeout(keepSessionAlive, 60_000);
        }
      };
      events.addEventListener("changed", (event) => {
        if (stopped) return;
        try { onChange(JSON.parse(event.data)); }
        catch { failed(codeError("workbench_change_response_invalid")); }
      });
      events.addEventListener("source-error", (event) => {
        if (stopped) return;
        sourceFailed = true;
        let code;
        try { code = JSON.parse(event.data)?.code; } catch { /* Keep a fixed public fallback. */ }
        failed(codeError(publicCode(code, "workbench_change_source_failed")));
      });
      events.addEventListener("source-ready", () => {
        const firstReady = !sourceReady;
        sourceReady = true;
        sourceFailed = false;
        // Initial Host readiness can arrive after the first snapshot timed out,
        // without any preceding SSE error. Deliver that recovery exactly once.
        if (firstReady && !reconnecting && !stopped) onReconnect?.();
        else recovered();
      });
      events.addEventListener("open", recovered);
      events.addEventListener("error", () => failed(codeError("workbench_change_stream_failed")));
      keepAliveTimer = setTimeout(keepSessionAlive, 60_000);
      return () => {
        stopped = true;
        clearTimeout(keepAliveTimer);
        events.close();
      };
    },
  });
}

function publicCode(value, fallback) {
  return typeof value === "string" && (/^(?:workbench|host|neutral_[a-z_]+|hellolynk_[a-z_]+)_[a-z0-9_]{1,120}$/.test(value)
    || ["powershell7_missing", "credential_helper_unavailable", "agent_instance_name_invalid", "agent_instance_name_conflict",
      "device_enrollment_name_invalid", "device_enrollment_hellolynk_id_invalid", "device_enrollment_existing_profile_requires_setup",
      "device_enrollment_intent_conflict", "device_enrollment_authorization_expired", "device_enrollment_owner_conflict",
      "device_enrollment_busy", "device_enrollment_request_timeout", "device_enrollment_request_failed"].includes(value)) ? value : fallback;
}

function codeError(code) {
  return Object.assign(new Error(code), { code });
}

function privateActionGrant(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{31,511}$/.test(value)) {
    const error = new Error("workbench_surface_action_grant_invalid");
    error.code = "workbench_surface_action_grant_invalid";
    error.outcome = "known-failed";
    throw error;
  }
  return value;
}

function knownPreMutationError(code) {
  return /^(?:workbench_surface_(?:action_grant_(?:required|invalid|expired)|command_invalid|commands_not_enabled|csrf_invalid|origin_not_allowed|session_invalid)|host_app_action_grant_(?:required|invalid|expired|mismatch|revoked))$/.test(String(code || ""));
}

function positiveTimeout(value, fallback) {
  if (value == null) return fallback;
  const timeout = Number(value);
  if (!Number.isFinite(timeout) || timeout <= 0) throw new Error("workbench_http_transport_timeout_invalid");
  return timeout;
}
