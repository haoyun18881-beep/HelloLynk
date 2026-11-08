import {
  HELLOLYNK_WORKBENCH_COMMAND_TYPES,
  HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
  validateWorkbenchReadRequest,
  validateWorkbenchSnapshot,
} from "./contract.mjs";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;

export class HelloLynkWorkbenchTransportError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkWorkbenchTransportError";
    this.code = code;
  }
}

export function createLoopbackHttpWorkbenchTransport(options = {}) {
  return createValidatedTransport("loopback-http", options);
}

export function createMcpAppRpcWorkbenchTransport(options = {}) {
  return createValidatedTransport("mcp-app-rpc", options);
}

export function createSyntheticMemoryWorkbenchTransport(options = {}) {
  if (options.explicitSynthetic !== true) fail("workbench_synthetic_transport_requires_explicit_injection");
  return createValidatedTransport("synthetic-memory", options);
}

function createValidatedTransport(transport, options) {
  const readSnapshot = requiredFunction(options.readSnapshot, "workbench_transport_read_snapshot_required");
  const synthetic = transport === "synthetic-memory";
  const executeCommand = synthetic ? null : requiredFunction(options.executeCommand, "workbench_transport_execute_command_required");
  const issueActionGrant = synthetic ? null : requiredFunction(options.issueActionGrant, "workbench_transport_action_grant_issuer_required");
  const source = Object.freeze({
    mode: transport === "synthetic-memory" ? "synthetic-preview" : "neutral-host",
    transport,
    clientId: safeId(options.clientId, "workbench_transport_client_id_invalid"),
    clientLabel: boundedText(options.clientLabel, 80, "workbench_transport_client_label_invalid"),
  });
  let snapshotRequiredAfterUnknown = false;

  return Object.freeze({
    kind: transport,
    source,
    actionGrantMode: synthetic ? "none" : "host-single-use-v1",

    async readSnapshot(input = {}) {
      const request = validateWorkbenchReadRequest(input);
      const snapshot = validateWorkbenchSnapshot(await readSnapshot(request, { source }));
      assertSnapshotSource(snapshot.source, source);
      snapshotRequiredAfterUnknown = false;
      return snapshot;
    },

    async executeCommand(value) {
      const command = validateWorkbenchCommand(value);
      if (synthetic) return knownFailureResult(command.requestId, "workbench_transport_commands_not_enabled");
      const statusRead = command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus;
      if (snapshotRequiredAfterUnknown && !statusRead) {
        return knownFailureResult(command.requestId, "workbench_transport_snapshot_required");
      }
      let actionGrant;
      if (!statusRead) {
        try {
          const issued = await issueActionGrant(command, { source });
          actionGrant = privateActionGrant(issued?.actionGrant);
        } catch (error) {
          return knownFailureResult(command.requestId, publicPreMutationCode(error));
        }
      }
      try {
        const result = validateWorkbenchCommandResult(
          await executeCommand(command, statusRead ? { source } : { source, actionGrant }),
          command.command,
        );
        if (result.requestId !== command.requestId) throw new Error("workbench_transport_request_id_mismatch");
        if (!statusRead && !result.ok && result.error.outcome === "unknown") snapshotRequiredAfterUnknown = true;
        return result;
      } catch (error) {
        if (error?.outcome === "known-failed") {
          return knownFailureResult(command.requestId, publicPreMutationCode(error));
        }
        if (!statusRead) snapshotRequiredAfterUnknown = true;
        return unknownOutcomeResult(command.requestId);
      }
    },
  });
}

function privateActionGrant(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{31,511}$/.test(value)) {
    fail("workbench_transport_action_grant_invalid");
  }
  return value;
}

function publicPreMutationCode(error) {
  const code = String(error?.code || "workbench_transport_action_grant_failed");
  return /^(?:workbench_transport_[a-z0-9_]{1,100}|host_app_action_grant_[a-z0-9_]{1,100})$/.test(code)
    ? code
    : "workbench_transport_action_grant_failed";
}

function knownFailureResult(requestId, code) {
  return validateWorkbenchCommandResult({
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: false,
    requestId,
    revision: null,
    changeCursor: null,
    error: {
      code,
      retryable: false,
      outcome: "known-failed",
      retryAfterMs: null,
      currentRevision: null,
    },
  });
}

function unknownOutcomeResult(requestId) {
  return validateWorkbenchCommandResult({
    contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    ok: false,
    requestId,
    revision: null,
    changeCursor: null,
    error: {
      code: "workbench_transport_outcome_unknown",
      retryable: false,
      outcome: "unknown",
      retryAfterMs: null,
      currentRevision: null,
    },
  });
}

function assertSnapshotSource(actual, expected) {
  if (actual.mode !== expected.mode
    || actual.transport !== expected.transport
    || actual.clientId !== expected.clientId
    || actual.clientLabel !== expected.clientLabel) {
    fail("workbench_transport_snapshot_source_mismatch");
  }
}

function requiredFunction(value, code) {
  if (typeof value !== "function") fail(code);
  return value;
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function boundedText(value, maximum, code) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || value.includes("\u0000")) fail(code);
  return value;
}

function fail(code) {
  throw new HelloLynkWorkbenchTransportError(code);
}
