import {
  HELLOLYNK_WORKBENCH_COMMAND_TYPES,
  HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
  validateWorkbenchSnapshot,
  workbenchCommandWindowFromKey,
} from "./contract.mjs";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/;
const REAL_TRANSPORTS = new Set(["loopback-http", "mcp-app-rpc", "cursor-webview-rpc"]);
const REVISION_OPTIONAL_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.openAccount,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus,
]);
// These commands name an exact request/relationship/block (or a Host-bound
// search target). Their controller/cloud endpoint validates that target and
// owns the durable outcome; rereading unrelated lists adds no authority.
const REMOTE_RELATIONSHIP_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock,
]);
// These Host-authorized reads return authority-bound results without changing
// local state. They do not need the unrelated snapshot a mutation refreshes.
// Instance rename is a local compare-and-set: the Host validates the observed
// identity and label inside the store lock, without consulting cloud lists.
const SNAPSHOT_REFRESH_EXEMPT_COMMANDS = new Set([
  ...REMOTE_RELATIONSHIP_COMMANDS,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance,
]);
const AUTHORITY_BOUND_RESULT_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock,
]);
const OFFLINE_LOCAL_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads,
]);
// These actions carry their own local target/boundary. The Host checks message
// IDs, receipt watermarks, conversation ownership or the name CAS under its
// store lock. Unrelated inbox/connection revisions do not change that intent.
// Permissions and broad destructive confirmations still use snapshot revision.
const TARGET_SCOPED_LOCAL_COMMANDS = new Set([
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact,
  HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance,
]);
const CLAIMED_HOST_GENERATIONS = new Set();

export class HelloLynkWorkbenchServiceError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkWorkbenchServiceError";
    this.code = code;
  }
}

export function createHelloLynkWorkbenchService(options = {}) {
  const hostGeneration = opaqueId(options.hostGeneration, "workbench_service_host_generation_invalid");
  const writerRegistrationKey = opaqueId(
    options.writerRegistrationKey ?? hostGeneration,
    "workbench_service_writer_registration_key_invalid",
  );
  let currentRevision = opaqueRevision(options.revision, "workbench_service_revision_invalid");
  let currentChangeCursor = opaqueRevision(options.changeCursor, "workbench_service_change_cursor_invalid");
  const readSnapshotFromHost = requiredFunction(options.readSnapshot, "workbench_service_read_snapshot_required");
  const executeCommandInHost = requiredFunction(options.executeCommand, "workbench_service_execute_command_required");
  const runCommandOperation = options.runCommandOperation == null
    ? (_command, operation) => operation()
    : requiredFunction(options.runCommandOperation, "workbench_service_command_operation_invalid");
  const serviceMode = options.explicitSynthetic === true ? "synthetic-preview" : "neutral-host";
  const refreshBeforeCommand = options.refreshBeforeCommand === true;
  const idempotencyCapacity = positiveInteger(
    options.idempotencyCapacity ?? 4_096,
    "workbench_service_idempotency_capacity_invalid",
  );
  if (CLAIMED_HOST_GENERATIONS.has(writerRegistrationKey)) {
    fail("workbench_service_writer_already_registered");
  }
  CLAIMED_HOST_GENERATIONS.add(writerRegistrationKey);

  let operationTail = Promise.resolve();
  let revisionObservation = 0;
  const commandInstanceId = globalThis.crypto.randomUUID().replaceAll("-", "");
  let commandEpoch = 1;
  const currentCommandWindow = () => `wb5.${commandInstanceId}.${commandEpoch}`;
  let snapshotRequiredAfterUnknown = false;
  const idempotencyJournal = new Map();

  function runExclusive(operation) {
    const running = operationTail.then(operation, operation);
    operationTail = running.then(() => undefined, () => undefined);
    return running;
  }

  async function readSnapshot(input = {}, context = {}) {
    const source = validateSource(context.source, serviceMode);
    const authority = context.authority ?? null;
    return runExclusive(async () => {
      const rawSnapshot = await readSnapshotFromHost(input, Object.freeze({
        hostGeneration,
        revision: currentRevision,
        changeCursor: currentChangeCursor,
        source,
        authority,
      }));
      const snapshot = validateWorkbenchSnapshot(rawSnapshot);
      if (snapshot.hostGeneration !== hostGeneration) {
        fail("workbench_service_host_generation_mismatch");
      }
      assertSnapshotSource(snapshot.source, source);
      currentRevision = snapshot.revision;
      currentChangeCursor = snapshot.changeCursor;
      revisionObservation += 1;
      snapshotRequiredAfterUnknown = false;
      // This serial read is the retirement barrier. Admissions made after this
      // read was queued still reserve slots, so do not retire their window.
      if (idempotencyJournal.size >= idempotencyCapacity
        && [...idempotencyJournal.values()].every((entry) => entry.settled)) {
        if (!Number.isSafeInteger(commandEpoch + 1)) fail("workbench_command_window_exhausted");
        commandEpoch += 1;
        idempotencyJournal.clear();
      }
      return validateWorkbenchSnapshot({ ...snapshot, commandWindow: currentCommandWindow() });
    });
  }

  function executeCommand(value, context = {}) {
    const command = validateWorkbenchCommand(value);
    const source = validateSource(context.source, serviceMode);
    const authority = context.authority ?? null;
    const fingerprint = commandFingerprint(command);
    const authorityKey = commandAuthorityKey(command.command, authority);
    if (workbenchCommandWindowFromKey(command.idempotencyKey) !== currentCommandWindow()) {
      // A retired/foreign service may have executed this intent. We know only
      // that it cannot execute here, not its original business outcome.
      return Promise.resolve(failureResult(command, {
        code: "host_app_command_window_expired", currentRevision,
        outcome: "unknown",
      }));
    }
    if (AUTHORITY_BOUND_RESULT_COMMANDS.has(command.command) && authorityKey == null) {
      return runExclusive(() => failureResult(command, {
        code: "host_app_authorization_required",
        currentRevision,
      }));
    }
    const existing = idempotencyJournal.get(command.idempotencyKey);

    if (existing) {
      if (existing.fingerprint !== fingerprint || existing.authorityKey !== authorityKey) {
        return runExclusive(() => failureResult(command, {
          code: "host_app_idempotency_conflict",
          currentRevision,
        }));
      }
      return existing.promise.then((result) => rebindRequestId(result, command.requestId, command.command));
    }

    if (idempotencyJournal.size >= idempotencyCapacity) {
      return Promise.resolve(failureResult(command, {
        code: "host_app_command_window_full",
        currentRevision,
      }));
    }

    const entry = { fingerprint, authorityKey, promise: null, settled: false };
    entry.promise = runExclusive(async () => {
      try { return await runCommandOperation(command, () => executeOnce(command, source, authority)); }
      catch { return unknownOutcomeResult(command); }
    }).then((result) => result.deferredCompletion ?? result)
      .finally(() => { entry.settled = true; });
    idempotencyJournal.set(command.idempotencyKey, entry);
    return entry.promise;
  }

  async function executeOnce(command, source, authority) {
    if (snapshotRequiredAfterUnknown
      && command.command !== HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
      return failureResult(command, {
        code: "host_app_snapshot_required",
        currentRevision: null,
        resultRevision: null,
        resultChangeCursor: null,
      });
    }
    if (refreshBeforeCommand && !SNAPSHOT_REFRESH_EXEMPT_COMMANDS.has(command.command)
      && !OFFLINE_LOCAL_COMMANDS.has(command.command)) {
      let snapshot;
      try {
        snapshot = validateWorkbenchSnapshot(await readSnapshotFromHost({}, Object.freeze({
          hostGeneration,
          revision: currentRevision,
          changeCursor: currentChangeCursor,
          source,
          authority,
          beforeCommand: true,
          commandType: command.command,
        })));
        if (snapshot.hostGeneration !== hostGeneration) {
          fail("workbench_service_host_generation_mismatch");
        }
        assertSnapshotSource(snapshot.source, source);
      } catch {
        // No command has reached the Host yet. A failed preflight read cannot
        // make its write outcome unknown or lock unrelated local actions.
        return failureResult(command, { code: "host_app_snapshot_unavailable", currentRevision });
      }
      currentRevision = snapshot.revision;
      currentChangeCursor = snapshot.changeCursor;
      revisionObservation += 1;
      if (snapshot.security.hostStatus === "offline"
        && !OFFLINE_LOCAL_COMMANDS.has(command.command)) {
        return failureResult(command, { code: "host_app_cloud_unavailable", currentRevision });
      }
    }
    if (command.expectedRevision == null && !REVISION_OPTIONAL_COMMANDS.has(command.command)) {
      return failureResult(command, {
        code: "host_app_revision_required",
        currentRevision,
      });
    }
    if (command.expectedRevision != null && command.expectedRevision !== currentRevision
      && !TARGET_SCOPED_LOCAL_COMMANDS.has(command.command)) {
      return failureResult(command, {
        code: "host_app_revision_conflict",
        currentRevision,
      });
    }

    let pendingResult;
    try {
      pendingResult = Promise.resolve(executeCommandInHost(command, Object.freeze({
        hostGeneration,
        revision: currentRevision,
        changeCursor: currentChangeCursor,
        source,
        authority,
      }))).catch(() => null);
    } catch {
      return unknownOutcomeResult(command);
    }

    if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry
      || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply
      || command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal
      || REMOTE_RELATIONSHIP_COMMANDS.has(command.command)) {
      // Admission, the fresh revision check and the journal reservation remain
      // serial. The Host owns the durable retry claim; awaiting transport must
      // not prevent this same page from reading or revoking authorization.
      // Directory search only returns authority-bound targets. Its cloud wait
      // must also leave local reads and actions available.
      // Targeted relationship commands keep their controller's per-record
      // admission and server checks, while local revocation remains usable.
      const admittedObservation = revisionObservation;
      return { deferredCompletion: pendingResult.then((rawResult) => runExclusive(() =>
        finishCommand(command, rawResult, revisionObservation === admittedObservation))) };
    }
    return finishCommand(command, await pendingResult);
  }

  function finishCommand(command, rawResult, updateRevision = true) {
    let result;
    try {
      result = validateWorkbenchCommandResult(rawResult, command.command);
      if (result.requestId !== command.requestId) fail("workbench_service_request_id_mismatch");
      if (result.ok && (result.revision == null || result.changeCursor == null)) {
        fail("workbench_service_success_metadata_missing");
      }
    } catch {
      return unknownOutcomeResult(command);
    }

    // A delayed retry may return a snapshot older than a read or revocation
    // that completed meanwhile. Its outcome remains valid, not its authority
    // to replace the service's newer observed baseline.
    if (updateRevision) {
      if (result.revision != null) currentRevision = result.revision;
      if (result.changeCursor != null) currentChangeCursor = result.changeCursor;
      if (result.revision != null || result.changeCursor != null) revisionObservation += 1;
    }
    if (!result.ok && result.error.outcome === "unknown"
      && command.command !== HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal
      && command.command !== HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
      snapshotRequiredAfterUnknown = true;
    }
    return result;
  }

  function unknownOutcomeResult(command) {
    // Directory search can consume remote quota, but it cannot mutate local
    // contacts/messages or authorize a later write. Keep its exact
    // idempotency record for replay, without blocking a new human search on a
    // full snapshot that may be unrelated to the directory failure.
    if (command.command !== HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal
      && command.command !== HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus) {
      snapshotRequiredAfterUnknown = true;
    }
    return validateWorkbenchCommandResult({
      contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
      schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
      ok: false,
      requestId: command.requestId,
      revision: null,
      changeCursor: null,
      error: {
        code: "workbench_command_outcome_unknown",
        retryable: false,
        outcome: "unknown",
        retryAfterMs: null,
        currentRevision: null,
      },
    });
  }

  function failureResult(command, {
    code,
    currentRevision: failureRevision,
    resultRevision = currentRevision,
    resultChangeCursor = currentChangeCursor,
    outcome = "known-failed",
  }) {
    return validateWorkbenchCommandResult({
      contractId: HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
      schemaVersion: HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
      ok: false,
      requestId: command.requestId,
      revision: resultRevision,
      changeCursor: resultChangeCursor,
      error: {
        code,
        retryable: false,
        outcome,
        retryAfterMs: null,
        currentRevision: failureRevision,
      },
    });
  }

  return Object.freeze({
    hostGeneration,
    readSnapshot,
    executeCommand,
    getState() {
      return Object.freeze({
        hostGeneration,
        commandWindow: currentCommandWindow(),
        revision: currentRevision,
        changeCursor: currentChangeCursor,
        snapshotRequired: snapshotRequiredAfterUnknown,
        idempotencyEntries: idempotencyJournal.size,
      });
    },
  });
}

function commandFingerprint(command) {
  return JSON.stringify({
    contractId: command.contractId,
    schemaVersion: command.schemaVersion,
    command: command.command,
    expectedRevision: command.expectedRevision,
    payload: command.payload,
  });
}

function commandAuthorityKey(commandType, authority) {
  if (!AUTHORITY_BOUND_RESULT_COMMANDS.has(commandType)) return null;
  const fields = ["hostGeneration", "delegateId", "capabilityId", "adapterInstanceId"];
  if (!authority || fields.some((field) => typeof authority[field] !== "string" || !SAFE_ID.test(authority[field]))) {
    return null;
  }
  return fields.map((field) => authority[field]).join("\u001f");
}

function rebindRequestId(result, requestId, expectedCommand) {
  if (result.requestId === requestId) return result;
  return validateWorkbenchCommandResult({ ...result, requestId }, expectedCommand);
}

function validateSource(value, serviceMode) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("workbench_service_source_required");
  }
  const source = Object.freeze({
    mode: value.mode,
    transport: value.transport,
    clientId: opaqueId(value.clientId, "workbench_service_source_invalid"),
    clientLabel: boundedText(value.clientLabel, 80, "workbench_service_source_invalid"),
  });
  const synthetic = source.mode === "synthetic-preview" && source.transport === "synthetic-memory";
  const real = source.mode === "neutral-host" && REAL_TRANSPORTS.has(source.transport);
  if (serviceMode === "synthetic-preview" ? !synthetic : !real) {
    fail(synthetic ? "workbench_service_synthetic_not_enabled" : "workbench_service_source_invalid");
  }
  return source;
}

function assertSnapshotSource(actual, expected) {
  if (actual.mode !== expected.mode
    || actual.transport !== expected.transport
    || actual.clientId !== expected.clientId
    || actual.clientLabel !== expected.clientLabel) {
    fail("workbench_service_snapshot_source_mismatch");
  }
}

function requiredFunction(value, code) {
  if (typeof value !== "function") fail(code);
  return value;
}

function opaqueId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function opaqueRevision(value, code) {
  if (typeof value !== "string" || !SAFE_REVISION.test(value)) fail(code);
  return value;
}

function boundedText(value, maximum, code) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || value.includes("\u0000")) fail(code);
  return value;
}

function positiveInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) fail(code);
  return value;
}

function fail(code) {
  throw new HelloLynkWorkbenchServiceError(code);
}
