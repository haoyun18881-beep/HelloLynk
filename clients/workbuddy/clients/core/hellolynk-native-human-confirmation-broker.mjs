import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

export const HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT =
  "hellolynk-native-human-confirmation-v1";
export const HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT =
  "hellolynk-native-human-confirmation-ledger-v1";
export const HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_TTL_MS = 120_000;
export const HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_RATE_LIMIT = 3;
export const HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_RATE_WINDOW_MS = 60_000;

const RESPONSE_KEYS = Object.freeze([
  "actionId", "adapterId", "adapterInstanceId", "clientMessageId", "contract",
  "createdAtMs", "decision", "delegateId", "expiresAtMs", "hostGeneration",
  "hostInstallationId", "principalId", "proof", "recipientHelloLynkId", "textDigest",
]);
const RECIPIENT_INSTANCE_KEYS = Object.freeze(["recipientDelegateId", "recipientInstanceDisplayName"]);
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,198}$/;
const HELLOLYNK_ID_PATTERN = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const HEX_64_PATTERN = /^[a-f0-9]{64}$/;
const MAX_TEXT_BYTES = 20_480;
// JSON can escape each body byte as six ASCII bytes; allow the fixed metadata too.
const MAX_CHILD_INPUT_BYTES = MAX_TEXT_BYTES * 6 + 8_192;
const MAX_CHILD_STDOUT_BYTES = 8_192;
const MAX_CHILD_STDERR_BYTES = 4_096;
const POWERSHELL_SCRIPT = fileURLToPath(new URL(
  "../platform/windows/hellolynk-native-human-confirmation-broker.ps1",
  import.meta.url,
));

/*
 * Threat boundary: this broker separates an ordinary adapter/model request from a
 * human decision made in a Host-owned native child process. It does not defend
 * against arbitrary malicious code already executing as the same Windows user.
 *
 * The injected ledger is deliberately narrow. It may durably retain only the
 * sanitized admission/tombstone records passed here. Message text, challenge,
 * HMAC key and proof never cross that interface.
 */
export function createHelloLynkNativeHumanConfirmationBroker(options = {}) {
  const ledger = assertLedger(options.ledger);
  const launcher = options.launcher || createWindowsNativeHumanConfirmationLauncher();
  const onApproved = typeof options.onApproved === "function"
    ? options.onApproved
    : async () => { throw codeError("human_confirmation_approval_handler_missing", 500); };
  const clock = normalizeClock(options.clock);
  const scheduler = normalizeScheduler(options.scheduler);
  const randomBytes = typeof options.randomBytes === "function" ? options.randomBytes : crypto.randomBytes;
  const approvalDrainTimeoutMs = normalizeDrainTimeout(options.approvalDrainTimeoutMs);
  let hostGeneration = assertIdentifier(
    options.hostGeneration,
    "human_confirmation_host_generation_invalid",
  );
  let closed = false;
  let gate = Promise.resolve();
  const actions = new Map();
  const pendingByPartition = new Map();
  const approvalTasks = new Map();
  const settlementTasks = new Set();
  let closePromise = null;

  function locked(operation) {
    const next = gate.then(operation, operation);
    gate = next.catch(() => {});
    return next;
  }

  async function request(value, context = {}) {
    const normalized = normalizeRequest(value, hostGeneration);
    const nativeAuthority = context.nativeAuthority;
    if (nativeAuthority != null && (typeof nativeAuthority.assertCurrent !== "function"
      || typeof nativeAuthority.revalidate !== "function")) {
      throw codeError("human_confirmation_authority_invalidated", 409);
    }
    assertNativeAuthority(nativeAuthority);
    const nowMs = assertNow(clock.now());
    const partitionHash = hashParts(normalized.capabilityId, normalized.adapterInstanceId);
    const requestHash = hashParts(
      normalized.principalId,
      normalized.delegateId,
      normalized.hostInstallationId,
      normalized.adapterId,
      normalized.adapterInstanceId,
      normalized.hostGeneration,
      normalized.recipientHelloLynkId,
      ...(Object.hasOwn(normalized, "recipientDelegateId") ? [normalized.recipientDelegateId] : []),
      normalized.clientMessageId,
      normalized.textDigest,
    );
    let launchRecord;
    const response = await locked(async () => {
      if (closed) throw codeError("human_confirmation_broker_closed", 503);
      assertNativeAuthority(nativeAuthority);
      if (normalized.hostGeneration !== hostGeneration) {
        throw codeError("human_confirmation_host_generation_mismatch", 409);
      }
      const currentId = pendingByPartition.get(partitionHash);
      const current = currentId ? actions.get(currentId) : null;
      if (current && current.state === "pending" && current.expiresAtMs <= nowMs) {
        await terminalizeLocked(current, "expired", "human_confirmation_timed_out", nowMs);
      }
      assertNativeAuthority(nativeAuthority);
      // Keep the selected stable peer attached to this client message after the
      // dialog settles too. A result whose delivery may be unknown is queried,
      // never turned into a second human approval or a different peer.
      for (const previous of actions.values()) {
        if (previous.partitionHash !== partitionHash || previous.clientMessageId !== normalized.clientMessageId
          || (!Object.hasOwn(previous, "recipientDelegateId") && !Object.hasOwn(normalized, "recipientDelegateId"))) continue;
        if (previous.requestHash !== requestHash) throw codeError("human_confirmation_message_conflict", 409);
        return publicStatus(previous, ["pending", "consuming"].includes(previous.state) ? 202 : 200, true);
      }
      const stillPendingId = pendingByPartition.get(partitionHash);
      const stillPending = stillPendingId ? actions.get(stillPendingId) : null;
      if (stillPending?.state === "pending") {
        if (stillPending.requestHash === requestHash) return publicStatus(stillPending, 202, true);
        throw codeError("human_confirmation_pending_conflict", 409);
      }

      const actionId = `human_${randomToken(randomBytes, 24)}`;
      const createdAtMs = nowMs;
      const expiresAtMs = createdAtMs + HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_TTL_MS;
      const admission = await ledger.admit(Object.freeze({
        contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT,
        actionId,
        partitionHash,
        createdAtMs,
        expiresAtMs,
        rateWindowMs: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_RATE_WINDOW_MS,
        rateLimit: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_RATE_LIMIT,
        restartTombstoneState: "invalidated",
        restartTombstoneCode: "human_confirmation_restart_invalidated",
      }));
      if (!admission || admission.accepted !== true) {
        if (admission?.reason === "rate_limited") {
          throw codeError("human_confirmation_rate_limited", 429, admission.retryAfterMs);
        }
        if (admission?.reason === "partition_pending") {
          throw codeError("human_confirmation_ledger_unavailable", 503);
        }
        throw codeError("human_confirmation_ledger_unavailable", 503);
      }

      // Admission may itself be a durable I/O wait. Never launch a dialog from
      // the stale pre-I/O timestamp after the entire action TTL has elapsed.
      try {
        if (nativeAuthority) await nativeAuthority.revalidate();
        assertNativeAuthority(nativeAuthority);
      } catch (error) {
        try {
          await recordTombstone({ actionId, partitionHash, createdAtMs, expiresAtMs },
            "invalidated", "human_confirmation_authority_invalidated", assertNow(clock.now()));
        } catch {
          throw codeError("human_confirmation_ledger_unavailable", 503);
        }
        throw error;
      }
      const admittedAtMs = assertNow(clock.now());
      if (admittedAtMs >= expiresAtMs) {
        try {
          await ledger.record(Object.freeze({
            contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT,
            actionId,
            partitionHash,
            state: "expired",
            code: "human_confirmation_timed_out",
            createdAtMs,
            expiresAtMs,
            recordedAtMs: admittedAtMs,
          }));
        } catch {
          throw codeError("human_confirmation_ledger_unavailable", 503);
        }
        throw codeError("human_confirmation_timed_out", 408);
      }

      const challenge = randomToken(randomBytes, 32);
      const hmacKey = Buffer.from(randomBytes(32));
      if (hmacKey.length !== 32) throw codeError("human_confirmation_random_source_invalid", 500);
      const action = {
        ...normalized,
        actionId,
        createdAtMs,
        expiresAtMs,
        partitionHash,
        requestHash,
        challenge,
        hmacKey,
        nativeAuthority,
        state: "pending",
        code: null,
        abortController: new AbortController(),
        timer: null,
      };
      actions.set(actionId, action);
      pendingByPartition.set(partitionHash, actionId);
      action.timer = scheduler.setTimeout(() => {
        void expire(actionId);
      }, expiresAtMs - admittedAtMs);
      launchRecord = action;
      return publicStatus(action, 202, false);
    });
    if (launchRecord) startLauncher(launchRecord);
    return response;
  }

  async function status(value) {
    const query = normalizeStatusQuery(value);
    const partitionHash = hashParts(query.capabilityId, query.adapterInstanceId);
    return locked(async () => {
      const action = actions.get(query.actionId);
      if (action) {
        if (action.partitionHash !== partitionHash) throw codeError("human_confirmation_not_found", 404);
        if (action.state === "pending" && action.expiresAtMs <= assertNow(clock.now())) {
          await terminalizeLocked(
            action,
            "expired",
            "human_confirmation_timed_out",
            assertNow(clock.now()),
          );
        }
        return publicStatus(action, 200, false);
      }
      const tombstone = await ledger.lookup(Object.freeze({
        contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT,
        actionId: query.actionId,
        partitionHash,
      }));
      if (!tombstone) throw codeError("human_confirmation_not_found", 404);
      return publicTombstone(tombstone);
    });
  }

  async function detachAdapter(value) {
    const query = normalizePartitionQuery(value);
    const partitionHash = hashParts(query.capabilityId, query.adapterInstanceId);
    return locked(async () => {
      const actionId = pendingByPartition.get(partitionHash);
      const action = actionId ? actions.get(actionId) : null;
      if (!action || action.state !== "pending") return Object.freeze({ detached: true, invalidated: 0 });
      await terminalizeLocked(
        action,
        "invalidated",
        "human_confirmation_adapter_detached",
        assertNow(clock.now()),
      );
      return Object.freeze({ detached: true, invalidated: 1 });
    });
  }

  async function setHostGeneration(nextGeneration) {
    const normalized = assertIdentifier(
      nextGeneration,
      "human_confirmation_host_generation_invalid",
    );
    return locked(async () => {
      if (closed) throw codeError("human_confirmation_broker_closed", 503);
      if (normalized === hostGeneration) return Object.freeze({ hostGeneration, invalidated: 0 });
      const nowMs = assertNow(clock.now());
      let invalidated = 0;
      for (const action of actions.values()) {
        if (action.state !== "pending") continue;
        await terminalizeLocked(
          action,
          "invalidated",
          "human_confirmation_host_generation_mismatch",
          nowMs,
        );
        invalidated += 1;
      }
      hostGeneration = normalized;
      return Object.freeze({ hostGeneration, invalidated });
    });
  }

  async function close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      const consuming = await locked(async () => {
        if (!closed) {
          closed = true;
          const nowMs = assertNow(clock.now());
          for (const action of actions.values()) {
            if (action.state !== "pending") continue;
            await terminalizeLocked(
              action,
              "invalidated",
              "human_confirmation_restart_invalidated",
              nowMs,
            );
          }
          for (const action of actions.values()) {
            if (action.state === "consuming") action.approvalAbortController?.abort();
          }
        }
        return [...new Set([...settlementTasks, ...approvalTasks.values()])];
      });
      if (consuming.length === 0) return;
      let timedOut = false;
      let timeoutHandle = null;
      const timeout = new Promise((resolve) => {
        timeoutHandle = scheduler.setTimeout(() => { timedOut = true; resolve(); }, approvalDrainTimeoutMs);
      });
      await Promise.race([Promise.allSettled(consuming), timeout]);
      if (!timedOut && timeoutHandle != null) scheduler.clearTimeout(timeoutHandle);
      if (!timedOut) return;
      await locked(async () => {
        for (const action of actions.values()) {
          if (action.state !== "consuming") continue;
          action.state = "failed";
          action.code = "human_confirmation_approval_failed";
          try {
            await recordTombstone(action, action.state, action.code, assertNow(clock.now()));
          } catch {
            action.code = "human_confirmation_ledger_unavailable";
          } finally {
            scrubActionSecrets(action);
          }
        }
      });
    })();
    return closePromise;
  }

  function startLauncher(action) {
    Promise.resolve().then(async () => {
      if (action.state !== "pending") return;
      try {
        assertNativeAuthority(action.nativeAuthority);
      } catch {
        await locked(() => terminalizeLocked(action, "invalidated",
          "human_confirmation_authority_invalidated", assertNow(clock.now())));
        return;
      }
      const input = Object.freeze({
        contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT,
        actionId: action.actionId,
        principalId: action.principalId,
        delegateId: action.delegateId,
        hostInstallationId: action.hostInstallationId,
        adapterId: action.adapterId,
        adapterInstanceId: action.adapterInstanceId,
        hostGeneration: action.hostGeneration,
        recipientHelloLynkId: action.recipientHelloLynkId,
        ...recipientInstanceFields(action),
        clientMessageId: action.clientMessageId,
        textDigest: action.textDigest,
        createdAtMs: action.createdAtMs,
        expiresAtMs: action.expiresAtMs,
        challenge: action.challenge,
        hmacKey: action.hmacKey.toString("base64url"),
        displayText: action.text,
      });
      return launcher.run(input, {
        signal: action.abortController.signal,
        deliver: (result) => trackSettlement(action.actionId, result),
      });
    }).catch(() => trackSettlement(action.actionId, {
      kind: "failure",
      code: "human_confirmation_dialog_crashed",
    }));
  }

  function trackSettlement(actionId, result) {
    const task = settle(actionId, result);
    settlementTasks.add(task);
    task.finally(() => settlementTasks.delete(task)).catch(() => {});
    return task;
  }

  async function settle(actionId, childResult) {
    let approved;
    try {
      approved = await locked(async () => {
        const action = actions.get(actionId);
        if (!action || action.state !== "pending") return null;
        try {
          assertNativeAuthority(action.nativeAuthority);
        } catch {
          await terminalizeLocked(action, "invalidated",
            "human_confirmation_authority_invalidated", assertNow(clock.now()));
          return null;
        }
        const decisionReceivedAtMs = assertNow(clock.now());
        if (decisionReceivedAtMs >= action.expiresAtMs) {
          await terminalizeLocked(
            action,
            "expired",
            "human_confirmation_timed_out",
            decisionReceivedAtMs,
          );
          return null;
        }
        if (action.hostGeneration !== hostGeneration) {
          await terminalizeLocked(
            action,
            "invalidated",
            "human_confirmation_host_generation_mismatch",
            assertNow(clock.now()),
          );
          return null;
        }
        if (childResult?.kind === "failure") {
          await terminalizeLocked(
            action,
            failureState(childResult.code),
            normalizeLauncherFailure(childResult.code),
            assertNow(clock.now()),
          );
          return null;
        }
        let response;
        try {
          response = assertChildResponse(childResult?.value, action);
        } catch (error) {
          await terminalizeLocked(
            action,
            "failed",
            safeCode(error, "human_confirmation_response_malformed"),
            assertNow(clock.now()),
          );
          return null;
        }
        const mismatch = responseBindingMismatch(action, response);
        if (mismatch) {
          await terminalizeLocked(action, "failed", mismatch, assertNow(clock.now()));
          return null;
        }
        const expectedProof = createDecisionProof(action, response.decision);
        if (!safeHexEqual(expectedProof, response.proof)) {
          await terminalizeLocked(
            action,
            "failed",
            "human_confirmation_proof_invalid",
            assertNow(clock.now()),
          );
          return null;
        }
        if (response.decision === "cancel") {
          await terminalizeLocked(
            action,
            "cancelled",
            "human_confirmation_cancelled",
            assertNow(clock.now()),
          );
          return null;
        }

        // This state transition is deliberately synchronous and happens before
        // the first await. Concurrent/replayed child deliveries can no longer win.
        action.state = "consuming";
        action.code = null;
        action.approvalAbortController = new AbortController();
        pendingByPartition.delete(action.partitionHash);
        clearActionResources(action);
        try {
          await recordTombstone(action, "consuming", null, assertNow(clock.now()));
        } catch {
          action.state = "failed";
          action.code = "human_confirmation_ledger_unavailable";
          scrubActionSecrets(action);
          return null;
        }
        return {
          action,
          approval: Object.freeze({
            contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT,
            actionId: action.actionId,
            principalId: action.principalId,
            delegateId: action.delegateId,
            hostInstallationId: action.hostInstallationId,
            adapterId: action.adapterId,
            adapterInstanceId: action.adapterInstanceId,
            hostGeneration: action.hostGeneration,
            recipientHelloLynkId: action.recipientHelloLynkId,
            ...recipientInstanceFields(action),
            clientMessageId: action.clientMessageId,
            text: action.text,
            textDigest: action.textDigest,
            intentSource: "human_native_dialog",
            approvedAtMs: assertNow(clock.now()),
          }),
        };
      });
    } catch {
      return;
    }
    if (!approved) return;
    const task = runApproved(approved);
    approvalTasks.set(actionId, task);
    try { await task; } finally { approvalTasks.delete(actionId); }
  }

  async function runApproved(approved) {
    let finalState = "approved";
    let finalCode = null;
    try {
      if (approved.action.nativeAuthority) await approved.action.nativeAuthority.revalidate();
      assertNativeAuthority(approved.action.nativeAuthority);
      await onApproved(approved.approval, {
        signal: approved.action.approvalAbortController.signal,
        nativeAuthority: approved.action.nativeAuthority,
      });
    } catch {
      finalState = "failed";
      finalCode = "human_confirmation_approval_failed";
    }
    await locked(async () => {
      const { action } = approved;
      if (action.state !== "consuming") return;
      action.state = finalState;
      action.code = finalCode;
      try {
        await recordTombstone(action, finalState, finalCode, assertNow(clock.now()));
      } catch {
        action.state = "failed";
        action.code = "human_confirmation_ledger_unavailable";
      } finally {
        scrubActionSecrets(action);
      }
    });
  }

  async function expire(actionId) {
    await locked(async () => {
      const action = actions.get(actionId);
      if (!action || action.state !== "pending") return;
      await terminalizeLocked(
        action,
        "expired",
        "human_confirmation_timed_out",
        assertNow(clock.now()),
      );
    });
  }

  async function terminalizeLocked(action, state, code, nowMs) {
    if (action.state !== "pending") return;
    action.state = state;
    action.code = code;
    pendingByPartition.delete(action.partitionHash);
    clearActionResources(action);
    try {
      await recordTombstone(action, state, code, nowMs);
    } catch {
      action.state = "failed";
      action.code = "human_confirmation_ledger_unavailable";
    } finally {
      scrubActionSecrets(action);
    }
  }

  async function recordTombstone(action, state, code, recordedAtMs) {
    await ledger.record(Object.freeze({
      contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT,
      actionId: action.actionId,
      partitionHash: action.partitionHash,
      state,
      code,
      createdAtMs: action.createdAtMs,
      expiresAtMs: action.expiresAtMs,
      recordedAtMs,
    }));
  }

  function clearActionResources(action) {
    if (action.timer != null) scheduler.clearTimeout(action.timer);
    action.timer = null;
    action.abortController.abort();
  }

  return Object.freeze({ request, status, detachAdapter, setHostGeneration, close });
}

export function createWindowsNativeHumanConfirmationLauncher() {
  return Object.freeze({
    async run(input, context = {}) {
      if (context.signal?.aborted) {
        await context.deliver?.({ kind: "failure", code: "human_confirmation_timed_out" });
        return;
      }
      if (process.platform !== "win32") {
        await context.deliver?.({ kind: "failure", code: "human_confirmation_platform_unsupported" });
        return;
      }
      const serialized = JSON.stringify(input);
      if (Buffer.byteLength(serialized, "utf8") > MAX_CHILD_INPUT_BYTES) {
        await context.deliver?.({ kind: "failure", code: "human_confirmation_request_too_large" });
        return;
      }
      await runPowerShellChild(serialized, context);
    },
  });
}

async function runPowerShellChild(serialized, context) {
  await new Promise((resolve) => {
    let delivered = false;
    let stdout = "";
    const stdoutDecoder = new StringDecoder("utf8");
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let forcedCode = null;
    const child = spawn("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-STA", "-File", POWERSHELL_SCRIPT,
    ], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: sanitizeHelloLynkChildEnvironment(process.env),
    });
    const finish = async (result) => {
      if (delivered) return;
      delivered = true;
      try { await context.deliver?.(result); } finally { resolve(); }
    };
    const abort = () => {
      forcedCode ||= "human_confirmation_timed_out";
      child.kill();
    };
    if (context.signal?.aborted) abort();
    else context.signal?.addEventListener("abort", abort, { once: true });
    child.once("error", () => void finish({
      kind: "failure",
      code: "human_confirmation_dialog_crashed",
    }));
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_CHILD_STDOUT_BYTES) {
        forcedCode = "human_confirmation_stdout_oversize";
        child.kill();
        return;
      }
      stdout += stdoutDecoder.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_CHILD_STDERR_BYTES) {
        forcedCode = "human_confirmation_stderr_oversize";
        child.kill();
      }
    });
    child.once("close", (code) => {
      context.signal?.removeEventListener("abort", abort);
      if (delivered) return;
      if (forcedCode) return void finish({ kind: "failure", code: forcedCode });
      if (code !== 0) return void finish({
        kind: "failure",
        code: "human_confirmation_dialog_crashed",
      });
      stdout += stdoutDecoder.end();
      if (!/^[^\r\n]+(?:\r?\n)?$/.test(stdout)) {
        return void finish({ kind: "failure", code: "human_confirmation_stdout_extra" });
      }
      try {
        const value = JSON.parse(stdout.trim());
        return void finish({ kind: "response", value });
      } catch {
        return void finish({ kind: "failure", code: "human_confirmation_response_malformed" });
      }
    });
    child.stdin.once("error", () => {});
    child.stdin.end(serialized, "utf8");
  });
}

function normalizeRequest(value, expectedGeneration) {
  assertPlainObject(value, "human_confirmation_request_invalid");
  // Legacy standalone callers keep their exact old shape. The formal Host
  // requires both peer fields before entering this internal boundary.
  const hasRecipientInstance = RECIPIENT_INSTANCE_KEYS.some((key) => Object.hasOwn(value, key));
  assertExactKeys(value, [
    "adapterId", "adapterInstanceId", "capabilityId", "clientMessageId", "delegateId",
    "hostGeneration", "hostInstallationId", "principalId", "recipientHelloLynkId", "text",
    ...(hasRecipientInstance ? RECIPIENT_INSTANCE_KEYS : []),
  ], "human_confirmation_request_invalid");
  const text = assertText(value.text);
  const normalized = {
    capabilityId: assertIdentifier(value.capabilityId, "human_confirmation_capability_id_invalid"),
    principalId: assertIdentifier(value.principalId, "human_confirmation_principal_id_invalid"),
    delegateId: assertIdentifier(value.delegateId, "human_confirmation_delegate_id_invalid"),
    hostInstallationId: assertIdentifier(
      value.hostInstallationId,
      "human_confirmation_host_installation_id_invalid",
    ),
    adapterId: assertIdentifier(value.adapterId, "human_confirmation_adapter_id_invalid"),
    adapterInstanceId: assertIdentifier(
      value.adapterInstanceId,
      "human_confirmation_adapter_instance_id_invalid",
    ),
    hostGeneration: assertIdentifier(
      value.hostGeneration,
      "human_confirmation_host_generation_invalid",
    ),
    recipientHelloLynkId: assertHelloLynkId(value.recipientHelloLynkId),
    ...(hasRecipientInstance ? {
      recipientDelegateId: assertIdentifier(value.recipientDelegateId, "human_confirmation_recipient_delegate_id_invalid"),
      recipientInstanceDisplayName: assertInstanceDisplayName(value.recipientInstanceDisplayName),
    } : {}),
    clientMessageId: assertIdentifier(
      value.clientMessageId,
      "human_confirmation_client_message_id_invalid",
    ),
    text,
    textDigest: crypto.createHash("sha256").update(text, "utf8").digest("hex"),
  };
  if (normalized.hostGeneration !== expectedGeneration) {
    throw codeError("human_confirmation_host_generation_mismatch", 409);
  }
  return Object.freeze(normalized);
}

function normalizeStatusQuery(value) {
  assertPlainObject(value, "human_confirmation_status_query_invalid");
  assertExactKeys(
    value,
    ["actionId", "adapterInstanceId", "capabilityId"],
    "human_confirmation_status_query_invalid",
  );
  return Object.freeze({
    actionId: assertIdentifier(value.actionId, "human_confirmation_action_id_invalid"),
    capabilityId: assertIdentifier(value.capabilityId, "human_confirmation_capability_id_invalid"),
    adapterInstanceId: assertIdentifier(
      value.adapterInstanceId,
      "human_confirmation_adapter_instance_id_invalid",
    ),
  });
}

function normalizePartitionQuery(value) {
  assertPlainObject(value, "human_confirmation_adapter_query_invalid");
  assertExactKeys(
    value,
    ["adapterInstanceId", "capabilityId"],
    "human_confirmation_adapter_query_invalid",
  );
  return Object.freeze({
    capabilityId: assertIdentifier(value.capabilityId, "human_confirmation_capability_id_invalid"),
    adapterInstanceId: assertIdentifier(
      value.adapterInstanceId,
      "human_confirmation_adapter_instance_id_invalid",
    ),
  });
}

function assertChildResponse(value, action) {
  assertPlainObject(value, "human_confirmation_response_malformed");
  const hasRecipientInstance = Object.hasOwn(action, "recipientDelegateId");
  assertExactKeys(value, [...RESPONSE_KEYS, ...(hasRecipientInstance ? RECIPIENT_INSTANCE_KEYS : [])], "human_confirmation_response_malformed");
  if (value.contract !== HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT) {
    throw codeError("human_confirmation_response_malformed", 500);
  }
  if (value.decision !== "approve" && value.decision !== "cancel") {
    throw codeError("human_confirmation_response_malformed", 500);
  }
  const normalized = {
    contract: value.contract,
    actionId: assertIdentifier(value.actionId, "human_confirmation_response_malformed"),
    decision: value.decision,
    principalId: assertIdentifier(value.principalId, "human_confirmation_response_malformed"),
    delegateId: assertIdentifier(value.delegateId, "human_confirmation_response_malformed"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "human_confirmation_response_malformed"),
    adapterId: assertIdentifier(value.adapterId, "human_confirmation_response_malformed"),
    adapterInstanceId: assertIdentifier(value.adapterInstanceId, "human_confirmation_response_malformed"),
    hostGeneration: assertIdentifier(value.hostGeneration, "human_confirmation_response_malformed"),
    recipientHelloLynkId: assertHelloLynkId(value.recipientHelloLynkId, "human_confirmation_response_malformed"),
    ...(hasRecipientInstance ? {
      recipientDelegateId: assertIdentifier(value.recipientDelegateId, "human_confirmation_response_malformed"),
      recipientInstanceDisplayName: assertInstanceDisplayName(value.recipientInstanceDisplayName, "human_confirmation_response_malformed"),
    } : {}),
    clientMessageId: assertIdentifier(value.clientMessageId, "human_confirmation_response_malformed"),
    textDigest: assertHex(value.textDigest, "human_confirmation_response_malformed"),
    createdAtMs: assertNow(value.createdAtMs),
    expiresAtMs: assertNow(value.expiresAtMs),
    proof: assertHex(value.proof, "human_confirmation_response_malformed"),
  };
  return Object.freeze(normalized);
}

function responseBindingMismatch(action, response) {
  if (response.hostGeneration !== action.hostGeneration) {
    return "human_confirmation_host_generation_mismatch";
  }
  for (const key of [
    "actionId", "principalId", "delegateId", "hostInstallationId", "adapterId",
    "adapterInstanceId", "recipientHelloLynkId", "clientMessageId", "textDigest",
    "createdAtMs", "expiresAtMs",
    ...(Object.hasOwn(action, "recipientDelegateId") ? RECIPIENT_INSTANCE_KEYS : []),
  ]) {
    if (response[key] !== action[key]) return "human_confirmation_binding_mismatch";
  }
  return null;
}

function createDecisionProof(action, decision) {
  return crypto.createHmac("sha256", action.hmacKey)
    .update(canonicalDecisionMessage({ ...action, decision }), "utf8")
    .digest("hex");
}

function canonicalDecisionMessage(value) {
  return [
    HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT,
    value.actionId,
    value.decision,
    value.principalId,
    value.delegateId,
    value.hostInstallationId,
    value.adapterId,
    value.adapterInstanceId,
    value.hostGeneration,
    value.recipientHelloLynkId,
    ...(Object.hasOwn(value, "recipientDelegateId") ? [value.recipientDelegateId, value.recipientInstanceDisplayName] : []),
    value.clientMessageId,
    value.textDigest,
    String(value.createdAtMs),
    String(value.expiresAtMs),
    value.challenge,
  ].join("\n");
}

function publicStatus(action, httpStatus, idempotent) {
  return Object.freeze({
    status: httpStatus,
    body: Object.freeze({
      contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT,
      actionId: action.actionId,
      state: action.state,
      code: action.code,
      createdAtMs: action.createdAtMs,
      expiresAtMs: action.expiresAtMs,
      idempotent,
    }),
  });
}

function publicTombstone(value) {
  assertPlainObject(value, "human_confirmation_ledger_response_invalid");
  return Object.freeze({
    status: 200,
    body: Object.freeze({
      contract: HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_CONTRACT,
      actionId: assertIdentifier(value.actionId, "human_confirmation_ledger_response_invalid"),
      state: assertTombstoneState(value.state),
      code: value.code == null ? null : safeLedgerCode(value.code),
      createdAtMs: assertNow(value.createdAtMs),
      expiresAtMs: assertNow(value.expiresAtMs),
      idempotent: false,
    }),
  });
}

function assertLedger(value) {
  if (!value || value.contract !== HELLOLYNK_NATIVE_HUMAN_CONFIRMATION_LEDGER_CONTRACT
    || value.durability !== "cross-process"
    || typeof value.admit !== "function" || typeof value.record !== "function"
    || typeof value.lookup !== "function") {
    throw codeError("human_confirmation_ledger_invalid", 500);
  }
  return value;
}

function normalizeLauncherFailure(value) {
  const code = String(value || "");
  const allowed = new Set([
    "human_confirmation_dialog_crashed",
    "human_confirmation_platform_unsupported",
    "human_confirmation_request_too_large",
    "human_confirmation_response_malformed",
    "human_confirmation_stderr_oversize",
    "human_confirmation_stdout_extra",
    "human_confirmation_stdout_oversize",
    "human_confirmation_timed_out",
  ]);
  return allowed.has(code) ? code : "human_confirmation_dialog_crashed";
}

function failureState(code) {
  return code === "human_confirmation_timed_out" ? "expired" : "failed";
}

function scrubActionSecrets(action) {
  action.challenge = null;
  if (Buffer.isBuffer(action.hmacKey)) action.hmacKey.fill(0);
  action.hmacKey = null;
  action.text = null;
  action.nativeAuthority = null;
}

function assertNativeAuthority(authority) {
  if (!authority) return; // Standalone broker callers do not own a Host attachment.
  try {
    authority.assertCurrent();
  } catch {
    throw codeError("human_confirmation_authority_invalidated", 409);
  }
}

function hashParts(...parts) {
  return crypto.createHash("sha256").update(parts.join("\0"), "utf8").digest("hex");
}

function randomToken(randomBytes, size) {
  const value = Buffer.from(randomBytes(size));
  if (value.length !== size) throw codeError("human_confirmation_random_source_invalid", 500);
  return value.toString("base64url");
}

function safeHexEqual(expected, candidate) {
  if (!HEX_64_PATTERN.test(candidate)) return false;
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(candidate, "hex"));
}

function assertText(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")
    || Buffer.byteLength(value, "utf8") > MAX_TEXT_BYTES) {
    throw codeError("human_confirmation_text_invalid", 400);
  }
  return value;
}

function assertIdentifier(value, code) {
  const text = String(value || "");
  if (!IDENTIFIER_PATTERN.test(text)) throw codeError(code, 400);
  return text;
}

function assertInstanceDisplayName(value, code = "human_confirmation_recipient_instance_display_name_invalid") {
  if (typeof value !== "string" || value.trim() !== value || !value.length
    || [...value].length > 128 || Buffer.byteLength(value, "utf8") > 512
    || /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u.test(value)) {
    throw codeError(code, 400);
  }
  return value;
}

function recipientInstanceFields(value) {
  return Object.hasOwn(value, "recipientDelegateId") ? {
    recipientDelegateId: value.recipientDelegateId,
    recipientInstanceDisplayName: value.recipientInstanceDisplayName,
  } : {};
}

function assertHelloLynkId(value, code = "human_confirmation_recipient_hellolynk_id_invalid") {
  const text = String(value || "");
  if (!HELLOLYNK_ID_PATTERN.test(text)) throw codeError(code, 400);
  return text;
}

function assertHex(value, code) {
  const text = String(value || "").toLowerCase();
  if (!HEX_64_PATTERN.test(text)) throw codeError(code, 500);
  return text;
}

function assertNow(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw codeError("human_confirmation_clock_invalid", 500);
  }
  return number;
}

function assertPlainObject(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw codeError(code, 400);
  }
}

function assertExactKeys(value, expected, code) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError(code, 400);
  }
}

function assertTombstoneState(value) {
  const state = String(value || "");
  if (!new Set(["approved", "cancelled", "consuming", "expired", "failed", "invalidated"]).has(state)) {
    throw codeError("human_confirmation_ledger_response_invalid", 500);
  }
  return state;
}

function safeLedgerCode(value) {
  const code = String(value || "");
  if (!/^human_confirmation_[a-z0-9_]{1,100}$/.test(code)) {
    throw codeError("human_confirmation_ledger_response_invalid", 500);
  }
  return code;
}

function normalizeClock(value) {
  if (value == null) return Object.freeze({ now: () => Date.now() });
  if (typeof value === "function") return Object.freeze({ now: value });
  if (typeof value?.now === "function") return Object.freeze({ now: () => value.now() });
  throw codeError("human_confirmation_clock_invalid", 500);
}

function normalizeScheduler(value) {
  if (value == null) return Object.freeze({
    setTimeout: (callback, delay) => setTimeout(callback, delay),
    clearTimeout: (handle) => clearTimeout(handle),
  });
  if (typeof value.setTimeout !== "function" || typeof value.clearTimeout !== "function") {
    throw codeError("human_confirmation_scheduler_invalid", 500);
  }
  return value;
}

function normalizeDrainTimeout(value) {
  const accepted = value == null ? 5_000 : Number(value);
  if (!Number.isSafeInteger(accepted) || accepted < 10 || accepted > 60_000) {
    throw codeError("human_confirmation_drain_timeout_invalid", 500);
  }
  return accepted;
}

function codeError(code, status = 400, retryAfterMs = undefined) {
  const error = new Error(code);
  error.code = code;
  error.status = status;
  if (Number.isSafeInteger(retryAfterMs) && retryAfterMs >= 0) error.retryAfterMs = retryAfterMs;
  return error;
}

function safeCode(error, fallback) {
  const code = String(error?.code || "");
  return /^human_confirmation_[a-z0-9_]{1,100}$/.test(code) ? code : fallback;
}
