import { randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

export const HELLOLYNK_HUMAN_CONFIRMATION_LEDGER_CONTRACT =
  "hellolynk-native-human-confirmation-ledger-v1";

const HELPER_PATH = fileURLToPath(new URL(
  "../platform/windows/hellolynk-human-confirmation-ledger.ps1",
  import.meta.url,
));
const HEX_64 = /^[a-f0-9]{64}$/;
const ACTION_ID = /^human_[A-Za-z0-9_-]{16,96}$/;
const CODE = /^human_confirmation_[a-z0-9_]{1,100}$/;
const TERMINAL_STATES = new Set([
  "approved", "cancelled", "consuming", "expired", "failed", "invalidated",
]);

export function createWindowsHumanConfirmationLedger(options = {}) {
  if ((options.platform || process.platform) !== "win32") {
    throw error("human_confirmation_ledger_platform_unsupported");
  }
  const root = assertRoot(options.root);
  const helperPath = resolve(options.helperPath || HELPER_PATH);
  const invoke = options.invoke || ((command, value) => invokeHelper({
    command, value, root, helperPath,
  }));

  async function admit(value) {
    const input = normalizeAdmission(value);
    const result = await invoke("Admit", input);
    assertPlain(result);
    if (result.accepted === true && Object.keys(result).length === 1) {
      return Object.freeze({ accepted: true });
    }
    if (result.accepted !== false) throw error("human_confirmation_ledger_response_invalid");
    if (result.reason === "rate_limited") {
      assertExact(result, ["accepted", "reason", "retryAfterMs"], "human_confirmation_ledger_response_invalid");
      return Object.freeze({
        accepted: false,
        reason: "rate_limited",
        retryAfterMs: integer(result.retryAfterMs, "human_confirmation_ledger_response_invalid"),
      });
    }
    if (result.reason === "partition_pending") {
      assertExact(result, ["accepted", "reason"], "human_confirmation_ledger_response_invalid");
      return Object.freeze({ accepted: false, reason: "partition_pending" });
    }
    throw error("human_confirmation_ledger_response_invalid");
  }

  async function record(value) {
    const input = normalizeRecord(value);
    const result = await invoke("Record", input);
    assertExact(result, ["recorded"], "human_confirmation_ledger_response_invalid");
    if (result.recorded !== true) throw error("human_confirmation_ledger_response_invalid");
  }

  async function lookup(value) {
    const input = normalizeLookup(value);
    const result = await invoke("Lookup", input);
    assertExact(result, ["record"], "human_confirmation_ledger_response_invalid");
    if (result.record === null) return null;
    return normalizeTombstone(result.record, input);
  }

  return Object.freeze({
    contract: HELLOLYNK_HUMAN_CONFIRMATION_LEDGER_CONTRACT,
    durability: "cross-process",
    admit,
    record,
    lookup,
  });
}

function normalizeAdmission(value) {
  assertExact(value, [
    "actionId", "contract", "createdAtMs", "expiresAtMs", "partitionHash",
    "rateLimit", "rateWindowMs", "restartTombstoneCode", "restartTombstoneState",
  ]);
  if (value.contract !== HELLOLYNK_HUMAN_CONFIRMATION_LEDGER_CONTRACT
    || value.restartTombstoneState !== "invalidated"
    || value.restartTombstoneCode !== "human_confirmation_restart_invalidated"
    || value.rateLimit !== 3 || value.rateWindowMs !== 60_000) {
    throw error("human_confirmation_ledger_input_invalid");
  }
  const createdAtMs = integer(value.createdAtMs);
  const expiresAtMs = integer(value.expiresAtMs);
  if (expiresAtMs <= createdAtMs) throw error("human_confirmation_ledger_input_invalid");
  return Object.freeze({
    contract: value.contract,
    actionId: actionId(value.actionId),
    partitionDigest: digest(value.partitionHash),
    createdAtMs,
    expiresAtMs,
    rateWindowMs: value.rateWindowMs,
    rateLimit: value.rateLimit,
    restartTombstoneState: value.restartTombstoneState,
    restartTombstoneCode: value.restartTombstoneCode,
  });
}

function normalizeRecord(value) {
  assertExact(value, [
    "actionId", "code", "contract", "createdAtMs", "expiresAtMs", "partitionHash",
    "recordedAtMs", "state",
  ]);
  if (value.contract !== HELLOLYNK_HUMAN_CONFIRMATION_LEDGER_CONTRACT
    || !TERMINAL_STATES.has(value.state)) throw error("human_confirmation_ledger_input_invalid");
  const createdAtMs = integer(value.createdAtMs);
  const expiresAtMs = integer(value.expiresAtMs);
  const recordedAtMs = integer(value.recordedAtMs);
  if (expiresAtMs <= createdAtMs || recordedAtMs < createdAtMs) {
    throw error("human_confirmation_ledger_input_invalid");
  }
  const code = value.code === null ? null : String(value.code);
  if (code !== null && !CODE.test(code)) throw error("human_confirmation_ledger_input_invalid");
  if (value.state === "consuming" && code !== null) throw error("human_confirmation_ledger_input_invalid");
  return Object.freeze({
    contract: value.contract,
    actionId: actionId(value.actionId),
    partitionDigest: digest(value.partitionHash),
    state: value.state,
    code,
    createdAtMs,
    expiresAtMs,
    recordedAtMs,
  });
}

function normalizeLookup(value) {
  assertExact(value, ["actionId", "contract", "partitionHash"]);
  if (value.contract !== HELLOLYNK_HUMAN_CONFIRMATION_LEDGER_CONTRACT) {
    throw error("human_confirmation_ledger_input_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    actionId: actionId(value.actionId),
    partitionDigest: digest(value.partitionHash),
  });
}

function normalizeTombstone(value, query) {
  assertExact(value, ["actionId", "code", "createdAtMs", "expiresAtMs", "state"], "human_confirmation_ledger_response_invalid");
  if (value.actionId !== query.actionId || !TERMINAL_STATES.has(value.state)) {
    throw error("human_confirmation_ledger_response_invalid");
  }
  const code = value.code === null ? null : String(value.code);
  if (code !== null && !CODE.test(code)) throw error("human_confirmation_ledger_response_invalid");
  return Object.freeze({
    actionId: value.actionId,
    state: value.state,
    code,
    createdAtMs: integer(value.createdAtMs, "human_confirmation_ledger_response_invalid"),
    expiresAtMs: integer(value.expiresAtMs, "human_confirmation_ledger_response_invalid"),
  });
}

async function invokeHelper(input) {
  const helper = await lstat(input.helperPath);
  if (!helper.isFile() || helper.isSymbolicLink()) throw error("human_confirmation_ledger_helper_invalid");
  const pipeName = `HelloLynkHumanLedger-${process.pid}-${randomBytes(18).toString("base64url")}`;
  const pipePath = `\\\\.\\pipe\\${pipeName}`;
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", input.helperPath,
    "-Command", input.command, "-StoreRoot", input.root, "-ResultPipeName", pipeName,
  ];
  const child = spawn("pwsh.exe", args, {
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: minimalEnvironment(process.env),
  });
  let cancelled = false;
  const resultPromise = readPipe(pipePath, () => cancelled);
  resultPromise.catch(() => {});
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  child.stdout.on("data", (chunk) => { stdoutBytes += chunk.length; if (stdoutBytes <= 1024) stdout.push(chunk); });
  child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes <= 4096) stderr.push(chunk); });
  child.stdin.end(JSON.stringify(input.value), "utf8");
  const exitCode = await new Promise((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("close", resolveExit);
  });
  if (stdoutBytes) { cancelled = true; throw error("human_confirmation_ledger_helper_stdout_forbidden"); }
  if (stderrBytes > 4096) { cancelled = true; throw error("human_confirmation_ledger_helper_stderr_oversize"); }
  if (exitCode !== 0) {
    cancelled = true;
    throw error(publicCode(Buffer.concat(stderr).toString("utf8").trim()));
  }
  const raw = await resultPromise;
  try { return JSON.parse(raw); } catch { throw error("human_confirmation_ledger_response_invalid"); }
}

async function readPipe(path, cancelled) {
  const deadline = Date.now() + 45_000;
  while (true) {
    try {
      return await new Promise((resolvePipe, rejectPipe) => {
        const chunks = [];
        let bytes = 0;
        const socket = createConnection(path);
        socket.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 64 * 1024) socket.destroy(error("human_confirmation_ledger_response_too_large"));
          else chunks.push(chunk);
        });
        socket.on("error", rejectPipe);
        socket.on("end", () => resolvePipe(Buffer.concat(chunks).toString("utf8")));
      });
    } catch (cause) {
      if (cancelled()) throw error("human_confirmation_ledger_result_cancelled");
      if (cause?.code !== "ENOENT" || Date.now() >= deadline) throw cause;
      await new Promise((resolveWait) => setTimeout(resolveWait, 10));
    }
  }
}

function minimalEnvironment(source) {
  const allowed = ["PATH", "Path", "PATHEXT", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "COMSPEC"];
  return sanitizeHelloLynkChildEnvironment(Object.fromEntries(
    allowed.filter((key) => source[key] !== undefined).map((key) => [key, source[key]]),
  ));
}

function publicCode(value) {
  return /^human_confirmation_ledger_[a-z0-9_]{1,90}$/.test(value)
    ? value
    : "human_confirmation_ledger_operation_failed";
}

function assertRoot(value) {
  const raw = String(value || "");
  if (!/^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith("\\\\") || raw.includes("\0")) {
    throw error("human_confirmation_ledger_root_invalid");
  }
  const root = resolve(raw);
  if (!isAbsolute(root) || !/^[A-Za-z]:\\/.test(root) || root.length < 4) {
    throw error("human_confirmation_ledger_root_invalid");
  }
  return root;
}
function actionId(value) { const v = String(value || ""); if (!ACTION_ID.test(v)) throw error("human_confirmation_ledger_input_invalid"); return v; }
function digest(value) { const v = String(value || "").toLowerCase(); if (!HEX_64.test(v)) throw error("human_confirmation_ledger_input_invalid"); return v; }
function integer(value, code = "human_confirmation_ledger_input_invalid") { if (!Number.isSafeInteger(value) || value < 0) throw error(code); return value; }
function assertPlain(value) { if (!value || typeof value !== "object" || Array.isArray(value)) throw error("human_confirmation_ledger_response_invalid"); }
function assertExact(value, keys, code = "human_confirmation_ledger_input_invalid") { assertPlain(value); const a = Object.keys(value).sort(); const b = [...keys].sort(); if (a.length !== b.length || a.some((v, i) => v !== b[i])) throw error(code); }
function error(code) { const value = new Error(code); value.code = code; return value; }
