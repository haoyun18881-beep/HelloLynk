import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { standaloneHelloLynkNodeEnvironment, resolveHelloLynkStandaloneNode, assertHelloLynkClientNodeVersion, assertHelloLynkPowerShell7 } = runtimeSafety;

export const HELLOLYNK_NEUTRAL_HOST_LAUNCH_FAILURE_CONTRACT = "hellolynk-neutral-host-launch-failure-v1";
const HELLOLYNK_NEUTRAL_HOST_LAUNCH_ATTEMPT_CONTRACT = "hellolynk-neutral-host-launch-attempt-v1";

const RUNNER_RELATIVE = "runtime/neutral-host-bootstrap.mjs";
const BOOTSTRAP_STDERR_MAX_BYTES = 4 * 1024;
const DEFAULT_BOOTSTRAP_FAILURE_OBSERVATION_MS = 75_000;
const MAX_BOOTSTRAP_FAILURE_OBSERVATION_MS = 120_000;
const LAUNCH_FAILURE_MAX_BYTES = 2 * 1024;
// Pre-spawn timings a launcher may hand over for the next cold-start investigation.
const LAUNCH_STAGE_MS_FIELDS = Object.freeze(["bindingResolvedMs", "discoverProbedMs", "lockAcquiredMs"]);
const LAUNCH_STAGE_MAX_MS = 86_400_000;
const SAFE_BOOTSTRAP_FAILURE_CODES = new Set([
  "hellolynk_node_22_16_required",
  "neutral_codex_binding_configuration_required",
  "neutral_codex_binding_invalid",
  "neutral_codex_launch_failed",
  "neutral_codex_runner_integrity_invalid",
  "neutral_codex_runner_unavailable",
  "neutral_codex_uncaught_exception",
  "neutral_host_already_running",
  "neutral_host_bootstrap_exited",
  "neutral_host_bootstrap_failed",
  "neutral_host_drain_timeout",
  "neutral_host_launch_configuration_required",
  "neutral_host_launch_failed",
  "neutral_host_launch_failure_store_failed",
  "neutral_host_launch_failure_store_invalid",
  // The Host refused to start below the release an installer recorded; the caller
  // waits briefly for a Host of that release, then reports this client out of date.
  "neutral_host_release_superseded",
  "neutral_host_runner_integrity_invalid",
  "neutral_host_runner_unavailable",
  "neutral_host_singleton_claim_failed",
  "neutral_host_singleton_lock_invalid",
  "neutral_host_singleton_owner_mismatch",
  "neutral_host_singleton_owner_unknown",
  "neutral_host_singleton_stale_quarantine_failed",
  "neutral_host_stop_failed",
  "neutral_runtime_uncaught_exception",
  "neutral_trae_work_uncaught_exception",
  "powershell7_missing",
]);
const SAFE_RELATIVE = /^(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*\.(?:bin|cjs|cs|css|html|js|json|md|mjs|ps1|swift|vbs)$/;
const REQUIRED_RUNTIME_RECORDS = Object.freeze([
  "neutral-host-bootstrap.mjs",
  "neutral-host-release-loader.mjs",
  "neutral-host-release-entry.mjs",
  "core/hellolynk-host-protected-store.mjs",
  "core/hellolynk-runtime-safety.cjs",
  "core/hellolynk-local-data-migration.mjs",
  "core/hellolynk-local-data-protection.mjs",
  "core/hellolynk-indexed-message-store.mjs",
  "core/hellolynk-neutral-host-installation-store.mjs",
  "core/hellolynk-neutral-host-assembly.mjs",
  "core/hellolynk-neutral-host-process.mjs",
  "core/hellolynk-neutral-host-workbench-read-model.mjs",
  "core/hellolynk-workbench-action-grants.mjs",
  ...(process.platform === "darwin" ? [
    "core/hellolynk-darwin-vault.mjs",
    "core/hellolynk-darwin-host.mjs",
    "platform/darwin/hellolynk-keychain-helper.bin",
  ] : [
    "platform/windows/hellolynk-host-protected-store.ps1",
    "platform/windows/hellolynk-local-data-key.ps1",
  ]),
  "workbench/contract.mjs",
]);

export async function launchPinnedNeutralHost(binding, options = {}) {
  assertHelloLynkClientNodeVersion();
  assertHelloLynkPowerShell7();
  const launch = normalize(binding, options);
  await verifyPinnedNeutralHostRuntime(launch);
  const lockPath = path.join(
    launch.runtimeRoot,
    "neutral-host",
    `${sha256(`${launch.region}\0${launch.principalId}\0${launch.hostInstallationId}`)}.${launch.adapterId}-launch.lock`,
  );
  await safeDirectory(launch.runtimeRoot, true);
  await safeDirectory(path.dirname(lockPath), true);
  const wait = options.wait || delay;
  const deadline = Date.now() + bounded(options.lockTimeoutMs, 15_000, 500, 60_000);
  let ownsLock = false;
  while (Date.now() < deadline) {
    try {
      await fs.mkdir(lockPath, { mode: 0o700 });
      await fs.writeFile(path.join(lockPath, "owner.json"), `${JSON.stringify({
        contract: "hellolynk-neutral-host-launch-lock-v1",
        adapterId: launch.adapterId,
        pid: process.pid,
        createdAtMs: Date.now(),
      })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
      ownsLock = true;
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw codeError("neutral_host_launch_failed");
      await safeDirectory(lockPath, false);
      await reclaimDeadLock(lockPath).catch(() => false);
      await wait(50);
    }
  }
  if (!ownsLock) throw codeError("neutral_host_launch_lock_timeout");
  try {
    await launchPinnedNeutralHostBootstrap(launch, options);
    return Object.freeze({ started: true, owner: `${launch.adapterId}_process` });
  } finally {
    await fs.rm(path.join(lockPath, "owner.json"), { force: true }).catch(() => {});
    await fs.rmdir(lockPath).catch(() => {});
  }
}

export async function launchPinnedNeutralHostBootstrap(binding, options = {}) {
  assertHelloLynkClientNodeVersion();
  assertHelloLynkPowerShell7();
  const launch = normalize(binding, options);
  const failureBasePath = launchFailurePath(launch);
  await safeDirectory(launch.runtimeRoot, true);
  await safeDirectory(path.dirname(failureBasePath), true);
  const failureAttemptId = await beginLaunchFailureAttempt(failureBasePath, launchStages(options.stages));
  const observation = bootstrapObservationWindows(options);
  const spawnRunner = options.spawnRunner || spawnBootstrap;
  try {
    await spawnRunner({
      bootstrapPath: launch.bootstrapPath,
      storeRoot: launch.storeRoot,
      expected: owner(launch),
      failurePath: launchFailureRecordPath(failureBasePath, failureAttemptId),
      failureBasePath,
      failureAttemptId,
      observationMs: observation.observationMs,
      failureObservationMs: observation.failureObservationMs,
      env: options.env || process.env,
    });
  } catch (error) {
    const code = stableBootstrapFailureCode(error?.code);
    if (error?.launchFailureRecorded !== true) {
      await writeLaunchFailure(failureBasePath, failureAttemptId, code);
    }
    const reported = codeError(code);
    reported.launchFailure = await readLaunchFailure(failureBasePath, failureAttemptId).catch(() => null);
    throw reported;
  }
  return Object.freeze({ started: true, owner: `${launch.adapterId}_process` });
}

export async function readPinnedNeutralHostLaunchFailure(binding, options = {}) {
  const launch = normalize(binding, options);
  return readLaunchFailure(launchFailurePath(launch));
}

export async function verifyPinnedNeutralHostRuntime(binding, options = {}) {
  const launch = normalize(binding, options);
  const pinPath = path.join(launch.releaseRoot, "runtime", "neutral-host-release-pin.json");
  const manifestPath = path.join(launch.releaseRoot, "runtime", "neutral-host-release-manifest.json");
  const [pinBytes, manifestBytes] = await Promise.all([
    readSafeFile(pinPath, 16 * 1024),
    readSafeFile(manifestPath, 256 * 1024),
  ]);
  const pin = parseJson(pinBytes);
  const manifest = parseJson(manifestBytes);
  if (!plain(pin) || !exact(pin, ["contract", "manifestSha256"])
    || pin.contract !== "hellolynk-neutral-host-release-pin-v1"
    || pin.manifestSha256 !== launch.releaseManifestSha256
    || sha256(manifestBytes) !== launch.releaseManifestSha256
    || !plain(manifest) || !exact(manifest, ["contract", "entry", "files"])
    || manifest.contract !== "hellolynk-neutral-host-release-manifest-v1"
    || manifest.entry !== "neutral-host-release-entry.mjs"
    || !Array.isArray(manifest.files) || manifest.files.length < 3 || manifest.files.length > 256) fail();
  const records = new Map();
  const paths = new Map();
  for (const item of manifest.files) {
    if (!plain(item) || !exact(item, ["path", "sha256"])
      || !/^[a-f0-9]{64}$/.test(String(item.sha256 || ""))) fail();
    const recordPath = String(item.path || "");
    const file = resolveManifestFile(launch, recordPath);
    const canonical = canonicalPath(file);
    if (records.has(recordPath) || paths.has(canonical)) fail();
    const bytes = await readSafeFile(file, 2 * 1024 * 1024).catch(() => fail());
    if (sha256(bytes) !== item.sha256) fail();
    const record = Object.freeze({ recordPath, file, bytes });
    records.set(recordPath, record);
    paths.set(canonical, record);
  }
  for (const required of REQUIRED_RUNTIME_RECORDS) if (!records.has(required)) fail();
  if (!samePath(records.get("neutral-host-bootstrap.mjs").file, launch.bootstrapPath)
    || !records.has(manifest.entry)) fail();
  verifyStaticImports(records, paths, launch.releaseRoot);
  return Object.freeze({ ok: true, bootstrapPath: launch.bootstrapPath, verifiedFileCount: records.size });
}

function normalize(value, options) {
  if (!plain(value)) throw codeError("neutral_host_launch_configuration_required");
  const runtimeRoot = absolute(value.runtimeRoot);
  const releaseRoot = absolute(value.releaseRoot);
  const profileManifestPath = absolute(value.profileManifestPath);
  const releaseManifestSha256 = String(value.releaseManifestSha256 || "");
  if (value.runnerRelativePath !== RUNNER_RELATIVE || !/^[a-f0-9]{64}$/.test(releaseManifestSha256)) {
    throw codeError("neutral_host_launch_configuration_required");
  }
  const storeRoot = options.storeRoot ? absolute(options.storeRoot) : path.dirname(runtimeRoot);
  if (path.basename(runtimeRoot).toLowerCase() !== "runtime"
    || !samePath(storeRoot, path.dirname(runtimeRoot))
    || !samePath(profileManifestPath, path.join(storeRoot, "profile-manifest-v1.json"))) {
    throw codeError("neutral_host_launch_configuration_required");
  }
  return Object.freeze({
    runtimeRoot, releaseRoot, profileManifestPath, releaseManifestSha256, storeRoot,
    runnerRelativePath: RUNNER_RELATIVE,
    bootstrapPath: path.join(releaseRoot, ...RUNNER_RELATIVE.split("/")),
    region: safeId(value.region), principalId: safeId(value.principalId),
    delegateId: safeId(value.delegateId), hostInstallationId: safeId(value.hostInstallationId),
    profileId: safeId(value.profileId), adapterId: safeId(value.adapterId),
    version: Number(value.version), scopes: Object.freeze([...(value.scopes || [])].map(String)),
  });
}

function resolveManifestFile(launch, recordPath) {
  if (!SAFE_RELATIVE.test(recordPath) || recordPath.split("/").includes("..")) fail();
  const external = recordPath.startsWith("release/");
  const base = external ? launch.releaseRoot : path.join(launch.releaseRoot, "runtime");
  const relative = external ? recordPath.slice("release/".length) : recordPath;
  const result = path.resolve(base, ...relative.split("/"));
  if (!inside(base, result)) fail();
  return result;
}

function verifyStaticImports(records, paths, releaseRoot) {
  const imports = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g;
  for (const record of records.values()) {
    if (!record.file.endsWith(".mjs")) continue;
    const source = record.bytes.toString("utf8");
    imports.lastIndex = 0;
    for (let match = imports.exec(source); match; match = imports.exec(source)) {
      const imported = path.resolve(path.dirname(record.file), ...match[1].split("/"));
      if (!inside(releaseRoot, imported) || !paths.has(canonicalPath(imported))) fail();
    }
  }
}

async function spawnBootstrap(input) {
  assertHelloLynkClientNodeVersion();
  const executable = await resolveHelloLynkStandaloneNode({ env: input.env });
  const child = spawn(executable, [input.bootstrapPath, "run", "--root", input.storeRoot], {
    cwd: path.dirname(input.bootstrapPath),
    detached: true,
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true,
    env: standaloneHelloLynkNodeEnvironment(input.env || process.env),
  });
  const observation = observeBootstrap(child, input.observationMs, input.failureObservationMs);
  const outcome = await observation.initial;
  if (outcome.running) {
    child.stderr?.unref?.();
    child.unref();
    void observation.terminal.then(async (lateOutcome) => {
      if (!lateOutcome) return;
      const code = bootstrapFailureCode(lateOutcome);
      await writeLaunchFailure(input.failureBasePath, input.failureAttemptId, code);
    }).catch(() => {});
    return;
  }
  const code = bootstrapFailureCode(outcome);
  const recorded = await writeLaunchFailure(input.failureBasePath, input.failureAttemptId, code);
  const error = codeError(code);
  error.launchFailureRecorded = Boolean(recorded);
  error.launchFailure = await readLaunchFailure(input.failureBasePath, input.failureAttemptId).catch(() => null);
  throw error;
}

function observeBootstrap(child, observationMs, failureObservationMs) {
  let stderr = Buffer.alloc(0);
  const failureDeadlineAtMs = Date.now() + failureObservationMs;
  const capture = (chunk) => {
    if (stderr.length >= BOOTSTRAP_STDERR_MAX_BYTES) return;
    const bytes = Buffer.from(chunk);
    stderr = Buffer.concat([
      stderr,
      bytes.subarray(0, BOOTSTRAP_STDERR_MAX_BYTES - stderr.length),
    ]);
  };
  child.stderr?.on("data", capture);
  let initialSettled = false;
  let terminalSettled = false;
  let initialResolve;
  let terminalResolve;
  const initial = new Promise((resolve) => { initialResolve = resolve; });
  const terminal = new Promise((resolve) => { terminalResolve = resolve; });
  let initialTimer = null;
  let failureTimer = null;
  const settleInitial = (value) => {
    if (initialSettled) return;
    initialSettled = true;
    clearTimeout(initialTimer);
    initialResolve(value);
  };
  const cleanup = () => {
    clearTimeout(initialTimer);
    clearTimeout(failureTimer);
    child.off?.("error", onError);
    child.off?.("close", onClose);
    child.stderr?.off?.("data", capture);
    // Keep the detached child's pipe drained without retaining our evidence
    // closure after the bounded discovery window.
    child.stderr?.resume?.();
    child.stderr?.unref?.();
  };
  const settleTerminal = (value) => {
    if (terminalSettled) return;
    if (Date.now() >= failureDeadlineAtMs) {
      expireObservation();
      return;
    }
    terminalSettled = true;
    const outcome = Object.freeze({ ...value, stderr });
    settleInitial(outcome);
    cleanup();
    terminalResolve(outcome);
  };
  const onError = () => settleTerminal({ running: false, spawnError: true, exitCode: null });
  const onClose = (exitCode) => settleTerminal({ running: false, spawnError: false, exitCode });
  const expireObservation = () => {
    if (terminalSettled) return;
    terminalSettled = true;
    settleInitial(Object.freeze({ running: true }));
    stderr.fill(0);
    stderr = Buffer.alloc(0);
    cleanup();
    terminalResolve(null);
  };
  child.once("error", onError);
  child.once("close", onClose);
  initialTimer = setTimeout(() => settleInitial(Object.freeze({ running: true })), observationMs);
  failureTimer = setTimeout(expireObservation, failureObservationMs);
  failureTimer.unref?.();
  return Object.freeze({ initial, terminal });
}

function bootstrapFailureCode(outcome) {
  let parsedCode = null;
  try { parsedCode = parseBootstrapFailureCode(outcome.stderr); }
  finally { outcome.stderr?.fill?.(0); }
  return outcome.spawnError
    ? "neutral_host_launch_failed"
    : parsedCode || (outcome.exitCode === 0 ? "neutral_host_bootstrap_exited" : "neutral_host_bootstrap_failed");
}

function parseBootstrapFailureCode(stderr) {
  const text = Buffer.isBuffer(stderr) ? stderr.toString("utf8") : "";
  for (const line of text.split(/\r?\n/).slice(-8).reverse()) {
    let record;
    try { record = JSON.parse(line); } catch { continue; }
    if (plain(record) && record.ok === false && typeof record.code === "string") {
      return stableBootstrapFailureCode(record.code);
    }
  }
  return null;
}

function stableBootstrapFailureCode(value) {
  const code = String(value || "");
  return SAFE_BOOTSTRAP_FAILURE_CODES.has(code) ? code : "neutral_host_bootstrap_failed";
}

function bootstrapObservationWindows(options) {
  const requestedObservationMs = bounded(options.bootstrapObservationMs, 3_000, 100, 10_000);
  const explicitDeadline = Number(options.bootstrapFailureDeadlineMs);
  let failureObservationMs;
  if (Number.isSafeInteger(explicitDeadline)) {
    failureObservationMs = Math.max(0, Math.min(
      explicitDeadline - Date.now(),
      MAX_BOOTSTRAP_FAILURE_OBSERVATION_MS,
    ));
  } else {
    failureObservationMs = bounded(
      options.bootstrapFailureObservationMs,
      DEFAULT_BOOTSTRAP_FAILURE_OBSERVATION_MS,
      0,
      MAX_BOOTSTRAP_FAILURE_OBSERVATION_MS,
    );
  }
  return Object.freeze({
    observationMs: Math.min(requestedObservationMs, failureObservationMs),
    failureObservationMs,
  });
}

function launchFailurePath(launch) {
  return path.join(
    launch.runtimeRoot,
    "neutral-host",
    `${sha256(`${launch.region}\0${launch.principalId}\0${launch.hostInstallationId}`)}.${launch.adapterId}-launch-failure`,
  );
}

function launchAttemptPath(base) { return `${base}-attempt.json`; }
function launchFailureRecordPath(base, attemptId) { return `${base}.${attemptId}.json`; }

async function beginLaunchFailureAttempt(base, stages = null) {
  const prior = await readLaunchAttempt(base);
  await removeLaunchFile(launchAttemptPath(base));
  if (prior) await removeLaunchFile(launchFailureRecordPath(base, prior.attemptId));
  const attemptId = crypto.randomBytes(16).toString("hex");
  // Stages ride on this one write; no second file or write is added for them.
  await writeAtomicLaunchFile(launchAttemptPath(base), Object.freeze({
    contract: HELLOLYNK_NEUTRAL_HOST_LAUNCH_ATTEMPT_CONTRACT,
    attemptId,
    startedAt: new Date().toISOString(),
    ...(stages ? { stages } : {}),
  }));
  return attemptId;
}

async function writeLaunchFailure(base, attemptId, code) {
  const current = await readLaunchAttempt(base);
  if (current?.attemptId !== attemptId) return null;
  const record = Object.freeze({
    contract: HELLOLYNK_NEUTRAL_HOST_LAUNCH_FAILURE_CONTRACT,
    code: stableBootstrapFailureCode(code),
    observedAt: new Date().toISOString(),
  });
  const target = launchFailureRecordPath(base, attemptId);
  await writeAtomicLaunchFile(target, record);
  const after = await readLaunchAttempt(base);
  if (after?.attemptId !== attemptId) {
    await removeLaunchFile(target);
    return null;
  }
  return record;
}

async function readLaunchFailure(base, expectedAttemptId = null) {
  const before = await readLaunchAttempt(base);
  if (!before || (expectedAttemptId && before.attemptId !== expectedAttemptId)) return null;
  const bytes = await readLaunchFile(launchFailureRecordPath(base, before.attemptId));
  if (!bytes) return null;
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); }
  catch { throw codeError("neutral_host_launch_failure_store_invalid"); }
  if (!plain(record) || !exact(record, ["code", "contract", "observedAt"])
    || record.contract !== HELLOLYNK_NEUTRAL_HOST_LAUNCH_FAILURE_CONTRACT
    || stableBootstrapFailureCode(record.code) !== record.code
    || !Number.isFinite(Date.parse(String(record.observedAt || "")))) {
    throw codeError("neutral_host_launch_failure_store_invalid");
  }
  const after = await readLaunchAttempt(base);
  if (after?.attemptId !== before.attemptId) return null;
  return Object.freeze(structuredClone(record));
}

async function readLaunchAttempt(base) {
  const bytes = await readLaunchFile(launchAttemptPath(base));
  if (!bytes) return null;
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); }
  catch { throw codeError("neutral_host_launch_failure_store_invalid"); }
  if (!plain(record)
    || !(exact(record, ["attemptId", "contract", "startedAt"])
      || (exact(record, ["attemptId", "contract", "stages", "startedAt"]) && validLaunchStages(record.stages)))
    || record.contract !== HELLOLYNK_NEUTRAL_HOST_LAUNCH_ATTEMPT_CONTRACT
    || !/^[a-f0-9]{32}$/.test(String(record.attemptId || ""))
    || !Number.isFinite(Date.parse(String(record.startedAt || "")))) {
    throw codeError("neutral_host_launch_failure_store_invalid");
  }
  return Object.freeze(record);
}

async function readLaunchFile(target) {
  await assertLaunchParent(target);
  let pathMetadata;
  try { pathMetadata = await fs.lstat(target, { bigint: true }); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw codeError("neutral_host_launch_failure_store_failed");
  }
  if (!pathMetadata.isFile() || pathMetadata.isSymbolicLink()
    || pathMetadata.nlink !== 1n || pathMetadata.size > BigInt(LAUNCH_FAILURE_MAX_BYTES)) {
    throw codeError("neutral_host_launch_failure_store_invalid");
  }
  let handle;
  try { handle = await fs.open(target, "r"); }
  catch { throw codeError("neutral_host_launch_failure_store_failed"); }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(LAUNCH_FAILURE_MAX_BYTES)
      || !sameIdentity(pathMetadata, before)) {
      throw codeError("neutral_host_launch_failure_store_invalid");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (bytes.length > LAUNCH_FAILURE_MAX_BYTES || !sameIdentity(before, after)) {
      throw codeError("neutral_host_launch_failure_store_invalid");
    }
    return bytes;
  } finally { await handle.close().catch(() => {}); }
}

async function writeAtomicLaunchFile(target, record) {
  await assertLaunchParent(target);
  await assertLaunchFailureTarget(target);
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
  if (bytes.length > LAUNCH_FAILURE_MAX_BYTES) throw codeError("neutral_host_launch_failure_store_failed");
  const temporary = `${target}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
  } catch {
    await handle?.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw codeError("neutral_host_launch_failure_store_failed");
  }
}

async function removeLaunchFile(target) {
  await assertLaunchParent(target);
  let metadata;
  try { metadata = await fs.lstat(target, { bigint: true }); }
  catch (error) {
    if (error?.code === "ENOENT") return;
    throw codeError("neutral_host_launch_failure_store_failed");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || metadata.nlink !== 1n || metadata.size > BigInt(LAUNCH_FAILURE_MAX_BYTES)) {
    throw codeError("neutral_host_launch_failure_store_invalid");
  }
  try { await fs.unlink(target); }
  catch { throw codeError("neutral_host_launch_failure_store_failed"); }
}

async function assertLaunchParent(target) {
  try { await noReparseAncestors(path.dirname(target)); }
  catch { throw codeError("neutral_host_launch_failure_store_invalid"); }
}

async function assertLaunchFailureTarget(target) {
  let metadata;
  try { metadata = await fs.lstat(target, { bigint: true }); }
  catch (error) {
    if (error?.code === "ENOENT") return;
    throw codeError("neutral_host_launch_failure_store_failed");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || metadata.nlink !== 1n || metadata.size > BigInt(LAUNCH_FAILURE_MAX_BYTES)) {
    throw codeError("neutral_host_launch_failure_store_invalid");
  }
}

async function readSafeFile(file, maximum) {
  await noReparseAncestors(file);
  let handle;
  try { handle = await fs.open(file, "r"); }
  catch { throw codeError("neutral_host_runner_unavailable"); }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!sameIdentity(before, after)) fail();
    return bytes;
  } catch (error) {
    if (/^neutral_host_/.test(String(error?.code || ""))) throw error;
    throw codeError("neutral_host_runner_integrity_invalid");
  } finally { await handle?.close(); }
}

async function noReparseAncestors(target) {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  let cursor = parsed.root;
  for (const segment of path.relative(parsed.root, resolved).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    let metadata;
    try { metadata = await fs.lstat(cursor); }
    catch { throw codeError("neutral_host_runner_unavailable"); }
    if (metadata.isSymbolicLink()) fail();
  }
}

async function safeDirectory(target, create) {
  if (create) await fs.mkdir(target, { recursive: true, mode: 0o700 });
  const metadata = await fs.lstat(target).catch(() => null);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) {
    throw codeError("neutral_host_launch_configuration_required");
  }
}

async function reclaimDeadLock(lockPath) {
  const metadata = await fs.lstat(lockPath);
  let ownerRecord;
  try { ownerRecord = JSON.parse(await fs.readFile(path.join(lockPath, "owner.json"), "utf8")); }
  catch {
    if (Date.now() - metadata.mtimeMs <= 10_000) return false;
    return quarantineStaleLock(lockPath);
  }
  const pid = Number(ownerRecord?.pid);
  if (Date.now() - metadata.mtimeMs <= 10_000
    || (Number.isSafeInteger(pid) && pid > 0 && processAlive(pid))) return false;
  return quarantineStaleLock(lockPath);
}

async function quarantineStaleLock(lockPath) {
  const quarantine = `${lockPath}.stale.${Date.now()}.${crypto.randomBytes(8).toString("hex")}`;
  try { await fs.rename(lockPath, quarantine); }
  catch (error) { if (error?.code === "ENOENT") return false; throw error; }
  await fs.rm(quarantine, { recursive: true, force: true });
  return true;
}

function owner(value) {
  return Object.freeze({
    region: value.region, principalId: value.principalId, delegateId: value.delegateId,
    hostInstallationId: value.hostInstallationId, profileId: value.profileId,
    adapterId: value.adapterId, version: value.version, scopes: value.scopes,
  });
}
function safeId(value) { const text = String(value || ""); if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(text)) fail(); return text; }
function absolute(value) { const text = String(value || ""); if (!path.isAbsolute(text) || path.resolve(text) !== text) fail(); return text; }
function inside(root, target) { const relative = path.relative(path.resolve(root), path.resolve(target)); return Boolean(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); }
function canonicalPath(value) { const result = path.resolve(value); return process.platform === "win32" ? result.toLowerCase() : result; }
function samePath(left, right) { return canonicalPath(left) === canonicalPath(right); }
function sameIdentity(left, right) {
  return left.ino === right.ino
    && (left.dev === right.dev
      || (process.platform === "win32" && (left.dev === 0n || right.dev === 0n)))
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.nlink === right.nlink;
}
function processAlive(pid) { try { process.kill(pid, 0); return true; } catch (error) { return error?.code === "EPERM"; } }
function parseJson(value) { try { return JSON.parse(value); } catch { fail(); } }
// Stages are diagnostics only. On the way in, unknown or unusable values are dropped so
// they can never block a launch; on disk they are validated as strictly as the other fields.
function launchStages(value) {
  if (!plain(value)) return null;
  const stages = {};
  if (isoTimestamp(value.enteredAt)) stages.enteredAt = value.enteredAt;
  for (const field of LAUNCH_STAGE_MS_FIELDS) {
    if (stageMs(value[field])) stages[field] = value[field];
  }
  return Object.keys(stages).length ? Object.freeze(stages) : null;
}
function validLaunchStages(value) {
  if (!plain(value)) return false;
  const keys = Object.keys(value);
  return keys.length > 0
    && keys.every((key) => key === "enteredAt" || LAUNCH_STAGE_MS_FIELDS.includes(key))
    && (!("enteredAt" in value) || isoTimestamp(value.enteredAt))
    && LAUNCH_STAGE_MS_FIELDS.every((field) => !(field in value) || stageMs(value[field]));
}
function isoTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
}
function stageMs(value) { return Number.isSafeInteger(value) && value >= 0 && value <= LAUNCH_STAGE_MAX_MS; }
function exact(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((item, index) => item === wanted[index]); }
function plain(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function bounded(value, fallback, minimum, maximum) { const result = Number(value ?? fallback); return Number.isSafeInteger(result) && result >= minimum && result <= maximum ? result : fallback; }
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function fail() { throw codeError("neutral_host_runner_integrity_invalid"); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
