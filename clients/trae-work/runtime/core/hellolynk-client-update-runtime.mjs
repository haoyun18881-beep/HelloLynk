import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createClientUpdateManager, extractClientUpdateArchive, compareClientUpdateVersions, CLIENT_UPDATE_CLIENTS } from "./hellolynk-client-update.mjs";
import { withNeutralHostStoreLock } from "./hellolynk-neutral-host-installation-store.mjs";
import { readClientAccount } from "./hellolynk-client-account.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { pruneInstalledReleases } from "./hellolynk-release-retention.mjs";

const SELF = fileURLToPath(import.meta.url);
const HASH = /^[a-f0-9]{64}$/;
const VERSION = /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?$/;
const NAMES = { codex: "@hellolynk-ai/codex-plugin", openclaw: "@hellolynk-ai/openclaw-channel", "trae-work": "@hellolynk-ai/trae-work-mcp", workbuddy: "@hellolynk-ai/workbuddy-mcp", dsh: "hellolynk-dsh-local-connect", "claude-code": "@hellolynk-ai/claude-code-mcp" };
const CONTRACT = "hellolynk-client-update-runtime-v1";
const STAGES = ["idle", "applying", "applied", "failed"];
const MAX_LEASES = 128;
// A version gets one automatic retry, and only for failures the machine caused rather than the package.
const RETRYABLE = new Set(["client_update_apply_interrupted", "client_update_setup_failed_previous_preserved", "client_update_native_install_failed_rolled_back", "client_update_installer_timeout", "client_update_lock_timeout"]);
// The retry waits this long after the failure, so a cause that lasts a few minutes (a held file, a virus scan) does not use it up.
const RETRY_AFTER_MS = 10 * 60_000;

// Call after a client's initialize response. Nothing here installs: the promise
// waits only for DSH's lease, and a downloaded update is applied by a worker in
// the background. Checking the network is always detached.
export async function startClientUpdateRuntime(options = {}) {
  if ((options.platform || process.platform) !== "win32") return disabled();
  let config;
  try { config = normalize(options); await verifyInstalledContext(config); }
  catch { return disabled(); }
  const io = createRuntime(config, options);
  const token = crypto.randomBytes(24).toString("hex");
  let stopped = false, timer;
  // DSH replaces files its running Harness has loaded, so its worker waits for every lease. Other clients have none.
  if (config.client === "dsh") {
    await io.gate(async () => {
      const leases = await io.leases();
      leases.push({ pid: process.pid, token, writtenAt: Date.now() });
      await io.writeLeases(leases);
    });
  }
  await io.sweepLockCandidates().catch(() => {});
  async function check({ force = false } = {}) {
    if (stopped) return io.readState();
    const downloaded = await io.manager.check({ force });
    if (downloaded.stage === "downloaded" && downloaded.sha256 && !downloaded.error) await io.ensureWorker();
    return io.readState();
  }
  // Network failures and a pending update must never reject host startup.
  queueMicrotask(() => { void io.ensureWorker().catch(() => {}).then(() => check()).catch(() => {}); });
  timer = setInterval(() => { void check().catch(() => {}); }, 24 * 3_600_000);
  timer.unref?.();
  return Object.freeze({
    disabled: false,
    check,
    readState: io.readState,
    async stop() {
      if (stopped) return;
      stopped = true; clearInterval(timer);
      if (config.client !== "dsh") return;
      await io.gate(async () => { await io.writeLeases((await io.leases()).filter((lease) => lease.token !== token)); });
    },
  });
}

// Exported for bounded integration tests and the hidden worker entry point.
export async function runClientUpdateWorker(options = {}) {
  const config = normalize(options);
  await verifyInstalledContext(config);
  const io = createRuntime(config, options);
  // Only DSH waits: its files are replaced under a running Harness. Every other client installs at once.
  const waits = config.client === "dsh";
  const deadline = Date.now() + (options.workerLifetimeMs || 24 * 3_600_000);
  while (Date.now() < deadline) {
    let result;
    try {
      result = await io.gate(async () => {
        if (waits && (await io.leases()).length) return null;
        return (await io.applyPending()) || { done: true };
      });
    } catch (error) {
      if (error?.code !== "client_update_lock_timeout") throw error;
      await io.recordLockTimeout().catch(() => {});
      return { ok: false };
    }
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, options.workerPollMs || 2_000));
  }
  return { deferred: true };
}

function createRuntime(config, options) {
  const { root, client, currentVersion, installContext } = config;
  const directory = path.join(root, "client-updates", client);
  const statePath = path.join(directory, "runtime.json"), leasePath = path.join(directory, "leases.json"), installedPath = path.join(directory, "installed.json");
  const manager = createClientUpdateManager({ ...options, root, client, currentVersion });
  const alive = options.isProcessAlive || processAlive;
  async function gate(operation) {
    await safeDirectory(directory);
    // An installation can take longer than the shared lock's single wait. Keep
    // waiting locally instead of starting an old binding during its commit.
    const attempts = options.lockAttempts || 36;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try { return await withNeutralHostStoreLock(directory, "update-apply", operation); }
      catch (error) {
        if (error?.code !== "host_registry_lock_timeout") throw error;
        if (attempt === attempts - 1) throw failure("lock_timeout");
      }
    }
  }
  async function readRuntime() {
    const idle = { contract: CONTRACT, client, stage: "idle" };
    let value;
    try { value = await readJson(statePath, null); }
    catch (error) { if (!damaged(error)) throw error; return idle; }
    // A damaged record starts over; the next attempt overwrites it.
    if (value == null || value.contract !== CONTRACT || value.client !== client || !STAGES.includes(value.stage)
      || (value.sha256 != null && !HASH.test(value.sha256)) || (value.retried != null && typeof value.retried !== "boolean")) return idle;
    return value;
  }
  async function readState() {
    const [downloaded, runtime] = await Promise.all([manager.readState(), readRuntime()]);
    const relevant = runtime.sha256 && runtime.sha256 === downloaded.sha256;
    return Object.freeze({ ...downloaded, ...(relevant ? runtime : {}), client, downloadStage: downloaded.stage });
  }
  // Leases exist for DSH alone. Dead processes drop out first, a lease written
  // before the machine booted is stale, and the file never holds more than
  // MAX_LEASES. A file in any other shape is discarded and written afresh.
  async function leases() {
    let value;
    try { value = await readJson(leasePath, null); }
    catch (error) { if (!damaged(error)) throw error; return []; }
    if (value?.contract !== CONTRACT || value.client !== client || !Array.isArray(value.leases)
      || value.leases.some((lease) => !Number.isSafeInteger(lease?.pid) || lease.pid <= 0 || !/^[a-f0-9]{48}$/.test(lease.token)
        || !Number.isFinite(lease.writtenAt))) return [];
    const booted = Date.now() - os.uptime() * 1000;
    return value.leases.filter((lease) => lease.writtenAt >= booted && alive(lease.pid)).slice(-MAX_LEASES);
  }
  async function writeLeases(value) { await atomicJson(leasePath, { contract: CONTRACT, client, leases: value.slice(-MAX_LEASES) }); }
  function isReleaseRoot(value) {
    return typeof value === "string" && path.dirname(value) === path.join(path.dirname(root), "releases")
      && new RegExp(`^${client}-[a-f0-9]{64}$`).test(path.basename(value));
  }
  // A later run for an artifact already installed verifies that release and reports it again.
  async function installedRelease(previous, downloaded) {
    const next = previous.nextPackageRoot;
    if (!isReleaseRoot(next)) throw failure("state_invalid");
    if (!options.runInstaller) await verifyPackage(next, client, downloaded.version);
    return { ok: true, nextPackageRoot: next };
  }
  // A process that stays open keeps the code it started with while its updater installs newer
  // releases. Newest first: the release this updater installed last, when it is newer than the
  // startup one and older than the next, then the startup one.
  async function knownInstalls(nextVersion) {
    const startup = { currentVersion, installContext };
    const record = await readJson(installedPath, null).catch(() => null);
    if (record?.contract !== CONTRACT || record.client !== client || !VERSION.test(String(record.version)) || !isReleaseRoot(record.packageRoot)
      || compareClientUpdateVersions(record.version, currentVersion) <= 0 || compareClientUpdateVersions(nextVersion, record.version) <= 0) return [startup];
    return [{ currentVersion: record.version, installContext: { ...installContext, packageRoot: record.packageRoot } }, startup];
  }
  // DSH installs only after every DSH process has exited, so its next worker always starts from
  // the current install. A record that could not be written only means the startup one is tried.
  async function recordInstalled(version, packageRoot) {
    if (client === "dsh") return;
    await atomicJson(installedPath, { contract: CONTRACT, client, version, packageRoot }).catch(() => {});
  }
  // A crashed lock attempt leaves its candidate file behind. Sweep only this
  // updater's two locks, only after an hour, and only once its process is gone.
  async function sweepLockCandidates() {
    await safePath(directory);
    let names;
    try { names = await fs.readdir(directory); } catch (error) { if (error.code === "ENOENT") return; throw error; }
    for (const name of names) {
      const owner = /^\.(?:update-apply|client-update)\.lock\.candidate\.(\d+)\.[a-f0-9]{16}$/.exec(name);
      if (!owner || alive(Number(owner[1]))) continue;
      const file = path.join(directory, name), stat = await fs.lstat(file);
      if (stat.isFile() && Date.now() - stat.mtimeMs > 3_600_000) await fs.rm(file, { force: true });
    }
  }
  // Giving up on the lock is an environment failure and counts as an attempt,
  // unless another process is still installing this very package.
  async function recordLockTimeout() {
    const downloaded = await manager.readState(), previous = await readRuntime();
    if (downloaded.stage !== "downloaded" || downloaded.error || !HASH.test(String(downloaded.sha256 || ""))) return;
    const same = previous.sha256 === downloaded.sha256;
    if (same && !(previous.stage === "failed" && previous.retried !== true && RETRYABLE.has(previous.error))) return;
    await atomicJson(statePath, { contract: CONTRACT, client, stage: "failed", version: downloaded.version, sha256: downloaded.sha256,
      error: "client_update_lock_timeout", attemptedAt: Date.now(), ...(same ? { retried: true } : {}) });
  }
  // After a good install the update cache keeps only the downloaded package. Cleanup never undoes an install.
  async function tidyCache() { try { await manager.prune(); } catch { /* best effort */ } }
  async function ensureWorker() {
    return gate(async () => {
      const downloaded = await manager.readState(), runtime = await readRuntime();
      // One recorded attempt per version, plus one retry of a failure the machine caused.
      const retryable = runtime.stage === "failed" && runtime.retried !== true && RETRYABLE.has(runtime.error)
        && !(Number.isFinite(runtime.attemptedAt) && Date.now() >= runtime.attemptedAt && Date.now() - runtime.attemptedAt < RETRY_AFTER_MS);
      const attempted = runtime.sha256 === downloaded.sha256 && !(runtime.stage === "applying" || retryable);
      if (downloaded.stage !== "downloaded" || downloaded.error || attempted) return;
      // A damaged worker record means no known worker.
      const worker = await readJson(path.join(directory, "worker.json"), null).catch((error) => { if (!damaged(error)) throw error; return null; });
      if (worker?.client === client && Number.isSafeInteger(worker.pid) && alive(worker.pid)) return;
      const launch = options.spawnWorker || launchWorker;
      let pid;
      try {
        pid = await launch(config);
        if (!Number.isSafeInteger(pid) || pid <= 0) throw failure("worker_launch_failed");
      } catch (error) {
        // Retain only this rejected launch attempt, not raw errors or proof of
        // worker absence. Keep an earlier PID's conservative liveness check.
        await atomicJson(path.join(directory, "worker.json"), { client,
          ...(worker?.client === client && Number.isSafeInteger(worker.pid) ? { pid: worker.pid } : {}),
          sha256: downloaded.sha256, error: "client_update_worker_launch_failed", failedAt: Date.now(),
        }).catch(() => {});
        throw error;
      }
      await atomicJson(path.join(directory, "worker.json"), { client, pid });
    });
  }
  async function applyPending() {
    const downloaded = await manager.readState();
    if (!["downloaded", "current"].includes(downloaded.stage) || !downloaded.version || !HASH.test(String(downloaded.sha256 || "")) || downloaded.error) return null;
    let previous = await readRuntime();
    // The startup install until the doctor below proves which install this attempt starts from.
    let { currentVersion, installContext } = config;
    const versionOrder = compareClientUpdateVersions(downloaded.version, currentVersion);
    if (versionOrder < 0) return null;
    if (versionOrder === 0) {
      if (previous.sha256 === downloaded.sha256 && ["applying", "failed"].includes(previous.stage)) {
        let proof;
        try {
          proof = await prepareCandidate(config, downloaded);
          await verifyPackage(installContext.packageRoot, client, currentVersion);
          if (sha(await safeFile(path.join(proof.packageRoot, "hellolynk-client-pack-manifest.json")))
            !== sha(await safeFile(path.join(installContext.packageRoot, "hellolynk-client-pack-manifest.json")))) throw failure("adoption_invalid");
          const doctor = await (options.runInstaller || runInstaller)({ executable: installContext.nodePath || process.execPath,
            args: [path.join(installContext.packageRoot, "bin", "hellolynk-client-setup.mjs"), "doctor"], cwd: installContext.packageRoot, root, timeoutMs: 180_000 });
          if (!doctorProves(doctor, client, currentVersion)) throw failure("adoption_invalid");
          const adoptedRoot = path.join(path.dirname(root), "releases", `${client}-${sha(await safeFile(path.join(proof.packageRoot, "hellolynk-client-pack-manifest.json")))}`);
          if (!options.runInstaller) await verifyPackage(adoptedRoot, client, currentVersion);
          await recordInstalled(currentVersion, adoptedRoot);
          await atomicJson(statePath, { ...previous, stage: "applied", nextPackageRoot: adoptedRoot, appliedAt: Date.now(), error: null });
          await pruneInstalledReleases({ releasesRoot: path.dirname(adoptedRoot), client,
            currentRelease: adoptedRoot, previousRelease: previous.previousPackageRoot || null });
          await tidyCache();
        } catch { /* Unproven commits remain unavailable, never reported as success. */ }
        finally { if (proof) await fs.rm(proof.temporaryRoot, { recursive: true, force: true }); }
      }
      return null;
    }
    const retrying = previous.sha256 === downloaded.sha256;
    if (retrying) {
      if (previous.stage === "applied") return installedRelease(previous, downloaded);
      if (previous.stage === "applying") {
        previous = { ...previous, stage: "failed", error: "client_update_apply_interrupted" };
        await atomicJson(statePath, previous);
      }
      // One more attempt for a failure the machine caused; never for the package itself.
      if (previous.stage !== "failed" || previous.retried === true || !RETRYABLE.has(previous.error)) return null;
      if (Number.isFinite(previous.attemptedAt) && Date.now() >= previous.attemptedAt && Date.now() - previous.attemptedAt < RETRY_AFTER_MS) return null;
    }
    if (client === "dsh" && (!installContext.dshProfile || !installContext.dshRoot || !installContext.expectedInstalledManifestSha256)) return null;
    let expectedAccountRevision;
    try {
      const account = readClientAccount(client, root);
      if (account.phase !== "ready") return null;
      expectedAccountRevision = account.revision;
    } catch { return null; }
    let candidate, rollbackRoot = null, previousImmutableRoot = null, bindingCommitted = false, nativeCommitted = false, nativeRecoveryAllowed = true;
    const run = options.runInstaller || runInstaller;
    const doctorAt = async (packageRoot, version) => {
      try {
        await verifyPackage(packageRoot, client, version);
        const inspected = await run({ executable: installContext.nodePath || process.execPath,
          args: [path.join(packageRoot, "bin", "hellolynk-client-setup.mjs"), "doctor"], cwd: packageRoot, root, timeoutMs: 180_000 });
        return doctorProves(inspected, client, version);
      } catch { return false; }
    };
    // Packages can be loaded before first enrollment. Do not consume this
    // artifact's one installation attempt until the existing account/binding
    // and client configuration are independently ready. The binding names the
    // release installed last, or the startup one after a reinstall by hand.
    let proven = null;
    for (const install of await knownInstalls(downloaded.version)) {
      if (await doctorAt(install.installContext.packageRoot, install.currentVersion)) { proven = install; break; }
    }
    if (!proven) return null;
    ({ currentVersion, installContext } = proven);
    try {
      candidate = await prepareCandidate(config, downloaded);
      previousImmutableRoot = path.join(path.dirname(root), "releases", `${client}-${sha(await safeFile(path.join(installContext.packageRoot, "hellolynk-client-pack-manifest.json")))}`);
      if (client === "dsh") {
        await verifyPackage(installContext.packageRoot, client, currentVersion);
        rollbackRoot = path.join(candidate.temporaryRoot, "rollback");
        await fs.cp(installContext.packageRoot, rollbackRoot, { recursive: true, force: false, errorOnExist: true });
        await verifyPackage(rollbackRoot, client, currentVersion);
        previousImmutableRoot = path.join(path.dirname(root), "releases", `${client}-${sha(await safeFile(path.join(rollbackRoot, "hellolynk-client-pack-manifest.json")))}`);
        if (!options.runInstaller) await verifyPackage(previousImmutableRoot, client, currentVersion);
      }
      await atomicJson(statePath, { contract: CONTRACT, client, stage: "applying", version: downloaded.version, sha256: downloaded.sha256, previousPackageRoot: previousImmutableRoot, attemptedAt: Date.now(), ...(retrying ? { retried: true } : {}) });
      const packManifest = await safeFile(path.join(candidate.packageRoot, "hellolynk-client-pack-manifest.json"));
      const nextPackageRoot = path.join(path.dirname(root), "releases", `${client}-${sha(packManifest)}`);
      try {
        const installed = await run({ executable: installContext.nodePath || process.execPath,
          args: [candidate.setupPath, "setup", "--defer-release-cleanup"], cwd: candidate.packageRoot, root, timeoutMs: 180_000 });
        if (installed?.ok !== true || installed.client !== client || installed.packageVersion !== downloaded.version) throw failure("install_result_invalid");
        if (!options.runInstaller) await verifyPackage(nextPackageRoot, client, downloaded.version);
      } catch {
        // An exit code, missing stdout or timeout is not evidence of rollback.
        // Inspect actual binding AND client configuration before deciding. These
        // reads never overwrite a concurrent human change to a third release.
        if (await doctorAt(candidate.packageRoot, downloaded.version)) {
          if (!options.runInstaller) await verifyPackage(nextPackageRoot, client, downloaded.version);
        } else if (await doctorAt(rollbackRoot || installContext.packageRoot, currentVersion)) {
          throw failure("setup_failed_previous_preserved");
        } else {
          throw failure("setup_recovery_required");
        }
      }
      bindingCommitted = true;
      if (client === "dsh") {
        const request = { executable: installContext.nodePath || process.execPath,
          args: [path.join(candidate.extractedRoot, "scripts", "install.mjs"), "--upgrade", "--profile", installContext.dshProfile,
            "--dsh-root", installContext.dshRoot, "--expected-installed-manifest-sha256", installContext.expectedInstalledManifestSha256, "--live-profile"],
          cwd: candidate.extractedRoot, root, timeoutMs: 180_000 };
        nativeRecoveryAllowed = false;
        try {
          const result = await run({ ...request, args: [...request.args, "--apply"] });
          if (result?.ok !== true || (result.upgraded !== true && result.alreadyCurrent !== true)) throw failure("native_install_failed");
          nativeCommitted = true;
        } catch {
          // DSH may commit its outer tree before stdout is lost. Its existing
          // read-only upgrade preflight verifies the installed tree and journal.
          // Only a proven old outer tree permits reverting the new binding.
          try {
            const inspected = await run(request);
            if (inspected?.ok !== true || inspected.plannedMutation !== "upgrade"
              || !await samePath(inspected.profile, installContext.dshProfile) || !await samePath(inspected.dshRoot, installContext.dshRoot)
              || typeof inspected.alreadyCurrent !== "boolean") throw failure("native_recovery_required");
            if (inspected.alreadyCurrent) nativeCommitted = true;
            else {
              const installedManifest = await safeFile(path.join(installContext.dshProfile, "node_modules", "hellolynk-dsh-nav", "hellolynk-dsh-nav-build.json"));
              if (sha(installedManifest) !== installContext.expectedInstalledManifestSha256) throw failure("native_recovery_required");
              nativeRecoveryAllowed = true;
            }
          } catch { throw failure("native_recovery_required"); }
          if (!nativeCommitted) throw failure("native_install_failed");
        }
      }
      // setup owns the immutable install and protected binding. Never report
      // applied on the strength of an installer stdout string alone.
      await recordInstalled(downloaded.version, nextPackageRoot);
      const state = { contract: CONTRACT, client, stage: "applied", version: downloaded.version,
        sha256: downloaded.sha256, appliedAt: Date.now(), nextPackageRoot, previousPackageRoot: previousImmutableRoot, error: null };
      await atomicJson(statePath, state);
      const releaseCleanup = await pruneInstalledReleases({ releasesRoot: path.dirname(nextPackageRoot), client,
        currentRelease: nextPackageRoot, previousRelease: previousImmutableRoot });
      await tidyCache();
      return { ok: true, nextPackageRoot, releaseCleanup };
    } catch (error) {
      if (rollbackRoot && bindingCommitted && !nativeCommitted && nativeRecoveryAllowed) {
        try {
          const releasePin = await readJson(path.join(candidate.packageRoot, "runtime", "neutral-host-release-pin.json"));
          if (!HASH.test(String(releasePin.manifestSha256 || ""))) throw failure("rollback_failed");
          // Recovery is performed by the NEW trusted setup under its account
          // lock. Its exact-current binding CAS must reject a human switch to
          // any third release between native installation and recovery.
          const restored = await run({ executable: installContext.nodePath || process.execPath,
            args: [candidate.setupPath, "setup", "--recover-previous-root", previousImmutableRoot,
              "--expected-current-release-manifest-sha256", releasePin.manifestSha256,
              "--expected-account-revision", expectedAccountRevision], cwd: candidate.packageRoot, root, timeoutMs: 180_000 });
          if (restored?.ok !== true || restored.client !== client || restored.recovered !== true
            || restored.restoredPackageVersion !== currentVersion) throw failure("rollback_failed");
          error = failure("native_install_failed_rolled_back");
        } catch {
          // Recovery itself may have committed before losing stdout. Adopt a
          // fully verified old pair; otherwise retain the explicit uncertainty.
          error = failure(await doctorAt(rollbackRoot, currentVersion)
            ? "native_install_failed_rolled_back" : "native_recovery_required");
        }
      }
      await atomicJson(statePath, { contract: CONTRACT, client, stage: "failed", version: downloaded.version, sha256: downloaded.sha256,
        error: /^client_update_[a-z_]+$/.test(error?.code || "") ? error.code : "client_update_apply_failed", attemptedAt: Date.now(),
        ...(retrying ? { retried: true } : {}) });
      return { ok: false };
    } finally { if (candidate?.temporaryRoot) await fs.rm(candidate.temporaryRoot, { recursive: true, force: true }); }
  }
  return { gate, manager, readState, leases, writeLeases, sweepLockCandidates, recordLockTimeout, ensureWorker, applyPending };
}

export async function prepareClientUpdateCandidate(config, record) { return prepareCandidate(normalize(config), record); }
// An installer checks its release the way this updater will before recording it.
export async function verifyClientUpdatePackage(root, client, version) { return verifyPackage(root, client, version); }
async function prepareCandidate(config, record) {
  const directory = path.join(config.root, "client-updates", config.client);
  if (!HASH.test(record.sha256) || typeof record.version !== "string" || !/^[0-9A-Za-z.+-]{1,100}$/.test(record.version)
    || typeof record.filename !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$/.test(record.filename)) throw failure("candidate_invalid");
  const artifactPath = path.join(directory, "releases", `${record.version}-${record.sha256}`, record.filename);
  if (artifactPath !== record.artifactPath) throw failure("candidate_path_invalid");
  const archive = await safeFile(artifactPath, 64 * 1024 * 1024);
  if (archive.length !== record.bytes || sha(archive) !== record.sha256) throw failure("artifact_integrity_invalid");
  const temporaryRoot = path.join(directory, `.apply-${crypto.randomUUID()}`);
  await fs.mkdir(temporaryRoot, { mode: 0o700 });
  const extractedRoot = path.join(temporaryRoot, "extracted");
  try {
    // Re-extract the hash-verified archive; never execute a mutable earlier
    // extractedRoot or an executable path supplied by state.json.
    const sealed = path.join(temporaryRoot, record.filename);
    await fs.writeFile(sealed, archive, { flag: "wx", mode: 0o600 });
    await extractClientUpdateArchive({ archivePath: sealed, destination: extractedRoot });
    let packageRoot;
    if (config.client === "dsh") {
      const descriptor = await readJson(path.join(extractedRoot, "trusted-release.json"));
      const manifestBytes = await safeFile(path.join(extractedRoot, "dist", "package", "hellolynk-dsh-nav-build.json"));
      if (descriptor?.contract !== "hellolynk-dsh-nav-release-v1" || descriptor.manifestSha256 !== sha(manifestBytes)) throw failure("package_pin_invalid");
      const manifest = JSON.parse(manifestBytes.toString("utf8"));
      if (manifest.contract !== "hellolynk-dsh-nav-build-v3") throw failure("package_pin_invalid");
      await verifyRecords(path.join(extractedRoot, "dist", "package"), manifest.packageFiles, ["hellolynk-dsh-nav-build.json"]);
      packageRoot = path.join(extractedRoot, "dist", "package", "runtime", "connect");
      await safeFile(path.join(extractedRoot, "scripts", "install.mjs"));
    } else {
      const candidates = [extractedRoot, path.join(extractedRoot, "package"), path.join(extractedRoot, `hellolynk-${config.client}-${record.version}`, "package")];
      const matches = [];
      for (const candidate of candidates) if (await exists(path.join(candidate, "package.json"))) matches.push(candidate);
      if (matches.length !== 1) throw failure("package_identity_invalid");
      packageRoot = matches[0];
    }
    await verifyPackage(packageRoot, config.client, record.version);
    return { temporaryRoot, extractedRoot, artifactPath: sealed, packageRoot, setupPath: path.join(packageRoot, "bin", "hellolynk-client-setup.mjs") };
  } catch (error) { await fs.rm(temporaryRoot, { recursive: true, force: true }); throw error; }
}

async function verifyPackage(root, client, version) {
  const pkg = await readJson(path.join(root, "package.json"));
  const manifestBytes = await safeFile(path.join(root, "hellolynk-client-pack-manifest.json"));
  const pin = await readJson(path.join(root, "hellolynk-client-pack-pin.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (pkg.version !== version || pkg.hellolynkClient?.client !== client || pkg.name !== NAMES[client]
    || manifest.contract !== "hellolynk-client-npm-pack-manifest-v1" || manifest.client !== client
    || manifest.packageName !== pkg.name || manifest.version !== version
    || pin.contract !== "hellolynk-client-npm-pack-pin-v1" || pin.manifestSha256 !== sha(manifestBytes)) throw failure("package_identity_invalid");
  await verifyRecords(root, manifest.files, ["hellolynk-client-pack-manifest.json", "hellolynk-client-pack-pin.json"]);
  if (!manifest.files.some((file) => file.path === "bin/hellolynk-client-setup.mjs")) throw failure("package_pin_invalid");
}
async function verifyRecords(root, records, allowedExtra) {
  if (!Array.isArray(records) || records.length < 1 || records.length > 5000) throw failure("package_pin_invalid");
  const expected = new Set(allowedExtra);
  for (const record of records) {
    if (!record || typeof record.path !== "string" || !/^(?:[A-Za-z0-9_.@-]+\/)*[A-Za-z0-9_.@-]+$/.test(record.path)
      || record.path.split("/").some((part) => part === "." || part === "..") || !HASH.test(record.sha256) || expected.has(record.path)) throw failure("package_pin_invalid");
    const body = await safeFile(path.join(root, ...record.path.split("/")), 32 * 1024 * 1024);
    if (sha(body) !== record.sha256 || (record.bytes != null && body.length !== record.bytes)) throw failure("package_pin_invalid");
    expected.add(record.path);
  }
  async function visit(directory, relative = "") {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) throw failure("package_pin_invalid");
      if (entry.isDirectory()) await visit(path.join(directory, entry.name), name);
      else if (!expected.delete(name)) throw failure("package_pin_invalid");
    }
  }
  await visit(root);
  if (expected.size) throw failure("package_pin_invalid");
}

async function verifyInstalledContext(config) {
  const context = config.installContext;
  await verifyPackage(context.packageRoot, config.client, config.currentVersion);
}
function normalize(value) {
  if (!CLIENT_UPDATE_CLIENTS.includes(value.client) || typeof value.currentVersion !== "string" || !VERSION.test(value.currentVersion)
    || !path.isAbsolute(String(value.root || "")) || !path.isAbsolute(String(value.installContext?.packageRoot || ""))) throw failure("configuration_invalid");
  const context = { packageRoot: path.resolve(value.installContext.packageRoot) };
  for (const name of ["nodePath", "dshProfile", "dshRoot"]) {
    if (value.installContext[name] != null) {
      if (!path.isAbsolute(value.installContext[name])) throw failure("configuration_invalid");
      context[name] = path.resolve(value.installContext[name]);
    }
  }
  if (value.installContext.expectedInstalledManifestSha256 != null) {
    if (!HASH.test(value.installContext.expectedInstalledManifestSha256)) throw failure("configuration_invalid");
    context.expectedInstalledManifestSha256 = value.installContext.expectedInstalledManifestSha256;
  }
  return { root: path.resolve(value.root), client: value.client, currentVersion: value.currentVersion, installContext: context };
}
async function launchWorker(config) {
  // A host may execute this module from an ephemeral captured import graph.
  // The detached updater must outlive that graph and use the pinned release.
  const packageRoot = config.installContext.packageRoot;
  const metadata = await readJson(path.join(packageRoot, "package.json"));
  const coreRoot = metadata.hellolynkClient?.coreRoot;
  if (typeof coreRoot !== "string" || !/^(?:[A-Za-z0-9_.@-]+\/)*[A-Za-z0-9_.@-]+$/.test(coreRoot)
    || coreRoot.split("/").some((part) => part === "." || part === "..")) throw failure("configuration_invalid");
  const workerEntry = path.join(packageRoot, ...coreRoot.split("/"), "hellolynk-client-update-runtime.mjs");
  await safeFile(workerEntry);
  const executable = await runtimeSafety.resolveHelloLynkStandaloneNode({ preferredExecutable: config.installContext.nodePath });
  const workerConfig = { ...config, installContext: { ...config.installContext, nodePath: executable } };
  const child = spawn(executable, [workerEntry, "--worker", JSON.stringify(workerConfig)], {
    // Keep the detached worker out of the client's installation directory.
    cwd: config.root,
    detached: true, windowsHide: true, stdio: "ignore", shell: false,
    env: runtimeSafety.standaloneHelloLynkNodeEnvironment(process.env),
  });
  await new Promise((resolve, reject) => { child.once("spawn", resolve); child.once("error", reject); });
  child.unref(); return child.pid;
}
async function runInstaller({ executable, args, cwd, root, timeoutMs }) {
  executable = await runtimeSafety.resolveHelloLynkStandaloneNode({ preferredExecutable: executable });
  const env = { ...runtimeSafety.standaloneHelloLynkNodeEnvironment(process.env), HELLOLYNK_NEUTRAL_STORE_ROOT: root };
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], shell: false });
    let stdout = "", stderr = "", finished = false, terminalError = null;
    const timer = setTimeout(() => terminate(failure("installer_timeout")), timeoutMs);
    function finish(error, value) { if (finished) return; finished = true; clearTimeout(timer); error ? reject(error) : resolve(value); }
    function terminate(error) {
      if (finished || terminalError) return;
      terminalError = error;
      // A setup process owns synchronous configurator children. Stop that tree
      // and wait for exit before a doctor can classify the resulting state.
      const killChild = () => { try { child.kill(); } catch {} };
      if (process.platform === "win32" && child.pid) {
        try {
          const killer = spawn(path.join(process.env.SystemRoot || "C:\\Windows", "System32", "taskkill.exe"),
            ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, shell: false, stdio: "ignore" });
          const killTimer = setTimeout(() => { try { killer.kill(); } catch {} if (!finished) killChild(); }, 10_000);
          killer.on("error", () => { clearTimeout(killTimer); if (!finished) killChild(); });
          killer.once("close", () => { clearTimeout(killTimer); if (!finished) killChild(); });
        } catch { killChild(); }
      } else killChild();
    }
    child.on("error", () => {
      // An error raised while terminating is not an exit receipt. Keep the
      // ownership fence until close, and retain the original failure reason.
      if (!terminalError) finish(failure("installer_timeout"));
    });
    child.stdout.on("data", (data) => {
      if (finished || terminalError) return;
      if (stdout.length + data.length > 64 * 1024) { terminate(failure("install_output_invalid")); return; }
      stdout += data;
    });
    child.stderr.on("data", (data) => { stderr = (stderr + data).slice(-16 * 1024); });
    child.once("close", (code) => {
      if (terminalError) { finish(terminalError); return; }
      if (code !== 0) { finish(failure("install_failed")); return; }
      try { finish(null, JSON.parse(stdout)); } catch { finish(failure("install_output_invalid")); }
    });
  });
}
async function readJson(file, fallback) {
  try { return JSON.parse((await safeFile(file)).toString("utf8")); }
  catch (error) { if (error.code === "ENOENT" && arguments.length > 1) return fallback; throw error; }
}
async function safeFile(file, maxBytes = 2 * 1024 * 1024) {
  await safePath(file);
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes) throw failure("path_invalid");
  return fs.readFile(file);
}
async function safePath(target) {
  let current = path.resolve(target);
  while (current !== path.dirname(current)) {
    try { if ((await fs.lstat(current)).isSymbolicLink()) throw failure("path_invalid"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    current = path.dirname(current);
  }
}
async function safeDirectory(directory) { await safePath(directory); await fs.mkdir(directory, { recursive: true, mode: 0o700 }); await safePath(directory); }
async function atomicJson(file, value) {
  await safePath(file);
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try { await fs.writeFile(temporary, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o600 }); await fs.rename(temporary, file); }
  finally { await fs.rm(temporary, { force: true }); }
}
function processAlive(pid) { try { process.kill(pid, 0); return true; } catch (error) { return error.code !== "ESRCH"; } }
// A record in a shape this version cannot read is replaced, not repaired.
function damaged(error) { return error instanceof SyntaxError || error?.code === "client_update_path_invalid"; }
// Windows paths compare case-insensitively and may differ by a link or short name.
async function samePath(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || !path.isAbsolute(left) || !path.isAbsolute(right)) return false;
  const same = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
  if (same(left, right)) return true;
  try { return same(await fs.realpath(left), await fs.realpath(right)); } catch { return false; }
}
async function exists(file) { try { await fs.lstat(file); return true; } catch (error) { if (error.code === "ENOENT") return false; throw error; } }
function sha(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function doctorProves(value, client, version) {
  return value?.ok === true && value.client === client && value.packageVersion === version
    && value.activated === true && value.stableReleaseVerified === true
    && value.exactBindingVerified === true && value.clientConfigurationVerified === true;
}
function failure(code) { return Object.assign(new Error(`client_update_${code}`), { code: `client_update_${code}` }); }
function disabled() { return Object.freeze({ disabled: true, check: async () => ({ stage: "disabled" }), readState: async () => ({ stage: "disabled" }), stop: async () => {} }); }

if (process.argv[1] && path.resolve(process.argv[1]) === SELF && process.argv[2] === "--worker") {
  Promise.resolve().then(() => JSON.parse(process.argv[3] || "{}"))
    .then((options) => runClientUpdateWorker(options)).catch(() => { process.exitCode = 1; });
}
