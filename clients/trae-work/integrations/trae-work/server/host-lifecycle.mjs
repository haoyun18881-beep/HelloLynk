import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { launchPinnedNeutralHostBootstrap } from "../../../runtime/core/hellolynk-neutral-host-launcher.mjs";

const RUNNER_RELATIVE = "runtime/neutral-host-bootstrap.mjs";
const LOCK_STALE_MS = 10_000;
const SAFE_RELATIVE = /^(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*\.(?:cjs|mjs|ps1)$/;
// The TRAE server entry points are part of the pinned closure. Shared Workbench
// runtime modules are pinned separately by REQUIRED_RUNTIME_RECORDS below.
const REQUIRED_RELEASE_RECORDS = Object.freeze([
  "release/integrations/trae-work/package.json",
  "release/integrations/trae-work/server/trae-neutral-production.mjs", "release/integrations/trae-work/server/mcp-proxy.mjs",
  "release/integrations/trae-work/server/mcp-server.mjs", "release/integrations/trae-work/server/neutral-host-adapter.mjs",
  "release/integrations/trae-work/server/dynamic-ui-contract.mjs",
  "release/integrations/trae-work/server/ui-action-gate.mjs", "release/integrations/trae-work/server/host-lifecycle.mjs",
  "release/integrations/trae-work/server/trae-ui-launch.mjs",
  "release/integrations/trae-work/server/native-task-cdp.mjs", "release/integrations/trae-work/server/native-task-worker.mjs",
  "release/integrations/trae-work/skills/hellolynk-inbox/SKILL.md",
]);
const REQUIRED_RUNTIME_RECORDS = Object.freeze([
  "neutral-host-bootstrap.mjs", "neutral-host-release-loader.mjs", "neutral-host-release-entry.mjs",
  "bootstrap/core/hellolynk-host-protected-store.mjs", "bootstrap/core/hellolynk-neutral-host-installation-store.mjs",
  "bootstrap/core/hellolynk-host-auth.mjs", "bootstrap/core/hellolynk-client-profile.mjs",
  "bootstrap/core/hellolynk-platform-credential-store.mjs", "bootstrap/core/hellolynk-client-core.mjs",
  "bootstrap/platform/windows/hellolynk-host-protected-store.ps1",
  "core/hellolynk-local-data-migration.mjs", "core/hellolynk-local-data-protection.mjs",
  "core/hellolynk-local-identity-trust.mjs",
  "core/hellolynk-neutral-host-workbench-read-model.mjs",
  "core/hellolynk-native-worker-lease.mjs",
  "core/hellolynk-workbench-action-grants.mjs",
  "platform/windows/hellolynk-local-data-key.ps1", "workbench/contract.mjs",
  "workbench/candidate-bootstrap.mjs",
]);

export async function launchTraeWorkNeutralHost(binding, options = {}) {
  const launch = normalizeLaunchBinding(binding, options);
  await verifyPinnedBootstrap(launch);
  const lockPath = path.join(launch.runtimeRoot, "neutral-host", `${tupleDigest(launch)}.trae-work-launch.lock`);
  await ensureSafeDirectory(launch.runtimeRoot, true); await ensureSafeDirectory(path.dirname(lockPath), true);
  const wait = options.wait || delay; const deadline = Date.now() + bounded(options.lockTimeoutMs, 15_000, 500, 60_000);
  let ownsLock = false;
  while (Date.now() < deadline) {
    try {
      await fs.mkdir(lockPath, { mode: 0o700 });
      await fs.writeFile(path.join(lockPath, "owner.json"), `${JSON.stringify({ contract: "hellolynk-trae-work-host-launch-lock-v1", pid: process.pid, createdAtMs: Date.now() })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
      ownsLock = true; break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw codeError("neutral_trae_work_launch_failed");
      await ensureSafeDirectory(lockPath, false); await reclaimDeadLock(lockPath).catch(() => false); await wait(50);
    }
  }
  if (!ownsLock) throw codeError("neutral_trae_work_launch_lock_timeout");
  try {
    await launchPinnedNeutralHostBootstrap(launch, {
      storeRoot: launch.storeRoot,
      ...(options.spawnRunner ? { spawnRunner: options.spawnRunner } : {}),
      ...(options.bootstrapObservationMs !== undefined ? { bootstrapObservationMs: options.bootstrapObservationMs } : {}),
      ...(options.bootstrapFailureObservationMs !== undefined ? { bootstrapFailureObservationMs: options.bootstrapFailureObservationMs } : {}),
      ...(options.bootstrapFailureDeadlineMs !== undefined ? { bootstrapFailureDeadlineMs: options.bootstrapFailureDeadlineMs } : {}),
      env: options.env || process.env,
    });
    return Object.freeze({ started: true, owner: "trae_work_mcp_process" });
  } finally {
    await fs.rm(path.join(lockPath, "owner.json"), { force: true }).catch(() => {}); await fs.rmdir(lockPath).catch(() => {});
  }
}

export async function verifyPinnedBootstrap(binding, options = {}) {
  const launch = normalizeLaunchBinding(binding, options);
  const [pinBytes, manifestBytes] = await Promise.all([
    readSafeFile(path.join(launch.releaseRoot, "runtime", "neutral-host-release-pin.json"), 16 * 1024),
    readSafeFile(path.join(launch.releaseRoot, "runtime", "neutral-host-release-manifest.json"), 256 * 1024),
  ]);
  const pin = parseJson(pinBytes); const manifest = parseJson(manifestBytes);
  if (!plain(pin) || !exactKeys(pin, ["contract", "manifestSha256"]) || pin.contract !== "hellolynk-neutral-host-release-pin-v1"
    || pin.manifestSha256 !== launch.releaseManifestSha256 || sha256(manifestBytes) !== launch.releaseManifestSha256
    || !plain(manifest) || !exactKeys(manifest, ["contract", "entry", "files"])
    || manifest.contract !== "hellolynk-neutral-host-release-manifest-v1" || manifest.entry !== "neutral-host-release-entry.mjs"
    || !Array.isArray(manifest.files) || manifest.files.length < 39 || manifest.files.length > 256) fail();
  const records = new Map(); const resolvedPaths = new Map();
  for (const item of manifest.files) {
    if (!plain(item) || !exactKeys(item, ["path", "sha256"]) || !/^[a-f0-9]{64}$/.test(String(item.sha256 || ""))) fail();
    const recordPath = String(item.path || ""); const file = resolveManifestFile(launch, recordPath); const canonical = canonicalPath(file);
    if (records.has(recordPath) || resolvedPaths.has(canonical)) fail();
    const bytes = await readSafeFile(file, 2 * 1024 * 1024).catch(() => fail()); if (sha256(bytes) !== item.sha256) fail();
    const record = Object.freeze({ recordPath, file, bytes }); records.set(recordPath, record); resolvedPaths.set(canonical, record);
  }
  for (const required of [...REQUIRED_RUNTIME_RECORDS, ...REQUIRED_RELEASE_RECORDS]) if (!records.has(required)) fail();
  if (!samePath(records.get("neutral-host-bootstrap.mjs").file, launch.bootstrapPath) || !records.has(manifest.entry)) fail();
  verifyStaticImportClosure(records, resolvedPaths, launch.releaseRoot);
  return Object.freeze({ ok: true, bootstrapPath: launch.bootstrapPath, verifiedFileCount: records.size });
}

function resolveManifestFile(launch, recordPath) {
  if (recordPath.startsWith("release/")) {
    if (!REQUIRED_RELEASE_RECORDS.includes(recordPath)) fail();
    return insideRoot(launch.releaseRoot, recordPath.slice(8));
  }
  if (!SAFE_RELATIVE.test(recordPath) || recordPath.split("/").includes("..")) fail(); return insideRoot(path.join(launch.releaseRoot, "runtime"), recordPath);
}
function verifyStaticImportClosure(records, resolvedPaths, releaseRoot) {
  const pattern = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g;
  for (const record of records.values()) {
    if (!record.file.endsWith(".mjs")) continue; const source = record.bytes.toString("utf8"); pattern.lastIndex = 0;
    for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
      const imported = path.resolve(path.dirname(record.file), ...match[1].split("/"));
      if (!inside(releaseRoot, imported) || !resolvedPaths.has(canonicalPath(imported))) fail();
    }
  }
}
function normalizeLaunchBinding(value, options) {
  if (!plain(value)) throw codeError("neutral_trae_work_launch_configuration_required");
  const runtimeRoot = absolute(value.runtimeRoot); const releaseRoot = absolute(value.releaseRoot); const profileManifestPath = absolute(value.profileManifestPath);
  const releaseManifestSha256 = String(value.releaseManifestSha256 || "");
  if (value.runnerRelativePath !== RUNNER_RELATIVE || !/^[a-f0-9]{64}$/.test(releaseManifestSha256) || path.basename(runtimeRoot).toLowerCase() !== "runtime") throw codeError("neutral_trae_work_launch_configuration_required");
  const derivedStoreRoot = path.dirname(runtimeRoot); const storeRoot = options.storeRoot ? absolute(options.storeRoot) : derivedStoreRoot;
  if (!samePath(storeRoot, derivedStoreRoot)) throw codeError("neutral_trae_work_launch_configuration_required");
  return Object.freeze({ runtimeRoot, releaseRoot, profileManifestPath, releaseManifestSha256, storeRoot, runnerRelativePath: RUNNER_RELATIVE,
    bootstrapPath: path.join(releaseRoot, ...RUNNER_RELATIVE.split("/")), region: safeId(value.region), principalId: safeId(value.principalId), delegateId: safeId(value.delegateId), hostInstallationId: safeId(value.hostInstallationId), profileId: safeId(value.profileId), adapterId: value.adapterId === "trae-work" ? "trae-work" : fail(), version: Number(value.version), scopes: Object.freeze([...(value.scopes || [])].map(String)) });
}
async function readSafeFile(file, maximum) { await assertNoReparseAncestors(file); let handle; try { handle = await fs.open(file, "r"); } catch { throw codeError("neutral_trae_work_runner_unavailable"); } try { const before = await handle.stat({ bigint: true }); if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) fail(); const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true }); if (!sameIdentity(before, after)) fail(); return bytes; } catch (error) { if (/^neutral_trae_work_/.test(String(error?.code || ""))) throw error; throw codeError("neutral_trae_work_runner_integrity_invalid"); } finally { await handle.close().catch(() => {}); } }
async function assertNoReparseAncestors(target) { const resolved = path.resolve(target); const parsed = path.parse(resolved); let cursor = parsed.root; for (const segment of path.relative(parsed.root, resolved).split(path.sep).filter(Boolean)) { cursor = path.join(cursor, segment); const metadata = await fs.lstat(cursor).catch(() => { throw codeError("neutral_trae_work_runner_unavailable"); }); if (metadata.isSymbolicLink()) throw codeError("neutral_trae_work_runner_integrity_invalid"); } }
async function ensureSafeDirectory(target, create) { if (create) await fs.mkdir(target, { recursive: true, mode: 0o700 }); const metadata = await fs.lstat(target).catch(() => null); if (!metadata?.isDirectory() || metadata.isSymbolicLink()) throw codeError("neutral_trae_work_launch_configuration_required"); }
async function reclaimDeadLock(lockPath) { const metadata = await fs.lstat(lockPath); let owner; try { owner = JSON.parse(await fs.readFile(path.join(lockPath, "owner.json"), "utf8")); } catch { return false; } const pid = Number(owner?.pid); if (Date.now() - metadata.mtimeMs <= LOCK_STALE_MS || (Number.isSafeInteger(pid) && pid > 0 && processAlive(pid))) return false; await fs.rm(path.join(lockPath, "owner.json"), { force: true }); await fs.rmdir(lockPath).catch(() => {}); return true; }
function insideRoot(root, relative) { const result = path.resolve(root, ...relative.split("/")); if (!inside(root, result)) fail(); return result; }
function inside(root, target) { const relative = path.relative(path.resolve(root), path.resolve(target)); return Boolean(relative) && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative); }
function tupleDigest(value) { return sha256(`${value.region}\0${value.principalId}\0${value.hostInstallationId}`); } function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); } function parseJson(value) { try { return JSON.parse(value); } catch { fail(); } } function sameIdentity(left, right) { return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs && left.nlink === right.nlink; } function processAlive(pid) { try { process.kill(pid, 0); return true; } catch (error) { return error?.code === "EPERM"; } } function safeId(value) { const result = String(value || ""); if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(result)) fail(); return result; } function absolute(value) { const result = String(value || ""); if (!path.isAbsolute(result) || path.resolve(result) !== result) fail(); return result; } function samePath(left, right) { return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right; } function canonicalPath(value) { const result = path.resolve(value); return process.platform === "win32" ? result.toLowerCase() : result; } function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((item, index) => item === wanted[index]); } function bounded(value, fallback, minimum, maximum) { const result = Number(value ?? fallback); return Number.isSafeInteger(result) && result >= minimum && result <= maximum ? result : fallback; } function plain(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); } function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); } function fail() { throw codeError("neutral_trae_work_runner_integrity_invalid"); } function codeError(code) { const error = new Error(code); error.code = code; return error; }
