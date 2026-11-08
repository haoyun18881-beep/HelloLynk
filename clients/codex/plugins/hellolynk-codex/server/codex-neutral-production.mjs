import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { discoverNeutralHost } from "./neutral-host-adapter.mjs";
import { launchPinnedNeutralHostBootstrap, verifyPinnedNeutralHostRuntime } from "../runtime/core/hellolynk-neutral-host-launcher.mjs";
import { resolveClientAccountRoot } from "../runtime/core/hellolynk-client-account.mjs";
import { startInstalledClientUpdate } from "../runtime/core/hellolynk-client-update-entry.mjs";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.dirname(MODULE_DIR);
const BOOTSTRAP = path.join(PLUGIN_ROOT, "runtime", "neutral-host-bootstrap.mjs");
const RELEASE_LOADER = path.join(PLUGIN_ROOT, "runtime", "neutral-host-release-loader.mjs");
const LOCK_WAIT_MS = 10_000;
const DISCOVERY_WAIT_MS = 75_000;
const MAX_DISCOVERY_WAIT_MS = 120_000;
let installedPrepare = null;
const TRUSTED_BOOTSTRAP_FILES = Object.freeze(new Map([
  ["runtime/bootstrap/core/hellolynk-local-process-lock.mjs", "5212990a98b9ad2eb83fa2d5fb8a123d687c5ef6daf6cba49a4b6d04a7fe251e"],
  ["runtime/bootstrap/core/hellolynk-client-account.mjs", "ab7ec5dda92e510e7deb14f900fd2df4c6c3373fbeb4af4fb2b6c1a72aa41a99"],
  ["runtime/neutral-host-release-loader.mjs", "15593e237fd5cbd765b65e60efe7a1c87e24a5390ad932c8a23d2c03b8da9770"],
  ["runtime/neutral-host-bootstrap.mjs", "53513deed7f0155a6603a1489d1609fae37776442358181ff7650d0cd9351f0a"],
  ["runtime/bootstrap/core/hellolynk-runtime-safety.cjs", "43d576d9f774409f4a735793c1503a6f397e787b10c59a4ac9cc9257299f5efe"],
  ["runtime/bootstrap/core/hellolynk-host-protected-store.mjs", "89b6e6c4ce9c6ba2984f8c301de4251da6004bdd402cc44d578a4505c21b75b1"],
  ["runtime/bootstrap/core/hellolynk-neutral-host-installation-store.mjs", "b5f6288732af6f9b9c0c750f6002eae657dde9513fc97674f6e59200f3cc9dc6"],
  ["runtime/bootstrap/core/hellolynk-host-auth.mjs", "db1ec56f4e60e6450fba50188eecf89748f39f5d7a75c2456c30a6053233555d"],
  ["runtime/bootstrap/core/hellolynk-client-profile.mjs", "4b45a78b4d6c4794a1f494bd95777579c32c56a68321a1d3b484048942ae4742"],
  ["runtime/bootstrap/core/hellolynk-platform-credential-store.mjs", "f27f5f377cc4d6d2b5664212cf8fcc4c98d910064c1677ff9c1f776df1a59dba"],
  ["runtime/bootstrap/core/hellolynk-client-core.mjs", "94bbad1d0ccee969bbffed176449e427188f1b892512a64167ab31f63d258e2b"],
  ["runtime/bootstrap/platform/windows/hellolynk-host-protected-store.ps1", "24357e8ce54090b4ec68e457f02c9e834a80f3273ef3c03a8c0fa7258797fb49"],
]));

// A still-open cache may load a different installed release during an update.
// Share initialization objects only when both use the same pinned bootstrap.
export const CODEX_INITIAL_BINDING_HANDOFF = crypto.createHash("sha256")
  .update(JSON.stringify([...TRUSTED_BOOTSTRAP_FILES])).digest("hex");

export async function createCodexNeutralProduction(options = {}, preparedRelease = null) {
  const env = options.env || process.env;
  // The cache delegates to the pinned release that prepared this object.
  // Keep that one initialization alive instead of resolving it a second time.
  if (preparedRelease && path.resolve(preparedRelease.releaseRoot) !== path.resolve(PLUGIN_ROOT)) {
    preparedRelease.binding.capability?.secretBuffer?.fill(0);
    preparedRelease = null;
  }
  const prepared = preparedRelease || await prepareCodexNeutralRelease({ ...options, env }, true);
  const { inspection, releaseRoot, storeRoot, protectedStore, initialBindingFingerprint } = prepared;
  try {
    if (!options.releaseLoaderPath && path.resolve(releaseRoot) !== path.resolve(PLUGIN_ROOT)) {
      const production = await import(pathToFileURL(path.join(releaseRoot, "server/codex-neutral-production.mjs")).href);
      const share = production.CODEX_INITIAL_BINDING_HANDOFF === CODEX_INITIAL_BINDING_HANDOFF;
      if (!share) prepared.binding.capability?.secretBuffer?.fill(0);
      return await production.createCodexNeutralProduction({ ...options,
        releaseLoaderPath: path.join(releaseRoot, "runtime/neutral-host-release-loader.mjs"), storeRoot }, share ? prepared : null);
    }
    // The protected binding alone selects the release; the updater only installs in the background.
    if (!options.clientUpdateReady) {
      await startInstalledClientUpdate({ client: "codex", packageRoot: path.resolve(releaseRoot, "../.."), storeRoot });
    }
    const discover = options.discoverHost || discoverNeutralHost;
    const spawnRunner = options.spawnRunner;
    let initialBinding = prepared.binding;
    let launchBinding = null;
    return Object.freeze({
      capabilityProvider: async () => {
        // Consume before awaiting: two concurrent callers must not share the
        // one-time handoff. Reconnects always resolve current credentials.
        const initial = initialBinding;
        initialBinding = null;
        let resolved; let fingerprint;
        try {
          const current = initial && initialBindingFingerprint
            ? await initializationFingerprint(storeRoot, initial) : null;
          if (current && JSON.stringify(current) === JSON.stringify(initialBindingFingerprint)) {
            resolved = initial;
            fingerprint = current;
          } else {
            initial?.capability?.secretBuffer?.fill(0);
            const latest = await resolveInitialBinding(protectedStore, storeRoot);
            resolved = latest.binding;
            fingerprint = latest.fingerprint;
          }
          if (path.resolve(resolved.releaseRoot) !== releaseRoot
            || resolved.releaseManifestSha256 !== inspection.manifestSha256
            || resolved.runnerRelativePath !== "runtime/neutral-host-bootstrap.mjs") {
            throw codeError("neutral_codex_runner_integrity_invalid");
          }
          const { capability, ...publicLaunch } = resolved;
          launchBinding = { binding: publicLaunch, fingerprint };
          return Object.freeze({
            region: resolved.region,
            principalId: resolved.principalId,
            delegateId: resolved.delegateId,
            hostInstallationId: resolved.hostInstallationId,
            adapterId: "codex",
            runtimeRoot: resolved.runtimeRoot,
            capability,
          });
        } catch (error) {
          initial?.capability?.secretBuffer?.fill(0);
          resolved?.capability?.secretBuffer?.fill(0);
          throw error;
        }
      },
      hostLauncher: async (publicBinding) => {
        const verifiedLaunch = launchBinding;
        launchBinding = null;
        return launchCodexNeutralHost({
          publicBinding,
          verifiedLaunch,
          storeRoot,
          protectedStore,
          discover,
          spawnRunner,
          bootstrapPath: options.bootstrapPath || path.join(releaseRoot, "runtime", "neutral-host-bootstrap.mjs"),
          wait: options.wait,
          launchTimeoutMs: options.launchTimeoutMs,
          env,
        });
      },
    });
  } catch (error) {
    prepared.binding.capability?.secretBuffer?.fill(0);
    throw error;
  }
}

export async function prepareCodexNeutralRelease(options = {}, finalBindingDeferred = false, verifiedInitial = null) {
  const env = options.env || process.env;
  if (options.releaseLoaderPath) {
    const prepared = await prepareSelectedRelease({ ...options, env, loaderPath: path.resolve(options.releaseLoaderPath) }, verifiedInitial);
    if (!finalBindingDeferred) prepared.binding.capability?.secretBuffer?.fill(0);
    return prepared;
  }
  // A warmed conversation can outlive Codex's disposable plugin cache. Keep
  // only the verified installed entry point; that entry still resolves the
  // current account, protected binding and release pin on every reconnect.
  if (installedPrepare) return installedPrepare({ ...options, env }, finalBindingDeferred);

  // Codex executes the MCP proxy from its disposable plugin cache, while the
  // protected binding deliberately points at an immutable HelloLynk release. Use
  // the cache only as a pinned bootstrap to discover that bound release; the
  // release itself remains the authority for runtime activation.
  const bootstrapLoaderPath = path.resolve(RELEASE_LOADER);
  const bootstrapReleaseRoot = path.dirname(path.dirname(bootstrapLoaderPath));
  const bootstrapTrusted = await loadTrustedBootstrap({
    loaderPath: bootstrapLoaderPath,
    releaseRoot: bootstrapReleaseRoot,
  });
  const storeRoot = resolveClientAccountRoot("codex", absolutePath(
    options.storeRoot || env.HELLOLYNK_NEUTRAL_STORE_ROOT || bootstrapTrusted.defaultStoreRoot("win32", env),
    "neutral_codex_binding_configuration_required",
  ));
  const bootstrapInstallationStore = bootstrapTrusted.createInstallationStore({ root: storeRoot });
  const bootstrapProtectedStore = bootstrapTrusted.createProtectedStore({
    root: storeRoot,
    installationStore: bootstrapInstallationStore,
  });
  const initial = await resolveInitialBinding(bootstrapProtectedStore, storeRoot);
  const bootstrapBinding = initial.binding;
  let handedOff = false;
  try {
    const boundReleaseRoot = absolutePath(bootstrapBinding.releaseRoot, "neutral_codex_binding_invalid");
    if (boundReleaseRoot !== bootstrapReleaseRoot) {
      // An installed update may advance the binding before Codex retires its old
      // cache. Authenticate the new complete runtime with the protected pin;
      // its own production module then validates its own bootstrap hash set.
      await verifyPinnedNeutralHostRuntime(bootstrapBinding, { storeRoot });
      const production = await import(pathToFileURL(path.join(boundReleaseRoot, "server/codex-neutral-production.mjs")).href);
      if (typeof production.prepareCodexNeutralRelease !== "function") throw codeError("neutral_codex_runner_integrity_invalid");
      installedPrepare = production.prepareCodexNeutralRelease;
      const share = production.CODEX_INITIAL_BINDING_HANDOFF === CODEX_INITIAL_BINDING_HANDOFF;
      if (!share) bootstrapBinding.capability.secretBuffer.fill(0);
      const selected = await production.prepareCodexNeutralRelease({ ...options, env, storeRoot,
        releaseLoaderPath: path.join(boundReleaseRoot, "runtime/neutral-host-release-loader.mjs") }, finalBindingDeferred, share ? initial : null);
      handedOff = finalBindingDeferred && selected.binding === bootstrapBinding;
      return selected;
    }
    const selected = await prepareSelectedRelease({
      ...options,
      env,
      storeRoot,
      loaderPath: path.join(boundReleaseRoot, "runtime", "neutral-host-release-loader.mjs"),
    }, initial);
    if (!finalBindingDeferred) selected.binding.capability?.secretBuffer?.fill(0);
    handedOff = finalBindingDeferred && selected.binding === bootstrapBinding;
    return selected;
  } finally {
    if (!handedOff) bootstrapBinding.capability.secretBuffer.fill(0);
  }
}

async function prepareSelectedRelease(options, verifiedInitial = null) {
  const env = options.env || process.env;
  const loaderPath = path.resolve(options.loaderPath);
  const releaseRoot = path.dirname(path.dirname(loaderPath));
  const trusted = await loadTrustedBootstrap({ loaderPath, releaseRoot });
  const storeRoot = resolveClientAccountRoot("codex", absolutePath(
    options.storeRoot || env.HELLOLYNK_NEUTRAL_STORE_ROOT || trusted.defaultStoreRoot("win32", env),
    "neutral_codex_binding_configuration_required",
  ));
  const installationStore = trusted.createInstallationStore({ root: storeRoot });
  const protectedStore = trusted.createProtectedStore({ root: storeRoot, installationStore });
  const loader = trusted.loader;
  const inspection = await loader.inspectNeutralHostRelease();
  const current = verifiedInitial?.fingerprint
    ? await initializationFingerprint(storeRoot, verifiedInitial.binding) : null;
  if (verifiedInitial && (!current || JSON.stringify(current) !== JSON.stringify(verifiedInitial.fingerprint))) {
    verifiedInitial.binding.capability?.secretBuffer?.fill(0);
    verifiedInitial = null;
  }
  const initial = verifiedInitial || await resolveInitialBinding(protectedStore, storeRoot);
  const { binding, fingerprint: initialBindingFingerprint } = initial;
  try {
    assertReleaseBinding(binding, inspection);
    const release = await loader.activateNeutralHostRelease(inspection);
    if (!release || typeof release.run !== "function") throw codeError("neutral_codex_runner_integrity_invalid");
    return Object.freeze({ release, inspection, binding, initialBindingFingerprint,
      releaseRoot, storeRoot, installationStore, protectedStore,
      runnerBinding: (root) => currentRunnerBinding(storeRoot, root, binding, initialBindingFingerprint) });
  } catch (error) {
    binding.capability?.secretBuffer?.fill(0);
    throw error;
  }
}

// The runner in this process starts from the binding resolved above while the
// same initialization fingerprint holds; otherwise it resolves the current one.
// Only public launch fields cross over, never the capability.
async function currentRunnerBinding(storeRoot, root, binding, fingerprint) {
  if (!fingerprint || path.resolve(String(root || "")) !== path.resolve(storeRoot)) return null;
  const current = await initializationFingerprint(storeRoot, binding);
  if (!current || JSON.stringify(current) !== JSON.stringify(fingerprint)) return null;
  const { capability, ...publicBinding } = binding;
  return Object.freeze(publicBinding);
}

async function resolveInitialBinding(protectedStore, storeRoot) {
  const before = await initializationFingerprint(storeRoot);
  const binding = await protectedStore.resolveCodexNeutralBinding();
  const after = await initializationFingerprint(storeRoot, binding);
  return { binding, fingerprint: before && after && before.state === after.state ? after : null };
}

// This is an initialization handoff, not a timed authorization cache. Native
// resolution has already checked the credentials and registry; reuse only if
// those exact files, account and launch paths remain unchanged. Directory
// identity matters, but unrelated lock-file writes must not invalidate it.
async function initializationFingerprint(storeRoot, binding = null) {
  try {
    if (resolveClientAccountRoot("codex", storeRoot) !== storeRoot) return null;
    const seen = new Map();
    const stat = async (file, directory, maxBytes = null) => {
      const metadata = await fs.lstat(file, { bigint: true });
      if (metadata.isSymbolicLink() || (directory ? !metadata.isDirectory()
        : !metadata.isFile() || metadata.nlink !== 1n)
        || (maxBytes != null && metadata.size > BigInt(maxBytes))) throw new Error("changed");
      const identity = [metadata.dev, metadata.ino, metadata.birthtimeNs];
      if (!directory) identity.push(metadata.size, metadata.ctimeNs, metadata.mtimeNs);
      seen.set(file, identity.join(":"));
      for (let parent = path.dirname(file); !seen.has(parent); parent = path.dirname(parent)) {
        const metadata = await fs.lstat(parent, { bigint: true });
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("changed");
        seen.set(parent, [metadata.dev, metadata.ino, metadata.birthtimeNs].join(":"));
        if (parent === path.dirname(parent)) break;
      }
    };
    await stat(path.join(storeRoot, "capabilities-v1.dpapi.clixml"), false);
    await stat(path.join(storeRoot, "installations-v1.json"), false);
    const state = JSON.stringify([...seen]);
    if (binding) {
      await stat(binding.runtimeRoot, true);
      await stat(binding.profileManifestPath, false, 65536);
      await stat(path.join(binding.releaseRoot, binding.runnerRelativePath), false, 1048576);
    }
    return { state, paths: JSON.stringify([...seen]) };
  } catch { return null; }
}

async function loadTrustedBootstrap({ loaderPath, releaseRoot }) {
  for (const [relative, expectedHash] of TRUSTED_BOOTSTRAP_FILES) {
    const file = relative === "runtime/neutral-host-release-loader.mjs" ? loaderPath : path.join(releaseRoot, ...relative.split("/"));
    await readVerifiedFile(file, expectedHash);
  }
  let loader; let protectedModule; let installationModule;
  try {
    [loader, protectedModule, installationModule] = await Promise.all([
      import(pathToFileURL(loaderPath).href),
      import(pathToFileURL(path.join(releaseRoot, "runtime", "bootstrap", "core", "hellolynk-host-protected-store.mjs")).href),
      import(pathToFileURL(path.join(releaseRoot, "runtime", "bootstrap", "core", "hellolynk-neutral-host-installation-store.mjs")).href),
    ]);
  } catch { throw codeError("neutral_codex_runner_integrity_invalid"); }
  if (typeof loader.inspectNeutralHostRelease !== "function" || typeof loader.activateNeutralHostRelease !== "function"
    || typeof protectedModule.createHostProtectedStore !== "function"
    || typeof installationModule.createNeutralHostInstallationStore !== "function"
    || typeof installationModule.defaultNeutralHostStoreRoot !== "function") {
    throw codeError("neutral_codex_runner_integrity_invalid");
  }
  return Object.freeze({
    loader,
    createProtectedStore: protectedModule.createHostProtectedStore,
    createInstallationStore: installationModule.createNeutralHostInstallationStore,
    defaultStoreRoot: installationModule.defaultNeutralHostStoreRoot,
  });
}

export async function launchCodexNeutralHost(options = {}) {
  // Pre-spawn timings travel with the attempt record the launcher already writes,
  // so a slow cold start can be split into stages without a second evidence file.
  const enteredAt = new Date().toISOString();
  const entered = performance.now();
  const elapsedMs = () => Math.max(0, Math.round(performance.now() - entered));
  const expected = normalizePublicBinding(options.publicBinding);
  const handed = options.verifiedLaunch;
  const current = handed?.fingerprint ? await initializationFingerprint(options.storeRoot, handed.binding) : null;
  const resolved = current && JSON.stringify(current) === JSON.stringify(handed.fingerprint)
    ? handed.binding : await options.protectedStore.resolveCodexNeutralBinding();
  // The provider has just verified this public launch descriptor. A changed
  // account/store still resolves afresh; the runner resolves in its own process.
  resolved.capability?.secretBuffer?.fill(0);
  assertSamePublicBinding(expected, resolved);
  const bindingResolvedMs = elapsedMs();
  const discoverOptions = {
    runtimeRoot: resolved.runtimeRoot,
    region: resolved.region,
    principalId: resolved.principalId,
    hostInstallationId: resolved.hostInstallationId,
  };
  const discovered = await tryDiscover(options.discover, discoverOptions);
  const discoverProbedMs = elapsedMs();
  if (discovered) return;
  const lockPath = path.join(resolved.runtimeRoot, "neutral-host", `${tupleDigest(resolved)}.launch.lock`);
  await assertSafeDirectory(resolved.runtimeRoot, true);
  await assertSafeDirectory(path.dirname(lockPath), true);
  const wait = options.wait || delay;
  const deadline = Date.now() + bounded(options.launchTimeoutMs, DISCOVERY_WAIT_MS, 1_000, MAX_DISCOVERY_WAIT_MS);
  let ownsLock = false;
  while (Date.now() < deadline) {
    if (await tryDiscover(options.discover, discoverOptions)) return;
    try {
      await fs.mkdir(lockPath, { mode: 0o700 });
      await fs.writeFile(path.join(lockPath, "owner.json"), `${JSON.stringify({
        contract: "hellolynk-codex-neutral-launch-lock-v1", pid: process.pid, createdAtMs: Date.now(),
      })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
      ownsLock = true;
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw codeError("neutral_codex_launch_failed");
      await assertSafeDirectory(lockPath, false);
      await reclaimDeadLaunchLock(lockPath).catch(() => {});
      await wait(50);
    }
  }
  if (!ownsLock) throw codeError("neutral_codex_launch_lock_timeout");
  const lockAcquiredMs = elapsedMs();
  try {
    if (await tryDiscover(options.discover, discoverOptions)) return;
    await assertBootstrap(options.bootstrapPath, "neutral_codex_runner_unavailable");
    await launchPinnedNeutralHostBootstrap(resolved, {
      storeRoot: options.storeRoot,
      ...(options.spawnRunner ? { spawnRunner: options.spawnRunner } : {}),
      env: options.env,
      wait,
      bootstrapFailureDeadlineMs: deadline,
      stages: { enteredAt, bindingResolvedMs, discoverProbedMs, lockAcquiredMs },
    });
    while (Date.now() < deadline) {
      await wait(50);
      if (await tryDiscover(options.discover, discoverOptions)) return;
    }
    throw codeError("neutral_codex_discovery_timeout");
  } finally {
    await fs.rm(path.join(lockPath, "owner.json"), { force: true }).catch(() => {});
    await fs.rmdir(lockPath).catch(() => {});
  }
}

async function reclaimDeadLaunchLock(lockPath) {
  const metadata = await fs.lstat(lockPath);
  const ownerPath = path.join(lockPath, "owner.json");
  let owner = null;
  try {
    const ownerMetadata = await fs.lstat(ownerPath);
    if (!ownerMetadata.isFile() || ownerMetadata.isSymbolicLink() || ownerMetadata.size > 4096) return false;
    owner = JSON.parse(await fs.readFile(ownerPath, "utf8"));
  } catch (error) { if (error?.code !== "ENOENT") return false; }
  const oldEnough = Date.now() - metadata.mtimeMs > LOCK_WAIT_MS;
  const pid = Number(owner?.pid);
  if (!oldEnough || (Number.isSafeInteger(pid) && pid > 0 && processAlive(pid))) return false;
  await fs.rm(ownerPath, { force: true });
  await fs.rmdir(lockPath).catch(() => {});
  return true;
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code === "EPERM"; }
}

async function tryDiscover(discover, input) {
  try { return await discover(input); } catch (error) {
    if (["neutral_host_discovery_stale", "neutral_host_discovery_generation_mismatch", "ENOENT"].includes(error?.code)) {
      return null;
    }
    throw error;
  }
}

async function assertBootstrap(value, missingCode) {
  const bootstrap = absolutePath(value, missingCode);
  await readVerifiedFile(bootstrap, TRUSTED_BOOTSTRAP_FILES.get("runtime/neutral-host-bootstrap.mjs"));
}

function assertReleaseBinding(binding, inspection) {
  if (path.resolve(binding.releaseRoot) !== path.resolve(inspection.releaseRoot)
    || binding.releaseManifestSha256 !== inspection.manifestSha256
    || binding.runnerRelativePath !== "runtime/neutral-host-bootstrap.mjs") {
    throw codeError("neutral_codex_runner_integrity_invalid");
  }
}

async function readVerifiedFile(file, expectedHash) {
  await assertNoReparseAncestors(file);
  let handle;
  try { handle = await fs.open(file, "r"); }
  catch (error) {
    if (error?.code === "ENOENT") throw codeError("neutral_codex_runner_unavailable");
    throw codeError("neutral_codex_runner_integrity_invalid");
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > 2n * 1024n * 1024n) {
      throw codeError("neutral_codex_runner_integrity_invalid");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!sameFileIdentity(before, after) || sha256(bytes) !== expectedHash) {
      throw codeError("neutral_codex_runner_integrity_invalid");
    }
  } catch (error) {
    if (/^neutral_codex_/.test(String(error?.code || ""))) throw error;
    throw codeError("neutral_codex_runner_integrity_invalid");
  } finally { await handle.close().catch(() => {}); }
}

async function assertNoReparseAncestors(file) {
  const resolved = path.resolve(file);
  const parsed = path.parse(resolved);
  let cursor = parsed.root;
  for (const segment of path.relative(parsed.root, resolved).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    let metadata;
    try { metadata = await fs.lstat(cursor); }
    catch (error) {
      if (error?.code === "ENOENT") throw codeError("neutral_codex_runner_unavailable");
      throw codeError("neutral_codex_runner_integrity_invalid");
    }
    if (metadata.isSymbolicLink()) throw codeError("neutral_codex_runner_integrity_invalid");
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.nlink === right.nlink;
}
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

async function assertSafeDirectory(value, create) {
  if (create) await fs.mkdir(value, { recursive: true, mode: 0o700 });
  const metadata = await fs.lstat(value).catch(() => null);
  if (!metadata || !metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw codeError("neutral_codex_binding_invalid");
  }
}

function normalizePublicBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("neutral_codex_binding_invalid");
  return Object.freeze({
    region: safeId(value.region), principalId: safeId(value.principalId),
    delegateId: safeId(value.delegateId), hostInstallationId: safeId(value.hostInstallationId),
    adapterId: value.adapterId === "codex" ? "codex" : fail("neutral_codex_binding_invalid"),
    capabilityVersion: Number(value.capabilityVersion), scopes: Object.freeze([...(value.scopes || [])].map(String)),
  });
}

function assertSamePublicBinding(expected, actual) {
  if (actual.region !== expected.region || actual.principalId !== expected.principalId
    || actual.delegateId !== expected.delegateId || actual.hostInstallationId !== expected.hostInstallationId
    || actual.adapterId !== expected.adapterId || actual.version !== expected.capabilityVersion
    || JSON.stringify(actual.scopes) !== JSON.stringify(expected.scopes)) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
}

function tupleDigest(value) {
  return crypto.createHash("sha256")
    .update(`${value.region}\0${value.principalId}\0${value.hostInstallationId}`).digest("hex");
}

function safeId(value) {
  const text = String(value || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(text)) throw codeError("neutral_codex_binding_invalid");
  return text;
}

function absolutePath(value, code) {
  const text = String(value || "");
  if (!text || !path.isAbsolute(text)) throw codeError(code);
  return path.resolve(text);
}

function bounded(value, fallback, minimum, maximum) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) return fallback;
  return number;
}

function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function fail(code) { throw codeError(code); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
