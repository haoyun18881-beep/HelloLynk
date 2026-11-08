import { randomBytes, timingSafeEqual } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, parse, resolve } from "node:path";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { withLocalProcessLock } from "./hellolynk-local-process-lock.mjs";
import { defaultHelloLynkClientRoot, readClientProfile } from "./hellolynk-client-profile.mjs";
import { assertIdentifier } from "./hellolynk-host-auth.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

export const HELLOLYNK_NEUTRAL_HOST_INSTALLATIONS_CONTRACT = "hellolynk-neutral-host-installations-v1";
export const HELLOLYNK_NEUTRAL_HOST_REGISTRY_FILE = "installations-v1.json";
export const HELLOLYNK_NEUTRAL_HOST_PROFILE_MANIFEST_CONTRACT = "hellolynk-neutral-host-profile-manifest-v1";
export const HELLOLYNK_NEUTRAL_HOST_PROFILE_MANIFEST_FILE = "profile-manifest-v1.json";

const HOST_ID_PATTERN = /^host_[A-Za-z0-9_-]{32}$/;
const MAX_REGISTRY_BYTES = 256 * 1024;
const LOCK_TIMEOUT_MS = 10_000;
const REGISTRY_LOCK_CONTRACT = "hellolynk-neutral-host-registry-lock-v2";
const MAX_REGISTRY_LOCK_BYTES = 16 * 1024;
const REGISTRY_LOCK_STALE_MS = 5_000;
const REGISTRY_LOCK_STABILITY_WAIT_MS = 20;
const WINDOWS_SYSTEM_DIR = join(process.env.SystemRoot || process.env.WINDIR || "C:\\Windows", "System32");

export function defaultNeutralHostStoreRoot(platform = process.platform, env = process.env) {
  const configured = String(env.HELLOLYNK_NEUTRAL_STORE_ROOT || "").trim();
  if (configured) {
    if (!isAbsolute(configured)) throw codeError("neutral_host_store_root_invalid");
    const root = resolve(configured);
    const parent = dirname(root);
    if (basename(root).toLowerCase() !== "host" || parent === parse(parent).root) {
      throw codeError("neutral_host_store_root_invalid");
    }
    return root;
  }
  return join(defaultHelloLynkClientRoot(platform, env), "host");
}

export function createNeutralHostInstallationStore(options = {}) {
  const root = assertAbsoluteRoot(options.root || defaultNeutralHostStoreRoot());
  const readOnly = options.readOnly === true;
  const verifyPath = typeof options.verifyPath === "function" ? options.verifyPath : null;
  if (readOnly && process.platform === "win32" && !verifyPath) {
    throw codeError("host_store_read_only_verifier_required");
  }
  const clock = normalizeClock(options.clock);
  const random = typeof options.randomBytes === "function" ? options.randomBytes : randomBytes;
  const registryPath = join(root, HELLOLYNK_NEUTRAL_HOST_REGISTRY_FILE);
  const lockPath = join(root, ".installations-v1.lock");

  async function createId() {
    if (readOnly) throw codeError("host_store_read_only");
    return withRegistryLock(root, lockPath, async () => {
      const registry = await readRegistry(registryPath);
      if (registry.installations.length > 1) throw codeError("host_installation_ambiguous");
      const existing = registry.installations[0];
      if (existing) return publicInstallation(existing);
      const now = safeTimestamp(clock());
      const hostInstallationId = createHostInstallationId(random);
      const installation = validateInstallation({
        region: null,
        principalId: null,
        hostInstallationId,
        canonicalProfileId: null,
        state: "unclaimed",
        delegateBindings: [],
        createdAt: now,
        updatedAt: now,
      });
      await writeRegistry(registryPath, {
        contract: HELLOLYNK_NEUTRAL_HOST_INSTALLATIONS_CONTRACT,
        installations: [installation],
      });
      return publicInstallation(installation);
    });
  }

  async function adoptProfileFile(input = {}) {
    if (readOnly) throw codeError("host_store_read_only");
    const profileFile = assertExplicitProfileFile(input.profileFile);
    const adapterId = assertIdentifier(input.adapterId, "host_adapter_id_invalid");
    const profile = await readSyntheticProfile(profileFile);
    return withRegistryLock(root, lockPath, async () => {
      const registry = await readRegistry(registryPath);
      if (registry.installations.length > 1) throw codeError("host_installation_ambiguous");
      const current = registry.installations[0] || null;
      const now = safeTimestamp(clock());
      let installation;
      if (!current) {
        installation = validateInstallation({
          region: profile.region,
          principalId: profile.principalId,
          hostInstallationId: profile.hostId,
          canonicalProfileId: profile.profileId,
          state: "active",
          delegateBindings: [bindingFromProfile(profile, adapterId)],
          createdAt: now,
          updatedAt: now,
        });
      } else {
        if (current.hostInstallationId !== profile.hostId) {
          throw codeError("host_installation_id_conflict");
        }
        if (current.state === "active" && (
          current.region !== profile.region || current.principalId !== profile.principalId
        )) {
          throw codeError("host_installation_owner_conflict");
        }
        if (!['active', 'unclaimed'].includes(current.state)) {
          throw codeError("host_installation_inactive");
        }
        const bindings = current.delegateBindings.map(cloneBinding);
        const sameProfile = bindings.find((item) => item.profileId === profile.profileId);
        const sameDelegate = bindings.find((item) => item.delegateId === profile.delegateId);
        if (sameProfile && sameProfile.delegateId !== profile.delegateId) {
          throw codeError("host_profile_delegate_conflict");
        }
        if (sameDelegate && sameDelegate.profileId !== profile.profileId) {
          throw codeError("host_delegate_profile_conflict");
        }
        const existing = sameProfile || sameDelegate;
        if (existing) {
          if (existing.authorizationVersion !== profile.authorizationVersion) {
            throw codeError("host_authorization_version_conflict");
          }
          if (!existing.adapters.includes(adapterId)) {
            existing.adapters = [...existing.adapters, adapterId].sort();
          }
        } else {
          bindings.push(bindingFromProfile(profile, adapterId));
        }
        bindings.sort((left, right) => left.profileId.localeCompare(right.profileId));
        installation = validateInstallation({
          ...current,
          region: profile.region,
          principalId: profile.principalId,
          canonicalProfileId: current.canonicalProfileId || profile.profileId,
          state: "active",
          delegateBindings: bindings,
          updatedAt: now,
        });
      }
      await writeRegistry(registryPath, {
        contract: HELLOLYNK_NEUTRAL_HOST_INSTALLATIONS_CONTRACT,
        installations: [installation],
      });
      return publicInstallation(installation);
    });
  }

  async function status() {
    // The read-only registry verifier checks root ACL, all path ancestors and
    // the file ACL together. Do not launch a second root-only verifier.
    if (readOnly && process.platform !== "win32") await assertReadOnlyPath(root, true, verifyPath);
    if (!readOnly) await assertSecureDirectory(root, false, false);
    const registry = await readRegistry(registryPath, { readOnly, verifyPath });
    return Object.freeze({
      contract: registry.contract,
      installations: Object.freeze(registry.installations.map(publicInstallation)),
    });
  }

  async function resolveBinding(input = {}) {
    if (readOnly && process.platform !== "win32") await assertReadOnlyPath(root, true, verifyPath);
    if (!readOnly) await assertSecureDirectory(root, false, false);
    const registry = await readRegistry(registryPath, { readOnly, verifyPath });
    const active = registry.installations.filter((item) => item.state === "active");
    if (active.length !== 1) throw codeError(active.length ? "host_installation_ambiguous" : "host_installation_missing");
    const installation = active[0];
    const profileId = input.profileId == null ? null : assertIdentifier(input.profileId, "host_profile_id_invalid");
    const delegateId = input.delegateId == null ? null : assertIdentifier(input.delegateId, "host_delegate_id_invalid");
    if (!profileId && !delegateId && installation.delegateBindings.length !== 1) {
      throw codeError("host_delegate_binding_ambiguous");
    }
    const matches = installation.delegateBindings.filter((item) => (
      (!profileId || item.profileId === profileId) && (!delegateId || item.delegateId === delegateId)
    ));
    if (matches.length !== 1) throw codeError(matches.length ? "host_delegate_binding_ambiguous" : "host_delegate_binding_missing");
    return Object.freeze({
      region: installation.region,
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      canonicalProfileId: installation.canonicalProfileId,
      ...cloneBinding(matches[0]),
    });
  }

  return Object.freeze({ root, registryPath, createId, adoptProfileFile, status, resolveBinding });
}

export async function writeNeutralHostProfileManifest(options = {}) {
  const root = assertAbsoluteRoot(options.root || defaultNeutralHostStoreRoot());
  if (!Array.isArray(options.profiles) || options.profiles.length < 1 || options.profiles.length > 32) {
    throw codeError("host_profile_manifest_profiles_invalid");
  }
  let profiles = options.profiles.map(assertExplicitProfileFile);
  if (new Set(profiles.map((value) => value.toLowerCase())).size !== profiles.length) {
    throw codeError("host_profile_manifest_profiles_invalid");
  }
  const manifestPath = join(root, HELLOLYNK_NEUTRAL_HOST_PROFILE_MANIFEST_FILE);
  // Keep registry membership and manifest publication in one critical section.
  // Lock order is registry -> manifest; adoption only takes the registry lock.
  return withRegistryLock(root, join(root, ".installations-v1.lock"), () =>
    withRegistryLock(root, join(root, ".profile-manifest-v1.lock"), async () => {
      const registry = await readRegistry(join(root, HELLOLYNK_NEUTRAL_HOST_REGISTRY_FILE));
      const active = registry.installations.filter((item) => item.state === "active");
      if (active.length !== 1) {
        throw codeError(active.length ? "host_installation_ambiguous" : "host_installation_missing");
      }
      const installation = active[0];
      if (options.mergeRegisteredProfiles === true) {
        const paths = new Map();
        const addPath = (file) => {
          const path = assertExplicitProfileFile(file);
          const id = basename(path, ".json");
          const previous = paths.get(id);
          if (previous && previous.toLowerCase() !== path.toLowerCase()) throw codeError("host_profile_manifest_profiles_invalid");
          paths.set(id, path);
        };
        try {
          const metadata = await lstat(manifestPath);
          if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_REGISTRY_BYTES) {
            throw codeError("host_profile_manifest_profiles_invalid");
          }
          const body = await readFile(manifestPath, "utf8");
          if (Buffer.byteLength(body, "utf8") > MAX_REGISTRY_BYTES) throw codeError("host_profile_manifest_profiles_invalid");
          const existing = JSON.parse(body);
          if (existing?.contract !== HELLOLYNK_NEUTRAL_HOST_PROFILE_MANIFEST_CONTRACT
            || !Array.isArray(existing.profiles) || existing.profiles.length > 32) throw codeError("host_profile_manifest_profiles_invalid");
          existing.profiles.forEach(addPath);
        } catch (error) { if (error?.code !== "ENOENT") throw error; }
        profiles.forEach(addPath);
        const profileRoot = assertAbsoluteRoot(options.clientRoot);
        const ids = [installation.canonicalProfileId, ...installation.delegateBindings.map((item) => item.profileId)
          .filter((id) => id !== installation.canonicalProfileId).sort()];
        profiles = ids.map((id) => paths.get(id) || join(profileRoot, "profiles", `${id}.json`));
        if (profiles.length > 32 || new Set(profiles.map((path) => path.toLowerCase())).size !== profiles.length) {
          throw codeError("host_profile_manifest_profiles_invalid");
        }
      }
      const loaded = await Promise.all(profiles.map(readSyntheticProfile));
      if (loaded[0].profileId !== installation.canonicalProfileId) {
        throw codeError("host_profile_manifest_canonical_profile_invalid");
      }
      for (const profile of loaded) {
        const binding = installation.delegateBindings.find((item) => item.profileId === profile.profileId);
        if (!binding || binding.delegateId !== profile.delegateId
          || binding.authorizationVersion !== profile.authorizationVersion
          || profile.region !== installation.region || profile.principalId !== installation.principalId
          || profile.hostId !== installation.hostInstallationId) {
          throw codeError("host_profile_manifest_owner_mismatch");
        }
      }
      const manifest = Object.freeze({
        contract: HELLOLYNK_NEUTRAL_HOST_PROFILE_MANIFEST_CONTRACT,
        profiles: Object.freeze([...profiles]),
      });
      await writeRegistry(manifestPath, manifest);
      return Object.freeze({ manifestPath, contract: manifest.contract, profiles: manifest.profiles });
    }));
}

export function createHostInstallationId(random = randomBytes) {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const bytes = Buffer.from(random(24));
    if (bytes.length !== 24) throw codeError("host_installation_random_invalid");
    const candidate = `host_${bytes.toString("base64url")}`;
    if (HOST_ID_PATTERN.test(candidate) && /[A-Za-z0-9]$/.test(candidate)) return candidate;
  }
  throw codeError("host_installation_random_invalid");
}

async function readSyntheticProfile(profileFile) {
  const metadata = await lstat(profileFile).catch((error) => {
    if (error?.code === "ENOENT") throw codeError("host_profile_file_missing");
    throw error;
  });
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 128 * 1024) {
    throw codeError("host_profile_file_invalid");
  }
  const profile = await readClientProfile(profileFile);
  if (profile.schemaVersion !== 2) throw codeError("host_profile_schema_2_required");
  return profile;
}

function bindingFromProfile(profile, adapterId) {
  return {
    profileId: profile.profileId,
    delegateId: profile.delegateId,
    authorizationVersion: profile.authorizationVersion,
    adapters: [adapterId],
  };
}

async function readRegistry(path, options = {}) {
  let raw;
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_REGISTRY_BYTES) {
      throw codeError("host_registry_path_invalid");
    }
    if (options.readOnly) await assertReadOnlyPath(path, false, options.verifyPath);
    // Registry permissions are established on creation/atomic publication.
    // Reading through a writable store must not change ctime and invalidate
    // another Host's successful path verification.
    raw = await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT" && !options.readOnly) {
      return Object.freeze({ contract: HELLOLYNK_NEUTRAL_HOST_INSTALLATIONS_CONTRACT, installations: Object.freeze([]) });
    }
    throw error;
  }
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw codeError("host_registry_invalid"); }
  assertExactKeys(parsed, ["contract", "installations"], "host_registry_fields_invalid");
  if (parsed.contract !== HELLOLYNK_NEUTRAL_HOST_INSTALLATIONS_CONTRACT || !Array.isArray(parsed.installations)) {
    throw codeError("host_registry_invalid");
  }
  if (parsed.installations.length > 64) throw codeError("host_registry_too_large");
  const installations = parsed.installations.map(validateInstallation);
  const ids = new Set(installations.map((item) => item.hostInstallationId));
  if (ids.size !== installations.length) throw codeError("host_installation_duplicate");
  return Object.freeze({ contract: parsed.contract, installations: Object.freeze(installations) });
}

async function assertReadOnlyPath(path, directory, verifyPath) {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || (directory ? !metadata.isDirectory() : !metadata.isFile())) {
    throw codeError(directory ? "host_store_root_invalid" : "host_registry_path_invalid");
  }
  if (process.platform === "win32") {
    await verifyPath({ path, directory });
  }
}

function validateInstallation(value) {
  assertExactKeys(value, [
    "canonicalProfileId", "createdAt", "delegateBindings", "hostInstallationId",
    "principalId", "region", "state", "updatedAt",
  ], "host_installation_fields_invalid");
  if (!HOST_ID_PATTERN.test(String(value.hostInstallationId || ""))) throw codeError("host_installation_id_invalid");
  if (!['active', 'unclaimed'].includes(value.state)) throw codeError("host_installation_state_invalid");
  const unclaimed = value.state === "unclaimed";
  const region = unclaimed && value.region === null ? null : assertIdentifier(value.region, "host_region_invalid");
  const principalId = unclaimed && value.principalId === null
    ? null : assertIdentifier(value.principalId, "host_principal_id_invalid");
  const canonicalProfileId = unclaimed && value.canonicalProfileId === null
    ? null : assertIdentifier(value.canonicalProfileId, "host_profile_id_invalid");
  if (!Array.isArray(value.delegateBindings) || value.delegateBindings.length > 64) {
    throw codeError("host_delegate_bindings_invalid");
  }
  if (unclaimed && value.delegateBindings.length) throw codeError("host_unclaimed_bindings_invalid");
  const delegateBindings = value.delegateBindings.map(validateBinding);
  const profiles = new Set(delegateBindings.map((item) => item.profileId));
  const delegates = new Set(delegateBindings.map((item) => item.delegateId));
  if (profiles.size !== delegateBindings.length || delegates.size !== delegateBindings.length) {
    throw codeError("host_delegate_binding_duplicate");
  }
  if (!unclaimed && (!delegateBindings.length || !profiles.has(canonicalProfileId))) {
    throw codeError("host_canonical_profile_invalid");
  }
  return Object.freeze({
    region,
    principalId,
    hostInstallationId: value.hostInstallationId,
    canonicalProfileId,
    state: value.state,
    delegateBindings: Object.freeze(delegateBindings),
    createdAt: safeTimestamp(value.createdAt),
    updatedAt: safeTimestamp(value.updatedAt),
  });
}

function validateBinding(value) {
  assertExactKeys(value, ["adapters", "authorizationVersion", "delegateId", "profileId"], "host_delegate_binding_fields_invalid");
  if (!Array.isArray(value.adapters) || !value.adapters.length || value.adapters.length > 32) {
    throw codeError("host_delegate_adapters_invalid");
  }
  const adapters = value.adapters.map((item) => assertIdentifier(item, "host_adapter_id_invalid"));
  const canonical = [...new Set(adapters)].sort();
  if (canonical.length !== adapters.length || canonical.some((item, index) => item !== adapters[index])) {
    throw codeError("host_delegate_adapters_noncanonical");
  }
  const authorizationVersion = Number(value.authorizationVersion);
  if (!Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1) {
    throw codeError("host_authorization_version_invalid");
  }
  return Object.freeze({
    profileId: assertIdentifier(value.profileId, "host_profile_id_invalid"),
    delegateId: assertIdentifier(value.delegateId, "host_delegate_id_invalid"),
    authorizationVersion,
    adapters: Object.freeze(adapters),
  });
}

async function writeRegistry(path, registry) {
  const root = dirname(path);
  await assertSecureDirectory(root, true);
  const output = `${JSON.stringify(registry, null, 2)}\n`;
  if (Buffer.byteLength(output) > MAX_REGISTRY_BYTES) throw codeError("host_registry_too_large");
  const temp = join(root, `.${basename(path)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let handle;
  try {
    handle = await open(temp, "wx", 0o600);
    await handle.writeFile(output, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await chmod(temp, 0o600);
    await applyCurrentUserAcl(temp, false);
    for (let attempt = 0; ; attempt += 1) {
      try {
        await rename(temp, path);
        break;
      } catch (error) {
        const transient = ["EACCES", "EBUSY", "EPERM"].includes(error?.code);
        if (!transient || attempt >= 20) throw error;
        await new Promise((resolveWait) => setTimeout(resolveWait, 5 * (attempt + 1)));
      }
    }
  } finally {
    await handle?.close().catch(() => {});
    await rm(temp, { force: true }).catch(() => {});
  }
}

export function withNeutralHostStoreLock(root, name, operation) {
  if (!/^[a-z][a-z0-9-]{1,70}$/.test(name)) throw codeError("host_registry_lock_name_invalid");
  return withRegistryLock(root, join(root, `.${name}.lock`), operation);
}

async function withRegistryLock(root, lockPath, operation) {
  await assertSecureDirectory(root, true, false);
  // Serialize the whole ownership lifetime. Snapshot checks and a rename alone
  // cannot stop another stale-lock reclaimer from moving a new owner's file.
  try {
    return await withLocalProcessLock(lockPath, () => withRegistryLockUnderGuard(lockPath, operation), { timeoutMs: LOCK_TIMEOUT_MS });
  } catch (error) {
    if (error?.code === "hellolynk_local_process_lock_busy") throw codeError("host_registry_lock_timeout");
    throw error;
  }
}

async function withRegistryLockUnderGuard(lockPath, operation) {
  const deadline = performance.now() + LOCK_TIMEOUT_MS;
  let ownershipToken = null;
  while (true) {
    if (performance.now() >= deadline) throw codeError("host_registry_lock_timeout");
    try {
      ownershipToken = await publishRegistryLock(lockPath);
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (await recoverStaleRegistryLock(lockPath)) continue;
      if (performance.now() >= deadline) throw codeError("host_registry_lock_timeout");
      await new Promise((resolveWait) => setTimeout(resolveWait, 15));
    }
  }
  try { return await operation(); } finally { await releaseRegistryLock(lockPath, ownershipToken); }
}

async function publishRegistryLock(lockPath) {
  const ownershipToken = randomBytes(24).toString("hex");
  const candidatePath = `${lockPath}.candidate.${process.pid}.${randomBytes(8).toString("hex")}`;
  let handle = null;
  try {
    handle = await open(candidatePath, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify({
      contract: REGISTRY_LOCK_CONTRACT,
      pid: process.pid,
      ownershipToken,
      createdAt: Date.now(),
    })}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await chmod(candidatePath, 0o600);
    await applyCurrentUserAcl(candidatePath, false);
    await link(candidatePath, lockPath);
    return ownershipToken;
  } finally {
    await handle?.close().catch(() => {});
    await rm(candidatePath, { force: true }).catch(() => {});
  }
}

async function releaseRegistryLock(lockPath, ownershipToken) {
  try {
    const snapshot = await readRegistryLockSnapshot(lockPath);
    if (snapshot?.record.ownershipToken === ownershipToken) await rm(lockPath);
  } catch {}
}

async function recoverStaleRegistryLock(lockPath) {
  const first = await readRegistryLockSnapshotForRecovery(lockPath);
  if (first === undefined) return false;
  if (!first) return true;
  if (!registryLockEligibleForRecovery(first)) return false;
  await new Promise((resolveWait) => setTimeout(resolveWait, REGISTRY_LOCK_STABILITY_WAIT_MS));
  const second = await readRegistryLockSnapshotForRecovery(lockPath);
  if (second === undefined) return false;
  if (!second) return true;
  if (!registryLockEligibleForRecovery(second) || !sameRegistryLockSnapshot(first, second)) return false;
  const quarantinedPath = `${lockPath}.stale.${process.pid}.${randomBytes(8).toString("hex")}`;
  try {
    await rename(lockPath, quarantinedPath);
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM", "EBUSY"].includes(error?.code)) return false;
    throw error;
  }
  const quarantined = await readRegistryLockSnapshot(quarantinedPath);
  if (!quarantined || !sameRegistryLockSnapshot(second, quarantined)) {
    try {
      await link(quarantinedPath, lockPath);
      await rm(quarantinedPath);
    } catch {}
    return false;
  }
  await rm(quarantinedPath);
  return true;
}

async function readRegistryLockSnapshotForRecovery(lockPath) {
  try {
    return await readRegistryLockSnapshot(lockPath);
  } catch (error) {
    if (["EACCES", "EBUSY", "EPERM"].includes(error?.code)) return undefined;
    throw error;
  }
}

async function readRegistryLockSnapshot(lockPath) {
  let before;
  try { before = await lstat(lockPath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (before.isDirectory() && !before.isSymbolicLink()) {
    throw codeError("host_registry_legacy_lock_requires_manual_recovery");
  }
  if (before.isSymbolicLink() || !before.isFile() || before.size > MAX_REGISTRY_LOCK_BYTES) {
    throw codeError("host_registry_lock_path_invalid");
  }
  let handle;
  let body;
  let metadata;
  try {
    const noFollow = Number(fsConstants.O_NOFOLLOW || 0);
    handle = await open(lockPath, fsConstants.O_RDONLY | noFollow);
    metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > MAX_REGISTRY_LOCK_BYTES
      || !sameRegistryLockFileIdentity(before, metadata)) {
      return null;
    }
    body = await handle.readFile();
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
  if (body.length !== metadata.size) throw codeError("host_registry_lock_path_invalid");
  let after;
  try { after = await lstat(lockPath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!after.isFile() || after.isSymbolicLink()
    || !sameRegistryLockFileIdentity(metadata, after)
    || after.size !== metadata.size || after.mtimeMs !== metadata.mtimeMs) {
    return null;
  }
  let record;
  try { record = JSON.parse(body.toString("utf8")); }
  catch { throw codeError("host_registry_lock_path_invalid"); }
  assertExactKeys(record, ["contract", "createdAt", "ownershipToken", "pid"], "host_registry_lock_path_invalid");
  if (record.contract !== REGISTRY_LOCK_CONTRACT
    || !Number.isSafeInteger(Number(record.pid)) || Number(record.pid) <= 0
    || typeof record.ownershipToken !== "string" || record.ownershipToken.length < 16
    || !Number.isFinite(Number(record.createdAt))) {
    throw codeError("host_registry_lock_path_invalid");
  }
  return Object.freeze({ metadata, body, record: Object.freeze({ ...record, pid: Number(record.pid) }) });
}

function registryLockEligibleForRecovery(snapshot) {
  return Date.now() - snapshot.metadata.mtimeMs >= REGISTRY_LOCK_STALE_MS
    && processDefinitelyDead(snapshot.record.pid);
}

function processDefinitelyDead(pid) {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return error?.code === "ESRCH";
  }
}

function sameRegistryLockSnapshot(left, right) {
  return (
    sameRegistryLockFileIdentity(left.metadata, right.metadata)
    && left.metadata.size === right.metadata.size
    && left.metadata.mtimeMs === right.metadata.mtimeMs
    && left.body.length === right.body.length
    && timingSafeEqual(left.body, right.body)
  );
}

function sameRegistryLockFileIdentity(left, right) {
  if (process.platform === "win32" && (left.dev === 0 || right.dev === 0)
    && left.ino !== right.ino) return false;
  if (Number.isSafeInteger(left.dev) && Number.isSafeInteger(left.ino)
    && Number.isSafeInteger(right.dev) && Number.isSafeInteger(right.ino)) {
    return left.ino === right.ino
      && (left.dev === right.dev
        || (process.platform === "win32" && (left.dev === 0 || right.dev === 0)));
  }
  return left.size === right.size && left.mtimeMs === right.mtimeMs;
}

async function assertSecureDirectory(path, create, secureAcl = true) {
  if (!isAbsolute(path)) throw codeError("host_store_root_invalid");
  const created = create ? await mkdir(path, { recursive: true, mode: 0o700 }) : undefined;
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw codeError("host_store_root_invalid");
  if (secureAcl || created !== undefined) {
    await chmod(path, 0o700);
    await applyCurrentUserAcl(path, true);
  }
}

let currentUserSidPromise;
function currentWindowsUserSid() {
  // The process token does not change during ordinary Host operations. Retry
  // lookup failures, but do not launch whoami for every newly written file.
  if (!currentUserSidPromise) currentUserSidPromise = spawnText(join(WINDOWS_SYSTEM_DIR, "whoami.exe"), ["/user", "/fo", "csv", "/nh"])
    .then(output => {
      const sid = output.match(/S-1-[0-9-]+/)?.[0];
      if (!sid) throw codeError("host_store_sid_unavailable");
      return sid;
    }).catch(error => { currentUserSidPromise = undefined; throw error; });
  return currentUserSidPromise;
}

export async function applyCurrentUserAcl(path, directory) {
  if (process.platform !== "win32") return;
  const sid = await currentWindowsUserSid();
  const permission = directory ? `(OI)(CI)F` : "F";
  try {
    await spawnText(join(WINDOWS_SYSTEM_DIR, "icacls.exe"), [path, "/setowner", `*${sid}`]);
  } catch (error) {
    if (await readWindowsOwnerSid(path) !== sid) throw error;
  }
  const grants = directory
    ? [`*${sid}:${permission}`, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]
    : [`*${sid}:${permission}`];
  await spawnText(join(WINDOWS_SYSTEM_DIR, "icacls.exe"), [path, "/inheritance:r", "/grant:r", ...grants]);
}

async function readWindowsOwnerSid(path) {
  const script = "$ErrorActionPreference='Stop'; $p=$env:HELLOLYNK_ACL_TARGET; "
    + "if([IO.Directory]::Exists($p)){$acl=[IO.Directory]::GetAccessControl($p)}else{$acl=[IO.File]::GetAccessControl($p)}; "
    + "$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value";
  return (await spawnText(join(WINDOWS_SYSTEM_DIR, "WindowsPowerShell", "v1.0", "powershell.exe"), [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
  ], { HELLOLYNK_ACL_TARGET: path })).trim();
}

function spawnText(file, args, environment = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(file, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: sanitizeHelloLynkChildEnvironment(process.env, environment),
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolvePromise(Buffer.concat(stdout).toString("utf8"));
      else reject(codeError(Buffer.concat(stderr).toString("utf8").trim() || "host_acl_failed"));
    });
  });
}

function publicInstallation(value) {
  return Object.freeze({
    region: value.region,
    principalId: value.principalId,
    hostInstallationId: value.hostInstallationId,
    canonicalProfileId: value.canonicalProfileId,
    state: value.state,
    delegateBindings: Object.freeze(value.delegateBindings.map(cloneBinding)),
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  });
}

function cloneBinding(value) {
  return {
    profileId: value.profileId,
    delegateId: value.delegateId,
    authorizationVersion: value.authorizationVersion,
    adapters: [...value.adapters],
  };
}

function assertExactKeys(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw codeError(code);
}

function assertAbsoluteRoot(value) {
  const root = resolve(String(value || ""));
  if (!isAbsolute(root) || root.length < 4) throw codeError("host_store_root_invalid");
  return root;
}

function assertExplicitProfileFile(value) {
  const text = String(value || "");
  if (!text || !isAbsolute(text)) throw codeError("host_profile_file_required");
  return resolve(text);
}

function safeTimestamp(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) throw codeError("host_timestamp_invalid");
  return result;
}

function normalizeClock(value) {
  if (value == null) return () => Date.now();
  if (typeof value === "function") return value;
  if (typeof value?.now === "function") return () => value.now();
  throw codeError("host_clock_invalid");
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
