import { checkDarwinPath, DARWIN_HELPER, invokeDarwinHelper, withDarwinVault } from "./hellolynk-darwin-vault.mjs";
import { AsyncLocalStorage } from "node:async_hooks";
import { spawn as nodeSpawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { inspectProcessIdentity } from "./hellolynk-local-process-lock.mjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CLIENTS_DIR = dirname(MODULE_DIR);
const MAX_OUTPUT_BYTES = 256 * 1024;
const RUNTIME_SESSION_LOCK_WAIT_MS = 25;
const RUNTIME_SESSION_LOCK_STALE_MS = 15_000;
// A holder can load a persisted session, make two bounded recovery requests,
// then save it. The client request cap is 30 seconds per request.
const RUNTIME_SESSION_RECOVERY_REQUEST_TIMEOUT_MS = 30_000;
const MAX_E2EE_PRIVATE_KEY_MATERIAL_BYTES = 96 * 1024;
// A Host start reads every profile's keys in one helper process. Its output
// may exceed one read's cap by at most the base64 of one capped read per profile.
const MAX_E2EE_BATCH_PROFILES = 64;
const MAX_E2EE_BATCH_ITEM_OUTPUT_BYTES = Math.ceil(MAX_OUTPUT_BYTES / 3) * 4 + 256;
const MAX_E2EE_BATCH_OUTPUT_BYTES = MAX_E2EE_BATCH_PROFILES * MAX_E2EE_BATCH_ITEM_OUTPUT_BYTES + 2;
export const E2EE_PRIVATE_KEY_MATERIAL_SCHEMA_VERSION = 2;
export const E2EE_PRIVATE_KEY_MATERIAL_FORMAT = "hellolynk_direct_text_e2ee_private_keys_v2";

export class HelloLynkCredentialStoreError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkCredentialStoreError";
    this.code = code;
  }
}

export function assertCredentialProfileId(value) {
  const profileId = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/.test(profileId)) {
    throw new HelloLynkCredentialStoreError("invalid_credential_profile_id");
  }
  return profileId;
}

function assertCredential(value) {
  const credential = String(value || "");
  if (!/^hellolynk_device_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$/.test(credential)) {
    throw new HelloLynkCredentialStoreError("invalid_device_credential_format");
  }
  return credential;
}

function assertRuntimeSession(value) {
  const session = value && typeof value === "object" ? value : null;
  const safeId = (candidate) => /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(String(candidate || ""));
  const allowedScopes = Array.isArray(session?.allowedScopes) ? session.allowedScopes.map(String) : [];
  const delegateId = session?.delegateId == null ? null : String(session.delegateId);
  const hostId = session?.hostId == null ? null : String(session.hostId);
  const authorizationVersion = session?.authorizationVersion == null
    ? null : Number(session.authorizationVersion);
  const routeFieldCount = [delegateId, hostId, authorizationVersion]
    .filter((item) => item != null).length;
  if (
    !session ||
    !safeId(session.sessionId) ||
    !safeId(session.runtimeId) ||
    !safeId(session.principalId) ||
    !safeId(session.agentId) ||
    !safeId(session.deviceId) ||
    !/^runtime_[a-f0-9]{48}$/.test(String(session.sessionSecret || "")) ||
    (routeFieldCount !== 0 && routeFieldCount !== 3) ||
    (routeFieldCount === 3 && (
      !safeId(delegateId) || !safeId(hostId)
      || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1
    )) ||
    !Number.isFinite(Number(session.expiresAtMs))
  ) throw new HelloLynkCredentialStoreError("invalid_runtime_session_handle");
  return {
    sessionId: String(session.sessionId),
    sessionSecret: String(session.sessionSecret),
    runtimeId: String(session.runtimeId),
    principalId: String(session.principalId),
    agentId: String(session.agentId),
    ...(routeFieldCount === 3 ? { delegateId, hostId, authorizationVersion } : {}),
    deviceId: String(session.deviceId),
    allowedScopes,
    expiresAtMs: Number(session.expiresAtMs),
  };
}

function encodeDirectTextPrivateKeyMaterial(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkCredentialStoreError("invalid_e2ee_private_key_material");
  }
  let privateKeyMaterial;
  try {
    privateKeyMaterial = JSON.stringify(value);
  } catch {
    throw new HelloLynkCredentialStoreError("invalid_e2ee_private_key_material");
  }
  if (
    !privateKeyMaterial
    || Buffer.byteLength(privateKeyMaterial, "utf8") > MAX_E2EE_PRIVATE_KEY_MATERIAL_BYTES
  ) throw new HelloLynkCredentialStoreError("invalid_e2ee_private_key_material");
  const encoded = JSON.stringify({
    schemaVersion: E2EE_PRIVATE_KEY_MATERIAL_SCHEMA_VERSION,
    format: E2EE_PRIVATE_KEY_MATERIAL_FORMAT,
    privateKeyMaterial,
  });
  if (Buffer.byteLength(encoded, "utf8") > MAX_OUTPUT_BYTES) {
    throw new HelloLynkCredentialStoreError("invalid_e2ee_private_key_material");
  }
  return encoded;
}

function decodeDirectTextPrivateKeyMaterial(value) {
  try {
    const wrapper = JSON.parse(String(value || ""));
    const fields = Object.keys(wrapper || {});
    if (
      fields.length !== 3
      || !fields.includes("schemaVersion")
      || !fields.includes("format")
      || !fields.includes("privateKeyMaterial")
      || wrapper.schemaVersion !== E2EE_PRIVATE_KEY_MATERIAL_SCHEMA_VERSION
      || wrapper.format !== E2EE_PRIVATE_KEY_MATERIAL_FORMAT
      || typeof wrapper.privateKeyMaterial !== "string"
      || Buffer.byteLength(wrapper.privateKeyMaterial, "utf8") > MAX_E2EE_PRIVATE_KEY_MATERIAL_BYTES
    ) throw new Error("schema");
    const decoded = JSON.parse(wrapper.privateKeyMaterial);
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("material");
    return decoded;
  } catch {
    throw new HelloLynkCredentialStoreError("invalid_e2ee_private_key_material");
  }
}

// Entries come back in request order; a present value is checked exactly as
// a single read would check it, so a damaged file fails instead of looking absent.
function decodeDirectTextPrivateKeyBatch(output, profileIds) {
  let entries = null;
  try { entries = JSON.parse(String(output || "")); } catch {}
  if (!Array.isArray(entries) || entries.length !== profileIds.length) {
    throw new HelloLynkCredentialStoreError("e2ee_private_key_batch_invalid");
  }
  return entries.map((entry, index) => {
    const fields = entry && typeof entry === "object" && !Array.isArray(entry) ? Object.keys(entry) : [];
    if (entry?.profileId !== profileIds[index]) throw new HelloLynkCredentialStoreError("e2ee_private_key_batch_invalid");
    if (entry.state === "missing" && fields.length === 2) return { profileId: entry.profileId, output: null };
    if (entry.state !== "present" || fields.length !== 3 || typeof entry.value !== "string"
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(entry.value)) throw new HelloLynkCredentialStoreError("e2ee_private_key_batch_invalid");
    const value = Buffer.from(entry.value, "base64").toString("utf8");
    decodeDirectTextPrivateKeyMaterial(value);
    return { profileId: entry.profileId, output: value };
  });
}

export function runCredentialHelper(file, args, options = {}) {
  const spawnImpl = options.spawnImpl || nodeSpawn;
  const stdin = options.stdin == null ? "" : String(options.stdin);
  const timeoutMs = Math.min(Math.max(Number(options.timeoutMs) || 10_000, 1_000), 30_000);
  const maxStdoutBytes = Math.min(Math.max(Number(options.maxOutputBytes) || MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES),
    MAX_E2EE_BATCH_OUTPUT_BYTES);
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(file, args, {
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...sanitizeHelloLynkChildEnvironment(process.env, options.env),
          ...(options.trustedHelperEnvironment || {}),
        },
      });
    } catch (error) {
      reject(new HelloLynkCredentialStoreError("credential_helper_unavailable", { cause: error }));
      return;
    }
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    let terminalCode = null;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    // Timeout/overflow is an unconfirmed operation, never evidence that the
    // native write was cancelled. Its first cause survives errors from kill.
    const stop = (code) => {
      if (settled || terminalCode) return;
      terminalCode = code;
      try { child.kill(); } catch {}
      finish(() => reject(new HelloLynkCredentialStoreError(terminalCode)));
    };
    const timer = setTimeout(() => stop("credential_helper_timeout"), timeoutMs);
    child.on("error", (error) => finish(() => reject(
      new HelloLynkCredentialStoreError(terminalCode || "credential_helper_unavailable", { cause: error }),
    )));
    child.stdout.on("data", (chunk) => {
      if (settled || terminalCode) return;
      if (stdout.length + chunk.length > maxStdoutBytes) { stop("credential_helper_output_too_large"); return; }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", (chunk) => {
      if (settled || terminalCode) return;
      if (stderr.length + chunk.length > MAX_OUTPUT_BYTES) { stop("credential_helper_output_too_large"); return; }
      stderr = Buffer.concat([stderr, chunk]);
    });
    for (const stream of [child.stdin, child.stdout, child.stderr]) {
      stream.on("error", () => stop("credential_helper_failed"));
    }
    child.on("close", (code) => finish(() => {
      if (terminalCode) {
        reject(new HelloLynkCredentialStoreError(terminalCode));
      } else if (code !== 0) {
        const helperCode = stderr.toString("utf8").trim();
        reject(new HelloLynkCredentialStoreError(
          /^[a-z][a-z0-9_]{0,127}$/.test(helperCode) ? helperCode : "credential_helper_failed",
        ));
      } else {
        resolve(stdout.toString("utf8").replace(/[\r\n]+$/, ""));
      }
    }));
    try { child.stdin.end(stdin); } catch { stop("credential_helper_failed"); }
  });
}

function windowsClientRootForStore(storeRoot) {
  const absolute = resolve(String(storeRoot || ""));
  return basename(absolute).toLowerCase() === "credentials" ? dirname(absolute) : absolute;
}

export async function runWindowsClientTrustCommand(command, options = {}) {
  if ((options.platform || process.platform) !== "win32") {
    throw new HelloLynkCredentialStoreError("windows_client_trust_unavailable");
  }
  const shell = options.powerShellPath || "pwsh";
  const script = options.helperPath || join(CLIENTS_DIR, "platform", "windows", "credential-store.ps1");
  const profileId = assertCredentialProfileId(options.profileId);
  const clientRoot = String(options.clientRoot || "");
  if (!clientRoot) throw new HelloLynkCredentialStoreError("client_root_unavailable");
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
    "-Command", command,
    "-ProfileId", profileId,
    "-ClientRoot", clientRoot,
  ];
  if (options.managedRelativePath != null) {
    args.push("-ManagedRelativePath", String(options.managedRelativePath));
  }
  return (options.runHelper || runCredentialHelper)(shell, args, {
    spawnImpl: options.spawnImpl,
    timeoutMs: options.timeoutMs,
    stdin: options.stdin == null ? "" : String(options.stdin),
  });
}

export async function prepareWindowsClientRoot(clientRoot, options = {}) {
  if ((options.platform || process.platform) === "darwin") {
    checkDarwinPath(clientRoot, { directory: true, create: true, privateMode: true });
    for (const sub of ["profiles", "credentials", "e2ee-private-keys", "status", "host", "host/runtime", "releases"]) {
      checkDarwinPath(join(clientRoot, sub), { directory: true, create: true, privateMode: true });
    }
    await invokeDarwinHelper(options.helperPath || DARWIN_HELPER, ["verify-acl", clientRoot]);
    return "prepared";
  }
  return runWindowsClientTrustCommand("PrepareRoot", {
    ...options,
    clientRoot,
    profileId: options.profileId || "root-validation",
  });
}

export async function secureWindowsClientReleaseTree(clientRoot, releaseId, options = {}) {
  const acceptedReleaseId = String(releaseId || "");
  if (!/^(?!\.{1,2}$)[A-Za-z0-9.][A-Za-z0-9_.-]{2,191}$/.test(acceptedReleaseId)) {
    throw new HelloLynkCredentialStoreError("client_release_path_invalid");
  }
  if ((options.platform || process.platform) === "darwin") {
    checkDarwinPath(clientRoot, { directory: true, privateMode: true });
    checkDarwinPath(join(clientRoot, "releases"), { directory: true, privateMode: true });
    const release = join(clientRoot, "releases", acceptedReleaseId);
    checkDarwinPath(release, { directory: true });
    await invokeDarwinHelper(options.helperPath || DARWIN_HELPER, [options.verifyOnly ? "verify-tree" : "secure-tree", release]);
    return options.verifyOnly ? "verified" : "secured";
  }
  return runWindowsClientTrustCommand(options.verifyOnly === true ? "VerifyReleaseTree" : "SecureReleaseTree", {
    ...options,
    clientRoot,
    profileId: options.profileId || "release-validation",
    managedRelativePath: `releases\\${acceptedReleaseId}`,
  });
}

export function createPlatformCredentialStore(options = {}) {
  const platform = options.platform || process.platform;
  const run = options.runHelper || runCredentialHelper;
  const runnerOptions = {
    spawnImpl: options.spawnImpl,
    timeoutMs: options.timeoutMs,
  };

  if (platform === "win32") {
    const shell = options.powerShellPath || "pwsh";
    const script = options.helperPath || join(CLIENTS_DIR, "platform", "windows", "credential-store.ps1");
    const runtimeStoreRoot = options.storeRoot || (
      process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, "HelloLynk", "credentials") : null
    );
    if (!runtimeStoreRoot) throw new HelloLynkCredentialStoreError("credential_store_root_unavailable");
    const clientRoot = options.clientRoot || windowsClientRootForStore(runtimeStoreRoot);
    const e2eeStoreRoot = options.e2eeStoreRoot || join(clientRoot, "e2ee-private-keys");
    const storeRootArgs = [
      "-ClientRoot", clientRoot,
      "-StoreRoot", runtimeStoreRoot,
    ];
    if (
      runtimeStoreRoot
      && e2eeStoreRoot
      && resolve(runtimeStoreRoot).toLowerCase() === resolve(e2eeStoreRoot).toLowerCase()
    ) throw new HelloLynkCredentialStoreError("e2ee_private_key_store_not_separated");
    const invoke = (command, profileId, stdin) => run(shell, [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
      "-Command", command, "-ProfileId", profileId, ...storeRootArgs,
    ], { ...runnerOptions, stdin });
    const invokeE2ee = (command, profileId, stdin, extra = {}) => {
      if (!e2eeStoreRoot) throw new HelloLynkCredentialStoreError("e2ee_private_key_store_root_unavailable");
      return run(shell, [
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
        "-Command", command,
        "-ProfileId", profileId,
        ...storeRootArgs,
        "-E2eeStoreRoot", e2eeStoreRoot,
      ], { ...runnerOptions, stdin, ...extra });
    };
    // A helper read is reused only while the file, the helper and every
    // ancestor of both keep the identity seen just before that read. Saves
    // replace the file; ACL, reparse-point, directory or helper changes alter
    // the identity, so the helper checks them again. Own saves and removes
    // clear it; a save confirmed under this instance's lock re-seeds it.
    const e2eeReads = new Map();
    // Bumped when an own save or remove starts and ends. A read that began
    // before then cannot seed the cache, even with a matching identity.
    const e2eeWrites = new Map();
    const e2eeWriteMark = (profileId) => e2eeWrites.set(profileId, (e2eeWrites.get(profileId) || 0) + 1);
    const e2eeReadIdentity = (profileId) => protectedReadIdentity([
      join(resolve(e2eeStoreRoot), `direct-text-private-keys-${profileId}.dpapi.clixml`),
      resolve(script),
    ]);
    // What a save leaves alone: the helper chain and the key directory's
    // parent with its ancestors (renaming or replacing the key directory
    // changes that parent too).
    const e2eeOuterIdentity = () => protectedReadIdentity([resolve(script)], [dirname(resolve(e2eeStoreRoot))]);
    // Set while this instance's lock callback for a profile runs. Every writer
    // of a profile's key file holds that cross-process lock.
    const lockScopes = new AsyncLocalStorage();
    return {
      platform,
      async save(profile, credential) {
        await invoke("Store", assertCredentialProfileId(profile), assertCredential(credential));
      },
      async load(profile) {
        return assertCredential(await invoke("Load", assertCredentialProfileId(profile), ""));
      },
      async remove(profile) {
        await invoke("Remove", assertCredentialProfileId(profile), "");
      },
      runtimeSessions: {
        async save(profile, session) {
          const body = JSON.stringify({ schemaVersion: 1, ...assertRuntimeSession(session) });
          await invoke("StoreRuntimeSession", assertCredentialProfileId(profile), body);
        },
        async load(profile) {
          const output = await invoke("LoadRuntimeSession", assertCredentialProfileId(profile), "");
          if (output === "missing") return null;
          try {
            const parsed = JSON.parse(output);
            if (parsed?.schemaVersion !== 1) throw new Error("schema");
            return assertRuntimeSession(parsed);
          } catch (error) {
            if (error instanceof HelloLynkCredentialStoreError) throw error;
            throw new HelloLynkCredentialStoreError("invalid_runtime_session_handle", { cause: error });
          }
        },
        async remove(profile) {
          await invoke("RemoveRuntimeSession", assertCredentialProfileId(profile), "");
        },
        async withLock(profile, operation) {
          if (!runtimeStoreRoot) throw new HelloLynkCredentialStoreError("credential_store_root_unavailable");
          if (typeof operation !== "function") throw new HelloLynkCredentialStoreError("runtime_session_lock_operation_invalid");
          const profileId = assertCredentialProfileId(profile);
          return withRuntimeSessionFileLock(
            runtimeStoreRoot,
            profileId,
            () => {
              // Inactive before the lock is released, so work that outlives
              // the callback counts as unlocked.
              const scope = { profileId, active: true };
              return lockScopes.run(scope, async () => {
                try { return await operation(); } finally { scope.active = false; }
              });
            },
            options.runtimeSessionLockDependencies,
            runnerOptions.timeoutMs,
          );
        },
      },
      directTextPrivateKeys: {
        async save(profile, privateKeyMaterial) {
          const profileId = assertCredentialProfileId(profile);
          const scope = lockScopes.getStore();
          const locked = scope?.active === true && scope.profileId === profileId;
          let written = null;
          e2eeReads.delete(profileId);
          e2eeWriteMark(profileId);
          try {
            const encoded = encodeDirectTextPrivateKeyMaterial(privateKeyMaterial);
            const outer = locked ? await e2eeOuterIdentity() : null;
            const output = await invokeE2ee("StoreE2eePrivateKeys", profileId, encoded);
            // Under the lock no other writer can replace the file, so a
            // confirmed save is what the next read would return, unless
            // something the save leaves alone changed meanwhile.
            if (outer && output === "stored") {
              const [identity, outerAfter] = await Promise.all([e2eeReadIdentity(profileId), e2eeOuterIdentity()]);
              if (identity && outerAfter === outer && scope.active) written = { identity, output: encoded };
            }
          } finally {
            e2eeWriteMark(profileId);
            if (written) e2eeReads.set(profileId, written);
            else e2eeReads.delete(profileId);
          }
        },
        async load(profile) {
          const profileId = assertCredentialProfileId(profile);
          const writes = e2eeWrites.get(profileId);
          const before = await e2eeReadIdentity(profileId);
          const cached = e2eeReads.get(profileId);
          // Decode again on every hit: callers mutate state before saving.
          if (before && cached?.identity === before) return decodeDirectTextPrivateKeyMaterial(cached.output);
          e2eeReads.delete(profileId);
          const output = await invokeE2ee("LoadE2eePrivateKeys", profileId, "");
          if (output === "missing") return null;
          const material = decodeDirectTextPrivateKeyMaterial(output);
          if (before && e2eeWrites.get(profileId) === writes) e2eeReads.set(profileId, { identity: before, output });
          return material;
        },
        // Seeds the read cache for many profiles with one helper process; each
        // later load still checks its file identity. Missing keys seed nothing.
        async preload(profiles) {
          const profileIds = [...new Set((Array.isArray(profiles) ? profiles : []).map(assertCredentialProfileId))];
          if (profileIds.length === 0) return;
          if (profileIds.length > MAX_E2EE_BATCH_PROFILES) throw new HelloLynkCredentialStoreError("e2ee_private_key_batch_invalid");
          const writes = profileIds.map((profileId) => e2eeWrites.get(profileId));
          const before = await Promise.all(profileIds.map(e2eeReadIdentity));
          // Up to 64 reads share one process, so it gets the helper's longest wait.
          const output = await invokeE2ee("LoadE2eePrivateKeysBatch", "e2ee-key-batch", JSON.stringify(profileIds),
            { maxOutputBytes: profileIds.length * MAX_E2EE_BATCH_ITEM_OUTPUT_BYTES + 2, timeoutMs: 30_000 });
          decodeDirectTextPrivateKeyBatch(output, profileIds).forEach((entry, index) => {
            if (entry.output == null || !before[index] || e2eeWrites.get(entry.profileId) !== writes[index]) return;
            e2eeReads.set(entry.profileId, { identity: before[index], output: entry.output });
          });
        },
        async remove(profile) {
          const profileId = assertCredentialProfileId(profile);
          e2eeReads.delete(profileId);
          e2eeWriteMark(profileId);
          try {
            await invokeE2ee("RemoveE2eePrivateKeys", profileId, "");
          } finally { e2eeWriteMark(profileId); e2eeReads.delete(profileId); }
        },
      },
    };
  }

  if (platform === "darwin") {
    const clientRoot = options.clientRoot || (options.storeRoot ? windowsClientRootForStore(options.storeRoot)
      : join(homedir(), "Library", "Application Support", "HelloLynk"));
    if (clientRoot !== resolve(clientRoot) || clientRoot === "/") throw new HelloLynkCredentialStoreError("client_root_path_invalid");
    const credentials = join(clientRoot, "credentials");
    const privateKeys = join(clientRoot, "e2ee-private-keys");
    const root = options.storeRoot || credentials;
    const e2eeRoot = options.e2eeStoreRoot || privateKeys;
    if (root !== clientRoot && root !== credentials) throw new HelloLynkCredentialStoreError("credential_store_root_invalid");
    if (e2eeRoot !== privateKeys) throw new HelloLynkCredentialStoreError("e2ee_private_key_store_root_invalid");
    function entry(location, section, profile, operation, value) {
      const slot = section + ":" + assertCredentialProfileId(profile);
      return withDarwinVault({ root: location, helperPath: options.helperPath, readOnly: operation === "load", allowMissing:true }, data => {
        if (operation === "save") data[slot] = value;
        if (operation === "remove") delete data[slot];
        return data[slot] ?? null;
      });
    }
    return {
      platform,
      async save(profile, credential) { await entry(root, "device", profile, "save", assertCredential(credential)); },
      async load(profile) {
        const value = await entry(root, "device", profile, "load");
        if (value === null) throw new HelloLynkCredentialStoreError("device_credential_missing");
        return assertCredential(value);
      },
      async remove(profile) { await entry(root, "device", profile, "remove"); },
      runtimeSessions: {
        async save(profile, session) { await entry(root, "session", profile, "save", assertRuntimeSession(session)); },
        async load(profile) {
          const value = await entry(root, "session", profile, "load");
          return value === null ? null : assertRuntimeSession(value);
        },
        async remove(profile) { await entry(root, "session", profile, "remove"); },
        async withLock(profile, operation) {
          const id = assertCredentialProfileId(profile);
          if (typeof operation !== "function") throw new HelloLynkCredentialStoreError("runtime_session_lock_operation_invalid");
          checkDarwinPath(root, { directory:true, create:true, privateMode:true });
          return withRuntimeSessionFileLock(root, id, operation, options.runtimeSessionLockDependencies, options.timeoutMs);
        },
      },
      directTextPrivateKeys: {
        async save(profile, material) { await entry(e2eeRoot, "keys", profile, "save", encodeDirectTextPrivateKeyMaterial(material)); },
        async load(profile) {
          const value = await entry(e2eeRoot, "keys", profile, "load");
          return value === null ? null : decodeDirectTextPrivateKeyMaterial(value);
        },
        async remove(profile) { await entry(e2eeRoot, "keys", profile, "remove"); },
        async preload(profiles) {
          const ids = [...new Set((Array.isArray(profiles) ? profiles : []).map(assertCredentialProfileId))];
          if (!ids.length) return;
          if (ids.length > MAX_E2EE_BATCH_PROFILES) throw new HelloLynkCredentialStoreError("e2ee_private_key_batch_invalid");
          await withDarwinVault({root:e2eeRoot, helperPath:options.helperPath, readOnly:true, allowMissing:true}, data => {
            for (const id of ids) if (data["keys:" + id] !== undefined) decodeDirectTextPrivateKeyMaterial(data["keys:" + id]);
          });
        },
      },
    };
  }

  if (platform === "linux") {
    const helper = options.helperPath || join(CLIENTS_DIR, "platform", "linux", "credential-store.sh");
    // The bundled script can be copied/unpacked without an executable bit.
    // An explicitly supplied helper may be a binary, so keep its direct invocation.
    const executable = options.helperPath || "/bin/sh";
    const helperArgs = options.helperPath ? [] : [helper];
    const trustedHelperEnvironment = options.secretToolPath
      ? { HELLOLYNK_SECRET_TOOL_BIN: options.secretToolPath }
      : {};
    const invoke = (command, profileId, stdin) => run(
      executable,
      [...helperArgs, command.toLowerCase(), profileId],
      { ...runnerOptions, env: trustedHelperEnvironment, trustedHelperEnvironment, stdin },
    );
    return {
      platform,
      async save(profile, credential) {
        await invoke("Store", assertCredentialProfileId(profile), assertCredential(credential));
      },
      async load(profile) {
        return assertCredential(await invoke("Load", assertCredentialProfileId(profile), ""));
      },
      async remove(profile) {
        await invoke("Remove", assertCredentialProfileId(profile), "");
      },
    };
  }

  throw new HelloLynkCredentialStoreError("unsupported_client_platform");
}

// Type, file id, size and times (including ctime, which ACL changes update)
// of each given file or directory and of every ancestor directory. A missing,
// linked, id-less or wrongly typed component returns null: such reads are
// never cached and the helper decides.
async function protectedReadIdentity(files, directories = []) {
  const components = new Map(files.map((file) => [file, "file"]));
  for (const directory of directories) components.set(directory, "directory");
  for (const path of [...components.keys()]) {
    for (let directory = dirname(path); ; directory = dirname(directory)) {
      components.set(directory, "directory");
      if (dirname(directory) === directory) break;
    }
  }
  try {
    const entries = [...components];
    const stats = await Promise.all(entries.map(([path]) => lstat(path, { bigint: true })));
    return entries.map(([path, kind], index) => {
      const metadata = stats[index];
      if (metadata.isSymbolicLink() || metadata.ino === 0n
        || (kind === "file" ? !metadata.isFile() : !metadata.isDirectory())) throw new Error("uncacheable");
      return [path, metadata.dev, metadata.ino, metadata.mode, metadata.size,
        metadata.mtimeNs, metadata.ctimeNs, metadata.birthtimeNs].join(":");
    }).join("\n");
  } catch {
    return null;
  }
}

async function withRuntimeSessionFileLock(storeRoot, profileId, operation, dependencies = {}, helperTimeoutOption) {
  await mkdir(storeRoot, { recursive: true, mode: 0o700 });
  const rootMetadata = await lstat(storeRoot);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
    throw new HelloLynkCredentialStoreError("credential_store_root_invalid");
  }
  const lockDir = join(storeRoot, `.runtime-session-${profileId}.lock`);
  const helperTimeoutMs = Math.min(Math.max(Number(helperTimeoutOption) || 10_000, 1_000), 30_000);
  // Invalid saved data can instead take one request and three helper calls
  // (load, remove, save); the helper cap is no greater than the request cap.
  const recoveryWaitMs = 2 * RUNTIME_SESSION_RECOVERY_REQUEST_TIMEOUT_MS
    + 2 * helperTimeoutMs + 2 * RUNTIME_SESSION_LOCK_WAIT_MS;
  if (dependencies?.waitTimeoutMs !== undefined && (
    !Number.isSafeInteger(dependencies.waitTimeoutMs)
    || dependencies.waitTimeoutMs < 1
    || dependencies.waitTimeoutMs > recoveryWaitMs
  )) throw new HelloLynkCredentialStoreError("runtime_session_lock_wait_timeout_invalid");
  const waitTimeoutMs = dependencies?.waitTimeoutMs ?? recoveryWaitMs;
  const deadline = Date.now() + waitTimeoutMs;
  const ownerProcess = await inspectProcessIdentity(process.pid);
  const ownerIdentityCache = {};
  while (true) {
    const owner = {
      pid: process.pid,
      ownerIdentity: ownerProcess?.identity || null,
      generation: randomBytes(24).toString("hex"),
      createdAtMs: Date.now(),
    };
    if (!(await publishRuntimeSessionLockCandidate(lockDir, owner))) {
      await reclaimDeadRuntimeSessionLock(lockDir, dependencies, ownerIdentityCache).catch((reclaimError) => {
        if (!["ENOENT", "EACCES", "EPERM"].includes(reclaimError?.code)) throw reclaimError;
      });
      if (Date.now() >= deadline) throw new HelloLynkCredentialStoreError("runtime_session_lock_timeout");
      await new Promise((resolve) => setTimeout(resolve, RUNTIME_SESSION_LOCK_WAIT_MS));
      continue;
    }
    try {
      return await operation();
    } finally {
      await releaseRuntimeSessionLock(lockDir, owner);
    }
  }
}

async function publishRuntimeSessionLockCandidate(lockDir, owner) {
  const candidateDir = `${lockDir}.candidate.${process.pid}.${owner.generation}`;
  try {
    await mkdir(candidateDir, { mode: 0o700 });
    await writeFile(join(candidateDir, "owner.json"), `${JSON.stringify(owner)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    for (let attempt = 0; ; attempt += 1) {
      try {
        await rename(candidateDir, lockDir);
        return true;
      } catch (error) {
        const current = await lstat(lockDir).catch(() => null);
        if (current) return false;
        const transient = ["EACCES", "EBUSY", "EPERM"].includes(error?.code);
        if (!transient || attempt >= 5) throw error;
        await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1)));
      }
    }
  } finally {
    await rm(candidateDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function reclaimDeadRuntimeSessionLock(lockDir, dependencies, ownerIdentityCache) {
  const observed = await observeRuntimeSessionLock(lockDir);
  if (!(await runtimeSessionLockObservationIsStale(observed, dependencies, ownerIdentityCache))) return false;
  await dependencies?.afterStaleObservation?.({ lockDir, observed });
  const takeover = await claimRuntimeSessionLockTakeover(lockDir, observed);
  if (!takeover) return false;
  const stalePath = `${lockDir}.stale.${process.pid}.${randomBytes(8).toString("hex")}`;
  let renamed = false;
  try {
    const verified = await observeRuntimeSessionLock(lockDir);
    const sameGeneration = sameRuntimeSessionLockGeneration(observed, verified);
    await dependencies?.afterTakeoverRevalidation?.({
      lockDir,
      observed,
      verified,
      sameGeneration,
    });
    if (
      !sameGeneration
      || !(await runtimeSessionLockObservationIsStale(observed.owner ? verified : observed, dependencies, ownerIdentityCache, true))
    ) return false;
    await rename(lockDir, stalePath);
    renamed = true;
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM"].includes(error?.code)) return false;
    throw error;
  } finally {
    if (!renamed) await releaseRuntimeSessionLockTakeover(takeover).catch(() => {});
  }
  await rm(stalePath, { recursive: true, force: true });
  return true;
}

async function observeRuntimeSessionLock(lockDir) {
  const metadata = await lstat(lockDir);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new HelloLynkCredentialStoreError("runtime_session_lock_path_invalid");
  }
  let owner = null;
  try {
    owner = JSON.parse(await readFile(join(lockDir, "owner.json"), "utf8"));
  } catch {
    // A stale incomplete lock remains reclaimable after the full stale window.
  }
  return { metadata, owner };
}

async function runtimeSessionLockObservationIsStale(observation, dependencies, cache, fresh = false) {
  const ownerCreatedAtMs = Number(observation.owner?.createdAtMs);
  const createdAtMs = Number.isFinite(ownerCreatedAtMs)
    ? ownerCreatedAtMs
    : observation.metadata.mtimeMs;
  if (Date.now() - createdAtMs < RUNTIME_SESSION_LOCK_STALE_MS) return false;
  const pid = Number(observation.owner?.pid);
  if (!processAlive(pid)) return true;
  // Avoid spawning a system probe every 25 ms while a slow owner holds the
  // same lock. Death is still checked above; takeover always probes afresh.
  const key = `${pid}:${observation.owner?.generation || ""}`;
  if (fresh || cache.key !== key || performance.now() - cache.at >= 5_000) {
    const value = await (dependencies?.inspectProcessIdentity || inspectProcessIdentity)(pid);
    Object.assign(cache, { key, at: performance.now(), value });
  }
  const current = cache.value;
  if (!current) return false;
  const recorded = observation.owner?.ownerIdentity;
  // Portable self-only fallbacks and native identities are not comparable.
  // An unavailable probe never gives permission to evict a live owner.
  if (typeof recorded === "string" && current.identity
    && recorded.split(":", 1)[0] === current.identity.split(":", 1)[0]) {
    return recorded !== current.identity;
  }
  // Locks left by the installed version have no birth identity. A process
  // born after the lock cannot own it, even if Windows reused its PID.
  return Number.isFinite(current.startedAtMs) && current.startedAtMs > createdAtMs + 1_000;
}

function sameRuntimeSessionLockGeneration(left, right) {
  if (left.owner?.generation || right.owner?.generation) {
    return Boolean(
      left.owner
      && right.owner
      && left.owner.generation === right.owner.generation
      && left.owner.pid === right.owner.pid,
    );
  }
  const sameDirectory = left.metadata.dev === right.metadata.dev
    && left.metadata.ino === right.metadata.ino
    && left.metadata.birthtimeMs === right.metadata.birthtimeMs;
  if (!sameDirectory) return false;
  if (!left.owner && !right.owner) return true;
  return Boolean(
    left.owner
    && right.owner
    && left.owner.pid === right.owner.pid
    && left.owner.createdAtMs === right.owner.createdAtMs,
  );
}

async function claimRuntimeSessionLockTakeover(lockDir, observed) {
  const claimPath = join(lockDir, "takeover.json");
  const claim = {
    pid: process.pid,
    token: randomBytes(24).toString("hex"),
    observedGeneration: observed.owner?.generation || null,
    createdAtMs: Date.now(),
  };
  try {
    await writeFile(claimPath, `${JSON.stringify(claim)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    return { claimPath, claim };
  } catch (error) {
    if (["EEXIST", "ENOENT"].includes(error?.code)) return null;
    throw error;
  }
}

async function releaseRuntimeSessionLockTakeover(takeover) {
  const current = JSON.parse(await readFile(takeover.claimPath, "utf8"));
  if (current?.token !== takeover.claim.token || current?.pid !== takeover.claim.pid) return false;
  await rm(takeover.claimPath);
  return true;
}

async function releaseRuntimeSessionLock(lockDir, owner) {
  const releasedPath = `${lockDir}.released.${process.pid}.${randomBytes(8).toString("hex")}`;
  for (let attempt = 0; ; attempt += 1) {
    const observed = await observeRuntimeSessionLock(lockDir).catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    });
    if (!observed) return false;
    if (
      observed.owner?.generation !== owner.generation
      || observed.owner?.pid !== owner.pid
    ) return false;
    try {
      await rename(lockDir, releasedPath);
      break;
    } catch (error) {
      const transient = ["EACCES", "EBUSY", "EPERM"].includes(error?.code);
      if (!transient || attempt >= 20) throw error;
      await new Promise((resolve) => setTimeout(resolve, 5 * (attempt + 1)));
    }
  }
  await rm(releasedPath, { recursive: true, force: true });
  return true;
}

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}
