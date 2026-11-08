import { lstat, mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  assertCredentialProfileId,
  runWindowsClientTrustCommand,
} from "./hellolynk-platform-credential-store.mjs";
import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const {
  containsHelloLynkCredentialMaterial,
  normalizeHelloLynkClientProfileContainer,
} = runtimeSafety;

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const SAFE_SCOPE = /^[a-z][a-z0-9_.:-]{0,127}$/;
const MAX_PROFILE_BYTES = 64 * 1024;

export function defaultHelloLynkClientRoot(platform = process.platform, env = process.env) {
  const home = resolve(String((platform === "win32" ? env.USERPROFILE || env.HOME : env.HOME || env.USERPROFILE) || homedir()));
  if (platform === "win32") {
    const current = join(home, ".hellolynk", "hellolynk-v2");
    // Once selected, another client's older installer must not move us back.
    if (hasWindowsClientInstallation(current)) return current;
    const existing = resolve(String(env.LOCALAPPDATA || join(home, "AppData", "Local")), "HelloLynk");
    // AppData created from a packaged desktop app can be private to that app.
    // Keep an existing installation; an empty failed setup is not an account.
    if (hasWindowsClientInstallation(existing)) return existing;
    return current;
  }
  if (platform === "darwin") return join(home, "Library", "Application Support", "HelloLynk");
  return resolve(String(env.XDG_DATA_HOME || join(home, ".local", "share")), "hellolynk");
}

function hasWindowsClientInstallation(root) {
  for (const directory of ["profiles", "releases", "host", "credentials", "e2ee-private-keys"]) {
    try {
      const entries = readdirSync(join(root, directory), { withFileTypes: true });
      if (entries.some((entry) => directory !== "host" || entry.name !== "runtime")) return true;
    } catch (error) {
      // An unreadable existing location must not silently become a fresh account.
      if (error.code !== "ENOENT") return true;
    }
  }
  return false;
}

function safeId(value, code) {
  const normalized = String(value || "").trim();
  if (!SAFE_ID.test(normalized)) throw new Error(code);
  return normalized;
}

function validateProfile(value) {
  const allowedScopes = Array.isArray(value.allowedScopes) ? value.allowedScopes.map((scope) => {
    const normalized = String(scope || "");
    if (!SAFE_SCOPE.test(normalized)) throw new Error("client_profile_scope_invalid");
    return normalized;
  }) : [];
  const schemaVersion = value.schemaVersion == null ? 1 : Number(value.schemaVersion);
  if (![1, 2].includes(schemaVersion)) throw new Error("client_profile_schema_unsupported");
  const delegateId = value.delegateId == null
    ? null : safeId(value.delegateId, "client_profile_delegate_id_invalid");
  const hostId = value.hostId == null ? null : safeId(value.hostId, "client_profile_host_id_invalid");
  const authorizationVersion = value.authorizationVersion == null ? null : Number(value.authorizationVersion);
  if (
    (schemaVersion === 1 && (hostId != null || authorizationVersion != null))
    || (schemaVersion === 2 && (
      !delegateId || !hostId || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1
    ))
  ) throw new Error("client_profile_route_binding_invalid");
  return {
    contract: value.contract,
    schemaVersion,
    profileId: assertCredentialProfileId(value.profileId),
    baseUrl: normalizeHelloLynkBaseUrl(value.baseUrl, { allowLoopbackHttp: value.allowLoopbackHttp === true }),
    allowLoopbackHttp: value.allowLoopbackHttp === true,
    deviceId: safeId(value.deviceId, "client_profile_device_id_invalid"),
    credentialId: safeId(value.credentialId, "client_profile_credential_id_invalid"),
    principalId: safeId(value.principalId, "client_profile_principal_id_invalid"),
    hellolynkId: value.hellolynkId == null ? null : safeId(value.hellolynkId, "client_profile_hellolynk_id_invalid"),
    agentId: safeId(value.agentId, "client_profile_agent_id_invalid"),
    delegateId,
    ...(schemaVersion === 2 ? { hostId, authorizationVersion } : {}),
    region: safeId(value.region, "client_profile_region_invalid"),
    allowedScopes,
    platform: String(value.platform || process.platform),
  };
}

async function atomicWriteJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  const body = `${JSON.stringify(value, null, 2)}\n`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

function windowsClientFile(path, category) {
  const requested = String(path || "");
  if (!requested || !isAbsolute(requested)) throw new Error("client_root_path_invalid");
  const absolute = resolve(requested);
  const parent = dirname(absolute);
  const profileId = assertCredentialProfileId(basename(absolute, ".json"));
  const clientRoot = dirname(parent);
  if (
    basename(parent).toLowerCase() !== category
    || absolute.toLowerCase() !== join(clientRoot, category, `${profileId}.json`).toLowerCase()
  ) throw new Error("client_root_path_invalid");
  return { clientRoot, profileId };
}

async function writeWindowsClientJson(path, category, command, value) {
  const target = windowsClientFile(path, category);
  await runWindowsClientTrustCommand(command, {
    ...target,
    stdin: `${JSON.stringify(value, null, 2)}\n`,
  });
}

export async function writeClientProfile(path, value) {
  const original = JSON.stringify(value);
  if (containsHelloLynkCredentialMaterial(original)) {
    throw new Error("client_profile_contains_secret");
  }
  const container = normalizeHelloLynkClientProfileContainer(value);
  const profile = validateProfile(container.value);
  const serialized = JSON.stringify(profile);
  if (containsHelloLynkCredentialMaterial(serialized)) {
    throw new Error("client_profile_contains_secret");
  }
  if (process.platform === "win32") {
    await writeWindowsClientJson(path, "profiles", "StoreProfile", profile);
  } else {
    await atomicWriteJson(path, profile);
  }
  return profile;
}

export async function readClientProfile(path) {
  const body = await readClientProfileBody(path);
  const container = normalizeHelloLynkClientProfileContainer(JSON.parse(body));
  return validateProfile(container.value);
}

// A profile holds no secret, so Windows reads it directly too, avoiding
// one helper process per profile. Writes keep the helper.
async function readClientProfileBody(path) {
  const windows = process.platform === "win32";
  if (windows) windowsClientFile(path, "profiles");
  let metadata;
  try { metadata = await (windows ? lstat : stat)(path); }
  catch (error) { throw windows && error?.code === "ENOENT" ? new Error("client_profile_missing") : error; }
  if (!metadata.isFile()) throw new Error("client_profile_not_regular_file");
  if (metadata.size > MAX_PROFILE_BYTES) throw new Error("client_profile_too_large");
  const bytes = await readFile(path);
  if (bytes.length > MAX_PROFILE_BYTES) throw new Error("client_profile_too_large");
  let body;
  try { body = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("client_profile_invalid_utf8"); }
  if (containsHelloLynkCredentialMaterial(body)) throw new Error("client_profile_contains_secret");
  return body;
}

export async function writeSanitizedHostStatus(path, value) {
  const runtimeSessionExpiresAt = value.runtimeSessionExpiresAt == null
    ? null
    : new Date(value.runtimeSessionExpiresAt).toISOString();
  const status = {
    schemaVersion: 1,
    checkedAt: new Date(value.checkedAt || Date.now()).toISOString(),
    ok: value.ok === true,
    serviceReachable: value.serviceReachable === true,
    credentialPresent: value.credentialPresent === true,
    runtimeSessionReady: value.runtimeSessionReady === true,
    runtimeSessionExpiresAt,
    messageReceiverReady: value.messageReceiverReady === true,
    lastPollStatus: ["no_messages", "events_projected", "receiver_error"].includes(value.lastPollStatus)
      ? value.lastPollStatus
      : null,
    newEventCount: Number.isSafeInteger(Number(value.newEventCount)) && Number(value.newEventCount) >= 0
      ? Number(value.newEventCount)
      : 0,
    newNotificationCount: Number.isSafeInteger(Number(value.newNotificationCount)) && Number(value.newNotificationCount) >= 0
      ? Number(value.newNotificationCount)
      : 0,
    platform: String(value.platform || process.platform),
    errorCode: value.errorCode == null ? null : String(value.errorCode),
  };
  const serialized = JSON.stringify(status);
  if (containsHelloLynkCredentialMaterial(serialized)) {
    throw new Error("host_status_contains_secret");
  }
  if (process.platform === "win32") {
    await writeWindowsClientJson(path, "status", "StoreStatus", status);
  } else {
    await atomicWriteJson(path, status);
  }
  return status;
}
