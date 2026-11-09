import { checkDarwinPath, DARWIN_VAULT_FILE, withDarwinVault } from "./hellolynk-darwin-vault.mjs";
import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes as cryptoRandomBytes,
} from "node:crypto";
import { lstat, mkdir, open } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { TextDecoder } from "node:util";
import { AsyncLocalStorage } from "node:async_hooks";
import { fileURLToPath } from "node:url";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

export const HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT = "hellolynk-local-data-envelope-v1";
export const HELLOLYNK_LOCAL_DATA_ENVELOPE_SCHEMA_VERSION = 1;
export const HELLOLYNK_LOCAL_DATA_ENVELOPE_ALGORITHM = "A256GCM";
export const HELLOLYNK_LOCAL_DATA_KEY_RECORD_CONTRACT = "hellolynk-local-data-key-v1";

const CURRENT_LOCAL_DATA_MIGRATION_CONTRACT = "hellolynk-local-data-migration-v1";

const ENVELOPE_FIELDS = Object.freeze([
  "algorithm",
  "ciphertext",
  "contract",
  "keyId",
  "nonce",
  "schemaVersion",
  "tag",
]);
const ENVELOPE_MARKER_FIELDS = new Set([
  "algorithm",
  "ciphertext",
  "keyId",
  "nonce",
  "tag",
]);
const KEY_ID_PATTERN = /^ldk_[A-Za-z0-9_-]{22}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const MIGRATION_STATE_FILE = "local-data-migration-v1.json";
const WINDOWS_KEY_FILE = "local-data-key-v1.dpapi.json";
const MAX_KEY_STORE_BYTES = 64 * 1024;
const HELPER_TIMEOUT_MS = 30_000;
const WINDOWS_HELPER_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "platform",
  "windows",
  "hellolynk-local-data-key.ps1",
);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function createLocalDataProtector(options = {}) {
  const binding = Object.freeze({
    region: assertBindingValue(options.region, "local_data_region_invalid"),
    principalId: assertBindingValue(options.principalId, "local_data_principal_id_invalid"),
    hostInstallationId: assertBindingValue(
      options.hostInstallationId,
      "local_data_host_installation_id_invalid",
    ),
  });
  const keyProvider = assertKeyProvider(options.keyProvider);
  const random = typeof options.randomBytes === "function" ? options.randomBytes : cryptoRandomBytes;

  async function ensureKey() {
    let record;
    try {
      record = await keyProvider.getOrCreate();
    } catch (error) {
      throw normalizeKeyProviderError(error);
    }
    return normalizeKeyRecord(record);
  }

  async function sealJson(value, context = {}) {
    const serialized = serializeJson(value);
    const record = await ensureKey();
    try {
      return sealBytes(Buffer.from(serialized, "utf8"), record, binding, context, random);
    } finally {
      record.key.fill(0);
    }
  }

  async function assertKeyAvailable(keyId) {
    const expectedKeyId = assertKeyId(keyId);
    let record;
    try {
      record = await keyProvider.load(expectedKeyId);
    } catch (error) {
      throw normalizeKeyProviderError(error);
    }
    if (record == null) throw codeError("local_data_key_missing");
    const normalized = normalizeKeyRecord(record);
    try {
      if (normalized.keyId !== expectedKeyId) throw codeError("local_data_key_id_mismatch");
      return Object.freeze({ keyId: expectedKeyId, available: true });
    } finally {
      normalized.key.fill(0);
    }
  }

  async function openJson(value, context = {}, openOptions = {}) {
    if (!looksLikeEnvelope(value)) {
      if (openOptions.requireProtected !== false) {
        throw codeError("local_data_plaintext_forbidden");
      }
      return cloneJson(value);
    }
    const envelope = assertEnvelope(value).envelope;
    let record;
    try {
      record = await keyProvider.load(envelope.keyId);
    } catch (error) {
      throw normalizeKeyProviderError(error);
    }
    if (record == null) throw codeError("local_data_key_missing");
    const normalized = normalizeKeyRecord(record);
    let plain;
    try {
      if (normalized.keyId !== envelope.keyId) throw codeError("local_data_key_id_mismatch");
      plain = openBytes(envelope, normalized, binding, context);
    } finally {
      normalized.key.fill(0);
    }
    try {
      return JSON.parse(utf8Decoder.decode(plain));
    } catch (error) {
      if (error?.code) throw error;
      throw codeError("local_data_plaintext_json_invalid");
    } finally {
      plain.fill(0);
    }
  }

  async function sealArchiveLine(value, context = {}) {
    return JSON.stringify(await sealJson(value, context));
  }

  async function openArchiveLine(line, context = {}, openOptions = {}) {
    if (typeof line !== "string" || !line || line.includes("\n") || line.includes("\r")) {
      throw codeError("local_data_archive_line_invalid");
    }
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw codeError("local_data_archive_line_invalid");
    }
    return openJson(parsed, context, openOptions);
  }

  // The former encrypted index keyed its identifiers with this derivation. The
  // one-time plaintext conversion stores it so existing rows keep their ids.
  async function deriveIndexKey(keyId, context = {}) {
    const expectedKeyId = assertKeyId(keyId);
    const normalizedContext = normalizeContext(context);
    let record;
    try {
      record = await keyProvider.load(expectedKeyId);
    } catch (error) {
      throw normalizeKeyProviderError(error);
    }
    if (record == null) throw codeError("local_data_key_missing");
    const normalized = normalizeKeyRecord(record);
    try {
      if (normalized.keyId !== expectedKeyId) throw codeError("local_data_key_id_mismatch");
      return createHmac("sha256", normalized.key).update(JSON.stringify([
        "hellolynk-local-index-key-v1", binding, normalizedContext,
      ])).digest();
    } finally {
      normalized.key.fill(0);
    }
  }

  return Object.freeze({
    contract: HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT,
    ensureKey,
    assertKeyAvailable,
    sealJson,
    openJson,
    sealArchiveLine,
    openArchiveLine,
    deriveIndexKey,
    withKeyBatch(operation) {
      if (typeof operation !== "function") throw codeError("local_data_key_batch_invalid");
      return typeof keyProvider.withBatch === "function" ? keyProvider.withBatch(operation) : operation();
    },
  });
}

export function createMemoryLocalDataKeyProvider(options = {}) {
  const random = typeof options.randomBytes === "function" ? options.randomBytes : cryptoRandomBytes;
  let current = options.record == null ? null : normalizeKeyRecord(options.record);
  return Object.freeze({
    async getOrCreate() {
      if (current == null) {
        current = normalizeKeyRecord({
          keyId: `ldk_${randomExact(random, 16, "local_data_key_generation_failed").toString("base64url")}`,
          key: randomExact(random, 32, "local_data_key_generation_failed"),
        });
      }
      return copyKeyRecord(current);
    },
    async load(keyId) {
      const id = assertKeyId(keyId);
      return current?.keyId === id ? copyKeyRecord(current) : null;
    },
    clear() {
      if (current) current.key.fill(0);
      current = null;
    },
  });
}

export async function assertLocalDataProtectionAccess(root, protectedAccess) {
  const acceptedRoot = assertAbsoluteRoot(root);
  const state = await readProtectionState(join(acceptedRoot, MIGRATION_STATE_FILE));
  if (!state) return Object.freeze({ required: false });
  if (protectedAccess !== true) throw codeError("local_data_protection_required");
  if (state.phase !== "committed") throw codeError("local_data_migration_incomplete");
  return Object.freeze({ required: true });
}

async function readProtectionState(statePath) {
  let handle;
  let contract;
  let phase;
  try {
    const before = await lstat(statePath);
    if (!before.isFile() || before.isSymbolicLink() || before.size < 2 || before.size > 1024 * 1024) {
      throw codeError("local_data_migration_state_invalid");
    }
    handle = await open(statePath, "r");
    const opened = await handle.stat();
    if (!sameFile(before, opened) || opened.size > 1024 * 1024) {
      throw codeError("local_data_migration_state_invalid");
    }
    const value = JSON.parse(await handle.readFile("utf8"));
    const fields = Object.keys(value || {}).sort().join(",");
    if (fields !== "assets,bindingDigest,contract,keyId,phase,schemaVersion"
      || value.contract !== CURRENT_LOCAL_DATA_MIGRATION_CONTRACT || value.schemaVersion !== 1
      || !["preparing", "staged", "committed"].includes(value.phase)) {
      throw codeError("local_data_migration_state_invalid");
    }
    contract = value.contract;
    phase = value.phase;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (typeof error?.code === "string" && /^local_data_[a-z0-9_]+$/.test(error.code)) throw error;
    throw codeError("local_data_migration_state_invalid");
  } finally {
    await handle?.close().catch(() => {});
  }
  return Object.freeze({ contract, phase });
}

export function createWindowsLocalDataKeyProvider(options = {}) {
  const platform = options.platform || process.platform;
  if (!["darwin", "win32"].includes(platform)) throw codeError("local_data_key_platform_unsupported");
  const root = assertAbsoluteRoot(options.root);
  const helperPath = resolve(options.helperPath || WINDOWS_HELPER_PATH);
  const invoke = options.invoke || (platform === "darwin"
    ? command => withDarwinVault({ root, helperPath:options.helperPath, readOnly:command === "Load", allowMissing:true }, state => {
      if (!state.localDataKey) {
        if (command === "Load") throw codeError("local_data_key_missing");
        state.localDataKey = { keyId:"ldk_" + cryptoRandomBytes(16).toString("base64url"), key:cryptoRandomBytes(32).toString("base64url") };
      }
      return state.localDataKey;
    })
    : command => invokeWindowsDataKey({ command, root, helperPath }));
  const slot = platform === "darwin" ? DARWIN_VAULT_FILE : WINDOWS_KEY_FILE;
  let current = null;
  let durableFingerprint = null;
  const batches = new AsyncLocalStorage();

  async function rememberDurableSlot() {
    try {
      durableFingerprint = await keySlotFingerprint(root, slot);
      const batch = batches.getStore();
      if (batch?.active) batch.record = current;
    } catch (error) {
      current?.key.fill(0);
      current = null;
      durableFingerprint = null;
      throw error;
    }
  }

  async function assertDurableSlotUnchanged() {
    const batch = batches.getStore();
    if (batch?.active && current != null && batch.record === current) return;
    let observed;
    try {
      observed = await keySlotFingerprint(root, slot);
    } catch (error) {
      current?.key.fill(0);
      current = null;
      durableFingerprint = null;
      throw error;
    }
    if (durableFingerprint == null || observed !== durableFingerprint) {
      current?.key.fill(0);
      current = null;
      durableFingerprint = null;
      throw codeError("local_data_key_store_changed");
    }
    if (batch?.active) batch.record = current;
  }

  return Object.freeze({
    async withBatch(operation) {
      if (typeof operation !== "function") throw codeError("local_data_key_batch_invalid");
      if (batches.getStore()?.active) return operation();
      const batch = { active: true, record: null };
      return batches.run(batch, async () => {
        try { return await operation(); }
        finally { batch.active = false; batch.record = null; }
      });
    },
    async getOrCreate() {
      if (current != null) {
        await assertDurableSlotUnchanged();
        return copyKeyRecord(current);
      }
      current = normalizeKeyRecord(await invoke("CreateOrLoad"));
      await rememberDurableSlot();
      return copyKeyRecord(current);
    },
    async load(keyId) {
      const expectedKeyId = assertKeyId(keyId);
      if (current != null) {
        if (current.keyId !== expectedKeyId) throw codeError("local_data_key_id_mismatch");
        await assertDurableSlotUnchanged();
        return copyKeyRecord(current);
      }
      try {
        const result = normalizeKeyRecord(await invoke("Load"));
        if (result.keyId !== expectedKeyId) throw codeError("local_data_key_id_mismatch");
        current = result;
        await rememberDurableSlot();
        return copyKeyRecord(current);
      } catch (error) {
        if (error?.code === "local_data_key_missing") return null;
        throw error;
      }
    },
    clear() {
      current?.key.fill(0);
      current = null;
      durableFingerprint = null;
    },
  });
}

async function keySlotFingerprint(root, slot) {
  const rootMetadata = await lstat(root).catch((error) => {
    if (error?.code === "ENOENT") throw codeError("local_data_key_missing");
    throw error;
  });
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw codeError("local_data_key_root_invalid");
  }
  const slotPath = join(root, slot);
  let before;
  let handle;
  try {
    before = await lstat(slotPath);
    if (slot === DARWIN_VAULT_FILE) {
      checkDarwinPath(root, { directory:true, privateMode:true });
      checkDarwinPath(slotPath, { privateMode:true });
    }
    if (!before.isFile() || before.isSymbolicLink() || before.size < 2 || before.size > MAX_KEY_STORE_BYTES) {
      throw codeError("local_data_key_store_invalid");
    }
    handle = await open(slotPath, "r");
    const opened = await handle.stat();
    if (!sameFile(before, opened) || opened.size > MAX_KEY_STORE_BYTES) {
      throw codeError("local_data_key_store_invalid");
    }
    const bytes = await handle.readFile();
    const permissions = slot === DARWIN_VAULT_FILE ? `${rootMetadata.ctimeMs}:${opened.ctimeMs}:` : "";
    return `${permissions}${opened.dev}:${opened.ino}:${createHash("sha256").update(bytes).digest("hex")}`;
  } catch (error) {
    if (error?.code === "ENOENT") throw codeError("local_data_key_missing");
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

function sameFile(left, right) {
  if (process.platform === "win32" && (left.dev === 0 || right.dev === 0)
    && left.ino !== right.ino) return false;
  return left.isFile() && right.isFile()
    && (!Number.isSafeInteger(left.dev) || !Number.isSafeInteger(left.ino)
      || !Number.isSafeInteger(right.dev) || !Number.isSafeInteger(right.ino)
      || (left.ino === right.ino
        && (left.dev === right.dev
          || (process.platform === "win32" && (left.dev === 0 || right.dev === 0)))));
}

function sealBytes(plain, record, binding, context, random) {
  const normalizedContext = normalizeContext(context);
  const nonce = randomExact(random, 12, "local_data_nonce_generation_failed");
  let ciphertext;
  let tag;
  try {
    const cipher = createCipheriv("aes-256-gcm", record.key, nonce, { authTagLength: 16 });
    cipher.setAAD(aadBytes(binding, normalizedContext, record.keyId));
    ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    tag = cipher.getAuthTag();
  } catch {
    throw codeError("local_data_encrypt_failed");
  } finally {
    plain.fill(0);
  }
  return Object.freeze({
    contract: HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT,
    schemaVersion: HELLOLYNK_LOCAL_DATA_ENVELOPE_SCHEMA_VERSION,
    algorithm: HELLOLYNK_LOCAL_DATA_ENVELOPE_ALGORITHM,
    keyId: record.keyId,
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: tag.toString("base64url"),
  });
}

function openBytes(envelope, record, binding, context) {
  const normalizedContext = normalizeContext(context);
  const nonce = decodeBase64Url(envelope.nonce, 12, "local_data_envelope_nonce_invalid");
  const ciphertext = decodeBase64Url(
    envelope.ciphertext,
    null,
    "local_data_envelope_ciphertext_invalid",
  );
  const tag = decodeBase64Url(envelope.tag, 16, "local_data_envelope_tag_invalid");
  try {
    const decipher = createDecipheriv("aes-256-gcm", record.key, nonce, { authTagLength: 16 });
    decipher.setAAD(aadBytes(binding, normalizedContext, record.keyId));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw codeError("local_data_authentication_failed");
  }
}

function aadBytes(binding, context, keyId) {
  return Buffer.from(JSON.stringify({
    contract: HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT,
    schemaVersion: HELLOLYNK_LOCAL_DATA_ENVELOPE_SCHEMA_VERSION,
    region: binding.region,
    principalId: binding.principalId,
    hostInstallationId: binding.hostInstallationId,
    profileId: context.profileId,
    assetKind: context.assetKind,
    logicalPath: context.logicalPath,
    keyId,
  }), "utf8");
}

function assertEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("local_data_envelope_invalid");
  }
  const actual = Object.keys(value).sort();
  if (actual.length !== ENVELOPE_FIELDS.length
    || actual.some((field, index) => field !== ENVELOPE_FIELDS[index])) {
    throw codeError("local_data_envelope_fields_invalid");
  }
  if (value.contract !== HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT) {
    throw codeError("local_data_envelope_contract_invalid");
  }
  if (value.schemaVersion !== HELLOLYNK_LOCAL_DATA_ENVELOPE_SCHEMA_VERSION) {
    throw codeError("local_data_envelope_version_unsupported");
  }
  if (value.algorithm !== HELLOLYNK_LOCAL_DATA_ENVELOPE_ALGORITHM) {
    throw codeError("local_data_envelope_algorithm_unsupported");
  }
  assertKeyId(value.keyId);
  decodeBase64Url(value.nonce, 12, "local_data_envelope_nonce_invalid");
  decodeBase64Url(value.ciphertext, null, "local_data_envelope_ciphertext_invalid");
  decodeBase64Url(value.tag, 16, "local_data_envelope_tag_invalid");
  return Object.freeze({
    kind: "current",
    contract: value.contract,
    schemaVersion: HELLOLYNK_LOCAL_DATA_ENVELOPE_SCHEMA_VERSION,
    envelope: value,
  });
}

export function classifyHelloLynkLocalDataEnvelope(value) {
  if (!looksLikeEnvelope(value)) return null;
  return assertEnvelope(value).kind;
}

function looksLikeEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return value.contract === HELLOLYNK_LOCAL_DATA_ENVELOPE_CONTRACT
    || Object.keys(value).some((field) => ENVELOPE_MARKER_FIELDS.has(field));
}

function normalizeContext(value) {
  return Object.freeze({
    profileId: assertBindingValue(value?.profileId, "local_data_profile_id_invalid"),
    assetKind: assertBindingValue(value?.assetKind, "local_data_asset_kind_invalid"),
    logicalPath: assertBindingValue(value?.logicalPath, "local_data_logical_path_invalid", 1024),
  });
}

function assertBindingValue(value, errorCode, maxLength = 256) {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength
    || value.includes("\0") || value.trim() !== value) {
    throw codeError(errorCode);
  }
  return value;
}

function assertKeyProvider(value) {
  if (!value || typeof value.getOrCreate !== "function" || typeof value.load !== "function") {
    throw codeError("local_data_key_provider_invalid");
  }
  return value;
}

function normalizeKeyRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw codeError("local_data_key_record_invalid");
  }
  const keyId = assertKeyId(value.keyId);
  let key;
  if (Buffer.isBuffer(value.key) || value.key instanceof Uint8Array) {
    key = Buffer.from(value.key);
  } else if (typeof value.key === "string") {
    key = decodeBase64Url(value.key, 32, "local_data_key_invalid");
  } else {
    throw codeError("local_data_key_invalid");
  }
  if (key.length !== 32) throw codeError("local_data_key_invalid");
  return { keyId, key };
}

function copyKeyRecord(record) {
  return { keyId: record.keyId, key: Buffer.from(record.key) };
}

function assertKeyId(value) {
  if (typeof value !== "string" || !KEY_ID_PATTERN.test(value)) {
    throw codeError("local_data_key_id_invalid");
  }
  return value;
}

function serializeJson(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw codeError("local_data_plaintext_json_invalid");
  }
  if (typeof serialized !== "string") throw codeError("local_data_plaintext_json_invalid");
  return serialized;
}

function cloneJson(value) {
  const serialized = serializeJson(value);
  try {
    return JSON.parse(serialized);
  } catch {
    throw codeError("local_data_plaintext_json_invalid");
  }
}

function decodeBase64Url(value, expectedLength, errorCode) {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) throw codeError(errorCode);
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw codeError(errorCode);
  }
  if (decoded.toString("base64url") !== value
    || (expectedLength != null && decoded.length !== expectedLength)) {
    throw codeError(errorCode);
  }
  return decoded;
}

function randomExact(random, size, errorCode) {
  let value;
  try {
    value = Buffer.from(random(size));
  } catch {
    throw codeError(errorCode);
  }
  if (value.length !== size) throw codeError(errorCode);
  return value;
}

function assertAbsoluteRoot(value) {
  if (typeof value !== "string" || !value || value.includes("\0") || !isAbsolute(value)) {
    throw codeError("local_data_key_root_invalid");
  }
  return resolve(value);
}

async function invokeWindowsDataKey(input) {
  try {
    return await invokeWindowsDataKeyUnsafe(input);
  } catch (error) {
    if (typeof error?.code === "string" && /^local_data_[a-z0-9_]+$/.test(error.code)) throw error;
    throw codeError("local_data_key_helper_failed");
  }
}

async function invokeWindowsDataKeyUnsafe(input) {
  let helperMetadata;
  try {
    helperMetadata = await lstat(input.helperPath);
  } catch {
    throw codeError("local_data_key_helper_invalid");
  }
  if (!helperMetadata.isFile() || helperMetadata.isSymbolicLink()) {
    throw codeError("local_data_key_helper_invalid");
  }
  if (input.command === "CreateOrLoad") {
    await mkdir(input.root, { recursive: true, mode: 0o700 });
  }
  try {
    const rootMetadata = await lstat(input.root);
    if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
      throw codeError("local_data_key_root_invalid");
    }
  } catch (error) {
    if (input.command === "Load" && error?.code === "ENOENT") {
      // The read-only helper returns the stable missing-slot error without
      // creating the root. Keep this path inside the real Windows boundary.
    } else {
      throw error;
    }
  }

  const pipeName = `HelloLynkLocalDataKey-${process.pid}-${cryptoRandomBytes(18).toString("base64url")}`;
  const pipePath = `\\\\.\\pipe\\${pipeName}`;
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", input.helperPath,
    "-Command", input.command,
    "-StoreRoot", input.root,
    "-ResultPipeName", pipeName,
  ];
  const child = spawn("pwsh.exe", args, {
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: sanitizeHelloLynkChildEnvironment(process.env),
  });
  let cancelled = false;
  const resultPromise = readCurrentUserPipe(pipePath, () => cancelled);
  resultPromise.catch(() => {});
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  let exitCode;
  let timeout;
  try {
    const exitPromise = new Promise((resolveExit, rejectExit) => {
      child.on("error", rejectExit);
      child.on("close", resolveExit);
    });
    const timeoutPromise = new Promise((_, rejectTimeout) => {
      timeout = setTimeout(() => {
        cancelled = true;
        child.kill();
        rejectTimeout(codeError("local_data_key_helper_timeout"));
      }, HELPER_TIMEOUT_MS);
      timeout.unref?.();
    });
    exitCode = await Promise.race([exitPromise, timeoutPromise]);
  } catch (error) {
    cancelled = true;
    if (child.exitCode == null) child.kill();
    if (error?.code === "local_data_key_helper_timeout") throw error;
    throw codeError("local_data_key_helper_unavailable");
  } finally {
    clearTimeout(timeout);
  }
  const stdoutText = Buffer.concat(stdout).toString("utf8");
  const stderrText = Buffer.concat(stderr).toString("utf8").trim();
  if (stdoutText.length) {
    cancelled = true;
    throw codeError("local_data_key_helper_stdout_forbidden");
  }
  if (exitCode !== 0) {
    cancelled = true;
    throw codeError(publicHelperError(stderrText));
  }
  let result;
  try {
    result = JSON.parse(await resultPromise);
  } catch (error) {
    if (error?.code) throw error;
    throw codeError("local_data_key_result_invalid");
  }
  const actual = Object.keys(result || {}).sort().join(",");
  if (actual !== "contract,key,keyId"
    || result.contract !== HELLOLYNK_LOCAL_DATA_KEY_RECORD_CONTRACT) {
    throw codeError("local_data_key_result_invalid");
  }
  return { keyId: result.keyId, key: result.key };
}

async function readCurrentUserPipe(pipePath, cancelled) {
  const deadline = Date.now() + 30_000;
  while (true) {
    try {
      return await new Promise((resolvePipe, rejectPipe) => {
        const chunks = [];
        let bytes = 0;
        const socket = createConnection(pipePath);
        socket.setTimeout(Math.max(1, deadline - Date.now()), () => {
          socket.destroy(codeError("local_data_key_result_timeout"));
        });
        socket.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 4096) {
            socket.destroy(codeError("local_data_key_result_too_large"));
            return;
          }
          chunks.push(chunk);
        });
        socket.on("error", rejectPipe);
        socket.on("end", () => resolvePipe(Buffer.concat(chunks).toString("utf8")));
      });
    } catch (error) {
      if (cancelled()) throw codeError("local_data_key_result_cancelled");
      if (error?.code !== "ENOENT" || Date.now() >= deadline) throw error;
      await new Promise((resolveWait) => setTimeout(resolveWait, 10));
    }
  }
}

function publicHelperError(value) {
  return /^[a-z][a-z0-9_]{2,127}$/.test(value)
    ? value
    : "local_data_key_helper_failed";
}

function normalizeKeyProviderError(error) {
  if (typeof error?.code === "string" && /^local_data_[a-z0-9_]+$/.test(error.code)) return error;
  return codeError("local_data_key_provider_failed");
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
