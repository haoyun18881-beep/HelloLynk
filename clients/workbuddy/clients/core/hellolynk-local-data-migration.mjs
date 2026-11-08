import crypto from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  link,
  mkdir,
  rename,
  rm,
  open,
} from "node:fs/promises";
import path from "node:path";
import { classifyHelloLynkLocalDataEnvelope } from "./hellolynk-local-data-protection.mjs";
import {
  assertHelloLynkLocalMessageArchiveEnvelope,
  assertHelloLynkLocalMessageStore,
} from "./hellolynk-local-messaging.mjs";
import {
  assertHelloLynkLocalContactStore,
} from "./hellolynk-local-contacts.mjs";
import {
  HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT,
  convertEncryptedIndexedMessageDatabase,
} from "./hellolynk-indexed-message-store.mjs";

// Local business records are plaintext. An installation that ran the former
// encryption migration still has its journal, which keeps every store closed.
// prepare() converts those records forward once and removes the journal last,
// so an interrupted run resumes on the next start. The key slot and every
// credential file are left untouched.
export const HELLOLYNK_LOCAL_DATA_MIGRATION_CONTRACT = "hellolynk-local-data-migration-v1";

const STATE_FILE = "local-data-migration-v1.json";
const STAGE_DIRECTORY = ".local-data-migration-v1.staged";
const MAX_ASSET_BYTES = 256 * 1024 * 1024;
const MAX_STORE_LOCK_BYTES = 16 * 1024;
const STORE_LOCK_STALE_MS = 5_000;
const STORE_LOCK_STABILITY_WAIT_MS = 20;
const PROFILE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,199}$/;
const KEY_ID = /^ldk_[A-Za-z0-9_-]{22}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const STATE_FIELDS = Object.freeze([
  "assets",
  "bindingDigest",
  "contract",
  "keyId",
  "phase",
  "schemaVersion",
]);
const ASSET_STATE_FIELDS = Object.freeze([
  "assetId",
  "canonicalDigest",
  "format",
  "recordCount",
  "sourceBytesDigest",
  "stableIdsDigest",
  "stageFile",
  "targetRelativePath",
]);
export function createLocalDataMigrationCoordinator(options = {}) {
  const root = absoluteRoot(options.root);
  const region = safeId(options.region, "local_data_migration_region_invalid");
  const principalId = safeId(
    options.principalId,
    "local_data_migration_principal_id_invalid",
  );
  const hostInstallationId = safeId(
    options.hostInstallationId,
    "local_data_migration_host_installation_id_invalid",
  );
  const profileIds = normalizeProfileIds(options.profileIds);
  const canonicalProfileId = normalizeProfileId(options.canonicalProfileId);
  if (!profileIds.includes(canonicalProfileId)) {
    throw failure("local_data_migration_canonical_profile_untrusted");
  }
  if (options.createLegacyDataProtector != null && typeof options.createLegacyDataProtector !== "function") {
    throw failure("local_data_migration_protector_invalid");
  }
  const faultInjector = typeof options.faultInjector === "function"
    ? options.faultInjector
    : async () => undefined;
  const statePath = path.join(root, STATE_FILE);
  const stageRoot = path.join(root, STAGE_DIRECTORY);
  const descriptors = assetDescriptors(root, profileIds, canonicalProfileId, principalId);
  // The former journal canonicalized object keys and sorted the profile set.
  // Before commit, its plaintext backups have no envelope to prove ownership.
  const bindingDigest = digestBytes(JSON.stringify({
    canonicalProfileId, hostInstallationId, principalId, profileIds, region,
  }));

  async function prepare(lockContext = {}) {
    assertLockContext(lockContext, { region, principalId, hostInstallationId });
    await assertSafeMigrationLayout(root, stageRoot);
    await reclaimExpectedStaleStoreLocks(root, descriptors, faultInjector);
    const state = await readMigrationState(statePath, descriptors, bindingDigest);
    if (!state) {
      await removeStageDirectory(root, stageRoot);
      return Object.freeze({ phase: "plaintext", converted: false });
    }
    // An interrupted encryption never published its journal as committed; the
    // immutable source backups are the plaintext originals.
    if (state.phase === "staged") await restoreSourceBackups({ root, stageRoot, state });
    const protector = requireLegacyProtector(await options.createLegacyDataProtector?.());
    const result = await protector.withKeyBatch(() => convertProtectedAssets({
      root,
      descriptors,
      profileIds,
      keyId: state.keyId,
      protector,
      faultInjector,
    }));
    await faultInjector("journal", result);
    await rm(statePath);
    await syncDirectory(root);
    await removeStageDirectory(root, stageRoot);
    return Object.freeze({ phase: "plaintext", converted: true, ...result });
  }

  return Object.freeze({
    contract: HELLOLYNK_LOCAL_DATA_MIGRATION_CONTRACT,
    statePath,
    prepare,
  });
}

async function convertProtectedAssets({ root, descriptors, profileIds, keyId, protector, faultInjector }) {
  const decrypt = async (envelope, context) => {
    assertEnvelopeKey(envelope, keyId);
    try { return await protector.openJson(envelope, context); }
    catch (error) { throw failure("local_data_migration_protected_asset_invalid", error); }
  };
  // Decrypt and validate every file before rewriting any of them, so a damaged
  // asset leaves the installation as it was. Each database converts in one
  // transaction, and every step skips what an earlier run already converted.
  const pending = [];
  for (const item of conversionItems(descriptors)) {
    const text = await plaintextAsset(item, decrypt);
    if (text != null) pending.push({ item, text });
  }
  let rows = 0;
  for (const profileId of profileIds) {
    const result = await convertEncryptedIndexedMessageDatabase({
      storePath: path.join(root, "messages", `${profileId}.json`),
      profileId,
      isEncrypted: (value) => envelopeProtection(value) !== "plaintext",
      decrypt,
      deriveIndexKey: async (context) => {
        try { return await protector.deriveIndexKey(keyId, context); }
        catch (error) { throw failure("local_data_migration_protected_asset_invalid", error); }
      },
    });
    if (!result.converted) continue;
    rows += result.rows;
    await faultInjector("database", Object.freeze({ profileId, rows: result.rows }));
  }
  for (const { item, text } of pending) {
    await atomicWriteText(item.target, text);
    if (item.source !== item.target) {
      await rm(item.source);
      await syncDirectory(path.dirname(item.source));
    }
    await faultInjector("asset", Object.freeze({ assetId: item.descriptor.assetId }));
  }
  return Object.freeze({ assetCount: pending.length, rows });
}

function conversionItems(descriptors) {
  const items = [];
  for (const descriptor of descriptors) {
    items.push({ descriptor, source: descriptor.targetPath, target: descriptor.targetPath });
    // The indexed store kept its pre-import copy of the legacy main file.
    if (descriptor.assetId === `messages-main__${descriptor.profileId}`) {
      items.push({
        descriptor,
        source: `${descriptor.targetPath}.pre-indexed.encrypted`,
        target: `${descriptor.targetPath}.pre-indexed.json`,
      });
    }
  }
  return items;
}

async function plaintextAsset(item, decrypt) {
  if (!await optionalRegularFile(item.source)) return null;
  const { descriptor } = item;
  const { bytes } = await readRegularFile(item.source, MAX_ASSET_BYTES);
  const reveal = (value) => (envelopeProtection(value) === "plaintext"
    ? value
    : decrypt(value, descriptor.context));
  if (descriptor.format === "json") {
    const stored = parseJson(bytes);
    if (item.source === item.target && envelopeProtection(stored) === "plaintext") return null;
    const value = await reveal(stored);
    descriptor.validate(value);
    return `${JSON.stringify(value, null, 2)}\n`;
  }
  const stored = parseArchiveLines(bytes);
  if (stored.every((value) => envelopeProtection(value) === "plaintext")) return null;
  const lines = [];
  for (const line of stored) {
    const value = await reveal(line);
    descriptor.validate(value);
    lines.push(JSON.stringify(value));
  }
  return lines.length ? `${lines.join("\n")}\n` : "";
}

async function restoreSourceBackups(input) {
  const backups = [];
  for (const asset of input.state.assets) {
    const backupPath = safeChild(input.stageRoot, sourceBackupFile(asset));
    const backup = await readRegularFile(backupPath, MAX_ASSET_BYTES);
    if (digestBytes(backup.bytes) !== asset.sourceBytesDigest) {
      throw failure("local_data_migration_source_backup_invalid");
    }
    backups.push({ target: safeChild(input.root, asset.targetRelativePath), bytes: backup.bytes });
  }
  // A damaged later backup must be detected before any target is restored.
  for (const backup of backups) await atomicWriteBytes(backup.target, backup.bytes);
}

function sourceBackupFile(asset) {
  return `${asset.assetId}.source.bak`;
}

function assetDescriptors(root, profileIds, canonicalProfileId, principalId) {
  const descriptors = [];
  for (const profileId of profileIds) {
    descriptors.push(jsonDescriptor({
      root,
      profileId,
      assetId: `messages-main__${profileId}`,
      assetKind: "messages",
      targetRelativePath: `messages/${profileId}.json`,
      validate(value) {
        if (value?.storage === "sqlite") {
          assertExactFields(value, ["contract", "profileId", "storage"], "local_data_migration_indexed_fence_invalid");
          if (value.contract !== HELLOLYNK_INDEXED_MESSAGE_STORE_CONTRACT || value.profileId !== profileId) {
            throw failure("local_data_migration_indexed_fence_invalid");
          }
          return;
        }
        try { assertHelloLynkLocalMessageStore(value, profileId); }
        catch (error) { throw failure("local_data_migration_source_invalid", error); }
      },
    }));
    descriptors.push(archiveDescriptor({
      root,
      profileId,
      assetId: `messages-archive__${profileId}`,
      assetKind: "messages-archive-line",
      targetRelativePath: `messages/${profileId}.json.archive.ndjson`,
      validate(value) {
        try { assertHelloLynkLocalMessageArchiveEnvelope(value, profileId); }
        catch (error) { throw failure("local_data_migration_source_invalid", error); }
      },
    }));
    descriptors.push(jsonDescriptor({
      root,
      profileId,
      assetId: `messages-history__${profileId}`,
      assetKind: "messages",
      targetRelativePath: `messages/${profileId}.json.local-history.json`,
      validate(value) {
        assertExactFields(value, ["contractId", "schemaVersion", "profileId", "cleanupPending", "deleted", "hidden"],
          "local_data_migration_source_invalid");
        if (value.contractId !== "hellolynk-local-history-v1" || value.schemaVersion !== 1
          || value.profileId !== profileId || typeof value.cleanupPending !== "boolean"
          || !Array.isArray(value.deleted) || !Array.isArray(value.hidden)) {
          throw failure("local_data_migration_source_invalid");
        }
        for (const item of value.deleted) {
          if (item?.messageType !== "local-deleted" || typeof item.localMessageId !== "string"
            || !SAFE_ID.test(item.localMessageId)) throw failure("local_data_migration_source_invalid");
        }
        for (const item of value.hidden) {
          assertExactFields(item, ["delegateId", "knownMessageIds", "principalId", "region", "threadId"],
            "local_data_migration_source_invalid");
          if (!["intl", "cn"].includes(item.region) || !SAFE_ID.test(item.principalId)
            || !SAFE_ID.test(item.delegateId) || !SAFE_ID.test(item.threadId)
            || !Array.isArray(item.knownMessageIds) || item.knownMessageIds.some((id) => !SAFE_ID.test(id))) {
            throw failure("local_data_migration_source_invalid");
          }
        }
      },
    }));
    descriptors.push(jsonDescriptor({
      root,
      profileId,
      assetId: `contacts__${profileId}`,
      assetKind: "contacts",
      targetRelativePath: `contacts/${profileId}.json`,
      validate(value) {
        try { assertHelloLynkLocalContactStore(value, profileId); }
        catch (error) { throw failure("local_data_migration_source_invalid", error); }
      },
    }));
    descriptors.push(jsonDescriptor({
      root,
      profileId,
      assetId: `contact-requests__${profileId}`,
      assetKind: "contact-requests",
      targetRelativePath: `contact-requests/${profileId}.json`,
      validate(value) {
        if (![1, 2].includes(value?.schemaVersion) || value?.contractId !== "hellolynk-contact-request-local-store-v2"
          || value?.profileId !== profileId || !Array.isArray(value.records)) {
          throw failure("local_data_migration_source_invalid");
        }
      },
    }));
  }
  descriptors.push(jsonDescriptor({
    root,
    profileId: canonicalProfileId,
    assetId: "neutral-host-recovery",
    assetKind: "neutral-host-recovery",
    targetRelativePath: "neutral-host-recovery-v1.json",
    validate(value) {
      if (value?.contract !== "hellolynk-neutral-host-recovery-v1"
        || value?.principalId !== principalId || !Array.isArray(value.operations)) {
        throw failure("local_data_migration_source_invalid");
      }
    },
  }));
  return Object.freeze(descriptors.sort((left, right) => left.assetId.localeCompare(right.assetId)));
}

function jsonDescriptor(input) {
  return Object.freeze({
    ...input,
    format: "json",
    targetPath: safeChild(input.root, input.targetRelativePath),
    context: Object.freeze({
      profileId: input.profileId,
      assetKind: input.assetKind,
      logicalPath: input.targetRelativePath,
    }),
  });
}

function archiveDescriptor(input) {
  return Object.freeze({
    ...input,
    format: "ndjson",
    targetPath: safeChild(input.root, input.targetRelativePath),
    context: Object.freeze({
      profileId: input.profileId,
      assetKind: input.assetKind,
      logicalPath: input.targetRelativePath,
    }),
  });
}

async function reclaimExpectedStaleStoreLocks(root, descriptors, faultInjector) {
  const tokenFieldByAssetKind = Object.freeze({
    messages: "ownershipToken",
    contacts: "token",
    "contact-requests": "ownershipToken",
  });
  for (const descriptor of descriptors) {
    const tokenField = tokenFieldByAssetKind[descriptor.assetKind];
    if (!tokenField) continue;
    await reclaimExpectedStaleStoreLock(
      path.join(root, descriptor.targetRelativePath.replaceAll("/", path.sep)),
      tokenField,
      faultInjector,
    );
  }
}

async function reclaimExpectedStaleStoreLock(storePath, tokenField, faultInjector) {
  const lockPath = `${storePath}.lock`;
  const first = await readStoreLockSnapshot(lockPath);
  if (!isStaleDeadStoreLock(first, tokenField)) return false;
  await faultInjector("lock_recovery_stability_wait");
  await wait(STORE_LOCK_STABILITY_WAIT_MS);
  const second = await readStoreLockSnapshot(lockPath);
  if (!isStaleDeadStoreLock(second, tokenField) || !sameStoreLockSnapshot(first, second)) return false;
  const quarantinedPath = `${lockPath}.stale.${process.pid}.${crypto.randomBytes(8).toString("hex")}`;
  try {
    await rename(lockPath, quarantinedPath);
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM", "EBUSY"].includes(error?.code)) return false;
    throw failure("local_data_migration_lock_recovery_failed", error);
  }
  const quarantined = await readStoreLockSnapshot(quarantinedPath);
  if (!quarantined || !sameStoreLockSnapshot(second, quarantined)) {
    // Do not overwrite a final path that another writer might have acquired
    // after the quarantine rename. A hard link only restores the original
    // owner when that final path is still absent.
    try {
      await link(quarantinedPath, lockPath);
      await rm(quarantinedPath);
    } catch {}
    return false;
  }
  try {
    await rm(quarantinedPath);
    await syncDirectory(path.dirname(lockPath));
    return true;
  } catch (error) {
    throw failure("local_data_migration_lock_recovery_failed", error);
  }
}

async function readStoreLockSnapshot(lockPath) {
  let metadata;
  try { metadata = await lstat(lockPath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw failure("local_data_migration_lock_recovery_failed", error);
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > MAX_STORE_LOCK_BYTES) return null;
  let body;
  try {
    const opened = await readRegularFile(lockPath, MAX_STORE_LOCK_BYTES);
    body = opened.bytes;
    return body.length === metadata.size
      ? Object.freeze({ metadata, identity: opened.identity, body })
      : null;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    return null;
  }
}

function isStaleDeadStoreLock(snapshot, tokenField) {
  if (!snapshot || Date.now() - snapshot.metadata.mtimeMs < STORE_LOCK_STALE_MS) return false;
  let record;
  try { record = JSON.parse(snapshot.body.toString("utf8")); } catch { return false; }
  const pid = Number(record?.pid);
  const token = record?.[tokenField];
  return Number.isSafeInteger(pid)
    && pid > 0
    && typeof token === "string"
    && token.length >= 16
    && Number.isFinite(Number(record?.createdAt))
    && processDefinitelyDead(pid);
}

function processDefinitelyDead(pid) {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return error?.code === "ESRCH";
  }
}

function sameStoreLockSnapshot(left, right) {
  return left.identity.dev === right.identity.dev && left.identity.ino === right.identity.ino
    && left.metadata.size === right.metadata.size
    && left.metadata.mtimeMs === right.metadata.mtimeMs
    && left.body.length === right.body.length
    && crypto.timingSafeEqual(left.body, right.body);
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function parseArchiveLines(body) {
  return String(body).split(/\r?\n/u).filter(Boolean).map(parseJson);
}

function parseJson(body) {
  try { return JSON.parse(String(body)); }
  catch (error) { throw failure("local_data_migration_source_invalid", error); }
}

function envelopeProtection(value) {
  try {
    return classifyHelloLynkLocalDataEnvelope(value) || "plaintext";
  } catch (error) {
    throw failure("local_data_migration_protected_asset_invalid", error);
  }
}

function assertEnvelopeKey(value, expectedKeyId) {
  if (envelopeProtection(value) !== "current") {
    throw failure("local_data_migration_protected_asset_version_invalid");
  }
  if (value?.keyId !== expectedKeyId) throw failure("local_data_migration_mixed_keys");
}

async function readMigrationState(statePath, descriptors, bindingDigest) {
  let value;
  try {
    try {
      value = JSON.parse((await readRegularFile(statePath, 1024 * 1024)).bytes.toString("utf8"));
    } catch (error) {
      if (error?.code === "ENOENT") throw error;
      throw failure("local_data_migration_state_invalid", error);
    }
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  assertExactFields(value, STATE_FIELDS, "local_data_migration_state_invalid");
  if (value.contract !== HELLOLYNK_LOCAL_DATA_MIGRATION_CONTRACT || value.schemaVersion !== 1
    || !["preparing", "staged", "committed"].includes(value.phase) || !DIGEST.test(value.bindingDigest)
    || !KEY_ID.test(value.keyId) || !Array.isArray(value.assets)
    || value.assets.length > descriptors.length
    || (value.phase === "preparing" && value.assets.length !== 0)) {
    throw failure("local_data_migration_state_invalid");
  }
  if (value.phase !== "committed" && value.bindingDigest !== bindingDigest) {
    throw failure("local_data_migration_binding_mismatch");
  }
  // Recorded assets must still belong to this installation's profiles, or
  // their records would be left behind when the journal is removed.
  const seen = new Set();
  for (const asset of value.assets) {
    assertAssetState(asset);
    if (seen.has(asset.assetId)) throw failure("local_data_migration_state_invalid");
    seen.add(asset.assetId);
    descriptorForState(asset, descriptors);
  }
  return Object.freeze({ phase: value.phase, keyId: value.keyId, assets: Object.freeze(value.assets) });
}

function assertAssetState(asset) {
  assertExactFields(
    asset,
    ASSET_STATE_FIELDS,
    "local_data_migration_state_invalid",
  );
  if (!SAFE_ID.test(asset.assetId) || !["json", "ndjson"].includes(asset.format)
    || typeof asset.targetRelativePath !== "string" || typeof asset.stageFile !== "string"
    || !DIGEST.test(asset.canonicalDigest) || !DIGEST.test(asset.stableIdsDigest)
    || !DIGEST.test(asset.sourceBytesDigest)
    || !Number.isSafeInteger(asset.recordCount) || asset.recordCount < 0) {
    throw failure("local_data_migration_state_invalid");
  }
}

function descriptorForState(asset, descriptors) {
  const descriptor = descriptors.find((item) => item.assetId === asset.assetId);
  if (!descriptor || descriptor.format !== asset.format
    || descriptor.targetRelativePath !== asset.targetRelativePath
    || asset.stageFile !== `${descriptor.assetId}.${descriptor.format === "json" ? "json" : "ndjson"}`) {
    throw failure("local_data_migration_state_invalid");
  }
  return descriptor;
}

async function atomicWriteText(targetPath, value) {
  await atomicWriteBytes(targetPath, Buffer.from(value, "utf8"));
}

async function atomicWriteBytes(targetPath, value) {
  await ensureSafeDirectory(path.dirname(targetPath));
  const temporary = `${targetPath}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(value);
    await handle.sync();
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw failure("local_data_migration_write_failed", error);
  } finally {
    await handle?.close().catch(() => {});
  }
  try {
    await rename(temporary, targetPath);
    await syncDirectory(path.dirname(targetPath));
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw failure("local_data_migration_write_failed", error);
  }
}

async function syncDirectory(directoryPath) {
  let handle;
  try {
    handle = await open(directoryPath, "r");
    await handle.sync();
  } catch (error) {
    if (!["EBADF", "EINVAL", "EISDIR", "ENOTSUP", "EPERM"].includes(error?.code)) throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function removeStageDirectory(root, stageRoot) {
  const resolved = path.resolve(stageRoot);
  if (path.dirname(resolved) !== path.resolve(root) || path.basename(resolved) !== STAGE_DIRECTORY) {
    throw failure("local_data_migration_stage_path_invalid");
  }
  let metadata;
  try { metadata = await lstat(resolved); }
  catch (error) {
    if (error?.code === "ENOENT") return;
    throw failure("local_data_migration_stage_path_invalid", error);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw failure("local_data_migration_stage_path_invalid");
  }
  await rm(resolved, { recursive: true, force: true });
}

async function assertSafeMigrationLayout(root, stageRoot) {
  await requireSafeDirectory(root);
  for (const name of ["messages", "contacts", "contact-requests"]) {
    await optionalSafeDirectory(path.join(root, name));
  }
  await optionalSafeDirectory(stageRoot);
}

async function ensureSafeDirectory(directoryPath) {
  const existing = await optionalSafeDirectory(directoryPath);
  if (existing) return existing;
  await mkdir(directoryPath, { recursive: true, mode: 0o700 });
  return requireSafeDirectory(directoryPath);
}

async function optionalSafeDirectory(directoryPath) {
  try { return await requireSafeDirectory(directoryPath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function requireSafeDirectory(directoryPath) {
  let metadata;
  try { metadata = await lstat(directoryPath); }
  catch (error) {
    if (error?.code === "ENOENT") throw error;
    throw failure("local_data_migration_directory_invalid", error);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw failure("local_data_migration_directory_invalid");
  }
  return metadata;
}

async function optionalRegularFile(filePath) {
  try { return await requiredRegularFile(filePath); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function requiredRegularFile(filePath) {
  let metadata;
  try { metadata = await lstat(filePath); }
  catch (error) {
    if (error?.code === "ENOENT") throw error;
    throw failure("local_data_migration_asset_invalid", error);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw failure("local_data_migration_asset_invalid");
  }
  return metadata;
}

async function readRegularFile(filePath, maximumBytes) {
  const before = await requiredRegularFile(filePath);
  if (before.size > maximumBytes) throw failure("local_data_migration_asset_too_large");
  let handle;
  try {
    const noFollow = Number(fsConstants.O_NOFOLLOW || 0);
    handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > maximumBytes || !sameFileIdentity(before, opened)) {
      throw failure("local_data_migration_asset_invalid");
    }
    return Object.freeze({ metadata: opened, identity: await handle.stat({ bigint: true }), bytes: await handle.readFile() });
  } catch (error) {
    if (error?.code === "local_data_migration_asset_too_large"
      || error?.code === "local_data_migration_asset_invalid") throw error;
    throw failure("local_data_migration_asset_invalid", error);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function sameFileIdentity(left, right) {
  if (process.platform === "win32" && (left.dev === 0 || right.dev === 0)
    && left.ino !== right.ino) return false;
  if (Number.isSafeInteger(left.dev) && Number.isSafeInteger(left.ino)
    && Number.isSafeInteger(right.dev) && Number.isSafeInteger(right.ino)) {
    if (left.dev === right.dev && left.ino === right.ino) return true;
    // Node 22 on Windows may report dev=0 for lstat(path), while fstat(handle)
    // reports the volume number for the same open file. Keep the file index and
    // immutable snapshot fields bound when accepting that platform difference.
    if (process.platform !== "win32" || (left.dev !== 0 && right.dev !== 0)
      || left.ino !== right.ino) return false;
  }
  return left.size === right.size && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function normalizeProfileIds(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
    throw failure("local_data_migration_profile_ids_invalid");
  }
  return Object.freeze([...new Set(value.map(normalizeProfileId))].sort());
}

function normalizeProfileId(value) {
  const profileId = String(value || "");
  if (!PROFILE_ID.test(profileId)) throw failure("local_data_migration_profile_id_invalid");
  return profileId;
}

function requireLegacyProtector(value) {
  if (value == null) throw failure("local_data_migration_protector_required");
  if (["openJson", "deriveIndexKey", "withKeyBatch"].some((method) => typeof value[method] !== "function")) {
    throw failure("local_data_migration_protector_invalid");
  }
  return value;
}

function assertLockContext(value, expected) {
  if (value?.lockHeld !== true || value.region !== expected.region
    || value.principalId !== expected.principalId
    || value.hostInstallationId !== expected.hostInstallationId) {
    throw failure("local_data_migration_installation_lock_required");
  }
}

function assertExactFields(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((field, index) => field !== wanted[index])) {
    throw failure(code);
  }
}

function digestBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function absoluteRoot(value) {
  if (typeof value !== "string" || !value || value.includes("\0") || !path.isAbsolute(value)) {
    throw failure("local_data_migration_root_invalid");
  }
  return path.resolve(value);
}

function safeChild(root, relative) {
  if (typeof relative !== "string" || !relative || path.isAbsolute(relative) || relative.includes("\0")) {
    throw failure("local_data_migration_path_invalid");
  }
  const target = path.resolve(root, relative);
  const prefix = path.resolve(root) + path.sep;
  if (!target.startsWith(prefix)) throw failure("local_data_migration_path_invalid");
  return target;
}

function safeId(value, code) {
  const id = String(value || "");
  if (!SAFE_ID.test(id)) throw failure(code);
  return id;
}

function failure(code, cause = null) {
  const error = new Error(code, cause ? { cause } : undefined);
  error.code = code;
  return error;
}
