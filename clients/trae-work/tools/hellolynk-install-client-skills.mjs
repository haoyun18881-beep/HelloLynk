#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SUPPORTED_TARGETS = new Set(["trae", "trae-solo", "trae-ide", "workbuddy", "cursor", "all"]);

export async function installClientSkills(options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || ROOT);
  const home = path.resolve(options.home || os.homedir());
  const appData = path.resolve(options.appData || process.env.APPDATA || path.join(home, "AppData", "Roaming"));
  const localAppData = path.resolve(options.localAppData || process.env.LOCALAPPDATA || path.join(home, "AppData", "Local"));
  const target = String(options.target || "all").toLowerCase();
  if (!SUPPORTED_TARGETS.has(target)) throw new Error(`client_skill_target_unsupported:${target}`);

  const resolvedTargets = await resolveTargets(target, { home, appData, localAppData });
  const plans = [];
  for (const name of resolvedTargets) {
    const location = await resolveProfileLocation(targetPlan(name, { sourceRoot, home, appData }), home);
    const previousSource = name === "cursor" && options.previousSourceRoot
      ? targetPlan(name, { sourceRoot: path.resolve(options.previousSourceRoot), home, appData }).source : null;
    const previousState = previousSource ? await assertSkillSource({ ...location, source: previousSource }) : null;
    const plan = Object.freeze({ ...location, ...(previousSource ? { previousSource, previousState } : {}),
      ...(location.legacyDestination ? { backupRoot: path.join(location.trustedAnchor, ".hellolynk", "skill-backups", name) } : {}),
    });
    const sourceState = await assertSkillSource(plan);
    const legacy = name === "cursor" ? Object.freeze({ active: false, status: "not-applicable", digest: null }) : await inspectLegacyClientSkill({
      destination: plan.legacyDestination,
      trustedAnchor: plan.trustedAnchor,
      target: plan.target,
    });
    const destinationState = await inspectClientSkillDestination(plan, {
      trustedAnchor: plan.trustedAnchor,
      replace: name !== "cursor" && options.replace === true,
    });
    const chineseLegacy = name.startsWith("trae-") ? await inspectChineseLegacySkill({
      destination: path.join(path.dirname(plan.destination), "HelloLynk收件箱"),
      trustedAnchor: plan.trustedAnchor, target: name,
    }) : null;
    plans.push(Object.freeze({ ...plan, sourceState, legacy, chineseLegacy, destinationState }));
  }
  const fingerprint = clientSkillPlanFingerprint(plans);
  if (target === "cursor" && options.apply === true && options.expectedPlanFingerprint == null) {
    throw new Error("client_skill_preflight_required:cursor");
  }
  if (options.expectedPlanFingerprint != null
    && String(options.expectedPlanFingerprint) !== fingerprint) {
    throw new Error("client_skill_changed_since_preflight");
  }
  if (options.apply !== true) return Object.freeze({ ok: true, applied: false, fingerprint, targets: plans });

  const committed = [];
  const recoveryPaths = new Set();
  try {
    for (const plan of plans) {
      const trustedAnchor = plan.trustedAnchor;
      await assertProfileLocation(plan);
      await assertClientSkillPathChain(trustedAnchor, path.dirname(plan.destination), { allowMissing: true });
      const afterActivate = async (value) => {
        if (typeof options.afterActivate === "function") await options.afterActivate(value);
        await assertProfileLocation(plan);
      };
      if (plan.target === "cursor") {
        const installed = await installCursorSkill(plan, {
          trustedAnchor, fingerprint, afterActivate,
        });
        committed.push(Object.freeze({
          trustedAnchor,
          install: installed,
          retirement: Object.freeze({ undo: Object.freeze({ mode: "noop" }) }),
          result: installed.result,
        }));
        continue;
      }
      const installed = await installOne(plan, {
        replace: options.replace === true,
        trustedAnchor,
        recoveryPaths,
        afterActivate,
      });
      let retired;
      let chineseRetired;
      try {
        retired = await retireLegacySkill(plan, {
          trustedAnchor,
          afterRetire: typeof options.afterRetireLegacy === "function" ? options.afterRetireLegacy : null, recoveryPaths,
        });
        if (plan.chineseLegacy) chineseRetired = await retireLegacySkill({ ...plan,
          legacyDestination: plan.chineseLegacy.destination, legacy: plan.chineseLegacy,
        }, { trustedAnchor, afterRetire: typeof options.afterRetireLegacy === "function" ? options.afterRetireLegacy : null, recoveryPaths, chinese: true });
        await verifyClientSkillMigration({
          source: plan.source,
          destination: plan.destination,
          legacyDestination: plan.legacyDestination,
          trustedAnchor,
          target: plan.target,
        });
        await assertProfileLocation(plan);
      } catch (error) {
        try {
          if (retired) {
            await rollbackCompletedMigration({ install: installed, retirement: retired, chineseRetirement: chineseRetired }, trustedAnchor, recoveryPaths);
          } else {
            await rollbackCompletedInstall(installed, trustedAnchor, recoveryPaths);
          }
        } catch (rollbackError) {
          const failure = new Error(`client_skill_migration_rollback_failed:${plan.target}`);
          failure.cause = rollbackError;
          failure.migrationCause = error;
          throw failure;
        }
        throw error;
      }
      committed.push(Object.freeze({
        trustedAnchor,
        install: installed,
        retirement: retired,
        chineseRetirement: chineseRetired,
        result: Object.freeze({ ...installed.result, legacy: retired.result, ...(chineseRetired ? { chineseLegacy: chineseRetired.result } : {}) }),
      }));
    }
  } catch (error) {
    const rollbackFailures = [];
    for (const item of [...committed].reverse()) {
      try {
        await rollbackCompletedMigration(item, item.trustedAnchor, recoveryPaths);
      } catch (rollbackError) {
        rollbackFailures.push(rollbackError);
      }
    }
    let failure = error instanceof Error ? error : new Error(String(error));
    if (rollbackFailures.length > 0) {
      failure = new Error("client_skill_batch_rollback_failed");
      failure.cause = rollbackFailures[0];
      failure.rollbackFailures = rollbackFailures;
      failure.installationCause = error;
    }
    if (recoveryPaths.size > 0) failure.recoveryPaths = [...recoveryPaths];
    throw failure;
  }
  return Object.freeze({
    ok: true,
    applied: true,
    fingerprint,
    targets: committed.map((item) => item.result),
  });
}

function clientSkillPlanFingerprint(plans) {
  const state = plans.map((item) => ({
    target: item.target,
    source: item.source,
    destination: item.destination,
    profileMapping: item.profileMapping,
    legacyDestination: item.legacyDestination,
    legacyActive: item.legacy?.active,
    legacyDigest: item.legacy?.digest,
    chineseLegacy: item.chineseLegacy,
    sourceDigest: item.sourceState?.digest,
    sourceName: item.sourceState?.name,
    sourceMetadataIdentity: item.sourceState?.metadataIdentity,
    previousSource: item.previousSource,
    previousDigest: item.previousState?.digest,
    destinationStatus: item.destinationState?.status,
    destinationDigest: item.destinationState?.digest,
  }));
  return crypto.createHash("sha256").update(JSON.stringify(state), "utf8").digest("hex");
}

async function resolveProfileLocation(plan, home) {
  const logicalRoot = path.dirname(path.dirname(plan.destination));
  const metadata = await lstatMaybe(logicalRoot);
  if (!metadata?.isSymbolicLink()) return Object.freeze({ ...plan, trustedAnchor: home, profileMapping: null });
  const canonicalRoot = await fs.realpath(logicalRoot);
  await assertClientSkillPathChain(canonicalRoot, canonicalRoot);
  const identity = await fs.stat(canonicalRoot);
  return Object.freeze({
    ...plan,
    destination: path.join(canonicalRoot, path.relative(logicalRoot, plan.destination)),
    legacyDestination: plan.legacyDestination ? path.join(canonicalRoot, path.relative(logicalRoot, plan.legacyDestination)) : null,
    trustedAnchor: canonicalRoot,
    profileMapping: Object.freeze({ logicalRoot, canonicalRoot, dev: identity.dev, ino: identity.ino }),
  });
}

async function assertProfileLocation(plan) {
  const mapping = plan.profileMapping;
  if (!mapping) return;
  try {
    const canonical = await fs.realpath(mapping.logicalRoot);
    const identity = await fs.stat(canonical);
    if (canonical === mapping.canonicalRoot && identity.dev === mapping.dev && identity.ino === mapping.ino) return;
  } catch { /* Treat an unavailable or replaced mapping as a changed plan. */ }
  throw new Error("client_skill_profile_path_changed");
}

async function resolveTargets(target, locations) {
  if (target === "all") return [await resolveTraeTarget(locations), "workbuddy"];
  if (target === "trae") return [await resolveTraeTarget(locations)];
  return [target];
}

async function resolveTraeTarget({ appData, localAppData }) {
  if (await exists(path.join(appData, "Trae CN"))) return "trae-ide";
  const soloExecutable = path.join(localAppData, "Programs", "TRAE SOLO CN", "TRAE SOLO CN.exe");
  const soloData = path.join(appData, "TRAE SOLO CN");
  return (await exists(soloExecutable)) || (await exists(soloData)) ? "trae-solo" : "trae-ide";
}

function targetPlan(target, { sourceRoot, home, appData }) {
  if (target === "cursor") return Object.freeze({
    target,
    source: path.join(sourceRoot, "integrations", "hellolynk-cursor", "skills", "hellolynk-messaging"),
    destination: path.join(home, ".cursor", "skills", "hellolynk-messaging"),
    legacyDestination: null,
    restartClient: "Cursor",
  });
  if (target === "trae-solo") return Object.freeze({
    target,
    source: path.join(sourceRoot, "integrations", "trae-work", "skills", "hellolynk-inbox"),
    destination: path.join(home, ".trae-cn", "skills", "hellolynk-inbox"),
    legacyDestination: path.join(home, ".trae-cn", "skills", "lynk-inbox"),
    restartClient: "TRAE SOLO CN",
  });
  if (target === "trae-ide") return Object.freeze({
    target,
    source: path.join(sourceRoot, "integrations", "trae-work", "skills", "hellolynk-inbox"),
    // The official global Skill directory is .trae-cn/skills. The .agents
    // directory in the IDE guide is project-scoped, not HOME-scoped.
    destination: path.join(home, ".trae-cn", "skills", "hellolynk-inbox"),
    legacyDestination: path.join(home, ".trae-cn", "skills", "lynk-inbox"),
    restartClient: "TRAE CN",
  });
  return Object.freeze({
    target,
    source: path.join(sourceRoot, "integrations", "workbuddy", "skills", "hellolynk-inbox"),
    destination: path.join(home, ".workbuddy", "skills", "hellolynk-inbox"),
    legacyDestination: path.join(home, ".workbuddy", "skills", "lynk-inbox"),
    restartClient: "WorkBuddy",
  });
}

async function assertSkillSource(plan) {
  const metadata = await fs.lstat(plan.source).catch(() => null);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) throw new Error(`client_skill_source_invalid:${plan.target}`);
  const required = plan.target === "workbuddy" ? ["SKILL.md", "workbuddy.json"] : ["SKILL.md"];
  for (const name of required) {
    const item = await fs.lstat(path.join(plan.source, name)).catch(() => null);
    if (!item?.isFile() || item.isSymbolicLink()) throw new Error(`client_skill_source_invalid:${plan.target}:${name}`);
  }
  if (plan.target === "cursor" && (await fs.readdir(plan.source)).sort().join(",") !== "SKILL.md") {
    throw new Error("client_skill_source_invalid:cursor:unexpected_file");
  }
  const name = await assertSkillSourceMetadata(plan.source, plan.target === "cursor" ? "hellolynk-messaging" : "hellolynk-inbox");
  const metadataIdentity = plan.target === "workbuddy"
    ? await assertWorkBuddySourceMetadata(plan.source)
    : `skill:${name}`;
  let digest;
  try { digest = await regularTreeDigest(plan.source); }
  catch (error) {
    if (error?.message === "client_skill_tree_invalid") {
      throw new Error(`client_skill_source_file_invalid:${plan.target}`);
    }
    throw error;
  }
  const body = plan.target === "cursor" ? await fs.readFile(path.join(plan.source, "SKILL.md")) : null;
  return Object.freeze({ digest, name, metadataIdentity, ...(body ? {
    files: Object.freeze([Object.freeze({ path: "SKILL.md", bytes: body.length,
      sha256: crypto.createHash("sha256").update(body).digest("hex") })]),
  } : {}) });
}

async function assertSkillSourceMetadata(root, expectedName = "hellolynk-inbox") {
  const skillPath = path.join(root, "SKILL.md");
  const body = await fs.readFile(skillPath, "utf8");
  const lines = body.split(/\r?\n/);
  if (lines[0] !== "---") throw new Error("client_skill_source_metadata_invalid");
  const closing = lines.findIndex((line, index) => index > 0 && line === "---");
  if (closing < 2) throw new Error("client_skill_source_metadata_invalid");
  const names = lines.slice(1, closing)
    .filter((line) => /^\s*name\s*:/.test(line))
    .map((line) => line.trim().replace(/^name\s*:\s*/, "").trim());
  if (names.length !== 1 || names[0] !== expectedName) {
    throw new Error("client_skill_source_metadata_invalid");
  }
  if (expectedName === "hellolynk-messaging") {
    const descriptions = lines.slice(1, closing).filter((line) => /^description:\s*\S/.test(line));
    if (descriptions.length !== 1) throw new Error("client_skill_source_metadata_invalid");
  }
  return names[0];
}

async function assertWorkBuddySourceMetadata(root) {
  let value;
  try { value = JSON.parse(await fs.readFile(path.join(root, "workbuddy.json"), "utf8")); }
  catch { throw new Error("client_skill_source_metadata_invalid"); }
  const keys = ["description_en", "description_zh", "display_name", "display_name_en"];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== keys.join(",")
    || value.display_name !== "HelloLynk 通讯" || value.display_name_en !== "HelloLynk Messaging"
    || typeof value.description_zh !== "string" || !value.description_zh.trim()
    || typeof value.description_en !== "string" || !value.description_en.trim()) {
    throw new Error("client_skill_source_metadata_invalid");
  }
  return "workbuddy:HelloLynk 通讯:HelloLynk Messaging";
}

async function inspectClientSkillDestination(plan, { trustedAnchor, replace }) {
  await assertClientSkillPathChain(trustedAnchor, path.dirname(plan.destination), { allowMissing: true });
  const state = await lstatMaybe(plan.destination);
  if (state === null) return Object.freeze({ status: "absent", digest: null, matchesSource: false });
  await assertClientSkillPathChain(trustedAnchor, plan.destination);
  const digest = await regularTreeDigest(plan.destination);
  const matchesSource = await equalTrees(plan.source, plan.destination);
  const matchesPrevious = plan.target === "cursor" && plan.previousState?.digest === digest;
  if (!matchesSource && !matchesPrevious && replace !== true) throw new Error(`client_skill_destination_differs:${plan.target}`);
  return Object.freeze({ status: matchesSource ? "current" : matchesPrevious ? "managed-upgrade" : "replaceable", digest, matchesSource });
}

export async function inspectLegacyClientSkill({ destination, trustedAnchor, target = "unknown" }) {
  const resolvedDestination = path.resolve(String(destination || ""));
  try {
    await assertClientSkillPathChain(trustedAnchor, path.dirname(resolvedDestination), { allowMissing: true });
    const state = await lstatMaybe(resolvedDestination);
    if (state === null) return Object.freeze({
      destination: resolvedDestination,
      active: false,
      status: "absent",
      name: null,
      digest: null,
    });
    await assertClientSkillPathChain(trustedAnchor, resolvedDestination);
    const legacyName = await assertLegacySkillMetadata(resolvedDestination);
    if (legacyName === "HelloLynk收件箱" && (!target.startsWith("trae-")
      || (path.basename(resolvedDestination) !== "HelloLynk收件箱"
        && !path.basename(resolvedDestination).startsWith("lynk-inbox.retired-")))) {
      throw new Error("client_skill_legacy_metadata_invalid");
    }
    const digest = await regularTreeDigest(resolvedDestination);
    return Object.freeze({
      destination: resolvedDestination,
      active: true,
      status: "ready-to-retire",
      name: legacyName,
      digest,
    });
  } catch (error) {
    if (error?.message === "client_skill_destination_path_invalid") throw error;
    const failure = new Error(`client_skill_legacy_invalid:${target}`);
    failure.cause = error;
    throw failure;
  }
}

async function inspectChineseLegacySkill({ destination, trustedAnchor, target }) {
  const resolved = path.resolve(destination);
  await assertClientSkillPathChain(trustedAnchor, path.dirname(resolved), { allowMissing: true });
  const state = await lstatMaybe(resolved);
  if (!state) return Object.freeze({ destination: resolved, active: false, status: "absent", name: null, digest: null });
  await assertClientSkillPathChain(trustedAnchor, resolved);
  const entries = await fs.readdir(resolved);
  if (entries.length !== 1 || entries[0] !== "SKILL.md") {
    return Object.freeze({ destination: resolved, active: false, status: "unknown", name: null, digest: null });
  }
  const metadata = await fs.lstat(path.join(resolved, "SKILL.md"));
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
    throw new Error(`client_skill_legacy_invalid:${target}`);
  }
  let name;
  try { name = await assertLegacySkillMetadata(resolved); }
  catch (error) {
    if (error?.message !== "client_skill_legacy_metadata_invalid") throw error;
    return Object.freeze({ destination: resolved, active: false, status: "unknown", name: null, digest: null });
  }
  if (name !== "HelloLynk收件箱") return Object.freeze({ destination: resolved, active: false, status: "unknown", name: null, digest: null });
  return Object.freeze({ destination: resolved, active: true, status: "ready-to-retire", name, digest: await regularTreeDigest(resolved) });
}

async function assertLegacySkillMetadata(root) {
  const skillPath = path.join(root, "SKILL.md");
  const metadata = await lstatMaybe(skillPath);
  if (!metadata?.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size > 1024 * 1024) {
    throw new Error("client_skill_legacy_metadata_invalid");
  }
  const body = await fs.readFile(skillPath, "utf8");
  const lines = body.split(/\r?\n/);
  if (lines[0] !== "---") throw new Error("client_skill_legacy_metadata_invalid");
  const closing = lines.findIndex((line, index) => index > 0 && line === "---");
  if (closing < 2) throw new Error("client_skill_legacy_metadata_invalid");
  const names = lines.slice(1, closing)
    .filter((line) => /^\s*name\s*:/.test(line))
    .map((line) => line.trim().replace(/^name\s*:\s*/, "").trim());
  const chinese = names.length === 1 && names[0] === "HelloLynk收件箱"
    && (await fs.readdir(root)).length === 1
    && body.includes("在 TRAE Work 中打开和使用 HelloLynk 通讯")
    && body.includes("已有独立只读授权内调用 `hellolynk_read_authorized_inbox_message`")
    && body.includes("`OpenPreview`");
  if (names.length !== 1 || (names[0] !== "lynk-inbox" && !chinese)) {
    throw new Error("client_skill_legacy_metadata_invalid");
  }
  return names[0];
}

async function retireLegacySkill(plan, { trustedAnchor, afterRetire, recoveryPaths, chinese = false }) {
  const expected = plan.legacy;
  const current = await (chinese ? inspectChineseLegacySkill : inspectLegacyClientSkill)({
    destination: plan.legacyDestination,
    trustedAnchor,
    target: plan.target,
  });
  if (current.active !== expected.active || current.digest !== expected.digest) {
    throw new Error(`client_skill_legacy_changed:${plan.target}`);
  }
  if (!current.active) return Object.freeze({
    result: Object.freeze({
      destination: plan.legacyDestination,
      active: false,
      status: current.status,
      backup: null,
      digest: null,
      backupDigestVerified: false,
      recoverable: false,
    }),
    undo: Object.freeze({ mode: "noop", createdParents: Object.freeze([]) }),
  });

  const createdParents = await ensureDirectoryChain(trustedAnchor, plan.backupRoot);
  const backup = path.join(
    plan.backupRoot,
    `lynk-inbox.retired-${new Date().toISOString().replace(/[-:.TZ]/g, "")}-${crypto.randomUUID()}`,
  );
  let moved = false;
  try {
    if (await lstatMaybe(backup)) throw new Error("client_skill_legacy_backup_conflict");
    await fs.rename(plan.legacyDestination, backup);
    moved = true;
    if (await lstatMaybe(plan.legacyDestination)) throw new Error("client_skill_legacy_still_active");
    const retired = await inspectLegacyClientSkill({
      destination: backup,
      trustedAnchor,
      target: plan.target,
    });
    if (!retired.active || retired.digest !== current.digest) {
      throw new Error("client_skill_legacy_backup_digest_invalid");
    }
    if (afterRetire) await afterRetire({
      target: plan.target,
      destination: plan.legacyDestination,
      backup,
      digest: current.digest,
    });
    return Object.freeze({
      result: Object.freeze({
        destination: plan.legacyDestination,
        active: false,
        status: "retired",
        backup,
        digest: current.digest,
        backupDigestVerified: true,
        recoverable: true,
      }),
      undo: Object.freeze({
        mode: "retired",
        destination: plan.legacyDestination,
        backup,
        digest: current.digest,
        createdParents,
        target: plan.target,
      }),
    });
  } catch (error) {
    try {
      if (moved) {
        await restoreRetiredLegacy({
          mode: "retired",
          destination: plan.legacyDestination,
          backup,
          digest: current.digest,
          createdParents,
          target: plan.target,
        }, trustedAnchor);
      } else {
        await removeCreatedDirectories(createdParents, trustedAnchor);
      }
    } catch (restoreError) {
      if (moved) await recordRecoveryPath(recoveryPaths, backup);
      const failure = new Error(`client_skill_legacy_retirement_rollback_failed:${plan.target}`);
      failure.cause = restoreError;
      failure.retirementCause = error;
      throw failure;
    }
    throw error;
  }
}

export async function verifyClientSkillMigration({
  source,
  destination,
  legacyDestination,
  trustedAnchor,
  target = "unknown",
}) {
  await verifyInstalledClientSkill({ source, destination, trustedAnchor });
  const legacy = await inspectLegacyClientSkill({
    destination: legacyDestination,
    trustedAnchor,
    target,
  });
  const chineseLegacy = target.startsWith("trae-") ? await inspectChineseLegacySkill({
    destination: path.join(path.dirname(destination), "HelloLynk收件箱"), trustedAnchor, target,
  }) : null;
  if (legacy.active || chineseLegacy?.active) throw new Error(`client_skill_legacy_still_active:${target}`);
  return Object.freeze({ verified: true, legacyActive: false, legacyStatus: legacy.status });
}

// Cursor owns one file, including an unchanged file from a verified prior release.
// Never replace user content or
// retire unrelated legacy skills, and never recursively delete its destination.
async function installCursorSkill(plan, { trustedAnchor, fingerprint, afterActivate }) {
  const sourceState = await assertSkillSource(plan);
  const previousState = plan.previousSource
    ? await assertSkillSource({ ...plan, source: plan.previousSource }) : null;
  const destinationState = await inspectClientSkillDestination(plan, { trustedAnchor, replace: false });
  if (clientSkillPlanFingerprint([{ ...plan, sourceState, previousState, destinationState }]) !== fingerprint) {
    throw new Error("client_skill_changed_since_preflight");
  }
  const file = sourceState.files[0];
  const receipt = Object.freeze({
    contract: "hellolynk-cursor-skill-install-receipt-v1", target: "cursor",
    destination: plan.destination, fingerprint,
    files: Object.freeze([Object.freeze({ ...file })]),
  });
  if (destinationState.status === "current") {
    return Object.freeze({ result: Object.freeze({ ...plan, changed: false, backup: null, receipt }),
      undo: Object.freeze({ mode: "noop" }) });
  }
  if (destinationState.status === "managed-upgrade") {
    return upgradeCursorSkill(plan, { trustedAnchor, receipt, afterActivate });
  }

  const directories = [];
  let ownedFile = null;
  let handle = null;
  try {
    await createCursorDirectoryChain(trustedAnchor, path.dirname(plan.destination), directories);
    // mkdir must be exclusive: rename could replace a concurrently created
    // empty user directory. The same rule applies to the single file below.
    try { await fs.mkdir(plan.destination); }
    catch (error) {
      if (error?.code === "EEXIST") throw new Error("client_skill_changed_since_preflight");
      throw error;
    }
    const directoryState = await fs.lstat(plan.destination);
    directories.push(Object.freeze({ path: plan.destination, dev: directoryState.dev, ino: directoryState.ino }));
    await assertClientSkillPathChain(trustedAnchor, plan.destination);
    const body = await fs.readFile(path.join(plan.source, "SKILL.md"));
    if (body.length !== file.bytes || sha256Bytes(body) !== file.sha256) {
      throw new Error("client_skill_changed_since_preflight");
    }
    const destinationFile = path.join(plan.destination, "SKILL.md");
    handle = await fs.open(destinationFile, "wx+", 0o600);
    const identity = await handle.stat();
    ownedFile = { path: destinationFile, dev: identity.dev, ino: identity.ino, bytes: 0,
      sha256: sha256Bytes(Buffer.alloc(0)) };
    try {
      await handle.writeFile(body);
      ownedFile.bytes = file.bytes;
      ownedFile.sha256 = file.sha256;
    } catch (error) {
      // Capture a failed write's actual bytes through our still-owned handle.
      const partial = Buffer.alloc((await handle.stat()).size);
      await handle.read(partial, 0, partial.length, 0);
      ownedFile.bytes = partial.length;
      ownedFile.sha256 = sha256Bytes(partial);
      throw error;
    }
    await handle.close();
    handle = null;
    if (afterActivate) await afterActivate({ target: "cursor", destination: plan.destination });
    await verifyInstalledClientSkill({ source: plan.source, destination: plan.destination, trustedAnchor });
    if ((await assertSkillSource(plan)).digest !== sourceState.digest) {
      throw new Error("client_skill_changed_since_preflight");
    }
    return Object.freeze({
      result: Object.freeze({ ...plan, changed: true, backup: null, receipt }),
      undo: Object.freeze({ mode: "cursor-new", file: Object.freeze(ownedFile), directories: Object.freeze(directories) }),
    });
  } catch (error) {
    await handle?.close().catch(() => {});
    try { await rollbackCursorSkill({ file: ownedFile, directories }, trustedAnchor); }
    catch (rollbackError) {
      const failure = new Error("client_skill_cursor_rollback_preserved_changed_files");
      failure.cause = rollbackError;
      failure.installCause = error;
      throw failure;
    }
    throw error;
  }
}

async function upgradeCursorSkill(plan, { trustedAnchor, receipt, afterActivate }) {
  const destinationFile = path.join(plan.destination, "SKILL.md");
  const previous = await fs.readFile(path.join(plan.previousSource, "SKILL.md"));
  const next = await fs.readFile(path.join(plan.source, "SKILL.md"));
  if (sha256Bytes(previous) !== plan.previousState.files[0].sha256
    || sha256Bytes(next) !== plan.sourceState.files[0].sha256) {
    throw new Error("client_skill_changed_since_preflight");
  }
  let undo = null;
  try {
    const identity = await fs.lstat(destinationFile);
    const owned = await replaceCursorOwnedFile(destinationFile, { ...identity, sha256: sha256Bytes(previous) }, next, trustedAnchor);
    undo = Object.freeze({ mode: "cursor-upgrade", file: owned, previous });
    if (afterActivate) await afterActivate({ target: "cursor", destination: plan.destination });
    await verifyInstalledClientSkill({ source: plan.source, destination: plan.destination, trustedAnchor });
    if ((await assertSkillSource(plan)).digest !== plan.sourceState.digest) throw new Error("client_skill_changed_since_preflight");
    return Object.freeze({ result: Object.freeze({ ...plan, changed: true, backup: null, receipt }), undo });
  } catch (error) {
    if (undo) {
      try { await replaceCursorOwnedFile(undo.file.path, undo.file, previous, trustedAnchor); }
      catch (rollbackError) {
        const failure = new Error("client_skill_cursor_rollback_preserved_changed_files");
        failure.cause = rollbackError;
        failure.installCause = error;
        throw failure;
      }
    }
    throw error;
  }
}

// Stage a complete single file, then replace only the still-owned bytes. A
// failed write leaves the old file intact; rollback preserves concurrent edits.
async function replaceCursorOwnedFile(file, expected, body, trustedAnchor) {
  const parent = path.dirname(file);
  await assertClientSkillPathChain(trustedAnchor, parent);
  const staging = path.join(parent, `.hellolynk-${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(staging, "wx", 0o600);
    const identity = await handle.stat();
    await handle.writeFile(body);
    await handle.sync();
    await handle.close();
    handle = null;
    await assertClientSkillPathChain(trustedAnchor, parent);
    const current = await fs.lstat(file);
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1
      || current.dev !== expected.dev || current.ino !== expected.ino
      || sha256Bytes(await fs.readFile(file)) !== expected.sha256) {
      throw new Error("client_skill_changed_since_preflight");
    }
    await fs.rename(staging, file);
    return Object.freeze({ path: file, dev: identity.dev, ino: identity.ino, sha256: sha256Bytes(body) });
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(staging).catch((error) => { if (error?.code !== "ENOENT") throw error; });
  }
}

async function createCursorDirectoryChain(anchor, target, created) {
  await assertClientSkillPathChain(anchor, target, { allowMissing: true });
  let cursor = path.resolve(anchor);
  for (const segment of path.relative(cursor, target).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    if (await lstatMaybe(cursor) === null) {
      try {
        await fs.mkdir(cursor);
        const state = await fs.lstat(cursor);
        created.push(Object.freeze({ path: cursor, dev: state.dev, ino: state.ino }));
      } catch (error) { if (error?.code !== "EEXIST") throw error; }
    }
    await assertClientSkillPathChain(anchor, cursor);
  }
}

async function rollbackCursorSkill(undo, trustedAnchor) {
  let changedFile = false;
  if (undo.file) {
    await assertClientSkillPathChain(trustedAnchor, path.dirname(undo.file.path));
    const current = await lstatMaybe(undo.file.path);
    if (current) {
      if (current.isFile() && !current.isSymbolicLink() && current.nlink === 1
        && current.dev === undo.file.dev && current.ino === undo.file.ino
        && current.size === undo.file.bytes
        && sha256Bytes(await fs.readFile(undo.file.path)) === undo.file.sha256) {
        await fs.unlink(undo.file.path);
      } else changedFile = true;
    }
  }
  for (const directory of [...undo.directories].reverse()) {
    const current = await lstatMaybe(directory.path);
    if (!current || !current.isDirectory() || current.isSymbolicLink()
      || current.dev !== directory.dev || current.ino !== directory.ino) continue;
    await assertClientSkillPathChain(trustedAnchor, directory.path);
    try { await fs.rmdir(directory.path); }
    catch (error) { if (!["ENOTEMPTY", "EEXIST"].includes(error?.code)) throw error; }
  }
  if (changedFile) throw new Error("client_skill_cursor_owned_file_changed");
}

function sha256Bytes(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

async function installOne(plan, { replace, trustedAnchor, afterActivate, recoveryPaths }) {
  const parent = path.dirname(plan.destination);
  const privateStagingRoot = path.join(trustedAnchor, ".hellolynk", "skill-installs");
  const staging = path.join(privateStagingRoot, `hellolynk-inbox.staging-${crypto.randomUUID()}`);
  const createdParents = await ensureDirectoryChain(trustedAnchor, parent);
  await ensureDirectoryChain(trustedAnchor, privateStagingRoot);
  let backup = null;
  let previousDigest = null;
  try {
    await copyRegularTree(plan.source, staging);
    await assertClientSkillPathChain(trustedAnchor, staging);
    await verifyExactRegularTree(plan.source, staging);
    if ((await lstatMaybe(plan.destination)) === null) {
      await fs.rename(staging, plan.destination);
      try {
        if (afterActivate) await afterActivate({ destination: plan.destination, target: plan.target });
        await verifyInstalledClientSkill({
          source: plan.source,
          destination: plan.destination,
          trustedAnchor,
          allowLegacyActive: true,
        });
      } catch (error) {
        await deactivateUnverifiedDestination(
          plan.destination,
          privateStagingRoot,
          trustedAnchor,
          recoveryPaths,
        );
        throw error;
      }
      return Object.freeze({
        result: Object.freeze({ ...plan, changed: true, backup: null }),
        undo: Object.freeze({ mode: "new", createdParents }),
      });
    }
    await assertClientSkillPathChain(trustedAnchor, plan.destination);
    if (await equalTrees(staging, plan.destination)) {
      await removePrivateTree(staging);
      await verifyInstalledClientSkill({
        source: plan.source,
        destination: plan.destination,
        trustedAnchor,
        allowLegacyActive: true,
      });
      return Object.freeze({
        result: Object.freeze({ ...plan, changed: false, backup: null }),
        undo: Object.freeze({ mode: "noop", createdParents }),
      });
    }
    if (!replace) throw new Error(`client_skill_destination_differs:${plan.target}`);
    await ensureDirectoryChain(trustedAnchor, plan.backupRoot);
    backup = path.join(plan.backupRoot, `hellolynk-inbox.backup-${new Date().toISOString().replace(/[-:.TZ]/g, "")}-${crypto.randomUUID()}`);
    previousDigest = await regularTreeDigest(plan.destination);
    await fs.rename(plan.destination, backup);
    recoveryPaths.add(backup);
    await assertClientSkillPathChain(trustedAnchor, backup);
    if (await regularTreeDigest(backup) !== previousDigest) {
      throw new Error("client_skill_backup_digest_invalid");
    }
    let activated = false;
    try {
      await fs.rename(staging, plan.destination);
      activated = true;
      if (afterActivate) await afterActivate({ destination: plan.destination, target: plan.target });
      await verifyInstalledClientSkill({
        source: plan.source,
        destination: plan.destination,
        trustedAnchor,
        allowLegacyActive: true,
      });
    } catch (error) {
      try {
        if (activated && await lstatMaybe(plan.destination)) {
          await deactivateUnverifiedDestination(
            plan.destination,
            privateStagingRoot,
            trustedAnchor,
            recoveryPaths,
          );
        }
        await assertClientSkillPathChain(trustedAnchor, backup);
        if (await regularTreeDigest(backup) !== previousDigest) {
          throw new Error("client_skill_restore_digest_invalid");
        }
        await fs.rename(backup, plan.destination);
        recoveryPaths.delete(backup);
        await assertClientSkillPathChain(trustedAnchor, plan.destination);
        if (await regularTreeDigest(plan.destination) !== previousDigest) {
          throw new Error("client_skill_restore_digest_invalid");
        }
      } catch (restoreError) {
        const failure = new Error(`client_skill_activation_rollback_failed:${plan.target}`);
        failure.cause = restoreError;
        throw failure;
      }
      throw error;
    }
    return Object.freeze({
      result: Object.freeze({ ...plan, changed: true, backup }),
      undo: Object.freeze({ mode: "replace", backup, previousDigest, createdParents }),
    });
  } catch (error) {
    try {
      if (backup && await lstatMaybe(backup) && (await lstatMaybe(plan.destination)) === null) {
        await assertClientSkillPathChain(trustedAnchor, backup);
        if (await regularTreeDigest(backup) !== previousDigest) {
          throw new Error("client_skill_restore_digest_invalid");
        }
        await fs.rename(backup, plan.destination);
        recoveryPaths.delete(backup);
        await assertClientSkillPathChain(trustedAnchor, plan.destination);
        if (await regularTreeDigest(plan.destination) !== previousDigest) {
          throw new Error("client_skill_restore_digest_invalid");
        }
      }
      await removePrivateTree(staging).catch(() => {});
      await removeCreatedDirectories(createdParents, trustedAnchor);
    } catch (restoreError) {
      const failure = new Error(`client_skill_activation_rollback_failed:${plan.target}`);
      failure.cause = restoreError;
      throw failure;
    }
    throw error;
  }
}

async function rollbackCompletedInstall(item, trustedAnchor, recoveryPaths) {
  if (item.undo.mode === "noop") return;
  if (item.undo.mode === "cursor-new") return rollbackCursorSkill(item.undo, trustedAnchor);
  if (item.undo.mode === "cursor-upgrade") return replaceCursorOwnedFile(item.undo.file.path, item.undo.file, item.undo.previous, trustedAnchor);
  const privateStagingRoot = path.join(trustedAnchor, ".hellolynk", "skill-installs");
  await deactivateUnverifiedDestination(
    item.result.destination,
    privateStagingRoot,
    trustedAnchor,
    recoveryPaths,
  );
  if (item.undo.mode === "replace") {
    await assertClientSkillPathChain(trustedAnchor, item.undo.backup);
    if (await regularTreeDigest(item.undo.backup) !== item.undo.previousDigest) {
      throw new Error("client_skill_restore_digest_invalid");
    }
    await fs.rename(item.undo.backup, item.result.destination);
    recoveryPaths.delete(item.undo.backup);
    await assertClientSkillPathChain(trustedAnchor, item.result.destination);
    if (await regularTreeDigest(item.result.destination) !== item.undo.previousDigest) {
      await deactivateUnverifiedDestination(
        item.result.destination,
        privateStagingRoot,
        trustedAnchor,
        recoveryPaths,
      ).catch(() => {});
      throw new Error("client_skill_restore_digest_invalid");
    }
  }
  await removeCreatedDirectories(item.undo.createdParents, trustedAnchor);
}

async function rollbackCompletedMigration(item, trustedAnchor, recoveryPaths) {
  const failures = [];
  try {
    await rollbackCompletedInstall(item.install, trustedAnchor, recoveryPaths);
  } catch (error) {
    failures.push(error);
  }
  try {
    if (item.chineseRetirement) await restoreRetiredLegacy(item.chineseRetirement.undo, trustedAnchor);
  } catch (error) {
    await recordRecoveryPath(recoveryPaths, item.chineseRetirement?.undo.backup);
    failures.push(error);
  }
  try {
    await restoreRetiredLegacy(item.retirement.undo, trustedAnchor);
  } catch (error) {
    await recordRecoveryPath(recoveryPaths, item.retirement.undo.backup);
    failures.push(error);
  }
  if (failures.length > 0) {
    const failure = new Error(`client_skill_migration_rollback_failed:${item.install.result.target}`);
    failure.cause = failures[0];
    if (failures.length > 1) failure.secondaryCause = failures[1];
    throw failure;
  }
}

async function recordRecoveryPath(recoveryPaths, backup) {
  if (!recoveryPaths || !backup) return;
  try { if (await lstatMaybe(backup)) recoveryPaths.add(backup); }
  catch { /* Recovery diagnostics must not interrupt other rollback attempts. */ }
}

async function restoreRetiredLegacy(undo, trustedAnchor) {
  if (undo.mode === "noop") return;
  if (await lstatMaybe(undo.destination)) {
    throw new Error(`client_skill_legacy_restore_conflict:${undo.target}`);
  }
  const backup = await inspectLegacyClientSkill({
    destination: undo.backup,
    trustedAnchor,
    target: undo.target,
  });
  if (!backup.active || backup.digest !== undo.digest) {
    throw new Error("client_skill_legacy_restore_digest_invalid");
  }
  await assertClientSkillPathChain(trustedAnchor, path.dirname(undo.destination), { allowMissing: false });
  await fs.rename(undo.backup, undo.destination);
  const restored = await inspectLegacyClientSkill({
    destination: undo.destination,
    trustedAnchor,
    target: undo.target,
  });
  if (!restored.active || restored.digest !== undo.digest) {
    throw new Error("client_skill_legacy_restore_digest_invalid");
  }
  await removeCreatedDirectories(undo.createdParents, trustedAnchor);
}

async function deactivateUnverifiedDestination(destination, privateStagingRoot, trustedAnchor, recoveryPaths) {
  await assertClientSkillPathChain(trustedAnchor, path.dirname(destination));
  const state = await lstatMaybe(destination);
  if (state === null) return null;
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error("client_skill_unverified_destination_deactivation_failed");
  }
  const failed = path.join(privateStagingRoot, `hellolynk-inbox.failed-${crypto.randomUUID()}`);
  if (await lstatMaybe(failed)) throw new Error("client_skill_failed_path_invalid");
  try {
    await fs.rename(destination, failed);
    // Published trees may contain later user writes. Retain them outside the
    // client's Skill scan roots, even when they currently match our source.
    recoveryPaths.add(failed);
    if (await lstatMaybe(destination)) throw new Error("client_skill_unverified_destination_active");
    await assertClientSkillPathChain(trustedAnchor, failed);
    return failed;
  } catch (renameError) {
    // A blocked move is a rollback failure, not permission to delete a live tree.
    if (await lstatMaybe(destination)) recoveryPaths.add(destination);
    const failure = new Error("client_skill_unverified_destination_deactivation_failed");
    failure.cause = renameError;
    throw failure;
  }
}

async function removePrivateTree(target) {
  if ((await lstatMaybe(target)) === null) return;
  await fs.rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  if (await lstatMaybe(target)) throw new Error("client_skill_private_cleanup_failed");
}

async function ensureDirectoryChain(trustedAnchor, destination) {
  const anchor = path.resolve(trustedAnchor);
  const target = path.resolve(destination);
  const relative = path.relative(anchor, target);
  if (relative === ".." || path.isAbsolute(relative) || relative.startsWith(`..${path.sep}`)) {
    throw new Error("client_skill_destination_path_invalid");
  }
  await assertClientSkillPathChain(anchor, anchor);
  const created = [];
  let cursor = anchor;
  try {
    for (const segment of relative.split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      const state = await lstatMaybe(cursor);
      if (state === null) {
        try { await fs.mkdir(cursor); }
        catch (error) {
          if (error?.code !== "EEXIST") throw error;
        }
        const createdState = await lstatMaybe(cursor);
        if (!createdState?.isDirectory() || createdState.isSymbolicLink()) {
          throw new Error("client_skill_destination_path_invalid");
        }
        created.push(cursor);
      } else if (!state.isDirectory() || state.isSymbolicLink()) {
        throw new Error("client_skill_destination_path_invalid");
      }
      await assertClientSkillPathChain(anchor, cursor);
    }
    return Object.freeze(created);
  } catch (error) {
    await removeCreatedDirectories(created, anchor);
    throw error;
  }
}

async function removeCreatedDirectories(created, trustedAnchor) {
  for (const directory of [...created].reverse()) {
    if ((await lstatMaybe(directory)) === null) continue;
    await assertClientSkillPathChain(trustedAnchor, directory);
    try { await fs.rmdir(directory); }
    catch (error) {
      if (error?.code === "ENOTEMPTY" || error?.code === "EEXIST") continue;
      throw error;
    }
  }
}

async function lstatMaybe(target) {
  try { return await fs.lstat(target); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function regularTreeDigest(root) {
  const hash = crypto.createHash("sha256");
  await hashRegularTree(root, "", hash);
  return hash.digest("hex");
}

async function hashRegularTree(root, relative, hash) {
  const absolute = relative ? path.join(root, ...relative.split("/")) : root;
  const metadata = await fs.lstat(absolute);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("client_skill_tree_invalid");
  const entries = await fs.readdir(absolute, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const itemRelative = relative ? `${relative}/${entry.name}` : entry.name;
    const item = path.join(root, ...itemRelative.split("/"));
    const itemMetadata = await fs.lstat(item);
    if (itemMetadata.isSymbolicLink()) throw new Error("client_skill_tree_invalid");
    if (itemMetadata.isDirectory()) {
      hash.update(`d\0${itemRelative}\0`);
      await hashRegularTree(root, itemRelative, hash);
    } else if (itemMetadata.isFile() && itemMetadata.nlink === 1) {
      const body = await fs.readFile(item);
      hash.update(`f\0${itemRelative}\0${body.length}\0`);
      hash.update(body);
    } else throw new Error("client_skill_tree_invalid");
  }
}

async function copyRegularTree(source, destination) {
  await fs.mkdir(destination, { recursive: false });
  for (const entry of await fs.readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(destination, entry.name);
    const metadata = await fs.lstat(from);
    if (metadata.isSymbolicLink()) throw new Error("client_skill_source_link_invalid");
    if (metadata.isDirectory()) await copyRegularTree(from, to);
    else if (metadata.isFile() && metadata.nlink === 1) await fs.copyFile(from, to, fs.constants.COPYFILE_EXCL);
    else throw new Error("client_skill_source_file_invalid");
  }
}

async function equalTrees(left, right) {
  const [leftRoot, rightRoot] = await Promise.all([fs.lstat(left), fs.lstat(right)]);
  if (!leftRoot.isDirectory() || leftRoot.isSymbolicLink()
    || !rightRoot.isDirectory() || rightRoot.isSymbolicLink()) throw new Error("client_skill_tree_invalid");
  const leftEntries = await fs.readdir(left, { withFileTypes: true });
  const rightEntries = await fs.readdir(right, { withFileTypes: true });
  if (leftEntries.length !== rightEntries.length) return false;
  const rightMap = new Map(rightEntries.map((entry) => [entry.name, entry]));
  for (const entry of leftEntries) {
    const peer = rightMap.get(entry.name);
    if (!peer || entry.isSymbolicLink() || peer.isSymbolicLink()) return false;
    const leftPath = path.join(left, entry.name);
    const rightPath = path.join(right, entry.name);
    const [leftMetadata, rightMetadata] = await Promise.all([fs.lstat(leftPath), fs.lstat(rightPath)]);
    if (leftMetadata.isSymbolicLink() || rightMetadata.isSymbolicLink()) throw new Error("client_skill_tree_invalid");
    if (leftMetadata.isDirectory() && rightMetadata.isDirectory()) {
      if (!(await equalTrees(leftPath, rightPath))) return false;
    } else if (leftMetadata.isFile() && rightMetadata.isFile()) {
      if (leftMetadata.nlink !== 1 || rightMetadata.nlink !== 1) throw new Error("client_skill_tree_invalid");
      if (leftMetadata.size !== rightMetadata.size
        || !(await fs.readFile(leftPath)).equals(await fs.readFile(rightPath))) return false;
    } else return false;
  }
  return true;
}

async function verifyExactRegularTree(source, destination) {
  if (!(await equalTrees(source, destination))) throw new Error("client_skill_destination_differs");
}

// Uninstall removes the installed Skill only while it matches one that an installed release
// ships. It leaves the client's Skill folder before it is deleted, so nothing partial stays active.
export async function removeInstalledClientSkill(options = {}) {
  const home = path.resolve(options.home || os.homedir());
  const appData = path.resolve(options.appData || process.env.APPDATA || path.join(home, "AppData", "Roaming"));
  const localAppData = path.resolve(options.localAppData || process.env.LOCALAPPDATA || path.join(home, "AppData", "Local"));
  const target = String(options.target || "").toLowerCase();
  if (!["trae", "workbuddy"].includes(target)) throw new Error("client_skill_target_unsupported");
  const [name] = await resolveTargets(target, { home, appData, localAppData });
  const plan = await resolveProfileLocation(targetPlan(name, { sourceRoot: ROOT, home, appData }), home);
  if (await lstatMaybe(plan.destination) === null) return Object.freeze({ present: false, removed: false, destination: plan.destination });
  await assertClientSkillPathChain(plan.trustedAnchor, plan.destination);
  let shipped = false;
  for (const sourceRoot of options.sourceRoots || []) {
    const { source } = targetPlan(name, { sourceRoot: path.resolve(sourceRoot), home, appData });
    if (await lstatMaybe(source) && await equalTrees(source, plan.destination)) { shipped = true; break; }
  }
  if (!shipped) throw new Error("client_skill_destination_differs");
  if (options.apply !== true) return Object.freeze({ present: true, removed: false, destination: plan.destination });
  const privateStagingRoot = path.join(plan.trustedAnchor, ".hellolynk", "skill-installs");
  await ensureDirectoryChain(plan.trustedAnchor, privateStagingRoot);
  const removed = path.join(privateStagingRoot, `hellolynk-inbox.removed-${crypto.randomUUID()}`);
  await fs.rename(plan.destination, removed);
  await removePrivateTree(removed);
  return Object.freeze({ present: true, removed: true, destination: plan.destination });
}

export async function verifyInstalledClientSkill({
  source,
  destination,
  trustedAnchor,
  allowLegacyActive = false,
}) {
  await assertClientSkillPathChain(trustedAnchor, destination);
  await verifyExactRegularTree(source, destination);
  if (path.basename(destination) === "hellolynk-messaging") {
    return Object.freeze({ verified: true, legacyActive: false, legacyStatus: "not-applicable" });
  }
  const legacyDestination = path.join(path.dirname(destination), "lynk-inbox");
  const legacy = await inspectLegacyClientSkill({
    destination: legacyDestination,
    trustedAnchor,
    target: path.basename(path.dirname(path.dirname(destination))),
  });
  if (legacy.active && allowLegacyActive !== true) {
    throw new Error("client_skill_legacy_still_active");
  }
  return Object.freeze({ verified: true, legacyActive: legacy.active, legacyStatus: legacy.status });
}

export async function assertClientSkillPathChain(trustedAnchor, destination, options = {}) {
  const anchor = path.resolve(String(trustedAnchor || ""));
  const target = path.resolve(String(destination || ""));
  const relative = path.relative(anchor, target);
  if (relative === ".." || path.isAbsolute(relative) || relative.startsWith(`..${path.sep}`)) {
    throw new Error("client_skill_destination_path_invalid");
  }
  let anchorMetadata;
  try { anchorMetadata = await fs.lstat(anchor); }
  catch { throw new Error("client_skill_destination_path_invalid"); }
  if (!anchorMetadata.isDirectory() || anchorMetadata.isSymbolicLink()) {
    throw new Error("client_skill_destination_path_invalid");
  }
  const anchorCanonical = await fs.realpath(anchor);
  let cursor = anchor;
  const candidates = [anchor];
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    candidates.push(cursor);
  }
  for (const candidate of candidates) {
    let metadata;
    try { metadata = await fs.lstat(candidate); }
    catch (error) {
      if (error?.code === "ENOENT" && options.allowMissing === true) break;
      throw new Error("client_skill_destination_path_invalid");
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("client_skill_destination_path_invalid");
    }
    const canonical = await fs.realpath(candidate);
    const expectedCanonical = path.resolve(anchorCanonical, path.relative(anchor, candidate));
    const actual = process.platform === "win32" ? canonical.toLowerCase() : canonical;
    const expected = process.platform === "win32" ? expectedCanonical.toLowerCase() : expectedCanonical;
    if (actual !== expected) throw new Error("client_skill_destination_path_invalid");
  }
  return Object.freeze({ verified: true });
}

async function exists(target) {
  return (await lstatMaybe(target)) !== null;
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--apply") options.apply = true;
    else if (argument === "--replace") options.replace = true;
    else if (argument === "--json") options.json = true;
    else if (argument === "--target") options.target = take(argv, ++index, argument);
    else if (argument === "--source-root") options.sourceRoot = take(argv, ++index, argument);
    else if (argument === "--home") options.home = take(argv, ++index, argument);
    else if (argument === "--app-data") options.appData = take(argv, ++index, argument);
    else if (argument === "--local-app-data") options.localAppData = take(argv, ++index, argument);
    else if (argument === "--expected-plan-fingerprint") options.expectedPlanFingerprint = take(argv, ++index, argument);
    else throw new Error(`client_skill_arg_unknown:${argument}`);
  }
  return options;
}

function take(argv, index, argument) {
  const value = argv[index];
  if (!value || value.startsWith("--")) throw new Error(`client_skill_arg_missing:${argument}`);
  return value;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = parseArgs(process.argv.slice(2));
  installClientSkills(options).then(
    (result) => process.stdout.write(`${JSON.stringify(result, null, options.json ? 2 : 0)}\n`),
    (error) => {
      process.stderr.write(`${JSON.stringify({ ok: false, error: String(error?.message || error), ...(error?.recoveryPaths?.length ? { recoveryPaths: error.recoveryPaths } : {}) })}\n`);
      process.exitCode = 1;
    },
  );
}
