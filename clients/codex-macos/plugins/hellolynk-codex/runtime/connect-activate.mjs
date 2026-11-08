#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { verifyDarwinUnclaimedAuthorization } from "./core/hellolynk-darwin-host.mjs";
import { readClientProfile } from "./core/hellolynk-client-profile.mjs";
import { createNeutralHostInstallationStore } from "./core/hellolynk-neutral-host-installation-store.mjs";
import { clientAccountBaseRoot } from "./core/hellolynk-client-account.mjs";
import { createDeviceEnrollmentClient } from "./core/hellolynk-device-enrollment.mjs";
import { verifyPinnedNeutralHostRuntime } from "./core/hellolynk-neutral-host-launcher.mjs";
import {
  createHostProtectedStore,
  HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES,
  HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES,
  verifyHostProtectedStorePath,
} from "./core/hellolynk-host-protected-store.mjs";

const ADAPTER_IDS = Object.freeze(["codex", "cursor", "dsh", "openclaw", "trae-work", "workbuddy", "claude-code"]);

const args = parseArgs(process.argv.slice(2));
const requestedClient = requiredClient(args.client);
const preflightOnly = optionalBoolean(args.preflight, "activation_preflight_invalid");
const preBindOnly = optionalBoolean(args["pre-bind"], "activation_pre_bind_invalid");
if (preBindOnly && !preflightOnly) throw new Error("activation_pre_bind_invalid");
const finalCurrentRoot = requiredPersistentRoot(
  args["final-current-root"],
  "activation_final_current_root_invalid",
);
const root = requiredAbsolute(args.root, "activation_root_invalid");
const releaseCurrentRoot = args["release-current-root"]
  ? requiredPersistentRoot(args["release-current-root"], "activation_release_root_invalid") : finalCurrentRoot;
if (releaseCurrentRoot !== finalCurrentRoot && path.join(releaseCurrentRoot, "host") !== clientAccountBaseRoot(root)) {
  throw new Error("activation_persistent_binding_path_invalid");
}
const releaseRoot = requiredAbsolute(args["release-root"], "activation_release_root_invalid");
const expectedReleaseManifestSha256 = requiredSha256(
  args["expected-release-manifest-sha256"],
  "activation_expected_release_manifest_sha256_invalid",
);
const profileManifestPath = requiredAbsolute(
  args["profile-manifest"],
  "activation_profile_manifest_invalid",
);
if (path.resolve(root) !== path.join(finalCurrentRoot, "host")
  || !isStrictDescendant(releaseRoot, path.join(releaseCurrentRoot, "releases"))
  || path.resolve(profileManifestPath) !== path.join(finalCurrentRoot, "host", "profile-manifest-v1.json")
  || [root, releaseRoot, profileManifestPath].some(hasForbiddenPersistentSegment)) {
  throw new Error("activation_persistent_binding_path_invalid");
}
const runtimeRoot = path.join(root, "runtime");

let profileManifest = null;
try { profileManifest = JSON.parse(await fs.readFile(profileManifestPath, "utf8")); }
catch (error) {
  if (!(preBindOnly && error?.code === "ENOENT")) throw error;
}
if (profileManifest) validateProfileManifest(profileManifest);

const releaseManifestPath = path.join(releaseRoot, "runtime", "neutral-host-release-manifest.json");
const releasePinPath = path.join(releaseRoot, "runtime", "neutral-host-release-pin.json");
const runnerRelativePath = "runtime/neutral-host-bootstrap.mjs";
await fs.access(path.join(releaseRoot, ...runnerRelativePath.split("/")));
const releaseManifestSha256 = crypto.createHash("sha256")
  .update(await fs.readFile(releaseManifestPath))
  .digest("hex");
const releasePin = JSON.parse(await fs.readFile(releasePinPath, "utf8"));
assert.deepEqual(Object.keys(releasePin).sort(), ["contract", "manifestSha256"]);
assert.equal(releasePin.contract, "hellolynk-neutral-host-release-pin-v1");
assert.equal(releasePin.manifestSha256, releaseManifestSha256);
assert.equal(releaseManifestSha256, expectedReleaseManifestSha256);

const installations = createNeutralHostInstallationStore(preflightOnly ? {
  root,
  readOnly: true,
  verifyPath: ({ path: targetPath, directory }) => verifyHostProtectedStorePath({
    root,
    path: targetPath,
    directory,
  }),
} : { root });
const installationStatus = await installations.status();
const active = installationStatus.installations.filter((item) => item.state === "active");
const unclaimed = installationStatus.installations.filter((item) => item.state === "unclaimed");
const freshPreBind = preBindOnly && active.length === 0 && unclaimed.length === 1
  && installationStatus.installations.length === 1;
if (!freshPreBind) assert.equal(active.length, 1);
const installation = freshPreBind ? unclaimed[0] : active[0];
const store = createHostProtectedStore({ root, installationStore: installations, readOnly: preflightOnly });
let recoveryPreBind = false;
if (preBindOnly && !freshPreBind && (!profileManifest || installation.delegateBindings.length !== profileManifest.profiles.length)) {
  const recorded = new Set((profileManifest?.profiles || []).map((file) => path.basename(file, ".json")));
  const missing = installation.delegateBindings.filter((item) => !recorded.has(item.profileId));
  if (missing.length !== 1 || missing[0].adapters?.length !== 1 || missing[0].adapters[0] !== requestedClient
    || recorded.size !== installation.delegateBindings.length - 1) throw new Error("activation_profile_manifest_invalid");
  const recovery = await createDeviceEnrollmentClient({ root: finalCurrentRoot, hostRoot: root, baseUrl: "https://hellolynk.com" }, {
    protectedStore: store, installationStore: installations,
  }).verifyLocalRecovery({ clientType: requestedClient, profileId: missing[0].profileId });
  // Complete only the read-only projection. The ordinary enrollment retry
  // validates live authorization and publishes the real manifest afterwards.
  profileManifest = { contract: "hellolynk-neutral-host-profile-manifest-v1",
    profiles: [...(profileManifest?.profiles || []), recovery.configPath] };
  validateProfileManifest(profileManifest);
  recoveryPreBind = true;
}
if (freshPreBind && profileManifest !== null) throw new Error("activation_profile_manifest_invalid");
if (!freshPreBind && profileManifest === null) throw new Error("activation_profile_manifest_invalid");
profileManifest ||= Object.freeze({
  contract: "hellolynk-neutral-host-profile-manifest-v1",
  profiles: Object.freeze([]),
});
assert.equal(installation.delegateBindings.length, profileManifest.profiles.length);
const existingAdapters = installation.delegateBindings.map((binding) => binding.adapters?.[0]);
const profileIdsByAdapter = freshPreBind ? Object.freeze({}) : resolveAdapterProfileIds(
    profileManifest,
    installation,
    preflightOnly ? existingAdapters : [requestedClient],
  );
if (preflightOnly && !freshPreBind) await verifyManifestProfiles(profileManifest, installation);

const targetProfileId = profileIdsByAdapter[requestedClient] || null;
const verificationAdapter = targetProfileId ? requestedClient : (existingAdapters[0] || requestedClient);
const verificationDelegate = freshPreBind ? Object.freeze({
  region: "prebind",
  principalId: "prebind-principal",
  delegateId: "prebind-delegate",
  hostInstallationId: installation.hostInstallationId,
  profileId: `prebind-${requestedClient}`,
}) : await installations.resolveBinding({
    profileId: profileIdsByAdapter[verificationAdapter],
  });
const verificationScopes = {
  codex: HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES,
  cursor: HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES,
  dsh: HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES,
  openclaw: HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES,
  "trae-work": HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES,
  workbuddy: HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES,
  "claude-code": HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES,
}[verificationAdapter];
const releaseVerification = await verifyPinnedNeutralHostRuntime({
  runtimeRoot,
  releaseRoot,
  releaseManifestSha256,
  runnerRelativePath,
  profileManifestPath,
  region: verificationDelegate.region,
  principalId: verificationDelegate.principalId,
  delegateId: verificationDelegate.delegateId,
  hostInstallationId: verificationDelegate.hostInstallationId,
  profileId: verificationDelegate.profileId,
  adapterId: verificationAdapter,
  version: 2,
  scopes: verificationScopes,
}, { storeRoot: root });
assert.equal(releaseVerification.verifiedFileCount >= 8, true);

let transport = null;
let bootstrapTransportRequired = false;
let protectedStorePresent = true;
try { await fs.lstat(path.join(root, process.platform === "darwin" ? "protected-v1.sqlite" : "capabilities-v1.dpapi.clixml")); }
catch (error) {
  if (error?.code !== "ENOENT") throw error;
  protectedStorePresent = false;
}
if (!protectedStorePresent) {
  if (!(freshPreBind || recoveryPreBind)) await store.status();
  await verifyHostProtectedStorePath({ root, path: root, directory: true });
  bootstrapTransportRequired = true;
} else if (process.platform === "darwin" && freshPreBind) {
  await verifyDarwinUnclaimedAuthorization(root);
  bootstrapTransportRequired = true;
} else {
  assert.equal((await store.status()).protected, true);
  try { transport = preflightOnly ? await store.verifyTransport() : await store.resolveTransport(); }
  catch (error) {
    if (!(freshPreBind || recoveryPreBind) || String(error?.code || error?.message) !== "host_transport_credential_required") throw error;
    bootstrapTransportRequired = true;
  }
}
if (transport) {
  assert.equal(transport.credential.hostInstallationId, installation.hostInstallationId);
  assert.equal(transport.credential.principalId, installation.principalId);
}

const specs = [
  {
    adapterId: "codex",
    profileId: profileIdsByAdapter.codex,
    scopes: HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveCodexNeutralBinding(),
    verify: () => store.verifyCodexNeutralBinding(),
    save: (input) => store.saveCodexNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    replace: (previousBinding, replacementBinding) => store.replaceCodexNeutralBinding({
      previousBinding,
      replacementBinding: {
        ...replacementBinding,
        runtimeRoot,
        releaseRoot,
        releaseManifestSha256,
        runnerRelativePath,
        profileManifestPath,
      },
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateCodexNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot) === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath) === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrateScopes: true,
  },
  {
    adapterId: "openclaw",
    profileId: profileIdsByAdapter.openclaw,
    scopes: HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveOpenClawNeutralBinding({ profileId: profileIdsByAdapter.openclaw }),
    verify: () => store.verifyOpenClawNeutralBinding({ profileId: profileIdsByAdapter.openclaw }),
    save: (input) => store.saveOpenClawNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateOpenClawNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrateScopes: true,
  },
  {
    adapterId: "trae-work",
    profileId: profileIdsByAdapter["trae-work"],
    scopes: HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveTraeWorkNeutralBinding({ profileId: profileIdsByAdapter["trae-work"] }),
    verify: () => store.verifyTraeWorkNeutralBinding({ profileId: profileIdsByAdapter["trae-work"] }),
    save: (input) => store.saveTraeWorkNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateTraeWorkNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrateScopes: true,
  },
  {
    adapterId: "workbuddy",
    profileId: profileIdsByAdapter.workbuddy,
    scopes: HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveWorkBuddyNeutralBinding({ profileId: profileIdsByAdapter.workbuddy }),
    verify: () => store.verifyWorkBuddyNeutralBinding({ profileId: profileIdsByAdapter.workbuddy }),
    save: (input) => store.saveWorkBuddyNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateWorkBuddyNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrateScopes: true,
  },
  {
    adapterId: "claude-code",
    profileId: profileIdsByAdapter["claude-code"],
    scopes: HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveClaudeCodeNeutralBinding({ profileId: profileIdsByAdapter["claude-code"] }),
    verify: () => store.verifyClaudeCodeNeutralBinding({ profileId: profileIdsByAdapter["claude-code"] }),
    save: (input) => store.saveClaudeCodeNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateClaudeCodeNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    // Claude has no legacy scope set; use the existing atomic binding migration
    // path for a pinned release change, preserving the same exact scopes.
    migrateScopes: true,
  },
  {
    adapterId: "cursor",
    profileId: profileIdsByAdapter.cursor,
    scopes: HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveCursorNeutralBinding({ profileId: profileIdsByAdapter.cursor }),
    verify: () => store.verifyCursorNeutralBinding({ profileId: profileIdsByAdapter.cursor }),
    save: (input) => store.saveCursorNeutralBinding({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => (
      store.migrateCursorNeutralBinding({
        previousBinding,
        replacementBinding,
        previousCapabilityId,
      })
    ),
    current: (binding) => (
      hasExactScopes(binding, HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath
    ),
    upgrade: (input) => ({
      ...input,
      runtimeRoot,
      releaseRoot,
      releaseManifestSha256,
      runnerRelativePath,
      profileManifestPath,
    }),
    migrateScopes: true,
  },
  {
    adapterId: "dsh",
    profileId: profileIdsByAdapter.dsh,
    scopes: HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES,
    resolve: () => store.resolveDshNeutralBinding({ profileId: profileIdsByAdapter.dsh }),
    verify: () => store.verifyDshNeutralBinding({ profileId: profileIdsByAdapter.dsh }),
    save: (input) => store.saveDshNeutralBinding({ ...input, runtimeRoot, releaseRoot, releaseManifestSha256, runnerRelativePath, profileManifestPath }),
    migrate: (previousBinding, replacementBinding, previousCapabilityId) => store.migrateDshNeutralBinding({ previousBinding, replacementBinding, previousCapabilityId }),
    current: (binding) => hasExactScopes(binding, HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES)
      && path.resolve(binding.releaseRoot || ".") === releaseRoot
      && binding.releaseManifestSha256 === releaseManifestSha256
      && binding.runnerRelativePath === runnerRelativePath
      && path.resolve(binding.profileManifestPath || ".") === profileManifestPath,
    upgrade: (input) => ({ ...input, runtimeRoot, releaseRoot, releaseManifestSha256, runnerRelativePath, profileManifestPath }),
    migrateScopes: true,
  },
];

const results = [];
for (const spec of specs.filter((item) => item.adapterId === requestedClient)) {
  if (preflightOnly) {
    results.push(await preflightBinding(spec, targetProfileId));
    continue;
  }
  let existing = null;
  try {
    existing = await spec.resolve();
  } catch (error) {
    if (!isRecoverableMissingBinding(error)) throw error;
  }
  if (existing) {
    if (!spec.current || spec.current(existing)) {
      results.push(publicResult(existing, true));
      continue;
    }
    if (hasExactScopes(existing, spec.scopes) && typeof spec.replace === "function") {
      const priorCapabilityId = existing.capability.capabilityId;
      const priorBinding = codexBindingInput(existing);
      const updated = await spec.replace(priorBinding, priorBinding);
      const resolved = await spec.resolve();
      assert.equal(updated.releaseManifestSha256, releaseManifestSha256);
      assert.equal(resolved.capability.capabilityId, priorCapabilityId);
      results.push(publicResult(resolved, true, true));
      continue;
    }
    if (spec.migrateScopes === true) {
      results.push(await migrateScopedBinding({ store, installations, installation, spec, existing }));
      continue;
    }
    const priorCapabilityId = existing.capability.capabilityId;
    const priorBinding = codexBindingInput(existing);
    const updated = await spec.replace(priorBinding, priorBinding);
    const resolved = await spec.resolve();
    assert.equal(updated.releaseManifestSha256, releaseManifestSha256);
    assert.equal(resolved.capability.capabilityId, priorCapabilityId);
    results.push(publicResult(resolved, true, true));
    continue;
  }
  const delegate = await installations.resolveBinding({ profileId: spec.profileId });
  const capability = await store.issue({
    region: delegate.region,
    principalId: delegate.principalId,
    delegateId: delegate.delegateId,
    hostInstallationId: delegate.hostInstallationId,
    adapterId: spec.adapterId,
    version: 2,
    scopes: spec.scopes,
  });
  try {
    await spec.save({
      profileId: spec.profileId,
      delegateId: delegate.delegateId,
      adapterId: spec.adapterId,
      version: 2,
      scopes: spec.scopes,
    });
    const resolved = await spec.resolve();
    assert.equal(resolved.capability.capabilityId, capability.capabilityId);
    results.push(publicResult(resolved, false));
  } catch (error) {
    await store.revoke(capability.capabilityId).catch(() => {});
    throw error;
  }
}

process.stdout.write(`${JSON.stringify({
  ok: true,
  preflight: preflightOnly,
  preBind: preBindOnly,
  readOnly: preflightOnly,
  protected: true,
  installationState: installation.state,
  profileManifestState: freshPreBind ? "deferred" : recoveryPreBind ? "recovery_pending" : "verified",
  bootstrapTransportRequired,
  transportCredentialState: bootstrapTransportRequired
    ? "bootstrap_required" : (preflightOnly ? "active" : transport.credential.state),
  releaseManifestSha256,
  verifiedReleaseFileCount: releaseVerification.verifiedFileCount,
  clients: results,
}, null, 2)}\n`);

async function preflightBinding(spec, targetProfile) {
  if (!targetProfile) {
    return Object.freeze({
      adapterId: spec.adapterId,
      profileId: null,
      delegatePresent: false,
      bindingPresent: false,
      bindingState: "awaiting_delegate_binding",
      plannedMutation: "deferred",
      bindingUpdated: false,
    });
  }
  let existing = null;
  try {
    if (protectedStorePresent) existing = await spec.verify();
  } catch (error) {
    if (!isRecoverableMissingBinding(error)) throw error;
  }
  if (!existing) {
    return Object.freeze({
      adapterId: spec.adapterId,
      profileId: targetProfile,
      delegatePresent: true,
      bindingPresent: false,
      bindingState: "missing",
      plannedMutation: "issue_and_save",
      bindingUpdated: false,
    });
  }
  const current = !spec.current || spec.current(existing);
  const plannedMutation = current
    ? "none"
    : hasExactScopes(existing, spec.scopes) && typeof spec.replace === "function"
      ? "replace"
      : spec.migrateScopes === true ? "migrate" : "replace";
  return Object.freeze({
    ...publicResult(existing, true),
    delegatePresent: true,
    bindingPresent: true,
    bindingState: current ? "current" : `${plannedMutation}_required`,
    plannedMutation,
    bindingUpdated: false,
  });
}

function validateProfileManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || Object.keys(manifest).sort().join(",") !== "contract,profiles"
    || manifest.contract !== "hellolynk-neutral-host-profile-manifest-v1"
    || !Array.isArray(manifest.profiles)
    || manifest.profiles.length < 1 || manifest.profiles.length > ADAPTER_IDS.length) {
    throw new Error("activation_profile_manifest_invalid");
  }
  for (const profileFile of manifest.profiles) {
    const absolute = requiredAbsolute(profileFile, "activation_profile_manifest_invalid");
    if (!isStrictDescendant(absolute, path.join(finalCurrentRoot, "profiles"))
      || hasForbiddenPersistentSegment(absolute)) {
      throw new Error("activation_profile_manifest_invalid");
    }
  }
}

async function verifyManifestProfiles(manifest, installationValue) {
  for (const profileFile of manifest.profiles) {
    const profile = await readClientProfile(profileFile);
    const profileId = path.basename(profileFile, ".json");
    const delegate = installationValue.delegateBindings.find((item) => item.profileId === profileId);
    if (profile.contract !== "hellolynk-client-profile-v1"
      || profile.schemaVersion !== 2
      || profile.profileId !== profileId
      || !delegate
      || profile.region !== installationValue.region
      || profile.principalId !== installationValue.principalId
      || profile.hostId !== installationValue.hostInstallationId
      || profile.delegateId !== delegate.delegateId
      || profile.authorizationVersion !== delegate.authorizationVersion) {
      throw new Error("activation_profile_binding_invalid");
    }
  }
}

function publicResult(binding, reused, bindingUpdated = false) {
  return {
    adapterId: binding.adapterId,
    profileId: binding.profileId,
    capabilityState: binding.capability.state,
    version: binding.version,
    scopeCount: binding.scopes.length,
    reused,
    bindingUpdated,
  };
}

async function migrateScopedBinding({ store, installations, installation, spec, existing }) {
  const delegate = await installations.resolveBinding({ profileId: spec.profileId });
  assert.equal(delegate.region, installation.region);
  assert.equal(delegate.principalId, installation.principalId);
  assert.equal(delegate.hostInstallationId, installation.hostInstallationId);
  const priorBinding = neutralBindingInput(existing);
  const replacementBinding = Object.freeze(spec.upgrade ? spec.upgrade({
    ...priorBinding,
    scopes: [...spec.scopes],
    runtimeRoot,
  }) : {
    ...priorBinding,
    scopes: [...spec.scopes],
    runtimeRoot,
  });
  const migrated = await spec.migrate(
    priorBinding,
    replacementBinding,
    existing.capability.capabilityId,
  );
  const resolved = await spec.resolve();
  assert.equal(resolved.capability.capabilityId, migrated.capability.capabilityId);
  assert.notEqual(resolved.capability.capabilityId, existing.capability.capabilityId);
  return {
    ...publicResult(resolved, false, true),
    capabilityMigrated: true,
  };
}

function neutralBindingInput(binding) {
  return {
    contract: binding.contract,
    region: binding.region,
    principalId: binding.principalId,
    delegateId: binding.delegateId,
    hostInstallationId: binding.hostInstallationId,
    profileId: binding.profileId,
    adapterId: binding.adapterId,
    version: binding.version,
    scopes: [...binding.scopes],
    runtimeRoot: binding.runtimeRoot,
    ...(binding.releaseRoot ? {
      releaseRoot: binding.releaseRoot,
      releaseManifestSha256: binding.releaseManifestSha256,
      runnerRelativePath: binding.runnerRelativePath,
      profileManifestPath: binding.profileManifestPath,
    } : {}),
  };
}

function hasExactScopes(binding, expected) {
  return binding.scopes.length === expected.length
    && binding.scopes.every((scope, index) => scope === expected[index]);
}

function codexBindingInput(binding) {
  return {
    contract: binding.contract,
    region: binding.region,
    principalId: binding.principalId,
    delegateId: binding.delegateId,
    hostInstallationId: binding.hostInstallationId,
    profileId: binding.profileId,
    adapterId: binding.adapterId,
    version: binding.version,
    scopes: [...binding.scopes],
    runtimeRoot: binding.runtimeRoot,
    releaseRoot: binding.releaseRoot,
    releaseManifestSha256: binding.releaseManifestSha256,
    runnerRelativePath: binding.runnerRelativePath,
    profileManifestPath: binding.profileManifestPath,
  };
}

function isRecoverableMissingBinding(error) {
  return [
    "neutral_codex_binding_configuration_required",
    "neutral_codex_capability_missing",
    "neutral_openclaw_binding_configuration_required",
    "neutral_openclaw_capability_missing",
    "neutral_trae_work_binding_configuration_required",
    "neutral_trae_work_capability_missing",
    "neutral_workbuddy_binding_configuration_required",
    "neutral_workbuddy_capability_missing",
    "neutral_claude_code_binding_configuration_required",
    "neutral_claude_code_capability_missing",
    "neutral_cursor_binding_configuration_required",
    "neutral_cursor_capability_missing",
    "neutral_dsh_binding_configuration_required",
    "neutral_dsh_capability_missing",
  ].includes(error?.code || error?.message);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value == null) throw new Error("activation_arguments_invalid");
    const name = key.slice(2);
    if (!new Set([
      "root", "release-root", "expected-release-manifest-sha256", "profile-manifest", "client",
      "final-current-root", "release-current-root", "preflight", "pre-bind",
    ]).has(name)
      || Object.hasOwn(options, name)) throw new Error("activation_arguments_invalid");
    options[name] = value;
  }
  return options;
}

function optionalBoolean(value, code) {
  if (value == null) return false;
  if (!new Set(["false", "true"]).has(value)) throw new Error(code);
  return value === "true";
}

function requiredClient(value) {
  const client = String(value || "");
  if (!ADAPTER_IDS.includes(client)) throw new Error("activation_client_invalid");
  return client;
}

function requiredAbsolute(value, code) {
  const text = String(value || "");
  if (!path.isAbsolute(text) || path.resolve(text) !== text) throw new Error(code);
  return text;
}

function requiredSha256(value, code) {
  const text = String(value || "");
  if (!/^[a-f0-9]{64}$/.test(text)) throw new Error(code);
  return text;
}

function requiredPersistentRoot(value, code) {
  const rootValue = requiredAbsolute(value, code);
  if (hasForbiddenPersistentSegment(rootValue)
    || /(?:^|[-_.])stage(?:$|[-_.])/iu.test(path.basename(rootValue))) {
    throw new Error(code);
  }
  return rootValue;
}

function hasForbiddenPersistentSegment(value) {
  const normalized = path.resolve(String(value || "")).replaceAll("\\", "/").toLowerCase();
  return normalized.includes("/.codex/worktrees/")
    || normalized.endsWith("/.codex/worktrees")
    || /(?:^|\/)[^/]*hellolynk[^/]*stage[^/]*(?:\/|$)/u.test(normalized);
}

function isStrictDescendant(value, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(value));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

export function resolveAdapterProfileIds(
  profileManifestValue,
  installationValue,
  requestedAdapters = ADAPTER_IDS,
) {
  if (!Array.isArray(requestedAdapters) || requestedAdapters.length < 1
    || requestedAdapters.length > ADAPTER_IDS.length
    || new Set(requestedAdapters).size !== requestedAdapters.length
    || requestedAdapters.some((adapterId) => !ADAPTER_IDS.includes(adapterId))) {
    throw new Error("activation_client_invalid");
  }
  const profileFiles = profileManifestValue?.profiles;
  if (!Array.isArray(profileFiles) || profileFiles.length < 1
    || profileFiles.length > ADAPTER_IDS.length) {
    throw new Error("activation_profile_manifest_invalid");
  }
  const manifestProfileIds = new Set(profileFiles.map((profileFile) => {
    const profileId = path.basename(String(profileFile || ""), ".json");
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/u.test(profileId)
      || path.basename(String(profileFile || "")) !== `${profileId}.json`) {
      throw new Error("activation_profile_manifest_invalid");
    }
    return profileId;
  }));
  if (manifestProfileIds.size !== profileFiles.length) {
    throw new Error("activation_profile_manifest_invalid");
  }
  const delegateBindings = installationValue?.delegateBindings;
  if (!Array.isArray(delegateBindings) || delegateBindings.length !== manifestProfileIds.size) {
    throw new Error("activation_profile_binding_invalid");
  }
  const bindingProfileIds = new Set(delegateBindings.map((binding) => binding?.profileId));
  if (bindingProfileIds.size !== delegateBindings.length
    || bindingProfileIds.size !== manifestProfileIds.size
    || [...manifestProfileIds].some((profileId) => !bindingProfileIds.has(profileId))) {
    throw new Error("activation_profile_binding_invalid");
  }
  const boundAdapters = new Set();
  for (const binding of delegateBindings) {
    if (!Array.isArray(binding.adapters) || binding.adapters.length !== 1
      || !ADAPTER_IDS.includes(binding.adapters[0]) || boundAdapters.has(binding.adapters[0])) {
      throw new Error("activation_profile_binding_invalid");
    }
    boundAdapters.add(binding.adapters[0]);
  }
  const mapping = Object.fromEntries(requestedAdapters.map((adapterId) => {
    const matches = delegateBindings.filter(
      (binding) => Array.isArray(binding.adapters) && binding.adapters.includes(adapterId)
        && manifestProfileIds.has(binding.profileId),
    );
    if (matches.length !== 1) throw new Error(`activation_${adapterId}_profile_binding_invalid`);
    return [adapterId, matches[0].profileId];
  }));
  if (new Set(Object.values(mapping)).size !== requestedAdapters.length) {
    throw new Error("activation_profile_binding_invalid");
  }
  return Object.freeze(mapping);
}
