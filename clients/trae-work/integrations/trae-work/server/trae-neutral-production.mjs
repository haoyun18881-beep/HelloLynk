import path from "node:path";
import { resolveClientAccountRoot } from "../../../runtime/core/hellolynk-client-account.mjs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createHostProtectedStore } from "../../../runtime/core/hellolynk-host-protected-store.mjs";
import { createNeutralHostInstallationStore, defaultNeutralHostStoreRoot } from "../../../runtime/core/hellolynk-neutral-host-installation-store.mjs";
import { launchTraeWorkNeutralHost, verifyPinnedBootstrap } from "./host-lifecycle.mjs";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const RELEASE_ROOT = path.resolve(MODULE_DIR, "..", "..", "..");

// This is intentionally TRAE-owned: it obtains the protected binding locally,
// checks that it points at this fixed release, and starts no other client host.
export async function createTraeWorkNeutralProduction(options = {}) {
  const releaseRoot = path.resolve(options.releaseRoot || RELEASE_ROOT);
  const { storeRoot, protectedStore } = traeStores(options);
  const resolved = options.resolvedBinding || await protectedStore.resolveTraeWorkNeutralBinding();
  assertReleaseBinding(resolved, releaseRoot);
  const preverified = String(options.verifiedReleaseManifestSha256 || "");
  if (preverified && preverified !== resolved.releaseManifestSha256) {
    throw codeError("neutral_trae_work_runner_integrity_invalid");
  }
  const inspection = preverified
    ? Object.freeze({ ok: true, preverified: true })
    : await verifyPinnedBootstrap(resolved, { storeRoot });
  let initialBinding = resolved;
  let launchCandidate = null;
  return Object.freeze({
    inspection, releaseRoot, storeRoot, protectedStore,
    capabilityProvider: async () => {
      const binding = initialBinding || await protectedStore.resolveTraeWorkNeutralBinding();
      initialBinding = null;
      assertReleaseBinding(binding, releaseRoot);
      launchCandidate = binding;
      return binding;
    },
    hostLauncher: async (binding) => {
      if (!launchCandidate) throw codeError("neutral_trae_work_capability_binding_mismatch");
      assertSamePublicBinding(binding, launchCandidate);
      launchCandidate = null;
      return launchTraeWorkNeutralHost(binding, {
        storeRoot,
        ...(options.spawnRunner ? { spawnRunner: options.spawnRunner } : {}),
        ...(options.wait ? { wait: options.wait } : {}),
      });
    },
  });
}

// A background update can move the binding to a newer release while this MCP stays open.
// Each connection uses the production of the release the binding names now; that module
// checks the binding against its own location again.
export async function createCurrentTraeWorkNeutralProduction(options = {}) {
  const { protectedStore } = traeStores(options);
  const resolved = await protectedStore.resolveTraeWorkNeutralBinding();
  const ownRoot = path.resolve(options.releaseRoot || RELEASE_ROOT);
  const boundRoot = path.resolve(String(resolved?.releaseRoot || ownRoot));
  if (boundRoot === ownRoot) return createTraeWorkNeutralProduction({ ...options, protectedStore, resolvedBinding: resolved });
  // Installed releases sit side by side; a binding that names any other place is not loaded.
  if (path.dirname(boundRoot) !== path.dirname(ownRoot)) {
    resolved?.capability?.secretBuffer?.fill(0);
    throw codeError("neutral_trae_work_runner_integrity_invalid");
  }
  const { releaseRoot: _ownRoot, ...forwarded } = options;
  const bound = await import(pathToFileURL(path.join(boundRoot, "integrations", "trae-work", "server", "trae-neutral-production.mjs")).href);
  return bound.createTraeWorkNeutralProduction({ ...forwarded, resolvedBinding: resolved });
}

function traeStores(options) {
  const env = options.env || process.env;
  const storeRoot = resolveClientAccountRoot("trae-work", absolutePath(
    options.storeRoot || env.HELLOLYNK_NEUTRAL_STORE_ROOT || defaultNeutralHostStoreRoot("win32", env),
    "neutral_trae_work_binding_configuration_required",
  ));
  const installationStore = options.installationStore || createNeutralHostInstallationStore({ root: storeRoot });
  return { storeRoot, protectedStore: options.protectedStore || createHostProtectedStore({ root: storeRoot, installationStore }) };
}

function assertReleaseBinding(binding, releaseRoot) {
  if (!binding?.releaseRoot || path.resolve(binding.releaseRoot) !== releaseRoot
    || !/^[a-f0-9]{64}$/.test(String(binding.releaseManifestSha256 || ""))
    || binding.runnerRelativePath !== "runtime/neutral-host-bootstrap.mjs"
    || !path.isAbsolute(String(binding.profileManifestPath || ""))) {
    throw codeError("neutral_trae_work_runner_integrity_invalid");
  }
}
function assertSamePublicBinding(expected, actual) {
  for (const key of [
    "region", "principalId", "delegateId", "hostInstallationId", "profileId", "adapterId", "version",
    "runtimeRoot", "releaseRoot", "releaseManifestSha256", "runnerRelativePath", "profileManifestPath",
  ]) {
    if (expected?.[key] !== actual?.[key]) throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
  if (JSON.stringify(expected.scopes) !== JSON.stringify(actual.scopes)) throw codeError("neutral_trae_work_capability_binding_mismatch");
}
function absolutePath(value, code) { const text = String(value || ""); if (!path.isAbsolute(text)) throw codeError(code); return path.resolve(text); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
