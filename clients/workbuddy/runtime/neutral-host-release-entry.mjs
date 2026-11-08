import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createHostProtectedStore } from "./core/hellolynk-host-protected-store.mjs";
import {
  createNeutralHostInstallationStore,
  defaultNeutralHostStoreRoot,
} from "./core/hellolynk-neutral-host-installation-store.mjs";
import { startHelloLynkNeutralHostAssembly } from "./core/hellolynk-neutral-host-assembly.mjs";

export async function createNeutralHostReleaseRuntime() {
  return Object.freeze({
    defaultStoreRoot: (env) => defaultNeutralHostStoreRoot("win32", env),
    createInstallationStore: (options) => createNeutralHostInstallationStore(options),
    createProtectedStore: (options) => createHostProtectedStore(options),
    run: async ({ root }) => runProductionHost(root),
  });
}

async function runProductionHost(rootInput) {
  const rootText = String(rootInput || "");
  if (!path.isAbsolute(rootText) || path.resolve(rootText) !== rootText || rootText.length < 4) {
    throw codeError("neutral_runtime_launch_configuration_required");
  }
  const root = rootText;
  const installationStore = createNeutralHostInstallationStore({ root });
  const protectedStore = createHostProtectedStore({ root, installationStore });
  const binding = await resolveInstalledBinding(protectedStore);
  const profiles = await readProfileManifest(binding.profileManifestPath);
  const assembly = await startHelloLynkNeutralHostAssembly({
    root,
    runtimeRoot: binding.runtimeRoot,
    profiles: profiles.map((profileFile) => ({ profileFile })),
  }, { installationStore, protectedStore });
  return Object.freeze({
    stop: assembly.stop,
    waitUntilStopped: async () => {
      while (assembly.host.status !== "stopped") {
        // A failed Host never reaches "stopped"; end the wait so the bootstrap exits with its code.
        if (assembly.host.status === "failed") throw codeError(assembly.host.failureCode || "neutral_host_stop_failed");
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    },
  });
}

async function resolveInstalledBinding(store) {
  const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const candidates = [];
  for (const resolveBinding of [
    () => store.resolveWorkBuddyNeutralBinding(),
    () => store.resolveOpenClawNeutralBinding(),
  ]) {
    try {
      const binding = await resolveBinding();
      if (path.resolve(binding.releaseRoot || "") === releaseRoot) candidates.push(binding);
    } catch {}
  }
  if (candidates.length !== 1) throw codeError("neutral_runtime_binding_invalid");
  return candidates[0];
}

async function readProfileManifest(manifestPath) {
  let manifest;
  try { manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")); }
  catch { throw codeError("neutral_runtime_profile_manifest_invalid"); }
  if (!manifest || manifest.contract !== "hellolynk-neutral-host-profile-manifest-v1"
    || !Array.isArray(manifest.profiles) || !manifest.profiles.length || manifest.profiles.length > 16
    || Object.keys(manifest).sort().join(",") !== "contract,profiles") {
    throw codeError("neutral_runtime_profile_manifest_invalid");
  }
  const profiles = manifest.profiles.map((value) => String(value || ""));
  if (profiles.some((value, index) => !path.isAbsolute(value)
    || path.resolve(value) !== value || profiles.indexOf(value) !== index)) {
    throw codeError("neutral_runtime_profile_manifest_invalid");
  }
  return Object.freeze(profiles);
}

function codeError(code) { const error = new Error(code); error.code = code; return error; }
