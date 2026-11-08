import fs from "node:fs/promises";
import path from "node:path";
import { createHostProtectedStore } from "./core/hellolynk-host-protected-store.mjs";
import { createNeutralHostInstallationStore, defaultNeutralHostStoreRoot } from "./core/hellolynk-neutral-host-installation-store.mjs";
import { startHelloLynkNeutralHostAssembly } from "./core/hellolynk-neutral-host-assembly.mjs";

export async function createNeutralHostReleaseRuntime() { return Object.freeze({ defaultStoreRoot: (env) => defaultNeutralHostStoreRoot("win32", env), createInstallationStore: (options) => createNeutralHostInstallationStore(options), createProtectedStore: (options) => createHostProtectedStore(options), run: async ({ root }) => runProductionHost(root) }); }
async function runProductionHost(rootInput) {
  const root = path.resolve(String(rootInput || "")); if (!path.isAbsolute(root) || root.length < 4) throw codeError("neutral_trae_work_launch_configuration_required");
  const installationStore = createNeutralHostInstallationStore({ root }); const protectedStore = createHostProtectedStore({ root, installationStore }); const binding = await protectedStore.resolveTraeWorkNeutralBinding();
  const profiles = await readProfileManifest(binding.profileManifestPath); const assembly = await startHelloLynkNeutralHostAssembly({ root, runtimeRoot: binding.runtimeRoot, profiles: profiles.map((profileFile) => ({ profileFile })) }, { installationStore, protectedStore });
  // A failed Host never reaches "stopped"; end the wait so the bootstrap exits with its code.
  return Object.freeze({ stop: assembly.stop, waitUntilStopped: async () => { while (assembly.host.status !== "stopped") { if (assembly.host.status === "failed") throw codeError(assembly.host.failureCode || "neutral_host_stop_failed"); await new Promise((resolve) => setTimeout(resolve, 50)); } } });
}
async function readProfileManifest(input) { const manifestPath = path.resolve(String(input || "")); if (!path.isAbsolute(manifestPath)) throw codeError("neutral_trae_work_launch_manifest_invalid"); let manifest; try { manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")); } catch { throw codeError("neutral_trae_work_launch_manifest_invalid"); } if (!manifest || manifest.contract !== "hellolynk-neutral-host-profile-manifest-v1" || !Array.isArray(manifest.profiles) || !manifest.profiles.length || manifest.profiles.length > 16 || Object.keys(manifest).sort().join(",") !== "contract,profiles") throw codeError("neutral_trae_work_launch_manifest_invalid"); const profiles = manifest.profiles.map((value) => path.resolve(String(value || ""))); if (profiles.some((value, index) => !path.isAbsolute(value) || profiles.indexOf(value) !== index)) throw codeError("neutral_trae_work_launch_manifest_invalid"); return Object.freeze(profiles); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
