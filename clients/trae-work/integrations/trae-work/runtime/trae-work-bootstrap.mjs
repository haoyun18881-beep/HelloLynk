#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isWorkbenchConnectionRequired } from "../../../clients/core/hellolynk-workbench-connection.mjs";
import { resolveClientAccountRoot } from "../../../clients/core/hellolynk-client-account.mjs";
import { createHostProtectedStore } from "../../../clients/core/hellolynk-host-protected-store.mjs";
import { createNeutralHostInstallationStore, defaultNeutralHostStoreRoot } from "../../../clients/core/hellolynk-neutral-host-installation-store.mjs";
import { verifyPinnedBootstrap } from "../server/host-lifecycle.mjs";

const RELEASE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export async function runTraeWorkBootstrap(argv = process.argv.slice(2), options = {}) {
  const expected = parse(argv); const root = resolveClientAccountRoot("trae-work", options.storeRoot || defaultNeutralHostStoreRoot("win32", options.env || process.env));
  const installationStore = createNeutralHostInstallationStore({ root }); const store = createHostProtectedStore({ root, installationStore });
  let binding;
  try { binding = await store.resolveTraeWorkNeutralBinding(); }
  catch (error) { if (!isWorkbenchConnectionRequired(error)) throw error; }
  const verification = binding || {
    adapterId: "trae-work", profileId: "hellolynk-host-trae-work-v2", version: 2, scopes: [],
    region: "intl", principalId: "connection-preflight", delegateId: "connection-preflight", hostInstallationId: "connection-preflight",
    releaseRoot: RELEASE_ROOT, releaseManifestSha256: expected, runnerRelativePath: "runtime/neutral-host-bootstrap.mjs",
    runtimeRoot: path.join(root, "runtime"), profileManifestPath: path.join(root, "profile-manifest-v1.json"),
  };
  if (path.resolve(verification.releaseRoot || "") !== RELEASE_ROOT || verification.releaseManifestSha256 !== expected) throw codeError("neutral_trae_work_runner_integrity_invalid");
  await verifyPinnedBootstrap(verification, { storeRoot: root });
  const proxy = await import(pathToFileURL(path.join(RELEASE_ROOT, "integrations", "trae-work", "server", "mcp-proxy.mjs")).href);
  return proxy.runTraeWorkMcpProxy({ storeRoot: root });
}
function parse(argv) { if (argv.length !== 3 || argv[0] !== "run" || argv[1] !== "--expected-manifest-sha256" || !/^[a-f0-9]{64}$/.test(String(argv[2] || ""))) throw codeError("trae_work_bootstrap_arguments_invalid"); return argv[2]; }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) runTraeWorkBootstrap().catch((error) => { process.stderr.write(`${JSON.stringify({ ok: false, error: error.code || "trae_work_bootstrap_failed" })}\n`); process.exitCode = 1; });
