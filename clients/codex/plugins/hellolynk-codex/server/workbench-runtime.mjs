import fs from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

// Codex uses resource metadata before the app can report its intrinsic size.
// Keep a usable frame when its initial container limit is echoed by the app.
export const CODEX_WORKBENCH_RESOURCE_META = Object.freeze({
  ui: Object.freeze({ prefersBorder: true, domain: "hellolynk.local" }),
  "openai/widgetPrefersBorder": true,
  "openai/widgetHeightHint": 680,
  "openai/widgetMinFrameHeight": 680,
});

const CODEX_RESOURCE_URI_SEED = "ui://hellolynk/workbench-codex-pending.html";
const OUTPUT_SHA256_RE = /^[a-f0-9]{64}$/;
const SHARED_ROOTS = Object.freeze([
  new URL("../runtime/workbench/", import.meta.url),
  new URL("../../../clients/workbench/", import.meta.url),
]);
let sharedWorkbenchModulesPromise = null;

export async function bootstrapCodexWorkbenchRuntime(options = {}) {
  const shared = options.sharedModules || await loadSharedWorkbenchModules();
  if (typeof shared?.bootstrapWorkbenchCandidate !== "function"
    || !shared.HELLOLYNK_WORKBENCH_COMMAND_TYPES
    || typeof shared.HELLOLYNK_WORKBENCH_COMMAND_TYPES !== "object"
    || Array.isArray(shared.HELLOLYNK_WORKBENCH_COMMAND_TYPES)
    || typeof shared.HELLOLYNK_WORKBENCH_COMMAND_CONTRACT !== "string"
    || typeof shared.HELLOLYNK_WORKBENCH_RESULT_CONTRACT !== "string"
    || !Number.isSafeInteger(shared.HELLOLYNK_WORKBENCH_SCHEMA_VERSION)
    || shared.HELLOLYNK_WORKBENCH_SCHEMA_VERSION <= 0
    || typeof shared.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT !== "string"
    || !Number.isSafeInteger(shared.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION)
    || shared.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION <= 0
    || typeof shared.validateWorkbenchReadRequest !== "function"
    || typeof shared.validateWorkbenchSnapshot !== "function"
    || typeof shared.validateWorkbenchCommand !== "function"
    || typeof shared.validateWorkbenchCommandResult !== "function") {
    throw codeError("workbench_codex_shared_bootstrap_invalid");
  }
  const explicitResourceUri = options.resourceUri == null ? null : options.resourceUri;
  const bootstrapped = await shared.bootstrapWorkbenchCandidate("codex", {
    resourceUri: explicitResourceUri || CODEX_RESOURCE_URI_SEED,
  });
  const resourceUri = explicitResourceUri || codexWorkbenchResourceUri(bootstrapped);
  const candidate = resourceUri === bootstrapped.resourceUri
    ? bootstrapped
    : Object.freeze({ ...bootstrapped, resourceUri });
  if (options.adapter === undefined) return candidate;
  if (typeof options.adapter?.readWorkbenchSnapshot !== "function") {
    throw codeError("workbench_codex_rpc_adapter_invalid");
  }
  const commandTypes = Object.freeze(Object.values(shared.HELLOLYNK_WORKBENCH_COMMAND_TYPES));
  if (commandTypes.length === 0 || new Set(commandTypes).size !== commandTypes.length
    || commandTypes.some((value) => typeof value !== "string")) {
    throw codeError("workbench_codex_shared_commands_invalid");
  }
  const readOnlyCandidate = {
    resourceUri: candidate.resourceUri,
    html: candidate.html,
    readSnapshot: (input = {}) => options.adapter.readWorkbenchSnapshot(input),
    ...(typeof options.adapter.readWorkbenchChanges === "function"
      ? { readChanges: (input) => options.adapter.readWorkbenchChanges(input) } : {}),
    ...(typeof options.connectAccount === "function" ? { connectAccount: options.connectAccount } : {}),
    validateReadRequest: shared.validateWorkbenchReadRequest,
    validateSnapshot: shared.validateWorkbenchSnapshot,
  };
  if (!supportsF3ActionGrantTransport(shared, candidate, options.adapter)) {
    return Object.freeze(readOnlyCandidate);
  }
  return Object.freeze({
    ...readOnlyCandidate,
    snapshotContractId: shared.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
    snapshotSchemaVersion: shared.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
    commandContractId: shared.HELLOLYNK_WORKBENCH_COMMAND_CONTRACT,
    commandSchemaVersion: shared.HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    resultContractId: shared.HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
    resultSchemaVersion: shared.HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
    commandTypes,
    issueActionGrant: (command) => options.adapter.issueWorkbenchActionGrant(command),
    executeCommand: (command, context) => options.adapter.executeWorkbenchCommand(command, context),
    validateCommand: shared.validateWorkbenchCommand,
    validateCommandResult: shared.validateWorkbenchCommandResult,
  });
}

function codexWorkbenchResourceUri(candidate) {
  const outputSha256 = String(candidate?.manifest?.outputSha256 || "");
  if (!OUTPUT_SHA256_RE.test(outputSha256)) throw codeError("workbench_codex_output_sha256_invalid");
  // Metadata changes must also invalidate Codex's cached resource.
  const resourceSha256 = createHash("sha256")
    .update(JSON.stringify({ outputSha256, meta: CODEX_WORKBENCH_RESOURCE_META }))
    .digest("hex");
  return `ui://hellolynk/workbench-codex-${resourceSha256}.html`;
}

function supportsF3ActionGrantTransport(shared, candidate, adapter) {
  return shared.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT === "hellolynk-workbench-snapshot-v12"
    && shared.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION === 12
    && shared.HELLOLYNK_WORKBENCH_COMMAND_CONTRACT === "hellolynk-workbench-command-v6"
    && shared.HELLOLYNK_WORKBENCH_RESULT_CONTRACT === "hellolynk-workbench-command-result-v6"
    && shared.HELLOLYNK_WORKBENCH_SCHEMA_VERSION === 6
    && candidate?.manifest?.sourceContract === shared.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT
    && typeof candidate.html === "string"
    && candidate.html.includes("hellolynk_workbench_action_grant")
    && candidate.html.includes("hellolynk_workbench_command")
    && candidate.html.includes("_hellolynkUiActionGrant")
    && typeof adapter?.issueWorkbenchActionGrant === "function"
    && adapter.issueWorkbenchActionGrant.length >= 1
    && typeof adapter?.executeWorkbenchCommand === "function"
    && adapter.executeWorkbenchCommand.length >= 2;
}

export async function loadCodexWorkbenchContract() {
  const shared = await loadSharedWorkbenchModules();
  for (const name of [
    "validateWorkbenchReadRequest",
    "validateWorkbenchSnapshot",
    "validateWorkbenchCommand",
    "validateWorkbenchCommandResult",
  ]) {
    if (typeof shared[name] !== "function") {
      throw codeError("workbench_codex_shared_contract_invalid");
    }
  }
  return shared;
}

async function loadSharedWorkbenchModules() {
  if (!sharedWorkbenchModulesPromise) {
    sharedWorkbenchModulesPromise = (async () => {
      const root = await resolveSharedWorkbenchRoot();
      const [bootstrap, contract] = await Promise.all([
        import(new URL("candidate-bootstrap.mjs", root)),
        import(new URL("contract.mjs", root)),
      ]).catch(() => {
        throw codeError("workbench_codex_shared_bootstrap_invalid");
      });
      return Object.freeze({
        bootstrapWorkbenchCandidate: bootstrap.bootstrapWorkbenchCandidate,
        HELLOLYNK_WORKBENCH_COMMAND_CONTRACT: contract.HELLOLYNK_WORKBENCH_COMMAND_CONTRACT,
        HELLOLYNK_WORKBENCH_RESULT_CONTRACT: contract.HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
        HELLOLYNK_WORKBENCH_SCHEMA_VERSION: contract.HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
        HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT: contract.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
        HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION: contract.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
        HELLOLYNK_WORKBENCH_COMMAND_TYPES: contract.HELLOLYNK_WORKBENCH_COMMAND_TYPES,
        validateWorkbenchReadRequest: contract.validateWorkbenchReadRequest,
        validateWorkbenchSnapshot: contract.validateWorkbenchSnapshot,
        validateWorkbenchCommand: contract.validateWorkbenchCommand,
        validateWorkbenchCommandResult: contract.validateWorkbenchCommandResult,
      });
    })();
  }
  try {
    return await sharedWorkbenchModulesPromise;
  } catch (error) {
    sharedWorkbenchModulesPromise = null;
    throw error;
  }
}

async function resolveSharedWorkbenchRoot() {
  for (const root of SHARED_ROOTS) {
    const required = ["candidate-bootstrap.mjs", "contract.mjs"]
      .map((relative) => fileURLToPath(new URL(relative, root)));
    try {
      const metadata = await Promise.all(required.map((target) => fs.lstat(target)));
      if (metadata.every((item) => item.isFile() && !item.isSymbolicLink())) return root;
    } catch (error) {
      if (error?.code !== "ENOENT") throw codeError("workbench_codex_shared_bootstrap_invalid");
    }
  }
  throw codeError("workbench_codex_shared_bootstrap_unavailable");
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
