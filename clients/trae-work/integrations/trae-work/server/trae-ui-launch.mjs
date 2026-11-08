import { createWorkbenchAccountOpener, createWorkbenchConnection, workbenchConnectionError, isWorkbenchConnectionRequired } from "../../../runtime/core/hellolynk-workbench-connection.mjs";
import path from "node:path";
import { lstat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

let active = null;
const PACKAGED_WORKBENCH = new URL("../../../runtime/workbench/candidate-bootstrap.mjs", import.meta.url);
const SOURCE_WORKBENCH = new URL("../../../runtime/workbench/candidate-bootstrap.mjs", import.meta.url);
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;

// TRAE SOLO CN rejects user VSIX extensions in its current Solo-Lite runtime,
// but its official Browser plugin can open loopback pages inside the client.
// This launcher returns only a clean 127.0.0.1 URL. Each explicit open request
// arms one top-level browser navigation, which becomes a short HttpOnly local
// session without putting a reusable secret in MCP, the URL, or the clipboard.
export async function openTraeWorkInbox(options = {}) {
  const adapter = options.adapter;
  requireReadAdapter(adapter);
  if (typeof adapter.start === "function") await adapter.start().catch((error) => { if (!isWorkbenchConnectionRequired(error)) throw error; });
  if (active && active.adapter === adapter) {
    active.candidate.surface.armNavigation();
    return active.result;
  }
  if (active) await closeTraeWorkInbox();
  const sharedWorkbench = options.bootstrapWorkbenchCandidate
    ? injectedSharedWorkbench(options)
    : await loadSharedWorkbench();
  const workbenchAdapter = createTraeWorkbenchAdapterFacade(adapter, sharedWorkbench.contract);
  const bootstrapWorkbenchCandidate = sharedWorkbench.bootstrapWorkbenchCandidate;
  const candidate = await bootstrapWorkbenchCandidate("trae-work", {
    openAccount: options.openAccount || createWorkbenchAccountOpener(),
    connectAccount: options.connectAccount || createWorkbenchConnection({ client: "trae-work", releaseRoot: path.resolve(fileURLToPath(new URL("../../../", import.meta.url))) }),
    adapter: workbenchAdapter,
    ...(options.port == null ? {} : { port: options.port }),
    pagePath: "/inbox",
  });
  const result = Object.freeze({
    launched: true,
    cleanUrl: candidate.cleanUrl,
    status: "ready_for_browser_navigation",
  });
  active = { adapter, candidate, result };
  return result;
}

export async function closeTraeWorkInbox() {
  if (!active) return;
  const current = active; active = null;
  await current.candidate.close();
}

export function createTraeWorkbenchAdapterFacade(adapter, contract) {
  requireReadAdapter(adapter);
  const facade = {
    readSnapshot: (input) => Promise.resolve().then(() => adapter.readWorkbenchSnapshot(input)).catch((error) => { throw workbenchConnectionError(error); }),
  };
  if (typeof adapter.readWorkbenchChanges === "function") {
    facade.readChanges = (input) => adapter.readWorkbenchChanges(input);
  }
  if (supportsF3Contract(contract) && hasHostActionGrantPair(adapter)) {
    const issueWorkbenchActionGrant = adapter.issueWorkbenchActionGrant.bind(adapter);
    const executeWorkbenchCommand = adapter.executeWorkbenchCommand.bind(adapter);
    facade.issueActionGrant = async (command) => requireIssuedActionGrant(
      await issueWorkbenchActionGrant(contract.validateWorkbenchCommand(command)),
      "trae_workbench_action_grant_invalid",
    );
    facade.executeCommand = async (command, context) => {
      const validated = contract.validateWorkbenchCommand(command);
      const normalizedContext = validated.command === "message.send-status"
        ? requireEmptyContext(context, "trae_workbench_action_grant_invalid")
        : requireActionGrantContext(context, "trae_workbench_action_grant_required");
      return contract.validateWorkbenchCommandResult(
        await executeWorkbenchCommand(validated, normalizedContext),
        validated.command,
      );
    };
  }
  return Object.freeze(facade);
}

async function loadSharedWorkbench() {
  const moduleUrl = await selectWorkbenchModule();
  let loaded;
  let contract;
  try {
    [loaded, contract] = await Promise.all([
      import(moduleUrl.href),
      import(new URL("./contract.mjs", moduleUrl).href),
    ]);
  } catch {
    throw codeError("trae_shared_workbench_unavailable");
  }
  if (typeof loaded.bootstrapWorkbenchCandidate !== "function") {
    throw codeError("trae_shared_workbench_unavailable");
  }
  return Object.freeze({ bootstrapWorkbenchCandidate: loaded.bootstrapWorkbenchCandidate, contract });
}

function injectedSharedWorkbench(options) {
  if (typeof options.bootstrapWorkbenchCandidate !== "function") {
    throw codeError("trae_shared_workbench_unavailable");
  }
  return Object.freeze({
    bootstrapWorkbenchCandidate: options.bootstrapWorkbenchCandidate,
    contract: options.workbenchContract || null,
  });
}

async function selectWorkbenchModule() {
  const packaged = await regularFile(PACKAGED_WORKBENCH);
  if (packaged) return PACKAGED_WORKBENCH;
  if (await regularFile(SOURCE_WORKBENCH)) return SOURCE_WORKBENCH;
  throw codeError("trae_shared_workbench_unavailable");
}

async function regularFile(url) {
  try {
    const metadata = await lstat(fileURLToPath(url));
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw codeError("trae_shared_workbench_unavailable");
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function requireReadAdapter(adapter) {
  if (!adapter || typeof adapter.readWorkbenchSnapshot !== "function") {
    throw codeError("trae_shared_workbench_adapter_required");
  }
}

function supportsF3Contract(value) {
  return Boolean(value)
    && value.HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT === "hellolynk-workbench-snapshot-v12"
    && value.HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION === 12
    && value.HELLOLYNK_WORKBENCH_COMMAND_CONTRACT === "hellolynk-workbench-command-v6"
    && value.HELLOLYNK_WORKBENCH_RESULT_CONTRACT === "hellolynk-workbench-command-result-v6"
    && value.HELLOLYNK_WORKBENCH_SCHEMA_VERSION === 6
    && typeof value.validateWorkbenchCommand === "function"
    && typeof value.validateWorkbenchCommandResult === "function";
}

function hasHostActionGrantPair(adapter) {
  return typeof adapter.issueWorkbenchActionGrant === "function"
    && adapter.issueWorkbenchActionGrant.length >= 1
    && typeof adapter.executeWorkbenchCommand === "function"
    && adapter.executeWorkbenchCommand.length >= 2;
}

function requireActionGrantContext(value, errorCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, "actionGrant")
    || typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError(errorCode);
  }
  return value;
}

function requireEmptyContext(value, errorCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 0) {
    throw codeError(errorCode);
  }
  return value;
}

function requireIssuedActionGrant(value, errorCode) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, "actionGrant")
    || typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError(errorCode);
  }
  return value;
}

function codeError(code) { const error = new Error(code); error.code = code; return error; }
