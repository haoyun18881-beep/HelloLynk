import { createWorkbenchAccountOpener, createWorkbenchConnection, workbenchConnectionError, isWorkbenchConnectionRequired } from "../../../clients/core/hellolynk-workbench-connection.mjs";
import path from "node:path";
import { lstat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

let active = null;
const PACKAGED_WORKBENCH = new URL("../../../runtime/workbench/candidate-bootstrap.mjs", import.meta.url);
const SOURCE_WORKBENCH = new URL("../../../clients/workbench/candidate-bootstrap.mjs", import.meta.url);
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;

export async function bootstrapWorkBuddyWorkbenchCandidate(options = {}) {
  const sharedWorkbench = options.bootstrapWorkbenchCandidate
    ? injectedSharedWorkbench(options)
    : await loadSharedWorkbench();
  const {
    bootstrapWorkbenchCandidate: _ignored,
    workbenchContract: _ignoredContract,
    adapter,
    ...candidateOptions
  } = options;
  requireReadAdapter(adapter);
  if (typeof adapter.start === "function") await adapter.start().catch((error) => { if (!isWorkbenchConnectionRequired(error)) throw error; });
  return sharedWorkbench.bootstrapWorkbenchCandidate("workbuddy", {
    openAccount: options.openAccount || createWorkbenchAccountOpener(),
    connectAccount: options.connectAccount || createWorkbenchConnection({ client: "workbuddy", releaseRoot: path.resolve(fileURLToPath(new URL("../../../", import.meta.url))) }),
    ...candidateOptions,
    adapter: createWorkBuddyWorkbenchAdapterFacade(adapter, sharedWorkbench.contract),
  });
}

export async function launchWorkBuddyWorkbench(options = {}) {
  const adapter = options.adapter;
  requireReadAdapter(adapter);
  if (typeof adapter.start === "function") await adapter.start().catch((error) => { if (!isWorkbenchConnectionRequired(error)) throw error; });
  if (active && active.adapter === adapter) {
    active.candidate.surface.armNavigation();
    return active.result;
  }
  if (active) await closeWorkBuddyWorkbench();
  const sharedWorkbench = options.bootstrapWorkbenchCandidate
    ? injectedSharedWorkbench(options)
    : await loadSharedWorkbench();
  const workbenchAdapter = createWorkBuddyWorkbenchAdapterFacade(adapter, sharedWorkbench.contract);
  const candidate = await sharedWorkbench.bootstrapWorkbenchCandidate("workbuddy", {
    openAccount: options.openAccount || createWorkbenchAccountOpener(),
    connectAccount: options.connectAccount || createWorkbenchConnection({ client: "workbuddy", releaseRoot: path.resolve(fileURLToPath(new URL("../../../", import.meta.url))) }),
    adapter: workbenchAdapter,
    ...(options.port == null ? {} : { port: options.port }),
    pagePath: "/inbox",
  });
  const result = Object.freeze({
    ok: true,
    host: candidate.surface,
    cleanUrl: candidate.cleanUrl,
    status: "ready_for_browser_navigation",
  });
  active = { adapter, candidate, result };
  return result;
}

export async function closeWorkBuddyWorkbench() {
  if (!active) return;
  const current = active;
  active = null;
  await current.candidate.close();
}

export function createWorkBuddyWorkbenchAdapterFacade(adapter, contract) {
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
      "workbuddy_workbench_action_grant_invalid",
    );
    facade.executeCommand = async (command, context) => {
      const validated = contract.validateWorkbenchCommand(command);
      const normalizedContext = validated.command === "message.send-status"
        ? requireEmptyContext(context, "workbuddy_workbench_action_grant_invalid")
        : requireActionGrantContext(context, "workbuddy_workbench_action_grant_required");
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
    throw codeError("workbuddy_shared_workbench_unavailable");
  }
  if (typeof loaded.bootstrapWorkbenchCandidate !== "function") {
    throw codeError("workbuddy_shared_workbench_unavailable");
  }
  return Object.freeze({ bootstrapWorkbenchCandidate: loaded.bootstrapWorkbenchCandidate, contract });
}

function injectedSharedWorkbench(options) {
  if (typeof options.bootstrapWorkbenchCandidate !== "function") {
    throw codeError("workbuddy_shared_workbench_unavailable");
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
  throw codeError("workbuddy_shared_workbench_unavailable");
}

async function regularFile(url) {
  try {
    const metadata = await lstat(fileURLToPath(url));
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw codeError("workbuddy_shared_workbench_unavailable");
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function requireReadAdapter(adapter) {
  if (!adapter || typeof adapter.readWorkbenchSnapshot !== "function") {
    throw codeError("workbuddy_shared_workbench_adapter_required");
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

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
