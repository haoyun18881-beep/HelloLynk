import { randomBytes } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { applyCurrentUserAcl, defaultNeutralHostStoreRoot, withNeutralHostStoreLock } from "./hellolynk-neutral-host-installation-store.mjs";

export const ACCOUNT_CLIENTS = Object.freeze(["codex", "openclaw", "trae-work", "workbuddy", "dsh", "claude-code"]);
const GENERATION = /^[a-f0-9]{32}$/;
const INITIAL = "initial";

// Packages and account data have separate lifetimes. Existing installations
// keep their shared account until the user disconnects one particular client.
export function clientAccountBaseRoot(root = defaultNeutralHostStoreRoot()) {
  if (!path.isAbsolute(root)) throw failure("workbench_account_path_invalid");
  root = path.resolve(root);
  const generation = path.dirname(root), client = path.dirname(generation), accounts = path.dirname(client);
  if (path.basename(root) === "host" && GENERATION.test(path.basename(generation))
    && ACCOUNT_CLIENTS.includes(path.basename(client)) && path.basename(accounts) === "account-data") {
    return path.join(path.dirname(accounts), "host");
  }
  return root;
}

function statePath(client, baseRoot) {
  if (!ACCOUNT_CLIENTS.includes(client)) throw failure("workbench_account_client_invalid");
  return path.join(baseRoot, `client-account-${client}.json`);
}

export function readClientAccount(client, root = defaultNeutralHostStoreRoot()) {
  const baseRoot = clientAccountBaseRoot(root);
  const file = statePath(client, baseRoot);
  let record;
  try {
    assertPath(file);
    const stat = lstatSync(file);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 1024) throw failure("workbench_account_state_invalid");
    record = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw failure("workbench_account_state_invalid");
    return Object.freeze({ client, baseRoot, root: baseRoot, revision: INITIAL, phase: "ready", previousRevision: null });
  }
  if (record?.version !== 1 || !GENERATION.test(record.revision)
    || !["disconnecting", "ready"].includes(record.phase)
    || (record.previousRevision !== INITIAL && !GENERATION.test(record.previousRevision))
    || Object.keys(record).sort().join(",") !== "phase,previousRevision,revision,version") {
    throw failure("workbench_account_state_invalid");
  }
  return Object.freeze({ client, baseRoot, root: generationRoot(client, baseRoot, record.revision), ...record });
}

export function resolveClientAccountRoot(client, root) {
  const account = readClientAccount(client, root);
  if (account.phase !== "ready") throw failure("workbench_account_disconnect_incomplete");
  return account.root;
}

export function assertClientAccountCurrent(client, root) {
  if (!ACCOUNT_CLIENTS.includes(client)) return;
  const account = readClientAccount(client, root);
  if (account.phase !== "ready" || !samePath(root, account.root)) throw failure("workbench_account_changed");
}

export function withClientAccountLock(client, root, operation) {
  const baseRoot = clientAccountBaseRoot(root);
  statePath(client, baseRoot);
  return withNeutralHostStoreLock(baseRoot, `client-account-${client}`, operation);
}

export function createClientAccountActions(options) {
  const client = options?.client;
  const root = options?.storeRoot || defaultNeutralHostStoreRoot("win32", options?.env || process.env);
  statePath(client, clientAccountBaseRoot(root));
  const readAccountState = () => {
    const state = readClientAccount(client, root);
    return { revision: state.revision, disconnecting: state.phase === "disconnecting", canDisconnect: true };
  };
  const assertRevision = (revision) => {
    const state = readClientAccount(client, root);
    if (state.revision !== revision) throw failure("workbench_account_changed");
    if (state.phase !== "ready") throw failure("workbench_account_disconnect_incomplete");
    return state.root;
  };
  return Object.freeze({
    readAccountState, assertRevision,
    runForAccount(revision, operation) {
      return withClientAccountLock(client, root, () => operation(assertRevision(revision)));
    },
    async runSafetyVerificationForAccount(revision, operation) {
      // Only native safety verification may wait outside the account lock.
      // The Host fences its eventual write with the original attachment and
      // exact device identity; the account revision also fences its UI result.
      const pending = await withClientAccountLock(client, root, () => ({
        completion: Promise.resolve(operation(assertRevision(revision))).then(
          (value) => ({ value }), (error) => ({ error }),
        ),
      }));
      const outcome = await pending.completion;
      return withClientAccountLock(client, root, () => {
        assertRevision(revision);
        if (Object.hasOwn(outcome, "error")) throw outcome.error;
        return outcome.value;
      });
    },
    async disconnectAccount(input) {
      if (!input || Object.keys(input).join(",") !== "revision"
        || typeof input.revision !== "string" || !/^(?:initial|[a-f0-9]{32})$/.test(input.revision)) {
        throw failure("workbench_disconnect_input_invalid");
      }
      return disconnectClientAccount({ client, root, revision: input.revision }, async (previousRoot) => {
        const { createHostProtectedStore } = await import("./hellolynk-host-protected-store.mjs");
        await createHostProtectedStore({ root: previousRoot, followClientAccount: false,
          ...(options.helperPath ? { helperPath: options.helperPath } : {}),
        }).disconnectLocalClient(client);
      });
    },
  });
}

// The pending record is a durable fence: a crash while revoking the old local
// capability must never make it usable again. Retrying resumes that same fence.
export async function disconnectClientAccount({ client, root, revision }, revokePrevious) {
  return withClientAccountLock(client, root, async () => {
    let account = readClientAccount(client, root);
    if (account.phase === "ready" && account.previousRevision === revision) {
      return { disconnected: true, revision: account.revision };
    }
    if (revision !== account.revision && !(account.phase === "disconnecting" && revision === account.previousRevision)) {
      throw failure("workbench_account_changed");
    }
    if (account.phase === "ready") {
      await save(client, account.baseRoot, {
        version: 1, revision: randomBytes(16).toString("hex"), previousRevision: account.revision, phase: "disconnecting",
      });
      account = readClientAccount(client, root);
    }
    const previousRoot = generationRoot(client, account.baseRoot, account.previousRevision);
    await revokePrevious(previousRoot);
    await save(client, account.baseRoot, {
      version: 1, revision: account.revision, previousRevision: account.previousRevision, phase: "ready",
    });
    return { disconnected: true, revision: account.revision };
  });
}

function generationRoot(client, baseRoot, revision) {
  return revision === INITIAL ? baseRoot : path.join(path.dirname(baseRoot), "account-data", client, revision, "host");
}

async function save(client, root, record) {
  const file = statePath(client, root);
  assertPath(root);
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString("hex")}`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(record)}\n`);
    await handle.sync();
    await handle.close(); handle = null;
    await fs.chmod(temporary, 0o600);
    await applyCurrentUserAcl(temporary, false);
    await fs.rename(temporary, file);
  } finally {
    await handle?.close();
    await fs.unlink(temporary).catch((error) => { if (error.code !== "ENOENT") throw error; });
  }
}

function assertPath(file) {
  let cursor = path.resolve(file);
  while (cursor !== path.dirname(cursor)) {
    try { if (lstatSync(cursor).isSymbolicLink()) throw failure("workbench_account_path_invalid"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    cursor = path.dirname(cursor);
  }
}
function samePath(a, b) {
  const normalize = (v) => process.platform === "win32" ? path.resolve(v).toLowerCase() : path.resolve(v);
  return normalize(a) === normalize(b);
}
function failure(code) { return Object.assign(new Error(code), { code, status: 409 }); }
