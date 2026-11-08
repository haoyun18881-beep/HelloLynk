import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { withHelloLynkLocalMutationLock } from "../../../clients/core/hellolynk-local-messaging.mjs";
import { defaultNeutralHostStoreRoot } from "../../../clients/core/hellolynk-neutral-host-installation-store.mjs";
import { loadPinnedWorkBuddyProxy } from "./package-bootstrap.mjs";
import { workBuddyMcpExpectedConfig } from "./native-task-mcp-registration.mjs";

const failure = code => Object.assign(new Error(code), { code });
const sameRelease = (left, right) => left.root.toLowerCase() === path.resolve(right.root).toLowerCase() && left.expectedManifestSha256 === right.expectedManifestSha256;

// This record only identifies an explicitly installed, on-demand native task.
// The same short lock covers record changes and Verify/Start, so Uninstall can
// withdraw the record before stopping the task without a late MCP restarting it.
export async function withWorkBuddyNativeServiceRecord(storeRoot, operation) {
  const configured = storeRoot || defaultNeutralHostStoreRoot();
  if (!path.isAbsolute(configured)) throw failure("workbuddy_native_service_record_invalid");
  const directory = path.resolve(configured);
  const filename = path.join(directory, "workbuddy-native-service.json");
  try { await safeParents(directory); }
  catch (error) { if (error.code === "ENOENT") return operation(null); throw error; }
  const write = async record => {
    const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify(record), { flag: "wx", mode: 0o600 });
      await fs.rename(temporary, filename);
    } finally { await fs.rm(temporary, { force: true }); }
  };
  return withHelloLynkLocalMutationLock(filename, async () => operation({
    async read() {
      try {
        const stat = await fs.lstat(filename);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 8192) throw failure("workbuddy_native_service_record_invalid");
        const record = JSON.parse(await fs.readFile(filename, "utf8"));
        validate(record);
        return record;
      } catch (error) { if (error.code === "ENOENT") return null; throw error; }
    },
    async save(options, taskName) {
      const record = { version: 1, root: path.resolve(options.root), expectedManifestSha256: options.expectedManifestSha256,
        nodePath: options.nodePath || process.execPath, debugEndpoint: new URL(options.debugEndpoint).origin, taskName,
        ...(options.pendingMcpTrust ? { pendingMcpTrust: { command: options.pendingMcpTrust.command } } : {}) };
      validate(record);
      await safeParents(record.root);
      await loadPinnedWorkBuddyProxy(record);
      await write(record);
    },
    // Same release and task; only the trust request is dropped.
    async clearMcpTrustRequest(record) {
      const { pendingMcpTrust, ...kept } = record;
      validate(kept);
      await write(kept);
    },
    async removeOwned(options) {
      const record = await this.read();
      if (record && sameRelease(record, options)) await fs.rm(filename);
    },
    storeRoot: directory,
  }));
}

export async function startRecordedWorkBuddyNativeService({ storeRoot, loadProxy = loadPinnedWorkBuddyProxy } = {}) {
  return withWorkBuddyNativeServiceRecord(storeRoot, async registry => {
    const record = await registry?.read();
    if (!record) return { configured: false, status: "not_installed" };
    await safeParents(record.root);
    const node = await fs.lstat(record.nodePath);
    if (!node.isFile() || node.isSymbolicLink()) throw failure("workbuddy_native_service_record_invalid");
    const proxy = await loadProxy(record);
    if (typeof proxy.configureWorkBuddyNativeTaskService !== "function") throw failure("workbuddy_native_service_entry_unavailable");
    const options = { ...record, storeRoot: registry.storeRoot };
    const verified = await proxy.configureWorkBuddyNativeTaskService(options, "Verify");
    if (verified?.ok !== true || verified.taskName !== record.taskName) throw failure("workbuddy_native_service_record_mismatch");
    const started = await proxy.configureWorkBuddyNativeTaskService(options, "Start");
    if (started?.ok !== true || started.taskName !== record.taskName) throw failure("workbuddy_native_service_record_mismatch");
    // This is a Scheduler handoff, never a child process owned by the MCP Job.
    return { configured: true, status: "service_started" };
  });
}

// A package update changes the MCP command, so WorkBuddy asks for trust
// again. The update leaves one request in the record; the service of that
// same release approves exactly that configuration once, then clears it.
// Approval runs outside the lock: connecting starts an MCP that takes it.
export function workBuddyMcpTrustRequests(release) {
  const pending = (record) => record?.pendingMcpTrust && sameRelease(record, release) ? record : null;
  return Object.freeze({
    take: () => withWorkBuddyNativeServiceRecord(release.storeRoot, async registry => {
      const record = pending(await registry?.read());
      return record && workBuddyMcpExpectedConfig({ command: record.pendingMcpTrust.command, releaseRoot: record.root,
        expectedManifestSha256: record.expectedManifestSha256, storeRoot: registry.storeRoot });
    }),
    settle: () => withWorkBuddyNativeServiceRecord(release.storeRoot, async registry => {
      const record = pending(await registry?.read());
      if (record) await registry.clearMcpTrustRequest(record);
    }),
  });
}

function validate(record) {
  const trust = record?.pendingMcpTrust;
  if (trust !== undefined && (!trust || typeof trust !== "object" || Object.keys(trust).join() !== "command" || !path.isAbsolute(trust.command || "") || !/^node(?:\.exe)?$/i.test(path.basename(trust.command)))) throw failure("workbuddy_native_service_record_invalid");
  if (record?.version !== 1|| !path.isAbsolute(record.root || "") || path.resolve(record.root) !== record.root || !/^[a-f0-9]{64}$/.test(record.expectedManifestSha256 || "") || !path.isAbsolute(record.nodePath || "") || !/^node(?:\.exe)?$/i.test(path.basename(record.nodePath)) || !/^HelloLynk WorkBuddy Native - [A-F0-9]{20} - [A-F0-9]{16}$/.test(record.taskName || "")) throw failure("workbuddy_native_service_record_invalid");
  const endpoint = new URL(record.debugEndpoint);
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password || endpoint.origin !== record.debugEndpoint) throw failure("workbuddy_native_service_record_invalid");
}
async function safeParents(target) {
  const root = path.parse(target).root;
  let current = root;
  for (const part of path.relative(root, target).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await fs.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure("workbuddy_native_service_record_invalid");
  }
}
