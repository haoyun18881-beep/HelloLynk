import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { withHelloLynkLocalMutationLock } from "../../../clients/core/hellolynk-local-messaging.mjs";

const exec = promisify(execFile);
const failure = code => Object.assign(new Error(code), { code });

// Transfer only our existing restore receipt. Never recreate or change the
// user's environment variable during a normal package update.
export async function transferWorkBuddyDebugStartupOwner({ storeRoot, previousInstallationId, installationId }) {
  if (!path.isAbsolute(storeRoot || "") || ![previousInstallationId, installationId].every(value => /^[a-f0-9]{64}$/.test(value || ""))) throw failure("workbuddy_native_debug_startup_invalid");
  await assertSafeParents(storeRoot);
  const filename = path.join(storeRoot, "workbuddy-native-debug-startup.json");
  return withHelloLynkLocalMutationLock(filename, async () => {
    const state = await readState(filename);
    if (!state) return;
    if (state.phase !== "applied") throw failure("workbuddy_native_debug_startup_outcome_uncertain");
    if (state.owner === installationId) return;
    if (state.owner !== previousInstallationId) throw failure("workbuddy_native_debug_startup_conflict");
    await writeState(filename, { ...state, owner: installationId });
  });
}

// The vendor reads this user environment variable on normal cold startup.
// No shortcut, vendor file, current window or login trigger is changed.
export async function configureWorkBuddyDebugStartup({ storeRoot, debugEndpoint, installationId, enableDebugStartup = false, environment = windowsEnvironment } = {}, operation = "Install") {
  if (!["Install", "Uninstall"].includes(operation)) return { status: "unchanged" };
  if (operation === "Install" && enableDebugStartup !== true) return { status: "not_selected" };
  const endpoint = new URL(debugEndpoint || "http://127.0.0.1:9337");
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password || !path.isAbsolute(storeRoot || "") || !/^[a-f0-9]{64}$/.test(installationId || "")) throw failure("workbuddy_native_debug_startup_invalid");
  const filename = path.join(storeRoot, "workbuddy-native-debug-startup.json");
  await assertSafeParents(storeRoot);
  return withHelloLynkLocalMutationLock(filename, async () => {
    const state = await readState(filename);
    if (operation === "Uninstall" && (!state || state.owner !== installationId)) return { status: "not_owned" };
    const current = await environment.read();
    if (operation === "Install") {
      // First installation reuses a user-selected local port. Explicit callers
      // still require their requested endpoint and never silently switch it.
      if (!debugEndpoint && current !== null) {
        if (!/^[1-9]\d{0,4}$/.test(current) || Number(current) > 65535) throw failure("workbuddy_native_debug_startup_conflict");
        endpoint.port = current;
        if (!endpoint.port) throw failure("workbuddy_native_debug_startup_conflict");
      }
      if (state && state.applied !== endpoint.port || current !== null && current !== endpoint.port) throw failure("workbuddy_native_debug_startup_conflict");
      if (current === endpoint.port) {
        if (state?.phase === "preparing") throw failure("workbuddy_native_debug_startup_outcome_uncertain");
        // The replacement release takes over the existing original-value record.
        if (state && state.owner !== installationId) await writeState(filename, { ...state, owner: installationId });
        return { status: state ? "enabled" : "already_configured", debugEndpoint: endpoint.origin, coldStartRequired: true };
      }
      const next = { version: 1, variable: "WORKBUDDY_REMOTE_DEBUGGING_PORT", previous: null, applied: endpoint.port, owner: installationId, phase: "preparing" };
      await writeState(filename, next);
      const result = await environment.compareExchange(null, endpoint.port);
      if (!result.exchanged) {
        await fs.rm(filename);
        throw failure("workbuddy_native_debug_startup_conflict");
      }
      await writeState(filename, { ...next, phase: "applied" });
      return { status: "enabled", debugEndpoint: endpoint.origin, coldStartRequired: true, broadcastDelivered: result.broadcastDelivered };
    }
    if (state.phase !== "applied") return { status: "unconfirmed_not_restored" };
    if (current !== state.applied) {
      await fs.rm(filename);
      return { status: "preserved_user_change" };
    }
    const result = await environment.compareExchange(state.applied, state.previous);
    await fs.rm(filename);
    return { status: result.exchanged ? "restored" : "preserved_user_change", broadcastDelivered: result.broadcastDelivered };
  });
}

const windowsEnvironment = {
  async read() { return (await callWindows("Read")).value; },
  async compareExchange(expected, value) { return callWindows("CompareExchange", expected, value); },
};
async function callWindows(operation, expected, value) {
  if (process.platform !== "win32") throw failure("workbuddy_native_debug_startup_windows_required");
  try {
    const args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      fileURLToPath(new URL("./native-task-debug-startup.ps1", import.meta.url)), "-Operation", operation];
    if (operation === "CompareExchange") args.push("-Expected", expected ?? "absent", "-Value", value ?? "absent");
    const { stdout } = await exec("powershell.exe", args, { windowsHide: true, timeout: 15_000, maxBuffer: 4096 });
    const result = JSON.parse(stdout);
    if (result?.ok !== true || operation === "Read" && result.value !== null && typeof result.value !== "string" || operation === "CompareExchange" && typeof result.exchanged !== "boolean") throw failure("workbuddy_native_debug_startup_failed");
    return result;
  } catch { throw failure("workbuddy_native_debug_startup_failed"); }
}
async function assertSafeParents(target) {
  const root = path.parse(path.resolve(target)).root;
  let current = root;
  for (const part of path.relative(root, path.resolve(target)).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await fs.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure("workbuddy_native_debug_startup_state_invalid");
  }
}
async function readState(filename) {
  try {
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 2048) throw failure("workbuddy_native_debug_startup_state_invalid");
    const state = JSON.parse(await fs.readFile(filename, "utf8"));
    if (state?.version !== 1 || state.variable !== "WORKBUDDY_REMOTE_DEBUGGING_PORT" || state.previous !== null || !/^[a-f0-9]{64}$/.test(state.owner || "") || !["preparing", "applied"].includes(state.phase) || !/^\d{1,5}$/.test(state.applied) || Number(state.applied) < 1 || Number(state.applied) > 65535) throw failure("workbuddy_native_debug_startup_state_invalid");
    return state;
  } catch (error) { if (error.code === "ENOENT") return null; throw error; }
}
async function writeState(filename, state) {
  const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify(state), { flag: "wx", mode: 0o600 });
    await fs.rename(temporary, filename);
  } finally { await fs.rm(temporary, { force: true }); }
}
