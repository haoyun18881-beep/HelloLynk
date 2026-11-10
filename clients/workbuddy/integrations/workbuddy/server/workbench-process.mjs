import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import runtimeSafety from "../../../clients/core/hellolynk-runtime-safety.cjs";
import { applyCurrentUserAcl, defaultNeutralHostStoreRoot } from "../../../clients/core/hellolynk-neutral-host-installation-store.mjs";
import { bootstrapWorkBuddyWorkbenchCandidate } from "./workbench-candidate.mjs";
import { registerWorkBuddyNativeMcp } from "./native-task-mcp-registration.mjs";
import { configureWorkBuddyDebugStartup, transferWorkBuddyDebugStartupOwner } from "./native-task-debug-startup.mjs";
import { withWorkBuddyNativeServiceRecord } from "./native-task-service-registration.mjs";
import { removeWorkBuddyOriginHook, workBuddyOriginHookCommand, workBuddyOriginInbox } from "./origin-routes.mjs";
import { loadPinnedWorkBuddyProxy } from "./package-bootstrap.mjs";

const exec = promisify(execFile);
const STARTUP_TIMEOUT_MS = 90_000;

// WorkBuddy may replace its conversation worker after a normal turn. Windows
// uses the installed on-demand page service; other platforms use a detached
// handoff. Both run only the pinned package.
export async function launchDetachedWorkBuddyWorkbench(options) {
  const args = bootstrapArgs("handoff-workbench", options);
  if ((options.platform || process.platform) === "win32") return launchScheduledWorkbench(options);
  const executable = await runtimeSafety.resolveHelloLynkStandaloneNode({ preferredExecutable: options.nodePath });
  let stdout;
  try {
    ({ stdout } = await (options.exec || exec)(executable, args, {
      cwd: options.root,
      env: runtimeSafety.standaloneHelloLynkNodeEnvironment(process.env),
      windowsHide: true,
      timeout: STARTUP_TIMEOUT_MS + 5_000,
      maxBuffer: 4096,
    }));
  } catch (error) {
    // Only bounded, known diagnostic codes cross the subprocess boundary.
    // Never return the command line, stderr or native exception to the client.
    if (error?.killed === true && error?.signal === "SIGTERM"
      && error?.code !== "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
      throw failure("workbuddy_local_web_launch_timeout");
    }
    let reported;
    try { reported = JSON.parse(String(error?.stderr || "").slice(0, 4096)); } catch {}
    const known = ["workbuddy_local_web_launch_timeout", "workbuddy_local_web_launch_failed",
      "workbuddy_local_web_launch_invalid", "workbuddy_local_web_launch_handoff_missing"];
    throw failure(reported?.ok === false && known.includes(reported.error)
      ? reported.error : "workbuddy_local_web_launch_failed");
  }
  try { return validateReady(JSON.parse(stdout)); }
  catch { throw failure("workbuddy_local_web_launch_invalid"); }
}

// Installed once by setup. The on-demand task owns the page, so a client's
// Windows Job cleanup cannot terminate an active browser session.
export async function configureWorkBuddyWorkbenchTask(options, operation = "Install") {
  bootstrapArgs("workbench-service", options);
  if (!["Install", "Verify", "Start", "Uninstall"].includes(operation)) throw failure("workbuddy_page_task_operation_invalid");
  try {
    const driverRoot = operation === "Verify" ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..") : options.root;
    const { stdout } = await exec("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      path.join(driverRoot, "integrations/workbuddy/server/workbench-task.ps1"),
      "-Command", operation, "-Root", options.root, "-Manifest", options.expectedManifestSha256,
      "-DriverRoot", driverRoot,
      "-NodePath", options.nodePath || process.execPath,
      "-StoreRoot", options.storeRoot || defaultNeutralHostStoreRoot()], {
      windowsHide: true, timeout: 30_000, maxBuffer: 4096,
      env: runtimeSafety.sanitizeHelloLynkChildEnvironment(process.env),
    });
    const result = JSON.parse(stdout);
    if (result?.ok !== true) throw failure("workbuddy_page_task_failed");
    return result;
  } catch (error) {
    const code = String(error?.stderr || "").trim();
    throw failure(/^workbuddy_[a-z_]+$/.test(code) ? code : "workbuddy_page_task_failed");
  }
}

// Uses the same installed, hidden launcher and pinned verifier as the page
// service, with a separate task identity and explicit loopback CDP opt-in.
export async function configureWorkBuddyNativeTaskService(options, operation = "Install") {
  if (!["Install", "Uninstall"].includes(operation)) return configureNativeTaskService(options, operation);
  bootstrapArgs("native-task-service", options);
  const endpoint = new URL(options.debugEndpoint || "");
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password) throw failure("workbuddy_native_debug_endpoint_invalid");
  // MCP connection can initialize a new proxy which reads the service record.
  // Complete that handshake before taking the record/Start lock.
  const debugStartup = operation === "Install" ? await prepareNativeTaskServiceInstall(options, endpoint) : undefined;
  return withWorkBuddyNativeServiceRecord(options.storeRoot, async registry => {
    if (!registry && operation === "Install") throw failure("workbuddy_native_service_store_missing");
    // Withdraw before stopping, under the same lock used by MCP Verify/Start.
    if (operation === "Uninstall") await registry?.removeOwned(options);
    const result = await configureNativeTaskService(options, operation, debugStartup);
    if (operation === "Install") await registry.save(options, result.taskName);
    // Without the service nobody imports hook records; leave WorkBuddy's
    // other hooks and settings untouched.
    if (operation === "Uninstall") result.originHook = await removeWorkBuddyOriginHook({ settingsPath: options.workBuddySettingsPath,
      command: workBuddyOriginHookCommand({ nodePath: options.nodePath || process.execPath,
        hookPath: path.join(options.root, "integrations/workbuddy/server/origin-hook.mjs"),
        inbox: workBuddyOriginInbox(options.storeRoot || defaultNeutralHostStoreRoot()) }) })
      .catch(() => ({ changed: false, status: "unavailable" }));
    return result;
  });
}

// An ordinary package upgrade must carry forward an existing listener even
// while WorkBuddy is closed. First customer install explicitly enables it. The
// new release's MCP command needs WorkBuddy's trust again: leave one request,
// which that release's own service approves once WorkBuddy is open.
export async function updateRecordedWorkBuddyNativeTaskService(options, operation = "Install") {
  if (!["Install", "Verify"].includes(operation)) throw failure("workbuddy_page_task_operation_invalid");
  let pendingService = null;
  const updated = await withWorkBuddyNativeServiceRecord(options.storeRoot, async registry => {
    const record = await registry?.read();
    if (!record) {
      if (operation !== "Install" || options.installIfMissing !== true) return { configured: false, status: "not_installed" };
      if (!registry) throw failure("workbuddy_native_service_store_missing");
      const target = { ...options, nodePath: options.nodePath || process.execPath };
      await loadPinnedWorkBuddyProxy(target);
      const startupOptions = { storeRoot: registry.storeRoot, debugEndpoint: target.debugEndpoint,
        installationId: nativeDebugStartupOwner(target), enableDebugStartup: true,
        ...(options.debugStartupEnvironment ? { environment: options.debugStartupEnvironment } : {}) };
      const debugStartup = await configureWorkBuddyDebugStartup(startupOptions, "Install");
      target.debugEndpoint = debugStartup.debugEndpoint;
      try {
        const result = await configureNativeTaskService(target, "Install", debugStartup);
        // Trust is completed by this receiver after the client reopens. Setup
        // does not require or attach to a running WorkBuddy window.
        await registry.save({ ...target, pendingMcpTrust: { command: target.nodePath } }, result.taskName);
        pendingService = target;
        return { ...result, configured: true, restartRequired: true };
      } catch (error) {
        let rollbackError;
        // Each cleanup is independent: a Scheduler failure must not leave our
        // newly enabled startup setting behind. Preserve any user change.
        for (const undo of [() => registry.removeOwned(target),
          () => configureNativeTaskService({ ...target, debugStartupEnvironment: options.debugStartupEnvironment }, "Uninstall"),
          () => configureWorkBuddyDebugStartup(startupOptions, "Uninstall")]) {
          try { await undo(); } catch (cause) { rollbackError ||= cause; }
        }
        if (rollbackError) {
          throw Object.assign(failure("local_configuration_outcome_uncertain"), { cause: rollbackError, configurationCause: error });
        }
        throw error;
      }
    }
    const target = { ...options, nodePath: record.nodePath, debugEndpoint: record.debugEndpoint };
    const sameRelease = path.resolve(record.root).toLowerCase() === path.resolve(target.root).toLowerCase()
      && record.expectedManifestSha256 === target.expectedManifestSha256;
    if (operation === "Verify" && !sameRelease) throw failure("workbuddy_native_service_record_mismatch");
    await loadPinnedWorkBuddyProxy(target);
    const result = await configureNativeTaskService(target, operation);
    if (operation === "Install") {
      await transferWorkBuddyDebugStartupOwner({ storeRoot: registry.storeRoot,
        previousInstallationId: nativeDebugStartupOwner(record), installationId: nativeDebugStartupOwner(target) });
      // The installer wrote mcp.json with this process's node.
      const pendingMcpTrust = sameRelease ? record.pendingMcpTrust : { command: process.execPath };
      await registry.save({ ...target, pendingMcpTrust }, result.taskName);
      if (pendingMcpTrust) pendingService = target;
    }
    return { ...result, configured: true };
  });
  // After the lock: the MCP that approval connects takes it to Verify/Start.
  if (pendingService) updated.serviceStarted = await (options.startNativeService || (target => configureNativeTaskService(target, "Start")))(pendingService)
    .then(() => true, () => false);
  return updated;
}

async function prepareNativeTaskServiceInstall(options, endpoint) {
  // Explicit opt-in only. Persist ownership before configuring the task so a
  // later repair/uninstall can recover a partially completed installation.
  const debugStartup = await configureWorkBuddyDebugStartup({
    storeRoot: options.storeRoot || defaultNeutralHostStoreRoot(), debugEndpoint: endpoint.origin,
    installationId: nativeDebugStartupOwner(options),
    enableDebugStartup: options.enableDebugStartup === true,
  }, "Install");
  await registerWorkBuddyNativeMcp({
    debugEndpoint: endpoint.origin,
    command: options.nodePath || process.execPath,
    releaseRoot: options.mcpRegistration?.releaseRoot || options.root,
    expectedManifestSha256: options.mcpRegistration?.expectedManifestSha256 || options.expectedManifestSha256,
    storeRoot: options.storeRoot || defaultNeutralHostStoreRoot(),
  });
  return debugStartup;
}

async function configureNativeTaskService(options, operation, debugStartup) {
  bootstrapArgs("native-task-service", options);
  const endpoint = new URL(options.debugEndpoint || "");
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password) throw failure("workbuddy_native_debug_endpoint_invalid");
  if (!["Install", "Verify", "Start", "Uninstall"].includes(operation)) throw failure("workbuddy_page_task_operation_invalid");
  try {
    const { stdout } = await exec("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
      path.join(options.root, "integrations/workbuddy/server/workbench-task.ps1"), "-Command", operation,
      "-Root", options.root, "-Manifest", options.expectedManifestSha256, "-NodePath", options.nodePath || process.execPath,
      "-StoreRoot", options.storeRoot || defaultNeutralHostStoreRoot(), "-Mode", "native-task-service", "-DebugEndpoint", endpoint.origin], {
      windowsHide: true, timeout: 30_000, maxBuffer: 4096, env: runtimeSafety.sanitizeHelloLynkChildEnvironment(process.env),
    });
    const result = JSON.parse(stdout); if (result?.ok !== true) throw failure("workbuddy_page_task_failed");
    if (operation === "Uninstall") result.debugStartup = await configureWorkBuddyDebugStartup({
      storeRoot: options.storeRoot || defaultNeutralHostStoreRoot(), debugEndpoint: endpoint.origin,
      installationId: nativeDebugStartupOwner(options),
      ...(options.debugStartupEnvironment ? { environment: options.debugStartupEnvironment } : {}),
    }, operation);
    else if (debugStartup) result.debugStartup = debugStartup;
    return result;
  } catch { throw failure("workbuddy_native_service_configuration_failed"); }
}

function nativeDebugStartupOwner(options) {
  return crypto.createHash("sha256").update(`${path.resolve(options.root).toLowerCase()}|${options.expectedManifestSha256}`).digest("hex");
}

function controlPipe(options) {
  const key = crypto.createHash("sha256").update(`${options.root.toLowerCase()}|${options.expectedManifestSha256}`).digest("hex");
  return `\\\\.\\pipe\\hellolynk-workbuddy-${key}`;
}

// The service creates the key before listening, so a missing key means no
// service yet: ENOENT keeps the existing start-and-poll path.
async function readPageKey(options) {
  const filename = pageKeyFile(options);
  let value;
  try {
    const metadata = await fs.lstat(filename);
    if (!metadata.isFile() || metadata.size > 256) throw failure("workbuddy_page_service_key_invalid");
    value = JSON.parse(await fs.readFile(filename, "utf8"));
  } catch (error) { throw error?.code === "ENOENT" ? error : failure("workbuddy_page_service_key_invalid"); }
  if (!/^[A-Za-z0-9_-]{43}$/.test(value?.key || "")) throw failure("workbuddy_page_service_key_invalid");
  return value.key;
}

// The pipe admits every local caller, so this file's ACL is the boundary: one
// key per user store, readable only by this user, shared by every release and
// never replaced. The empty file is limited to this user before the key is
// written; the link fails if another service created the key first, and both
// then use that one. The installed store root must already exist.
async function ensurePageKey(options) {
  const filename = pageKeyFile(options);
  for (let attempt = 0; ; attempt += 1) {
    try { return await readPageKey(options); }
    catch (error) { if (error?.code !== "ENOENT" || attempt) throw error; }
    const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
    try {
      await (await fs.open(temporary, "wx", 0o600)).close();
      await applyCurrentUserAcl(temporary, false);
      await fs.writeFile(temporary, JSON.stringify({ key: crypto.randomBytes(32).toString("base64url") }), { flag: "r+" });
      await fs.link(temporary, filename).catch((error) => { if (error?.code !== "EEXIST") throw error; });
    } finally { await fs.rm(temporary, { force: true }); }
  }
}

function pageKeyFile(options) {
  return path.join(options.storeRoot || defaultNeutralHostStoreRoot(), "workbuddy-page-key.json");
}

async function requestExistingWorkbench(options) {
  const key = await readPageKey(options);
  return new Promise((resolve, reject) => {
    const socket = net.connect(controlPipe(options));
    let text = "";
    socket.setTimeout(3000, () => socket.destroy(failure("workbuddy_page_service_timeout")));
    // Only "no service yet" may start the task; any other refusal is reported.
    socket.on("error", (error) => reject(["ENOENT", "ECONNREFUSED"].includes(error?.code) || /^workbuddy_/.test(error?.code || "")
      ? error : failure("workbuddy_page_service_unreachable")));
    socket.on("connect", () => socket.write(`open ${key}\n`));
    socket.on("data", (chunk) => {
      text += chunk.toString("utf8");
      if (text.length > 4096) socket.destroy(failure("workbuddy_local_web_launch_invalid"));
    });
    socket.on("end", () => {
      try { resolve(validateReady(JSON.parse(text))); }
      catch { reject(failure("workbuddy_local_web_launch_invalid")); }
    });
  });
}

async function launchScheduledWorkbench(options) {
  try { return await requestExistingWorkbench(options); }
  catch (error) { if (!["ENOENT", "ECONNREFUSED"].includes(error?.code)) throw error; }
  await configureWorkBuddyWorkbenchTask(options, "Start");
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  do {
    await delay(200);
    try { return await requestExistingWorkbench(options); }
    catch (error) { if (!["ENOENT", "ECONNREFUSED"].includes(error?.code)) throw error; }
  } while (Date.now() < deadline);
  throw failure("workbuddy_local_web_launch_timeout");
}

export async function serveWorkBuddyWorkbenchService(options) {
  let server;
  const sockets = new Set();
  try {
    const request = Buffer.from(`open ${await ensurePageKey(options)}\n`);
    await serveWorkBuddyWorkbench({ ...options, async publishReady(value, surface) {
      server = net.createServer((socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
        socket.on("error", () => {});
        socket.setTimeout(3000, () => socket.destroy());
        let received = Buffer.alloc(0);
        socket.on("data", (chunk) => {
          received = Buffer.concat([received, chunk]);
          if (received.length < request.length && !received.includes(0x0a)) return;
          if (received.length === request.length && crypto.timingSafeEqual(received, request)) {
            surface.armNavigation(); socket.end(`${JSON.stringify(validateReady(value))}\n`);
          } else socket.destroy();
        });
      });
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        // Task Scheduler can run this service with the full token of a built-in
        // Administrator while WorkBuddy runs unelevated; the default pipe ACL
        // would then refuse WorkBuddy. Any local caller may connect, and only
        // one that can read this user's page key gets the page.
        server.listen({ path: controlPipe(options), readableAll: true, writableAll: true },
          () => { server.off("error", reject); resolve(); });
      });
    } });
  } finally {
    for (const socket of sockets) socket.destroy();
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
  }
}

export async function handoffWorkBuddyWorkbench(options) {
  const executable = await runtimeSafety.resolveHelloLynkStandaloneNode();
  const child = spawn(executable, bootstrapArgs("workbench", options), {
    cwd: options.root,
    env: runtimeSafety.standaloneHelloLynkNodeEnvironment(process.env),
    detached: true,
    windowsHide: true,
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  try {
    const ready = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => done(failure("workbuddy_local_web_launch_timeout")), STARTUP_TIMEOUT_MS);
      const failed = () => done(failure("workbuddy_local_web_launch_failed"));
      const message = (value) => {
        try { done(null, validateReady(value)); }
        catch { failed(); }
      };
      const done = (error, value) => {
        clearTimeout(timer);
        child.off("message", message);
        child.off("error", failed);
        child.off("exit", failed);
        if (error) reject(error); else resolve(value);
      };
      child.once("error", failed);
      child.once("exit", failed);
      child.once("message", message);
    });
    child.disconnect();
    child.unref();
    return ready;
  } catch (error) {
    child.kill();
    throw error;
  }
}

export async function serveWorkBuddyWorkbench(options) {
  const { adapter, signal, publishReady = sendReady } = options;
  let page;
  try {
    page = await bootstrapWorkBuddyWorkbenchCandidate({
      adapter, pagePath: "/inbox",
      ...(options.bootstrapWorkbenchCandidate ? {
        bootstrapWorkbenchCandidate: options.bootstrapWorkbenchCandidate,
        workbenchContract: options.workbenchContract,
      } : {}),
    });
    if (signal?.aborted) return;
    await publishReady({ cleanUrl: page.cleanUrl }, page.surface);
    while (!signal?.aborted) {
      const state = page.surface.status();
      // Reuse the existing navigation and session expiry rules. Keeping a
      // browser page alive does not grant any extra Host or message access.
      if (!state.navigationArmed && state.liveSessionCount === 0) return;
      try { await delay(options.checkIntervalMs ?? 1000, undefined, { signal }); }
      catch (error) { if (!signal?.aborted) throw error; }
    }
  } finally {
    try { await page?.close(); }
    finally { await adapter.close(); }
  }
}

function bootstrapArgs(mode, options) {
  if (!path.isAbsolute(options?.root || "")
    || path.resolve(options.root) !== options.root
    || !/^[a-f0-9]{64}$/.test(options?.expectedManifestSha256 || "")) {
    throw failure("workbuddy_local_web_launch_configuration_invalid");
  }
  return [path.join(options.root, "integrations/workbuddy/server/package-bootstrap.mjs"),
    mode, "--root", options.root, "--expected-manifest-sha256", options.expectedManifestSha256];
}

function validateReady(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== 1 || typeof value.cleanUrl !== "string"
    || !/^http:\/\/127\.0\.0\.1:\d{1,5}\/inbox$/.test(value.cleanUrl)) {
    throw failure("workbuddy_local_web_launch_invalid");
  }
  const port = Number(new URL(value.cleanUrl).port);
  if (port < 1 || port > 65535) throw failure("workbuddy_local_web_launch_invalid");
  return Object.freeze({ cleanUrl: value.cleanUrl });
}

function sendReady(value) {
  return new Promise((resolve, reject) => {
    if (!process.connected || typeof process.send !== "function") {
      reject(failure("workbuddy_local_web_launch_handoff_missing"));
      return;
    }
    process.send(validateReady(value), (error) => error ? reject(error) : resolve());
  });
}

function failure(code) { return Object.assign(new Error(code), { code }); }
