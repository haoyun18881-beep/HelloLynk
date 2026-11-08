import crypto from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import safety from "./hellolynk-runtime-safety.cjs";
import { createNeutralHostInstallationStore, defaultNeutralHostStoreRoot } from "./hellolynk-neutral-host-installation-store.mjs";
import { verifyPinnedNeutralHostRuntime } from "./hellolynk-neutral-host-launcher.mjs";
import { prepareWindowsClientRoot, secureWindowsClientReleaseTree } from "./hellolynk-platform-credential-store.mjs";
import { runRelayClientCli } from "./hellolynk-relay-client-cli.mjs";
import { createHelloLynkAccountLauncher } from "./hellolynk-neutral-host-assembly.mjs";
import { ACCOUNT_CLIENTS, clientAccountBaseRoot, createClientAccountActions } from "./hellolynk-client-account.mjs";

const CLIENTS = new Set(ACCOUNT_CLIENTS);
const CONFIRMATION_URL = /^https:\/\/hellolynk\.com\/account\?deviceRequest=devreq_[a-f0-9]{48}$/;

// Restricted to our account pages, including the current device-confirmation
// link. No arbitrary URL or shell text can come from the browser.
export function createWorkbenchAccountOpener(options = {}) {
  const launch = createHelloLynkAccountLauncher({ ...options, baseUrl: "https://hellolynk.com" });
  return async ({ url } = {}) => {
    if (typeof url !== "string" || (!/^https:\/\/hellolynk\.com\/account(?:#(?:keys|devices))?$/.test(url)
      && !CONFIRMATION_URL.test(url))) throw code("workbench_portal_target_invalid", 400);
    const parsed = new URL(url);
    const deviceRequest = parsed.searchParams.get("deviceRequest");
    const result = await launch({ target: parsed.hash.slice(1) || "account", ...(deviceRequest ? { deviceRequest } : {}) });
    if (!result.opened) throw code("workbench_portal_open_failed", 502);
    return { opened: true };
  };
}

export function isWorkbenchConnectionRequired(error) {
  return ["host_installation_missing", "host_delegate_binding_missing", "workbench_connection_required"].includes(error?.code)
    || /^neutral_(?:codex|openclaw|trae_work|workbuddy|cursor|dsh|claude_code)_binding_configuration_required$/.test(String(error?.code || ""));
}

export function workbenchConnectionError(error) {
  return isWorkbenchConnectionRequired(error) ? code("workbench_connection_required", 409) : error;
}

export function validateWorkbenchConnectionInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "hellolynkId,instanceName"
    || typeof value.hellolynkId !== "string"
    || !safety.classifyHelloLynkStableId(value.hellolynkId)) throw code("workbench_connect_id_invalid", 400);
  if (typeof value.instanceName !== "string" || [...value.instanceName].length > 80
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value.instanceName)) {
    throw code("workbench_connect_name_invalid", 400);
  }
  return {
    hellolynkId: value.hellolynkId,
    // The enrollment layer has the durable intent needed to distinguish an
    // exact legacy retry from a new name. Preserve the value until then.
    instanceName: value.instanceName,
  };
}

// One small adapter for the existing enrollment and binding commands. Client,
// package and local store come from the installed integration, never the page.
export function createWorkbenchConnection(options) {
  if (!CLIENTS.has(options?.client) || !path.isAbsolute(options?.releaseRoot || "")) throw code("workbench_connect_configuration_invalid");
  const env = options.env || process.env;
  const storeRoot = options.storeRoot || env.HELLOLYNK_NEUTRAL_STORE_ROOT || defaultNeutralHostStoreRoot(process.platform, env);
  if (!path.isAbsolute(storeRoot)) throw code("workbench_connect_configuration_invalid");
  let busy = false;
  const accounts = createClientAccountActions(options);
  const connect = async (input, revision = accounts.readAccountState().revision) => {
    const validated = validateWorkbenchConnectionInput(input);
    if (busy) throw code("workbench_connect_busy", 409);
    busy = true;
    try {
      const result = await accounts.runForAccount(revision, (selectedRoot) => executeJson(
        path.join(options.releaseRoot, "runtime/core/hellolynk-workbench-connection.mjs"),
        ["connect", options.client, options.releaseRoot, selectedRoot], env, validated));
      if (result?.status === "confirmation_required" && CONFIRMATION_URL.test(result.verificationUrl)) {
        return { status: result.status, verificationUrl: result.verificationUrl };
      }
      if (result?.status !== "registered") throw code("workbench_connect_result_invalid", 502);
      return publicRegistration(result);
    } finally { busy = false; }
  };
  return Object.assign(connect, accounts);
}

export function createWorkbenchAccountActions(options) {
  return createClientAccountActions(options);
}

async function connectAccount(client, sourceRoot, storeRoot, input) {
  if (!["win32", "darwin"].includes(process.platform)) throw code("workbench_connect_platform_unsupported", 400);
  if (!CLIENTS.has(client) || !path.isAbsolute(sourceRoot) || !path.isAbsolute(storeRoot)
    || path.basename(storeRoot).toLowerCase() !== "host") throw code("workbench_connect_configuration_invalid");
  const value = validateWorkbenchConnectionInput(input);
  const currentRoot = path.dirname(storeRoot);
  const releaseCurrentRoot = path.dirname(clientAccountBaseRoot(storeRoot));
  const profileId = `hellolynk-host-${client}-v2`;
  const profileManifest = path.join(storeRoot, "profile-manifest-v1.json");
  const pin = JSON.parse(await fs.readFile(path.join(sourceRoot, "runtime/neutral-host-release-pin.json"), "utf8"));
  const binding = {
    adapterId: client, profileId, version: 2, scopes: [], region: "intl",
    principalId: "connection-preflight", delegateId: "connection-preflight", hostInstallationId: "connection-preflight",
    releaseRoot: sourceRoot, releaseManifestSha256: pin.manifestSha256,
    runnerRelativePath: "runtime/neutral-host-bootstrap.mjs", runtimeRoot: path.join(storeRoot, "runtime"), profileManifestPath: profileManifest,
  };
  await verifyPinnedNeutralHostRuntime(binding);
  await prepareWindowsClientRoot(currentRoot);
  const releaseRoot = await retainRelease(binding, releaseCurrentRoot, client);
  await createNeutralHostInstallationStore({ root: storeRoot }).createId();
  const activationArgs = ["--client", client, "--final-current-root", currentRoot, "--root", storeRoot,
    "--release-current-root", releaseCurrentRoot,
    "--release-root", releaseRoot, "--expected-release-manifest-sha256", pin.manifestSha256, "--profile-manifest", profileManifest];
  const activationScript = path.join(releaseRoot, "runtime/connect-activate.mjs");
  const preflight = await executeJson(activationScript, [...activationArgs, "--preflight", "true", "--pre-bind", "true"], process.env);
  if (preflight?.ok !== true || preflight.preflight !== true || preflight.preBind !== true || preflight.readOnly !== true
    || preflight.releaseManifestSha256 !== pin.manifestSha256 || preflight.clients?.length !== 1
    || preflight.clients[0]?.adapterId !== client || preflight.clients[0]?.bindingUpdated !== false) throw code("workbench_connect_preflight_invalid");
  const result = await runRelayClientCli(["connect", "--hellolynk-id", value.hellolynkId,
    "--base-url", "https://hellolynk.com", "--root", currentRoot, "--neutral-host-root", storeRoot,
    "--adapter", client, "--profile", profileId, ...(value.instanceName ? ["--instance-name", value.instanceName] : [])]);
  if (result?.ok !== true || result.hellolynkId !== value.hellolynkId) throw code("workbench_connect_result_invalid");
  if (result.status === "confirmation_required" && CONFIRMATION_URL.test(result.verificationUrl)) {
    return { status: result.status, verificationUrl: result.verificationUrl };
  }
  if (result.status !== "registered" || result.clientType !== client || result.profileId !== profileId
    || result.hostProfileRegistered !== true || result.configPath !== path.join(currentRoot, "profiles", `${profileId}.json`)) {
    throw code("workbench_connect_result_invalid");
  }
  const activated = await executeJson(activationScript, activationArgs, process.env);
  if (activated?.ok !== true || activated.releaseManifestSha256 !== pin.manifestSha256
    || activated.clients?.length !== 1 || activated.clients[0]?.adapterId !== client) throw code("workbench_connect_activation_invalid");
  return publicRegistration(result);
}

function publicRegistration(result) {
  return { status: "registered",
    ...(typeof result.instanceName === "string" ? { instanceName: result.instanceName } : {}),
    ...(result.recoveredExistingName === true ? { recoveredExistingName: true } : {}) };
}

async function retainRelease(binding, currentRoot, client) {
  const releases = path.join(currentRoot, "releases");
  const sourceRoot = path.resolve(binding.releaseRoot);
  // Normal installers already put the package here. Codex's disposable plugin
  // cache needs a durable copy of the verified runtime before creating a binding.
  if (sourceRoot.startsWith(`${releases}${path.sep}`)) {
    await secureWindowsClientReleaseTree(currentRoot, path.relative(releases, sourceRoot).split(path.sep)[0], { verifyOnly: true });
    return sourceRoot;
  }
  // Prefer the installed package that supplied this exact Codex cache. This
  // keeps the binding and installer diagnostics pointed at the same release.
  if (client === "codex") {
    for (const entry of (await fs.readdir(releases, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory() || !/^codex-[a-f0-9]{64}$/.test(entry.name)) continue;
      const candidate = path.join(releases, entry.name, "plugins/hellolynk-codex");
      let pin;
      try { pin = JSON.parse(await fs.readFile(path.join(candidate, "runtime/neutral-host-release-pin.json"), "utf8")); }
      catch { continue; }
      if (pin.manifestSha256 !== binding.releaseManifestSha256) continue;
      await secureWindowsClientReleaseTree(currentRoot, entry.name, { verifyOnly: true });
      await verifyPinnedNeutralHostRuntime({ ...binding, releaseRoot: candidate });
      return candidate;
    }
  }
  const id = `${client}-connection-${binding.releaseManifestSha256}`;
  const target = path.join(releases, id);
  try {
    await fs.lstat(target);
    await secureWindowsClientReleaseTree(currentRoot, id, { verifyOnly: true });
    await verifyPinnedNeutralHostRuntime({ ...binding, releaseRoot: target });
    return target;
  } catch (error) { if (error?.code !== "ENOENT") throw error; }
  const stageId = `.${id}.install-${crypto.randomUUID()}`;
  const stage = path.join(releases, stageId);
  await fs.mkdir(stage, { recursive: true, mode: 0o700 });
  try {
    const manifestPath = path.join(sourceRoot, "runtime/neutral-host-release-manifest.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    const paths = ["runtime/neutral-host-release-pin.json", "runtime/neutral-host-release-manifest.json",
      ...manifest.files.map((item) => item.path.startsWith("release/") ? item.path.slice(8) : `runtime/${item.path}`)];
    for (const relative of paths) {
      const destination = path.resolve(stage, relative);
      if (!destination.startsWith(`${stage}${path.sep}`)) throw code("workbench_connect_release_invalid");
      await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      await fs.writeFile(destination, await fs.readFile(path.join(sourceRoot, relative)), {
        flag: "wx", mode: relative.endsWith(".bin") ? 0o700 : 0o600,
      });
    }
    await verifyPinnedNeutralHostRuntime({ ...binding, releaseRoot: stage });
    await secureWindowsClientReleaseTree(currentRoot, stageId);
    try { await fs.rename(stage, target); }
    catch (error) { if (!["EEXIST", "ENOTEMPTY", "EPERM"].includes(error?.code)) throw error; }
    await secureWindowsClientReleaseTree(currentRoot, id, { verifyOnly: true });
    await verifyPinnedNeutralHostRuntime({ ...binding, releaseRoot: target });
    return target;
  } finally {
    if (path.dirname(stage) === releases && path.basename(stage) === stageId) await fs.rm(stage, { recursive: true, force: true }).catch(() => {});
  }
}

async function executeJson(script, args, env, input) {
  const executable = await safety.resolveHelloLynkStandaloneNode({ env });
  return new Promise((resolve, reject) => {
    const child = execFile(executable, [script, ...args], {
      cwd: path.dirname(script), shell: false, windowsHide: true, timeout: 150_000,
      maxBuffer: 256 * 1024, encoding: "utf8", env: safety.standaloneHelloLynkNodeEnvironment(env),
    }, (error, stdout, stderr) => {
      if (error) {
        let failure; try { failure = JSON.parse(stderr); } catch {}
        const safe = failure?.error;
        return reject(code(typeof safe === "string" && /^[a-z][a-z0-9_]{1,127}$/.test(safe)
          ? safe : error.killed ? "workbench_connect_timeout" : "workbench_connect_failed"));
      }
      try { resolve(JSON.parse(stdout)); } catch { reject(code("workbench_connect_result_invalid")); }
    });
    child.stdin?.on("error", () => {}); // execFile's callback reports early exit.
    child.stdin?.end(input ? JSON.stringify(input) : undefined);
  });
}

function code(value, status = 503) { return Object.assign(new Error(value), { code: value, status }); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  Promise.resolve().then(async () => {
    if (process.argv.length !== 6 || process.argv[2] !== "connect") throw code("workbench_connect_arguments_invalid");
    let input = "";
    for await (const chunk of process.stdin) {
      input += chunk;
      if (Buffer.byteLength(input) > 4096) throw code("workbench_connect_input_invalid");
    }
    return connectAccount(process.argv[3], process.argv[4], process.argv[5], JSON.parse(input));
  }).then((result) => process.stdout.write(`${JSON.stringify(result)}\n`), (error) => {
    const safe = String(error?.code || error?.message || "");
    process.stderr.write(`${JSON.stringify({ ok: false, error: /^[a-z][a-z0-9_]{1,127}$/.test(safe) ? safe : "workbench_connect_failed" })}\n`);
    process.exitCode = 1;
  });
}
