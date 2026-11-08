#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHostProtectedStore } from "./hellolynk-host-protected-store.mjs";
import { defaultNeutralHostStoreRoot } from "./hellolynk-neutral-host-installation-store.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { containsHelloLynkCredentialMaterial, sanitizeHelloLynkChildEnvironment } = runtimeSafety;

const MAX_CONFIG_BYTES = 1024 * 1024;
const configurationRollbackSnapshots = new WeakMap();

function parseArgs(argv) {
  const [client, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    if (!rest[index]?.startsWith("--") || index + 1 >= rest.length) throw new Error("agent_setup_arguments_invalid");
    options[rest[index].slice(2)] = rest[index + 1];
  }
  return { client, options };
}

function required(options, key) {
  const value = String(options[key] || "").trim();
  if (!value) throw new Error(`agent_setup_${key}_required`);
  return value;
}

// Desktop clients can move their whole profile through a user-owned junction.
// Pin the existing parent to its physical location; the config file itself
// must still be regular, and the Windows writer keeps its no-reparse checks.
function resolveConfigPath(options) {
  const logical = path.resolve(options.configPath);
  let parent = path.dirname(logical);
  const missing = [];
  while (!fs.existsSync(parent)) {
    missing.unshift(path.basename(parent));
    const next = path.dirname(parent);
    if (next === parent) throw new Error("agent_setup_config_path_invalid");
    parent = next;
  }
  const resolved = path.join(fs.realpathSync(parent), ...missing, path.basename(logical));
  if (options.expectedConfigPath != null && !samePath(resolved, options.expectedConfigPath)) {
    throw new Error("agent_setup_config_path_changed");
  }
  return resolved;
}

function readJsonConfig(configPath, options = {}) {
  let metadata;
  try {
    metadata = fs.lstatSync(configPath);
  } catch (error) {
    if (options.allowMissing === true && error?.code === "ENOENT") {
      return { exists: false, value: {}, bytes: null, sha256: null };
    }
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_CONFIG_BYTES) {
    throw new Error("agent_setup_config_invalid");
  }
  const bytes = fs.readFileSync(configPath);
  let body;
  try { body = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("agent_setup_config_encoding_invalid"); }
  if (containsHelloLynkCredentialMaterial(body)) throw new Error("agent_setup_config_contains_secret");
  const value = options.jsonc ? JSON.parse(jsoncWithoutComments(body).replace(/("(?:\\.|[^"\\])*")|,(?=\s*[}\]])/g, (match, quoted) => quoted || "")) : JSON.parse(body);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("agent_setup_config_invalid");
  return { exists: true, value, bytes, jsonc: options.jsonc === true, sha256: createHash("sha256").update(bytes).digest("hex") };
}

// Keep strings and offsets intact: argv.json permits comments and trailing
// commas. JSON.parse still validates all remaining syntax before any write.
function jsoncWithoutComments(body) {
  return body.replace(/^\uFEFF/, " ").replace(/("(?:\\.|[^"\\])*")|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g,
    (match, quoted) => quoted || match.replace(/[^\r\n]/g, " "));
}

function windowsAtomicReplace(configPath, temporary, expectedSha256) {
  const helper = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../platform/windows/configure-agent.ps1");
  const result = spawnSync("pwsh", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", helper, "-AtomicReplace",
  ], {
    encoding: "utf8",
    windowsHide: true,
    env: sanitizeHelloLynkChildEnvironment(process.env),
    input: JSON.stringify({
      configPath,
      temporary,
      expectedSha256,
      replacementSha256: createHash("sha256").update(fs.readFileSync(temporary)).digest("hex"),
    }),
  });
  const code = String(result.stdout || "").trim();
  if (result.status !== 0 || code !== "agent_setup_config_replace_ok") {
    throw new Error(/^[a-z][a-z0-9_]{0,127}$/.test(code) ? code : "agent_setup_config_replace_failed");
  }
}

function serializedJsonBytes(value) {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_CONFIG_BYTES
    || containsHelloLynkCredentialMaterial(serialized)) {
    throw new Error("agent_setup_config_contains_secret");
  }
  return Buffer.from(serialized, "utf8");
}

function atomicWriteBytes(configPath, bytes, expectedSha256) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_CONFIG_BYTES
    || containsHelloLynkCredentialMaterial(bytes.toString("utf8"))) {
    throw new Error("agent_setup_config_contains_secret");
  }
  fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
  const temporary = path.join(path.dirname(configPath), `.${path.basename(configPath)}.${randomUUID()}.tmp`);
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (expectedSha256 == null) {
      // Linking the fully written temporary file publishes a missing config without
      // overwriting a concurrently-created path on either Windows or POSIX.
      fs.linkSync(temporary, configPath);
      // The config is committed now. Removing its temporary name must not hide
      // that success or prevent finishConfiguration from retaining its receipt.
      try { fs.unlinkSync(temporary); } catch {}
    } else if (process.platform === "win32") {
      windowsAtomicReplace(configPath, temporary, expectedSha256);
    } else {
      const current = readJsonConfig(configPath, { jsonc: true });
      if (current.sha256 !== expectedSha256) throw new Error("agent_setup_config_changed");
      fs.renameSync(temporary, configPath);
    }
  } catch (error) {
    try { fs.rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

function assertPreparedConfig(snapshot, replacementBytes, options) {
  if (Object.hasOwn(options, "expectedConfigSha256")
    && options.expectedConfigSha256 !== snapshot.sha256) {
    throw new Error("agent_setup_config_changed");
  }
  const replacementSha256 = createHash("sha256").update(replacementBytes).digest("hex");
  if (Object.hasOwn(options, "expectedReplacementSha256")
    && options.expectedReplacementSha256 !== replacementSha256) {
    throw new Error("agent_setup_config_plan_changed");
  }
  return replacementSha256;
}

function finishConfiguration({ result, snapshot, replacementBytes, replacementSha256, apply }) {
  const changed = snapshot.sha256 !== replacementSha256;
  const publicResult = Object.freeze({
    ...result,
    planned: apply !== true,
    changed,
    expectedConfigSha256: snapshot.sha256,
    replacementSha256,
  });
  if (apply !== true || !changed) return publicResult;
  atomicWriteBytes(result.configPath, replacementBytes, snapshot.sha256);
  configurationRollbackSnapshots.set(publicResult, Object.freeze({
    configPath: result.configPath,
    priorExists: snapshot.exists,
    priorBytes: snapshot.bytes,
    replacementSha256,
    jsonc: snapshot.jsonc === true,
  }));
  return publicResult;
}

export async function rollbackAgentConfiguration(configured) {
  const snapshot = configurationRollbackSnapshots.get(configured);
  if (!snapshot) return Object.freeze({ rolledBack: false, reason: "unchanged" });
  const current = readJsonConfig(snapshot.configPath, { jsonc: snapshot.jsonc });
  if (current.sha256 !== snapshot.replacementSha256) {
    throw new Error("agent_setup_config_rollback_conflict");
  }
  if (snapshot.priorExists) {
    atomicWriteBytes(snapshot.configPath, snapshot.priorBytes, snapshot.replacementSha256);
  } else {
    const quarantine = path.join(
      path.dirname(snapshot.configPath),
      `.${path.basename(snapshot.configPath)}.${randomUUID()}.rollback`,
    );
    fs.renameSync(snapshot.configPath, quarantine);
    try {
      const quarantined = readJsonConfig(quarantine, { jsonc: snapshot.jsonc });
      if (quarantined.sha256 !== snapshot.replacementSha256) {
        throw new Error("agent_setup_config_rollback_conflict");
      }
      fs.unlinkSync(quarantine);
    } catch (error) {
      if (!fs.existsSync(snapshot.configPath) && fs.existsSync(quarantine)) {
        fs.renameSync(quarantine, snapshot.configPath);
      }
      throw error;
    }
  }
  configurationRollbackSnapshots.delete(configured);
  return Object.freeze({ rolledBack: true });
}

export async function runAgentConfigurationTransaction(options = {}) {
  const plans = Array.isArray(options.plans) ? options.plans : null;
  if (!plans || typeof options.apply !== "function" || typeof options.rollback !== "function"
    || (options.finalize != null && typeof options.finalize !== "function")) {
    throw new Error("agent_setup_transaction_invalid");
  }
  const committed = [];
  try {
    for (const plan of plans) committed.push(await options.apply(plan));
    if (options.finalize) await options.finalize();
    return Object.freeze({ committed: Object.freeze(committed) });
  } catch (error) {
    const rollbackFailures = [];
    for (const item of [...committed].reverse()) {
      try { await options.rollback(item); }
      catch (rollbackError) { rollbackFailures.push(rollbackError); }
    }
    if (rollbackFailures.length > 0 || localConfigurationMayBeUncertain(error)) {
      const failure = new Error("local_configuration_outcome_uncertain");
      failure.localConfigurationOutcomeUncertain = true;
      failure.cause = rollbackFailures[0] || error;
      failure.configurationCause = error;
      if (rollbackFailures.length > 1) failure.rollbackFailures = rollbackFailures;
      throw failure;
    }
    throw error;
  }
}

function localConfigurationMayBeUncertain(error) {
  const code = String(error?.code || error?.message || "");
  return error?.localConfigurationOutcomeUncertain === true
    || code === "local_configuration_outcome_uncertain"
    || /^(?:agent_setup_config|client_skill)(?:_[a-z0-9]+)*_rollback_failed(?::|$)/u.test(code);
}

function requirePluginDirectory(pluginPath) {
  const absolute = path.resolve(String(pluginPath || ""));
  const metadata = fs.lstatSync(absolute);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("agent_setup_plugin_invalid");
  const manifestPath = path.join(absolute, "openclaw.plugin.json");
  const manifest = fs.lstatSync(manifestPath);
  if (!manifest.isFile() || manifest.isSymbolicLink()) throw new Error("agent_setup_plugin_invalid");
  return absolute;
}

function pluginIdAt(pluginPath) {
  try {
    const manifestPath = path.join(path.resolve(String(pluginPath || "")), "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    return typeof manifest?.id === "string" ? manifest.id.trim() : "";
  } catch {
    return "";
  }
}

export function buildOpenClawChannelConfig(nativeModel) {
  // Match the current OpenClaw channel's optional native model contract.
  if (nativeModel !== undefined && (!plainObject(nativeModel)
    || Object.keys(nativeModel).some((key) => !["provider", "model", "thinkingLevel"].includes(key))
    || typeof nativeModel.provider !== "string" || !/^[a-z0-9][a-z0-9._-]{0,79}$/.test(nativeModel.provider)
    || typeof nativeModel.model !== "string" || nativeModel.model.length > 240
    || !/^[^\s\u0000-\u001f\u007f]+$/.test(nativeModel.model)
    || (nativeModel.thinkingLevel !== undefined && (typeof nativeModel.thinkingLevel !== "string"
      || !/^[a-z][a-z0-9_-]{0,31}$/.test(nativeModel.thinkingLevel))))) {
    throw new Error("neutral_openclaw_native_model_invalid");
  }
  return Object.freeze({
    enabled: true,
    hostMode: "neutral",
    bindingRef: "protected-store:openclaw",
    ...(nativeModel !== undefined ? { nativeModel: Object.freeze({ ...nativeModel }) } : {}),
  });
}

export async function configureOpenClaw(options) {
  const configPath = resolveConfigPath(options);
  const pluginPath = requirePluginDirectory(options.pluginPath);
  const configSnapshot = readJsonConfig(configPath, { allowMissing: options.allowMissing === true });
  const config = configSnapshot.value;
  migrateLegacyOpenClawConfig(config);
  assertExistingOpenClawNeutralConfig(config);
  config.channels = config.channels && typeof config.channels === "object" && !Array.isArray(config.channels)
    ? config.channels
    : {};
  config.channels.hellolynk = buildOpenClawChannelConfig(config.channels.hellolynk?.nativeModel);
  config.plugins = config.plugins && typeof config.plugins === "object" && !Array.isArray(config.plugins)
    ? config.plugins
    : {};
  config.plugins.load = config.plugins.load && typeof config.plugins.load === "object" && !Array.isArray(config.plugins.load)
    ? config.plugins.load
    : {};
  const existingPaths = Array.isArray(config.plugins.load.paths) ? config.plugins.load.paths : [];
  const pluginId = pluginIdAt(pluginPath);
  let exactPathCount = 0;
  const unrelatedPaths = existingPaths.map((candidate) => {
    const absoluteCandidate = path.resolve(String(candidate || ""));
    if (samePath(absoluteCandidate, pluginPath)) {
      exactPathCount += 1;
      return null;
    }
    if (pluginId && pluginIdAt(absoluteCandidate) === pluginId) {
      if (isPriorStableOpenClawPluginPath(absoluteCandidate, pluginPath)) return null;
      throw new Error("neutral_openclaw_plugin_conflict");
    }
    return candidate;
  });
  if (exactPathCount > 1) throw new Error("neutral_openclaw_plugin_conflict");
  config.plugins.load.paths = [...new Set([...unrelatedPaths.filter(Boolean), pluginPath])];
  config.plugins.entries = config.plugins.entries && typeof config.plugins.entries === "object" && !Array.isArray(config.plugins.entries)
    ? config.plugins.entries
    : {};
  const existingEntry = config.plugins.entries.hellolynk && typeof config.plugins.entries.hellolynk === "object" && !Array.isArray(config.plugins.entries.hellolynk)
    ? config.plugins.entries.hellolynk
    : {};
  config.plugins.entries.hellolynk = { ...existingEntry, enabled: true };
  // The installed sidebar is a native plugin page. Enable the host's supported
  // setting in the same guarded config transaction, preserving other settings.
  let ui = config;
  for (const key of ["gateway", "controlUi", "experimental"]) {
    if (Object.hasOwn(ui, key) && !plainObject(ui[key])) throw new Error("agent_setup_config_invalid");
    ui[key] ??= {};
    ui = ui[key];
  }
  ui.customPlugins = true;
  const replacementBytes = serializedJsonBytes(config);
  const replacementSha256 = assertPreparedConfig(configSnapshot, replacementBytes, options);
  if (options.apply !== false) await requireOpenClawNeutralBinding(options);
  if (!samePath(resolveConfigPath(options), configPath)) throw new Error("agent_setup_config_path_changed");
  return finishConfiguration({
    snapshot: configSnapshot,
    replacementBytes,
    replacementSha256,
    apply: options.apply !== false,
    result: {
    ok: true,
    client: "openclaw",
    mode: "neutral",
    bindingRef: "protected-store:openclaw",
    pluginRegistered: true,
    pluginPath,
    configPath,
    },
  });
}

export async function configureNeutralHostMcpClient(options) {
  const client = String(options.client || "");
  if (!["trae-work", "workbuddy"].includes(client)) throw new Error("agent_setup_client_unsupported");
  const configPath = resolveConfigPath(options);
  const nodePath = requireRegularFile(options.nodePath, "agent_setup_node_invalid");
  const proxyPath = requireRegularFile(options.proxyPath, "agent_setup_proxy_invalid");
  const entryArgs = normalizeMcpEntryArgs(options.entryArgs);
  const storeRoot = normalizeNeutralHostStoreRoot(
    options.storeRoot || defaultNeutralHostStoreRoot(process.platform, options.env || process.env),
  );
  const configSnapshot = readJsonConfig(configPath, { allowMissing: options.allowMissing === true });
  const config = configSnapshot.value;
  if (Object.hasOwn(config, "mcpServers")
    && (!config.mcpServers || typeof config.mcpServers !== "object" || Array.isArray(config.mcpServers))) {
    throw new Error("agent_setup_config_invalid");
  }
  config.mcpServers = config.mcpServers || {};
  const hadManagedEntry = Object.hasOwn(config.mcpServers, "hellolynk") || Object.hasOwn(config.mcpServers, "lynk");
  migrateLegacyMcpServer(config.mcpServers, client);
  config.mcpServers.hellolynk = {
    command: nodePath,
    args: [proxyPath, ...entryArgs],
    env: { HELLOLYNK_NEUTRAL_STORE_ROOT: storeRoot },
  };
  const replacementBytes = serializedJsonBytes(config);
  const replacementSha256 = assertPreparedConfig(configSnapshot, replacementBytes, options);
  return finishConfiguration({
    snapshot: configSnapshot,
    replacementBytes,
    replacementSha256,
    apply: options.apply !== false,
    result: { ok: true, client, mode: "neutral", configPath, proxyPath, entryArgCount: entryArgs.length, hadManagedEntry },
  });
}

// Uninstall removes the entry only while it starts a release under releasesRoot; an entry that
// starts anything else is not this installation's. Other servers and settings stay as they are.
export async function removeNeutralHostMcpClient(options) {
  const client = String(options.client || "");
  if (!["trae-work", "workbuddy"].includes(client)) throw new Error("agent_setup_client_unsupported");
  const configPath = resolveConfigPath(options);
  const configSnapshot = readJsonConfig(configPath, { allowMissing: true });
  const config = configSnapshot.value;
  if (Object.hasOwn(config, "mcpServers") && !plainObject(config.mcpServers)) throw new Error("agent_setup_config_invalid");
  const server = config.mcpServers?.hellolynk;
  if (server !== undefined && !inInstalledRelease(server?.args?.[0], options.releasesRoot, client)) {
    throw new Error("agent_setup_uninstall_conflict");
  }
  if (server !== undefined) delete config.mcpServers.hellolynk;
  return finishRemoval(configSnapshot, server !== undefined ? serializedJsonBytes(config) : configSnapshot.bytes, options,
    { ok: true, client, configPath });
}

// OpenClaw rejects a channel whose plugin is gone, so the channel and plugin entry go with the
// load path. A HelloLynk plugin loaded from anywhere else is not this installation's.
export async function removeOpenClaw(options) {
  const configPath = resolveConfigPath(options);
  const configSnapshot = readJsonConfig(configPath, { allowMissing: true });
  const config = configSnapshot.value;
  const paths = Array.isArray(config.plugins?.load?.paths) ? config.plugins.load.paths : [];
  const installed = paths.filter((candidate) => isLegacyOpenClawPluginPath(candidate)
    || inInstalledRelease(candidate, options.releasesRoot, "openclaw", ["integrations", "openclaw-channel"]));
  if (paths.some((candidate) => !installed.includes(candidate) && pluginIdAt(candidate) === "hellolynk")) {
    throw new Error("agent_setup_uninstall_conflict");
  }
  if (installed.length) {
    config.plugins.load.paths = paths.filter((candidate) => !installed.includes(candidate));
    if (plainObject(config.channels)) delete config.channels.hellolynk;
    if (plainObject(config.plugins.entries)) delete config.plugins.entries.hellolynk;
  }
  return finishRemoval(configSnapshot, installed.length ? serializedJsonBytes(config) : configSnapshot.bytes, options,
    { ok: true, client: "openclaw", configPath });
}

function finishRemoval(snapshot, replacementBytes, options, result) {
  if (!snapshot.exists) {
    return Object.freeze({ ...result, planned: options.apply === false, changed: false, expectedConfigSha256: null, replacementSha256: null });
  }
  const replacementSha256 = assertPreparedConfig(snapshot, replacementBytes, options);
  if (!samePath(resolveConfigPath(options), result.configPath)) throw new Error("agent_setup_config_path_changed");
  return finishConfiguration({ snapshot, replacementBytes, replacementSha256, apply: options.apply !== false, result });
}

// A path inside <releasesRoot>\<client>-<sha256>, the releases the installer writes.
function inInstalledRelease(value, releasesRoot, client, tail = null) {
  const candidate = String(value || "");
  if (!path.isAbsolute(candidate) || !path.isAbsolute(String(releasesRoot || ""))) return false;
  const relative = path.relative(path.resolve(releasesRoot), path.resolve(candidate));
  const [release, ...rest] = relative.split(path.sep);
  return !relative.startsWith("..") && !path.isAbsolute(relative)
    && new RegExp(`^${escapeRegExp(client)}-[a-f0-9]{64}$`, "i").test(release || "")
    && (tail === null ? rest.length > 0 : rest.join("/").toLowerCase() === tail.join("/").toLowerCase());
}

// The merged TRAE client reads this one user startup argument. Only add a
// missing port; preserve existing settings, comments and user-chosen ports.
export async function configureTraeNativeStartup(options) {
  const configPath = resolveConfigPath(options);
  const snapshot = readJsonConfig(configPath, { allowMissing: true, jsonc: true });
  const config = snapshot.value;
  const current = config["remote-debugging-port"];
  if (current !== undefined && (!/^[1-9]\d{0,4}$/.test(String(current)) || Number(current) > 65535)) {
    throw new Error("trae_native_debug_startup_conflict");
  }
  const endpoint = new URL(options.debugEndpoint || `http://127.0.0.1:${current ?? 9338}`);
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port
    || endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password) {
    throw new Error("trae_native_debug_endpoint_invalid");
  }
  if (current !== undefined && String(current) !== endpoint.port
    || config["remote-debugging-address"] !== undefined && config["remote-debugging-address"] !== "127.0.0.1") {
    throw new Error("trae_native_debug_startup_conflict");
  }
  let replacementBytes = snapshot.bytes;
  if (current === undefined) {
    const original = snapshot.bytes?.toString("utf8") || "{}\n";
    const insertAt = jsoncWithoutComments(original).indexOf("{") + 1;
    const eol = original.includes("\r\n") ? "\r\n" : "\n";
    const setting = `${eol}  "remote-debugging-port": ${JSON.stringify(endpoint.port)}${Object.keys(config).length ? "," : ""}${eol}`;
    replacementBytes = Buffer.from(original.slice(0, insertAt) + setting + original.slice(insertAt));
  }
  const replacementSha256 = assertPreparedConfig(snapshot, replacementBytes, options);
  return finishConfiguration({ snapshot: { ...snapshot, jsonc: true }, replacementBytes, replacementSha256,
    apply: options.apply !== false, result: { ok: true, configPath, debugEndpoint: endpoint.origin, restartRequired: current === undefined } });
}

function migrateLegacyOpenClawConfig(config) {
  const channels = plainObject(config.channels) ? config.channels : null;
  const entries = plainObject(config.plugins?.entries) ? config.plugins.entries : null;
  const paths = Array.isArray(config.plugins?.load?.paths) ? config.plugins.load.paths : null;
  const channelPresent = Boolean(channels && Object.hasOwn(channels, "lynk"));
  const entryPresent = Boolean(entries && Object.hasOwn(entries, "lynk"));
  const legacyPaths = paths ? paths.filter(isLegacyOpenClawPluginPath) : [];
  if (!channelPresent && !entryPresent && legacyPaths.length === 0) return;
  const exactChannel = channelPresent && exactObject(channels.lynk, {
    enabled: true,
    hostMode: "neutral",
    bindingRef: "protected-store:openclaw",
  });
  const exactEntry = entryPresent && exactObject(entries.lynk, { enabled: true });
  if (!exactChannel || !exactEntry || !paths || legacyPaths.length !== 1) {
    throw new Error("neutral_openclaw_legacy_config_conflict");
  }
  delete channels.lynk;
  delete entries.lynk;
  config.plugins.load.paths = paths.filter((candidate) => candidate !== legacyPaths[0]);
}

function migrateLegacyMcpServer(servers, client) {
  if (!Object.hasOwn(servers, "lynk")) return;
  if (!isLegacyMcpServer(servers.lynk, client)) throw new Error("neutral_mcp_legacy_config_conflict");
  delete servers.lynk;
}

function isLegacyMcpServer(value, client) {
  if (!plainObject(value)) return false;
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "args,command" && keys !== "args,command,disabled") return false;
  if (Object.hasOwn(value, "disabled") && value.disabled !== false) return false;
  const command = String(value.command || "");
  if (!path.isAbsolute(command) || !/^node(?:\.exe)?$/i.test(path.basename(command))) return false;
  const args = Array.isArray(value.args) ? value.args.map((item) => String(item || "")) : [];
  if (client === "trae-work") {
    return args.length === 4
      && isLegacyReleaseFile(args[0], "trae-work", ["runtime", "trae-work-bootstrap.mjs"])
      && args[1] === "run"
      && args[2] === "--expected-manifest-sha256"
      && /^[a-f0-9]{64}$/.test(args[3]);
  }
  if (args.length !== 6
    || !isLegacyReleaseFile(args[0], "workbuddy", ["integrations", "workbuddy", "server", "package-bootstrap.mjs"])
    || args[1] !== "run" || args[2] !== "--root"
    || args[4] !== "--expected-manifest-sha256" || !/^[a-f0-9]{64}$/.test(args[5])) return false;
  const releaseRoot = legacyReleaseRoot(args[0], ["integrations", "workbuddy", "server", "package-bootstrap.mjs"]);
  return Boolean(releaseRoot) && samePath(args[3], releaseRoot);
}

function isLegacyOpenClawPluginPath(value) {
  return Boolean(legacyReleaseRoot(value, ["integrations", "openclaw-channel"], "openclaw"));
}

function isPriorStableOpenClawPluginPath(candidate, current) {
  const tail = ["integrations", "openclaw-channel"];
  const currentPath = path.resolve(String(current || ""));
  const candidatePath = path.resolve(String(candidate || ""));
  const currentPackageRoot = path.dirname(path.dirname(currentPath));
  const candidatePackageRoot = path.dirname(path.dirname(candidatePath));
  const releasesRoot = path.dirname(currentPackageRoot);
  if (!/^openclaw-[a-f0-9]{64}$/i.test(path.basename(currentPackageRoot))
    || !/^openclaw-[a-f0-9]{64}$/i.test(path.basename(candidatePackageRoot))
    || !samePath(path.dirname(candidatePackageRoot), releasesRoot)
    || !samePath(currentPath, path.join(currentPackageRoot, ...tail))
    || !samePath(candidatePath, path.join(candidatePackageRoot, ...tail))) {
    return false;
  }
  return !samePath(candidatePackageRoot, currentPackageRoot);
}

function isLegacyReleaseFile(value, client, tail) {
  return Boolean(legacyReleaseRoot(value, tail, client));
}

function legacyReleaseRoot(value, tail, expectedClient = "workbuddy") {
  const candidate = String(value || "");
  if (!path.isAbsolute(candidate)) return null;
  const normalized = path.resolve(candidate);
  const segments = normalized.split(path.sep);
  if (segments.length < tail.length + 3) return null;
  const actualTail = segments.slice(-tail.length);
  if (!actualTail.every((segment, index) => segment.toLowerCase() === tail[index].toLowerCase())) return null;
  const releaseIndex = segments.length - tail.length - 1;
  const releaseName = segments[releaseIndex];
  if (!new RegExp(`^${escapeRegExp(expectedClient)}-[0-9]+\\.[0-9]+\\.[0-9]+-[A-Za-z0-9._-]+$`, "i").test(releaseName)) return null;
  if (segments[releaseIndex - 1]?.toLowerCase() !== "releases"
    || segments[releaseIndex - 2]?.toLowerCase() !== "lynk") return null;
  return segments.slice(0, releaseIndex + 1).join(path.sep);
}

function normalizeNeutralHostStoreRoot(value) {
  const input = String(value || "").trim();
  if (!path.isAbsolute(input)) throw new Error("neutral_host_store_root_invalid");
  const root = path.resolve(input);
  if (path.basename(root).toLowerCase() !== "host") throw new Error("neutral_host_store_root_invalid");
  return root;
}

function exactObject(value, expected) {
  if (!plainObject(value)) return false;
  const keys = Object.keys(value).sort();
  const expectedKeys = Object.keys(expected).sort();
  return keys.length === expectedKeys.length
    && keys.every((key, index) => key === expectedKeys[index] && value[key] === expected[key]);
}

function plainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function samePath(left, right) {
  const a = path.resolve(String(left || ""));
  const b = path.resolve(String(right || ""));
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeMcpEntryArgs(value) {
  const args = value == null ? [] : value;
  if (!Array.isArray(args) || args.length > 12) throw new Error("agent_setup_entry_args_invalid");
  return args.map((item) => {
    const text = String(item ?? "");
    if (!text || text.length > 2048 || /[\0\r\n]/.test(text)
      || /hellolynk_(?:bind|device)_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,}/i.test(text)) {
      throw new Error("agent_setup_entry_args_invalid");
    }
    return text;
  });
}

function parseMcpEntryArgs(value) {
  if (value == null) return [];
  let parsed;
  try { parsed = JSON.parse(String(value)); } catch { throw new Error("agent_setup_entry_args_invalid"); }
  return normalizeMcpEntryArgs(parsed);
}

function assertExistingOpenClawNeutralConfig(config) {
  if (!Object.hasOwn(config, "channels")) return;
  const channels = config.channels;
  if (!channels || typeof channels !== "object" || Array.isArray(channels)) {
    throw new Error("neutral_openclaw_legacy_config_rejected");
  }
  if (!Object.hasOwn(channels, "hellolynk")) return;
  const hellolynk = channels.hellolynk;
  const expected = buildOpenClawChannelConfig(hellolynk?.nativeModel);
  if (!hellolynk || typeof hellolynk !== "object" || Array.isArray(hellolynk)
    || Object.keys(hellolynk).sort().join(",") !== Object.keys(expected).sort().join(",")
    || hellolynk.enabled !== true
    || hellolynk.hostMode !== "neutral"
    || hellolynk.bindingRef !== "protected-store:openclaw"
    || !["bindingRef", "enabled", "hostMode"].every((key) => Object.hasOwn(hellolynk, key))) {
    throw new Error("neutral_openclaw_legacy_config_rejected");
  }
}

function requireRegularFile(value, code) {
  const absolute = path.resolve(String(value || ""));
  let metadata;
  try { metadata = fs.lstatSync(absolute); } catch { throw new Error(code); }
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(code);
  return absolute;
}

export async function runAgentConfigurator(argv = process.argv.slice(2)) {
  const { client, options } = parseArgs(argv);
  if (client === "openclaw") return await configureOpenClaw({
    configPath: required(options, "config-path"), pluginPath: required(options, "plugin-path"),
  });
  if (["trae-work", "workbuddy"].includes(client)) return await configureNeutralHostMcpClient({
    client,
    configPath: required(options, "config-path"),
    nodePath: required(options, "node-path"),
    proxyPath: required(options, "proxy-path"),
    entryArgs: parseMcpEntryArgs(options["entry-args-json"]),
  });
  throw new Error("agent_setup_client_unsupported");
}

async function requireOpenClawNeutralBinding(options = {}) {
  const provider = options.bindingProvider || (() => createHostProtectedStore({
    ...(options.storeRoot ? { root: options.storeRoot } : {}),
  }).resolveOpenClawNeutralBinding());
  if (typeof provider !== "function") throw new Error("neutral_capability_provider_required");
  let binding;
  try {
    binding = await provider();
  } catch (error) {
    if (options.allowUnconnected === true && ["host_installation_missing", "host_delegate_binding_missing", "neutral_openclaw_binding_configuration_required"].includes(error?.code)) return;
    throw new Error("neutral_openclaw_binding_unavailable");
  }
  if (!binding || binding.adapterId !== "openclaw" || Number(binding.capability?.version) !== 2
    || binding.capability?.state !== "active") {
    throw new Error("neutral_openclaw_binding_invalid");
  }
}

function publicError(error) {
  const code = String(error?.code || error?.message || "agent_setup_failed");
  return /^[a-z][a-z0-9_]{0,127}$/.test(code) ? code : "agent_setup_failed";
}

const directRun = process.argv[1] && path.basename(process.argv[1]) === path.basename(fileURLToPath(import.meta.url));
if (directRun) {
  runAgentConfigurator().then(
    (result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`),
    (error) => {
      process.stderr.write(`${JSON.stringify({ ok: false, error: publicError(error) })}\n`);
      process.exitCode = 1;
    },
  );
}
