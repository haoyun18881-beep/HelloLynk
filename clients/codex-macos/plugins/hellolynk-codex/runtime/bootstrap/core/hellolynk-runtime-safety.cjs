"use strict";

const HELLOLYNK_CLIENT_PROFILE_CONTRACT = "hellolynk-client-profile-v1";
const HELLOLYNK_CONTACTS_CONTRACT = "hellolynk-local-contacts-v1";
const HELLOLYNK_MINIMUM_CLIENT_NODE = "22.16.0";
const CURRENT_PRINCIPAL_ID_COLUMN = "hellolynk_id";
const CURRENT_STABLE_ID = /^hellolynk:(intl|cn):([a-z0-9][a-z0-9._-]{2,179})$/;
const SENSITIVE_ENVIRONMENT_KEY = /(?:^|_)(?:api_?key|authorization|bearer|cookie|credential|database_url|password|passwd|private_?key|secret|token)(?:_|$)/i;
const BRANDED_SENSITIVE_ENVIRONMENT_KEY = /^(?:hellolynk|lynk)(?:_|$).*(?:authorization|cookie|credential|key|password|secret|token)(?:_|$)/i;
const AMBIENT_CAPABILITY_ENVIRONMENT_KEY = /^(?:AWS_ACCESS_KEY_ID|AWS_SHARED_CREDENTIALS_FILE|AWS_CONFIG_FILE|AWS_WEB_IDENTITY_TOKEN_FILE|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_CERTIFICATE_PATH|SSH_AUTH_SOCK|SSH_AGENT_PID|GIT_ASKPASS|SSH_ASKPASS|NPM_CONFIG_USERCONFIG|NODE_OPTIONS|NODE_PATH|DOCKER_CONFIG|KUBECONFIG|NETRC)$/i;
const BRANDED_RAW_CREDENTIAL = /(?:hellolynk|lynk)_(?:account|account_session|bind|dev_enroll|device|host_transport)_v\d+_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,}/i;
const BRANDED_RAW_HOST_CAPABILITY = /(?:hellolynk|lynk)_host_v\d+_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/i;
const PROFILE_FIELDS = Object.freeze([
  "schemaVersion", "profileId", "baseUrl", "allowLoopbackHttp", "deviceId",
  "credentialId", "principalId", "hellolynkId", "agentId", "delegateId",
  "region", "allowedScopes", "platform", "contract",
]);
const ROUTED_PROFILE_FIELDS = Object.freeze([...PROFILE_FIELDS, "hostId", "authorizationVersion"]);
const CONTACT_CONTAINER_FIELDS = Object.freeze(["schemaVersion", "contractId", "profileId", "contacts"]);
const CONTACT_CONTAINER_FIELDS_V3 = Object.freeze([...CONTACT_CONTAINER_FIELDS, "contactRequestReadDelegateIds"]);
const CONTACT_CONTAINER_FIELDS_V4 = Object.freeze([...CONTACT_CONTAINER_FIELDS_V3, "relationshipSync"]);
const CONTACT_FIELDS = Object.freeze([
  "contactId", "hellolynkId", "displayName", "safetyCode",
  "autonomousSendDelegateIds", "createdAt", "updatedAt",
]);
const CONTACT_FIELDS_WITH_SAFETY_VERIFICATION = Object.freeze([
  ...CONTACT_FIELDS,
  "safetyCodeVerificationState",
]);
const CONTACT_FIELDS_V3 = Object.freeze([
  "contactId", "hellolynkId", "displayName", "principalId", "instances", "safetyCode",
  "safetyCodeVerificationState", "autonomousSendDelegateIds", "continuousReadDelegateIds",
  "createdAt", "updatedAt",
]);
const CONTACT_INSTANCE_FIELDS_V3 = Object.freeze([
  "delegateId", "clientType", "displayName", "createdAt", "updatedAt",
  "autonomousSendDelegateIds", "continuousReadDelegateIds",
]);

function isHelloLynkSensitiveEnvironmentKey(value) {
  const key = String(value || "");
  return SENSITIVE_ENVIRONMENT_KEY.test(key)
    || BRANDED_SENSITIVE_ENVIRONMENT_KEY.test(key)
    || AMBIENT_CAPABILITY_ENVIRONMENT_KEY.test(key);
}

function sanitizeHelloLynkChildEnvironment(source = {}, overrides = {}) {
  const environment = { ...(source || {}), ...(overrides || {}) };
  for (const key of Object.keys(environment)) {
    if (isHelloLynkSensitiveEnvironmentKey(key)) delete environment[key];
  }
  return environment;
}

function standaloneHelloLynkNodeEnvironment(source = {}) {
  const environment = sanitizeHelloLynkChildEnvironment(source);
  for (const key of Object.keys(environment)) {
    if (/^ELECTRON_(?:RUN_AS_NODE|NO_ASAR)$/i.test(key)) delete environment[key];
  }
  // Node versions supporting these opt-ins consume them at startup. Unknown
  // environment variables are harmless on older supported Node releases.
  environment.NODE_USE_ENV_PROXY = "1";
  environment.NODE_USE_SYSTEM_CA = "1";
  const bypass = environment.no_proxy ?? environment.NO_PROXY ?? "";
  environment.NO_PROXY = environment.no_proxy = [bypass, "localhost", "127.0.0.1", "::1"].filter(Boolean).join(",");
  return environment;
}

function helloLynkNetworkErrorCode(error, fallback = "network_request_failed") {
  // Only classify known codes, never expose proxy URLs, credentials or native
  // error messages. This is diagnostic information, not permission to resend.
  const causes = Array.isArray(error?.cause?.errors) ? error.cause.errors : [];
  const codes = [error?.code, error?.cause?.code, ...causes.map((item) => item?.code)];
  if (codes.some((code) => ["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "DEPTH_ZERO_SELF_SIGNED_CERT",
    "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "ERR_TLS_CERT_ALTNAME_INVALID"].includes(code))) return "network_certificate_untrusted";
  if (codes.some((code) => ["ENOTFOUND", "EAI_AGAIN"].includes(code))) return "network_name_resolution_failed";
  if (codes.some((code) => ["ECONNREFUSED", "UND_ERR_PRX_TLS", "UND_ERR_PROXY"].includes(code))) return "network_connection_refused";
  for (const code of ["network_proxy_runtime_unsupported", "network_proxy_configuration_invalid", "network_system_proxy_unavailable"]) {
    if (codes.includes(code)) return code;
  }
  return fallback;
}

async function readHelloLynkWindowsProxy(baseUrl, env) {
  const { execFile } = require("node:child_process");
  const script = "$ErrorActionPreference='Stop'; $u=[Uri]$env:HELLOLYNK_PROXY_DESTINATION; "
    + "$p=[System.Net.Http.HttpClient]::DefaultProxy; "
    + "if(-not $p.IsBypassed($u)){ $v=$p.GetProxy($u); if($v -ne $u){[Console]::Out.Write($v.AbsoluteUri)} }";
  return new Promise((resolve, reject) => {
    execFile("pwsh.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      windowsHide: true, shell: false, timeout: 8_000, maxBuffer: 8192, encoding: "utf8",
      env: sanitizeHelloLynkChildEnvironment(env, { HELLOLYNK_PROXY_DESTINATION: new URL(baseUrl).origin }),
    }, (error, stdout) => error ? reject(codedError("network_system_proxy_unavailable")) : resolve(stdout.trim()));
  });
}

async function prepareHelloLynkNetwork(baseUrl, options = {}) {
  const env = options.env || process.env;
  const http = options.http || require("node:http");
  const tls = options.tls || require("node:tls");
  const platform = options.platform || process.platform;
  const url = new URL(baseUrl);
  // Local IPC never needs system proxy discovery or extra trust roots.
  if (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) return;
  if (typeof tls.getCACertificates === "function" && typeof tls.setDefaultCACertificates === "function") {
    tls.setDefaultCACertificates([...new Set([...tls.getCACertificates("default"), ...tls.getCACertificates("system")])]);
  }
  const proxyEnv = { ...env };
  let systemProxy = false;
  const explicitProxy = env.https_proxy || env.HTTPS_PROXY || env.http_proxy || env.HTTP_PROXY || env.all_proxy || env.ALL_PROXY;
  if (!explicitProxy && platform === "win32") {
    const proxy = await (options.resolveSystemProxy || readHelloLynkWindowsProxy)(baseUrl, env);
    if (proxy) { proxyEnv.HTTPS_PROXY = proxyEnv.HTTP_PROXY = proxy; systemProxy = true; }
  }
  const allProxy = env.all_proxy || env.ALL_PROXY;
  if (allProxy) {
    proxyEnv.HTTP_PROXY = env.http_proxy || env.HTTP_PROXY || allProxy;
    proxyEnv.HTTPS_PROXY = env.https_proxy || env.HTTPS_PROXY || allProxy;
  }
  const proxies = [proxyEnv.https_proxy || proxyEnv.HTTPS_PROXY, proxyEnv.http_proxy || proxyEnv.HTTP_PROXY].filter(Boolean);
  for (const proxy of proxies) {
    try { if (!["http:", "https:"].includes(new URL(proxy).protocol)) throw new Error(); }
    catch { throw codedError("network_proxy_configuration_invalid"); }
  }
  if (!proxies.length) return;
  proxyEnv.NO_PROXY = proxyEnv.no_proxy = [env.no_proxy ?? env.NO_PROXY ?? "", "localhost", "127.0.0.1", "::1"].filter(Boolean).join(",");
  if (typeof http.setGlobalProxyFromEnv === "function") {
    http.setGlobalProxyFromEnv(proxyEnv);
  } else {
    const [major, minor] = String(options.nodeVersion || process.versions.node).split(".").map(Number);
    const startupSupported = major >= 25 || (major === 24 && minor >= 5) || (major === 22 && minor >= 21);
    // Older Node can honor explicit proxy environment at process startup, but
    // cannot apply a discovered Windows proxy without replacing its dispatcher.
    if (systemProxy || allProxy || !startupSupported || env.NODE_USE_ENV_PROXY !== "1") {
      throw codedError("network_proxy_runtime_unsupported");
    }
  }
}

let networkPreparation;
async function helloLynkNetworkFetch(url, options) {
  // These requests run in HelloLynk's standalone CLI/Host. Never replace an
  // Electron client's shared dispatcher if it imports the core for local use.
  if (!process.versions.electron && !["localhost", "127.0.0.1", "[::1]"].includes(new URL(url).hostname)) {
    networkPreparation ??= prepareHelloLynkNetwork(url).catch((error) => { networkPreparation = null; throw error; });
    await networkPreparation;
  }
  options?.signal?.throwIfAborted();
  return globalThis.fetch(url, options);
}

let standaloneNodeSelection = null;

// A shared Host can outlive the client that started it. Running it with an
// Electron executable would keep that client's installation in use after quit.
// Resolve the existing standalone Node; never fall back to the client binary.
async function resolveHelloLynkStandaloneNode(options = {}) {
  const path = require("node:path");
  const fs = require("node:fs/promises");
  const { execFile } = require("node:child_process");
  const runtime = options.runtime || process;
  const platform = runtime.platform || process.platform;
  const paths = platform === "win32" ? path.win32 : path.posix;
  const canonical = (value) => platform === "win32" ? value.toLowerCase() : value;
  const realpath = options.realpath || fs.realpath;
  const env = standaloneHelloLynkNodeEnvironment(options.env || process.env);
  const environmentValue = (name) => Object.entries(env).find(([key]) => key.toLowerCase() === name)?.[1];
  const cacheKey = !options.runtime && !options.probe && !options.realpath
    ? JSON.stringify([runtime.execPath, runtime.versions?.electron, runtime.versions?.bun, options.preferredExecutable, environmentValue("path"),
      environmentValue("programfiles"), environmentValue("programw6432"), environmentValue("localappdata")]) : null;
  if (cacheKey && standaloneNodeSelection?.key === cacheKey) {
    try {
      if (await realpath(standaloneNodeSelection.executable) === standaloneNodeSelection.executable) return standaloneNodeSelection.executable;
    } catch {}
    standaloneNodeSelection = null;
  }
  const selected = (executable) => {
    if (cacheKey) standaloneNodeSelection = { key: cacheKey, executable };
    return executable;
  };
  const candidates = [];
  const add = (value) => {
    if (typeof value === "string" && paths.isAbsolute(value) && !/[\r\n\0]/.test(value)) candidates.push(value);
  };
  let current = null, clientDirectory = null;
  try { current = await realpath(runtime.execPath); } catch {}
  if (current && runtime.versions?.electron) {
    clientDirectory = paths.dirname(current);
    if (platform === "darwin" && paths.basename(clientDirectory) === "MacOS") clientDirectory = paths.dirname(clientDirectory);
  }
  add(options.preferredExecutable);
  if (!runtime.versions?.electron && !runtime.versions?.bun) add(current);
  const searchPath = environmentValue("path");
  for (const directory of String(searchPath || "").split(paths.delimiter)) {
    const clean = directory.trim().replace(/^"(.*)"$/, "$1");
    if (paths.isAbsolute(clean)) add(paths.join(clean, platform === "win32" ? "node.exe" : "node"));
  }
  if (platform === "win32") {
    for (const variable of ["programw6432", "programfiles"]) {
      const directory = environmentValue(variable);
      if (typeof directory === "string" && paths.isAbsolute(directory)) add(paths.join(directory, "nodejs", "node.exe"));
    }
    const local = environmentValue("localappdata");
    if (typeof local === "string" && paths.isAbsolute(local)) add(paths.join(local, "Programs", "nodejs", "node.exe"));
  }
  const probe = options.probe || ((executable) => new Promise((resolve, reject) => {
    execFile(executable, ["--eval", "process.stdout.write(JSON.stringify({execPath:process.execPath,node:process.versions.node,electron:process.versions.electron,bun:process.versions.bun,release:process.release.name}))"], {
      env, windowsHide: true, shell: false, encoding: "utf8", timeout: 5_000, maxBuffer: 4 * 1024,
    }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
  }));
  const seen = new Set();
  const outsideClient = (file) => !clientDirectory || (canonical(file) !== canonical(current)
    && !canonical(file).startsWith(canonical(clientDirectory + paths.sep)));
  const clientRuntime = async (file) => {
    // A separate node.exe inside a client's runtime cache is still owned by
    // that client's updater. Electron's resources may contain such a binary.
    if (/[\\/]\.cache[\\/]codex-runtimes[\\/]|[\\/]OpenAI[\\/]Codex[\\/]runtimes[\\/]/i.test(file)) return true;
    const resources = /[\\/]resources[\\/]/ig;
    for (const match of file.matchAll(resources)) {
      const root = file.slice(0, match.index + match[0].length);
      for (const marker of ["app.asar", paths.join("app", "package.json")]) {
        if (await fs.stat(paths.join(root, marker)).then(stat => stat.isFile(), () => false)) return true;
      }
    }
    return false;
  };
  for (const candidate of candidates) {
    try {
      const executable = await realpath(candidate);
      if (seen.has(canonical(executable))) continue;
      seen.add(canonical(executable));
      if (!outsideClient(executable) || !/^node(?:\.exe)?$/i.test(paths.basename(executable)) || await clientRuntime(executable)) continue;
      if (current && canonical(executable) === canonical(current)
        && !runtime.versions?.electron && !runtime.versions?.bun && runtime.release?.name === "node") {
        assertHelloLynkClientNodeVersion(runtime.versions.node);
        return selected(executable);
      }
      const result = await probe(executable, env);
      if (result?.electron || result?.bun || result?.release !== "node") continue;
      assertHelloLynkClientNodeVersion(result.node);
      const actual = await realpath(result.execPath);
      if (!outsideClient(actual) || !/^node(?:\.exe)?$/i.test(paths.basename(actual)) || await clientRuntime(actual)) continue;
      return selected(actual);
    } catch { /* Missing, outdated or embedded runtimes cannot host this background. */ }
  }
  const error = codedError("hellolynk_node_22_16_required");
  error.message = `HelloLynk 后台需要本机独立安装的 Node.js ${HELLOLYNK_MINIMUM_CLIENT_NODE} 或更高版本`;
  throw error;
}

function containsHelloLynkCredentialMaterial(value) {
  const text = String(value || "");
  return BRANDED_RAW_CREDENTIAL.test(text) || BRANDED_RAW_HOST_CAPABILITY.test(text);
}

function classifyHelloLynkStableId(value) {
  const text = String(value || "");
  const current = CURRENT_STABLE_ID.exec(text);
  if (!current) return null;
  return Object.freeze({
    kind: "current",
    value: text,
    region: current[1],
    localPart: current[2],
    aliasKey: `${current[1]}:${current[2]}`,
  });
}

function helloLynkStableIdMatchesRegion(identityOrValue, regionValue) {
  const identity = typeof identityOrValue === "string"
    ? classifyHelloLynkStableId(identityOrValue)
    : identityOrValue;
  if (!identity) return false;
  const region = String(regionValue || "").trim().toLowerCase();
  const canonicalRegion = region === "international" || region === "intl" ? "intl" : region;
  return canonicalRegion === identity.region;
}

function isHelloLynkStableIdReservedText(value) {
  return String(value ?? "").normalize("NFKC").trim().toLowerCase().startsWith("hellolynk:");
}

function normalizeHelloLynkClientProfileContainer(value) {
  if (!isPlainObject(value)) throw codedError("client_profile_invalid");
  const schemaVersion = Number(value.schemaVersion);
  if (![1, 2].includes(schemaVersion)) throw codedError("client_profile_schema_unsupported");
  if (value.contract !== HELLOLYNK_CLIENT_PROFILE_CONTRACT || !Object.hasOwn(value, "hellolynkId")) {
    throw codedError("client_profile_contract_invalid");
  }
  if (schemaVersion === 2 && ["delegateId", "hostId", "authorizationVersion"].some(
    (field) => !Object.hasOwn(value, field),
  )) throw codedError("client_profile_route_binding_invalid");
  assertExactFields(value, schemaVersion === 2 ? ROUTED_PROFILE_FIELDS : PROFILE_FIELDS);
  return Object.freeze({ value: { ...value }, migrated: false });
}

function normalizeHelloLynkContactsContainer(value, expectedProfileId) {
  if (!isPlainObject(value)) throw codedError("contact_store_invalid");
  const schemaVersion = Number(value.schemaVersion);
  if (![2, 3, 4].includes(schemaVersion)) throw codedError("contact_store_invalid");
  assertExactFields(value, schemaVersion === 4 ? CONTACT_CONTAINER_FIELDS_V4
    : schemaVersion === 3 ? CONTACT_CONTAINER_FIELDS_V3 : CONTACT_CONTAINER_FIELDS,
    "contact_store_invalid");
  if (schemaVersion === 4) normalizeHelloLynkRelationshipSync(value.relationshipSync);
  if (value.contractId !== HELLOLYNK_CONTACTS_CONTRACT
    || value.profileId !== expectedProfileId || !Array.isArray(value.contacts)) {
    throw codedError("contact_store_invalid");
  }
  for (const contact of value.contacts) {
    if (!isPlainObject(contact)) throw codedError("contact_store_invalid");
    if (schemaVersion >= 3) {
      assertExactFields(contact, CONTACT_FIELDS_V3, "contact_store_invalid");
      if (!Array.isArray(contact.instances)) throw codedError("contact_store_invalid");
      for (const instance of contact.instances) {
        if (!isPlainObject(instance)) throw codedError("contact_store_invalid");
        assertExactFields(instance, [...CONTACT_INSTANCE_FIELDS_V3,
          ...(Object.hasOwn(instance, "continuousReadAfterSeq") ? ["continuousReadAfterSeq"] : [])], "contact_store_invalid");
        if (Object.hasOwn(instance, "continuousReadAfterSeq")) {
          if (!Array.isArray(instance.continuousReadAfterSeq) || instance.continuousReadAfterSeq.length > 32) {
            throw codedError("contact_store_invalid");
          }
          const seen = new Set();
          for (const entry of instance.continuousReadAfterSeq) {
            assertExactFields(entry, ["delegateId", "afterSeq"], "contact_store_invalid");
            if (typeof entry.delegateId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(entry.delegateId)
              || seen.has(entry.delegateId) || !instance.continuousReadDelegateIds?.includes(entry.delegateId)
              || (entry.afterSeq !== null && (!Number.isSafeInteger(entry.afterSeq) || entry.afterSeq < 0))) {
              throw codedError("contact_store_invalid");
            }
            seen.add(entry.delegateId);
          }
        }
      }
    } else {
      assertExactFields(
        contact,
        Object.hasOwn(contact, "safetyCodeVerificationState")
          ? CONTACT_FIELDS_WITH_SAFETY_VERIFICATION
          : CONTACT_FIELDS,
        "contact_store_invalid",
      );
    }
  }
  return Object.freeze({ value, migrated: false, source: "current" });
}

function normalizeHelloLynkRelationshipSync(value) {
  const invalid = () => { throw codedError("contact_store_invalid"); };
  if (!isPlainObject(value)) invalid();
  assertExactFields(value, ["owner", "generations", "pendingDeletedHelloLynkIds"], "contact_store_invalid");
  if (!Array.isArray(value.generations) || !Array.isArray(value.pendingDeletedHelloLynkIds)
    || value.generations.length + value.pendingDeletedHelloLynkIds.length > 2000) invalid();
  let owner = null;
  if (value.owner !== null) {
    if (!isPlainObject(value.owner)) invalid();
    assertExactFields(value.owner, ["principalId", "hellolynkId"], "contact_store_invalid");
    if (typeof value.owner.principalId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/.test(value.owner.principalId)) invalid();
    owner = classifyHelloLynkStableId(value.owner.hellolynkId);
    if (!owner) invalid();
  } else if (value.generations.length) invalid();
  const validatePeer = (peerId) => {
    if (typeof peerId !== "string") invalid();
    const peer = classifyHelloLynkStableId(peerId);
    if (!peer || (owner && (peer.region !== owner.region || peer.aliasKey === owner.aliasKey))) invalid();
  };
  const relationshipIds = new Set();
  const generationPeers = new Set();
  for (const generation of value.generations) {
    if (!isPlainObject(generation)) invalid();
    assertExactFields(generation, ["relationshipId", "hellolynkId", "suppressed"], "contact_store_invalid");
    if (typeof generation.relationshipId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/.test(generation.relationshipId)
      || typeof generation.suppressed !== "boolean" || relationshipIds.has(generation.relationshipId)) invalid();
    validatePeer(generation.hellolynkId);
    relationshipIds.add(generation.relationshipId);
    generationPeers.add(generation.hellolynkId);
  }
  const pending = new Set();
  for (const peer of value.pendingDeletedHelloLynkIds) {
    validatePeer(peer);
    if (pending.has(peer) || generationPeers.has(peer)) invalid();
    pending.add(peer);
  }
  return value;
}

function assertExactFields(value, fields, code = "client_profile_fields_invalid") {
  const expected = [...fields].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw codedError(code);
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function codedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function assertHelloLynkClientNodeVersion(version = process.versions.node) {
  const parts = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(version || ""));
  const supported = parts && (Number(parts[1]) > 22
    || (Number(parts[1]) === 22 && Number(parts[2]) >= 16));
  if (!supported) {
    const error = codedError("hellolynk_node_22_16_required");
    error.message = `HelloLynk 本地客户端需要 Node.js ${HELLOLYNK_MINIMUM_CLIENT_NODE} 或更高版本（当前 ${String(version || "unknown")}）`;
    throw error;
  }
}

// A clean Windows 11 ships Windows PowerShell 5.1 only; the protected stores, the Host launch and the
// human confirmation window need PowerShell 7 (pwsh). Probe it once per process and report a stable code
// instead of letting a missing pwsh surface later as an unrelated Host bootstrap failure.
let powerShell7Verdict;

function probePowerShell7() {
  const { spawnSync } = require("node:child_process");
  const result = spawnSync("pwsh.exe", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"],
    { encoding: "utf8", windowsHide: true, shell: false, timeout: 5000 });
  if (result.error?.code === "ENOENT") return "missing";
  // A slow or odd answer does not prove pwsh is absent; the real call will report its own error.
  if (result.error || result.status !== 0) return "unknown";
  const major = Number.parseInt(String(result.stdout || "").trim(), 10);
  return Number.isSafeInteger(major) && major >= 7 ? "ok" : "missing";
}

function assertHelloLynkPowerShell7(options = {}) {
  if ((options.platform ?? process.platform) !== "win32") return;
  const injected = typeof options.probe === "function";
  const verdict = injected ? options.probe() : (powerShell7Verdict ??= probePowerShell7());
  if (verdict === "missing") {
    const error = codedError("powershell7_missing");
    error.message = "这台电脑没有 PowerShell 7（pwsh），HelloLynk 需要它。请安装 PowerShell 7 后重新打开客户端。";
    throw error;
  }
}

module.exports = Object.freeze({
  HELLOLYNK_MINIMUM_CLIENT_NODE,
  assertHelloLynkClientNodeVersion,
  assertHelloLynkPowerShell7,
  CURRENT_PRINCIPAL_ID_COLUMN,
  HELLOLYNK_CLIENT_PROFILE_CONTRACT,
  HELLOLYNK_CONTACTS_CONTRACT,
  classifyHelloLynkStableId,
  helloLynkStableIdMatchesRegion,
  containsHelloLynkCredentialMaterial,
  isHelloLynkStableIdReservedText,
  isHelloLynkSensitiveEnvironmentKey,
  normalizeHelloLynkClientProfileContainer,
  normalizeHelloLynkContactsContainer,
  normalizeHelloLynkRelationshipSync,
  sanitizeHelloLynkChildEnvironment,
  standaloneHelloLynkNodeEnvironment,
  helloLynkNetworkFetch,
  helloLynkNetworkErrorCode,
  prepareHelloLynkNetwork,
  resolveHelloLynkStandaloneNode,
});
