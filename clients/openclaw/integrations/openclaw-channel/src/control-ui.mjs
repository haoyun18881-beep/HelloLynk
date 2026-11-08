import path from "node:path";
import { workbenchConnectionError } from "../../../clients/core/hellolynk-workbench-connection.mjs";
import {
  HELLOLYNK_WORKBENCH_COMMAND_CONTRACT,
  HELLOLYNK_WORKBENCH_RESULT_CONTRACT,
  HELLOLYNK_WORKBENCH_SCHEMA_VERSION,
  HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT,
  HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION,
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
  validateWorkbenchSnapshot,
} from "../../../clients/workbench/contract.mjs";

const PANEL_BASE_PATH = "/plugins/hellolynk/inbox";
const WORKBENCH_CANDIDATE_PATH = "/plugins/hellolynk/workbench-candidate";
const ACTION_GRANT = /^[A-Za-z0-9._~-]{32,512}$/;
const F3_SHARED_CONTRACT_AVAILABLE = HELLOLYNK_WORKBENCH_SNAPSHOT_CONTRACT === "hellolynk-workbench-snapshot-v12"
  && HELLOLYNK_WORKBENCH_SNAPSHOT_SCHEMA_VERSION === 12
  && HELLOLYNK_WORKBENCH_COMMAND_CONTRACT === "hellolynk-workbench-command-v6"
  && HELLOLYNK_WORKBENCH_RESULT_CONTRACT === "hellolynk-workbench-command-result-v6"
  && HELLOLYNK_WORKBENCH_SCHEMA_VERSION === 6;

export function registerHelloLynkWorkbenchControlUi(api, options = {}) {
  if (api?.registrationMode !== "full") return false;
  const workbenchProvider = options.workbenchProvider;
  if (typeof workbenchProvider !== "function") {
    throw codeError("openclaw_workbench_provider_required");
  }
  const controls = api?.session?.controls;
  if (typeof controls?.registerControlUiDescriptor !== "function") {
    throw codeError("openclaw_control_ui_descriptor_api_unavailable");
  }
  if (typeof api.registerHttpRoute !== "function") {
    throw codeError("openclaw_http_route_api_unavailable");
  }

  controls.registerControlUiDescriptor({
    surface: "tab",
    id: "hellolynk-inbox",
    label: "HelloLynk 通讯",
    description: "本地消息与联系人界面；共享 Host 权限、安全与设置合同",
    icon: "message-circle",
    path: PANEL_BASE_PATH,
    group: "agent",
    order: 86,
    requiredScopes: ["operator.read"],
  });
  api.registerHttpRoute({
    path: PANEL_BASE_PATH,
    auth: "gateway",
    match: "prefix",
    handler: createWorkbenchCandidateRedirectHandler(
      workbenchProvider,
      PANEL_BASE_PATH,
      "openclaw_workbench_unavailable",
    ),
  });
  // Native browser pages use the authenticated host bridge. The generic
  // external-tab sandbox has an opaque origin and cannot run our cookie-based
  // loopback UI. Do not relax its CORS or copy Gateway credentials into it.
  if (typeof api.registerGatewayMethod === "function") {
    api.registerGatewayMethod("hellolynk.workbench.open", async ({ params, client, respond }) => {
      try {
        if (!params || Object.keys(params).length !== 0) throw codeError("openclaw_workbench_input_invalid");
        const browser = client?.browserOrigin;
        if (browser?.isLocalClient !== true || !browser.origin || !browser.requestHost) {
          throw codeError("openclaw_workbench_local_browser_required");
        }
        const parent = assertGatewayOrigin(browser.origin);
        if (parent.host !== browser.requestHost) throw codeError("openclaw_workbench_gateway_origin_invalid");
        const candidate = validateWorkbenchCandidate(await workbenchProvider({ gatewayOrigin: parent.origin }));
        const armed = await candidate.armNavigation();
        if (armed?.cleanUrl !== candidate.cleanUrl || !Number.isSafeInteger(armed.expiresAtMs)
          || armed.expiresAtMs <= Date.now()) throw codeError("openclaw_workbench_candidate_rearm_invalid");
        respond(true, { url: armed.cleanUrl }, undefined);
      } catch (error) {
        respond(false, undefined, { code: "UNAVAILABLE", message: "HelloLynk page unavailable",
          details: { reason: /^openclaw_workbench_[a-z_]+$/.test(error?.code || "")
            ? error.code : "openclaw_workbench_unavailable" } });
      }
    }, { scope: "operator.write" });
  }
  return true;
}

export function createOpenClawWorkbenchAdapterFacade(adapter) {
  if (!adapter || typeof adapter.readWorkbenchSnapshot !== "function") {
    throw codeError("openclaw_workbench_host_adapter_invalid");
  }
  const hostOwnsActionGrantPair = F3_SHARED_CONTRACT_AVAILABLE
    && typeof adapter.issueWorkbenchActionGrant === "function"
    && adapter.issueWorkbenchActionGrant.length >= 1
    && typeof adapter.executeWorkbenchCommand === "function"
    && adapter.executeWorkbenchCommand.length >= 2;
  const facade = {
    async readSnapshot(input = {}) {
      try { return validateWorkbenchSnapshot(await adapter.readWorkbenchSnapshot(input)); }
      catch (error) { throw workbenchConnectionError(error); }
    },
  };
  if (typeof adapter.readWorkbenchChanges === "function") {
    facade.readChanges = (input) => adapter.readWorkbenchChanges(input);
  }
  if (hostOwnsActionGrantPair) {
    facade.issueActionGrant = async (command) => {
      const validated = validateWorkbenchCommand(command);
      return exactActionGrantEnvelope(await adapter.issueWorkbenchActionGrant(validated));
    };
    facade.executeCommand = async (command, context) => {
      const validated = validateWorkbenchCommand(command);
      const normalizedContext = validated.command === "message.send-status"
        ? exactEmptyContext(context)
        : exactActionGrantContext(context);
      return validateWorkbenchCommandResult(
        await adapter.executeWorkbenchCommand(validated, normalizedContext),
        validated.command,
      );
    };
  }
  return Object.freeze(facade);
}

function exactActionGrantEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, "actionGrant")
    || typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError("openclaw_workbench_action_grant_invalid");
  }
  return Object.freeze({ actionGrant: value.actionGrant });
}

function exactActionGrantContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, "actionGrant")
    || typeof value.actionGrant !== "string" || !ACTION_GRANT.test(value.actionGrant)) {
    throw codeError("openclaw_workbench_action_grant_required");
  }
  return Object.freeze({ actionGrant: value.actionGrant });
}

function exactEmptyContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).length !== 0) {
    throw codeError("openclaw_workbench_action_grant_invalid");
  }
  return Object.freeze({});
}

export function createOpenClawWorkbenchRuntime(options = {}) {
  return createOpenClawWorkbenchRuntimeInternal(
    options,
    "hellolynk-openclaw-workbench",
    "openclaw_workbench_not_started",
    true,
  );
}

export function resolveOpenClawWorkbenchParentOrigin(config) {
  const gateway = config?.gateway;
  // Saved configuration is a fallback for callers outside the HTTP route.
  // The route derives the actual origin from its authenticated Gateway request.
  if (gateway?.port === undefined || (gateway.bind !== undefined && gateway.bind !== "loopback")
    || gateway.tls?.enabled === true) return null;
  if (!Number.isSafeInteger(gateway.port) || gateway.port < 1 || gateway.port > 65_535) {
    throw codeError("openclaw_workbench_gateway_port_invalid");
  }
  return new URL(`http://localhost:${gateway.port}`).origin;
}

export function createOpenClawWorkbenchCandidateRuntime(options = {}) {
  return createOpenClawWorkbenchRuntimeInternal(
    options,
    "hellolynk-openclaw-workbench-candidate",
    "openclaw_workbench_candidate_not_started",
    false,
  );
}

function createOpenClawWorkbenchRuntimeInternal(
  options,
  serviceId,
  notStartedCode,
  bootstrapOnProvider,
) {
  if (typeof options.adapterProvider !== "function") {
    throw codeError("openclaw_workbench_adapter_provider_required");
  }
  let adapter = null;
  const candidates = new Map();
  const bootstrapPromises = new Map();
  let adapterPromise = null;
  let serviceStarted = false;

  async function bootstrap(parentOrigin = options.trustedParentOrigin ?? null) {
    const key = parentOrigin || "standalone";
    if (candidates.has(key)) return candidates.get(key);
    if (!bootstrapPromises.has(key)) {
      const pending = (async () => {
        adapterPromise ||= Promise.resolve().then(options.adapterProvider);
        try { adapter = await adapterPromise; }
        catch (error) { adapterPromise = null; throw error; }
        const { bootstrapWorkbenchCandidate, workbenchRoot } = await loadWorkbenchCandidateBootstrap(options.releaseRoot);
        const started = await bootstrapWorkbenchCandidate("openclaw", {
          adapter: createOpenClawWorkbenchAdapterFacade(adapter),
          workbenchRoot,
          connectAccount: options.connectAccount,
          ...(options.port === undefined ? {} : { port: options.port }),
          ...(options.pagePath === undefined ? {} : { pagePath: options.pagePath }),
          allowSameSiteTopLevelNavigation: true,
          trustedParentOrigin: parentOrigin,
        });
        candidates.set(key, started);
        return started;
      })();
      bootstrapPromises.set(key, pending);
    }
    try {
      return await bootstrapPromises.get(key);
    } finally {
      bootstrapPromises.delete(key);
    }
  }

  async function start() {
    serviceStarted = true;
    if (bootstrapOnProvider) return undefined;
    try {
      return await bootstrap();
    } catch (error) {
      serviceStarted = false;
      throw error;
    }
  }

  async function stop() {
    serviceStarted = false;
    await Promise.allSettled([...bootstrapPromises.values()]);
    const current = [...candidates.values()];
    candidates.clear();
    bootstrapPromises.clear();
    const currentAdapter = adapter;
    adapter = null;
    adapterPromise = null;
    try {
      await Promise.all(current.map((candidate) => candidate.close()));
    } finally {
      if (currentAdapter && typeof currentAdapter.close === "function") await currentAdapter.close();
    }
  }

  const workbenchProvider = async (context = {}) => {
    if (!serviceStarted) throw codeError(notStartedCode);
    // This hint comes only from our authenticated Gateway HTTP route. It uses
    // the actual listener port and request hostname, independent of the page
    // path, query, default port, or a CLI override of the saved Gateway port.
    const parentOrigin = context.gatewayOrigin ?? options.trustedParentOrigin ?? null;
    if (parentOrigin != null) assertGatewayOrigin(parentOrigin);
    if (candidates.size + bootstrapPromises.size >= 3
      && !candidates.has(parentOrigin || "standalone") && !bootstrapPromises.has(parentOrigin || "standalone")) {
      throw codeError("openclaw_workbench_gateway_origin_invalid");
    }
    const current = bootstrapOnProvider || context.gatewayOrigin
      ? await bootstrap(parentOrigin)
      : candidates.get(parentOrigin || "standalone");
    if (!serviceStarted || !current) throw codeError(notStartedCode);
    return Object.freeze({
      cleanUrl: current.cleanUrl,
      armNavigation: () => current.surface.armNavigation(),
    });
  };
  return Object.freeze({
    workbenchProvider,
    candidateProvider: workbenchProvider,
    service: Object.freeze({
      id: serviceId,
      start,
      stop,
    }),
  });
}

async function loadWorkbenchCandidateBootstrap(releaseRoot) {
  for (const [specifier, relativeRoot] of [
    ["../../../clients/workbench/candidate-bootstrap.mjs", "clients/workbench"],
    ["../../../runtime/workbench/candidate-bootstrap.mjs", "runtime/workbench"],
  ]) {
    try {
      const loaded = await import(specifier);
      if (typeof loaded.bootstrapWorkbenchCandidate === "function") {
        return {
          bootstrapWorkbenchCandidate: loaded.bootstrapWorkbenchCandidate,
          workbenchRoot: releaseRoot ? path.join(releaseRoot, relativeRoot) : undefined,
        };
      }
    } catch (error) {
      if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
    }
  }
  throw codeError("openclaw_workbench_runtime_unavailable");
}

function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function validateWorkbenchCandidate(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "armNavigation,cleanUrl"
    || typeof value.armNavigation !== "function") {
    throw new Error("openclaw_workbench_candidate_invalid");
  }
  const url = new URL(String(value.cleanUrl || ""));
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(url.hostname) || Number(url.port || 80) < 1
    || url.pathname !== "/workbench" || url.search || url.hash || url.username || url.password) {
    throw new Error("openclaw_workbench_candidate_url_invalid");
  }
  return Object.freeze({
    cleanUrl: url.href.replace(/\/$/, ""),
    armNavigation: value.armNavigation,
  });
}

function createWorkbenchCandidateRedirectHandler(
  candidateProvider,
  routePath = WORKBENCH_CANDIDATE_PATH,
  unavailableCode = "openclaw_workbench_candidate_unavailable",
) {
  return async (req, res) => {
    const url = new URL(req.url || WORKBENCH_CANDIDATE_PATH, "http://127.0.0.1");
    const pathname = url.pathname.replace(/\/+$/, "") || "/";
    if (String(req.method || "GET").toUpperCase() !== "GET" || pathname !== routePath) {
      res.statusCode = 404;
      res.setHeader("cache-control", "no-store");
      res.end();
      return true;
    }
    if (req.headers?.["sec-fetch-dest"] === "iframe") {
      // The host's default external-tab sandbox omits allow-same-origin.
      // Explain the official native-page prerequisite instead of consuming a
      // loopback navigation and leaving a broken frame behind.
      send(res, 200, "text/html; charset=utf-8", "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>HelloLynk</title><body><h2>HelloLynk 通讯</h2><p>要在这里显示 HelloLynk，请打开 设置 → Labs → Custom plugin UI，开启后重新点左侧“HelloLynk 通讯”。也可以直接对 AI 说「打开 HelloLynk」。</p><p>To show HelloLynk here, enable Settings → Labs → Custom plugin UI, then click “HelloLynk 通讯” in the left sidebar again. You can also ask your AI to open HelloLynk.</p></body></html>");
      return true;
    }
    let candidate;
    try {
      candidate = validateWorkbenchCandidate(await candidateProvider(gatewayRequestContext(req)));
    } catch {
      sendJson(res, 503, { ok: false, error: unavailableCode });
      return true;
    }
    let armed;
    try {
      armed = await candidate.armNavigation();
    } catch {
      sendJson(res, 503, { ok: false, error: unavailableCode });
      return true;
    }
    if (!armed || typeof armed !== "object" || Array.isArray(armed)
      || armed.cleanUrl !== candidate.cleanUrl
      || !Number.isSafeInteger(armed.expiresAtMs) || armed.expiresAtMs <= Date.now()) {
      throw new Error("openclaw_workbench_candidate_rearm_invalid");
    }
    res.statusCode = 302;
    res.setHeader("location", armed.cleanUrl);
    res.setHeader("cache-control", "no-store");
    res.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'self'; base-uri 'none'");
    res.setHeader("referrer-policy", req.headers?.["sec-fetch-dest"] === "iframe" ? "origin" : "no-referrer");
    res.end();
    return true;
  };
}

function assertGatewayOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw codeError("openclaw_workbench_gateway_origin_invalid"); }
  if (url.protocol !== "http:" || !["localhost", "127.0.0.1"].includes(url.hostname)
    || url.username || url.password || url.origin !== value) {
    throw codeError("openclaw_workbench_gateway_origin_invalid");
  }
  return url;
}

function gatewayRequestContext(req) {
  if (!req.headers?.host) return {};
  const url = new URL(`http://${req.headers.host}`);
  assertGatewayOrigin(url.origin);
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash
    || (req.socket?.localPort != null && Number(url.port || 80) !== req.socket.localPort)
    || req.socket?.encrypted === true) {
    throw codeError("openclaw_workbench_gateway_origin_invalid");
  }
  return { gatewayOrigin: url.origin };
}

function send(res, statusCode, contentType, body) {
  res.statusCode = statusCode;
  res.setHeader("content-type", contentType);
  res.setHeader("cache-control", "no-store");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("content-security-policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'self'; base-uri 'none'");
  res.end(body);
}

function sendJson(res, statusCode, value) {
  send(res, statusCode, "application/json; charset=utf-8", JSON.stringify(value));
}
