// MCP Apps use JSON-RPC over postMessage for both initialization and calls back
// to their MCP server. Keeping the entire Workbench on this one channel avoids
// losing app-only `_meta` when a host also exposes an older compatibility API.
export function createStandardMcpAppClient(appWindow, options = {}) {
  const positiveTimeout = (value, fallback) => Number.isSafeInteger(value) && value > 0 ? value : fallback;
  const DEFAULT_MCP_BRIDGE_TIMEOUT_MS = 10_000;
  const DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS = 60_000;
  const MCP_APP_PROTOCOL_VERSION = "2026-01-26";
  if (!appWindow || !appWindow.parent || appWindow.parent === appWindow
    || typeof appWindow.parent.postMessage !== "function"
    || typeof appWindow.addEventListener !== "function") {
    throw new Error("workbench_mcp_app_bridge_required");
  }
  const bridgeTimeoutMs = positiveTimeout(options.bridgeTimeoutMs, DEFAULT_MCP_BRIDGE_TIMEOUT_MS);
  const parent = appWindow.parent;
  const pending = new Map();
  const hostContextListeners = new Set();
  const toolResultListeners = new Set();
  let requestSequence = 0;
  let connected = null;
  let closed = false;

  function post(message) {
    if (closed) throw new Error("workbench_mcp_app_bridge_closed");
    parent.postMessage(message, "*");
  }

  function notify(method, params) {
    post({
      jsonrpc: "2.0",
      method,
      ...(params === undefined ? {} : { params }),
    });
  }

  function request(method, params, timeoutMs = bridgeTimeoutMs) {
    if (closed) return Promise.reject(new Error("workbench_mcp_app_bridge_closed"));
    const id = `hellolynk-workbench-${Date.now()}-${++requestSequence}`;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        const error = new Error("workbench_mcp_app_bridge_timeout");
        error.code = "workbench_mcp_app_bridge_timeout";
        reject(error);
      }, timeoutMs);
      pending.set(id, { resolve, reject, timeout });
      try {
        post({ jsonrpc: "2.0", id, method, params });
      } catch (error) {
        clearTimeout(timeout);
        pending.delete(id);
        reject(error);
      }
    });
  }

  function onMessage(event) {
    if (event.source !== parent) return;
    const message = event.data;
    if (message?.jsonrpc !== "2.0") return;
    if (!Object.hasOwn(message, "id")) {
      if (message.method === "ui/notifications/tool-result") {
        for (const listener of toolResultListeners) listener(message.params);
      }
      if (message.method === "ui/notifications/host-context-changed"
        && message.params && typeof message.params === "object" && !Array.isArray(message.params)) {
        for (const listener of hostContextListeners) listener(message.params);
      }
      return;
    }
    if (message.method) return;
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    clearTimeout(entry.timeout);
    if (message.error) {
      const code = message.error?.data?.code || message.error?.code || "workbench_mcp_app_bridge_error";
      const error = new Error(String(message.error?.message || code));
      error.code = code;
      entry.reject(error);
      return;
    }
    if (!Object.hasOwn(message, "result")) {
      const error = new Error("workbench_mcp_app_bridge_response_invalid");
      error.code = "workbench_mcp_app_bridge_response_invalid";
      entry.reject(error);
      return;
    }
    entry.resolve(message.result);
  }

  appWindow.addEventListener("message", onMessage);

  async function connect() {
    if (connected) return connected;
    const attempt = request("ui/initialize", {
      appInfo: options.appInfo || { name: "HelloLynk Workbench", version: "2" },
      appCapabilities: {},
      protocolVersion: MCP_APP_PROTOCOL_VERSION,
    }).then((result) => {
      if (!result || typeof result !== "object" || Array.isArray(result)) {
        throw new Error("workbench_mcp_app_initialize_invalid");
      }
      notify("ui/notifications/initialized");
      return result;
    });
    connected = attempt.catch((error) => {
      connected = null;
      throw error;
    });
    return connected;
  }

  return Object.freeze({
    async connect() {
      return connect();
    },
    async callTool(name, args = {}, timeoutMs = DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS) {
      await connect();
      return request("tools/call", { name, arguments: args }, timeoutMs);
    },
    async openLink(url) {
      const session = await connect();
      if (!session?.hostCapabilities?.openLinks) {
        throw new Error("workbench_mcp_open_link_unavailable");
      }
      return request("ui/open-link", { url });
    },
    notify,
    onToolResult(listener) {
      toolResultListeners.add(listener);
      return () => toolResultListeners.delete(listener);
    },
    onHostContextChanged(listener) {
      hostContextListeners.add(listener);
      return () => hostContextListeners.delete(listener);
    },
    close() {
      if (closed) return;
      closed = true;
      appWindow.removeEventListener?.("message", onMessage);
      for (const entry of pending.values()) {
        clearTimeout(entry.timeout);
        entry.reject(new Error("workbench_mcp_app_bridge_closed"));
      }
      pending.clear();
      hostContextListeners.clear();
      toolResultListeners.clear();
    },
  });
}
