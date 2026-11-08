export const HELLOLYNK_WORKBENCH_REAL_TRANSPORTS = Object.freeze(["mcp-app-rpc", "loopback-http"]);

export const HELLOLYNK_WORKBENCH_HOST_CAPABILITIES = deepFreeze({
  codex: {
    candidateVersion: "0.1.7",
    container: "mcp-app",
    transport: "mcp-app-rpc",
    launch: "embedded-resource",
    iframeRequired: false,
    sameOriginRequired: false,
    keyboard: "host-forwarded",
    ime: "browser-engine",
    lifecycle: "mcp-resource",
    fallback: "safe-loopback-deep-link",
  },
  openclaw: {
    candidateVersion: "0.1.9",
    container: "gateway-control-ui",
    transport: "loopback-http",
    launch: "gateway-authenticated-exact-parent-frame",
    pagePath: "/workbench",
    iframeRequired: true,
    sameOriginRequired: false,
    keyboard: "browser-native",
    ime: "browser-native",
    lifecycle: "gateway-session",
    fallback: "safe-loopback-deep-link",
  },
  "trae-work": {
    candidateVersion: "0.3.9",
    container: "open-preview",
    transport: "loopback-http",
    launch: "secure-top-level-preview",
    pagePath: "/inbox",
    iframeRequired: false,
    sameOriginRequired: true,
    keyboard: "browser-native",
    ime: "browser-native",
    lifecycle: "armed-local-session",
    fallback: "safe-loopback-deep-link",
  },
  workbuddy: {
    candidateVersion: "0.2.9",
    container: "local-web",
    transport: "loopback-http",
    launch: "secure-top-level-local-web",
    pagePath: "/inbox",
    iframeRequired: false,
    sameOriginRequired: true,
    keyboard: "browser-native",
    ime: "browser-native",
    lifecycle: "armed-local-session",
    fallback: "safe-loopback-deep-link",
  },
  "claude-code": {
    candidateVersion: "0.1.0",
    container: "local-web",
    transport: "loopback-http",
    launch: "secure-top-level-local-web",
    pagePath: "/inbox",
    iframeRequired: false,
    sameOriginRequired: true,
    keyboard: "browser-native",
    ime: "browser-native",
    lifecycle: "armed-local-session",
    fallback: "safe-loopback-deep-link",
  },
});

export function workbenchLaunchPlan(host) {
  const plan = HELLOLYNK_WORKBENCH_HOST_CAPABILITIES[String(host || "").toLowerCase()];
  if (!plan) throw new Error("workbench_host_unsupported");
  return plan;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
