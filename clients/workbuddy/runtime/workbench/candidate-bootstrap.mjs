import { workbenchLaunchPlan } from "./host-capabilities.mjs";
import { createWorkbenchLoopbackSurface } from "./loopback-surface.mjs";
import { composeWorkbenchMcpAppHtml } from "./mcp-app-bundle.mjs";

export async function bootstrapWorkbenchCandidate(host, options = {}) {
  const plan = workbenchLaunchPlan(host);
  if (plan.transport === "mcp-app-rpc") {
    const bundle = await composeWorkbenchMcpAppHtml({ withManifest: true });
    const resourceUri = options.resourceUri || "ui://hellolynk/workbench-phase-c-candidate.html";
    if (!/^ui:\/\/hellolynk\/[a-z0-9][a-z0-9._/-]{1,120}\.html$/.test(resourceUri)) {
      throw new Error("workbench_candidate_resource_uri_invalid");
    }
    return Object.freeze({
      host,
      plan,
      kind: "mcp-app-resource",
      resourceUri,
      html: bundle.html,
      manifest: bundle.manifest,
      close: async () => {},
    });
  }
  if (plan.transport !== "loopback-http") throw new Error("workbench_candidate_transport_unsupported");
  if (options.trustedParentOrigin != null && host !== "openclaw") {
    throw new Error("workbench_candidate_parent_origin_host_invalid");
  }
  if (!options.adapter || typeof options.adapter.readSnapshot !== "function") {
    throw new Error("workbench_candidate_read_adapter_required");
  }
  const surface = createWorkbenchLoopbackSurface({
    adapter: options.adapter,
    workbenchRoot: options.workbenchRoot,
    connectAccount: options.connectAccount,
    readAccountState: options.readAccountState || options.connectAccount?.readAccountState,
    disconnectAccount: options.disconnectAccount || options.connectAccount?.disconnectAccount,
    runForAccount: options.runForAccount || options.connectAccount?.runForAccount,
    runSafetyVerificationForAccount: options.runSafetyVerificationForAccount || options.connectAccount?.runSafetyVerificationForAccount,
    openAccount: options.openAccount,
    port: options.port,
    pagePath: options.pagePath || plan.pagePath,
    explicitSyntheticMarker: options.explicitSyntheticMarker === true,
    allowSameSiteTopLevelNavigation: options.allowSameSiteTopLevelNavigation === true,
    trustedParentOrigin: options.trustedParentOrigin,
  });
  const started = await surface.start();
  return Object.freeze({
    host,
    plan,
    kind: "loopback-top-level",
    surface,
    ...started,
    close: () => surface.close(),
  });
}
