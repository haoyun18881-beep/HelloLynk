import path from "node:path";
import fs from "node:fs/promises";
import { loadPinnedWorkBuddyProxy } from "./package-bootstrap.mjs";
import { createWorkBuddyNativeTaskClient } from "./native-task-cdp.mjs";

// Call during explicit HelloLynk installation/repair, after writing mcp.json.
// Normal WorkBuddy UI approval is configuration-hash-specific and therefore
// must be repeated for an installed package update that changes its command.
export async function registerWorkBuddyNativeMcp({ debugEndpoint, command, releaseRoot, expectedManifestSha256, storeRoot } = {}) {
  const expected = workBuddyMcpExpectedConfig({ command, releaseRoot, expectedManifestSha256, storeRoot });
  const stat = await fs.lstat(expected.command);
  if (!stat.isFile() || stat.isSymbolicLink()) throw failure("workbuddy_native_mcp_node_invalid");
  await loadPinnedWorkBuddyProxy({ root: expected.args[3], expectedManifestSha256 });
  const result = await createWorkBuddyNativeTaskClient({ debugEndpoint }).approveHelloLynkMcp(expected);
  // Approved, but WorkBuddy may still be starting the server; the native
  // service connects it on its next check.
  if (result.trusted && result.enabled && result.status !== "ready") return result;
  const toolNames = new Set((result.tools || []).filter(tool=>tool.enabled).map(tool=>tool.name));
  if (!result.trusted || !result.enabled || result.status !== "ready" || !["hellolynk_claim_message", "hellolynk_send_authorized_message", "hellolynk_reply_authorized_message"].every(name=>toolNames.has(name))) throw failure("workbuddy_native_mcp_registration_failed");
  return result;
}

// The exact mcp.json entry an installer writes for this release. Paths are
// canonical, so a differently spelled path does not fail the exact match.
export function workBuddyMcpExpectedConfig({ command, releaseRoot, expectedManifestSha256, storeRoot } = {}) {
  if (![command, releaseRoot, storeRoot].every(v=>typeof v==='string'&&path.isAbsolute(v)) || !/^node(?:\.exe)?$/i.test(path.basename(command)) || !/^[a-f0-9]{64}$/.test(expectedManifestSha256 || "")) throw failure("workbuddy_native_mcp_installation_invalid");
  const root = path.resolve(releaseRoot);
  return { command: path.resolve(command), args: [path.join(root, "integrations", "workbuddy", "server", "package-bootstrap.mjs"), "run", "--root", root, "--expected-manifest-sha256", expectedManifestSha256], storeRoot: path.resolve(storeRoot) };
}
function failure(code) { return Object.assign(new Error(code), { code }); }
