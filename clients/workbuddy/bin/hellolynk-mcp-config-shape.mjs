import fs from "node:fs/promises";
import path from "node:path";

export function isHelloLynkMcpServerShape(clientInput, server) {
  const client = String(clientInput || "");
  if (!server || typeof server !== "object" || Array.isArray(server)) return false;
  const keys = Object.keys(server).sort().join(",");
  if (keys === "args,command,env") return true;
  return client === "workbuddy"
    && keys === "args,command,disabled,env"
    && server.disabled === false;
}

export async function traeConfigPaths(appData) {
  // The merged client migrates its config to Trae CN but leaves SOLO data behind.
  // Select the current client first; do not update the retired copy as well.
  const current = path.join(appData, "Trae CN");
  const previous = path.join(appData, "TRAE SOLO CN");
  const directory = await exists(current) || !await exists(previous) ? current : previous;
  return [path.join(directory, "User", "mcp.json")];
}

async function exists(file) { return fs.access(file).then(() => true, () => false); }
