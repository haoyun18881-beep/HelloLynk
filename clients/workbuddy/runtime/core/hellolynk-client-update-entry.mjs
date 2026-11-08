import fs from "node:fs/promises";
import path from "node:path";
import { clientAccountBaseRoot } from "./hellolynk-client-account.mjs";
import { startClientUpdateRuntime } from "./hellolynk-client-update-runtime.mjs";

const running = new Map();

// Callers start this outside protocol discovery, then await it before attaching
// to the Host. A checkout or an uninstalled test fixture never self-updates.
export function startInstalledClientUpdate(options = {}) {
  const { client, packageRoot, storeRoot } = options;
  if (process.platform !== "win32" || !path.isAbsolute(String(packageRoot || ""))) return Promise.resolve(null);
  let baseRoot;
  try { baseRoot = clientAccountBaseRoot(storeRoot); } catch { return Promise.resolve(null); }
  const key = `${client}\0${path.resolve(packageRoot)}\0${baseRoot}`;
  if (!running.has(key)) running.set(key, start().catch(() => null));
  return running.get(key);

  async function start() {
    const packageFile = path.join(packageRoot, "package.json");
    const metadata = await fs.lstat(packageFile);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size > 64 * 1024) return null;
    const manifest = JSON.parse(await fs.readFile(packageFile, "utf8"));
    if (manifest.hellolynkClient?.client !== client
      || !/^\d+\.\d+\.\d+$/.test(manifest.version || "")) return null;
    return startClientUpdateRuntime({
      root: baseRoot, client, currentVersion: manifest.version,
      installContext: { ...options.installContext, packageRoot: path.resolve(packageRoot) },
    });
  }
}
