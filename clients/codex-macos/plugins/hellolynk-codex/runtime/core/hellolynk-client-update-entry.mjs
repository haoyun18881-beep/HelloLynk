import fs from "node:fs/promises";
import path from "node:path";
import { clientAccountBaseRoot } from "./hellolynk-client-account.mjs";
import { startClientUpdateRuntime } from "./hellolynk-client-update-runtime.mjs";
import { clientUpdateCatalogId, MAC_CLIENT_VERSION } from "./hellolynk-client-update.mjs";

const running = new Map();

// Callers start this outside protocol discovery, then await it before attaching
// to the Host. A checkout or an uninstalled test fixture never self-updates.
export function startInstalledClientUpdate(options = {}) {
  const { client, packageRoot, storeRoot } = options;
  const catalogId = clientUpdateCatalogId(client, process.platform);
  const mac = process.platform === "darwin";
  if (!catalogId || (mac && process.arch !== "arm64") || !path.isAbsolute(String(packageRoot || ""))) return Promise.resolve(null);
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
    const version = mac ? MAC_CLIENT_VERSION : /^\d+\.\d+\.\d+$/u;
    if (manifest.hellolynkClient?.client !== client || !version.test(manifest.version || "")
      || (mac && (manifest.os?.[0] !== "darwin" || manifest.cpu?.[0] !== "arm64"))) return null;
    return startClientUpdateRuntime({
      root: baseRoot, client, currentVersion: manifest.version,
      installContext: { ...options.installContext, packageRoot: path.resolve(packageRoot) },
    });
  }
}
