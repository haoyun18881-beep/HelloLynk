import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { withHelloLynkLocalMutationLock } from "./hellolynk-local-messaging.mjs";

// A live OS handle elects one receiver for a client/account. It has no expiry:
// slow model work must never let a second receiver take over. Process death
// closes the handle. Only election itself takes the short filesystem lock.
export async function tryAcquireNativeWorkerLease(scope) {
  const { runtimeRoot, adapterId, principalId, delegateId, region } = scope || {};
  if (typeof runtimeRoot !== "string" || !path.isAbsolute(runtimeRoot)
    || [adapterId, principalId, delegateId, region].some((value) =>
      typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,240}$/.test(value))) {
    throw failure("native_worker_scope_invalid");
  }
  const root = process.platform === "win32" ? path.resolve(runtimeRoot).toLowerCase() : path.resolve(runtimeRoot);
  const key = crypto.createHash("sha256").update(JSON.stringify([root, adapterId, principalId, delegateId, region])).digest("hex");
  const guard = path.join(runtimeRoot, "native-workers", key);
  let endpoint;
  if (process.platform === "win32") endpoint = `\\\\.\\pipe\\hellolynk-native-${key}`;
  else {
    const directory = path.join(os.tmpdir(), `hellolynk-native-${process.getuid()}`);
    await fs.mkdir(directory, { mode: 0o700 }).catch((error) => { if (error.code !== "EEXIST") throw error; });
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) {
      throw failure("native_worker_socket_directory_unsafe");
    }
    endpoint = path.join(directory, `${key.slice(0, 40)}.sock`);
  }
  return withHelloLynkLocalMutationLock(guard, async () => {
    let server = await listen(endpoint);
    if (!server && process.platform !== "win32" && await isStaleSocket(endpoint)) {
      // Every acquisition/release uses the same guard, so a different worker
      // cannot bind between the liveness check and removing the stale socket.
      await fs.unlink(endpoint).catch((error) => { if (error.code !== "ENOENT") throw error; });
      server = await listen(endpoint);
    }
    if (!server) return null;
    let releaseFlight;
    return Object.freeze({
      release() {
        if (!releaseFlight) releaseFlight = withHelloLynkLocalMutationLock(guard, () =>
          new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
        return releaseFlight;
      },
    });
  });
}

function listen(endpoint) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.destroy());
    server.once("error", (error) => {
      if (error.code === "EADDRINUSE") resolve(null);
      else reject(error);
    });
    server.listen({ path: endpoint, exclusive: true }, () => {
      server.unref();
      resolve(server);
    });
  });
}

async function isStaleSocket(endpoint) {
  const stat = await fs.lstat(endpoint).catch((error) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  if (!stat) return true;
  if (!stat.isSocket() || stat.isSymbolicLink() || stat.uid !== process.getuid()) throw failure("native_worker_socket_unsafe");
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(endpoint);
    socket.once("connect", () => { socket.destroy(); resolve(false); });
    socket.once("error", (error) => {
      socket.destroy();
      if (["ECONNREFUSED", "ENOENT"].includes(error.code)) resolve(true);
      else reject(error);
    });
  });
}

function failure(code) { return Object.assign(new Error(code), { code }); }
