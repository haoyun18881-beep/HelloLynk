import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { performance } from "node:perf_hooks";

// Serialize lock-file changes with an OS-owned resource. A check followed by
// rename/unlink is not a compare-and-swap, even when the file is checked twice.
// The OS releases this guard if its process exits; there is no second stale
// lock file to reclaim. Nothing is read from or written to connected clients.
export async function withLocalProcessLock(target, operation, { timeoutMs = 10_000 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || typeof operation !== "function") {
    throw lockError("hellolynk_local_process_lock_invalid");
  }
  const started = performance.now();
  const parent = await fs.realpath(path.dirname(target));
  const canonical = path.join(parent, path.basename(target));
  const scope = process.platform === "win32" || process.platform === "darwin"
    ? canonical.toLowerCase() : canonical;
  const digest = crypto.createHash("sha256").update(scope).digest("hex");
  const address = process.platform === "win32"
    ? { path: `\\\\.\\pipe\\hellolynk-file-lock-${digest}` }
    : process.platform === "linux"
      ? { path: `\0hellolynk-file-lock-${digest}` }
      // macOS has no abstract Unix sockets. A deterministic loopback port is
      // also released on crash. A collision fails closed; never select another
      // port, which would let contenders for the same file use different locks.
      : { host: "127.0.0.1", port: 16_384 + (Number.parseInt(digest.slice(0, 8), 16) % 49_152) };
  let server;
  for (;;) {
    if (performance.now() - started >= timeoutMs) throw lockError("hellolynk_local_process_lock_busy");
    server = net.createServer((socket) => { socket.on("error", () => {}); socket.destroy(); });
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen({ ...address, exclusive: true }, resolve);
      });
      break;
    } catch (error) {
      server.close();
      if (error?.code !== "EADDRINUSE") throw lockError("hellolynk_local_process_lock_unavailable", error);
      await new Promise((resolve) => setTimeout(resolve, Math.min(25, Math.max(1, timeoutMs - (performance.now() - started)))));
    }
  }
  try { return await operation(); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function lockError(code, cause) { return Object.assign(new Error(code, cause ? { cause } : undefined), { code }); }

// Process birth identity distinguishes an active lock owner from a reused PID.
const SELF_PROCESS_STARTED_AT_MS = Date.now() - (process.uptime() * 1_000);
let selfProcessIdentityPromise = null;

export async function inspectProcessIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return null;
  if (pid === process.pid) {
    selfProcessIdentityPromise ||= inspectPlatformProcessIdentity(pid).then((value) => value || Object.freeze({
      identity: `portable:${process.platform}:${Math.round(SELF_PROCESS_STARTED_AT_MS)}`,
      startedAtMs: SELF_PROCESS_STARTED_AT_MS,
    }));
    return selfProcessIdentityPromise;
  }
  return inspectPlatformProcessIdentity(pid);
}

async function inspectPlatformProcessIdentity(pid) {
  if (process.platform === "linux") return inspectLinuxProcessIdentity(pid);
  if (process.platform === "win32") return inspectWindowsProcessIdentity(pid);
  if (process.platform === "darwin") return inspectDarwinProcessIdentity(pid);
  return null;
}

async function inspectLinuxProcessIdentity(pid) {
  try {
    const [statText, bootId, processMetadata] = await Promise.all([
      fs.readFile(`/proc/${pid}/stat`, "utf8"),
      fs.readFile("/proc/sys/kernel/random/boot_id", "utf8"),
      fs.stat(`/proc/${pid}`),
    ]);
    const close = statText.lastIndexOf(")");
    if (close < 1) return null;
    const fields = statText.slice(close + 2).trim().split(/\s+/);
    const startTicks = fields[19];
    const normalizedBootId = bootId.trim().toLowerCase();
    if (!/^\d+$/.test(String(startTicks || ""))
      || !/^[a-f0-9-]{32,40}$/.test(normalizedBootId)) return null;
    return Object.freeze({
      identity: `linux:${normalizedBootId}:${startTicks}`,
      startedAtMs: Number.isFinite(processMetadata.ctimeMs) ? processMetadata.ctimeMs : null,
    });
  } catch { return null; }
}

async function inspectWindowsProcessIdentity(pid) {
  const systemRoot = String(process.env.SystemRoot || "C:\\Windows");
  if (!path.isAbsolute(systemRoot)) return null;
  const powershell = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const script = `$p=Get-Process -Id ${pid} -ErrorAction Stop;[Console]::Out.Write($p.StartTime.ToUniversalTime().Ticks.ToString())`;
  const output = await runIdentityProbe(powershell, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
  ]);
  if (!/^\d{12,20}$/.test(String(output || ""))) return null;
  const ticks = Number(output);
  const startedAtMs = (ticks / 10_000) - 62_135_596_800_000;
  if (!Number.isFinite(startedAtMs) || startedAtMs < 0) return null;
  return Object.freeze({ identity: `win32:${output}`, startedAtMs });
}

async function inspectDarwinProcessIdentity(pid) {
  const output = await runIdentityProbe("/bin/ps", ["-o", "lstart=", "-p", String(pid)]);
  const startedAtMs = Date.parse(String(output || "").trim());
  if (!Number.isFinite(startedAtMs)) return null;
  return Object.freeze({
    identity: `darwin:${crypto.createHash("sha256").update(output.trim()).digest("hex")}`,
    startedAtMs,
  });
}

async function runIdentityProbe(executable, args) {
  return new Promise((resolve) => {
    let output = "";
    let overflow = false;
    let settled = false;
    let child;
    const settle = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      child?.kill();
      settle(null);
    }, 2_000);
    try {
      child = spawn(executable, args, {
        windowsHide: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      settle(null);
      return;
    }
    child.stdout.on("data", (chunk) => {
      if (overflow) return;
      output += chunk.toString("utf8");
      if (Buffer.byteLength(output, "utf8") > 256) {
        output = "";
        overflow = true;
      }
    });
    child.once("error", () => settle(null));
    child.once("close", (code) => settle(code === 0 && !overflow ? output.trim() : null));
  });
}
