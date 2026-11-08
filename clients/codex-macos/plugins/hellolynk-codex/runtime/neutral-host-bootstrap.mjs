#!/usr/bin/env node
import path from "node:path";
import { pathToFileURL } from "node:url";
import { prepareCodexNeutralRelease } from "../server/codex-neutral-production.mjs";

export async function runNeutralHostBootstrap(argv = process.argv.slice(2)) {
  const options = parse(argv);
  const prepared = await prepareCodexNeutralRelease({ storeRoot: options.root });
  const { release } = prepared;
  if (typeof release.run !== "function") throw codeError("neutral_codex_runner_integrity_invalid");
  // Hand over the binding this process just resolved; null makes the runner resolve it again.
  const binding = await prepared.runnerBinding?.(options.root) ?? null;
  return release.run({ root: options.root, binding });
}

function parse(argv) {
  if (argv.length !== 3 || argv[0] !== "run" || argv[1] !== "--root"
    || !path.isAbsolute(String(argv[2] || ""))) throw codeError("neutral_codex_launch_configuration_required");
  return { root: path.resolve(argv[2]) };
}

function safeCode(error) {
  const value = String(error?.code || error?.message || "neutral_codex_launch_failed");
  return /^neutral_(?:codex|host)_[a-z0-9_]{2,100}$/.test(value) ? value : "neutral_codex_launch_failed";
}
function codeError(code) { const error = new Error(code); error.code = code; return error; }

// Start failures and a failed Host both end here. A failed Host keeps its lock until this
// process exits on its own: a closed stderr pipe (the detached launcher may be gone) must
// not crash it before admitted work finishes.
function exitWithFailure(code) {
  process.stderr.on("error", () => {});
  process.stderr.write(`${JSON.stringify({ ok: false, code })}\n`);
  process.exitCode = 1;
}

// A stray rejection must not take the Host down: log a stable code and keep serving. A synchronous
// uncaught exception leaves state unknown: stop the Host (releases its lock), then exit; 15 s bounds a stuck stop.
function guardHostProcess(result) {
  process.on("unhandledRejection", (reason) => writeFailure("neutral_codex_unhandled_rejection", reason));
  process.on("uncaughtException", (error) => {
    writeFailure("neutral_codex_uncaught_exception", error);
    process.exitCode = 1;
    const exit = () => process.exit(1);
    setTimeout(exit, 15_000).unref?.();
    Promise.resolve().then(() => result?.stop?.("uncaught_exception")).then(exit, exit);
  });
  return result;
}

function writeFailure(code, cause) {
  if (!process.stderr.listenerCount("error")) process.stderr.on("error", () => {});
  process.stderr.write(`${JSON.stringify({ ok: false, code, cause: String(cause?.code || cause?.name || "").slice(0, 80) })}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  runNeutralHostBootstrap()
    .then((result) => {
      guardHostProcess(result);
      if (typeof result?.waitUntilStopped === "function") return result.waitUntilStopped();
      return new Promise(() => {});
    })
    .catch((error) => exitWithFailure(safeCode(error)));
}
