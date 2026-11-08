#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

import { loadNeutralHostRelease } from "./neutral-host-release-loader.mjs";

export async function runNeutralHostBootstrap(argv = process.argv.slice(2)) {
  const root = parse(argv);
  const release = await loadNeutralHostRelease();
  if (typeof release?.run !== "function") throw codeError("neutral_runtime_integrity_invalid");
  return release.run({ root });
}

function parse(argv) {
  if (argv.length !== 3 || argv[0] !== "run" || argv[1] !== "--root"
    || !path.isAbsolute(String(argv[2] || ""))) {
    throw codeError("neutral_runtime_launch_configuration_required");
  }
  return path.resolve(argv[2]);
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
  process.on("unhandledRejection", (reason) => writeFailure("neutral_runtime_unhandled_rejection", reason));
  process.on("uncaughtException", (error) => {
    writeFailure("neutral_runtime_uncaught_exception", error);
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
    .then((result) => guardHostProcess(result)?.waitUntilStopped?.() || new Promise(() => {}))
    .catch((error) => exitWithFailure(String(error?.code || "neutral_runtime_launch_failed")));
}
