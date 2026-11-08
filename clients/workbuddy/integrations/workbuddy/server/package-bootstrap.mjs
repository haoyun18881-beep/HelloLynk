import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const ENTRY = "integrations/workbuddy/server/mcp-proxy.mjs";
const REQUIRED = new Set([
  ENTRY,
  "integrations/workbuddy/package.json",
  "integrations/workbuddy/server/mcp-server.mjs",
  "integrations/workbuddy/server/neutral-host-adapter.mjs",
  "integrations/workbuddy/server/workbench-candidate.mjs",
  "integrations/workbuddy/server/workbench-process.mjs",
  "integrations/workbuddy/server/workbench-task.ps1",
  "integrations/workbuddy/server/workbench-hidden-launcher.vbs",
  "clients/core/hellolynk-runtime-safety.cjs",
  "integrations/workbuddy/server/package-bootstrap.mjs",
  "integrations/workbuddy/skills/hellolynk-inbox/SKILL.md",
  "integrations/workbuddy/skills/hellolynk-inbox/workbuddy.json",
  "clients/core/hellolynk-local-data-migration.mjs",
  "clients/core/hellolynk-local-data-protection.mjs",
  "clients/core/hellolynk-local-identity-trust.mjs",
  "clients/core/hellolynk-neutral-host-workbench-read-model.mjs",
  "clients/workbench/contract.mjs",
  "clients/platform/windows/credential-store.ps1",
  "clients/platform/windows/hellolynk-host-protected-store.ps1",
  "clients/platform/windows/hellolynk-local-data-key.ps1",
  "clients/platform/windows/hellolynk-human-confirmation-ledger.ps1",
  "clients/platform/windows/hellolynk-native-human-confirmation-broker.ps1",
  "runtime/neutral-host-bootstrap.mjs",
  "runtime/neutral-host-release-loader.mjs",
  "runtime/neutral-host-release-entry.mjs",
  "runtime/neutral-host-release-manifest.json",
  "runtime/neutral-host-release-pin.json",
  "runtime/core/hellolynk-host-protected-store.mjs",
  "runtime/core/hellolynk-local-data-migration.mjs",
  "runtime/core/hellolynk-local-data-protection.mjs",
  "runtime/core/hellolynk-local-identity-trust.mjs",
  "runtime/core/hellolynk-neutral-host-assembly.mjs",
  "runtime/core/hellolynk-neutral-host-workbench-read-model.mjs",
  "runtime/core/hellolynk-workbench-action-grants.mjs",
  "runtime/workbench/contract.mjs",
  "runtime/workbench/candidate-bootstrap.mjs",
  "runtime/platform/windows/hellolynk-local-data-key.ps1",
]);
export async function loadPinnedWorkBuddyProxy(options={}) {
  const root=absolute(options.root), expected=hash(options.expectedManifestSha256);
  const [mb,pb]=await Promise.all([safeRead(root,"workbuddy-package-manifest.json"),safeRead(root,"workbuddy-package-pin.json")]);
  if(sha(mb)!==expected)throw code("workbuddy_package_manifest_mismatch"); const manifest=parse(mb),pin=parse(pb);
  if(!plain(pin)||!exact(pin,["contract","manifestSha256"])||pin.contract!=="hellolynk-workbuddy-immutable-package-pin-v1"||pin.manifestSha256!==expected)throw code("workbuddy_package_pin_invalid");
  if(!plain(manifest)||!exact(manifest,["contract","entry","files"])||manifest.contract!=="hellolynk-workbuddy-immutable-package-v1"||manifest.entry!==ENTRY||!Array.isArray(manifest.files))throw code("workbuddy_package_manifest_invalid");
  const required=new Set(REQUIRED),seen=new Set(); for(const record of manifest.files){if(!plain(record)||!exact(record,["path","sha256"])||!safeRelative(record.path)||!/^[a-f0-9]{64}$/.test(String(record.sha256||""))||seen.has(record.path))throw code("workbuddy_package_manifest_invalid");seen.add(record.path);required.delete(record.path);if(sha(await safeRead(root,record.path))!==record.sha256)throw code("workbuddy_package_file_integrity_invalid");}
  if(required.size)throw code("workbuddy_package_closure_incomplete"); return import(pathToFileURL(path.join(root,...ENTRY.split("/"))).href);
}
export async function runWorkBuddyPackageBootstrap(args = process.argv.slice(2)) {
  if (!["run", "--wait-for-pending", "handoff-workbench", "workbench", "workbench-service", "native-task-service"].includes(args[0])
    || args.length !== 5 || args[1] !== "--root" || args[3] !== "--expected-manifest-sha256") {
    throw code("workbuddy_package_arguments_invalid");
  }
  const options = { root: args[2], expectedManifestSha256: args[4] };
  // Every entry, including the detached page, verifies the immutable closure
  // before importing adapter or UI code.
  const proxy = await loadPinnedWorkBuddyProxy(options);
  if (args[0] === "--wait-for-pending") {
    const stop = new AbortController();
    const terminate = () => stop.abort();
    process.once("SIGTERM", terminate);
    process.once("SIGINT", terminate);
    try { await proxy.waitForWorkBuddyPending({ signal: stop.signal }); }
    finally { process.off("SIGTERM", terminate); process.off("SIGINT", terminate); }
  } else if (args[0] === "run") {
    await proxy.runWorkBuddyMcpProxy({ openLocalWeb: () => proxy.launchDetachedWorkBuddyWorkbench(options) });
  } else if (args[0] === "handoff-workbench") {
    process.stdout.write(`${JSON.stringify(await proxy.handoffWorkBuddyWorkbench(options))}\n`);
  } else if (["workbench-service", "native-task-service"].includes(args[0])) {
    const stop = new AbortController();
    const terminate = () => stop.abort();
    process.once("SIGTERM", terminate);
    process.once("SIGINT", terminate);
    try {
      if (args[0] === "native-task-service") await proxy.runWorkBuddyNativeTaskService({ ...options, originHook: true, signal: stop.signal });
      else await proxy.runWorkBuddyWorkbenchService({ ...options, signal: stop.signal });
    }
    finally { process.off("SIGTERM", terminate); process.off("SIGINT", terminate); }
  } else {
    const stop = new AbortController();
    const terminate = () => stop.abort();
    process.once("SIGTERM", terminate);
    process.once("SIGINT", terminate);
    // A launch abandoned before readiness must not leave an idle worker.
    const deadline = setTimeout(() => process.exit(1), 90_000);
    deadline.unref();
    try {
      await proxy.runWorkBuddyWorkbenchProcess({
        signal: stop.signal,
        publishReady: (value) => new Promise((resolve, reject) => {
          if (!process.connected) return reject(code("workbuddy_local_web_launch_handoff_missing"));
          process.send(value, (error) => {
            if (error) reject(error);
            else { clearTimeout(deadline); resolve(); }
          });
        }),
      });
    } finally {
      clearTimeout(deadline);
      process.off("SIGTERM", terminate);
      process.off("SIGINT", terminate);
    }
  }
}
function absolute(v){const r=String(v||"");if(!path.isAbsolute(r)||path.resolve(r)!==r)throw code("workbuddy_package_root_required");return r}function hash(v){const r=String(v||"");if(!/^[a-f0-9]{64}$/.test(r))throw code("workbuddy_package_expected_manifest_required");return r}function safeRelative(v){return typeof v==="string"&&/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(v)&&!v.includes("..")&&!v.startsWith("/")}async function safeRead(root,relative){const f=path.resolve(root,...relative.split("/"));if(!f.startsWith(`${root}${path.sep}`))throw code("workbuddy_package_path_invalid");try{const s=await fs.lstat(f);if(!s.isFile()||s.isSymbolicLink()||s.size>4*1024*1024)throw 0;return await fs.readFile(f)}catch{throw code("workbuddy_package_file_unavailable")}}function parse(v){try{return JSON.parse(v)}catch{throw code("workbuddy_package_manifest_invalid")}}function exact(v,k){const a=Object.keys(v).sort(),b=[...k].sort();return a.length===b.length&&a.every((x,i)=>x===b[i])}function sha(v){return crypto.createHash("sha256").update(v).digest("hex")}function plain(v){return Boolean(v)&&typeof v==="object"&&!Array.isArray(v)}function code(v){const e=new Error(v);e.code=v;return e}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))runWorkBuddyPackageBootstrap().catch(e=>{process.stderr.write(`${JSON.stringify({ok:false,error:/^(?:workbuddy|neutral|host)_[a-z0-9_]{1,100}$/.test(e?.code||"")?e.code:"workbuddy_package_failed"})}\n`);process.exitCode=1});
