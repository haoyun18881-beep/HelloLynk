import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PIN_PATH = path.join(ROOT, "neutral-host-release-pin.json");
const MANIFEST_PATH = path.join(ROOT, "neutral-host-release-manifest.json");
const SAFE_RUNTIME_RELATIVE = /^(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*\.(?:cjs|mjs|ps1|swift|bin)$/;
const SAFE_RELEASE_RELATIVE = /^release\/(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*\.(?:mjs|ps1|md|html|js|css|json)$/;

export async function inspectNeutralHostRelease() {
  await assertNoReparseAncestors(ROOT);
  const pinArtifact = await readArtifact(PIN_PATH, 16 * 1024);
  const pin = parseJson(pinArtifact.bytes);
  exact(pin, ["contract", "manifestSha256"]);
  if (pin.contract !== "hellolynk-neutral-host-release-pin-v1" || !HASH.test(String(pin.manifestSha256 || ""))) fail();
  const manifestArtifact = await readArtifact(MANIFEST_PATH, 256 * 1024);
  if (sha256(manifestArtifact.bytes) !== pin.manifestSha256) fail();
  let manifest;
  try { manifest = JSON.parse(manifestArtifact.bytes); } catch { fail(); }
  exact(manifest, ["contract", "entry", "files"]);
  if (manifest.contract !== "hellolynk-neutral-host-release-manifest-v1"
    || !Array.isArray(manifest.files) || manifest.files.length < 3 || manifest.files.length > 128) fail();
  const files = [];
  const seen = new Set();
  for (const item of manifest.files) {
    exact(item, ["path", "sha256"]);
    const relative = safeRelative(item.path);
    if (seen.has(relative) || !HASH.test(String(item.sha256 || ""))) fail();
    seen.add(relative);
    const artifact = await readArtifact(inside(relative), 2 * 1024 * 1024);
    if (sha256(artifact.bytes) !== item.sha256) fail();
    files.push(Object.freeze({ relative, sha256: item.sha256, identity: artifact.identity }));
  }
  const entry = safeRelative(manifest.entry);
  if (!seen.has(entry) || !seen.has("neutral-host-bootstrap.mjs")
    || !seen.has("neutral-host-release-loader.mjs")) fail();
  return Object.freeze({
    contract: "hellolynk-neutral-host-release-inspection-v1",
    releaseRoot: path.dirname(ROOT),
    manifestSha256: pin.manifestSha256,
    entry,
    controls: Object.freeze([
      Object.freeze({ relative: "neutral-host-release-pin.json", sha256: sha256(pinArtifact.bytes), identity: pinArtifact.identity }),
      Object.freeze({ relative: "neutral-host-release-manifest.json", sha256: pin.manifestSha256, identity: manifestArtifact.identity }),
    ]),
    files: Object.freeze(files),
  });
}

export async function activateNeutralHostRelease(inspection) {
  if (!inspection || inspection.contract !== "hellolynk-neutral-host-release-inspection-v1"
    || inspection.releaseRoot !== path.dirname(ROOT) || !Array.isArray(inspection.controls)
    || inspection.controls.length !== 2 || !Array.isArray(inspection.files)) fail();
  await assertNoReparseAncestors(ROOT);
  for (const expected of inspection.controls) {
    const control = CONTROL_PATHS.get(expected.relative);
    if (!control) fail();
    const artifact = await readArtifact(control, 256 * 1024);
    if (sha256(artifact.bytes) !== expected.sha256 || !sameIdentity(artifact.identity, expected.identity)) fail();
  }
  for (const expected of inspection.files) {
    const artifact = await readArtifact(inside(safeRelative(expected.relative)), 2 * 1024 * 1024);
    if (sha256(artifact.bytes) !== expected.sha256 || !sameIdentity(artifact.identity, expected.identity)) fail();
  }
  const entryFile = inside(safeRelative(inspection.entry));
  let module;
  try { module = await import(`${pathToFileURL(entryFile).href}?verified=${inspection.manifestSha256}`); }
  catch { throw codeError("neutral_codex_runner_integrity_invalid"); }
  if (typeof module.createNeutralHostReleaseRuntime !== "function") fail();
  const runtime = await module.createNeutralHostReleaseRuntime();
  if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) fail();
  return Object.freeze({ ...runtime, releaseManifestSha256: inspection.manifestSha256 });
}

export async function loadNeutralHostRelease() {
  return activateNeutralHostRelease(await inspectNeutralHostRelease());
}

async function readArtifact(file, maximum) {
  await assertNoReparseAncestors(file);
  let handle;
  try { handle = await fs.open(file, "r"); }
  catch (error) {
    if (error?.code === "ENOENT") throw codeError("neutral_codex_runner_unavailable");
    throw codeError("neutral_codex_runner_integrity_invalid");
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!sameIdentity(identity(before), identity(after))) fail();
    return Object.freeze({ bytes, identity: identity(after) });
  } catch (error) {
    if (/^neutral_codex_/.test(String(error?.code || ""))) throw error;
    throw codeError("neutral_codex_runner_integrity_invalid");
  } finally { await handle?.close(); }
}

async function assertNoReparseAncestors(target) {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  let cursor = parsed.root;
  for (const segment of path.relative(parsed.root, resolved).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    let stat;
    try { stat = await fs.lstat(cursor); }
    catch (error) {
      if (error?.code === "ENOENT") throw codeError("neutral_codex_runner_unavailable");
      throw codeError("neutral_codex_runner_integrity_invalid");
    }
    if (stat.isSymbolicLink()) fail();
  }
}

function identity(stat) {
  return Object.freeze({
    dev: String(stat.dev), ino: String(stat.ino), size: String(stat.size),
    mtimeNs: String(stat.mtimeNs), nlink: String(stat.nlink),
  });
}
function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.nlink === right.nlink;
}
function parseJson(bytes) { try { return JSON.parse(bytes); } catch { fail(); } }
function safeRelative(value) {
  const text = String(value || "");
  const allowed = text.startsWith("release/") ? SAFE_RELEASE_RELATIVE : SAFE_RUNTIME_RELATIVE;
  if (!allowed.test(text) || text.split("/").includes("..")) fail();
  return text;
}
function inside(relative) {
  const releaseRoot = path.dirname(ROOT);
  const result = relative.startsWith("release/")
    ? path.resolve(releaseRoot, relative.slice("release/".length))
    : path.resolve(ROOT, relative);
  const base = relative.startsWith("release/") ? releaseRoot : ROOT;
  if (!result.startsWith(`${base}${path.sep}`)) fail();
  return result;
}
function exact(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail();
}
const HASH = /^[a-f0-9]{64}$/;
const CONTROL_PATHS = new Map([
  ["neutral-host-release-pin.json", PIN_PATH],
  ["neutral-host-release-manifest.json", MANIFEST_PATH],
]);
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function fail() { throw codeError("neutral_codex_runner_integrity_invalid"); }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
