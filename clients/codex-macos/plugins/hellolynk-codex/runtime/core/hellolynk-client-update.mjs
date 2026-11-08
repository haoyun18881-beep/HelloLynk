import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { inflateRawSync } from "node:zlib";
import { withNeutralHostStoreLock } from "./hellolynk-neutral-host-installation-store.mjs";

const CATALOG = "https://hellolynk.com/downloads/clients.json";
export const CLIENT_UPDATE_CLIENTS = Object.freeze(["codex", "openclaw", "trae-work", "workbuddy", "dsh", "claude-code"]);
export const MAC_CODEX_VERSION = /^\d+\.\d+\.\d+-macos\.[1-9]\d*$/u;
const HOUR = 3_600_000;
const MAX_ARTIFACT = 64 * 1024 * 1024;
const HASH = /^[a-f0-9]{64}$/;
const CONTRACT = "hellolynk-client-update-v1";
// A failed integrity or path check keeps a downloaded package from installing. Every other failure is transient.
const BLOCKING = /^client_update_(?:same_version_changed|version_rollback|artifact_integrity_invalid|archive_[a-z_]+|path_invalid|url_invalid|redirect_invalid)$/;

export function clientUpdateCatalogId(client, platform) {
  if (platform === "win32") return client;
  if (platform === "darwin" && client === "codex") return "codex-macos";
  return null;
}

// This component only stages verified files. Host lifecycle and client-native
// installation remain the responsibility of the caller.
export function createClientUpdateManager(options = {}) {
  const { client, currentVersion, platform = process.platform } = options;
  if (!CLIENT_UPDATE_CLIENTS.includes(client) || !semver(currentVersion) || !path.isAbsolute(String(options.root || ""))) fail("configuration_invalid");
  const catalogId = clientUpdateCatalogId(client, platform);
  const mac = catalogId === "codex-macos";
  if (mac && !MAC_CODEX_VERSION.test(currentVersion)) fail("configuration_invalid");
  const root = path.join(path.resolve(options.root), "client-updates", client);
  const stateFile = path.join(root, "state.json");
  const fetcher = options.fetchImpl || globalThis.fetch;
  const clock = options.clock || Date.now;
  const timeoutMs = bounded(options.timeoutMs, 30_000, 50, 120_000);
  const probeTimeoutMs = bounded(options.probeTimeoutMs, 4_000, 50, 10_000);
  const currentSha256 = options.currentSha256;
  if (currentSha256 != null && !HASH.test(currentSha256)) fail("configuration_invalid");
  let inFlight = null;

  async function readState() {
    try {
      await safeAncestors(stateFile, false);
      const stat = await fs.lstat(stateFile);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 64 * 1024) fail("state_invalid");
      const result = JSON.parse(await fs.readFile(stateFile, "utf8"));
      if (result?.contract !== CONTRACT || result.client !== client
        || !["idle", "current", "downloaded", "error", "unsupported"].includes(result.stage)
        || !Number.isFinite(result.checkedAt) || result.checkedAt < 0) fail("state_invalid");
      if (result.observedVersion != null && (!semver(result.observedVersion) || !HASH.test(String(result.observedSha256 || "")))) fail("state_invalid");
      if (result.sourceCache != null && (!result.sourceCache || !["official", "github"].includes(result.sourceCache.name)
        || !["https://hellolynk.com", "https://github.com"].includes(result.sourceCache.origin)
        || !Number.isFinite(result.sourceCache.selectedAt))) fail("state_invalid");
      if (result.stage === "downloaded") {
        if (!semver(result.version) || !HASH.test(String(result.sha256 || ""))
          || !Number.isSafeInteger(result.bytes) || result.bytes < 1 || result.bytes > MAX_ARTIFACT
          || !safeFilename(result.filename)) fail("state_invalid");
        const release = releasePath(result);
        if (result.artifactPath !== path.join(release, result.filename)
          || result.extractedRoot !== path.join(release, "extracted")) fail("state_invalid");
        await safeAncestors(result.artifactPath, false);
        await safeAncestors(result.extractedRoot, true);
      }
      return Object.freeze(result);
    } catch (error) {
      // Missing or damaged: start over, and the next check overwrites the file.
      // Any other read error (a busy or locked file) says nothing about the contents, so it propagates.
      if (error?.code !== "ENOENT" && error?.name !== "SyntaxError" && error?.code !== "client_update_state_invalid") throw error;
      return Object.freeze({ contract: CONTRACT, client, stage: "idle", checkedAt: 0 });
    }
  }

  function releasePath(record) { return path.join(root, "releases", `${record.version}-${record.sha256}`); }
  async function save(record) {
    await safeDirectory(root);
    const temporary = path.join(root, `.state-${crypto.randomUUID()}.tmp`);
    try {
      await fs.writeFile(temporary, `${JSON.stringify(record)}\n`, { flag: "wx", mode: 0o600 });
      await safeAncestors(stateFile, false);
      await fs.rename(temporary, stateFile);
    } finally { await fs.rm(temporary, { force: true }); }
    return Object.freeze(record);
  }

  async function perform(force) {
    await safeDirectory(root);
    // Reuse the Host's protected, ownership-token lock and its conservative
    // crash recovery rather than adding a second lock protocol.
    return withNeutralHostStoreLock(root, "client-update", async () => {
      let old = await readState();
      const now = clock();
      if (!force && old.checkedAt > 0 && now >= old.checkedAt && now - old.checkedAt < 23 * HOUR) return old;
      if (!catalogId) return save({ ...old, stage: "unsupported", checkedAt: now });
      try {
        const metadata = await request(CATALOG, { limit: 256 * 1024, timeout: timeoutMs, kind: "catalog" });
        let catalog;
        try { catalog = JSON.parse(metadata.toString("utf8")); } catch { fail("catalog_invalid"); }
        const artifact = validateCatalog(catalog, catalogId, mac);
        // The catalog has no build for this client: there is nothing to install.
        if (!artifact) {
          // A downloaded package keeps its stage and any integrity block; only an empty cache is "current".
          if (old.stage === "downloaded") return save({ ...old, checkedAt: now, error: BLOCKING.test(old.error || "") ? old.error : null });
          return save({ ...old, stage: "current", checkedAt: now, error: null });
        }
        const installedOrder = compareVersions(artifact.version, currentVersion);
        if ((installedOrder === 0 && currentSha256 && artifact.sha256 !== currentSha256)
          || (old.observedVersion && compareVersions(old.observedVersion, artifact.version) === 0 && old.observedSha256 !== artifact.sha256)) fail("same_version_changed");
        if (old.observedVersion && compareVersions(artifact.version, old.observedVersion) < 0) fail("version_rollback");
        old = { ...old, observedVersion: artifact.version, observedSha256: artifact.sha256 };
        if (installedOrder <= 0) return save({ ...old, stage: "current", checkedAt: now, error: null });
        // A newer process already installed this release (its record may since have met a failed
        // check): keep it as current instead of downloading it again.
        if (["current", "error"].includes(old.stage) && old.version === artifact.version && old.sha256 === artifact.sha256) {
          return save({ ...old, stage: "current", checkedAt: now, error: null });
        }
        if (old.stage === "downloaded" && old.version === artifact.version && old.sha256 === artifact.sha256) {
          try {
            await verifyDownloaded(old);
            return save({ ...old, checkedAt: now, error: null });
          } catch { /* A missing/corrupt local cache is re-downloaded once. */ }
        }
        const sources = artifact.sources;
        let chosen, selectedAt = now;
        const cache = old.sourceCache;
        if (cache && Number.isFinite(cache.selectedAt) && now >= cache.selectedAt && now - cache.selectedAt < 24 * HOUR) {
          chosen = sources.find((source) => source.name === cache.name && sourceOrigin(source.url) === cache.origin);
          if (chosen) selectedAt = cache.selectedAt;
        }
        const failed = new Set();
        let bytes;
        for (let attempt = 0; attempt < sources.length; attempt += 1) {
          if (!chosen || failed.has(chosen.url)) { chosen = await fastest(sources.filter((item) => !failed.has(item.url))); selectedAt = now; }
          try {
            bytes = await request(chosen.url, { limit: artifact.bytes, timeout: timeoutMs, kind: "artifact" });
            if (bytes.length !== artifact.bytes || sha(bytes) !== artifact.sha256) fail("artifact_integrity_invalid");
            break;
          } catch (error) {
            failed.add(chosen.url);
            bytes = null;
            if (failed.size === sources.length) throw error;
            chosen = null;
          }
        }
        if (!bytes) fail("source_unavailable");
        const release = releasePath(artifact);
        await safeDirectory(path.dirname(release));
        const stage = path.join(root, "releases", `.stage-${crypto.randomUUID()}`);
        await fs.mkdir(stage, { mode: 0o700 });
        try {
          const archivePath = path.join(stage, artifact.filename);
          await fs.writeFile(archivePath, bytes, { flag: "wx", mode: 0o600 });
          await extractClientUpdateArchive({ archivePath, destination: path.join(stage, "extracted"), platform });
          await fs.rename(stage, release).catch(async (error) => {
            if (!["EEXIST", "ENOTEMPTY", "EPERM"].includes(error.code)) throw error;
            try {
              await verifyDownloaded({ ...artifact, artifactPath: path.join(release, artifact.filename), extractedRoot: path.join(release, "extracted") });
              return;
            } catch { /* Preserve damaged evidence without reusing it. */ }
            await safeAncestors(release, true);
            const quarantine = path.join(root, "releases", `.corrupt-${artifact.sha256}-${crypto.randomUUID()}`);
            await fs.rename(release, quarantine);
            try { await fs.rename(stage, release); }
            catch (replacement) { await fs.rename(quarantine, release).catch(() => {}); throw replacement; }
          });
        } finally { await fs.rm(stage, { recursive: true, force: true }); }
        // Finish staging cleanup before starting publication: a failed cleanup
        // must not race an earlier downloaded-state save and lose its error.
        return save({ ...old, stage: "downloaded", version: artifact.version, filename: artifact.filename,
          artifactPath: path.join(release, artifact.filename), extractedRoot: path.join(release, "extracted"),
          sha256: artifact.sha256, bytes: artifact.bytes, checkedAt: now, error: null,
          sourceCache: { name: chosen.name, origin: sourceOrigin(chosen.url), selectedAt },
        });
      } catch (error) {
        const code = /^client_update_[a-z_]+$/.test(error?.code || "") ? error.code : "client_update_check_failed";
        if (BLOCKING.test(code)) return save({ ...old, stage: old.stage === "downloaded" ? "downloaded" : "error", checkedAt: now, error: code });
        // Anything else is transient: a downloaded package stays installable and the next check tries again.
        // checkedAt is backdated so that retry comes after one hour, not after the full 23-hour window.
        const retryAt = now - 22 * HOUR;
        if (old.stage === "downloaded") return save({ ...old, checkedAt: retryAt, error: BLOCKING.test(old.error || "") ? old.error : null });
        return save({ ...old, stage: "error", checkedAt: retryAt, error: code });
      }
    });
  }

  // After an install only the package state.json names stays cached; older
  // versions and quarantined copies go. Holding the check lock means no
  // download is in flight to be mistaken for leftovers.
  async function prune() {
    await safeDirectory(root);
    return withNeutralHostStoreLock(root, "client-update", async () => {
      const state = await readState();
      if (!semver(state.version) || !HASH.test(String(state.sha256 || ""))) return [];
      const keep = path.basename(releasePath(state)), releases = path.join(root, "releases"), removed = [];
      await safeAncestors(releases, true);
      let entries;
      try { entries = await fs.readdir(releases, { withFileTypes: true }); }
      catch (error) { if (error.code === "ENOENT") return removed; throw error; }
      for (const entry of entries) {
        if (entry.name === keep || !entry.isDirectory()) continue;
        await fs.rm(path.join(releases, entry.name), { recursive: true, force: true });
        removed.push(entry.name);
      }
      return removed;
    });
  }

  async function fastest(sources) {
    const outcomes = await Promise.allSettled(sources.map(async (source) => {
      const started = performance.now();
      await request(source.url, { limit: 4096, timeout: probeTimeoutMs, kind: "probe" });
      return { source, elapsed: performance.now() - started };
    }));
    const successes = outcomes.filter((item) => item.status === "fulfilled").map((item) => item.value).sort((a, b) => a.elapsed - b.elapsed);
    if (!successes.length) fail("source_unavailable");
    return successes[0].source;
  }

  async function request(url, { limit, timeout, kind }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let response;
    try {
      let current = new URL(url);
      for (let redirect = 0; redirect <= 3; redirect += 1) {
        validateUrl(current, kind === "catalog" ? "catalog" : "artifact", redirect > 0, new URL(url));
        response = await fetcher(current.href, { method: "GET", credentials: "omit", redirect: "manual", signal: controller.signal,
          headers: kind === "probe" ? { Range: "bytes=0-4095", Accept: "application/octet-stream" } : { Accept: kind === "catalog" ? "application/json" : "application/octet-stream" } });
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          await response.body?.cancel();
          const next = response.headers.get("location");
          if (!next || redirect === 3) fail("redirect_invalid");
          current = new URL(next, current);
          continue;
        }
        if (response.status !== 200 && !(kind === "probe" && response.status === 206)) fail("source_unavailable");
        if (response.url && response.url !== current.href) fail("redirect_invalid");
        if (/text\/html|application\/xhtml/i.test(response.headers.get("content-type") || "")) fail("source_invalid");
        const length = response.headers.get("content-length");
        if (kind !== "probe" && length != null && (!/^\d+$/.test(length) || Number(length) > limit)) fail("response_too_large");
        if (!response.body) fail("source_invalid");
        const reader = response.body.getReader();
        const chunks = []; let total = 0;
        try {
          while (true) {
            const nextChunk = await reader.read();
            if (nextChunk.done) break;
            const chunk = Buffer.from(nextChunk.value);
            if (kind === "probe") {
              const take = chunk.subarray(0, limit - total); chunks.push(take); total += take.length;
              if (total >= limit) break;
            } else {
              total += chunk.length;
              if (total > limit) fail("response_too_large");
              chunks.push(chunk);
            }
          }
        } finally { await reader.cancel().catch(() => {}); }
        const body = Buffer.concat(chunks);
        if (kind !== "catalog" && (body.length < 4 || body.readUInt32LE(0) !== 0x04034b50)) fail("source_invalid");
        return body;
      }
      fail("redirect_invalid");
    } finally {
      clearTimeout(timer);
      await response?.body?.cancel().catch(() => {});
    }
  }

  return Object.freeze({
    check({ force = false } = {}) {
      if (!inFlight) inFlight = perform(force).finally(() => { inFlight = null; });
      return inFlight;
    },
    prune,
    state: readState,
    readState,
  });
}

function validateCatalog(catalog, client, mac) {
  if (!catalog || !Array.isArray(catalog.clients) || catalog.clients.length > 32) fail("catalog_invalid");
  const matches = catalog.clients.filter((item) => item?.client === client);
  if (matches.length === 0) return null;
  if (matches.length > 1) fail("catalog_invalid");
  const item = matches[0];
  if (!semver(item.version) || (mac && !MAC_CODEX_VERSION.test(item.version))
    || !HASH.test(String(item.sha256 || "")) || !safeFilename(item.filename)
    || !Number.isSafeInteger(item.bytes) || item.bytes < 4 || item.bytes > MAX_ARTIFACT
    || !Array.isArray(item.platforms) || !item.platforms.includes(mac ? "macOS" : "Windows")) fail("catalog_invalid");
  const official = new URL(String(item.url || ""), CATALOG);
  if (official.origin !== "https://hellolynk.com" || !official.pathname.startsWith("/downloads/")) fail("catalog_invalid");
  validateUrl(official, "artifact");
  if (decodeURIComponent(official.pathname.split("/").at(-1)) !== item.filename) fail("catalog_invalid");
  const sources = [{ name: "official", url: official.href }];
  if (item.sources != null && (!Array.isArray(item.sources) || item.sources.length > 3)) fail("catalog_invalid");
  for (const source of item.sources || []) {
    if (!source || !["official", "github"].includes(source.name) || typeof source.url !== "string") fail("catalog_invalid");
    const url = new URL(source.url);
    validateUrl(url, "artifact");
    if ((source.name === "official" && url.hostname !== "hellolynk.com")
      || (source.name === "github" && url.hostname !== "github.com")
      || decodeURIComponent(url.pathname.split("/").at(-1)) !== item.filename) fail("catalog_invalid");
    if (sources.some((entry) => entry.url === url.href)) continue;
    if (sources.some((entry) => entry.name === source.name)) fail("catalog_invalid");
    sources.push({ name: source.name, url: url.href });
  }
  return { client, version: item.version, filename: item.filename, bytes: item.bytes, sha256: item.sha256, sources };
}

function validateUrl(url, kind, redirected = false, initial = url) {
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash) fail("url_invalid");
  if (kind === "catalog") { if (url.href !== CATALOG) fail("url_invalid"); return; }
  const direct = !url.search && ((url.hostname === "hellolynk.com" && /^\/downloads\/[A-Za-z0-9._/-]+$/.test(url.pathname))
    || (url.hostname === "github.com" && /^\/haoyun18881-beep\/HelloLynk\/releases\/download\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(url.pathname)));
  // GitHub release downloads use a signed CDN redirect. Only this exact CDN is
  // accepted, and only when reached from the fixed repository release URL.
  const githubCdn = redirected && initial.hostname === "github.com"
    && url.hostname === "release-assets.githubusercontent.com"
    && /^\/github-production-release-asset\/[A-Za-z0-9/_-]+$/.test(url.pathname);
  if (!direct && !githubCdn) fail("url_invalid");
}

export async function extractClientUpdateArchive({ archivePath, destination, platform = process.platform, maxTotalBytes = 128 * 1024 * 1024, maxFileBytes = 32 * 1024 * 1024, maxEntries = 4096 }) {
  if (!path.isAbsolute(archivePath) || !path.isAbsolute(destination)) fail("archive_path_invalid");
  await safeAncestors(archivePath, false);
  const stat = await fs.lstat(archivePath);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_ARTIFACT) fail("archive_invalid");
  const bytes = await fs.readFile(archivePath);
  let eocd = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50 && offset + 22 + bytes.readUInt16LE(offset + 20) === bytes.length) { eocd = offset; break; }
  }
  if (eocd < 0 || bytes.readUInt16LE(eocd + 4) !== 0 || bytes.readUInt16LE(eocd + 6) !== 0) fail("archive_invalid");
  const count = bytes.readUInt16LE(eocd + 10), centralSize = bytes.readUInt32LE(eocd + 12), central = bytes.readUInt32LE(eocd + 16);
  if (!count || count > maxEntries || count === 65535 || count !== bytes.readUInt16LE(eocd + 8) || central + centralSize !== eocd) fail("archive_invalid");
  const entries = [], nodes = new Map(), spans = [];
  let cursor = central, total = 0;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > eocd || bytes.readUInt32LE(cursor) !== 0x02014b50) fail("archive_invalid");
    const flags = bytes.readUInt16LE(cursor + 8), method = bytes.readUInt16LE(cursor + 10);
    const crc = bytes.readUInt32LE(cursor + 16), packed = bytes.readUInt32LE(cursor + 20), size = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28), extraLength = bytes.readUInt16LE(cursor + 30), commentLength = bytes.readUInt16LE(cursor + 32);
    const external = bytes.readUInt32LE(cursor + 38), local = bytes.readUInt32LE(cursor + 42);
    if (cursor + 46 + nameLength + extraLength + commentLength > eocd || flags & ~0x080e || flags & 1
      || ![0, 8].includes(method) || bytes.readUInt16LE(cursor + 34) !== 0 || size > maxFileBytes
      || packed === 0xffffffff || size === 0xffffffff || local === 0xffffffff) fail("archive_invalid");
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString("utf8");
    if (!Buffer.from(name, "utf8").equals(nameBytes)) fail("archive_path_invalid");
    const directory = name.endsWith("/");
    const segments = safeArchivePath(name, directory);
    const mode = external >>> 16;
    if ((mode & 0xf000) && (mode & 0xf000) !== (directory ? 0x4000 : 0x8000)) fail("archive_path_invalid");
    if ((external & 0x400) !== 0) fail("archive_path_invalid");
    for (let part = 0; part < segments.length; part += 1) {
      const key = segments.slice(0, part + 1).join("/").toLowerCase();
      const leaf = part === segments.length - 1;
      const wanted = !leaf || directory ? "directory" : "file";
      const prior = nodes.get(key);
      if (prior && (prior.kind !== wanted || (leaf && prior.explicit)
        || prior.spelling !== segments.slice(0, part + 1).join("/"))) fail("archive_duplicate_path");
      nodes.set(key, { kind: wanted, explicit: Boolean(prior?.explicit || leaf), spelling: segments.slice(0, part + 1).join("/") });
    }
    if (local + 30 > central || bytes.readUInt32LE(local) !== 0x04034b50
      || bytes.readUInt16LE(local + 6) !== flags || bytes.readUInt16LE(local + 8) !== method) fail("archive_invalid");
    const localNameLength = bytes.readUInt16LE(local + 26), localExtraLength = bytes.readUInt16LE(local + 28);
    const start = local + 30 + localNameLength + localExtraLength;
    if (start + packed > central || !bytes.subarray(local + 30, local + 30 + localNameLength).equals(nameBytes)) fail("archive_invalid");
    if (!(flags & 8) && (bytes.readUInt32LE(local + 14) !== crc || bytes.readUInt32LE(local + 18) !== packed || bytes.readUInt32LE(local + 22) !== size)) fail("archive_invalid");
    if (directory && (size !== 0 || packed > 2)) fail("archive_invalid");
    total += size;
    if (total > maxTotalBytes) fail("archive_too_large");
    spans.push([local, start + packed]);
    entries.push({ segments, directory, start, packed, size, method, crc, mode });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  if (cursor !== eocd) fail("archive_invalid");
  spans.sort((a, b) => a[0] - b[0]);
  if (spans[0][0] !== 0 || spans.some((entry, index) => index > 0 && entry[0] < spans[index - 1][1])) fail("archive_invalid");
  await safeAncestors(destination, true);
  await fs.mkdir(destination, { mode: 0o700 });
  for (const entry of entries) {
    const target = path.join(destination, ...entry.segments);
    if (entry.directory) { await safeDirectory(target); continue; }
    await safeDirectory(path.dirname(target));
    const compressed = bytes.subarray(entry.start, entry.start + entry.packed);
    let body;
    try { body = entry.method === 0 ? compressed : inflateRawSync(compressed, { maxOutputLength: Math.max(1, entry.size) }); }
    catch { fail("archive_integrity_invalid"); }
    if (body.length !== entry.size || crc32(body) !== entry.crc) fail("archive_integrity_invalid");
    // A Mac update runs a bundled Keychain helper. Keep its execute bit without
    // inheriting group/other access or special permission bits from the ZIP.
    const ownerExecute = platform === "darwin" ? entry.mode & 0o100 : 0;
    await fs.writeFile(target, body, { flag: "wx", mode: 0o600 | ownerExecute });
  }
  return Object.freeze({ files: entries.filter((item) => !item.directory).length, bytes: total });
}

function safeArchivePath(name, directory) {
  if (!name || name.length > 240 || name.includes("\\") || name.startsWith("/")) fail("archive_path_invalid");
  const segments = (directory ? name.slice(0, -1) : name).split("/");
  for (const segment of segments) {
    if (!segment || segment === "." || segment === ".." || /[\x00-\x1f\x7f<>:"|?*~]/.test(segment)
      || /[. ]$/.test(segment) || /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/i.test(segment)
      || /^(?:conin\$|conout\$)(?:\.|$)/i.test(segment)
      || segment.normalize("NFC") !== segment) fail("archive_path_invalid");
  }
  return segments;
}
async function verifyDownloaded(record) {
  await safeAncestors(record.artifactPath, false);
  await safeAncestors(record.extractedRoot, true);
  const stat = await fs.lstat(record.artifactPath);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size !== record.bytes || sha(await fs.readFile(record.artifactPath)) !== record.sha256) fail("artifact_integrity_invalid");
  if (!(await fs.lstat(record.extractedRoot)).isDirectory()) fail("artifact_integrity_invalid");
}
async function safeDirectory(directory) { await safeAncestors(directory, true); await fs.mkdir(directory, { recursive: true, mode: 0o700 }); await safeAncestors(directory, true); }
async function safeAncestors(target, directory) {
  const absolute = path.resolve(target), base = path.parse(absolute).root;
  let current = base;
  const parts = absolute.slice(base.length).split(path.sep).filter(Boolean);
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink() || ((index < parts.length - 1 || directory) && !stat.isDirectory())) fail("path_invalid");
    } catch (error) { if (error.code === "ENOENT") continue; throw error; }
  }
}
function safeFilename(value) { return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$/.test(value); }
function sourceOrigin(url) { return new URL(url).origin; }
function sha(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function bounded(value, fallback, min, max) { return Number.isInteger(value) && value >= min && value <= max ? value : fallback; }
function updateError(code) { return Object.assign(new Error(`client_update_${code}`), { code: `client_update_${code}` }); }
function fail(code) { throw updateError(code); }
function semver(value) {
  if (typeof value !== "string" || value.length > 100) return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(value);
  if (!match || match.slice(1, 4).some((part) => !Number.isSafeInteger(Number(part)))) return null;
  const pre = match[4]?.split(".") || [];
  if (pre.some((part) => /^\d+$/.test(part) && ((part.length > 1 && part[0] === "0") || !Number.isSafeInteger(Number(part))))) return null;
  return { nums: match.slice(1, 4).map(Number), pre };
}
export function compareClientUpdateVersions(a, b) { return compareVersions(a, b); }
function compareVersions(a, b) {
  const left = semver(a), right = semver(b);
  if (!left || !right) fail("version_invalid");
  for (let index = 0; index < 3; index += 1) if (left.nums[index] !== right.nums[index]) return left.nums[index] > right.nums[index] ? 1 : -1;
  if (!left.pre.length || !right.pre.length) return left.pre.length === right.pre.length ? 0 : left.pre.length ? -1 : 1;
  for (let index = 0; index < Math.max(left.pre.length, right.pre.length); index += 1) {
    const x = left.pre[index], y = right.pre[index];
    if (x == null || y == null) return x == null ? -1 : 1;
    if (x === y) continue;
    const xn = /^\d+$/.test(x), yn = /^\d+$/.test(y);
    if (xn !== yn) return xn ? -1 : 1;
    return xn ? Number(x) > Number(y) ? 1 : -1 : x > y ? 1 : -1;
  }
  return 0;
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
