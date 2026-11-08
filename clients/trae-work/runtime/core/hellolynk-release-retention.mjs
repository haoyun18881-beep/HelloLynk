import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const clients = ['codex', 'openclaw', 'trae-work', 'workbuddy', 'dsh', 'claude-code'];
const contract = 'hellolynk-release-retention-v1';
// Claude starts every HelloLynk process through one stable copy of the entry, so
// a command line never names the release that process loaded. The entry records
// it under releases/.claude-code-processes/<pid>.json (see stable-entry.mjs).
// Cleanup code from before these records reads only a v1 receipt and stops at
// any other one before deleting, so a client with a stable entry keeps a v2
// receipt: an older worker that cleans up after an update deletes nothing.
const ENTRY = { 'claude-code': ['claude-code', 'hellolynk-claude-code.mjs'] };
const contractWithEntry = 'hellolynk-release-retention-v2';
const PROCESS_CONTRACT = 'hellolynk-release-process-v1';
const START_TOLERANCE_MS = 15000;
export const releaseProcessDirectory = (releasesRoot, client) => path.join(releasesRoot, `.${client}-processes`);
const failure = code => Object.assign(new Error(code), { code });
const equal = (a, b) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;

async function directory(target) {
  const stat = await fs.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure('release_retention_path_invalid');
  return stat;
}

async function rootPath(root) {
  if (!path.isAbsolute(root || '') || path.basename(root) !== 'releases') throw failure('release_retention_root_invalid');
  const resolved = path.resolve(root);
  for (let p = resolved; ; p = path.dirname(p)) {
    await directory(p);
    if (p === path.dirname(p)) break;
  }
  // Windows may supply an 8.3 TEMP/user path. Parents were checked above;
  // delete only under its canonical absolute spelling.
  return fs.realpath(resolved);
}

async function regularTree(target) {
  await directory(target);
  for (const item of await fs.readdir(target, { withFileTypes: true })) {
    const child = path.join(target, item.name), stat = await fs.lstat(child);
    if (stat.isSymbolicLink()) throw failure('release_retention_link');
    if (stat.isDirectory()) await regularTree(child);
    else if (!stat.isFile() || stat.nlink !== 1) throw failure('release_retention_file_invalid');
  }
}

// Read only release references, never return process command lines. A running
// older Host may still import files after installation; deletion waits for the
// next successful install instead of stopping any user process.
export async function runningReleaseNames(releasesRoot) {
  if (process.platform !== 'win32') throw failure('release_retention_process_check_unavailable');
  const root = await rootPath(releasesRoot);
  const literal = `${root}${path.sep}`.replaceAll("'", "''");
  const script = `$ErrorActionPreference='Stop'; $pattern=[regex]::Escape('${literal}')+'((?:codex|openclaw|trae-work|workbuddy|dsh|claude-code)-[a-f0-9]{64})(?=[\\\\/"\\s]|$)'; $names=@(Get-CimInstance Win32_Process | ForEach-Object { if ($_.CommandLine) { foreach ($m in [regex]::Matches($_.CommandLine,$pattern,'IgnoreCase')) { $m.Groups[1].Value.ToLowerInvariant() } } }); ConvertTo-Json -Compress -InputObject @($names | Sort-Object -Unique)`;
  const shell = path.join(process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const result = await execute(shell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: 15000, maxBuffer: 256 * 1024 });
  const names = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim());
  if (!Array.isArray(names) || names.some(n => typeof n !== 'string' || !/^(?:codex|openclaw|trae-work|workbuddy|dsh|claude-code)-[a-f0-9]{64}$/.test(n))) {
    throw failure('release_retention_process_check_invalid');
  }
  return names;
}

// The given pids and every process whose command line runs this installation's
// stable entry: pid, start time and whether it runs the entry. Only processes
// with a positive pid are listed, and command lines never leave PowerShell.
export async function entryProcessList(client, releasesRoot, pids = []) {
  if (!ENTRY[client]) return [];
  if (process.platform !== 'win32') throw failure('release_retention_process_check_unavailable');
  if (!Array.isArray(pids) || pids.some(pid => !Number.isSafeInteger(pid) || pid <= 0)) throw failure('release_retention_process_check_invalid');
  const root = await rootPath(releasesRoot);
  // This installation's entry only, in its given and canonical spellings:
  // any case, either slash, quoted or not.
  const literal = value => value.split(/[\\/]+/).map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[\\\\/]+');
  const entries = [...new Set([root, path.resolve(releasesRoot)])].map(value => literal(path.join(path.dirname(value), ...ENTRY[client])));
  const pattern = `(?<=^|["\\s])(?:${entries.join('|')})(?=["\\s]|$)`.replaceAll("'", "''");
  const script = `$ErrorActionPreference='Stop'; $wanted=@(${pids.join(',')}); $epoch=[datetime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc); $list=@(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { $entry=[bool]($_.CommandLine -and [regex]::IsMatch($_.CommandLine,'${pattern}','IgnoreCase')); if ($entry -or ($wanted -contains [int64]$_.ProcessId)) { [pscustomobject]@{ pid=[int64]$_.ProcessId; startedAt=$(if ($_.CreationDate) { [int64](($_.CreationDate.ToUniversalTime() - $epoch).TotalMilliseconds) } else { $null }); entry=$entry } } }); ConvertTo-Json -Compress -InputObject $list`;
  const shell = path.join(process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const { stdout } = await execute(shell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 });
  const list = JSON.parse(stdout.replace(/^\uFEFF/, '').trim() || '[]');
  if (!Array.isArray(list) || list.some(p => !Number.isSafeInteger(p?.pid) || p.pid <= 0 || typeof p.entry !== 'boolean'
    || (p.startedAt !== null && !Number.isSafeInteger(p.startedAt)))) throw failure('release_retention_process_check_invalid');
  return list;
}

// Releases named by live entry records, and whether a process started through
// the stable entry has no matching record (one from before records existed).
// Records of exited or reused pids are removed, so a release can go at the
// next install once its last process is gone.
async function entryReleases(releasesRoot, root, client, pattern, dependencies) {
  if (!ENTRY[client]) return { names: [], unregistered: false };
  const folder = releaseProcessDirectory(root, client);
  let items = [];
  try {
    await directory(folder);
    items = await fs.readdir(folder, { withFileTypes: true });
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const records = items.filter(item => item.isFile() && /^[1-9]\d{0,9}\.json$/.test(item.name))
    .map(item => ({ pid: Number(item.name.slice(0, -5)), file: path.join(folder, item.name) }));
  // The given root too: an entry may be named in the spelling the caller uses, not only the canonical one.
  const processes = await (dependencies.entryProcesses || entryProcessList)(client, releasesRoot, records.map(record => record.pid));
  const live = new Map(processes.map(p => [p.pid, p])), names = new Set(), registered = new Set();
  let unregistered = false;
  for (const { pid, file } of records) {
    const alive = live.get(pid), started = Number.isSafeInteger(alive?.startedAt) ? alive.startedAt : null;
    let record = null;
    try { record = JSON.parse(await fs.readFile(file, 'utf8')); } catch {}
    const valid = record?.contract === PROCESS_CONTRACT && record.pid === pid && Number.isSafeInteger(record.startedAt)
      && typeof record.release === 'string' && pattern.test(record.release);
    if (valid && started !== null && Math.abs(started - record.startedAt) <= START_TOLERANCE_MS) {
      registered.add(pid); names.add(record.release);
    } else if (!alive || (valid && started !== null)) {
      await fs.rm(file, { force: true }).catch(() => {}); // Exited, or the pid now belongs to a later process.
    } else unregistered = true; // Live, but its record is still being written or its start time is unknown.
  }
  if (processes.some(p => p.entry && !registered.has(p.pid))) unregistered = true;
  return { names: [...names], unregistered };
}

// A stopped on-demand task is still a configuration reference. Keeping only
// live processes can delete its executable before the next client startup.
export async function configuredReleaseNames(releasesRoot) {
  if (process.platform !== 'win32') throw failure('release_retention_configuration_check_unavailable');
  const root = await rootPath(releasesRoot);
  const prefixes = [...new Set([root, path.resolve(releasesRoot)])].map(value => (value + path.sep).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const pattern = ('(?:' + prefixes.join('|') + ')((?:codex|openclaw|trae-work|workbuddy|dsh|claude-code)-[a-f0-9]{64})(?=[\\\\/"\\s]|$)').replaceAll("'", "''");
  const script = "$ErrorActionPreference='Stop'; $pattern='" + pattern + "'; $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); $names=@($scheduler.GetFolder('\\').GetTasks(1) | Where-Object { $_.Name -like 'HelloLynk *' } | ForEach-Object { foreach ($a in $_.Definition.Actions) { foreach ($v in @($a.Path,$a.Arguments,$a.WorkingDirectory)) { foreach ($m in [regex]::Matches([string]$v,$pattern,'IgnoreCase')) { $m.Groups[1].Value.ToLowerInvariant() } } } }); ConvertTo-Json -Compress -InputObject @($names | Sort-Object -Unique)";
  const shell = path.join(process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const { stdout } = await execute(shell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: 15000, maxBuffer: 256 * 1024 });
  const names = JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  if (!Array.isArray(names) || names.some(n => typeof n !== 'string' || !/^(?:codex|openclaw|trae-work|workbuddy|dsh|claude-code)-[a-f0-9]{64}$/.test(n))) {
    throw failure('release_retention_configuration_check_invalid');
  }
  return names;
}

// Call only after the caller's complete adoption transaction succeeds, while
// holding its install/account lock. Never call from candidate staging or a
// rollback. The receipt records adoption order, not directory timestamps.
// Cleanup failure is reported separately and must not roll back a good install.
export async function pruneInstalledReleases({ releasesRoot, client, currentRelease, previousRelease = null, referencedReleases = [] }, dependencies = {}) {
  const result = { complete: false, retained: [], removed: [], deferred: [] };
  try {
    if (!clients.includes(client)) throw failure('release_retention_client_invalid');
    const root = await rootPath(releasesRoot), pattern = new RegExp(`^${client}-[a-f0-9]{64}$`);
    const nameOf = value => {
      if (typeof value !== 'string' || !path.isAbsolute(value)
        || ![root, path.resolve(releasesRoot)].some(p => equal(path.dirname(path.resolve(value)), p))
        || !pattern.test(path.basename(value))) throw failure('release_retention_target_invalid');
      return path.basename(value);
    };
    const current = nameOf(currentRelease);
    const receiptPath = path.join(root, `.${client}-retention.json`);
    const old = await readReceipt(receiptPath, client, pattern);
    const supplied = previousRelease === null ? null : nameOf(previousRelease);
    const previous = supplied && supplied !== current ? supplied
      : old?.current === current ? old.previous : old?.current || null;
    const retained = [current, previous].filter(Boolean);
    for (const name of retained) await directory(path.join(root, name));
    const referenced = new Set([...referencedReleases.map(nameOf),
      ...await (dependencies.configuredReleases || configuredReleaseNames)(releasesRoot)]);
    const entry = await entryReleases(releasesRoot, root, client, pattern, dependencies);
    const running = new Set([...await (dependencies.runningReleases || runningReleaseNames)(root), ...entry.names]);
    // Publish before deleting. An interrupted cleanup can retry the exact same
    // pair on same-version reinstall without accidentally dropping its backup.
    await writeReceipt(receiptPath, { contract: receiptContract(client), client, current, previous });
    result.retained = retained;
    await removeReleases(root, name => pattern.test(name) && !retained.includes(name), referenced, running, result, dependencies, entry.unregistered);
    result.complete = result.deferred.length === 0;
  } catch (error) { result.error = safeCode(error); }
  return result;
}

// A stable-entry client calls this before it switches an install on its stable
// entry. An update worker of an earlier release cleans up after that install with
// its own code, which cannot see what a stable-entry process runs and stops
// before deleting only at a receipt other than v1. Resolves once the receipt is
// v2, keeping the adoption it records, with whether it wrote. Throws when that
// cannot be confirmed, even for a cause that passes before the worker reads the
// receipt (a file another process holds open): the caller then switches nothing.
// currentRelease, the release the install starts now, is recorded only when
// there is no receipt yet.
export async function protectRetentionReceipt({ releasesRoot, client, currentRelease }) {
  if (!ENTRY[client]) throw failure('release_retention_client_invalid');
  const root = await rootPath(releasesRoot), pattern = new RegExp(`^${client}-[a-f0-9]{64}$`);
  const receiptPath = path.join(root, `.${client}-retention.json`);
  const old = await readReceipt(receiptPath, client, pattern);
  if (old?.contract === contractWithEntry) return false;
  let current = old?.current;
  if (!current) {
    if (typeof currentRelease !== 'string' || !path.isAbsolute(currentRelease) || !pattern.test(path.basename(currentRelease))
      || ![root, path.resolve(releasesRoot)].some(p => equal(path.dirname(path.resolve(currentRelease)), p))) throw failure('release_retention_target_invalid');
    current = path.basename(currentRelease);
    await directory(path.join(root, current));
  }
  await writeReceipt(receiptPath, { contract: contractWithEntry, client, current, previous: old ? old.previous : null });
  return true;
}

const receiptContract = client => ENTRY[client] ? contractWithEntry : contract;

async function readReceipt(receiptPath, client, pattern) {
  let old = null;
  try {
    const stat = await fs.lstat(receiptPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4096) throw failure('release_retention_receipt_invalid');
    old = JSON.parse(await fs.readFile(receiptPath, 'utf8'));
    if (![contract, contractWithEntry].includes(old?.contract) || old.client !== client || !pattern.test(old.current)
      || old.previous !== null && !pattern.test(old.previous) || old.current === old.previous) throw failure('release_retention_receipt_invalid');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error.code ? error : failure('release_retention_receipt_invalid');
  }
  return old;
}

async function writeReceipt(receiptPath, receipt) {
  const temporary = `${receiptPath}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify(receipt) + '\n', { flag: 'wx', mode: 0o600 });
    await fs.rename(temporary, receiptPath);
  } finally { await fs.unlink(temporary).catch(e => { if (e.code !== 'ENOENT') throw e; }); }
}

// Uninstall keeps no release. One a process or scheduled task still uses is
// left for the next install or uninstall, like any other deferred release.
export async function removeInstalledReleases({ releasesRoot, client }, dependencies = {}) {
  const result = { complete: false, removed: [], deferred: [] };
  try {
    if (!clients.includes(client)) throw failure('release_retention_client_invalid');
    try { await fs.lstat(releasesRoot); } catch (error) { if (error.code === 'ENOENT') return { ...result, complete: true }; throw error; }
    const root = await rootPath(releasesRoot), pattern = new RegExp(`^${client}-[a-f0-9]{64}$`);
    const referenced = new Set(await (dependencies.configuredReleases || configuredReleaseNames)(releasesRoot));
    const entry = await entryReleases(releasesRoot, root, client, pattern, dependencies);
    const running = new Set([...await (dependencies.runningReleases || runningReleaseNames)(root), ...entry.names]);
    await removeReleases(root, name => pattern.test(name), referenced, running, result, dependencies, entry.unregistered);
    if (!result.deferred.length) {
      await fs.rm(path.join(root, `.${client}-retention.json`), { force: true });
      // entryReleases checked above that this is a folder in the releases root.
      if (ENTRY[client]) await fs.rm(releaseProcessDirectory(root, client), { recursive: true, force: true });
    }
    result.complete = result.deferred.length === 0;
  } catch (error) { result.error = safeCode(error); }
  return result;
}

// An unregistered entry process may run any release of its client, so then
// none is removed until it exits.
async function removeReleases(root, selected, referenced, running, result, dependencies, unregistered = false) {
  for (const name of await fs.readdir(root)) {
    if (!selected(name)) continue;
    if (referenced.has(name)) { result.deferred.push({ name, reason: 'release_still_referenced' }); continue; }
    if (running.has(name)) { result.deferred.push({ name, reason: 'release_in_use' }); continue; }
    if (unregistered) { result.deferred.push({ name, reason: 'release_in_use_unregistered' }); continue; }
    try {
      // The final absolute target is a checked direct child of the canonical
      // releases root; never follow a junction inside an obsolete package.
      const target = path.resolve(root, name);
      if (!equal(path.dirname(target), root) || !equal(await fs.realpath(target), target)) throw failure('release_retention_path_invalid');
      await regularTree(target);
      await (dependencies.remove || fs.rm)(target, { recursive: true });
      result.removed.push(name);
    } catch (error) { result.deferred.push({ name, reason: safeCode(error) }); }
  }
}

function safeCode(error) {
  return /^(?:release_retention_[a-z_]+|E[A-Z]+)$/.test(error?.code || '') ? error.code : 'release_retention_failed';
}
