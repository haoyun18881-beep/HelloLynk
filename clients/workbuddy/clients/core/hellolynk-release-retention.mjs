import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const clients = ['codex', 'openclaw', 'trae-work', 'workbuddy', 'dsh', 'claude-code'];
const contract = 'hellolynk-release-retention-v1';
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
    let old = null;
    try {
      const stat = await fs.lstat(receiptPath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4096) throw failure('release_retention_receipt_invalid');
      old = JSON.parse(await fs.readFile(receiptPath, 'utf8'));
      if (old?.contract !== contract || old.client !== client || !pattern.test(old.current)
        || old.previous !== null && !pattern.test(old.previous) || old.current === old.previous) throw failure('release_retention_receipt_invalid');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const supplied = previousRelease === null ? null : nameOf(previousRelease);
    const previous = supplied && supplied !== current ? supplied
      : old?.current === current ? old.previous : old?.current || null;
    const retained = [current, previous].filter(Boolean);
    for (const name of retained) await directory(path.join(root, name));
    const referenced = new Set([...referencedReleases.map(nameOf),
      ...await (dependencies.configuredReleases || configuredReleaseNames)(releasesRoot)]);
    const running = new Set(await (dependencies.runningReleases || runningReleaseNames)(root));
    // Publish before deleting. An interrupted cleanup can retry the exact same
    // pair on same-version reinstall without accidentally dropping its backup.
    const temporary = `${receiptPath}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify({ contract, client, current, previous }) + '\n', { flag: 'wx', mode: 0o600 });
      await fs.rename(temporary, receiptPath);
    } finally { await fs.unlink(temporary).catch(e => { if (e.code !== 'ENOENT') throw e; }); }
    result.retained = retained;
    await removeReleases(root, name => pattern.test(name) && !retained.includes(name), referenced, running, result, dependencies);
    result.complete = result.deferred.length === 0;
  } catch (error) { result.error = safeCode(error); }
  return result;
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
    const running = new Set(await (dependencies.runningReleases || runningReleaseNames)(root));
    await removeReleases(root, name => pattern.test(name), referenced, running, result, dependencies);
    if (!result.deferred.length) await fs.rm(path.join(root, `.${client}-retention.json`), { force: true });
    result.complete = result.deferred.length === 0;
  } catch (error) { result.error = safeCode(error); }
  return result;
}

async function removeReleases(root, selected, referenced, running, result, dependencies) {
  for (const name of await fs.readdir(root)) {
    if (!selected(name)) continue;
    if (referenced.has(name)) { result.deferred.push({ name, reason: 'release_still_referenced' }); continue; }
    if (running.has(name)) { result.deferred.push({ name, reason: 'release_in_use' }); continue; }
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
