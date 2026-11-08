import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { nativeReplyRouteLocation, rememberNativeReplyRoute } from "../../../clients/core/hellolynk-native-reply-routes.mjs";
import { WORKBUDDY_ACTIVE_SCOPE_FILE, WORKBUDDY_ORIGIN_DIRECT_TOOL_MATCHER, WORKBUDDY_ORIGIN_TOOL_MATCHER, readWorkBuddyActiveScope } from "./origin-hook.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const THREAD = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const DROP = /^[a-f0-9]{64}\.json$/;
const SCOPE = /^[a-f0-9]{64}$/;
const TEMPORARY = /^[a-f0-9]{64}\.json\.\d+\.[a-f0-9]{12}\.tmp$/;
const STATUS = /^[a-z][a-z0-9_]{0,79}$/;
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const failure = (code) => Object.assign(new Error(code), { code });

export function workBuddyOriginInbox(storeRoot) {
  if (typeof storeRoot !== "string" || !path.isAbsolute(storeRoot)) throw failure("workbuddy_origin_inbox_invalid");
  return path.join(storeRoot, "workbuddy-origin-inbox");
}

// Tells the hook which account the MCP proxy or worker is connected to. Rewritten only
// when the account changes; the hash names no person and holds no secret.
export async function markWorkBuddyActiveScope(inbox, scope) {
  const { scopeHash } = nativeReplyRouteLocation(scope);
  if (await readWorkBuddyActiveScope(inbox) === scopeHash) return false;
  await fs.mkdir(inbox, { recursive: true });
  const file = path.join(inbox, WORKBUDDY_ACTIVE_SCOPE_FILE), temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify({ version: 1, scopeHash }), { flag: "wx", mode: 0o600 });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
  return true;
}

// Moves hook records into the current account's reply-route store. Records
// made under another account, invalid or conflicting records are dropped (the
// first route wins); a temporary file error keeps the record for the next tick.
export async function importWorkBuddyOriginDrops(inbox, scope, { remember = rememberNativeReplyRoute, now = Date.now, limit = 200 } = {}) {
  const { scopeHash } = nativeReplyRouteLocation(scope);
  let names;
  try { names = await fs.readdir(inbox); }
  catch (error) { if (error.code === "ENOENT") return 0; throw error; }
  const drops = [];
  for (const name of names) {
    const file = path.join(inbox, name);
    if (TEMPORARY.test(name)) {
      // Left by an interrupted hook; a live hook renames within milliseconds.
      const stat = await fs.lstat(file).catch(() => null);
      if (stat && now() - stat.mtimeMs > 60 * 60 * 1000) await fs.rm(file, { force: true });
    } else if (DROP.test(name) && drops.length < limit) {
      // A file that cannot be read right now (busy, or removed meanwhile) waits for the next tick.
      try { drops.push({ file, record: await readDrop(file) }); } catch {}
    }
  }
  drops.sort((a, b) => (a.record?.createdAt ?? 0) - (b.record?.createdAt ?? 0) || a.file.localeCompare(b.file));
  let imported = 0;
  for (const { file, record } of drops) {
    if (record?.scopeHash === scopeHash) {
      try { await remember(scope, record); imported += 1; }
      catch (error) { if (!["native_reply_route_conflict", "native_reply_route_invalid"].includes(error?.message)) continue; }
    }
    await fs.rm(file, { force: true });
  }
  return imported;
}

// null marks a file that is not a valid record, which is deleted. A file
// error is thrown instead, so the caller keeps the file.
async function readDrop(file) {
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return null;
  const text = await fs.readFile(file, "utf8");
  let record;
  try { record = JSON.parse(text); } catch { return null; }
  const keys = Object.keys(record || {}).sort().join();
  if (keys !== "clientMessageId,conversationKey,createdAt,peerDelegateId,scopeHash,threadId,version" || record.version !== 1
    || !SCOPE.test(record.scopeHash || "") || !THREAD.test(record.threadId || "") || !ID.test(record.clientMessageId || "")
    || !Number.isSafeInteger(record.createdAt) || (record.conversationKey === null) === (record.peerDelegateId === null)
    || ![record.conversationKey, record.peerDelegateId].every((value) => value === null || ID.test(value))) return null;
  return { scopeHash: record.scopeHash, threadId: record.threadId, clientMessageId: record.clientMessageId,
    conversationKey: record.conversationKey, peerDelegateId: record.peerDelegateId, createdAt: record.createdAt };
}

// One file per reply delivered to an original conversation. It is written
// before the desktop call, so a crash or unknown result is never repeated.
export function createWorkBuddyOriginLedger(scope) {
  const { scopeHash } = nativeReplyRouteLocation(scope);
  const directory = path.join(path.resolve(scope.runtimeRoot), "native-origin-deliveries", scopeHash);
  const file = (id) => { if (!ID.test(id || "")) throw failure("workbuddy_native_pending_invalid"); return path.join(directory, `${hash(id)}.json`); };
  return Object.freeze({
    async get(localMessageId) {
      let text;
      try { text = await fs.readFile(file(localMessageId), "utf8"); }
      catch (error) { if (error.code === "ENOENT") return null; throw error; }
      // An unreadable record still means a native write may have started.
      try { return JSON.parse(text); } catch { return { status: "dispatch_unknown" }; }
    },
    async begin(localMessageId, threadId) {
      const target = file(localMessageId);
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
      let handle;
      try {
        handle = await fs.open(target, "wx", 0o600);
        await handle.writeFile(JSON.stringify({ localMessageId, threadId, status: "dispatching" }));
        await handle.sync();
        return true;
      } catch (error) { if (error.code === "EEXIST") return false; throw error; }
      finally { await handle?.close(); }
    },
    async finish(localMessageId, threadId, status) {
      if (!STATUS.test(status || "")) throw failure("workbuddy_native_dispatch_unavailable");
      const target = file(localMessageId), temporary = `${target}.${crypto.randomUUID()}.tmp`;
      try {
        await fs.writeFile(temporary, JSON.stringify({ localMessageId, threadId, status }), { flag: "wx", mode: 0o600 });
        await fs.rename(temporary, target);
      } finally { await fs.rm(temporary, { force: true }); }
    },
    // Only for a record whose desktop call has not started.
    async undo(localMessageId) { await fs.rm(file(localMessageId), { force: true }); },
  });
}

export function workBuddySettingsPath(env = process.env) {
  return path.join(env.WORKBUDDY_CONFIG_DIR || path.join(os.homedir(), ".workbuddy"), "settings.json");
}

// WorkBuddy runs a command whose program is powershell.exe directly, with or
// without Git Bash. The hook inherits stdin, so the payload stays byte-exact;
// piping it through PowerShell would re-encode non-ASCII text.
export function workBuddyOriginHookCommand({ nodePath, hookPath, inbox,
  powershellPath = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe") }) {
  for (const value of [powershellPath, nodePath, hookPath, inbox]) {
    if (typeof value !== "string" || !path.win32.isAbsolute(value) || /["\r\n\0`]|\$\{/.test(value)) throw failure("workbuddy_origin_hook_path_invalid");
  }
  const quote = (value) => `'${value.replace(/'/g, "''")}'`;
  return `"${powershellPath}" -NoProfile -Command "$ErrorActionPreference='SilentlyContinue'; & ${quote(nodePath)} ${quote(hookPath)} --inbox ${quote(inbox)} 2>$null; exit 0"`;
}

// Called when the installed native-task service starts, so the hook always
// runs this release's file. A failed registration never stops delivery;
// replies to sends it missed stay in the HelloLynk inbox.
export async function prepareWorkBuddyOriginHook({ storeRoot, settingsPath, nodePath = process.execPath,
  hookPath = fileURLToPath(new URL("./origin-hook.mjs", import.meta.url)), platform = process.platform } = {}) {
  const inbox = workBuddyOriginInbox(storeRoot);
  let hook = { changed: false, status: "unsupported_platform" };
  if (platform === "win32") {
    try { hook = await ensureWorkBuddyOriginHook({ settingsPath, command: workBuddyOriginHookCommand({ nodePath, hookPath, inbox }) }); }
    catch (error) { hook = { changed: false, status: "unavailable", errorCode: /^workbuddy_[a-z_]{1,80}$/.test(error?.code || "") ? error.code : "workbuddy_origin_hook_unavailable" }; }
  }
  return { inbox, hook };
}

// Adds or replaces the one HelloLynk entry; other hooks and settings stay as they are.
export async function ensureWorkBuddyOriginHook({ command, settingsPath = workBuddySettingsPath() } = {}) {
  if (typeof command !== "string" || !command.includes("origin-hook.mjs")) throw failure("workbuddy_origin_hook_command_invalid");
  const ours = { matcher: WORKBUDDY_ORIGIN_TOOL_MATCHER, hooks: [{ type: "command", command, timeout: 30 }] };
  return updatePreToolUse(settingsPath, (entries) => {
    const index = entries.findIndex(isOriginHook);
    return index < 0 ? [...entries, ours] : entries.flatMap((entry, at) => at === index ? [ours] : isOriginHook(entry) ? [] : [entry]);
  });
}

export async function removeWorkBuddyOriginHook({ command, settingsPath = workBuddySettingsPath() } = {}) {
  if (typeof command !== "string" || !command.includes("origin-hook.mjs")) throw failure("workbuddy_origin_hook_command_invalid");
  // An old release or isolated task must not remove the active installation's hook.
  return updatePreToolUse(settingsPath, (entries) => entries.flatMap((entry) => {
    if (!isOriginHook(entry)) return [entry];
    const hooks = entry.hooks.filter((hook) => hook.command !== command);
    return hooks.length ? [{ ...entry, hooks }] : [];
  }));
}

function isOriginHook(entry) {
  // Recognize installed B248 matchers only to replace/remove their old hook.
  const previous = '^mcp__hellolynk__(?:hellolynk_)?(send|reply)_authorized_message$';
  return [WORKBUDDY_ORIGIN_DIRECT_TOOL_MATCHER, WORKBUDDY_ORIGIN_TOOL_MATCHER,
    previous, `^(?:DeferExecuteTool|${previous.slice(1, -1)})$`].includes(entry?.matcher) && Array.isArray(entry.hooks)
    && entry.hooks.some((hook) => typeof hook?.command === "string" && hook.command.includes("origin-hook.mjs"));
}

async function updatePreToolUse(settingsPath, change) {
  let text;
  // A missing file means WorkBuddy is not set up for this user; never create its directory.
  try { text = await fs.readFile(settingsPath, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return { changed: false, status: "settings_missing" }; throw error; }
  let settings;
  try { settings = JSON.parse(text.replace(/^\uFEFF/, "")); } catch { throw failure("workbuddy_settings_invalid"); }
  const hooks = settings?.hooks ?? {};
  const entries = hooks?.PreToolUse ?? [];
  if (!plain(settings) || !plain(hooks) || !Array.isArray(entries)) throw failure("workbuddy_settings_invalid");
  const next = change(entries);
  if (JSON.stringify(next) === JSON.stringify(entries)) return { changed: false, status: "unchanged" };
  const nextHooks = { ...hooks, PreToolUse: next };
  if (!next.length) delete nextHooks.PreToolUse;
  const nextSettings = { ...settings, hooks: nextHooks };
  if (!Object.keys(nextHooks).length) delete nextSettings.hooks;
  const temporary = `${settingsPath}.${crypto.randomUUID()}.tmp`;
  try {
    // Same layout as WorkBuddy's own settings writes.
    await fs.writeFile(temporary, JSON.stringify(nextSettings, null, 2), { flag: "wx" });
    // Replace only the version read above. If the person or WorkBuddy changed
    // it meanwhile, keep theirs; the next service start registers again.
    if (await fs.readFile(settingsPath, "utf8").catch(() => null) !== text) return { changed: false, status: "settings_changed" };
    await fs.rename(temporary, settingsPath);
  } finally { await fs.rm(temporary, { force: true }); }
  return { changed: true, status: "updated" };
}

function plain(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
