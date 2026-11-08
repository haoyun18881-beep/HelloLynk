import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const HASH = /^[a-f0-9]{64}$/;
const TTL = 10 * 60_000;
export const WORKBUDDY_MODEL_INBOX_NAMES = new Set([
  "hellolynk_get_unread_count", "hellolynk_list_authorized_inbox_messages",
  "hellolynk_read_authorized_inbox_message", "hellolynk_list_pending_messages",
  "hellolynk_claim_message", "hellolynk_reply_authorized_message",
]);
const failure = () => Object.assign(new Error("model_inbox_context_unavailable"), { code: "model_inbox_context_unavailable" });
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const argsHash = args => hash(JSON.stringify(stable(args)));
function object(value) {
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return null; } }
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
export function workBuddyModelHookCall(payload) {
  if (payload?.hook_event_name !== "PreToolUse") return null;
  let name = payload.tool_name, args = object(payload.tool_input);
  if (name === "DeferExecuteTool") { name = args?.toolName; args = object(args?.params); }
  if (typeof name !== "string" || !/^mcp__hellolynk__/.test(name)) return null;
  name = name.replace(/^mcp__hellolynk__/, "");
  if (!name.startsWith("hellolynk_")) name = "hellolynk_" + name;
  return WORKBUDDY_MODEL_INBOX_NAMES.has(name) && args ? { name, args } : null;
}
export async function recordWorkBuddyModelCall(inbox, payload, scopeHash, now = Date.now()) {
  const call = workBuddyModelHookCall(payload);
  if (!call) return false;
  if (![payload.session_id, payload.tool_use_id || payload.call_id, payload.generation_id].every(v => ID.test(v || ""))
    || !HASH.test(scopeHash || "") || (payload.agent_id && payload.agent_id !== payload.session_id)) throw failure();
  const directory = path.join(inbox, "model-calls");
  await fs.mkdir(directory, { recursive: true });
  const record = { version: 1, scopeHash, threadId: payload.session_id, generationId: payload.generation_id,
    toolUseId: payload.tool_use_id || payload.call_id, name: call.name, argsHash: argsHash(call.args), createdAt: now };
  const file = path.join(directory, hash(scopeHash + "\0" + record.toolUseId) + ".json");
  const temporary = file + "." + crypto.randomUUID() + ".tmp";
  try {
    await fs.writeFile(temporary, JSON.stringify(record), { flag: "wx" });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
  // Short-lived request evidence, cleaned on subsequent calls; no timer.
  for (const name of await fs.readdir(directory)) if (/^[a-f0-9]{64}\.json$/.test(name)) {
    const candidate = path.join(directory, name), stat = await fs.stat(candidate).catch(() => null);
    if (stat && now - stat.mtimeMs > TTL) await fs.rm(candidate, { force: true });
  }
  return true;
}
function baggage(meta) {
  if (typeof meta?.baggage !== "string") return null;
  const fields = new Map();
  try {
    for (const part of meta.baggage.split(",")) {
      const item = part.split(";")[0], equal = item.indexOf("=");
      if (equal < 0) continue;
      const key = item.slice(0, equal).trim(), value = decodeURIComponent(item.slice(equal + 1).trim());
      if (fields.has(key)) return null;
      fields.set(key, value);
    }
  } catch { return null; }
  const threadId = fields.get("codebuddy.session_id"), generationId = fields.get("codebuddy.conversation_request_id");
  return ID.test(threadId || "") && ID.test(generationId || "") ? { threadId, generationId } : null;
}
export async function readWorkBuddyModelCaller(inbox, meta, name, args, scopeHash, now = Date.now()) {
  const native = baggage(meta);
  if (!native || !HASH.test(scopeHash || "")) return undefined;
  const directory = path.join(inbox, "model-calls"), digest = argsHash(args);
  const files = await fs.readdir(directory).catch(error => { if (error.code === "ENOENT") return []; throw error; });
  const callers = new Set();
  for (const file of files) if (/^[a-f0-9]{64}\.json$/.test(file)) {
    let record;
    try { record = JSON.parse(await fs.readFile(path.join(directory, file), "utf8")); }
    catch { return undefined; }
    if (record.version !== 1 || record.scopeHash !== scopeHash || record.name !== name || record.argsHash !== digest
      || record.generationId !== native.generationId || !Number.isSafeInteger(record.createdAt)
      || now - record.createdAt < 0 || now - record.createdAt > TTL) continue;
    if (!ID.test(record.threadId || "")) return undefined;
    callers.add(record.threadId);
  }
  // Do not trust baggage alone: it can be inherited from a parent turn.
  // The current hook must independently agree on the native chat and arguments.
  return callers.size === 1 && callers.has(native.threadId) ? { threadId: native.threadId } : undefined;
}
