#!/usr/bin/env node
import { recordWorkBuddyModelCall, workBuddyModelHookCall } from "./model-call-origin.mjs";
// WorkBuddy PreToolUse hook: new sends keep best-effort origin registration.
// Inbox calls publish request evidence; a missing native source stops that
// invocation without a prompt. Reply origins are registered after the MCP guard.
// The installed native-task worker moves each record into the account's
// reply-route store; this process holds no binding or credentials. Each record
// carries the account scope the MCP proxy or worker last marked active (a non-secret hash),
// so a record made under one account is never imported into another.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Conversation IDs must also be valid WorkBuddy SDK IDs (128 characters).
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
// Some aggregated MCP modes drop the repeated server prefix from tool names.
const TOOL = /^mcp__hellolynk__(?:hellolynk_)?(send|reply)_authorized_message$/;
export const WORKBUDDY_ORIGIN_DIRECT_TOOL_MATCHER = "^mcp__hellolynk__(?:hellolynk_)?(?:send_authorized_message|reply_authorized_message|get_unread_count|list_authorized_inbox_messages|read_authorized_inbox_message|list_pending_messages|claim_message)$";
export const WORKBUDDY_ORIGIN_TOOL_MATCHER = `^(?:DeferExecuteTool|${WORKBUDDY_ORIGIN_DIRECT_TOOL_MATCHER.slice(1, -1)})$`;
export const WORKBUDDY_ACTIVE_SCOPE_FILE = "active-scope.json";
const SCOPE = /^[a-f0-9]{64}$/;

export function workBuddyOriginFromHook(payload) {
  if (!payload || typeof payload !== "object" || payload.hook_event_name !== "PreToolUse") return null;
  // agent_type is the active agent's name, even in a main conversation.
  // A different store ID identifies a subagent of the named conversation.
  // Equal IDs are accepted; no live restored-session payload is assumed here.
  if (payload.agent_id && payload.agent_id !== payload.session_id) return null;
  let name = payload.tool_name, input = objectInput(payload.tool_input);
  // Current WorkBuddy invokes deferred MCP tools through this one wrapper.
  // Unrelated wrapped calls return before reading or writing any route files.
  if (name === "DeferExecuteTool") { name = input?.toolName; input = objectInput(input?.params); }
  const tool = TOOL.exec(typeof name === "string" ? name : "");
  if (!tool || !input) return null;
  const reply = tool[1] === "reply", target = reply ? input.conversationKey : input.recipientDelegateId;
  if (![payload.session_id, input.clientMessageId, target].every((value) => typeof value === "string" && ID.test(value))) return null;
  return { threadId: payload.session_id, clientMessageId: input.clientMessageId,
    conversationKey: reply ? target : null, peerDelegateId: reply ? null : target };
}

function objectInput(value) {
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return null; } }
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

// Same name for the same record: a repeated hook run is idempotent.
export function workBuddyOriginDropName(origin) {
  return `${crypto.createHash("sha256").update(JSON.stringify([origin.scopeHash, origin.clientMessageId, origin.threadId,
    origin.conversationKey, origin.peerDelegateId])).digest("hex")}.json`;
}

// Written by the MCP proxy or worker for the connected account. Missing or
// damaged: the hook records nothing and replies stay in the HelloLynk inbox.
export async function readWorkBuddyActiveScope(inbox) {
  try {
    const file = path.join(inbox, WORKBUDDY_ACTIVE_SCOPE_FILE);
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.size > 256) return null;
    const marker = JSON.parse(await fs.readFile(file, "utf8"));
    return Object.keys(marker || {}).sort().join() === "scopeHash,version" && marker.version === 1
      && SCOPE.test(marker.scopeHash || "") ? marker.scopeHash : null;
  } catch { return null; }
}

export async function writeWorkBuddyOriginDrop(inbox, origin, now = Date.now()) {
  await fs.mkdir(inbox, { recursive: true });
  const file = path.join(inbox, workBuddyOriginDropName(origin));
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify({ version: 1, ...origin, createdAt: now }), { flag: "wx", mode: 0o600 });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
}

export async function runWorkBuddyOriginHook(argv = process.argv.slice(2), input = process.stdin) {
  const inbox = argv[0] === "--inbox" && argv.length === 2 ? argv[1] : "";
  if (!path.isAbsolute(inbox)) return false;
  const chunks = [];
  let size = 0;
  for await (const chunk of input) {
    size += chunk.length;
    if (size > 1024 * 1024) return false;
    chunks.push(chunk);
  }
  let payload;
  try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return false; }
  const call = workBuddyModelHookCall(payload);
  if (call) {
    try { await recordWorkBuddyModelCall(inbox, payload, await readWorkBuddyActiveScope(inbox)); }
    catch (error) { throw Object.assign(error, { code: "model_inbox_context_unavailable" }); }
    // A reply registers its origin only after the MCP handler checks ownership.
    return true;
  }
  const origin = workBuddyOriginFromHook(payload);
  if (!origin) return false;
  const scopeHash = await readWorkBuddyActiveScope(inbox);
  if (!scopeHash) return false;
  await writeWorkBuddyOriginDrop(inbox, { scopeHash, ...origin });
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runWorkBuddyOriginHook().catch(error => {
    if (error?.code === "model_inbox_context_unavailable") process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny",
        permissionDecisionReason: "无法确定本次调用所在的对话，尚未查信或处理来信。" },
    }) + "\n");
    return false;
  }).finally(() => { process.exitCode = 0; });
}
