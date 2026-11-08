import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const valid = (value) => typeof value === "string" && ID.test(value);
const fail = () => { throw new Error("native_reply_route_invalid"); };

// Only local executor metadata supplies threadId. Neither message text nor a
// model-supplied tool argument can name the native destination.
export async function rememberNativeReplyRoute(scope, input) {
  const { directory, scopeHash } = location(scope);
  const record = { version: 1, scopeHash, clientMessageId: input.clientMessageId,
    threadId: input.threadId, conversationKey: input.conversationKey ?? null,
    peerDelegateId: input.peerDelegateId ?? null };
  validate(record, scopeHash, input.clientMessageId);
  await safeDirectory(scope.runtimeRoot);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await safeDirectory(directory);
  const file = path.join(directory, `${hash(record.clientMessageId)}.json`);
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let handle, temporaryCreated = false;
  try {
    // Publish only a complete, synced record. A link is exclusive and atomic;
    // an existing clientMessageId is never replaced or taken over.
    handle = await fs.open(temporary, "wx", 0o600);
    temporaryCreated = true;
    await handle.writeFile(JSON.stringify(record));
    await handle.sync();
    await handle.close();
    handle = null;
    try {
      await fs.link(temporary, file);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const existing = await readRecord(file, scopeHash, record.clientMessageId);
      if (JSON.stringify(existing) !== JSON.stringify(record)) throw new Error("native_reply_route_conflict");
    }
  } finally {
    // The body either published a complete route or already threw its cause.
    // Cleanup must not replace that result with a secondary close/unlink error.
    try { await handle?.close(); } catch {}
    if (temporaryCreated) await fs.unlink(temporary).catch(() => {});
  }
}

export async function readNativeReplyRoute(scope, message) {
  if (message.replyToClientMessageId == null) return null;
  if (!valid(message.replyToClientMessageId)) fail();
  const { directory, scopeHash } = location(scope);
  try {
    await safeDirectory(directory);
    const record = await readRecord(path.join(directory, `${hash(message.replyToClientMessageId)}.json`),
      scopeHash, message.replyToClientMessageId);
    if (record.conversationKey && record.conversationKey !== message.conversationKey) fail();
    if (record.peerDelegateId && record.peerDelegateId !== message.peerDelegateId) fail();
    return record;
  } catch (error) { if (error.code === "ENOENT") return null; throw error; }
}

export function nativeReplyRouteLocation(scope) {
  if (!scope || !path.isAbsolute(scope.runtimeRoot || "") || !["codex", "claude-code", "dsh", "openclaw", "workbuddy", "cursor", "trae-work"].includes(scope.adapterId)) fail();
  for (const key of ["region", "principalId", "delegateId"])
    if (typeof scope[key] !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,240}$/.test(scope[key])) fail();
  const root = path.resolve(scope.runtimeRoot);
  const scopeHash = hash(JSON.stringify([process.platform === "win32" ? root.toLowerCase() : root,
    scope.region, scope.principalId, scope.delegateId, scope.adapterId]));
  return { scopeHash, directory: path.join(root, "native-origins", scopeHash) };
}
const location = nativeReplyRouteLocation;
function validate(record, scopeHash, id) {
  if (record?.version !== 1 || record.scopeHash !== scopeHash || record.clientMessageId !== id
    || !valid(id) || !valid(record.threadId)
    || (!record.conversationKey && !record.peerDelegateId)
    || (record.conversationKey !== null && !valid(record.conversationKey))
    || (record.peerDelegateId !== null && !valid(record.peerDelegateId))
    || Object.keys(record).sort().join() !== "clientMessageId,conversationKey,peerDelegateId,scopeHash,threadId,version") fail();
}
async function readRecord(file, scopeHash, id) {
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8192) fail();
  const record = JSON.parse(await fs.readFile(file, "utf8"));
  validate(record, scopeHash, id);
  return record;
}
async function safeDirectory(value) {
  let current = path.resolve(value);
  while (true) {
    const stat = await fs.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
    const parent = path.dirname(current);
    if (current === parent) return;
    current = parent;
  }
}
