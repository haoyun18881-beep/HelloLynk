import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

// This framing lives inside the existing E2EE ciphertext, never its public
// authenticated header. Ordinary text that starts with the marker is escaped.
// Older receivers reject unknown control kinds. A friend send requires a
// matching reply to its control request before it can transmit a message.
const PREFIX = "HelloLynk/native-content/1\n";
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
const REGION = { international: "intl", intl: "intl", china: "cn", cn: "cn" };
const error = code => Object.assign(new Error(code), { code });
export function nativeConversationId(value) {
  if (typeof value !== "string" || !ID.test(value)) throw error("native_conversation_id_invalid");
  return value;
}
export function nativeConversationTitle(value) {
  if (typeof value !== "string" || value.length > 512 || [...value].length > 256
    || !value.trim() || value.includes("\0")) throw error("native_conversation_title_invalid");
  return value.trim();
}
// Exact titles still compare whole titles, ignoring case and outer spaces.
// Spacing is the one tolerated difference: a run of spaces counts as one, and
// a space where Chinese or Japanese text meets Latin letters or digits is
// dropped, so "通过 HELLOLYNK 联系人" equals "通过HELLOLYNK联系人". Spaces
// between Latin words, or between two Chinese characters, still count.
const IDEOGRAPHIC = "\\p{Script=Han}\\p{Script=Hiragana}\\p{Script=Katakana}";
const ALPHANUMERIC = "\\p{Script=Latin}0-9";
const BOUNDARY_SPACE = new RegExp(`(?<=[${IDEOGRAPHIC}]) (?=[${ALPHANUMERIC}])|(?<=[${ALPHANUMERIC}]) (?=[${IDEOGRAPHIC}])`, "gu");
export function nativeTitleMatchKey(value) {
  return value.normalize("NFC").trim().replace(/\s+/gu, " ").replace(BOUNDARY_SPACE, "").toLowerCase();
}
export function nativeConversationQuery(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Object.keys(input).some(key => !["title", "project", "cursor", "targetConversationId", "exactTitle"].includes(key)))
    throw error("native_directory_query_invalid");
  if (Object.hasOwn(input, "exactTitle")) {
    if (input.exactTitle !== true || Object.keys(input).length !== 2) throw error("native_directory_query_invalid");
    return { title: nativeConversationTitle(input.title), exactTitle: true };
  }
  const result = {};
  for (const key of ["title", "project"]) if (input[key] != null) {
    // A code point uses at most two UTF-16 units; bound work before counting.
    if (typeof input[key] !== "string" || input[key].length > 512 || [...input[key]].length > 256) throw error("native_directory_query_invalid");
    result[key] = input[key].trim();
  }
  if (input.targetConversationId != null) result.targetConversationId = nativeConversationId(input.targetConversationId);
  if (input.cursor != null) {
    if (typeof input.cursor !== "string" || !/^[a-zA-Z0-9_-]{1,512}$/.test(input.cursor)) throw error("native_directory_cursor_invalid");
    result.cursor = input.cursor;
  }
  return result;
}
export function encodeNativeContent(input) {
  const { text, targetConversationId, nativeDirectory } = input;
  if (targetConversationId != null && (nativeDirectory != null || input.replyToClientMessageId != null))
    throw error("native_target_conflicts_with_reply");
  if (nativeDirectory != null) {
    if (text !== "" || input.replyToClientMessageId != null) throw error("native_directory_content_invalid");
    return PREFIX + JSON.stringify({ nativeDirectory: directoryControl(nativeDirectory) });
  }
  if (targetConversationId != null || text.startsWith(PREFIX)) return PREFIX + JSON.stringify(
    targetConversationId == null ? {} : { targetConversationId: nativeConversationId(targetConversationId) }) + "\n" + text;
  return text;
}
export function decodeNativeContent(text) {
  if (!text.startsWith(PREFIX)) return { text };
  try { return decodeNativeFrame(text); }
  catch { return { text: "", rejectedNativeContent: true }; }
}
function decodeNativeFrame(text) {
  const framed = text.slice(PREFIX.length), separator = framed.indexOf("\n");
  let content;
  try { content = JSON.parse(separator < 0 ? framed : framed.slice(0, separator)); } catch { throw error("native_content_invalid"); }
  if (!content || typeof content !== "object" || Array.isArray(content)) throw error("native_content_invalid");
  if (Object.hasOwn(content, "nativeDirectory")) {
    if (separator >= 0 || Object.keys(content).length !== 1) throw error("native_content_invalid");
    return { text: "", nativeDirectory: directoryControl(content.nativeDirectory) };
  }
  const body = separator < 0 ? "" : framed.slice(separator + 1);
  if (!body.length || Buffer.byteLength(body, "utf8") > 20 * 1024
    || Object.keys(content).some(k => k !== "targetConversationId"))
    throw error("native_content_invalid");
  return { text: body, ...(content.targetConversationId == null ? {}
    : { targetConversationId: nativeConversationId(content.targetConversationId) }) };
}
function directoryControl(value) {
  if (value?.kind === "friend_target_request") {
    if (Object.keys(value).some(key => !["kind", "requestId", "clientMessageId", "title"].includes(key)))
      throw error("native_directory_content_invalid");
    return { kind: value.kind, requestId: nativeConversationId(value.requestId),
      clientMessageId: nativeConversationId(value.clientMessageId), title: nativeConversationTitle(value.title) };
  }
  if (value?.kind === "friend_target_response") {
    if (Object.keys(value).some(key => !["kind", "requestId", "targetConversationId"].includes(key)))
      throw error("native_directory_content_invalid");
    const requestId = nativeConversationId(value.requestId);
    return { kind: value.kind, requestId,
      targetConversationId: value.targetConversationId === null ? null : nativeConversationId(value.targetConversationId) };
  }
  if (!value || !["request", "response"].includes(value.kind)
    || Object.keys(value).some(key => !["kind", "requestId", value.kind === "request" ? "query" : "result"].includes(key)))
    throw error("native_directory_content_invalid");
  const requestId = nativeConversationId(value.requestId);
  if (value.kind === "request") return { kind: "request", requestId, query: nativeConversationQuery(value.query) };
  return { kind: "response", requestId, result: nativeDirectoryResult(value.result) };
}
function textField(value, max = 256) { return typeof value === "string" ? value.slice(0, max) : ""; }
export function nativeConversationEntry(value) {
  // Explicit projection: SDK previews, summaries, prompts and paths never leave
  // the adapter through this catalog, even if a native list supplies them.
  return { targetConversationId: nativeConversationId(value.targetConversationId), title: textField(value.title),
    project: textField(value.project), state: ["idle", "active", "notLoaded", "archived", "deleted", "unavailable"].includes(value.state)
      ? value.state : "unavailable" };
}
export function nativeDirectoryResult(value) {
  if (!value || !Array.isArray(value.conversations) || value.conversations.length > 20)
    throw error("native_directory_result_invalid");
  const coverage = ["complete", "partial", "unavailable"].includes(value.coverage) ? value.coverage : "unavailable";
  const result = { conversations: value.conversations.map(nativeConversationEntry), coverage,
    available: value.available === true, exactTargetSupported: value.exactTargetSupported === true,
    observedAt: typeof value.observedAt === "string" && Number.isFinite(Date.parse(value.observedAt)) ? value.observedAt : null,
    nextCursor: value.nextCursor == null ? null : nativeConversationQuery({ cursor: value.nextCursor }).cursor };
  if (value.reason && /^[a-z][a-z0-9_]{2,100}$/.test(value.reason)) result.reason = value.reason;
  return result;
}
export function nativeConversationDirectoryLocation(scope) {
  if (!path.isAbsolute(scope?.runtimeRoot || "") || !REGION[scope.region]) throw error("native_directory_scope_invalid");
  const owner = [REGION[scope.region], ...["principalId", "delegateId", "adapterId"].map(k => nativeConversationId(scope[k]))];
  const hash = crypto.createHash("sha256").update(JSON.stringify(owner)).digest("hex");
  return { filename: path.join(scope.runtimeRoot, "native-conversations", hash + ".json"), owner };
}
const location = nativeConversationDirectoryLocation;
async function read(file) { try { return JSON.parse(await fs.readFile(file, "utf8")); } catch (e) { if (["ENOENT", "EPERM", "EBUSY"].includes(e.code)) return null; throw e; } }
async function atomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temporary = file + "." + crypto.randomUUID() + ".tmp";
  try { await fs.writeFile(temporary, JSON.stringify(value), { flag: "wx" }); await fs.rename(temporary, file); }
  finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
}
export async function readNativeConversationDirectory(scope) {
  const { filename, owner } = location(scope), value = await read(filename);
  if (value && JSON.stringify(value.owner) !== JSON.stringify(owner)) throw error("native_directory_scope_mismatch");
  return value;
}
export async function publishNativeConversationDirectory(scope, value) {
  const { filename, owner } = location(scope);
  const conversations = [...new Map(value.conversations.map(nativeConversationEntry).map(item => [item.targetConversationId, item])).values()];
  await atomic(filename, { owner, conversations, coverage: value.coverage,
    exactTargetSupported: value.exactTargetSupported === true, observedAt: new Date().toISOString(),
    requestId: value.requestId || null });
}
export function filterNativeConversations(snapshot, query = {}, available = false) {
  query = nativeConversationQuery(query);
  if (query.exactTitle) {
    const supported = available && snapshot?.exactTargetSupported === true
      && (snapshot.coverage === "complete" || snapshot.exactTitleSupported === true);
    const wanted = nativeTitleMatchKey(query.title);
    // Archived or deleted chats cannot receive, so they neither match nor make
    // a usable title ambiguous. A chat in an unknown state still counts.
    const matches = supported ? snapshot.conversations.filter(row => typeof row.title === "string"
      && row.title !== row.targetConversationId && !["archived", "deleted"].includes(row.state)
      && nativeTitleMatchKey(row.title) === wanted) : [];
    return nativeDirectoryResult({ conversations: matches.length === 1 ? matches : [],
      available: Boolean(supported), exactTargetSupported: Boolean(supported),
      coverage: supported ? "complete" : "unavailable", observedAt: snapshot?.observedAt });
  }
  const signature = crypto.createHash("sha256").update(JSON.stringify([query.title || "", query.project || "", query.targetConversationId || ""])).digest("hex").slice(0, 16);
  let after = "";
  if (query.cursor) {
    let cursor; try { cursor = JSON.parse(Buffer.from(query.cursor, "base64url").toString("utf8")); } catch { throw error("native_directory_cursor_invalid"); }
    if (!Array.isArray(cursor) || cursor[0] !== signature) throw error("native_directory_cursor_invalid");
    after = nativeConversationId(cursor[1]);
  }
  if (!snapshot) return nativeDirectoryResult({ conversations: [], coverage: "unavailable", available: false,
    exactTargetSupported: false, reason: "native_directory_unavailable" });
  const rows = snapshot.conversations.filter(row => (!query.targetConversationId || row.targetConversationId === query.targetConversationId)
    && (!query.title || row.title.toLocaleLowerCase().includes(query.title.toLocaleLowerCase()))
    && (!query.project || row.project.toLocaleLowerCase().includes(query.project.toLocaleLowerCase())))
    .sort((a, b) => a.targetConversationId.localeCompare(b.targetConversationId));
  const page = rows.filter(row => !after || row.targetConversationId.localeCompare(after) > 0).slice(0, 21);
  let count = Math.min(page.length, 20), result;
  do {
    result = nativeDirectoryResult({ conversations: page.slice(0, count), coverage: snapshot.coverage, available,
      exactTargetSupported: snapshot.exactTargetSupported, observedAt: snapshot.observedAt,
      nextCursor: page.length > count ? Buffer.from(JSON.stringify([signature, page[count - 1].targetConversationId])).toString("base64url") : null });
    // Keep an encrypted directory page within the same edge budget as a user
    // message. Large escaped titles reduce this page, not the full directory.
  } while (Buffer.byteLength(JSON.stringify(result), "utf8") > 20 * 1024 && --count > 0);
  return result;
}

// Transient requests are serviced together by the existing receiver timer.
// Separate replies avoid one exact lookup overwriting another; no model runs.
export async function queryLocalNativeConversations(scope, input, options = {}) {
  const query = nativeConversationQuery(input), { filename } = location(scope);
  filterNativeConversations(null, query); // Reject mismatched cursors before creating a request.
  const requestId = "directory_" + crypto.randomUUID();
  const requestFile = path.join(filename + ".requests", requestId + ".json"), responseFile = requestFile + ".response";
  const deadline = Date.now() + (options.waitMs ?? 6500);
  await atomic(requestFile, { requestId, query, deadline });
  try {
    do {
      const result = await read(responseFile);
      if (result) return nativeDirectoryResult(result);
      if (Date.now() >= deadline) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (true);
    return filterNativeConversations(await readNativeConversationDirectory(scope), query, false);
  } finally {
    await fs.rm(requestFile, { force: true }).catch(() => {});
    await fs.rm(responseFile, { force: true }).catch(() => {});
  }
}
export function createNativeDirectoryPublisher(native) {
  let currentOwner = null, flight, cacheWrite = Promise.resolve();
  async function publish(scope, stillCurrent) {
    if (typeof native?.listConversations !== "function") return;
    const { filename } = location(scope), directory = filename + ".requests";
    const names = await fs.readdir(directory).catch(e => { if (e.code === "ENOENT") return []; throw e; });
    const requests = names.filter(name => /^directory_[a-f0-9-]{36}\.json$/.test(name));
    async function collect(query) {
      const value = await native.listConversations(query, scope);
      if (!await stillCurrent()) return null;
      // Match the full live title before projecting or truncating metadata.
      if (query.exactTitle) return filterNativeConversations(value, query, true);
      // Native reads are independent. Serialize the short shared-cache rename
      // because Windows can reject simultaneous replacement of one file.
      cacheWrite = cacheWrite.catch(() => {}).then(async () => {
        if (!await stillCurrent()) return false;
        if (!query.targetConversationId || value.coverage === "complete") return publishNativeConversationDirectory(scope, value);
        const prior = await readNativeConversationDirectory(scope);
        if (!prior) return; // A partial answer cannot replace an unreadable cache.
        if (!await stillCurrent()) return false;
        // An exact lookup must not replace the whole offline catalog with one row.
        return publishNativeConversationDirectory(scope, { ...value, coverage: prior?.coverage ?? value.coverage,
          conversations: [...(prior?.conversations || []).filter(row => row.targetConversationId !== query.targetConversationId),
            ...value.conversations.map(row => {
              const cached = prior?.conversations.find(item => item.targetConversationId === row.targetConversationId);
              // Lifecycle-only replies do not erase a previously observed name/project.
              return cached && row.title === row.targetConversationId && !row.project ? { ...cached, state: row.state } : row;
            })] });
      });
      if ((await cacheWrite) === false) return null;
      return filterNativeConversations({ ...value, conversations: value.conversations.map(nativeConversationEntry),
        observedAt: new Date().toISOString() }, query, true);
    }
    if (filename !== currentOwner) {
      if (!await stillCurrent()) return;
      currentOwner = filename;
      // Cancellation belongs to the old receiver lease, not a completed first
      // snapshot. Retry when current again; ordinary failures still scan once.
      if (!requests.length && await collect({}) === null) currentOwner = null;
    }
    await Promise.all(requests.map(async name => {
      const requestFile = path.join(directory, name), responseFile = requestFile + ".response";
      const request = await read(requestFile);
      if (!request) return;
      if (request.deadline < Date.now()) {
        await fs.rm(requestFile, { force: true }).catch(() => {});
        await fs.rm(responseFile, { force: true }).catch(() => {}); return;
      }
      if (await read(responseFile)) return;
      const query = nativeConversationQuery(request.query);
      let result;
      try { result = await collect(query); }
      catch { result = filterNativeConversations(await readNativeConversationDirectory(scope), query, false); }
      if (!result || !await stillCurrent() || !await read(requestFile)) return;
      if (!await stillCurrent()) return;
      await atomic(responseFile, result);
      // A query may have timed out during the native read/write.
      if (!await read(requestFile)) await fs.rm(responseFile, { force: true }).catch(() => {});
    }));
  }
  return (scope, stillCurrent = async () => true) => {
    if (flight) return flight;
    flight = publish(scope, stillCurrent).finally(() => { flight = null; });
    return flight;
  };
}
