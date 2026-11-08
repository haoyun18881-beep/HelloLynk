import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createNativeInboxRuntime } from "../../../runtime/core/hellolynk-native-inbox-runtime.mjs";
import { readNativeReplyRoute } from "../../../runtime/core/hellolynk-native-reply-routes.mjs";
import { createTraeNativeTaskCdp, discoverTraeNativeTaskTarget } from "./native-task-cdp.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const HASH = /^[a-f0-9]{64}$/;
const DELIVERY = new Set(["dispatching", "prepared_not_submitted", "dispatch_unknown", "submitted_unconfirmed", "native_idle"]);
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fail = (code) => Object.assign(new Error(code), { code });
const scopeKey = (scope) => hash([path.resolve(scope.runtimeRoot).toLowerCase(), scope.adapterId, scope.region, scope.principalId, scope.delegateId]);
const CONFIG = "trae-native-cdp.json";

export async function configureTraeNativeTaskWorker({ storeRoot, enabled, debugEndpoint = "http://127.0.0.1:9338" } = {}) {
  const filename = await configPath(storeRoot, true);
  if (enabled === false) { await fs.rm(filename, { force: true }); return { enabled: false }; }
  if (enabled !== true) throw fail("trae_native_config_invalid");
  const endpoint = checkedDebugEndpoint(debugEndpoint);
  const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify({ contract: "hellolynk-trae-native-cdp-v1", debugEndpoint: endpoint })}\n`, { flag: "wx", mode: 0o600 });
    await fs.rename(temporary, filename);
  } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  return { enabled: true, debugEndpoint: endpoint };
}

export async function readTraeNativeTaskWorkerConfig(storeRoot) {
  if (!storeRoot) return null;
  const filename = await configPath(storeRoot, false);
  try {
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024) throw fail("trae_native_config_invalid");
    const value = JSON.parse(await fs.readFile(filename, "utf8"));
    if (!value || value.contract !== "hellolynk-trae-native-cdp-v1" || Object.keys(value).sort().join(",") !== "contract,debugEndpoint") throw fail("trae_native_config_invalid");
    return checkedDebugEndpoint(value.debugEndpoint);
  } catch (error) { if (error?.code === "ENOENT") return null; throw error; }
}

async function configPath(storeRoot, create) {
  if (typeof storeRoot !== "string" || !path.isAbsolute(storeRoot)) throw fail("trae_native_config_root_invalid");
  const runtime = path.join(storeRoot, "runtime"), directory = path.join(runtime, "native-tasks");
  if (create) await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await safeParents(create ? directory : storeRoot);
  if (!create) {
    for (const candidate of [runtime, directory]) {
      const stat = await fs.lstat(candidate).catch((error) => error?.code === "ENOENT" ? null : Promise.reject(error));
      if (!stat) break;
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw fail("trae_native_config_invalid");
    }
  }
  return path.join(directory, CONFIG);
}
function checkedDebugEndpoint(value) {
  let url;
  try { url = new URL(value); } catch { throw fail("trae_native_config_invalid"); }
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.pathname !== "/"
    || url.username || url.password || url.search || url.hash) throw fail("trae_native_config_invalid");
  return url.href;
}

// Native SDK operations stay here; batching and delivery state are shared
// with Codex and WorkBuddy rather than three separate per-message engines.
export function startTraeNativeTaskWorker({ adapter, debugEndpoint = process.env.HELLOLYNK_TRAE_DEBUG_ENDPOINT || "http://127.0.0.1:9338",
  recoveryMs = 5_000, acquireLease, readNoticeLocale, discoverTarget = discoverTraeNativeTaskTarget,
  clientFactory = createTraeNativeTaskCdp, storeFactory = openTraeNativeTaskStore, readRoute = readNativeReplyRoute } = {}) {
  if (!adapter || !Number.isSafeInteger(recoveryMs) || recoveryMs < 10) throw fail("trae_native_worker_options_invalid");
  let store, client, status = { status: "starting" };
  const unsent = () => Object.assign(fail("trae_native_not_submitted"), { nativeDispatchStarted: false });
  const native = {
    async listConversations(query = {}) {
      const directoryClient = clientFactory({ debugEndpoint, targetId: await discoverTarget(debugEndpoint), ownedTaskIds: [],
        originalTaskIds: query.targetConversationId ? [query.targetConversationId] : [] });
      try {
        if (query.targetConversationId) {
          const current = await directoryClient.inspectLifecycle(query.targetConversationId, { directory: true }).catch(() => null);
          const state = current?.state === 'deleted' ? 'deleted' : current?.state === 'present' ? current.idle ? 'idle' : 'active' : 'unavailable';
          return { conversations: [{ targetConversationId: query.targetConversationId, title: query.targetConversationId, project: '', state }], coverage: 'partial', exactTargetSupported: true };
        }
        return await directoryClient.listConversations();
      } finally { await directoryClient.close?.(); }
    },
    async configureScope(scope) { store = await storeFactory(scope); },
    async releaseScope() { await client?.close?.(); store = client = null; },
    async legacyDelivery(item, scope) {
      const route = item.replyToClientMessageId ? await readRoute(scope, item) : null;
      const old = store.records[hash(route ? [item.conversationKey, route.threadId] : item.conversationKey)]?.deliveries[hash(item.localMessageId)];
      return old ? /unknown|dispatching/.test(old.status) ? "unknown" : "sent" : null;
    },
    legacyCarrier(key) { return store.records[hash(key)]?.nativeTaskId ?? null; },
    async prepare(scope, state, groups, batches) {
      await client?.close?.(); client = null;
      if (!groups.size && !batches.size && !Object.keys(state.carriers).length) { status = { status: "listening" }; return; }
      const ownedTaskIds = [...new Set([...Object.values(state.carriers),
        ...Object.values(state.batches).filter(b => b.target.startsWith("trae-work-conv:")).map(b => b.threadId),
        ...Object.values(store.records).filter(r => !r.originalThreadId || r.ownedOriginal).map(r => r.nativeTaskId)].filter(Boolean))];
      const originalTaskIds = [...new Set([...groups.keys(), ...[...batches.values()].map(b => b.target)])]
        .filter(t => t.startsWith("trae-work-origin:")).map(t => t.slice("trae-work-origin:".length));
      client = clientFactory({ debugEndpoint, targetId: await discoverTarget(debugEndpoint), ownedTaskIds, originalTaskIds });
      if ((await client.probe())?.available !== true) throw fail("trae_native_api_unavailable");
    },
    async inspectThread(id) {
      const current = await client.inspectLifecycle(id);
      if (current?.state === "deleted") return { state: "deleted" };
      if (current?.state !== "present" || typeof current.idle !== "boolean") throw fail("trae_native_lifecycle_unknown");
      return { state: "present", thread: { status: current.idle ? "idle" : "active" } };
    },
    canNotifyOrigin(value) { return value?.state === "present" && value.thread?.status === "idle"; },
    async call(operation, args, context) {
      if (operation === "list_threads") { if ((await client.probe())?.available !== true) throw fail("trae_native_api_unavailable"); return {}; }
      let id = args.threadId;
      if (operation === "create_thread") {
        const created = await client.create({ beforeSend: context.stillCurrent });
        if (created?.status === "not_submitted") throw unsent();
        if (created?.status !== "created" || !ID.test(created.nativeTaskId || "")) throw fail("trae_native_create_unknown");
        id = created.nativeTaskId;
        try { await context.rememberThread(id); }
        catch (error) { throw Object.assign(error, { nativeDispatchStarted: false }); }
      }
      if (!await context.stillCurrent()) throw unsent();
      const result = await client.send({ nativeTaskId: id, clientRequestId: context.batchId, text: args.prompt, beforeSend: context.stillCurrent });
      if (result?.status === "not_submitted") throw unsent();
      if (result?.nativeTaskId !== id || result?.status !== "submitted_unconfirmed") throw fail("trae_native_dispatch_unknown");
      status = { status: "delivered", nativeTaskId: id };
      return { ok: true, threadId: id };
    },
  };
  const runtime = createNativeInboxRuntime({ adapterId: "trae-work", native, acquireLease, readNoticeLocale, pollMs: recoveryMs,
    adapter: { nativeTaskScope: () => adapter.getNativeTaskScope(), listPendingMessages: input => adapter.listPendingMessages(input), inboxBatch: (...args) => adapter.inboxBatch(...args) },
    readReplyRoute: readRoute, onError: e => { if (e.operation !== "directory") status = { status: "unavailable", errorCode: e.code }; } });
  const tick = () => runtime.tick().catch(error => { status = { status: "unavailable", errorCode: error.code || error.message }; });
  const ready = tick(); runtime.start();
  return Object.freeze({ ready, tick, get status() { return { ...status }; },
    taskStatus() { return { ...status }; }, close: () => runtime.close() });
}

export async function openTraeNativeTaskStore(scope) {
  if (!scope || !path.isAbsolute(scope.runtimeRoot || "") || scope.adapterId !== "trae-work"
    || [scope.region, scope.principalId, scope.delegateId].some((value) => typeof value !== "string" || !ID.test(value))) throw fail("trae_native_scope_invalid");
  await safeParents(scope.runtimeRoot);
  const directory = path.join(scope.runtimeRoot, "native-tasks");
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await safeParents(directory);
  const filename = path.join(directory, `${hash([scope.adapterId, scope.region, scope.principalId, scope.delegateId])}.json`);
  let records = {};
  try {
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024) throw fail("trae_native_state_invalid");
    records = JSON.parse(await fs.readFile(filename, "utf8"));
    if (!records || typeof records !== "object" || Array.isArray(records) || Object.keys(records).length > 5_000) throw fail("trae_native_state_invalid");
    for (const [conversation, record] of Object.entries(records)) {
      if (!HASH.test(conversation) || !record || typeof record !== "object" || Array.isArray(record)
        || record.nativeTaskId !== null && !ID.test(record.nativeTaskId || "")
        || record.originalThreadId != null && (!ID.test(record.originalThreadId) || record.originalThreadId !== record.nativeTaskId)
        || record.ownedOriginal != null && (typeof record.ownedOriginal !== "boolean" || !record.originalThreadId)
        || !record.deliveries || typeof record.deliveries !== "object" || Array.isArray(record.deliveries)) throw fail("trae_native_state_invalid");
      for (const [message, delivery] of Object.entries(record.deliveries)) {
        if (!HASH.test(message) || !delivery || !DELIVERY.has(delivery.status)
          || delivery.nativeTaskId != null && !ID.test(delivery.nativeTaskId)
          || !Number.isSafeInteger(delivery.assistantBaseline) || delivery.assistantBaseline < 0) throw fail("trae_native_state_invalid");
      }
    }
  } catch (error) { if (error?.code !== "ENOENT") throw error; }
  return { records, async save() {
    await safeParents(directory);
    const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify(records), { flag: "wx", mode: 0o600 });
      await fs.rename(temporary, filename);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  } };
}

async function safeParents(target) {
  const resolved = path.resolve(target), root = path.parse(resolved).root;
  let cursor = root;
  for (const part of path.relative(root, resolved).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const stat = await fs.lstat(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw fail("trae_native_state_invalid");
  }
}
function safeCode(error, fallback) { return /^[A-Za-z][A-Za-z0-9_]{1,119}$/.test(error?.code || "") ? error.code : fallback; }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, flag, storeRoot, endpointFlag, endpoint] = process.argv.slice(2);
  const valid = flag === "--root" && typeof storeRoot === "string"
    && (action === "disable" && endpointFlag === undefined || action === "enable" && (endpointFlag === undefined || endpointFlag === "--endpoint" && typeof endpoint === "string"));
  if (!valid) {
    process.stderr.write("usage: native-task-worker.mjs enable|disable --root ABSOLUTE_STORE_ROOT [--endpoint http://127.0.0.1:9338]\n");
    process.exitCode = 2;
  } else {
    configureTraeNativeTaskWorker({ storeRoot, enabled: action === "enable", ...(endpoint ? { debugEndpoint: endpoint } : {}) })
      .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
      .catch((error) => { process.stderr.write(`${JSON.stringify({ error: safeCode(error, "trae_native_config_failed") })}\n`); process.exitCode = 1; });
  }
}
