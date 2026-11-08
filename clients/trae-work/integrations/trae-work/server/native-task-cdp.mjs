import { NATIVE_NOTICE_PREFIXES } from '../../../runtime/core/hellolynk-native-notice.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
export async function discoverTraeNativeTaskTarget(debugEndpoint = "http://127.0.0.1:9338", request = fetch) {
  const endpoint = checkedEndpoint(debugEndpoint);
  const response = await request(new URL("/json/list", endpoint), { signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw failure("trae_native_debug_unavailable");
  const targets = await response.json();
  if (!Array.isArray(targets)) throw failure("trae_native_debug_response_invalid");
  const pages = targets.filter((item) => {
    if (item?.type !== "page" || typeof item.id !== "string" || !/^[A-Za-z0-9-]{8,100}$/.test(item.id)) return false;
    try {
      const url = new URL(item.url);
      return url.protocol === "vscode-file:" && url.hostname === "vscode-app" && /\/vs\/code\/electron-browser\/solo\/solo-lite\.html$/.test(url.pathname);
    } catch { return false; }
  });
  if (pages.length !== 1) throw failure("trae_native_target_not_unique");
  return pages[0].id;
}

// Executed in TRAE's already initialized SOLO Lite SDK. No editor, selection,
// window command, synthetic keyboard event or DOM mutation is used.
export async function invokeTraeSdk(requireModule, operation, input, noticePrefixes = NATIVE_NOTICE_PREFIXES) {
  // Read only modules TRAE already loaded: requiring an ID would run its factory, and TRAE
  // builds renumber the SDK entry module, which is found by its named exports instead.
  const own = (value, key) => { try { return Object.prototype.hasOwnProperty.call(value, key); } catch { return false; } };
  const loaded = id => own(requireModule?.c, id) && requireModule.c[id]?.loaded === true ? requireModule.c[id].exports : undefined;
  const entries = Object.keys(requireModule?.c || {}).map(loaded).filter(exports => exports
    && ["streamDomainService", "sessionStore", "isSessionProcessing", "SessionStatus", "SoloEnv", "SoloMode"].every(name => own(exports, name)));
  const sdk = entries.length === 1 ? entries[0] : undefined, service = loaded(40650)?.kd;
  if (typeof service?.createSession !== "function" || typeof service?.sendMessage !== "function"
    || typeof service?.initSessionForSoloLite !== "function"
    || typeof service?.chatApi?.getSession !== "function" || typeof sdk?.streamDomainService?.createUserMessage !== "function"
    || typeof sdk?.sessionStore?.sessionById?.get !== "function" || typeof sdk?.sessionStore?.sessionMessageIds?.get !== "function"
    || typeof sdk?.sessionStore?.lastUserMessage?.get !== "function" || typeof sdk?.isSessionProcessing !== "function")
    throw new Error("trae_native_api_unavailable");
  const idPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/;
  const id = input?.nativeTaskId;
  let emptyNewSession = false;
  const valid = value => typeof value === "string" && idPattern.test(value);
  // TRAE 3.4.11 rejects a deleted session with ApiRequestError 995001 "session not found".
  const missing = r => r?.code === 991200 || r?.code === 995001
    && (r.message === `get_chat_session failed: chat session not found for session_id: ${id}` || r.message === "session not found");
  async function inspect() {
    if (!valid(id)) throw new Error("trae_native_target_id_required");
    const current = sdk.sessionStore.sessionById.get(id);
    // Local and remote native sessions retain the host's own routing choice.
    let response;
    try { response = await service.chatApi.getSession({ chat_session_id: id, env: current?.env ?? sdk.SoloEnv.Local }); }
    catch (error) {
      // The native SDK may reject with the same exact not-found API result.
      if (missing(error)) return { state: "deleted" };
      throw error;
    }
    if (missing(response)) return { state: "deleted" };
    if (response?.code !== 0 || response.data?.chat_session_id !== id) throw new Error("trae_native_lifecycle_unknown");
    if (input.directory === true && (response.data.parent_session_id || current?.parent_session_id)) return { state: "deleted" };
    const latest = sdk.sessionStore.sessionById.get(id);
    const terminal = [sdk.SessionStatus.Finished, sdk.SessionStatus.Stopped, sdk.SessionStatus.Failed];
    const emptyNew = input.allowEmpty === true && response.data.status === sdk.SessionStatus.Pending
      && (sdk.sessionStore.sessionMessageIds.get(id) || []).length === 0;
    emptyNewSession = emptyNew;
    return { state: "present", idle: (terminal.includes(response.data.status) || emptyNew)
      && (!latest || !sdk.isSessionProcessing(latest.status) || emptyNew), nativeTaskId: id };
  }
  if (operation === "directory") {
    if (typeof service.chatApi.listSessions !== "function") throw new Error("trae_native_catalog_unavailable");
    const conversations = [], projects = new Map();
    if (typeof service.projectApi?.listProjects === "function") {
      let token;
      const seenProjectTokens = new Set();
      do {
        const response = await service.projectApi.listProjects({ env: sdk.SoloEnv.Local, page_size: 100, ...(token ? { page_token: token } : {}) });
        const data = response.data?.data ?? response.data;
        if (response.code !== 0 || !Array.isArray(data?.items)) break;
        for (const row of data.items) projects.set(row.local_project_id || row.project_id, row.name || "");
        if (data.next_page_token && (data.next_page_token === token || seenProjectTokens.has(data.next_page_token))) throw new Error("trae_native_catalog_cursor_invalid");
        if (data.next_page_token) seenProjectTokens.add(data.next_page_token);
        token = data.next_page_token;
      } while (token);
    }
    let token;
    const seenSessionTokens = new Set();
    do {
      const response = await service.chatApi.listSessions({ env: sdk.SoloEnv.Local, page_size: 100, ...(token ? { page_token: token } : {}) });
      const data = response.data?.data ?? response.data;
      if (response.code !== 0 || !Array.isArray(data?.items)) throw new Error("trae_native_catalog_unavailable");
      for (const row of data.items) if (valid(row.chat_session_id) && !row.parent_session_id) conversations.push({
        targetConversationId: row.chat_session_id, title: row.title || row.chat_session_id,
        project: projects.get(row.local_project_id) || "", state: sdk.isSessionProcessing(row.status) ? "active" : "idle" });
      if (data.next_page_token && (data.next_page_token === token || seenSessionTokens.has(data.next_page_token) || !data.items.length)) throw new Error("trae_native_catalog_cursor_invalid");
      if (data.next_page_token) seenSessionTokens.add(data.next_page_token);
      token = data.next_page_token;
    } while (token);
    // This native endpoint enumerates local SOLO sessions; remote sessions have
    // different lifecycle/transport semantics and are not guessed from cache.
    return { conversations, coverage: "partial", exactTargetSupported: true, exactTitleSupported: true };
  }
  if (operation === "probe") return { available: true };
  if (operation === "inspect") return inspect();
  if (operation === "create") {
    const nativeTaskId = await service.createSession({ mode: sdk.SoloMode.Work, env: sdk.SoloEnv.Local,
      project_name: "HelloLynk", auto_create_project: true, origin: "hellolynk" });
    if (!valid(nativeTaskId)) return { status: "dispatch_unknown", nativeTaskId: null };
    return { status: "created", nativeTaskId };
  }
  if (operation !== "send" || !valid(id) || typeof input.text !== "string" || input.text.length > 16384
    || !noticePrefixes.some(prefix => input.text.startsWith(prefix)) || !valid(input.clientRequestId)
    || !input.text.includes(input.clientRequestId)) throw new Error("trae_native_prompt_invalid");
  const before = await inspect();
  if (before.state !== "present" || !before.idle) return { status: "not_submitted", nativeTaskId: id, reason: before.state === "deleted" ? "deleted" : "busy" };
  // An unopened conversation may lack its selected agent/history in memory.
  // Use the host's bounded initialization (20 messages), never choose a model.
  if (!sdk.sessionStore.lastUserMessage.get(id) && !emptyNewSession) {
    try {
      await service.initSessionForSoloLite(id, sdk.sessionStore.sessionById.get(id)?.env ?? sdk.SoloEnv.Local,
        { skipSubscription: true, preserveLocalChangesDuringInit: true, strictMessageLoad: true });
    } catch (error) {
      // The user may delete the session after inspect; no prompt exists yet.
      if (missing(error)) return { status: "not_submitted", nativeTaskId: id, reason: "deleted" };
      throw error;
    }
  }
  const session = sdk.sessionStore.sessionById.get(id);
  if (!session || sdk.isSessionProcessing(session.status) && !(input.allowEmpty === true && session.status === sdk.SessionStatus.Pending))
    return { status: "not_submitted", nativeTaskId: id, reason: "busy" };
  const userMessage = sdk.streamDomainService.createUserMessage({ sessionId: id,
    query: [{ type: "text", data: { content: input.text } }], mode: session.mode, env: session.env });
  let admitted = false, refused = false;
  let result;
  try { result = await service.sendMessage({ userMessage, origin: "hellolynk" }, () => {
    // The SDK calls this before submission and again after its own stream has
    // started. Its own Running status must not invalidate an accepted send.
    if (admitted) return true;
    const live = sdk.sessionStore.sessionById.get(id);
    admitted = !!live && (!sdk.isSessionProcessing(live.status)
      || input.allowEmpty === true && live.status === sdk.SessionStatus.Pending
        && (sdk.sessionStore.sessionMessageIds.get(id) || []).length === 0);
    refused = !admitted;
    return admitted;
  }); } catch {
    if (refused && !admitted) return { status: "not_submitted", nativeTaskId: id, reason: "busy" };
    return { status: "dispatch_unknown", nativeTaskId: id };
  }
  if (refused && !admitted) return { status: "not_submitted", nativeTaskId: id, reason: "busy" };
  if (!valid(result?.userMessageId)) return { status: "dispatch_unknown", nativeTaskId: id };
  return { status: "submitted_unconfirmed", nativeTaskId: id, userMessageId: result.userMessageId };
}

export async function findTraeLoadedRuntime(call) {
  const imported = await call("Runtime.evaluate", { expression: `(async()=>{const url=new URL('../../../../../node_modules/@byted-icube/solo-lite/dist/index.mjs',location.href);return (await import(url.href)).bootstrapSoloLite})()`, awaitPromise: true, returnByValue: false });
  if (imported.exceptionDetails || !imported.result?.objectId) throw failure("trae_native_api_unavailable");
  const props = await call("Runtime.getProperties", { objectId: imported.result.objectId, ownProperties: true });
  const scopes = props.internalProperties?.find(p => p.name === "[[Scopes]]")?.value?.objectId;
  if (!scopes) throw failure("trae_native_api_unavailable");
  const list = await call("Runtime.getProperties", { objectId: scopes, ownProperties: true });
  for (const scope of list.result || []) {
    if (!scope.value?.objectId || scope.value.description === "Global") continue;
    const vars = await call("Runtime.getProperties", { objectId: scope.value.objectId, ownProperties: true });
    for (const variable of vars.result || []) {
      if (variable.name !== "l" || variable.value?.type !== "function") continue;
      const check = await call("Runtime.callFunctionOn", { objectId: variable.value.objectId,
        functionDeclaration: `function(){return (${invokeTraeSdk.toString()})(this,"probe",{},${JSON.stringify(NATIVE_NOTICE_PREFIXES)})}`, awaitPromise: true, returnByValue: true });
      if (!check.exceptionDetails && check.result?.value?.available === true) return variable.value.objectId;
    }
  }
  throw failure("trae_native_api_unavailable");
}

export function createTraeNativeTaskCdp({ debugEndpoint = "http://127.0.0.1:9338", targetId,
  ownedTaskIds = [], originalTaskIds = [], timeoutMs = 15_000, connect = connectTraeCdp, invoke } = {}) {
  const endpoint = checkedEndpoint(debugEndpoint);
  if (typeof targetId !== "string" || !/^[A-Za-z0-9-]{8,100}$/.test(targetId)) throw failure("trae_native_target_id_required");
  const owned = new Set(ownedTaskIds.map(validId)), originals = new Set(originalTaskIds.map(validId));
  let connection, runtime, opening;
  const callSdk = invoke || (async (operation, input) => {
    opening ||= connect(endpoint, targetId, timeoutMs).then(async c => { connection = c; runtime = await findTraeLoadedRuntime(c.call); });
    await opening;
    const reply = await connection.call("Runtime.callFunctionOn", { objectId: runtime,
      functionDeclaration: `function(operation,input){return (${invokeTraeSdk.toString()})(this,operation,input,${JSON.stringify(NATIVE_NOTICE_PREFIXES)})}`,
      arguments: [{ value: operation }, { value: input }], awaitPromise: true, returnByValue: true });
    if (reply.exceptionDetails || !reply.result?.value) throw failure("trae_native_api_call_failed");
    return reply.result.value;
  });
  const addressable = value => owned.has(validId(value)) || originals.has(value);
  return Object.freeze({
    probe: () => callSdk("probe", {}),
    listConversations: () => callSdk("directory", {}),
    inspectLifecycle(nativeTaskId, { directory = false } = {}) {
      if (!addressable(nativeTaskId)) throw failure("trae_native_task_not_owned");
      return callSdk("inspect", { nativeTaskId, allowEmpty: owned.has(nativeTaskId), directory });
    },
    async create({ beforeSend } = {}) {
      if (beforeSend && !await beforeSend()) return { status: "not_submitted", reason: "authorization_changed" };
      const result = await callSdk("create", {});
      if (result?.status !== "created" || !ID.test(result.nativeTaskId || "")) return { status: "dispatch_unknown", nativeTaskId: null };
      owned.add(result.nativeTaskId);
      return result;
    },
    async send({ nativeTaskId, clientRequestId, text, beforeSend } = {}) {
      if (!addressable(nativeTaskId)) throw failure("trae_native_task_not_owned");
      validId(clientRequestId);
      if (typeof text !== "string" || Buffer.byteLength(text) > 16384 || !text.includes(clientRequestId)) throw failure("trae_native_prompt_invalid");
      if (beforeSend && !await beforeSend()) return { status: "not_submitted", nativeTaskId, reason: "authorization_changed" };
      // Once the RPC starts, a lost result is uncertain. The worker's durable
      // fence prevents replay; there is no typing/navigation fallback.
      const result = await callSdk("send", { nativeTaskId, clientRequestId, text, allowEmpty: owned.has(nativeTaskId) });
      if (result?.nativeTaskId !== nativeTaskId || !["not_submitted", "submitted_unconfirmed", "dispatch_unknown"].includes(result?.status))
        return { status: "dispatch_unknown", nativeTaskId };
      return result;
    },
    async close() { await opening?.catch(() => {}); connection?.close(); },
  });
}

async function connectTraeCdp(endpoint, targetId, timeoutMs) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) throw failure("trae_native_timeout_invalid");
  const url = new URL(endpoint); url.protocol = "ws:"; url.pathname = `/devtools/page/${targetId}`;
  const socket = new WebSocket(url);
  const pending = new Map(); let sequence = 0;
  await new Promise((resolve, reject) => { const timer = setTimeout(() => { socket.close(); reject(failure("trae_native_debug_unavailable")); }, timeoutMs);
    socket.onopen = () => { clearTimeout(timer); resolve(); }; socket.onerror = () => { clearTimeout(timer); reject(failure("trae_native_debug_unavailable")); }; });
  socket.onmessage = event => { let message; try { message = JSON.parse(event.data); } catch { return; }
    const item = pending.get(message.id); if (!item) return; pending.delete(message.id); clearTimeout(item.timer);
    message.error ? item.reject(failure("trae_native_api_call_failed")) : item.resolve(message.result); };
  const close = () => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(failure("trae_native_debug_unavailable")); } pending.clear(); socket.close(); };
  socket.onclose = () => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(failure("trae_native_debug_unavailable")); } pending.clear(); };
  return { close, call(method, params) { return new Promise((resolve, reject) => { const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(failure("trae_native_api_timeout")); }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    try { socket.send(JSON.stringify({ id, method, params })); } catch { clearTimeout(timer); pending.delete(id); reject(failure("trae_native_debug_unavailable")); }
  }); } };
}
function checkedEndpoint(value) {
  let url; try { url = new URL(value); } catch { throw failure("trae_native_debug_endpoint_invalid"); }
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.pathname !== "/" || url.username || url.password || url.search || url.hash)
    throw failure("trae_native_debug_endpoint_invalid");
  return url.href;
}
function validId(value) { if (!ID.test(value || "")) throw failure("trae_native_target_id_required"); return value; }
function failure(code) { return Object.assign(new Error(code), { code }); }
