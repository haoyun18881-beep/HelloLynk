import { readCodexConversationDirectory } from "./native-conversation-directory.mjs";
import crypto from "node:crypto";
import net from "node:net";

const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const ALLOWED = new Set(["create_thread", "send_message_to_thread", "read_thread", "list_threads", "list_projects", "list_archived_threads", "wait_threads", "open_in_codex"]);

export function createNativeTaskClient({ env = process.env, connect = net.createConnection,
  timeoutMs = 30_000, connectTimeoutMs = 10_000, executorMetadata = null, registeredCallerThreadId = null } = {}) {
  const pipePath = env.CODEX_APP_TOOLS_PIPE_PATH?.trim();
  const environmentThreadId = env.CODEX_THREAD_ID?.trim();
  const metadataContext = inspectCodexExecutorMetadata(executorMetadata);
  if (metadataContext.conflict) return null;
  const callerThreadId = metadataContext.threadId || environmentThreadId || registeredCallerThreadId;
  if (!pipePath || !callerThreadId) return null;
  let callerVerified = Boolean(metadataContext.threadId || environmentThreadId);
  let socket = null;
  let connecting = null;
  let connectingSocket = null;
  let rejectConnecting = null;
  let closed = false;
  let generation = 0;
  let nextId = 1;
  let catalog = null;
  let archivedPages = null;
  const pending = new Map();
  const isCurrentConnection = (connection) => !closed && connection?.socket === socket
    && socket && !socket.destroyed && connection.generation === generation;
  const assertCurrentConnection = (connection) => {
    if (closed) throw new Error("native_client_closed");
    if (!isCurrentConnection(connection)) throw new Error("native_pipe_changed");
  };

  const failSocket = (candidate, error) => {
    if (socket !== candidate) return; // A late close from an old pipe cannot cancel a new request.
    socket = null;
    catalog = null;
    archivedPages?.clear();
    for (const [id, item] of pending) {
      if (item.generation !== generation) continue;
      pending.delete(id);
      item.reject(error);
    }
  };
  const connectOnce = async () => {
    if (closed) throw new Error("native_client_closed");
    if (socket && !socket.destroyed) return;
    if (connecting) return connecting;
    connecting = new Promise((resolve, reject) => {
      const candidate = connect(pipePath);
      connectingSocket = candidate;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        candidate.off("error", onError);
        candidate.off("close", onClose);
        connectingSocket = null;
        rejectConnecting = null;
        if (error) { candidate.destroy(); reject(error); }
        else resolve();
      };
      const onError = () => finish(new Error("native_connect_failed"));
      const onClose = () => finish(new Error("native_connect_closed"));
      rejectConnecting = (error) => finish(error);
      const timeout = setTimeout(() => finish(new Error("native_connect_timeout")), connectTimeoutMs);
      timeout.unref?.();
      candidate.once("error", onError);
      candidate.once("close", onClose);
      candidate.once("connect", () => {
        if (closed) { finish(new Error("native_client_closed")); return; }
        candidate.off("error", onError);
        candidate.off("close", onClose);
        socket = candidate;
        generation += 1;
        const socketGeneration = generation;
        let buffer = Buffer.alloc(0);
        candidate.on("data", (chunk) => {
          if (socket !== candidate || generation !== socketGeneration) return;
          buffer = Buffer.concat([buffer, chunk]);
          while (buffer.length >= 4) {
            const length = buffer.readUInt32LE(0);
            if (length > MAX_FRAME_BYTES) { candidate.destroy(); failSocket(candidate, new Error("native_frame_too_large")); return; }
            if (buffer.length < length + 4) return;
            let response;
            try { response = JSON.parse(buffer.subarray(4, length + 4).toString("utf8")); }
            catch { candidate.destroy(); failSocket(candidate, new Error("native_frame_invalid")); return; }
            buffer = buffer.subarray(length + 4);
            if (response?.jsonrpc !== "2.0" || !Number.isSafeInteger(Number(response.id))) {
              candidate.destroy(); failSocket(candidate, new Error("native_response_invalid")); return;
            }
            const id = Number(response.id);
            const waiter = pending.get(id);
            if (!waiter || waiter.generation !== socketGeneration) continue;
            pending.delete(id);
            if (response.error) waiter.reject(new Error("native_tool_error"));
            else waiter.resolve(response.result);
          }
        });
        candidate.on("error", () => failSocket(candidate, new Error("native_pipe_error")));
        candidate.on("close", () => failSocket(candidate, new Error("native_pipe_closed")));
        finish();
      });
    }).finally(() => { connecting = null; });
    return connecting;
  };
  const request = async (method, params, connection, beforeWrite) => {
    // Discovery and the eventual byte-write must use the very same pipe.
    // Never reconnect inside a call carrying a previously selected namespace.
    assertCurrentConnection(connection);
    const candidate = connection.socket;
    const requestGeneration = connection.generation;
    const id = nextId++;
    const requestParams = method === "tools/call" ? { ...params, turnId: `mcp-turn-${id}` } : params;
    const payload = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, method, params: requestParams }), "utf8");
    if (payload.length > MAX_FRAME_BYTES) throw new Error("native_request_too_large");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32LE(payload.length, 0);
    payload.copy(frame, 4);
    const result = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error("native_request_timeout"));
      }, timeoutMs);
      timeout.unref?.();
      pending.set(id, {
        generation: requestGeneration,
        resolve(value) { clearTimeout(timeout); resolve(value); },
        reject(error) { clearTimeout(timeout); reject(error); },
      });
    });
    try {
      assertCurrentConnection(connection);
      beforeWrite?.();
      candidate.write(frame);
    } catch (error) {
      pending.get(id)?.reject(error);
      pending.delete(id);
    }
    return result;
  };
  const list = async () => {
    if (isCurrentConnection(catalog)) return catalog;
    await connectOnce();
    const connection = { socket, generation };
    const result = await request("tools/list", { threadStartKind: "all" }, connection);
    // A valid frame can be followed by close/bad-frame before this resumes.
    assertCurrentConnection(connection);
    if (!Array.isArray(result?.tools)) throw new Error("native_catalog_invalid");
    catalog = { ...connection, tools: new Map(result.tools.filter((tool) => typeof tool?.name === "string" && typeof tool?.namespace === "string")
      .map((tool) => [tool.name, tool.namespace])) };
    return catalog;
  };
  const client = {
    callerThreadId,
    beforeTick() { archivedPages = new Map(); },
    async ensureTools(names) {
      const available = await list();
      assertCurrentConnection(available);
      if (!Array.isArray(names) || names.some((name) => !ALLOWED.has(name) || !available.tools.has(name)))
        throw new Error("native_tool_unavailable");
      if (!callerVerified) {
        // Runtime calls ensureTools before acquiring its worker lease. A window
        // that is still starting can retry on the existing tick without owning
        // delivery or needing a new model tool call.
        const read = await client.call("read_thread", { threadId: callerThreadId, hostId: "local", turnLimit: 1, includeOutputs: false });
        assertCurrentConnection(available);
        if (read?.thread?.id !== callerThreadId || read.thread.kind !== "codex" || read.thread.hostId !== "local")
          throw new Error("native_caller_unavailable");
        callerVerified = true;
      }
    },
    async call(tool, args, context) {
      let dispatched = false;
      try {
        if (!ALLOWED.has(tool)) throw new Error("native_tool_disallowed");
        const available = await list();
        assertCurrentConnection(available);
        const namespace = available.tools.get(tool);
        if (!namespace) throw new Error("native_tool_unavailable");
        const dispatch = tool === "create_thread" || tool === "send_message_to_thread";
        // Discovery/reconnect may outlive receiver stop or an account change.
        // Recheck after that wait; no native request has been written yet.
        if (dispatch && context?.stillCurrent && !await context.stillCurrent()) throw new Error("native_scope_changed");
        const result = await request("tools/call", {
          arguments: args, callId: `mcp-call-${crypto.randomUUID()}`, namespace,
          callerSource: "codex", threadId: callerThreadId, tool,
        }, available, () => {
          // Synchronous fence adjacent to write(), including stop while an
          // asynchronous scope check or argument serialization was pending.
          if (dispatch && context?.isStopped?.()) throw new Error("native_scope_changed");
          dispatched = true;
        });
        if (result?.success !== true || !Array.isArray(result.contentItems)) {
          // Only the host's exact not-found response is a deletion proof. A
          // timeout, unavailable host or unreadable result must keep the mapping.
          const message = result?.contentItems?.filter((item) => item.type === "inputText").map((item) => item.text).join("\n");
          if (tool === "read_thread" && args?.hostId === "local" && typeof args.threadId === "string" && localThreadMissing(message, args.threadId))
            throw new Error("native_thread_deleted");
          throw new Error("native_tool_result_unknown");
        }
        const text = result.contentItems.filter((item) => item.type === "inputText").map((item) => item.text).join("\n");
        try {
          const data = JSON.parse(text);
          return data && typeof data === "object" && !Array.isArray(data)
            ? { ...data, _nativeToolSuccess: true } : { value: data, _nativeToolSuccess: true };
        } catch { return { text, _nativeToolSuccess: true }; }
      } catch (error) {
        // Discovery/connection failures cannot have executed this tool. Once
        // write() starts, even a synchronous error may be an unknown result.
        if (dispatched) throw error;
        // Socket failure objects can be shared by several pending requests.
        // The delivery classification belongs only to this invocation.
        const failure = new Error(error?.message || "native_call_failed", { cause: error });
        if (error?.code) failure.code = error.code;
        failure.nativeDispatchStarted = false;
        throw failure;
      }
    },
    async findCreatedThread(prompt, sourceThreadId = callerThreadId) {
      const escape = text => text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      const expected = `<codex_delegation>\n  <source_thread_id>${escape(sourceThreadId)}</source_thread_id>\n  <input>${escape(prompt)}</input>\n</codex_delegation>`;
      if (expected.length > 20_000) return null; // Host output projection ceiling.
      const listed = await client.call("list_threads", { limit: 50 });
      if (!Array.isArray(listed?.pinnedThreads) || !Array.isArray(listed?.threads))
        throw new Error("native_thread_lifecycle_unknown");
      const candidates = new Map([...listed.pinnedThreads, ...listed.threads]
        .filter(thread => thread.kind === "codex" && thread.hostId === "local"
          && typeof thread.title === "string" && /^HelloLynk[\s·•:：-]*独立会话$/u.test(thread.title) && typeof thread.id === "string")
        .map(thread => [thread.id, thread]));
      const matches = [];
      for (const threadId of candidates.keys()) {
        let read;
        try { read = await client.call("read_thread", { threadId, hostId: "local", turnLimit: 10,
          includeOutputs: true, maxOutputCharsPerItem: expected.length }); }
        catch (error) {
          if (error?.message === "native_thread_deleted") continue;
          throw error; // Do not repeat an unavailable transport for every candidate.
        }
        // New unknown creates normally have one turn. Do not walk an old
        // conversation to find a match: a partial page cannot prove its origin.
        if (read?.thread?.id !== threadId || read.thread.kind !== "codex" || read.thread.hostId !== "local"
          || read.page?.order !== "newest_first" || read.page.hasMore !== false || !Array.isArray(read.turns)) continue;
        const first = read.turns.at(-1)?.items?.[0];
        const userMatch = first?.type === "userMessage" && first.content?.length === 1
          && first.content[0].type === "text" && first.content[0].text === expected;
        const toolMatch = first?.type === "functionCallOutput" && first.name === "create_thread"
          && first.namespace === "codex_app" && first.output?.truncated === false && first.output.text === expected;
        if (userMatch || toolMatch) matches.push(threadId);
      }
      return matches.length === 1 ? { threadId: matches[0] } : null;
    },
    async listConversations(query = {}) {
      let projects = [];
      try { const value = await client.call("list_projects", {}); projects = value.projects || []; } catch {}
      let directory;
      try { directory = await readCodexConversationDirectory({ home: env.CODEX_HOME, callerThreadId, projects }); }
      catch {
        const value = await client.call("list_threads", { limit: 1000 });
        directory = { coverage: "partial", exactTargetSupported: true,
          conversations: [...(value.pinnedThreads || []), ...(value.threads || [])]
            .filter(row => row.kind === "codex" && row.hostId === "local").map(row => ({
              targetConversationId: row.id, title: row.name || row.id, project: row.project?.name || row.projectName || "",
              state: row.status?.type || row.status || "notLoaded" })) };
      }
      if (query.targetConversationId) {
        const state = await client.inspectThread(query.targetConversationId);
        const row = directory.conversations.find(row => row.targetConversationId === query.targetConversationId);
        const lifecycle = ["archived", "deleted"].includes(state.state) ? state.state : state.thread?.status?.type || state.thread?.status || "unavailable";
        if (row) row.state = lifecycle;
        else directory.conversations.push({ targetConversationId: query.targetConversationId,
          title: state.thread?.name || query.targetConversationId, project: "", state: lifecycle });
      }
      return directory;
    },
    async inspectThread(threadId) {
      // The read_thread projection omits archive state. Read the host's archive
      // metadata first; never infer deletion from a truncated recent list.
      let cursor;
      const seen = new Set();
      for (let page = 0; page < 100; page += 1) {
        // All destinations in one receiver tick share the same archive pages.
        // The next tick or a lost connection discards them; live status and
        // exact-thread reads below remain fresh for each destination.
        const pageKey = cursor || "";
        let reading = archivedPages?.get(pageKey);
        if (!reading) {
          reading = client.call("list_archived_threads", { hostId: "local", limit: 50, ...(cursor ? { cursor } : {}) });
          archivedPages?.set(pageKey, reading);
        }
        const result = await reading;
        if (!Array.isArray(result?.threads)) throw new Error("native_thread_lifecycle_unknown");
        if (result.threads.some((entry) => entry.id === threadId && entry.kind === "codex")) return { state: "archived" };
        if (result.nextCursor == null) {
          try {
            // Availability is runtime metadata. Do not make notification depend
            // on fetching conversation history (which can be separately limited).
            const available = await list();
            if (available.tools.has("list_threads")) {
              // This immediate metadata call works on the app-tools pipe.
              // wait_threads is advertised there but can end without a result.
              const snapshot = await client.call("list_threads", { limit: 50 });
              if (!Array.isArray(snapshot?.pinnedThreads) || !Array.isArray(snapshot?.threads))
                throw new Error("native_thread_lifecycle_unknown");
              const current = [...snapshot.pinnedThreads, ...snapshot.threads].find((entry) =>
                entry.id === threadId && entry.hostId === "local" && entry.kind === "codex");
              if (current) return { state: "present", thread: current };
              // The list holds only pinned plus the 50 most recent threads and
              // has no cursor, so absence proves nothing: ask for this thread.
            }
            const current = await client.call("read_thread", { threadId, hostId: "local", turnLimit: 1, includeOutputs: false });
            if (current?.thread?.id !== threadId || (current.thread.hostId != null && current.thread.hostId !== "local"))
              throw new Error("native_thread_lifecycle_unknown");
            // This adapter owns the lifecycle label; unrelated host metadata
            // named state must not replace the exact-thread lookup result.
            return { ...current, state: "present" };
          } catch (error) { if (error.message === "native_thread_deleted") return { state: "deleted" }; throw error; }
        }
        if (typeof result.nextCursor !== "string" || !result.nextCursor || seen.has(result.nextCursor)) break;
        cursor = result.nextCursor; seen.add(cursor);
      }
      throw new Error("native_thread_lifecycle_unknown");
    },
    close() {
      if (closed) return;
      closed = true;
      rejectConnecting?.(new Error("native_client_closed"));
      connectingSocket?.destroy();
      const current = socket;
      socket = null;
      archivedPages = null;
      current?.destroy();
      for (const item of pending.values()) item.reject(new Error("native_client_closed"));
      pending.clear();
    },
  };
  return Object.freeze(client);
}

// Our origins and carriers are local threads. Codex asks the preferred local
// host first and lists it as failed only when that lookup itself failed, so a
// failed cloud host beside a local not-found still proves the thread is gone.
function localThreadMissing(message, threadId) {
  if (typeof message !== "string") return false;
  const notFound = `No Codex thread found for threadId: ${threadId}`;
  if (message === notFound) return true;
  const hosts = (prefix) => {
    if (!message.startsWith(prefix)) return null;
    const entries = message.slice(prefix.length).split(", ");
    // Unexpected punctuation/whitespace is not the host's known error format.
    return entries.every((entry) => entry.length > 0 && !/[^a-z0-9_.:-]/.test(entry)) ? entries : null;
  };
  const unmatched = hosts(`${notFound}. Hosts without a readable match: `);
  if (unmatched) return unmatched.includes("local");
  const failed = hosts(`Could not determine whether Codex thread ${threadId} exists. Unavailable or failed hosts: `);
  return failed != null && !failed.includes("local");
}

// Only call this with params._meta from an executor-owned MCP tools/call
// request. Tool arguments and external message bodies are never sources of
// caller identity. These fields match the installed Codex app-tools bridge.
export function readCodexExecutorThreadId(metadata) {
  return inspectCodexExecutorMetadata(metadata).threadId;
}

export function inspectCodexExecutorMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return { threadId: null, conflict: false };
  const ids = new Set();
  const add = (value) => { if (typeof value === "string" && value.trim()) ids.add(value.trim()); };
  for (const key of ["openai/threadId", "openai/thread_id", "codexThreadId", "codex_thread_id", "threadId", "thread_id"]) {
    add(metadata[key]);
  }
  let turn = metadata["x-codex-turn-metadata"];
  if (typeof turn === "string") {
    try { turn = JSON.parse(turn); } catch { turn = null; }
  }
  if (turn && typeof turn === "object" && !Array.isArray(turn)) add(turn.thread_id);
  const nested = metadata.thread;
  if (nested && typeof nested === "object" && !Array.isArray(nested)) add(nested.id);
  return { threadId: ids.size === 1 ? [...ids][0] : null, conflict: ids.size > 1 };
}
