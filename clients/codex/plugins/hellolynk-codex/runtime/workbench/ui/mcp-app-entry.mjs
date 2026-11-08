import { mountWorkbench, publicError } from "./app.mjs";
import { createStandardMcpAppClient } from "./mcp-app-client.mjs";

// A true first launch can spend about 32 seconds verifying the immutable
// release, resolving the protected Windows binding and starting the local
// Host. Keep a finite ceiling so a broken bridge cannot spin forever, while
// still allowing that verified cold-start path to finish.
const DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS = 60_000;
const PORTAL_URLS = Object.freeze({
  keys: "https://hellolynk.com/account#keys",
  devices: "https://hellolynk.com/account#devices",
});

function enableMcpAppSizeNotifications(client, initialHostContext = {}) {
  if (window.parent === window) return;

  // The shared layout fills its viewport. Echoing that viewport's height keeps
  // a host's small bootstrap iframe small forever. Request a useful chat height
  // independently, while leaving fixed and capped containers under host control.
  const preferredHeight = 680;
  let hostContext = initialHostContext;
  let frameRequested = false;
  let lastWidth = 0;
  let lastHeight = 0;

  function sendSizeChanged() {
    frameRequested = false;
    const width = Math.ceil(document.documentElement.clientWidth || window.innerWidth || 0);
    const dimensions = hostContext?.containerDimensions;
    const positiveDimension = (value) => Number.isFinite(value) && value > 0;
    const height = Math.floor(positiveDimension(dimensions?.height)
      ? dimensions.height
      : positiveDimension(dimensions?.maxHeight)
        ? Math.min(preferredHeight, dimensions.maxHeight)
        : preferredHeight);
    if (!width || !height || (width === lastWidth && height === lastHeight)) return;
    lastWidth = width;
    lastHeight = height;
    client.notify("ui/notifications/size-changed", { width, height });
  }

  function scheduleSizeChanged() {
    if (frameRequested) return;
    frameRequested = true;
    window.requestAnimationFrame(sendSizeChanged);
  }

  if (typeof window.ResizeObserver === "function") {
    const observer = new window.ResizeObserver(scheduleSizeChanged);
    observer.observe(document.documentElement);
    observer.observe(document.body);
  }
  window.addEventListener("resize", scheduleSizeChanged);
  client.onHostContextChanged((update) => {
    hostContext = { ...hostContext, ...update };
    scheduleSizeChanged();
  });
  scheduleSizeChanged();
}

function createMcpAppTransport(client, options = {}) {
  if (!client || typeof client.callTool !== "function") throw new Error("workbench_mcp_app_bridge_required");
  const snapshotTimeoutMs = positiveTimeout(options.snapshotTimeoutMs, DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS);
  // Codex's retained global surface offers only fullscreen. Chat cards also
  // offer inline, even while expanded; they must not become background polls.
  const refreshesWhileHidden = options.hostContext?.displayMode === "fullscreen"
    && options.hostContext?.availableDisplayModes?.length === 1
    && options.hostContext.availableDisplayModes[0] === "fullscreen";
  // Chat history can keep several cards mounted under the same capability.
  // Leave room in its replay budget for heartbeats, native inbox reads and
  // human actions; each empty change read is still an authenticated request.
  const changePollMs = positiveTimeout(options.changePollMs, refreshesWhileHidden ? 1_000 : 5_000);
  const pageDocument = typeof document === "object" ? document : null;
  // MCP dispatch can queue this metadata read behind a snapshot or command.
  // Keep its bridge deadline wide enough for that queue; Host changes HTTP is
  // still bounded at eight seconds once dispatched.
  const changeTimeoutMs = positiveTimeout(options.changeTimeoutMs, DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS);
  let accountRevision = null;
  const scoped = (args) => accountRevision === null ? args : { ...args, _hellolynkAccountRevision: accountRevision };
  async function accountCall(name, input, field) {
    const response = await client.callTool(name, input);
    if (response?.isError) throw knownFailure(response?.structuredContent?.errorCode || "workbench_account_unavailable");
    if (!privateOnlyVisibleEnvelope(response)) throw knownFailure("workbench_account_state_invalid");
    const payload = response?._meta?.hellolynkWorkbench;
    if (!payload || Object.keys(payload).join(",") !== field
      || !/^(?:initial|[a-f0-9]{32})$/.test(payload[field]?.revision)) throw knownFailure("workbench_account_state_invalid");
    accountRevision = payload[field].revision;
    return payload[field];
  }
  async function readPrivateSnapshot(args) {
    const response = await withTimeout(
      client.callTool("hellolynk_workbench_snapshot", scoped(args)),
      snapshotTimeoutMs,
      "workbench_mcp_snapshot_timeout",
    );
    if (response?.isError) {
      const code = response?.structuredContent?.errorCode
        || response?.structuredContent?.error
        || response?._meta?.errorCode
        || "workbench_mcp_call_failed";
      const error = new Error(code);
      error.code = code;
      throw error;
    }
    if (!privateOnlyVisibleEnvelope(response)) {
      throw new Error("workbench_mcp_model_visible_snapshot_rejected");
    }
    const payload = response?._meta?.hellolynkWorkbench;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || Object.keys(payload).length !== 1 || !payload.snapshot) {
      throw new Error("workbench_mcp_private_snapshot_missing");
    }
    if (payload.snapshot?.source?.mode !== "neutral-host"
      || payload.snapshot?.source?.transport !== "mcp-app-rpc") {
      throw new Error("workbench_mcp_snapshot_source_mismatch");
    }
    return restoreMcpNullFields(payload.snapshot, [
      "commandWindow", "contactRequestNextCursor",
      "subject.principalLabel", "subject.delegateLabel",
      "threads.nextCursor", "threads.items.*.localDelegateId", "threads.items.*.peerDelegateId",
      "threads.items.*.contactId", "threads.items.*.peerPrincipalId", "threads.items.*.peerHelloLynkId",
      "threads.items.*.delegateLabel", "threads.items.*.lastMessage",
      "messages.threadId", "messages.nextCursor",
      "localHistory.autoArchiveAfterHours", "localHistory.selection", "localHistory.selection.before",
      "messages.items.*.senderPrincipalId", "messages.items.*.senderDelegateId",
      "messages.items.*.intentSource", "messages.items.*.authorizationScope",
      "outbox.*.threadId", "outbox.*.localDelegateId", "outbox.*.recipientDelegateId", "outbox.*.errorCategory",
      "contactRequests.*.senderLabel", "contactRequests.*.otherLabel",
      "contactRequests.*.decisionOutcome", "contactRequests.*.decisionAction",
      "outgoingContactRequests.*.senderLabel", "outgoingContactRequests.*.otherLabel",
      "outgoingContactRequests.*.decisionOutcome", "outgoingContactRequests.*.decisionAction",
      "relationships.*.otherLabel", "relationships.*.endedAt", "blocks.*.otherLabel",
    ]);
  }
  async function executePrivateCommand(command) {
    const actionGrant = command.command === "message.send-status" ? null : await issuePrivateActionGrant(command);
    const response = await client.callTool("hellolynk_workbench_command", scoped({
      command,
      ...(actionGrant ? { _hellolynkUiActionGrant: actionGrant } : {}),
    }), DEFAULT_MCP_SNAPSHOT_TIMEOUT_MS);
    if (response?.isError) {
      const code = response?.structuredContent?.errorCode
        || response?.structuredContent?.error
        || response?._meta?.errorCode
        || "workbench_mcp_call_failed";
      const error = new Error(code);
      error.code = code;
      if (knownPreMutationError(code)) error.outcome = "known-failed";
      throw error;
    }
    if (!privateOnlyVisibleEnvelope(response)) {
      throw new Error("workbench_mcp_model_visible_command_result_rejected");
    }
    const payload = response?._meta?.hellolynkWorkbench;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || Object.keys(payload).length !== 1 || !payload.commandResult) {
      throw new Error("workbench_mcp_private_command_result_missing");
    }
    const nullableFields = ["revision", "changeCursor", "error.retryAfterMs", "error.currentRevision"];
    if (payload.commandResult.result?.kind === "principal-search") {
      nullableFields.push("result.results.*.displayName", "result.results.*.hellolynkId");
    } else if (payload.commandResult.result?.kind === "contact-request-send") {
      nullableFields.push("result.quota");
    } else if (payload.commandResult.result?.kind === "message-send") {
      nullableFields.push("result.code");
    }
    return restoreMcpNullFields(payload.commandResult, nullableFields);
  }
  async function issuePrivateActionGrant(command) {
    const response = await client.callTool("hellolynk_workbench_action_grant", scoped({ command }));
    if (response?.isError) {
      const code = response?.structuredContent?.errorCode
        || response?.structuredContent?.error
        || response?._meta?.errorCode
        || "workbench_mcp_action_grant_failed";
      const error = new Error(code);
      error.code = code;
      error.outcome = "known-failed";
      throw error;
    }
    if (!privateOnlyVisibleEnvelope(response)) {
      throw knownFailure("workbench_mcp_model_visible_action_grant_rejected");
    }
    const payload = response?._meta?.hellolynkWorkbench;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || Object.keys(payload).length !== 1 || !Object.hasOwn(payload, "actionGrant")) {
      throw knownFailure("workbench_mcp_private_action_grant_missing");
    }
    return privateActionGrant(payload.actionGrant);
  }
  return Object.freeze({
    mode: "mcp-app-rpc",
    actionGrantMode: "host-single-use-v1",
    refreshesWhileHidden,
    readAccountState: () => accountCall("hellolynk_workbench_account", {}, "account"),
    disconnectAccount: (input) => accountCall("hellolynk_workbench_disconnect", input, "disconnection"),
    async readSnapshot(input = {}) {
      return readPrivateSnapshot(Object.fromEntries(
        ["threadId", "threadCursor", "messageCursor", "contactRequestCursor", "query", "filter", "historyBefore"]
          .filter((key) => Object.hasOwn(input, key)
            && input[key] !== ""
            && (key === "contactRequestCursor" || key === "historyBefore" || input[key] != null))
          .map((key) => [key, input[key]]),
      ));
    },
    async connectAccount(input) {
      const response = await client.callTool("hellolynk_workbench_connect", scoped(input), 160_000);
      if (response?.isError) throw knownFailure(response?.structuredContent?.errorCode || "workbench_connect_failed");
      if (!privateOnlyVisibleEnvelope(response)) throw knownFailure("workbench_connect_result_invalid");
      const payload = response?._meta?.hellolynkWorkbench;
      if (!payload || Object.keys(payload).join(",") !== "connection") throw knownFailure("workbench_connect_result_invalid");
      return payload.connection;
    },
    executeCommand: executePrivateCommand,
    subscribe(onChange, onError, onReconnect) {
      let stopped = false;
      let timer;
      let inFlight = false;
      let cursor = 0;
      let generation = null;
      let revision = accountRevision;
      let ready = false;
      let failures = 0;
      let resyncing = false;
      let inViewport = true;
      let cardWasHidden = false;
      let preparedWhileHidden = false;
      let viewportObserver;
      const hidden = () => !refreshesWhileHidden && (pageDocument?.visibilityState === "hidden" || !inViewport);
      const schedule = (delay) => {
        clearTimeout(timer);
        if (!stopped && !hidden() && !inFlight) timer = setTimeout(poll, delay);
      };
      const poll = async () => {
        if (stopped || hidden() || inFlight) return;
        inFlight = true;
        if (revision !== accountRevision) {
          revision = accountRevision; cursor = 0; generation = null; ready = false;
        }
        const observedRevision = revision;
        // A read already in flight when intersection is lost must not treat
        // that event as a sidebar close before visibilitychange can follow.
        const prepareHiddenView = cardWasHidden && !inViewport;
        let resync = false;
        try {
          // The initial account read owns initialization. Never query an
          // unscoped account while that read is still in flight.
          if (observedRevision === null) return;
          const response = await withTimeout(client.callTool("hellolynk_workbench_changes",
            scoped({ afterCursor: cursor }), changeTimeoutMs), changeTimeoutMs, "workbench_mcp_changes_timeout");
          if (stopped || hidden() || observedRevision !== accountRevision) return;
          if (!privateOnlyVisibleEnvelope(response)) throw knownFailure("workbench_mcp_model_visible_changes_rejected");
          if (response?.isError) throw knownFailure(response?._meta?.hellolynkWorkbench?.changeError?.code || "workbench_changes_failed");
          const payload = response?._meta?.hellolynkWorkbench;
          const batch = payload?.changes;
          if (!payload || Object.keys(payload).join(",") !== "changes"
            || !batch || Object.keys(batch).sort().join(",") !== "changed,cursor,hostGeneration,snapshotRequired"
            || !Number.isSafeInteger(batch.cursor) || batch.cursor < 0
            || !/^[a-f0-9]{48}$/.test(batch.hostGeneration)
            || typeof batch.snapshotRequired !== "boolean" || typeof batch.changed !== "boolean") {
            throw knownFailure("workbench_changes_invalid");
          }
          const replaced = generation !== null && generation !== batch.hostGeneration;
          if (!replaced && batch.cursor < cursor) throw knownFailure("host_app_state_conflict");
          cursor = batch.cursor;
          generation = batch.hostGeneration;
          // Prepare a collapsed latest message page while the retained sidebar
          // is away. Check after the async read so a window hide can cancel an
          // apparent card close; minimization must preserve the history window.
          if (refreshesWhileHidden && prepareHiddenView && cardWasHidden && !inViewport && !preparedWhileHidden
            && pageDocument?.visibilityState !== "hidden") {
            preparedWhileHidden = true;
            onReconnect?.({ reason: "background" });
          }
          if (replaced || batch.snapshotRequired || batch.changed) onChange?.({ hostGeneration: generation, changeCursor: String(cursor), snapshotRequired: true });
          if (!ready || failures) onReconnect?.();
          ready = true;
          failures = 0;
          resyncing = false;
        } catch (error) {
          if (stopped || hidden() || observedRevision !== accountRevision) return;
          if (error?.code === "host_app_state_conflict" && !resyncing) {
            // A Host restarted after idle shutdown or an update starts a new
            // cursor and rejects ours. That is a read-cursor reset, not a page
            // failure: an unordered change keeps the view with old writes
            // fenced, and the cursor rereads from zero at once.
            cursor = 0; ready = false; resyncing = resync = true;
            onChange?.({ snapshotRequired: true });
            return;
          }
          resyncing = false;
          if (error?.code === "host_app_state_conflict") cursor = 0;
          failures = Math.min(failures + 1, 5);
          onError?.(error?.code === "host_app_state_conflict"
            ? knownFailure("workbench_change_cursor_resync_failed") : error);
          // Account switches are read-only recovery; permissions and connection
          // establishment remain owned by the existing account UI.
          if (error?.code === "workbench_account_changed") {
            try { await accountCall("hellolynk_workbench_account", {}, "account"); } catch { /* Retry the change source later. */ }
          }
        } finally {
          inFlight = false;
          schedule(resync ? 0 : Math.min(changePollMs * 2 ** failures, 30_000));
        }
      };
      const visibilityChanged = () => {
        // Browsers may deliver intersection loss before visibilitychange when
        // minimizing. A document hide must cancel that apparent card close.
        if (pageDocument?.visibilityState === "hidden") cardWasHidden = false;
        schedule(hidden() ? changePollMs : 0);
      };
      pageDocument?.addEventListener?.("visibilitychange", visibilityChanged);
      // Embedded chat history can remain mounted and report a visible document
      // after its card scrolls away. Observe the frame's viewport intersection
      // as well; hosts without this API retain the bounded document polling.
      if (typeof IntersectionObserver === "function" && pageDocument?.documentElement) {
        try {
          viewportObserver = new IntersectionObserver((entries) => {
            if (stopped) return;
            const entry = entries.find((item) => item.target === pageDocument.documentElement);
            if (!entry || entry.isIntersecting === inViewport) return;
            inViewport = entry.isIntersecting;
            // A sidebar can hide a mounted iframe without hiding its document.
            // Returning to it opens the latest page, even if no data changed.
            if (!inViewport) {
              cardWasHidden = pageDocument?.visibilityState !== "hidden";
              preparedWhileHidden = false;
            }
            else {
              // A minimized/background window can also lose intersection.
              // Only a card hidden while its page was visible counts as closed.
              if (cardWasHidden && pageDocument?.visibilityState !== "hidden") onReconnect?.({ reason: "reopen" });
              cardWasHidden = false;
            }
            // Intersection loss can precede the window's visibility event.
            // Use the normal next probe to prepare a hidden sidebar, allowing
            // minimization to cancel that preparation without another timer.
            if (refreshesWhileHidden && !inViewport) schedule(changePollMs);
            else visibilityChanged();
          });
          viewportObserver.observe(pageDocument.documentElement);
        } catch {
          viewportObserver?.disconnect();
          viewportObserver = null;
          inViewport = true;
        }
      }
      schedule(changePollMs);
      return () => {
        stopped = true; clearTimeout(timer);
        viewportObserver?.disconnect();
        pageDocument?.removeEventListener?.("visibilitychange", visibilityChanged);
      };
    },
  });
}

// Codex removes null-valued object properties from tools/call results, even in
// private _meta. Restore only explicitly nullable contract fields. Missing
// containers, required values, and invalid values still fail shared validation.
function restoreMcpNullFields(value, paths) {
  function restoreAt(node, [key, ...rest]) {
    if (key === "*") return Array.isArray(node) ? node.map(item => restoreAt(item, rest)) : node;
    if (!node || typeof node !== "object" || Array.isArray(node)) return node;
    if (!rest.length) return Object.hasOwn(node, key) ? node : { ...node, [key]: null };
    if (!Object.hasOwn(node, key)) return node;
    const child = restoreAt(node[key], rest);
    return child === node[key] ? node : { ...node, [key]: child };
  }
  return paths.reduce((result, path) => restoreAt(result, path.split(".")), value);
}

function privateOnlyVisibleEnvelope(response) {
  const content = response?.content;
  if (content != null && (!Array.isArray(content) || content.length !== 0)) return false;
  const visible = response?.structuredContent;
  return visible == null || (visible && typeof visible === "object" && !Array.isArray(visible)
    && Object.keys(visible).length === 1 && visible.ok === true);
}

function privateActionGrant(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{31,511}$/.test(value)) {
    throw knownFailure("workbench_mcp_private_action_grant_invalid");
  }
  return value;
}

function knownFailure(code) {
  const error = new Error(code);
  error.code = code;
  error.outcome = "known-failed";
  return error;
}

function knownPreMutationError(code) {
  return /^(?:workbench_(?:mcp_)?action_grant_(?:required|invalid|expired|mismatch|revoked)|host_app_action_grant_(?:required|invalid|expired|mismatch|revoked))$/.test(String(code || ""));
}

function positiveTimeout(value, fallback) {
  if (value == null) return fallback;
  const timeout = Number(value);
  if (!Number.isFinite(timeout) || timeout <= 0) throw new Error("workbench_mcp_snapshot_timeout_invalid");
  return timeout;
}

function withTimeout(value, timeoutMs, code) {
  let timeout;
  const deadline = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      const error = new Error(code);
      error.code = code;
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([Promise.resolve(value), deadline]).finally(() => clearTimeout(timeout));
}

async function startMcpApp() {
  const bridge = createStandardMcpAppClient(window);
  const session = await bridge.connect();
  let resizeEnabled = false;
  const connectedClient = Object.freeze({
    async callTool(name, args, timeoutMs) {
      await bridge.connect();
      if (!resizeEnabled) {
        resizeEnabled = true;
        enableMcpAppSizeNotifications(bridge, session.hostContext);
      }
      return bridge.callTool(name, args, timeoutMs);
    },
  });
  const openPortal = session?.hostCapabilities?.openLinks
    ? async (target) => {
        const url = PORTAL_URLS[target];
        if (!url) throw new Error("workbench_portal_target_invalid");
        const result = await bridge.openLink(url);
        if (result?.isError) throw new Error("workbench_portal_open_failed");
      }
    : null;
  mountWorkbench({ transport: createMcpAppTransport(connectedClient, { hostContext: session.hostContext }), openPortal,
    openConnectionLink: session?.hostCapabilities?.openLinks ? (url) => bridge.openLink(url).then((result) => {
      if (result?.isError) throw new Error("workbench_portal_open_failed");
    }) : undefined,
  });
}

// __HELLOLYNK_MCP_APP_START__
void startMcpApp().catch((error) => {
  document.getElementById("state-title").textContent = "HelloLynk 暂时打不开 / HelloLynk couldn’t open";
  document.getElementById("state-message").textContent = `页面没能启动。请回到客户端，重新打开 HelloLynk 通讯；一直不行，请把下面的错误码告诉你的 AI。 / The page didn’t start. Go back to your client and reopen HelloLynk Messaging; if it keeps failing, tell your AI the error code below.\n${publicError(error)}`;
  document.querySelector(".spinner")?.setAttribute("hidden", "");
});
