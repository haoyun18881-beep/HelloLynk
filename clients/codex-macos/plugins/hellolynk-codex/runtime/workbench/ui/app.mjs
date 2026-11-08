import {
  HELLOLYNK_WORKBENCH_COMMAND_TYPES,
  createWorkbenchCommand,
  createWorkbenchIdempotencyKey,
  hasWorkbenchCapability,
  validateWorkbenchCommandResult,
  validateWorkbenchContactRequestIntro,
  validateWorkbenchSnapshot,
} from "/modules/contract.mjs";
import {
  createWorkbenchViewState,
  deriveWorkbenchContacts,
  deriveWorkbenchConversations,
  reduceWorkbenchViewState,
  selectVisibleThreads,
} from "/modules/state.mjs";
import {
  normalizeWorkbenchLocale,
  translateWorkbench,
} from "/modules/i18n.mjs";

import { createWorkbenchConnectionForm } from "./connection-form.mjs";

const $ = (id) => document.getElementById(id);
function replaceLocationHash(hash) {
  // A srcdoc widget inherits its parent's base URI. Resolve fragments against
  // this document, otherwise replaceState can attempt a cross-origin rewrite.
  history.replaceState(null, "", `${location.href.split("#")[0]}${hash}`);
}
const SECTIONS = new Set(["inbox", "messages", "contacts", "security", "settings"]);
const SAFE_ROUTE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;
const HELLOLYNK_ID_PATTERN = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const PORTAL_TARGETS = new Set(["keys", "devices"]);
const LOCALE_STORAGE_KEY = "hellolynk.uiLocale";
const MANUAL_RETRY_OUTBOX_STATES = new Set(["recipient_offline", "failed_retryable", "failed_permanent"]);
const VISIBLE_OUTBOX_STATES = new Set([...MANUAL_RETRY_OUTBOX_STATES, "delivery_state_unknown", "delivery_state_unconfirmed", "unknown"]);
const CONTACT_REQUEST_STATE_BY_DECISION = Object.freeze({ accept: "accepted", reject: "rejected", block: "blocked" });
const RETRYABLE_SNAPSHOT_ERRORS = new Set([
  "workbench_loopback_timeout", "workbench_loopback_unreachable",
  "workbench_surface_host_timeout", "workbench_surface_host_unreachable",
  "workbench_mcp_snapshot_timeout", "workbench_mcp_app_bridge_timeout",
  "workbench_snapshot_timeout", "neutral_host_connection_refused", "neutral_host_connection_reset",
  "host_nonce_capability_cache_full", "host_nonce_cache_full",
  "host_app_workbench_snapshot_busy",
]);
// Only proves the first read has not returned yet; the Host may be starting or slow.
const FIRST_READ_WAIT_ERRORS = new Set([
  "workbench_mcp_snapshot_timeout", "workbench_mcp_app_bridge_timeout", "workbench_loopback_timeout",
]);
const COMMAND_CAPABILITY_BY_TYPE = new Map([
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead, "messages.mark-read"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead, "messages.mark-all-read"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead, "messages.auto-read.manage"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead, "messages.delete-read"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent, "messages.delete-sent"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory, "threads.manage-local"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry, "outbox.request-retry"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply, "outbox.request-retry"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact, "contact.save"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact, "contact.rename"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact, "contact.delete"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances, "contact.instances.list"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance, "contact.instance.save"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance, "contact.instance.rename"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance, "contact.instance.delete"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests, "contact-request.clear-resolved"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest, "contact-request.respond"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision, "contact-request.recover-decision"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest, "contact-request.cancel"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization, "contact.authorization.manage"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal, "principal.search"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest, "contact-request.send"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship, "relationship.end"],
  [HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock, "block.remove"],
]);

export function mountWorkbench(options = {}) {
  if (!options.transport || typeof options.transport.readSnapshot !== "function") {
    throw new Error("workbench_transport_required");
  }
  const transport = options.transport;
  const openPortal = typeof options.openPortal === "function" ? options.openPortal : null;
  const extraTranslations = options.translations ?? {};
  const translate = (target, key, variables) => extraTranslations[normalizeWorkbenchLocale(target)]?.[key]
    ?? translateWorkbench(target, key, variables);
  const startConnection = typeof options.startConnection === "function" ? options.startConnection
    : typeof transport.connectAccount === "function" ? createWorkbenchConnectionForm({
      connect: (input) => transport.connectAccount(input),
      onConnected: async (result) => {
        await refreshReadOnly({ quiet: false });
        recoveredConnectionName = result.recoveredExistingName === true ? result.instanceName : null;
        renderConnectionResult();
      },
      openLink: options.openConnectionLink,
      translate: (key) => copy(key, key),
    }) : null;
  const mobileViewportQuery = matchMedia("(max-width: 700px)");
  const storedLocalePreference = readLocalePreference();
  let locale = normalizeWorkbenchLocale([
    options.locale,
    storedLocalePreference.value,
    ...(Array.isArray(navigator.languages) ? navigator.languages : []),
    navigator.language,
  ]);
  let localePreferenceSaved = storedLocalePreference.available
    && storedLocalePreference.value === locale;
  let snapshot = null;
  let accountRevision = null;
  let recoveredConnectionName = null;
  let accountViewEpoch = 0;
  let disconnectRevision = null;
  let disconnectPending = false;
  let disconnectNeedsRefresh = false;
  let view = createWorkbenchViewState({ section: "inbox" });
  let stopped = false;
  let loadSequence = 0;
  let appliedReadSequence = 0;
  let navigationSequence = 0;
  let authorityFailureSequence = 0;
  let manualRefreshPending = false;
  let activeReads = 0;
  let changeSequence = 0;
  let latestChange = null;
  let unorderedChangeSequence = 0;
  let changeRefreshPending = false;
  let recoveryRefreshPending = false;
  let lifecycleRefreshScheduled = false;
  let readRetryTimer = null;
  let readRetryAttempt = 0;
  let firstReadConnecting = false;
  let readRefreshError = null;
  let unsubscribe = null;
  let searchTimer = null;
  let threadTimeTimer = null;
  let loadingThreadPage = null;
  let threadPageCursors = [null];
  let loadingMessagePage = null;
  let messagePageWindow = null;
  let historyView = "active";
  let historyManagerOpen = false;
  let loadingContactRequestPage = false;
  // Retain only read cursors for backwards navigation, not all visited bodies.
  // Every root refresh/account or authority change starts a fresh page trail.
  let contactRequestPageCursors = [undefined];
  let authorityReloadRequired = false;
  const threadPageCursorById = new Map();
  const draftsByThreadId = new Map();
  const sendStateByThreadId = new Map();
  const sendApprovalByTarget = new Map();
  // UI-only projections bridge the command and the next authoritative read.
  // They never enter the local outbox or prove that a message was sent.
  const sendPreviewByMessageId = new Map();
  const actionStateByKey = new Map();
  const actionOperationByKey = new Map();
  const markReadOperationById = new Map();
  const instanceDirectoryByContact = new Map();
  const instanceCreatedAtByContact = new Map();
  const portalStateByTarget = new Map();
  let contactQuery = "";
  let selectedContactId = null;
  let contactWorkspaceMode = null;
  let detailsOpen = false;
  let detailsObjectKey = null;
  let detailsMessageId = null;
  let localHistoryConfirmation = null;
  let contactEditor = null;
  let contactInstanceEditor = null;
  let contactInstancePickerId = null;
  let deleteConfirmation = null;
  let contactContextNotice = null;
  let lifecycleConfirmation = null;
  let clearResolvedConfirmation = null;
  let principalDiscovery = {
    mode: "hellolynk_id",
    query: "",
    phase: "idle",
    code: null,
    results: [],
    quota: null,
    revision: null,
    hostGeneration: null,
  };
  const contactRequestDraftByTarget = new Map();
  const contactRequestSendStateByTarget = new Map();
  const contactRequestOutcomeByTarget = new Map();
  let globalComposer = {
    open: false,
    contactId: null,
    recipientDelegateId: null,
    returnFocusId: null,
    draft: "",
    phase: "idle",
    code: null,
  };
  let globalSubmitInFlight = false;
  let pendingModuleFocus = null;
  let lastRenderedLocale = null;

  // Only source presentation recipes are retained. The ordinary copy contract
  // remains a string for shell/event-only UI outside the retained regions.
  const localeBindings = createLocaleBindings({ getLocale: () => locale, translate });
  const { copy: localizedCopy, parts: localizedParts, trim: localizedTrim,
    setText: localizedText, setAttribute: localizedAttribute, node } = localeBindings;
  const localizedTime = (value) => localeBindings.format(value, "time");
  const localizedDateTime = (value) => localeBindings.format(value, "datetime");
  const localizedRelativeTime = (value) => localeBindings.format(value, "relative");
  const localizedDateParts = (value) => ({ ...localDateParts(value, locale), label: localeBindings.format(value, "date") });

  const copy = (key, fallback, variables) => {
    try {
      const result = translate(locale, key, variables);
      return result && result !== key ? result : fallback;
    } catch {
      return fallback;
    }
  };

  function dispatch(event) {
    view = reduceWorkbenchViewState(view, event);
    render();
  }

  function resetAccountView(failureCode = "workbench_connection_required") {
    recoveredConnectionName = null;
    renderConnectionResult();
    clearReadRetry();
    for (const approval of sendApprovalByTarget.values()) clearTimeout(approval.timer);
    sendApprovalByTarget.clear();
    sendPreviewByMessageId.clear();
    globalSubmitInFlight = false;
    accountViewEpoch++;
    loadSequence++;
    changeSequence++;
    latestChange = null;
    unorderedChangeSequence = changeSequence;
    snapshot = null;
    view = createWorkbenchViewState({ section: "inbox" });
    for (const map of [threadPageCursorById, draftsByThreadId, sendStateByThreadId, actionStateByKey, actionOperationByKey, markReadOperationById,
      instanceDirectoryByContact, instanceCreatedAtByContact, contactRequestDraftByTarget, contactRequestSendStateByTarget,
      contactRequestOutcomeByTarget]) map.clear();
    contactQuery = ""; selectedContactId = null; contactWorkspaceMode = null;
    contactEditor = null; contactInstanceEditor = null; deleteConfirmation = null; lifecycleConfirmation = null; clearResolvedConfirmation = null;
    contactInstancePickerId = null;
    detailsOpen = false; detailsObjectKey = null; detailsMessageId = null; contactContextNotice = null;
    localHistoryConfirmation = null;
    messagePageWindow = null;
    threadPageCursors = [null];
    contactRequestPageCursors = [undefined];
    historyView = "active"; historyManagerOpen = false;
    principalDiscovery = { mode: "hellolynk_id", query: "", phase: "idle", code: null, results: [], quota: null, revision: null, hostGeneration: null };
    globalComposer = { open: false, contactId: null, recipientDelegateId: null, returnFocusId: null, draft: "", phase: "idle", code: null };
    clearTimeout(searchTimer);
    startConnection?.close?.();
    authorityReloadRequired = false;
    changeRefreshPending = false;
    dispatch({ type: "FAILED", code: failureCode });
    recoveryRefreshPending = false;
  }

  async function load({
    threadId = view.selectedThreadId,
    query = view.query,
    filter = view.filter,
    threadCursor = null,
    threadPageIndex = 0,
    messageCursor = null,
    historyBefore: requestedHistoryBefore,
    contactRequestCursor,
    contactRequestPageIndex = 0,
    quiet = false,
    append = null,
    preserveUiContext = false,
    refreshMessagePage = false,
    preserveThreadPage = false,
  } = {}) {
    if (stopped) return;
    const requestedMessageScrollTop = ["messages", "messages-newer"].includes(append)
      ? Number(document.querySelector(".messages")?.scrollTop) || 0 : null;
    clearTimeout(readRetryTimer);
    readRetryTimer = null;
    let sequence = ++loadSequence;
    if (typeof transport.readAccountState === "function") {
      try {
        const state = await transport.readAccountState();
        if (stopped || sequence !== loadSequence) return;
        if (accountRevision !== null && state.revision !== accountRevision) {
          resetAccountView();
          sequence = loadSequence;
          threadId = null; query = ""; filter = "all"; threadCursor = null; messageCursor = null; contactRequestCursor = undefined; append = null;
        }
        accountRevision = state.revision;
        if ($("account-disconnect")) $("account-disconnect").hidden = !state.canDisconnect;
        if (state.disconnecting) {
          resetAccountView();
          dispatch({ type: "FAILED", code: "workbench_account_disconnect_incomplete" });
          return;
        }
      } catch (error) {
        if (!stopped && sequence === loadSequence) {
          handleSnapshotReadFailure(error, quiet);
        }
        return;
      }
    }
    const observedChange = changeSequence;
    changeRefreshPending = false;
    activeReads++;
    if (!quiet) dispatch({ type: "LOAD" });
    else if (view.phase === "stale") renderChrome();
    try {
      let missingThreadId = null;
      const readInput = {
        ...(threadId ? { threadId } : {}),
        ...(threadCursor ? { threadCursor } : {}),
        ...(messageCursor ? { messageCursor } : {}),
        ...(contactRequestCursor !== undefined ? { contactRequestCursor } : {}),
        ...(query ? { query } : {}),
        filter: historyView === "archived" && filter === "all" ? "archived" : filter,
        ...(requestedHistoryBefore !== undefined ? { historyBefore: requestedHistoryBefore } : {}),
      };
      const setRefreshCursor = (followLatestGap = false) => {
        const cursor = followLatestGap && isFollowingLatestMessages(threadId) ? null : visibleMessageRefreshCursor(threadId);
        if (cursor) readInput.messageCursor = cursor;
        else delete readInput.messageCursor;
        return cursor;
      };
      if (refreshMessagePage) setRefreshCursor();
      let response, cursorReset = false;
      try {
        response = await transport.readSnapshot(readInput);
      } catch (error) {
        if (stopped || sequence !== loadSequence) return;
        if ((readInput.messageCursor || readInput.threadCursor)
          && ["host_app_workbench_cursor_invalid", "neutral_host_workbench_cursor_invalid"].includes(publicError(error))) {
          // A Host restart or changed list invalidates cursors, not the read.
          // Retry this read once without them; no writes or authority retries.
          delete readInput.messageCursor; delete readInput.threadCursor;
          threadCursor = null; messageCursor = null; cursorReset = true;
          append = threadId ? "selection" : null;
          response = await transport.readSnapshot(readInput);
        } else {
          // Only a missing selection permits falling back to the root here.
          // Authorization and connection failures remain blocking errors.
          if (!threadId || publicError(error) !== "host_app_workbench_thread_not_found") throw error;
          missingThreadId = threadId;
          threadId = null; threadCursor = null; messageCursor = null;
          contactRequestCursor = undefined; append = null;
          response = await transport.readSnapshot({ ...(query ? { query } : {}), filter: historyView === "archived" && filter === "all" ? "archived" : filter });
        }
      }
      let next = validateWorkbenchSnapshot(response);
      if (stopped || sequence !== loadSequence) return;
      if (refreshMessagePage && threadId && !cursorReset) {
        // Preserve the expanded window, including when following latest. Only
        // arrivals beyond its bound require reading the current tail instead.
        const followLatestGap = Boolean(next.messages.previousCursor);
        for (let attempt = 0; ; attempt++) {
          const requestedCursor = readInput.messageCursor ?? null;
          if (setRefreshCursor(followLatestGap) === requestedCursor) break;
          if (attempt === 2) throw Object.assign(new Error("host_app_workbench_snapshot_busy"), { code: "host_app_workbench_snapshot_busy" });
          next = validateWorkbenchSnapshot(await transport.readSnapshot(readInput));
          if (stopped || sequence !== loadSequence) return;
        }
      }
      let effectiveAppend = append;
      let clearAuthorityReload = false;
      const contactRequestRootRequired = append === "contact-requests" && snapshot
        && (authorityReloadRequired
          || snapshot.hostGeneration !== next.hostGeneration
          || snapshot.revision !== next.revision);
      if (contactRequestRootRequired) {
        authorityReloadRequired = true;
        next = validateWorkbenchSnapshot(await transport.readSnapshot({
          ...(threadId ? { threadId } : {}),
          ...(threadCursor ? { threadCursor } : {}),
          ...(messageCursor ? { messageCursor } : {}),
          ...(query ? { query } : {}),
          filter: readInput.filter,
        }));
        if (stopped || sequence !== loadSequence) return;
        effectiveAppend = null;
        clearAuthorityReload = true;
      } else if (contactRequestCursor === undefined) {
        clearAuthorityReload = true;
      }
      let changedDuringRead = observedChange !== changeSequence
        && (unorderedChangeSequence > observedChange || !coversChange(next, latestChange));
      const historyWindowRead = ["messages", "messages-newer"].includes(effectiveAppend) && next.messages.refreshCursor
        && ["ready", "stale"].includes(view.phase) && snapshot?.hostGeneration === next.hostGeneration;
      if (changedDuringRead && !historyWindowRead) {
        markSnapshotStale();
        return;
      }
      if (snapshot && (snapshot.subject.principalId !== next.subject.principalId
        || snapshot.subject.delegateId !== next.subject.delegateId
        || snapshot.subject.hellolynkId !== next.subject.hellolynkId)) {
        resetAccountView();
        sequence = loadSequence;
        effectiveAppend = null;
        threadId = null;
      }
      // Capture just before replacing the current DOM, after the read has
      // settled. Input, focus and scrolling may have changed while it waited.
      // Indexed pagination already returns one coherent, bounded history
      // window. Do not merge it with an older cached window or trim its cursors.
      if (historyWindowRead) effectiveAppend = "selection";
      const messageWindowChanged = snapshot && ["messages", "messages-newer"].includes(effectiveAppend)
        && (snapshot.revision !== next.revision || snapshot.hostGeneration !== next.hostGeneration);
      if (messageWindowChanged) {
        // Never combine old history with a different store revision, or replace
        // the currently viewed records with an unrelated older/newer page.
        changeRefreshPending = true;
        markSnapshotStale();
        return;
      }
      const uiContext = (typeof preserveUiContext === "function" ? preserveUiContext() : preserveUiContext) ? captureRefreshUiContext({ followLatest: refreshMessagePage }) : null;
      if (historyWindowRead && uiContext?.messageAnchor && requestedMessageScrollTop !== null
        && Math.abs(uiContext.messageScrollTop - requestedMessageScrollTop) > 1
        && !uiContext.messageAnchor.candidates.some(candidate => next.messages.items.some(item => item.localMessageId === candidate.recordId))) {
        // The reader moved into the part a bounded page would evict while it
        // was loading. Keep their newer position and refresh that window; an
        // obsolete page request must not pull them to an unrelated record.
        changeRefreshPending = true;
        markSnapshotStale();
        return;
      }
      const sameThreadList = snapshot?.revision === next.revision && snapshot?.hostGeneration === next.hostGeneration;
      // Paging one history window must not navigate the independent sidebar.
      // Reuse only a current list page; changed revisions still replace it so
      // new conversations, changed permissions and invalid cursors are seen.
      const keepThreadPage = preserveThreadPage && sameThreadList && !cursorReset
        && messagePageContextMatches(threadId) && next.messages.threadId === threadId
        && snapshot.threads.items.some(item => item.threadId === threadId);
      if (keepThreadPage) {
        const refreshed = new Map(next.threads.items.map(item => [item.threadId, item]));
        next = { ...next, threads: { ...snapshot.threads,
          items: snapshot.threads.items.map(item => refreshed.get(item.threadId) ?? item) } };
      }
      snapshot = mergeSnapshotPage(snapshot, next, effectiveAppend, messagePageWindow);
      // A rejected/partial merge cannot cover a notice using an unapplied
      // response. Only the snapshot actually displayed can absorb that notice.
      if (observedChange !== changeSequence) {
        changedDuringRead = unorderedChangeSequence > observedChange || !coversChange(snapshot, latestChange);
        if (!changedDuringRead) changeRefreshPending = false;
      }
      if (effectiveAppend === "threads" && sameThreadList) {
        threadPageCursors = [...threadPageCursors.slice(0, threadPageIndex), threadCursor];
      } else if (!keepThreadPage && (!sameThreadList || !["messages", "messages-newer", "contact-requests"].includes(effectiveAppend))) {
        const pageIndex = sameThreadList ? threadPageCursors.indexOf(threadCursor) : -1;
        threadPageCursors = pageIndex >= 0 ? threadPageCursors.slice(0, pageIndex + 1) : [threadCursor];
      }
      contactRequestPageCursors = effectiveAppend === "contact-requests"
        ? [...contactRequestPageCursors.slice(0, contactRequestPageIndex), contactRequestCursor]
        : [undefined];
      if (messageWindowChanged || !["messages", "messages-newer", "threads", "contact-requests"].includes(effectiveAppend)) {
        messagePageWindow = snapshot.messages.threadId
          ? { threadId: snapshot.messages.threadId, query, filter: readInput.filter, pages: [snapshot.messages],
            latestPage: !readInput.messageCursor || (refreshMessagePage && messagePageWindow?.latestPage === true
              && !snapshot.messages.previousCursor) } : null;
      }
      clearReadRetry();
      invalidateSendApprovalContexts();
      if (clearAuthorityReload) authorityReloadRequired = false;
      if (view.section === "security" && !hasWorkbenchCapability(snapshot, "security.read")) {
        applyLocation({ replace: true });
      }
      if (effectiveAppend == null) threadPageCursorById.clear();
      if (!keepThreadPage && effectiveAppend !== "messages" && effectiveAppend !== "messages-newer" && effectiveAppend !== "contact-requests") rememberThreadPage(next.threads.items, threadCursor);
      const visibleThreadIds = new Set(snapshot.threads.items.map((item) => item.threadId));
      for (const id of threadPageCursorById.keys()) if (!visibleThreadIds.has(id)) threadPageCursorById.delete(id);
      if (missingThreadId && view.selectedThreadId === missingThreadId) {
        if (parseRoute(location.hash).threadId === missingThreadId) replaceLocationHash("#/messages");
        dispatch({ type: "CLEAR_SELECTION" });
      }
      const selectionStillCurrent = threadId && view.selectedThreadId === threadId && view.section === "inbox";
      appliedReadSequence = sequence;
      dispatch({ type: "LOADED", snapshot });
      if (selectionStillCurrent && snapshot.threads.items.some((item) => item.threadId === threadId)) {
        dispatch({ type: "SELECT_THREAD", threadId });
      }
      if (changedDuringRead) {
        // Display the requested history, but keep writes fenced until the
        // queued refresh covers notifications received during this read.
        changeRefreshPending = true;
        markSnapshotStale();
      }
      if (uiContext) restoreRefreshUiContext(uiContext);
      return { sequence, navigationSequence };
    } catch (error) {
      if (stopped || sequence !== loadSequence) return;
      if (error?.code === "workbench_account_changed") resetAccountView();
      handleSnapshotReadFailure(error, quiet);
    } finally {
      activeReads--;
      let actionReleased = false;
      for (const [key, operation] of actionOperationByKey) actionReleased = releaseRefreshedAction(key, operation) || actionReleased;
      if (!stopped && actionReleased) render();
      if (!stopped && readRefreshError) renderChrome();
      if (!stopped && (view.phase !== "error" || recoveryRefreshPending || changeRefreshPending)) queueMicrotask(refreshAfterChange);
    }
  }

  $("account-disconnect")?.addEventListener("click", () => {
    if (disconnectPending || typeof transport.disconnectAccount !== "function" || accountRevision === null) return;
    disconnectRevision = accountRevision;
    disconnectNeedsRefresh = false;
    $("account-disconnect-title").textContent = copy("disconnect.title", "解除当前客户端的账号连接？");
    $("account-disconnect-copy").textContent = copy("disconnect.copy", "旧账号的历史记录保留，解除后可以重新连接账号。");
    $("account-disconnect-cancel").textContent = copy("action.cancel", "取消");
    $("account-disconnect-confirm").textContent = copy("portal.disconnect", "解除连接");
    $("account-disconnect-status").textContent = "";
    $("account-disconnect-layer").hidden = false;
    setElementIsolation($("workbench"), true);
    $("account-disconnect-cancel").focus();
  });
  async function closeDisconnectDialog() {
    $("account-disconnect-layer").hidden = true;
    setElementIsolation($("workbench"), globalComposer.open);
    if (disconnectNeedsRefresh) {
      disconnectNeedsRefresh = false;
      await load({ threadId: null, query: "", filter: "all" });
    }
    if (stopped || !$("account-disconnect-layer").hidden) return;
    const target = [$("account-disconnect"), $("connection-start"), $("state-retry")]
      .find((button) => button && !button.hidden && !button.disabled);
    target?.focus();
  }
  $("account-disconnect-cancel")?.addEventListener("click", () => {
    if (!disconnectPending) void closeDisconnectDialog();
  });
  $("account-disconnect-confirm")?.addEventListener("click", async () => {
    if (!disconnectPending && disconnectNeedsRefresh) return closeDisconnectDialog();
    if (disconnectPending || disconnectRevision === null) return;
    disconnectPending = true;
    $("account-disconnect-confirm").disabled = true;
    $("account-disconnect-cancel").disabled = true;
    $("account-disconnect-status").textContent = copy("disconnect.progress", "正在解除连接…");
    try {
      const result = await transport.disconnectAccount({ revision: disconnectRevision });
      if (result?.disconnected !== true) throw new Error("workbench_disconnect_failed");
      accountRevision = result.revision;
      resetAccountView();
      closeDisconnectDialog();
      await load({ threadId: null, query: "", filter: "all" });
    } catch (error) {
      // A failed response does not establish whether the account was detached.
      // Discard the old writable view and recover through an authoritative read.
      accountRevision = null;
      disconnectRevision = null;
      disconnectNeedsRefresh = true;
      resetAccountView("workbench_disconnect_result_unknown");
      $("account-disconnect-status").textContent = copy("disconnect.unknown", "尚未确认解除结果，关闭此窗口后会重新检查连接状态。错误码：") + publicError(error);
      $("account-disconnect-confirm").textContent = copy("disconnect.checkStatus", "检查状态");
    } finally {
      disconnectPending = false;
      $("account-disconnect-confirm").disabled = false;
      $("account-disconnect-cancel").disabled = false;
    }
  });

  function refreshAfterChange() {
    if (stopped || (!changeRefreshPending && !recoveryRefreshPending) || activeReads || manualRefreshPending || lifecycleRefreshScheduled) return;
    // A change invalidates old writes, but must not interrupt a command already
    // awaiting its outcome. Its normal follow-up read can absorb this notice.
    if (globalSubmitInFlight || [...sendStateByThreadId.values(), ...actionStateByKey.values(),
      ...contactRequestSendStateByTarget.values()]
      .some((state) => state.phase === "pending" && !state.actionId)) return;
    const recover = recoveryRefreshPending && (["error", "stale"].includes(view.phase) || firstReadConnecting);
    recoveryRefreshPending = false;
    if (!changeRefreshPending && !recover) return;
    changeRefreshPending = false;
    void refreshReadOnly({ quiet: Boolean(snapshot) && view.phase === "stale" });
  }

  function resetMessagePage() {
    // Opening a conversation starts at its latest page. Expanded history is
    // only retained while the reader stays in that open conversation.
    loadSequence++;
    messagePageWindow = null;
    loadingMessagePage = null;
    const messages = document.querySelector(".messages");
    if (messages) messages.dataset.scrollTarget = "latest";
  }

  function prepareBackgroundReopen() {
    // The change source has kept this view current. Only expanded/older history
    // needs a new latest page; prepare it before the sidebar is shown again.
    if (loadingMessagePage || (messagePageContextMatches(view.selectedThreadId) && !messagePageWindow.latestPage)) {
      scheduleLifecycleRefresh({ reopen: true });
      return;
    }
    const messages = document.querySelector(".messages");
    if (messages) {
      messages.dataset.scrollTarget = "latest";
      messages.scrollTop = messages.scrollHeight;
    }
    recoveryRefreshPending = true;
    refreshAfterChange();
  }

  function scheduleLifecycleRefresh({ reopen = false } = {}) {
    if (reopen && !stopped) resetMessagePage();
    if (stopped || document.hidden === true || lifecycleRefreshScheduled) return;
    lifecycleRefreshScheduled = true;
    queueMicrotask(() => {
      lifecycleRefreshScheduled = false;
      if (stopped || document.hidden === true) return;
      // Treat a resumed page like a change notification. This keeps the last
      // verified view readable, fences writes, and coalesces with an in-flight
      // read without renewing or creating a browser/Host authorization.
      changeSequence++;
      unorderedChangeSequence = changeSequence;
      changeRefreshPending = true;
      markSnapshotStale();
      refreshAfterChange();
    });
  }

  function refreshThreadTimes() {
    if (stopped || document.hidden === true) return;
    for (const label of $("list-content").querySelectorAll(".thread-time")) {
      localizedText(label, localizedRelativeTime(label.getAttribute("datetime")));
    }
  }

  function syncThreadTimeRefresh() {
    clearInterval(threadTimeTimer);
    threadTimeTimer = null;
    if (stopped || document.hidden === true) return;
    refreshThreadTimes();
    threadTimeTimer = setInterval(refreshThreadTimes, 60_000);
  }

  const handleVisibilityRecovery = () => {
    syncThreadTimeRefresh();
    if (document.hidden === true) return;
    if (transport.refreshesWhileHidden === true) {
      // The change source can be healthy after snapshot retries are exhausted.
      // Recover only a failed/stale view; a healthy view keeps its history.
      recoveryRefreshPending = true;
      refreshAfterChange();
    } else scheduleLifecycleRefresh();
  };
  const handleOnlineRecovery = () => scheduleLifecycleRefresh();
  const handlePageShowRecovery = (event) => {
    // The initial pageshow follows the mount's own load. A persisted page is
    // returning from browser history and needs a new authoritative read.
    if (event?.persisted === true) scheduleLifecycleRefresh({ reopen: true });
  };

  function clearReadRetry() {
    clearTimeout(readRetryTimer);
    readRetryTimer = null;
    readRetryAttempt = 0;
    firstReadConnecting = false;
    readRefreshError = null;
  }

  function handleSnapshotReadFailure(error, quiet) {
    const code = publicError(error);
    if (quiet && snapshot && ["ready", "empty", "stale"].includes(view.phase)
      && RETRYABLE_SNAPSHOT_ERRORS.has(code)) {
      // Keep the last verified local view, but stale data never authorizes a
      // write. Authentication/schema errors still use the blocking error UI.
      readRefreshError = code;
      markSnapshotStale();
      retrySnapshotRead(error);
      renderChrome();
      return;
    }
    if (!snapshot && FIRST_READ_WAIT_ERRORS.has(code)) {
      // While the existing bounded retry continues, keep the loading view and
      // say it is connecting. The last timeout still shows the error.
      retrySnapshotRead(error);
      if (readRetryTimer) {
        readRefreshError = null;
        authorityFailureSequence++;
        firstReadConnecting = true;
        if (view.phase === "loading") renderState();
        else dispatch({ type: "LOAD" });
        return;
      }
    }
    firstReadConnecting = false;
    readRefreshError = null;
    authorityFailureSequence++;
    dispatch({ type: "FAILED", code });
    retrySnapshotRead(error);
  }

  function retrySnapshotRead(error) {
    // A notification cursor can advance even when its ensuing snapshot fails.
    // Recover the read with bounded backoff; never replay a mutation or renew
    // a revoked/expired session. Keep the error's write fence until success.
    if (!RETRYABLE_SNAPSHOT_ERRORS.has(publicError(error))) {
      clearReadRetry();
      return;
    }
    if (stopped || readRetryTimer || readRetryAttempt >= 4) return;
    const epoch = accountViewEpoch;
    const delay = 1_000 * 2 ** readRetryAttempt++;
    readRetryTimer = setTimeout(() => {
      readRetryTimer = null;
      if (stopped || accountViewEpoch !== epoch) return;
      recoveryRefreshPending = true;
      refreshAfterChange();
    }, delay);
  }

  function markSnapshotStale() {
    // A queued change is not renewed authority. Keep recovery/error overlays
    // closed until a later successful read covers every observed change.
    if (["ready", "empty", "stale"].includes(view.phase)) dispatch({ type: "STALE" });
  }

  function orderedChange(value) {
    if (typeof value?.hostGeneration !== "string" || typeof value.changeCursor !== "string"
      || !/^(0|[1-9][0-9]*)$/.test(value.changeCursor)) return null;
    const cursor = Number(value.changeCursor);
    return Number.isSafeInteger(cursor) ? { hostGeneration: value.hostGeneration, changeCursor: value.changeCursor, cursor } : null;
  }

  function coversChange(current, change) {
    const applied = orderedChange(current), observed = orderedChange(change);
    return Boolean(applied && observed && applied.hostGeneration === observed.hostGeneration && applied.cursor >= observed.cursor);
  }

  function rememberThreadPage(items, cursor) {
    for (const item of items) threadPageCursorById.set(item.threadId, cursor ?? null);
  }

  function isCurrentThreadPagePending() {
    return Boolean(loadingThreadPage
      && loadingThreadPage.readSequence === loadSequence
      && loadingThreadPage.query === view.query
      && loadingThreadPage.filter === view.filter
      && loadingThreadPage.historyView === historyView);
  }

  async function loadThreadPage(pageIndex) {
    if (!snapshot || isCurrentThreadPagePending() || !Number.isInteger(pageIndex)
      || pageIndex < 0 || pageIndex > threadPageCursors.length) return;
    const cursor = pageIndex === threadPageCursors.length
      ? snapshot.threads.nextCursor : threadPageCursors[pageIndex];
    if (pageIndex > 0 && !cursor) return;
    const operation = {
      readSequence: loadSequence + 1,
      query: view.query,
      filter: view.filter,
      historyView,
    };
    loadingThreadPage = operation;
    try {
      const pendingRead = load({
        threadId: null,
        threadCursor: cursor,
        threadPageIndex: pageIndex,
        query: view.query,
        filter: view.filter,
        quiet: true,
        append: "threads",
      });
      // load increments its sequence synchronously before the read awaits.
      render();
      await pendingRead;
    } finally {
      if (loadingThreadPage === operation) {
        loadingThreadPage = null;
        render();
      }
    }
  }

  function showMessagePagePending(threadId) {
    const root = document.querySelector(".messages");
    if (root?.dataset.threadId !== threadId) return;
    // Keep the mounted timeline, draft, focus and scroll while the read waits.
    for (const className of ["load-more-messages", "load-newer-messages", "jump-latest-messages"]) {
      const button = root.querySelector(`.${className}`);
      if (!button) continue;
      button.disabled = true;
      localizedText(button, localizedCopy("pagination.loading", "正在加载…"));
    }
  }

  async function loadMoreMessages(threadId, direction = "older") {
    const cursor = direction === "older" ? snapshot?.messages.nextCursor : snapshot?.messages.previousCursor;
    if (!cursor || loadingMessagePage?.threadId === threadId || !messagePageContextMatches(threadId)) return;
    if (direction === "older" && snapshot.messages.items.length >= 200) return;
    const operation = { threadId };
    loadingMessagePage = operation;
    showMessagePagePending(threadId);
    try {
      await load({
        threadId,
        messageCursor: cursor,
        quiet: true,
        append: direction === "older" ? "messages" : "messages-newer",
        preserveUiContext: true,
        preserveThreadPage: true,
      });
    } finally {
      if (loadingMessagePage === operation) { loadingMessagePage = null; render(); }
    }
  }

  async function jumpToLatestMessages(threadId) {
    if (loadingMessagePage?.threadId === threadId || !messagePageContextMatches(threadId)) return;
    const operation = { threadId };
    loadingMessagePage = operation;
    showMessagePagePending(threadId);
    let applied;
    try {
      applied = await load({ threadId,
        quiet: true, append: "selection", preserveThreadPage: true });
    } finally {
      if (loadingMessagePage === operation) { loadingMessagePage = null; render(); }
      queueMicrotask(() => {
        if (!applied || stopped || applied.sequence !== loadSequence
          || applied.navigationSequence !== navigationSequence) return;
        const root = document.querySelector(".messages");
        if (root?.dataset.threadId === threadId) root.scrollTop = root.scrollHeight;
      });
    }
  }

  async function loadContactRequestPage(pageIndex) {
    if (!snapshot || loadingContactRequestPage || !Number.isInteger(pageIndex)
      || pageIndex < 0 || pageIndex > contactRequestPageCursors.length) return;
    const cursor = pageIndex === contactRequestPageCursors.length
      ? snapshot.contactRequestNextCursor : contactRequestPageCursors[pageIndex];
    if (pageIndex > 0 && !cursor) return;
    loadingContactRequestPage = true;
    render();
    try {
      await load({
        threadId: null,
        contactRequestCursor: cursor,
        contactRequestPageIndex: pageIndex,
        quiet: true,
        append: "contact-requests",
        preserveUiContext: () => view.section !== "contacts" || contactWorkspaceMode !== "requests",
      });
    } finally {
      loadingContactRequestPage = false;
      if (!stopped && view.section === "contacts" && contactWorkspaceMode === "requests") render();
    }
  }

  function messagePageContextMatches(threadId) {
    if (!threadId || snapshot?.messages.threadId !== threadId || messagePageWindow?.threadId !== threadId) return false;
    const filter = historyView === "archived" && view.filter === "all" ? "archived" : view.filter;
    return messagePageWindow.query === view.query && messagePageWindow.filter === filter;
  }

  function isFollowingLatestMessages(threadId) {
    const root = document.querySelector(".messages");
    return root?.dataset.threadId === threadId && snapshot?.messages.threadId === threadId
      && !snapshot.messages.previousCursor && root.scrollHeight - root.scrollTop - root.clientHeight < 2;
  }

  function visibleMessageRefreshCursor(threadId) {
    if (!messagePageContextMatches(threadId)) return null;
    const root = document.querySelector(".messages");
    if (!root || root.dataset.threadId !== threadId) return null;
    return messagePageWindow?.pages[0]?.refreshCursor ?? null;
  }

  async function refreshReadOnly({ quiet = true } = {}) {
    await load({
      threadId: view.selectedThreadId,
      quiet,
      append: view.selectedThreadId ? "selection" : null,
      preserveUiContext: true,
      refreshMessagePage: true,
      preserveThreadPage: true,
    });
  }

  function scheduleReadRefresh() {
    // A new query/filter supersedes old reads immediately, including the
    // debounce interval before its own request starts.
    loadSequence++;
    clearTimeout(searchTimer);
    const navigationAtSearch = navigationSequence;
    searchTimer = setTimeout(() => {
      searchTimer = null;
      // Finish the local search without undoing a newer navigation choice.
      if (view.section === "inbox" && navigationSequence === navigationAtSearch) navigate("inbox");
      void load({ threadId: view.selectedThreadId, quiet: true });
    }, 180);
  }

  function applyLocation({ replace = false, loadSelection = true } = {}) {
    navigationSequence++;
    let route = parseRoute(location.hash);
    if (route.section === "security" && snapshot && !hasWorkbenchCapability(snapshot, "security.read")) {
      replaceLocationHash("#/messages");
      route = parseRoute("#/messages");
    }
    selectedContactId = route.section === "contacts" ? route.contactId : null;
    contactWorkspaceMode = route.section === "contacts" ? route.contactMode : null;
    if (contactInstancePickerId !== selectedContactId) contactInstancePickerId = null;
    const nextObjectKey = route.threadId
      ? `thread:${route.threadId}`
      : route.contactId
        ? `contact:${route.contactId}`
        : null;
    if (detailsObjectKey !== nextObjectKey) {
      detailsOpen = false;
      detailsObjectKey = nextObjectKey;
      detailsMessageId = null;
    }
    pendingModuleFocus = !route.threadId && route.section === "contacts" && (route.contactId || route.contactMode)
      ? "contacts"
      : !route.threadId && ["security", "settings"].includes(route.section)
      ? route.section
      : null;
    dispatch({ type: "SET_SECTION", section: route.section });
    if (route.threadId) {
      dispatch({ type: "SELECT_THREAD", threadId: route.threadId });
      document.documentElement.querySelector("#workbench")?.classList.add("is-content-open");
      if (loadSelection) {
        resetMessagePage();
        load({
          threadId: route.threadId,
          threadCursor: threadPageCursorById.get(route.threadId) ?? null,
          quiet: true,
          append: "selection",
        });
      }
      queueMicrotask(() => $("content-pane")?.focus({ preventScroll: true }));
    } else {
      dispatch({ type: "CLEAR_SELECTION" });
      document.documentElement.querySelector("#workbench")?.classList.toggle("is-content-open", contactContentOpen(route));
    }
    if ((!location.hash || location.hash === "#/inbox") && replace) replaceLocationHash("#/messages");
  }

  function navigate(section, threadId = null) {
    const publicSection = section === "inbox" ? "messages" : section;
    const target = threadId ? `#/${publicSection}/thread/${encodeURIComponent(threadId)}` : `#/${publicSection}`;
    if (location.hash === target) applyLocation();
    else location.hash = target;
  }

  function navigateContact(contactId) {
    const target = `#/contacts/contact/${encodeURIComponent(contactId)}`;
    if (location.hash === target) applyLocation();
    else location.hash = target;
  }

  function navigateContactMode(mode) {
    const target = `#/contacts/${mode}`;
    if (location.hash === target) applyLocation();
    else location.hash = target;
  }

  function contactContentOpen(route = {}) {
    return Boolean(route.contactId || route.contactMode)
      || ["security", "settings"].includes(route.section);
  }

  function render() {
    const localeChanged = lastRenderedLocale !== locale;
    lastRenderedLocale = locale;
    reconcileSendUnknownLocks();
    for (const [id, preview] of sendPreviewByMessageId) {
      if (!isSendPreviewContextCurrent(preview)
        || snapshot.messages.items.some((message) => message.clientMessageId === id
          && message.direction === "outgoing" && isSentStatus(message.status)
          && message.senderPrincipalId === preview.principalId && message.senderDelegateId === preview.delegateId
          && snapshot.threads.items.some((thread) => thread.threadId === message.threadId && sendPreviewMatchesThread(preview, thread)))) {
        sendPreviewByMessageId.delete(id);
      }
    }
    document.documentElement.lang = locale;
    syncMobilePaneIsolation();
    renderChrome();
    renderState();
    renderGlobalComposer();
    renderLocalHistoryDialog();
    if (!snapshot) return;
    // Preserve drafts and pending command cards until new authority arrives.
    // Detached controls are also fenced by canExecute, not just the DOM state.
    if (view.phase === "stale" || changeRefreshPending) {
      // Editing a local draft does not exercise stale authority. Leave text
      // fields usable; canExecute still fences Enter and detached submissions.
      for (const selector of ["button", "input[type=checkbox]", "input[type=radio]", "select"]) {
        for (const control of $("content-view").querySelectorAll(selector)) control.disabled = true;
      }
      if (localeChanged) localeBindings.retranslate([$("list-content"), $("history-manage"), $("history-management"), $("inbox-read-actions"), $("content-view")], [$("list-pane"), $("content-pane")]);
      return;
    }
    renderList();
    renderContent();
    restorePendingModuleFocus();
  }

  function restorePendingModuleFocus() {
    const section = pendingModuleFocus;
    if (!section || view.section !== section || !document.getElementById(`${section}-title`)) return;
    pendingModuleFocus = null;
    queueMicrotask(() => {
      if (view.section === section) document.getElementById(`${section}-title`)?.focus({ preventScroll: true });
    });
  }

  function syncMobilePaneIsolation() {
    const mobile = matchMedia("(max-width: 700px)").matches;
    const contentOpen = Boolean(view.selectedThreadId)
      || (view.section === "contacts" && Boolean(selectedContactId || contactWorkspaceMode))
      || ["security", "settings"].includes(view.section);
    const blockingContentOpen = !snapshot || ["loading", "error"].includes(view.phase);
    const mobileContentOpen = contentOpen || blockingContentOpen;
    $("workbench")?.classList.toggle("is-content-open", mobileContentOpen);
    $("workbench")?.classList.toggle("is-details-open", detailsOpen && contentOpen);
    setElementIsolation($("app-rail"), mobile && mobileContentOpen);
    setElementIsolation($("list-pane"), mobile && mobileContentOpen);
    setElementIsolation($("content-pane"), mobile && !mobileContentOpen);
    const renderedDetails = document.querySelector(".details-pane");
    const renderedMain = document.querySelector(".conversation-main") || document.querySelector(".contact-main");
    if (renderedMain && renderedDetails) syncRenderedDetailIsolation(renderedMain, renderedDetails);
  }

  function setElementIsolation(element, isolated) {
    if (!element) return;
    element.inert = Boolean(isolated);
    element.setAttribute("aria-hidden", String(Boolean(isolated)));
  }

  function renderChrome() {
    const titleBySection = {
      inbox: copy("shell.conversations", "会话"),
      contacts: copy("nav.contacts", "联系人"),
      security: copy("nav.security", "安全"),
      settings: copy("nav.settings", "设置"),
    };
    const contactsActive = view.section === "contacts";
    $("list-header").hidden = view.section === "inbox";
    $("space-label").textContent = copy("shell.personalSpace", "个人空间");
    $("space-label").hidden = contactsActive;
    $("section-title").textContent = titleBySection[view.section] || titleBySection.inbox;
    $("section-title").hidden = contactsActive;
    // Contacts use the header's left slot for the requests entry instead.
    $("list-heading").hidden = contactsActive;
    $("filter-all-label").textContent = copy("filter.all", "全部");
    $("filter-unread-label").textContent = copy("filter.unread", "未读");
    $("thread-filters").setAttribute("aria-label", copy("filter.label", "会话筛选"));
    const searchCopy = view.section === "contacts"
      ? copy("contacts.searchPlaceholder", "搜索联系人")
      : copy("search.placeholder", "搜索会话和消息");
    const searchInput = $("search-input");
    $("search-region").hidden = !["inbox", "contacts"].includes(view.section);
    searchInput.placeholder = searchCopy;
    // One visible input serves two independent local filters. Do not replace
    // a focused value during refresh or IME composition.
    if (searchInput.dataset.section !== view.section || document.activeElement !== searchInput)
      searchInput.value = contactsActive ? contactQuery : view.query;
    searchInput.dataset.section = view.section;
    $("search-label").textContent = searchCopy;
    $("locale-toggle").textContent = locale === "zh-CN" ? "EN" : "中";
    $("locale-toggle").setAttribute("aria-label", locale === "zh-CN" ? "Switch to English" : "切换为中文");
    if ($("account-disconnect")) $("account-disconnect").textContent = copy("portal.disconnect", "解除连接");
    const globalRefresh = $("global-refresh");
    if (globalRefresh) {
      const refreshing = manualRefreshPending || (view.phase === "stale" && activeReads > 0);
      const label = refreshing ? copy("action.refreshing", "正在刷新") : copy("action.refreshMessages", "刷新消息");
      globalRefresh.setAttribute("aria-label", label);
      globalRefresh.setAttribute("aria-busy", String(refreshing));
      const hint = copy("action.refreshHint", "没看到新消息？点刷新");
      globalRefresh.title = label;
      $("refresh-label").textContent = label;
      $("refresh-hint").textContent = hint;
      globalRefresh.disabled = refreshing || view.phase === "loading";
    }
    const pendingContactRequests = incomingPendingContactRequestCount();
    const contactsLabel = titleBySection.contacts;
    $("contacts-nav-label").textContent = contactsLabel;
    // Requests live inside Contacts; the contacts tab still shows pending
    // incoming requests from every page.
    const contactsBadge = $("contacts-nav-badge");
    contactsBadge.hidden = pendingContactRequests === 0;
    contactsBadge.textContent = pendingContactRequests > 0 ? String(pendingContactRequests) : "";
    const contactRequestLink = $("contact-request-link");
    const contactRequestBadge = $("contact-request-badge");
    contactRequestLink.hidden = !contactsActive;
    const requestsLabel = copy("nav.contactRequests", "联系申请");
    $("contact-request-label").textContent = requestsLabel;
    const requestsActive = contactsActive && contactWorkspaceMode === "requests" && !selectedContactId;
    contactRequestLink.classList.toggle("is-pending", pendingContactRequests > 0);
    contactRequestLink.classList.toggle("is-active", requestsActive);
    contactRequestLink.setAttribute("aria-current", requestsActive ? "page" : "false");
    contactRequestLink.setAttribute("aria-label", pendingContactRequests > 0
      ? copy("nav.contactRequestsPending", "联系申请，{count} 条待处理", { count: pendingContactRequests }) : requestsLabel);
    contactRequestBadge.hidden = pendingContactRequests === 0;
    contactRequestBadge.textContent = pendingContactRequests > 0 ? String(pendingContactRequests) : "";
    const navLabels = {
      inbox: copy("nav.messages", "消息"),
      // The visible name plus the count its badge shows; plain when none waits.
      contacts: pendingContactRequests > 0
        ? copy("nav.contactsPending", "联系人，{count} 条待处理申请", { count: pendingContactRequests }) : contactsLabel,
      security: titleBySection.security,
      settings: titleBySection.settings,
    };
    document.querySelectorAll(".rail-link[data-section]").forEach((link) => {
      if (link.dataset.section === "inbox") link.textContent = navLabels.inbox;
      link.hidden = link.dataset.section === "security"
        && (!snapshot || !hasWorkbenchCapability(snapshot, "security.read"));
      const current = link.dataset.section === view.section;
      link.classList.toggle("is-active", current);
      link.setAttribute("aria-current", current ? "page" : "false");
      link.setAttribute("aria-label", navLabels[link.dataset.section] || "HelloLynk");
    });
    $("thread-filters").hidden = view.section !== "inbox";
    const listAction = $("list-primary-action");
    if (listAction) {
      listAction.hidden = view.section !== "contacts";
      listAction.disabled = !canExecute("principal.search") || !canExecute("contact-request.send");
      listAction.textContent = copy("contacts.add", "添加联系人");
      listAction.setAttribute("aria-label", copy("contacts.add", "添加联系人"));
    }
    $("account-link-devices").setAttribute("aria-label", copy("portal.devicesExternal", "在浏览器中打开设备与撤销"));
    renderPortalTarget("keys");
    renderPortalTarget("devices");
    if (snapshot) {
      const synthetic = snapshot.source.mode === "synthetic-preview";
      const online = !synthetic && snapshot.security.hostStatus === "online";
      const localOnly = isLocalHistoryOnly(snapshot);
      const hostDot = document.querySelector(".host-dot");
      hostDot?.classList.toggle("is-online", online && !(view.phase === "stale" && readRefreshError));
      hostDot?.classList.toggle("is-synthetic", synthetic);
      $("host-status").textContent = synthetic
        ? copy("host.synthetic", "")
        : localOnly
          ? copy("host.localOnly", "本地记录与设置")
        : online
          ? copy("host.online", "已连接本机 Host")
          : copy("host.unavailable", "本机 Host 暂不可用");
      $("host-status").title = localOnly
        ? copy("host.localOnlyHint", "断网时仍可查看和整理本机记录、调整本地设置。需要联网的操作恢复连接后再试。")
        : "";
      if (online && snapshot.relationshipMetadataState && snapshot.relationshipMetadataState !== "fresh") {
        const syncing = snapshot.relationshipMetadataState === "loading";
        const text = locale.startsWith("en")
          ? (syncing ? "Syncing contacts…" : "Contact sync pending")
          : (syncing ? "正在同步联系人…" : "联系人待同步");
        $("host-status").textContent = `${copy("host.online", "已连接本机 Host")} · ${text}`;
        $("host-status").title = locale.startsWith("en")
          ? "Local messages are available. Relationship actions become available after syncing."
          : "本地消息可正常查看，关系操作将在同步完成后恢复。";
      }
      if (view.phase === "stale" && readRefreshError) {
        const exhausted = !readRetryTimer && readRetryAttempt >= 4 && activeReads === 0;
        $("host-status").textContent = locale.startsWith("en")
          ? (exhausted ? "Refresh paused · Please refresh" : "Refresh delayed · Retrying…")
          : (exhausted ? "刷新暂不可用 · 请手动刷新" : "刷新暂时延迟 · 正在重试…");
        $("host-status").title = locale.startsWith("en")
          ? `Showing the last verified local view. Actions are paused until refresh succeeds. (${readRefreshError})`
          : `正在显示上次核验的本地记录，刷新成功前暂不能操作。（${readRefreshError}）`;
      }
    }
  }

  function renderConnectionResult() {
    const note = $("connection-result-note");
    if (!note) return;
    note.hidden = !recoveredConnectionName;
    note.textContent = recoveredConnectionName ? copy("connection.recovered",
      "连接已完成，本次使用的 AI 名称为“{name}”。", { name: recoveredConnectionName }) : "";
  }

  function renderState() {
    renderConnectionResult();
    const layer = $("state-layer");
    const content = $("content-view");
    const retry = $("state-retry");
    const phase = view.phase;
    const blocking = ["loading", "error", "conflict"].includes(phase) || !snapshot;
    $("workbench").setAttribute("data-phase", phase);
    layer.hidden = !blocking;
    content.hidden = blocking;
    $("workbench").setAttribute("aria-busy", String(phase === "loading"));
    document.querySelector(".spinner").hidden = phase !== "loading";
    retry.hidden = phase === "loading";
    const syntheticTransport = transport?.mode === "synthetic-memory"
      || transport?.initialSourceMode === "synthetic-preview";
    const failureCode = publicError(view.failure);
    const needsConnection = ["workbench_connection_required", ...["codex", "openclaw", "trae_work", "workbuddy", "cursor", "dsh"].map((client) => `neutral_${client}_binding_configuration_required`)].includes(failureCode);
    const showConnection = phase === "error" && needsConnection && !syntheticTransport;
    if ($("account-disconnect")) $("account-disconnect").hidden = accountRevision === null || needsConnection;
    layer.classList.toggle("is-connection", showConnection);
    $("connection-welcome").hidden = !showConnection;
    $("connection-guide").hidden = !showConnection;
    $("connection-eyebrow").textContent = copy("connection.welcome", "欢迎使用 HelloLynk");
    $("connection-hint").textContent = copy("connection.hint", "首次连接这台电脑时，我们会请你去官网确认。已确认过，就直接继续。");
    $("connection-start").hidden = !showConnection || !startConnection;
    $("connection-key-link").hidden = !showConnection || !openPortal;
    $("connection-start").textContent = copy("connection.start", "连接 HelloLynk");
    $("connection-help").textContent = startConnection
      ? copy("connection.help", "确认只需一次，以后打开即可连接。")
      : copy("connection.commandHelp", "请从当前客户端重新打开 HelloLynk；若仍无法连接，把这个情况告诉本地 AI。");
    if (phase === "error" && needsConnection) retry.hidden = true;
    const notificationFailed = view.failure?.source === "notification";
    const readTimedOut = ["workbench_snapshot_timeout", "workbench_mcp_snapshot_timeout", "workbench_mcp_app_bridge_timeout", "workbench_loopback_timeout", "workbench_surface_host_timeout", "neutral_host_request_timeout"]
      .includes(failureCode);
    const sessionExpired = failureCode === "workbench_surface_session_invalid";
    const versionMismatch = failureCode === "workbench_snapshot_contract_unsupported";
    let errorBody = copy("state.error.body", "这次没能读到页面数据，请重试。");
    if (failureCode === "workbench_disconnect_result_unknown") errorBody = copy("state.error.disconnectUnknown", "暂时无法确认连接状态。请先刷新核对，再决定是否重新连接。");
    else if (failureCode === "workbench_account_disconnect_incomplete") errorBody = copy("state.error.disconnectIncomplete", "上次解除连接被中断。请再点一次“解除连接”完成。");
    else if (failureCode === "workbench_account_changed") errorBody = copy("state.error.accountChanged", "当前客户端的账号连接已改变，请刷新后继续。");
    else if (versionMismatch) errorBody = copy("state.error.versionMismatch", "HelloLynk 客户端版本不一致，请将已安装的 HelloLynk 插件更新到同一批版本，再关闭并重开客户端。");
    else if (needsConnection) errorBody = copy("state.error.cursorNotConnected", "输入你的 HelloLynk ID，让消息和联系人来到这里。");
    else if (sessionExpired) errorBody = copy("state.error.sessionExpired", "本次页面连接已过期，请在客户端中重新打开 LYNK。");
    else if (failureCode === "cursor_host_reconnecting") errorBody = copy("state.error.reconnecting", "连接中断，正在重新连接。");
    else if (failureCode === "neutral_host_heartbeat_failed") errorBody = copy("state.error.hostConnection", "与 HelloLynk 后台的连接已失效，请重新打开 LYNK。");
    else if (readTimedOut) errorBody = copy("state.error.timeout", "读取超时，请重试。");
    else if (failureCode === "workbench_loopback_unreachable" || /^neutral_host_connection_(?:refused|reset)$/.test(failureCode)) errorBody = copy("state.error.unreachable", "页面无法连接到本机服务，请在客户端中重新打开 LYNK。");
    else if (failureCode === "workbench_surface_host_unreachable") errorBody = copy("state.error.backendUnreachable", "无法连接到 HelloLynk 后台，请重试。");
    else if (/^(?:host_attachment_|neutral_host_(?:attachment_|discovery_|generation_|adapter_closed))/.test(failureCode)) errorBody = copy("state.error.hostConnection", "与 HelloLynk 后台的连接已失效，请重新打开 LYNK。");
    else if (/^(?:host_request_unauthorized|host_app_authorization_required|host_capability_|workbench_surface_(?:origin_not_allowed|csrf_invalid))/.test(failureCode)) errorBody = copy("state.error.authorization", "本次连接未通过授权校验，请重新打开 LYNK。");
    else if (/(?:response_invalid|snapshot_invalid|source_mismatch)$/.test(failureCode)) errorBody = copy("state.error.invalidData", "收到的页面数据格式不正确，请重试。");
    else if (notificationFailed) errorBody = copy("state.error.notificationBody", "未能接收消息变化通知。连接恢复后会重新读取页面，也可以点重试。");
    const states = {
      loading: syntheticTransport
        ? [copy("state.synthetic.loading.title", ""), copy("state.synthetic.loading.body", ""), ""]
        : firstReadConnecting
          ? [copy("state.connecting.title", "正在连接本机服务"), copy("state.connecting.body", "第一次连接可能要多等一会儿。"), ""]
          : [copy("state.loading.title", "正在打开 HelloLynk"), copy("state.loading.body", "正在读取这台电脑上的消息。"), ""],
      error: syntheticTransport
        ? [copy("state.synthetic.error.title", ""), copy("state.synthetic.error.body", ""), copy("action.retry", "重试")]
        : [needsConnection ? copy("state.error.notConnectedTitle", "尚未连接 HelloLynk") : notificationFailed ? copy("state.error.notificationTitle", "消息变化通知中断") : copy("state.error.title", "暂时无法打开"), errorBody, copy("action.retry", "重试")],
      stale: [copy("state.stale.title", "数据已有变化"), copy("state.stale.body", "刷新后再继续，避免在旧数据上操作。"), copy("action.refresh", "刷新")],
      conflict: [copy("state.conflict.title", "数据发生冲突"), copy("state.conflict.body", "操作结果没有被猜测或自动重试。请刷新确认最新状态。"), copy("action.refresh", "刷新")],
    };
    const selected = states[phase] || states.loading;
    $("state-title").textContent = selected[0];
    $("state-message").textContent = phase === "error" && !showConnection && !versionMismatch
      ? `${selected[1]}\n${copy("state.error.code", "错误码")}：${failureCode}`
      : selected[1];
    retry.textContent = selected[2];
  }

  function renderList() {
    const all = deriveWorkbenchConversations(snapshot);
    const visible = historyView === "archived"
      ? all.filter((thread) => thread.archived === true)
      : selectVisibleThreads(view, snapshot).filter((thread) => thread.archived !== true);
    renderHistoryManagement();
    renderInboxReadActions(all);
    $("unread-count").textContent = String(all.filter((item) => item.unreadCount > 0).length);
    document.querySelectorAll(".filter-button").forEach((button) => {
      if (!button.dataset.filter) return;
      button.hidden = historyView === "archived";
      const active = button.dataset.filter === view.filter;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    const root = $("list-content");
    if (view.section === "contacts") {
      renderContactList(root);
      return;
    }
    if (view.section !== "inbox") {
      root.replaceChildren();
      return;
    }
    if (!visible.length && !snapshot.threads.nextCursor && threadPageCursors.length === 1) {
      const hasSearchQuery = view.query.normalize("NFKC").trim().length > 0;
      const emptyTitle = hasSearchQuery
        ? localizedCopy("list.empty.search.title", "没有匹配的会话")
        : historyView === "archived" ? localizedCopy("history.archivedEmpty", "没有已归档会话")
          : view.filter === "unread" ? localizedCopy("list.empty.unread.title", "暂无未读会话")
            : localizedCopy("list.empty.title", "这里还没有会话");
      const emptyBody = hasSearchQuery ? localizedCopy("list.empty.search", "没有找到匹配的本机记录。")
        : historyView === "archived" ? ""
          : view.filter === "unread" ? localizedCopy("list.empty.unread.body", "切换到“全部”查看所有会话。")
            : localizedCopy("list.empty.body", "新消息会显示在这里。");
      root.replaceChildren(node("div", "empty-list", [
        node("strong", "", emptyTitle),
        node("span", "", emptyBody),
      ]));
      return;
    }
    const conversationById = new Map(all.map((item) => [item.threadId, item]));
    const cards = visible.map((thread) => {
      const conversation = conversationById.get(thread.threadId) || thread;
      const button = node("button", `thread-card${view.selectedThreadId === thread.threadId ? " is-selected" : ""}`);
      button.type = "button";
      button.dataset.threadId = thread.threadId;
      button.setAttribute("aria-pressed", String(view.selectedThreadId === thread.threadId));
      const timeLabel = node("time", "thread-time", localizedRelativeTime(thread.updatedAt));
      timeLabel.setAttribute("datetime", thread.updatedAt);
      const copyRoot = node("span", "thread-copy", [
        node("span", "thread-row", [
          node("strong", "thread-name", thread.displayName),
          timeLabel,
        ]),
        node("span", "thread-route", conversationRouteLabel(thread)),
      ]);
      button.append(node("span", "thread-avatar", initials(thread.displayName)), copyRoot);
      if (thread.unreadCount > 0) button.append(node("span", "unread-badge", String(thread.unreadCount)));
      else if (conversation.hasSendFailure) button.append(node("span", "thread-status is-failed", localizedCopy("thread.sendFailed", "发送失败")));
      button.addEventListener("click", () => navigate("inbox", thread.threadId));
      const controls = threadLocalHistoryControls(thread, "list");
      if (!controls.length) return button;
      const more = renderContactMore(`thread-more-${thread.threadId}`, thread.displayName, controls);
      more.classList.add("thread-more");
      localizedText(more.children[0], localizedCopy("history.manage", "管理"));
      const row = node("div", "thread-list-row", [button, more]);
      const state = actionStateByKey.get(`local-history:${thread.archived === true ? "restore" : "hide"}:${thread.threadId}`);
      if (state && state.phase !== "idle" && state.phase !== "ok") row.append(actionStatus(state));
      return row;
    });
    if (snapshot.threads.nextCursor || threadPageCursors.length > 1) {
      const pageIndex = threadPageCursors.length - 1;
      const previous = contactActionButton("previous-threads", localizedCopy("pagination.previousThreads", "上一页"),
        () => void loadThreadPage(pageIndex - 1));
      previous.disabled = isCurrentThreadPagePending() || pageIndex === 0;
      const next = contactActionButton("load-more-threads", isCurrentThreadPagePending()
        ? localizedCopy("pagination.loading", "正在加载…") : localizedCopy("pagination.threads", "下一页"),
        () => void loadThreadPage(pageIndex + 1));
      next.disabled = isCurrentThreadPagePending() || !snapshot.threads.nextCursor;
      const first = contactActionButton("first-threads", localizedCopy("pagination.firstThreads", "回到第一页"),
        () => void loadThreadPage(0));
      first.disabled = isCurrentThreadPagePending() || pageIndex === 0;
      cards.push(node("div", "thread-pagination", [previous,
        node("span", "", localizedCopy("pagination.pageNumber", "第 {page} 页", { page: pageIndex + 1 })), next, first]));
    }
    root.replaceChildren(...cards);
  }

  function renderHistoryManagement() {
    const available = snapshot?.localHistory && hasWorkbenchCapability(snapshot, "threads.read");
    const trigger = $("history-manage");
    const panel = $("history-management");
    if (!trigger || !panel) return;
    trigger.hidden = !available || view.section !== "inbox";
    panel.hidden = trigger.hidden || !historyManagerOpen;
    localizedText(trigger, localizedCopy("history.manage", "管理"));
    trigger.setAttribute("aria-expanded", String(!panel.hidden));
    if (panel.hidden) return;
    const button = (label, handler, active = false) => {
      const control = node("button", `secondary-button${active ? " is-active" : ""}`, label);
      control.type = "button";
      control.addEventListener("click", handler);
      return control;
    };
    const active = button(localizedCopy("history.active", "聊天"), () => void selectHistoryView("active"), historyView === "active");
    const archived = button(localizedParts([localizedCopy("history.archived", "已归档"), ` (${snapshot.localHistory.archivedThreadCount})`]),
      () => void selectHistoryView("archived"), historyView === "archived");
    const enabled = snapshot.localHistory.autoArchiveAfterHours === 24;
    const configureState = actionStateByKey.get("local-history:configure");
    const autoArchive = button(localizedCopy(enabled ? "history.autoArchiveOn" : "history.autoArchiveOff",
      enabled ? "24 小时未活动自动归档：开" : "24 小时未活动自动归档：关"), () => {
      if (!canExecute("threads.manage-local") || !HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory) return;
      void runAction("local-history:configure", HELLOLYNK_WORKBENCH_COMMAND_TYPES.configureHistory,
        { autoArchiveAfterHours: enabled ? null : 24 }, { lockUnknown: true });
    });
    autoArchive.disabled = !canExecute("threads.manage-local") || ["pending", "unknown"].includes(configureState?.phase);
    const deleteArchived = button(localizedCopy("history.deleteArchived", "删除全部归档会话"), () =>
      openLocalHistoryConfirmation({ threadId: "archived" }, lifecycleSnapshotKey(), "history-manage", "deleteArchived"));
    deleteArchived.classList.add("danger-button");
    deleteArchived.hidden = historyView !== "archived";
    deleteArchived.disabled = !canExecute("threads.manage-local") || snapshot.localHistory.archivedThreadCount === 0
      || ["pending", "unknown"].includes(actionStateByKey.get("local-history:deleteArchived:archived")?.phase);
    panel.replaceChildren(active, archived, autoArchive,
      deleteArchived,
      ...(configureState && configureState.phase !== "idle" && configureState.phase !== "ok" ? [actionStatus(configureState)] : []));
  }

  async function selectHistoryView(nextView) {
    if (!snapshot?.localHistory || nextView === historyView) return;
    historyView = nextView;
    if (view.filter !== "all") dispatch({ type: "SET_FILTER", filter: "all" });
    if (view.selectedThreadId) navigate("inbox");
    await load({ threadId: null, filter: "all", quiet: true });
    queueMicrotask(() => $("history-manage")?.focus({ preventScroll: true }));
  }

  function renderContactList(root) {
    const normalizedQuery = contactQuery.normalize("NFKC").trim().toLocaleLowerCase(locale);
    const contacts = deriveWorkbenchContacts(snapshot).filter((contact) => {
      if (!normalizedQuery) return true;
      return [contact.displayName, contact.hellolynkId].some(
        (value) => String(value || "").normalize("NFKC").toLocaleLowerCase(locale).includes(normalizedQuery),
      );
    });
    const items = [];
    for (const contact of contacts) {
      const button = node("button", `contact-list-item${selectedContactId === contact.contactId ? " is-selected" : ""}`, [
        node("span", "thread-avatar", initials(contact.displayName)),
        node("span", "contact-list-copy", [
          node("strong", "", contact.displayName),
          node("span", "", localizedCopy("instances.count", "已添加 {count} 个 AI", { count: contact.instances.length })),
        ]),
      ]);
      button.type = "button";
      button.dataset.contactId = contact.contactId;
      button.setAttribute("aria-pressed", String(selectedContactId === contact.contactId));
      button.addEventListener("click", () => navigateContact(contact.contactId));
      items.push(button);
    }
    if (!contacts.length) {
      const empty = node("div", "empty-list", [
        node("strong", "", normalizedQuery ? localizedCopy("contacts.emptySearch", "没有匹配结果") : localizedCopy("contacts.empty", "没有联系人")),
      ]);
      if (!normalizedQuery) empty.append(node("span", "", localizedCopy("contacts.emptyBody", "添加联系人后会显示在这里")));
      items.push(empty);
    }
    root.replaceChildren(...items);
  }

  function renderContent() {
    const root = $("content-view");
    if (view.section === "contacts") return renderContacts(root);
    if (view.section === "security") return renderSecurity(root);
    if (view.section === "settings") return renderSettings(root);
    const thread = view.selectedThreadId
      ? snapshot.threads.items.find((item) => item.threadId === view.selectedThreadId) || null
      : null;
    if (!thread) return renderEmptyConversation(root);
    renderConversation(root, thread);
  }

  function renderEmptyConversation(root) {
    root.replaceChildren(node("section", "contact-workspace-empty", [
      node("h2", "", localizedCopy("conversation.empty.title", "选择一段会话")),
      node("p", "", localizedCopy("conversation.empty.body", "选择一段会话开始查看。")),
    ]));
  }

  function renderConversation(root, thread) {
    const contact = currentContactForThread(thread);
    const previousMessages = root.querySelector(".messages");
    const previousScrollTop = previousMessages?.dataset.threadId === thread.threadId ? previousMessages.scrollTop : 0;
    const messagesReady = snapshot.messages.threadId === thread.threadId;
    const messages = messagesReady ? snapshot.messages.items : [];
    if (detailsMessageId && !messages.some((message) => message.localMessageId === detailsMessageId)) detailsMessageId = null;
    const previews = [...sendPreviewByMessageId.values()].filter((preview) => sendPreviewMatchesThread(preview, thread));
    const outbox = snapshot.outbox.filter((item) => (
      (VISIBLE_OUTBOX_STATES.has(item.status) || previews.some((preview) => sendPreviewMatchesOutbox(preview, item)))
      && item.threadId != null && item.threadId === thread.threadId
    ));
    const outboxByMessageId = new Map(outbox.map((item) => [item.clientMessageId, item]));
    const outgoingMessageIds = new Set(messages
      .filter((message) => message.direction === "outgoing")
      .map((message) => message.clientMessageId));
    const shell = node("div", `conversation-shell${detailsOpen ? " has-details" : ""}`);
    const main = node("section", "conversation-main");
    const back = node("button", "back-button", iconAsset("arrow-left"));
    back.type = "button";
    localizedAttribute(back, "aria-label", localizedCopy("action.back", "返回"));
    back.addEventListener("click", () => navigate("inbox"));
    const detailToggle = node("button", "detail-toggle", "⋯");
    detailToggle.type = "button";
    localizedAttribute(detailToggle, "aria-label", localizedCopy("details.open", "会话设置"));
    localizedAttribute(detailToggle, "title", localizedCopy("details.open", "会话设置"));
    detailToggle.setAttribute("aria-expanded", String(detailsOpen && !detailsMessageId));
    detailToggle.setAttribute("aria-controls", "conversation-details");
    detailToggle.addEventListener("click", () => setDetailsOpen(!detailsOpen || Boolean(detailsMessageId), `thread:${thread.threadId}`));
    const readActions = [
      ...(thread.conversationKind === "instance" && hasWorkbenchCapability(snapshot, "messages.auto-read.manage")
        ? [autoReadButton(thread)] : []),
      ...(canBulkMarkRead() && thread.unreadCount > 0 ? [bulkMarkReadButton(thread.threadId)] : []),
    ];
    const header = node("header", "conversation-header", [
      back,
      node("span", "thread-avatar", initials(thread.displayName)),
      node("div", "conversation-heading", [
        node("h2", "", thread.displayName),
        node("p", "", conversationAssistStatus(contact, thread)),
      ]),
      ...(readActions.length ? [node("div", "conversation-read-actions", readActions)] : []),
      detailToggle,
    ]);
    const messageRoot = node("div", "messages");
    const newerControls = [];
    messageRoot.dataset.threadId = thread.threadId;
    const newLocalBubble = previews.some((preview) => ![...(previousMessages?.querySelectorAll(".message") || [])]
      .some((item) => item.dataset.clientMessageId === preview.clientMessageId));
    // Consecutive renders may replace this node before its scroll runs. Carry
    // the pending target forward, including an empty view awaiting its data.
    const scrollTarget = newLocalBubble || !previousMessages || previousMessages.dataset.threadId !== thread.threadId
      ? "latest" : previousMessages.dataset.scrollTarget ?? String(previousScrollTop);
    messageRoot.dataset.scrollTarget = scrollTarget;
    queueMicrotask(() => {
      if (document.querySelector(".messages") !== messageRoot) return;
      messageRoot.scrollTop = scrollTarget === "latest" ? messageRoot.scrollHeight : Number(scrollTarget);
      if (messagesReady) delete messageRoot.dataset.scrollTarget;
    });
    const messagePagePending = loadingMessagePage?.threadId === thread.threadId;
    if (snapshot.messages.threadId === thread.threadId && snapshot.messages.nextCursor && messages.length >= 200) {
      messageRoot.append(node("p", "message-history-limit", localizedCopy("pagination.historyLimit", "已显示 200 条消息。更早的消息可以让 AI 帮你查。")));
    } else if (snapshot.messages.threadId === thread.threadId && snapshot.messages.nextCursor) {
      const more = node("button", "load-more-button load-more-messages", messagePagePending
        ? localizedCopy("pagination.loading", "正在加载…")
        : localizedCopy("pagination.messages", "加载更早消息"));
      more.type = "button";
      more.disabled = messagePagePending;
      more.dataset.action = "load-more-messages";
      more.addEventListener("click", () => void loadMoreMessages(thread.threadId));
      messageRoot.append(more);
    }
    if (snapshot.messages.threadId === thread.threadId && snapshot.messages.previousCursor) {
      const newer = node("button", "load-more-button load-newer-messages", messagePagePending
        ? localizedCopy("pagination.loading", "正在加载…") : localizedCopy("pagination.newer", "加载较新消息"));
      newer.type = "button";
      newer.disabled = messagePagePending;
      newer.dataset.action = "load-newer-messages";
      newer.addEventListener("click", () => void loadMoreMessages(thread.threadId, "newer"));
      const latest = node("button", "load-more-button jump-latest-messages", messagePagePending
        ? localizedCopy("pagination.loading", "正在加载…") : localizedCopy("pagination.latest", "回到最新"));
      latest.type = "button";
      latest.disabled = messagePagePending;
      latest.dataset.action = "jump-latest-messages";
      latest.addEventListener("click", () => void jumpToLatestMessages(thread.threadId));
      newerControls.push(newer, latest);
    }
    const timeline = messages.map((message, index) => ({ kind: "message", value: message, index, at: message.createdAt }));
    const standalone = [
      ...outbox
        // The outbox spans all history. It may decorate the current page, but
        // must not inject an old failed/unknown message into the latest page.
        .filter((item) => messagesReady && !outgoingMessageIds.has(item.clientMessageId)
          && (!messages.length || String(item.createdAt) >= String(messages[0].createdAt))
          && (!snapshot.messages.previousCursor || !messages.length
            || String(item.createdAt) <= String(messages.at(-1).createdAt)))
        .map((item, index) => ({ kind: "outbox", value: item, index, at: item.createdAt })),
      ...previews
        .filter((preview) => !outgoingMessageIds.has(preview.clientMessageId) && !outboxByMessageId.has(preview.clientMessageId))
        .map((preview, index) => ({ kind: "preview", value: preview, index, at: preview.createdAt })),
    ].sort((left, right) => String(left.at).localeCompare(String(right.at)) || left.index - right.index);
    for (const entry of standalone) {
      const index = timeline.findIndex((current) => String(current.at) > String(entry.at));
      timeline.splice(index < 0 ? timeline.length : index, 0, entry);
    }
    if (timeline.length > 200) timeline.splice(0, timeline.length - 200);
    const canCompose = canSendToThread(thread);
    if (!timeline.length) {
      messageRoot.append(node("div", "empty-list", [
        node("strong", "", localizedCopy("conversation.noMessages.title", "暂无本机消息")),
        node("span", "", canCompose
          ? localizedCopy("conversation.noMessages.body", "在下方输入消息，开始聊天。")
          : localizedCopy("conversation.noMessages.readonly", "当前会话没有可显示的本机记录。")),
      ]));
    } else {
      let previousLocalDate = null;
      for (const entry of timeline) {
        const localDate = localizedDateParts(entry.at);
        if (localDate.key !== previousLocalDate) {
          const divider = node("div", "day-divider", localDate.label);
          const time = node("time", "", localDate.label);
          time.dateTime = localDate.key;
          divider.replaceChildren(time);
          messageRoot.append(divider);
          previousLocalDate = localDate.key;
        }
        if (entry.kind === "outbox") {
          messageRoot.append(renderStandaloneOutboxMessage(thread, entry.value, entry.index));
          continue;
        }
        if (entry.kind === "preview") {
          messageRoot.append(renderSendPreview(entry.value));
          continue;
        }
        const message = entry.value;
        const rendered = renderMessage(thread, message);
        const delivery = message.direction === "outgoing" ? outboxByMessageId.get(message.clientMessageId) : null;
        if (delivery) {
          rendered.append(renderInlineOutboxStatus(delivery, `inline-${message.localMessageId}`));
        } else if (message.direction === "outgoing" && ["delivery_state_unknown", "delivery_state_unconfirmed"].includes(message.status)) {
          rendered.append(renderInlineOutboxStatus(message, `inline-${message.localMessageId}`));
        } else if (message.direction === "outgoing" && (isSentStatus(message.status)
          || previews.some((preview) => preview.clientMessageId === message.clientMessageId && preview.phase === "ok"))) {
          rendered.append(renderSentStatus(message.status));
        }
        messageRoot.append(rendered);
      }
    }
    messageRoot.append(...newerControls);
    const bulkReadState = actionStateByKey.get(`messages:mark-all:${thread.threadId}`);
    if (["failed", "unknown"].includes(bulkReadState?.phase)) messageRoot.append(actionStatus(bulkReadState));
    main.append(header, messageRoot);
    if (canCompose) main.append(renderComposer(thread));
    else main.append(node("p", "conversation-readonly", conversationRouteLabel(thread)));
    shell.append(main);
    if (!detailsOpen) {
      root.replaceChildren(shell);
      return;
    }
    const detailMessage = messages.find((message) => message.localMessageId === detailsMessageId);
    const historyState = actionStateByKey.get(`local-history:${thread.archived === true ? "restore" : "hide"}:${thread.threadId}`);
    const close = node("button", "details-close", iconAsset("close"));
    close.type = "button";
    localizedAttribute(close, "aria-label", localizedCopy("details.close", "关闭详情"));
    close.addEventListener("click", () => setDetailsOpen(false, `thread:${thread.threadId}`));
    const details = node("aside", "details-pane", [
      node("header", "details-header", [node("h3", "", detailMessage ? localizedCopy("message.details", "消息详情") : localizedCopy("details.title", "会话详情")), close]),
      node("div", "details-body", detailMessage ? [renderMessageDetails(detailMessage)] : [
        node("div", "identity-card", [
          node("span", "thread-avatar", initials(thread.displayName)),
          node("div", "", [node("strong", "", thread.displayName), node("span", "", thread.peerHelloLynkId)]),
        ]),
        node("section", "detail-section", [
          node("h4", "", localizedCopy("details.aiRoute", "会话 AI")),
          node("p", "conversation-route-details", conversationRouteLabel(thread)),
        ]),
        node("section", "detail-section", [
          node("h4", "", localizedCopy("details.authorization", "授权状态")),
          renderThreadAuthorization(thread),
        ]),
        ...(thread.conversationKind === "instance" && hasWorkbenchCapability(snapshot, "messages.auto-read.manage")
          ? [node("section", "detail-section conversation-auto-read-details", [
            node("h4", "", autoReadStateLabel(thread)),
            node("p", "", localizedCopy("message.autoReadHint", "开启后，本对话的消息由 AI 读取时自动标为你已读；关闭后仍由你手动标记。已有未读可用“全部已读”处理。")),
          ])] : []),
        node("section", "detail-section", [
          node("h4", "", localizedCopy("details.localBoundary", "数据位置")),
          detailRow(localizedCopy("details.messages", "消息与历史"), localizedCopy("details.onDevice", "保存在本机")),
          detailRow(localizedCopy("details.cloud", "云端消息正文"), localizedCopy("details.none", "不保存")),
        ]),
        node("section", "detail-section thread-history-actions", [
          ...threadLocalHistoryControls(thread),
          ...(["failed", "unknown", "pending"].includes(historyState?.phase)
            ? [actionStatus(historyState)] : []),
        ]),
      ]),
    ]);
    details.id = "conversation-details";
    shell.append(details);
    root.replaceChildren(shell);
    syncRenderedDetailIsolation(main, details);
  }

  function conversationAssistStatus(contact, thread) {
    if (thread.conversationKind !== "instance" || thread.localDelegateId !== snapshot.subject.delegateId) return conversationRouteLabel(thread);
    const peer = currentInstanceForThread(thread)?.displayName || thread.delegateLabel || localizedCopy("instances.unavailable", "名称未记录的 AI");
    const assistance = currentInstanceForThread(thread)?.autonomousSendAuthorized
      ? localizedCopy("authorization.activeShort", "AI 自主收发已开启")
      : localizedCopy("authorization.humanShort", "发送由你确认");
    return localizedParts(["", peer, " · ", assistance, ""]);
  }

  function renderMessage(thread, message) {
    const outgoing = message.direction === "outgoing";
    const missing = localizedCopy("message.provenanceMissing", "历史未记录");
    const delegate = message.senderDelegateId || missing;
    const senderLabel = outgoing
      ? (message.senderDelegateId === snapshot.subject.delegateId ? snapshot.subject.delegateLabel : null)
      : (message.senderDelegateId === thread.peerDelegateId ? thread.delegateLabel : null);
    const sender = localizedParts(["", outgoing ? localizedCopy("message.you", "你") : thread.displayName, " · ", senderLabel || delegate, ""]);
    const more = messageActionButton("message-details", "⋯", message.localMessageId,
      () => setDetailsOpen(true, `thread:${thread.threadId}`, message.localMessageId), "message-details-button");
    const messageLabel = localizedParts(["", sender, " · ", localizedTime(message.createdAt), ""]);
    localizedAttribute(more, "aria-label", localizedParts(["", localizedCopy("message.details", "消息详情"), " · ", messageLabel, ""]));
    localizedAttribute(more, "title", localizedCopy("message.details", "消息详情"));
    more.setAttribute("aria-expanded", String(detailsOpen && detailsMessageId === message.localMessageId));
    more.setAttribute("aria-controls", "conversation-details");
    more.id = `message-details-${message.localMessageId}`;
    const actions = node("div", "message-actions");
    const meta = node("div", "message-meta", messageLabel);
    localizedAttribute(meta, "title", messageLabel);
    const heading = node("div", "message-heading", [meta, actions, more]);
    if (message.automaticDeliveryState === "expired")
      heading.append(node("span", "status-pill", localizedCopy("message.expired", "已过期 · AI 不再自动处理")));
    const article = node("article", `message${outgoing ? " is-outgoing" : ""}`, [
      heading,
      node("div", "message-bubble", message.text),
    ]);
    article.dataset.recordId = message.localMessageId;
    article.dataset.clientMessageId = message.clientMessageId;
    if (outgoing) {
      const stateKey = `message:delete-sent:${message.localMessageId}`;
      const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
      if (canExecute("messages.delete-sent") && isDeliveredStatus(message.status)
        && message.senderPrincipalId === snapshot.subject.principalId
        && message.senderDelegateId === snapshot.subject.delegateId
        && thread.localDelegateId === snapshot.subject.delegateId) {
        const contextKey = lifecycleSnapshotKey();
        const button = messageActionButton("delete-sent-message", localizedCopy("message.deleteSent", "删除本机消息"), message.localMessageId, () => {
          if (contextKey !== lifecycleSnapshotKey()) return;
          void runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteSent,
            { localMessageIds: [message.localMessageId] }, { lockUnknown: true });
        }, "danger-button");
        button.disabled = ["pending", "unknown"].includes(state.phase);
        localizedAttribute(button, "aria-label", localizedParts(["", localizedCopy("message.deleteSent", "删除本机消息"), " · ", messageLabel, ""]));
        actions.append(button);
      }
      if (state.phase !== "idle") article.append(actionStatus(state));
      return article;
    }
    const operation = message.unread ? "mark-read" : "delete-read";
    const stateKey = `message:${operation}:${message.localMessageId}`;
    const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
    let button = null;
    if (state.phase !== "unknown" && message.unread && canExecute("messages.mark-read")) {
      button = messageActionButton(
        "mark-message-read",
        state.phase === "pending" ? localizedCopy("action.working", "正在请求 Host…") : localizedCopy("message.markRead", "标为已读"),
        message.localMessageId,
        () => void markMessageRead(thread, message),
      );
    } else if (state.phase !== "unknown" && !message.unread && canExecute("messages.delete-read")) {
      button = messageActionButton(
        "delete-read-message",
        state.phase === "pending" ? localizedCopy("action.working", "正在请求 Host…") : localizedCopy("message.deleteRead", "删除本机已读消息"),
        message.localMessageId,
        () => void runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteRead, { localMessageIds: [message.localMessageId] }, { lockUnknown: true, capability: "messages.delete-read" }),
        "danger-button",
      );
    }
    if (button) {
      button.disabled = state.phase === "pending";
      localizedAttribute(button, "aria-label", localizedParts(["", localeBindings.textRecipe(button), " · ", messageLabel, ""]));
      actions.append(button);
      if (state.phase !== "idle") article.append(actionStatus(state));
    } else if (state.phase !== "idle") {
      article.append(actionStatus(state));
    }
    return article;
  }

  function renderMessageDetails(message) {
    const missing = localizedCopy("message.provenanceMissing", "历史未记录");
    return node("section", "message-provenance", [
      node("p", "", localizedCopy("message.detailsHint", "这条消息的发送来源和授权记录。")),
      detailRow(localizedCopy("message.principal", "所属账号"), message.senderPrincipalId || missing),
      detailRow(localizedCopy("message.delegate", "实际 AI"), message.senderDelegateId || missing),
      detailRow(localizedCopy("message.intent", "发起方式"), message.intentSource || missing),
      detailRow(localizedCopy("message.scope", "授权范围"), message.authorizationScope || missing),
    ]);
  }

  function threadLocalHistoryControls(thread, placement = "details") {
    if (!canExecute("threads.manage-local") || thread.conversationKind !== "instance"
      || thread.localDelegateId !== snapshot.subject.delegateId) return [];
    const snapshotKey = lifecycleSnapshotKey();
    return [thread.archived === true ? "restore" : "hide", "clear", "delete"].map((kind) => {
      const state = actionStateByKey.get(`local-history:${kind}:${thread.threadId}`);
      const button = contactActionButton(`${kind}-local-thread`, localizedCopy(`history.${kind}`, kind === "hide" ? "归档" : kind === "restore" ? "移回聊天" : "清理本机记录"), () => {
        if (snapshotKey !== lifecycleSnapshotKey() || !canExecute("threads.manage-local")) return;
        if (["clear", "delete"].includes(kind)) openLocalHistoryConfirmation(thread, snapshotKey,
          placement === "list" ? `thread-more-${thread.threadId}-summary` : button.id, kind);
        else void runThreadLocalHistory(kind, thread.threadId, snapshotKey);
      }, thread.threadId, `contact-more-action${["clear", "delete"].includes(kind) ? " danger-button" : ""}`);
      button.disabled = ["pending", "unknown"].includes(state?.phase);
      button.id = `thread-${kind}-${placement}-${thread.threadId}`;
      return button;
    });
  }

  async function runThreadLocalHistory(kind, threadId, snapshotKey) {
    if (snapshotKey !== lifecycleSnapshotKey()) return;
    const epoch = accountViewEpoch;
    const navigation = navigationSequence;
    const result = await runAction(`local-history:${kind}:${threadId}`,
      kind === "hide" ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.hideThread
        : kind === "restore" ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread
          : kind === "delete" ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteThread
          : kind === "deleteArchived" ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteArchivedThreads
          : kind === "resendReply" ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply
          : HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearThread,
      kind === "resendReply" ? { clientMessageId: threadId } : kind === "deleteArchived" ? {} : kind === "clear" && snapshot?.localHistory ? { threadId, before: localHistoryConfirmation?.before ?? null } : { threadId },
      { lockUnknown: true });
    if (epoch !== accountViewEpoch) return;
    const focusRemainingThread = result?.ok && ["hide", "restore", "delete", "deleteArchived"].includes(kind) && navigation === navigationSequence;
    if (focusRemainingThread && (location.hash === `#/messages/thread/${encodeURIComponent(threadId)}` || kind === "deleteArchived")) {
      // Replace the removed selection synchronously so a later hashchange does
      // not replace the list node after keyboard focus has been restored.
      replaceLocationHash("#/messages");
      applyLocation();
    }
    render();
    if (["hide", "restore"].includes(kind) && detailsOpen && (result === null || result?.ok === false)) {
      queueMicrotask(() => document.querySelector(".details-pane .thread-history-actions .action-status")
        ?.scrollIntoView({ block: "nearest" }));
    }
    if (focusRemainingThread) {
      queueMicrotask(() => {
        const manager = $("history-manage");
        (document.querySelector(".thread-card") || (manager && !manager.hidden ? manager : null)
          || document.querySelector(".filter-button"))?.focus({ preventScroll: true });
      });
    }
  }

  function openLocalHistoryConfirmation(thread, snapshotKey, returnFocusId, kind = "clear") {
    const state = actionStateByKey.get(`local-history:${kind}:${thread.threadId}`);
    if (["pending", "unknown"].includes(state?.phase)) return;
    localHistoryConfirmation = { kind, threadId: thread.threadId, snapshotKey, returnFocusId, submitted: false,
      range: "all", before: null, pending: false };
    renderLocalHistoryDialog();
    queueMicrotask(() => $("local-history-cancel")?.focus({ preventScroll: true }));
    if (kind === "clear" && snapshot?.localHistory) void requestHistorySelection(localHistoryConfirmation);
  }

  function beforeForHistoryRange(range, dateValue = "") {
    if (range === "all") return null;
    if (range === "date") {
      const value = new Date(`${dateValue}T00:00:00`);
      return Number.isFinite(value.getTime()) ? value.toISOString() : undefined;
    }
    const days = { day: 1, week: 7, month: 30 }[range];
    return days ? new Date(Date.now() - days * 86400000).toISOString() : undefined;
  }

  async function requestHistorySelection(context) {
    if (!snapshot?.localHistory || context.kind !== "clear" || context !== localHistoryConfirmation || context.before === undefined) return;
    const selectionSeq = context.selectionSeq = (context.selectionSeq || 0) + 1;
    context.pending = true;
    renderLocalHistoryDialog();
    await load({ threadId: context.threadId, threadCursor: threadPageCursorById.get(context.threadId) ?? null,
      historyBefore: context.before, quiet: true, append: "selection" });
    if (context !== localHistoryConfirmation || context.selectionSeq !== selectionSeq) return;
    context.pending = false;
    renderLocalHistoryDialog();
  }

  function closeLocalHistoryConfirmation() {
    if (!localHistoryConfirmation) return;
    const previous = localHistoryConfirmation;
    if (actionStateByKey.get(`local-history:${previous.kind}:${previous.threadId}`)?.phase === "pending") return;
    localHistoryConfirmation = null;
    renderLocalHistoryDialog();
    queueMicrotask(() => (document.getElementById(previous.returnFocusId) || document.querySelector(".detail-toggle") || $("list-content"))?.focus({ preventScroll: true }));
  }

  function renderLocalHistoryDialog() {
    const layer = $("local-history-layer");
    if (!layer) return;
    layer.hidden = !localHistoryConfirmation;
    setElementIsolation($("workbench"), Boolean(localHistoryConfirmation) || globalComposer.open || $("account-disconnect-layer")?.hidden === false);
    if (!localHistoryConfirmation) return;
    const context = localHistoryConfirmation;
    const deleting = context.kind === "delete" || context.kind === "deleteArchived";
    const resending = context.kind === "resendReply";
    const state = context.submitted ? actionStateByKey.get(`local-history:${context.kind}:${context.threadId}`) : null;
    const stale = !snapshot || context.snapshotKey !== lifecycleSnapshotKey();
    $("local-history-title").textContent = copy("history.clearTitle", "清空这段会话的本机记录？");
    $("local-history-copy").textContent = copy("history.clearHint", "删除本机已读来信和已发送消息，不能恢复。未读来信、未交付和处理中的记录会保留。联系人、对方及其他电脑的记录不受影响。");
    if (deleting) {
      $("local-history-title").textContent = copy(context.kind === "deleteArchived" ? "history.deleteArchivedTitle" : "history.deleteTitle", "删除聊天？");
      $("local-history-copy").textContent = copy("history.deleteHint", "删除本机 HelloLynk 聊天，包括未读和未完成任务的消息，不能恢复。不会停止其他客户端已开始的任务。联系人、授权及其他客户端的记录保留。");
    }
    if (resending) {
      $("local-history-title").textContent = copy("outbox.resendTitle", "允许新建对话重新发送？");
      $("local-history-copy").textContent = copy("outbox.resendHint", "只将已保存的这条回复作为新消息发送给原接收方，不会重新执行任务。");
    }
    const status = $("local-history-status");
    status.replaceChildren();
    const ranged = context.kind === "clear" && Boolean(snapshot?.localHistory);
    const rangeLabel = $("local-history-range-label"), range = $("local-history-range");
    const dateLabel = $("local-history-date-label"), date = $("local-history-date");
    if (rangeLabel && range && dateLabel && date) {
      rangeLabel.hidden = range.hidden = !ranged;
      dateLabel.hidden = date.hidden = !ranged || context.range !== "date";
      rangeLabel.textContent = copy("history.range", "清理范围");
      dateLabel.textContent = copy("history.date", "早于日期");
    }
    if (ranged && range) {
      const choices = [["all", "history.rangeAll", "全部"], ["day", "history.rangeDay", "一天前"],
        ["week", "history.rangeWeek", "7 天前"], ["month", "history.rangeMonth", "30 天前"],
        ["date", "history.rangeDate", "指定日期前"]];
      range.replaceChildren(...choices.map(([value, key, fallback]) => {
        const option = node("option", "", copy(key, fallback)); option.value = value; return option;
      }));
      range.value = context.range;
    }
    const selection = snapshot?.localHistory?.selection;
    const matchingSelection = selection?.threadId === context.threadId && selection.before === context.before ? selection : null;
    const estimate = $("local-history-estimate");
    if (estimate) { estimate.hidden = !ranged;
    estimate.textContent = !ranged ? "" : context.pending ? copy("history.counting", "正在统计…")
      : matchingSelection ? copy("history.estimate", "可清理 {count} 条，正文约 {size}；保留未读 {unread} 条、未交付 {outgoing} 条。", {
        count: matchingSelection.deletableCount, size: formatHistoryBytes(matchingSelection.deletableBytes),
        unread: matchingSelection.retainedUnreadCount, outgoing: matchingSelection.retainedOutgoingCount,
      }) : copy("history.countUnavailable", "统计暂不可用，请刷新后重试。"); }
    if (state?.phase === "ok") {
      status.textContent = resending ? copy(`outbox.resend.${state.result?.status || "unknown"}`, "补发结果未知，请查看新消息的状态，不要重复发送。")
        : deleting ? copy("history.deleted", "聊天已删除。") : copy("history.cleared", "已清理 {count} 条；保留未读 {unread} 条、未交付 {outgoing} 条。", {
        count: state.result?.deletedCount ?? 0,
        unread: state.result?.retainedUnreadCount ?? 0,
        outgoing: state.result?.retainedOutgoingCount ?? 0,
      });
    } else if (state) status.append(actionStatus(state));
    else if (stale) status.textContent = copy("history.changed", "会话内容已更新，请关闭后重新打开清空操作。");
    $("local-history-cancel").textContent = copy(state?.phase === "ok" ? "action.close" : "action.cancel", state?.phase === "ok" ? "关闭" : "取消");
    $("local-history-cancel").disabled = state?.phase === "pending";
    const confirm = $("local-history-confirm");
    confirm.textContent = resending ? copy("outbox.resendConfirm", "允许，发送已有回复") : deleting ? copy("history.delete", "删除聊天") : copy("history.clear", "清空本机记录");
    confirm.hidden = state?.phase === "ok";
    confirm.disabled = stale || context.submitted || context.pending || context.before === undefined
      || (ranged && (!matchingSelection || matchingSelection.deletableCount === 0))
      || !(resending ? canResendDeletedReply(snapshot?.outbox.find(item => item.clientMessageId === context.threadId)) : canExecute("threads.manage-local"));
  }

  function messageActionButton(action, label, recordId, handler, extraClass = "") {
    const button = node("button", `message-action-button ${extraClass}`.trim(), label);
    button.type = "button";
    button.dataset.action = action;
    button.dataset.recordId = recordId;
    button.addEventListener("click", handler);
    return button;
  }

  function canBulkMarkRead() {
    return Number.isSafeInteger(snapshot?.inboxReadBoundary) && snapshot.inboxReadBoundary >= 0
      && hasWorkbenchCapability(snapshot, "messages.mark-all-read");
  }
  function autoReadStateLabel(thread) {
    const enabled = thread.autoReadAfterAi === true;
    return localizedParts(["", localizedCopy("message.autoRead", "AI 读后自动已读"), "", localeBindings.localeText("：", ": "), "", localizedCopy(enabled ? "action.on" : "action.off", enabled ? "开" : "关"), ""]);
  }

  function autoReadButton(thread) {
    const enabled = thread.autoReadAfterAi === true;
    const stateKey = `messages:auto-read:${thread.threadId}`;
    const state = actionStateByKey.get(stateKey);
    const stateLabel = autoReadStateLabel(thread);
    const button = node("button", "compact-action auto-read-toggle", stateLabel);
    button.type = "button";
    button.dataset.action = "set-auto-read";
    button.dataset.threadId = thread.threadId;
    button.setAttribute("role", "switch");
    button.setAttribute("aria-checked", String(enabled));
    localizedAttribute(button, "aria-label", stateLabel);
    localizedAttribute(button, "title", localizedCopy("message.autoReadHint", "开启后，本对话的消息由 AI 读取时自动标为你已读；关闭后仍由你手动标记。已有未读可用“全部已读”处理。"));
    button.disabled = state?.phase === "pending" || !canExecute("messages.auto-read.manage");
    button.setAttribute("aria-busy", String(state?.phase === "pending"));
    button.addEventListener("click", () => {
      if (!canExecute("messages.auto-read.manage")) return;
      void runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead,
        { threadId: thread.threadId, enabled: !enabled }, { lockUnknown: false });
    });
    return node("div", "conversation-auto-read", [button,
      ...(["failed", "unknown"].includes(state?.phase) ? [actionStatus(state)] : [])]);
  }

  function bulkMarkReadButton(threadId = null) {
    const stateKey = `messages:mark-all:${threadId ?? "all"}`;
    const state = actionStateByKey.get(stateKey);
    const pending = state?.phase === "pending";
    const button = node("button", "compact-action mark-all-read", pending
      ? localizedCopy("message.markingRead", "正在标记…")
      : threadId === null ? localizedCopy("message.markAllRead", "全部标为已读") : localizedCopy("message.markThreadRead", "全部已读"));
    button.type = "button";
    button.dataset.action = "mark-all-read";
    if (threadId !== null) button.dataset.threadId = threadId;
    localizedAttribute(button, "title", threadId === null ? localizedCopy("message.markAllReadHint", "将当前客户端的未读消息标为已读")
      : localizedCopy("message.markThreadReadHint", "将当前对话的未读消息标为已读"));
    button.setAttribute("aria-busy", String(pending));
    button.disabled = pending || !canExecute("messages.mark-all-read");
    button.addEventListener("click", () => {
      if (!canBulkMarkRead() || !canExecute("messages.mark-all-read")) return;
      // Capture a Host-issued arrival boundary, not a browser clock or just
      // the displayed page. A new human click is safe; there is no auto retry.
      void runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead,
        { threadId, beforeReceiptSeq: snapshot.inboxReadBoundary }, { lockUnknown: false });
    });
    return button;
  }

  function renderInboxReadActions(threads) {
    const root = $("inbox-read-actions");
    if (!root) return;
    const state = actionStateByKey.get("messages:mark-all:all");
    const feedback = ["failed", "unknown", "pending"].includes(state?.phase);
    root.hidden = view.section !== "inbox" || view.filter !== "unread" || !canBulkMarkRead()
      || (!feedback && !threads.some(thread => thread.unreadCount > 0));
    root.replaceChildren(...(root.hidden ? [] : [bulkMarkReadButton(), ...(feedback ? [actionStatus(state)] : [])]));
  }

  function markReadFingerprint(thread, message) {
    return JSON.stringify([
      thread.threadId, thread.conversationKind, thread.localDelegateId, thread.peerPrincipalId,
      thread.peerHelloLynkId, thread.peerDelegateId, message.localMessageId, message.clientMessageId,
      message.threadId, message.direction, message.senderPrincipalId, message.senderDelegateId,
      message.intentSource, message.authorizationScope, message.createdAt, message.text,
    ]);
  }

  function currentMarkReadTarget(operation) {
    if (stopped || operation.epoch !== accountViewEpoch || operation.navigation !== navigationSequence
      || operation.authorityFailure !== authorityFailureSequence
      || markReadOperationById.get(operation.localMessageId) !== operation
      || !["ready", "empty"].includes(view.phase) || authorityReloadRequired || !snapshot
      || snapshot.hostGeneration !== operation.hostGeneration || snapshot.source.clientId !== operation.sourceClientId
      || snapshot.source.transport !== operation.sourceTransport
      || snapshot.source.mode !== "neutral-host" || snapshot.subject.principalId !== operation.principalId
      || snapshot.subject.delegateId !== operation.delegateId || snapshot.subject.hellolynkId !== operation.ownerHelloLynkId
      || view.selectedThreadId !== operation.threadId || snapshot.messages.threadId !== operation.threadId) return null;
    const thread = snapshot.threads.items.find((item) => item.threadId === operation.threadId);
    const message = snapshot.messages.items.find((item) => item.localMessageId === operation.localMessageId);
    return thread && message && markReadFingerprint(thread, message) === operation.fingerprint ? message : null;
  }

  async function markMessageRead(thread, message) {
    if (!canExecute("messages.mark-read") || markReadOperationById.has(message.localMessageId)) return;
    const operation = {
      epoch: accountViewEpoch, navigation: navigationSequence, authorityFailure: authorityFailureSequence, hostGeneration: snapshot.hostGeneration,
      sourceClientId: snapshot.source.clientId, sourceTransport: snapshot.source.transport, principalId: snapshot.subject.principalId,
      delegateId: snapshot.subject.delegateId, ownerHelloLynkId: snapshot.subject.hellolynkId,
      threadId: thread.threadId, localMessageId: message.localMessageId,
      baselineRevision: snapshot.revision, fingerprint: markReadFingerprint(thread, message),
    };
    markReadOperationById.set(message.localMessageId, operation);
    const stateKey = `message:mark-read:${message.localMessageId}`;
    try {
      const current = currentMarkReadTarget(operation);
      if (!current?.unread || current.direction !== "incoming") return;
      await runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.markRead,
        { localMessageId: message.localMessageId }, { lockUnknown: true, capability: "messages.mark-read" });
      const refreshed = currentMarkReadTarget(operation);
      if (!refreshed || snapshot.revision === operation.baselineRevision) return;
      if (!refreshed.unread) {
        actionStateByKey.set(stateKey, { phase: "ok", code: null });
        render();
        return;
      }
    } finally {
      if (markReadOperationById.get(message.localMessageId) === operation) markReadOperationById.delete(message.localMessageId);
    }
  }

  function renderStandaloneOutboxMessage(thread, item, index) {
    const article = node("article", "message is-outgoing standalone-outbox", [
      node("div", "message-bubble", item.text || localizedCopy("outbox.noText", "没有可显示的正文。")),
      renderInlineOutboxStatus(item, `standalone-${index}`),
    ]);
    article.dataset.recordId = item.clientMessageId;
    article.dataset.clientMessageId = item.clientMessageId;
    article.dataset.threadId = thread.threadId;
    return article;
  }

  function renderInlineOutboxStatus(item, index) {
    if (isSentStatus(item.status)) return renderSentStatus(item.status);
    if (!VISIBLE_OUTBOX_STATES.has(item.status)) {
      return sendPreviewByMessageId.get(item.clientMessageId)?.phase === "ok" ? renderSentStatus() : node("span", "");
    }
    const stateKey = `outbox:retry:${item.clientMessageId}`;
    const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
    const knownFailure = MANUAL_RETRY_OUTBOX_STATES.has(item.status) && state.phase !== "unknown";
    const row = node("div", `message-delivery-status${knownFailure ? " is-failed" : " is-unknown"}`);
    row.dataset.recordId = item.clientMessageId;
    row.id = `outbox-inline-${index}`;

    if (!knownFailure) {
      row.append(node("span", "", localizedCopy("outbox.inline.unknown", "发送结果尚未确认")));
      return row;
    }

    if (["reply_target_deleted", "reply_target_deleted_resent"].includes(item.errorCategory)) {
      row.append(node("span", "", localizedCopy("outbox.error.reply_target_deleted", "原对话已删除，回复未送达。")));
      if (item.errorCategory === "reply_target_deleted_resent") row.append(node("span", "", localizedCopy("outbox.resendCreated", "已另建一条补发消息，请查看它的发送状态。")));
      else {
        const resend = messageActionButton("resend-deleted-reply", localizedCopy("outbox.resend", "新建对话补发"), item.clientMessageId, () => {
          const current = snapshot.outbox.find(candidate => candidate.clientMessageId === item.clientMessageId);
          if (!canResendDeletedReply(current)) return;
          openLocalHistoryConfirmation({ threadId: current.clientMessageId }, lifecycleSnapshotKey(), resend.id, "resendReply");
        });
        resend.id = `resend-deleted-reply-${item.clientMessageId}`;
        resend.disabled = !canResendDeletedReply(item);
        row.append(resend);
      }
      return row;
    }
    const failureDetail = ["connectivity", "encryption", "message_time", "device_identity_changed", "external_contact_disabled", "authorization", "rate_limit", "validation"].includes(item.errorCategory)
      ? localizedCopy(`outbox.error.${item.errorCategory}`, "") : "";
    row.append(node("span", "", localizedParts([localizedCopy("outbox.inline.failed", "发送失败"), localeBindings.optionalPrefix(failureDetail, " · ")])));
    if (canRetryOutbox(item)) {
      row.append(node("span", "", " · "));
      const button = messageActionButton(
        "retry-outbox-message",
        state.refreshing ? localizedCopy("action.status.refreshing", "正在更新状态…")
          : state.phase === "pending" ? localizedCopy("outbox.retrying", "正在重试…")
          : localizedCopy("outbox.retry", "重试"),
        item.clientMessageId,
        () => {
          const current = snapshot.outbox.find((candidate) => candidate.clientMessageId === item.clientMessageId);
          if (!current || current.threadId !== item.threadId || current.localDelegateId !== item.localDelegateId
            || current.recipientDelegateId !== item.recipientDelegateId || !canRetryOutbox(current)) return;
          void runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestRetry, { clientMessageId: current.clientMessageId }, { lockUnknown: true, capability: "outbox.request-retry" });
        },
      );
      button.setAttribute("aria-describedby", row.id);
      button.disabled = state.phase === "pending" || actionOperationByKey.has(stateKey);
      row.append(button);
    } else {
      row.append(node("span", "", localizedParts([" · ", localizedCopy("outbox.inline.noRetryAvailable", "当前连接暂不支持重试"), ""])));
    }
    return row;
  }

  function canResendDeletedReply(item) {
    return item?.errorCategory === "reply_target_deleted" && item.status === "failed_permanent"
      && item.localDelegateId === snapshot.subject.delegateId && Boolean(item.recipientDelegateId)
      && !["pending", "unknown", "ok"].includes(actionStateByKey.get(`local-history:resendReply:${item.clientMessageId}`)?.phase)
      && canExecute("outbox.request-retry") && snapshot.threads.items.some(thread => thread.threadId === item.threadId
        && canSendToThread(thread, "outbox.request-retry") && thread.peerDelegateId === item.recipientDelegateId);
  }

  function canRetryOutbox(item) {
    return item.retryAllowed === true
      && item.localDelegateId === snapshot.subject.delegateId
      && Boolean(item.recipientDelegateId)
      && snapshot.threads.items.some((thread) => thread.threadId === item.threadId
        && canSendToThread(thread, "outbox.request-retry") && thread.peerDelegateId === item.recipientDelegateId)
      && MANUAL_RETRY_OUTBOX_STATES.has(item.status)
      && canExecute("outbox.request-retry");
  }

  function canSendToThread(thread, capability = "messages.request-send") {
    const contact = currentContactForThread(thread);
    return canExecute(capability) && thread?.conversationKind === "instance"
      && snapshot.threads.items.some((current) => current.threadId === thread.threadId
        && current.conversationKind === "instance" && current.localDelegateId === thread.localDelegateId
        && current.peerDelegateId === thread.peerDelegateId && current.peerPrincipalId === thread.peerPrincipalId)
      && thread.localDelegateId === snapshot.subject.delegateId
      && thread.peerPrincipalId === contact?.principalId
      && Boolean(currentInstanceForThread(thread)) && Boolean(contact?.hellolynkId);
  }

  function currentInstanceForThread(thread) {
    return currentContactForThread(thread)?.instances.find((item) => item.delegateId === thread.peerDelegateId) ?? null;
  }

  // The same switch as the contact page, where people read the conversation.
  function renderThreadAuthorization(thread) {
    const contact = currentContactForThread(thread);
    const instance = currentInstanceForThread(thread);
    const row = node("div", "detail-authorization-row", [statusPill(instance?.autonomousSendAuthorized ? "active" : "neutral",
      instance?.autonomousSendAuthorized ? localizedCopy("authorization.active", "AI 自主收发已授权") : localizedCopy("authorization.human", "发送由你确认"))]);
    // Read-only history (old or another local AI's) shows the state without the switch.
    if (!contact || !instance || thread.conversationKind !== "instance" || thread.localDelegateId !== snapshot.subject.delegateId) return row;
    const state = actionStateByKey.get(`authorization:${contact.contactId}:${instance.delegateId}`) || { phase: "idle", code: null };
    if (canManageAuthorization() && state.phase !== "unknown") row.append(renderAuthorizationButton(contact, state, instance));
    return node("div", "detail-authorization", [row,
      ...(state.phase === "idle" ? [] : [renderContactActionStatus(state, localizedCopy("contacts.permissionsSaved", "权限已更新"))])]);
  }

  function conversationRouteLabel(thread) {
    const peer = currentInstanceForThread(thread)?.displayName || thread.delegateLabel || localizedCopy("instances.unavailable", "名称未记录的 AI");
    const label = snapshot.subject.delegateLabel;
    const local = label && label !== snapshot.subject.delegateId ? label : localizedCopy("instances.current", "当前 AI");
    return localizedCopy("instances.route", "{local} → {peer}", { local, peer });
  }

  function canRequestGlobalSend() {
    return canPresentGlobalSend()
      && !authorityReloadRequired
      && ["ready", "empty"].includes(view.phase);
  }

  function canPresentGlobalSend() {
    return canExecute("messages.request-send") && snapshot.contacts.some((contact) => contact.principalId && contact.instances.length > 0);
  }

  function openGlobalComposerForContact(contact) {
    if (!contact || !canRequestGlobalSend()) return;
    if (["pending", "unknown"].includes(globalComposer.phase)) {
      globalComposer = { ...globalComposer, open: true };
      renderGlobalComposer();
      return;
    }
    const savedInstances = snapshot.contacts.find((item) => item.contactId === contact.contactId)?.instances ?? [];
    globalComposer = {
      ...globalComposer,
      open: true,
      contactId: contact.contactId,
      recipientDelegateId: !globalComposer.draft.trim() && savedInstances.length === 1 ? savedInstances[0].delegateId : null,
      returnFocusId: contactMessageButtonId(contact.contactId),
      phase: "idle",
      code: null,
      sendOutcome: null,
      actionId: null,
    };
    renderGlobalComposer();
    queueMicrotask(() => $("global-message-draft")?.focus({ preventScroll: true }));
  }

  function setDetailsOpen(open, objectKey, messageId = null) {
    const requested = Boolean(open);
    if (requested && !objectKey) return;
    const returnMessageId = detailsMessageId;
    detailsOpen = requested;
    detailsMessageId = requested ? messageId : null;
    detailsObjectKey = requested ? objectKey : detailsObjectKey;
    render();
    if (requested) queueMicrotask(() => document.querySelector(".details-close")?.focus({ preventScroll: true }));
    else queueMicrotask(() => (document.getElementById(`message-details-${returnMessageId}`) || document.querySelector(".detail-toggle"))?.focus({ preventScroll: true }));
  }

  function syncRenderedDetailIsolation(main, details) {
    const mobile = matchMedia("(max-width: 700px)").matches;
    setElementIsolation(main, mobile && detailsOpen);
    setElementIsolation(details, false);
  }

  function closeGlobalComposer() {
    if (globalComposer.phase === "pending") return;
    globalComposer = { ...globalComposer, open: false };
    renderGlobalComposer();
    focusGlobalComposerReturn();
  }

  function focusGlobalComposerReturn() {
    queueMicrotask(() => document.getElementById(globalComposer.returnFocusId)?.focus({ preventScroll: true }));
  }

  function renderGlobalComposer() {
    const layer = $("global-compose-layer");
    if (!layer) return;
    layer.hidden = !globalComposer.open;
    setElementIsolation($("workbench"), globalComposer.open || Boolean(localHistoryConfirmation) || $("account-disconnect-layer")?.hidden === false);
    if (!globalComposer.open) {
      const draft = $("global-message-draft");
      if (draft && draft.value !== globalComposer.draft) draft.value = globalComposer.draft;
      const previewRoot = $("global-message-preview");
      if (previewRoot) { previewRoot.replaceChildren(); previewRoot.hidden = true; }
      if (draft) draft.hidden = false;
      return;
    }
    $("global-compose-title").textContent = copy("globalSend.title", "新消息");
    $("global-contact-label").textContent = copy("globalSend.contact", "联系人");
    $("global-instance-label").textContent = copy("instances.recipient", "对方 AI");
    $("global-local-ai").textContent = copy("instances.local", "我的当前 AI：{name}", { name: snapshot.subject.delegateLabel || copy("instances.current", "当前 AI") });
    $("global-message-label").textContent = copy("globalSend.message", "消息");
    const select = $("global-contact-select");
    const options = [];
    for (const contact of snapshot?.contacts ?? []) {
      const option = document.createElement("option");
      option.value = contact.contactId;
      option.textContent = `${contact.displayName} · ${contact.hellolynkId}`;
      options.push(option);
    }
    if (globalComposer.contactId != null
      && !(snapshot?.contacts ?? []).some((item) => item.contactId === globalComposer.contactId)) {
      const missing = document.createElement("option");
      missing.value = globalComposer.contactId;
      missing.textContent = copy("globalSend.contactMissing", "所选联系人已不在最新本机记录中");
      missing.disabled = true;
      options.unshift(missing);
    }
    select.replaceChildren(...options);
    select.value = globalComposer.contactId ?? "";
    const locked = globalComposer.phase === "pending" || globalComposer.phase === "unknown";
    select.disabled = locked;
    const draft = $("global-message-draft");
    if (draft.value !== globalComposer.draft) draft.value = globalComposer.draft;
    draft.placeholder = copy("globalSend.placeholder", "输入消息…");
    draft.disabled = locked;
    $("global-compose-cancel").textContent = copy("action.cancel", "取消");
    $("global-compose-cancel").disabled = globalComposer.phase === "pending";
    const submit = $("global-compose-submit");
    submit.textContent = copy("composer.send", "发送");
    const selectedContact = (snapshot?.contacts ?? [])
      .find((item) => item.contactId === globalComposer.contactId);
    const instanceSelect = $("global-instance-select");
    const placeholder = node("option", "", copy("instances.choose", "请选择对方 AI"));
    placeholder.value = "";
    instanceSelect.replaceChildren(placeholder, ...(selectedContact?.instances ?? []).map((instance) => {
      const clientLabel = String(clientTypeCopy(instance.clientType));
      const label = instance.displayName.toLowerCase() === clientLabel.toLowerCase()
        ? instance.displayName : `${instance.displayName} · ${clientLabel}`;
      const option = node("option", "", label);
      option.value = instance.delegateId;
      return option;
    }));
    instanceSelect.value = globalComposer.recipientDelegateId || "";
    instanceSelect.disabled = locked;
    const selectedInstance = selectedContact?.instances.find((item) => item.delegateId === globalComposer.recipientDelegateId);
    submit.disabled = locked || !selectedContact?.principalId || !selectedInstance || !globalComposer.draft.trim() || !canRequestGlobalSend();
    const status = $("global-compose-status");
    status.className = `composer-status is-${globalComposer.phase}`;
    status.textContent = sendStatusCopy(globalComposer);
    const preview = sendPreviewByMessageId.get(globalComposer.clientMessageId);
    const previewRoot = $("global-message-preview");
    if (previewRoot) {
      previewRoot.hidden = !locked || !preview || !isSendPreviewContextCurrent(preview);
      previewRoot.replaceChildren(...(!previewRoot.hidden ? [renderSendPreview(preview)] : []));
      draft.hidden = !previewRoot.hidden;
    }
  }

  async function submitGlobalMessage() {
    if (globalSubmitInFlight || globalComposer.phase === "pending" || globalComposer.phase === "unknown") return;
    if (!canRequestGlobalSend()) return;
    const contactId = globalComposer.contactId;
    const contact = snapshot.contacts.find((item) => item.contactId === contactId) || null;
    const text = globalComposer.draft;
    const recipientDelegateId = globalComposer.recipientDelegateId;
    if (!contact?.principalId || !contact.instances.some((item) => item.delegateId === recipientDelegateId) || !text.trim()) return;
    let thread = snapshot.threads.items.find((item) => item.conversationKind === "instance"
      && item.localDelegateId === snapshot.subject.delegateId && item.peerPrincipalId === contact.principalId
      && item.peerHelloLynkId === contact.hellolynkId && item.peerDelegateId === recipientDelegateId);
    if (thread && ["pending", "unknown"].includes(sendStateForThread(thread).phase)) {
      globalComposer = { ...globalComposer, open: false };
      renderGlobalComposer();
      navigate("inbox", thread.threadId);
      return;
    }
    // An independently composed thread draft must not be overwritten by the
    // contact modal. In that case keep this send and its backup in the modal.
    if (thread && draftsByThreadId.get(thread.threadId)?.trim()
      && draftsByThreadId.get(thread.threadId) !== text) thread = null;
    globalSubmitInFlight = true;
    if (thread) {
      draftsByThreadId.set(thread.threadId, text);
      globalComposer = { ...globalComposer, open: false, draft: "", phase: "idle", code: null };
    }
    const approval = createSendApproval(thread ? `thread:${thread.threadId}` : "global", {
      contactId, threadId: thread?.threadId, text, recipientDelegateId,
      recipientHelloLynkId: contact.hellolynkId, recipientPrincipalId: contact.principalId,
    });
    if (thread) navigate("inbox", thread.threadId);
    try {
      await requestSendApproval(approval, { recipientHelloLynkId: contact.hellolynkId, recipientDelegateId, text });
    } finally {
      if (approval.epoch === accountViewEpoch) globalSubmitInFlight = false;
      if (!stopped && approval.epoch === accountViewEpoch
        && approval.principalId === snapshot?.subject.principalId
        && approval.delegateId === snapshot?.subject.delegateId) { renderGlobalComposer(); refreshAfterChange(); }
    }
  }

  function trapGlobalComposerFocus(event) {
    if (!globalComposer.open || event.key !== "Tab") return false;
    const focusable = [
      $("global-contact-select"),
      $("global-instance-select"),
      $("global-message-draft"),
      $("global-compose-cancel"),
      $("global-compose-submit"),
    ].filter((element) => element && !element.hidden && !element.disabled);
    if (focusable.length === 0) return false;
    const first = focusable[0];
    const last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus({ preventScroll: true });
      return true;
    }
    if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus({ preventScroll: true });
      return true;
    }
    return false;
  }

  function isTextSelectionControl(element) {
    return element?.tagName === "TEXTAREA"
      || (element?.tagName === "INPUT" && ["text", "search", "tel", "url", "password"].includes(element.type));
  }

  function captureRefreshUiContext({ followLatest = false } = {}) {
    const activeElement = document.activeElement;
    const activeTextSelection = isTextSelectionControl(activeElement)
      && Number.isInteger(activeElement.selectionStart) && Number.isInteger(activeElement.selectionEnd)
      ? { value: activeElement.value, start: activeElement.selectionStart,
          end: activeElement.selectionEnd, direction: activeElement.selectionDirection }
      : null;
    const messages = document.querySelector(".messages");
    const preserveMessageScroll = messages && snapshot?.messages.threadId === messages.dataset.threadId
      && messages.dataset.scrollTarget !== "latest";
    return {
      readSequence: loadSequence,
      navigationSequence,
      activeElementId: typeof activeElement?.id === "string"
        ? activeElement.id
        : null,
      activeTextSelection,
      activeThreadId: document.activeElement?.matches?.("button.thread-card[data-thread-id]")
        ? document.activeElement.dataset.threadId
        : null,
      activeContactId: document.activeElement?.matches?.("button.contact-list-item[data-contact-id]")
        ? document.activeElement.dataset.contactId
        : null,
      listScrollTop: Number($("list-content")?.scrollTop) || 0,
      messageThreadId: preserveMessageScroll ? messages.dataset.threadId : null,
      messageScrollTop: Number(messages?.scrollTop) || 0,
      messageAnchor: preserveMessageScroll ? captureMessageScrollAnchor(messages.dataset.threadId) : null,
      followLatest: followLatest && preserveMessageScroll && !snapshot.messages.previousCursor
        && messages.scrollHeight - messages.scrollTop - messages.clientHeight < 2,
    };
  }

  function restoreRefreshUiContext(context) {
    queueMicrotask(() => {
      if (stopped || context.readSequence !== loadSequence
        || context.navigationSequence !== navigationSequence) return;
      const list = $("list-content");
      if (list) list.scrollTop = context.listScrollTop;
      const messages = document.querySelector(".messages");
      if (messages && messages.dataset.threadId === context.messageThreadId) {
        if (context.followLatest) messages.scrollTop = messages.scrollHeight;
        else if (context.messageAnchor) restoreMessageScrollAnchor(context.messageAnchor);
        else messages.scrollTop = context.messageScrollTop;
      }
      if (context.activeElementId) {
        const activeElement = $(context.activeElementId);
        activeElement?.focus({ preventScroll: true });
        const selection = context.activeTextSelection;
        // A read may replace the field, but must not move the reader's caret.
        // Ignore changed values and non-text controls instead of applying an
        // obsolete range or calling an unsupported setSelectionRange method.
        if (selection && document.activeElement === activeElement
          && isTextSelectionControl(activeElement) && activeElement.value === selection.value) {
          activeElement.setSelectionRange(selection.start, selection.end, selection.direction);
        }
      } else if (context.activeThreadId) {
        // Compare stable record IDs directly rather than interpolating them
        // into a selector; a refresh may reorder or remove a conversation.
        const threadButton = [...($("list-content")?.querySelectorAll("button.thread-card[data-thread-id]") || [])]
          .find((button) => button.dataset.threadId === context.activeThreadId);
        (threadButton || $("search-input"))?.focus({ preventScroll: true });
      } else if (context.activeContactId) {
        const contactButton = [...($("list-content")?.querySelectorAll("button.contact-list-item[data-contact-id]") || [])]
          .find((button) => button.dataset.contactId === context.activeContactId);
        (contactButton || $("search-input"))?.focus({ preventScroll: true });
      }
    });
  }

  function currentContactForThread(thread) {
    if (!snapshot || !thread) return null;
    if (thread.contactId != null) {
      const byContactId = snapshot.contacts.find((item) => item.contactId === thread.contactId);
      if (byContactId) return byContactId;
    }
    if (thread.peerPrincipalId != null) {
      const byPrincipalId = snapshot.contacts.find((item) => item.principalId === thread.peerPrincipalId);
      if (byPrincipalId) return byPrincipalId;
    }
    if (thread.peerHelloLynkId != null) {
      return snapshot.contacts.find((item) => item.hellolynkId === thread.peerHelloLynkId) || null;
    }
    return null;
  }

  function sendStateForThread(thread) {
    // A global send may be admitted before its thread appears in the read
    // model. That later entry must share the same unresolved-send lock.
    const contact = snapshot.contacts.find((item) => item.contactId === globalComposer.contactId);
    if (["pending", "unknown"].includes(globalComposer.phase) && thread.conversationKind === "instance"
      && thread.localDelegateId === snapshot.subject.delegateId && thread.peerPrincipalId === contact?.principalId
      && thread.peerHelloLynkId === contact?.hellolynkId && thread.peerDelegateId === globalComposer.recipientDelegateId) return globalComposer;
    return sendStateByThreadId.get(thread.threadId) || { phase: "idle", code: null };
  }

  function renderComposer(thread) {
    const state = sendStateForThread(thread);
    const currentContact = currentContactForThread(thread);
    const sendLocked = state.phase === "pending" || state.phase === "unknown";
    const composer = node("div", "composer");
    composer.dataset.threadId = thread.threadId;
    composer.dataset.contactId = currentContactForThread(thread)?.contactId || "";
    const label = node("label", "sr-only", localizedCopy("composer.label", "发送消息"));
    const textarea = node("textarea", "composer-input");
    const textareaId = `composer-${thread.threadId}`;
    label.htmlFor = textareaId;
    textarea.id = textareaId;
    textarea.rows = 4;
    textarea.maxLength = 20_480;
    localizedAttribute(textarea, "placeholder", localizedCopy("composer.placeholder", "输入消息…"));
    localizedAttribute(textarea, "aria-description", conversationRouteLabel(thread));
    textarea.value = sendLocked ? "" : draftsByThreadId.get(thread.threadId) || "";
    textarea.disabled = sendLocked;
    textarea.addEventListener("input", () => {
      if (!["pending", "unknown"].includes(sendStateForThread(thread).phase)) draftsByThreadId.set(thread.threadId, textarea.value);
    });
    const send = node("button", "primary-button composer-send", localizedCopy("composer.send", "发送"));
    send.type = "button";
    send.disabled = sendLocked;
    send.dataset.action = "send-message";
    const submit = () => void submitMessage(thread, textarea);
    send.addEventListener("click", submit);
    textarea.addEventListener("keydown", (event) => {
      if (event.isComposing || event.keyCode === 229 || event.shiftKey || event.key !== "Enter" || event.repeat) return;
      event.preventDefault();
      submit();
    });
    const controls = node("div", "composer-controls", [
      node("span", "composer-hint", localizedCopy("composer.hint", "Enter 发送 · Shift+Enter 换行")),
      send,
    ]);
    const status = node("div", `composer-status is-${state.phase}`, sendStatusCopy(state));
    status.dataset.sendState = state.phase;
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    composer.append(label, textarea, controls, status);
    return composer;
  }

  async function submitMessage(thread, textarea) {
    const current = sendStateForThread(thread);
    if (!canSendToThread(thread) || current?.phase === "pending" || current?.phase === "unknown") return;
    if (document.getElementById(textarea.id) !== textarea) return;
    const text = textarea.value;
    if (!text.trim()) return;
    const recipientHelloLynkId = currentContactForThread(thread)?.hellolynkId || null;
    if (!recipientHelloLynkId || snapshot?.messages.threadId !== thread.threadId) return;
    draftsByThreadId.set(thread.threadId, text);
    const approval = createSendApproval(`thread:${thread.threadId}`, { threadId: thread.threadId, text, recipientDelegateId: thread.peerDelegateId, recipientHelloLynkId, recipientPrincipalId: thread.peerPrincipalId });
    await requestSendApproval(approval, { recipientHelloLynkId, recipientDelegateId: thread.peerDelegateId, text });
    if (!stopped && approval.epoch === accountViewEpoch) refreshAfterChange();
  }

  function isSendPreviewContextCurrent(preview) {
    return !stopped && snapshot && preview.epoch === accountViewEpoch
      && preview.hostGeneration === snapshot.hostGeneration && preview.sourceClientId === snapshot.source.clientId
      && preview.principalId === snapshot.subject.principalId && preview.delegateId === snapshot.subject.delegateId
      && preview.ownerHelloLynkId === snapshot.subject.hellolynkId;
  }

  function sendPreviewMatchesThread(preview, thread) {
    return isSendPreviewContextCurrent(preview) && thread.conversationKind === "instance"
      && (!preview.threadId || preview.threadId === thread.threadId)
      && thread.localDelegateId === preview.delegateId && thread.peerPrincipalId === preview.recipientPrincipalId
      && thread.peerHelloLynkId === preview.recipientHelloLynkId && thread.peerDelegateId === preview.recipientDelegateId;
  }

  function sendPreviewMatchesOutbox(preview, item) {
    return item.clientMessageId === preview.clientMessageId && item.localDelegateId === preview.delegateId
      && item.recipientDelegateId === preview.recipientDelegateId && item.recipientHelloLynkId === preview.recipientHelloLynkId
      && item.threadId != null && (!preview.threadId || preview.threadId === item.threadId);
  }

  function renderSentStatus(status) {
    return node("div", "message-delivery-status is-sent", isDeliveredStatus(status)
      ? localizedCopy("message.delivered", "已送达")
      : localizedCopy("message.sent", "已发送"));
  }

  function renderSendPreview(preview) {
    const article = node("article", "message is-outgoing pending-send-message", [
      node("div", "message-bubble", preview.text),
    ]);
    article.dataset.clientMessageId = preview.clientMessageId;
    if (preview.phase === "ok") article.append(renderSentStatus());
    return article;
  }

  function createSendApproval(target, fields) {
    const previous = sendApprovalByTarget.get(target);
    if (previous) clearTimeout(previous.timer);
    const approval = {
      target, ...fields, epoch: accountViewEpoch, hostGeneration: snapshot.hostGeneration,
      principalId: snapshot.subject.principalId, delegateId: snapshot.subject.delegateId,
      sourceClientId: snapshot.source.clientId,
      baselineRevision: snapshot.revision, ownerHelloLynkId: snapshot.subject.hellolynkId,
      actionId: null, clientMessageId: generatedId("client-message"), timer: null, failures: 0,
      createdAt: new Date().toISOString(),
    };
    sendApprovalByTarget.set(target, approval);
    publishSendApproval(approval, { phase: "pending", code: null });
    return approval;
  }

  function isCurrentSendApproval(approval) {
    return !stopped && sendApprovalByTarget.get(approval.target) === approval
      && approval.epoch === accountViewEpoch && snapshot
      && approval.hostGeneration === snapshot.hostGeneration
      && approval.sourceClientId === snapshot.source.clientId
      && approval.principalId === snapshot.subject.principalId
      && approval.delegateId === snapshot.subject.delegateId;
  }

  function invalidateSendApprovalContexts() {
    for (const approval of sendApprovalByTarget.values()) {
      if (isCurrentSendApproval(approval)) continue;
      clearTimeout(approval.timer);
      // A replaced Host cannot prove the previous send outcome. Keep its draft
      // locked, and never query that action through a different identity.
      if (approval.epoch === accountViewEpoch) {
        const state = { phase: "unknown", code: "workbench_send_context_changed" };
        if (approval.target === "global") globalComposer = { ...globalComposer, ...state };
        else sendStateByThreadId.set(approval.threadId, state);
      }
      sendApprovalByTarget.delete(approval.target);
    }
  }

  function publishSendApproval(approval, state) {
    if (!isCurrentSendApproval(approval)) return;
    const next = { sendOutcome: null, ...state, actionId: approval.actionId, clientMessageId: approval.clientMessageId };
    if (next.phase === "failed") sendPreviewByMessageId.delete(approval.clientMessageId);
    else sendPreviewByMessageId.set(approval.clientMessageId, { ...approval, ...next });
    if (approval.target === "global") globalComposer = { ...globalComposer, ...next };
    else sendStateByThreadId.set(approval.threadId, next);
    render();
  }

  function isDeliveredStatus(status) {
    return status === "delivered_to_live_connection" || status === "acknowledged_by_recipient_local_store" || status === "delivered";
  }

  function isSentStatus(status) {
    // Neither sent nor delivered is evidence that the recipient model read or completed the task.
    return status === "sent" || status === "accepted" || isDeliveredStatus(status);
  }

  function reconcileSendUnknownLocks() {
    // As with local note recovery, only a fresh authoritative read can settle
    // a lost command response. Text similarity and queued rows are not proof.
    if (!snapshot || !["ready", "empty"].includes(view.phase) || authorityReloadRequired
      || snapshot.source.mode !== "neutral-host") return;
    for (const approval of sendApprovalByTarget.values()) {
      const state = approval.target === "global" ? globalComposer : sendStateByThreadId.get(approval.threadId);
      if (!["pending", "unknown"].includes(state?.phase) || !isCurrentSendApproval(approval)
        || snapshot.revision === approval.baselineRevision
        || snapshot.subject.hellolynkId !== approval.ownerHelloLynkId) continue;
      // The read model scopes outbox rows to the current principal. Match the
      // exact operation and both AI endpoints before accepting its sent state.
      const sentOutbox = snapshot.outbox.some((item) => item.clientMessageId === approval.clientMessageId
        && isSentStatus(item.status) && item.localDelegateId === approval.delegateId
        && item.recipientDelegateId === approval.recipientDelegateId
        && item.recipientHelloLynkId === approval.recipientHelloLynkId
        && item.threadId != null && (!approval.threadId || item.threadId === approval.threadId));
      const notDelivered = snapshot.outbox.find((item) => item.clientMessageId === approval.clientMessageId
        && MANUAL_RETRY_OUTBOX_STATES.has(item.status) && item.localDelegateId === approval.delegateId
        && !["pending", "unknown"].includes(actionStateByKey.get(`outbox:retry:${item.clientMessageId}`)?.phase)
        && item.recipientDelegateId === approval.recipientDelegateId
        && item.recipientHelloLynkId === approval.recipientHelloLynkId
        && item.threadId != null && (!approval.threadId || item.threadId === approval.threadId));
      if (notDelivered) {
        clearTimeout(approval.timer);
        sendApprovalByTarget.delete(approval.target);
        sendPreviewByMessageId.delete(approval.clientMessageId);
        const failed = { phase: "failed", code: null, sendOutcome: "not-delivered", actionId: approval.actionId, clientMessageId: approval.clientMessageId };
        if (approval.target === "global") globalComposer = { ...globalComposer, ...failed };
        else sendStateByThreadId.set(approval.threadId, failed);
        continue;
      }
      const sentMessage = snapshot.messages.items.some((message) => {
        if (message.clientMessageId !== approval.clientMessageId || message.direction !== "outgoing"
          || !isSentStatus(message.status) || message.senderPrincipalId !== approval.principalId
          || message.senderDelegateId !== approval.delegateId
          || (approval.threadId && message.threadId !== approval.threadId)) return false;
        const thread = snapshot.threads.items.find((item) => item.threadId === message.threadId);
        return thread?.conversationKind === "instance" && thread.localDelegateId === approval.delegateId
          && thread.peerDelegateId === approval.recipientDelegateId
          && thread.peerPrincipalId === approval.recipientPrincipalId
          && thread.peerHelloLynkId === approval.recipientHelloLynkId;
      });
      if (!sentOutbox && !sentMessage) continue;
      clearTimeout(approval.timer);
      sendApprovalByTarget.delete(approval.target);
      const confirmed = { phase: "ok", code: null, sendOutcome: "approved", actionId: approval.actionId, clientMessageId: approval.clientMessageId };
      sendPreviewByMessageId.set(approval.clientMessageId, { ...approval, ...confirmed });
      if (approval.target === "global") {
        const wasOpen = globalComposer.open;
        globalComposer = { ...globalComposer, ...confirmed, open: false, draft: "" };
        if (wasOpen) focusGlobalComposerReturn();
      } else {
        draftsByThreadId.delete(approval.threadId);
        sendStateByThreadId.set(approval.threadId, confirmed);
      }
    }
  }

  async function requestSendApproval(approval, payload) {
    let command;
    try {
      command = createWorkbenchCommand(HELLOLYNK_WORKBENCH_COMMAND_TYPES.requestSend, {
        clientMessageId: approval.clientMessageId, ...payload,
      }, {
        requestId: generatedId("request"),
        idempotencyKey: createWorkbenchIdempotencyKey(snapshot.commandWindow, approval.clientMessageId),
        expectedRevision: snapshot.revision,
      });
    } catch (error) {
      // Construction is pure local validation. No transport was called, so
      // this approval is known not sent and its retained draft stays editable.
      if (!isCurrentSendApproval(approval)) return;
      publishSendApproval(approval, { phase: "failed", code: publicError(error) });
      sendApprovalByTarget.delete(approval.target);
      return;
    }
    try {
      const result = validateWorkbenchCommandResult(await transport.executeCommand(command), command.command);
      if (!isCurrentSendApproval(approval)) return;
      if (result.requestId !== command.requestId) throw new Error("workbench_send_result_unconfirmed");
      if (result.ok) await acceptSendApprovalResult(approval, result.result);
      else {
        publishSendApproval(approval, { phase: result.error.outcome === "unknown" ? "unknown" : "failed", code: result.error.code });
        if (result.error.outcome !== "unknown") sendApprovalByTarget.delete(approval.target);
        if (result.error.outcome === "unknown" || result.error.code === "host_app_command_window_full") await refreshReadOnly();
      }
    } catch (error) {
      if (!isCurrentSendApproval(approval)) return;
      const phase = transportFailurePhase(error);
      publishSendApproval(approval, { phase, code: publicError(error) });
      if (phase === "failed") sendApprovalByTarget.delete(approval.target);
      await refreshReadOnly();
    }
  }

  async function acceptSendApprovalResult(approval, result) {
    if (!isCurrentSendApproval(approval)) return;
    if (!result || result.kind !== "message-send" || typeof result.actionId !== "string"
      || !result.actionId || (approval.actionId && approval.actionId !== result.actionId)) {
      publishSendApproval(approval, { phase: "unknown", code: "workbench_send_result_unconfirmed" });
      return;
    }
    approval.actionId = result.actionId;
    approval.failures = 0;
    const sendOutcome = result.state;
    if (sendOutcome === "approved") {
      clearTimeout(approval.timer);
      if (approval.target === "global") globalComposer = { ...globalComposer, open: false, draft: "" };
      else draftsByThreadId.delete(approval.threadId);
      publishSendApproval(approval, { phase: "ok", code: null, sendOutcome });
      sendApprovalByTarget.delete(approval.target);
      // Refresh whichever conversation is visible now, without navigating back
      // to the conversation that originally requested this send.
      await refreshReadOnly();
      if (!stopped && approval.epoch === accountViewEpoch && approval.target === "global") focusGlobalComposerReturn();
      return;
    }
    if (["cancelled", "expired", "invalidated"].includes(sendOutcome)) {
      clearTimeout(approval.timer);
      publishSendApproval(approval, { phase: "failed", code: result.code, sendOutcome });
      sendApprovalByTarget.delete(approval.target);
      return;
    }
    if (sendOutcome === "failed") {
      clearTimeout(approval.timer);
      publishSendApproval(approval, { phase: "unknown", code: result.code, sendOutcome });
      await refreshReadOnly();
      return;
    }
    if (!["pending", "consuming"].includes(sendOutcome)) {
      publishSendApproval(approval, { phase: "unknown", code: "workbench_send_result_unconfirmed" });
      return;
    }
    publishSendApproval(approval, { phase: "pending", code: result.code, sendOutcome });
    scheduleSendApprovalQuery(approval);
  }

  function scheduleSendApprovalQuery(approval) {
    if (!isCurrentSendApproval(approval) || !approval.actionId) return;
    clearTimeout(approval.timer);
    approval.timer = setTimeout(() => { approval.timer = null; void querySendApproval(approval); }, Math.min(1000 * (approval.failures + 1), 10000));
  }

  async function querySendApproval(approval) {
    if (!isCurrentSendApproval(approval)) return;
    try {
      // An admitted action lives in the local broker. A cloud outage can
      // remove new-send capability without removing permission to read its
      // outcome; the Host still validates the account and attachment scope.
      if (!approval.actionId || snapshot.source.mode !== "neutral-host"
        || snapshot.commandWindow === null
        || transport.actionGrantMode !== "host-single-use-v1"
        || typeof transport.executeCommand !== "function") throw new Error("workbench_send_status_unavailable");
      const command = createWorkbenchCommand(HELLOLYNK_WORKBENCH_COMMAND_TYPES.getSendStatus, { actionId: approval.actionId }, {
        requestId: generatedId("request"),
        idempotencyKey: createWorkbenchIdempotencyKey(snapshot.commandWindow, generatedId("send-status")),
        expectedRevision: null,
      });
      const result = validateWorkbenchCommandResult(await transport.executeCommand(command), command.command);
      if (!isCurrentSendApproval(approval)) return;
      if (result.requestId !== command.requestId) throw new Error("workbench_send_result_unconfirmed");
      if (result.ok) await acceptSendApprovalResult(approval, result.result);
      else if (result.error.code === "human_confirmation_not_found") {
        publishSendApproval(approval, { phase: "unknown", code: result.error.code });
      } else throw new Error(result.error.code);
    } catch (error) {
      if (!isCurrentSendApproval(approval)) return;
      approval.failures++;
      const code = publicError(error);
      publishSendApproval(approval, { phase: "unknown", code });
      if (["host_app_command_window_full", "host_app_command_window_expired"].includes(code)) await refreshReadOnly();
      scheduleSendApprovalQuery(approval);
    }
  }

  function sendStatusCopy(state) {
    if (state.sendOutcome === "not-delivered") return localizedCopy("composer.status.notDelivered", "未送达，草稿已保留。请按消息下方提示处理后再发送。");
    if (["cancelled", "expired", "invalidated"].includes(state.sendOutcome)) return localizedCopy(`composer.status.${state.sendOutcome}`, "未发送，草稿已保留。请确认后再次点击发送。");
    if (state.sendOutcome === "failed") return localizedCopy("composer.status.sendFailed", "发送未能确认。草稿已保留，请先查看会话中的发送状态，不要重复发送。");
    if (state.phase === "pending") return state.sendOutcome === "pending"
      ? localizedCopy("composer.status.awaitingApproval", "等待你在确认窗口批准发送。草稿已保留。") : "";
    if (state.phase === "ok") return localizedCopy("composer.status.ok", "已发送。");
    if (state.phase === "failed" && ["host_app_command_window_full", "host_app_human_send_text_too_large"].includes(state.code)) return actionErrorCopy(state.code);
    if (state.phase === "failed") return localizedCopy("composer.status.failed", "发送失败，未自动重试。请检查后重新输入。", { code: state.code || "workbench_command_failed" });
    if (state.phase === "unknown") return localizedCopy("composer.status.unknown", "发送结果未知。消息已保留，请勿重复发送。", { code: state.code || "workbench_command_outcome_unknown" });
    return "";
  }

  function renderContacts(root) {
    reconcileContactRecordUnknownLocks();
    const invalidatedContext = reconcileContactContexts();
    reconcileLifecycleUnknownLocks();
    const invalidatedLifecycle = reconcileLifecycleConfirmation();
    const contactUiPruned = Boolean(
      (contactEditor && !canExecute(contactEditorCapability(contactEditor)))
      || (deleteConfirmation && !canExecute("contact.delete"))
      || (clearResolvedConfirmation && !canExecute("contact-request.clear-resolved")),
    );
    if (contactEditor && !canExecute(contactEditorCapability(contactEditor))) contactEditor = null;
    if (deleteConfirmation && !canExecute("contact.delete")) deleteConfirmation = null;
    if (!canExecute("contact-request.clear-resolved")) {
      clearResolvedConfirmation = null;
      actionStateByKey.delete("contact-request:clear-resolved");
    }
    const normalizedQuery = contactQuery.normalize("NFKC").trim().toLocaleLowerCase(locale);
    const matchesQuery = (...values) => !normalizedQuery || values.some((value) => String(value || "").normalize("NFKC").toLocaleLowerCase(locale).includes(normalizedQuery));
    const incomingRequests = snapshot.contactRequests.filter((request) => matchesQuery(request.otherLabel, request.otherHelloLynkId));
    const outgoingRequests = snapshot.outgoingContactRequests.filter((request) => matchesQuery(request.otherLabel, request.otherHelloLynkId));
    const relationships = snapshot.relationships.filter((relationship) => matchesQuery(relationship.otherLabel, relationship.otherHelloLynkId));
    const blocks = snapshot.blocks.filter((block) => matchesQuery(block.otherLabel, block.otherHelloLynkId));
    reconcilePrincipalDiscoveryContext();
    const selectedContact = selectedContactId
      ? deriveWorkbenchContacts(snapshot).find((contact) => contact.contactId === selectedContactId) || null
      : null;
    if (selectedContactId && !selectedContact) {
      selectedContactId = null;
      detailsOpen = false;
      detailsObjectKey = null;
      if (location.hash.startsWith("#/contacts/contact/")) replaceLocationHash("#/contacts");
      syncMobilePaneIsolation();
    }
    const shell = node("div", "conversation-shell contact-shell");
    const main = node("section", "contact-main");
    if (selectedContact) {
      if (contactInstancePickerId === selectedContact.contactId) renderContactInstancePicker(main, selectedContact);
      else renderSelectedContact(main, selectedContact);
      shell.append(main);
    } else if (contactWorkspaceMode === "requests") {
      const content = node("section", "module-view contacts-view", [
        contactWorkspaceHeader(localizedCopy("requests.title", "联系人申请"), localizedCopy("requests.summary", "处理申请、关系与屏蔽。")),
      ]);
      if (isLocalHistoryOnly(snapshot)) {
        content.append(node("p", "contact-context-notice", localizedCopy("requests.unsynced", "联系申请暂未同步，请检查连接和设备授权后刷新。")));
      } else content.append(...[
        hasWorkbenchCapability(snapshot, "contacts.read")
          ? renderContactSection(localizedCopy("requests.incomingTitle", "收到的申请"), incomingRequests.map(renderContactRequestCard),
            (snapshot.contactRequestNextCursor || contactRequestPageCursors.length > 1) && incomingRequests.length === 0
              ? localizedCopy("requests.incomingPageEmpty", "当前结果为空，可继续加载。")
              : localizedCopy("requests.incomingEmpty", "没有收到的申请。"), "record-list")
          : null,
        hasWorkbenchCapability(snapshot, "contacts.read")
          ? renderContactSection(localizedCopy("requests.outgoingTitle", "发出的申请"), outgoingRequests.map(renderContactRequestCard),
            (snapshot.contactRequestNextCursor || contactRequestPageCursors.length > 1) && outgoingRequests.length === 0
              ? localizedCopy("requests.outgoingPageEmpty", "当前结果为空，可继续加载。")
              : localizedCopy("requests.outgoingEmpty", "没有发出的申请。"), "record-list")
          : null,
        (snapshot.contactRequestNextCursor || contactRequestPageCursors.length > 1)
          && hasWorkbenchCapability(snapshot, "contacts.read") ? renderContactRequestPager() : null,
        hasWorkbenchCapability(snapshot, "relationships.read")
          ? renderContactSection(localizedCopy("relationships.title", "关系"), relationships.map(renderRelationshipCard), localizedCopy("relationships.empty", "没有关系记录。"), "record-list")
          : null,
        hasWorkbenchCapability(snapshot, "blocks.read")
          ? renderContactSection(localizedCopy("blocks.title", "已屏蔽"), blocks.map(renderBlockCard), localizedCopy("blocks.empty", "没有屏蔽记录。"), "record-list")
          : null,
      ].filter(Boolean));
      if (canExecute("contact-request.clear-resolved")) content.append(renderClearResolvedControl());
      main.append(content);
      shell.append(main);
    } else if (contactWorkspaceMode === "add") {
      const content = node("section", "module-view contacts-view", [
        contactWorkspaceHeader(localizedCopy("contacts.add", "添加联系人"), ""),
      ]);
      if (contactContextNotice) content.append(renderContactContextNotice());
      if (contactRequestOutcomeByTarget.size) content.append(renderContactRequestOutcomes());
      if (contactEditor) content.append(renderContactEditor());
      else if (canExecute("principal.search") && canExecute("contact-request.send")) content.append(renderPrincipalDiscovery());
      main.append(content);
      shell.append(main);
    } else {
      const hasContacts = deriveWorkbenchContacts(snapshot).length > 0;
      main.append(node("section", "contact-workspace-empty", [
        node("h2", "", hasContacts ? localizedCopy("contacts.selectTitle", "选择联系人") : localizedCopy("contacts.empty", "没有联系人")),
      ]));
      if (contactContextNotice) main.append(renderContactContextNotice());
      shell.append(main);
    }
    root.replaceChildren(shell);
    if (contactUiPruned) queueMicrotask(() => document.getElementById("contacts-title")?.focus({ preventScroll: true }));
    if (invalidatedContext) focusContactContext(invalidatedContext.kind, invalidatedContext.contactId, invalidatedContext.recipientDelegateId);
    if (invalidatedLifecycle) focusLifecycleOutcome(invalidatedLifecycle.kind, invalidatedLifecycle.recordId);
  }

  function contactWorkspaceHeader(titleCopy, bodyCopy, options = {}) {
    const back = node("button", "back-button", iconAsset("arrow-left"));
    back.type = "button";
    localizedAttribute(back, "aria-label", localizedCopy("action.back", "返回"));
    back.addEventListener("click", () => navigate("contacts"));
    const title = node("h2", "", titleCopy);
    title.id = "contacts-title";
    title.tabIndex = -1;
    const heading = node("div", "conversation-heading", [title]);
    if (bodyCopy) heading.append(node("p", "", bodyCopy));
    const children = [back, heading];
    if (options.detailToggle) children.push(options.detailToggle);
    return node("header", "conversation-header", children);
  }

  function renderSelectedContact(main, contact) {
    main.classList.add("contact-main-selected");
    const relationCopy = !hasWorkbenchCapability(snapshot, "relationships.read")
      ? localizedCopy("relationship.unsynced", "关系状态未同步")
      : contact.relationship?.status === "active"
      ? localizedCopy("relationship.activeShort", "关系已建立")
      : localizedCopy("relationship.localShort", "本机联系人");
    const title = node("h2", "", contact.displayName);
    title.id = "contacts-title";
    title.tabIndex = -1;
    const contactName = node("div", "contact-name-row", [title]);
    const back = node("button", "back-button", iconAsset("arrow-left"));
    back.type = "button";
    back.id = `contact-profile-back-${contact.contactId}`;
    localizedAttribute(back, "aria-label", localizedCopy("action.back", "返回"));
    back.addEventListener("click", () => navigate("contacts"));
    const content = node("div", "contact-content", node("article", "contact-profile", [
      node("header", "contact-profile-header", [
        back,
        node("span", "thread-avatar", initials(contact.displayName)),
        node("div", "contact-profile-identity", [contactName, node("p", "contact-identity-meta", [
          node("span", "", contact.hellolynkId), node("span", "", relationCopy),
        ])]),
      ]),
      renderContactManagement(contact),
      renderContactInstances(contact),
    ]));
    main.append(content);
  }

  function renderContactInstances(contact) {
    if (contactInstanceEditor && contactInstanceEditor.contactId !== contact.contactId) contactInstanceEditor = null;
    const heading = node("div", "contact-instances-heading", [node("h3", "", localizedCopy("instances.title", "对方的 AI"))]);
    if (canExecute("contact.instances.list") && canExecute("contact.instance.save")) {
      heading.append(contactActionButton("list-contact-instances", localizedCopy("instances.add", "添加 AI"), () => void openContactSetup(contact.contactId), contact.contactId));
    }
    const section = node("section", "contact-instances", [heading]);
    // Creation times only matter once several saved AIs could be confused.
    // Read the existing directory once per contact; never store or poll it.
    const showCreatedAt = contact.instances.length > 1;
    if (showCreatedAt && !instanceCreatedAtByContact.has(contact.contactId) && canExecute("contact.instances.list")) {
      instanceCreatedAtByContact.set(contact.contactId, new Map());
      queueMicrotask(() => void listContactInstances(contact));
    }
    const createdAtByDelegate = showCreatedAt ? instanceCreatedAtByContact.get(contact.contactId) : null;
    for (const instance of contact.instances) {
      const stateKey = `authorization:${contact.contactId}:${instance.delegateId}`;
      const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
      const nameText = node("div", "instance-choice-text", [node("strong", "", instance.displayName)]);
      const createdAt = createdAtByDelegate?.get(instance.delegateId);
      if (createdAt) nameText.append(node("span", "instance-choice-created",
        localizedCopy("instances.createdAt", "{time} 建立", { time: localizedDateTime(createdAt) })));
      const instanceName = node("div", "instance-name-row", [nameText]);
      const controls = node("div", "instance-header-actions");
      const conversation = instance.conversation;
      const open = contactActionButton("open-instance-conversation", localizedCopy("instances.open", "打开会话"), async () => {
        const current = deriveWorkbenchContacts(snapshot).find((item) => item.contactId === contact.contactId)
          ?.instances.find((item) => item.delegateId === instance.delegateId);
        if (!current || current.conversationKey !== instance.conversationKey) return;
        if (current.conversation && current.conversation.threadId === conversation?.threadId) { navigate("inbox", current.conversation.threadId); return; }
        if (!current.conversationKey || !canExecute("threads.manage-local")) return;
        const epoch = accountViewEpoch;
        const navigation = navigationSequence;
        const result = await runAction(`local-history:restore:${current.conversationKey}`,
          HELLOLYNK_WORKBENCH_COMMAND_TYPES.restoreThread, { threadId: current.conversationKey }, { lockUnknown: true });
        if (result?.ok && epoch === accountViewEpoch && navigation === navigationSequence) navigate("inbox", current.conversationKey);
      }, contact.contactId, "contact-inline-action");
      open.dataset.delegateId = instance.delegateId;
      const restoreState = actionStateByKey.get(`local-history:restore:${instance.conversationKey}`);
      open.disabled = !conversation && (!instance.conversationKey || !canExecute("threads.manage-local") || ["pending", "unknown"].includes(restoreState?.phase));
      controls.append(open);
      if (restoreState && !["idle", "ok"].includes(restoreState.phase)) section.append(actionStatus(restoreState));
      const moreActions = [];
      if (canExecute("contact.instance.rename")) {
        const editName = contactActionButton("edit-contact-instance", localizedCopy("instances.editName", "修改备注"), () => {
          const currentContact = snapshot.contacts.find((item) => item.contactId === contact.contactId);
          const current = currentContact?.instances.find((item) => item.delegateId === instance.delegateId);
          if (!current || !canExecute("contact.instance.rename")) return;
          contactContextNotice = null;
          const stateKey = `instance-rename:${contact.contactId}:${instance.delegateId}`;
          if (!["pending", "unknown"].includes(actionStateByKey.get(stateKey)?.phase)) actionStateByKey.delete(stateKey);
          contactInstanceEditor = {
            contactId: contact.contactId,
            recipientDelegateId: instance.delegateId,
            displayName: current.displayName,
            openedRevision: snapshot.revision,
            openedHostGeneration: snapshot.hostGeneration,
            ownerHelloLynkId: snapshot.subject.hellolynkId,
            localDelegateId: snapshot.subject.delegateId,
            expectedHelloLynkId: currentContact.hellolynkId,
            expectedPrincipalId: currentContact.principalId,
            expectedDisplayName: current.displayName,
          };
          render();
          queueMicrotask(() => document.getElementById(contactInstanceNameInputId(contact.contactId, instance.delegateId))?.focus({ preventScroll: true }));
        }, contact.contactId, "contact-more-action");
        editName.dataset.delegateId = instance.delegateId;
        moreActions.push(editName);
      }
      const deleteState = actionStateByKey.get(`instance-delete:${contact.contactId}:${instance.delegateId}`);
      if (canExecute("contact.instance.delete")) {
        const remove = contactActionButton("delete-contact-instance", localizedCopy("instances.remove", "移除 AI 入口"), () => void mutateContactInstance(contact, instance.delegateId, "delete"), contact.contactId, "contact-more-action danger-button");
        remove.dataset.delegateId = instance.delegateId;
        remove.disabled = ["pending", "unknown"].includes(deleteState?.phase);
        moreActions.push(remove);
      }
      if (moreActions.length) controls.append(renderContactMore(`instance-more-${contact.contactId}-${instance.delegateId}`, instance.displayName, moreActions));
      instanceName.append(controls);
      const card = node("article", "data-card instance-card", [
        instanceName,
        renderContactInstancePermissions(contact, instance, state),
      ]);
      card.dataset.delegateId = instance.delegateId;
      if (deleteState) card.append(renderContactActionStatus(deleteState, localizedCopy("instances.removed", "AI 入口已移除")));
      if (contactInstanceEditor?.contactId === contact.contactId
        && contactInstanceEditor.recipientDelegateId === instance.delegateId) {
        card.append(renderContactInstanceNameEditor(contact, instance, contactInstanceEditor));
      }
      section.append(card);
    }
    const isSelf = contact.hellolynkId === snapshot.subject.hellolynkId;
    if (!contact.instances.length) section.append(node("p", "", isSelf
      ? localizedCopy("instances.selfEmpty", "选择你的另一个 AI，再开始会话。")
      : localizedCopy("instances.empty", "先添加对方的 AI，再开始会话。")));
    return section;
  }

  async function listContactInstances(contact) {
    const epoch = accountViewEpoch;
    const context = { openedRevision: snapshot.revision, openedHostGeneration: snapshot.hostGeneration };
    const shouldRenderDirectory = () => view.section === "contacts" && selectedContactId === contact.contactId
      && contactInstancePickerId === contact.contactId;
    const result = await runAction(`instance-list:${contact.contactId}`, HELLOLYNK_WORKBENCH_COMMAND_TYPES.listContactInstances, { contactId: contact.contactId }, {
      lockUnknown: false, shouldRenderCompletion: shouldRenderDirectory,
    });
    if (!result?.ok || epoch !== accountViewEpoch || result.result.contactId !== contact.contactId
      || result.result.hellolynkId !== contact.hellolynkId
      || (contact.principalId != null && result.result.principalId !== contact.principalId)) return;
    if (rememberInstanceCreatedAt(contact.contactId, result.result.instances) && !shouldRenderDirectory()
      && view.section === "contacts" && selectedContactId === contact.contactId) render();
    if (!isCurrentSnapshotContext(context)) return;
    instanceDirectoryByContact.set(contact.contactId, { ...context, instances: result.result.instances });
    if (shouldRenderDirectory()) render();
  }

  // The relay writes an AI's creation time once, so it outlives a directory
  // snapshot and keeps same-name saved AIs apart after the picker closes.
  function rememberInstanceCreatedAt(contactId, instances) {
    const known = instanceCreatedAtByContact.get(contactId) || new Map();
    instanceCreatedAtByContact.set(contactId, known);
    let changed = false;
    for (const instance of instances) {
      if (!instance.createdAt || known.get(instance.delegateId) === instance.createdAt) continue;
      known.set(instance.delegateId, instance.createdAt);
      changed = true;
    }
    return changed;
  }

  function renderContactInstanceNameEditor(contact, instance, editor) {
    const key = `instance-rename:${contact.contactId}:${instance.delegateId}`;
    const state = actionStateByKey.get(key) || { phase: "idle", code: null };
    const input = node("input", "field-input instance-name-input");
    input.id = contactInstanceNameInputId(contact.contactId, instance.delegateId);
    input.type = "text";
    input.maxLength = 80;
    input.value = editor.displayName;
    input.disabled = ["pending", "unknown"].includes(state.phase);
    input.addEventListener("input", () => {
      if (contactInstanceEditor !== editor) return;
      editor.displayName = input.value;
      const displayName = editor.displayName.normalize("NFKC").trim().replace(/\s+/gu, " ");
      save.disabled = input.disabled || !displayName || displayName === instance.displayName;
    });
    const label = node("label", "form-field", [node("span", "form-label", localizedCopy("instances.localName", "本机显示备注")), input]);
    label.htmlFor = input.id;
    const cancel = contactActionButton("cancel-contact-instance-edit", localizedCopy("action.cancel", "取消"), () => {
      if (contactInstanceEditor !== editor) return;
      contactInstanceEditor = null;
      render();
      focusContactMore(contact.contactId, instance.delegateId);
    }, contact.contactId);
    cancel.dataset.delegateId = instance.delegateId;
    const save = contactActionButton("save-contact-instance-name", localizedCopy("instances.saveName", "保存备注"), () => void renameContactInstance(contact, instance, editor), contact.contactId);
    save.dataset.delegateId = instance.delegateId;
    const displayName = editor.displayName.normalize("NFKC").trim().replace(/\s+/gu, " ");
    save.disabled = input.disabled || !displayName || displayName === instance.displayName;
    return node("div", "instance-name-editor", [label, node("div", "card-actions", [cancel, save]), contactFlowActionStatus(state)]);
  }

  async function renameContactInstance(contact, instance, editor) {
    if (contactInstanceEditor !== editor) return;
    if (!isCurrentContactInstanceEditor(editor)) { render(); return; }
    const epoch = accountViewEpoch;
    const displayName = editor.displayName.normalize("NFKC").trim().replace(/\s+/gu, " ");
    if (!displayName || displayName === instance.displayName) return;
    const result = await runAction(`instance-rename:${contact.contactId}:${instance.delegateId}`,
      HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContactInstance, {
        contactId: contact.contactId, recipientDelegateId: instance.delegateId, displayName,
        expectedDisplayName: editor.expectedDisplayName,
        expectedHelloLynkId: editor.expectedHelloLynkId, expectedPrincipalId: editor.expectedPrincipalId,
      }, { onConfirmed: () => {
        if (isCurrentContactInstanceEditor(editor)) snapshot = {
          ...snapshot,
          contacts: snapshot.contacts.map((item) => item.contactId === editor.contactId
            ? { ...item, instances: item.instances.map((ai) => ai.delegateId === editor.recipientDelegateId
              ? { ...ai, displayName } : ai) } : item),
        };
        if (contactInstanceEditor === editor) contactInstanceEditor = null;
        contactContextNotice = null;
        render();
        focusContactMore(contact.contactId, instance.delegateId);
      }, unknownEvidence: {
        kind: "contact-instance-note", contactId: contact.contactId,
        recipientDelegateId: instance.delegateId, displayName,
        hellolynkId: contact.hellolynkId, principalId: contact.principalId,
        baselineRevision: snapshot.revision, hostGeneration: snapshot.hostGeneration,
        ownerHelloLynkId: snapshot.subject.hellolynkId, localDelegateId: snapshot.subject.delegateId,
      } });
    if (epoch !== accountViewEpoch) return;
    if (result?.ok && contactInstanceEditor === editor) contactInstanceEditor = null;
    render();
    if (result?.ok) focusContactMore(contact.contactId, instance.delegateId);
  }

  async function mutateContactInstance(contact, recipientDelegateId, operation, displayName = "", context = null) {
    const epoch = accountViewEpoch;
    const originHash = location.hash;
    const originPickerId = contactInstancePickerId;
    const originEditor = contactInstanceEditor;
    // Adding an entry owns its picker, not a note editor opened after a read
    // has already shown that entry committed before the Add reply arrives.
    const shouldRenderCompletion = () => operation !== "save" || (epoch === accountViewEpoch
      && location.hash === originHash && view.section === "contacts" && selectedContactId === contact.contactId
      && contactInstancePickerId === originPickerId && contactInstanceEditor === originEditor);
    const current = snapshot.contacts.find((item) => item.contactId === contact.contactId);
    if (!current) return;
    if (context && !isCurrentSnapshotContext(context)) return;
    if (operation === "save") {
      if (recipientDelegateId === snapshot.subject.delegateId) return;
      const directory = instanceDirectoryByContact.get(contact.contactId);
      const alreadySaved = current.instances.some((item) => item.delegateId === recipientDelegateId);
      if (alreadySaved && !String(displayName || "").trim()) return;
      if (!alreadySaved && (!directory || !isCurrentSnapshotContext(directory)
        || !directory.instances.some((item) => item.delegateId === recipientDelegateId))) return;
    } else if (!current.instances.some((item) => item.delegateId === recipientDelegateId)) return;
    const payload = { contactId: contact.contactId, recipientDelegateId };
    const normalizedDisplayName = String(displayName || "").trim();
    if (operation === "save" && normalizedDisplayName) payload.displayName = normalizedDisplayName;
    const result = await runAction(`instance-${operation}:${contact.contactId}:${recipientDelegateId}`, operation === "save"
      ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContactInstance : HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContactInstance,
    payload, { shouldRenderCompletion });
    if (epoch !== accountViewEpoch) return;
    if (operation === "delete" && result?.ok && contactInstanceEditor?.contactId === contact.contactId
      && contactInstanceEditor.recipientDelegateId === recipientDelegateId) contactInstanceEditor = null;
    if (operation === "delete" || result?.ok) instanceDirectoryByContact.delete(contact.contactId);
    if (shouldRenderCompletion()) {
      render();
      if (result?.ok && normalizedDisplayName) focusContactMore(contact.contactId, recipientDelegateId);
    }
    if (result?.ok && operation === "save" && contactInstancePickerId === contact.contactId
      && context?.openedHostGeneration === snapshot.hostGeneration) await listContactInstances(contact);
  }

  function contactInstanceNameInputId(contactId, recipientDelegateId) {
    return `contact-instance-name-${contactId}-${recipientDelegateId}`;
  }

  function contactMessageButton(contact) {
    const button = node("button", "primary-button", localizedCopy("contacts.message", "发消息"));
    button.type = "button";
    button.id = contactMessageButtonId(contact.contactId);
    button.dataset.action = "message-contact";
    button.dataset.recordId = contact.contactId;
    button.disabled = !canExecute("messages.request-send") || !contact.principalId || !contact.instances.length;
    button.addEventListener("click", () => openGlobalComposerForContact(contact));
    return button;
  }

  function contactMessageButtonId(contactId) {
    return `message-contact-${contactId}`;
  }

  function renderContactManagement(contact) {
    const body = node("section", "contact-management");
    const controls = node("div", "card-actions contact-profile-actions", [contactMessageButton(contact)]);
    const moreActions = [];
    if (canExecute("contact.rename")) {
      const edit = contactActionButton("edit-contact-name", localizedCopy("contacts.editName", "修改备注"), () => openContactEditor(contact, `contact-more-${contact.contactId}-summary`), contact.contactId, "contact-more-action");
      edit.id = editContactNameButtonId(contact.contactId);
      moreActions.push(edit);
    }
    if (canExecute("contact.delete")) {
      const remove = contactActionButton("delete", localizedCopy("contacts.delete", "删除本机联系人"), () => beginDeleteContact(contact), contact.contactId, "contact-more-action danger-button");
      remove.id = deleteContactButtonId(contact.contactId);
      moreActions.push(remove);
    }
    if (moreActions.length) controls.append(renderContactMore(`contact-more-${contact.contactId}`, contact.displayName, moreActions));
    body.append(controls);
    const contextNotice = contactContextNotice?.contactId === contact.contactId ? contactContextNotice : null;
    if (contextNotice) body.append(renderContactContextNotice());
    if (contactEditor?.contactId === contact.contactId) body.append(renderContactEditor());
    if (deleteConfirmation?.contactId === contact.contactId) body.append(renderDeleteConfirmation(contact, deleteConfirmation));
    const stateKey = actionStateByKey.has(`delete:${contact.contactId}`)
      ? `delete:${contact.contactId}` : contactSaveStateKey(contact.contactId);
    if (contextNotice?.kind !== "save" || contextNotice.reason !== "unknown" || contextNotice.stateKey !== stateKey) {
      body.append(renderContactActionStatus(actionStateByKey.get(stateKey), localizedCopy("contacts.saved", "联系人已保存")));
    }
    return body;
  }

  function renderContactDisclosure(id, className, summaryCopy, children, { keepOpen = false } = {}) {
    const disclosure = node("details", className);
    disclosure.id = id;
    const summary = node("summary", `${className}-summary`, summaryCopy);
    summary.id = `${id}-summary`;
    const previous = document.getElementById(id);
    if (keepOpen || previous?.hasAttribute("open")) disclosure.setAttribute("open", "");
    disclosure.append(summary, ...children);
    disclosure.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || !disclosure.hasAttribute("open")) return;
      event.preventDefault();
      event.stopPropagation?.();
      disclosure.removeAttribute("open");
      summary.focus({ preventScroll: true });
    });
    return disclosure;
  }

  function renderContactMore(id, name, actions) {
    const more = renderContactDisclosure(id, "contact-more", localizedCopy("contacts.more", "更多"), [node("div", "contact-more-actions", actions)]);
    localizedAttribute(more.children[0], "aria-label", localizedCopy("contacts.moreFor", "{name}的更多操作", { name }));
    more.addEventListener("click", (event) => {
      if (more.children[1].contains(event.target)) more.removeAttribute("open");
    }, true);
    const closeOutside = (event) => {
      if (!more.isConnected || !more.contains(event.target)) {
        more.removeAttribute("open");
        document.removeEventListener?.("click", closeOutside);
      }
    };
    more.addEventListener("toggle", () => {
      if (more.hasAttribute("open")) document.addEventListener?.("click", closeOutside);
      else document.removeEventListener?.("click", closeOutside);
    });
    return more;
  }

  function focusContactMore(contactId, delegateId = null) {
    queueMicrotask(() => {
      if (selectedContactId !== contactId || contactInstancePickerId === contactId) return;
      const target = (delegateId ? document.getElementById(`instance-more-${contactId}-${delegateId}-summary`) : null)
        || document.getElementById(`contact-more-${contactId}-summary`)
        || document.getElementById("contacts-title") || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function renderContactActionStatus(state, successCopy) {
    const status = actionStatus(state);
    if (state?.phase === "ok" && (!state.refreshing || state.localNoteConfirmed === true)) localizedText(status, successCopy);
    return status;
  }

  function renderContactInstancePermissions(contact, instance, authorizationState) {
    const sendRow = node("div", "instance-permission-row", [
      node("div", "instance-permission-copy", [
        node("strong", "", localizedCopy("authorization.title", "自主收发")),
        node("span", "instance-permission-state", instance.autonomousSendAuthorized
          ? localizedCopy("authorization.activeShort", "AI 自主收发已开启") : localizedCopy("authorization.humanShort", "发送由你确认")),
      ]),
    ]);
    if (canManageAuthorization() && authorizationState.phase !== "unknown") sendRow.append(renderAuthorizationButton(contact, authorizationState, instance));
    sendRow.append(renderContactActionStatus(authorizationState, localizedCopy("contacts.permissionsSaved", "权限已更新")));
    const keepOpen = ["pending", "unknown", "failed"].includes(authorizationState.phase);
    return renderContactDisclosure("instance-permissions-" + contact.contactId + "-" + instance.delegateId, "instance-permissions",
      localizedCopy("instances.permissions", "AI 权限"), [node("div", "instance-permissions-body", [sendRow])], { keepOpen });
  }

  function renderContactInstancePicker(main, contact) {
    const section = node("section", "module-view contacts-view instance-picker");
    section.dataset.action = "contact-instance-picker";
    section.append(contactWorkspaceHeader(localizedCopy("discovery.chooseSelfInstance", "选择 AI"), contact.hellolynkId));
    const controls = node("div", "card-actions");
    controls.append(contactActionButton("close-instance-picker", localizedCopy("instances.backToContact", "返回联系人"), () => {
      contactInstancePickerId = null;
      render();
    }, contact.contactId));
    const state = actionStateByKey.get(`instance-list:${contact.contactId}`);
    const canList = canExecute("contact.instances.list") && canExecute("contact.instance.save");
    const refresh = contactActionButton("list-contact-instances", localizedCopy("action.refresh", "刷新"), () => {
      if (contactInstancePickerId === contact.contactId && canExecute("contact.instance.save")) void listContactInstances(contact);
    }, contact.contactId);
    refresh.disabled = !canList || state?.phase === "pending";
    controls.append(refresh);
    section.append(controls);
    section.setAttribute("aria-busy", state?.phase === "pending" ? "true" : "false");
    const directory = instanceDirectoryByContact.get(contact.contactId);
    if (canList && directory && isCurrentSnapshotContext(directory)) {
      const rows = node("div", "instance-picker-list");
      for (const instance of directory.instances) {
        const current = instance.delegateId === snapshot.subject.delegateId;
        const saved = contact.instances.some((item) => item.delegateId === instance.delegateId);
        const key = `instance-save:${contact.contactId}:${instance.delegateId}`;
        const saveState = actionStateByKey.get(key);
        const context = { openedRevision: directory.openedRevision, openedHostGeneration: directory.openedHostGeneration };
        const button = contactActionButton("save-contact-instance", current ? localizedCopy("instances.current", "当前 AI")
          : saved ? localizedCopy("instances.added", "已添加") : localizedCopy("instances.addSelected", "添加这个 AI"),
        () => {
          if (contactInstancePickerId === contact.contactId && !current && !saved) void mutateContactInstance(contact, instance.delegateId, "save", "", context);
        }, contact.contactId);
        button.dataset.delegateId = instance.delegateId;
        button.disabled = current || saved || ["pending", "unknown"].includes(saveState?.phase);
        const identity = node("div", "instance-choice-text", [node("strong", "instance-choice-name", instance.displayName)]);
        // Same-name AIs stay separate; the relay's registration time tells them apart.
        if (instance.createdAt) identity.append(node("span", "instance-choice-created",
          localizedCopy("instances.createdAt", "{time} 建立", { time: localizedDateTime(instance.createdAt) })));
        const row = node("article", "instance-choice", [identity, button]);
        row.dataset.delegateId = instance.delegateId;
        if (saveState && saveState.phase !== "ok") row.append(contactFlowActionStatus(saveState));
        rows.append(row);
      }
      section.append(rows);
      if (!directory.instances.length) section.append(node("p", "", contact.hellolynkId === snapshot.subject.hellolynkId
        ? localizedCopy("instances.selfDirectoryEmpty", "尚未找到其他已登记的 AI。连接另一个客户端后刷新。")
        : localizedCopy("instances.noMore", "暂无可添加的 AI。")));
    } else if (state?.phase === "pending") {
      const loading = node("p", "action-status is-pending", localizedCopy("discovery.loadingInstances", "正在加载 AI…"));
      loading.setAttribute("role", "status");
      section.append(loading);
    } else if (!canList) section.append(node("p", "action-status", actionErrorCopy("host_app_capability_unavailable")));
    else if (state?.phase === "ok") section.append(node("p", "action-status", localizedCopy("instances.directoryStale", "AI 列表已过期，请刷新。")));
    if (state?.phase === "failed") section.append(contactFlowActionStatus(state));
    else if (state?.phase === "unknown") {
      const status = node("p", "action-status is-unknown", withVisibleErrorCode(localizedCopy("instances.directoryUnknown", "AI 列表加载结果未知，请刷新。"), state.code));
      status.setAttribute("role", "status");
      section.append(status);
    }
    main.append(section);
  }

  function principalDiscoveryAuthority() {
    // Search targets follow the Host connection, not unrelated message
    // revisions or the service's rotating command journal window.
    return JSON.stringify([accountViewEpoch, authorityFailureSequence, snapshot.hostGeneration,
      snapshot.source.mode, snapshot.source.transport, snapshot.source.clientId,
      snapshot.subject.region, snapshot.subject.principalId, snapshot.subject.hellolynkId,
      snapshot.subject.delegateId, snapshot.subject.hostInstallationId, snapshot.subject.authorizationVersion]);
  }

  function isCurrentPrincipalDiscoveryContext(context) {
    return !stopped && snapshot && context?.authority === principalDiscoveryAuthority();
  }

  function isCurrentPrincipalDiscoveryTarget(result) {
    return isCurrentPrincipalDiscoveryContext(principalDiscovery.context)
      && principalDiscovery.results.includes(result)
      && ((result.targetRef === "local-self" && result.hellolynkId === snapshot.subject.hellolynkId)
        || Date.parse(result.expiresAt) > Date.now());
  }

  function reconcilePrincipalDiscoveryContext() {
    if (!principalDiscovery.context) return;
    if (!isCurrentPrincipalDiscoveryContext(principalDiscovery.context)) {
      principalDiscovery = { ...principalDiscovery, phase: "stale", code: "host_app_contact_target_expired",
        results: [], quota: null, revision: null, hostGeneration: null, context: null };
      contactRequestDraftByTarget.clear();
      contactRequestSendStateByTarget.clear();
      return;
    }
    if (principalDiscovery.phase === "pending") return;
    const expired = principalDiscovery.results.length > 0
      && !principalDiscovery.results.some(isCurrentPrincipalDiscoveryTarget);
    principalDiscovery = { ...principalDiscovery,
      ...(expired ? { phase: "stale", code: "host_app_contact_target_expired" } : {}),
      revision: expired ? null : snapshot.revision,
    };
    // Expiry disables target use but preserves drafts and in-flight/unknown
    // locks. A later read may show acceptance without replaying a request.
  }

  function renderPrincipalDiscovery() {
    const section = node("section", "contact-section principal-discovery");
    const controls = node("div", "discovery-controls");
    const modeLabel = node("label", "form-field discovery-mode");
    const mode = node("select", "field-input");
    mode.id = "principal-search-mode";
    mode.dataset.action = "principal-search-mode";
    modeLabel.htmlFor = mode.id;
    for (const [value, label] of [["hellolynk_id", localizedCopy("discovery.modeId", "完整 HelloLynk ID")], ["nickname", localizedCopy("discovery.modeNickname", "精确昵称")]]) {
      const option = node("option", "", label);
      option.value = value;
      option.selected = principalDiscovery.mode === value;
      mode.append(option);
    }
    mode.disabled = principalDiscovery.phase === "pending";
    mode.addEventListener("change", () => {
      principalDiscovery = { ...principalDiscovery, mode: mode.value, phase: "idle", code: null, results: [], revision: null, hostGeneration: null, context: null };
      contactRequestDraftByTarget.clear();
      contactRequestSendStateByTarget.clear();
      render();
      queueMicrotask(() => document.getElementById("principal-search-query")?.focus());
    });
    modeLabel.append(node("span", "form-label", localizedCopy("discovery.mode", "搜索方式")), mode);
    const queryLabel = node("label", "form-field discovery-query");
    const query = node("input", "field-input");
    query.id = "principal-search-query";
    query.dataset.action = "principal-search-query";
    query.type = "search";
    query.maxLength = 200;
    query.autocomplete = "off";
    query.value = principalDiscovery.query;
    localizedAttribute(query, "placeholder", principalDiscovery.mode === "hellolynk_id"
      ? localizedCopy("discovery.idPlaceholder", "hellolynk:intl:完整稳定ID")
      : localizedCopy("discovery.nicknamePlaceholder", "输入完整昵称"));
    query.disabled = principalDiscovery.phase === "pending";
    queryLabel.htmlFor = query.id;
    queryLabel.append(node("span", "form-label", localizedCopy("discovery.query", "搜索内容")), query);
    query.addEventListener("input", () => {
      principalDiscovery = { ...principalDiscovery, query: query.value, ...(principalDiscovery.phase === "failed" ? { phase: "idle", code: null } : {}) };
    });
    query.addEventListener("keydown", (event) => {
      if (event.isComposing || event.keyCode === 229 || event.key !== "Enter" || event.repeat) return;
      event.preventDefault();
      void submitPrincipalSearch();
    });
    const button = contactActionButton("principal-search", principalDiscovery.phase === "pending"
      ? localizedCopy("discovery.searching", "正在搜索…") : localizedCopy("discovery.search", "精确搜索"), () => void submitPrincipalSearch());
    button.id = "principal-search-submit";
    button.disabled = principalDiscovery.phase === "pending";
    controls.append(modeLabel, queryLabel, button);
    section.append(controls, principalDiscoveryStatus());
    if (principalDiscovery.quota) {
      section.append(node("p", "quota-copy", localizedCopy("discovery.searchQuota", "今日搜索剩余 {remaining}/{limit}", principalDiscovery.quota)));
    }
    const results = node("div", "card-grid discovery-results");
    for (const result of principalDiscovery.results) results.append(renderPrincipalSearchResult(result));
    if (principalDiscovery.phase === "ok" && principalDiscovery.results.length === 0) {
      results.append(node("article", "data-card", node("p", "", localizedCopy("discovery.empty", "没有找到联系人。"))));
    }
    if (results.children.length) section.append(results);
    return section;
  }

  function principalDiscoveryStatus() {
    const text = principalDiscovery.phase === "failed"
      ? withVisibleErrorCode(actionErrorCopy(principalDiscovery.code), principalDiscovery.code)
      : principalDiscovery.phase === "unknown"
        ? withVisibleErrorCode(discoveryUnknownCopy(principalDiscovery.code), principalDiscovery.code)
        : principalDiscovery.phase === "stale"
          ? withVisibleErrorCode(localizedCopy("discovery.stale", "搜索结果已过期，请重新搜索。"), principalDiscovery.code)
          : "";
    const status = node("p", `action-status is-${principalDiscovery.phase}`, text);
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    return status;
  }

  function renderPrincipalSearchResult(result) {
    const sendState = contactRequestSendStateByTarget.get(result.targetRef) || { phase: "idle", code: null, quota: null };
    const isSelf = result.hellolynkId != null && result.hellolynkId === snapshot.subject.hellolynkId;
    const savedContact = result.hellolynkId
      ? deriveWorkbenchContacts(snapshot).find((contact) => contact.hellolynkId === result.hellolynkId) || null
      : null;
    const activeRelationship = result.hellolynkId
      ? snapshot.relationships.find((relationship) => relationship.otherHelloLynkId === result.hellolynkId && relationship.status === "active") || null
      : null;
    const knownRequest = result.hellolynkId
      ? [...snapshot.contactRequests, ...snapshot.outgoingContactRequests]
        .find((request) => request.otherHelloLynkId === result.hellolynkId && ["pending", "accepted"].includes(request.state)) || null
      : null;
    const card = node("article", "data-card discovery-card", [
      node("h4", "", result.displayName || localizedCopy("discovery.unnamed", "未命名联系人")),
      result.hellolynkId ? node("p", "discovery-public-id", result.hellolynkId) : node("p", "privacy-copy", localizedCopy("discovery.nicknamePrivacy", "昵称结果不会显示稳定 HelloLynk ID。")),
    ]);
    if (isSelf) {
      card.append(node("p", "module-copy", localizedCopy("discovery.selfInstances", "我的其他 AI")));
      const choose = contactActionButton("choose-self-instance", localizedCopy("discovery.chooseSelfInstance", "选择 AI"), () => {
        if (!isCurrentPrincipalDiscoveryTarget(result)) return;
        if (savedContact) void openContactSetup(savedContact.contactId);
        else chooseSelfInstance(result);
      }, savedContact?.contactId || result.targetRef);
      choose.disabled = !canExecute("contact.instances.list") || !canExecute("contact.instance.save")
        || (!savedContact && (!canExecute("contact.save")
          || ["pending", "unknown"].includes(actionStateByKey.get(contactSaveStateKey(null))?.phase)));
      card.append(choose);
      return card;
    }
    if (savedContact) {
      const choose = contactActionButton("complete-contact", localizedCopy("contacts.complete", "选择 AI"), () => void openContactSetup(savedContact.contactId), savedContact.contactId);
      choose.disabled = !canExecute("contact.instances.list") || !canExecute("contact.instance.save");
      card.append(choose);
      return card;
    }
    if (activeRelationship) {
      const add = contactActionButton("add-relationship-contact", localizedCopy("contacts.addRelationship", "添加并选择 AI"), () => openRelationshipContactEditor(activeRelationship), activeRelationship.relationshipId);
      add.disabled = !canExecute("contact.save") || !canExecute("contact.instances.list") || !canExecute("contact.instance.save");
      card.append(add);
      return card;
    }
    if (knownRequest) {
      if (knownRequest.state === "accepted") {
        card.append(node("p", "action-status is-ok", localizedCopy("discovery.accepted", "对方已接受，正在同步联系人关系。")));
      } else if (contactRequestOutcomeByTarget.get(result.targetRef)?.phase !== "submitted") {
        card.append(node("p", "action-status is-ok", knownRequest.direction === "incoming"
          ? localizedCopy("requests.pending", "等待你决定")
          : localizedCopy("discovery.waiting", "申请已发送，等待对方接受。")));
      }
      if (knownRequest.state !== "accepted" && knownRequest.direction === "outgoing") {
        card.append(node("p", "module-copy", localizedCopy("discovery.aiAfterConsent", "对方同意后，可选择要添加的 AI。")));
      }
      return card;
    }
    const label = node("label", "field-label", localizedCopy("discovery.intro", "介绍语（选填）"));
    const draft = node("textarea", "field-input intro-input");
    draft.id = `contact-intro-${result.targetRef}`;
    label.htmlFor = draft.id;
    draft.dataset.action = "contact-request-intro";
    draft.dataset.targetRef = result.targetRef;
    draft.maxLength = 80;
    draft.rows = 2;
    draft.value = contactRequestDraftByTarget.get(result.targetRef) || "";
    draft.disabled = !canExecute("contact-request.send") || !isCurrentPrincipalDiscoveryTarget(result) || sendState.phase === "pending"
      || sendState.phase === "submitted" || sendState.phase === "unknown";
    const validation = validateIntroDraft(draft.value);
    const counter = node("p", "intro-counter", localizedCopy("discovery.introWeight", "{weight}/40", { weight: validation.weight }));
    counter.id = `contact-intro-count-${result.targetRef}`;
    draft.setAttribute("aria-describedby", counter.id);
    draft.addEventListener("input", () => {
      contactRequestDraftByTarget.set(result.targetRef, draft.value);
      const next = validateIntroDraft(draft.value);
      localizedText(counter, localizedCopy("discovery.introWeight", "{weight}/40", { weight: next.weight }));
    });
    draft.addEventListener("keydown", (event) => {
      if (event.isComposing || event.keyCode === 229 || event.shiftKey || event.key !== "Enter" || event.repeat) return;
      event.preventDefault();
      void submitContactRequest(result.targetRef);
    });
    const send = contactActionButton("contact-request-send", sendState.phase === "pending"
      ? localizedCopy("discovery.sending", "正在发送…") : localizedCopy("discovery.send", "发送联系申请"), () => void submitContactRequest(result.targetRef));
    send.disabled = draft.disabled;
    card.append(node("p", "module-copy", localizedCopy("discovery.aiAfterConsent", "对方同意后，可选择要添加的 AI。")), label, draft, counter, send);
    if (sendState.phase === "pending") card.append(contactRequestSendStatus(sendState));
    if (sendState.quota) card.append(node("p", "quota-copy", localizedCopy("discovery.sendQuota", "今天还可向此人发送 {remaining}/{limit} 次申请", sendState.quota)));
    return card;
  }

  function contactRequestSendStatus(state) {
    const text = state.phase === "submitted" ? localizedCopy("discovery.sent", "已发送")
      : state.phase === "unknown" ? withVisibleErrorCode(localizedCopy("discovery.deliveryUnknown", "发送结果未知，未自动重试。"), state.code || "workbench_command_outcome_unknown")
        : state.phase === "failed" ? withVisibleErrorCode(actionErrorCopy(state.code), state.code)
          : state.phase === "pending" ? localizedCopy("discovery.sending", "正在发送…") : "";
    const status = node("p", `action-status is-${state.phase}`, text);
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    return status;
  }

  function renderContactRequestOutcomes() {
    const outcomes = node("section", "contact-request-outcomes");
    outcomes.dataset.action = "contact-request-outcomes";
    for (const [targetRef, state] of contactRequestOutcomeByTarget) {
      const status = contactRequestSendStatus(state);
      status.dataset.action = "contact-request-outcome";
      status.dataset.targetRef = targetRef;
      outcomes.append(status);
    }
    return outcomes;
  }

  function rememberContactRequestOutcome(targetRef, state) {
    contactRequestOutcomeByTarget.set(targetRef, { ...state });
  }

  async function submitPrincipalSearch() {
    if (!canExecute("principal.search") || principalDiscovery.phase === "pending") return;
    const query = principalDiscovery.query.trim();
    if (!query || (principalDiscovery.mode === "hellolynk_id" && !/^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(query))) {
      principalDiscovery = { ...principalDiscovery, phase: "failed", code: "workbench_command_principal_search_query_invalid", results: [] };
      render();
      return;
    }
    const searchContext = { authority: principalDiscoveryAuthority(), openedHostGeneration: snapshot.hostGeneration };
    if (principalDiscovery.mode === "hellolynk_id" && query === snapshot.subject.hellolynkId) {
      principalDiscovery = {
        ...principalDiscovery,
        query,
        phase: "ok",
        code: null,
        results: [{
          targetRef: "local-self",
          displayName: snapshot.subject.principalLabel || copy("discovery.selfName", "我"),
          hellolynkId: snapshot.subject.hellolynkId,
          expiresAt: snapshot.generatedAt,
        }],
        quota: null,
        revision: snapshot.revision,
        hostGeneration: snapshot.hostGeneration,
        context: searchContext,
      };
      render();
      return;
    }
    principalDiscovery = { ...principalDiscovery, query, phase: "pending", code: null, results: [], context: searchContext };
    render();
    try {
      const command = createWorkbenchCommand(HELLOLYNK_WORKBENCH_COMMAND_TYPES.searchPrincipal, { mode: principalDiscovery.mode, query }, {
        requestId: generatedId("request"),
        idempotencyKey: createWorkbenchIdempotencyKey(snapshot.commandWindow, generatedId("action")),
        expectedRevision: snapshot.revision,
      });
      const result = validateWorkbenchCommandResult(await transport.executeCommand(command), command.command);
      if (principalDiscovery.context !== searchContext || !isCurrentPrincipalDiscoveryContext(searchContext)) return;
      if (!result.ok) {
        principalDiscovery = { ...principalDiscovery, phase: result.error.outcome === "unknown" ? "unknown" : "failed", code: result.error.code };
        if (result.error.outcome === "known-failed" && result.error.code === "host_app_revision_conflict") {
          await load({ threadId: view.selectedThreadId, quiet: true, preserveUiContext: true });
        }
      } else if (result.result.kind !== "principal-search") {
        principalDiscovery = { ...principalDiscovery, phase: "unknown", code: "workbench_command_result_invalid" };
      } else {
        principalDiscovery = {
          ...principalDiscovery,
          phase: "ok",
          code: null,
          results: result.result.results,
          quota: result.result.quota,
          revision: snapshot.revision,
          hostGeneration: searchContext.openedHostGeneration,
        };
      }
    } catch (error) {
      if (principalDiscovery.context !== searchContext || !isCurrentPrincipalDiscoveryContext(searchContext)) return;
      principalDiscovery = { ...principalDiscovery, phase: transportFailurePhase(error), code: publicError(error), results: [] };
    }
    // Retain lookup results without rebuilding a screen the user moved to.
    if (view.section !== "contacts" || contactWorkspaceMode !== "add" || contactEditor) return;
    render();
    queueMicrotask(() => document.getElementById("principal-search-query")?.focus({ preventScroll: true }));
  }

  async function submitContactRequest(targetRef) {
    if (!canExecute("contact-request.send")) return;
    const currentTarget = principalDiscovery.results.find((result) => result.targetRef === targetRef) || null;
    if (!currentTarget || currentTarget.hellolynkId === snapshot.subject.hellolynkId) return;
    if (!isCurrentPrincipalDiscoveryTarget(currentTarget)) {
      reconcilePrincipalDiscoveryContext();
      render();
      return;
    }
    const current = contactRequestSendStateByTarget.get(targetRef);
    if (["pending", "submitted", "unknown"].includes(current?.phase)) return;
    const submissionEpoch = accountViewEpoch;
    const submissionContext = principalDiscovery.context;
    const introText = contactRequestDraftByTarget.get(targetRef) || "";
    const validation = validateIntroDraft(introText);
    if (!validation.ok) {
      const failed = { phase: "failed", code: validation.code, quota: null };
      contactRequestSendStateByTarget.set(targetRef, failed);
      rememberContactRequestOutcome(targetRef, failed);
      render();
      return;
    }
    contactRequestSendStateByTarget.set(targetRef, { phase: "pending", code: null, quota: null });
    render();
    try {
      const command = createWorkbenchCommand(HELLOLYNK_WORKBENCH_COMMAND_TYPES.sendContactRequest, { targetRef, introText }, {
        requestId: generatedId("request"),
        idempotencyKey: createWorkbenchIdempotencyKey(snapshot.commandWindow, generatedId("action")),
        expectedRevision: snapshot.revision,
      });
      const result = validateWorkbenchCommandResult(await transport.executeCommand(command), command.command);
      if (submissionEpoch !== accountViewEpoch || !isCurrentPrincipalDiscoveryContext(submissionContext)) return;
      if (!result.ok) {
        const failed = {
          phase: result.error.outcome === "unknown" ? "unknown" : "failed",
          code: result.error.code,
          quota: null,
        };
        contactRequestSendStateByTarget.set(targetRef, failed);
        rememberContactRequestOutcome(targetRef, failed);
      } else if (result.result.kind === "contact-request-send") {
        const submitted = {
          phase: result.result.status === "delivery_unknown" ? "unknown" : "submitted",
          code: null,
          quota: result.result.quota,
        };
        contactRequestSendStateByTarget.set(targetRef, submitted);
        rememberContactRequestOutcome(targetRef, submitted);
        if (submitted.phase === "submitted") contactRequestDraftByTarget.delete(targetRef);
      } else {
        const unknown = { phase: "unknown", code: "workbench_command_result_invalid", quota: null };
        contactRequestSendStateByTarget.set(targetRef, unknown);
        rememberContactRequestOutcome(targetRef, unknown);
      }
      await load({ threadId: view.selectedThreadId, quiet: true });
    } catch (error) {
      if (submissionEpoch !== accountViewEpoch || !isCurrentPrincipalDiscoveryContext(submissionContext)) return;
      const failed = { phase: transportFailurePhase(error), code: publicError(error), quota: null };
      contactRequestSendStateByTarget.set(targetRef, failed);
      rememberContactRequestOutcome(targetRef, failed);
      await load({ threadId: view.selectedThreadId, quiet: true });
    }
    render();
  }

  function reconcileContactRecordUnknownLocks() {
    for (const [stateKey, state] of actionStateByKey.entries()) {
      const evidence = state?.phase === "unknown" ? state.unknownEvidence : null;
      if (evidence?.kind === "contact-save" || evidence?.kind === "contact-instance-note") {
        // A read can confirm the requested local note without replaying its
        // write. Old, failed or differently scoped snapshots are not proof.
        if (!["ready", "empty"].includes(view.phase) || authorityReloadRequired
          || snapshot.source.mode !== "neutral-host"
          || snapshot.revision === evidence.baselineRevision
          || snapshot.hostGeneration !== evidence.hostGeneration
          || snapshot.subject.hellolynkId !== evidence.ownerHelloLynkId
          || snapshot.subject.delegateId !== evidence.localDelegateId) continue;
        const contact = snapshot.contacts.find((item) => item.contactId === evidence.contactId);
        if (evidence.kind === "contact-instance-note") {
          const instance = contact?.instances.find((item) => item.delegateId === evidence.recipientDelegateId);
          if (contact?.hellolynkId === evidence.hellolynkId && contact.principalId === evidence.principalId
            && instance?.displayName === evidence.displayName) {
            actionStateByKey.set(stateKey, { phase: "ok", code: null });
            if (contactInstanceEditor?.contactId === evidence.contactId
              && contactInstanceEditor.recipientDelegateId === evidence.recipientDelegateId
              && !isCurrentContactInstanceEditor(contactInstanceEditor)) contactInstanceEditor = null;
          }
        } else if (contact?.hellolynkId === evidence.hellolynkId && contact.displayName === evidence.displayName) {
          actionStateByKey.set(stateKey, { phase: "ok", code: null });
          if (contactContextNotice?.stateKey === stateKey) contactContextNotice = null;
          if (contactEditor?.contactId === evidence.contactId && !isCurrentContactEditor(contactEditor)) contactEditor = null;
        }
      } else if (evidence?.kind === "authorization") {
        const contact = snapshot.contacts.find((item) => item.contactId === evidence.contactId);
        if (contact?.instances.find((item) => item.delegateId === evidence.recipientDelegateId)?.autonomousSendAuthorized === evidence.expectedAuthorized) {
          actionStateByKey.set(stateKey, { phase: "ok", code: null });
        }
      } else if (evidence?.kind === "contact-request") {
        const request = snapshot.contactRequests.find((item) => item.requestId === evidence.requestId);
        if (request?.actionReady === true) {
          actionStateByKey.delete(stateKey);
        } else if (request?.state === evidence.expectedState) {
          actionStateByKey.set(stateKey, { phase: "ok", code: null });
        }
      }
    }
  }

  function reconcileContactContexts() {
    if (contactInstanceEditor && (!canExecute("contact.instance.rename") || !isCurrentContactInstanceEditor(contactInstanceEditor))) {
      const editor = contactInstanceEditor;
      const stateKey = `instance-rename:${editor.contactId}:${editor.recipientDelegateId}`;
      const state = actionStateByKey.get(stateKey);
      if (state?.phase === "ok") {
        contactInstanceEditor = null;
        contactContextNotice = null;
      } else if (state?.phase !== "pending") {
        const invalidated = { kind: "instance-rename", contactId: editor.contactId, recipientDelegateId: editor.recipientDelegateId };
        closeContactContext(invalidated.kind, invalidated.contactId, state?.phase === "unknown" ? "unknown" : "conflict", invalidated.recipientDelegateId);
        return invalidated;
      }
    }
    if (contactEditor && !isCurrentContactEditor(contactEditor)) {
      const state = actionStateByKey.get(contactSaveStateKey(contactEditor.contactId));
      if (state?.phase === "ok") {
        contactEditor = null;
        contactContextNotice = null;
      } else if (state?.phase !== "pending") {
        const invalidated = { kind: "save", contactId: contactEditor.contactId };
        closeContactContext(invalidated.kind, invalidated.contactId, state?.phase === "unknown" ? "unknown" : "conflict");
        return invalidated;
      }
    }
    if (deleteConfirmation && !isCurrentSnapshotContext(deleteConfirmation)) {
      const state = actionStateByKey.get(`delete:${deleteConfirmation.contactId}`);
      const contactStillExists = snapshot.contacts.some((item) => item.contactId === deleteConfirmation.contactId);
      if (state?.phase === "ok" || (state?.phase === "unknown" && !contactStillExists)) {
        deleteConfirmation = null;
        contactContextNotice = null;
      } else if (state?.phase !== "pending") {
        const invalidated = { kind: "delete", contactId: deleteConfirmation.contactId };
        closeContactContext(invalidated.kind, invalidated.contactId, state?.phase === "unknown" ? "unknown" : "conflict");
        return invalidated;
      }
    }
    return null;
  }

  function closeContactContext(kind, contactId, reason, recipientDelegateId = null) {
    const stateKey = kind === "instance-rename" ? `instance-rename:${contactId}:${recipientDelegateId}`
      : kind === "save" ? contactSaveStateKey(contactId) : `delete:${contactId}`;
    if (reason === "conflict") actionStateByKey.set(stateKey, { phase: "failed", code: "host_app_revision_conflict" });
    else if (actionStateByKey.get(stateKey)?.phase !== "unknown") {
      actionStateByKey.set(stateKey, { phase: "unknown", code: "workbench_command_outcome_unknown" });
    }
    contactContextNotice = { kind, contactId, reason, stateKey };
    if (kind === "save") contactEditor = null;
    else if (kind === "instance-rename") contactInstanceEditor = null;
    else deleteConfirmation = null;
  }

  function renderContactContextNotice() {
    const state = actionStateByKey.get(contactContextNotice.stateKey)
      || (contactContextNotice.reason === "unknown"
        ? { phase: "unknown", code: "workbench_command_outcome_unknown" }
        : { phase: "failed", code: "host_app_revision_conflict" });
    const conflictCopy = contactContextNotice.kind === "instance-rename"
      ? localizedCopy("instances.editConflict", "这个 AI 的备注或身份已变化，或入口已移除。旧编辑没有提交；请查看最新状态后重新修改。")
      : contactContextNotice.kind === "save"
      ? localizedCopy("contacts.editConflict", "联系人已在另一处更新。旧编辑内容已失效且没有提交；请从刚刷新的联系人重新打开后再修改。")
      : localizedCopy("contacts.deleteConflict", "联系人已在另一处更新。旧删除确认已失效且没有执行；请查看最新状态后重新确认。");
    const unknownCopy = contactContextNotice.kind === "instance-rename"
      ? localizedCopy("instances.editUnknown", "AI 备注保存结果未知，未自动重试。请先核对最新备注。")
      : contactContextNotice.kind === "save"
      ? localizedCopy("contacts.editUnknown", "联系人保存结果未知。旧编辑上下文已关闭且不会重试；请先核对刷新后的联系人，再显式重新打开。")
      : localizedCopy("contacts.deleteUnknown", "联系人删除结果未知。旧删除确认已关闭且不会重试；请先核对刷新后的联系人，再显式重新确认。");
    const notice = actionStatus(state, { conflictCopy, unknownCopy });
    notice.dataset.action = "contact-context-notice";
    notice.dataset.operation = contactContextNotice.kind;
    notice.dataset.reason = contactContextNotice.reason;
    return notice;
  }

  function isCurrentSnapshotContext(context) {
    return context.openedRevision === snapshot.revision
      && context.openedHostGeneration === snapshot.hostGeneration;
  }

  function contactEditorCapability(editor) {
    return editor?.contactId && editor.hellolynkId.trim() === editor.expectedHelloLynkId
      ? "contact.rename" : "contact.save";
  }

  function isCurrentContactEditor(editor) {
    if (contactEditorCapability(editor) !== "contact.rename") return isCurrentSnapshotContext(editor);
    const contact = snapshot.contacts.find((item) => item.contactId === editor.contactId);
    return editor.openedHostGeneration === snapshot.hostGeneration
      && editor.ownerHelloLynkId === snapshot.subject.hellolynkId
      && editor.localDelegateId === snapshot.subject.delegateId
      && contact?.hellolynkId === editor.expectedHelloLynkId
      && contact.displayName === editor.expectedDisplayName;
  }

  function isCurrentContactInstanceEditor(editor) {
    const contact = snapshot.contacts.find((item) => item.contactId === editor.contactId);
    const instance = contact?.instances.find((item) => item.delegateId === editor.recipientDelegateId);
    return editor.openedHostGeneration === snapshot.hostGeneration
      && editor.ownerHelloLynkId === snapshot.subject.hellolynkId
      && editor.localDelegateId === snapshot.subject.delegateId
      && contact?.hellolynkId === editor.expectedHelloLynkId
      && contact.principalId === editor.expectedPrincipalId
      && instance?.displayName === editor.expectedDisplayName;
  }

  function focusContactContext(kind, contactId, recipientDelegateId = null) {
    if (kind === "instance-rename") { focusContactMore(contactId, recipientDelegateId); return; }
    queueMicrotask(() => {
      const actionId = kind === "save" ? editContactButtonId(contactId) : deleteContactButtonId(contactId);
      const target = document.getElementById(`contact-more-${contactId}-summary`)
        || document.getElementById(actionId) || document.getElementById("contacts-title") || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function renderContactSection(title, cards, emptyCopy, layout = "card-grid") {
    return node("section", `contact-section${layout === "record-list" ? " record-section" : ""}`, [
      node("h3", "contact-section-title", title),
      node("div", layout, cards.length ? cards : [node("article", "data-card", node("p", "", emptyCopy))]),
    ]);
  }

  function renderContactRequestPager() {
    const pageIndex = contactRequestPageCursors.length - 1;
    const previous = contactActionButton(
      "previous-contact-requests", localizedCopy("requests.previousPage", "上一页"),
      () => void loadContactRequestPage(pageIndex - 1),
    );
    previous.disabled = loadingContactRequestPage || pageIndex === 0;
    const next = contactActionButton(
      "load-more-contact-requests",
      loadingContactRequestPage ? localizedCopy("requests.loadingMore", "正在加载…") : localizedCopy("requests.loadMore", "下一页"),
      () => void loadContactRequestPage(pageIndex + 1),
    );
    next.disabled = loadingContactRequestPage || !snapshot.contactRequestNextCursor;
    localizedAttribute(next, "aria-label", localizedCopy("requests.loadMoreLabel", "加载下一页收到和发出的联系申请"));
    const first = contactActionButton(
      "latest-contact-requests", localizedCopy("requests.firstPage", "回到第一页"),
      () => void loadContactRequestPage(0),
    );
    first.disabled = loadingContactRequestPage || pageIndex === 0;
    return node("div", "pagination-actions", [previous,
      node("span", "", localizedCopy("requests.pageNumber", "第 {page} 页", { page: pageIndex + 1 })), next, first]);
  }

  function renderAuthorizationButton(contact, state, instance) {
    const context = {
      contactId: contact.contactId,
      recipientDelegateId: instance.delegateId,
      enabled: !instance.autonomousSendAuthorized,
      baselineAuthorized: instance.autonomousSendAuthorized,
      openedRevision: snapshot.revision,
      openedHostGeneration: snapshot.hostGeneration,
    };
    const busy = state.phase === "pending" || state.refreshing
      || actionOperationByKey.has(`authorization:${contact.contactId}:${instance.delegateId}`);
    const button = node("button", "secondary-button permission-toggle", busy
      ? localizedCopy("contacts.permissionPending", "处理中…")
      : instance.autonomousSendAuthorized ? localizedCopy("contacts.permissionRevoke", "撤销") : localizedCopy("contacts.permissionEnable", "允许"));
    button.type = "button";
    button.disabled = Boolean(busy);
    button.dataset.action = "set-contact-authorization";
    // A stable id keeps keyboard focus here across a refresh.
    button.id = `authorization-${contact.contactId}-${instance.delegateId}`;
    button.dataset.contactId = contact.contactId;
    button.dataset.delegateId = instance.delegateId;
    localizedAttribute(button, "aria-label", instance.autonomousSendAuthorized ? localizedCopy("authorization.revoke", "撤销 AI 自主收发") : localizedCopy("authorization.enable", "允许 AI 自主收发"));
    button.addEventListener("click", () => void setContactAuthorization(context));
    return button;
  }

  // Requests, relationships and blocks share one compact row, as in other
  // messengers: who, where it stands and when; the rest opens on click. Only a
  // decision-ready incoming request keeps its main action on the row.
  function renderRecordRow({ id, cardClass, recordId, avatarSource, label, status = null, time = null, body, keepOpen = false, quickAction = null }) {
    const avatar = node("span", "thread-avatar record-row-avatar", initials(avatarSource || "?"));
    avatar.setAttribute("aria-hidden", "true");
    // Status and time travel together, so a narrow row can move them under the name.
    const meta = [...(status ? [node("span", "record-row-status", status)] : []), ...(time ? [time] : [])];
    const summary = [avatar, node("strong", "record-row-name", label), ...(meta.length ? [node("span", "record-row-meta", meta)] : [])];
    const card = node("article", `data-card ${cardClass}${quickAction ? " has-quick-action" : ""}`, [
      renderContactDisclosure(id, "record-row", summary, [node("div", "record-row-body", body)], { keepOpen }),
      ...(quickAction ? [quickAction] : []),
    ]);
    card.dataset.recordId = recordId;
    return card;
  }

  // An unsettled result or an open confirmation keeps its row open.
  function recordNeedsAttention(confirming, ...states) {
    return confirming || states.some((item) => ["unknown", "failed"].includes(item.phase));
  }

  function renderContactRequestCard(request) {
    const stateKey = `request:${request.requestId}`;
    const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
    const recoveryStateKey = `request-recovery:${request.requestId}`;
    const recoveryState = actionStateByKey.get(recoveryStateKey) || { phase: "idle", code: null };
    const cancelStateKey = lifecycleStateKey("cancel-request", request.requestId);
    const cancelState = actionStateByKey.get(cancelStateKey) || { phase: "idle", code: null };
    const decisionReady = isContactRequestDecisionReady(request);
    const recoveryReady = isContactRequestRecoveryReady(request);
    const introText = typeof request.introText === "string" ? request.introText.trim() : "";
    const requestTime = node("time", "record-row-time", localeBindings.format(request.receivedAt, "datetime"));
    requestTime.setAttribute("datetime", request.receivedAt);
    const body = [
      node("p", "", request.otherHelloLynkId),
      // The requester's own words are shown as plain text only: never markup,
      // a link, or an instruction. An empty introduction leaves no placeholder.
      ...(introText ? [node("div", "request-intro", [
        node("span", "request-intro-label", localizedCopy("requests.intro", "介绍语")),
        node("p", "request-intro-text", introText),
      ])] : []),
    ];
    let quickAction = null;
    if (request.direction === "incoming" && decisionReady && canExecute("contact-request.respond")) {
      const controls = node("div", "card-actions");
      const gate = { consumed: false };
      for (const [decision, key, fallback, extraClass] of [
        ["accept", "requests.accept", "接受", "record-quick-action"],
        ["reject", "requests.reject", "拒绝", ""],
        ["block", "requests.block", "屏蔽", "danger-button"],
      ]) {
        const context = {
          requestId: request.requestId,
          baselineState: request.state,
          baselineActionReady: request.actionReady,
          baselineDecisionOutcome: request.decisionOutcome,
          baselineDecisionAction: request.decisionAction,
          decision,
          expectedState: CONTACT_REQUEST_STATE_BY_DECISION[decision],
          openedRevision: snapshot.revision,
          openedHostGeneration: snapshot.hostGeneration,
          gate,
        };
        // The row's own Accept shows the work in progress; a folded row has no other hint.
        const working = decision === "accept" && state.phase === "pending";
        const button = contactActionButton(`request-${decision}`, working ? localizedCopy("action.working", "正在处理…") : localizedCopy(key, fallback),
          () => void respondContactRequest(context), request.requestId, extraClass);
        button.id = contactRequestDecisionButtonId(request.requestId, decision);
        button.dataset.decision = decision;
        button.disabled = state.phase === "pending";
        if (decision === "accept") {
          // Every row has an Accept; its name says whose request it takes.
          if (!working) localizedAttribute(button, "aria-label", localizedCopy("requests.acceptFor", "接受 {name} 的申请",
            { name: request.otherLabel || request.otherHelloLynkId }));
          quickAction = button;
        } else controls.append(button);
      }
      body.push(controls);
    }
    if (request.direction === "incoming" && recoveryReady && canExecute("contact-request.recover-decision")) {
      const context = {
        requestId: request.requestId,
        baselineState: request.state,
        baselineActionReady: request.actionReady,
        baselineDecisionOutcome: request.decisionOutcome,
        baselineDecisionAction: request.decisionAction,
        openedRevision: snapshot.revision,
        openedHostGeneration: snapshot.hostGeneration,
        gate: { consumed: false },
      };
      const recover = contactActionButton(
        "recover-contact-request",
        recoveryState.phase === "pending" ? localizedCopy("requests.recoverWorking", "正在重新核对…") : localizedCopy("requests.recover", "重新核对状态"),
        () => void recoverContactRequestDecision(context),
        request.requestId,
      );
      recover.id = contactRequestRecoveryButtonId(request.requestId);
      recover.disabled = recoveryState.phase === "pending";
      body.push(node("div", "card-actions", [recover]));
    }
    if (request.direction === "outgoing" && request.state === "pending"
      && canExecute("contact-request.cancel") && cancelState.phase !== "unknown") {
      const cancel = contactActionButton(
        "cancel-contact-request",
        localizedCopy("requests.cancel", "取消发出的申请"),
        () => beginLifecycleConfirmation("cancel-request", request),
        request.requestId,
        "danger-button",
      );
      cancel.id = lifecycleActionButtonId("cancel-request", request.requestId);
      cancel.disabled = cancelState.phase === "pending";
      body.push(node("div", "card-actions", [cancel]));
    }
    const confirming = lifecycleConfirmation?.kind === "cancel-request" && lifecycleConfirmation.recordId === request.requestId;
    if (confirming) body.push(renderLifecycleConfirmation(lifecycleConfirmation));
    body.push(request.direction === "incoming"
      ? renderContactRequestStatus(request, state, recoveryState)
      : renderLifecycleRecordStatus(cancelState, request.state === "pending"
        ? ""
        : localizedCopy("requests.outgoingTerminal", "当前 Host 快照显示申请状态为“{state}”。取消只适用于仍在等待中的发出申请。", { state: statusCopy(request.state) })));
    const card = renderRecordRow({
      id: `request-details-${request.requestId}`,
      cardClass: "request-card",
      recordId: request.requestId,
      avatarSource: request.otherLabel,
      label: request.otherLabel || (request.direction === "outgoing"
        ? localizedCopy("requests.unknownRecipient", "未命名接收方")
        : localizedCopy("requests.unknownSender", "未命名申请人")),
      // The row's Accept already says it waits for you.
      status: quickAction ? null : request.state !== "pending"
        ? statusCopy(request.state)
        : request.direction === "outgoing"
          ? localizedCopy("requests.outgoingPending", "等待对方决定")
        : recoveryReady || request.actionReady !== true
          ? localizedCopy("requests.frozen", "等待重新核对")
          : localizedCopy("requests.pending", "等待你决定"),
      time: requestTime,
      body,
      keepOpen: recordNeedsAttention(confirming, state, recoveryState, cancelState),
      quickAction,
    });
    if (request.direction === "outgoing") {
      card.id = lifecycleRecordCardId("cancel-request", request.requestId);
      card.tabIndex = -1;
    }
    return card;
  }

  function renderRelationshipCard(relationship) {
    const state = actionStateByKey.get(lifecycleStateKey("end-relationship", relationship.relationshipId)) || { phase: "idle", code: null };
    const savedContact = deriveWorkbenchContacts(snapshot).find((contact) => contact.hellolynkId === relationship.otherHelloLynkId) || null;
    const body = [node("p", "", relationship.otherHelloLynkId)];
    const controls = node("div", "card-actions");
    if (relationship.status === "active" && savedContact) {
      const choose = contactActionButton("complete-contact", localizedCopy("contacts.complete", "选择 AI"), () => void openContactSetup(savedContact.contactId), savedContact.contactId);
      choose.disabled = !canExecute("contact.instances.list") || !canExecute("contact.instance.save");
      controls.append(choose);
    } else if (relationship.status === "active" && canExecute("contact.save")) {
      const add = contactActionButton("add-relationship-contact", localizedCopy("contacts.addRelationship", "添加并选择 AI"), () => openRelationshipContactEditor(relationship), relationship.relationshipId);
      add.id = relationshipContactButtonId(relationship.relationshipId);
      add.disabled = !canExecute("contact.instances.list") || !canExecute("contact.instance.save");
      controls.append(add);
    }
    if (relationship.status === "active" && canExecute("relationship.end") && state.phase !== "unknown") {
      const button = contactActionButton(
        "end-relationship",
        localizedCopy("relationships.end", "终止主体关系"),
        () => beginLifecycleConfirmation("end-relationship", relationship),
        relationship.relationshipId,
        "danger-button",
      );
      button.id = lifecycleActionButtonId("end-relationship", relationship.relationshipId);
      button.disabled = state.phase === "pending";
      controls.append(button);
    }
    if (controls.children.length) body.push(controls);
    const confirming = lifecycleConfirmation?.kind === "end-relationship" && lifecycleConfirmation.recordId === relationship.relationshipId;
    if (confirming) body.push(renderLifecycleConfirmation(lifecycleConfirmation));
    body.push(renderLifecycleRecordStatus(state, relationship.status === "ended"
      ? localizedCopy("relationships.ended", "关系已终止；双方本机已有历史不会因此删除。") : ""));
    const card = renderRecordRow({
      id: `relationship-details-${relationship.relationshipId}`,
      cardClass: "relationship-card",
      recordId: relationship.relationshipId,
      avatarSource: relationship.otherLabel,
      label: relationship.otherLabel || localizedCopy("relationships.unknown", "未命名关系主体"),
      status: statusCopy(relationship.status),
      body,
      keepOpen: recordNeedsAttention(confirming, state),
    });
    card.id = lifecycleRecordCardId("end-relationship", relationship.relationshipId);
    card.tabIndex = -1;
    return card;
  }

  function renderBlockCard(block) {
    const state = actionStateByKey.get(lifecycleStateKey("remove-block", block.blockId)) || { phase: "idle", code: null };
    const body = [node("p", "", block.otherHelloLynkId)];
    if (canExecute("block.remove") && state.phase !== "unknown") {
      const button = contactActionButton(
        "remove-block",
        localizedCopy("blocks.remove", "解除屏蔽"),
        () => beginLifecycleConfirmation("remove-block", block),
        block.blockId,
        "danger-button",
      );
      button.id = lifecycleActionButtonId("remove-block", block.blockId);
      button.disabled = state.phase === "pending";
      body.push(node("div", "card-actions", [button]));
    }
    const confirming = lifecycleConfirmation?.kind === "remove-block" && lifecycleConfirmation.recordId === block.blockId;
    if (confirming) body.push(renderLifecycleConfirmation(lifecycleConfirmation));
    body.push(renderLifecycleRecordStatus(state, ""));
    const card = renderRecordRow({
      id: `block-details-${block.blockId}`,
      cardClass: "block-card",
      recordId: block.blockId,
      avatarSource: block.otherLabel,
      label: block.otherLabel || localizedCopy("blocks.unknown", "未命名被屏蔽主体"),
      status: statusCopy(block.status),
      body,
      keepOpen: recordNeedsAttention(confirming, state),
    });
    card.id = lifecycleRecordCardId("remove-block", block.blockId);
    card.tabIndex = -1;
    return card;
  }

  function renderLifecycleRecordStatus(state, boundary) {
    if (state.phase !== "idle") return actionStatus(state, {
      unknownCopy: localizedCopy("lifecycle.unknown", "结果未知。此精确对象已锁定；刷新只会读取权威快照，不会重放操作。"),
    });
    const status = node("p", "record-boundary", boundary);
    status.setAttribute("role", "status");
    return status;
  }

  function isContactRequestDecisionReady(request) {
    return request?.state === "pending"
      && request.humanOnly === true
      && request.actionReady === true
      && request.decisionOutcome === null
      && request.decisionAction === null;
  }

  function isContactRequestRecoveryReady(request) {
    return Boolean(request?.state === "pending"
      && request.humanOnly === true
      && request.actionReady === false
      && ((request.decisionOutcome === "unknown" && CONTACT_REQUEST_STATE_BY_DECISION[request.decisionAction])
        || (request.decisionOutcome === "recovery-required" && request.decisionAction === null)));
  }

  function renderContactRequestStatus(request, state, recoveryState) {
    let visibleState = state;
    let message = null;
    if (request.state !== "pending") {
      visibleState = { phase: "ok", code: null };
      message = recoveryState.phase === "ok"
        ? localizedCopy("requests.recoveredTerminal", "已核对: 申请已进入“{state}”状态，没有重放任何决定。", { state: statusCopy(request.state) })
        : localizedCopy("requests.terminal", "当前 Host 快照显示申请状态为“{state}”；不再提供决定或恢复操作。", { state: statusCopy(request.state) });
    } else if (recoveryState.phase === "pending") {
      visibleState = recoveryState;
      message = localizedCopy("requests.recoverChecking", "正在通过 Host 重新核对远端状态；不会重放任何决定。");
    } else if (recoveryState.phase === "failed") {
      visibleState = recoveryState;
      message = recoveryState.code === "host_app_revision_conflict"
        ? localizedCopy("action.status.conflict", "本机数据已在另一处发生变化。已刷新最新状态，没有覆盖新内容。")
        : localizedCopy("requests.recoverFailed", "重新核对失败，没有重放决定。你可以再次手动核对。");
    } else if (recoveryState.phase === "unknown") {
      visibleState = recoveryState;
      message = localizedCopy("requests.recoverUnknown", "重新核对结果未知，没有自动重试；申请仍保持冻结。");
    } else if (recoveryState.phase === "ok" && isContactRequestDecisionReady(request)) {
      visibleState = recoveryState;
      message = localizedCopy("requests.recoveredPending", "已核对: 申请仍在等待决定。若要继续，请重新选择一次操作。");
    } else if (request.decisionOutcome === "unknown") {
      visibleState = { phase: "unknown", code: "workbench_command_outcome_unknown" };
      message = localizedCopy(`requests.decisionUnknown.${request.decisionAction}`, "上一次决定的结果仍未确认。为避免重复决定，所有决定操作已冻结；请显式重新核对远端状态。");
    } else if (request.decisionOutcome === "recovery-required") {
      visibleState = { phase: "unknown", code: "workbench_command_outcome_unknown" };
      message = localizedCopy("requests.recoveryRequired", "这条申请需要重新核对远端状态后才能继续。当前没有猜测之前的决定，所有决定操作保持冻结。");
    } else if (request.state === "pending" && request.actionReady !== true) {
      visibleState = { phase: "unknown", code: "workbench_contact_request_not_actionable" };
      message = localizedCopy("requests.notActionable", "当前 Host 快照未确认这条申请可以操作。为避免重复决定，所有决定操作保持冻结。");
    }
    const status = actionStatus(visibleState);
    if (message !== null) localizedText(status, localizedTrim(message));
    status.id = contactRequestStatusId(request.requestId);
    status.tabIndex = -1;
    status.dataset.recordId = request.requestId;
    return status;
  }

  function lifecycleDefinition(kind) {
    if (kind === "cancel-request") return {
      capability: "contact-request.cancel",
      command: HELLOLYNK_WORKBENCH_COMMAND_TYPES.cancelContactRequest,
      payloadKey: "requestId",
      title: localizedCopy("requests.cancelConfirmTitle", "确认取消这条发出的联系申请？"),
      body: localizedCopy("requests.cancelConfirmBody", "只有仍在等待中的发出申请可以取消。取消不会屏蔽对方，也不会删除本机已有记录。"),
      confirmCopy: localizedCopy("requests.cancelConfirm", "确认取消申请"),
    };
    if (kind === "end-relationship") return {
      capability: "relationship.end",
      command: HELLOLYNK_WORKBENCH_COMMAND_TYPES.endRelationship,
      payloadKey: "relationshipId",
      title: localizedCopy("relationships.endConfirmTitle", "确认终止这段主体关系？"),
      body: localizedCopy("relationships.endConfirmBody", "终止后双方不能再以该关系发送普通消息，但不会删除双方各自本机已有的聊天历史。删除本机联系人是另一个独立操作。"),
      confirmCopy: localizedCopy("relationships.endConfirm", "确认终止主体关系"),
    };
    if (kind === "remove-block") return {
      capability: "block.remove",
      command: HELLOLYNK_WORKBENCH_COMMAND_TYPES.removeBlock,
      payloadKey: "blockId",
      title: localizedCopy("blocks.removeConfirmTitle", "确认解除对该主体的屏蔽？"),
      body: localizedCopy("blocks.removeConfirmBody", "解除屏蔽不会自动恢复主体关系、本机联系人或任何 AI 自主授权；如需恢复，必须分别重新建立。"),
      confirmCopy: localizedCopy("blocks.removeConfirm", "确认解除屏蔽"),
    };
    return null;
  }

  function beginLifecycleConfirmation(kind, record) {
    const definition = lifecycleDefinition(kind);
    const recordId = lifecycleRecordId(kind, record);
    const state = actionStateByKey.get(lifecycleStateKey(kind, recordId));
    if (!definition || !recordId || !canExecute(definition.capability)
      || ["pending", "unknown"].includes(state?.phase)
      || !lifecycleRecordActionable(kind, record)) return;
    clearResolvedConfirmation = null;
    lifecycleConfirmation = {
      kind,
      recordId,
      baselineTuple: lifecycleRecordTuple(kind, record),
      openedSnapshotKey: lifecycleSnapshotKey(),
      attempt: 0,
    };
    render();
    queueMicrotask(() => document.getElementById(lifecycleCancelButtonId(kind, recordId))?.focus({ preventScroll: true }));
  }

  function renderLifecycleConfirmation(context) {
    const definition = lifecycleDefinition(context.kind);
    const stateKey = lifecycleStateKey(context.kind, context.recordId);
    const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
    const titleId = `${lifecycleDialogId(context.kind, context.recordId)}-title`;
    const bodyId = `${lifecycleDialogId(context.kind, context.recordId)}-body`;
    const title = node("strong", "", definition.title);
    title.id = titleId;
    const body = node("p", "", definition.body);
    body.id = bodyId;
    const dialog = node("div", "delete-confirmation lifecycle-confirmation", [title, body]);
    dialog.id = lifecycleDialogId(context.kind, context.recordId);
    dialog.tabIndex = -1;
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-labelledby", titleId);
    dialog.setAttribute("aria-describedby", bodyId);
    const cancel = contactActionButton("cancel-lifecycle-confirmation", localizedCopy("action.cancel", "取消"), () => {
      closeLifecycleConfirmation(context, { restoreFocus: true });
    });
    cancel.id = lifecycleCancelButtonId(context.kind, context.recordId);
    cancel.disabled = state.phase === "pending";
    const expectedAttempt = context.attempt;
    const confirm = contactActionButton(
      `confirm-${context.kind}`,
      state.phase === "pending" ? localizedCopy("action.working", "正在请求 Host…") : definition.confirmCopy,
      () => void executeLifecycleConfirmation(context, expectedAttempt),
      context.recordId,
      "danger-button",
    );
    confirm.id = lifecycleConfirmButtonId(context.kind, context.recordId);
    confirm.disabled = state.phase === "pending" || state.phase === "unknown";
    dialog.append(node("div", "card-actions", [cancel, confirm]), renderLifecycleRecordStatus(state, ""));
    return dialog;
  }

  async function executeLifecycleConfirmation(context, expectedAttempt) {
    if (!context || lifecycleConfirmation !== context || context.attempt !== expectedAttempt) return;
    const definition = lifecycleDefinition(context.kind);
    const stateKey = lifecycleStateKey(context.kind, context.recordId);
    const state = actionStateByKey.get(stateKey);
    if (!definition || ["pending", "unknown"].includes(state?.phase)
      || !canExecute(definition.capability) || !isCurrentLifecycleContext(context)) {
      if (state?.phase !== "pending" && state?.phase !== "unknown") {
        actionStateByKey.set(stateKey, { phase: "failed", code: "host_app_revision_conflict" });
        lifecycleConfirmation = null;
        render();
        focusLifecycleOutcome(context.kind, context.recordId);
      }
      return;
    }
    const shouldRenderCompletion = () => lifecycleConfirmation === context
      && view.section === "contacts" && contactWorkspaceMode === "requests" && !selectedContactId;
    context.attempt += 1;
    const pending = runAction(
      stateKey,
      definition.command,
      { [definition.payloadKey]: context.recordId },
      { lockUnknown: true, capability: definition.capability, shouldRenderCompletion },
    );
    queueMicrotask(() => document.getElementById(lifecycleDialogId(context.kind, context.recordId))?.focus({ preventScroll: true }));
    const result = await pending;
    if (result === undefined) return;
    const finalState = actionStateByKey.get(stateKey);
    if (finalState?.phase === "unknown") {
      actionStateByKey.set(stateKey, {
        ...finalState,
        unknownEvidence: { kind: "lifecycle", operation: context.kind, recordId: context.recordId },
      });
    }
    const renderCompletion = shouldRenderCompletion();
    if (result?.ok && lifecycleConfirmation === context) lifecycleConfirmation = null;
    if (renderCompletion) {
      const preserveInputFocus = isTextSelectionControl(document.activeElement);
      render();
      if (!preserveInputFocus) focusLifecycleOutcome(context.kind, context.recordId);
    }
  }

  function reconcileLifecycleUnknownLocks() {
    for (const [stateKey, state] of actionStateByKey.entries()) {
      const evidence = state?.phase === "unknown" ? state.unknownEvidence : null;
      if (evidence?.kind !== "lifecycle") continue;
      // Missing block metadata is proof only when this read can actually list
      // blocks. A cold/stale or local-only projection may contain no records.
      if (evidence.operation === "remove-block" && (!hasWorkbenchCapability(snapshot, "blocks.read")
        || (snapshot.relationshipMetadataState != null && snapshot.relationshipMetadataState !== "fresh"))) continue;
      const record = currentLifecycleRecord(evidence.operation, evidence.recordId);
      if (lifecycleOperationProved(evidence.operation, record)) {
        actionStateByKey.set(stateKey, { phase: "ok", code: null });
      } else if (record && !lifecycleRecordActionable(evidence.operation, record)) {
        actionStateByKey.set(stateKey, { phase: "failed", code: "host_app_state_conflict" });
      }
    }
  }

  function reconcileLifecycleConfirmation() {
    const context = lifecycleConfirmation;
    if (!context) return null;
    const definition = lifecycleDefinition(context.kind);
    const state = actionStateByKey.get(lifecycleStateKey(context.kind, context.recordId)) || { phase: "idle" };
    if (state.phase === "ok") {
      lifecycleConfirmation = null;
      return { kind: context.kind, recordId: context.recordId };
    }
    if (state.phase === "unknown") return null;
    if (!definition || !canExecute(definition.capability) || !isCurrentLifecycleContext(context)) {
      if (state.phase !== "pending") {
        actionStateByKey.set(lifecycleStateKey(context.kind, context.recordId), {
          phase: "failed",
          code: "host_app_revision_conflict",
        });
        lifecycleConfirmation = null;
        return { kind: context.kind, recordId: context.recordId };
      }
    }
    return null;
  }

  function closeLifecycleConfirmation(context, { restoreFocus = false } = {}) {
    if (!context || lifecycleConfirmation !== context) return;
    const state = actionStateByKey.get(lifecycleStateKey(context.kind, context.recordId));
    if (state?.phase === "pending") return;
    lifecycleConfirmation = null;
    render();
    if (restoreFocus) focusLifecycleOutcome(context.kind, context.recordId);
  }

  function isCurrentLifecycleContext(context) {
    const record = currentLifecycleRecord(context.kind, context.recordId);
    return Boolean(record
      && context.openedSnapshotKey === lifecycleSnapshotKey()
      && context.baselineTuple === lifecycleRecordTuple(context.kind, record)
      && lifecycleRecordActionable(context.kind, record));
  }

  function lifecycleSnapshotKey() {
    return JSON.stringify([
      snapshot.hostGeneration,
      snapshot.revision,
      snapshot.source.mode,
      snapshot.source.transport,
      snapshot.source.clientId,
      snapshot.subject.principalId,
      snapshot.subject.delegateId,
      snapshot.subject.hostInstallationId,
    ]);
  }

  function currentLifecycleRecord(kind, recordId) {
    if (kind === "cancel-request") return snapshot.outgoingContactRequests.find((item) => item.requestId === recordId) || null;
    if (kind === "end-relationship") return snapshot.relationships.find((item) => item.relationshipId === recordId) || null;
    if (kind === "remove-block") return snapshot.blocks.find((item) => item.blockId === recordId) || null;
    return null;
  }

  function lifecycleRecordActionable(kind, record) {
    if (!record) return false;
    if (kind === "cancel-request") return record.direction === "outgoing" && record.state === "pending";
    if (kind === "end-relationship") return record.status === "active";
    if (kind === "remove-block") return record.status === "active";
    return false;
  }

  function lifecycleOperationProved(kind, record) {
    if (kind === "cancel-request") return record?.state === "cancelled";
    if (kind === "end-relationship") return record?.status === "ended";
    if (kind === "remove-block") return record == null;
    return false;
  }

  function lifecycleRecordTuple(kind, record) {
    if (kind === "cancel-request") return JSON.stringify([record.requestId, record.direction, record.otherHelloLynkId, record.state]);
    if (kind === "end-relationship") return JSON.stringify([record.relationshipId, record.otherHelloLynkId, record.status, record.updatedAt]);
    if (kind === "remove-block") return JSON.stringify([record.blockId, record.otherHelloLynkId, record.status, record.createdAt]);
    return "";
  }

  function lifecycleRecordId(kind, record) {
    if (kind === "cancel-request") return record?.requestId || null;
    if (kind === "end-relationship") return record?.relationshipId || null;
    if (kind === "remove-block") return record?.blockId || null;
    return null;
  }

  function focusLifecycleOutcome(kind, recordId) {
    queueMicrotask(() => {
      const target = document.getElementById(lifecycleActionButtonId(kind, recordId))
        || document.getElementById(lifecycleRecordCardId(kind, recordId))
        || document.getElementById("contacts-title")
        || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function lifecycleStateKey(kind, recordId) { return `lifecycle:${kind}:${recordId}`; }
  function lifecycleActionButtonId(kind, recordId) { return `lifecycle-${kind}-${recordId}`; }
  function lifecycleRecordCardId(kind, recordId) { return `lifecycle-card-${kind}-${recordId}`; }
  function lifecycleDialogId(kind, recordId) { return `lifecycle-dialog-${kind}-${recordId}`; }
  function lifecycleCancelButtonId(kind, recordId) { return `lifecycle-cancel-${kind}-${recordId}`; }
  function lifecycleConfirmButtonId(kind, recordId) { return `lifecycle-confirm-${kind}-${recordId}`; }
  function editContactNameButtonId(contactId) { return `edit-contact-name-${contactId}`; }

  function contactActionButton(action, label, handler, recordId = "", extraClass = "") {
    const button = node("button", `secondary-button ${extraClass}`.trim(), label);
    button.type = "button";
    button.dataset.action = action;
    if (recordId) button.dataset.recordId = recordId;
    button.addEventListener("click", handler);
    return button;
  }

  function openContactEditor(contact = null, returnFocusId = null) {
    if (!canExecute(contact ? "contact.rename" : "contact.save")) return;
    const currentContact = contact?.contactId
      ? snapshot.contacts.find((item) => item.contactId === contact.contactId)
      : null;
    if (contact && !currentContact) return;
    const sourceContact = currentContact || null;
    contactContextNotice = null;
    actionStateByKey.delete(contactSaveStateKey(sourceContact?.contactId || null));
    deleteConfirmation = null;
    contactEditor = {
      contactId: sourceContact?.contactId || null,
      hellolynkId: sourceContact?.hellolynkId || "",
      displayName: sourceContact?.displayName || "",
      expectedDisplayName: sourceContact?.displayName || "",
      expectedHelloLynkId: sourceContact?.hellolynkId || "",
      ownerHelloLynkId: snapshot.subject.hellolynkId,
      localDelegateId: snapshot.subject.delegateId,
      relationshipId: null,
      identityLocked: false,
      returnFocusId: returnFocusId || (sourceContact?.contactId ? editContactButtonId(sourceContact.contactId) : "new-contact-button"),
      openedRevision: snapshot.revision,
      openedHostGeneration: snapshot.hostGeneration,
    };
    render();
    queueMicrotask(() => document.getElementById("contact-hellolynk-id")?.focus({ preventScroll: true }));
  }

  function openRelationshipContactEditor(relationship) {
    if (!canExecute("contact.save")) return;
    const current = snapshot.relationships.find((item) => item.relationshipId === relationship.relationshipId);
    if (!current || current.status !== "active"
      || snapshot.contacts.some((contact) => contact.hellolynkId === current.otherHelloLynkId)) return;
    contactContextNotice = null;
    actionStateByKey.delete(contactSaveStateKey(null));
    deleteConfirmation = null;
    contactEditor = {
      contactId: null,
      hellolynkId: current.otherHelloLynkId,
      displayName: current.otherLabel || "",
      relationshipId: current.relationshipId,
      identityLocked: true,
      returnFocusId: relationshipContactButtonId(current.relationshipId),
      openedRevision: snapshot.revision,
      openedHostGeneration: snapshot.hostGeneration,
    };
    navigateContactMode("add");
    render();
    queueMicrotask(() => document.getElementById("contact-display-name")?.focus({ preventScroll: true }));
  }

  function chooseSelfInstance(result) {
    if (!canExecute("contact.save") || !canExecute("contact.instances.list") || !canExecute("contact.instance.save")
      || ["pending", "unknown"].includes(actionStateByKey.get(contactSaveStateKey(null))?.phase)
      || !result?.hellolynkId
      || result.hellolynkId !== snapshot.subject.hellolynkId
      || !isCurrentPrincipalDiscoveryTarget(result)
      || !principalDiscovery.results.some((item) => item.targetRef === result.targetRef
        && item.hellolynkId === result.hellolynkId)) return;
    contactContextNotice = null;
    actionStateByKey.delete(contactSaveStateKey(null));
    deleteConfirmation = null;
    const selfName = copy("discovery.selfName", "我");
    const usedNames = new Set(snapshot.contacts.map((contact) => contact.displayName.normalize("NFKC").trim().replace(/\s+/gu, " ").toLocaleLowerCase("und")));
    let displayName = selfName;
    for (let suffix = 2; usedNames.has(displayName.toLocaleLowerCase("und")); suffix++) displayName = `${selfName}_${suffix}`;
    contactEditor = {
      contactId: null,
      hellolynkId: result.hellolynkId,
      displayName,
      relationshipId: null,
      openSetupAfterSave: true,
      identityLocked: true,
      returnFocusId: null,
      openedRevision: snapshot.revision,
      openedHostGeneration: snapshot.hostGeneration,
    };
    void saveContact(contactEditor);
  }

  function renderContactEditor() {
    const editor = contactEditor;
    const editing = Boolean(editor.contactId);
    const stateKey = contactSaveStateKey(editor.contactId);
    const state = actionStateByKey.get(stateKey) || { phase: "idle", code: null };
    if (editor.openSetupAfterSave) {
      const card = node("article", "data-card", [
        node("h3", "", localizedCopy("discovery.selfInstances", "我的其他 AI")),
        node("p", "", editor.hellolynkId),
      ]);
      card.dataset.action = "self-instance-loading";
      card.setAttribute("aria-busy", state.phase === "pending" ? "true" : "false");
      if (state.phase === "pending") {
        const status = node("p", "action-status is-pending", localizedCopy("discovery.loadingInstances", "正在加载 AI…"));
        status.setAttribute("role", "status");
        card.append(status);
      } else card.append(contactFlowActionStatus(state));
      if (state.phase === "failed") {
        card.append(contactActionButton("retry-self-instance", localizedCopy("action.retry", "重试"), () => void saveContact(editor)));
        card.append(contactActionButton("cancel-self-instance", localizedCopy("action.cancel", "取消"), () => {
          if (contactEditor !== editor) return;
          contactEditor = null;
          render();
        }));
      }
      return card;
    }
    const form = node("form", "contact-editor data-card");
    form.dataset.action = editing ? "edit-contact-form" : "new-contact-form";
    if (editing) form.append(node("h3", "", localizedCopy("contacts.editTitle", "修改联系人")));
    if (editor.identityLocked) {
      form.append(node("div", "contact-known-identity", [
        node("strong", "", editor.displayName || localizedCopy("relationships.unknown", "未命名联系人")),
        node("span", "", editor.hellolynkId),
      ]));
    } else {
      form.append(contactField(editor, "contact-hellolynk-id", localizedCopy("contacts.hellolynkId", "HelloLynk ID"), "hellolynkId", 200, "text", true));
    }
    form.append(contactField(editor, "contact-display-name", localizedCopy("contacts.displayName", "备注名称"), "displayName", 160, "text", true));
    const cancel = contactActionButton("cancel-contact-editor", localizedCopy("action.cancel", "取消"), () => {
      if (contactEditor !== editor) return;
      actionStateByKey.delete(stateKey);
      contactEditor = null;
      render();
      focusContactEditorReturn(editor);
    });
    const submit = node("button", "primary-button form-submit", state.phase === "pending" ? localizedCopy("contacts.saving", "正在保存…") : localizedCopy("action.save", "保存"));
    // DSH deliberately embeds the Workbench without `allow-forms`. Keep the
    // strict sandbox and make this local command explicit instead of relying
    // on the browser's native form-submission path.
    submit.type = "button";
    submit.disabled = state.phase === "pending" || state.phase === "unknown";
    submit.dataset.action = "save-contact";
    form.append(node("div", "card-actions", [cancel, submit]), editor.identityLocked ? contactFlowActionStatus(state) : actionStatus(state));
    submit.addEventListener("click", (event) => {
      event.preventDefault();
      void saveContact(editor);
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void saveContact(editor);
    });
    form.addEventListener("keydown", (event) => {
      if (event.target?.tagName !== "INPUT" || event.key !== "Enter" || event.shiftKey
        || event.repeat || event.isComposing || event.keyCode === 229) return;
      event.preventDefault();
      void saveContact(editor);
    });
    return form;
  }

  function contactField(editor, id, labelCopy, key, maximum, type, required) {
    const label = node("label", "form-field");
    label.htmlFor = id;
    const input = node("input", "form-input");
    input.id = id;
    input.type = type;
    input.maxLength = maximum;
    input.required = required;
    input.value = editor[key];
    input.addEventListener("input", () => {
      if (contactEditor !== editor) return;
      editor[key] = input.value;
    });
    label.append(node("span", "form-label", labelCopy), input);
    return label;
  }

  async function saveContact(editor) {
    const originHash = location.hash;
    const originEpoch = accountViewEpoch;
    const originContactId = selectedContactId;
    const originWorkspaceMode = contactWorkspaceMode;
    // A completed save owns only its original editor, not a replacement draft
    // or another contact the user opened while the command was pending.
    const shouldRenderCompletion = () => originEpoch === accountViewEpoch && location.hash === originHash
      && view.section === "contacts" && selectedContactId === originContactId && contactWorkspaceMode === originWorkspaceMode
      && (contactEditor === editor || contactEditor === null);
    if (!editor || contactEditor !== editor || !canExecute(contactEditorCapability(editor))) return;
    const stateKey = contactSaveStateKey(editor.contactId);
    if (!isCurrentContactEditor(editor)) {
      closeContactContext("save", editor.contactId, "conflict");
      render();
      focusContactContext("save", editor.contactId);
      return;
    }
    const hellolynkId = editor.hellolynkId.trim();
    const displayName = editor.displayName.normalize("NFKC").trim().replace(/\s+/gu, " ");
    if (!hellolynkId || !displayName) {
      actionStateByKey.set(stateKey, { phase: "failed", code: "workbench_contact_required_fields" });
      render();
      return;
    }
    if (!HELLOLYNK_ID_PATTERN.test(hellolynkId)) {
      actionStateByKey.set(stateKey, { phase: "failed", code: "workbench_contact_hellolynk_id_invalid" });
      render();
      queueMicrotask(() => {
        const input = document.getElementById("contact-hellolynk-id");
        input?.setAttribute("aria-invalid", "true");
        input?.focus({ preventScroll: true });
      });
      return;
    }
    const payload = {
      contactId: editor.contactId,
      hellolynkId,
      displayName,
    };
    const localRename = contactEditorCapability(editor) === "contact.rename";
    const commandType = localRename ? HELLOLYNK_WORKBENCH_COMMAND_TYPES.renameContact : HELLOLYNK_WORKBENCH_COMMAND_TYPES.saveContact;
    const commandPayload = localRename ? {
      contactId: editor.contactId, displayName,
      expectedDisplayName: editor.expectedDisplayName, expectedHelloLynkId: editor.expectedHelloLynkId,
    } : payload;
    const result = await runAction(stateKey, commandType, commandPayload, {
      lockUnknown: true,
      shouldRenderCompletion,
      onConfirmed: localRename ? () => {
        // The Host has durably saved this exact note. Show it now instead of
        // waiting for unrelated snapshot/cloud reads. Do not overwrite a newer
        // observed edit, and retain the action lock until a fresh read applies.
        actionStateByKey.get(stateKey).localNoteConfirmed = true;
        if (isCurrentContactEditor(editor)) snapshot = {
          ...snapshot,
          contacts: snapshot.contacts.map((contact) => contact.contactId === editor.contactId
            ? { ...contact, displayName } : contact),
        };
        if (contactEditor === editor) contactEditor = null;
        if (contactContextNotice?.stateKey === stateKey) contactContextNotice = null;
        if (shouldRenderCompletion()) {
          render();
          focusContactEditorReturn(editor);
        }
      } : null,
      unknownEvidence: editor.contactId ? {
        kind: "contact-save", ...payload,
        baselineRevision: snapshot.revision,
        hostGeneration: snapshot.hostGeneration,
        ownerHelloLynkId: snapshot.subject.hellolynkId,
        localDelegateId: snapshot.subject.delegateId,
      } : null,
    });
    if (result === undefined || originEpoch !== accountViewEpoch) return;
    const finalState = actionStateByKey.get(stateKey);
    if (result?.ok) {
      if (contactEditor === editor) contactEditor = null;
      if (contactContextNotice?.stateKey === stateKey) contactContextNotice = null;
    } else if (contactEditor === editor && result?.error?.code === "host_app_revision_conflict") {
      closeContactContext("save", editor.contactId, "conflict");
    } else if (contactEditor === editor && finalState?.phase === "unknown") {
      closeContactContext("save", editor.contactId, "unknown");
    }
    if (!shouldRenderCompletion()) return;
    render();
    if (result?.ok) {
      const savedContact = deriveWorkbenchContacts(snapshot).find((contact) => contact.hellolynkId === hellolynkId) || null;
      if ((editor.relationshipId || editor.openSetupAfterSave) && savedContact
        && originEpoch === accountViewEpoch && location.hash === originHash) void openContactSetup(savedContact.contactId);
      else focusContactEditorReturn(editor);
    }
    else if (result?.error?.code === "host_app_revision_conflict" || finalState?.phase === "unknown") focusContactContext("save", editor.contactId);
  }

  function focusContactEditorReturn(editor) {
    queueMicrotask(() => {
      const target = (editor?.contactId ? document.getElementById(`contact-more-${editor.contactId}-summary`) : null)
        || document.getElementById(editor?.returnFocusId)
        || document.getElementById("contacts-title")
        || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  async function openContactSetup(contactId) {
    const contact = deriveWorkbenchContacts(snapshot).find((item) => item.contactId === contactId);
    if (!contact || !canExecute("contact.instances.list") || !canExecute("contact.instance.save")) return;
    contactInstancePickerId = contact.contactId;
    detailsOpen = false;
    contactEditor = null;
    contactInstanceEditor = null;
    navigateContact(contact.contactId);
    await listContactInstances(contact);
  }

  function relationshipContactButtonId(relationshipId) {
    return `add-relationship-contact-${relationshipId}`;
  }

  function beginDeleteContact(contact) {
    if (!canExecute("contact.delete")) return;
    const currentContact = snapshot.contacts.find((item) => item.contactId === contact.contactId);
    if (!currentContact) return;
    contactContextNotice = null;
    actionStateByKey.delete(`delete:${currentContact.contactId}`);
    deleteConfirmation = {
      contactId: currentContact.contactId,
      openedRevision: snapshot.revision,
      openedHostGeneration: snapshot.hostGeneration,
    };
    contactEditor = null;
    render();
    queueMicrotask(() => document.getElementById(deleteContactCancelButtonId(contact.contactId))?.focus({ preventScroll: true }));
  }

  function renderDeleteConfirmation(contact, confirmationContext) {
    const titleId = `delete-contact-title-${contact.contactId}`;
    const bodyId = `delete-contact-body-${contact.contactId}`;
    const title = node("strong", "", localizedCopy("contacts.deleteConfirmTitle", "确认只删除这台电脑上的联系人？"));
    title.id = titleId;
    const body = node("p", "", localizedCopy("contacts.deleteConfirmBody", "这不会解除云端主体关系，也不会屏蔽对方。删除后，旧的联系人授权将不能继续使用。"));
    body.id = bodyId;
    const confirmation = node("div", "delete-confirmation", [
      title,
      body,
    ]);
    confirmation.id = deleteContactDialogId(contact.contactId);
    confirmation.tabIndex = -1;
    confirmation.setAttribute("role", "dialog");
    confirmation.setAttribute("aria-labelledby", titleId);
    confirmation.setAttribute("aria-describedby", bodyId);
    const cancel = contactActionButton("cancel-delete-contact", localizedCopy("action.cancel", "取消"), () => {
      if (deleteConfirmation !== confirmationContext) return;
      deleteConfirmation = null;
      render();
      focusContactMore(contact.contactId);
    });
    cancel.id = deleteContactCancelButtonId(contact.contactId);
    const confirm = contactActionButton("confirm-delete-contact", localizedCopy("contacts.deleteConfirm", "确认删除本机联系人"), () => void deleteContact(confirmationContext), contact.contactId, "danger-button");
    const pending = actionStateByKey.get(`delete:${contact.contactId}`)?.phase === "pending";
    confirm.id = deleteContactConfirmButtonId(contact.contactId);
    confirm.disabled = pending;
    cancel.disabled = pending;
    confirmation.append(node("div", "card-actions", [cancel, confirm]));
    return confirmation;
  }

  async function deleteContact(confirmationContext) {
    if (!confirmationContext || deleteConfirmation !== confirmationContext || !canExecute("contact.delete")) return;
    const contactId = confirmationContext.contactId;
    const stateKey = `delete:${contactId}`;
    if (actionStateByKey.get(stateKey)?.phase === "pending") return;
    if (!isCurrentSnapshotContext(confirmationContext)) {
      closeContactContext("delete", contactId, "conflict");
      render();
      focusContactContext("delete", contactId);
      return;
    }
    const actionEpoch = accountViewEpoch;
    const pending = runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.deleteContact, { contactId }, { lockUnknown: true });
    queueMicrotask(() => {
      if (actionEpoch !== accountViewEpoch) return;
      document.getElementById(deleteContactDialogId(contactId))?.focus({ preventScroll: true });
    });
    const result = await pending;
    // The command may already have completed for the original account. Only
    // retire its UI continuation; never project it into a replacement account.
    if (actionEpoch !== accountViewEpoch || result === undefined) return;
    const finalState = actionStateByKey.get(stateKey);
    const contactStillExists = snapshot.contacts.some((item) => item.contactId === contactId);
    if (result?.ok) {
      if (deleteConfirmation === confirmationContext) deleteConfirmation = null;
      contactContextNotice = null;
    } else if (result?.error?.code === "host_app_revision_conflict") {
      closeContactContext("delete", contactId, "conflict");
    } else if (finalState?.phase === "unknown" && contactStillExists) {
      closeContactContext("delete", contactId, "unknown");
    } else if (finalState?.phase === "unknown") {
      actionStateByKey.set(stateKey, { phase: "ok", code: null });
      if (deleteConfirmation === confirmationContext) deleteConfirmation = null;
      contactContextNotice = null;
    }
    render();
    queueMicrotask(() => {
      if (actionEpoch !== accountViewEpoch) return;
      const preferredId = result?.ok
        ? "contacts-title"
        : result?.error?.code === "host_app_revision_conflict"
          ? `contact-more-${contactId}-summary`
          : finalState?.phase === "unknown"
            ? `contact-more-${contactId}-summary`
            : deleteContactConfirmButtonId(contactId);
      const target = document.getElementById(preferredId) || document.getElementById("contacts-title") || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function deleteContactButtonId(contactId) { return `delete-contact-${contactId}`; }
  function editContactButtonId(contactId) { return editContactNameButtonId(contactId); }
  function deleteContactCancelButtonId(contactId) { return `cancel-delete-contact-${contactId}`; }
  function deleteContactConfirmButtonId(contactId) { return `confirm-delete-contact-${contactId}`; }
  function deleteContactDialogId(contactId) { return `delete-contact-dialog-${contactId}`; }

  async function respondContactRequest(context) {
    if (!context || context.gate.consumed || !canExecute("contact-request.respond") || !isCurrentSnapshotContext(context)) return;
    const currentRequest = snapshot.contactRequests.find((item) => item.requestId === context.requestId);
    if (!isCurrentContactRequestContext(context, currentRequest) || !isContactRequestDecisionReady(currentRequest)) return;
    const stateKey = `request:${context.requestId}`;
    if (actionStateByKey.get(stateKey)?.phase === "pending") return;
    const shouldRenderCompletion = () => view.section === "contacts"
      && contactWorkspaceMode === "requests" && !selectedContactId;
    context.gate.consumed = true;
    const result = await runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.respondContactRequest, {
      requestId: context.requestId,
      decision: context.decision,
    }, { lockUnknown: false, shouldRenderCompletion });
    if (result === undefined) return;
    const nextRequest = snapshot.contactRequests.find((item) => item.requestId === context.requestId);
    const state = actionStateByKey.get(stateKey);
    if (state?.phase === "unknown") {
      actionStateByKey.set(stateKey, nextRequest?.state === context.expectedState
        ? { phase: "ok", code: null }
        : { ...state, unknownEvidence: { kind: "contact-request", requestId: context.requestId, expectedState: context.expectedState } });
      if (shouldRenderCompletion()) render();
    }
    if (!shouldRenderCompletion()) return;
    const knownFailureStillActionable = result?.ok === false
      && result.error.outcome !== "unknown"
      && result.error.code !== "host_app_revision_conflict"
      && isCurrentSnapshotContext(context)
      && isCurrentContactRequestContext(context, nextRequest)
      && isContactRequestDecisionReady(nextRequest);
    focusContactRequestOutcome(context.requestId, knownFailureStillActionable ? context.decision : null);
  }

  async function recoverContactRequestDecision(context) {
    if (!context || context.gate.consumed || !canExecute("contact-request.recover-decision") || !isCurrentSnapshotContext(context)) return;
    const currentRequest = snapshot.contactRequests.find((item) => item.requestId === context.requestId);
    if (!isCurrentContactRequestContext(context, currentRequest) || !isContactRequestRecoveryReady(currentRequest)) return;
    const stateKey = `request-recovery:${context.requestId}`;
    if (actionStateByKey.get(stateKey)?.phase === "pending") return;
    const shouldRenderCompletion = () => view.section === "contacts"
      && contactWorkspaceMode === "requests" && !selectedContactId;
    context.gate.consumed = true;
    const pending = runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.recoverContactRequestDecision, {
      requestId: context.requestId,
    }, { lockUnknown: false, shouldRenderCompletion });
    focusContactRequestOutcome(context.requestId);
    const result = await pending;
    if (result === undefined || !shouldRenderCompletion()) return;
    const nextRequest = snapshot.contactRequests.find((item) => item.requestId === context.requestId);
    const knownFailureStillRecoverable = result?.ok === false
      && result.error.outcome !== "unknown"
      && result.error.code !== "host_app_revision_conflict"
      && isCurrentSnapshotContext(context)
      && isCurrentContactRequestContext(context, nextRequest)
      && isContactRequestRecoveryReady(nextRequest);
    focusContactRequestOutcome(context.requestId, knownFailureStillRecoverable ? "recover" : null);
  }

  function isCurrentContactRequestContext(context, request) {
    return Boolean(request
      && request.requestId === context.requestId
      && request.state === context.baselineState
      && request.actionReady === context.baselineActionReady
      && request.decisionOutcome === context.baselineDecisionOutcome
      && request.decisionAction === context.baselineDecisionAction);
  }

  function focusContactRequestOutcome(requestId, preferredAction = null) {
    queueMicrotask(() => {
      const preferredId = preferredAction === "recover"
        ? contactRequestRecoveryButtonId(requestId)
        : preferredAction ? contactRequestDecisionButtonId(requestId, preferredAction) : null;
      const status = document.getElementById(contactRequestStatusId(requestId));
      const target = (preferredId && document.getElementById(preferredId))
        || (status?.checkVisibility?.() === false ? null : status)
        || document.getElementById(`request-details-${requestId}-summary`)
        || document.getElementById("contacts-title")
        || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function contactRequestDecisionButtonId(requestId, decision) { return `contact-request-${decision}-${requestId}`; }
  function contactRequestRecoveryButtonId(requestId) { return `contact-request-recover-${requestId}`; }
  function contactRequestStatusId(requestId) { return `contact-request-status-${requestId}`; }

  function renderClearResolvedControl() {
    const state = actionStateByKey.get("contact-request:clear-resolved") || { phase: "idle", code: null, result: null };
    const section = node("section", "contact-section clear-resolved-control", [
      node("h3", "contact-section-title", localizedCopy("requests.clearResolvedTitle", "清理已处理联系申请")),
      node("p", "module-copy", localizedCopy("requests.clearResolvedBody", "只删除本机已处理记录；不会改变联系人关系、云端决定或屏蔽，也不会删除仍在等待中的申请。")),
    ]);
    const trigger = contactActionButton(
      "clear-resolved-contact-requests",
      state.phase === "pending" ? localizedCopy("action.working", "正在请求 Host…") : localizedCopy("requests.clearResolvedAction", "清理已处理记录"),
      () => beginClearResolvedConfirmation(),
      "",
      "danger-button",
    );
    trigger.id = "clear-resolved-contact-requests";
    trigger.disabled = state.phase === "pending" || state.phase === "unknown";
    section.append(trigger);
    if (clearResolvedConfirmation) section.append(renderClearResolvedConfirmation(clearResolvedConfirmation));
    section.append(clearResolvedStatus(state));
    return section;
  }

  function beginClearResolvedConfirmation() {
    const state = actionStateByKey.get("contact-request:clear-resolved");
    if (!canExecute("contact-request.clear-resolved") || ["pending", "unknown"].includes(state?.phase)) return;
    lifecycleConfirmation = null;
    deleteConfirmation = null;
    clearResolvedConfirmation = {
      openedSnapshotKey: lifecycleSnapshotKey(),
      attempt: 0,
    };
    render();
    queueMicrotask(() => document.getElementById("clear-resolved-cancel")?.focus({ preventScroll: true }));
  }

  function renderClearResolvedConfirmation(context) {
    const state = actionStateByKey.get("contact-request:clear-resolved") || { phase: "idle", code: null };
    const title = node("strong", "", localizedCopy("requests.clearResolvedConfirmTitle", "确认清理本机已处理联系申请？"));
    title.id = "clear-resolved-dialog-title";
    const body = node("p", "", localizedCopy("requests.clearResolvedConfirmBody", "这只删除 accepted、rejected、cancelled、blocked 或 expired 的本机记录；pending 申请受保护。此操作不会改变联系人关系或云端决定。"));
    body.id = "clear-resolved-dialog-body";
    const dialog = node("div", "delete-confirmation lifecycle-confirmation", [title, body]);
    dialog.id = "clear-resolved-dialog";
    dialog.tabIndex = -1;
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-labelledby", title.id);
    dialog.setAttribute("aria-describedby", body.id);
    const cancel = contactActionButton("cancel-clear-resolved", localizedCopy("action.cancel", "取消"), () => closeClearResolvedConfirmation(true));
    cancel.id = "clear-resolved-cancel";
    cancel.disabled = state.phase === "pending";
    const expectedAttempt = context.attempt;
    const confirm = contactActionButton(
      "confirm-clear-resolved",
      state.phase === "pending" ? localizedCopy("action.working", "正在请求 Host…") : localizedCopy("requests.clearResolvedConfirm", "确认清理本机记录"),
      () => void executeClearResolved(context, expectedAttempt),
      "",
      "danger-button",
    );
    confirm.id = "clear-resolved-confirm";
    confirm.disabled = state.phase === "pending" || state.phase === "unknown";
    dialog.append(node("div", "card-actions", [cancel, confirm]));
    return dialog;
  }

  function closeClearResolvedConfirmation(restoreFocus = false) {
    const state = actionStateByKey.get("contact-request:clear-resolved");
    if (state?.phase === "pending") return;
    clearResolvedConfirmation = null;
    render();
    if (restoreFocus) queueMicrotask(() => document.getElementById("clear-resolved-contact-requests")?.focus({ preventScroll: true }));
  }

  async function executeClearResolved(context, expectedAttempt) {
    const stateKey = "contact-request:clear-resolved";
    const state = actionStateByKey.get(stateKey);
    if (!context || clearResolvedConfirmation !== context || context.attempt !== expectedAttempt
      || ["pending", "unknown"].includes(state?.phase) || !canExecute("contact-request.clear-resolved")) return;
    if (context.openedSnapshotKey !== lifecycleSnapshotKey()) {
      actionStateByKey.set(stateKey, { phase: "failed", code: "host_app_revision_conflict", result: null });
      clearResolvedConfirmation = null;
      render();
      focusClearResolvedStatus();
      return;
    }
    const shouldRenderCompletion = () => clearResolvedConfirmation === context
      && view.section === "contacts" && contactWorkspaceMode === "requests" && !selectedContactId;
    context.attempt += 1;
    const pending = runAction(
      stateKey,
      HELLOLYNK_WORKBENCH_COMMAND_TYPES.clearResolvedContactRequests,
      {},
      { lockUnknown: true, shouldRenderCompletion },
    );
    queueMicrotask(() => document.getElementById("clear-resolved-dialog")?.focus({ preventScroll: true }));
    const result = await pending;
    // Account replacement or a newer confirmation retires this UI continuation,
    // including when replacement happened during the mandatory result refresh.
    if (result === undefined || clearResolvedConfirmation !== context) return;
    const renderCompletion = shouldRenderCompletion();
    clearResolvedConfirmation = null;
    if (!renderCompletion) return;
    render();
    focusClearResolvedStatus();
  }

  function clearResolvedStatus(state) {
    let message = "";
    if (state.phase === "pending") message = localizedCopy("requests.clearResolvedPending", "正在等待 Host 清理本机已处理记录…");
    else if (state.phase === "unknown") message = localizedCopy("requests.clearResolvedUnknown", "清理结果未知，系统没有自动重放。请先查看刷新后的权威快照；此操作保持锁定。");
    else if (state.phase === "failed") message = actionErrorCopy(state.code);
    else if (state.phase === "ok") {
      const count = state.result?.deletedCount ?? 0;
      message = count === 0
        ? localizedCopy("requests.clearResolvedZero", "Host 确认没有可清理的已处理记录。")
        : localizedCopy("requests.clearResolvedCount", "Host 确认已清理 {count} 条本机已处理记录。", { count });
      if (state.result?.inboundResume === "resume_scheduled") {
        message = localizedParts([message, localizedParts([" ", localizedCopy("requests.clearResolvedResumeScheduled", "正在后台尝试恢复接收。")])]);
      } else if (state.result?.inboundResume === "resume_attempted") {
        message = localizedParts([message, localizedParts([" ", localizedCopy("requests.clearResolvedResumeAttempted", "Host 已尝试恢复接收；若仍提示暂停，请再次由你手动发起清理。"), ""])]);
      } else if (state.result?.inboundResume === "retry_required") {
        message = localizedParts([message, localizedParts([" ", localizedCopy("requests.clearResolvedRetryRequired", "接收仍暂停；系统没有自动重试。请由你手动再次发起。"), ""])]);
      }
    }
    const status = node("p", `action-status is-${state.phase}`, localizedTrim(message));
    status.id = "clear-resolved-status";
    status.tabIndex = -1;
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    return status;
  }

  function focusClearResolvedStatus() {
    queueMicrotask(() => {
      const target = document.getElementById("clear-resolved-status")
        || document.getElementById("contacts-title")
        || $("content-pane");
      target?.focus({ preventScroll: true });
    });
  }

  function renderSecurity(root) {
    const security = snapshot.security;
    const synthetic = snapshot.source.mode === "synthetic-preview";
    const cards = [];
    cards.push(node("article", "data-card", synthetic
      ? [
          node("h3", "", localizedCopy("security.syntheticSource", "")),
          node("p", "", localizedCopy("security.syntheticSourceBody", "")),
          securityStatusPill("synthetic", localizedCopy("host.synthetic", "")),
        ]
      : [
          node("h3", "", localizedCopy("security.host", "本机 Host")),
          node("p", "", localizedCopy("security.hostBody", "状态来自当前本机 Host；不显示安装标识或连接凭据。")),
          securityStatusPill(security.hostStatus),
        ]));
    if (snapshot.subject.delegateLabel) {
      cards.push(node("article", "data-card", [
        node("h3", "", localizedCopy("security.delegate", "当前代表")),
        node("p", "", snapshot.subject.delegateLabel),
        securityStatusPill("active", localizedCopy("security.currentDelegate", "当前授权代表")),
      ]));
    }
    if (hasWorkbenchCapability(snapshot, "contacts.read")) {
      const authorizedContactCount = snapshot.contacts.filter((contact) => contact.instances.some((instance) => instance.autonomousSendAuthorized)).length;
      cards.push(node("article", "data-card", [
        node("h3", "", localizedCopy("security.authorizedContacts", "已授权联系人")),
        node("p", "", localizedCopy("security.authorizedContactsBody", "当前代表可自主收发的联系人")),
        securityStatusPill(authorizedContactCount > 0 ? "active" : "neutral", authorizedContactsCountCopy(authorizedContactCount)),
      ]));
    }
    if (!synthetic) {
      cards.push(...security.connectedClients.map((client) => node("article", "data-card", [
        node("h3", "", clientTypeCopy(client.clientType)),
        node("p", "", localizedCopy("security.connectedClientBody", "状态来自 Host 的真实连接快照；不显示客户端内部标识。")),
        securityStatusPill(client.state),
      ])));
    }
    renderModule(
      root,
      localizedCopy("security.title", "安全中心"),
      synthetic
        ? localizedCopy("security.syntheticBody", "")
        : localizedCopy("security.body", "查看本机连接和安全边界，不在网页云端暴露消息正文。"),
      cards,
    );
  }

  function renderSettings(root) {
    const persistenceCopy = localePreferenceSaved
      ? localizedCopy("settings.savedLocal", "保存在本机浏览器")
      : localizedCopy("settings.sessionOnly", "当前会话有效，尚未保存在本机浏览器");
    const language = node("article", "data-card", [
      node("h3", "", localizedCopy("settings.language", "界面语言")),
      node("p", "", localeBindings.localeName(false)),
      securityStatusPill(localePreferenceSaved ? "active" : "neutral", persistenceCopy),
    ]);
    const languageButton = node("button", "secondary-button", localeBindings.localeName(true));
    languageButton.type = "button";
    languageButton.id = "settings-language-toggle";
    languageButton.dataset.action = "toggle-language";
    languageButton.addEventListener("click", () => toggleLocale({ restoreSettingsFocus: true }));
    language.append(languageButton);
    renderModule(root, localizedCopy("settings.title", "设置"), localizedCopy("settings.body", "这里只显示当前真实可用的本机设置。"), [language]);
  }

  function canExecute(capability) {
    return !stopped && !changeRefreshPending && ["ready", "empty"].includes(view.phase) && !authorityReloadRequired && snapshot?.source.mode === "neutral-host"
      && snapshot.commandWindow !== null
      && transport.actionGrantMode === "host-single-use-v1"
      && typeof transport.executeCommand === "function" && hasWorkbenchCapability(snapshot, capability);
  }

  function canManageAuthorization() { return canExecute("contact.authorization.manage"); }

  function actionStatus(state = { phase: "idle", code: null }, { conflictCopy = null, unknownCopy = null } = {}) {
    const isConflict = state.code === "host_app_revision_conflict";
    const status = node("div", `action-status is-${isConflict ? "conflict" : state.phase}`, state.refreshing
      ? localizedCopy("action.status.refreshing", "正在更新状态…") : state.phase === "pending"
      ? localizedCopy("action.status.pending", "正在等待 Host 返回结果…")
      : state.phase === "ok" ? localizedCopy("action.status.ok", "Host 已确认操作。")
        : state.phase === "unknown" ? unknownCopy || localizedCopy("action.status.unknown", "结果未知，未自动重试。请刷新后确认。")
          : isConflict ? conflictCopy || localizedCopy("action.status.conflict", "本机数据已在另一处发生变化。已刷新最新状态，没有覆盖新内容。")
            : state.phase === "failed" ? actionErrorCopy(state.code) : "");
    status.dataset.actionState = isConflict ? "conflict" : state.phase;
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    return status;
  }

  function contactFlowActionStatus(state = { phase: "idle", code: null }) {
    const message = state.phase === "pending"
      ? localizedCopy("contacts.saving", "正在保存…")
      : state.phase === "unknown"
        ? withVisibleErrorCode(localizedCopy("contacts.saveUnknownShort", "保存结果未知，请检查联系人列表。"), state.code || "workbench_command_outcome_unknown")
        : state.phase === "failed"
          ? withVisibleErrorCode(actionErrorCopy(state.code), state.code)
          : "";
    const status = node("div", `action-status is-${state.phase}`, message);
    status.dataset.actionState = state.phase;
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    return status;
  }

  function contactSaveStateKey(contactId) { return `contact:${contactId || "new"}`; }

  async function setContactAuthorization(context) {
    if (!canManageAuthorization() || !isCurrentSnapshotContext(context)) return;
    const currentContact = snapshot.contacts.find((item) => item.contactId === context.contactId);
    const currentInstance = currentContact?.instances.find((item) => item.delegateId === context.recipientDelegateId);
    if (!currentInstance || currentInstance.autonomousSendAuthorized !== context.baselineAuthorized) return;
    const stateKey = `authorization:${context.contactId}:${context.recipientDelegateId}`;
    if (["pending", "unknown"].includes(actionStateByKey.get(stateKey)?.phase)) return;
    const result = await runAction(stateKey, HELLOLYNK_WORKBENCH_COMMAND_TYPES.setContactAuthorization, {
      contactId: context.contactId,
      recipientDelegateId: context.recipientDelegateId,
      enabled: context.enabled,
    }, { lockUnknown: true });
    if (result === undefined) return;
    const nextContact = snapshot.contacts.find((item) => item.contactId === context.contactId);
    const state = actionStateByKey.get(stateKey);
    if (state?.phase === "unknown") {
      actionStateByKey.set(stateKey, nextContact?.instances.find((item) => item.delegateId === context.recipientDelegateId)?.autonomousSendAuthorized === context.enabled
        ? { phase: "ok", code: null }
        : { ...state, unknownEvidence: { kind: "authorization", contactId: context.contactId, recipientDelegateId: context.recipientDelegateId, expectedAuthorized: context.enabled } });
      render();
    }
    return result;
  }

  async function runAction(stateKey, commandType, payload, { lockUnknown = true, capability = null, unknownEvidence = null, onConfirmed = null, shouldRenderCompletion = null } = {}) {
    const currentPhase = actionStateByKey.get(stateKey)?.phase;
    const requiredCapability = capability || COMMAND_CAPABILITY_BY_TYPE.get(commandType);
    if (!requiredCapability || !canExecute(requiredCapability) || actionOperationByKey.has(stateKey)
      || currentPhase === "pending" || (lockUnknown && currentPhase === "unknown")) return;
    const actionEpoch = accountViewEpoch;
    const operation = { epoch: actionEpoch, afterRead: Infinity, readFinished: false };
    actionOperationByKey.set(stateKey, operation);
    actionStateByKey.set(stateKey, { phase: "pending", code: null });
    render();
    try {
      const requestId = generatedId("request");
      const command = createWorkbenchCommand(commandType, payload, {
        requestId,
        idempotencyKey: createWorkbenchIdempotencyKey(snapshot.commandWindow, generatedId("action")),
        expectedRevision: snapshot.revision,
      });
      const result = validateWorkbenchCommandResult(await transport.executeCommand(command), command.command);
      if (actionEpoch !== accountViewEpoch) return;
      if (result.requestId !== requestId) throw new Error("workbench_command_outcome_unknown");
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.resendDeletedReply && result.ok
        && result.result.originalClientMessageId !== command.payload.clientMessageId) throw new Error("workbench_command_outcome_unknown");
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.markAllRead && result.ok
        && (result.result.threadId !== command.payload.threadId
          || result.result.beforeReceiptSeq !== command.payload.beforeReceiptSeq)) throw new Error("workbench_command_outcome_unknown");
      if (command.command === HELLOLYNK_WORKBENCH_COMMAND_TYPES.setAutoRead && result.ok
        && (result.result.threadId !== command.payload.threadId
          || result.result.enabled !== command.payload.enabled)) throw new Error("workbench_command_outcome_unknown");
      actionStateByKey.set(stateKey, {
        phase: result.ok ? "ok" : result.error.outcome === "unknown" ? "unknown" : "failed",
        code: result.ok ? null : result.error.code,
        result: result.ok ? result.result : null,
        unknownEvidence,
        refreshing: true,
      });
      operation.afterRead = loadSequence;
      if (result.ok) onConfirmed?.();
      await refreshReadOnly();
      return result;
    } catch (error) {
      if (actionEpoch !== accountViewEpoch) return;
      actionStateByKey.set(stateKey, {
        phase: transportFailurePhase(error),
        code: publicError(error),
        result: null,
        unknownEvidence,
        refreshing: true,
      });
      operation.afterRead = loadSequence;
      await refreshReadOnly();
      return null;
    } finally {
      operation.readFinished = true;
      const released = releaseRefreshedAction(stateKey, operation);
      if (released && !stopped && (!shouldRenderCompletion || shouldRenderCompletion())) render();
    }
  }

  function releaseRefreshedAction(stateKey, operation) {
    // A superseded or failed read leaves the old snapshot in place. Wait for
    // an applied read; an old account/finally must never release a new action.
    if (!operation.readFinished || appliedReadSequence <= operation.afterRead
      || operation.epoch !== accountViewEpoch || actionOperationByKey.get(stateKey) !== operation) return false;
    actionOperationByKey.delete(stateKey);
    const state = actionStateByKey.get(stateKey);
    if (state?.refreshing) {
      const { refreshing, ...settled } = state;
      actionStateByKey.set(stateKey, settled);
    }
    return true;
  }

  function actionErrorCopy(code) {
    const keyByCode = {
      host_app_human_send_text_too_large: "action.error.humanSendTextTooLarge",
      host_app_input_invalid: "action.error.input",
      host_app_record_not_found: "action.error.missing",
      host_app_authorization_required: "action.error.authorization",
      host_app_state_conflict: "action.error.stateConflict",
      host_app_capability_unavailable: "action.error.unavailable",
      host_app_local_history_unread_protected: "history.unreadProtected",
      host_app_local_history_outgoing_protected: "history.outgoingProtected",
      host_app_cloud_unavailable: "host.localOnlyHint",
      host_app_command_window_full: "action.error.windowFull",
      host_app_command_window_expired: "action.error.windowExpired",
      workbench_contact_required_fields: "action.error.required",
      workbench_contact_hellolynk_id_invalid: "action.error.hellolynkId",
      host_app_contact_hellolynk_id_invalid: "action.error.hellolynkId",
      contact_hellolynk_id_invalid: "action.error.hellolynkId",
      workbench_command_principal_search_query_invalid: "discovery.error.query",
      directory_search_rate_limited: "discovery.error.searchQuota",
      contact_request_intro_invalid: "discovery.error.intro",
      contact_request_intro_too_long: "discovery.error.introLong",
      contact_request_intro_forbidden_character: "discovery.error.introCharacter",
      contact_request_intro_link_forbidden: "discovery.error.introLink",
      contact_request_recipient_prekey_unavailable: "discovery.error.recipientUnavailable",
      contact_request_recipient_endpoint_ambiguous: "discovery.error.recipientEndpointAmbiguous",
      host_app_contact_target_expired: "discovery.error.targetExpired",
      workbench_surface_action_grant_expired: "action.error.grantExpired",
      workbench_mcp_action_grant_expired: "action.error.grantExpired",
      host_app_action_grant_expired: "action.error.grantExpired",
      host_app_action_grant_required: "action.error.grantInvalid",
      workbench_surface_action_grant_invalid: "action.error.grantInvalid",
      workbench_mcp_action_grant_invalid: "action.error.grantInvalid",
      host_app_action_grant_invalid: "action.error.grantInvalid",
      host_app_action_grant_mismatch: "action.error.grantInvalid",
      host_app_action_grant_revoked: "action.error.grantInvalid",
    };
    const key = keyByCode[code];
    return key ? localizedCopy(key, localizedCopy("action.status.failed", "操作失败，未自动重试。")) : localizedCopy("action.status.failed", "操作失败，未自动重试。");
  }

  function discoveryUnknownCopy(code) {
    const timeoutCodes = new Set([
      "workbench_snapshot_timeout", "workbench_mcp_snapshot_timeout", "workbench_mcp_app_bridge_timeout",
      "workbench_loopback_timeout", "workbench_surface_host_timeout", "neutral_host_request_timeout",
    ]);
    return timeoutCodes.has(code)
      ? localizedCopy("discovery.timeout", "搜索超时，请重试。")
      : localizedCopy("discovery.unknown", "搜索结果未知，请重试。");
  }

  function withVisibleErrorCode(message, code) {
    if (!code) return message;
    return localizedParts(["", message, " ", localizedCopy("state.error.code", "错误码"), "：", code, ""]);
  }

  function toggleLocale({ restoreSettingsFocus = false } = {}) {
    locale = locale === "zh-CN" ? "en" : "zh-CN";
    localePreferenceSaved = persistLocalePreference(locale);
    render();
    if (restoreSettingsFocus) {
      queueMicrotask(() => document.getElementById("settings-language-toggle")?.focus({ preventScroll: true }));
    }
  }

  function renderPortalTarget(target) {
    const button = $(target === "keys" ? "connection-key-link" : `account-link-${target}`);
    const state = portalStateByTarget.get(target);
    button.disabled = !openPortal;
    button.textContent = state?.phase === "pending" ? copy("portal.opening", "正在打开…")
      : state?.phase === "failed" ? copy("portal.openFailed", "打开失败，点此重试")
      : target === "keys" ? copy("connection.keyLink", "去官网获取 KEY ↗") : copy("portal.devices", "设备与撤销");
    if (state?.phase === "pending") button.setAttribute("aria-busy", "true");
    else button.removeAttribute("aria-busy");
    if (state?.phase === "failed") button.setAttribute("title", `${button.textContent} (${state.code})`);
    else button.removeAttribute("title");
  }

  async function openPortalTarget(target) {
    if (stopped || !openPortal || !PORTAL_TARGETS.has(target)
      || portalStateByTarget.get(target)?.phase === "pending") return;
    portalStateByTarget.set(target, { phase: "pending", code: null });
    renderPortalTarget(target);
    try {
      await openPortal(target);
      portalStateByTarget.delete(target);
    } catch (error) {
      portalStateByTarget.set(target, { phase: "failed", code: publicError(error) });
    } finally { if (!stopped) renderPortalTarget(target); }
  }

  function incomingPendingContactRequestCount() {
    return snapshot?.contactRequests?.filter(
      (request) => request.direction === "incoming" && request.state === "pending",
    ).length || 0;
  }

  function transportFailurePhase(error) {
    return error?.outcome === "known-failed" ? "failed" : "unknown";
  }

  function renderModule(root, title, body, cards, notice = "") {
    const heading = node("h2", "", title);
    heading.id = `${view.section}-title`;
    heading.tabIndex = -1;
    const content = node("section", "module-view", [
      node("header", "module-header", [heading, node("p", "", body)]),
      node("div", "card-grid", cards.length ? cards : [node("article", "data-card", node("p", "", localizedCopy("module.empty", "这里暂时没有本机记录。")))]),
    ]);
    if (notice) content.append(node("div", "notice-card", notice));
    root.replaceChildren(content);
  }

  function statusCopy(value) {
    return localizedCopy(`status.${String(value)}`, String(value));
  }

  function securityStatusPill(state, label = statusCopy(state)) {
    const success = new Set(["online", "available", "connected", "active"]);
    const warning = new Set(["offline", "rebind-required", "verification-required", "disconnected", "stale"]);
    const danger = new Set(["error"]);
    const tone = success.has(state) ? "success"
      : warning.has(state) ? "warning"
        : danger.has(state) ? "danger" : "neutral";
    return node("span", `status-pill is-${tone}`, label);
  }

  function statusPill(state, label) {
    return securityStatusPill(state, label);
  }

  function clientTypeCopy(value) {
    return localizedCopy(`security.clientType.${String(value)}`, localizedCopy("security.clientType.unknown", "未知客户端"));
  }

  function authorizedContactsCountCopy(count) {
    const key = count === 1 ? "security.authorizedContactsCount.one" : "security.authorizedContactsCount.other";
    return localizedCopy(key, "{count} 个联系人", { count });
  }

  function detailRow(label, value) {
    return node("div", "detail-row", [node("span", "", label), node("strong", "", value)]);
  }

  function clearListSearch() {
    $("search-input").value = "";
    if (view.section === "contacts") {
      contactQuery = "";
      render();
    } else {
      dispatch({ type: "SET_QUERY", query: "" });
      scheduleReadRefresh();
    }
    queueMicrotask(() => $("search-input").focus({ preventScroll: true }));
  }

  $("search-input").addEventListener("input", (event) => {
    if (view.section === "contacts") {
      contactQuery = event.currentTarget.value;
      render();
      queueMicrotask(() => $("search-input")?.focus({ preventScroll: true }));
    } else {
      dispatch({ type: "SET_QUERY", query: event.currentTarget.value });
      scheduleReadRefresh();
    }
  });
  $("locale-toggle").addEventListener("click", () => {
    toggleLocale();
  });
  document.querySelectorAll("[data-portal-target]").forEach((button) => {
    button.addEventListener("click", () => openPortalTarget(button.dataset.portalTarget));
  });
  $("list-primary-action")?.addEventListener("click", () => {
    if (!canExecute("principal.search") || !canExecute("contact-request.send")) return;
    contactWorkspaceMode = "add";
    selectedContactId = null;
    detailsOpen = false;
    navigateContactMode("add");
  });
  $("state-retry").addEventListener("click", () => {
    if (view.phase !== "loading") void refreshReadOnly({ quiet: false });
  });
  $("connection-start").addEventListener("click", async () => {
    const button = $("connection-start");
    if (!startConnection || stopped || button.disabled || button.hidden) return;
    button.disabled = true;
    try { await startConnection(); }
    catch {
      if (!stopped) $("connection-help").textContent = copy("connection.openFailed", "没能打开连接入口。请重新打开 HelloLynk 通讯，再点击“连接 HelloLynk”。");
    } finally { button.disabled = false; }
  });
  $("global-refresh")?.addEventListener("click", () => {
    if (stopped || manualRefreshPending || view.phase === "loading") return;
    manualRefreshPending = true;
    renderChrome();
    void refreshReadOnly().finally(() => {
      manualRefreshPending = false;
      if (!stopped) { renderChrome(); refreshAfterChange(); }
    });
  });
  $("global-compose-cancel")?.addEventListener("click", () => closeGlobalComposer());
  $("global-contact-select")?.addEventListener("change", (event) => {
    if (globalComposer.phase === "pending" || globalComposer.phase === "unknown") return;
    globalComposer = { ...globalComposer, contactId: event.currentTarget.value || null, recipientDelegateId: null, phase: "idle", code: null };
    renderGlobalComposer();
  });
  $("global-instance-select")?.addEventListener("change", (event) => {
    if (["pending", "unknown"].includes(globalComposer.phase)) return;
    globalComposer = { ...globalComposer, recipientDelegateId: event.currentTarget.value || null, phase: "idle", code: null };
    renderGlobalComposer();
  });
  $("global-message-draft")?.addEventListener("input", (event) => {
    if (["pending", "unknown"].includes(globalComposer.phase)) return;
    globalComposer = {
      ...globalComposer,
      draft: event.currentTarget.value,
      ...(globalComposer.phase === "failed" ? { phase: "idle", code: null } : {}),
    };
    renderGlobalComposer();
  });
  $("global-message-draft")?.addEventListener("keydown", (event) => {
    if (event.isComposing || event.keyCode === 229 || event.shiftKey || event.key !== "Enter" || event.repeat) return;
    event.preventDefault();
    void submitGlobalMessage();
  });
  $("global-compose-submit")?.addEventListener("click", () => void submitGlobalMessage());
  $("local-history-cancel")?.addEventListener("click", closeLocalHistoryConfirmation);
  $("local-history-range")?.addEventListener("change", (event) => {
    const context = localHistoryConfirmation;
    if (!context || context.submitted) return;
    context.range = event.currentTarget.value;
    context.before = beforeForHistoryRange(context.range, $("local-history-date").value);
    renderLocalHistoryDialog();
    void requestHistorySelection(context);
  });
  $("local-history-date")?.addEventListener("change", (event) => {
    const context = localHistoryConfirmation;
    if (!context || context.submitted || context.range !== "date") return;
    context.before = beforeForHistoryRange("date", event.currentTarget.value);
    renderLocalHistoryDialog();
    void requestHistorySelection(context);
  });
  $("local-history-confirm")?.addEventListener("click", () => {
    const context = localHistoryConfirmation;
    if (!context || context.submitted || context.snapshotKey !== lifecycleSnapshotKey()
      || !(context.kind === "resendReply" ? canResendDeletedReply(snapshot?.outbox.find(item => item.clientMessageId === context.threadId)) : canExecute("threads.manage-local"))) return;
    context.submitted = true;
    void runThreadLocalHistory(context.kind, context.threadId, context.snapshotKey);
  });
  $("history-manage")?.addEventListener("click", () => {
    historyManagerOpen = !historyManagerOpen;
    renderHistoryManagement();
    if (historyManagerOpen) queueMicrotask(() => $("history-management")?.querySelector("button")?.focus({ preventScroll: true }));
  });
  document.querySelectorAll(".filter-button").forEach((button) => {
    if (!button.dataset.filter) return;
    button.addEventListener("click", () => {
    dispatch({ type: "SET_FILTER", filter: button.dataset.filter });
    scheduleReadRefresh();
    });
  });
  // Fragment anchors in srcdoc inherit the host page's base URL. Keep product
  // navigation in this document instead of letting the browser replace the card.
  document.querySelector(".brand")?.addEventListener("click", (event) => {
    event.preventDefault();
    navigate("inbox");
  });
  document.querySelectorAll(".rail-link[data-section]").forEach((link) => link.addEventListener("click", (event) => {
    event.preventDefault();
    navigate(link.dataset.section);
  }));
  $("contact-request-link").addEventListener("click", (event) => {
    event.preventDefault();
    navigateContactMode("requests");
  });
  addEventListener("hashchange", () => applyLocation());
  mobileViewportQuery.addEventListener?.("change", syncMobilePaneIsolation);
  document.addEventListener?.("visibilitychange", handleVisibilityRecovery);
  addEventListener("online", handleOnlineRecovery);
  addEventListener("pageshow", handlePageShowRecovery);
  addEventListener("keydown", (event) => {
    // While an input method is composing, Escape only cancels its candidate.
    if (event.key === "Escape" && (event.isComposing || event.keyCode === 229)) return;
    if (localHistoryConfirmation) {
      if (event.key === "Escape") { event.preventDefault(); closeLocalHistoryConfirmation(); }
      else if (event.key === "Tab") {
        const controls = [$("local-history-range"), $("local-history-date"), $("local-history-cancel"), $("local-history-confirm")]
          .filter((button) => !button.hidden && !button.disabled);
        event.preventDefault();
        const index = controls.indexOf(document.activeElement);
        controls[(index + (event.shiftKey ? -1 : 1) + controls.length) % controls.length]?.focus();
      }
      return;
    }
    if ($("account-disconnect-layer")?.hidden === false) {
      if (event.key === "Escape" && !disconnectPending) {
        event.preventDefault(); void closeDisconnectDialog();
      } else if (event.key === "Tab") {
        event.preventDefault();
        if (!disconnectPending) {
          const cancel = $("account-disconnect-cancel"), confirm = $("account-disconnect-confirm");
          (document.activeElement === cancel ? confirm : cancel).focus();
        }
      }
      return;
    }
    if (trapGlobalComposerFocus(event)) return;
    if (event.key === "Escape" && historyManagerOpen && document.activeElement?.closest?.("#history-management")) {
      event.preventDefault(); historyManagerOpen = false; renderHistoryManagement(); $("history-manage")?.focus({ preventScroll: true }); return;
    }
    if (event.key === "Escape" && globalComposer.open) {
      event.preventDefault();
      closeGlobalComposer();
    }
    else if (event.key === "Escape" && detailsOpen) {
      event.preventDefault();
      setDetailsOpen(false, detailsObjectKey);
    }
    else if (event.key === "Escape" && clearResolvedConfirmation) closeClearResolvedConfirmation(true);
    else if (event.key === "Escape" && lifecycleConfirmation) {
      const context = lifecycleConfirmation;
      closeLifecycleConfirmation(context, { restoreFocus: true });
    }
    else if (event.key === "Escape" && document.activeElement === $("search-input") && $("search-input").value) {
      event.preventDefault();
      clearListSearch();
    }
    else if (event.key === "Escape" && matchMedia("(max-width: 700px)").matches && view.selectedThreadId) navigate("inbox");
    else if (event.key === "Escape" && matchMedia("(max-width: 700px)").matches && view.section === "contacts" && (selectedContactId || contactWorkspaceMode)) navigate("contacts");
    else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && ["inbox", "contacts"].includes(view.section)) {
      event.preventDefault();
      queueMicrotask(() => $("search-input").focus({ preventScroll: true }));
    }
  });

  // Initialize the route before the single initial load; later navigation
  // still reads fresh account state and the selected conversation.
  applyLocation({ replace: true, loadSelection: false });
  load();
  syncThreadTimeRefresh();
  if (typeof transport.subscribe === "function") {
    unsubscribe = transport.subscribe(
      (change) => {
        if (stopped) return;
        if (coversChange(snapshot, change)) return;
        changeSequence++;
        const ordered = orderedChange(change);
        if (!ordered || (latestChange && latestChange.hostGeneration !== ordered.hostGeneration)) {
          unorderedChangeSequence = changeSequence;
        }
        if (!ordered || !coversChange(latestChange, ordered)) latestChange = ordered;
        changeRefreshPending = true;
        // The read already in flight may include this same-generation notice.
        // Fence commands immediately without interrupting local typing; let
        // its result decide whether a further refresh is actually necessary.
        if (!activeReads || !ordered || snapshot?.hostGeneration !== ordered.hostGeneration) markSnapshotStale();
        else render(); // Show the existing write fence without replacing text fields or marking the view stale.
        refreshAfterChange();
      },
      (error) => {
        if (stopped) return;
        // An in-flight response predating a revoked/expired notification
        // channel cannot clear its error fence. Recovery needs a later read.
        loadSequence++;
        authorityFailureSequence++;
        clearReadRetry();
        recoveryRefreshPending = false;
        const code = error?.code || "workbench_change_stream_failed";
        if (["host_nonce_capability_cache_full", "host_nonce_cache_full",
          "workbench_change_cursor_resync_failed"].includes(code)
          && ["ready", "empty", "stale"].includes(view.phase)) {
          // Capacity pressure or a cursor that still conflicts after rereading
          // is temporary, not renewed write authority. Keep the verified view
          // and draft, show the delay, and let the backed-off changes poll
          // recover before requesting another snapshot.
          readRefreshError = code;
          markSnapshotStale();
          renderChrome();
          return;
        }
        if (code === "host_app_state_conflict" && ["ready", "empty", "stale"].includes(view.phase)) {
          // A Host restarted after idle shutdown or an update starts a new
          // change cursor. The stream rereads from zero and reports readiness;
          // until that read lands, keep the verified view with writes fenced.
          markSnapshotStale();
          return;
        }
        dispatch({ type: "FAILED", code, source: "notification" });
      },
      (context) => {
        if (stopped) return;
        if (transport.refreshesWhileHidden === true
          && ["background", "reopen"].includes(context?.reason)) {
          prepareBackgroundReopen();
          return;
        }
        if (context?.reason === "reopen") {
          scheduleLifecycleRefresh({ reopen: true });
          return;
        }
        // Keep readiness received during an active read. If that read fails,
        // one follow-up read can recover; success consumes it without a reload.
        recoveryRefreshPending = true;
        refreshAfterChange();
      },
    );
  }
  return Object.freeze({
    refresh: () => refreshReadOnly(),
    stop: () => {
      stopped = true;
      clearInterval(threadTimeTimer);
      threadTimeTimer = null;
      actionOperationByKey.clear();
      clearReadRetry();
      for (const approval of sendApprovalByTarget.values()) clearTimeout(approval.timer);
      sendApprovalByTarget.clear();
      sendPreviewByMessageId.clear();
      loadSequence += 1;
      clearTimeout(searchTimer);
      mobileViewportQuery.removeEventListener?.("change", syncMobilePaneIsolation);
      document.removeEventListener?.("visibilitychange", handleVisibilityRecovery);
      removeEventListener?.("online", handleOnlineRecovery);
      removeEventListener?.("pageshow", handlePageShowRecovery);
      if (typeof unsubscribe === "function") unsubscribe();
    },
  });
}

function readLocalePreference() {
  try {
    if (typeof localStorage === "undefined" || typeof localStorage.getItem !== "function") {
      return { available: false, value: null };
    }
    return { available: true, value: localStorage.getItem(LOCALE_STORAGE_KEY) };
  } catch {
    return { available: false, value: null };
  }
}

function persistLocalePreference(value) {
  try {
    if (typeof localStorage === "undefined" || typeof localStorage.setItem !== "function") return false;
    localStorage.setItem(LOCALE_STORAGE_KEY, value);
    return localStorage.getItem(LOCALE_STORAGE_KEY) === value;
  } catch {
    return false;
  }
}

function validateIntroDraft(value) {
  // Acceptance is the shared contract rule; only the counter's weight is local.
  let weight = 0;
  if (typeof value === "string" && value.length <= 80 && !/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value)
    && !/^\p{Zs}*$/u.test(value)) {
    for (const codePoint of value) {
      const scalar = codePoint.codePointAt(0);
      weight += scalar >= 0x20 && scalar <= 0x7e ? 1 : 2;
      if (weight > 40) break;
    }
  }
  try {
    validateWorkbenchContactRequestIntro(value);
    return { ok: true, code: null, weight };
  } catch (error) {
    if (typeof error?.code !== "string") throw error;
    return { ok: false, code: error.code, weight };
  }
}

function isLocalHistoryOnly(value) {
  return value?.source.mode === "neutral-host" && value.security.hostStatus === "offline"
    && value.capabilities.every((capability) => [
      "contact.authorization.manage", "contact.delete", "contact.rename", "contact.instance.delete", "contact.instance.rename",
      "messages.mark-read", "messages.mark-all-read", "messages.auto-read.manage", "messages.delete-read", "messages.delete-sent", "threads.manage-local",
      "contact-request.clear-resolved", "contacts.read", "messages.read", "outbox.read", "search.local", "security.read", "threads.read",
    ].includes(capability));
}

function mergeSnapshotPage(current, next, append, messagePageWindow = null) {
  if (!current || !append) return next;
  if (["messages", "messages-newer"].includes(append) && next.messages.refreshCursor) return next;
  if (append === "contact-requests"
    && (current.hostGeneration !== next.hostGeneration || current.revision !== next.revision)) return current;
  if (current.hostGeneration !== next.hostGeneration) return next;
  if (current.revision !== next.revision) return next;
  if (append === "threads") {
    // Keep one list page and the open conversation. The wire-page budget must
    // not become a lifetime limit on how many conversations can be browsed.
    const selected = current.threads.items.find((item) => item.threadId === current.messages.threadId);
    const items = selected && !next.threads.items.some((item) => item.threadId === selected.threadId)
      ? [...next.threads.items, selected] : next.threads.items;
    return validateWorkbenchSnapshot({
      ...next,
      threads: {
        items,
        nextCursor: next.threads.nextCursor,
      },
      messages: current.messages,
    });
  }
  if (append === "messages" || append === "messages-newer") {
    if (current.messages.threadId !== next.messages.threadId) return next;
    const older = append === "messages";
    const pages = messagePageWindow?.threadId === next.messages.threadId
      ? messagePageWindow.pages : [current.messages];
    if (older) pages.unshift(next.messages);
    else pages.push(next.messages);
    while (pages.length > 10) older ? pages.pop() : pages.shift();
    if (messagePageWindow) {
      messagePageWindow.threadId = next.messages.threadId;
      messagePageWindow.pages = pages;
      messagePageWindow.latestPage = false;
    }
    const merged = pages.reduce((items, page) => prependMessagesById(items, page.items), []);
    const trimmed = older ? merged.slice(0, 200) : merged.slice(-200);
    return validateWorkbenchSnapshot({
      ...next,
      threads: {
        items: mergeById(current.threads.items, next.threads.items, "threadId"),
        nextCursor: current.threads.nextCursor,
      },
      messages: {
        threadId: next.messages.threadId,
        items: trimmed,
        nextCursor: pages[0].nextCursor,
        previousCursor: pages[pages.length - 1].previousCursor ?? null,
      },
    });
  }
  if (append === "contact-requests") {
    return validateWorkbenchSnapshot({
      ...next,
      threads: current.threads,
      messages: current.messages,
    });
  }
  return next;
}

function mergeById(existing, incoming, key) {
  const merged = new Map(existing.map((item) => [item[key], item]));
  for (const item of incoming) merged.set(item[key], item);
  return [...merged.values()];
}

function prependMessagesById(older, current) {
  const latestById = new Map(current.map((item) => [item.localMessageId, item]));
  for (const item of older) latestById.set(item.localMessageId, item);
  const orderedIds = [...new Set([
    ...older.map((item) => item.localMessageId),
    ...current.map((item) => item.localMessageId),
  ])];
  return orderedIds.map((id) => latestById.get(id));
}

function formatHistoryBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${Math.ceil(bytes / 1024)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function localDateParts(value, locale) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("workbench_message_time_invalid");
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return {
    key: `${year}-${month}-${day}`,
    label: new Intl.DateTimeFormat(locale, {
      year: "numeric",
      month: "long",
      day: "numeric",
    }).format(date),
  };
}

function captureMessageScrollAnchor(threadId) {
  const root = document.querySelector(".messages");
  if (!root || root.dataset.threadId !== threadId) return null;
  const rootTop = typeof root.getBoundingClientRect === "function"
    ? root.getBoundingClientRect().top
    : null;
  const records = [...root.querySelectorAll("[data-record-id]")];
  const seen = new Set();
  const candidates = rootTop == null ? [] : records.filter((item) => (
    typeof item.getBoundingClientRect === "function"
    && item.getBoundingClientRect().bottom >= rootTop
    && !seen.has(item.dataset.recordId) && seen.add(item.dataset.recordId)
  )).slice(0, 5).map(item => ({ recordId: item.dataset.recordId, recordTop: item.getBoundingClientRect().top }));
  const anchor = candidates[0];
  return {
    threadId,
    recordId: anchor?.recordId ?? null,
    recordTop: anchor?.recordTop ?? null,
    candidates,
    scrollTop: Number(root.scrollTop) || 0,
    scrollHeight: Number(root.scrollHeight) || 0,
  };
}

function restoreMessageScrollAnchor(anchor) {
  if (!anchor) return;
  const root = document.querySelector(".messages");
  if (!root || root.dataset.threadId !== anchor.threadId) return;
  const records = [...root.querySelectorAll("[data-record-id]")];
  for (const candidate of anchor.candidates ?? [anchor]) {
    const record = candidate.recordId == null ? null : records.find(item => item.dataset.recordId === candidate.recordId);
    if (record && candidate.recordTop != null && typeof record.getBoundingClientRect === "function") {
      root.scrollTop += record.getBoundingClientRect().top - candidate.recordTop;
      return;
    }
  }
  root.scrollTop = anchor.scrollTop + Math.max(0, (Number(root.scrollHeight) || 0) - anchor.scrollHeight);
}

function generatedId(prefix) {
  if (typeof globalThis.crypto?.randomUUID !== "function") throw new Error("workbench_secure_random_unavailable");
  return `${prefix}:${globalThis.crypto.randomUUID()}`;
}

function parseRoute(hash) {
  const segments = String(hash || "").replace(/^#\/?/, "").split("/").filter(Boolean).map(safeDecodeRouteSegment);
  const rawSection = SECTIONS.has(segments[0]) ? segments[0] : "messages";
  const section = rawSection === "messages" ? "inbox" : rawSection;
  const threadCandidate = section === "inbox" && segments[1] === "thread" ? segments[2] || null : null;
  const contactCandidate = section === "contacts" && segments[1] === "contact" ? segments[2] || null : null;
  const contactMode = section === "contacts" && ["requests", "add"].includes(segments[1]) ? segments[1] : null;
  const threadId = threadCandidate && SAFE_ROUTE_ID.test(threadCandidate) ? threadCandidate : null;
  const contactId = contactCandidate && SAFE_ROUTE_ID.test(contactCandidate) ? contactCandidate : null;
  return { section, threadId, contactId, contactMode };
}

function safeDecodeRouteSegment(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return "";
  }
}

function iconAsset(name) {
  const sources = Object.freeze({
    "arrow-left": "/assets/icons/arrow-left.svg",
    close: "/assets/icons/close.svg",
  });
  const image = document.createElement("img");
  image.src = sources[name] || "";
  image.alt = "";
  image.setAttribute("aria-hidden", "true");
  return image;
}

function initials(value) {
  const words = String(value || "LY").trim().split(/\s+/).filter(Boolean);
  return (words.length > 1 ? `${words[0][0]}${words.at(-1)[0]}` : words[0]?.slice(0, 2) || "LY").toUpperCase();
}

export function publicError(error) {
  const value = String(error?.code || error?.message || "workbench_failed");
  return /^(?:workbench|host|neutral_(?:host|codex|openclaw|trae_work|workbuddy|cursor|dsh)|cursor|synthetic_preview)_[a-z0-9_]{1,120}$/.test(value) ? value : "workbench_failed";
}

// Source-owned presentation recipes. Business values and the chosen display
// branch are captured at render time; refresh never looks up current records.
function createLocaleBindings({ getLocale, translate }) {
  const recipes = new WeakSet();
  const textBindings = new WeakMap();
  const attributeBindings = new WeakMap();
  function captureVariables(variables) {
    if (Array.isArray(variables)) return Object.freeze([]); // Remain invalid, as in translateWorkbench.
    if (!variables || typeof variables !== "object") return variables;
    // translateWorkbench stringifies each own placeholder value. Capture that
    // same presentation at render time, including null/undefined and Date/array
    // values, while nested source recipes remain translatable.
    return Object.freeze(Object.fromEntries(Object.entries(variables).map(([key, value]) =>
      [key, recipes.has(value) ? value : String(value)])));
  }
  function resolve(value, locale = getLocale()) {
    return recipes.has(value) ? value.resolve(locale) : String(value ?? "");
  }
  function recipe(render) {
    const value = Object.freeze({
      resolve: render,
      toString: () => render(getLocale()),
      [Symbol.toPrimitive]: () => render(getLocale()),
    });
    recipes.add(value);
    return value;
  }
  function copy(key, fallback, variables) {
    const savedKey = String(key);
    const savedFallback = recipes.has(fallback) ? fallback : String(fallback);
    const savedVariables = captureVariables(variables);
    return recipe((locale) => {
      const vars = savedVariables && typeof savedVariables === "object" && !Array.isArray(savedVariables)
        ? Object.fromEntries(Object.entries(savedVariables).map(([name, value]) => [name, recipes.has(value) ? resolve(value, locale) : value]))
        : savedVariables;
      try {
        const text = translate(locale, savedKey, vars);
        if (text && text !== savedKey) return text;
      } catch { /* Preserve the original literal/source fallback contract. */ }
      return resolve(savedFallback, locale);
    });
  }
  function parts(values) {
    const saved = values.map((value) => recipes.has(value) ? value : String(value));
    return recipe((locale) => saved.map((value) => resolve(value, locale)).join(""));
  }
  function optionalPrefix(value, prefix) {
    const saved = recipes.has(value) ? value : String(value);
    return recipe((locale) => {
      const text = resolve(saved, locale);
      return text ? prefix + text : "";
    });
  }
  function trim(value) {
    const saved = recipes.has(value) ? value : String(value ?? "");
    return recipe((locale) => resolve(saved, locale).trim());
  }
  function format(value, kind, referenceTime = Date.now()) {
    const time = Date.parse(value);
    return recipe((locale) => {
      if (!Number.isFinite(time)) return "";
      const date = new Date(time);
      if (kind === "date") return new Intl.DateTimeFormat(locale, { year: "numeric", month: "long", day: "numeric" }).format(date);
      if (kind === "time") return date.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
      if (kind === "datetime") {
        const sameYear = date.getFullYear() === new Date(referenceTime).getFullYear();
        return new Intl.DateTimeFormat(locale, { ...(sameYear ? {} : { year: "numeric" }), month: "short", day: "numeric",
          hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(date);
      }
      const difference = referenceTime - time;
      const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto", style: "short" });
      if (difference < 60_000) return formatter.format(0, "second");
      if (difference < 3_600_000) return formatter.format(-Math.max(1, Math.floor(difference / 60_000)), "minute");
      if (difference < 86_400_000) return formatter.format(-Math.max(1, Math.floor(difference / 3_600_000)), "hour");
      return date.toLocaleDateString(locale, { month: "numeric", day: "numeric" });
    });
  }
  function setText(element, value) {
    const text = resolve(value);
    // Only normal presentation writers use this path. Locale refresh below
    // mutates the registered Text.data, never the containing element.
    let leaf = element.firstChild;
    if (element.childNodes.length !== 1 || leaf?.nodeType !== 3) {
      element.textContent = text;
      leaf = element.firstChild;
    } else if (leaf.data !== text) leaf.data = text;
    if (!leaf && recipes.has(value)) {
      leaf = element.ownerDocument.createTextNode(text);
      element.append(leaf);
    }
    if (leaf) {
      if (recipes.has(value)) textBindings.set(leaf, value);
      else textBindings.delete(leaf);
    }
    return element;
  }
  function setAttribute(element, name, value) {
    if (!["aria-label", "aria-description", "title", "placeholder"].includes(name)) throw new Error("workbench_locale_attribute_invalid");
    element.setAttribute(name, resolve(value));
    let entries = attributeBindings.get(element);
    if (recipes.has(value)) {
      if (!entries) attributeBindings.set(element, entries = new Map());
      entries.set(name, value);
    } else entries?.delete(name);
    return value;
  }
  function textRecipe(element) {
    return textBindings.get(element.firstChild) ?? element.textContent;
  }
  function node(tag, className = "", children) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    function append(value) {
      if (value instanceof Node) element.append(value);
      else if (recipes.has(value)) {
        const leaf = document.createTextNode(resolve(value));
        textBindings.set(leaf, value);
        element.append(leaf);
      } else element.append(String(value));
    }
    if (Array.isArray(children)) children.forEach(append);
    else if (children instanceof Node) element.append(children);
    else if (children !== undefined && children !== null) setText(element, children);
    return element;
  }
  function retranslate(roots, scrollRoots = []) {
    const attached = roots.filter((root) => root?.isConnected);
    const elements = [...new Set(attached.flatMap((root) => [root, ...root.querySelectorAll("*")]))];
    const scroll = [...new Set([...elements, ...scrollRoots.filter((root) => root?.isConnected)])]
      .map((element) => [element, element.scrollTop, element.scrollLeft]);
    const locale = getLocale();
    for (const element of elements) {
      for (const [name, value] of attributeBindings.get(element) ?? []) element.setAttribute(name, resolve(value, locale));
      for (const leaf of element.childNodes) {
        const value = textBindings.get(leaf);
        if (value) {
          const text = resolve(value, locale);
          if (leaf.data !== text) leaf.data = text;
        }
      }
    }
    // The native layout may clamp an offset if translated content is shorter.
    // Preserve requested offsets without touching selection or focus objects.
    for (const [element, top, left] of scroll) {
      if (element.scrollTop !== top) element.scrollTop = top;
      if (element.scrollLeft !== left) element.scrollLeft = left;
    }
  }
  return Object.freeze({ copy, parts, optionalPrefix, trim, format, setText, setAttribute, textRecipe, node, retranslate,
    localeText: (chinese, english) => recipe((locale) => locale === "zh-CN" ? chinese : english),
    localeName: (opposite = false) => recipe((locale) => (locale === "zh-CN") !== opposite ? "简体中文" : "English"),
  });
}
