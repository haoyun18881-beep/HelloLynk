import { validateWorkbenchSnapshot, HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH } from "./contract.mjs";

export const WORKBENCH_PHASES = Object.freeze([
  "loading",
  "empty",
  "ready",
  "error",
  "stale",
  "conflict",
]);

export const WORKBENCH_FILTERS = Object.freeze(["all", "unread", "archived"]);

export const WORKBENCH_SECTIONS = Object.freeze([
  "inbox",
  "contacts",
  "security",
  "settings",
]);

export const WORKBENCH_FOCUS_TARGETS = Object.freeze([
  "status",
  "navigation",
  "search",
  "thread-list",
  "conversation",
  "section-panel",
]);

const PHASE_SET = new Set(WORKBENCH_PHASES);
const FILTER_SET = new Set(WORKBENCH_FILTERS);
const SECTION_SET = new Set(WORKBENCH_SECTIONS);
const FOCUS_TARGET_SET = new Set(WORKBENCH_FOCUS_TARGETS);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,198}$/;
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/;
const SAFE_ISSUE_CODE = /^[a-z][a-z0-9_.:-]{1,126}$/;
const MAX_QUERY_LENGTH = HELLOLYNK_WORKBENCH_MAX_QUERY_LENGTH;
const MAX_ROUTE_HISTORY = 100;

export class HelloLynkWorkbenchStateError extends Error {
  constructor(code) {
    super(code);
    this.name = "HelloLynkWorkbenchStateError";
    this.code = code;
  }
}

export function createWorkbenchViewState(options = {}) {
  const input = record(options, "workbench_state_options_invalid");
  const filter = input.filter == null ? "all" : oneOf(input.filter, FILTER_SET, "workbench_state_filter_invalid");
  const query = input.query == null ? "" : searchQuery(input.query);
  const selectedThreadId = input.selectedThreadId == null
    ? null
    : safeId(input.selectedThreadId, "workbench_state_thread_id_invalid");
  const section = input.section == null
    ? "inbox"
    : oneOf(input.section, SECTION_SET, "workbench_state_section_invalid");
  const focusTarget = input.focusTarget == null
    ? "status"
    : oneOf(input.focusTarget, FOCUS_TARGET_SET, "workbench_state_focus_target_invalid");

  if (selectedThreadId != null && section !== "inbox") {
    fail("workbench_state_selection_section_invalid");
  }

  const initialRoute = { section, selectedThreadId };
  return deepFreeze({
    phase: "loading",
    filter,
    query,
    selectedThreadId,
    section,
    focusTarget,
    failure: null,
    staleness: null,
    conflict: null,
    snapshotMeta: null,
    knownThreadIds: [],
    routeHistory: {
      entries: [initialRoute],
      index: 0,
    },
  });
}

export function reduceWorkbenchViewState(state, event) {
  const current = viewState(state);
  const input = record(event, "workbench_state_event_invalid");

  switch (input.type) {
    case "LOAD":
      return updateState(current, {
        phase: "loading",
        focusTarget: "status",
        failure: null,
        staleness: null,
        conflict: null,
      });

    case "LOADED":
      return loadedState(current, input.snapshot);

    case "FAILED":
      return updateState(current, {
        phase: "error",
        focusTarget: "status",
        failure: {
          code: issueCode(input.code ?? input.error?.code, "workbench_load_failed"),
          retryable: input.retryable === true || input.error?.retryable === true,
          ...(input.source === "notification" ? { source: "notification" } : {}),
        },
        staleness: null,
        conflict: null,
      });

    case "STALE":
      return updateState(current, {
        phase: "stale",
        focusTarget: "status",
        failure: null,
        staleness: {
          code: issueCode(input.code, "workbench_snapshot_stale"),
          observedRevision: optionalRevision(input.observedRevision),
        },
        conflict: null,
      });

    case "CONFLICT":
      return updateState(current, {
        phase: "conflict",
        focusTarget: "status",
        failure: null,
        staleness: null,
        conflict: {
          code: issueCode(input.code, "workbench_revision_conflict"),
          expectedRevision: optionalRevision(input.expectedRevision),
          currentRevision: optionalRevision(input.currentRevision),
        },
      });

    case "SET_FILTER":
      return updateState(current, {
        filter: oneOf(input.filter, FILTER_SET, "workbench_state_filter_invalid"),
        focusTarget: "thread-list",
      });

    case "SET_QUERY":
      return updateState(current, {
        query: searchQuery(input.query),
        focusTarget: "search",
      });

    case "SELECT_THREAD": {
      const selectedThreadId = safeId(input.threadId, "workbench_state_thread_id_invalid");
      return navigateTo(current, {
        section: "inbox",
        selectedThreadId,
      }, "conversation");
    }

    case "SET_SECTION": {
      const section = oneOf(input.section, SECTION_SET, "workbench_state_section_invalid");
      const route = {
        section,
        selectedThreadId: section === "inbox" ? current.selectedThreadId : null,
      };
      return navigateTo(current, route, focusForRoute(route));
    }

    case "CLEAR_SELECTION":
      return navigateTo(current, {
        section: current.section,
        selectedThreadId: null,
      }, current.section === "inbox" ? "thread-list" : "section-panel");

    case "NAVIGATE_BACK":
      return moveInHistory(current, -1);

    case "NAVIGATE_FORWARD":
      return moveInHistory(current, 1);

    case "SET_FOCUS":
      return updateState(current, {
        focusTarget: oneOf(input.focusTarget, FOCUS_TARGET_SET, "workbench_state_focus_target_invalid"),
      });

    default:
      fail("workbench_state_event_unsupported");
  }
}

export function selectVisibleThreads(state, snapshot) {
  const current = viewState(state);
  const validated = validateWorkbenchSnapshot(snapshot);
  if (validated.source.mode === "neutral-host") {
    return Object.freeze(validated.threads.items.filter(
      (thread) => matchesConversationFilter(thread, current.filter),
    ));
  }
  const tokens = normalizedSearch(current.query).split(/\s+/u).filter(Boolean);
  const messageTextByThread = new Map();
  for (const message of validated.messages.items) {
    const existing = messageTextByThread.get(message.threadId) ?? [];
    existing.push(message.text);
    messageTextByThread.set(message.threadId, existing);
  }

  const visible = validated.threads.items.filter((thread) => {
    if (!matchesConversationFilter(thread, current.filter)) return false;
    if (tokens.length === 0) return true;
    const haystack = normalizedSearch([
      thread.displayName,
      thread.peerHelloLynkId,
      thread.delegateLabel ?? "",
      thread.lastMessage?.text ?? "",
      ...(messageTextByThread.get(thread.threadId) ?? []),
    ].join("\n"));
    return tokens.every((token) => haystack.includes(token));
  });

  return Object.freeze(visible);
}

// These selectors only derive presentation data from the authoritative snapshot.
// They deliberately do not extend the wire contract or create another local store.
export function deriveWorkbenchConversations(snapshot) {
  const validated = validateWorkbenchSnapshot(snapshot);
  // The Host computes this from the last five messages in each conversation.
  // Old outbox failures remain available for history without resurfacing the
  // list badge while searching or paging through older messages.
  return Object.freeze(validated.threads.items.map((thread) => Object.freeze({
    ...thread,
    failedCount: thread.recentSendFailureCount ?? 0,
    hasSendFailure: (thread.recentSendFailureCount ?? 0) > 0,
  })));
}

export function deriveWorkbenchContacts(snapshot) {
  const validated = validateWorkbenchSnapshot(snapshot);
  return Object.freeze(validated.contacts.map((contact) => {
    const relationship = validated.relationships.find(
      (item) => item.otherHelloLynkId === contact.hellolynkId,
    ) ?? null;
    const conversations = validated.threads.items.filter((thread) => (
      thread.contactId === contact.contactId
      || (contact.principalId != null && thread.peerPrincipalId === contact.principalId)
      || thread.peerHelloLynkId === contact.hellolynkId
    ));
    return Object.freeze({
      ...contact,
      relationship,
      conversations: Object.freeze(conversations),
      instances: Object.freeze(contact.instances.map((instance) => Object.freeze({
        ...instance,
        conversation: conversations.find((thread) => thread.conversationKind === "instance"
          && thread.localDelegateId === validated.subject.delegateId
          && thread.peerDelegateId === instance.delegateId
          && thread.peerPrincipalId === contact.principalId) ?? null,
      }))),
    });
  }));
}

function matchesConversationFilter(thread, filter) {
  if (filter === "archived") return thread.archived === true;
  if (thread.archived === true) return false;
  if (filter === "unread") return thread.unreadCount > 0;
  return true;
}

function loadedState(state, snapshot) {
  const validated = validateWorkbenchSnapshot(snapshot);
  const knownThreadIds = validated.threads.items.map((thread) => thread.threadId);
  const selectionIsDefinitelyMissing = state.selectedThreadId != null
    && validated.threads.nextCursor == null
    && !knownThreadIds.includes(state.selectedThreadId);
  const selectedThreadId = selectionIsDefinitelyMissing ? null : state.selectedThreadId;
  const routeHistory = selectionIsDefinitelyMissing
    ? replaceCurrentRoute(state.routeHistory, { section: state.section, selectedThreadId: null })
    : state.routeHistory;
  const phase = knownThreadIds.length === 0 && validated.threads.nextCursor == null ? "empty" : "ready";

  return updateState(state, {
    phase,
    selectedThreadId,
    focusTarget: phase === "empty" && state.section === "inbox"
      ? "status"
      : focusForRoute({ section: state.section, selectedThreadId }),
    failure: null,
    staleness: null,
    conflict: null,
    knownThreadIds,
    routeHistory,
    snapshotMeta: {
      hostGeneration: validated.hostGeneration,
      revision: validated.revision,
      changeCursor: validated.changeCursor,
      generatedAt: validated.generatedAt,
      source: validated.source,
    },
  });
}

function navigateTo(state, route, focusTarget) {
  const routeHistory = pushRoute(state.routeHistory, route);
  return updateState(state, {
    section: route.section,
    selectedThreadId: route.selectedThreadId,
    focusTarget,
    routeHistory,
  });
}

function moveInHistory(state, delta) {
  const nextIndex = state.routeHistory.index + delta;
  if (nextIndex < 0 || nextIndex >= state.routeHistory.entries.length) return state;
  const route = state.routeHistory.entries[nextIndex];
  return updateState(state, {
    section: route.section,
    selectedThreadId: route.selectedThreadId,
    focusTarget: focusForRoute(route),
    routeHistory: {
      entries: state.routeHistory.entries,
      index: nextIndex,
    },
  });
}

function pushRoute(history, route) {
  const current = history.entries[history.index];
  if (sameRoute(current, route)) return history;

  let entries = [...history.entries.slice(0, history.index + 1), route];
  if (entries.length > MAX_ROUTE_HISTORY) entries = entries.slice(entries.length - MAX_ROUTE_HISTORY);
  return {
    entries,
    index: entries.length - 1,
  };
}

function replaceCurrentRoute(history, route) {
  const entries = [...history.entries];
  entries[history.index] = route;
  return { entries, index: history.index };
}

function sameRoute(left, right) {
  return left.section === right.section && left.selectedThreadId === right.selectedThreadId;
}

function focusForRoute(route) {
  if (route.selectedThreadId != null) return "conversation";
  return route.section === "inbox" ? "thread-list" : "section-panel";
}

function updateState(state, patch) {
  return deepFreeze({ ...state, ...patch });
}

function viewState(value) {
  const state = record(value, "workbench_state_invalid");
  if (!PHASE_SET.has(state.phase)
    || !FILTER_SET.has(state.filter)
    || !SECTION_SET.has(state.section)
    || !FOCUS_TARGET_SET.has(state.focusTarget)
    || !Array.isArray(state.routeHistory?.entries)
    || !Number.isSafeInteger(state.routeHistory?.index)
    || state.routeHistory.index < 0
    || state.routeHistory.index >= state.routeHistory.entries.length) {
    fail("workbench_state_invalid");
  }
  return state;
}

function searchQuery(value) {
  if (typeof value !== "string" || value.length > MAX_QUERY_LENGTH || value.includes("\u0000")) {
    fail("workbench_state_query_invalid");
  }
  return value;
}

function normalizedSearch(value) {
  return String(value).normalize("NFKC").trim().toLowerCase();
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function optionalRevision(value) {
  if (value == null) return null;
  if (typeof value !== "string" || !SAFE_REVISION.test(value)) fail("workbench_state_revision_invalid");
  return value;
}

function issueCode(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "string" || !SAFE_ISSUE_CODE.test(value)) fail("workbench_state_issue_code_invalid");
  return value;
}

function oneOf(value, allowed, code) {
  if (!allowed.has(value)) fail(code);
  return value;
}

function record(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function fail(code) {
  throw new HelloLynkWorkbenchStateError(code);
}
