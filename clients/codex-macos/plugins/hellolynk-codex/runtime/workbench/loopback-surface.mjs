import crypto from "node:crypto";
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  validateWorkbenchCommand,
  validateWorkbenchCommandResult,
  validateWorkbenchReadRequest,
  validateWorkbenchSnapshot,
} from "./contract.mjs";

const LOOPBACK = "127.0.0.1";
const NAVIGATION_WINDOW_MS = 120_000;
const SESSION_TTL_MS = 15 * 60_000;
const EVENT_HEARTBEAT_MS = 15_000;
const ACTION_GRANT = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,511}$/;
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

const STATIC_ASSETS = Object.freeze({
  "/assets/app.mjs": ["app.mjs", "text/javascript; charset=utf-8"],
  "/assets/connection-form.mjs": ["connection-form.mjs", "text/javascript; charset=utf-8"],
  "/assets/hellolynk-mark.png": ["hellolynk-mark.png", "image/png"],
  "/assets/http-transport.mjs": ["http-transport.mjs", "text/javascript; charset=utf-8"],
  "/assets/icons/arrow-left.svg": ["icons/arrow-left.svg", "image/svg+xml"],
  "/assets/icons/close.svg": ["icons/close.svg", "image/svg+xml"],
  "/assets/icons/contacts.svg": ["icons/contacts.svg", "image/svg+xml"],
  "/assets/icons/inbox.svg": ["icons/inbox.svg", "image/svg+xml"],
  "/assets/icons/refresh.svg": ["icons/refresh.svg", "image/svg+xml"],
  "/assets/icons/search.svg": ["icons/search.svg", "image/svg+xml"],
  "/assets/icons/security.svg": ["icons/security.svg", "image/svg+xml"],
  "/assets/icons/settings.svg": ["icons/settings.svg", "image/svg+xml"],
  "/assets/styles.css": ["styles.css", "text/css; charset=utf-8"],
  "/modules/contract.mjs": ["../contract.mjs", "text/javascript; charset=utf-8"],
  "/modules/state.mjs": ["../state.mjs", "text/javascript; charset=utf-8"],
  "/modules/i18n.mjs": ["../i18n.mjs", "text/javascript; charset=utf-8"],
});

export class HelloLynkWorkbenchSurfaceError extends Error {
  constructor(code, status = 500) {
    super(code);
    this.name = "HelloLynkWorkbenchSurfaceError";
    this.code = code;
    this.status = status;
  }
}

// This surface is deliberately transport-only. The caller injects the one
// Neutral Host service; this module never opens a store, messenger or receiver.
export function createWorkbenchLoopbackSurface(options = {}) {
  const adapter = validateAdapter(options.adapter);
  const moduleDir = options.workbenchRoot ? path.resolve(options.workbenchRoot) : MODULE_DIR;
  const uiRoot = path.join(moduleDir, "ui");
  const pagePath = normalizePagePath(options.pagePath);
  const syntheticPreview = options.explicitSyntheticPreview === true;
  const syntheticMarker = options.explicitSyntheticMarker === true || syntheticPreview;
  const allowSameSiteTopLevelNavigation = options.allowSameSiteTopLevelNavigation === true;
  const trustedParentOrigin = normalizeTrustedParentOrigin(options.trustedParentOrigin);
  const deferInitialNavigationArm = options.deferInitialNavigationArm === true;
  const expectedSource = syntheticPreview
    ? { mode: "synthetic-preview", transport: "synthetic-memory" }
    : { mode: "neutral-host", transport: "loopback-http" };
  const servedFiles = Object.freeze({
    [pagePath]: ["index.html", "text/html; charset=utf-8"],
    ...STATIC_ASSETS,
    "/assets/loopback-entry.mjs": [
      syntheticPreview ? "synthetic-preview-entry.mjs" : "loopback-entry.mjs",
      "text/javascript; charset=utf-8",
    ],
  });
  const port = integer(options.port, 0, 0, 65_535, "workbench_surface_port_invalid");
  const navigationWindowMs = integer(
    options.navigationWindowMs,
    NAVIGATION_WINDOW_MS,
    10_000,
    NAVIGATION_WINDOW_MS,
    "workbench_surface_navigation_window_invalid",
  );
  const sessions = new Map();
  const eventClients = new Set();
  let navigationArmedUntil = 0;
  let origin = null;
  let sessionCookieName = null;
  let closed = false;
  let staticFiles = null;
  let ipv6Server = null;
  const changePollMs = integer(options.changePollMs, 1_000, 10, 60_000, "workbench_surface_change_poll_invalid");
  let changeCursor = 0;
  let changeGeneration = null;
  let changeTimer = null;
  let changeBusy = false;

  async function handleRequest(request, response) {
    try {
      const url = parseUrl(request, origin);
      if (url.pathname.startsWith("/api/v1/")) return await api(request, response, url);
      if (request.method === "GET" && servedFiles[url.pathname]) return await staticFile(request, response, url.pathname);
      if (request.method === "GET" && url.pathname === "/favicon.ico") return empty(response, 204);
      return json(response, 404, { error: "workbench_surface_route_not_found" });
    } catch (error) {
      if (!response.headersSent) json(response, Number(error?.status) || 500, { error: publicCode(error) });
      else response.destroy();
    }
  }
  const server = http.createServer(handleRequest);

  async function api(request, response, url) {
    assertHost(request, origin);
    const session = requireSession(request);
    if (request.method === "GET") assertReadOrigin(request);
    else assertSameOrigin(request);

    if (request.method === "GET" && url.pathname === "/api/v1/account") {
      return json(response, 200, options.readAccountState ? await options.readAccountState() : { revision: null, canDisconnect: false });
    }
    const accountRevision = typeof options.readAccountState === "function"
      ? (await options.readAccountState()).revision : null;
    const assertAccount = async () => {
      if (accountRevision !== null && (
        request.headers["x-hellolynk-account-revision"] !== accountRevision
        || (await options.readAccountState()).revision !== accountRevision)) throw fail("workbench_account_changed", 409);
    };
    const mutateAccount = (operation) => options.runForAccount && accountRevision !== null
      ? options.runForAccount(accountRevision, operation) : operation();
    // Reads also carry the page's account revision. Existing test/injected
    // surfaces without account management retain their original contract.
    if (["/api/v1/snapshot", "/api/v1/connect", "/api/v1/action-grants", "/api/v1/command"].includes(url.pathname)) await assertAccount();
    if (request.method === "POST" && url.pathname === "/api/v1/disconnect") {
      assertCsrf(request, session);
      if (typeof options.disconnectAccount !== "function") throw fail("workbench_disconnect_unavailable", 503);
      let input;
      try { input = exactPrivateEnvelope(JSON.parse(await readRequestBody(request)), ["revision"]); }
      catch { throw fail("workbench_disconnect_input_invalid", 400); }
      return json(response, 200, await options.disconnectAccount(input));
    }

    if (request.method === "GET" && url.pathname === "/api/v1/csrf") {
      return json(response, 200, { csrf: session.csrf });
    }
    if (request.method === "GET" && url.pathname === "/api/v1/session") {
      if (url.search) throw fail("workbench_surface_read_request_invalid", 400);
      renewSession(request, response, session);
      return json(response, 200, { ok: true });
    }
    if (request.method === "GET" && url.pathname === "/api/v1/snapshot") {
      const allowed = new Set(["threadId", "threadCursor", "messageCursor", "contactRequestCursor", "query", "filter", "historyBefore"]);
      for (const key of url.searchParams.keys()) {
        if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) {
          throw fail("workbench_surface_read_request_invalid", 400);
        }
      }
      let input;
      try {
        const rawInput = Object.fromEntries(url.searchParams);
        if (Object.hasOwn(rawInput, "contactRequestCursor") && rawInput.contactRequestCursor === "") {
          rawInput.contactRequestCursor = null;
        }
        if (Object.hasOwn(rawInput, "historyBefore") && rawInput.historyBefore === "") {
          rawInput.historyBefore = null;
        }
        input = validateWorkbenchReadRequest(rawInput);
      } catch {
        throw fail("workbench_surface_read_request_invalid", 400);
      }
      const snapshot = validateWorkbenchSnapshot(await adapter.readSnapshot(input));
      await assertAccount();
      if (snapshot.source.mode !== expectedSource.mode || snapshot.source.transport !== expectedSource.transport) {
        throw fail("workbench_surface_source_mismatch", 502);
      }
      renewSession(request, response, session);
      return json(response, 200, { snapshot });
    }
    if (request.method === "GET" && url.pathname === "/api/v1/events") {
      return openEventStream(request, response, session);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/connect") {
      assertCsrf(request, session);
      if (typeof options.connectAccount !== "function") throw fail("workbench_connect_unavailable", 503);
      let input;
      try { input = exactPrivateEnvelope(JSON.parse(await readRequestBody(request)), ["hellolynkId", "instanceName"]); }
      catch { throw fail("workbench_connect_input_invalid", 400); }
      const result = await options.connectAccount(input, accountRevision ?? undefined);
      renewSession(request, response, session);
      return json(response, 200, result);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/open-account") {
      assertCsrf(request, session);
      if (typeof options.openAccount !== "function") throw fail("workbench_portal_unavailable", 503);
      let input;
      try { input = exactPrivateEnvelope(JSON.parse(await readRequestBody(request)), ["url"]); }
      catch { throw fail("workbench_portal_target_invalid", 400); }
      const result = await options.openAccount(input);
      renewSession(request, response, session);
      return json(response, 200, result);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/action-grants") {
      assertCsrf(request, session);
      if (typeof adapter.issueActionGrant !== "function" || typeof adapter.executeCommand !== "function") {
        throw fail("workbench_surface_commands_not_enabled", 503);
      }
      let command;
      try {
        const body = exactPrivateEnvelope(JSON.parse(await readRequestBody(request)), ["command"]);
        command = validateWorkbenchCommand(body.command);
        if (command.command === "message.send-status") throw fail("workbench_surface_action_grant_invalid", 400);
      } catch (error) {
        if (error instanceof HelloLynkWorkbenchSurfaceError) throw error;
        throw fail("workbench_surface_command_invalid", 400);
      }
      const issued = await mutateAccount(() => adapter.issueActionGrant(command));
      const grantEnvelope = exactPrivateEnvelope(issued, ["actionGrant"]);
      return json(response, 200, { actionGrant: privateActionGrant(grantEnvelope.actionGrant) });
    }
    if (request.method === "POST" && url.pathname === "/api/v1/command") {
      assertCsrf(request, session);
      if (typeof adapter.issueActionGrant !== "function" || typeof adapter.executeCommand !== "function") {
        throw fail("workbench_surface_commands_not_enabled", 503);
      }
      let command;
      let actionGrant;
      let statusRead = false;
      try {
        const body = JSON.parse(await readRequestBody(request));
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("workbench_surface_command_invalid");
        command = validateWorkbenchCommand(body.command);
        statusRead = command.command === "message.send-status";
        const expectedKeys = statusRead ? ["command"] : ["actionGrant", "command"];
        exactPrivateEnvelope(body, expectedKeys);
        actionGrant = statusRead ? null : privateActionGrant(body.actionGrant);
      } catch (error) {
        if (error instanceof HelloLynkWorkbenchSurfaceError) throw error;
        throw fail("workbench_surface_command_invalid", 400);
      }
      const result = validateWorkbenchCommandResult(
        await mutateAccount(() => adapter.executeCommand(
          command,
          statusRead ? Object.freeze({}) : Object.freeze({ actionGrant }),
        )),
        command.command,
      );
      return json(response, 200, { result });
    }
    throw fail("workbench_surface_route_not_found", 404);
  }

  async function staticFile(request, response, pathname) {
    assertHost(request, origin);
    const bytes = staticFiles.get(pathname);
    if (!bytes) throw fail("workbench_surface_static_unavailable");
    const [, type] = servedFiles[pathname];
    const extra = pathname === pagePath ? ensureNavigationSession(request) : {};
    response.writeHead(200, { ...securityHeaders(type, pathname === pagePath ? trustedParentOrigin : null), ...extra });
    response.end(bytes);
  }

  function openEventStream(request, response, session) {
    response.writeHead(200, {
      ...securityHeaders("text/event-stream; charset=utf-8"),
      connection: "keep-alive",
      "cache-control": "no-store, no-transform",
    });
    response.write(": hellolynk-workbench\n\n");
    const client = { response, session, needsReady: true };
    eventClients.add(client);
    if (typeof adapter.readChanges === "function") void pollChanges();
    // Comments keep idle proxy connections alive, without renewing authority.
    const heartbeat = setInterval(() => {
      if (response.writableEnded || response.destroyed) return;
      if (session.expiresAt < Date.now()) response.end();
      else response.write(": keepalive\n\n");
    }, EVENT_HEARTBEAT_MS);
    heartbeat.unref();
    response.once("close", () => {
      clearInterval(heartbeat);
      eventClients.delete(client);
      if (!eventClients.size) { clearTimeout(changeTimer); changeTimer = null; }
    });
  }

  // The Host already exposes an authorized cursor query. Poll only while a
  // browser is listening; never read message bodies or create another Host.
  async function pollChanges() {
    if (closed || changeBusy || !eventClients.size) return;
    clearTimeout(changeTimer);
    changeTimer = null;
    changeBusy = true;
    try {
      const batch = await adapter.readChanges({ afterCursor: changeCursor });
      if (closed || !eventClients.size) return;
      const generation = batch?.hostGeneration ?? null;
      const replacedHost = generation !== null && changeGeneration !== null && generation !== changeGeneration;
      if (!batch || (generation !== null && !/^[a-f0-9]{48}$/.test(generation))
        || !Number.isSafeInteger(batch.cursor) || batch.cursor < 0 || (!replacedHost && batch.cursor < changeCursor)
        || typeof batch.snapshotRequired !== "boolean" || !Array.isArray(batch.events) || batch.events.length > 256) {
        throw fail("workbench_surface_change_response_invalid", 502);
      }
      changeCursor = batch.cursor;
      changeGeneration = generation;
      // Deliver a change before recovery, so the UI's one active read absorbs
      // both signals instead of starting an immediately obsolete first read.
      if (replacedHost || batch.snapshotRequired || batch.events.length) {
        notifyChange({ hostGeneration: generation, revision: null, changeCursor: String(changeCursor), snapshotRequired: true });
      }
      for (const client of eventClients) {
        if (client.needsReady && client.session.expiresAt >= Date.now()
          && !client.response.writableEnded && !client.response.destroyed) {
          client.response.write("event: source-ready\ndata: {}\n\n");
          client.needsReady = false;
        }
      }
    } catch (error) {
      // A replaced Host may restart its cursor. The next read starts from zero;
      // no command, grant or message is replayed as part of recovery.
      if (error?.code === "host_app_state_conflict") changeCursor = 0;
      const payload = JSON.stringify({ code: publicCode(error) });
      if (!closed) for (const client of eventClients) {
        if (client.response.writableEnded || client.response.destroyed) continue;
        if (client.session.expiresAt < Date.now()) { client.response.end(); continue; }
        client.needsReady = true;
        client.response.write(`event: source-error\ndata: ${payload}\n\n`);
      }
    } finally {
      changeBusy = false;
      if (!closed && eventClients.size) {
        changeTimer = setTimeout(pollChanges, changePollMs);
        changeTimer.unref?.();
      }
    }
  }

  function notifyChange(change = {}) {
    const payload = JSON.stringify({
      hostGeneration: change.hostGeneration == null ? null : opaque(change.hostGeneration),
      revision: change.revision == null ? null : opaque(change.revision),
      changeCursor: opaque(change.changeCursor),
      snapshotRequired: change.snapshotRequired !== false,
    });
    for (const client of eventClients) {
      if (client.response.writableEnded || client.response.destroyed) {
        eventClients.delete(client);
        continue;
      }
      if (client.session.expiresAt < Date.now()) {
        client.response.end();
        eventClients.delete(client);
        continue;
      }
      client.response.write(`event: changed\ndata: ${payload}\n\n`);
    }
  }

  function ensureNavigationSession(request) {
    // An existing browser cookie must not turn a framed navigation into a
    // bypass of the exact parent check. Rejected frames never consume the arm.
    const knownFrameSession = sessions.get(cookies(request.headers.cookie).get(sessionCookieName));
    const allowFrameSelfReload = Boolean(knownFrameSession?.expiresAt >= Date.now());
    if (request.headers["sec-fetch-dest"] === "iframe") {
      assertTopLevelNavigation(request, origin, allowSameSiteTopLevelNavigation, trustedParentOrigin, allowFrameSelfReload);
    }
    expireSessions();
    const now = Date.now();
    const existingId = cookies(request.headers.cookie).get(sessionCookieName);
    const existing = existingId && sessions.get(existingId);
    if (existing?.expiresAt >= now) {
      if (navigationArmedUntil >= now) {
        assertTopLevelNavigation(request, origin, allowSameSiteTopLevelNavigation, trustedParentOrigin, allowFrameSelfReload);
        navigationArmedUntil = 0;
      }
      return {};
    }
    if (existingId) sessions.delete(existingId);
    assertTopLevelNavigation(request, origin, allowSameSiteTopLevelNavigation, trustedParentOrigin);
    if (now > navigationArmedUntil) throw fail("workbench_surface_navigation_not_armed", 403);
    if (sessions.size) throw fail("workbench_surface_session_already_active", 403);
    navigationArmedUntil = 0;
    const sessionId = randomSecret();
    sessions.set(sessionId, { csrf: randomSecret(), expiresAt: now + SESSION_TTL_MS });
    return { "set-cookie": sessionCookie(sessionCookieName, sessionId) };
  }

  function requireSession(request) {
    expireSessions();
    const id = cookies(request.headers.cookie).get(sessionCookieName);
    const session = id && sessions.get(id);
    if (!session) throw fail("workbench_surface_session_invalid", 401);
    return session;
  }

  function renewSession(request, response, session) {
    const id = cookies(request.headers.cookie).get(sessionCookieName);
    if (sessions.get(id) !== session || session.expiresAt < Date.now()) {
      throw fail("workbench_surface_session_invalid", 401);
    }
    // Only the same valid browser session renews itself. This never arms a new
    // navigation, creates a session, or changes the Host's authorization.
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    response.setHeader("set-cookie", sessionCookie(sessionCookieName, id));
  }

  function armNavigation() {
    if (!origin || closed) throw fail("workbench_surface_not_startable");
    navigationArmedUntil = Date.now() + navigationWindowMs;
    return Object.freeze({ origin, cleanUrl: `${origin}${pagePath}`, expiresAtMs: navigationArmedUntil });
  }

  async function start() {
    if (origin || closed) throw fail("workbench_surface_not_startable");
    staticFiles = new Map(await Promise.all(Object.entries(servedFiles).map(async ([pathname, [relative]] ) => {
      const file = path.resolve(uiRoot, relative);
      const allowedRoot = moduleDir;
      if (file !== allowedRoot && !file.startsWith(`${allowedRoot}${path.sep}`)) throw fail("workbench_surface_static_path_invalid");
      let bytes = await readFile(file);
      if (pathname === pagePath && typeof options.openAccount === "function") {
        bytes = Buffer.from(bytes.toString("utf8").replace("<body>", '<body data-native-account-links="true">'));
      }
      if (pathname === pagePath && syntheticMarker) bytes = markSyntheticPreview(bytes);
      return [pathname, bytes];
    })));
    const surfaceHostname = trustedParentOrigin ? new URL(trustedParentOrigin).hostname : LOOPBACK;
    let address;
    for (let attempt = 0; ; attempt += 1) {
      await listenOnLoopback(server, port, LOOPBACK);
      address = server.address();
      if (!address || typeof address === "string" || address.address !== LOOPBACK) {
        await closeServer(server);
        throw fail("workbench_surface_loopback_binding_failed");
      }
      // localhost can resolve to either loopback family. Both listeners must
      // share one port and session store, without opening a LAN interface.
      if (surfaceHostname === "localhost") {
        ipv6Server = http.createServer(handleRequest);
        try {
          await listenOnLoopback(ipv6Server, address.port, "::1");
        } catch (error) {
          ipv6Server = null;
          if (!["EAFNOSUPPORT", "EPROTONOSUPPORT", "EADDRNOTAVAIL", "ENODEV"].includes(error.code)) {
            await closeServer(server);
            // An ephemeral IPv4 port can already be occupied on IPv6.
            if (port === 0 && error.code === "EADDRINUSE" && attempt < 2) continue;
            throw error;
          }
        }
      }
      break;
    }
    // Preserve the actual Gateway hostname for SameSite cookies and framing.
    origin = `http://${surfaceHostname}:${address.port}`;
    // Cookies are shared across ports on one host. Keep each client surface's
    // session separate without changing its navigation or authorization rules.
    sessionCookieName = `__Host-hellolynk_workbench_${address.port}`;
    const cleanUrl = `${origin}${pagePath}`;
    if (!deferInitialNavigationArm) armNavigation();
    return Object.freeze({ origin, cleanUrl, host: LOOPBACK, port: address.port });
  }

  async function close() {
    closed = true;
    clearTimeout(changeTimer);
    sessions.clear();
    for (const client of eventClients) client.response.end();
    eventClients.clear();
    await Promise.all([closeServer(server), closeServer(ipv6Server)]);
  }

  function status() {
    expireSessions();
    return Object.freeze({
      origin,
      boundToLoopback: Boolean(origin),
      navigationArmed: navigationArmedUntil >= Date.now(),
      liveSessionCount: sessions.size,
      eventClientCount: eventClients.size,
      syntheticPreview,
      syntheticMarker,
      pagePath,
      allowSameSiteTopLevelNavigation,
    });
  }

  function expireSessions() {
    const now = Date.now();
    for (const [id, session] of sessions) if (session.expiresAt < now) sessions.delete(id);
  }

  return Object.freeze({ start, armNavigation, notifyChange, close, status });
}

function normalizePagePath(value) {
  const pagePath = value ?? "/workbench";
  if (!["/workbench", "/inbox"].includes(pagePath)) throw fail("workbench_surface_page_path_invalid");
  return pagePath;
}

function normalizeTrustedParentOrigin(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > 128) throw fail("workbench_surface_parent_origin_invalid");
  let url;
  try { url = new URL(value); } catch { throw fail("workbench_surface_parent_origin_invalid"); }
  // Match a complete loopback origin, never a URL prefix or page suffix.
  // The surface advertises this same hostname while binding only to loopback.
  if (url.protocol !== "http:" || ![LOOPBACK, "localhost"].includes(url.hostname)
    || url.username || url.password || url.pathname !== "/" || url.search || url.hash
    || url.origin !== value || Number(url.port || 80) < 1) {
    throw fail("workbench_surface_parent_origin_invalid");
  }
  return url.origin;
}

function markSyntheticPreview(bytes) {
  let output = bytes.toString("utf8");
  for (const [expected, replacement] of [
    [
      '<div id="synthetic-banner" class="synthetic-banner" hidden role="status"></div>',
      '<div id="synthetic-banner" class="synthetic-banner" role="status">固定合成测试数据 · 不是真实 HelloLynk 数据 / Fixed synthetic test data · not real HelloLynk data</div>',
    ],
    ['<span class="host-dot" aria-hidden="true"></span>', '<span class="host-dot is-synthetic" aria-hidden="true"></span>'],
    ['<span id="host-status">正在打开</span>', '<span id="host-status">合成数据 / Synthetic data</span>'],
    ['<h2 id="state-title">正在打开 HelloLynk</h2>', '<h2 id="state-title">正在打开合成预览 / Opening synthetic preview</h2>'],
    [
      '<p id="state-message">正在读取这台电脑上的消息。</p>',
      '<p id="state-message">正在读取固定合成数据，不会连接本机 Host。 / Reading fixed synthetic data without connecting to the local Host.</p>',
    ],
  ]) {
    if (!output.includes(expected)) throw fail("workbench_surface_synthetic_marker_missing");
    output = output.replace(expected, replacement);
  }
  return Buffer.from(output);
}

function validateAdapter(value) {
  if (!value || typeof value.readSnapshot !== "function") {
    throw fail("workbench_surface_adapter_required");
  }
  const hasIssuer = typeof value.issueActionGrant === "function";
  const hasExecutor = typeof value.executeCommand === "function";
  if (hasIssuer !== hasExecutor) throw fail("workbench_surface_action_grant_adapter_required");
  return value;
}

function exactPrivateEnvelope(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw fail("workbench_surface_command_invalid", 400);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw fail("workbench_surface_command_invalid", 400);
  }
  return value;
}

function privateActionGrant(value) {
  const grant = String(value || "");
  if (!ACTION_GRANT.test(grant)) throw fail("workbench_surface_action_grant_invalid", 403);
  return grant;
}

async function readRequestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1024) throw fail("workbench_surface_command_too_large", 413);
    chunks.push(chunk);
  }
  if (size === 0) throw fail("workbench_surface_command_invalid", 400);
  return Buffer.concat(chunks).toString("utf8");
}

function parseUrl(request, origin) {
  const host = String(request.headers.host || "");
  return new URL(request.url || "/", origin || `http://${host || LOOPBACK}`);
}

function assertHost(request, origin) {
  const remote = String(request.socket.remoteAddress || "");
  if (!origin || String(request.headers.host || "") !== new URL(origin).host || ![LOOPBACK, "::1", "::ffff:127.0.0.1"].includes(remote)) {
    throw fail("workbench_surface_host_not_allowed", 403);
  }
}

function listenOnLoopback(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ port, host, ipv6Only: true });
  });
}

async function closeServer(server) {
  if (server?.listening) await new Promise((resolve) => server.close(resolve));
}

function assertTopLevelNavigation(request, origin, allowSameSiteTopLevelNavigation = false, trustedParentOrigin = null, allowFrameSelfReload = false) {
  if (request.method !== "GET" || request.headers.origin) throw fail("workbench_surface_navigation_not_allowed", 403);
  const site = String(request.headers["sec-fetch-site"] || "");
  const mode = String(request.headers["sec-fetch-mode"] || "");
  const destination = String(request.headers["sec-fetch-dest"] || "");
  const user = String(request.headers["sec-fetch-user"] || "");
  if (destination === "iframe" && trustedParentOrigin) {
    const referer = String(request.headers.referer || "");
    let parent;
    try { parent = new URL(referer); } catch { throw fail("workbench_surface_navigation_not_allowed", 403); }
    // A frame reloading itself sends its own origin as Referer. It needs the
    // already-issued session and same-origin fetch metadata; first navigation
    // still needs the exact Gateway parent. CSP checks the full ancestor chain.
    const expectedParent = parent.origin === trustedParentOrigin
      || (allowFrameSelfReload && site === "same-origin" && parent.origin === origin);
    if (!["same-origin", "same-site"].includes(site) || mode !== "navigate" || (user && user !== "?1")
      || !expectedParent || parent.username || parent.password || parent.hash) {
      throw fail("workbench_surface_navigation_not_allowed", 403);
    }
    return;
  }
  const allowedSites = allowSameSiteTopLevelNavigation ? ["none", "same-origin", "same-site"] : ["none", "same-origin"];
  if (!allowedSites.includes(site) || mode !== "navigate" || destination !== "document" || (user && user !== "?1")) {
    throw fail("workbench_surface_navigation_not_allowed", 403);
  }
  const referer = String(request.headers.referer || "");
  if (referer) {
    try {
      if (new URL(referer).origin !== origin) throw fail("workbench_surface_navigation_not_allowed", 403);
    } catch (error) {
      if (error instanceof HelloLynkWorkbenchSurfaceError) throw error;
      throw fail("workbench_surface_navigation_not_allowed", 403);
    }
  }
}

function assertSameOrigin(request) {
  const expected = `http://${request.headers.host}`;
  if (String(request.headers.origin || "") !== expected || String(request.headers["sec-fetch-site"] || "same-origin") !== "same-origin") {
    throw fail("workbench_surface_origin_not_allowed", 403);
  }
}

function assertReadOrigin(request) {
  const origin = String(request.headers.origin || "");
  const site = String(request.headers["sec-fetch-site"] || "");
  if ((origin && origin !== `http://${request.headers.host}`) || ["cross-site", "same-site"].includes(site)) {
    throw fail("workbench_surface_origin_not_allowed", 403);
  }
}

function assertCsrf(request, session) {
  if (!sameSecret(request.headers["x-hellolynk-csrf"], session.csrf)) throw fail("workbench_surface_csrf_invalid", 403);
}

function securityHeaders(contentType, trustedParentOrigin = null) {
  const headers = {
    "content-type": contentType,
    "cache-control": "no-store, max-age=0",
    "content-security-policy": "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self';",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
  if (trustedParentOrigin) {
    headers["content-security-policy"] = headers["content-security-policy"].replace("frame-ancestors 'none'", `frame-ancestors ${trustedParentOrigin}`);
    headers["referrer-policy"] = "origin";
    delete headers["x-frame-options"];
  }
  return headers;
}

function json(response, status, value) {
  response.writeHead(status, securityHeaders("application/json; charset=utf-8"));
  response.end(`${JSON.stringify(value)}\n`);
}

function empty(response, status) {
  response.writeHead(status, securityHeaders("text/plain; charset=utf-8"));
  response.end();
}

function cookies(value) {
  const result = new Map();
  for (const part of String(value || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) result.set(part.slice(0, at).trim(), part.slice(at + 1).trim());
  }
  return result;
}

function sameSecret(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sessionCookie(name, id) {
  return `${name}=${id}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1_000)}`;
}

function randomSecret() {
  return crypto.randomBytes(32).toString("base64url");
}

function opaque(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/.test(value)) {
    throw fail("workbench_surface_change_invalid", 400);
  }
  return value;
}

function integer(value, fallback, minimum, maximum, code) {
  const candidate = value ?? fallback;
  if (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum) throw fail(code);
  return candidate;
}

function publicCode(error) {
  const networkCode = error?.cause?.code || error?.code;
  if (error?.name === "TimeoutError" || ["ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT"].includes(networkCode)) return "workbench_surface_host_timeout";
  if (["ECONNREFUSED", "ECONNRESET", "EPIPE", "UND_ERR_SOCKET"].includes(networkCode)) {
    return "workbench_surface_host_unreachable";
  }
  const code = String(error?.code || "workbench_surface_failed");
  return (/^workbench_(surface|snapshot|command|result|revision|unknown|connect|disconnect|account|portal)[a-z0-9_:-]{1,120}$/.test(code)
    || /^(?:host|neutral_host)_[a-z0-9_]{1,100}$/.test(code) || ["hellolynk_node_22_16_required", "powershell7_missing", "credential_helper_unavailable",
      "device_enrollment_name_invalid", "device_enrollment_hellolynk_id_invalid", "device_enrollment_existing_profile_requires_setup",
      "agent_instance_name_invalid", "agent_instance_name_conflict", "device_enrollment_busy",
      "device_enrollment_request_timeout", "device_enrollment_request_failed",
      "device_enrollment_intent_conflict", "device_enrollment_authorization_expired", "device_enrollment_owner_conflict"].includes(code))
    ? code
    : "workbench_surface_failed";
}

function fail(code, status = 500) {
  return new HelloLynkWorkbenchSurfaceError(code, status);
}
