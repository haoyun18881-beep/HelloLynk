"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const { createHash, randomUUID } = require("node:crypto");
const STORE_KEY = "hellolynk.nativeTasks.v1";
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const KEY = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const STATUS = /^[a-z][a-z0-9_]{0,79}$/;
const hash = value => createHash("sha256").update(value).digest("hex");
const object = value => value && typeof value === "object" && !Array.isArray(value);

async function createNativeTaskIndex(scope) {
  const cursor = scope?.adapterId === "cursor";
  const prefix = cursor ? "cursor_native_task" : "workbuddy_native";
  const FORMAT = `hellolynk-${scope?.adapterId}-native-task-index-v1`;
  const failure = () => Object.assign(new Error(`${prefix}_state_invalid`), { code: `${prefix}_state_invalid` });
  if (!scope || !["cursor", "workbuddy"].includes(scope.adapterId) || typeof scope.runtimeRoot !== "string" || !path.isAbsolute(scope.runtimeRoot)
    || [scope.region, scope.principalId, scope.delegateId].some(value => typeof value !== "string" || !ID.test(value))) {
    throw Object.assign(new Error(`${prefix}_scope_invalid`), { code: `${prefix}_scope_invalid` });
  }
  async function safeDirectory(target) {
    for (let current = path.resolve(target); ; current = path.dirname(current)) {
      const stat = await fs.lstat(current).catch(error => { if (error.code === "ENOENT") return null; throw error; });
      if (stat && (!stat.isDirectory() || stat.isSymbolicLink())) throw failure();
      if (path.dirname(current) === current) return;
    }
  }

  async function safeFile(filename) {
    const stat = await fs.lstat(filename).catch(error => { if (error.code === "ENOENT") return null; throw error; });
    if (stat && (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1)) throw failure();
    return stat;
  }

  async function atomicWrite(filename, content) {
    const temporary = `${filename}.${randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temporary, "wx", 0o600);
      await handle.writeFile(content);
      await handle.sync();
      await handle.close(); handle = null;
      await fs.rename(temporary, filename);
    } finally {
      await handle?.close();
      await fs.rm(temporary, { force: true });
    }
  }

  async function* fileChunks(filename) {
    const before = await safeFile(filename);
    if (!before) throw failure();
    const handle = await fs.open(filename, "r");
    try {
      const opened = await handle.stat();
      if (opened.dev !== before.dev || opened.ino !== before.ino) throw failure();
      const buffer = Buffer.alloc(64 * 1024);
      while (true) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (!bytesRead) break;
        yield buffer.subarray(0, bytesRead);
      }
      const after = await handle.stat();
      if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) throw failure();
    } finally { await handle.close(); }
  }

  async function fileHash(filename) {
    const digest = createHash("sha256");
    for await (const chunk of fileChunks(filename)) digest.update(chunk);
    return digest.digest("hex");
  }

  async function backupLegacy(filename, target, expectedHash) {
    if (await safeFile(target)) {
      if (await fileHash(target) !== expectedHash) throw failure();
      return;
    }
    const temporary = `${target}.${randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temporary, "wx", 0o600);
      const digest = createHash("sha256");
      for await (const chunk of fileChunks(filename)) { digest.update(chunk); await handle.writeFile(chunk); }
      if (digest.digest("hex") !== expectedHash || await safeFile(target)) throw failure();
      await handle.sync(); await handle.close(); handle = null;
      await fs.rename(temporary, target);
    } finally { await handle?.close(); await fs.rm(temporary, { force: true }); }
  }

  // The sole supported import is the current installed JSON shape. Token size,
  // nesting and fields stay bounded; the total history is streamed into SQLite.
  // A large or malformed field cannot bypass the previous bounded-input defense.
  async function importLegacy(db, filename) {
    const digest = createHash("sha256");
    async function* tokens() {
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let quoted = false, escaped = false, raw = "";
      for await (const chunk of fileChunks(filename)) {
        digest.update(chunk);
        for (const char of decoder.decode(chunk, { stream: true })) {
          if (quoted) {
            raw += char;
            if (raw.length > 4096) throw failure();
            if (escaped) escaped = false;
            else if (char === "\\") escaped = true;
            else if (char === '"') { quoted = false; yield { string: JSON.parse(raw) }; raw = ""; }
          } else if (char === '"') { quoted = true; raw = char; }
          else if ("{}:,".includes(char)) yield char;
          else if (!/[ \r\n\t]/.test(char)) throw failure();
        }
      }
      if (decoder.decode() || quoted) throw failure();
    }
    const iterator = tokens()[Symbol.asyncIterator]();
    let token;
    const next = async () => { token = await iterator.next(); };
    const expect = async value => { if (token.done || token.value !== value) throw failure(); await next(); };
    const string = async () => {
      if (token.done || !object(token.value) || typeof token.value.string !== "string") throw failure();
      const value = token.value.string; await next(); return value;
    };
    const dictionary = async visit => {
      await expect("{");
      if (token.value === "}") { await next(); return; }
      while (true) {
        const key = await string(); await expect(":"); await visit(key);
        if (token.value === "}") { await next(); return; }
        await expect(",");
      }
    };
    db.exec("CREATE TEMP TABLE import_deliveries (id TEXT PRIMARY KEY, status TEXT, session TEXT) WITHOUT ROWID");
    const existing = db.prepare("SELECT status, session FROM import_deliveries WHERE id = ?");
    const status = db.prepare("INSERT INTO import_deliveries (id,status) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status");
    const session = db.prepare("INSERT INTO import_deliveries (id,session) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET session=excluded.session");
    const putCurrent = db.prepare("INSERT INTO conversations VALUES (?, ?, ?, ?)");
    const roots = new Set();
    try {
      await next();
      const conversations = async () => dictionary(async conversation => {
          if (!KEY.test(conversation)) throw failure();
          const record = {}, fields = new Set();
          await dictionary(async field => {
            if (fields.has(field)) throw failure(); fields.add(field);
            if ((cursor ? ["nativeSessionId", "localMessageId", "status"] : ["nativeSessionId", "createState"]).includes(field)) record[field] = await string();
            else if (field === "deliveries" || field === "messageSessions") {
              await dictionary(async id => {
                const value = await string(), row = existing.get(id);
                if (!ID.test(id)) throw failure();
                if (field === "deliveries") {
                  if (!STATUS.test(value) || row?.status != null) throw failure(); status.run(id, value);
                } else {
                  if (!UUID.test(value) || row?.session != null) throw failure(); session.run(id, value);
                }
              });
            } else throw failure();
          });
          if (!cursor) {
            if (!["creating", "created", "create_unknown"].includes(record.createState)) throw failure();
            record.status = record.createState; record.localMessageId = "";
          }
          validateRecord(conversation, record);
          if (cursor) status.run(record.localMessageId, record.status);
          if (db.prepare("SELECT 1 FROM import_deliveries WHERE status IS NULL LIMIT 1").get()) throw failure();
          putCurrent.run(conversation, record.nativeSessionId, record.localMessageId, record.status);
          db.prepare("INSERT INTO deliveries SELECT ?, id, coalesce(session, ?), status FROM import_deliveries").run(conversation, record.nativeSessionId);
          db.exec("DELETE FROM import_deliveries");
      });
      if (cursor) await dictionary(async root => {
        if (root !== STORE_KEY || roots.has(root)) throw failure(); roots.add(root);
        await conversations();
      });
      else await conversations();
      if (!token.done) throw failure();
      return digest.digest("hex");
    } finally { await iterator.return?.(); db.exec("DROP TABLE import_deliveries"); }
  }

  function validateRecord(key, record) {
    if (!KEY.test(key) || !object(record) || !UUID.test(record.nativeSessionId || "")
      || (cursor ? !ID.test(record.localMessageId || "") : record.localMessageId !== "")
      || (cursor ? !STATUS.test(record.status || "") : !["creating", "created", "create_unknown"].includes(record.status))) throw failure();
  }

  const key = hash(JSON.stringify([scope.adapterId, scope.region, scope.principalId, scope.delegateId]));
  const directory = path.join(scope.runtimeRoot, "native-tasks");
  await safeDirectory(directory);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await safeDirectory(directory);
  const filename = path.join(directory, `${key}.json`);
  const database = path.join(directory, `${key}.sqlite`);
  // An array deliberately fails the previous reader's object-only validation.
  // A code rollback must not silently ignore new delivery evidence and replay it.
  const marker = JSON.stringify([FORMAT, path.basename(database), key]);
  const originalStat = await safeFile(filename);
  const indexed = originalStat && originalStat.size <= 1024 && (await fs.readFile(filename, "utf8")).trim() === marker;
  for (const suffix of ["", "-journal", "-wal", "-shm"]) await safeFile(`${database}${suffix}`);
  if (!await safeFile(database)) {
    if (indexed) throw failure(); // A missing index never means an empty history.
    const handle = await fs.open(database, "wx", 0o600);
    await handle.close();
  }
  const { DatabaseSync } = require("node:sqlite");
  let db;
  try {
    db = new DatabaseSync(database);
    db.exec("PRAGMA busy_timeout=0; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;");
    let sourceHash = "absent";
    const empty = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().length === 0;
    if (empty) {
      if (indexed) throw failure();
      db.exec("BEGIN IMMEDIATE");
      try {
        db.exec(`CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
          CREATE TABLE conversations (key TEXT PRIMARY KEY, nativeSessionId TEXT NOT NULL, localMessageId TEXT NOT NULL, status TEXT NOT NULL) WITHOUT ROWID;
          CREATE INDEX conversations_session ON conversations(nativeSessionId);
          CREATE TABLE deliveries (conversationKey TEXT NOT NULL, messageId TEXT NOT NULL, nativeSessionId TEXT NOT NULL, status TEXT NOT NULL,
            PRIMARY KEY(conversationKey, messageId)) WITHOUT ROWID;`);
        if (originalStat) sourceHash = await importLegacy(db, filename);
        const meta = db.prepare("INSERT INTO metadata VALUES (?, ?)");
        for (const [name, value] of [["format", FORMAT], ["scope", key], ["sourceHash", sourceHash]]) meta.run(name, value);
        db.exec("COMMIT");
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    else if (!indexed && originalStat) sourceHash = await fileHash(filename);
    const meta = Object.fromEntries(db.prepare("SELECT key, value FROM metadata").all().map(row => [row.key, row.value]));
    if (meta.format !== FORMAT || meta.scope !== key || !indexed && meta.sourceHash !== sourceHash) throw failure();
    db.prepare("SELECT key, nativeSessionId, localMessageId, status FROM conversations LIMIT 0").all();
    db.prepare("SELECT conversationKey, messageId, nativeSessionId, status FROM deliveries LIMIT 0").all();
    if (!indexed) {
      // Import the current installed JSON once; retain its exact bytes as the
      // recovery source. An interrupted prepared database is reused only when
      // this source is still identical. No downgrade or state overwrite occurs.
      if (originalStat) await backupLegacy(filename, `${filename}.before-indexed`, sourceHash);
      await safeDirectory(directory);
      const latestHash = await safeFile(filename) ? await fileHash(filename) : "absent";
      if (latestHash !== sourceHash) throw failure();
      await atomicWrite(filename, `${marker}\n`);
    }
    // Validate the required schema before returning a usable dispatcher state.
    const current = db.prepare("SELECT nativeSessionId, localMessageId, status FROM conversations WHERE key = ?");
    const delivery = db.prepare("SELECT nativeSessionId, status FROM deliveries WHERE conversationKey = ? AND messageId = ?");
    const owned = db.prepare("SELECT 1 FROM conversations WHERE nativeSessionId = ? AND (? IS NULL OR status = ?) LIMIT 1");
    const sessions = db.prepare("SELECT DISTINCT nativeSessionId FROM conversations WHERE status = ?");
    const putCurrent = db.prepare("INSERT INTO conversations VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET nativeSessionId=excluded.nativeSessionId, localMessageId=excluded.localMessageId, status=excluded.status");
    const putDelivery = db.prepare("INSERT INTO deliveries VALUES (?, ?, ?, ?) ON CONFLICT(conversationKey, messageId) DO UPDATE SET nativeSessionId=excluded.nativeSessionId, status=excluded.status");
    const deleteCurrent = db.prepare("DELETE FROM conversations WHERE key = ?");
    const deleteDelivery = db.prepare("DELETE FROM deliveries WHERE conversationKey = ? AND messageId = ?");
    const identity = await safeFile(database);
    let closed = false;
    const assertOpen = () => { if (closed) throw failure(); };
    const transaction = fn => {
      assertOpen(); db.exec("BEGIN IMMEDIATE");
      try { const result = fn(); db.exec("COMMIT"); return result; }
      catch (error) {
        try { db.exec("ROLLBACK"); } catch { closed = true; db.close(); }
        throw error;
      }
    };
    async function writable() {
      assertOpen(); await safeDirectory(directory);
      const stat = await safeFile(database);
      const markerStat = await safeFile(filename);
      if (!stat || stat.dev !== identity.dev || stat.ino !== identity.ino || !markerStat || markerStat.size > 1024
        || (await fs.readFile(filename, "utf8")).trim() !== marker) throw failure();
      for (const suffix of ["-journal", "-wal", "-shm"]) await safeFile(`${database}${suffix}`);
    }
    const recordFrom = row => row ? { ...row } : undefined;
    return Object.freeze({
      getConversation(conversation) { assertOpen(); if (!KEY.test(conversation)) throw failure(); return recordFrom(current.get(conversation)); },
      getDelivery(conversation, id) { assertOpen(); if (!KEY.test(conversation) || !ID.test(id)) throw failure(); return recordFrom(delivery.get(conversation, id)); },
      ownsSession(id, status = null) { assertOpen(); return UUID.test(id || "") && Boolean(owned.get(id, status, status)); },
      listSessions(status) { assertOpen(); if (!STATUS.test(status || "")) throw failure(); return sessions.all(status).map(row => row.nativeSessionId); },
      async save(conversation, record, id = null, status = null) {
        validateRecord(conversation, record);
        if (id !== null && (!ID.test(id) || !STATUS.test(status || ""))) throw failure();
        await writable();
        transaction(() => {
          const previous = id === null ? null : delivery.get(conversation, id);
          if (previous && previous.nativeSessionId !== record.nativeSessionId) throw failure();
          putCurrent.run(conversation, record.nativeSessionId, record.localMessageId, record.status);
          if (id !== null) putDelivery.run(conversation, id, record.nativeSessionId, status);
        });
      },
      async rollbackUnsubmitted(conversation, sessionId, previous, id = null) {
        if (!KEY.test(conversation) || !UUID.test(sessionId) || id !== null && !ID.test(id)) throw failure();
        if (previous) validateRecord(conversation, previous);
        await writable();
        return transaction(() => {
          const record = current.get(conversation), attempt = id === null ? null : delivery.get(conversation, id);
          if (record?.nativeSessionId !== sessionId || (id === null ? record.status !== "creating" : attempt?.nativeSessionId !== sessionId || attempt.status !== "dispatching")) return false;
          if (previous) putCurrent.run(conversation, previous.nativeSessionId, previous.localMessageId, previous.status);
          else deleteCurrent.run(conversation);
          if (id !== null) deleteDelivery.run(conversation, id);
          return true;
        });
      },
      close() { if (!closed) { closed = true; db.close(); } },
    });
  } catch (error) { db?.close(); throw failure(); }
}

module.exports = Object.freeze({ createNativeTaskIndex });
