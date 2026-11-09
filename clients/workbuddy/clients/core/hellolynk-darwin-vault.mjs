// macOS-only storage. Keychain holds the wrapping key. The SQLite rollback
// journal and database contain a single authenticated, root-bound ciphertext.
import { spawn } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { closeSync, constants, lstatSync, mkdirSync, openSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

export const DARWIN_HELPER = fileURLToPath(new URL("../platform/darwin/hellolynk-keychain-helper.bin", import.meta.url));
export const DARWIN_VAULT_FILE = "protected-v1.sqlite";
// Neither the wrapping-key process nor the approval UI needs a caller's
// shell, language runtime, dynamic-loader overrides or credential environment.
export function darwinHelperEnvironment() {
  return { HOME: homedir(), PATH: "/usr/bin:/bin", LANG: "en_US.UTF-8" };
}
export function vaultError(code) { return Object.assign(new Error(code), { code }); }

// Validate before creating any missing components (including in a supplied
// storeRoot). Never follow links or create children below a linked ancestor.
export function checkDarwinPath(target, { directory = false, privateMode = false, create = false, missing = false } = {}) {
  if (target === "/" || target !== resolve(target)) throw vaultError("macos_vault_path_invalid");
  const parts = target.slice(1).split("/");
  let current = "/";
  for (const [index, name] of parts.entries()) {
    current = join(current, name);
    const dir = index < parts.length - 1 || directory;
    let st = lstatSync(current, { throwIfNoEntry: false });
    if (!st && create && dir) {
      try { mkdirSync(current, { mode: 0o700 }); }
      catch (error) { if (error.code !== "EEXIST") throw error; }
      st = lstatSync(current);
    }
    if (!st && missing) return null;
    if (!st || st.isSymbolicLink() || (dir ? !st.isDirectory() : !st.isFile())) throw vaultError("macos_vault_path_invalid");
    if (index < parts.length - 1 && ((st.uid !== 0 && st.uid !== process.getuid()) ||
      ((st.mode & 0o022) && !(st.uid === 0 && (st.mode & 0o1000))))) {
      throw vaultError("macos_vault_ancestor_invalid");
    }
    if (index === parts.length - 1) {
      if (privateMode && (st.uid !== process.getuid() || (st.mode & 0o077) || (!dir && st.nlink !== 1))) {
        throw vaultError("macos_vault_permissions_invalid");
      }
      return st;
    }
  }
}

export async function invokeDarwinHelper(helper, args, signal) {
  const st = checkDarwinPath(helper);
  if ((st.mode & 0o022) || (st.uid !== 0 && st.uid !== process.getuid())) throw vaultError("macos_vault_helper_invalid");
  signal?.throwIfAborted();
  return new Promise((ok, reject) => {
    const child = spawn(helper, args, { stdio: ["ignore", "ignore", "pipe", "pipe"],
      env: darwinHelperEnvironment(), signal });
    const chunks = [];
    let size = 0, stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    child.stdio[3].on("data", chunk => {
      size += chunk.length;
      if (size <= 32) chunks.push(chunk);
      else child.kill("SIGKILL");
    });
    child.stderr.on("data", chunk => {
      stderr += chunk;
      if (stderr.length > 256) child.kill("SIGKILL");
    });
    child.on("error", error => { clearTimeout(timer); reject(error); });
    child.on("close", code => {
      clearTimeout(timer);
      const data = Buffer.concat(chunks);
      chunks.forEach(chunk => chunk.fill(0));
      if (code === 0 && data.length === (args[0] === "key" ? 32 : 0)) return ok(data);
      data.fill(0);
      reject(vaultError(/^macos_[a-z0-9_]{1,100}$/.test(stderr.trim()) ? stderr.trim() : "macos_vault_helper_failed"));
    });
  });
}

function openDocument(key, aad, bytes) {
  try {
    const blob = Buffer.from(bytes);
    const cipher = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    cipher.setAAD(aad);
    cipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([cipher.update(blob.subarray(28)), cipher.final()]);
  } catch { throw vaultError("macos_vault_authentication_failed"); }
}

function sealDocument(key, aad, plain) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), body]);
}

// The callback is synchronous. No event-loop work or network I/O is performed
// while SQLite owns the write lock. Concurrent first writers share SecItemAdd's
// winning key and re-read the committed document after BEGIN IMMEDIATE.
export async function withDarwinVault({ root, helperPath = DARWIN_HELPER, readOnly = false, allowMissing = false, signal }, operation) {
  const { DatabaseSync } = await import("node:sqlite");
  const directory = checkDarwinPath(root, { directory: true, privateMode: true, create: !readOnly, missing: readOnly && allowMissing });
  const path = join(root, DARWIN_VAULT_FILE);
  let stat = directory && checkDarwinPath(path, { privateMode: true, missing: true });
  if (!stat) {
    if (readOnly) {
      if (allowMissing) return operation({});
      throw vaultError("host_protected_store_path_invalid");
    }
    try { closeSync(openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)); }
    catch (error) { if (error.code !== "EEXIST") throw error; }
    stat = checkDarwinPath(path, { privateMode: true });
  }
  const newFile = stat.size === 0;
  const key = await invokeDarwinHelper(helperPath, ["key", root, !readOnly && newFile ? "create" : "load"], signal);
  let db, plain, encoded;
  try {
    signal?.throwIfAborted();
    checkDarwinPath(path, { privateMode: true });
    checkDarwinPath(path + "-journal", { privateMode: true, missing: true });
    for (const suffix of ["-wal", "-shm"]) {
      if (lstatSync(path + suffix, { throwIfNoEntry: false })) throw vaultError("macos_vault_journal_invalid");
    }
    db = new DatabaseSync(path, { readOnly, allowExtension: false });
    db.exec("PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=10000");
    if (db.prepare("PRAGMA journal_mode").get().journal_mode !== "delete") throw vaultError("macos_vault_journal_invalid");
    db.exec(readOnly ? "BEGIN" : "BEGIN IMMEDIATE");
    const schema = db.prepare("SELECT sql FROM sqlite_schema WHERE name = 'vault' AND type = 'table'").get();
    if (!schema) {
      if (!newFile || readOnly) throw vaultError("macos_vault_format_invalid");
      db.exec("CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK(id=1), sealed BLOB NOT NULL)");
    }
    const row = db.prepare("SELECT sealed FROM vault WHERE id=1").get();
    if (schema && !row) throw vaultError("macos_vault_format_invalid");
    const aad = Buffer.from("hellolynk-macos-vault-v1\0" + root);
    plain = row ? openDocument(key, aad, row.sealed) : Buffer.from("{}");
    const state = JSON.parse(plain);
    const result = operation(state);
    encoded = Buffer.from(JSON.stringify(state));
    if (!row || !plain.equals(encoded)) {
      if (readOnly) throw vaultError("host_protected_store_read_only");
      db.prepare("INSERT OR REPLACE INTO vault(id,sealed) VALUES(1,?)").run(sealDocument(key, aad, encoded));
    }
    db.exec("COMMIT");
    return result;
  } finally {
    key.fill(0);
    plain?.fill(0);
    encoded?.fill(0);
    db?.close(); // closes or rolls back a transaction whose callback failed
  }
}
