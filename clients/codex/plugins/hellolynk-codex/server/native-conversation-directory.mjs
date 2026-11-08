import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// The desktop's metadata index, read-only. Never read rollout bodies, previews,
// first_user_message or model summaries. Native read_thread still decides
// whether a selected conversation can actually receive a reminder.
export async function readCodexConversationDirectory({ home = process.env.CODEX_HOME || path.join(os.homedir(), ".codex"),
  callerThreadId, projects = [], openDatabase } = {}) {
  const names = (await fs.readdir(home)).filter(name => /^state_\d+\.sqlite$/.test(name))
    .sort((a, b) => Number(b.match(/\d+/)[0]) - Number(a.match(/\d+/)[0]));
  if (!names.length) throw new Error("codex_native_directory_unavailable");
  const Database = openDatabase || ((await import("node:sqlite")).DatabaseSync);
  const db = new Database(path.join(home, names[0]), { readOnly: true });
  try {
    const columns = new Set(db.prepare("PRAGMA table_info(threads)").all().map(row => row.name));
    if (!["id", "title", "cwd", "source", "archived", "creator_account_id"].every(key => columns.has(key)))
      throw new Error("codex_native_directory_schema_unavailable");
    const owner = db.prepare("SELECT creator_account_id FROM threads WHERE id = ?").get(callerThreadId);
    if (!owner) throw new Error("codex_native_directory_owner_unavailable");
    const optional = ["name", "project_id"].filter(key => columns.has(key));
    const rows = db.prepare(`SELECT id, cwd, archived${optional.length ? ", " + optional.join(", ") : ""}
      FROM threads WHERE creator_account_id IS ? AND source IN ('vscode','cli','exec','appServer')`).all(owner.creator_account_id);
    const byProject = new Map(projects.map(project => [project.id || project.projectId, project.name || project.title]));
    return { coverage: "complete", exactTargetSupported: true, conversations: rows.map(row => ({
      // In the native index, title can be the complete first user message.
      // Only the explicit conversation name is metadata safe to export.
      targetConversationId: row.id, title: row.name || row.id,
      project: byProject.get(row.project_id) || path.win32.basename(row.cwd || "") || path.posix.basename(row.cwd || ""),
      state: row.archived ? "archived" : "notLoaded",
    })) };
  } finally { db.close(); }
}
