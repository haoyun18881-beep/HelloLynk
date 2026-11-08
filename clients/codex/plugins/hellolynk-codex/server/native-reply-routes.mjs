export { rememberNativeReplyRoute, readNativeReplyRoute } from "../runtime/core/hellolynk-native-reply-routes.mjs";
import { nativeReplyRouteLocation } from "../runtime/core/hellolynk-native-reply-routes.mjs";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const validCaller = value => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/.test(value);

// This is the executor's previously observed source, not a delivery destination.
// Keep it beside the existing routes, scoped to the same HelloLynk identity.
export async function rememberNativeCaller(scope, threadId) {
  if (!validCaller(threadId)) throw new Error("native_caller_invalid");
  const { directory } = nativeReplyRouteLocation(scope);
  await fs.mkdir(directory, { recursive: true });
  const file = path.join(directory, "caller.json");
  const temporary = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify({ threadId }), { flag: "wx" });
    await fs.rename(temporary, file);
  } finally { await fs.unlink(temporary).catch(() => {}); }
}

export async function readNativeCaller(scope) {
  const { directory } = nativeReplyRouteLocation(scope);
  try {
    const record = JSON.parse(await fs.readFile(path.join(directory, "caller.json"), "utf8"));
    return validCaller(record?.threadId) ? record.threadId : null;
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}
