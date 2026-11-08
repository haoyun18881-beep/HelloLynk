import { createNativeInboxRuntime } from "../runtime/core/hellolynk-native-inbox-runtime.mjs";
import { createNativeTaskClient } from "./native-task-client.mjs";
import { readNativeReplyRoute } from "./native-reply-routes.mjs";

export function createNativeTaskRuntime(options = {}) {
  return createNativeInboxRuntime({ native: createNativeTaskClient(), readReplyRoute: readNativeReplyRoute,
    ...options, adapterId: "codex" });
}
