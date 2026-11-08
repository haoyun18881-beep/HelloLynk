import { rememberNativeReplyRoute, readNativeReplyRoute } from "../../../clients/core/hellolynk-native-reply-routes.mjs";

const AGENT = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SESSION = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function openClawModelInboxCaller(context) {
  if (!AGENT.test(context?.agentId || "") || !SESSION.test(context?.sessionId || "")
    || typeof context.sessionKey !== "string" || !context.sessionKey.startsWith(`agent:${context.agentId}:`)
    || /:subagent:/.test(context.sessionKey)) return undefined;
  context.assertInvocationCurrent?.();
  return { threadId: `${context.agentId}:${context.sessionId}` };
}

// sessionKey can be reused after /new or reset. Bind to the native session UUID,
// supplied by the host tool factory, so a later conversation cannot inherit mail.
export async function rememberOpenClawOrigin(adapter, context, message) {
  if (!AGENT.test(context?.agentId || "") || !SESSION.test(context?.sessionId || "")) return false;
  if (typeof context.sessionKey !== "string" || !context.sessionKey.startsWith(`agent:${context.agentId}:`)
    || /:subagent:/.test(context.sessionKey)) return false;
  try {
    context.assertInvocationCurrent?.();
    await rememberNativeReplyRoute({ ...adapter.binding, adapterId: "openclaw" }, {
      clientMessageId: message.clientMessageId, threadId: `${context.agentId}:${context.sessionId}`,
      peerDelegateId: message.recipientDelegateId || message.peerDelegateId,
      ...(message.conversationKey ? { conversationKey: message.conversationKey } : {}),
    });
    return true;
  } catch { return false; }
}

export async function resolveOpenClawOrigin(ctx, adapter, message) {
  if (!message.replyToClientMessageId) return null;
  const route = await readNativeReplyRoute({ ...adapter.binding, adapterId: "openclaw" }, message);
  const [agentId, sessionId, extra] = (route?.threadId || "").split(":");
  if (extra || !AGENT.test(agentId || "") || !SESSION.test(sessionId || "")) throw unavailable();
  if (typeof ctx.hellolynkResolveSessionKeyById !== "function" || typeof ctx.hellolynkGetSessionEntry !== "function") throw unavailable();
  const storePath = ctx.channelRuntime.session.resolveStorePath(ctx.cfg?.session?.store, { agentId });
  const sessionKey = await ctx.hellolynkResolveSessionKeyById({ agentId, sessionId, storePath });
  if (typeof sessionKey !== "string" || !sessionKey.startsWith(`agent:${agentId}:`) || /:subagent:/.test(sessionKey)) throw unavailable();
  const origin = { threadId: route.threadId, agentId, sessionId, sessionKey, storePath };
  await assertOpenClawOriginCurrent(ctx, origin);
  if (typeof ctx.hellolynkActiveSessionRun !== "function" || ctx.hellolynkActiveSessionRun(sessionKey)) throw unavailable();
  return origin;
}

export async function assertOpenClawOriginCurrent(ctx, origin) {
  const entry = await ctx.hellolynkGetSessionEntry({ agentId: origin.agentId, sessionKey: origin.sessionKey,
    storePath: origin.storePath, readConsistency: "latest", hydrateSkillPromptRefs: false });
  if (!entry || entry.sessionId !== origin.sessionId || entry.archivedAt != null) throw unavailable();
  return entry;
}

function unavailable() { return Object.assign(new Error("OpenClaw reply origin is unavailable"), { code: "openclaw_reply_origin_unavailable" }); }
