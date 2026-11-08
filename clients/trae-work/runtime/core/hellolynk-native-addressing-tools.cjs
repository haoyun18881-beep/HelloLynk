"use strict";
const ID = { type: "string", minLength: 3, maxLength: 241, pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$" };
const targetSchema = { ...ID, description: "目标对话编号，仅本人指定了对话时填写。" };
const titleSchema = { type: "string", minLength: 1, maxLength: 256, description: "本人点名的完整对话标题。给其他账号的 AI 指定对话时使用。" };
const contactSchema = { type: "string", minLength: 1, maxLength: 160, description: "对方名字。" };
// The Host directory query. A model's `contact` is resolved to these IDs before any adapter call.
const directoryProperties = {
  contactId: ID, recipientDelegateId: ID,
  title: { type: "string", maxLength: 256, description: "对话标题筛选，不唯一时返回候选" },
  project: { type: "string", maxLength: 256, description: "项目/工作区名筛选" },
  cursor: { type: "string", maxLength: 512, description: "上次目录查询的 nextCursor；同一筛选继续下一页" },
  targetConversationId: targetSchema,
};
const queryProperties = { contact: contactSchema, ...directoryProperties };
const queryDescription = "列出本人授权当前 AI 联系的对象。传 contact 可按名字筛选；定位本账号的 AI 对话时可传 title 或 project。给其他账号的 AI 定向发信用发送工具的 targetConversationTitle。";
// The only place the messaging rules are written. Every client's instructions and skill start with it.
const conversationGuidance = "HelloLynk 是本人授权的 AI 通讯。接着已有来往用 hellolynk_reply_authorized_message，沿用来信的 localMessageId 和 conversationKey；发起新通信用 hellolynk_send_authorized_message，contact 填对方名字。每条新消息用新的 clientMessageId；发送失败或结果未知时保留编号并停止，不重发；参数无效时改正后重新调用。收到本聊天的 HelloLynk 自动提醒时，用 hellolynk_claim_message 按 batchId 读一次。没有本聊天的提醒或本人查信要求时，不主动查信。用户要看全部来信时，打开本客户端的 HelloLynk 界面供本人查看。";
// What every client shows for the shared tools; nativeTool applies it.
const toolText = Object.freeze({
  hellolynk_reply_authorized_message: { title: "回复来信", description: "接着当前对话的一封来信发送；不接手其他对话。" },
  hellolynk_send_authorized_message: { title: "发起通信", description: "向本人授权的联系人发起新通信。contact 填对方名字；本人点名了对话时，targetConversationTitle 填完整标题。未指定对话的新通信默认送到对方的 HelloLynk 独立会话；要继续已有来往，用 hellolynk_reply_authorized_message 回复原信。" },
  hellolynk_list_authorized_contacts: { title: "查找联系人", description: queryDescription },
  hellolynk_claim_message: { title: "读取来信", description: "按自动提醒里的 batchId 一次读取整批来信（合计不超过 2 万字）；手动读单条传 localMessageId 和 conversationKey。" },
  hellolynk_list_pending_messages: { title: "待处理来信", description: "列出当前对话等待 AI 处理的来信，不含正文。" },
  hellolynk_host_status: { title: "连接状态", description: "查看本机 HelloLynk 连接状态。" },
  hellolynk_open_inbox: { title: "打开 HelloLynk", description: "打开 HelloLynk 界面。" },
  hellolynk_get_unread_count: { title: "未读数", description: "查看当前对话的人类未读和 AI 待处理数量；两者含义不同。" },
  hellolynk_list_authorized_inbox_messages: { title: "最近来信", description: "列出当前对话最近 10 条来信，不含正文；要更早的，把最后一条的 localMessageId 填进 before。" },
  hellolynk_read_authorized_inbox_message: { title: "读取一条来信", description: "读取当前对话的一条来信正文。" },
  hellolynk_list_authorized_contact_requests: { title: "联系申请", description: "列出联系申请。" },
  hellolynk_read_authorized_contact_request: { title: "读取联系申请", description: "读取一条联系申请。" },
});
const paramText = Object.freeze({
  clientMessageId: "本条消息的唯一编号。",
  text: "消息正文，最多 20480 字节（中文约 6800 字）。",
  localMessageId: "来信编号。",
  conversationKey: "来信会话键。",
  batchId: "自动提醒里的批次编号。",
  before: "上一页最后一条的 localMessageId。",
});
const ALLOW_PATH = "请本人在 HelloLynk → 联系人 → 对方的 AI → AI 权限里点“允许”。";
const RELEASE_SUPERSEDED_TEXT = "本机 HelloLynk 正在切换到新版本，请稍后重试。";
const POWERSHELL7_MISSING_TEXT = "这台电脑没有 PowerShell 7（pwsh）。请安装 PowerShell 7 后重新打开客户端。";
const REPLY_TARGET_DELETED_TEXT = "原对话已删除，回复未送达。本人可在 HelloLynk 卡片确认新建对话补发。";
const resultText = Object.freeze({
  sent: (status, clientMessageId) => `已发送（status=${status}），clientMessageId=${clientMessageId}。`,
  contacts: count => count ? `已授权联系人 ${count} 个。` : `没有已授权的联系人。${ALLOW_PATH}`,
  inbox: (count, older) => `${older ? "更早" : "最近"}来信 ${count} 条。`,
  pending: count => `待处理来信 ${count} 条。`,
  claimed: (count, expired) => `已读取 ${count} 条。${expired ? `另有 ${expired} 条较早来信超出单次读取上限，未处理。` : ""}`,
  unread: count => `未读 ${count} 条。`,
  ready: url => `HelloLynk 已就绪：${url}`,
});
const replyHintSchema = { type: "object", additionalProperties: false, required: ["tool", "arguments"], properties: {
  tool: { type: "string", const: "hellolynk_reply_authorized_message" },
  arguments: { type: "object", additionalProperties: false, required: ["localMessageId", "conversationKey"],
    properties: { localMessageId: ID, conversationKey: ID } },
} };
// A convenience projection of this letter's Host identifiers, not a new route
// or permission. Never copy a sender-supplied reply object or invent send IDs.
function replyHint(message) {
  if (message.automaticDeliveryState === "expired" || message.automationStatus === "expired") return {};
  return { reply: { tool: "hellolynk_reply_authorized_message",
    arguments: { localMessageId: message.localMessageId, conversationKey: message.conversationKey } } };
}
function addressingError(code) { return Object.assign(new Error(code), { code }); }
function fail() { throw addressingError("native_addressing_arguments_invalid"); }
function queryArgs(args = {}) {
  if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).some(k => !Object.hasOwn(directoryProperties, k))) fail();
  if (Object.keys(args).length === 0) return {};
  for (const key of ["contactId", "recipientDelegateId"]) if (typeof args[key] !== "string" || !new RegExp(ID.pattern).test(args[key])) fail();
  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string") fail();
    const max = directoryProperties[key].maxLength;
    // Only title/project use Unicode code points; keep other field limits unchanged.
    const tooLong = key === "title" || key === "project"
      ? value.length > max * 2 || [...value].length > max
      : value.length > max;
    if (tooLong) fail();
  }
  if (args.targetConversationId != null) optionalTarget(args);
  return { ...args };
}
function optionalTarget(args) {
  if (Object.hasOwn(args, "targetConversationTitle")) {
    const title = args.targetConversationTitle;
    if (Object.hasOwn(args, "targetConversationId") || typeof title !== "string"
      || !title.trim() || title.includes("\0") || title.length > 512 || [...title].length > 256) fail();
    return { targetConversationTitle: title.trim() };
  }
  if (!Object.hasOwn(args, "targetConversationId")) return {};
  if (typeof args.targetConversationId !== "string" || !new RegExp(ID.pattern).test(args.targetConversationId)) fail();
  return { targetConversationId: args.targetConversationId };
}
// A send names its recipient by `contact`, or by the exact contactId + recipientDelegateId pair.
function sendArgumentKeys(args) {
  return ["clientMessageId", "text", ...(Object.hasOwn(args, "contact") ? ["contact"] : ["contactId", "recipientDelegateId"]),
    ...Object.keys(optionalTarget(args))];
}
// `contact` matches the person's or the AI's name exactly, ignoring case and outer spaces.
async function contactMatches(contact, listContacts) {
  if (typeof contact !== "string" || !contact.trim() || contact.length > contactSchema.maxLength) fail();
  const wanted = contact.trim().toLowerCase();
  const result = await listContacts({});
  if (!Array.isArray(result?.contacts)) throw addressingError("host_app_response_invalid");
  return result.contacts.filter(item => [item?.displayName, item?.instanceDisplayName]
    .some(name => typeof name === "string" && name.trim().toLowerCase() === wanted)).map(item => {
    const candidate = { contactId: item.contactId, displayName: item.displayName, recipientDelegateId: item.recipientDelegateId, instanceDisplayName: item.instanceDisplayName };
    if (Object.values(candidate).some(value => typeof value !== "string" || !value || value.length > 241 || /[\0-\x1f]/.test(value))) throw addressingError("host_app_response_invalid");
    return candidate;
  });
}
function onlyMatch(matches) {
  if (!matches.length) throw addressingError("contact_not_found");
  if (matches.length > 1) throw Object.assign(addressingError("contact_ambiguous"), { candidates: matches });
  return { contactId: matches[0].contactId, recipientDelegateId: matches[0].recipientDelegateId };
}
// The IDs a send goes to. Resolving `contact` lists contacts and nothing more.
async function sendRecipient(args, listContacts) {
  if (!Object.hasOwn(args, "contact")) return { contactId: args.contactId, recipientDelegateId: args.recipientDelegateId };
  return onlyMatch(await contactMatches(args.contact, listContacts));
}
// The model's contact lookup. `contact` filters by name; with title, project, cursor or
// targetConversationId its one match is looked up in that AI's conversation directory.
async function findContacts(args, listContacts) {
  if (!args || typeof args !== "object" || Array.isArray(args) || !Object.hasOwn(args, "contact")) return listContacts(queryArgs(args));
  const { contact, ...query } = args;
  if (Object.hasOwn(query, "contactId") || Object.hasOwn(query, "recipientDelegateId")) fail();
  const matches = await contactMatches(contact, listContacts);
  if (!Object.keys(query).length) {
    if (!matches.length) throw addressingError("contact_not_found");
    return { contacts: matches };
  }
  return listContacts(queryArgs({ ...onlyMatch(matches), ...query }));
}
// Describe the validated request after the send receipt has been accepted.
// This is the chosen route, not proof of native delivery or model execution.
function firstSendReceipt(args, status) {
  const target = optionalTarget(args);
  return {
    destination: Object.keys(target).length ? { mode: "specified_conversation", ...target } : { mode: "independent_conversation" },
    text: resultText.sent(status, args.clientMessageId),
  };
}
function nativeAddressingError(error, attempt = null) {
  const reasons = {
    __proto__: null,
    model_inbox_context_unavailable: failureText("model_inbox_context_unavailable"),
    model_inbox_other_conversation: failureText("model_inbox_other_conversation"),
    model_inbox_owner_pending: failureText("model_inbox_owner_pending"),
    model_inbox_unassigned: failureText("model_inbox_unassigned"),
    model_inbox_scope_invalid: failureText("model_inbox_scope_invalid"),
    model_inbox_unavailable: failureText("model_inbox_unavailable"),
    native_directory_own_ai_only: "对话目录只供本账号查询。给其他账号的 AI 指定对话时，请在发送工具里填完整标题。",
    native_target_not_authorized: "没有向这个指定对话发送的权限。",
    native_directory_unavailable: "这个 AI 的对话目录当前不可用，接收端可能需要更新或重新打开。",
    e2ee_peer_identity_pin_mismatch: "接收端设备身份与连接记录不一致，需重新连接 HelloLynk。",
    recipient_e2ee_device_offline: "接收端当前未连接，请本人打开对应客户端。",
    e2ee_prekey_claim_rate_limited: "这两端的加密准备名额暂时已用满，需要等待释放，不要连续重试。",
    relay_request_body_too_large: "中继入口拒绝了过大的请求，正文未发送。",
    native_target_unsupported_or_unavailable: "这个 AI 当前不支持指定原对话，或接收入口不可用。",
    native_target_unavailable: "指定对话已归档、删除或当前不能接收。",
    native_target_title_not_unique: "未发出：接收端没有找到唯一可用的同名对话。请核对完整标题；对方客户端没打开时也会这样。",
    native_target_title_required: "未发出：给其他账号的 AI 指定对话时，请填完整标题。",
    native_addressing_arguments_invalid: "联系人可填名字，或同时填联系人和 AI 的编号。指定对话时只填完整标题或对话编号其中一项。",
    native_directory_cursor_invalid: "目录筛选或游标不匹配，请去掉 cursor 重新查询。",
    native_directory_query_invalid: "目录查询参数无效，请只使用工具列出的筛选字段。",
    native_conversation_id_invalid: "对话编号无效，请使用目录或本人提供的准确编号。",
    contact_not_found: "没有叫这个名字的已授权联系人。",
    contact_ambiguous: "匹配到多个 AI，请在 candidates 里选一个，用 contactId 和 recipientDelegateId 重新调用。",
  };
  const code = error?.code, reason = reasons[code];
  // Recipient arguments are checked before anything is sent, so the same call can be corrected and repeated.
  const corrected = Boolean(attempt) && ["input_validation", "preparation"].includes(attempt.phase)
    && ["contact_not_found", "contact_ambiguous", "native_addressing_arguments_invalid"].includes(code);
  if (!reason || (attempt && !corrected && attempt.phase !== "adapter_call" && !code.startsWith("model_inbox_"))) return null;
  return { content: [{ type: "text", text: reason }],
    structuredContent: { ok: false, errorCode: code, ...(attempt ? { status: "not_sent", phase: corrected ? "input_validation" : attempt.phase,
      ...(attempt.clientMessageId ? { clientMessageId: attempt.clientMessageId } : {}), automaticRetryAllowed: corrected || (code === "model_inbox_owner_pending" && attempt.phase === "preparation") } : {}),
    ...(code === "contact_ambiguous" ? { candidates: error.candidates } : {}) }, isError: true };
}
// What a failed send or reply means. The phase comes only from this invocation:
// input_validation checks arguments, preparation runs before the adapter is called.
function writeFailure(code, phase) {
  const called = phase === "adapter_call" || phase === "response_validation";
  const outcome = (status, automaticRetryAllowed, text) => ({ status, automaticRetryAllowed, text });
  if (phase === "adapter_call" && code === "host_app_authorization_required") return outcome("not_delivered", false, `未送达：尚未获准向此接收方发送。${ALLOW_PATH}`);
  if (phase === "adapter_call" && code === "host_app_record_not_found") return outcome("not_delivered", false, "未送达：联系人、接收方或原消息已不存在。");
  if (called && code === "host_app_reply_target_deleted") return outcome("not_delivered", false, REPLY_TARGET_DELETED_TEXT);
  // Raised only while connecting to the local Host, before anything is sent.
  if (code === "neutral_host_release_superseded") return outcome("not_sent", false, RELEASE_SUPERSEDED_TEXT);
  if (code === "powershell7_missing") return outcome(called ? "send_failed_or_unknown" : "not_sent", false, POWERSHELL7_MISSING_TEXT);
  if (phase === "input_validation") return outcome("not_sent", true, `参数无效：${code}。改正后重新调用，可沿用同一 clientMessageId。`);
  if (!called) return outcome("not_sent", false, failureText(code));
  return outcome("send_failed_or_unknown", false, `发送结果未知：${code}。请在 HelloLynk 通讯里看这条消息的状态，确认没发出再重发。`);
}
function failureText(code) {
  return { __proto__: null,
    model_inbox_context_unavailable: "无法确定本次调用所在的对话，尚未查信或处理来信。请在客户端原对话中重试。",
    model_inbox_other_conversation: "这封来信属于其他对话，请回到对应对话处理。查看全部来信请打开 HelloLynk 界面。",
    model_inbox_owner_pending: "来信的对话归属正在记录，尚未领取或发送。请稍后沿用原参数重试本次调用；回信沿用同一个 clientMessageId，不要重新发起一条消息。",
    model_inbox_unassigned: "这封来信缺少可确认的对话归属，尚未领取或发送。",
    model_inbox_scope_invalid: "查信只限当前对话，无需选择范围。查看全部来信请打开 HelloLynk 界面。",
    model_inbox_unavailable: "当前客户端尚未接入按对话查信，请在统一更新后重试。",
    host_app_reply_target_deleted: REPLY_TARGET_DELETED_TEXT,
    host_native_inbox_upgrade_required: "本机 HelloLynk 版本过低。请关闭所有接入 HelloLynk 的客户端，再重新打开。",
    neutral_host_release_superseded: RELEASE_SUPERSEDED_TEXT,
    powershell7_missing: POWERSHELL7_MISSING_TEXT,
  }[code] ?? `HelloLynk 操作失败：${code}。`;
}
function nativeTool(tool) {
  const named = { ...tool, ...toolText[tool.name] };
  const scoped = ["hellolynk_get_unread_count", "hellolynk_list_authorized_inbox_messages",
    "hellolynk_read_authorized_inbox_message", "hellolynk_list_pending_messages"].includes(tool.name);
  if (scoped) {
    named.inputSchema = { ...tool.inputSchema, properties: { ...tool.inputSchema.properties,
      ...(tool.name === "hellolynk_list_pending_messages" ? { cursor: { type: "integer", minimum: 0, description: "上一页返回的 nextCursor。" } } : {}),
    } };
    if (named.outputSchema?.properties && !named.outputSchema.properties.contract) named.outputSchema = { ...named.outputSchema, properties: {
      ...named.outputSchema.properties, scope: { type: "string", const: "current" },
      humanUnreadCount: { type: "integer", minimum: 0 }, aiPendingCount: { type: "integer", minimum: 0 }, nextCursor: { type: "integer", minimum: 0 },
    } };
  }
  if (tool.name === "hellolynk_list_authorized_contacts") return { ...named, inputSchema: { type: "object", additionalProperties: false, required: [], properties: queryProperties } };
  if (tool.name !== "hellolynk_send_authorized_message") return named;
  return { ...named, inputSchema: { ...tool.inputSchema, required: ["clientMessageId", "text"],
    properties: { contact: contactSchema, ...tool.inputSchema.properties, targetConversationId: targetSchema, targetConversationTitle: titleSchema } } };
}
module.exports = { queryArgs, optionalTarget, nativeTool, queryProperties, queryDescription, targetSchema, nativeAddressingError,
  conversationGuidance, replyHint, replyHintSchema, firstSendReceipt, toolText, paramText, resultText, sendArgumentKeys,
  sendRecipient, findContacts, writeFailure, failureText };
