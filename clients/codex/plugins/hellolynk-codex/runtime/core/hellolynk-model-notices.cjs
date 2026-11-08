"use strict";

const { AsyncLocalStorage } = require("node:async_hooks");
// Only collect responses belonging to this model tool invocation. Card refreshes,
// background polling and another account's concurrent call cannot supply notices.
const calls = new AsyncLocalStorage();

function captureHelloLynkModelNotices(response) {
  const call = calls.getStore();
  const state = response?.body?.modelNotices;
  if (call && state && typeof state === "object") {
    call.notices = [];
    if (Number.isSafeInteger(state.pendingContactRequests) && state.pendingContactRequests > 0) {
      call.notices.push(`有 ${state.pendingContactRequests} 个联系申请等你确认。`);
    }
    if (state.localStorageFull === true) call.notices.push("本机存储已满，已暂停接收新消息。");
  }
  return response;
}

function captureHelloLynkNativeDeliveryStatus(state) {
  const call = calls.getStore();
  if (!call) return;
  call.nativeNotices = [];
  if (state?.failure && /^[A-Za-z0-9_:-]{1,100}$/.test(state.failure.code)) {
    call.nativeNotices.push(`本机 AI 收信提醒检查失败（${state.failure.code}），与本次发信结果无关。`);
  }
  if (Number.isSafeInteger(state?.unknownCount) && state.unknownCount > 0) {
    call.nativeNotices.push(`本机 AI 收信提醒：${state.unknownCount} 条近期提醒结果未知；与本次发信结果、对方未读无关，请勿据此重发。`);
  }
}

function appendNotices(result, notices) {
  if (!notices?.length) return result;
  const text = `HelloLynk：${notices.join(" ")}`;
  if (typeof result === "string") {
    try {
      const value = JSON.parse(result);
      return JSON.stringify({ ...value, notices });
    } catch { return `${result}\n${text}`; }
  }
  if (result?.result) return { ...result, result: appendNotices(result.result, notices) };
  if (!Array.isArray(result?.content)) return result;
  return { ...result, content: [...result.content, { type: "text", text }],
    ...(result.structuredContent ? { structuredContent: { ...result.structuredContent, notices } } : {}),
    ...(result.details ? { details: { ...result.details, notices } } : {}) };
}

async function withHelloLynkModelNotices(operation) {
  const call = {};
  return calls.run(call, async () => {
    const result = await operation();
    // A notice can never turn a successful send into an error or cause a resend.
    try { return appendNotices(result, [...(call.notices || []), ...(call.nativeNotices || [])]); } catch { return result; }
  });
}

exports.captureHelloLynkModelNotices = captureHelloLynkModelNotices;
exports.captureHelloLynkNativeDeliveryStatus = captureHelloLynkNativeDeliveryStatus;
exports.withHelloLynkModelNotices = withHelloLynkModelNotices;
