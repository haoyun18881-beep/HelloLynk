const HELLOLYNK_SESSION_KEY_RE = /^agent:[^:\s]+:hellolynk:/i;
const DEFAULT_TTL_MS = 2 * 60 * 1000;
const MAX_PENDING_SESSIONS = 256;
const MAX_PENDING_PER_SESSION = 32;

const pendingBySession = new Map();

export function registerHelloLynkTranscriptAttribution({
  sessionKey,
  body,
  senderLabel,
  originalSession = false,
  now = Date.now(),
  ttlMs = DEFAULT_TTL_MS
}) {
  const normalizedSessionKey = normalizeSessionKey(sessionKey, originalSession);
  const normalizedBody = String(body ?? "");
  const normalizedSenderLabel = normalizeSenderLabel(senderLabel);
  const normalizedNow = requireFiniteNumber(now, "hellolynk transcript attribution time is invalid");
  const normalizedTtl = requireFiniteNumber(ttlMs, "hellolynk transcript attribution ttl is invalid");
  if (!normalizedBody) throw new Error("hellolynk transcript attribution body is missing");
  if (normalizedTtl <= 0 || normalizedTtl > DEFAULT_TTL_MS) {
    throw new Error("hellolynk transcript attribution ttl is out of range");
  }

  pruneExpired(normalizedNow);
  let records = pendingBySession.get(normalizedSessionKey);
  if (!records) {
    if (pendingBySession.size >= MAX_PENDING_SESSIONS) {
      throw new Error("hellolynk transcript attribution session capacity exceeded");
    }
    records = [];
    pendingBySession.set(normalizedSessionKey, records);
  }
  if (records.length >= MAX_PENDING_PER_SESSION) {
    throw new Error("hellolynk transcript attribution per-session capacity exceeded");
  }

  const token = Symbol("hellolynk-transcript-attribution");
  records.push({
    token,
    body: normalizedBody,
    senderLabel: normalizedSenderLabel,
    expiresAt: normalizedNow + normalizedTtl
  });
  return () => removeRecord(normalizedSessionKey, token);
}

export function applyHelloLynkTranscriptAttribution(event, hookContext, now = Date.now()) {
  const message = event?.message;
  if (!message || typeof message !== "object" || String(message.role || "").toLowerCase() !== "user") {
    return undefined;
  }
  if (typeof message.senderLabel === "string" && message.senderLabel.trim()) return undefined;

  const sessionKey = String(hookContext?.sessionKey || event?.sessionKey || "").trim();
  if (!/^agent:[^:\s]+:[^\s]+$/i.test(sessionKey)) return undefined;
  const records = pendingBySession.get(sessionKey);
  if (!records?.length) return undefined;

  const normalizedNow = requireFiniteNumber(now, "hellolynk transcript attribution hook time is invalid");
  const messageTexts = collectMessageTexts(message);
  let matchIndex = -1;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.expiresAt <= normalizedNow) continue;
    if (messageTexts.includes(record.body)) {
      matchIndex = index;
      break;
    }
  }
  pruneSession(sessionKey, normalizedNow);
  if (matchIndex < 0) return undefined;

  const currentRecords = pendingBySession.get(sessionKey);
  const matched = currentRecords?.find((record) => messageTexts.includes(record.body) && record.expiresAt > normalizedNow);
  if (!matched) return undefined;
  removeRecord(sessionKey, matched.token);
  return {
    message: {
      ...message,
      senderLabel: matched.senderLabel
    }
  };
}

function collectMessageTexts(message) {
  const values = [];
  if (typeof message.content === "string") values.push(message.content);
  if (Array.isArray(message.content)) {
    for (const block of message.content) {
      if (!block || typeof block !== "object") continue;
      if (typeof block.text === "string") values.push(block.text);
    }
  }
  if (typeof message.text === "string") values.push(message.text);
  return values;
}

function normalizeSessionKey(value, originalSession) {
  const sessionKey = String(value || "").trim();
  if (!(originalSession === true ? /^agent:[^:\s]+:[^\s]+$/i : HELLOLYNK_SESSION_KEY_RE).test(sessionKey) || sessionKey.length > 1024 || /[\r\n\u0000-\u001f\u007f]/.test(sessionKey)) {
    throw new Error("hellolynk transcript attribution session key is invalid");
  }
  return sessionKey;
}

function normalizeSenderLabel(value) {
  const senderLabel = String(value || "").trim();
  if (!senderLabel || senderLabel.length > 512 || /[\r\n\u0000-\u001f\u007f]/.test(senderLabel)) {
    throw new Error("hellolynk transcript attribution sender label is invalid");
  }
  return senderLabel;
}

function requireFiniteNumber(value, errorMessage) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(errorMessage);
  return number;
}

function pruneExpired(now) {
  for (const sessionKey of pendingBySession.keys()) pruneSession(sessionKey, now);
}

function pruneSession(sessionKey, now) {
  const records = pendingBySession.get(sessionKey);
  if (!records) return;
  const active = records.filter((record) => record.expiresAt > now);
  if (active.length) pendingBySession.set(sessionKey, active);
  else pendingBySession.delete(sessionKey);
}

function removeRecord(sessionKey, token) {
  const records = pendingBySession.get(sessionKey);
  if (!records) return;
  const active = records.filter((record) => record.token !== token);
  if (active.length) pendingBySession.set(sessionKey, active);
  else pendingBySession.delete(sessionKey);
}
