import crypto from "node:crypto";
import { validateDynamicUiEnvelope } from "./dynamic-ui-contract.mjs";

export const TRAE_PRIVATE_UI_CONTRACT = "hellolynk-trae-private-ui-v1";
export const TRAE_UI_ACTION_GATE_CONTRACT = "hellolynk-trae-ui-action-gate-v1";
export const TRAE_UI_ACTION_TOKEN_TTL_MS = 5 * 60 * 1000;
export const TRAE_UI_ACTION_TOKEN_MAX_ENTRIES = 2_048;

const TOKEN = /^hellolynkui_[A-Za-z0-9_-]{43}$/;
const TOOL = /^hellolynk_[a-z0-9_]{3,100}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const MODES = new Set(["exact", "subset", "new-contact", "send-form", "no-target"]);

export function createTraeUiActionGate(options = {}) {
  const now = typeof options.now === "function" ? options.now : Date.now;
  const randomBytes = typeof options.randomBytes === "function" ? options.randomBytes : crypto.randomBytes;
  const ttlMs = integer(options.ttlMs, TRAE_UI_ACTION_TOKEN_TTL_MS, 1_000, 15 * 60 * 1000);
  const maxEntries = integer(options.maxEntries, TRAE_UI_ACTION_TOKEN_MAX_ENTRIES, 1, 10_000);
  const entries = new Map();

  function issue(policy = {}) {
    cleanup();
    if (entries.size >= maxEntries) throw codeError("trae_ui_action_gate_full");
    const toolName = safeTool(policy.toolName);
    const mode = String(policy.mode || "");
    if (!MODES.has(mode)) throw codeError("trae_ui_action_policy_invalid");
    const allowedIds = canonicalIds(policy.allowedIds || []);
    if ((mode === "exact" && allowedIds.length !== 1)
      || (mode === "subset" && allowedIds.length < 1)
      || ((mode === "new-contact" || mode === "send-form" || mode === "no-target") && allowedIds.length > 500)) {
      throw codeError("trae_ui_action_policy_invalid");
    }
    let token;
    do { token = `hellolynkui_${randomBytes(32).toString("base64url")}`; } while (entries.has(digest(token)));
    const issuedAtMs = now();
    const expiresAtMs = issuedAtMs + ttlMs;
    entries.set(digest(token), Object.freeze({ toolName, mode, allowedIds, issuedAtMs, expiresAtMs }));
    return Object.freeze({
      contract: TRAE_UI_ACTION_GATE_CONTRACT,
      token,
      toolName,
      mode,
      expiresAtMs,
    });
  }

  function consume(tokenValue, intent = {}) {
    cleanup();
    const token = String(tokenValue || "");
    if (!TOKEN.test(token)) throw codeError("trae_ui_action_authorization_required");
    const key = digest(token);
    const entry = entries.get(key);
    if (!entry) throw codeError("trae_ui_action_authorization_invalid");
    entries.delete(key);
    if (entry.expiresAtMs <= now()) throw codeError("trae_ui_action_authorization_expired");
    if (entry.toolName !== safeTool(intent.toolName)) throw codeError("trae_ui_action_scope_mismatch");
    const targetIds = canonicalIds(intent.targetIds || []);
    const allowed = new Set(entry.allowedIds);
    if (entry.mode === "exact" && (targetIds.length !== 1 || targetIds[0] !== entry.allowedIds[0])) {
      throw codeError("trae_ui_action_scope_mismatch");
    }
    if (entry.mode === "subset" && (!targetIds.length || targetIds.some((id) => !allowed.has(id)))) {
      throw codeError("trae_ui_action_scope_mismatch");
    }
    if (entry.mode === "new-contact" && targetIds.length !== 0) throw codeError("trae_ui_action_scope_mismatch");
    if (entry.mode === "no-target" && targetIds.length !== 0) throw codeError("trae_ui_action_scope_mismatch");
    if (entry.mode === "send-form") {
      const recipientKind = String(intent.recipientKind || "");
      if (recipientKind === "contact") {
        if (targetIds.length !== 1 || !allowed.has(targetIds[0])) throw codeError("trae_ui_action_scope_mismatch");
      } else if (recipientKind === "typed") {
        if (targetIds.length !== 0) throw codeError("trae_ui_action_scope_mismatch");
      } else throw codeError("trae_ui_action_scope_mismatch");
    }
    return Object.freeze({ ok: true, consumed: true, toolName: entry.toolName, mode: entry.mode });
  }

  function cleanup() {
    const current = now();
    for (const [key, entry] of entries) if (entry.expiresAtMs <= current) entries.delete(key);
  }

  return Object.freeze({ issue, consume, get size() { cleanup(); return entries.size; } });
}

export function createPrivateUiMeta(widgetEnvelope, actionGrants = []) {
  try { validateDynamicUiEnvelope(widgetEnvelope); }
  catch { throw codeError("trae_private_ui_envelope_invalid"); }
  if (!Array.isArray(actionGrants) || actionGrants.length > 16) throw codeError("trae_private_ui_grants_invalid");
  return Object.freeze({
    hellolynkTraePrivateUi: Object.freeze({
      contract: TRAE_PRIVATE_UI_CONTRACT,
      modelVisibility: "none",
      widgetEnvelope,
      actionGrants: Object.freeze(actionGrants.map(validateGrant)),
    }),
  });
}

function validateGrant(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.contract !== TRAE_UI_ACTION_GATE_CONTRACT || !TOKEN.test(String(value.token || ""))
    || !TOOL.test(String(value.toolName || "")) || !MODES.has(String(value.mode || ""))
    || !Number.isSafeInteger(value.expiresAtMs) || value.expiresAtMs < 0) {
    throw codeError("trae_private_ui_grants_invalid");
  }
  return Object.freeze({
    contract: value.contract, token: value.token, toolName: value.toolName,
    mode: value.mode, expiresAtMs: value.expiresAtMs,
  });
}

function canonicalIds(value) {
  if (!Array.isArray(value) || value.length > 500) throw codeError("trae_ui_action_policy_invalid");
  const ids = value.map((item) => { const id = String(item || ""); if (!ID.test(id)) throw codeError("trae_ui_action_policy_invalid"); return id; }).sort();
  if (new Set(ids).size !== ids.length) throw codeError("trae_ui_action_policy_invalid");
  return Object.freeze(ids);
}
function safeTool(value) { const text = String(value || ""); if (!TOOL.test(text)) throw codeError("trae_ui_action_policy_invalid"); return text; }
function digest(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function integer(value, fallback, minimum, maximum) { const number = Number(value ?? fallback); if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw codeError("trae_ui_action_gate_limit_invalid"); return number; }
function codeError(code) { const error = new Error(code); error.code = code; return error; }
