const DEV_TRUSTED_IDENTITY_PROVENANCE_STATES = new Set([
  "legacy_compat_identity_projection"
]);

export function classifyDevInboundPolicy(identity, trustedPrincipalIds = []) {
  const principalId = normalizeIdentityId(identity?.senderPrincipalId);
  const delegateId = normalizeIdentityId(identity?.senderDelegateId);
  const provenance = normalizeProtocolValue(identity?.identityProvenanceState);
  if (!principalId) return pendingPolicy("sender_principal_missing");
  if (!delegateId) return pendingPolicy("sender_delegate_missing");
  if (principalId === delegateId) return pendingPolicy("sender_identity_collapsed");
  if (!DEV_TRUSTED_IDENTITY_PROVENANCE_STATES.has(provenance)) {
    return pendingPolicy("sender_identity_provenance_untrusted");
  }
  const trusted = new Set(normalizeDevTrustedSenderPrincipalIds(trustedPrincipalIds));
  if (!trusted.has(principalId)) return pendingPolicy("sender_principal_not_dev_trusted");
  // Trust makes a sender eligible for a later, explicit local authorization.
  // It never turns an ordinary remote chat message into model input by itself.
  return pendingPolicy("sender_principal_dev_trusted_requires_human");
}

export function normalizeDevTrustedSenderPrincipalIds(value) {
  if (!Array.isArray(value)) throw new Error("devTrustedSenderPrincipalIds must be an array");
  const normalized = value.map((item) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error("devTrustedSenderPrincipalIds must contain non-empty strings");
    }
    return item.trim();
  });
  return [...new Set(normalized)];
}

function pendingPolicy(reason) {
  return { decision: "pending_human_confirmation", reason };
}

function normalizeIdentityId(value) {
  if (value === undefined || value === null) return "";
  return String(value).trim();
}

function normalizeProtocolValue(value) {
  return typeof value === "string" ? value : "";
}
