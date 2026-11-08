import { isDeepStrictEqual as equal } from "node:util";
import { join } from "node:path";
import { checkDarwinPath, vaultError, withDarwinVault } from "./hellolynk-darwin-vault.mjs";

const permanent = 253402300799999;
const month = 30 * 86400000;
function fail(code) { throw vaultError(code); }
function fieldsMatch(a, b, fields) { return fields.every(field => equal(a[field], b[field])); }
function sameOwner(a, b) { return fieldsMatch(a, b, ["principalId", "hostInstallationId"]); }
function used(records, field, id) { return records.some(r => r[field].toLowerCase() === id.toLowerCase()); }
function unique(records, missing, ambiguous) {
  if (records.length !== 1) fail(records.length ? ambiguous : missing);
  return records[0];
}
function checkBindingPaths(b) {
  try {
    checkDarwinPath(b.runtimeRoot, { directory: true });
    checkDarwinPath(b.releaseRoot, { directory: true });
    if (checkDarwinPath(b.profileManifestPath).size > 65536 ||
        checkDarwinPath(join(b.releaseRoot, b.runnerRelativePath)).size > 1048576) fail("neutral_codex_launch_manifest_invalid");
  } catch { fail("neutral_codex_launch_manifest_invalid"); }
}
function capMatches(cap, b) {
  return cap.state === "active" && fieldsMatch(cap, b,
    ["region", "principalId", "delegateId", "hostInstallationId", "adapterId", "version", "scopes"]);
}
function addCapability(s, r) {
  if (used(s.caps, "capabilityId", r.capabilityId)) fail("host_capability_id_conflict");
  s.caps.push(r);
}
function revokeCapability(s, r) {
  if (!r) fail("host_capability_missing");
  if (r.state === "active") {
    const revokedAt = Date.now();
    if (revokedAt < r.issuedAt) fail("host_capability_state_invalid");
    // Keep the identifier spent while discarding the retired secret.
    r = s.caps[s.caps.indexOf(r)] = { capabilityId: r.capabilityId, issuedAt: r.issuedAt, state: "revoked", revokedAt };
  }
  return { capabilityId: r.capabilityId, revokedAt: r.revokedAt, state: "revoked" };
}
function codexBinding(s, command, input, oldId) {
  const b = s.codex;
  if (command === "ResolveCodexNeutralBinding" || command === "VerifyCodexNeutralBinding") {
    if (!b) fail("neutral_codex_binding_configuration_required");
    checkBindingPaths(b);
    const active = s.caps.filter(c => c.adapterId === "codex" && c.state === "active");
    const cap = unique(active.filter(c => capMatches(c, b)),
      active.length ? "neutral_codex_capability_binding_mismatch" : "neutral_codex_capability_missing", "neutral_codex_capability_ambiguous");
    if (command.startsWith("Resolve")) return { binding: b, record: cap };
    const {secret, ...record} = cap;
    return { binding: b, record };
  }
  if (command === "SaveCodexNeutralBinding" || command === "RemoveCodexNeutralBinding") {
    checkBindingPaths(input);
    if (command.startsWith("Remove")) {
      if (!equal(b, input)) fail("neutral_codex_binding_invalid");
      s.codex = null;
      return { removed: true };
    }
    if (b && !equal(b, input)) fail("neutral_codex_binding_invalid");
    s.codex = input;
    return { binding: input };
  }
  const { previousBinding: previous, replacementBinding: next, replacementRecord } = input;
  checkBindingPaths(previous);
  checkBindingPaths(next);
  if (!fieldsMatch(previous, next, ["contract","region","principalId","delegateId","hostInstallationId","profileId","adapterId","version","runtimeRoot"])) {
    fail("neutral_codex_capability_binding_mismatch");
  }
  if (!equal(b, previous)) fail("neutral_codex_binding_invalid");
  const active = s.caps.filter(c => capMatches(c, next));
  if (command === "ReplaceCodexNeutralBinding") {
    if (!equal(previous.scopes, next.scopes)) fail("neutral_codex_capability_binding_mismatch");
    if (active.length !== 1) fail("neutral_codex_capability_ambiguous");
    s.codex = next;
    return { binding: next };
  }
  if (command !== "MigrateCodexNeutralBinding") fail("host_protected_store_command_invalid");
  const old = s.caps.find(c => c.capabilityId === oldId);
  if (!old || !capMatches(old, previous) || !capMatches(replacementRecord, next)) fail("neutral_codex_capability_binding_mismatch");
  const other = active.filter(c => c.capabilityId !== oldId);
  if (other.length > 1) fail("neutral_codex_capability_ambiguous");
  if (!other.length) addCapability(s, replacementRecord);
  revokeCapability(s, old);
  s.codex = next;
  return { binding: next, record: other[0] || replacementRecord, replacedCapabilityId: oldId };
}

function retireSession(s, r) {
  s.sessions.splice(s.sessions.indexOf(r), 1);
  s.retiredSessions.push(r.sessionId.toLowerCase());
}
function revokeCredential(s, r, timestamp) {
  if (timestamp < r.issuedAt) fail("host_transport_credential_revoke_timestamp_invalid");
  const sessions = s.sessions.filter(session => session.credentialId === r.credentialId);
  if (r.state === "active") {
    sessions.forEach(session => retireSession(s, session));
    const { credentialId, issuedAt, principalId, hostInstallationId } = r;
    r = s.credentials[s.credentials.indexOf(r)] = { credentialId, issuedAt, principalId, hostInstallationId, state:"revoked", revokedAt:timestamp };
  }
  return { credentialId:r.credentialId, state:"revoked", revokedAt:r.revokedAt, cascadedSessionCount:sessions.length };
}
function exactFields(value, fields) {
  return value && typeof value === "object" && equal(Object.keys(value).sort(), fields.sort());
}
function checkEnrollment(value, record) {
  const a = value?.approval, approved = a?.hostTransportCredential;
  if (!exactFields(value, ["baseUrl","hellolynkId","hostId","deviceLabel","requestId","proof","approval","intents"])
      || !exactFields(a, ["status","principalId","hellolynkId","region","hostId","hostTransportCredential"])
      || !exactFields(approved, ["credentialId","credential","createdAt","expiresAt"])
      || a.status !== "approved" || a.principalId !== record.principalId || a.hostId !== record.hostInstallationId
      || value.hostId !== a.hostId || a.hellolynkId !== value.hellolynkId || approved.credentialId !== record.credentialId
      || approved.credential !== record.secret || Date.parse(approved.createdAt) !== record.issuedAt
      || Date.parse(approved.expiresAt) !== record.expiresAt) fail("device_enrollment_transport_approval_mismatch");
  if (record.expiresAt <= Date.now()) fail("host_transport_credential_expired");
}

function transport(s, q, input) {
  const {command, timestamp} = q;
  const id = q.credentialId || input?.credentialId;
  const credential = s.credentials.find(r => r.credentialId === id);
  const owned = query => s.credentials.filter(r => r.state === "active" && sameOwner(r, query));
  if (command === "SaveTransportCredential" || command === "SaveEnrollmentTransportCredential") {
    const upgrade = command === "SaveEnrollmentTransportCredential";
    if (upgrade) checkEnrollment(s.enrollment.value, input);
    if (credential) {
      if (!equal(credential,input)) fail("host_transport_credential_immutable_conflict");
    } else {
      if (used(s.credentials, "credentialId", id)) fail("host_transport_credential_immutable_conflict");
      const old = owned(input);
      if (old.length > 1 || (old.length && !upgrade)) fail("host_transport_credential_ambiguous");
      if (old.length) revokeCredential(s,old[0],Date.now());
      s.credentials.push(input);
    }
    return { record: input };
  }
  if (command === "VerifyTransportCredentialLifetimeMigration" || command === "MigrateTransportCredentialLifetime") {
    const record = unique(owned(q), "host_transport_migration_credential_inactive_or_ambiguous", "host_transport_migration_credential_inactive_or_ambiguous");
    if (record.expiresAt !== permanent && record.expiresAt - record.issuedAt !== month) fail("host_transport_migration_lifetime_invalid");
    if (command.startsWith("Verify")) return { record };
    if (record.expiresAt-record.issuedAt !== month || !equal(record,input.previous)) fail("host_transport_migration_compare_failed");
    const proof = input.proof;
    if (proof.credentialId !== record.credentialId || proof.hostId !== q.hostInstallationId || proof.principalId !== q.principalId
        || Date.parse(proof.credentialCreatedAt) !== record.issuedAt || Date.parse(proof.credentialExpiresAt) !== permanent) fail("host_transport_migration_proof_invalid");
    record.expiresAt = permanent;
    return { credentialId: record.credentialId, expiresAt: permanent, status:"migrated" };
  }
  if (command === "LoadTransportCredential" || command === "RevokeTransportCredential") {
    if (command.startsWith("Load") && credential?.state !== "active") fail("host_transport_credential_inactive");
    if (!credential) fail("host_transport_credential_missing");
    if (!sameOwner(credential,q)) fail("host_transport_credential_owner_mismatch");
    if (command.startsWith("Revoke")) return revokeCredential(s,credential,timestamp);
    if (credential.expiresAt <= timestamp) fail("host_transport_credential_expired");
    return { record: credential };
  }
  const sessionId = q.sessionId || input?.sessionId;
  const session = s.sessions.find(r => r.sessionId === sessionId);
  if (command === "SaveTransportSession" || command === "ReplaceTransportSession") {
    if (credential?.state !== "active") fail("host_transport_credential_inactive");
    if (!sameOwner(credential,input) || credential.expiresAt <= timestamp || input.expiresAt > credential.expiresAt) fail("host_transport_session_credential_mismatch");
    if (s.retiredSessions.includes(sessionId.toLowerCase())) fail("host_transport_session_retired");
    if (session) {
      if (!equal(session,input)) fail("host_transport_session_immutable_conflict");
    } else {
      if (used(s.sessions, "sessionId", sessionId)) fail("host_transport_session_duplicate");
      const previous = s.sessions.filter(r => sameOwner(r,input));
      if (previous.length && command.startsWith("Save")) fail("host_transport_session_ambiguous");
      previous.forEach(r => retireSession(s,r));
      s.sessions.push(input);
    }
    return { record: input };
  }
  if (command === "LoadTransportSession" || command === "RemoveTransportSession") {
    if (session && !sameOwner(session,q)) fail("host_transport_session_owner_mismatch");
    if (command.startsWith("Remove")) {
      if (session) retireSession(s,session);
      return { sessionId, removed: Boolean(session) };
    }
    if (!session) fail("host_transport_session_invalid");
    const parent = s.credentials.find(c => c.credentialId === session.credentialId);
    if (parent?.state !== "active" || parent.expiresAt <= timestamp) fail("host_transport_credential_inactive");
    if (session.expiresAt <= timestamp) fail("host_transport_session_expired");
    return { record: session };
  }
  if (command === "ResolveTransport" || command === "VerifyTransport") {
    const c = unique(owned(q),"host_transport_credential_required","host_transport_credential_ambiguous");
    if (c.expiresAt <= timestamp) fail("host_transport_credential_expired");
    const sessions = s.sessions.filter(r => r.credentialId === c.credentialId && sameOwner(r,q));
    if (sessions.length > 1) fail("host_transport_session_ambiguous");
    let selected = sessions[0] || null;
    if (selected && selected.expiresAt <= timestamp) {
      if (command.startsWith("Resolve")) retireSession(s,selected);
      selected = null;
    }
    if (command.startsWith("Resolve")) return { credential:c, session:selected };
    const publicFields = ({credentialId,principalId,hostInstallationId,expiresAt}) => ({credentialId,principalId,hostInstallationId,expiresAt});
    return { credential:publicFields(c), session:selected && {...publicFields(selected),sessionId:selected.sessionId} };
  }
  fail("host_protected_store_command_invalid");
}

function emptyHost(enrollment = { contract:"hellolynk-device-enrollment-v1", revision:0, value:null }) {
  return { caps:[], credentials:[], sessions:[], retiredSessions:[], codex:null, enrollment };
}

// On Windows the enrollment file exists independently of the capability file.
// An unclaimed Mac Host may have only its enrollment in the shared vault. Read
// its authenticated state without creating, repairing or replacing anything.
export function verifyDarwinUnclaimedAuthorization(root) {
  return withDarwinVault({ root, readOnly:true }, document => {
    const enrollment = document?.host?.enrollment;
    if (!exactFields(enrollment, ["contract", "revision", "value"])
        || enrollment.contract !== "hellolynk-device-enrollment-v1"
        || !Number.isSafeInteger(enrollment.revision) || enrollment.revision < 0
        || (enrollment.value !== null && (typeof enrollment.value !== "object" || Array.isArray(enrollment.value)))) {
      fail("device_enrollment_store_invalid");
    }
    if (!equal(document, { host:emptyHost(enrollment) })) fail("host_unclaimed_authorization_present");
  });
}

export function invokeDarwinHost(q) {
  const readOnly = q.verifyOnly || q.command.startsWith("Verify");
  return withDarwinVault({ root:q.root, helperPath:q.helperPath, readOnly, signal:q.signal }, document => {
    const s = document.host || emptyHost();
    if (!readOnly) document.host = s;
    const input = q.stdin ? JSON.parse(q.stdin) : null;
    const old = s.caps.find(c => c.capabilityId === q.capabilityId);
    switch (q.command) {
      case "Status": return {contract:"hellolynk-host-protected-store-v1",protected:true};
      case "LoadDeviceEnrollment": return s.enrollment;
      case "SaveDeviceEnrollment":
        if (s.enrollment.revision !== input.expectedRevision) fail("device_enrollment_revision_conflict");
        s.enrollment.value = input.value;
        s.enrollment.revision++;
        return s.enrollment;
      case "Issue": addCapability(s,input); return {record:input};
      case "Load":
        if (old?.state !== "active") fail("host_capability_inactive");
        return {record:old};
      case "Revoke": return revokeCapability(s,old);
      case "Rotate":
        if (old?.state !== "active") fail("host_capability_inactive");
        addCapability(s,input);
        revokeCapability(s,old);
        return {record:input, replacedCapabilityId:q.capabilityId};
      case "DisconnectLocalClient":
        for (const cap of s.caps.filter(c => c.adapterId === input.client && c.state === "active")) revokeCapability(s,cap);
        if (input.client === "codex") s.codex = null;
        return {disconnected:true,client:input.client};
    }
    if (q.command.endsWith("CodexNeutralBinding")) return codexBinding(s,q.command,input,q.capabilityId);
    if (q.command.includes("Transport")) return transport(s,q,input);
    fail("host_protected_store_command_unsupported");
  });
}
