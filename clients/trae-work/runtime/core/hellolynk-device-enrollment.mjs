import { createHash, randomBytes } from "node:crypto";
import { join, resolve } from "node:path";
import { lstat } from "node:fs/promises";
import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";
import { createPlatformCredentialStore, assertCredentialProfileId, prepareWindowsClientRoot } from "./hellolynk-platform-credential-store.mjs";
import { defaultHelloLynkClientRoot, readClientProfile, writeClientProfile } from "./hellolynk-client-profile.mjs";
import { createNeutralHostInstallationStore, defaultNeutralHostStoreRoot, writeNeutralHostProfileManifest } from "./hellolynk-neutral-host-installation-store.mjs";
import { createHostProtectedStore } from "./hellolynk-host-protected-store.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const CLIENT_TYPES = new Set(["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh", "claude-code"]);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const REQUEST = /^devreq_[a-f0-9]{48}$/;
const PROOF = /^[A-Za-z0-9_-]{43}$/;
const DEVICE = /^device_[a-f0-9]{48}$/;
const INTENT = /^reg_[a-f0-9]{48}$/;
const TRANSPORT = /^hellolynk_host_transport_v1_([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]{32,}$/;
const CREDENTIAL = /^hellolynk_device_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$/;
const SCOPES = new Set(["relay.text.send", "relay.text.receive", "runtime.session.refresh", "runtime.session.revoke"]);

function fail(code) { return Object.assign(new Error(code), { code }); }
function checkedId(value) {
  if (typeof value !== "string" || !ID.test(value)) throw fail("device_enrollment_response_invalid");
  return value;
}
function label(value, code) {
  if (typeof value !== "string" || !value.trim() || [...value.trim()].length > 80
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value)) throw fail(code);
  return value.trim();
}
function newInstanceName(value, code) {
  if (typeof value !== "string" || [...value].length < 1 || [...value].length > 40
    || !/^[\p{Script=Han}A-Za-z0-9_-]+$/u.test(value)) throw fail(code);
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase());
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function canonicalDateTime(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw fail("device_enrollment_response_invalid");
  return new Date(Date.parse(value)).toISOString();
}

// Only this local coordinator handles enrollment proofs and credentials. Its
// public result is deliberately not the server's claim/registration response.
export function createDeviceEnrollmentClient(options = {}, dependencies = {}) {
  const root = resolve(options.root || defaultHelloLynkClientRoot());
  const hostRoot = resolve(options.hostRoot || defaultNeutralHostStoreRoot());
  const baseUrl = normalizeHelloLynkBaseUrl(options.baseUrl, { allowLoopbackHttp: options.allowLoopbackHttp === true });
  const fetchImpl = dependencies.fetchImpl || runtimeSafety.helloLynkNetworkFetch;
  const installationStore = dependencies.installationStore || createNeutralHostInstallationStore({ root: hostRoot });
  const protectedStore = dependencies.protectedStore || createHostProtectedStore({ root: hostRoot, installationStore });
  const credentialStore = dependencies.credentialStore || createPlatformCredentialStore({ storeRoot: join(root, "credentials") });
  const now = dependencies.now || Date.now;
  const random = dependencies.randomBytes || randomBytes;
  const timeoutMs = Math.min(30_000, Math.max(1_000, options.timeoutMs || 10_000));

  async function request(path, body, credential) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(`${baseUrl}${path}`, {
        method: "POST", redirect: "error", credentials: "omit", cache: "no-store",
        headers: { "content-type": "application/json", ...(credential ? { "x-hellolynk-host-transport-credential": credential } : {}) },
        body: JSON.stringify(body), signal: controller.signal,
      });
      const reader = response.body?.getReader();
      if (!reader) throw fail("device_enrollment_response_invalid");
      const chunks = []; let size = 0;
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          size += chunk.value.byteLength;
          if (size > 64 * 1024) throw fail("device_enrollment_response_invalid");
          chunks.push(Buffer.from(chunk.value));
        }
      } finally { await reader.cancel().catch(() => {}); }
      let result;
      try { result = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
      catch { throw fail("device_enrollment_response_invalid"); }
      if (!response.ok) {
        const code = typeof result?.error === "string" && /^[a-z][a-z0-9_]{0,95}$/.test(result.error)
          ? result.error : "device_enrollment_request_failed";
        throw Object.assign(fail(code), { status: response.status });
      }
      return result;
    } catch (error) {
      if (error?.code && /^[a-z][a-z0-9_]{0,95}$/.test(error.code)) throw error;
      throw fail(controller.signal.aborted ? "device_enrollment_request_timeout"
        : runtimeSafety.helloLynkNetworkErrorCode(error, "device_enrollment_request_failed"));
    } finally { clearTimeout(timer); }
  }

  function validateState(value) {
    if (value === null) return null;
    if (value?.baseUrl !== baseUrl || !/^host_[A-Za-z0-9_-]{32}$/.test(value?.hostId || "")
      || !runtimeSafety.classifyHelloLynkStableId(value?.hellolynkId)
      || !REQUEST.test(value?.requestId || "") || !PROOF.test(value?.proof || "")
      || !value.intents || typeof value.intents !== "object" || Array.isArray(value.intents)
      || Object.keys(value.intents).length > 32) throw fail("device_enrollment_owner_conflict");
    label(value.deviceLabel, "device_enrollment_store_invalid");
    const normalized = { ...value, approval: value.approval === null ? null : validateApproval(value.approval, value), intents: {} };
    for (const [profileId, intent] of Object.entries(value.intents)) {
      assertCredentialProfileId(profileId);
      if (!CLIENT_TYPES.has(intent?.clientType) || !INTENT.test(intent?.registrationIntentId || "")
        || !DEVICE.test(intent?.deviceId || "")) throw fail("device_enrollment_store_invalid");
      if (intent.requestedName !== null) label(intent.requestedName, "device_enrollment_store_invalid");
      if (intent.previousRequestedNames !== undefined) {
        if (!Array.isArray(intent.previousRequestedNames)) throw fail("device_enrollment_store_invalid");
        for (const name of intent.previousRequestedNames) {
          if (name !== null) label(name, "device_enrollment_store_invalid");
        }
      }
      normalized.intents[profileId] = { ...intent,
        binding: intent.binding === null ? null : validateBinding(intent.binding, normalized, intent) };
    }
    return normalized;
  }

  async function load() {
    const record = await protectedStore.loadDeviceEnrollment();
    return { ...record, value: validateState(record.value) };
  }

  async function update(mutator) {
    // CAS protects two explicit client setups racing on the same computer.
    // The callback is local only: HTTP must never run inside a CAS retry.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const before = await load();
      const next = mutator(before.value && clone(before.value));
      if (next === undefined) return before.value;
      const normalized = validateState(next);
      try {
        // Native JSON serialization may omit insignificant fractional zeros.
        // Canonicalize the returned state as well as reads and HTTP responses
        // before comparing a retried registration with its durable result.
        return validateState((await protectedStore.saveDeviceEnrollment({ expectedRevision: before.revision, value: normalized })).value);
      } catch (error) {
        if (error?.code !== "device_enrollment_revision_conflict") throw error;
      }
    }
    throw fail("device_enrollment_busy");
  }

  function validateApproval(result, state) {
    const transport = result?.hostTransportCredential;
    const match = TRANSPORT.exec(transport?.credential || "");
    const identity = runtimeSafety.classifyHelloLynkStableId(state.hellolynkId);
    if (result?.status !== "approved" || result.hostId !== state.hostId
      || result.hellolynkId !== state.hellolynkId || result.region !== identity.region
      || !match || match[1] !== transport.credentialId
      || !Number.isFinite(Date.parse(transport.createdAt)) || !Number.isFinite(Date.parse(transport.expiresAt))
      || Date.parse(transport.expiresAt) <= Date.parse(transport.createdAt)) throw fail("device_enrollment_response_invalid");
    checkedId(result.principalId);
    return {
      status: "approved", principalId: result.principalId, hellolynkId: state.hellolynkId,
      region: result.region, hostId: state.hostId,
      hostTransportCredential: { credentialId: transport.credentialId, credential: transport.credential,
        createdAt: canonicalDateTime(transport.createdAt), expiresAt: canonicalDateTime(transport.expiresAt) },
    };
  }

  function validateBinding(result, state, intent) {
    const b = result?.binding; const i = result?.instance;
    if (!state.approval || b?.principalId !== state.approval.principalId
      || b.hellolynkId !== state.hellolynkId || b.hostId !== state.hostId
      || b.region !== state.approval.region || b.deviceId !== intent.deviceId
      || !CREDENTIAL.test(b.deviceCredential || "") || i?.delegateId !== b.delegateId
      || i.agentId !== b.agentId || i.ownerHostId !== state.hostId || i.deviceId !== intent.deviceId
      || i.clientType !== intent.clientType || !Number.isSafeInteger(i.authorizationVersion) || i.authorizationVersion < 1
      || !Array.isArray(b.allowedScopes) || !b.allowedScopes.length
      || b.allowedScopes.some((scope) => !SCOPES.has(scope))) throw fail("device_enrollment_response_invalid");
    for (const id of [b.delegateId, b.agentId, b.credentialId]) checkedId(id);
    label(i.displayName, "device_enrollment_response_invalid");
    if (intent.requestedName !== null && i.displayName !== intent.requestedName) throw fail("device_enrollment_response_invalid");
    return {
      instance: { delegateId: i.delegateId, agentId: i.agentId, displayName: i.displayName,
        clientType: i.clientType, ownerHostId: i.ownerHostId, deviceId: i.deviceId, authorizationVersion: i.authorizationVersion },
      binding: { principalId: b.principalId, hellolynkId: b.hellolynkId, hostId: b.hostId, region: b.region,
        agentId: b.agentId, delegateId: b.delegateId, deviceId: b.deviceId, credentialId: b.credentialId,
        deviceCredential: b.deviceCredential, allowedScopes: [...b.allowedScopes],
        expiresAt: b.expiresAt === null ? null : canonicalDateTime(b.expiresAt) },
    };
  }

  function publicPending(state, expiresAt = null) {
    return { ok: true, status: "confirmation_required", hellolynkId: state.hellolynkId,
      verificationUrl: `${baseUrl}/account?deviceRequest=${encodeURIComponent(state.requestId)}`, expiresAt };
  }

  function nameRejected(error) {
    return (error?.status === 400 && error.code === "agent_instance_name_invalid")
      || (error?.status === 409 && error.code === "agent_instance_name_conflict");
  }

  async function registerIntent(state, intent) {
    const response = await request("/api/v2/host-transport/instances", {
      registrationIntentId: intent.registrationIntentId, clientType: intent.clientType, deviceId: intent.deviceId,
      ...(intent.requestedName !== null ? { requestedName: intent.requestedName } : {}),
    }, state.approval.hostTransportCredential.credential);
    return { registered: validateBinding(response, state, intent), intent };
  }

  async function recoverRegistration(state, intent, profileId) {
    try { return await registerIntent(state, intent); }
    catch (error) {
      if (error?.status !== 409 || error.code !== "agent_instance_intent_conflict") throw error;
      const latest = (await load()).value?.intents[profileId];
      if (!latest || latest.registrationIntentId !== intent.registrationIntentId || latest.deviceId !== intent.deviceId) {
        throw fail("device_enrollment_intent_conflict");
      }
      // Another request may have committed an earlier name after its caller
      // lost the response. Reuse this intent to recover that one receipt.
      const candidates = new Set([latest.requestedName, ...(latest.previousRequestedNames || [])]);
      candidates.delete(intent.requestedName);
      for (const requestedName of candidates) {
        try { return await registerIntent(state, { ...intent, requestedName }); }
        catch (candidateError) {
          if (!nameRejected(candidateError)
            && !(candidateError?.status === 409 && candidateError.code === "agent_instance_intent_conflict")) throw candidateError;
        }
      }
      throw error;
    }
  }

  async function connect(input = {}) {
    if (!CLIENT_TYPES.has(input.clientType)) throw fail("device_enrollment_client_unsupported");
    const identity = runtimeSafety.classifyHelloLynkStableId(input.hellolynkId);
    if (!identity) throw fail("device_enrollment_hellolynk_id_invalid");
    const profileId = assertCredentialProfileId(input.profileId || `instance-${input.clientType}`);
    const rawRequestedName = input.requestedName == null ? null : input.requestedName;
    // PrepareRoot creates a trusted new root, but rejects an existing untrusted
    // directory. Creating the Host first would bypass that first-install step.
    if (process.platform === "win32") await (dependencies.prepareWindowsClientRoot || prepareWindowsClientRoot)(root);
    const savedBeforeConnect = (await load()).value;
    const priorIntent = savedBeforeConnect?.intents?.[profileId];
    const requestedName = rawRequestedName === null ? null
      : priorIntent?.requestedName === rawRequestedName
        ? rawRequestedName
        : newInstanceName(rawRequestedName, "device_enrollment_name_invalid");
    const installation = await installationStore.createId();
    const hostId = installation.hostInstallationId;
    if (installation.region && !runtimeSafety.helloLynkStableIdMatchesRegion(identity, installation.region)) {
      throw fail("device_enrollment_owner_conflict");
    }
    const configPath = join(root, "profiles", `${profileId}.json`);
    const profileReader = dependencies.readClientProfile || readClientProfile;
    let existingProfile = null;
    try {
      if (!dependencies.readClientProfile) await lstat(configPath);
      existingProfile = await profileReader(configPath);
    } catch (error) {
      if (!["ENOENT", "client_profile_not_found"].includes(error?.code || error?.message)) throw error;
    }
    if (existingProfile) {
      // A package has a fixed profile name. It may resume its own durable
      // enrollment, but must never register a new remote identity over an old
      // installation and discover the conflict only after the server write.
      const savedBinding = savedBeforeConnect?.intents[profileId]?.binding?.binding;
      if (!savedBinding) throw fail("device_enrollment_existing_profile_requires_setup");
      if (existingProfile.profileId !== profileId || existingProfile.baseUrl !== baseUrl
        || !runtimeSafety.helloLynkStableIdMatchesRegion(identity, existingProfile.region)
        || ["principalId", "hellolynkId", "delegateId", "agentId", "deviceId", "credentialId", "hostId"]
          .some((field) => existingProfile[field] !== savedBinding[field])) {
        throw fail("device_enrollment_profile_conflict");
      }
    }
    let state = await update((current) => {
      if (current) {
        if (current.hostId !== hostId) throw fail("device_enrollment_owner_conflict");
        if (current.hellolynkId === identity.value) return undefined;
        // Only an unclaimed draft may change owner. A saved approval, any AI
        // registration intent or an existing installation still binds identity.
        if (current.approval || Object.keys(current.intents).length || installation.principalId
          || installation.region || installation.delegateBindings?.length || existingProfile) {
          throw fail("device_enrollment_owner_conflict");
        }
      }
      return { baseUrl, hellolynkId: identity.value, hostId, deviceLabel: label(input.deviceLabel || "This computer", "device_enrollment_label_invalid"),
        requestId: `devreq_${random(24).toString("hex")}`, proof: random(32).toString("base64url"), approval: null, intents: {} };
    });

    for (let attempt = 0; !state.approval && attempt < 2; attempt += 1) {
      const requestId = state.requestId;
      try {
        const started = await request("/api/v2/device-authorizations", {
          requestId: state.requestId, hellolynkId: state.hellolynkId, hostId: state.hostId,
          deviceLabel: state.deviceLabel, proofChallenge: createHash("sha256").update(state.proof).digest("hex"),
        });
        if (started?.requestId !== state.requestId || !["pending", "approved"].includes(started.status)
          || !Number.isFinite(Date.parse(started.expiresAt))) throw fail("device_enrollment_response_invalid");
        const claimed = await request(`/api/v2/device-authorizations/${state.requestId}/claim`, { proof: state.proof });
        if (claimed?.status === "pending") return publicPending(state, started.expiresAt);
        const approval = validateApproval(claimed, state);
        if (installation.principalId && installation.principalId !== approval.principalId) throw fail("device_enrollment_owner_conflict");
        state = await update((current) => {
          if (current.requestId !== requestId) throw fail("device_enrollment_owner_conflict");
          if (current.approval && JSON.stringify(current.approval) !== JSON.stringify(approval)) throw fail("device_enrollment_response_invalid");
          current.approval = approval; return current;
        });
      } catch (error) {
        // A definite expired, unapproved request is safe to replace. Network
        // uncertainty never rotates its proof or discards registration intents.
        if (error?.status !== 410 || error?.code !== "device_authorization_expired" || attempt > 0) throw error;
        state = await update((current) => {
          if (current.requestId !== requestId || current.approval) return undefined;
          current.requestId = `devreq_${random(24).toString("hex")}`;
          current.proof = random(32).toString("base64url");
          return current;
        });
      }
    }
    if (Date.parse(state.approval.hostTransportCredential.expiresAt) <= now()) throw fail("device_enrollment_authorization_expired");

    state = await update((current) => {
      const existing = current.intents[profileId];
      if (existing) {
        if (existing.clientType !== input.clientType || (existing.binding && existing.requestedName !== requestedName)) {
          throw fail("device_enrollment_intent_conflict");
        }
        return undefined;
      }
      if (Object.keys(current.intents).length >= 32) throw fail("device_enrollment_instance_limit");
      current.intents[profileId] = { clientType: input.clientType, requestedName,
        registrationIntentId: `reg_${random(24).toString("hex")}`, deviceId: `device_${random(24).toString("hex")}`, binding: null };
      return current;
    });
    let intent = state.intents[profileId];
    // Always recheck the server's active authorization before reattaching a
    // cached profile. An old local success cannot undo a website revocation.
    let registration;
    try { registration = await recoverRegistration(state, intent, profileId); }
    catch (error) {
      // A changed name may replace an explicitly rejected, unfinished attempt.
      // Unknown outcomes never rotate identity or discard recovery candidates.
      if (!nameRejected(error) || intent.binding || intent.requestedName === requestedName) throw error;
      const rejectedName = intent.requestedName;
      state = await update((current) => {
        const saved = current.intents[profileId];
        if (saved.registrationIntentId !== intent.registrationIntentId || saved.deviceId !== intent.deviceId) {
          throw fail("device_enrollment_intent_conflict");
        }
        if (saved.binding) return undefined;
        if (saved.requestedName !== rejectedName) throw fail("device_enrollment_busy");
        saved.previousRequestedNames = [...new Set([...(saved.previousRequestedNames || []), rejectedName])];
        saved.requestedName = requestedName;
        return current;
      });
      intent = state.intents[profileId];
      registration = await recoverRegistration(state, intent, profileId);
    }
    const { registered } = registration;
    intent = registration.intent;
    state = await update((current) => {
      const saved = current.intents[profileId];
      if (saved.registrationIntentId !== intent.registrationIntentId) throw fail("device_enrollment_intent_conflict");
      if (saved.binding && JSON.stringify(saved.binding) !== JSON.stringify(registered)) throw fail("device_enrollment_response_invalid");
      saved.requestedName = intent.requestedName;
      saved.binding = registered;
      delete saved.previousRequestedNames;
      return current;
    });
    intent = state.intents[profileId];
    const b = registered.binding; const i = registered.instance;
    const profile = { contract: "hellolynk-client-profile-v1", schemaVersion: 2, profileId, baseUrl,
      allowLoopbackHttp: options.allowLoopbackHttp === true, deviceId: b.deviceId, credentialId: b.credentialId,
      principalId: b.principalId, hellolynkId: b.hellolynkId, agentId: b.agentId, delegateId: b.delegateId,
      // The API receipt uses "intl", while earlier Hosts store "international".
      // Keep all local profiles consistent without changing any existing binding.
      hostId: b.hostId, authorizationVersion: i.authorizationVersion, region: installation.region || b.region,
      allowedScopes: b.allowedScopes, platform: process.platform };
    try {
      if (!dependencies.readClientProfile) await lstat(configPath);
      const previous = await profileReader(configPath);
      if (previous.delegateId !== b.delegateId || previous.principalId !== b.principalId
        || previous.credentialId !== b.credentialId || previous.baseUrl !== baseUrl) throw fail("device_enrollment_profile_conflict");
    } catch (error) {
      if (!["ENOENT", "client_profile_not_found"].includes(error?.code || error?.message)) throw error;
    }
    const transport = { ...state.approval.hostTransportCredential,
      principalId: b.principalId, hostInstallationId: b.hostId, state: "active", revokedAt: null };
    // An existing Host upgrades atomically before local activation changes.
    // A first Host needs adoption to establish its owner before the same save.
    if (installation.state === "active") await protectedStore.saveEnrollmentTransportCredential(transport);
    // Keep resumable state and the credential on a partial activation failure.
    // Removing them would turn a harmless retry into a duplicate identity.
    await credentialStore.save(profileId, b.deviceCredential);
    await (dependencies.writeClientProfile || writeClientProfile)(configPath, profile);
    const active = await installationStore.adoptProfileFile({ profileFile: configPath, adapterId: input.clientType });
    if (installation.state !== "active") await protectedStore.saveEnrollmentTransportCredential(transport);
    await activateManifest(active, configPath);
    return { ok: true, status: "registered", hellolynkId: b.hellolynkId, clientType: i.clientType,
      instanceName: i.displayName, profileId, configPath, hostProfileRegistered: true,
      ...(intent.requestedName !== requestedName ? { recoveredExistingName: true } : {}) };
  }

  async function activateManifest(installation, configPath) {
    if (dependencies.activateManifest) return dependencies.activateManifest(installation, configPath);
    await writeNeutralHostProfileManifest({ root: hostRoot, clientRoot: root,
      profiles: [configPath], mergeRegisteredProfiles: true });
  }

  // Only a durable, approved registration can explain a profile that was
  // adopted before its manifest was published. This is read-only evidence for
  // preflight, not authorization to activate: connect still rechecks the server.
  async function verifyLocalRecovery({ clientType, profileId } = {}) {
    if (!CLIENT_TYPES.has(clientType)) throw fail("device_enrollment_client_unsupported");
    assertCredentialProfileId(profileId);
    const state = (await load()).value;
    const active = (await installationStore.status()).installations.filter((item) => item.state === "active");
    const installation = active[0];
    const intent = state?.intents[profileId];
    const saved = intent?.binding;
    if (active.length !== 1 || !state?.approval || !saved || intent.clientType !== clientType
      || state.hostId !== installation.hostInstallationId || state.approval.principalId !== installation.principalId
      || !runtimeSafety.helloLynkStableIdMatchesRegion(runtimeSafety.classifyHelloLynkStableId(state.hellolynkId), installation.region)) {
      throw fail("device_enrollment_recovery_invalid");
    }
    if (Date.parse(state.approval.hostTransportCredential.expiresAt) <= now()) throw fail("device_enrollment_authorization_expired");
    const delegate = installation.delegateBindings.find((item) => item.profileId === profileId);
    if (!delegate || delegate.adapters?.length !== 1 || delegate.adapters[0] !== clientType
      || delegate.delegateId !== saved.binding.delegateId || delegate.authorizationVersion !== saved.instance.authorizationVersion) {
      throw fail("device_enrollment_recovery_invalid");
    }
    const configPath = join(root, "profiles", `${profileId}.json`);
    const profile = await (dependencies.readClientProfile || readClientProfile)(configPath);
    if (profile.profileId !== profileId || profile.baseUrl !== baseUrl
      || profile.region !== installation.region || profile.authorizationVersion !== delegate.authorizationVersion
      || ["principalId", "hellolynkId", "delegateId", "agentId", "deviceId", "credentialId", "hostId"]
        .some((field) => profile[field] !== saved.binding[field])) throw fail("device_enrollment_profile_conflict");
    return Object.freeze({ profileId, configPath });
  }

  return Object.freeze({ connect, verifyLocalRecovery });
}
