import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import path from "node:path";
import { lstat } from "node:fs/promises";
import { ACCOUNT_CLIENTS, readClientAccount, clientAccountBaseRoot } from "./hellolynk-client-account.mjs";
import { createNeutralHostInstallationStore } from "./hellolynk-neutral-host-installation-store.mjs";
import { createHostProtectedStore, verifyHostProtectedStorePath } from "./hellolynk-host-protected-store.mjs";
import { normalizeHelloLynkBaseUrl } from "./hellolynk-client-core.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

export const LOCAL_IDENTITY_PROOF_PATH = "/host/v1/local-identity-proof";
export const LOCAL_IDENTITY_PROOF_CONTRACT = "hellolynk-local-identity-proof-v1";
const CLIENT_METHODS = Object.freeze({ codex: "Codex", openclaw: "OpenClaw", "trae-work": "TraeWork", workbuddy: "WorkBuddy", cursor: "Cursor", dsh: "Dsh", "claude-code": "ClaudeCode" });
const fail = () => Object.assign(new Error("local_identity_proof_invalid"), { code: "local_identity_proof_invalid" });
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== [...fields].sort().join(",")) throw fail();
}
function id(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/.test(value)) throw fail();
  return value;
}
function token(value) { if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw fail(); return value; }
function samePath(a, b) { return path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase(); }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

export function normalizeLocalIdentityOwner(value) {
  exact(value, ["region", "baseUrl", "principalId", "hellolynkId"]);
  const region = value.region === "international" ? "intl" : value.region;
  if (!["intl", "cn"].includes(region)
    || !runtimeSafety.helloLynkStableIdMatchesRegion(value.hellolynkId, region)) throw fail();
  return Object.freeze({ region, baseUrl: normalizeHelloLynkBaseUrl(value.baseUrl),
    principalId: id(value.principalId), hellolynkId: id(value.hellolynkId) });
}

export function validateLocalIdentityProofRequest(value) {
  exact(value, ["challenge", "owner", "target"]);
  exact(value.target, ["hostInstallationId", "delegateId", "authorizationVersion"]);
  if (!Number.isSafeInteger(value.target.authorizationVersion) || value.target.authorizationVersion < 1) throw fail();
  return Object.freeze({ challenge: token(value.challenge), owner: normalizeLocalIdentityOwner(value.owner),
    target: Object.freeze({ hostInstallationId: id(value.target.hostInstallationId), delegateId: id(value.target.delegateId),
      authorizationVersion: value.target.authorizationVersion }) });
}

function proofPayload({ request, hostGeneration, capabilityId, identity }) {
  request = validateLocalIdentityProofRequest(request);
  exact(identity, ["deviceId", "identityKeyId", "safetyCode"]);
  // The fingerprint is internal proof data, never a Workbench/MCP result.
  if (typeof identity.safetyCode !== "string" || !/^[A-F0-9]{4}(?:-[A-F0-9]{4}){11}$/.test(identity.safetyCode)) throw fail();
  return { contract: LOCAL_IDENTITY_PROOF_CONTRACT, request, hostGeneration: id(hostGeneration), capabilityId: id(capabilityId),
    identity: { deviceId: id(identity.deviceId), identityKeyId: id(identity.identityKeyId), safetyCode: identity.safetyCode.toUpperCase() } };
}
function mac(payload, secretBuffer) {
  if (!Buffer.isBuffer(secretBuffer) || secretBuffer.length < 32) throw fail();
  return createHmac("sha256", secretBuffer).update(`${LOCAL_IDENTITY_PROOF_CONTRACT}\n${JSON.stringify(payload)}`).digest("hex");
}
export function signLocalIdentityProof(input) {
  const payload = proofPayload(input);
  return Object.freeze({ ...payload, proof: mac(payload, input.secretBuffer) });
}
export function verifyLocalIdentityProof({ response, request, hostGeneration, capabilityId, secretBuffer }) {
  exact(response, ["contract", "request", "hostGeneration", "capabilityId", "identity", "proof"]);
  const payload = proofPayload(response);
  if (response.contract !== LOCAL_IDENTITY_PROOF_CONTRACT || !same(payload.request, validateLocalIdentityProofRequest(request))
    || payload.hostGeneration !== hostGeneration || payload.capabilityId !== capabilityId) throw fail();
  const expected = Buffer.from(mac(payload, secretBuffer), "hex"), received = Buffer.from(token(response.proof), "hex");
  if (!timingSafeEqual(expected, received)) throw fail();
  return payload.identity.safetyCode;
}

// All clients start from the same protected installation. Per-client account
// selectors still isolate a client that disconnects or changes account.
export function localIdentityInstallationCandidates({ root, clients }) {
  const base = clientAccountBaseRoot(root);
  if (path.basename(base) !== "host" || !Array.isArray(clients) || !clients.length
    || clients.some((client) => !ACCOUNT_CLIENTS.includes(client))) throw fail();
  return ACCOUNT_CLIENTS.map((client) => ({ client, baseRoot: base }));
}

async function accountSnapshot(candidate, operation) {
  const { signal } = operation;
  signal.throwIfAborted();
  // The selector check, or the registry check when no selector exists, also
  // verifies its root before any content is read. No root-only helper is needed.
  const selector = path.join(candidate.baseRoot, `client-account-${candidate.client}.json`);
  try { await lstat(selector); await verifyHostProtectedStorePath({ root: candidate.baseRoot, path: selector, signal }); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  const account = readClientAccount(candidate.client, candidate.baseRoot);
  if (account.phase !== "ready") throw fail();
  return account;
}

async function loadCandidate(candidate, operation) {
  const account = await accountSnapshot(candidate, operation);
  if (samePath(account.root, operation.excludeRoot)) return null;
  const { signal, installations } = operation;
  if (!installations.has(account.root)) {
    const store = createNeutralHostInstallationStore({ root: account.root, readOnly: true,
      verifyPath: ({ path: target, directory }) => verifyHostProtectedStorePath({ root: account.root, path: target, directory, signal }) });
    installations.set(account.root, store.status().then((snapshot) => ({ store, snapshot })));
  }
  const { store: installationStore, snapshot } = await installations.get(account.root);
  const active = snapshot.installations.filter((item) => item.state === "active");
  if (active.length !== 1 || active[0].principalId !== operation.owner.principalId
    || !runtimeSafety.helloLynkStableIdMatchesRegion(operation.owner.hellolynkId, active[0].region)) return null;
  const matchingTarget = active.length === 1 ? active[0].delegateBindings.find((item) => item.delegateId === operation.peerDelegateId
    && item.adapters.includes(candidate.client)) : null;
  if (!matchingTarget) return null;
  const selectionKey = `${account.root.toLowerCase()}\0${operation.peerDelegateId}`;
  if (operation.selectedTargets.has(selectionKey)) return null;
  operation.selectedTargets.add(selectionKey);
  // Reuse one ACL-verified registry snapshot for this single operation. Every
  // successful proof is followed by a fresh registry and binding verification.
  const snapshotStore = { status: async () => snapshot, resolveBinding: async (input) => {
    const active = snapshot.installations.filter((item) => item.state === "active");
    if (active.length !== 1) throw fail();
    const installation = active[0];
    const matches = installation.delegateBindings.filter((item) => (!input.profileId || item.profileId === input.profileId)
      && (!input.delegateId || item.delegateId === input.delegateId));
    if (matches.length !== 1) throw fail();
    return { region: installation.region, principalId: installation.principalId, hostInstallationId: installation.hostInstallationId,
      canonicalProfileId: installation.canonicalProfileId, ...matches[0] };
  } };
  // Several adapters may share one delegate. Resolve just one active installed
  // adapter for that exact target, trying another only when the first is absent
  // or revoked. Do not launch one PowerShell process per adapter per message.
  let lastError = fail();
  for (const choice of operation.candidates.filter((item) => matchingTarget.adapters.includes(item.client)
    && samePath(item.baseRoot, clientAccountBaseRoot(account.root)))) {
    let binding;
    try {
      const selectedAccount = await accountSnapshot(choice, operation);
      if (!samePath(selectedAccount.root, account.root)) continue;
      const store = createHostProtectedStore({ root: account.root, readOnly: true, followClientAccount: false, signal,
        installationStore: snapshotStore });
      binding = await store[`resolve${CLIENT_METHODS[choice.client]}NeutralBinding`]();
      const target = await snapshotStore.resolveBinding({ profileId: binding.profileId, delegateId: binding.delegateId });
      if (binding.delegateId !== operation.peerDelegateId || binding.capability.state !== "active"
        || !binding.capability.scopes.includes("app-data:contacts-read")) throw fail();
      return { account: selectedAccount, binding, target, async recheck() {
        const [currentAccount, current, currentTarget] = await Promise.all([
          accountSnapshot(choice, operation),
          store[`verify${CLIENT_METHODS[choice.client]}NeutralBinding`](),
          installationStore.resolveBinding({ profileId: binding.profileId, delegateId: binding.delegateId }),
        ]);
        if (!same(selectedAccount, currentAccount)) throw fail();
        if (current.capability.capabilityId !== binding.capability.capabilityId
          || current.hostInstallationId !== binding.hostInstallationId || current.delegateId !== binding.delegateId) throw fail();
        if (!same(currentTarget, target)) throw fail();
      } };
    } catch (error) { binding?.capability.secretBuffer?.fill(0); lastError = error; }
    signal.throwIfAborted();
  }
  throw lastError;
}

// No background polling, retries, trust writes, contact grants or outbox work.
// A failure supplies no additional trust; the normal remote verification gate
// remains responsible for unknown devices. Verified identity pins retain the
// existing E2EE semantics; this does not turn historical pins into live grants.
export function createLocalPeerAccess(options, dependencies = {}) {
  const profile = options.profile;
  const owner = normalizeLocalIdentityOwner({ region: profile.region, baseUrl: profile.baseUrl,
    principalId: profile.principalId, hellolynkId: profile.hellolynkId });
  const candidates = localIdentityInstallationCandidates({ root: options.root, clients: options.clients });
  const assertSourceCurrent = options.assertCurrent;
  if (typeof assertSourceCurrent !== "function") throw fail();
  const load = dependencies.loadCandidate || loadCandidate;
  const discover = dependencies.discover || (async (input) => (await import("./hellolynk-neutral-host-process.mjs")).discoverHelloLynkNeutralHost(input));
  const request = dependencies.request || (async (input) => (await import("./hellolynk-neutral-host-process.mjs")).requestHelloLynkNeutralHost(input));
  return async ({ peerHelloLynkId, peerDelegateId, peerHostId, peerAuthorizationVersion }, visit,
    { all = false, required = false, proveIdentity = true, timeoutMs = 12_000, signal: callerSignal } = {}) => {
    const absent = () => {
      if (required) throw Object.assign(new Error("local_peer_unavailable"), { code: "local_peer_unavailable" });
      return all ? [] : null;
    };
    if (peerHelloLynkId !== owner.hellolynkId || !peerDelegateId || process.platform !== "win32") return absent();
    if (typeof visit !== "function" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw fail();
    id(peerDelegateId);
    await assertSourceCurrent();
    const controller = new AbortController();
    const signal = callerSignal ? AbortSignal.any([controller.signal, callerSignal]) : controller.signal;
    const deadline = performance.now() + timeoutMs;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const operation = { signal, peerDelegateId, owner, excludeRoot: options.root, candidates,
      installations: new Map(), selectedTargets: new Set() };
    const loadedPeers = [];
    let localTargetFound = false;
    try {
      const results = await Promise.allSettled(candidates.map(async (candidate) => {
        const loaded = await load(candidate, operation);
        if (!loaded) return null;
        loadedPeers.push(loaded);
        const { binding, target } = loaded;
        if (signal.aborted || binding.delegateId !== peerDelegateId || binding.hostInstallationId === profile.hostId || binding.principalId !== owner.principalId
          || !runtimeSafety.helloLynkStableIdMatchesRegion(owner.hellolynkId, binding.region)
          || (peerHostId && binding.hostInstallationId !== peerHostId)
          || (peerAuthorizationVersion != null && target.authorizationVersion !== peerAuthorizationVersion)) return null;
        localTargetFound = true;
        const discovery = await discover(binding);
        if (!discovery || signal.aborted) return null;
        // A signed exchange already authenticates its response. It only
        // needs local binding selection here; E2EE independently checks keys.
        if (!proveIdentity) {
          await loaded.recheck();
          return { loaded, discovery, code: null, identity: null };
        }
        const body = validateLocalIdentityProofRequest({ challenge: randomBytes(32).toString("hex"), owner,
          target: { hostInstallationId: binding.hostInstallationId, delegateId: binding.delegateId,
            authorizationVersion: target.authorizationVersion } });
        // A cold Host may need protected capability resolution before it can
        // answer. Give that HTTP request the remaining operation budget,
        // without restarting the budget or retrying after a timeout.
        const remainingMs = Math.floor(deadline - performance.now());
        if (signal.aborted || remainingMs < 100) return null;
        const result = await request({ discovery, capability: binding.capability, method: "POST",
          pathname: LOCAL_IDENTITY_PROOF_PATH, body, timeoutMs: remainingMs, signal });
        if (result.status !== 200 || signal.aborted) return null;
        const code = verifyLocalIdentityProof({ response: result.body, request: body,
          hostGeneration: discovery.hostGeneration, capabilityId: binding.capability.capabilityId,
          secretBuffer: binding.capability.secretBuffer });
        await loaded.recheck();
        const currentDiscovery = await discover(binding);
        if (!currentDiscovery || currentDiscovery.hostGeneration !== discovery.hostGeneration
          || currentDiscovery.host !== discovery.host || currentDiscovery.port !== discovery.port) return null;
        await assertSourceCurrent();
        return signal.aborted ? null : { loaded, discovery, code, identity: result.body.identity };
      }));
      for (const result of results) if (result.status === "rejected" && dependencies.onCandidateRejected) {
        const code = /^[a-z][a-z0-9_]{1,100}$/.test(result.reason?.code || "") ? result.reason.code : "local_identity_candidate_unavailable";
        dependencies.onCandidateRejected(code);
      }
      await assertSourceCurrent();
      callerSignal?.throwIfAborted();
      const peers = results.filter((result) => result.status === "fulfilled" && result.value).map((result) => result.value);
      if (!peers.length) {
        // A known local binding whose Host is stopped must not turn into a
        // cloud send (and a runtime-renewal requirement) just because it is off.
        if (!all && localTargetFound) throw Object.assign(new Error("local_peer_unavailable"), { code: "local_peer_unavailable" });
        return absent();
      }
      if (!all && peers.length !== 1) throw fail();
      // Selection is read-only. Once a visitor starts a claim or delivery, its
      // errors must propagate; never swallow them as a failed discovery and
      // retry the message through another transport.
      const values = [];
      for (const peer of peers) {
        signal.throwIfAborted();
        const { binding, target } = peer.loaded;
        values.push(await visit({ owner, binding, target, discovery: peer.discovery, code: peer.code,
          identity: peer.identity, signal,
          async request(pathname, body) {
            signal.throwIfAborted();
            await assertSourceCurrent();
            const remainingMs = Math.floor(deadline - performance.now());
            if (remainingMs < 100) throw fail();
            return request({ discovery: peer.discovery, capability: binding.capability, method: "POST",
              pathname, body, timeoutMs: remainingMs, signal });
          },
        }));
        if (!all) await assertSourceCurrent();
        signal.throwIfAborted();
      }
      return all ? values : values[0];
    } finally {
      clearTimeout(timer);
      for (const peer of loadedPeers) peer.binding.capability.secretBuffer?.fill(0);
    }
  };
}

export function createLocalIdentityTrustProvider(options, dependencies = {}) {
  const access = createLocalPeerAccess(options, dependencies);
  return async (input) => [...new Set(await access(input, ({ code }) => code, { all: true }))];
}
