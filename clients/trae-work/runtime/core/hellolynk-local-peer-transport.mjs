import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { validateLocalIdentityProofRequest } from "./hellolynk-local-identity-trust.mjs";

export const LOCAL_PEER_EXCHANGE_PATH = "/host/v1/local-peer-exchange";
const CONTRACT = "hellolynk-local-peer-exchange-v1";
const fail = (code = "local_peer_exchange_invalid") => Object.assign(new Error(code), { code });
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== [...fields].sort().join(",")) throw fail();
}
function id(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/.test(value)) throw fail();
  return value;
}
const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");

export function validateLocalPeerRequest(value) {
  exact(value, ["challenge", "owner", "target", "source", "action", "payload"]);
  const base = validateLocalIdentityProofRequest({ challenge: value.challenge, owner: value.owner, target: value.target });
  const source = validateLocalIdentityProofRequest({ ...base, target: value.source }).target;
  if (source.hostInstallationId === base.target.hostInstallationId || source.delegateId === base.target.delegateId) throw fail();
  if (value.action === "claim") {
    exact(value.payload, ["routeKind", "clientMessageId", "recipientDeviceId",
      ...(value.payload?.nativeContentVersion == null ? [] : ["nativeContentVersion"])]);
    if (value.payload.nativeContentVersion != null && value.payload.nativeContentVersion !== 1) throw fail();
    if (!["owned_delegate", "instance_direct"].includes(value.payload.routeKind)) throw fail();
    id(value.payload.clientMessageId);
    if (value.payload.recipientDeviceId !== null) id(value.payload.recipientDeviceId);
  } else if (value.action === "deliver") {
    exact(value.payload, ["event", ...(value.payload?.nativeContentVersion == null ? [] : ["nativeContentVersion"])]);
    if (value.payload.nativeContentVersion != null && value.payload.nativeContentVersion !== 1) throw fail();
    const event = value.payload.event;
    if (!event || event.schemaVersion !== 2 || !event.e2eeEnvelope || typeof event.envelopeDigest !== "string") throw fail();
    if (event.eventId !== `same_host_${createHash("sha256").update(`${event.clientMessageId}\0${event.envelopeDigest}`).digest("hex").slice(0, 32)}`) throw fail();
    // The full envelope/signature and all outer bindings are validated by the
    // ordinary E2EE receiver; this boundary only fixes the selected local pair.
    if (event.senderPrincipalId !== base.owner.principalId || event.recipientPrincipalId !== base.owner.principalId
      || event.senderHelloLynkId !== base.owner.hellolynkId || event.recipientHelloLynkId !== base.owner.hellolynkId
      || event.senderHostId !== source.hostInstallationId || event.senderDelegateId !== source.delegateId
      || event.senderDelegateAuthorizationVersion !== source.authorizationVersion
      || event.recipientHostId !== base.target.hostInstallationId || event.recipientDelegateId !== base.target.delegateId
      || event.recipientDelegateAuthorizationVersion !== base.target.authorizationVersion
      || !["owned_delegate", "instance_direct"].includes(event.routeKind)) throw fail();
  } else throw fail();
  return { ...base, source, action: value.action, payload: value.payload };
}

function signedPayload({ request, hostGeneration, capabilityId, result }) {
  return { contract: CONTRACT, requestDigest: digest(validateLocalPeerRequest(request)),
    hostGeneration: id(hostGeneration), capabilityId: id(capabilityId), result };
}
function mac(value, secret) {
  if (!Buffer.isBuffer(secret) || secret.length < 32) throw fail();
  return createHmac("sha256", secret).update(`${CONTRACT}\n${JSON.stringify(value)}`).digest("hex");
}
export function signLocalPeerResult(input) {
  const value = signedPayload(input);
  return { ...value, proof: mac(value, input.secretBuffer) };
}
export function verifyLocalPeerResult(input) {
  exact(input.response, ["contract", "requestDigest", "hostGeneration", "capabilityId", "result", "proof"]);
  const expected = signedPayload({ ...input, result: input.response.result });
  const { proof, ...actual } = input.response;
  if (JSON.stringify(expected) !== JSON.stringify(actual) || !/^[a-f0-9]{64}$/.test(proof)
    || !timingSafeEqual(Buffer.from(proof, "hex"), Buffer.from(mac(expected, input.secretBuffer), "hex"))) throw fail();
  return actual.result;
}

export function createLocalPeerTransport({ profile, access }) {
  const source = { hostInstallationId: profile.hostId, delegateId: profile.delegateId,
    authorizationVersion: profile.authorizationVersion };
  async function exchange(target, action, payload, { required, signal } = {}) {
    return access(target, async (peer) => {
      if (!peer.binding.capability.scopes.includes("app-data:authorized-messaging")) throw fail("local_peer_messaging_unavailable");
      const request = validateLocalPeerRequest({ challenge: randomBytes(32).toString("hex"), owner: peer.owner,
        target: { hostInstallationId: peer.binding.hostInstallationId, delegateId: peer.binding.delegateId,
          authorizationVersion: peer.target.authorizationVersion }, source, action, payload });
      const response = await peer.request(LOCAL_PEER_EXCHANGE_PATH, request);
      // No transport switch after this call, including timeout/invalid ACK.
      // The messenger retains its existing outcome-unknown and retry rules.
      if (response.status !== 200) throw fail("local_peer_exchange_unconfirmed");
      return verifyLocalPeerResult({ response: response.body, request, hostGeneration: peer.discovery.hostGeneration,
        capabilityId: peer.binding.capability.capabilityId, secretBuffer: peer.binding.capability.secretBuffer });
    }, { required, signal, proveIdentity: false, timeoutMs: 30_000 });
  }
  return Object.freeze({
    claim(input, { signal } = {}) {
      return exchange({ peerHelloLynkId: profile.hellolynkId, peerDelegateId: input.recipientDelegateId,
        peerHostId: input.recipientHostId }, "claim", { routeKind: input.routeKind, clientMessageId: input.clientMessageId,
        recipientDeviceId: input.recipientDeviceId ?? null,
        ...(input.nativeContentVersion ? { nativeContentVersion: input.nativeContentVersion } : {}) }, { signal });
    },
    async deliver(event, nativeContentVersion = null) {
      const result = await exchange({ peerHelloLynkId: event.recipientHelloLynkId, peerDelegateId: event.recipientDelegateId,
        peerHostId: event.recipientHostId, peerAuthorizationVersion: event.recipientDelegateAuthorizationVersion },
      "deliver", { event, ...(nativeContentVersion == null ? {} : { nativeContentVersion }) }, { required: true });
      exact(result, ["acknowledged", "duplicate", "replyTargetDeleted", "eventId", "envelopeDigest"]);
      if (result.acknowledged !== true || typeof result.duplicate !== "boolean" || typeof result.replyTargetDeleted !== "boolean"
        || result.eventId !== event.eventId || result.envelopeDigest !== event.envelopeDigest) throw fail("local_peer_ack_invalid");
      return result;
    },
  });
}
