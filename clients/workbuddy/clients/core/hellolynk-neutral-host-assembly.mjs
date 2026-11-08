import crypto from "node:crypto";
import { createLocalPeerAccess, normalizeLocalIdentityOwner } from "./hellolynk-local-identity-trust.mjs";
import { createLocalPeerTransport } from "./hellolynk-local-peer-transport.mjs";
import { ACCOUNT_CLIENTS, assertClientAccountCurrent } from "./hellolynk-client-account.mjs";
import { spawn } from "node:child_process";
import path from "node:path";

import {
  createDeviceRuntimeSessionManager,
  issueDeviceRuntimeSession,
  normalizeHelloLynkBaseUrl,
} from "./hellolynk-client-core.mjs";
import { readClientProfile } from "./hellolynk-client-profile.mjs";
import { createPlatformCredentialStore } from "./hellolynk-platform-credential-store.mjs";
import { createDirectTextE2eeClientContext } from "./hellolynk-direct-text-e2ee-client.mjs";
import { openContactRequestIntroEnvelope } from "./hellolynk-contact-request-e2ee.mjs";
import {
  createLocalMessenger,
  createOnlineRelayTransport,
} from "./hellolynk-local-messaging.mjs";
import { createIndexedLocalMessageStore } from "./hellolynk-indexed-message-store.mjs";
import { createLocalContactRequestStore } from "./hellolynk-local-contact-requests.mjs";
import { createLocalContactStore } from "./hellolynk-local-contacts.mjs";
import {
  createLocalDataProtector,
  createWindowsLocalDataKeyProvider,
} from "./hellolynk-local-data-protection.mjs";
import { createLocalDataMigrationCoordinator } from "./hellolynk-local-data-migration.mjs";
import { createHelloLynkHostTransportClient } from "./hellolynk-host-transport-client.mjs";
import { createNeutralHostInstallationStore } from "./hellolynk-neutral-host-installation-store.mjs";
import { createHostProtectedStore } from "./hellolynk-host-protected-store.mjs";
import {
  assertHelloLynkNeutralHostReleaseCurrent,
  discoverHelloLynkNeutralHost,
  startHelloLynkNeutralHostProcess,
} from "./hellolynk-neutral-host-process.mjs";
import { createNeutralHostStoreAdapters } from "./hellolynk-neutral-host-store-adapters.mjs";
import { createWindowsHumanConfirmationLedger } from "./hellolynk-human-confirmation-ledger.mjs";
import { createHelloLynkNativeHumanConfirmationBroker } from "./hellolynk-native-human-confirmation-broker.mjs";
import { createHelloLynkHumanRelationshipController } from "./hellolynk-human-relationship-controller.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const { sanitizeHelloLynkChildEnvironment, assertHelloLynkClientNodeVersion } = runtimeSafety;

export const HELLOLYNK_NEUTRAL_HOST_ASSEMBLY_CONTRACT = "hellolynk-neutral-host-assembly-v1";
const ACCOUNT_TARGETS = new Set(["account", "devices", "keys"]);
const ADAPTER_DISPLAY_NAMES = Object.freeze({
  codex: "Codex", openclaw: "OpenClaw", "trae-work": "TRAE Work",
  workbuddy: "WorkBuddy", cursor: "Cursor", dsh: "DSH", "claude-code": "Claude Code",
});
const WINDOWS_ACCOUNT_LAUNCH_ACK = "hellolynk-account-opened";

export function createHelloLynkAccountLauncher(options = {}) {
  const baseUrl = normalizeHelloLynkBaseUrl(options.baseUrl, {
    allowLoopbackHttp: options.allowLoopbackHttp === true,
  });
  const accountBase = new URL("/account", `${new URL(baseUrl).origin}/`);
  const spawnImpl = options.spawnImpl || spawn;
  if (typeof spawnImpl !== "function") throw failure("neutral_host_account_launcher_spawn_invalid");
  const launchTimeoutMs = options.launchTimeoutMs ?? 10_000;
  if (!Number.isSafeInteger(launchTimeoutMs) || launchTimeoutMs < 1 || launchTimeoutMs > 30_000) {
    throw failure("neutral_host_account_launcher_timeout_invalid");
  }
  const platform = String(options.platform || process.platform);
  const childEnvironment = sanitizeHelloLynkChildEnvironment(options.env || process.env);

  return Object.freeze(async (input) => {
    if (!input || Array.isArray(input) || typeof input !== "object"
      || !ACCOUNT_TARGETS.has(input.target)
      || Object.keys(input).some((key) => !["target", "deviceRequest"].includes(key))
      || (Object.hasOwn(input, "deviceRequest") && (input.target !== "account"
        || !/^devreq_[a-f0-9]{48}$/.test(input.deviceRequest)))) {
      throw failure("neutral_host_account_launcher_target_invalid");
    }
    const target = new URL(accountBase);
    if (input.deviceRequest) target.searchParams.set("deviceRequest", input.deviceRequest);
    else target.hash = input.target;
    let child;
    try {
      if (platform === "win32") {
        child = spawnImpl("powershell.exe", [
          "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
          "$ErrorActionPreference='Stop'; $target=$env:HELLOLYNK_ACCOUNT_URL; Remove-Item Env:HELLOLYNK_ACCOUNT_URL; Start-Process -FilePath $target; Write-Output 'hellolynk-account-opened'",
        ], {
          env: { ...childEnvironment, HELLOLYNK_ACCOUNT_URL: target.toString() },
          // Windows PowerShell can exit 0 without running -Command when Node
          // starts it with DETACHED_PROCESS. This short helper must stay attached.
          detached: false,
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
        });
      } else {
        child = spawnImpl(platform === "darwin" ? "open" : "xdg-open", [target.toString()], {
          env: childEnvironment,
          detached: true,
          stdio: "ignore",
        });
      }
    } catch {
      return Object.freeze({ opened: false });
    }
    if (!child || typeof child.once !== "function") return Object.freeze({ opened: false });
    const outcome = await new Promise((resolve) => {
      let settled = false;
      let timer;
      let acknowledgement = "";
      const onOutput = (bytes) => { acknowledgement = (acknowledgement + String(bytes)).slice(0, 64); };
      child.stdout?.on("data", onOutput);
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.off?.("error", onError);
        child.off?.("close", onClose);
        child.stdout?.off("data", onOutput);
        resolve(value);
      };
      const onError = () => finish("failed");
      const onClose = (code, signal) => finish(code === 0 && signal == null
        && (platform !== "win32" || acknowledgement.trim() === WINDOWS_ACCOUNT_LAUNCH_ACK) ? "opened" : "failed");
      child.once("error", onError);
      child.once("close", onClose);
      timer = setTimeout(() => finish("unknown"), launchTimeoutMs);
    });
    if (outcome === "unknown") {
      child.stdout?.destroy?.();
      child.unref?.();
      throw failure("neutral_host_account_launcher_outcome_unknown");
    }
    if (outcome !== "opened") return Object.freeze({ opened: false });
    child.unref?.();
    return Object.freeze({ opened: true });
  });
}

export async function startHelloLynkNeutralHostAssembly(options = {}, dependencies = {}) {
  assertHelloLynkClientNodeVersion();
  const root = absoluteRoot(options.root, "neutral_host_assembly_root_required");
  const runtimeRoot = path.resolve(options.runtimeRoot || path.join(root, "runtime"));
  const installationStore = dependencies.installationStore || createNeutralHostInstallationStore({ root });
  const installation = await activeInstallation(installationStore);
  // Before the profile, credential and key reads, so a refusal reaches the launcher at once.
  await assertHelloLynkNeutralHostReleaseCurrent({ runtimeRoot, hostInstallationId: installation.hostInstallationId });
  const descriptors = normalizeDescriptors(options.profiles);
  const protectedStore = dependencies.protectedStore || createHostProtectedStore({ root });
  const transportOwner = Object.freeze({
    principalId: installation.principalId,
    hostInstallationId: installation.hostInstallationId,
  });
  const hostTransportCredentialProvider = bindTransportCredentialProvider(
    dependencies.hostTransportCredentialProvider
      || protectedStore.hostTransportCredentialProvider,
    transportOwner,
  );
  const hostTransportSessionProvider = bindTransportSessionProvider(
    dependencies.hostTransportSessionProvider
      || protectedStore.hostTransportSessionProvider,
    transportOwner,
  );
  // The protected credential is read alongside the profiles and keys, but it
  // must resolve before any E2EE runtime is built or the Host lifecycle
  // starts: missing, corrupt, ambiguous, expired, or cross-owner state cannot
  // start the local Host. Credential and key reads settle before startup returns.
  const credentialRead = settle(() => hostTransportCredentialProvider.get());
  let profiles;
  let credentialStore;
  let keysRead = null;
  try {
    profiles = await Promise.all(descriptors.map(async (descriptor) => {
      const profile = await (dependencies.readProfile || readClientProfile)(descriptor.profileFile);
      validateProfile(profile, installation);
      return Object.freeze({ descriptor, profile });
    }));
    validateBindings(profiles, installation);
    const clientRoot = commonProfileClientRoot(profiles);
    credentialStore = dependencies.credentialStore || (
      dependencies.createCredentialStore || createPlatformCredentialStore
    )({
      clientRoot,
      storeRoot: path.join(clientRoot, "credentials"),
      e2eeStoreRoot: path.join(clientRoot, "e2ee-private-keys"),
    });
    // One helper process reads every profile's keys. It only fills the read
    // cache: each runtime still loads its own keys and reports its own errors.
    if (typeof credentialStore.directTextPrivateKeys?.preload === "function") {
      keysRead = settle(() => credentialStore.directTextPrivateKeys.preload(profiles.map(({ profile }) => profile.profileId)));
    }
  } catch (error) {
    await credentialRead;
    throw error;
  }
  const credential = await credentialRead;
  await keysRead;
  let hostTransportCredential = credential.value;
  credential.value = null;
  if (credential.error) throw credential.error;
  if (typeof hostTransportCredential !== "string" || !hostTransportCredential) {
    hostTransportCredential = null;
    throw failure("host_transport_credential_required");
  }
  hostTransportCredential = null;

  const runtimeByDelegate = new Map();
  const assertLocalIdentityRuntimeCurrent = async (profile, adapterId = null) => {
    const current = await activeInstallation(installationStore);
    validateProfile(profile, current);
    const binding = current.delegateBindings.find((item) => item.profileId === profile.profileId
      && item.delegateId === profile.delegateId && item.authorizationVersion === profile.authorizationVersion);
    if (!binding) throw failure("neutral_host_same_host_authorization_inactive");
    const clients = binding.adapters.filter((client) => ACCOUNT_CLIENTS.includes(client) && (!adapterId || client === adapterId));
    if (!clients.length) throw failure("workbench_account_changed");
    for (const client of clients) {
      try { assertClientAccountCurrent(client, root); return; } catch {}
    }
    throw failure("workbench_account_changed");
  };
  let sameHostDeliver = null;
  let contacts = null;
  const assertCurrentSameHostBinding = async (delegateId, authorizationVersion) => {
    const current = await activeInstallation(installationStore);
    if (current.principalId !== installation.principalId
      || current.hostInstallationId !== installation.hostInstallationId) {
      throw failure("neutral_host_same_host_installation_changed");
    }
    const binding = current.delegateBindings.find((item) => item.delegateId === delegateId);
    if (!binding || binding.authorizationVersion !== authorizationVersion) {
      throw failure("neutral_host_same_host_authorization_inactive");
    }
    return binding;
  };
  const initializedProfiles = await Promise.all(profiles.map(async ({ profile }) => {
    const peerOptions = { root, profile,
      clients: [...new Set(installation.delegateBindings.flatMap((binding) => binding.adapters)
        .filter((client) => ACCOUNT_CLIENTS.includes(client)))],
      assertCurrent: () => assertLocalIdentityRuntimeCurrent(profile) };
    const localPeerAccess = !dependencies.createLocalPeerAccess && (profile.allowLoopbackHttp === true || !peerOptions.clients.length)
      ? async (_input, _visit, { required = false } = {}) => {
        if (required) throw failure("local_peer_unavailable");
        return null;
      } : (dependencies.createLocalPeerAccess || createLocalPeerAccess)(peerOptions);
    const localPeer = createLocalPeerTransport({ profile, access: localPeerAccess });
    const sessionKey = runtimeSessionKey(profile);
    const manager = (dependencies.createRuntimeSessionManager || createDeviceRuntimeSessionManager)({
      sessionStore: credentialStore.runtimeSessions,
      sessionKey,
      issue: async ({ previousSession } = {}) => {
        let deviceCredential = await credentialStore.load(profile.profileId);
        try {
          return await (dependencies.issueRuntimeSession || issueDeviceRuntimeSession)({
            baseUrl: profile.baseUrl,
            allowLoopbackHttp: profile.allowLoopbackHttp,
            deviceCredential,
            expectedPrincipalId: profile.principalId,
            expectedAgentId: profile.agentId,
            expectedDelegateId: profile.delegateId,
            expectedHostId: profile.hostId,
            expectedAuthorizationVersion: profile.authorizationVersion,
            previousSession,
            fetchImpl: dependencies.fetchImpl,
          });
        } finally { deviceCredential = null; }
      },
    });
    const sessionProvider = Object.freeze({
      get: () => manager.get({
        expectedPrincipalId: profile.principalId,
        expectedAgentId: profile.agentId,
        expectedDelegateId: profile.delegateId,
        expectedHostId: profile.hostId,
        expectedAuthorizationVersion: profile.authorizationVersion,
      }),
      clear: (error) => manager.clear(error),
      status: () => manager.status(),
    });
    const e2ee = await (dependencies.createE2eeContext || createDirectTextE2eeClientContext)({
      profileId: profile.profileId,
      baseUrl: profile.baseUrl,
      allowLoopbackHttp: profile.allowLoopbackHttp,
      principalId: profile.principalId,
      hellolynkId: profile.hellolynkId,
      agentId: profile.agentId,
      delegateId: profile.delegateId,
      hostId: profile.hostId,
      authorizationVersion: profile.authorizationVersion,
      deviceId: profile.deviceId,
      e2eeVersion: 2,
      deferCloudRegistration: true,
      localClaimTimeoutMs: 30_000,
      sessionProvider,
      credentialStore,
      fetchImpl: dependencies.fetchImpl,
      sameHostClaimProvider: async (input, { signal } = {}) => {
        signal?.throwIfAborted();
        await assertLocalIdentityRuntimeCurrent(profile);
        if (input.recipientHostId && input.recipientHostId !== installation.hostInstallationId) {
          return localPeer.claim(input, { signal });
        }
        const recipient = runtimeByDelegate.get(input.recipientDelegateId);
        if (!recipient) {
          if (input.recipientHostId === installation.hostInstallationId) throw failure("neutral_host_same_host_recipient_unavailable");
          return localPeer.claim(input, { signal });
        }
        await assertCurrentSameHostBinding(profile.delegateId, profile.authorizationVersion);
        await assertCurrentSameHostBinding(recipient.profile.delegateId, recipient.profile.authorizationVersion);
        signal?.throwIfAborted();
        if (input.recipientDeviceId != null && input.recipientDeviceId !== recipient.profile.deviceId) {
          throw failure("neutral_host_same_host_device_mismatch");
        }
        const claim = await recipient.e2ee.createSameHostClaim({
          routeKind: input.routeKind,
          recipientDelegateId: input.recipientDelegateId,
          recipientHostId: installation.hostInstallationId,
          clientMessageId: input.clientMessageId,
          senderPrincipalId: input.senderPrincipalId,
          senderDelegateId: input.senderDelegateId,
          senderDelegateAuthorizationVersion: input.senderDelegateAuthorizationVersion,
        }, { signal });
        signal?.throwIfAborted();
        await assertCurrentSameHostBinding(profile.delegateId, profile.authorizationVersion);
        await assertCurrentSameHostBinding(recipient.profile.delegateId, recipient.profile.authorizationVersion);
        signal?.throwIfAborted();
        return claim;
      },
    });
    const contactE2ee = (dependencies.createContactE2ee || createContactInboundE2ee)({
      profile,
      credentialStore,
      now: options.now,
    });
    return Object.freeze({ profile, manager, sessionProvider, e2ee, contactE2ee, localPeer, localPeerAccess });
  }));

  const endpoints = [];
  for (const { profile, manager, sessionProvider, e2ee, contactE2ee, localPeer, localPeerAccess } of initializedProfiles) {
    runtimeByDelegate.set(profile.delegateId, Object.freeze({ profile, manager, sessionProvider, e2ee, localPeer, localPeerAccess }));
    const binding = installation.delegateBindings.find((item) => item.delegateId === profile.delegateId);
    const boundAdapters = [...new Set((binding?.adapters ?? []).filter((id) => ACCOUNT_CLIENTS.includes(id)))];
    endpoints.push(Object.freeze({
      principalId: profile.principalId,
      principalLabel: null,
      hostInstallationId: profile.hostId,
      delegateId: profile.delegateId,
      // A single installed adapter identifies the local AI's display name.
      // Shared or unknown adapter bindings cannot identify one client label.
      delegateLabel: boundAdapters.length === 1 ? ADAPTER_DISPLAY_NAMES[boundAdapters[0]] : profile.agentId,
      hellolynkId: profile.hellolynkId,
      authorizationVersion: profile.authorizationVersion,
      identityKeyId: e2ee.identityKeyId,
      runtimeHeaders: () => runtimeHeaders(sessionProvider),
      e2ee,
      contactE2ee,
    }));
  }

  const transport = dependencies.transport || createHelloLynkHostTransportClient({
    baseUrl: commonValue(profiles, "baseUrl", "neutral_host_assembly_base_url_mismatch"),
    allowLoopbackHttp: commonValue(profiles, "allowLoopbackHttp", "neutral_host_assembly_base_url_mismatch"),
    expectedPrincipalId: installation.principalId,
    expectedHostId: installation.hostInstallationId,
    credentialProvider: hostTransportCredentialProvider,
    sessionProvider: hostTransportSessionProvider,
    runtimeHeadersForDelegate: async (delegateId) => {
      const runtime = runtimeByDelegate.get(delegateId);
      if (!runtime) throw failure("neutral_host_assembly_delegate_unknown");
      return runtimeHeaders(runtime.sessionProvider);
    },
    fetchImpl: dependencies.fetchImpl,
  });

  const canonicalProfile = profiles.find(({ profile }) => profile.profileId === installation.canonicalProfileId)?.profile;
  if (!canonicalProfile) throw failure("neutral_host_assembly_canonical_profile_missing");
  const accountLauncher = dependencies.accountLauncher === null
    ? null
    : dependencies.accountLauncher ?? createHelloLynkAccountLauncher({
        baseUrl: canonicalProfile.baseUrl,
        allowLoopbackHttp: canonicalProfile.allowLoopbackHttp,
      });
  // Business records are plaintext. The former local data key is opened only
  // to convert an installation that still carries the encryption journal.
  let localDataKeyProvider = dependencies.localDataKeyProvider || null;
  const createLegacyDataProtector = () => dependencies.dataProtector || createLocalDataProtector({
    region: installation.region,
    principalId: installation.principalId,
    hostInstallationId: installation.hostInstallationId,
    keyProvider: localDataKeyProvider ||= (
      dependencies.createLocalDataKeyProvider || createWindowsLocalDataKeyProvider
    )({ root: path.join(root, "local-data-key") }),
  });
  const localDataMigration = dependencies.localDataMigration || createLocalDataMigrationCoordinator({
    root,
    region: installation.region,
    principalId: installation.principalId,
    hostInstallationId: installation.hostInstallationId,
    profileIds: profiles.map(({ profile }) => profile.profileId),
    canonicalProfileId: canonicalProfile.profileId,
    createLegacyDataProtector,
  });
  const messageStore = dependencies.messageStore || await createIndexedLocalMessageStore({
    profileId: canonicalProfile.profileId,
    storePath: path.join(root, "messages", `${canonicalProfile.profileId}.json`),
    ownerScope: { region: installation.region, principalId: installation.principalId },
    deferInitialization: true,
  });
  const contactRequestStore = dependencies.contactRequestStore || createLocalContactRequestStore({
    profileId: canonicalProfile.profileId,
    root,
  });
  contacts = dependencies.contacts || createLocalContactStore({
    profileId: canonicalProfile.profileId,
    root,
  });
  const adapters = dependencies.storeAdapters || createNeutralHostStoreAdapters({
    principalId: installation.principalId,
    profileId: canonicalProfile.profileId,
    messageStore,
    contactRequestStore,
    journalPath: path.join(root, "neutral-host-recovery-v1.json"),
  });
  const productionEndpoints = endpoints.map((endpoint) => {
    const runtime = runtimeByDelegate.get(endpoint.delegateId);
    const clients = installation.delegateBindings.find((item) => item.delegateId === endpoint.delegateId)?.adapters.filter((id) => ACCOUNT_CLIENTS.includes(id)) || [];
    const assertEndpointCurrent = () => {
      if (!clients.length) return;
      for (const client of clients) {
        try { assertClientAccountCurrent(client, root); return; } catch {}
      }
      throw failure("workbench_account_changed");
    };
    const relayTransport = (dependencies.createOutboundTransport || createOnlineRelayTransport)({
      baseUrl: runtime.profile.baseUrl,
      allowLoopbackHttp: runtime.profile.allowLoopbackHttp,
      sessionProvider: runtime.sessionProvider,
      fetchImpl: dependencies.fetchImpl,
    });
    const routeTransport = Object.freeze({
      async sendText(message) {
        assertEndpointCurrent();
        const sealed = message?.e2ee;
        const crossHostLocal = sealed?.version === "2" && sealed.claimId?.startsWith("local_peer_");
        const sameHostLocal = sealed?.version === "2" && sealed.recipientHostId === installation.hostInstallationId
          && (sealed.routeKind === "owned_delegate" || sealed.claimId?.startsWith("same_host_"));
        if (!crossHostLocal && !sameHostLocal) {
          return relayTransport.sendText(message);
        }
        if (typeof sameHostDeliver !== "function") throw failure("neutral_host_same_host_delivery_unavailable");
        const recipient = runtimeByDelegate.get(sealed.recipientDelegateId);
        if (!crossHostLocal && !recipient) throw failure("neutral_host_same_host_recipient_unavailable");
        await assertLocalIdentityRuntimeCurrent(runtime.profile);
        await assertCurrentSameHostBinding(runtime.profile.delegateId, runtime.profile.authorizationVersion);
        if (!crossHostLocal) await assertCurrentSameHostBinding(recipient.profile.delegateId, recipient.profile.authorizationVersion);
        const protectedMetadata = sealed.envelope?.protected;
        const { authorizationScope: _authorizationScope, intentSource: _intentSource, ...outerMetadata } = protectedMetadata;
        const senderIdentity = await runtime.e2ee.publicDeviceIdentity();
        const event = Object.freeze({
          schemaVersion: 2,
          eventId: `same_host_${crypto.createHash("sha256").update(`${message.clientMessageId}\0${sealed.envelopeDigest}`).digest("hex").slice(0, 32)}`,
          ...outerMetadata,
          e2eeEnvelope: sealed.envelope,
          envelopeDigest: sealed.envelopeDigest,
          senderIdentity,
          relayedAt: new Date().toISOString(),
        });
        const delivered = crossHostLocal ? await runtime.localPeer.deliver(event, sealed.nativeContentVersion)
          : await sameHostDeliver(Object.freeze({ event: "message", data: event, localDelivery: true }));
        return Object.freeze({
          ok: delivered?.replyTargetDeleted !== true,
          status: delivered?.replyTargetDeleted ? "reply_target_deleted" : "acknowledged_by_recipient_local_store",
          deliveryPath: crossHostLocal ? "same_computer_local" : "same_host_local",
          duplicate: delivered?.duplicate === true,
          eventId: event.eventId,
        });
      },
      openEventStream: (...args) => relayTransport.openEventStream(...args),
    });
    let messenger = null;
    const localMessenger = () => {
      messenger ||= (dependencies.createMessenger || createLocalMessenger)({
        profileId: canonicalProfile.profileId,
        principalId: installation.principalId,
        delegateId: endpoint.delegateId,
        store: messageStore,
        transport: routeTransport,
        e2ee: runtime.e2ee,
        e2eeMode: "required",
        durableBeforeEncryption: true,
      });
      return messenger;
    };
    return Object.freeze({
      ...endpoint,
      nativeDirectoryAdapterId: clients.length === 1 ? clients[0] : null,
      assertNativeDirectoryCurrent: assertEndpointCurrent,
      outbound: Object.freeze({
        async sendDirectory(input) {
          assertEndpointCurrent();
          if (input.recipientPrincipalId !== installation.principalId && (input.route?.routeKind !== "instance_direct"
            || !["friend_target_request", "friend_target_response"].includes(input.nativeDirectory?.kind)))
            throw failure("native_directory_own_ai_only");
          const e2ee = await runtime.e2ee.prepareOutgoing({
            recipientHelloLynkId: input.recipientHelloLynkId, senderPrincipalId: installation.principalId,
            senderDelegateId: endpoint.delegateId, clientMessageId: input.clientMessageId,
            text: "", nativeDirectory: input.nativeDirectory, intentSource: "human_preauthorized_contact",
            ...input.route,
          }, { persistPrepared: false });
          return routeTransport.sendText({ ...input, clientMessageId: e2ee.envelope.protected.clientMessageId, e2ee });
        },
        async send(input) {
          assertEndpointCurrent();
          const result = await localMessenger().sendText(input);
          if (result?.message?.lastErrorCode === "reply_target_deleted") throw failure("reply_target_deleted");
          if (result?.ok !== true) throw failure(
            safeOutboundCode(result?.errorCode || result?.message?.lastErrorCode || result?.status),
          );
          return result;
        },
        async retry(clientMessageId, options) {
          assertEndpointCurrent();
          return localMessenger().retry(clientMessageId, options);
        },
      }),
    });
  });
  const applicationOutbox = Object.freeze({
    ...adapters.outbox,
    async retry(clientMessageId, delegateId, options) {
      const endpoint = productionEndpoints.find((item) => item.delegateId === delegateId);
      if (!endpoint) throw failure("neutral_host_assembly_delegate_unknown");
      return endpoint.outbound.retry(clientMessageId, options);
    },
  });
  const canonicalRuntime = runtimeByDelegate.get(canonicalProfile.delegateId);
  if (!canonicalRuntime) throw failure("neutral_host_assembly_canonical_runtime_missing");
  const humanRelationships = dependencies.humanRelationships
    || (dependencies.createHumanRelationships || createHelloLynkHumanRelationshipController)({
      cloud: transport,
      e2ee: canonicalRuntime.e2ee,
      localStore: contactRequestStore,
      runtimeHeaders: () => runtimeHeaders(canonicalRuntime.sessionProvider),
      principalId: canonicalProfile.principalId,
      hellolynkId: canonicalProfile.hellolynkId,
      deviceId: canonicalProfile.deviceId,
      identityKeyId: canonicalRuntime.e2ee.identityKeyId,
      contactAuthorizationStore: contacts,
      now: options.now,
    });
  const humanConfirmationLedger = dependencies.humanConfirmationLedger
    || createWindowsHumanConfirmationLedger({
      root: path.join(root, "human-confirmation-ledger"),
    });
  const nativeHumanConfirmationBrokerFactory = dependencies.nativeHumanConfirmationBrokerFactory
    || ((input) => createHelloLynkNativeHumanConfirmationBroker({
      ledger: humanConfirmationLedger,
      launcher: dependencies.nativeHumanConfirmationLauncher,
      hostGeneration: input.hostGeneration,
      onApproved: input.onApproved,
      approvalDrainTimeoutMs: options.drainTimeoutMs,
    }));
  let host;
  try {
    host = await (dependencies.startProcess || startHelloLynkNeutralHostProcess)({
      region: installation.region,
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      runtimeRoot,
      transport,
      endpoints: productionEndpoints,
      localStore: adapters.localStore,
      contactStore: adapters.contactStore,
      outbox: adapters.outbox,
      inboxStore: applicationOutbox,
      contacts,
      localIdentityProof: async (context) => {
        const { request } = context;
        const runtime = runtimeByDelegate.get(request.target.delegateId);
        if (!runtime || request.target.hostInstallationId !== installation.hostInstallationId
          || request.target.authorizationVersion !== runtime.profile.authorizationVersion
          || context.delegateId !== runtime.profile.delegateId) throw failure("neutral_host_local_identity_unavailable");
        await assertLocalIdentityRuntimeCurrent(runtime.profile, context.adapterId);
        const owner = normalizeLocalIdentityOwner({ region: runtime.profile.region, baseUrl: runtime.profile.baseUrl,
          principalId: runtime.profile.principalId, hellolynkId: runtime.profile.hellolynkId });
        if (JSON.stringify(owner) !== JSON.stringify(request.owner)) throw failure("neutral_host_local_identity_owner_mismatch");
        // Immutable local identity metadata needs no E2EE state lock. Simultaneous
        // sends between two Hosts therefore cannot acquire one another's locks.
        return { deviceId: runtime.profile.deviceId, identityKeyId: runtime.e2ee.identityKeyId,
          safetyCode: runtime.e2ee.localDeviceSafetyCode };
      },
      localPeerExchange: async (context) => {
        const { request } = context;
        const runtime = runtimeByDelegate.get(request.target.delegateId);
        if (!runtime || context.delegateId !== runtime.profile.delegateId
          || request.target.hostInstallationId !== installation.hostInstallationId
          || request.target.authorizationVersion !== runtime.profile.authorizationVersion) throw failure("local_peer_target_changed");
        await assertLocalIdentityRuntimeCurrent(runtime.profile, context.adapterId);
        const owner = normalizeLocalIdentityOwner({ region: runtime.profile.region, baseUrl: runtime.profile.baseUrl,
          principalId: runtime.profile.principalId, hellolynkId: runtime.profile.hellolynkId });
        if (JSON.stringify(owner) !== JSON.stringify(request.owner)) throw failure("local_peer_owner_mismatch");
        // Verify the source's current protected binding, not an arbitrary key
        // supplied in an HTTP request. No profile/store lock spans this proof.
        await runtime.localPeerAccess({ peerHelloLynkId: owner.hellolynkId,
          peerDelegateId: request.source.delegateId, peerHostId: request.source.hostInstallationId,
          peerAuthorizationVersion: request.source.authorizationVersion }, async () => true,
        { required: true, proveIdentity: false, timeoutMs: 30_000 });
        await assertLocalIdentityRuntimeCurrent(runtime.profile, context.adapterId);
        if (request.action === "claim") {
          if (request.payload.recipientDeviceId && request.payload.recipientDeviceId !== runtime.profile.deviceId) throw failure("local_peer_target_changed");
          const claim = await runtime.e2ee.createSameHostClaim({ routeKind: request.payload.routeKind,
            clientMessageId: request.payload.clientMessageId, recipientDelegateId: runtime.profile.delegateId,
            recipientHostId: installation.hostInstallationId, senderPrincipalId: owner.principalId,
            senderDelegateId: request.source.delegateId, senderDelegateAuthorizationVersion: request.source.authorizationVersion });
          return { ...claim, claimId: claim.claimId.replace(/^same_host_/, "local_peer_") };
        }
        if (typeof sameHostDeliver !== "function") throw failure("local_peer_receive_unavailable");
        const event = request.payload.event;
        const delivered = await sameHostDeliver({ event: "message", data: event, localDelivery: true });
        return { acknowledged: delivered.acknowledged === true, duplicate: delivered.duplicate === true,
          replyTargetDeleted: delivered.replyTargetDeleted === true, eventId: event.eventId, envelopeDigest: event.envelopeDigest };
      },
      applicationOutbox,
      capabilityResolver: protectedStore.capabilityResolver,
      humanRelationships,
      accountLauncher,
      nativeHumanConfirmationBrokerFactory,
      sameHostDeliveryRegistrar: (deliver) => { sameHostDeliver = deliver; },
      prepareLocalData: async (context) => {
        await (dependencies.prepareLocalData || ((input) => localDataMigration.prepare(input)))(context);
        await messageStore.initialize?.();
      },
      port: options.port,
      drainTimeoutMs: options.drainTimeoutMs,
      maintenanceEveryMs: options.maintenanceEveryMs,
    });
  } catch (error) {
    try { await messageStore.close?.(); }
    finally { localDataKeyProvider?.clear?.(); }
    throw error;
  }

  return Object.freeze({
    contractId: HELLOLYNK_NEUTRAL_HOST_ASSEMBLY_CONTRACT,
    host,
    installation,
    endpoints: Object.freeze(productionEndpoints.map((endpoint) => Object.freeze({
      delegateId: endpoint.delegateId,
      identityKeyId: endpoint.identityKeyId,
      e2eeVersion: endpoint.e2ee.version,
    }))),
    runtimeByDelegate,
    stores: Object.freeze({
      messageStore,
      contactRequestStore,
      contacts,
      recovery: adapters.journal,
      localDataMigration,
    }),
    async stop(reason) {
      try {
        return await host.stop(reason);
      } finally {
        try { await messageStore.close?.(); }
        finally { localDataKeyProvider?.clear?.(); }
      }
    },
  });
}

export async function statusHelloLynkNeutralHostAssembly(options = {}, dependencies = {}) {
  const root = absoluteRoot(options.root, "neutral_host_assembly_root_required");
  const installations = dependencies.installationStore || createNeutralHostInstallationStore({ root });
  const registry = await installations.status();
  const active = registry.installations.filter((item) => item.state === "active");
  let discovery = null;
  if (active.length === 1) {
    discovery = await (dependencies.discover || discoverHelloLynkNeutralHost)({
      region: active[0].region,
      principalId: active[0].principalId,
      hostInstallationId: active[0].hostInstallationId,
      runtimeRoot: path.resolve(options.runtimeRoot || path.join(root, "runtime")),
    }).catch((error) => {
      if (["ENOENT", "neutral_host_runtime_path_invalid"].includes(error?.code)) return null;
      throw error;
    });
  }
  return Object.freeze({
    contractId: HELLOLYNK_NEUTRAL_HOST_ASSEMBLY_CONTRACT,
    registry,
    running: Boolean(discovery),
    discovery,
  });
}

export function createContactInboundE2ee(options = {}) {
  const profile = options.profile;
  const privateKeys = options.credentialStore?.directTextPrivateKeys;
  const stateLock = options.credentialStore?.runtimeSessions;
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  if (!privateKeys || !stateLock?.withLock) throw failure("neutral_host_contact_e2ee_store_invalid");
  return Object.freeze({
    async openIncoming(input = {}) {
      if (input.recipientPrincipalId !== profile.principalId
        || input.recipientDelegateId !== profile.delegateId) {
        throw failure("neutral_host_contact_e2ee_route_mismatch");
      }
      const event = input.event;
      return stateLock.withLock(profile.profileId, async () => {
        const state = await privateKeys.load(profile.profileId);
        if (!state || state.owner?.principalId !== profile.principalId
          || state.owner?.delegateId !== profile.delegateId || state.owner?.hostId !== profile.hostId
          || Number(state.owner?.authorizationVersion) !== profile.authorizationVersion) {
          throw failure("neutral_host_contact_e2ee_owner_mismatch");
        }
        if (state.deviceKeyBundle?.keyId !== event.recipientIdentityKeyId) {
          throw failure("neutral_host_contact_e2ee_identity_mismatch");
        }
        const preKey = state.preKeys?.find((item) => item.privateKeyBundle?.preKeyId === event.recipientPreKeyId);
        if (!preKey || !["registered", "used"].includes(preKey.state)) {
          throw failure("neutral_host_contact_e2ee_prekey_unavailable");
        }
        const opened = openContactRequestIntroEnvelope({
          envelope: event.e2eeEnvelope,
          senderDeviceIdentity: event.senderIdentity,
          recipientDeviceKeyBundle: state.deviceKeyBundle,
          recipientOneTimePreKey: preKey.privateKeyBundle,
          expectedSender: {
            principalId: event.senderPrincipalId,
            hellolynkId: event.senderHelloLynkId,
            deviceId: event.senderDeviceId,
          },
          expectedRecipient: {
            principalId: profile.principalId,
            hellolynkId: profile.hellolynkId,
            deviceId: profile.deviceId,
          },
        }, { nowMs: now() });
        assertContactOuterBindings(event, opened);
        let commitStarted = false;
        return Object.freeze({
          text: opened.introText,
          introDigestSalt: opened.introDigestSalt,
          envelopeDigest: opened.envelopeDigest,
          async commit() {
            if (commitStarted) return;
            commitStarted = true;
            try {
              await stateLock.withLock(profile.profileId, async () => {
                const latest = await privateKeys.load(profile.profileId);
                consumeContactPreKey(latest, event, opened.envelopeDigest, now());
                await privateKeys.save(profile.profileId, latest);
              });
            } catch (error) { commitStarted = false; throw error; }
          },
        });
      });
    },
  });
}

function assertContactOuterBindings(event, opened) {
  if (opened.envelopeDigest !== event.envelopeDigest) throw failure("neutral_host_contact_e2ee_digest_mismatch");
  for (const field of [
    "attemptId", "clientRequestId", "requestDigest", "introDigest", "introWeight",
    "senderPrincipalId", "senderHelloLynkId", "senderDeviceId", "senderIdentityKeyId",
    "recipientPrincipalId", "recipientHelloLynkId", "recipientDeviceId", "recipientIdentityKeyId",
    "recipientPreKeyId", "createdAt", "expiresAt",
  ]) {
    if (event[field] !== opened.protectedMetadata[field]) {
      throw failure("neutral_host_contact_e2ee_binding_mismatch");
    }
  }
  if (opened.protectedMetadata.authorizationScope !== "contact.request.send"
    || opened.protectedMetadata.intentSource !== "hellolynk_host_explicit_human_ui"
    || opened.protectedMetadata.messageType !== "contact_request_intro") {
    throw failure("neutral_host_contact_e2ee_binding_mismatch");
  }
}

function consumeContactPreKey(state, event, envelopeDigest, nowMs) {
  const preKeyId = event.recipientPreKeyId;
  const messageId = event.clientRequestId;
  const consumed = state.consumedPreKeys?.find((item) => item.preKeyId === preKeyId);
  const preKey = state.preKeys?.find((item) => item.privateKeyBundle?.preKeyId === preKeyId);
  if (consumed) {
    if (consumed.clientMessageId !== messageId || consumed.envelopeDigest !== envelopeDigest) {
      throw failure("neutral_host_contact_e2ee_prekey_conflict");
    }
    return false;
  }
  if (!preKey) throw failure("neutral_host_contact_e2ee_prekey_unavailable");
  if (preKey.state === "used" && (preKey.usedClientMessageId !== messageId
    || preKey.usedEnvelopeDigest !== envelopeDigest)) {
    throw failure("neutral_host_contact_e2ee_prekey_conflict");
  }
  const expiresAt = openedExpiry(event);
  if (Date.parse(expiresAt) <= nowMs) throw failure("neutral_host_contact_e2ee_prekey_expired");
  preKey.state = "used";
  preKey.claimExpiresAt = expiresAt;
  preKey.usedClientMessageId = messageId;
  preKey.usedEnvelopeDigest = envelopeDigest;
  if (!Array.isArray(state.consumedPreKeys)) throw failure("neutral_host_contact_e2ee_state_invalid");
  if (state.consumedPreKeys.length >= 512) state.consumedPreKeys.shift();
  state.consumedPreKeys.push({
    preKeyId,
    clientMessageId: messageId,
    envelopeDigest,
    consumedAt: new Date(nowMs).toISOString(),
  });
  return true;
}

function openedExpiry(event) {
  const value = String(event.e2eeEnvelope?.protected?.expiresAt || event.expiresAt || "");
  if (!Number.isFinite(Date.parse(value))) throw failure("neutral_host_contact_e2ee_expiry_invalid");
  return value;
}

async function runtimeHeaders(provider) {
  const session = await provider.get();
  const secret = String(session?.sessionSecret || "");
  if (!/^runtime_[a-f0-9]{48}$/.test(secret)) throw failure("neutral_host_assembly_runtime_invalid");
  return {
    "x-hellolynk-runtime-session-id": safeId(session.sessionId, "neutral_host_assembly_runtime_invalid"),
    "x-hellolynk-runtime-session-secret": secret,
    "x-hellolynk-e2ee-version": "2",
  };
}

function runtimeSessionKey(profile) {
  const digest = crypto.createHash("sha256").update(JSON.stringify({
    profileId: profile.profileId,
    baseUrl: profile.baseUrl,
    principalId: profile.principalId,
    agentId: profile.agentId,
    delegateId: profile.delegateId,
    hostId: profile.hostId,
    authorizationVersion: profile.authorizationVersion,
    deviceId: profile.deviceId,
  })).digest("hex").slice(0, 40);
  return `host-runtime-${digest}`;
}

function settle(operation) {
  return Promise.resolve().then(operation).then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
}

function bindTransportCredentialProvider(provider, owner) {
  if (!provider || typeof provider.get !== "function") {
    throw failure("host_transport_credential_provider_required");
  }
  return Object.freeze({ get: () => provider.get(owner) });
}

function bindTransportSessionProvider(provider, owner) {
  if (!provider || typeof provider.get !== "function" || typeof provider.save !== "function") {
    throw failure("host_transport_session_provider_required");
  }
  return Object.freeze({
    get: () => provider.get(owner),
    save: (value) => provider.save(value, owner),
    ...(typeof provider.remove === "function" ? { remove: () => provider.remove(owner) } : {}),
  });
}

async function activeInstallation(store) {
  const status = await store.status();
  const active = status.installations.filter((item) => item.state === "active");
  if (active.length !== 1) throw failure(active.length ? "neutral_host_assembly_installation_ambiguous" : "neutral_host_assembly_installation_missing");
  return active[0];
}

function normalizeDescriptors(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) throw failure("neutral_host_assembly_profiles_required");
  const seen = new Set();
  return value.map((descriptor) => {
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)
      || Object.keys(descriptor).length !== 1 || typeof descriptor.profileFile !== "string") {
      throw failure("neutral_host_assembly_profile_descriptor_invalid");
    }
    const profileFile = path.resolve(descriptor.profileFile);
    if (seen.has(profileFile)) throw failure("neutral_host_assembly_profile_duplicate");
    seen.add(profileFile);
    return Object.freeze({ profileFile });
  });
}

function validateProfile(profile, installation) {
  if (profile.schemaVersion !== 2) throw failure("neutral_host_assembly_schema_2_required");
  if (!profile.hellolynkId) throw failure("neutral_host_assembly_hellolynk_id_required");
  if (profile.region !== installation.region || profile.principalId !== installation.principalId
    || profile.hostId !== installation.hostInstallationId) {
    throw failure("neutral_host_assembly_profile_owner_mismatch");
  }
}

function validateBindings(profiles, installation) {
  if (profiles.length !== installation.delegateBindings.length) throw failure("neutral_host_assembly_binding_set_mismatch");
  const delegates = new Set();
  for (const { profile } of profiles) {
    if (delegates.has(profile.delegateId)) throw failure("neutral_host_assembly_delegate_duplicate");
    delegates.add(profile.delegateId);
    const binding = installation.delegateBindings.find((item) => item.profileId === profile.profileId);
    if (!binding || binding.delegateId !== profile.delegateId
      || binding.authorizationVersion !== profile.authorizationVersion) {
      throw failure("neutral_host_assembly_binding_mismatch");
    }
  }
}

function commonProfileClientRoot(profiles) {
  const roots = profiles.map(({ descriptor, profile }) => {
    const profileFile = path.resolve(descriptor.profileFile);
    const profileDirectory = path.dirname(profileFile);
    const expectedFile = path.join(profileDirectory, `${profile.profileId}.json`);
    if (path.basename(profileDirectory).toLowerCase() !== "profiles"
      || !sameFilesystemPath(profileFile, expectedFile)) {
      throw failure("neutral_host_assembly_profile_location_invalid");
    }
    return path.dirname(profileDirectory);
  });
  const first = roots[0];
  if (roots.some((root) => !sameFilesystemPath(root, first))) {
    throw failure("neutral_host_assembly_client_root_mismatch");
  }
  return first;
}

function sameFilesystemPath(left, right) {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function commonValue(profiles, field, code) {
  const first = profiles[0].profile[field];
  if (profiles.some(({ profile }) => profile[field] !== first)) throw failure(code);
  return first;
}

function absoluteRoot(value, code) {
  if (!value || !path.isAbsolute(String(value))) throw failure(code);
  return path.resolve(String(value));
}

function safeId(value, code) {
  const normalized = String(value || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,199}$/.test(normalized)) throw failure(code);
  return normalized;
}

function failure(code) { const error = new Error(code); error.code = code; return error; }

function safeOutboundCode(value) {
  const code = String(value || "delivery_state_unknown");
  return /^[a-z][a-z0-9_]{1,127}$/.test(code) ? code : "delivery_state_unknown";
}
