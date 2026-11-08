import { randomBytes } from "node:crypto";
import { lstat, mkdir } from "node:fs/promises";
import { createConnection } from "node:net";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";
import { readClientProfile } from "./hellolynk-client-profile.mjs";
import { assertClientAccountCurrent, clientAccountBaseRoot, resolveClientAccountRoot } from "./hellolynk-client-account.mjs";
export { resolveClientAccountRoot } from "./hellolynk-client-account.mjs";
import {
  assertCapabilityRecord,
  assertIdentifier,
  HELLOLYNK_HOST_CAPABILITY_CONTRACT,
} from "./hellolynk-host-auth.mjs";
import {
  createNeutralHostInstallationStore,
  defaultNeutralHostStoreRoot,
} from "./hellolynk-neutral-host-installation-store.mjs";

const { sanitizeHelloLynkChildEnvironment } = runtimeSafety;

export const HELLOLYNK_HOST_PROTECTED_STORE_CONTRACT = "hellolynk-host-protected-store-v1";
export const HELLOLYNK_HOST_TRANSPORT_CREDENTIAL_CONTRACT = "hellolynk-host-transport-credential-v1";
export const HELLOLYNK_HOST_TRANSPORT_SESSION_CONTRACT = "hellolynk-host-transport-session-v1";
export const HELLOLYNK_CODEX_NEUTRAL_BINDING_CONTRACT = "hellolynk-codex-neutral-binding-v1";
export const HELLOLYNK_OPENCLAW_NEUTRAL_BINDING_CONTRACT = "hellolynk-openclaw-neutral-binding-v1";
export const HELLOLYNK_TRAE_WORK_NEUTRAL_BINDING_CONTRACT = "hellolynk-trae-work-neutral-binding-v1";
export const HELLOLYNK_WORKBUDDY_NEUTRAL_BINDING_CONTRACT = "hellolynk-workbuddy-neutral-binding-v1";
export const HELLOLYNK_CLAUDE_CODE_NEUTRAL_BINDING_CONTRACT = "hellolynk-claude-code-neutral-binding-v1";
export const HELLOLYNK_CURSOR_NEUTRAL_BINDING_CONTRACT = "hellolynk-cursor-neutral-binding-v1";
export const HELLOLYNK_DSH_NEUTRAL_BINDING_CONTRACT = "hellolynk-dsh-neutral-binding-v1";
export const HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES = Object.freeze([
  "app-data:authorized-messaging",
  "app-data:changes-read",
  "app-data:contact-requests-read",
  "app-data:contacts-manage",
  "app-data:contacts-read",
  "app-data:human-send-request",
  "app-data:inbox-manage",
  "app-data:inbox-read",
  "app-data:outbox-read",
  "app-data:outbox-retry",
  "attachments:manage",
  "surface:human-ui",
  "ui:launch",
]);
export const HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES = Object.freeze([
  ...HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES,
]);
const HELLOLYNK_CODEX_NEUTRAL_PREVIOUS_SCOPES = Object.freeze(
  HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES.filter((scope) => scope !== "app-data:authorized-messaging"),
);
const HELLOLYNK_OPENCLAW_NEUTRAL_PREVIOUS_SCOPES = Object.freeze([
  ...HELLOLYNK_CODEX_NEUTRAL_PREVIOUS_SCOPES,
]);
export const HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES = Object.freeze([
  "app-data:authorized-messaging",
  "app-data:changes-read",
  "app-data:contact-requests-read",
  "app-data:contacts-manage",
  "app-data:contacts-read",
  "app-data:human-send-request",
  "app-data:inbox-manage",
  "app-data:inbox-read",
  "app-data:outbox-read",
  "app-data:outbox-retry",
  "attachments:manage",
  "status:read",
  "surface:human-ui",
  "ui:launch",
]);
export const HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES = Object.freeze([
  ...HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES,
]);
export const HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES = Object.freeze([
  ...HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES,
]);
export const HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES = Object.freeze([
  "app-data:authorized-messaging",
  "app-data:changes-read",
  "app-data:contact-requests-read",
  "app-data:contacts-manage",
  "app-data:contacts-read",
  "app-data:human-send-request",
  "app-data:inbox-manage",
  "app-data:inbox-read",
  "app-data:outbox-read",
  "app-data:outbox-retry",
  "attachments:manage",
  "status:read",
  "surface:human-ui",
  "ui:launch",
]);
// DSH's native assistant may read/reply only through contact-authorized routes.
// Human Workbench commands still require independently issued single-use grants.
const HELLOLYNK_CURSOR_NEUTRAL_PREVIOUS_SCOPES = Object.freeze(
  HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES.filter((scope) => scope !== "app-data:authorized-messaging"),
);
export const HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES = Object.freeze([...HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES]);
const HELLOLYNK_DSH_NEUTRAL_PREVIOUS_SCOPES = Object.freeze([...HELLOLYNK_CURSOR_NEUTRAL_PREVIOUS_SCOPES]);
const HELLOLYNK_TRAE_WORK_NEUTRAL_PREVIOUS_SCOPES = Object.freeze(
  HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES.filter((scope) => scope !== "app-data:authorized-messaging"),
);
const HELLOLYNK_WORKBUDDY_NEUTRAL_PREVIOUS_SCOPES = Object.freeze([
  ...HELLOLYNK_TRAE_WORK_NEUTRAL_PREVIOUS_SCOPES,
]);
const HELLOLYNK_TRAE_WORK_NEUTRAL_LEGACY_SCOPES = Object.freeze([
  "app-data:human-send-request",
  "attachments:manage",
  "status:read",
  "surface:human-ui",
]);
const HELLOLYNK_WORKBUDDY_NEUTRAL_LEGACY_SCOPES = Object.freeze([
  ...HELLOLYNK_TRAE_WORK_NEUTRAL_LEGACY_SCOPES,
]);
const CAPABILITY_ID_PATTERN = /^cap_[A-Za-z0-9_-]{32}$/;
const TRANSPORT_CREDENTIAL_PATTERN = /^hellolynk_host_transport_v1_([A-Za-z0-9_-]{3,127})\.([A-Za-z0-9_-]{32,})$/;
const TRANSPORT_SESSION_ID_PATTERN = /^hosttransportsession_[A-Za-z0-9_-]{16,}$/;
const TRANSPORT_SESSION_SECRET_PATTERN = /^hostsession_[a-f0-9]{48}$/;
const SCRIPT_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "platform",
  "windows",
  "hellolynk-host-protected-store.ps1",
);
const ROOT_INVOKE_QUEUES = new Map();
const NEUTRAL_BINDING_READS = new Map();
const MAX_NEUTRAL_BINDING_READS = 256;
const NEUTRAL_BINDING_READ = /^(Resolve|Verify)(Codex|OpenClaw|TraeWork|WorkBuddy|ClaudeCode|Cursor|Dsh)NeutralBinding$/;
const PERSISTENT_CREDENTIAL_EXPIRES_AT = 253402300799999;
const LEGACY_CREDENTIAL_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const READ_ONLY_COMMANDS = new Set([
  "LoadDeviceEnrollment",
  "Status", "VerifyCodexNeutralBinding", "VerifyOpenClawNeutralBinding",
  "VerifyTraeWorkNeutralBinding", "VerifyWorkBuddyNeutralBinding",
  "VerifyClaudeCodeNeutralBinding",
  "VerifyCursorNeutralBinding", "VerifyDshNeutralBinding", "VerifyTransport", "VerifyTransportCredentialLifetimeMigration",
  "ResolveCodexNeutralBinding", "ResolveOpenClawNeutralBinding", "ResolveTraeWorkNeutralBinding",
  "ResolveWorkBuddyNeutralBinding", "ResolveClaudeCodeNeutralBinding", "ResolveCursorNeutralBinding", "ResolveDshNeutralBinding",
]);

export function defaultClaudeCodeStoreRoot(env = process.env) {
  return defaultNeutralHostStoreRoot("win32", env);
}

function assertClaudeCodeStoreRoot(root) {
  const base = clientAccountBaseRoot(root);
  if (basename(base) !== "host") {
    throw codeError("neutral_claude_code_store_root_invalid");
  }
}

export function createHostProtectedStore(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== "win32") throw codeError("host_protected_store_platform_unsupported");
  const root = assertRoot(options.root || defaultNeutralHostStoreRoot(platform, options.env));
  const helperPath = resolve(options.helperPath || SCRIPT_PATH);
  const clock = normalizeClock(options.clock);
  const random = typeof options.randomBytes === "function" ? options.randomBytes : randomBytes;
  const readOnly = options.readOnly === true;
  const installationStore = options.installationStore || createNeutralHostInstallationStore(readOnly ? {
    root,
    readOnly: true,
    verifyPath: ({ path, directory }) => verifyHostProtectedStorePath({
      root,
      path,
      directory,
      helperPath,
      signal: options.signal,
    }),
  } : { root });
  const nativeInvoke = (command, invokeOptions) => invokeWindowsStore({
    command, root, helperPath, verifyOnly: readOnly, ...(readOnly ? { signal: options.signal } : {}), ...invokeOptions,
  });
  const baseInvoke = options.invoke || ((command, invokeOptions) => serializeRootInvoke(root, () => nativeInvoke(command, invokeOptions)));
  const invoke = async (command, invokeOptions = {}) => {
    if (readOnly && !READ_ONLY_COMMANDS.has(command)) throw codeError("host_protected_store_read_only");
    // Each peer lookup creates a read-only store. Reuse its successful DPAPI
    // result across those instances, while checking live paths and the file
    // on every use. Registration/account checks remain in the public methods.
    if (readOnly && !options.invoke && NEUTRAL_BINDING_READ.test(command)) {
      return readNeutralBinding(command, invokeOptions);
    }
    try {
      return await baseInvoke(command, invokeOptions);
    } finally {
      if (!READ_ONLY_COMMANDS.has(command)) {
        for (const [key, entry] of NEUTRAL_BINDING_READS) {
          if (entry.root === root) NEUTRAL_BINDING_READS.delete(key);
        }
      }
    }
  };
  const capabilityStorePath = join(root, "capabilities-v1.dpapi.clixml");
  const capabilityCache = new Map();
  const capabilityLoadFlights = new Map();
  let capabilityCacheFingerprint = null;

  async function readNeutralBinding(command, invokeOptions, queued = false) {
    const key = JSON.stringify([root, helperPath, command.replace(/^Verify/, "Resolve")]);
    const signal = options.signal;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      signal?.throwIfAborted();
      // A cold native read already verifies root and credential-file ACLs,
      // with the file check under its data mutex. Reuse that result only while
      // protected paths remain intact, without a second VerifyPath process.
      const before = await protectedPathFingerprint(root, capabilityStorePath, helperPath, false, signal);
      const cached = NEUTRAL_BINDING_READS.get(key);
      if (before && cached?.fingerprint === before
        && await neutralBindingPathsPresent(cached.result.binding, signal)) {
        signal?.throwIfAborted();
        const result = structuredClone(cached.result);
        // Verify keeps its original public-only contract. Resolve's caller
        // decodes a fresh Buffer, so wiping it cannot damage the cached copy.
        if (command.startsWith("Verify")) delete result.record.secret;
        return result;
      }
      // Keep warm reads independent of unrelated native work. On a miss,
      // recheck after entering the existing root queue and publish the result
      // before releasing it, so concurrent callers do not repeat the helper.
      if (!queued) return serializeRootInvoke(root, () => readNeutralBinding(command, invokeOptions, true));
      NEUTRAL_BINDING_READS.delete(key);
      const result = await nativeInvoke(command, invokeOptions);
      const after = await protectedPathFingerprint(root, capabilityStorePath, helperPath, false, signal);
      signal?.throwIfAborted();
      if (before !== after) continue;
      if (before && command.startsWith("Resolve")) {
        if (NEUTRAL_BINDING_READS.size >= MAX_NEUTRAL_BINDING_READS) {
          NEUTRAL_BINDING_READS.delete(NEUTRAL_BINDING_READS.keys().next().value);
        }
        NEUTRAL_BINDING_READS.set(key, { root, fingerprint: after, result: structuredClone(result) });
      }
      return result;
    }
    throw codeError("host_protected_store_changed_during_read");
  }

  function accountStore(client) {
    if (options.followClientAccount === false) return null;
    const selected = resolveClientAccountRoot(client, root);
    if (selected === root) return null;
    return createHostProtectedStore({ ...options, root: selected, installationStore: undefined });
  }
  function currentCapability(record) {
    assertClientAccountCurrent(record.adapterId, root);
    return record;
  }

  function invalidateCapabilityCache() {
    capabilityCacheFingerprint = null;
    capabilityCache.clear();
  }

  async function readCapabilityStoreFingerprint() {
    try {
      const metadata = await lstat(capabilityStorePath, { bigint: true });
      return [
        metadata.dev,
        metadata.ino,
        metadata.size,
        metadata.mtimeNs,
        metadata.birthtimeNs,
      ].join(":");
    } catch (error) {
      if (error?.code === "ENOENT") return "missing";
      throw error;
    }
  }

  async function resolveCapability(capabilityId) {
    const id = assertCapabilityId(capabilityId);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const fingerprint = await readCapabilityStoreFingerprint();
      if (fingerprint !== capabilityCacheFingerprint) {
        capabilityCacheFingerprint = fingerprint;
        capabilityCache.clear();
      }
      if (capabilityCache.has(id)) return currentCapability(capabilityCache.get(id));
      const existingFlight = capabilityLoadFlights.get(id);
      const flight = existingFlight?.fingerprint === fingerprint
        ? existingFlight
        : {
          fingerprint,
          promise: load(id),
        };
      if (flight !== existingFlight) capabilityLoadFlights.set(id, flight);
      try {
        const record = await flight.promise;
        const currentFingerprint = await readCapabilityStoreFingerprint();
        if (currentFingerprint !== fingerprint) {
          capabilityCacheFingerprint = currentFingerprint;
          capabilityCache.clear();
          continue;
        }
        capabilityCache.set(id, record);
        return currentCapability(record);
      } finally {
        if (capabilityLoadFlights.get(id) === flight) capabilityLoadFlights.delete(id);
      }
    }
    throw codeError("host_protected_store_changed_during_read");
  }

  async function issue(input = {}) {
    const record = createRecord(input, { clock, random });
    let result;
    try {
      result = await invoke("Issue", { stdin: serializeRecord(record) });
    } finally {
      invalidateCapabilityCache();
    }
    return deserializeRecord(result?.record);
  }

  async function load(capabilityId) {
    const id = assertCapabilityId(capabilityId);
    const result = await invoke("Load", { capabilityId: id });
    return deserializeRecord(result?.record);
  }

  async function revoke(capabilityId) {
    const id = assertCapabilityId(capabilityId);
    let result;
    try {
      result = await invoke("Revoke", { capabilityId: id });
    } finally {
      invalidateCapabilityCache();
    }
    return Object.freeze({
      capabilityId: assertCapabilityId(result?.capabilityId),
      state: result?.state === "revoked" ? "revoked" : fail("host_capability_state_invalid"),
      revokedAt: assertTimestamp(result?.revokedAt),
    });
  }

  async function rotate(capabilityId, input = {}) {
    const oldId = assertCapabilityId(capabilityId);
    const record = createRecord(input, { clock, random });
    if (record.capabilityId === oldId) throw codeError("host_capability_rotation_id_reused");
    let result;
    try {
      result = await invoke("Rotate", {
        capabilityId: oldId,
        stdin: serializeRecord(record),
      });
    } finally {
      invalidateCapabilityCache();
    }
    if (result?.replacedCapabilityId !== oldId) throw codeError("host_capability_rotation_invalid");
    return deserializeRecord(result.record);
  }

  async function status() {
    const result = await invoke("Status", {});
    if (result?.contract !== HELLOLYNK_HOST_PROTECTED_STORE_CONTRACT || result?.protected !== true
      || Object.keys(result).sort().join(",") !== "contract,protected") {
      throw codeError("host_protected_store_status_invalid");
    }
    return Object.freeze({ contract: result.contract, protected: true });
  }

  async function saveCodexNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveCodexInstallationBinding(installationStore, input, installation);
    const descriptor = codexNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveCodexNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicCodexNeutralBinding(result?.binding), root);
  }

  async function resolveCodexNeutralBinding() {
    const selected = accountStore("codex");
    if (selected) return selected.resolveCodexNeutralBinding();
    const installationBefore = await resolveActiveInstallation(installationStore, {});
    const result = await invoke("ResolveCodexNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicCodexNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentCodexInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyCodexNeutralBinding() {
    const selected = accountStore("codex");
    if (selected) return selected.verifyCodexNeutralBinding();
    const installationBefore = await resolveActiveInstallation(installationStore, {});
    const result = await invoke("VerifyCodexNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicCodexNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentCodexInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeCodexNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveCodexInstallationBinding(installationStore, input, installation);
    const expected = publicCodexNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_codex_capability_binding_mismatch");
    }
    const result = await invoke("RemoveCodexNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_codex_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function replaceCodexNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input.replacementBinding);
    const delegateBinding = await resolveCodexInstallationBinding(
      installationStore,
      input.replacementBinding,
      installation,
    );
    const previousBinding = publicCodexNeutralBinding(input.previousBinding);
    const replacementBinding = codexNeutralBindingDescriptor(
      input.replacementBinding,
      installation,
      delegateBinding,
    );
    const result = await invoke("ReplaceCodexNeutralBinding", {
      stdin: JSON.stringify({ previousBinding, replacementBinding }),
    });
    return publicCodexNeutralBinding(result?.binding);
  }

  async function migrateCodexNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateCodexNeutralBinding",
      input,
      adapterId: "codex",
      bindingCode: "neutral_codex_capability_binding_mismatch",
      descriptor: codexNeutralBindingDescriptor,
      publicBinding: publicCodexNeutralBinding,
      resolveInstallationBinding: resolveCodexInstallationBinding,
      assertCurrent: assertCurrentCodexInstallationBinding,
    });
  }

  async function saveOpenClawNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveOpenClawInstallationBinding(installationStore, input, installation);
    const descriptor = openClawNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveOpenClawNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicOpenClawNeutralBinding(result?.binding), root);
  }

  async function resolveOpenClawNeutralBinding(input = {}) {
    const selected = accountStore("openclaw");
    if (selected) return selected.resolveOpenClawNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveOpenClawNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicOpenClawNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentOpenClawInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyOpenClawNeutralBinding(input = {}) {
    const selected = accountStore("openclaw");
    if (selected) return selected.verifyOpenClawNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyOpenClawNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicOpenClawNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentOpenClawInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeOpenClawNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveOpenClawInstallationBinding(installationStore, input, installation);
    const expected = publicOpenClawNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_openclaw_capability_binding_mismatch");
    }
    const result = await invoke("RemoveOpenClawNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_openclaw_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateOpenClawNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateOpenClawNeutralBinding",
      input,
      adapterId: "openclaw",
      bindingCode: "neutral_openclaw_capability_binding_mismatch",
      descriptor: openClawNeutralBindingDescriptor,
      publicBinding: publicOpenClawNeutralBinding,
      resolveInstallationBinding: resolveOpenClawInstallationBinding,
      assertCurrent: assertCurrentOpenClawInstallationBinding,
    });
  }

  async function saveTraeWorkNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveTraeWorkInstallationBinding(installationStore, input, installation);
    const descriptor = traeWorkNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveTraeWorkNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicTraeWorkNeutralBinding(result?.binding), root);
  }

  async function resolveTraeWorkNeutralBinding(input = {}) {
    const selected = accountStore("trae-work");
    if (selected) return selected.resolveTraeWorkNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveTraeWorkNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicTraeWorkNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentTraeWorkInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyTraeWorkNeutralBinding(input = {}) {
    const selected = accountStore("trae-work");
    if (selected) return selected.verifyTraeWorkNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyTraeWorkNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicTraeWorkNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentTraeWorkInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeTraeWorkNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveTraeWorkInstallationBinding(installationStore, input, installation);
    const expected = publicTraeWorkNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_trae_work_capability_binding_mismatch");
    }
    const result = await invoke("RemoveTraeWorkNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_trae_work_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateTraeWorkNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateTraeWorkNeutralBinding",
      input,
      adapterId: "trae-work",
      bindingCode: "neutral_trae_work_capability_binding_mismatch",
      descriptor: traeWorkNeutralBindingDescriptor,
      publicBinding: publicTraeWorkNeutralBinding,
      resolveInstallationBinding: resolveTraeWorkInstallationBinding,
      assertCurrent: assertCurrentTraeWorkInstallationBinding,
    });
  }

  async function saveWorkBuddyNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveWorkBuddyInstallationBinding(installationStore, input, installation);
    const descriptor = workBuddyNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveWorkBuddyNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicWorkBuddyNeutralBinding(result?.binding), root);
  }

  async function resolveWorkBuddyNeutralBinding(input = {}) {
    const selected = accountStore("workbuddy");
    if (selected) return selected.resolveWorkBuddyNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveWorkBuddyNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicWorkBuddyNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentWorkBuddyInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyWorkBuddyNeutralBinding(input = {}) {
    const selected = accountStore("workbuddy");
    if (selected) return selected.verifyWorkBuddyNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyWorkBuddyNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicWorkBuddyNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentWorkBuddyInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeWorkBuddyNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveWorkBuddyInstallationBinding(installationStore, input, installation);
    const expected = publicWorkBuddyNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_workbuddy_capability_binding_mismatch");
    }
    const result = await invoke("RemoveWorkBuddyNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_workbuddy_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateWorkBuddyNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateWorkBuddyNeutralBinding",
      input,
      adapterId: "workbuddy",
      bindingCode: "neutral_workbuddy_capability_binding_mismatch",
      descriptor: workBuddyNeutralBindingDescriptor,
      publicBinding: publicWorkBuddyNeutralBinding,
      resolveInstallationBinding: resolveWorkBuddyInstallationBinding,
      assertCurrent: assertCurrentWorkBuddyInstallationBinding,
    });
  }

  async function saveClaudeCodeNeutralBinding(input = {}) {
    assertClaudeCodeStoreRoot(root);
    assertClientAccountCurrent("claude-code", root);
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveClaudeCodeInstallationBinding(installationStore, input, installation);
    const descriptor = claudeCodeNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveClaudeCodeNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicClaudeCodeNeutralBinding(result?.binding), root);
  }

  async function resolveClaudeCodeNeutralBinding(input = {}) {
    assertClaudeCodeStoreRoot(root);
    const selected = accountStore("claude-code");
    if (selected) return selected.resolveClaudeCodeNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveClaudeCodeNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicClaudeCodeNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentClaudeCodeInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyClaudeCodeNeutralBinding(input = {}) {
    assertClaudeCodeStoreRoot(root);
    const selected = accountStore("claude-code");
    if (selected) return selected.verifyClaudeCodeNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyClaudeCodeNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicClaudeCodeNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentClaudeCodeInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeClaudeCodeNeutralBinding(input = {}) {
    assertClaudeCodeStoreRoot(root);
    assertClientAccountCurrent("claude-code", root);
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveClaudeCodeInstallationBinding(installationStore, input, installation);
    const expected = publicClaudeCodeNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_claude_code_capability_binding_mismatch");
    }
    const result = await invoke("RemoveClaudeCodeNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_claude_code_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateClaudeCodeNeutralBinding(input = {}) {
    assertClaudeCodeStoreRoot(root);
    assertClientAccountCurrent("claude-code", root);
    return migrateNeutralBinding({
      command: "MigrateClaudeCodeNeutralBinding",
      input,
      adapterId: "claude-code",
      bindingCode: "neutral_claude_code_capability_binding_mismatch",
      descriptor: claudeCodeNeutralBindingDescriptor,
      publicBinding: publicClaudeCodeNeutralBinding,
      resolveInstallationBinding: resolveClaudeCodeInstallationBinding,
      assertCurrent: assertCurrentClaudeCodeInstallationBinding,
    });
  }

  async function saveCursorNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveCursorInstallationBinding(installationStore, input, installation);
    const descriptor = cursorNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveCursorNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicCursorNeutralBinding(result?.binding), root);
  }

  async function resolveCursorNeutralBinding(input = {}) {
    const selected = accountStore("cursor");
    if (selected) return selected.resolveCursorNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveCursorNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicCursorNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentCursorInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function verifyCursorNeutralBinding(input = {}) {
    const selected = accountStore("cursor");
    if (selected) return selected.verifyCursorNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyCursorNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicCursorNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentCursorInstallationBinding(
      installationStore,
      installationBefore,
      binding,
      capability,
      input,
    );
    return Object.freeze({ ...binding, capability });
  }

  async function removeCursorNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveCursorInstallationBinding(installationStore, input, installation);
    const expected = publicCursorNeutralBinding(input);
    if (expected.region !== installation.region
      || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId
      || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_cursor_capability_binding_mismatch");
    }
    const result = await invoke("RemoveCursorNeutralBinding", {
      stdin: JSON.stringify(expected),
    });
    if (result?.removed !== true) throw codeError("neutral_cursor_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateCursorNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateCursorNeutralBinding",
      input,
      adapterId: "cursor",
      bindingCode: "neutral_cursor_capability_binding_mismatch",
      descriptor: cursorNeutralBindingDescriptor,
      publicBinding: publicCursorNeutralBinding,
      resolveInstallationBinding: resolveCursorInstallationBinding,
      assertCurrent: assertCurrentCursorInstallationBinding,
    });
  }

  async function saveDshNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveDshInstallationBinding(installationStore, input, installation);
    const descriptor = dshNeutralBindingDescriptor(input, installation, delegateBinding);
    const result = await invoke("SaveDshNeutralBinding", { stdin: JSON.stringify(descriptor) });
    return assertPersistentNeutralBinding(publicDshNeutralBinding(result?.binding), root);
  }

  async function resolveDshNeutralBinding(input = {}) {
    const selected = accountStore("dsh");
    if (selected) return selected.resolveDshNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("ResolveDshNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicDshNeutralBinding(result?.binding), root);
    const capability = deserializeRecord(result?.record);
    await assertCurrentDshInstallationBinding(installationStore, installationBefore, binding, capability, input);
    return Object.freeze({ ...binding, capability });
  }

  async function verifyDshNeutralBinding(input = {}) {
    const selected = accountStore("dsh");
    if (selected) return selected.verifyDshNeutralBinding(input);
    const installationBefore = await resolveActiveInstallation(installationStore, input);
    const result = await invoke("VerifyDshNeutralBinding", {});
    const binding = assertPersistentNeutralBinding(publicDshNeutralBinding(result?.binding), root);
    const capability = publicRecord(result?.record);
    await assertCurrentDshInstallationBinding(installationStore, installationBefore, binding, capability, input);
    return Object.freeze({ ...binding, capability });
  }

  async function removeDshNeutralBinding(input = {}) {
    const installation = await resolveActiveInstallation(installationStore, input);
    const delegateBinding = await resolveDshInstallationBinding(installationStore, input, installation);
    const expected = publicDshNeutralBinding(input);
    if (expected.region !== installation.region || expected.principalId !== installation.principalId
      || expected.hostInstallationId !== installation.hostInstallationId
      || expected.profileId !== delegateBinding.profileId || expected.delegateId !== delegateBinding.delegateId) {
      throw codeError("neutral_dsh_capability_binding_mismatch");
    }
    const result = await invoke("RemoveDshNeutralBinding", { stdin: JSON.stringify(expected) });
    if (result?.removed !== true) throw codeError("neutral_dsh_binding_configuration_required");
    return Object.freeze({ removed: true });
  }

  async function migrateDshNeutralBinding(input = {}) {
    return migrateNeutralBinding({
      command: "MigrateDshNeutralBinding", input, adapterId: "dsh",
      bindingCode: "neutral_dsh_capability_binding_mismatch",
      descriptor: dshNeutralBindingDescriptor, publicBinding: publicDshNeutralBinding,
      resolveInstallationBinding: resolveDshInstallationBinding,
      assertCurrent: assertCurrentDshInstallationBinding,
    });
  }

  // Explicit recovery to the one supported prior DSH scope contract. Normal
  // save/migrate still require current scopes; this cannot select arbitrary scopes.
  async function restoreDshNeutralBinding(input = {}) {
    if (!Array.isArray(input?.replacementBinding?.scopes)
      || !sameStrings(input.replacementBinding.scopes, HELLOLYNK_DSH_NEUTRAL_PREVIOUS_SCOPES)) {
      throw codeError("neutral_dsh_capability_binding_mismatch");
    }
    return migrateNeutralBinding({
      command: "RestoreDshNeutralBinding", input, adapterId: "dsh",
      bindingCode: "neutral_dsh_capability_binding_mismatch",
      descriptor: (value, installation, delegate) => dshNeutralBindingDescriptor(value, installation, delegate, true),
      publicBinding: publicDshNeutralBinding,
      resolveInstallationBinding: resolveDshInstallationBinding,
      assertCurrent: assertCurrentDshInstallationBinding,
    });
  }

  async function migrateNeutralBinding(spec) {
    const previousCapabilityId = assertCapabilityId(spec.input?.previousCapabilityId);
    const installation = await resolveActiveInstallation(
      installationStore,
      spec.input?.replacementBinding,
    );
    const delegateBinding = await spec.resolveInstallationBinding(
      installationStore,
      spec.input?.replacementBinding,
      installation,
    );
    const previousBinding = spec.publicBinding(spec.input?.previousBinding);
    if (previousBinding.region !== installation.region
      || previousBinding.principalId !== installation.principalId
      || previousBinding.hostInstallationId !== installation.hostInstallationId
      || previousBinding.profileId !== delegateBinding.profileId
      || previousBinding.delegateId !== delegateBinding.delegateId) {
      throw codeError(spec.bindingCode);
    }
    const replacementBinding = spec.descriptor(
      spec.input?.replacementBinding,
      installation,
      delegateBinding,
    );
    const replacementRecord = createRecord({
      region: replacementBinding.region,
      principalId: replacementBinding.principalId,
      delegateId: replacementBinding.delegateId,
      hostInstallationId: replacementBinding.hostInstallationId,
      adapterId: spec.adapterId,
      version: replacementBinding.version,
      scopes: replacementBinding.scopes,
    }, { clock, random });
    if (replacementRecord.capabilityId === previousCapabilityId) {
      replacementRecord.secretBuffer.fill(0);
      throw codeError("host_capability_rotation_id_reused");
    }
    let result;
    try {
      result = await invoke(spec.command, {
        capabilityId: previousCapabilityId,
        stdin: JSON.stringify({
          previousBinding,
          replacementBinding,
          replacementRecord: JSON.parse(serializeRecord(replacementRecord)),
        }),
      });
    } finally {
      replacementRecord.secretBuffer.fill(0);
      invalidateCapabilityCache();
    }
    if (result?.replacedCapabilityId !== previousCapabilityId) {
      throw codeError("host_capability_rotation_invalid");
    }
    let capability;
    try {
      const binding = spec.publicBinding(result?.binding);
      capability = deserializeRecord(result?.record);
      await spec.assertCurrent(installationStore, installation, binding, capability, binding);
      return Object.freeze({ ...binding, capability });
    } catch (error) {
      capability?.secretBuffer?.fill(0);
      throw error;
    }
  }

  async function saveTransportCredential(input = {}, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const record = transportCredentialRecord(input, installation);
    if (record.expiresAt <= assertTimestamp(clock())) throw codeError("host_transport_credential_expired");
    const result = await invoke("SaveTransportCredential", { stdin: JSON.stringify(record) });
    return deserializeTransportCredential(result?.record, installation, clock(), { allowExpired: false });
  }

  async function disconnectLocalClient(client) {
    if (!["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh", "claude-code"].includes(client)) throw codeError("workbench_account_client_invalid");
    if (client === "claude-code") assertClaudeCodeStoreRoot(root);
    try {
      const result = await invoke("DisconnectLocalClient", { stdin: JSON.stringify({ client }) });
      if (result?.disconnected !== true || result.client !== client) throw codeError("workbench_disconnect_failed");
      return Object.freeze({ disconnected: true });
    } finally { invalidateCapabilityCache(); }
  }

  async function saveEnrollmentTransportCredential(input = {}, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const record = transportCredentialRecord(input, installation);
    if (record.expiresAt <= assertTimestamp(clock())) throw codeError("host_transport_credential_expired");
    // The native transaction verifies the durable enrollment approval before
    // replacing an older transport credential. Ordinary saves stay immutable.
    const result = await invoke("SaveEnrollmentTransportCredential", { stdin: JSON.stringify(record) });
    return deserializeTransportCredential(result?.record, installation, clock(), { allowExpired: false });
  }

  async function loadDeviceEnrollment() {
    return validateDeviceEnrollmentResult(await invoke("LoadDeviceEnrollment"));
  }

  async function saveDeviceEnrollment(input = {}) {
    if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0
      || !input.value || typeof input.value !== "object" || Array.isArray(input.value)) {
      throw codeError("device_enrollment_store_invalid");
    }
    const stdin = JSON.stringify({ expectedRevision: input.expectedRevision, value: input.value });
    if (Buffer.byteLength(stdin, "utf8") > 60 * 1024) throw codeError("device_enrollment_store_invalid");
    return validateDeviceEnrollmentResult(await invoke("SaveDeviceEnrollment", { stdin }));
  }

  async function loadTransportCredential(credentialId, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const result = await invoke("LoadTransportCredential", {
      credentialId: assertIdentifier(credentialId, "host_transport_credential_id_invalid"),
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      timestamp: assertTimestamp(clock()),
    });
    return deserializeTransportCredential(result?.record, installation, clock(), { allowExpired: false });
  }

  // Explicit maintenance only. Ordinary load/save must continue rejecting expired
  // credentials and immutable changes. Never return candidate or session secrets.
  async function migrateTransportCredentialLifetime(input = {}) {
    if (input.apply === true && readOnly) throw codeError("host_protected_store_read_only");
    const installation = await resolveActiveInstallation(installationStore, input);
    const profile = await readClientProfile(input.profileFile);
    if (profile.principalId !== installation.principalId || profile.hostId !== installation.hostInstallationId
      || profile.region !== installation.region
      || !installation.delegateBindings?.some((binding) => binding.profileId === profile.profileId
        && binding.delegateId === profile.delegateId && binding.authorizationVersion === profile.authorizationVersion)) {
      throw codeError("host_transport_migration_profile_mismatch");
    }
    const relay = new URL(profile.baseUrl.replace(/\/api\/v1\/?$/, ""));
    if (relay.protocol !== "https:" || relay.username || relay.password || relay.search || relay.hash
      || relay.pathname !== "/") throw codeError("host_transport_migration_https_required");
    const query = { principalId: installation.principalId, hostInstallationId: installation.hostInstallationId };
    const result = await invoke("VerifyTransportCredentialLifetimeMigration", { ...query, verifyOnly: true });
    const previous = deserializeTransportCredential(result?.record, installation, clock(), { allowExpired: true });
    const permanent = previous.expiresAt === PERSISTENT_CREDENTIAL_EXPIRES_AT;
    if (!permanent && previous.expiresAt - previous.issuedAt !== LEGACY_CREDENTIAL_LIFETIME_MS) {
      throw codeError("host_transport_migration_lifetime_invalid");
    }
    const summary = { credentialId: previous.credentialId, principalId: previous.principalId,
      hostId: previous.hostInstallationId, previousExpiresAt: previous.expiresAt,
      expiresAt: permanent ? previous.expiresAt : PERSISTENT_CREDENTIAL_EXPIRES_AT };
    if (permanent || input.apply !== true) return Object.freeze({ ...summary, status: permanent ? "already_permanent" : "eligible" });
    let response;
    try {
      response = await (options.migrationFetchImpl || globalThis.fetch)(`${relay.origin}/api/v2/host-transport/sessions`, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(8_000),
        headers: { "content-type": "application/json", "x-hellolynk-host-transport-credential": previous.secret },
        body: "{}",
      });
    } catch { throw codeError("host_transport_migration_http_failed"); }
    if (!response.ok) throw codeError("host_transport_migration_http_failed");
    let proof;
    try { proof = await response.json(); } catch { throw codeError("host_transport_migration_proof_invalid"); }
    if (!proof || typeof proof !== "object" || Array.isArray(proof)
      || proof.credentialId !== previous.credentialId || proof.principalId !== previous.principalId
      || proof.hostId !== previous.hostInstallationId || Date.parse(proof.credentialCreatedAt) !== previous.issuedAt
      || Date.parse(proof.credentialExpiresAt) !== PERSISTENT_CREDENTIAL_EXPIRES_AT
      || !TRANSPORT_SESSION_ID_PATTERN.test(proof.hostTransportSessionId)
      || !TRANSPORT_SESSION_SECRET_PATTERN.test(proof.hostTransportSessionSecret)
      || !(Date.parse(proof.expiresAt) > clock()) || Date.parse(proof.expiresAt) >= PERSISTENT_CREDENTIAL_EXPIRES_AT) {
      throw codeError("host_transport_migration_proof_invalid");
    }
    // Recheck owner/profile after network I/O; the native helper compares every
    // original credential field under its per-root mutex before the only write.
    await resolveActiveInstallation(installationStore, installation);
    const currentProfile = await readClientProfile(input.profileFile);
    if (JSON.stringify(currentProfile) !== JSON.stringify(profile)) throw codeError("host_transport_migration_profile_changed");
    const migrated = await invoke("MigrateTransportCredentialLifetime", { ...query, stdin: JSON.stringify({
      previous, proof: { credentialId: proof.credentialId, principalId: proof.principalId,
        hostId: proof.hostId, credentialCreatedAt: proof.credentialCreatedAt, credentialExpiresAt: proof.credentialExpiresAt },
    }) });
    if (migrated?.credentialId !== previous.credentialId || migrated?.expiresAt !== PERSISTENT_CREDENTIAL_EXPIRES_AT
      || migrated?.status !== "migrated") throw codeError("host_transport_migration_result_invalid");
    return Object.freeze({ ...summary, status: "migrated" });
  }

  async function revokeTransportCredential(credentialId, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const result = await invoke("RevokeTransportCredential", {
      credentialId: assertIdentifier(credentialId, "host_transport_credential_id_invalid"),
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      timestamp: assertTimestamp(clock()),
    });
    assertExactKeys(result, ["cascadedSessionCount", "credentialId", "revokedAt", "state"]);
    if (result.credentialId !== credentialId || result.state !== "revoked") {
      throw codeError("host_transport_credential_revoke_invalid");
    }
    return Object.freeze({
      credentialId: result.credentialId,
      state: result.state,
      revokedAt: assertTimestamp(result.revokedAt),
      cascadedSessionCount: assertNonNegativeInteger(
        result.cascadedSessionCount,
        "host_transport_credential_revoke_invalid",
      ),
    });
  }

  async function saveTransportSession(input = {}, installationInput = {}) {
    return writeTransportSession("SaveTransportSession", input, installationInput);
  }

  async function replaceTransportSession(input = {}, installationInput = {}) {
    return writeTransportSession("ReplaceTransportSession", input, installationInput);
  }

  async function writeTransportSession(command, input, installationInput) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const record = transportSessionRecord(input, installation);
    const now = assertTimestamp(clock());
    if (record.expiresAt <= now) throw codeError("host_transport_session_expired");
    const result = await invoke(command, { stdin: JSON.stringify(record), timestamp: now });
    return deserializeTransportSession(result?.record, installation, null, now);
  }

  async function loadTransportSession(sessionId, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const result = await invoke("LoadTransportSession", {
      sessionId: assertTransportSessionId(sessionId),
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      timestamp: assertTimestamp(clock()),
    });
    return deserializeTransportSession(result?.record, installation, null, clock());
  }

  async function removeTransportSession(sessionId, installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const result = await invoke("RemoveTransportSession", {
      sessionId: assertTransportSessionId(sessionId),
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
    });
    assertExactKeys(result, ["removed", "sessionId"]);
    if (result.sessionId !== sessionId || typeof result.removed !== "boolean") {
      throw codeError("host_transport_session_remove_invalid");
    }
    return Object.freeze({ sessionId: result.sessionId, removed: result.removed });
  }

  async function resolveTransport(installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const now = assertTimestamp(clock());
    const result = await invoke("ResolveTransport", {
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      timestamp: now,
    });
    assertExactKeys(result, ["credential", "session"]);
    const credential = deserializeTransportCredential(result.credential, installation, now, { allowExpired: false });
    const session = result.session === null
      ? null
      : deserializeTransportSession(result.session, installation, credential.credentialId, now);
    return Object.freeze({ credential, session });
  }

  async function verifyTransport(installationInput = {}) {
    const installation = await resolveActiveInstallation(installationStore, installationInput);
    const now = assertTimestamp(clock());
    const result = await invoke("VerifyTransport", {
      principalId: installation.principalId,
      hostInstallationId: installation.hostInstallationId,
      timestamp: now,
    });
    assertExactKeys(result, ["credential", "session"]);
    assertExactKeys(result.credential, [
      "credentialId", "expiresAt", "hostInstallationId", "principalId",
    ]);
    const credential = Object.freeze({
      credentialId: assertIdentifier(result.credential.credentialId, "host_transport_credential_id_invalid"),
      principalId: assertIdentifier(result.credential.principalId, "host_principal_id_invalid"),
      hostInstallationId: assertIdentifier(result.credential.hostInstallationId, "host_installation_id_invalid"),
      expiresAt: assertTimestamp(result.credential.expiresAt),
    });
    if (credential.principalId !== installation.principalId
      || credential.hostInstallationId !== installation.hostInstallationId
      || credential.expiresAt <= now) throw codeError("host_transport_credential_owner_mismatch");
    let session = null;
    if (result.session !== null) {
      assertExactKeys(result.session, [
        "credentialId", "expiresAt", "hostInstallationId", "principalId", "sessionId",
      ]);
      session = Object.freeze({
        sessionId: assertTransportSessionId(result.session.sessionId),
        credentialId: assertIdentifier(result.session.credentialId, "host_transport_credential_id_invalid"),
        principalId: assertIdentifier(result.session.principalId, "host_principal_id_invalid"),
        hostInstallationId: assertIdentifier(result.session.hostInstallationId, "host_installation_id_invalid"),
        expiresAt: assertTimestamp(result.session.expiresAt),
      });
      if (session.credentialId !== credential.credentialId
        || session.principalId !== installation.principalId
        || session.hostInstallationId !== installation.hostInstallationId
        || session.expiresAt <= now) throw codeError("host_transport_session_owner_mismatch");
    }
    return Object.freeze({ credential, session });
  }

  const hostTransportCredentialProvider = Object.freeze({
    async get(installationInput = {}) {
      return (await resolveTransport(installationInput)).credential.secret;
    },
  });

  const hostTransportSessionProvider = Object.freeze({
    async get(installationInput = {}) {
      const resolved = await resolveTransport(installationInput);
      if (!resolved.session) throw codeError("host_transport_session_invalid");
      return clientTransportSession(resolved.session);
    },
    async save(value, installationInput = {}) {
      const resolved = await resolveTransport(installationInput);
      const session = await replaceTransportSession({
        ...value,
        credentialId: resolved.credential.credentialId,
        hostInstallationId: value?.hostInstallationId ?? value?.hostId,
        issuedAt: value?.issuedAt ?? clock(),
      }, installationInput);
      return clientTransportSession(session);
    },
    async remove(installationInput = {}) {
      const resolved = await resolveTransport(installationInput);
      if (!resolved.session) return Object.freeze({ sessionId: null, removed: false });
      return removeTransportSession(resolved.session.sessionId, installationInput);
    },
  });

  return Object.freeze({
    root,
    issue,
    load,
    revoke,
    disconnectLocalClient,
    rotate,
    status,
    capabilityResolver: resolveCapability,
    saveCodexNeutralBinding,
    resolveCodexNeutralBinding,
    verifyCodexNeutralBinding,
    removeCodexNeutralBinding,
    replaceCodexNeutralBinding,
    migrateCodexNeutralBinding,
    saveOpenClawNeutralBinding,
    resolveOpenClawNeutralBinding,
    verifyOpenClawNeutralBinding,
    removeOpenClawNeutralBinding,
    migrateOpenClawNeutralBinding,
    saveTraeWorkNeutralBinding,
    resolveTraeWorkNeutralBinding,
    verifyTraeWorkNeutralBinding,
    removeTraeWorkNeutralBinding,
    migrateTraeWorkNeutralBinding,
    saveWorkBuddyNeutralBinding,
    resolveWorkBuddyNeutralBinding,
    verifyWorkBuddyNeutralBinding,
    removeWorkBuddyNeutralBinding,
    migrateWorkBuddyNeutralBinding,
    saveClaudeCodeNeutralBinding,
    resolveClaudeCodeNeutralBinding,
    verifyClaudeCodeNeutralBinding,
    removeClaudeCodeNeutralBinding,
    migrateClaudeCodeNeutralBinding,
    saveCursorNeutralBinding,
    resolveCursorNeutralBinding,
    verifyCursorNeutralBinding,
    removeCursorNeutralBinding,
    migrateCursorNeutralBinding,
    saveDshNeutralBinding,
    resolveDshNeutralBinding,
    verifyDshNeutralBinding,
    removeDshNeutralBinding,
    migrateDshNeutralBinding,
    restoreDshNeutralBinding,
    saveTransportCredential,
    loadDeviceEnrollment,
    saveDeviceEnrollment,
    saveEnrollmentTransportCredential,
    loadTransportCredential,
    migrateTransportCredentialLifetime,
    revokeTransportCredential,
    saveTransportSession,
    loadTransportSession,
    removeTransportSession,
    replaceTransportSession,
    resolveTransport,
    verifyTransport,
    hostTransportCredentialProvider,
    hostTransportSessionProvider,
  });
}

// The native resolver also checks launch paths outside the credential file.
// Check those current paths even on a cache hit; never hide a removed runner
// or a directory replaced with a junction behind an unchanged credential.
async function neutralBindingPathsPresent(binding, signal) {
  const paths = [[binding.runtimeRoot, true, 0]];
  if (binding.adapterId === "codex") paths.push(
    [binding.releaseRoot, true, 0],
    [binding.profileManifestPath, false, 65536],
    [resolve(binding.releaseRoot, binding.runnerRelativePath), false, 1048576],
  );
  for (const [target, directory, maxBytes] of paths) {
    for (let current = target; ; current = dirname(current)) {
      signal?.throwIfAborted();
      const stat = await lstat(current).catch(() => null);
      if (!stat || stat.isSymbolicLink()) return false;
      if (current === target && !directory) {
        if (!stat.isFile() || stat.size > maxBytes) return false;
      } else if (!stat.isDirectory()) return false;
      if (dirname(current) === current) break;
    }
  }
  return true;
}

// Reuse a successful ACL/path check while files and directory identities stay
// unchanged. Files include ctime: Windows ACL edits need not change mtime.
// Directories omit timestamps so ordinary writes do not invalidate the cache.
// Per the user's 2026-10-12 decision, in-place directory ACL changes can remain
// cached until Host restart; cold checks and replacement/junction checks remain.
// Credentials, bindings and authorization state are still read separately.
const VERIFIED_PATHS = new Map();
const MAX_VERIFIED_PATHS = 256;

async function protectedPathFingerprint(root, target, helperPath, directory, signal) {
  const components = new Set();
  for (const leaf of [root, target, helperPath]) {
    for (let cursor = leaf; ; cursor = dirname(cursor)) {
      components.add(cursor);
      if (dirname(cursor) === cursor) break;
    }
  }
  const parts = [];
  for (const component of components) {
    signal?.throwIfAborted();
    let stat;
    try { stat = await lstat(component, { bigint: true }); }
    catch { return null; } // Let the existing verifier report the path error.
    const isFile = component === helperPath || (component === target && !directory);
    if (stat.isSymbolicLink() || (isFile ? !stat.isFile() : !stat.isDirectory())) return null;
    const identity = [component, stat.dev, stat.ino, stat.mode, stat.birthtimeNs];
    parts.push((isFile
      ? [...identity, stat.nlink, stat.size, stat.ctimeNs, stat.mtimeNs] : identity).join(":"));
  }
  signal?.throwIfAborted();
  return parts.join("\n");
}

export async function verifyHostProtectedStorePath(options = {}) {
  const root = assertRoot(options.root || defaultNeutralHostStoreRoot("win32", options.env));
  const target = resolve(String(options.path || ""));
  const relativeTarget = relative(root, target);
  if (!isAbsolute(String(options.path || ""))
    || (relativeTarget !== "" && (isAbsolute(relativeTarget) || relativeTarget === ".." || relativeTarget.startsWith(`..\\`)))) {
    throw codeError("host_protected_store_path_invalid");
  }
  const helperPath = resolve(options.helperPath || SCRIPT_PATH);
  const directory = options.directory === true;
  const key = JSON.stringify([root, target, helperPath, directory]);
  const before = await protectedPathFingerprint(root, target, helperPath, directory, options.signal);
  options.signal?.throwIfAborted();
  if (before && VERIFIED_PATHS.get(key) === before) return Object.freeze({ verified: true });
  VERIFIED_PATHS.delete(key);
  const result = await invokeWindowsStore({
    command: "VerifyPath",
    root,
    helperPath,
    verifyOnly: true,
    signal: options.signal,
    pathToVerify: target,
    verifyDirectory: directory,
  });
  assertExactKeys(result, ["verified"]);
  if (result.verified !== true) throw codeError("host_protected_store_path_invalid");
  const after = await protectedPathFingerprint(root, target, helperPath, directory, options.signal);
  if (before && after === before) {
    if (VERIFIED_PATHS.size >= MAX_VERIFIED_PATHS) VERIFIED_PATHS.delete(VERIFIED_PATHS.keys().next().value);
    VERIFIED_PATHS.set(key, after);
  }
  return Object.freeze({ verified: true });
}

function serializeRootInvoke(root, callback) {
  const key = process.platform === "win32"
    ? root.replace(/[\\/]+$/, "").toUpperCase()
    : root;
  const previous = ROOT_INVOKE_QUEUES.get(key) || Promise.resolve();
  const current = previous.catch(() => {}).then(callback);
  ROOT_INVOKE_QUEUES.set(key, current);
  return current.finally(() => {
    if (ROOT_INVOKE_QUEUES.get(key) === current) ROOT_INVOKE_QUEUES.delete(key);
  });
}

async function resolveOpenClawInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_openclaw_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_openclaw_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_openclaw_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("openclaw")) {
    throw codeError("neutral_openclaw_capability_binding_mismatch");
  }
  return binding;
}

async function resolveTraeWorkInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_trae_work_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_trae_work_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("trae-work")) {
    throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
  return binding;
}

function traeWorkNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES);
  const acceptedScopes = sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES)
    || (input?.allowLegacyScopes === true
      && (sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_PREVIOUS_SCOPES)
        || sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_LEGACY_SCOPES)));
  if (!acceptedScopes
    || (input?.adapterId ?? "trae-work") !== "trae-work"
    || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
  const release = optionalTraeWorkReleaseBinding(input);
  return Object.freeze({
    contract: HELLOLYNK_TRAE_WORK_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "trae-work",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_trae_work_binding_invalid"),
    ...release,
  });
}

function publicTraeWorkNeutralBinding(value) {
  const releaseKeys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value || {}, key)).length;
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version",
    ...(releaseCount ? releaseKeys : []),
  ], "neutral_trae_work_binding_invalid");
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) {
    throw codeError("neutral_trae_work_binding_invalid");
  }
  if (value.contract !== HELLOLYNK_TRAE_WORK_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "trae-work" || Number(value.version) !== 2) {
    throw codeError("neutral_trae_work_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_PREVIOUS_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_TRAE_WORK_NEUTRAL_LEGACY_SCOPES)) {
    throw codeError("neutral_trae_work_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_trae_work_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_trae_work_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_trae_work_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_trae_work_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_trae_work_binding_invalid"),
    adapterId: "trae-work",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_trae_work_binding_invalid"),
    ...(releaseCount === 0 ? {} : optionalTraeWorkReleaseBinding(value)),
  });
}

function optionalTraeWorkReleaseBinding(value) {
  const keys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const count = keys.filter((key) => Object.hasOwn(value || {}, key)).length;
  if (count === 0) return Object.freeze({});
  if (count !== keys.length) throw codeError("neutral_trae_work_launch_configuration_invalid");
  return Object.freeze({
    releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_trae_work_launch_configuration_invalid"),
    releaseManifestSha256: assertSha256(value.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(value.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      value.profileManifestPath,
      "neutral_trae_work_launch_configuration_invalid",
    ),
  });
}

async function assertCurrentTraeWorkInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
  const delegateBinding = await resolveTraeWorkInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "trae-work" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_trae_work_capability_binding_mismatch");
  }
}

async function resolveWorkBuddyInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_workbuddy_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_workbuddy_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("workbuddy")) {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
  return binding;
}

function workBuddyNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES);
  const acceptedScopes = sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES)
    || (input?.allowLegacyScopes === true
      && (sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_PREVIOUS_SCOPES)
        || sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_LEGACY_SCOPES)));
  if (!acceptedScopes
    || (input?.adapterId ?? "workbuddy") !== "workbuddy"
    || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
  const release = optionalWorkBuddyReleaseBinding(input);
  return Object.freeze({
    contract: HELLOLYNK_WORKBUDDY_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "workbuddy",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_workbuddy_binding_invalid"),
    ...release,
  });
}

function publicWorkBuddyNeutralBinding(value) {
  const releaseKeys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value || {}, key)).length;
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version",
    ...(releaseCount ? releaseKeys : []),
  ], "neutral_workbuddy_binding_invalid");
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) {
    throw codeError("neutral_workbuddy_binding_invalid");
  }
  if (value.contract !== HELLOLYNK_WORKBUDDY_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "workbuddy" || Number(value.version) !== 2) {
    throw codeError("neutral_workbuddy_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_PREVIOUS_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_WORKBUDDY_NEUTRAL_LEGACY_SCOPES)) {
    throw codeError("neutral_workbuddy_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_workbuddy_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_workbuddy_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_workbuddy_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_workbuddy_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_workbuddy_binding_invalid"),
    adapterId: "workbuddy",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_workbuddy_binding_invalid"),
    ...(releaseCount === 0 ? {} : optionalWorkBuddyReleaseBinding(value)),
  });
}

function optionalWorkBuddyReleaseBinding(value) {
  const keys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const count = keys.filter((key) => Object.hasOwn(value || {}, key)).length;
  if (count === 0) return Object.freeze({});
  if (count !== keys.length) throw codeError("neutral_workbuddy_launch_configuration_invalid");
  return Object.freeze({
    releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_workbuddy_launch_configuration_invalid"),
    releaseManifestSha256: assertSha256(value.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(value.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      value.profileManifestPath,
      "neutral_workbuddy_launch_configuration_invalid",
    ),
  });
}

async function assertCurrentWorkBuddyInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
  const delegateBinding = await resolveWorkBuddyInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "workbuddy" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_workbuddy_capability_binding_mismatch");
  }
}

async function resolveClaudeCodeInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_claude_code_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_claude_code_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_claude_code_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("claude-code")) {
    throw codeError("neutral_claude_code_capability_binding_mismatch");
  }
  return binding;
}

function claudeCodeNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES);
  const acceptedScopes = sameStrings(scopes, HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES);
  if (!acceptedScopes
    || (input?.adapterId ?? "claude-code") !== "claude-code"
    || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_claude_code_capability_binding_mismatch");
  }
  const release = optionalClaudeCodeReleaseBinding(input);
  return Object.freeze({
    contract: HELLOLYNK_CLAUDE_CODE_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "claude-code",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_claude_code_binding_invalid"),
    ...release,
  });
}

function publicClaudeCodeNeutralBinding(value) {
  const releaseKeys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value || {}, key)).length;
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version",
    ...(releaseCount ? releaseKeys : []),
  ], "neutral_claude_code_binding_invalid");
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) {
    throw codeError("neutral_claude_code_binding_invalid");
  }
  if (value.contract !== HELLOLYNK_CLAUDE_CODE_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "claude-code" || Number(value.version) !== 2) {
    throw codeError("neutral_claude_code_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_CLAUDE_CODE_NEUTRAL_EXACT_SCOPES)) {
    throw codeError("neutral_claude_code_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_claude_code_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_claude_code_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_claude_code_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_claude_code_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_claude_code_binding_invalid"),
    adapterId: "claude-code",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_claude_code_binding_invalid"),
    ...(releaseCount === 0 ? {} : optionalClaudeCodeReleaseBinding(value)),
  });
}

function optionalClaudeCodeReleaseBinding(value) {
  const keys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const count = keys.filter((key) => Object.hasOwn(value || {}, key)).length;
  if (count === 0) return Object.freeze({});
  if (count !== keys.length) throw codeError("neutral_claude_code_launch_configuration_invalid");
  return Object.freeze({
    releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_claude_code_launch_configuration_invalid"),
    releaseManifestSha256: assertSha256(value.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(value.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      value.profileManifestPath,
      "neutral_claude_code_launch_configuration_invalid",
    ),
  });
}

async function assertCurrentClaudeCodeInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_claude_code_capability_binding_mismatch");
  }
  const delegateBinding = await resolveClaudeCodeInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "claude-code" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_claude_code_capability_binding_mismatch");
  }
}

async function resolveCursorInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_cursor_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_cursor_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_cursor_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("cursor")) {
    throw codeError("neutral_cursor_capability_binding_mismatch");
  }
  return binding;
}

function cursorNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES);
  if (!sameStrings(scopes, HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES)
    || (input?.adapterId ?? "cursor") !== "cursor"
    || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_cursor_capability_binding_mismatch");
  }
  const release = optionalCursorReleaseBinding(input);
  return Object.freeze({
    contract: HELLOLYNK_CURSOR_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "cursor",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_cursor_binding_invalid"),
    ...release,
  });
}

function publicCursorNeutralBinding(value) {
  const releaseKeys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const releaseCount = releaseKeys.filter((key) => Object.hasOwn(value || {}, key)).length;
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version",
    ...(releaseCount ? releaseKeys : []),
  ], "neutral_cursor_binding_invalid");
  if (releaseCount !== 0 && releaseCount !== releaseKeys.length) {
    throw codeError("neutral_cursor_binding_invalid");
  }
  if (value.contract !== HELLOLYNK_CURSOR_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "cursor" || Number(value.version) !== 2) {
    throw codeError("neutral_cursor_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_CURSOR_NEUTRAL_PREVIOUS_SCOPES)) {
    throw codeError("neutral_cursor_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_cursor_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_cursor_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_cursor_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_cursor_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_cursor_binding_invalid"),
    adapterId: "cursor",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_cursor_binding_invalid"),
    ...(releaseCount === 0 ? {} : optionalCursorReleaseBinding(value)),
  });
}

function optionalCursorReleaseBinding(value) {
  const keys = [
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const count = keys.filter((key) => Object.hasOwn(value || {}, key)).length;
  if (count === 0) return Object.freeze({});
  if (count !== keys.length) throw codeError("neutral_cursor_launch_configuration_invalid");
  return Object.freeze({
    releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_cursor_launch_configuration_invalid"),
    releaseManifestSha256: assertSha256(
      value.releaseManifestSha256,
      "neutral_cursor_launch_configuration_invalid",
    ),
    runnerRelativePath: assertRunnerReference(
      value.runnerRelativePath,
      "neutral_cursor_launch_configuration_invalid",
    ),
    profileManifestPath: assertAbsolutePath(
      value.profileManifestPath,
      "neutral_cursor_launch_configuration_invalid",
    ),
  });
}

async function assertCurrentCursorInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_cursor_capability_binding_mismatch");
  }
  const delegateBinding = await resolveCursorInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "cursor" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_cursor_capability_binding_mismatch");
  }
}

async function resolveDshInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_dsh_binding_invalid");
  const delegateId = input?.delegateId == null ? null : assertIdentifier(input.delegateId, "neutral_dsh_binding_invalid");
  let binding;
  try { binding = await store.resolveBinding({ profileId, delegateId }); } catch {
    throw codeError("neutral_dsh_capability_binding_mismatch");
  }
  if (binding.region !== installation.region || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId || !binding.adapters.includes("dsh")) {
    throw codeError("neutral_dsh_capability_binding_mismatch");
  }
  return binding;
}

function dshNeutralBindingDescriptor(input, installation, delegateBinding, allowPrevious = false) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES);
  if (!(sameStrings(scopes, HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES)
      || (allowPrevious && sameStrings(scopes, HELLOLYNK_DSH_NEUTRAL_PREVIOUS_SCOPES)))
    || (input?.adapterId ?? "dsh") !== "dsh" || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_dsh_capability_binding_mismatch");
  }
  return Object.freeze({
    contract: HELLOLYNK_DSH_NEUTRAL_BINDING_CONTRACT, region: installation.region,
    principalId: installation.principalId, delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId, profileId: delegateBinding.profileId,
    adapterId: "dsh", version: 2, scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_dsh_binding_invalid"),
    ...optionalDshReleaseBinding(input),
  });
}

function publicDshNeutralBinding(value) {
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "profileManifestPath", "region", "releaseManifestSha256", "releaseRoot",
    "runnerRelativePath", "runtimeRoot", "scopes", "version",
  ], "neutral_dsh_binding_invalid");
  if (value.contract !== HELLOLYNK_DSH_NEUTRAL_BINDING_CONTRACT || value.adapterId !== "dsh"
    || Number(value.version) !== 2) throw codeError("neutral_dsh_binding_invalid");
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_DSH_NEUTRAL_PREVIOUS_SCOPES)) throw codeError("neutral_dsh_binding_invalid");
  return Object.freeze({
    contract: value.contract, region: assertIdentifier(value.region, "neutral_dsh_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_dsh_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_dsh_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_dsh_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_dsh_binding_invalid"), adapterId: "dsh",
    version: 2, scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_dsh_binding_invalid"),
    ...optionalDshReleaseBinding(value),
  });
}

function optionalDshReleaseBinding(value) {
  return Object.freeze({
    releaseRoot: assertAbsolutePath(value?.releaseRoot, "neutral_dsh_launch_configuration_invalid"),
    releaseManifestSha256: assertSha256(value?.releaseManifestSha256, "neutral_dsh_launch_configuration_invalid"),
    runnerRelativePath: assertRunnerReference(value?.runnerRelativePath, "neutral_dsh_launch_configuration_invalid"),
    profileManifestPath: assertAbsolutePath(value?.profileManifestPath, "neutral_dsh_launch_configuration_invalid"),
  });
}

async function assertCurrentDshInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId || binding.region !== after.region
    || binding.principalId !== after.principalId || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_dsh_capability_binding_mismatch");
  }
  const delegateBinding = await resolveDshInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "dsh" || capability.version !== 2 || capability.state !== "active"
    || !sameStrings(capability.scopes, binding.scopes)) throw codeError("neutral_dsh_capability_binding_mismatch");
}

function openClawNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES);
  if (!(sameStrings(scopes, HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES)
      || (input?.allowLegacyScopes === true
        && sameStrings(scopes, HELLOLYNK_OPENCLAW_NEUTRAL_PREVIOUS_SCOPES)))
    || (input?.adapterId ?? "openclaw") !== "openclaw"
    || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_openclaw_capability_binding_mismatch");
  }
  return Object.freeze({
    contract: HELLOLYNK_OPENCLAW_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "openclaw",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_openclaw_binding_invalid"),
    releaseRoot: assertAbsolutePath(input?.releaseRoot, "neutral_openclaw_binding_invalid"),
    releaseManifestSha256: assertSha256(input?.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(input?.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      input?.profileManifestPath,
      "neutral_openclaw_binding_invalid",
    ),
  });
}

function publicOpenClawNeutralBinding(value) {
  const legacyKeys = [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "region", "runtimeRoot", "scopes", "version",
  ];
  const currentKeys = [
    ...legacyKeys,
    "profileManifestPath", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
  ];
  const actualKeys = Object.keys(value || {}).sort();
  const isLegacy = sameStrings(actualKeys, [...legacyKeys].sort());
  if (!isLegacy && !sameStrings(actualKeys, [...currentKeys].sort())) {
    throw codeError("neutral_openclaw_binding_invalid");
  }
  if (value.contract !== HELLOLYNK_OPENCLAW_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "openclaw" || Number(value.version) !== 2) {
    throw codeError("neutral_openclaw_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_OPENCLAW_NEUTRAL_PREVIOUS_SCOPES)) {
    throw codeError("neutral_openclaw_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_openclaw_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_openclaw_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_openclaw_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_openclaw_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_openclaw_binding_invalid"),
    adapterId: "openclaw",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_openclaw_binding_invalid"),
    ...(!isLegacy ? {
      releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_openclaw_binding_invalid"),
      releaseManifestSha256: assertSha256(value.releaseManifestSha256),
      runnerRelativePath: assertRunnerReference(value.runnerRelativePath),
      profileManifestPath: assertAbsolutePath(value.profileManifestPath, "neutral_openclaw_binding_invalid"),
    } : {}),
  });
}

async function assertCurrentOpenClawInstallationBinding(store, before, binding, capability, input) {
  const after = await resolveActiveInstallation(store, input);
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_openclaw_capability_binding_mismatch");
  }
  const delegateBinding = await resolveOpenClawInstallationBinding(store, binding, after);
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "openclaw" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_openclaw_capability_binding_mismatch");
  }
}

async function resolveCodexInstallationBinding(store, input, installation) {
  const profileId = assertIdentifier(input?.profileId, "neutral_codex_binding_invalid");
  const delegateId = input?.delegateId == null
    ? null
    : assertIdentifier(input.delegateId, "neutral_codex_binding_invalid");
  let binding;
  try {
    binding = await store.resolveBinding({ profileId, delegateId });
  } catch {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
  if (binding.region !== installation.region
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || !binding.adapters.includes("codex")) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
  return binding;
}

function codexNeutralBindingDescriptor(input, installation, delegateBinding) {
  const scopes = canonicalScopes(input?.scopes || HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES);
  if (!(sameStrings(scopes, HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES)
      || (input?.allowLegacyScopes === true
        && sameStrings(scopes, HELLOLYNK_CODEX_NEUTRAL_PREVIOUS_SCOPES)))) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
  if ((input?.adapterId ?? "codex") !== "codex" || Number(input?.version ?? 2) !== 2) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
  return Object.freeze({
    contract: HELLOLYNK_CODEX_NEUTRAL_BINDING_CONTRACT,
    region: installation.region,
    principalId: installation.principalId,
    delegateId: delegateBinding.delegateId,
    hostInstallationId: installation.hostInstallationId,
    profileId: delegateBinding.profileId,
    adapterId: "codex",
    version: 2,
    scopes,
    runtimeRoot: assertAbsolutePath(input?.runtimeRoot, "neutral_codex_binding_invalid"),
    releaseRoot: assertAbsolutePath(input?.releaseRoot, "neutral_codex_binding_invalid"),
    releaseManifestSha256: assertSha256(input?.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(input?.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      input?.profileManifestPath,
      "neutral_codex_launch_configuration_required",
    ),
  });
}

function publicCodexNeutralBinding(value) {
  assertExactKeysWithCode(value, [
    "adapterId", "contract", "delegateId", "hostInstallationId", "principalId",
    "profileId", "profileManifestPath", "region", "releaseManifestSha256", "releaseRoot", "runnerRelativePath",
    "runtimeRoot", "scopes", "version",
  ], "neutral_codex_binding_invalid");
  if (value.contract !== HELLOLYNK_CODEX_NEUTRAL_BINDING_CONTRACT
    || value.adapterId !== "codex" || Number(value.version) !== 2) {
    throw codeError("neutral_codex_binding_invalid");
  }
  const scopes = canonicalScopes(value.scopes);
  if (!sameStrings(scopes, HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES)
    && !sameStrings(scopes, HELLOLYNK_CODEX_NEUTRAL_PREVIOUS_SCOPES)) {
    throw codeError("neutral_codex_binding_invalid");
  }
  return Object.freeze({
    contract: value.contract,
    region: assertIdentifier(value.region, "neutral_codex_binding_invalid"),
    principalId: assertIdentifier(value.principalId, "neutral_codex_binding_invalid"),
    delegateId: assertIdentifier(value.delegateId, "neutral_codex_binding_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "neutral_codex_binding_invalid"),
    profileId: assertIdentifier(value.profileId, "neutral_codex_binding_invalid"),
    adapterId: "codex",
    version: 2,
    scopes: Object.freeze(scopes),
    runtimeRoot: assertAbsolutePath(value.runtimeRoot, "neutral_codex_binding_invalid"),
    releaseRoot: assertAbsolutePath(value.releaseRoot, "neutral_codex_binding_invalid"),
    releaseManifestSha256: assertSha256(value.releaseManifestSha256),
    runnerRelativePath: assertRunnerReference(value.runnerRelativePath),
    profileManifestPath: assertAbsolutePath(
      value.profileManifestPath,
      "neutral_codex_binding_invalid",
    ),
  });
}

async function assertCurrentCodexInstallationBinding(store, before, binding, capability) {
  const after = await resolveActiveInstallation(store, {});
  if (before.region !== after.region || before.principalId !== after.principalId
    || before.hostInstallationId !== after.hostInstallationId
    || binding.region !== after.region || binding.principalId !== after.principalId
    || binding.hostInstallationId !== after.hostInstallationId) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
  // Use the delegate in the complete post-DPAPI registry snapshot. Reading
  // the registry a third time repeats path checks and can mix two
  // different snapshots; the post-read still rejects removed/rebound delegates.
  const matches = after.delegateBindings.filter((item) => item.profileId === binding.profileId
    && item.delegateId === binding.delegateId && item.adapters.includes("codex"));
  if (matches.length !== 1) throw codeError("neutral_codex_capability_binding_mismatch");
  const delegateBinding = matches[0];
  if (delegateBinding.profileId !== binding.profileId || delegateBinding.delegateId !== binding.delegateId
    || capability.region !== binding.region || capability.principalId !== binding.principalId
    || capability.delegateId !== binding.delegateId
    || capability.hostInstallationId !== binding.hostInstallationId
    || capability.adapterId !== "codex" || capability.version !== 2
    || capability.state !== "active" || !sameStrings(capability.scopes, binding.scopes)) {
    throw codeError("neutral_codex_capability_binding_mismatch");
  }
}

function assertAbsolutePath(value, code) {
  const text = String(value || "");
  if (!text || !isAbsolute(text) || resolve(text) !== text) throw codeError(code);
  return text;
}

function assertPersistentNeutralBinding(binding, storeRoot) {
  const pathFields = ["runtimeRoot", "releaseRoot", "profileManifestPath"];
  for (const field of pathFields) {
    if (!Object.hasOwn(binding, field)) continue;
    const normalized = resolve(String(binding[field] || "")).replaceAll("\\", "/").toLowerCase();
    if (normalized.includes("/.codex/worktrees/")
      || normalized.endsWith("/.codex/worktrees")
      || /(?:^|\/)[^/]*hellolynk[^/]*stage[^/]*(?:\/|$)/u.test(normalized)) {
      throw codeError("neutral_host_persistent_binding_path_invalid");
    }
  }
  if (basename(storeRoot).toLowerCase() !== "host") return binding;
  if (pathFields.some((field) => !Object.hasOwn(binding, field))) {
    throw codeError("neutral_host_persistent_binding_path_invalid");
  }
  const finalRoot = dirname(clientAccountBaseRoot(storeRoot));
  const releasesRoot = join(finalRoot, "releases");
  const releaseRelative = relative(releasesRoot, resolve(binding.releaseRoot));
  if (resolve(binding.runtimeRoot) !== join(storeRoot, "runtime")
    || resolve(binding.profileManifestPath) !== join(storeRoot, "profile-manifest-v1.json")
    || releaseRelative === "" || releaseRelative.startsWith("..") || isAbsolute(releaseRelative)) {
    throw codeError("neutral_host_persistent_binding_path_invalid");
  }
  return binding;
}

function assertRunnerReference(value, code = "neutral_codex_runner_integrity_invalid") {
  const text = String(value || "");
  if (!/^(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)*[A-Za-z0-9][A-Za-z0-9._-]*\.mjs$/.test(
    text.replaceAll("\\", "/"),
  )) throw codeError(code);
  if (text.includes("\\") || text.split("/").includes("..")) {
    throw codeError(code);
  }
  return text;
}

function assertSha256(value, code = "neutral_codex_runner_integrity_invalid") {
  const text = String(value || "");
  if (!/^[a-f0-9]{64}$/.test(text)) throw codeError(code);
  return text;
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function createRecord(input, dependencies) {
  const scopes = canonicalScopes(input.scopes);
  const secretBuffer = Buffer.from(dependencies.random(32));
  if (secretBuffer.length !== 32) throw codeError("host_capability_random_invalid");
  const capabilityId = createCapabilityId(dependencies.random);
  return assertCapabilityRecord({
    contract: HELLOLYNK_HOST_CAPABILITY_CONTRACT,
    capabilityId,
    region: assertIdentifier(input.region, "host_capability_region_invalid"),
    principalId: assertIdentifier(input.principalId, "host_principal_id_invalid"),
    delegateId: assertIdentifier(input.delegateId, "host_delegate_id_invalid"),
    hostInstallationId: assertIdentifier(input.hostInstallationId, "host_installation_id_invalid"),
    adapterId: assertIdentifier(input.adapterId, "host_adapter_id_invalid"),
    version: assertPositiveInteger(input.version ?? 1, "host_capability_version_invalid"),
    state: "active",
    scopes,
    issuedAt: assertTimestamp(dependencies.clock()),
    revokedAt: null,
    secretBuffer,
  });
}

function createCapabilityId(random) {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const bytes = Buffer.from(random(24));
    if (bytes.length !== 24) throw codeError("host_capability_random_invalid");
    const candidate = `cap_${bytes.toString("base64url")}`;
    if (CAPABILITY_ID_PATTERN.test(candidate) && /[A-Za-z0-9]$/.test(candidate)) return candidate;
  }
  throw codeError("host_capability_random_invalid");
}

function serializeRecord(record) {
  return JSON.stringify({
    contract: record.contract,
    capabilityId: record.capabilityId,
    region: record.region,
    principalId: record.principalId,
    delegateId: record.delegateId,
    hostInstallationId: record.hostInstallationId,
    adapterId: record.adapterId,
    version: record.version,
    state: record.state,
    scopes: [...record.scopes],
    issuedAt: record.issuedAt,
    revokedAt: null,
    secret: record.secretBuffer.toString("base64url"),
  });
}

function deserializeRecord(value) {
  assertExactKeys(value, [
    "adapterId", "capabilityId", "contract", "delegateId", "hostInstallationId",
    "issuedAt", "principalId", "region", "revokedAt", "scopes", "secret", "state", "version",
  ]);
  if (typeof value.secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.secret)) {
    throw codeError("host_capability_secret_invalid");
  }
  const { secret, ...publicFields } = value;
  return assertCapabilityRecord({
    ...publicFields,
    secretBuffer: Buffer.from(value.secret, "base64url"),
  });
}

function publicRecord(value) {
  assertExactKeys(value, [
    "adapterId", "capabilityId", "contract", "delegateId", "hostInstallationId",
    "issuedAt", "principalId", "region", "revokedAt", "scopes", "state", "version",
  ]);
  if (value.contract !== HELLOLYNK_HOST_CAPABILITY_CONTRACT) throw codeError("host_capability_contract_invalid");
  const state = value.state;
  if (!['active', 'revoked'].includes(state)) throw codeError("host_capability_state_invalid");
  const issuedAt = assertTimestamp(value.issuedAt);
  const revokedAt = state === "active" && value.revokedAt === null
    ? null : assertTimestamp(value.revokedAt);
  if (state === "revoked" && revokedAt < issuedAt) throw codeError("host_capability_state_invalid");
  return Object.freeze({
    contract: value.contract,
    capabilityId: assertCapabilityId(value.capabilityId),
    region: assertIdentifier(value.region, "host_capability_region_invalid"),
    principalId: assertIdentifier(value.principalId, "host_principal_id_invalid"),
    delegateId: assertIdentifier(value.delegateId, "host_delegate_id_invalid"),
    hostInstallationId: assertIdentifier(value.hostInstallationId, "host_installation_id_invalid"),
    adapterId: assertIdentifier(value.adapterId, "host_adapter_id_invalid"),
    version: assertPositiveInteger(value.version, "host_capability_version_invalid"),
    state,
    scopes: Object.freeze(canonicalScopes(value.scopes)),
    issuedAt,
    revokedAt,
  });
}

async function resolveActiveInstallation(store, input) {
  const status = await store.status();
  const active = status.installations.filter((item) => item.state === "active");
  if (active.length !== 1) {
    throw codeError(active.length ? "host_installation_ambiguous" : "host_installation_missing");
  }
  const installation = active[0];
  const requestedPrincipalId = input?.principalId == null
    ? installation.principalId
    : assertIdentifier(input.principalId, "host_principal_id_invalid");
  const requestedHostId = input?.hostInstallationId ?? input?.hostId ?? installation.hostInstallationId;
  if (requestedPrincipalId !== installation.principalId
    || assertIdentifier(requestedHostId, "host_installation_id_invalid") !== installation.hostInstallationId) {
    throw codeError("host_transport_installation_owner_mismatch");
  }
  return installation;
}

function transportCredentialRecord(input, installation) {
  const credentialId = assertIdentifier(input?.credentialId, "host_transport_credential_id_invalid");
  const secret = String(input?.secret ?? input?.credential ?? "");
  const match = TRANSPORT_CREDENTIAL_PATTERN.exec(secret);
  if (!match || match[1] !== credentialId) throw codeError("host_transport_credential_secret_invalid");
  const principalId = assertIdentifier(input?.principalId, "host_principal_id_invalid");
  const hostInstallationId = assertIdentifier(
    input?.hostInstallationId ?? input?.hostId,
    "host_installation_id_invalid",
  );
  if (principalId !== installation.principalId
    || hostInstallationId !== installation.hostInstallationId) {
    throw codeError("host_transport_credential_owner_mismatch");
  }
  const issuedAt = normalizeTransportTimestamp(input?.issuedAt ?? input?.createdAt);
  const expiresAt = normalizeTransportTimestamp(input?.expiresAt);
  if (expiresAt <= issuedAt) throw codeError("host_transport_credential_expiry_invalid");
  if ((input?.state ?? "active") !== "active" || (input?.revokedAt ?? null) !== null) {
    throw codeError("host_transport_credential_state_invalid");
  }
  return Object.freeze({
    contract: HELLOLYNK_HOST_TRANSPORT_CREDENTIAL_CONTRACT,
    credentialId,
    principalId,
    hostInstallationId,
    state: "active",
    secret,
    issuedAt,
    expiresAt,
    revokedAt: null,
  });
}

function deserializeTransportCredential(value, installation, now, options = {}) {
  assertExactKeys(value, [
    "contract", "credentialId", "expiresAt", "hostInstallationId", "issuedAt",
    "principalId", "revokedAt", "secret", "state",
  ]);
  if (value.contract !== HELLOLYNK_HOST_TRANSPORT_CREDENTIAL_CONTRACT) {
    throw codeError("host_transport_credential_contract_invalid");
  }
  const credentialId = assertIdentifier(value.credentialId, "host_transport_credential_id_invalid");
  const secret = String(value.secret || "");
  const match = TRANSPORT_CREDENTIAL_PATTERN.exec(secret);
  if (!match || match[1] !== credentialId) throw codeError("host_transport_credential_secret_invalid");
  const principalId = assertIdentifier(value.principalId, "host_principal_id_invalid");
  const hostInstallationId = assertIdentifier(value.hostInstallationId, "host_installation_id_invalid");
  if (principalId !== installation.principalId
    || hostInstallationId !== installation.hostInstallationId) {
    throw codeError("host_transport_credential_owner_mismatch");
  }
  const issuedAt = assertTimestamp(value.issuedAt);
  const expiresAt = assertTimestamp(value.expiresAt);
  if (expiresAt <= issuedAt) throw codeError("host_transport_credential_expiry_invalid");
  const state = value.state;
  const revokedAt = value.revokedAt === null ? null : assertTimestamp(value.revokedAt);
  if (!['active', 'revoked'].includes(state)
    || (state === "active" && revokedAt !== null)
    || (state === "revoked" && (revokedAt === null || revokedAt < issuedAt))) {
    throw codeError("host_transport_credential_state_invalid");
  }
  if (state !== "active") throw codeError("host_transport_credential_inactive");
  if (!options.allowExpired && expiresAt <= assertTimestamp(now)) {
    throw codeError("host_transport_credential_expired");
  }
  return Object.freeze({
    contract: value.contract,
    credentialId,
    principalId,
    hostInstallationId,
    state,
    secret,
    issuedAt,
    expiresAt,
    revokedAt,
  });
}

function transportSessionRecord(input, installation) {
  const sessionId = assertTransportSessionId(input?.sessionId);
  const sessionSecret = String(input?.sessionSecret || "");
  if (!TRANSPORT_SESSION_SECRET_PATTERN.test(sessionSecret)) {
    throw codeError("host_transport_session_secret_invalid");
  }
  const credentialId = assertIdentifier(input?.credentialId, "host_transport_credential_id_invalid");
  const principalId = assertIdentifier(input?.principalId, "host_principal_id_invalid");
  const hostInstallationId = assertIdentifier(
    input?.hostInstallationId ?? input?.hostId,
    "host_installation_id_invalid",
  );
  if (principalId !== installation.principalId
    || hostInstallationId !== installation.hostInstallationId) {
    throw codeError("host_transport_session_owner_mismatch");
  }
  const issuedAt = normalizeTransportTimestamp(input?.issuedAt);
  const expiresAt = normalizeTransportTimestamp(input?.expiresAt);
  if (expiresAt <= issuedAt) throw codeError("host_transport_session_expiry_invalid");
  return Object.freeze({
    contract: HELLOLYNK_HOST_TRANSPORT_SESSION_CONTRACT,
    sessionId,
    sessionSecret,
    credentialId,
    principalId,
    hostInstallationId,
    issuedAt,
    expiresAt,
  });
}

function deserializeTransportSession(value, installation, credentialId, now) {
  assertExactKeys(value, [
    "contract", "credentialId", "expiresAt", "hostInstallationId", "issuedAt",
    "principalId", "sessionId", "sessionSecret",
  ]);
  if (value.contract !== HELLOLYNK_HOST_TRANSPORT_SESSION_CONTRACT) {
    throw codeError("host_transport_session_contract_invalid");
  }
  const record = transportSessionRecord(value, installation);
  if (credentialId && record.credentialId !== credentialId) {
    throw codeError("host_transport_session_credential_mismatch");
  }
  if (record.expiresAt <= assertTimestamp(now)) throw codeError("host_transport_session_expired");
  return record;
}

function clientTransportSession(value) {
  return Object.freeze({
    sessionId: value.sessionId,
    sessionSecret: value.sessionSecret,
    principalId: value.principalId,
    hostId: value.hostInstallationId,
    expiresAt: new Date(value.expiresAt).toISOString(),
  });
}

function normalizeTransportTimestamp(value) {
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed)) throw codeError("host_timestamp_invalid");
    return assertTimestamp(parsed);
  }
  return assertTimestamp(value);
}

function assertTransportSessionId(value) {
  const sessionId = String(value || "");
  if (!TRANSPORT_SESSION_ID_PATTERN.test(sessionId)) {
    throw codeError("host_transport_session_id_invalid");
  }
  return sessionId;
}

function validateDeviceEnrollmentResult(value) {
  assertExactKeys(value, ["contract", "revision", "value"]);
  if (value.contract !== "hellolynk-device-enrollment-v1"
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || (value.value !== null && (typeof value.value !== "object" || Array.isArray(value.value)))) {
    throw codeError("device_enrollment_store_invalid");
  }
  return value;
}

async function invokeWindowsStore(input) {
  input.signal?.throwIfAborted();
  const helperMetadata = await lstat(input.helperPath);
  if (!helperMetadata.isFile() || helperMetadata.isSymbolicLink()) throw codeError("host_protected_helper_invalid");
  if (!input.verifyOnly) await mkdir(input.root, { recursive: true, mode: 0o700 });
  const rootMetadata = await lstat(input.root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) throw codeError("host_protected_store_root_invalid");

  const pipeName = `HelloLynkHostProtected-${process.pid}-${randomBytes(18).toString("base64url")}`;
  const pipePath = `\\\\.\\pipe\\${pipeName}`;
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", input.helperPath,
    "-Command", input.command,
    "-StoreRoot", input.root,
    "-ResultPipeName", pipeName,
  ];
  if (input.capabilityId) args.push("-CapabilityId", assertCapabilityId(input.capabilityId));
  if (input.credentialId) args.push(
    "-CredentialId",
    assertIdentifier(input.credentialId, "host_transport_credential_id_invalid"),
  );
  if (input.sessionId) args.push("-SessionId", assertTransportSessionId(input.sessionId));
  if (input.principalId) args.push(
    "-PrincipalId",
    assertIdentifier(input.principalId, "host_principal_id_invalid"),
  );
  if (input.hostInstallationId) args.push(
    "-HostInstallationId",
    assertIdentifier(input.hostInstallationId, "host_installation_id_invalid"),
  );
  if (input.timestamp != null) args.push("-Timestamp", String(assertTimestamp(input.timestamp)));
  if (input.pathToVerify) args.push("-PathToVerify", resolve(input.pathToVerify));
  if (input.verifyDirectory) args.push("-VerifyDirectory");
  if (input.verifyOnly) args.push("-VerifyOnly");
  input.signal?.throwIfAborted();
  const child = spawn("pwsh.exe", args, {
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: sanitizeHelloLynkChildEnvironment(process.env),
  });
  const controller = new AbortController();
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const exitPromise = new Promise((resolveExit, rejectExit) => {
    child.on("error", rejectExit);
    child.on("close", resolveExit);
    // An early helper failure can close stdin while the parent is still writing.
    for (const stream of [child.stdin, child.stdout, child.stderr]) stream.on("error", rejectExit);
    if (input.stdin) child.stdin.end(input.stdin, "utf8");
    else child.stdin.end();
  });
  let timeout;
  let abort;
  try {
    // One budget covers helper exit AND the entire pipe read, including a
    // connected peer that never ends. Retain the existing 30s allowance for
    // PowerShell startup, the full 10s SID mutex wait and local protected I/O.
    const timeoutPromise = new Promise((_, rejectTimeout) => {
      timeout = setTimeout(() => rejectTimeout(codeError("host_protected_helper_timeout")), 30_000);
      timeout.unref?.();
    });
    const resultPromise = readCurrentUserPipe(pipePath, controller.signal);
    const completed = Promise.all([
      exitPromise.then((exitCode) => {
        if (Buffer.concat(stdout).length) throw codeError("host_protected_helper_stdout_forbidden");
        if (exitCode !== 0) throw codeError(publicErrorCode(Buffer.concat(stderr).toString("utf8").trim()));
      }),
      resultPromise,
    ]);
    const cancelled = new Promise((_, reject) => {
      abort = () => reject(codeError("host_protected_result_cancelled"));
      if (input.signal?.aborted) abort();
      else input.signal?.addEventListener("abort", abort, { once: true });
    });
    const outcome = Promise.race([completed, timeoutPromise, cancelled]);
    const [, raw] = await outcome;
    try { return JSON.parse(raw); } catch { throw codeError("host_protected_result_invalid"); }
  } catch (error) {
    // A timed-out write may already have committed. Never retry it here.
    if (child.exitCode == null && child.signalCode == null) child.kill();
    throw error;
  } finally {
    clearTimeout(timeout);
    input.signal?.removeEventListener("abort", abort);
    controller.abort();
    for (const stream of [child.stdin, child.stdout, child.stderr]) stream.destroy();
  }
}

async function readCurrentUserPipe(pipePath, signal) {
  while (true) {
    if (signal.aborted) throw codeError("host_protected_result_cancelled");
    try {
      return await new Promise((resolvePipe, rejectPipe) => {
        const chunks = [];
        let bytes = 0;
        let settled = false;
        const socket = createConnection(pipePath);
        const finish = (error, result) => {
          if (settled) return;
          settled = true;
          signal.removeEventListener("abort", abort);
          socket.destroy();
          if (error) rejectPipe(error);
          else resolvePipe(result);
        };
        const abort = () => finish(codeError("host_protected_result_cancelled"));
        signal.addEventListener("abort", abort, { once: true });
        socket.on("data", (chunk) => {
          if (settled) return;
          bytes += chunk.length;
          if (bytes > 2 * 1024 * 1024) {
            finish(codeError("host_protected_result_too_large"));
            return;
          }
          chunks.push(chunk);
        });
        socket.on("error", (error) => finish(error));
        socket.on("end", () => finish(null, Buffer.concat(chunks).toString("utf8")));
        socket.on("close", () => finish(codeError("host_protected_result_incomplete")));
      });
    } catch (error) {
      if (signal.aborted) throw codeError("host_protected_result_cancelled");
      if (error?.code !== "ENOENT") throw error;
      await new Promise((resolveWait) => {
        const finish = () => {
          clearTimeout(retry);
          signal.removeEventListener("abort", finish);
          resolveWait();
        };
        const retry = setTimeout(finish, 10);
        signal.addEventListener("abort", finish, { once: true });
      });
    }
  }
}

function canonicalScopes(value) {
  if (!Array.isArray(value) || !value.length || value.length > 64) throw codeError("host_capability_scopes_invalid");
  const scopes = value.map((scope) => assertIdentifier(scope, "host_capability_scope_invalid"));
  const canonical = [...new Set(scopes)].sort();
  if (canonical.length !== scopes.length || canonical.some((scope, index) => scope !== scopes[index])) {
    throw codeError("host_capability_scopes_noncanonical");
  }
  return canonical;
}

function assertCapabilityId(value) {
  const id = String(value || "");
  if (!CAPABILITY_ID_PATTERN.test(id)) throw codeError("host_capability_id_invalid");
  return id;
}

function assertRoot(value) {
  const input = String(value || "");
  if (process.platform === "win32" && (!/^[A-Za-z]:[\\/]/.test(input) || input.startsWith("\\\\?\\")
    || input.startsWith("\\\\") || input.includes("\0"))) {
    throw codeError("host_protected_store_root_invalid");
  }
  const root = resolve(input);
  if (!isAbsolute(root) || root.length < 4) throw codeError("host_protected_store_root_invalid");
  return root;
}

function assertExactKeys(value, expected) {
  return assertExactKeysWithCode(value, expected, "host_capability_fields_invalid");
}

function assertExactKeysWithCode(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw codeError(code);
  }
}

function assertTimestamp(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw codeError("host_timestamp_invalid");
  return number;
}

function assertPositiveInteger(value, code) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw codeError(code);
  return number;
}

function assertNonNegativeInteger(value, code) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw codeError(code);
  return number;
}

function publicErrorCode(value) {
  const matches = String(value || "").match(/[a-z][a-z0-9_]{2,127}/g);
  return matches?.at(-1) || "host_protected_store_operation_failed";
}

function normalizeClock(value) {
  if (value == null) return () => Date.now();
  if (typeof value === "function") return value;
  if (typeof value?.now === "function") return () => value.now();
  throw codeError("host_clock_invalid");
}

function fail(code) { throw codeError(code); }
function codeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
