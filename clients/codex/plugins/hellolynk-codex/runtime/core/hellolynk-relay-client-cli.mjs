#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { redeemAgentBindingKey, runSanitizedDoctor } from "./hellolynk-client-core.mjs";
import { createPlatformCredentialStore } from "./hellolynk-platform-credential-store.mjs";
import {
  defaultHelloLynkClientRoot,
  readClientProfile,
  writeClientProfile,
} from "./hellolynk-client-profile.mjs";
import {
  createNeutralHostInstallationStore,
  writeNeutralHostProfileManifest,
} from "./hellolynk-neutral-host-installation-store.mjs";
import { createHostProtectedStore } from "./hellolynk-host-protected-store.mjs";
import { createDeviceEnrollmentClient } from "./hellolynk-device-enrollment.mjs";

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 1) {
    const part = rest[index];
    if ([
      "--allow-loopback-http", "--binding-key-from-stdin", "--bootstrap-host-transport",
    ].includes(part)) {
      options[part.slice(2)] = true;
      continue;
    }
    if (!part.startsWith("--") || index + 1 >= rest.length) throw new Error("client_arguments_invalid");
    options[part.slice(2)] = rest[index + 1];
    index += 1;
  }
  return { command, options };
}

function required(options, key) {
  const value = String(options[key] || "").trim();
  if (!value) throw new Error(`client_argument_${key}_required`);
  return value;
}

async function readBindingKeyFromStdin() {
  const chunks = [];
  let bytes = 0;
  for await (const input of process.stdin) {
    const chunk = Buffer.from(input);
    bytes += chunk.length;
    if (bytes > 4 * 1024) throw new Error("binding_key_input_too_large");
    chunks.push(chunk);
    const value = Buffer.concat(chunks);
    const lineEnd = value.indexOf(0x0a);
    if (lineEnd >= 0) {
      const line = value.subarray(0, lineEnd).toString("utf8").replace(/\r$/, "");
      if (!line) throw new Error("binding_key_stdin_required");
      return line;
    }
  }
  const value = Buffer.concat(chunks).toString("utf8").replace(/\r$/, "");
  if (!value) throw new Error("binding_key_stdin_required");
  return value;
}

function publicErrorCode(error) {
  const code = String(error?.code || error?.message || "client_operation_failed");
  return /^[a-z][a-z0-9_]{0,127}$/.test(code) ? code : "client_operation_failed";
}

async function bind(options, dependencies = {}) {
  if (options["binding-key-from-stdin"] !== true) throw new Error("binding_key_stdin_flag_required");
  const root = options.root || defaultHelloLynkClientRoot();
  const profileId = required(options, "profile");
  const configPath = options.config || join(root, "profiles", `${profileId}.json`);
  const bindingKey = await (dependencies.readSecret || readBindingKeyFromStdin)();
  const store = dependencies.store || createPlatformCredentialStore({ storeRoot: join(root, "credentials") });
  const redeemed = await redeemAgentBindingKey({
    baseUrl: required(options, "base-url"),
    bindingKey,
    deviceId: required(options, "device-id"),
    hostInstallationId: required(options, "host-installation-id"),
    bootstrapHostTransport: options["bootstrap-host-transport"] === true,
    allowLoopbackHttp: options["allow-loopback-http"] === true,
    fetchImpl: dependencies.fetchImpl,
  });
  await store.save(profileId, redeemed.credential);
  try {
    const profile = await writeClientProfile(configPath, {
      contract: "hellolynk-client-profile-v1",
      schemaVersion: redeemed.hostId && redeemed.authorizationVersion ? 2 : 1,
      profileId,
      baseUrl: options["base-url"],
      allowLoopbackHttp: options["allow-loopback-http"] === true,
      deviceId: redeemed.deviceId,
      credentialId: redeemed.credentialId,
      principalId: redeemed.principalId,
      hellolynkId: redeemed.hellolynkId,
      agentId: redeemed.agentId,
      delegateId: redeemed.delegateId,
      ...(redeemed.hostId && redeemed.authorizationVersion ? {
        hostId: redeemed.hostId,
        authorizationVersion: redeemed.authorizationVersion,
      } : {}),
      region: redeemed.region,
      allowedScopes: redeemed.allowedScopes,
      platform: process.platform,
    });
    const neutralHostRoot = options["neutral-host-root"] == null
      ? null : resolve(required(options, "neutral-host-root"));
    let neutralHostActivated = false;
    let bootstrapTransportStored = false;
    if (neutralHostRoot) {
      if (options.adapter == null) throw new Error("client_argument_adapter_required");
      const installationStore = dependencies.installationStore
        || createNeutralHostInstallationStore({ root: neutralHostRoot });
      const installation = await installationStore.adoptProfileFile({
        profileFile: configPath,
        adapterId: required(options, "adapter"),
      });
      await writeActivationProfileManifest({
        clientRoot: root,
        configPath,
        neutralHostRoot,
        installation,
      });
      if (redeemed.bootstrapHostTransportCredential) {
        const protectedStore = dependencies.protectedStore || createHostProtectedStore({
          root: neutralHostRoot,
          installationStore,
        });
        await protectedStore.saveTransportCredential({
          credentialId: redeemed.bootstrapHostTransportCredential.credentialId,
          principalId: redeemed.principalId,
          hostInstallationId: redeemed.hostId,
          state: "active",
          credential: redeemed.bootstrapHostTransportCredential.credential,
          createdAt: redeemed.bootstrapHostTransportCredential.createdAt,
          expiresAt: redeemed.bootstrapHostTransportCredential.expiresAt,
          revokedAt: null,
        });
        bootstrapTransportStored = true;
      }
      neutralHostActivated = true;
    }
    return {
      ok: true,
      profileId: profile.profileId,
      credentialStored: true,
      configPath,
      neutralHostActivated,
      bootstrapTransportStored,
    };
  } catch (error) {
    await store.remove(profileId).catch(() => {});
    throw error;
  }
}

async function writeActivationProfileManifest(input) {
  const manifestPath = join(input.neutralHostRoot, "profile-manifest-v1.json");
  const knownPaths = new Map([[basename(input.configPath, ".json"), input.configPath]]);
  try {
    const existing = JSON.parse(await readFile(manifestPath, "utf8"));
    if (existing?.contract === "hellolynk-neutral-host-profile-manifest-v1" && Array.isArray(existing.profiles)) {
      for (const candidate of existing.profiles) {
        const absolute = resolve(String(candidate || ""));
        knownPaths.set(basename(absolute, ".json"), absolute);
      }
    }
  } catch {}
  const profileIds = input.installation.delegateBindings.map((item) => item.profileId);
  const orderedIds = [
    input.installation.canonicalProfileId,
    ...profileIds.filter((profileId) => profileId !== input.installation.canonicalProfileId).sort(),
  ];
  const profiles = orderedIds.map((profileId) => (
    knownPaths.get(profileId) || join(input.clientRoot, "profiles", `${profileId}.json`)
  ));
  await writeNeutralHostProfileManifest({ root: input.neutralHostRoot, profiles });
}

async function doctor(options, dependencies = {}) {
  const root = options.root || defaultHelloLynkClientRoot();
  const profileId = required(options, "profile");
  const configPath = options.config || join(root, "profiles", `${profileId}.json`);
  const profile = await readClientProfile(configPath);
  if (profile.profileId !== profileId) throw new Error("client_profile_binding_mismatch");
  const store = dependencies.store || createPlatformCredentialStore({ storeRoot: join(root, "credentials") });
  let credentialPresent = false;
  try {
    let credential = await store.load(profileId);
    credentialPresent = Boolean(credential);
    credential = null;
  } catch {
    credentialPresent = false;
  }
  return runSanitizedDoctor({
    baseUrl: profile.baseUrl,
    allowLoopbackHttp: profile.allowLoopbackHttp,
    credentialPresent,
    platform: profile.platform,
    fetchImpl: dependencies.fetchImpl,
  });
}

export async function runRelayClientCli(argv = process.argv.slice(2), dependencies = {}) {
  const { command, options } = parseArgs(argv);
  if (command === "connect") {
    const allowed = new Set(["base-url", "root", "neutral-host-root", "allow-loopback-http", "hellolynk-id", "adapter", "profile", "instance-name", "device-label"]);
    if (Object.keys(options).some((key) => !allowed.has(key))) throw new Error("device_enrollment_argument_unknown");
    return createDeviceEnrollmentClient({
      baseUrl: required(options, "base-url"), root: options.root, hostRoot: options["neutral-host-root"],
      allowLoopbackHttp: options["allow-loopback-http"] === true,
    }, dependencies).connect({
      hellolynkId: required(options, "hellolynk-id"), clientType: required(options, "adapter"),
      profileId: options.profile, requestedName: options["instance-name"], deviceLabel: options["device-label"],
    });
  }
  if (command === "bind") return bind(options, dependencies);
  if (command === "doctor") return doctor(options, dependencies);
  throw new Error("client_command_invalid");
}

const directRun = process.argv[1] && basename(process.argv[1]) === basename(fileURLToPath(import.meta.url));
if (directRun) {
  runRelayClientCli().then(
    (result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`),
    (error) => {
      process.stderr.write(`${JSON.stringify({ ok: false, error: publicErrorCode(error) })}\n`);
      process.exitCode = 1;
    },
  );
}
