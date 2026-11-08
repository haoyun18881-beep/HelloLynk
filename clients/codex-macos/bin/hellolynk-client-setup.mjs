#!/usr/bin/env node

import crypto from "node:crypto";
import { constants, lstatSync, realpathSync, writeSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { isHelloLynkMcpServerShape, traeConfigPaths } from "./hellolynk-mcp-config-shape.mjs";

const PACKAGE_ROOT = path.resolve(import.meta.dirname, "..");
const MAX_JSON_BYTES = 1024 * 1024;
const PACK_MANIFEST = "hellolynk-client-pack-manifest.json";
const PACK_PIN = "hellolynk-client-pack-pin.json";

// A person at a terminal reads sentences in the system language; the updater, tests and other
// programs read one JSON line.
const jsonOutput = process.argv.includes("--json") || process.stdout.isTTY !== true;
const CHINESE = /^zh\b/i.test(Intl.DateTimeFormat().resolvedOptions().locale);
const CLIENT_NAMES = Object.freeze({ codex: "Codex", openclaw: "OpenClaw", "trae-work": "TRAE Work",
  workbuddy: "WorkBuddy", cursor: "Cursor", dsh: "DSH" });
const { packageJson, metadata } = await readPackage();
const macPackage = metadata.client === "codex" && packageJson.os?.[0] === "darwin"
  && packageJson.cpu?.[0] === "arm64";
const commandArguments = process.argv.slice(2).filter((value) => value !== "--json");
const command = String(commandArguments.shift() || "help").toLowerCase();
const waitForPending = command === "--wait-for-pending";
const setupArguments = [...commandArguments];
const migrateCursorPermissions = command === "setup" && metadata.client === "cursor"
  && setupArguments[0] === "--migrate-existing-plugin-permissions";
if (migrateCursorPermissions) setupArguments.shift();
const deferReleaseCleanup = command === "setup" && setupArguments.length === 1 && setupArguments[0] === "--defer-release-cleanup";
let setupRecovery = null;
let resolvedCodexRunner = null;
let mutationRecoveryState = "none";
let candidateClosure = null;

try {
  requireNode();
  setupRecovery = command === "setup" ? parseSetupRecoveryOptions(deferReleaseCleanup ? [] : setupArguments) : null;
  const existingDoctor = command === "doctor" ? parseExistingDoctorOptions(commandArguments) : null;
  if (isNativeClient() && !["connect", "setup", "doctor", "help", "--help"].includes(command)) {
    fail("hellolynk_native_command_invalid");
  }
  if (!isNativeClient() && setupRecovery !== null) fail("hellolynk_npm_setup_arguments_invalid");
  if (waitForPending && metadata.client !== "workbuddy") fail("hellolynk_npm_command_invalid");
  if (command !== "connect" && command !== "setup" && command !== "doctor" && commandArguments.length > 0) {
    fail(isNativeClient() ? "hellolynk_native_command_invalid" : "hellolynk_npm_command_invalid");
  }
  // Validate the public command before preparing even the local install root.
  const connectOptions = command === "connect" ? parseConnectOptions(commandArguments) : null;
  const packageClosure = await verifyPackageClosure(PACKAGE_ROOT);
  candidateClosure = packageClosure;
  const sourceReleaseRoot = path.resolve(PACKAGE_ROOT, metadata.releaseRoot);
  const sourceRelease = await verifyRelease(sourceReleaseRoot, PACKAGE_ROOT);
  if (command === "help" || command === "--help") {
    process.stdout.write(helpText());
  } else if (waitForPending) {
    const bootstrap = await importLocal(PACKAGE_ROOT, metadata.entry, "hellolynk_npm_entry_invalid");
    await bootstrap.runWorkBuddyPackageBootstrap([
      "--wait-for-pending", "--root", sourceReleaseRoot,
      "--expected-manifest-sha256", sourceRelease.outerManifestSha256,
    ]);
  } else {
  const accountModule = await importStableCore(PACKAGE_ROOT, "hellolynk-client-account.mjs", "hellolynk_npm_account_runtime_invalid");
  const originalLocations = resolveLocations(accountModule.clientAccountBaseRoot);
  if (macPackage && command !== "uninstall") {
    const config = await readJson(path.join(sourceReleaseRoot, ".mcp.json"), "hellolynk_npm_release_invalid", true);
    const commandPath = config.mcpServers?.["hellolynk-codex"]?.command;
    if (typeof commandPath !== "string" || !path.isAbsolute(commandPath)) fail("hellolynk_npm_release_invalid");
    await fs.access(commandPath, constants.X_OK).catch(() => fail("hellolynk_npm_codex_mac_node_required"));
  }
  const baseRoot = accountModule.clientAccountBaseRoot(originalLocations.hostRoot);
  const packageLocations = { ...originalLocations, hostRoot: baseRoot, finalCurrentRoot: path.dirname(baseRoot) };
  const accounts = accountModule.createClientAccountActions({ client: metadata.client, storeRoot: baseRoot });
  if (command === "activate" && !commandArguments.includes("--binding-key-from-stdin")) {
    fail("hellolynk_npm_binding_key_stdin_flag_required");
  }
  const mutating = ["init", "connect", "activate", "setup"].includes(command);
  if (mutating) await prepareFinalClientRoot(packageLocations);
  const revision = connectOptions?.accountRevision
    || setupRecovery?.expectedAccountRevision
    || accounts.readAccountState().revision;
  // Uninstall changes client settings under the account lock too, but never creates the root.
  const run = mutating || (command === "uninstall" && await exists(baseRoot))
    ? (operation) => accounts.runForAccount(revision, operation)
    : (operation) => operation(accounts.assertRevision(revision));
  await run(async (hostRoot) => {
  const locations = { ...packageLocations, hostRoot, finalCurrentRoot: path.dirname(hostRoot), releaseCurrentRoot: packageLocations.finalCurrentRoot };
  let installed = null;
  if (mutating) {
    await prepareFinalClientRoot(locations);
    installed = await installStablePackage({ packageClosure, sourceRelease, locations: packageLocations });
    if (metadata.client === "codex") {
      // The invoking updater can still be B255 code. Stop its old cleanup
      // before switching the binding/cache to a release with process records.
      const cleanup = await importStableCore(installed.packageRoot, "hellolynk-release-retention.mjs", "hellolynk_release_retention_unavailable");
      await cleanup.protectRetentionReceipt({ releasesRoot: path.dirname(installed.packageRoot),
        client: "codex", currentRelease: installed.packageRoot });
    }
  }
  const activation = await inspectActivation(locations.hostRoot, metadata.profileId);
  // Both public install commands use the actual account state. Native recovery
  // and updater-only options still require an existing activation.
  const initialSetup = !activation.ready && (command === "init"
    || (command === "setup" && !isNativeClient() && !deferReleaseCleanup));
  if (initialSetup) {
    const preparedConfiguration = await preflightClientConfiguration({ ...installed, locations, allowUnconnected: true });
    const host = await initializeHost(locations, installed.packageRoot);
    const configured = await configureClient({ ...installed, locations }, preparedConfiguration);
    const releaseCleanup = await cleanupInstalledReleases(installed);
    print({
      ok: true,
      client: metadata.client,
      hostId: host.hostInstallationId,
      state: host.state,
      configured,
      releaseCleanup,
      accountUrl: `${metadata.serviceBaseUrl}/account`,
      next: "open_client_and_connect",
      installsNode: false,
      installsGit: false,
      installsCodex: false,
    });
  } else if (command === "connect") {
    const preparedConfiguration = await preflightClientConfiguration({ ...installed, locations });
    const host = await initializeHost(locations, installed.packageRoot);
    if (isNativeClient()) await assertNativeEnrollmentProfile({ ...installed, locations, host });
    await preflightBindingActivation({ ...installed, locations, activation, preBind: true });
    const relay = await importStableCore(
      installed.packageRoot,
      "hellolynk-relay-client-cli.mjs",
      "hellolynk_npm_activation_runtime_invalid",
    );
    mutationRecoveryState = "device_connect_attempted";
    // The protected enrollment store owns the request and registration intent.
    // A subsequent explicit connect resumes them; this wrapper never retries HTTP.
    const connected = await relay.runRelayClientCli([
      "connect",
      "--hellolynk-id", connectOptions.hellolynkId,
      "--base-url", metadata.serviceBaseUrl,
      "--root", locations.finalCurrentRoot,
      "--neutral-host-root", locations.hostRoot,
      "--adapter", metadata.client,
      "--profile", metadata.profileId,
      ...(connectOptions.instanceName ? ["--instance-name", connectOptions.instanceName] : []),
      ...(connectOptions.deviceLabel ? ["--device-label", connectOptions.deviceLabel] : []),
    ]);
    if (connected?.ok !== true || connected.hellolynkId !== connectOptions.hellolynkId) {
      fail("hellolynk_npm_connect_response_invalid");
    }
    if (connected.status === "confirmation_required") {
      const verificationUrl = checkedVerificationUrl(connected.verificationUrl);
      mutationRecoveryState = "none";
      print({
        ok: true,
        status: "confirmation_required",
        client: metadata.client,
        hellolynkId: connectOptions.hellolynkId,
        verificationUrl,
        activated: false,
        instructions: {
          zh: "还差一步：请打开下方官网链接，确认这台电脑。确认后，让 AI 继续连接；同一台电脑只需确认一次。",
          en: "One more step: open the website link below and confirm this computer. Then ask your AI to continue connecting. Each computer only needs to be confirmed once.",
        },
        next: "confirm_on_website_then_repeat_connect",
      });
    } else {
      if (connected.status !== "registered" || connected.clientType !== metadata.client
        || connected.profileId !== metadata.profileId || connected.hostProfileRegistered !== true
        || connected.configPath !== path.join(locations.finalCurrentRoot, "profiles", `${metadata.profileId}.json`)) {
        fail("hellolynk_npm_connect_response_invalid");
      }
      const instanceName = checkedConnectLabel(connected.instanceName);
      mutationRecoveryState = "device_registration_committed_roll_forward_required";
      const activated = await inspectActivation(locations.hostRoot, metadata.profileId);
      if (!activated.ready) fail("hellolynk_npm_host_activation_failed");
      await activateBinding({ ...installed, locations, activation: activated });
      const configured = await configureClient({ ...installed, locations }, preparedConfiguration);
      mutationRecoveryState = "none";
      const releaseCleanup = await cleanupInstalledReleases(installed);
      const hostHandover = await requestInstalledHostHandover({ ...installed, locations, activation: activated });
      print({
        ok: true,
        status: "registered",
        client: metadata.client,
        hellolynkId: connectOptions.hellolynkId,
        instanceName,
        ...(connected.recoveredExistingName === true ? { recoveredExistingName: true } : {}),
        profileId: metadata.profileId,
        hostId: host.hostInstallationId,
        activated: true,
        configured,
        releaseCleanup,
        hostHandover,
        restartRequired: true,
        ...(isNativeClient() ? { next: "reopen_native_workbench" } : {}),
        installsNode: false,
        installsGit: false,
        installsCodex: false,
      });
    }
  } else if (command === "activate") {
    const preparedConfiguration = await preflightClientConfiguration({ ...installed, locations });
    const host = await initializeHost(locations, installed.packageRoot);
    await preflightBindingActivation({ ...installed, locations, activation, preBind: true });
    const relay = await importStableCore(
      installed.packageRoot,
      "hellolynk-relay-client-cli.mjs",
      "hellolynk_npm_activation_runtime_invalid",
    );
    const bindArgs = [
      "bind",
      "--binding-key-from-stdin",
      "--base-url", metadata.serviceBaseUrl,
      "--device-id", `hellolynk_${metadata.client.replaceAll("-", "_")}_${host.hostInstallationId.slice(-12)}`,
      "--host-installation-id", host.hostInstallationId,
      "--profile", metadata.profileId,
      "--root", locations.finalCurrentRoot,
      "--neutral-host-root", locations.hostRoot,
      "--adapter", metadata.client,
    ];
    const needsBootstrapTransport = host.state === "unclaimed"
      || !(await hasHostTransport(locations, installed.packageRoot));
    if (needsBootstrapTransport) bindArgs.splice(2, 0, "--bootstrap-host-transport");
    mutationRecoveryState = "binding_redemption_attempted";
    const bound = await relay.runRelayClientCli(bindArgs);
    if (bound?.neutralHostActivated !== true) fail("hellolynk_npm_host_activation_failed");
    mutationRecoveryState = "binding_committed_roll_forward_required";
    const activated = await inspectActivation(locations.hostRoot, metadata.profileId);
    if (!activated.ready) fail("hellolynk_npm_host_activation_failed");
    await activateBinding({ ...installed, locations, activation: activated });
    const configured = await configureClient({ ...installed, locations }, preparedConfiguration);
    mutationRecoveryState = "none";
    const releaseCleanup = await cleanupInstalledReleases(installed);
    const hostHandover = await requestInstalledHostHandover({ ...installed, locations, activation: activated });
    print({
      ok: true,
      client: metadata.client,
      hostId: host.hostInstallationId,
      activated: true,
      bootstrapTransportStored: bound.bootstrapTransportStored === true,
      configured,
      releaseCleanup,
      hostHandover,
      restartRequired: true,
      installsNode: false,
      installsGit: false,
      installsCodex: false,
    });
  } else if (command === "doctor") {
    if (existingDoctor && !activation.ready) fail("hellolynk_npm_existing_host_activation_required");
    const installed = existingDoctor
      ? await inspectExistingDoctorTarget(existingDoctor, { packageClosure, locations, packageLocations, activation })
      : activation.ready ? await inspectStablePackage({ packageClosure, sourceRelease, locations: packageLocations }) : null;
    if (installed) {
      await verifyExactBinding({ ...installed, locations, activation });
      await verifyClientConfiguration({ ...installed, locations });
    }
    print({
      ok: true,
      client: metadata.client,
      packageVersion: existingDoctor ? installed.packageJson.version : packageJson.version,
      ...(existingDoctor ? { existingPackageManifestSha256: installed.packageClosure.manifestSha256,
        compatibilityReaderVersion: packageJson.version, readOnly: true } : {}),
      releaseVerified: true,
      activated: activation.ready,
      activationState: activation.state,
      stableReleaseVerified: installed != null,
      exactBindingVerified: installed != null,
      clientConfigurationVerified: installed != null,
      installsNode: false,
      installsGit: false,
      installsCodex: false,
    });
  } else if (command === "setup" || command === "init") {
    if (!activation.ready) fail("hellolynk_npm_existing_host_activation_required");
    if (setupRecovery !== null) {
      if (!isNativeClient() || installed.release.manifestSha256 !== setupRecovery.expectedCurrentManifestSha256) {
        fail("hellolynk_native_recovery_candidate_mismatch");
      }
      const currentBinding = await verifyExactBinding({ ...installed, locations, activation });
      const previous = await inspectTrustedPackageRoot({
        packageRoot: setupRecovery.previousPackageRoot,
        currentPackageRoot: installed.packageRoot,
        locations,
        activation,
      });
      if (samePath(previous.packageRoot, installed.packageRoot)) fail("hellolynk_native_recovery_previous_invalid");
      const previousConfiguration = metadata.client === "cursor"
        ? await preflightClientConfiguration({ ...previous, previousCursorPackage: installed }) : null;
      if (previousConfiguration) {
        try {
          await configureClient(previous, previousConfiguration, { bindingContext: { ...installed, locations, activation } });
          await verifyClientConfiguration(previous);
        } catch (error) {
          // Keep the candidate binding until the complete old configuration
          // verifies. An old doctor cannot see the new plugin, so switching
          // first could misreport a partial rollback as a successful one.
          try { await establishClientState({ ...installed, locations, activation }, previousConfiguration, previous); }
          catch { throw codexUpgradeOutcomeUncertain(error); }
          throw error;
        }
      }
      mutationRecoveryState = "protected_binding_update_attempted";
      await activateBinding({ ...previous, expectedOwner: bindingOwner(currentBinding) });
      mutationRecoveryState = "binding_committed_roll_forward_required";
      await verifyExactBinding(previous);
      if (previousConfiguration) await verifyClientConfiguration(previous);
      mutationRecoveryState = "none";
      const hostHandover = await requestInstalledHostHandover(previous, { restore: true });
      print({
        ok: true,
        client: metadata.client,
        packageVersion: packageJson.version,
        recovered: true,
        restoredPackageVersion: previous.packageJson.version,
        activated: true,
        hostHandover,
        restartRequired: true,
        next: "reopen_native_workbench",
        installsNode: false,
        installsGit: false,
        installsCodex: false,
      });
      return;
    }
    const current = { ...installed, locations, activation };
    // Authenticate the old package and its unchanged Skill before proposing a
    // Cursor upgrade. Doctor remains strict and never accepts a previous Skill.
    const cursorPrevious = metadata.client === "cursor" ? await inspectPreviousOrAbsent(current) : null;
    const preparedConfiguration = await preflightClientConfiguration({ ...current, previousCursorPackage: cursorPrevious });
    await preflightBindingActivation(current);
    let configured, previousPackageRoot = null;
    if (metadata.client === "codex" && preparedConfiguration?.upgrade === true) {
      previousPackageRoot = preparedConfiguration.previous.packageRoot;
      configured = await upgradeCodexConfigurationAndBinding(
        { ...installed, locations, activation },
        preparedConfiguration,
      );
    } else {
      const previous = metadata.client === "cursor" ? cursorPrevious : await inspectPreviousOrAbsent(current);
      if (previous && !samePath(previous.packageRoot, current.packageRoot)) {
        previousPackageRoot = previous.packageRoot;
        configured = await upgradeClientConfigurationAndBinding(current, previous, preparedConfiguration);
      } else {
        mutationRecoveryState = "protected_binding_update_attempted";
        await activateBinding(current);
        mutationRecoveryState = "binding_committed_roll_forward_required";
        configured = await configureClient(current, preparedConfiguration);
      }
    }
    mutationRecoveryState = "none";
    const releaseCleanup = deferReleaseCleanup ? { deferredToUpdater: true }
      : await cleanupInstalledReleases(installed, previousPackageRoot);
    const hostHandover = await requestInstalledHostHandover(current);
    print({
      ok: true,
      client: metadata.client,
      packageVersion: packageJson.version,
      activated: true,
      configured,
      releaseCleanup,
      hostHandover,
      restartRequired: true,
      ...(isNativeClient() ? { next: "reopen_native_workbench" } : {}),
      installsNode: false,
      installsGit: false,
      installsCodex: false,
    });
  } else if (command === "uninstall") {
    const uninstalled = await uninstallClient(locations);
    print({ ok: true, client: metadata.client, uninstalled: true, ...uninstalled, restartRequired: true });
  } else {
    fail("hellolynk_npm_command_invalid");
  }
  });
  }
} catch (error) {
  const failure = failureResult(error, mutationRecoveryState);
  process.stderr.write(jsonOutput ? `${JSON.stringify(failure)}\n` : failureText(failure));
  process.exitCode = 1;
}

async function cleanupInstalledReleases(installed, previousRelease = null) {
  try {
    const cleanup = await importStableCore(installed.packageRoot, "hellolynk-release-retention.mjs", "hellolynk_release_retention_unavailable");
    return await cleanup.pruneInstalledReleases({ releasesRoot: path.dirname(installed.packageRoot),
      client: metadata.client, currentRelease: installed.packageRoot, previousRelease });
  } catch { return { complete: false, error: "release_retention_unavailable" }; }
}

// Uninstall reverses what setup wrote for this client, withdraws its local authorization and
// removes its releases; one still running waits for the next install or uninstall. host\ keeps
// the account, this computer's connection, contacts and history, so installing again issues a
// new authorization without connecting again.
async function uninstallClient(locations) {
  const releasesRoot = path.join(locations.releaseCurrentRoot, "releases");
  const releases = await installedReleaseRoots(releasesRoot);
  const result = {};
  if (metadata.client === "codex") {
    result.codexPluginRemoved = await removeCodexMarketplace(locations, releasesRoot);
  } else {
    const module = await importLocal(PACKAGE_ROOT, metadata.configurator, "hellolynk_npm_configurator_invalid");
    const remove = metadata.client === "openclaw" ? module.removeOpenClaw : module.removeNeutralHostMcpClient;
    const plans = [];
    for (const configPath of uninstallConfigPaths(locations)) {
      const options = { client: metadata.client, configPath, releasesRoot };
      const plan = await remove({ ...options, apply: false })
        .catch(uninstallConflict("agent_setup_uninstall_conflict", "hellolynk_npm_uninstall_config_conflict"));
      if (plan.changed) plans.push({ remove, options, plan });
    }
    // TRAE's argv.json stays as it is: setup may have kept a debugging port the user set, and
    // nothing records which. Only the receiver's own setting goes.
    const receiver = metadata.client === "trae-work"
      ? await importLocal(PACKAGE_ROOT, "integrations/trae-work/server/native-task-worker.mjs", "hellolynk_npm_trae_receiver_invalid") : null;
    const receiverConfigured = receiver && await exists(locations.hostRoot)
      && await receiver.readTraeNativeTaskWorkerConfig(locations.hostRoot);
    const skill = metadata.skillTarget
      ? await importLocal(PACKAGE_ROOT, "tools/hellolynk-install-client-skills.mjs", "hellolynk_npm_skill_installer_invalid") : null;
    const skillOptions = { sourceRoots: [PACKAGE_ROOT, ...releases], home: locations.home, appData: locations.appData,
      localAppData: locations.localAppData, target: metadata.skillTarget };
    const skillPlan = skill && await skill.removeInstalledClientSkill(skillOptions)
      .catch(uninstallConflict("client_skill_destination_differs", "hellolynk_npm_uninstall_skill_conflict"));
    // WorkBuddy's receiver and page tasks run from the releases removed below.
    if (metadata.client === "workbuddy") result.services = await uninstallWorkBuddyServices(locations, releases);
    const transaction = await module.runAgentConfigurationTransaction({
      plans,
      apply: ({ remove, options, plan }) => remove({ ...options, expectedConfigPath: plan.configPath,
        expectedConfigSha256: plan.expectedConfigSha256, expectedReplacementSha256: plan.replacementSha256 }),
      rollback: (item) => module.rollbackAgentConfiguration(item),
      finalize: skillPlan?.present ? () => skill.removeInstalledClientSkill({ ...skillOptions, apply: true }) : null,
    });
    result.configPaths = transaction.committed.map((item) => item.configPath);
    if (skillPlan) result.skillRemoved = skillPlan.present;
    if (receiverConfigured) await receiver.configureTraeNativeTaskWorker({ storeRoot: locations.hostRoot, enabled: false });
  }
  // A binding names the release it starts, so it cannot outlive the releases removed below.
  const protectedFile = macPackage ? "protected-v1.sqlite" : "capabilities-v1.dpapi.clixml";
  if (await exists(path.join(locations.hostRoot, protectedFile))) {
    const store = await importStableCore(PACKAGE_ROOT, "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
    await store.createHostProtectedStore({ root: locations.hostRoot, followClientAccount: false }).disconnectLocalClient(metadata.client);
  }
  const retention = await importStableCore(PACKAGE_ROOT, "hellolynk-release-retention.mjs", "hellolynk_release_retention_unavailable");
  result.releaseCleanup = await retention.removeInstalledReleases({ releasesRoot, client: metadata.client });
  return result;
}

function uninstallConflict(code, replacement) {
  return (error) => { if (String(error?.message || "") === code) fail(replacement); throw error; };
}

async function installedReleaseRoots(releasesRoot) {
  const names = await fs.readdir(releasesRoot).catch((error) => { if (error.code === "ENOENT") return []; throw error; });
  return names.filter((name) => new RegExp(`^${metadata.client}-[a-f0-9]{64}$`).test(name)).map((name) => path.join(releasesRoot, name));
}

// Setup writes one of these; uninstall checks every place an earlier setup could have used.
function uninstallConfigPaths({ home, appData }) {
  if (metadata.client === "openclaw") return [path.join(home, ".openclaw", "openclaw.json")];
  if (metadata.client === "trae-work") return ["Trae CN", "TRAE SOLO CN"].map((name) => path.join(appData, name, "User", "mcp.json"));
  return [".mcp.json", "mcp.json"].map((name) => path.join(home, ".workbuddy", name));
}

async function removeCodexMarketplace(locations, releasesRoot) {
  const marketplace = "hellolynk-npm-codex";
  // Without this marketplace in Codex's settings there is nothing to remove, and no Codex is needed.
  const settings = await fs.readFile(path.join(locations.codexHome, "config.toml"), "utf8").catch(() => "");
  if (!settings.includes(marketplace)) return false;
  const root = codexMarketplaceRoot(locations, marketplace);
  if (root === null) return false;
  if (!samePath(path.dirname(root), releasesRoot) || !/^codex-[a-f0-9]{64}$/i.test(path.basename(root))) {
    fail("hellolynk_npm_uninstall_config_conflict");
  }
  tryRunCodex(["plugin", "remove", `hellolynk-codex@${marketplace}`, "--json"], locations.codexHome);
  runCodex(["plugin", "marketplace", "remove", marketplace, "--json"],
    "hellolynk_npm_codex_marketplace_remove_failed", locations.codexHome);
  if (codexMarketplaceRoot(locations, marketplace) !== null) fail("hellolynk_npm_codex_marketplace_remove_failed");
  return true;
}

async function uninstallWorkBuddyServices(locations, releases) {
  const code = "hellolynk_npm_workbuddy_page_service_invalid";
  const tasks = await importLocal(PACKAGE_ROOT, "integrations/workbuddy/server/workbench-process.mjs", code);
  const registration = await importLocal(PACKAGE_ROOT, "integrations/workbuddy/server/native-task-service-registration.mjs", code);
  const record = await registration.withWorkBuddyNativeServiceRecord(locations.hostRoot,
    async (registry) => (registry ? registry.read() : null));
  if (record) await tasks.configureWorkBuddyNativeTaskService({ ...record, storeRoot: locations.hostRoot }, "Uninstall");
  for (const root of releases) {
    const release = await verifyRelease(root, root).catch(() => null);
    if (release) {
      await tasks.configureWorkBuddyWorkbenchTask({ root, expectedManifestSha256: release.outerManifestSha256,
        storeRoot: locations.hostRoot }, "Uninstall");
    }
  }
  return { nativeServiceRemoved: record !== null };
}

function parseConnectOptions(args) {
  const options = Object.create(null);
  const names = new Map([
    ["--hellolynk-id", "hellolynkId"],
    ["--instance-name", "instanceName"],
    ["--device-label", "deviceLabel"],
    ["--account-revision", "accountRevision"],
  ]);
  for (let index = 0; index < args.length; index += 2) {
    const name = names.get(args[index]);
    const value = args[index + 1];
    if (!name || Object.hasOwn(options, name) || typeof value !== "string"
      || value.startsWith("--")) fail("hellolynk_npm_connect_arguments_invalid");
    options[name] = value;
  }
  if (!/^hellolynk:(?:intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/.test(options.hellolynkId || "")) {
    fail("hellolynk_npm_connect_id_invalid");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/.test(metadata.profileId)) fail("hellolynk_npm_package_invalid");
  if (Object.hasOwn(options, "instanceName")) {
    options.instanceName = checkedRequestedInstanceName(options.instanceName);
  }
  if (Object.hasOwn(options, "deviceLabel")) options.deviceLabel = checkedConnectLabel(options.deviceLabel);
  if (options.accountRevision !== undefined && !/^(?:initial|[a-f0-9]{32})$/.test(options.accountRevision)) {
    fail("workbench_account_changed");
  }
  return Object.freeze(options);
}

function parseExistingDoctorOptions(args) {
  if (args.length === 0) return null;
  const code = "hellolynk_npm_doctor_arguments_invalid";
  if (!["codex", "dsh"].includes(metadata.client) || args.length !== 4) fail(code);
  const values = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index + 1];
    if (!["--existing-root", "--expected-existing-manifest-sha256"].includes(name)
      || Object.hasOwn(values, name) || typeof value !== "string" || !value) fail(code);
    values[name] = value;
  }
  const packageRoot = values["--existing-root"], manifestSha256 = values["--expected-existing-manifest-sha256"];
  if (!path.isAbsolute(packageRoot || "") || path.resolve(packageRoot) !== packageRoot
    || !/^[a-f0-9]{64}$/u.test(manifestSha256 || "")) fail(code);
  return Object.freeze({ packageRoot, manifestSha256 });
}

async function inspectExistingDoctorTarget(target, { packageClosure, locations, packageLocations, activation }) {
  const releasesRoot = path.join(packageLocations.finalCurrentRoot, "releases");
  if (!samePath(target.packageRoot, path.join(releasesRoot, `${metadata.client}-${target.manifestSha256}`))) {
    fail("hellolynk_npm_previous_install_invalid");
  }
  const input = { packageRoot: target.packageRoot,
    currentPackageRoot: path.join(releasesRoot, `${metadata.client}-${packageClosure.manifestSha256}`), locations, activation };
  const previous = metadata.client === "codex"
    ? await inspectTrustedCodexInstallation(input) : await inspectTrustedPackageRoot(input);
  if (previous.packageClosure.manifestSha256 !== target.manifestSha256) fail("hellolynk_npm_previous_install_invalid");
  return previous;
}

function parseSetupRecoveryOptions(args) {
  if (args.length === 0) return null;
  if (args.length !== 6) fail("hellolynk_npm_setup_arguments_invalid");
  const values = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!new Set([
      "--recover-previous-root",
      "--expected-current-release-manifest-sha256",
      "--expected-account-revision",
    ]).has(name) || Object.hasOwn(values, name) || typeof value !== "string" || !value) {
      fail("hellolynk_npm_setup_arguments_invalid");
    }
    values[name] = value;
  }
  const previousPackageRoot = values["--recover-previous-root"];
  const expectedCurrentManifestSha256 = values["--expected-current-release-manifest-sha256"];
  const expectedAccountRevision = values["--expected-account-revision"];
  if (!path.isAbsolute(previousPackageRoot) || path.resolve(previousPackageRoot) !== previousPackageRoot
    || !/^[a-f0-9]{64}$/u.test(expectedCurrentManifestSha256 || "")
    || !/^(?:initial|[a-f0-9]{32})$/u.test(expectedAccountRevision || "")) {
    fail("hellolynk_npm_setup_arguments_invalid");
  }
  return Object.freeze({ previousPackageRoot, expectedCurrentManifestSha256, expectedAccountRevision });
}

function checkedConnectLabel(value) {
  if (typeof value !== "string" || !value.trim() || [...value.trim()].length > 80
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value)) {
    fail("hellolynk_npm_connect_label_invalid");
  }
  return value.trim();
}

function checkedRequestedInstanceName(value) {
  if (typeof value !== "string" || !value || [...value].length > 80
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value)) {
    fail("hellolynk_npm_connect_label_invalid");
  }
  // The protected enrollment store decides whether this exact value resumes a
  // legacy intent or must satisfy the stricter rule for a new registration.
  return value;
}

function checkedVerificationUrl(value) {
  try {
    const url = new URL(value);
    if (url.origin !== metadata.serviceBaseUrl || url.username || url.password || url.hash
      || url.pathname !== "/account" || url.searchParams.size !== 1
      || !/^devreq_[a-f0-9]{48}$/.test(url.searchParams.get("deviceRequest") || "")) {
      fail("hellolynk_npm_connect_response_invalid");
    }
    return url.href;
  } catch { fail("hellolynk_npm_connect_response_invalid"); }
}

// Until the package names its client, a failure is reported without one.
async function readPackage() {
  try {
    const packageJson = await readJson(path.join(PACKAGE_ROOT, "package.json"), "hellolynk_npm_package_invalid");
    return { packageJson, metadata: normalizeMetadata(packageJson.hellolynkClient, packageJson) };
  } catch (error) {
    const code = safeCode(error);
    writeSync(2, jsonOutput ? `${JSON.stringify({ ok: false, error: code })}\n` : `${code}\n${failureReason(code, "HelloLynk")}\n`);
    process.exit(1);
  }
}

function normalizeMetadata(value, packageJson) {
  const allowed = [
    "activationTool", "client", "configurator", "coreRoot", "entry", "outerManifestPin",
    "pluginPath", "profileId", "releaseRoot", "serviceBaseUrl", "skillTarget",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !allowed.includes(key))) fail("hellolynk_npm_package_invalid");
  const client = String(value.client || "");
  if (!["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh"].includes(client)) fail("hellolynk_npm_package_invalid");
  if (["cursor", "dsh"].includes(client) && (packageJson.private !== true
    || Object.keys(value).sort().join(",") !== "activationTool,client,coreRoot,profileId,releaseRoot,serviceBaseUrl"
    || value.profileId !== `hellolynk-host-${client}-v2`
    || value.serviceBaseUrl !== "https://hellolynk.com" || value.releaseRoot !== "."
    || value.coreRoot !== "runtime/core"
    || value.activationTool !== "tools/hellolynk-activate-neutral-host-clients.mjs")) {
    fail("hellolynk_native_package_invalid");
  }
  const required = ["activationTool", "coreRoot", "profileId", "releaseRoot"];
  if (required.some((key) => !safeRelative(value[key]))) fail("hellolynk_npm_package_invalid");
  for (const key of ["configurator", "entry", "outerManifestPin", "pluginPath", "skillTarget"]) {
    if (value[key] != null && !safeRelative(value[key])) fail("hellolynk_npm_package_invalid");
  }
  let serviceBaseUrl;
  try {
    const parsed = new URL(String(value.serviceBaseUrl || ""));
    if (parsed.protocol !== "https:" || parsed.username || parsed.password
      || parsed.pathname !== "/" || parsed.search || parsed.hash) fail("hellolynk_npm_package_invalid");
    serviceBaseUrl = parsed.origin;
  } catch (error) {
    if (error?.code) throw error;
    fail("hellolynk_npm_package_invalid");
  }
  return Object.freeze({ ...value, client, serviceBaseUrl });
}

function isNativeClient() { return metadata.client === "cursor" || metadata.client === "dsh"; }

async function assertNativeEnrollmentProfile({ packageRoot, locations, host }) {
  // The native package has one fixed profile. An older binding or unfinished
  // registration for this client is not permission to create a second identity.
  if (host.delegateBindings.some((binding) => (
    binding.adapters.includes(metadata.client) && binding.profileId !== metadata.profileId
  ) || (binding.profileId === metadata.profileId
    && (binding.adapters.length !== 1 || binding.adapters[0] !== metadata.client)))) {
    fail("hellolynk_native_existing_profile_conflict");
  }
  const protectedModule = await importStableCore(packageRoot,
    "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
  const enrollment = await protectedModule.createHostProtectedStore({ root: locations.hostRoot }).loadDeviceEnrollment();
  if (enrollment.value === null) return;
  const intents = enrollment.value.intents;
  if (!intents || typeof intents !== "object" || Array.isArray(intents)) fail("device_enrollment_store_invalid");
  for (const [profileId, intent] of Object.entries(intents)) {
    if ((intent?.clientType === metadata.client && profileId !== metadata.profileId)
      || (profileId === metadata.profileId && intent?.clientType !== metadata.client)) {
      fail("hellolynk_native_existing_profile_conflict");
    }
  }
}

function safeRelative(value) {
  const text = String(value || "");
  return !!text && text.length <= 512 && !path.isAbsolute(text)
    && !text.split(/[\\/]/).includes("..") && !/[\0\r\n]/.test(text);
}

function requireNode() {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(process.versions.node || ""));
  if (!match || Number(match[1]) < 22 || (Number(match[1]) === 22 && Number(match[2]) < 16)) {
    fail("hellolynk_node_22_16_required");
  }
}

async function verifyPackageClosure(root, expectedManifestSha256 = null, expected = {}) {
  const expectedPackageJson = expected.packageJson || packageJson;
  const expectedMetadata = expected.metadata || metadata;
  const manifestPath = path.join(root, PACK_MANIFEST);
  const pin = await readJson(path.join(root, PACK_PIN), "hellolynk_npm_pack_invalid", true);
  const manifestBytes = await readRegularFile(manifestPath, "hellolynk_npm_pack_invalid", true);
  const manifestSha256 = sha256(manifestBytes);
  if (manifestBytes.length > MAX_JSON_BYTES
    || pin?.contract !== "hellolynk-client-npm-pack-pin-v1"
    || Object.keys(pin).sort().join(",") !== "contract,manifestSha256"
    || pin.manifestSha256 !== manifestSha256
    || (expectedManifestSha256 != null && expectedManifestSha256 !== manifestSha256)) {
    fail("hellolynk_npm_pack_invalid");
  }
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); }
  catch { fail("hellolynk_npm_pack_invalid"); }
  if (manifest?.contract !== "hellolynk-client-npm-pack-manifest-v1"
    || Object.keys(manifest).sort().join(",") !== "client,contract,files,packageName,version,workbench"
    || manifest.client !== expectedMetadata.client || manifest.packageName !== expectedPackageJson.name
    || manifest.version !== expectedPackageJson.version || !Array.isArray(manifest.files)
    || manifest.files.length < 8 || manifest.files.length > 5_000) fail("hellolynk_npm_pack_invalid");

  const rootRealPath = await fs.realpath(root).catch(() => fail("hellolynk_npm_pack_invalid"));
  const records = new Map();
  const portablePathNodes = new Map();
  registerPortablePackPath(portablePathNodes, PACK_MANIFEST);
  registerPortablePackPath(portablePathNodes, PACK_PIN);
  for (const record of manifest.files) {
    if (!record || typeof record !== "object" || Array.isArray(record)
      || Object.keys(record).sort().join(",") !== "bytes,path,sha256"
      || !safePackPath(record.path) || !Number.isSafeInteger(record.bytes) || record.bytes < 0
      || !/^[a-f0-9]{64}$/.test(record.sha256) || records.has(record.path)) fail("hellolynk_npm_pack_invalid");
    registerPortablePackPath(portablePathNodes, record.path);
    const file = path.resolve(root, ...record.path.split("/"));
    const fileRealPath = await fs.realpath(file).catch(() => fail("hellolynk_npm_pack_invalid"));
    const relativeRealPath = path.relative(rootRealPath, fileRealPath);
    if (!relativeRealPath || path.isAbsolute(relativeRealPath)
      || relativeRealPath === ".." || relativeRealPath.startsWith(`..${path.sep}`)) fail("hellolynk_npm_pack_invalid");
    const body = await readRegularFile(file, "hellolynk_npm_pack_invalid", true);
    if (body.length !== record.bytes || sha256(body) !== record.sha256) fail("hellolynk_npm_pack_invalid");
    records.set(record.path, record);
  }
  await assertExactPackageTree(root, records, rootRealPath);
  if (!records.has("package.json") || !records.has("bin/hellolynk-client-setup.mjs")) fail("hellolynk_npm_pack_invalid");
  if (expectedMetadata.client === "cursor"
    && (!records.has("tools/hellolynk-install-client-skills.mjs")
      || (expected.installedPreviousRelease !== true && (!records.has("tools/hellolynk-install-cursor-plugin.mjs")
        || !records.has("cursor-plugin/server/hellolynk-mcp.js") || !records.has("cursor-plugin/bin/hellolynk-waiter.mjs")))
      || !records.has("integrations/hellolynk-cursor/skills/hellolynk-messaging/SKILL.md"))) {
    fail("hellolynk_npm_pack_invalid");
  }
  const workbench = manifest.workbench;
  if (!workbench || typeof workbench !== "object" || Array.isArray(workbench)
    || Object.keys(workbench).sort().join(",") !== "contract,manifestSha256,path,version"
    || !safePackPath(workbench.path) || !/^[a-f0-9]{64}$/.test(workbench.manifestSha256)
    || records.get(workbench.path)?.sha256 !== workbench.manifestSha256) fail("hellolynk_npm_pack_invalid");
  return Object.freeze({ manifestSha256, fileCount: records.size });
}

function safePackPath(value) {
  return typeof value === "string" && value !== PACK_MANIFEST && value !== PACK_PIN
    && safeRelative(value) && !value.startsWith("./") && path.posix.normalize(value) === value
    && value.split("/").every(safePackPathSegment);
}

function safePackPathSegment(value) {
  const windowsBaseName = String(value).split(".")[0];
  return typeof value === "string" && value.length >= 1 && value.length <= 255
    && value !== "." && value !== ".." && !/[<>:"\\|?*\u0000-\u001F]/u.test(value)
    && !/[. ]$/u.test(value)
    && !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/iu.test(windowsBaseName);
}

function portablePathKey(value) {
  return typeof value === "string" ? value.normalize("NFC").toLowerCase() : "";
}

function registerPortablePackPath(nodes, value) {
  const segments = value.split("/");
  for (let index = 0; index < segments.length; index += 1) {
    const portablePath = segments.slice(0, index + 1).join("/");
    const kind = index === segments.length - 1 ? "file" : "directory";
    const key = portablePathKey(portablePath);
    const existing = nodes.get(key);
    if (existing && (existing.path !== portablePath || existing.kind !== kind)) fail("hellolynk_npm_pack_invalid");
    nodes.set(key, { path: portablePath, kind });
  }
}

async function assertExactPackageTree(root, records, rootRealPath) {
  const rootMetadata = await fs.lstat(root).catch(() => fail("hellolynk_npm_pack_invalid"));
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) fail("hellolynk_npm_pack_invalid");
  const expectedPaths = new Set([...records.keys(), PACK_MANIFEST, PACK_PIN]);
  const actualPaths = new Set();

  async function visit(directory, prefix = "") {
    const directoryRealPath = await fs.realpath(directory).catch(() => fail("hellolynk_npm_pack_invalid"));
    const relativeRealPath = path.relative(rootRealPath, directoryRealPath);
    if (relativeRealPath === ".." || relativeRealPath.startsWith(`..${path.sep}`)
      || path.isAbsolute(relativeRealPath)) fail("hellolynk_npm_pack_invalid");
    const entries = await fs.readdir(directory, { withFileTypes: true })
      .catch(() => fail("hellolynk_npm_pack_invalid"));
    for (const entry of entries) {
      if (!safePackPathSegment(entry.name)) fail("hellolynk_npm_pack_invalid");
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      const entryMetadata = await fs.lstat(absolute).catch(() => fail("hellolynk_npm_pack_invalid"));
      if (entryMetadata.isSymbolicLink()) fail("hellolynk_npm_pack_invalid");
      if (entryMetadata.isDirectory()) {
        await visit(absolute, relative);
      } else if (entryMetadata.isFile()) {
        if (entryMetadata.nlink !== 1 || actualPaths.has(relative)) fail("hellolynk_npm_pack_invalid");
        actualPaths.add(relative);
        if (!expectedPaths.has(relative)) fail("hellolynk_npm_pack_invalid");
      } else {
        fail("hellolynk_npm_pack_invalid");
      }
    }
  }

  await visit(root);
  if (actualPaths.size !== expectedPaths.size
    || [...expectedPaths].some((relative) => !actualPaths.has(relative))) fail("hellolynk_npm_pack_invalid");
}

async function verifyRelease(releaseRoot, packageRoot, expectedMetadata = metadata) {
  const runtime = path.join(releaseRoot, "runtime");
  const manifestPath = path.join(runtime, "neutral-host-release-manifest.json");
  const pin = await readJson(path.join(runtime, "neutral-host-release-pin.json"), "hellolynk_npm_release_invalid");
  const bytes = await readRegularFile(manifestPath, "hellolynk_npm_release_invalid");
  const manifestSha256 = sha256(bytes);
  if (pin?.contract !== "hellolynk-neutral-host-release-pin-v1"
    || Object.keys(pin).sort().join(",") !== "contract,manifestSha256"
    || pin.manifestSha256 !== manifestSha256) fail("hellolynk_npm_release_invalid");
  const manifest = JSON.parse(bytes.toString("utf8"));
  if (manifest?.contract !== "hellolynk-neutral-host-release-manifest-v1"
    || manifest.entry !== "neutral-host-release-entry.mjs" || !Array.isArray(manifest.files)
    || manifest.files.length < 8) fail("hellolynk_npm_release_invalid");
  let outerManifestSha256 = null;
  if (expectedMetadata.outerManifestPin) {
    const outerPin = await readJson(path.join(packageRoot, expectedMetadata.outerManifestPin), "hellolynk_npm_release_invalid");
    const outerManifestPath = path.join(packageRoot, expectedMetadata.outerManifestPin.replace(/-pin\.json$/, "-manifest.json"));
    outerManifestSha256 = sha256(await readRegularFile(outerManifestPath, "hellolynk_npm_release_invalid"));
    if (outerPin?.manifestSha256 !== outerManifestSha256) fail("hellolynk_npm_release_invalid");
  }
  return Object.freeze({ manifestSha256, outerManifestSha256 });
}

function resolveLocations(getDefaultHostRoot) {
  if (macPackage) {
    if (process.platform !== "darwin" || process.arch !== "arm64") fail("hellolynk_npm_platform_unsupported");
  } else if (process.platform !== "win32") fail("hellolynk_npm_windows_only");
  const home = path.resolve((macPackage ? process.env.HOME : process.env.USERPROFILE) || os.homedir());
  const localAppData = macPackage ? path.join(home, "Library", "Application Support")
    : path.resolve(process.env.LOCALAPPDATA || path.join(home, "AppData", "Local"));
  const appData = macPackage ? localAppData : path.resolve(process.env.APPDATA || path.join(home, "AppData", "Roaming"));
  const configuredCodexHome = String(process.env.CODEX_HOME || "");
  if (configuredCodexHome && !path.isAbsolute(configuredCodexHome)) fail("hellolynk_npm_codex_home_invalid");
  const codexHome = path.resolve(configuredCodexHome || path.join(home, ".codex"));
  const configuredHostRoot = String(process.env.HELLOLYNK_NEUTRAL_STORE_ROOT || "").trim();
  if (configuredHostRoot && !path.isAbsolute(configuredHostRoot)) fail("hellolynk_npm_store_root_invalid");
  const hostRoot = path.resolve(configuredHostRoot || getDefaultHostRoot());
  if (configuredHostRoot && path.basename(hostRoot).toLowerCase() !== "host") {
    fail("hellolynk_npm_store_root_invalid");
  }
  const finalCurrentRoot = path.dirname(hostRoot);
  if (finalCurrentRoot === path.parse(finalCurrentRoot).root) fail("hellolynk_npm_store_root_invalid");
  return Object.freeze({
    home,
    localAppData,
    appData,
    codexHome,
    finalCurrentRoot,
    hostRoot,
  });
}

async function installStablePackage({ packageClosure, sourceRelease, locations }) {
  const immutableId = `${metadata.client}-${packageClosure.manifestSha256}`;
  const releasesRoot = path.join(locations.finalCurrentRoot, "releases");
  const packageRoot = path.join(releasesRoot, immutableId);
  const temporaryRoot = path.join(releasesRoot, `.${immutableId}.install-${crypto.randomUUID()}`);
  await fs.mkdir(releasesRoot, { recursive: true, mode: 0o700 });

  if (!(await exists(packageRoot))) {
    try {
      await fs.cp(PACKAGE_ROOT, temporaryRoot, {
        recursive: true,
        force: false,
        errorOnExist: true,
        preserveTimestamps: false,
      });
      await verifyPackageClosure(temporaryRoot, packageClosure.manifestSha256);
      await secureStableReleaseTree(locations, path.basename(temporaryRoot));
      for (let attempt = 0; attempt < 6; attempt += 1) {
        try {
          await fs.rename(temporaryRoot, packageRoot);
          break;
        } catch (error) {
          const code = String(error?.code || "");
          const harmlessRace = ["EEXIST", "ENOTEMPTY"].includes(code)
            || (["EPERM", "EACCES"].includes(code) && await exists(packageRoot));
          if (harmlessRace) break;
          const transientWindowsLock = process.platform === "win32"
            && ["EPERM", "EACCES"].includes(code) && attempt < 5;
          if (!transientWindowsLock) throw error;
          await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
        }
      }
    } finally {
      await fs.rm(temporaryRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    }
  }

  await secureStableReleaseTree(locations, immutableId, { verifyOnly: true })
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  await verifyPackageClosure(packageRoot, packageClosure.manifestSha256)
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  const releaseRoot = path.resolve(packageRoot, metadata.releaseRoot);
  if (!isSameOrDescendant(releaseRoot, packageRoot)) fail("hellolynk_npm_stable_release_invalid");
  const release = await verifyRelease(releaseRoot, packageRoot)
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  if (release.manifestSha256 !== sourceRelease.manifestSha256
    || release.outerManifestSha256 !== sourceRelease.outerManifestSha256) {
    fail("hellolynk_npm_stable_release_invalid");
  }
  return Object.freeze({ packageRoot, releaseRoot, release });
}

async function inspectStablePackage({ packageClosure, sourceRelease, locations }) {
  const immutableId = `${metadata.client}-${packageClosure.manifestSha256}`;
  const packageRoot = path.join(locations.finalCurrentRoot, "releases", immutableId);
  await secureStableReleaseTree(locations, immutableId, { verifyOnly: true })
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  await verifyPackageClosure(packageRoot, packageClosure.manifestSha256)
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  const releaseRoot = path.resolve(packageRoot, metadata.releaseRoot);
  if (!isSameOrDescendant(releaseRoot, packageRoot)) fail("hellolynk_npm_stable_release_invalid");
  const release = await verifyRelease(releaseRoot, packageRoot)
    .catch(() => fail("hellolynk_npm_stable_release_invalid"));
  if (release.manifestSha256 !== sourceRelease.manifestSha256
    || release.outerManifestSha256 !== sourceRelease.outerManifestSha256) {
    fail("hellolynk_npm_stable_release_invalid");
  }
  return Object.freeze({ packageRoot, releaseRoot, release });
}

async function prepareFinalClientRoot(locations) {
  const module = await importCore(
    "hellolynk-platform-credential-store.mjs",
    "hellolynk_npm_client_root_security_unavailable",
  );
  try {
    await module.prepareWindowsClientRoot(locations.finalCurrentRoot);
  } catch (error) {
    fail(/^[a-z][a-z0-9_]{2,127}$/.test(error?.code || "")
      ? error.code : "hellolynk_npm_client_root_security_invalid");
  }
}

async function requestInstalledHostHandover(context, { restore = false } = {}) {
  let binding;
  const publishedAt = new Date().toISOString();
  try {
    binding = await verifyExactBinding(context);
    // Always use this verified installer's helper, including an explicit restore
    // to a former package that did not yet provide the handover entry point.
    const runtime = await importStableCore(PACKAGE_ROOT,
      "hellolynk-neutral-host-process.mjs", "hellolynk_npm_host_handover_unavailable");
    const request = {
      runtimeRoot: binding.runtimeRoot,
      hostInstallationId: binding.hostInstallationId,
      publishedAt,
    };
    // An explicit restore went back to an earlier release: it removes this release's record and
    // leaves whichever Host is running alone. It asks none to leave and starts none.
    if (restore) {
      await runtime.removeHelloLynkNeutralHostExpectedRelease({
        runtimeRoot: request.runtimeRoot, hostInstallationId: request.hostInstallationId,
      }).catch(() => {});
      return { status: "not_requested" };
    }
    const result = await runtime.requestHelloLynkNeutralHostHandover(request);
    // Only a Host that was running and made room is replaced. One started where there was
    // none would have nothing attached to it and never leave.
    if (["stopped", "restarted"].includes(result?.status)) {
      await startHostWhenAbsent(runtime, binding).catch(() => {});
    }
    return result;
  } catch {
    // The install has committed. Failure to request a restart must not roll
    // back valid configuration or report that installation itself failed.
    return { status: "unconfirmed", code: "hellolynk_npm_host_handover_unconfirmed" };
  } finally {
    binding?.capability?.secretBuffer?.fill(0);
  }
}

// A Host that left for this release is not started again until some client reconnects.
// Start one from the new binding unless another client has within two seconds.
async function startHostWhenAbsent(runtime, binding) {
  const probe = {
    region: binding.region,
    principalId: binding.principalId,
    hostInstallationId: binding.hostInstallationId,
    runtimeRoot: binding.runtimeRoot,
  };
  for (let attempt = 0; attempt < 8; attempt += 1) {
    if (await runtime.discoverHelloLynkNeutralHost(probe).catch(() => null)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const launcher = await importStableCore(PACKAGE_ROOT,
    "hellolynk-neutral-host-launcher.mjs", "hellolynk_npm_host_handover_unavailable");
  await launcher.launchPinnedNeutralHost(binding);
}

async function secureStableReleaseTree(locations, releaseId, options = {}) {
  const releasePath = path.resolve(locations.finalCurrentRoot, "releases", releaseId);
  // An existing AppData root can be shared while a new release is redirected
  // into one desktop app's private cache. Other clients cannot use that release.
  if (process.platform === "win32" && realpathSync.native(releasePath).toLowerCase() !== releasePath.toLowerCase()) {
    fail("client_root_alias_rejected");
  }
  const module = await importCore(
    "hellolynk-platform-credential-store.mjs",
    "hellolynk_npm_client_root_security_unavailable",
  );
  return module.secureWindowsClientReleaseTree(
    locations.finalCurrentRoot,
    releaseId,
    { verifyOnly: options.verifyOnly === true },
  );
}

async function verifyExactBinding({ packageRoot, releaseRoot, release, locations, activation }) {
  const installationModule = await importStableCore(
    PACKAGE_ROOT,
    "hellolynk-neutral-host-installation-store.mjs",
    "hellolynk_npm_binding_invalid",
  );
  const protectedModule = await importStableCore(
    PACKAGE_ROOT,
    "hellolynk-host-protected-store.mjs",
    "hellolynk_npm_binding_invalid",
  );
  const verifyPath = ({ path: target, directory }) => protectedModule.verifyHostProtectedStorePath({
    root: locations.hostRoot,
    path: target,
    directory,
  });
  const installationStore = installationModule.createNeutralHostInstallationStore({
    root: locations.hostRoot,
    readOnly: true,
    verifyPath,
  });
  const installationStatus = await installationStore.status();
  const activeInstallations = installationStatus.installations.filter((item) => item.state === "active");
  if (activeInstallations.length !== 1) fail("hellolynk_npm_binding_invalid");
  const installation = activeInstallations[0];
  const store = protectedModule.createHostProtectedStore({
    root: locations.hostRoot,
    installationStore,
    readOnly: true,
  });
  const binding = metadata.client === "codex"
    ? await store.verifyCodexNeutralBinding()
    : await store[{
        openclaw: "verifyOpenClawNeutralBinding",
        "trae-work": "verifyTraeWorkNeutralBinding",
        workbuddy: "verifyWorkBuddyNeutralBinding",
        cursor: "verifyCursorNeutralBinding",
        dsh: "verifyDshNeutralBinding",
      }[metadata.client]]({ profileId: metadata.profileId });
  // Parse the shared store with the pinned candidate, but keep the target
  // package's exact contract. A newer sibling does not change this target's scopes.
  const targetModule = await importStableCore(packageRoot, "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
  const expectedScopes = targetModule[{
    codex: "HELLOLYNK_CODEX_NEUTRAL_EXACT_SCOPES",
    openclaw: "HELLOLYNK_OPENCLAW_NEUTRAL_EXACT_SCOPES",
    "trae-work": "HELLOLYNK_TRAE_WORK_NEUTRAL_EXACT_SCOPES",
    workbuddy: "HELLOLYNK_WORKBUDDY_NEUTRAL_EXACT_SCOPES",
    cursor: "HELLOLYNK_CURSOR_NEUTRAL_EXACT_SCOPES",
    dsh: "HELLOLYNK_DSH_NEUTRAL_EXACT_SCOPES",
  }[metadata.client]];
  const transport = await store.verifyTransport({
    principalId: installation.principalId,
    hostInstallationId: installation.hostInstallationId,
  });
  if (binding?.adapterId !== metadata.client || binding?.profileId !== metadata.profileId
    || binding?.version !== 2 || binding?.capability?.state !== "active"
    || binding.capability?.version !== 2
    || path.resolve(binding.runtimeRoot || ".") !== path.join(locations.hostRoot, "runtime")
    || path.resolve(binding.releaseRoot || ".") !== releaseRoot
    || binding.releaseManifestSha256 !== release.manifestSha256
    || binding.runnerRelativePath !== "runtime/neutral-host-bootstrap.mjs"
    || path.resolve(binding.profileManifestPath || ".") !== activation.profileManifest
    || !sameStrings(binding.scopes, expectedScopes)
    || !sameStrings(binding.capability?.scopes, expectedScopes)
    || binding.principalId !== installation.principalId
    || binding.hostInstallationId !== installation.hostInstallationId
    || binding.capability?.principalId !== installation.principalId
    || binding.capability?.hostInstallationId !== installation.hostInstallationId
    || transport.credential?.principalId !== installation.principalId
    || transport.credential?.hostInstallationId !== installation.hostInstallationId
    || (transport.session !== null && (
      transport.session.principalId !== installation.principalId
      || transport.session.hostInstallationId !== installation.hostInstallationId
    ))) {
    fail("hellolynk_npm_binding_invalid");
  }
  return binding;
}

function bindingOwner(binding) {
  return Object.fromEntries(["region", "principalId", "delegateId", "hostInstallationId", "profileId", "adapterId", "version", "runtimeRoot"]
    .map((key) => [key, binding[key]]));
}

async function verifyClientConfiguration(context, { verifyNativeService = true } = {}) {
  // The native binding and Cursor's explicit-setup Skill are separate checks.
  // Doctor never installs a missing Skill or writes global client settings.
  if (isNativeClient()) {
    if (metadata.client === "cursor") {
      const skill = await preflightCursorSkill(context);
      await skill.module.verifyInstalledClientSkill({ source: skill.plan.targets[0].source,
        destination: skill.plan.targets[0].destination, trustedAnchor: skill.plan.targets[0].trustedAnchor });
      const plugin = await preflightCursorPlugin(context, { verifyOnly: true });
      await plugin.module.verifyCursorPlugin(plugin.plan);
    }
    return true;
  }
  if (metadata.client === "codex") return verifyCodexConfiguration(context);
  if (metadata.client === "openclaw") return verifyOpenClawConfiguration(context);
  await verifyMcpConfiguration(context);
  if (metadata.client === "workbuddy") {
    await configureWorkBuddyPageTask(context, "Verify");
    if (verifyNativeService) await updateWorkBuddyNativeService(context, "Verify");
  }
  return true;
}

async function configureWorkBuddyPageTask({ packageRoot, releaseRoot, release, locations }, operation) {
  // Keep all previous-package byte/config checks, but inspect its task through
  // this verified installer's driver instead of an obsolete CIM query.
  const module = await importLocal(operation === "Verify" ? PACKAGE_ROOT : packageRoot, "integrations/workbuddy/server/workbench-process.mjs", "hellolynk_npm_workbuddy_page_service_invalid");
  return module.configureWorkBuddyWorkbenchTask({ root: releaseRoot, expectedManifestSha256: release.outerManifestSha256, storeRoot: locations.hostRoot }, operation);
}

async function updateWorkBuddyNativeService({ releaseRoot, release, locations }, operation, installIfMissing = false) {
  // Use the current installer for a rollback target too. Older immutable
  // packages may predate this reconciliation entry point.
  const module = await importLocal(PACKAGE_ROOT, "integrations/workbuddy/server/workbench-process.mjs", "hellolynk_npm_workbuddy_page_service_invalid");
  return module.updateRecordedWorkBuddyNativeTaskService({ root: releaseRoot,
    expectedManifestSha256: release.outerManifestSha256, storeRoot: locations.hostRoot, installIfMissing }, operation);
}

async function verifyCodexConfiguration({ packageRoot, releaseRoot, locations }) {
  const marketplace = "hellolynk-npm-codex";
  const code = "hellolynk_npm_config_invalid";
  const configPath = path.join(locations.codexHome, "config.toml");
  await assertCanonicalDirectoryChain(locations.codexHome, path.dirname(configPath), code);
  const configBytes = await readRegularFile(configPath, code, true);
  if (configBytes.length > MAX_JSON_BYTES) fail(code);
  const tables = parseCodexConfiguration(configBytes.toString("utf8"), code);
  if (tables.marketplace.sourceType !== "local"
    || !path.isAbsolute(String(tables.marketplace.source || ""))
    || !samePath(tables.marketplace.source, packageRoot)
    || tables.plugin.enabled !== true) fail(code);

  const sourceManifest = await readJson(
    path.join(releaseRoot, ".codex-plugin", "plugin.json"),
    code,
    true,
  );
  const version = String(sourceManifest?.version || "");
  if (sourceManifest?.name !== "hellolynk-codex"
    || !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/u.test(version)) fail(code);
  const cacheParent = path.join(
    locations.codexHome,
    "plugins",
    "cache",
    marketplace,
    "hellolynk-codex",
  );
  await assertCanonicalDirectoryChain(locations.codexHome, cacheParent, code);
  // Windows may retain a locked, empty directory from a removed version. Check
  // the version Codex actually selects, then verify every installed byte.
  const plugins = runCodexJson(
    ["plugin", "list", "--marketplace", marketplace, "--json"], code, locations.codexHome,
  );
  if (!Array.isArray(plugins?.installed)) fail(code);
  const selected = plugins.installed.filter((item) => item?.pluginId === `hellolynk-codex@${marketplace}`);
  if (selected.length !== 1 || selected[0].enabled !== true || selected[0].version !== version
    || !samePath(String(selected[0].source?.path || ""), releaseRoot)) fail(code);
  const cacheRoot = path.join(cacheParent, version);
  await verifyExactRegularTree(releaseRoot, cacheRoot, locations.codexHome, code);
  return true;
}

async function verifyOpenClawConfiguration({ packageRoot, locations }) {
  const config = await readJson(
    path.join(locations.home, ".openclaw", "openclaw.json"),
    "hellolynk_npm_config_invalid",
  );
  const channel = config?.channels?.hellolynk;
  const configurator = await importLocal(packageRoot, metadata.configurator, "hellolynk_npm_configurator_invalid");
  let expectedChannel;
  try { expectedChannel = configurator.buildOpenClawChannelConfig(channel?.nativeModel); }
  catch { fail("hellolynk_npm_config_invalid"); }
  const pluginPath = path.resolve(packageRoot, metadata.pluginPath);
  const paths = config?.plugins?.load?.paths;
  const helloLynkPluginPaths = [];
  const legacyPluginPaths = [];
  if (Array.isArray(paths)) {
    for (const configuredPath of paths) {
      const absolute = path.resolve(String(configuredPath || ""));
      const manifest = await readJson(path.join(absolute, "openclaw.plugin.json"), "hellolynk_npm_config_invalid")
        .catch(() => null);
      if (manifest?.id === "hellolynk") helloLynkPluginPaths.push(absolute);
      if (isLegacyOpenClawPluginPath(absolute)) legacyPluginPaths.push(absolute);
    }
  }
  if (!channel || Object.keys(channel).sort().join(",") !== Object.keys(expectedChannel).sort().join(",")
    || channel.enabled !== true || channel.hostMode !== "neutral"
    || channel.bindingRef !== "protected-store:openclaw"
    || !Array.isArray(paths) || paths.filter((item) => path.resolve(String(item || "")) === pluginPath).length !== 1
    || helloLynkPluginPaths.length !== 1 || helloLynkPluginPaths[0] !== pluginPath
    || legacyPluginPaths.length !== 0
    || Object.hasOwn(config?.channels || {}, "lynk")
    || Object.hasOwn(config?.plugins?.entries || {}, "lynk")
    || config?.plugins?.entries?.hellolynk?.enabled !== true) {
    fail("hellolynk_npm_config_invalid");
  }
  return true;
}

async function verifyMcpConfiguration({ packageRoot, releaseRoot, release, locations }) {
  const configPaths = metadata.client === "trae-work"
    ? await traeConfigPaths(locations.appData)
    : await workBuddyConfigPaths(locations.home);
  const entry = path.join(packageRoot, metadata.entry);
  const expectedArgs = metadata.client === "trae-work"
    ? [entry, "run", "--expected-manifest-sha256", release.manifestSha256]
    : [entry, "run", "--root", releaseRoot, "--expected-manifest-sha256", release.outerManifestSha256];
  for (const configPath of configPaths) {
    const config = await readJson(configPath, "hellolynk_npm_config_invalid");
    const server = config?.mcpServers?.hellolynk;
    if (!isHelloLynkMcpServerShape(metadata.client, server)
      || path.resolve(String(server.command || "")) !== path.resolve(process.execPath)
      || !sameStrings(server.args, expectedArgs)
      || Object.keys(server.env || {}).sort().join(",") !== "HELLOLYNK_NEUTRAL_STORE_ROOT"
      || path.resolve(String(server.env.HELLOLYNK_NEUTRAL_STORE_ROOT || "")) !== locations.hostRoot
      || Object.hasOwn(config.mcpServers, "lynk")) fail("hellolynk_npm_config_invalid");
  }
  if (metadata.skillTarget) {
    // Check the installed skill with this verified installer's path rules;
    // packageRoot still supplies the previously pinned expected skill bytes.
    const skillModule = await importLocal(
      PACKAGE_ROOT,
      "tools/hellolynk-install-client-skills.mjs",
      "hellolynk_npm_skill_installer_invalid",
    );
    const plan = await skillModule.installClientSkills({
      sourceRoot: packageRoot,
      home: locations.home,
      appData: locations.appData,
      localAppData: locations.localAppData,
      target: metadata.skillTarget,
      apply: false,
    });
    if (!Array.isArray(plan?.targets) || plan.targets.length !== 1) fail("hellolynk_npm_config_invalid");
    await skillModule.verifyInstalledClientSkill({
      source: plan.targets[0].source,
      destination: plan.targets[0].destination,
      trustedAnchor: plan.targets[0].trustedAnchor,
    })
      .catch(() => fail("hellolynk_npm_config_invalid"));
  }
  return true;
}

async function importStableCore(packageRoot, name, code) {
  return importLocal(packageRoot, path.posix.join(metadata.coreRoot.replaceAll("\\", "/"), name), code);
}

function sameStrings(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length && left.every((value, index) => value === right[index]);
}

function isSameOrDescendant(candidate, root) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

async function inspectActivation(hostRoot, profileId) {
  const profileManifest = path.join(hostRoot, "profile-manifest-v1.json");
  let value;
  try { value = await readJson(profileManifest, "hellolynk_npm_existing_host_activation_required"); }
  catch { return Object.freeze({ ready: false, state: "missing", profileManifest }); }
  if (value?.contract !== "hellolynk-neutral-host-profile-manifest-v1" || !Array.isArray(value.profiles)) {
    return Object.freeze({ ready: false, state: "invalid", profileManifest });
  }
  const ready = value.profiles.some((item) => path.basename(String(item || "")) === `${profileId}.json`);
  return Object.freeze({ ready, state: ready ? "ready" : "client_profile_missing", profileManifest });
}

async function initializeHost(locations, packageRoot) {
  const module = await importStableCore(
    packageRoot,
    "hellolynk-neutral-host-installation-store.mjs",
    "hellolynk_npm_activation_runtime_invalid",
  );
  return module.createNeutralHostInstallationStore({ root: locations.hostRoot }).createId();
}

async function hasHostTransport(locations, packageRoot) {
  const installationModule = await importStableCore(
    packageRoot,
    "hellolynk-neutral-host-installation-store.mjs",
    "hellolynk_npm_activation_runtime_invalid",
  );
  const protectedModule = await importStableCore(
    packageRoot,
    "hellolynk-host-protected-store.mjs",
    "hellolynk_npm_activation_runtime_invalid",
  );
  const installationStore = installationModule.createNeutralHostInstallationStore({ root: locations.hostRoot });
  const store = protectedModule.createHostProtectedStore({ root: locations.hostRoot, installationStore });
  try {
    await store.resolveTransport();
    return true;
  } catch (error) {
    if (String(error?.code || error?.message) === "host_transport_credential_required") return false;
    throw error;
  }
}

async function importCore(name, code) {
  const coreRoot = path.resolve(PACKAGE_ROOT, metadata.coreRoot);
  const file = path.resolve(coreRoot, name);
  if (path.dirname(file) !== coreRoot) fail(code);
  await readRegularFile(file, code);
  return import(pathToFileURL(file).href);
}

async function activateBinding(context) {
  const { packageRoot, releaseRoot, release, locations, activation } = context;
  if (["codex", "dsh"].includes(metadata.client) && context.packageClosure
    && (context.recoveryPrevious || context.packageClosure.manifestSha256 !== candidateClosure.manifestSha256)) {
    return activateCompatibleRecoveryBinding(context);
  }
  const tool = path.join(packageRoot, metadata.activationTool);
  await readRegularFile(tool, "hellolynk_npm_activation_tool_invalid");
  const result = spawnSync(process.execPath, [
    tool,
    "--client", metadata.client,
    "--final-current-root", locations.finalCurrentRoot,
    "--root", locations.hostRoot,
    "--release-current-root", locations.releaseCurrentRoot || locations.finalCurrentRoot,
    "--release-root", releaseRoot,
    "--expected-release-manifest-sha256", release.manifestSha256,
    "--profile-manifest", activation.profileManifest,
  ], { encoding: "utf8", windowsHide: true, shell: false, env: minimalEnv() });
  if (result.status !== 0) fail(codeFromOutput(result.stderr, "hellolynk_npm_binding_activation_failed"));
}

async function activateCompatibleRecoveryBinding(context) {
  // The previous package is immutable. Never run its obsolete shared-store
  // parser or accept a caller-supplied helper. Recheck both pinned closures
  // immediately before this recovery mutation.
  await verifyPackageClosure(PACKAGE_ROOT, candidateClosure.manifestSha256);
  const target = await inspectTrustedPackageRoot({ ...context,
    currentPackageRoot: path.join(path.dirname(context.packageRoot), `${metadata.client}-${candidateClosure.manifestSha256}`) });
  if (target.packageClosure.manifestSha256 !== context.packageClosure.manifestSha256
    || target.release.manifestSha256 !== context.release.manifestSha256) fail("hellolynk_npm_previous_install_invalid");
  const anchorContext = context.recoveryPrevious || context;
  const anchor = await inspectTrustedPackageRoot({ ...anchorContext,
    currentPackageRoot: path.join(path.dirname(context.packageRoot), `${metadata.client}-${candidateClosure.manifestSha256}`) });
  if (anchor.packageClosure.manifestSha256 !== anchorContext.packageClosure.manifestSha256
    || anchor.release.manifestSha256 !== anchorContext.release.manifestSha256) fail("hellolynk_npm_previous_install_invalid");
  const reader = await importStableCore(PACKAGE_ROOT, "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
  const targetModule = await importStableCore(target.packageRoot, "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
  const scopes = targetModule[`HELLOLYNK_${metadata.client.toUpperCase()}_NEUTRAL_EXACT_SCOPES`];
  const anchorModule = await importStableCore(anchor.packageRoot, "hellolynk-host-protected-store.mjs", "hellolynk_npm_binding_invalid");
  const anchorScopes = anchorModule[`HELLOLYNK_${metadata.client.toUpperCase()}_NEUTRAL_EXACT_SCOPES`];
  const exact = reader[`HELLOLYNK_${metadata.client.toUpperCase()}_NEUTRAL_EXACT_SCOPES`];
  const previousScopes = exact.filter((scope) => scope !== "app-data:authorized-messaging");
  if ([scopes, anchorScopes].some((value) => !sameStrings(value, exact) && !sameStrings(value, previousScopes))) {
    fail("hellolynk_npm_previous_scope_contract_invalid");
  }
  const store = reader.createHostProtectedStore({ root: context.locations.hostRoot, readOnly: context.recoveryCheckOnly === true });
  const suffix = metadata.client === "codex" ? "Codex" : "Dsh";
  const binding = await store[`verify${suffix}NeutralBinding`]({ profileId: metadata.profileId });
  const keys = ["contract", "region", "principalId", "delegateId", "hostInstallationId", "profileId", "adapterId", "version",
    "scopes", "runtimeRoot", "releaseRoot", "releaseManifestSha256", "runnerRelativePath", "profileManifestPath"];
  const previousBinding = Object.fromEntries(keys.map((key) => [key, binding[key]]));
  const candidateReleaseRoot = path.resolve(path.dirname(target.packageRoot),
    `${metadata.client}-${candidateClosure.manifestSha256}`, metadata.releaseRoot);
  const candidateRelease = await verifyRelease(path.resolve(PACKAGE_ROOT, metadata.releaseRoot), PACKAGE_ROOT);
  if (binding.profileId !== metadata.profileId || binding.adapterId !== metadata.client
    || !context.expectedOwner || stableJson(bindingOwner(binding)) !== stableJson(context.expectedOwner)
    || !samePath(binding.runtimeRoot, path.join(context.locations.hostRoot, "runtime"))
    || !((samePath(binding.releaseRoot, anchor.releaseRoot) && binding.releaseManifestSha256 === anchor.release.manifestSha256
        && sameStrings(binding.scopes, anchorScopes))
      || (samePath(binding.releaseRoot, candidateReleaseRoot) && binding.releaseManifestSha256 === candidateRelease.manifestSha256
        && sameStrings(binding.scopes, exact)))) {
    fail("hellolynk_npm_binding_invalid");
  }
  if (context.recoveryCheckOnly === true) return;
  const replacementBinding = { ...previousBinding, scopes: [...scopes], releaseRoot: target.releaseRoot,
    releaseManifestSha256: target.release.manifestSha256, runnerRelativePath: "runtime/neutral-host-bootstrap.mjs",
    profileManifestPath: context.activation.profileManifest };
  if (stableJson(previousBinding) === stableJson(replacementBinding)) return;
  if (metadata.client === "codex" && sameStrings(binding.scopes, scopes)) {
    await store.replaceCodexNeutralBinding({ previousBinding, replacementBinding: { ...replacementBinding, allowLegacyScopes: true } });
  } else {
    const method = metadata.client === "dsh" && sameStrings(scopes, previousScopes)
      ? "restoreDshNeutralBinding" : `migrate${suffix}NeutralBinding`;
    const migrated = await store[method]({ previousBinding,
      replacementBinding: { ...replacementBinding, ...(metadata.client === "codex" ? { allowLegacyScopes: true } : {}) },
      previousCapabilityId: binding.capability.capabilityId });
    migrated.capability?.secretBuffer?.fill?.(0);
  }
}

async function preflightClientConfiguration(context) {
  if (isNativeClient()) return Object.freeze({ kind: "native", profileId: metadata.profileId,
    bindingRef: `protected-store:${metadata.client}`,
    ...(metadata.client === "cursor" ? { skill: await preflightCursorSkill(context), plugin: await preflightCursorPlugin(context) } : {}) });
  if (metadata.client === "codex") return preflightCodexMarketplace(context);
  if (metadata.client === "openclaw") return preflightOpenClaw(context);
  return preflightMcpClient(context);
}

async function preflightCursorSkill({ packageRoot, locations, previousCursorPackage }) {
  const module = await importLocal(PACKAGE_ROOT, "tools/hellolynk-install-client-skills.mjs", "hellolynk_npm_skill_installer_invalid");
  const options = Object.freeze({ sourceRoot: packageRoot, home: locations.home,
    appData: locations.appData, localAppData: locations.localAppData, target: "cursor",
    ...(previousCursorPackage ? { previousSourceRoot: previousCursorPackage.packageRoot } : {}) });
  const plan = await module.installClientSkills({ ...options, apply: false });
  if (!/^[a-f0-9]{64}$/.test(String(plan?.fingerprint || ""))
    || plan.targets?.length !== 1 || plan.targets[0].target !== "cursor") {
    fail("hellolynk_npm_skill_installer_invalid");
  }
  return Object.freeze({ module, options, plan });
}

async function preflightCursorPlugin(context, { verifyOnly = false } = {}) {
  const module = await importLocal(PACKAGE_ROOT, "tools/hellolynk-install-cursor-plugin.mjs", "hellolynk_npm_cursor_plugin_installer_invalid");
  const plan = await module.prepareCursorPlugin({ sourceRoot: context.packageRoot, home: context.locations.home,
    appData: context.locations.appData, localAppData: context.locations.localAppData, nodePath: process.execPath,
    migrateExistingPermissions: migrateCursorPermissions && !verifyOnly, useInstalledNode: verifyOnly,
    // Only the already verified previous package may lack the new plugin.
    allowLegacy: context.installedPreviousRelease === true });
  return { module, plan };
}

async function preflightBindingActivation({
  packageRoot, releaseRoot, release, locations, activation, preBind = false,
}) {
  const tool = path.join(packageRoot, metadata.activationTool);
  await readRegularFile(tool, "hellolynk_npm_activation_tool_invalid");
  const result = spawnSync(process.execPath, [
    tool,
    "--client", metadata.client,
    "--final-current-root", locations.finalCurrentRoot,
    "--root", locations.hostRoot,
    "--release-current-root", locations.releaseCurrentRoot || locations.finalCurrentRoot,
    "--release-root", releaseRoot,
    "--expected-release-manifest-sha256", release.manifestSha256,
    "--profile-manifest", activation.profileManifest,
    "--preflight", "true",
    ...(preBind ? ["--pre-bind", "true"] : []),
  ], { encoding: "utf8", windowsHide: true, shell: false, env: minimalEnv() });
  if (result.status !== 0) {
    fail(codeFromOutput(result.stderr, "hellolynk_npm_binding_preflight_failed"));
  }
  let verified;
  try { verified = JSON.parse(result.stdout); }
  catch { fail("hellolynk_npm_binding_preflight_invalid"); }
  const clients = Array.isArray(verified?.clients) ? verified.clients : [];
  if (verified?.ok !== true || verified.preflight !== true || verified.preBind !== preBind
    || verified.readOnly !== true
    || verified.protected !== true || verified.releaseManifestSha256 !== release.manifestSha256
    || !Number.isInteger(verified.verifiedReleaseFileCount) || verified.verifiedReleaseFileCount < 8
    || clients.length !== 1 || clients[0]?.adapterId !== metadata.client
    || clients[0]?.bindingUpdated !== false) {
    fail("hellolynk_npm_binding_preflight_invalid");
  }
  const freshPreBind = preBind && verified.installationState === "unclaimed";
  if (freshPreBind) {
    if (verified.profileManifestState !== "deferred"
      || verified.bootstrapTransportRequired !== true
      || verified.transportCredentialState !== "bootstrap_required"
      || clients[0].profileId !== null
      || clients[0].delegatePresent !== false
      || clients[0].bindingPresent !== false
      || clients[0].bindingState !== "awaiting_delegate_binding"
      || clients[0].plannedMutation !== "deferred") {
      fail("hellolynk_npm_binding_preflight_invalid");
    }
  } else if (verified.installationState !== "active"
    || verified.profileManifestState !== "verified"
    || verified.bootstrapTransportRequired !== false
    || verified.transportCredentialState !== "active") {
    fail("hellolynk_npm_binding_preflight_invalid");
  }
  if (isNativeClient() && clients[0].profileId !== null && clients[0].profileId !== metadata.profileId) {
    fail("hellolynk_native_existing_profile_conflict");
  }
  if (isNativeClient() && !freshPreBind && clients[0].profileId === null
    && (!preBind || clients[0].delegatePresent !== false || clients[0].bindingPresent !== false
      || clients[0].bindingState !== "awaiting_delegate_binding" || clients[0].plannedMutation !== "deferred")) {
    fail("hellolynk_npm_binding_preflight_invalid");
  }
  return Object.freeze({
    ready: true,
    freshPreBind,
    bindingState: String(clients[0].bindingState || "unknown"),
  });
}

async function configureClient(context, prepared, { bindingContext = context } = {}) {
  if (isNativeClient()) {
    if (prepared?.kind !== "native" || prepared.profileId !== metadata.profileId
      || prepared.bindingRef !== `protected-store:${metadata.client}`) fail("hellolynk_npm_configuration_preflight_required");
    const activation = await inspectActivation(context.locations.hostRoot, metadata.profileId);
    await verifyExactBinding({ ...bindingContext, activation });
    let skillReceipt, pluginReceipt;
    if (metadata.client === "cursor") {
      if (!prepared.skill || !prepared.plugin) fail("hellolynk_npm_configuration_preflight_required");
      const installed = await prepared.skill.module.installClientSkills({ ...prepared.skill.options,
        apply: true, expectedPlanFingerprint: prepared.skill.plan.fingerprint });
      skillReceipt = installed.targets[0].receipt;
      if (skillReceipt?.contract !== "hellolynk-cursor-skill-install-receipt-v1") {
        fail("hellolynk_npm_skill_installer_invalid");
      }
      pluginReceipt = await prepared.plugin.module.installCursorPlugin(prepared.plugin.plan);
    }
    return Object.freeze({ bindingRef: prepared.bindingRef, profileId: metadata.profileId,
      ...(skillReceipt ? { skillInstalled: true, skillReceipt, pluginReceipt } : {}) });
  }
  if (metadata.client === "codex") return configureCodexMarketplace(context, prepared);
  if (metadata.client === "openclaw") return configureOpenClaw(context, prepared);
  return configureMcpClient(context, prepared);
}

async function preflightCodexMarketplace({ packageRoot, locations }) {
  const marketplace = "hellolynk-npm-codex";
  const listed = runCodexJson(
    ["plugin", "marketplace", "list", "--json"],
    "hellolynk_npm_codex_marketplace_list_failed",
    locations.codexHome,
  );
  if (!Array.isArray(listed?.marketplaces)) fail("hellolynk_npm_codex_marketplace_list_invalid");
  const matches = listed.marketplaces.filter((item) => item?.name === marketplace);
  if (matches.length > 1) fail("hellolynk_npm_codex_marketplace_list_invalid");
  const existing = matches[0] || null;
  if (existing && path.resolve(String(existing.root || "")) !== packageRoot) {
    const previous = await inspectTrustedCodexInstallation({
      packageRoot: path.resolve(String(existing.root || "")),
      currentPackageRoot: packageRoot,
      locations,
    });
    return Object.freeze({
      kind: "codex",
      marketplace,
      existing: true,
      upgrade: true,
      previous,
    });
  }
  return Object.freeze({ kind: "codex", marketplace, existing: existing !== null, upgrade: false });
}

async function configureCodexMarketplace(context, prepared) {
  const { packageRoot, locations } = context;
  if (prepared?.kind !== "codex") fail("hellolynk_npm_configuration_preflight_required");
  if (prepared.upgrade === true) fail("hellolynk_npm_codex_upgrade_transaction_required");
  const marketplace = prepared.marketplace;
  const listed = runCodexJson(
    ["plugin", "marketplace", "list", "--json"],
    "hellolynk_npm_codex_marketplace_list_failed",
    locations.codexHome,
  );
  if (!Array.isArray(listed?.marketplaces)) fail("hellolynk_npm_codex_marketplace_list_invalid");
  const matches = listed.marketplaces.filter((item) => item?.name === marketplace);
  if (matches.length > 1) fail("hellolynk_npm_codex_marketplace_list_invalid");
  const existing = matches[0] || null;
  if (existing && !samePath(String(existing.root || ""), packageRoot)) {
    fail("hellolynk_npm_configuration_changed_since_preflight");
  }
  if (!existing) runCodex(
    ["plugin", "marketplace", "add", packageRoot],
    "hellolynk_npm_codex_marketplace_add_failed",
    locations.codexHome,
  );
  await ensureExactCodexPluginConfiguration(context);
  return Object.freeze({ marketplace, plugin: "hellolynk-codex", installed: true });
}

async function ensureExactCodexPluginConfiguration(context) {
  // A running Codex can already select this exact package while holding its
  // cache open. Do not ask the CLI to back up and replace those verified bytes.
  try { await verifyCodexConfiguration(context); return; }
  catch { /* An incomplete state still needs the official installation entry. */ }
  let installError = null;
  try {
    runCodex(
      ["plugin", "add", "hellolynk-codex@hellolynk-npm-codex", "--json"],
      "hellolynk_npm_codex_plugin_add_failed",
      context.locations.codexHome,
    );
  } catch (error) { installError = error; }
  // CLI failure can follow a completed selection/cache update. Only the full
  // configuration, source, selected version and exact cache tree prove success;
  // a partial result retains the original error and normal recovery behavior.
  try { await verifyCodexConfiguration(context); }
  catch (error) { throw installError || error; }
}

async function inspectTrustedCodexInstallation({ packageRoot, currentPackageRoot, locations }) {
  const code = "hellolynk_npm_codex_previous_install_invalid";
  const releasesRoot = path.dirname(currentPackageRoot);
  const stableLocations = Object.freeze({ ...locations, finalCurrentRoot: path.dirname(releasesRoot) });
  if (path.basename(releasesRoot).toLowerCase() !== "releases"
    || !samePath(path.dirname(packageRoot), releasesRoot)) fail(code);
  const relative = path.relative(releasesRoot, packageRoot);
  const match = /^codex-([a-f0-9]{64})$/u.exec(relative);
  if (!match || path.dirname(relative) !== "." || path.resolve(packageRoot) !== packageRoot) fail(code);
  await secureStableReleaseTree(stableLocations, path.basename(packageRoot), { verifyOnly: true }).catch(() => fail(code));
  const previousPackageJson = await readJson(path.join(packageRoot, "package.json"), code, true);
  const previousMetadata = previousPackageJson?.hellolynkClient;
  if (previousPackageJson?.name !== "@hellolynk-ai/codex-plugin"
    || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$/u.test(String(previousPackageJson.version || ""))
    || !isTrustedCodexMetadata(previousMetadata)) fail(code);
  const closure = await verifyPackageClosure(packageRoot, match[1], {
    packageJson: previousPackageJson,
    metadata: previousMetadata,
  }).catch(() => fail(code));
  const marketplaceRecord = await readJson(
    path.join(packageRoot, ".agents", "plugins", "marketplace.json"), code, true,
  );
  const plugins = Array.isArray(marketplaceRecord?.plugins) ? marketplaceRecord.plugins : [];
  if (marketplaceRecord?.name !== "hellolynk-npm-codex" || plugins.length !== 1
    || plugins[0]?.name !== "hellolynk-codex"
    || plugins[0]?.source?.source !== "local"
    || plugins[0]?.source?.path !== "./plugins/hellolynk-codex") fail(code);
  const releaseRoot = path.join(packageRoot, ...previousMetadata.releaseRoot.split("/"));
  const release = await verifyRelease(releaseRoot, packageRoot, previousMetadata).catch(() => fail(code));
  const pluginManifest = await readJson(
    path.join(releaseRoot, ".codex-plugin", "plugin.json"), code, true,
  );
  if (pluginManifest?.name !== "hellolynk-codex"
    || !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/u.test(String(pluginManifest.version || ""))) fail(code);
  const activation = await inspectActivation(locations.hostRoot, previousMetadata.profileId);
  if (!activation.ready) fail(code);
  const previous = Object.freeze({
    packageRoot,
    releaseRoot,
    release,
    locations,
    packageClosure: closure,
    packageJson: previousPackageJson,
    metadata: previousMetadata,
    activation,
  });
  const binding = await verifyExactBinding({ ...previous, locations, activation }).catch(() => fail(code));
  await verifyCodexConfiguration({ ...previous, locations }).catch(() => fail(code));
  return Object.freeze({ ...previous, expectedOwner: bindingOwner(binding) });
}

async function inspectTrustedPackageRoot({ packageRoot, currentPackageRoot, locations, activation }) {
  const code = "hellolynk_npm_previous_install_invalid";
  const releasesRoot = path.dirname(currentPackageRoot);
  const stableLocations = Object.freeze({ ...locations, finalCurrentRoot: path.dirname(releasesRoot) });
  if (path.basename(releasesRoot).toLowerCase() !== "releases"
    || !samePath(path.dirname(packageRoot), releasesRoot)) fail(code);
  const relative = path.relative(releasesRoot, packageRoot);
  const match = new RegExp(`^${metadata.client}-([a-f0-9]{64})$`, "u").exec(relative);
  if (!match || path.dirname(relative) !== "." || path.resolve(packageRoot) !== packageRoot) fail(code);
  await secureStableReleaseTree(stableLocations, path.basename(packageRoot), { verifyOnly: true }).catch(() => fail(code));
  const previousPackageJson = await readJson(path.join(packageRoot, "package.json"), code, true);
  const previousMetadata = previousPackageJson?.hellolynkClient;
  // TRAE's merged client uses the same global Skill source and destination.
  // Accept the installed SOLO target name only; every other package field and
  // the pinned payload/configuration must still match and verify below.
  const comparableMetadata = metadata.client === "trae-work" && metadata.skillTarget === "trae"
    && previousMetadata?.skillTarget === "trae-solo"
    ? { ...previousMetadata, skillTarget: "trae" } : previousMetadata;
  if (previousPackageJson?.name !== packageJson.name
    || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$/u.test(String(previousPackageJson.version || ""))
    || stableJson(comparableMetadata) !== stableJson(metadata)) fail(code);
  const closure = await verifyPackageClosure(packageRoot, match[1], {
    packageJson: previousPackageJson,
    metadata: previousMetadata,
    // The authenticated installed package may predate Desktop Bridge setup.
    // Its own pinned manifest/tree still has to verify in full; new packages
    // continue to require the bridge helper above.
    installedPreviousRelease: true,
  }).catch(() => fail(code));
  const releaseRoot = path.resolve(packageRoot, previousMetadata.releaseRoot);
  if (!isSameOrDescendant(releaseRoot, packageRoot)) fail(code);
  const release = await verifyRelease(releaseRoot, packageRoot, previousMetadata).catch(() => fail(code));
  return Object.freeze({
    packageRoot,
    releaseRoot,
    release,
    locations,
    activation,
    packageClosure: closure,
    packageJson: previousPackageJson,
    metadata: previousMetadata,
    installedPreviousRelease: true,
  });
}

async function inspectPreviousOrAbsent(current) {
  return inspectTrustedCurrentBindingPackage(current).catch((error) => {
    // A missing binding can be initialized. Invalid package/configuration
    // cannot silently discard the previous recovery point.
    if (new Set([`neutral_${metadata.client.replaceAll("-", "_")}_binding_configuration_required`,
      `neutral_${metadata.client.replaceAll("-", "_")}_capability_missing`]).has(error?.code || error?.message)) return null;
    throw error;
  });
}

async function inspectTrustedCurrentBindingPackage(current) {
  const binding = await resolveProtectedClientBinding(current);
  const releaseRoot = path.resolve(String(binding?.releaseRoot || ""));
  if (samePath(releaseRoot, current.releaseRoot)) {
    // Reinstalling this exact package may repair its client configuration.
    // There is no different previous package to restore in that case.
    await verifyExactBinding(current);
    return current;
  }
  let previousPackageRoot;
  if (metadata.releaseRoot === ".") {
    previousPackageRoot = releaseRoot;
  } else {
    const suffix = metadata.releaseRoot.split("/");
    previousPackageRoot = releaseRoot;
    for (let index = 0; index < suffix.length; index += 1) previousPackageRoot = path.dirname(previousPackageRoot);
    if (!samePath(path.resolve(previousPackageRoot, metadata.releaseRoot), releaseRoot)) {
      fail("hellolynk_npm_previous_install_invalid");
    }
  }
  const previous = await inspectTrustedPackageRoot({
    packageRoot: previousPackageRoot,
    currentPackageRoot: current.packageRoot,
    locations: current.locations,
    activation: current.activation,
  });
  const previousBinding = await verifyExactBinding(previous).catch(() => fail("hellolynk_npm_previous_install_invalid"));
  // A stale optional listener is repaired by setup, not a reason to block
  // upgrading otherwise intact account, package and MCP configuration.
  await verifyClientConfiguration(previous, { verifyNativeService: false }).catch(() => fail("hellolynk_npm_previous_install_invalid"));
  return Object.freeze({ ...previous, expectedOwner: bindingOwner(previousBinding) });
}

async function resolveProtectedClientBinding({ packageRoot, locations }) {
  const installationModule = await importStableCore(
    PACKAGE_ROOT,
    "hellolynk-neutral-host-installation-store.mjs",
    "hellolynk_npm_binding_invalid",
  );
  const protectedModule = await importStableCore(
    PACKAGE_ROOT,
    "hellolynk-host-protected-store.mjs",
    "hellolynk_npm_binding_invalid",
  );
  const verifyPath = ({ path: target, directory }) => protectedModule.verifyHostProtectedStorePath({
    root: locations.hostRoot,
    path: target,
    directory,
  });
  const installationStore = installationModule.createNeutralHostInstallationStore({
    root: locations.hostRoot,
    readOnly: true,
    verifyPath,
  });
  const store = protectedModule.createHostProtectedStore({
    root: locations.hostRoot,
    installationStore,
    readOnly: true,
  });
  return metadata.client === "codex"
    ? store.verifyCodexNeutralBinding()
    : store[{
        openclaw: "verifyOpenClawNeutralBinding",
        "trae-work": "verifyTraeWorkNeutralBinding",
        workbuddy: "verifyWorkBuddyNeutralBinding",
        cursor: "verifyCursorNeutralBinding",
        dsh: "verifyDshNeutralBinding",
      }[metadata.client]]({ profileId: metadata.profileId });
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function isTrustedCodexMetadata(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === "activationTool,client,coreRoot,profileId,releaseRoot,serviceBaseUrl"
    && value.client === "codex"
    && value.activationTool === "tools/hellolynk-activate-neutral-host-clients.mjs"
    && value.coreRoot === "plugins/hellolynk-codex/runtime/core"
    && value.profileId === "hellolynk-host-codex-v2"
    && value.releaseRoot === "plugins/hellolynk-codex"
    && value.serviceBaseUrl === "https://hellolynk.com";
}

async function upgradeCodexConfigurationAndBinding(current, prepared) {
  const previous = prepared?.previous;
  if (prepared?.kind !== "codex" || prepared.upgrade !== true
    || !previous || samePath(previous.packageRoot, current.packageRoot)) {
    fail("hellolynk_npm_codex_upgrade_transaction_required");
  }
  const allowedRoots = Object.freeze([previous.packageRoot, current.packageRoot]);
  let originalError = null;
  try {
    await switchCodexConfiguration(current, allowedRoots);
  } catch (error) {
    originalError = error;
    const recovered = await reconcileCodexUpgrade({ current, previous, allowedRoots, prefer: "previous" });
    if (recovered === "current") return codexConfiguredResult();
    if (recovered === "previous") {
      mutationRecoveryState = "none";
      throw originalError;
    }
    throw codexUpgradeOutcomeUncertain(originalError);
  }

  mutationRecoveryState = "protected_binding_update_attempted";
  try {
    await activateBinding(current);
    await verifyExactBinding(current);
    await verifyCodexConfiguration(current);
    mutationRecoveryState = "binding_committed_roll_forward_required";
    return codexConfiguredResult();
  } catch (error) {
    originalError = error;
    const recovered = await reconcileCodexUpgrade({ current, previous, allowedRoots, prefer: "previous" });
    if (recovered === "current") {
      mutationRecoveryState = "binding_committed_roll_forward_required";
      return codexConfiguredResult();
    }
    if (recovered === "previous") {
      mutationRecoveryState = "none";
      throw originalError;
    }
    throw codexUpgradeOutcomeUncertain(originalError);
  }
}

async function upgradeClientConfigurationAndBinding(current, previous, preparedConfiguration) {
  let originalError;
  mutationRecoveryState = "protected_binding_update_attempted";
  try {
    await activateBinding(current);
    mutationRecoveryState = "binding_committed_roll_forward_required";
    const configured = await configureClient(current, preparedConfiguration);
    await verifyExactBinding(current);
    await verifyClientConfiguration(current);
    return configured;
  } catch (error) {
    originalError = error;
  }
  const recovered = await reconcileClientUpgrade({ current, previous, preparedConfiguration, prefer: "previous" });
  if (recovered.state === "current") {
    mutationRecoveryState = "binding_committed_roll_forward_required";
    return recovered.configured;
  }
  if (recovered.state === "previous") {
    mutationRecoveryState = "none";
    throw originalError;
  }
  throw codexUpgradeOutcomeUncertain(originalError);
}

async function reconcileClientUpgrade({ current, previous, preparedConfiguration, prefer }) {
  const first = prefer === "current" ? current : previous;
  const second = prefer === "current" ? previous : current;
  for (const target of [first, second]) {
    try {
      const recoveryTarget = compatibleRecoveryTarget(target, previous);
      if (recoveryTarget.recoveryPrevious) await activateBinding({ ...recoveryTarget, recoveryCheckOnly: true });
      const configured = await establishClientState(recoveryTarget, preparedConfiguration, target === current ? previous : current);
      return Object.freeze({
        state: target === current ? "current" : "previous",
        configured,
      });
    } catch { /* try the other complete, verified state */ }
  }
  return Object.freeze({ state: "uncertain", configured: null });
}

function compatibleRecoveryTarget(target, previous) {
  if (!["codex", "dsh"].includes(metadata.client)) return target;
  return { ...target, packageClosure: target.packageClosure || candidateClosure,
    expectedOwner: previous.expectedOwner, recoveryPrevious: previous };
}

async function establishClientState(target, originalConfiguration, otherPackage) {
  if (isNativeClient()) {
    const prepared = await preflightClientConfiguration({ ...target, previousCursorPackage: otherPackage });
    await activateBinding(target);
    const configured = await configureClient(target, prepared);
    await verifyExactBinding(target);
    await verifyClientConfiguration(target);
    return configured;
  }
  const prepared = await preflightClientConfiguration(target);
  // Recovery may switch only between this transaction's original and proposed
  // bytes. A fresh preflight is not authorization to overwrite a later edit.
  const originalPlans = originalConfiguration.kind === "mcp"
    ? originalConfiguration.configs.map((item) => item.plan) : [originalConfiguration.plan];
  const recoveryPlans = prepared.kind === "mcp"
    ? prepared.configs.map((item) => item.plan) : [prepared.plan];
  if (recoveryPlans.length !== originalPlans.length) fail("hellolynk_npm_configuration_changed_since_preflight");
  for (const plan of recoveryPlans) {
    const original = originalPlans.find((item) => samePath(item.configPath, plan.configPath));
    if (!original || ![original.expectedConfigSha256, original.replacementSha256].includes(plan.expectedConfigSha256)) {
      fail("hellolynk_npm_configuration_changed_since_preflight");
    }
  }
  const configured = await configureClient(target, prepared);
  await activateBinding(target);
  await verifyExactBinding(target);
  await verifyClientConfiguration(target);
  return configured;
}

async function reconcileCodexUpgrade({ current, previous, allowedRoots, prefer }) {
  const first = prefer === "current" ? current : previous;
  const second = prefer === "current" ? previous : current;
  for (const target of [first, second]) {
    try {
      const recoveryTarget = compatibleRecoveryTarget(target, previous);
      await activateBinding({ ...recoveryTarget, recoveryCheckOnly: true });
      await switchCodexConfiguration(recoveryTarget, allowedRoots);
      await activateBinding(recoveryTarget);
      await verifyExactBinding(recoveryTarget);
      await verifyCodexConfiguration(recoveryTarget);
      return target === current ? "current" : "previous";
    } catch { /* try the other fully verified state */ }
  }
  return "uncertain";
}

async function switchCodexConfiguration(target, allowedRoots) {
  const marketplace = "hellolynk-npm-codex";
  const state = codexMarketplaceRoot(target.locations, marketplace);
  if (state !== null && !allowedRoots.some((root) => samePath(root, state))) {
    fail("hellolynk_npm_configuration_changed_since_preflight");
  }
  if (state !== null && !samePath(state, target.packageRoot)) {
    tryRunCodex(
      ["plugin", "remove", `hellolynk-codex@${marketplace}`, "--json"],
      target.locations.codexHome,
    );
    runCodex(
      ["plugin", "marketplace", "remove", marketplace, "--json"],
      "hellolynk_npm_codex_marketplace_remove_failed",
      target.locations.codexHome,
    );
  }
  const afterRemoval = codexMarketplaceRoot(target.locations, marketplace);
  if (afterRemoval !== null && !samePath(afterRemoval, target.packageRoot)) {
    fail("hellolynk_npm_codex_marketplace_remove_failed");
  }
  if (afterRemoval === null) runCodex(
    ["plugin", "marketplace", "add", target.packageRoot, "--json"],
    "hellolynk_npm_codex_marketplace_add_failed",
    target.locations.codexHome,
  );
  await ensureExactCodexPluginConfiguration(target);
}

function codexMarketplaceRoot(locations, marketplace) {
  const listed = runCodexJson(
    ["plugin", "marketplace", "list", "--json"],
    "hellolynk_npm_codex_marketplace_list_failed",
    locations.codexHome,
  );
  if (!Array.isArray(listed?.marketplaces)) fail("hellolynk_npm_codex_marketplace_list_invalid");
  const matches = listed.marketplaces.filter((item) => item?.name === marketplace);
  if (matches.length > 1) fail("hellolynk_npm_codex_marketplace_list_invalid");
  if (matches.length === 0) return null;
  const root = String(matches[0]?.root || "");
  if (!path.isAbsolute(root)) fail("hellolynk_npm_codex_marketplace_list_invalid");
  return path.resolve(root);
}

function tryRunCodex(args, codexHome) {
  try { runCodex(args, "hellolynk_npm_codex_cleanup_failed", codexHome); }
  catch { /* marketplace removal is authoritative and may repair a partial plugin state */ }
}

function codexConfiguredResult() {
  return Object.freeze({
    marketplace: "hellolynk-npm-codex",
    plugin: "hellolynk-codex",
    installed: true,
    upgraded: true,
  });
}

function codexUpgradeOutcomeUncertain(cause) {
  const error = new Error("local_configuration_outcome_uncertain", { cause });
  error.code = "local_configuration_outcome_uncertain";
  error.localConfigurationOutcomeUncertain = true;
  return error;
}

async function preflightOpenClaw({ packageRoot, releaseRoot, locations, allowUnconnected = false }) {
  const configPath = path.join(locations.home, ".openclaw", "openclaw.json");
  await readRegularFile(configPath, "hellolynk_npm_openclaw_config_missing");
  const module = await importLocal(PACKAGE_ROOT, metadata.configurator, "hellolynk_npm_configurator_invalid");
  const options = { configPath, pluginPath: path.join(packageRoot, metadata.pluginPath), storeRoot: locations.hostRoot, allowUnconnected };
  const plan = await module.configureOpenClaw({ ...options, apply: false });
  return Object.freeze({ kind: "openclaw", module, options: Object.freeze(options), plan });
}

async function configureOpenClaw({ packageRoot, releaseRoot, locations }, prepared) {
  if (prepared?.kind !== "openclaw") fail("hellolynk_npm_configuration_preflight_required");
  const transaction = await prepared.module.runAgentConfigurationTransaction({
    plans: [prepared.plan],
    apply: () => prepared.module.configureOpenClaw({
      ...prepared.options,
      expectedConfigPath: prepared.plan.configPath,
      expectedConfigSha256: prepared.plan.expectedConfigSha256,
      expectedReplacementSha256: prepared.plan.replacementSha256,
    }),
    rollback: (item) => prepared.module.rollbackAgentConfiguration(item),
  });
  const [configured] = transaction.committed;
  return Object.freeze({ configPaths: [configured.configPath], pluginPath: configured.pluginPath });
}

async function preflightMcpClient({ packageRoot, releaseRoot, release, locations }) {
  // Use this verified installer's transaction and path checks even when
  // restoring an older pinned release. Only the target payload comes from it.
  const module = await importLocal(PACKAGE_ROOT, metadata.configurator, "hellolynk_npm_configurator_invalid");
  const entry = path.join(packageRoot, metadata.entry);
  await readRegularFile(entry, "hellolynk_npm_entry_invalid");
  const configPaths = metadata.client === "trae-work"
    ? await traeConfigPaths(locations.appData)
    : await workBuddyConfigPaths(locations.home);
  const entryArgs = metadata.client === "trae-work"
    ? ["run", "--expected-manifest-sha256", release.manifestSha256]
    : ["run", "--root", releaseRoot, "--expected-manifest-sha256", release.outerManifestSha256];
  const configs = [];
  for (const configPath of configPaths) {
    const options = Object.freeze({
      client: metadata.client,
      configPath,
      nodePath: process.execPath,
      proxyPath: entry,
      entryArgs,
      storeRoot: locations.hostRoot,
      allowMissing: true,
    });
    const plan = await module.configureNeutralHostMcpClient({ ...options, apply: false });
    configs.push(Object.freeze({ options, plan }));
  }
  // Only the first managed installation opts in. A later upgrade/repair must
  // not turn a receiver back on after the user has disabled or removed it.
  const firstInstall = process.platform === "win32" && configs.every(item => item.plan.hadManagedEntry === false);
  let traeStartup = null, nativeSetupError = null;
  if (metadata.client === "trae-work" && firstInstall) {
    try {
      const worker = await importLocal(PACKAGE_ROOT, "integrations/trae-work/server/native-task-worker.mjs", "hellolynk_npm_trae_receiver_invalid");
      const currentReceiver = await worker.readTraeNativeTaskWorkerConfig(locations.hostRoot);
      const options = { configPath: path.join(locations.home, ".trae-cn", "argv.json"),
        ...(currentReceiver ? { debugEndpoint: currentReceiver } : {}) };
      const plan = await module.configureTraeNativeStartup({ ...options, apply: false });
      traeStartup = Object.freeze({ options: { ...options, debugEndpoint: plan.debugEndpoint }, plan, worker, currentReceiver });
    } catch (error) { nativeSetupError = receptionSetupFailure(error); }
  }
  let skill = null;
  if (metadata.skillTarget) {
    const skillModule = await importLocal(PACKAGE_ROOT, "tools/hellolynk-install-client-skills.mjs", "hellolynk_npm_skill_installer_invalid");
    const options = Object.freeze({
      sourceRoot: packageRoot,
      home: locations.home,
      appData: locations.appData,
      localAppData: locations.localAppData,
      target: metadata.skillTarget,
      replace: true,
    });
    const plan = await skillModule.installClientSkills({ ...options, apply: false });
    if (!/^[a-f0-9]{64}$/.test(String(plan?.fingerprint || ""))) {
      fail("hellolynk_npm_skill_installer_invalid");
    }
    skill = Object.freeze({ module: skillModule, options, fingerprint: plan.fingerprint });
  }
  return Object.freeze({ kind: "mcp", module, configs: Object.freeze(configs), skill, firstInstall, traeStartup, nativeSetupError });
}

function receptionSetupFailure(error) {
  const code = String(error?.code || error?.message || "");
  return { configured: false, errorCode: /^[a-z][a-z0-9_]{1,100}$/.test(code) ? code : "hellolynk_receiver_setup_failed" };
}

async function configureMcpClient({ packageRoot, releaseRoot, release, locations }, prepared) {
  if (prepared?.kind !== "mcp" || !Array.isArray(prepared.configs)) {
    fail("hellolynk_npm_configuration_preflight_required");
  }

  // Revalidate every config and the Skill tree before the first write. This is
  // what prevents WorkBuddy's second config from being discovered after the
  // first config has already migrated.
  for (const item of prepared.configs) {
    const current = await prepared.module.configureNeutralHostMcpClient({ ...item.options, apply: false });
    if (current.expectedConfigSha256 !== item.plan.expectedConfigSha256
      || current.replacementSha256 !== item.plan.replacementSha256) {
      fail("hellolynk_npm_configuration_changed_since_preflight");
    }
  }
  if (prepared.skill) {
    const currentSkillPlan = await prepared.skill.module.installClientSkills({
      ...prepared.skill.options,
      apply: false,
    });
    if (currentSkillPlan.fingerprint !== prepared.skill.fingerprint) {
      fail("hellolynk_npm_skill_changed_since_preflight");
    }
  }

  let nativeService = prepared.nativeSetupError, pageService;
  const transaction = await prepared.module.runAgentConfigurationTransaction({
    plans: prepared.configs,
    apply: (item) => prepared.module.configureNeutralHostMcpClient({
        ...item.options,
        expectedConfigPath: item.plan.configPath,
        expectedConfigSha256: item.plan.expectedConfigSha256,
        expectedReplacementSha256: item.plan.replacementSha256,
      }),
    rollback: (item) => prepared.module.rollbackAgentConfiguration(item),
    finalize: prepared.skill ? () => prepared.skill.module.installClientSkills({
        ...prepared.skill.options,
        apply: true,
        expectedPlanFingerprint: prepared.skill.fingerprint,
      }) : null,
  });
  // Receiving is an auxiliary setup step. Its failure must not undo a working
  // MCP/Skill installation or mix their versions with an already installed task.
  if (metadata.client === "workbuddy") {
    const context = { packageRoot, releaseRoot, release, locations };
    try { pageService = { ...await configureWorkBuddyPageTask(context, "Install"), configured: true }; }
    catch (error) { pageService = receptionSetupFailure(error); }
    try { nativeService = await updateWorkBuddyNativeService(context, "Install", prepared.firstInstall); }
    catch (error) { nativeService = receptionSetupFailure(error); }
  } else if (prepared.traeStartup) {
    const { worker, currentReceiver, options, plan } = prepared.traeStartup;
    try {
      if (await worker.readTraeNativeTaskWorkerConfig(locations.hostRoot) !== currentReceiver) {
        fail("hellolynk_npm_configuration_changed_since_preflight");
      }
      await prepared.module.runAgentConfigurationTransaction({
        plans: [prepared.traeStartup],
        apply: () => prepared.module.configureTraeNativeStartup({ ...options, expectedConfigPath: plan.configPath,
          expectedConfigSha256: plan.expectedConfigSha256, expectedReplacementSha256: plan.replacementSha256 }),
        rollback: item => prepared.module.rollbackAgentConfiguration(item),
        finalize: async () => {
          if (await worker.readTraeNativeTaskWorkerConfig(locations.hostRoot) !== currentReceiver) {
            fail("hellolynk_npm_configuration_changed_since_preflight");
          }
          nativeService = currentReceiver ? { enabled: true, debugEndpoint: currentReceiver }
            : await worker.configureTraeNativeTaskWorker({ storeRoot: locations.hostRoot, enabled: true, debugEndpoint: options.debugEndpoint });
          nativeService = { ...nativeService, configured: true, restartRequired: plan.restartRequired };
        },
      });
    } catch (error) { nativeService = receptionSetupFailure(error); }
  }
  const configured = transaction.committed;
  return Object.freeze({
    configPaths: configured.map((item) => item.configPath),
    skillInstalled: prepared.skill !== null,
    ...(nativeService ? { nativeService } : {}),
    ...(pageService ? { pageService } : {}),
    ...(nativeService?.errorCode || pageService?.errorCode ? { instructions: {
      zh: "插件已安装，自动接收或页面入口尚未设置好。请让 AI 根据安装结果检查；现有设置已保留。",
      en: "The plugin is installed, but receiving or the page entry needs attention. Ask your AI to check the setup result; existing settings were preserved.",
    } } : nativeService?.restartRequired ? { instructions: {
      zh: "自动收信已设置好，请完全退出并重新打开客户端一次。",
      en: "Automatic receiving is set up. Fully quit and reopen the client once.",
    } } : {}),
  });
}

function isLegacyOpenClawPluginPath(value) {
  const candidate = String(value || "");
  if (!path.isAbsolute(candidate)) return false;
  const segments = path.resolve(candidate).split(path.sep);
  const tail = ["integrations", "openclaw-channel"];
  if (segments.length < tail.length + 3
    || !segments.slice(-tail.length).every((segment, index) => segment.toLowerCase() === tail[index])) return false;
  const releaseIndex = segments.length - tail.length - 1;
  return /^openclaw-[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9._-]+$/i.test(segments[releaseIndex])
    && segments[releaseIndex - 1]?.toLowerCase() === "releases"
    && segments[releaseIndex - 2]?.toLowerCase() === "lynk";
}

async function workBuddyConfigPaths(home) {
  const root = path.join(home, ".workbuddy");
  const candidates = [path.join(root, ".mcp.json"), path.join(root, "mcp.json")];
  const existing = [];
  for (const candidate of candidates) if (await exists(candidate)) existing.push(candidate);
  return existing.length ? existing : [candidates[0]];
}

async function importLocal(root, relative, code) {
  const file = path.join(root, relative);
  if (!isSameOrDescendant(file, root)) fail(code);
  await readRegularFile(file, code);
  return import(pathToFileURL(file).href);
}

function runCodex(args, code, codexHome) {
  let runner;
  try { runner = resolveCodexRunner(codexHome); }
  catch (error) {
    const existing = String(error?.code || "");
    if (/^[a-z][a-z0-9_]{2,127}$/u.test(existing)) throw error;
    fail("hellolynk_npm_codex_runner_resolution_internal_failed");
  }
  let result;
  try {
    result = spawnSync(runner.command, [...runner.argsPrefix, ...args], {
      encoding: "utf8",
      windowsHide: true,
      shell: false,
      env: minimalEnv({ codexHome }),
    });
  } catch {
    fail(`${code}_${runner.kind}_spawn_threw`);
  }
  if (result.status !== 0) {
    const nested = codeFromOutput(result.stderr, null);
    if (nested) fail(nested);
    const spawnCode = String(result.error?.code || "").toLowerCase();
    if (/^[a-z0-9_]{2,32}$/u.test(spawnCode)) fail(`${code}_${runner.kind}_spawn_${spawnCode}`);
    if (Number.isInteger(result.status)) {
      const statusCode = result.status < 0 ? result.status >>> 0 : result.status;
      fail(`${code}_${runner.kind}_exit_${statusCode}`);
    }
    fail(`${code}_${runner.kind}_spawn_failed`);
  }
  return result.stdout;
}

function runCodexJson(args, code, codexHome) {
  const output = runCodex(args, code, codexHome);
  try { return JSON.parse(output); }
  catch { fail(`${code}_${resolvedCodexRunner?.kind || "runner"}_json_invalid`); }
}

function minimalEnv({ codexHome = null } = {}) {
  if (macPackage) return Object.freeze({
    PATH: process.env.PATH || "/usr/bin:/bin",
    HOME: process.env.HOME || os.homedir(),
    TMPDIR: process.env.TMPDIR || os.tmpdir(),
    LANG: process.env.LANG || "en_US.UTF-8",
    ...(codexHome ? { CODEX_HOME: codexHome } : {}),
  });
  return Object.freeze({
    PATH: process.env.Path || process.env.PATH || "",
    PATHEXT: process.env.PATHEXT || "",
    SystemRoot: process.env.SystemRoot || process.env.SYSTEMROOT || "",
    TEMP: process.env.TEMP || "",
    TMP: process.env.TMP || "",
    USERPROFILE: process.env.USERPROFILE || "",
    LOCALAPPDATA: process.env.LOCALAPPDATA || "",
    APPDATA: process.env.APPDATA || "",
    ...(codexHome ? { CODEX_HOME: codexHome } : {}),
  });
}

function resolveCodexRunner(codexHome) {
  if (resolvedCodexRunner) return resolvedCodexRunner;
  const searchPath = String((macPackage ? process.env.PATH : process.env.Path || process.env.PATH) || "");
  let sawLoaderCandidate = false;
  let sawNativeCandidate = false;
  for (const rawEntry of searchPath.split(path.delimiter)) {
    try {
      const logical = rawEntry.trim().replace(/^"(.*)"$/, "$1");
      if (!logical || !path.isAbsolute(logical)) continue;
      if (macPackage) {
        const runner = probeMacCodex(path.join(logical, "codex"), codexHome);
        if (runner) return (resolvedCodexRunner = runner);
        continue;
      }
      // nvm/fnm and user profile mappings can put a junction on PATH. Resolve
      // that directory once, then retain the ordinary-file checks below it.
      const entry = realpathSync(path.resolve(logical));
      const directoryMetadata = lstatSync(entry);
      if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) continue;
      const directoryRealPath = realpathSync(entry);
      try {
        sawLoaderCandidate ||= lstatSync(path.join(
          entry, "node_modules", "@openai", "codex", "bin", "codex.js",
        )).isFile();
      } catch { /* absent */ }
      const loader = resolveRegularDescendantSync(
        entry,
        directoryRealPath,
        ["node_modules", "@openai", "codex", "bin", "codex.js"],
      );
      if (loader) {
        resolvedCodexRunner = Object.freeze({
          command: process.execPath,
          argsPrefix: Object.freeze([loader]),
          kind: "npm_loader",
        });
        return resolvedCodexRunner;
      }
      try { sawNativeCandidate ||= lstatSync(path.join(entry, "codex.exe")).isFile(); }
      catch { /* absent */ }
      const candidate = resolveRegularDescendantSync(entry, directoryRealPath, ["codex.exe"]);
      if (!candidate) continue;
      const probe = spawnSync(candidate, ["--version"], {
        encoding: "utf8",
        windowsHide: true,
        shell: false,
        env: minimalEnv({ codexHome }),
      });
      if (probe.status !== 0) continue;
      resolvedCodexRunner = Object.freeze({
        command: candidate,
        argsPrefix: Object.freeze([]),
        kind: "native",
      });
      return resolvedCodexRunner;
    } catch {
      // A PATH entry without a safe, executable Codex runner is not authoritative.
    }
  }
  const desktopRunner = resolveCodexDesktopRunner(codexHome);
  if (desktopRunner) return (resolvedCodexRunner = desktopRunner);
  if (sawLoaderCandidate) fail("hellolynk_npm_codex_loader_invalid");
  if (sawNativeCandidate) fail("hellolynk_npm_codex_native_invalid");
  fail("hellolynk_npm_codex_cli_required");
}

function resolveCodexDesktopRunner(codexHome) {
  if (macPackage) {
    for (const directory of ["/Applications", path.join(os.homedir(), "Applications")]) {
      for (const app of ["ChatGPT.app", "Codex.app"]) {
        const runner = probeMacCodex(path.join(directory, app, "Contents", "Resources", "codex"), codexHome);
        if (runner) return runner;
      }
    }
    return null;
  }
  if (process.platform !== "win32") return null;
  const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT;
  if (!systemRoot || !path.isAbsolute(systemRoot)) return null;
  // Ask Windows for this user's installed desktop package, so neither a
  // separate CLI installation nor a hard-coded app version is necessary.
  const discovered = spawnSync(path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); Get-AppxPackage -Name OpenAI.Codex -ErrorAction Stop | Select-Object -ExpandProperty InstallLocation",
  ], { encoding: "utf8", windowsHide: true, shell: false, timeout: 10000,
    maxBuffer: 32768, env: minimalEnv({ codexHome }) });
  if (discovered.status !== 0) return null;
  for (const value of String(discovered.stdout || "").trim().split(/\r?\n/u)) {
    try {
      const location = value.trim();
      if (!location || !path.isAbsolute(location)) continue;
      const root = realpathSync(location);
      const candidate = resolveRegularDescendantSync(root, root, ["app", "resources", "codex.exe"]);
      if (!candidate) continue;
      const probe = spawnSync(candidate, ["--version"], { encoding: "utf8", windowsHide: true,
        shell: false, timeout: 5000, env: minimalEnv({ codexHome }) });
      if (probe.status === 0) return Object.freeze({ command: candidate,
        argsPrefix: Object.freeze([]), kind: "native" });
    } catch { /* Ignore an absent or incomplete desktop installation. */ }
  }
  return null;
}

function probeMacCodex(logicalPath, codexHome) {
  // npm and Homebrew commonly expose a symlink. Execute the canonical file directly.
  try {
    const command = realpathSync(logicalPath);
    const metadata = lstatSync(command);
    if (!metadata.isFile() || !(metadata.mode & 0o111)) return null;
    const result = spawnSync(command, ["--version"], {
      encoding: "utf8", shell: false, timeout: 5000, env: minimalEnv({ codexHome }),
    });
    if (result.status === 0 && /^codex-cli\s+\d+\.\d+\.\d+/u.test(String(result.stdout || "").trim())) {
      return Object.freeze({ command, argsPrefix: Object.freeze([]), kind: "native" });
    }
  } catch { /* Missing or unusable CLI. */ }
  return null;
}

function resolveRegularDescendantSync(anchor, anchorRealPath, segments) {
  let observed = anchor;
  for (let index = 0; index < segments.length; index += 1) {
    observed = path.join(observed, segments[index]);
    let metadata;
    try { metadata = lstatSync(observed); }
    catch (error) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
    if (metadata.isSymbolicLink()) return null;
    const final = index === segments.length - 1;
    if (final ? !metadata.isFile() : !metadata.isDirectory()) return null;
  }
  const canonical = realpathSync(observed);
  const relative = path.relative(
    normalizeWindowsNamespacePath(anchorRealPath),
    normalizeWindowsNamespacePath(canonical),
  );
  if (relative.toLowerCase() !== path.join(...segments).toLowerCase()) return null;
  return canonical;
}

function parseCodexConfiguration(source, code) {
  if (typeof source !== "string" || source.includes("\0")) fail(code);
  const tableNames = Object.freeze({
    "marketplaces.hellolynk-npm-codex": "marketplace",
    'plugins."hellolynk-codex@hellolynk-npm-codex"': "plugin",
  });
  const tables = { marketplace: null, plugin: null };
  let current = null;
  for (const rawLine of source.replace(/\r\n?/gu, "\n").split("\n")) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) continue;
    const table = /^\[([^\]]+)\]$/u.exec(line);
    if (table) {
      current = tableNames[table[1]] || null;
      if (current) {
        if (tables[current] !== null) fail(code);
        tables[current] = new Map();
      }
      continue;
    }
    if (!current) continue;
    const separator = findTomlAssignment(line);
    if (separator < 1) fail(code);
    const key = line.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(key) || tables[current].has(key)) fail(code);
    tables[current].set(key, parseTomlScalar(line.slice(separator + 1).trim(), code));
  }
  if (!(tables.marketplace instanceof Map) || !(tables.plugin instanceof Map)) fail(code);
  return Object.freeze({
    marketplace: Object.freeze({
      sourceType: tables.marketplace.get("source_type"),
      source: tables.marketplace.get("source"),
    }),
    plugin: Object.freeze({ enabled: tables.plugin.get("enabled") }),
  });
}

function stripTomlComment(value) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === '"') {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
    } else if (quote === "'") {
      if (character === quote) quote = null;
    } else if (character === '"' || character === "'") quote = character;
    else if (character === "#") return value.slice(0, index);
  }
  return value;
}

function findTomlAssignment(value) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === '"') {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
    } else if (quote === "'") {
      if (character === quote) quote = null;
    } else if (character === '"' || character === "'") quote = character;
    else if (character === "=") return index;
  }
  return -1;
}

function parseTomlScalar(value, code) {
  if (value === "true") return true;
  if (value === "false") return false;
  if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
    return value.slice(1, -1);
  }
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    try { return JSON.parse(value); }
    catch { fail(code); }
  }
  fail(code);
}

async function assertCanonicalDirectoryChain(anchor, candidate, code) {
  const anchorPath = path.resolve(anchor);
  const candidatePath = path.resolve(candidate);
  const relative = path.relative(anchorPath, candidatePath);
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) fail(code);
  const anchorMetadata = await fs.lstat(anchorPath).catch(() => fail(code));
  if (!anchorMetadata.isDirectory() || anchorMetadata.isSymbolicLink()) fail(code);
  const anchorCanonical = await fs.realpath(anchorPath).catch(() => fail(code));
  let observed = anchorPath;
  let expected = anchorCanonical;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    observed = path.join(observed, segment);
    expected = path.join(expected, segment);
    const metadata = await fs.lstat(observed).catch(() => fail(code));
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(code);
    const canonical = await fs.realpath(observed).catch(() => fail(code));
    if (!samePath(canonical, expected)) fail(code);
  }
}

async function verifyExactRegularTree(sourceRoot, targetRoot, trustedTargetAnchor, code) {
  const source = await snapshotRegularTree(sourceRoot, null, code);
  const target = await snapshotRegularTree(targetRoot, trustedTargetAnchor, code);
  if (source.size !== target.size) fail(code);
  for (const [relative, expected] of source) {
    const observed = target.get(relative);
    if (!observed || observed.bytes !== expected.bytes || observed.sha256 !== expected.sha256) fail(code);
  }
}

async function snapshotRegularTree(root, trustedAnchor, code) {
  const rootPath = path.resolve(root);
  if (trustedAnchor) await assertCanonicalDirectoryChain(trustedAnchor, rootPath, code);
  const rootMetadata = await fs.lstat(rootPath).catch(() => fail(code));
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) fail(code);
  const rootCanonical = await fs.realpath(rootPath).catch(() => fail(code));
  const records = new Map();
  async function visit(directory) {
    const entries = await fs.readdir(directory).catch(() => fail(code));
    entries.sort((left, right) => left.localeCompare(right, "en"));
    for (const name of entries) {
      const absolute = path.join(directory, name);
      const relative = path.relative(rootPath, absolute).split(path.sep).join("/");
      const before = await fs.lstat(absolute).catch(() => fail(code));
      if (before.isSymbolicLink()) fail(code);
      if (before.isDirectory()) {
        const canonical = await fs.realpath(absolute).catch(() => fail(code));
        if (!samePath(canonical, path.join(rootCanonical, ...relative.split("/")))) fail(code);
        await visit(absolute);
      } else if (before.isFile() && before.nlink === 1) {
        const body = await fs.readFile(absolute).catch(() => fail(code));
        const after = await fs.lstat(absolute).catch(() => fail(code));
        if (!sameFileIdentity(before, after) || after.size !== body.length) fail(code);
        records.set(relative, Object.freeze({ bytes: body.length, sha256: sha256(body) }));
      } else fail(code);
    }
  }
  await visit(rootPath);
  return records;
}

function sameFileIdentity(left, right) {
  return left.isFile() && right.isFile() && !right.isSymbolicLink()
    && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeMs === right.mtimeMs && right.nlink === 1;
}

function samePath(left, right) {
  const normalize = (value) => {
    const resolved = normalizeWindowsNamespacePath(value);
    let canonical = resolved;
    try { canonical = realpathSync(resolved); } catch { /* comparison can still reject a missing path */ }
    if (macPackage) return canonical;
    return normalizeWindowsNamespacePath(canonical).replace(/[\\/]+$/u, "").toLowerCase();
  };
  return normalize(left) === normalize(right);
}

function normalizeWindowsNamespacePath(value) {
  let input = String(value || "");
  if (/^\\\\\?\\UNC\\/iu.test(input)) input = `\\\\${input.slice(8)}`;
  else if (/^\\\\\?\\/u.test(input)) input = input.slice(4);
  return path.resolve(input);
}

function codeFromOutput(value, fallback) {
  try {
    const parsed = JSON.parse(String(value || "").trim().split(/\r?\n/).at(-1));
    return /^[a-z][a-z0-9_]{2,127}$/.test(parsed?.error) ? parsed.error : fallback;
  } catch { return fallback; }
}

async function readJson(file, code, requireSingleLink = false) {
  let bytes;
  try { bytes = await readRegularFile(file, code, requireSingleLink); }
  catch { fail(code); }
  if (bytes.length > MAX_JSON_BYTES) fail(code);
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail(code); }
}

async function readRegularFile(file, code, requireSingleLink = false) {
  let metadata;
  try { metadata = await fs.lstat(file); }
  catch { fail(code); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (requireSingleLink && metadata.nlink !== 1)) fail(code);
  return fs.readFile(file);
}

async function exists(file) { return fs.access(file).then(() => true, () => false); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function fail(code) { const error = new Error(code); error.code = code; throw error; }
function safeCode(error) {
  const value = String(error?.code || error?.message || "hellolynk_npm_setup_failed");
  return /^[a-z][a-z0-9_]{2,127}$/.test(value) ? value : "hellolynk_npm_setup_failed";
}
function failureResult(error, recoveryState) {
  const result = { ok: false, error: safeCode(error) };
  if (result.error === "hellolynk_native_existing_profile_conflict") {
    return Object.freeze({ ...result, recoveryState: "existing_profile_preserved", recovery: "inspect_existing_profile" });
  }
  if (recoveryState === "device_connect_attempted"
    && ["device_enrollment_existing_profile_requires_setup", "device_enrollment_profile_conflict"].includes(result.error)) {
    return Object.freeze({
      ...result,
      recoveryState: "existing_profile_preserved",
      recovery: result.error === "device_enrollment_existing_profile_requires_setup"
        ? "run_doctor_then_setup_same_candidate" : "inspect_existing_profile",
    });
  }
  if (error?.localConfigurationOutcomeUncertain === true
    || result.error === "local_configuration_outcome_uncertain") {
    return Object.freeze({
      ...result,
      recoveryState: "local_configuration_outcome_uncertain",
      localConfigurationRolledBack: "unknown",
      ...(recoveryState !== "none" ? { bindingRecoveryState: recoveryState } : {}),
      recovery: recoveryState.startsWith("device_")
        ? "inspect_local_configuration_then_repeat_connect_same_arguments_same_candidate"
        : "inspect_local_configuration_then_run_setup_same_candidate",
    });
  }
  if (recoveryState === "device_connect_attempted"
    || recoveryState === "device_registration_committed_roll_forward_required") {
    return Object.freeze({
      ...result,
      recoveryState: recoveryState === "device_connect_attempted"
        ? "device_connect_outcome_uncertain" : recoveryState,
      recovery: "repeat_connect_same_arguments_same_candidate",
    });
  }
  if (recoveryState === "binding_redemption_attempted") {
    return Object.freeze({
      ...result,
      recoveryState: "binding_outcome_uncertain",
      bindingKeyReusable: "unknown",
      recovery: "run_doctor_then_setup_same_candidate",
    });
  }
  if (recoveryState === "protected_binding_update_attempted") {
    return Object.freeze({
      ...result,
      recoveryState: "protected_binding_update_outcome_uncertain",
      recovery: "run_doctor_then_setup_same_candidate",
    });
  }
  if (recoveryState === "binding_committed_roll_forward_required") {
    return Object.freeze({
      ...result,
      recoveryState: "binding_committed_roll_forward_required",
      recovery: "run_setup_same_candidate",
    });
  }
  return Object.freeze(result);
}
function print(value) {
  process.stdout.write(jsonOutput ? `${JSON.stringify(value)}\n` : resultText(value));
}

function say(zh, en) { return CHINESE ? zh : en; }

function helpText() {
  const script = path.resolve(process.argv[1]);
  const relative = path.relative(process.cwd(), script);
  const shown = relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : script;
  const run = `node ${/\s/.test(shown) ? `"${shown}"` : shown}`;
  const connect = `connect --hellolynk-id ${say("<灵信号>", "<HelloLynk ID>")}`;
  const rows = isNativeClient()
    ? [[say("连接账号", "Connect an account"), connect], [say("检查", "Check"), "doctor"]]
    : [[say("安装", "Install"), "init"], [say("连接账号", "Connect an account"), connect],
      [say("更新或修复", "Update or repair"), "setup"], [say("检查", "Check"), "doctor"],
      [say("卸载", "Uninstall"), "uninstall"]];
  const platform = macPackage ? " (macOS arm64, Node.js 22.16.0+)"
    : say("（Windows，Node.js 22.16.0+）", " (Windows, Node.js 22.16.0+)");
  return `${[`HelloLynk for ${CLIENT_NAMES[metadata.client]}${platform}`,
    ...rows.map(([label, args]) => `${label}${say("：", ": ")}${run} ${args}`),
    say("加 --json 输出一行 JSON。", "Add --json for one line of JSON.")].join("\n")}\n`;
}

function resultText(value) {
  const name = CLIENT_NAMES[metadata.client];
  const reopen = say(`完全退出并重新打开 ${name} 后生效。`, `Fully quit and reopen ${name} for this to take effect.`);
  const lines = [];
  if (value.status === "confirmation_required") {
    lines.push(say("还差一步：打开下面的链接，在官网确认这台电脑，再运行一次同样的命令。",
      "One more step: open the link below, confirm this computer on the website, then run the same command again."), value.verificationUrl);
  } else if (value.uninstalled) {
    lines.push(`${say(`HelloLynk 已从 ${name} 卸载。`, `HelloLynk is uninstalled from ${name}. `)}${reopen}`,
      say("账号、联系人和聊天记录留在这台电脑上，重新安装后不用重新连接。",
        "Your account, contacts and chat history stay on this computer; reinstalling needs no new connection."));
    if (value.releaseCleanup?.complete !== true) {
      lines.push(say("有的版本还在使用，下次安装或卸载时删除。",
        "Some versions are still in use; they are removed the next time you install or uninstall."));
    }
  } else if (value.releaseVerified) {
    lines.push(value.clientConfigurationVerified
      ? say(`HelloLynk ${value.packageVersion} 已安装，账号已连接。`, `HelloLynk ${value.packageVersion} is installed and connected.`)
      : say(`HelloLynk ${value.packageVersion} 安装包完好，这台电脑还没有连接账号。`,
        `The HelloLynk ${value.packageVersion} package is intact; this computer is not connected yet.`));
  } else if (value.next === "open_client_and_connect") {
    lines.push(say(`HelloLynk 已装进 ${name}。完全退出并重新打开 ${name}，说“打开 HelloLynk”，按页面提示连接账号。`,
      `HelloLynk is installed in ${name}. Fully quit and reopen ${name}, say "open HelloLynk", and connect your account on the page.`));
  } else if (value.recovered) {
    lines.push(`${say(`已恢复到 HelloLynk ${value.restoredPackageVersion}。`, `Restored HelloLynk ${value.restoredPackageVersion}. `)}${reopen}`);
  } else if (value.status === "registered") {
    lines.push(`${say(`已连接灵信号 ${value.hellolynkId}。`, `Connected to ${value.hellolynkId}. `)}${reopen}`);
  } else {
    lines.push(`${value.packageVersion ? say(`HelloLynk ${value.packageVersion} 已就绪。`, `HelloLynk ${value.packageVersion} is ready. `)
      : say("HelloLynk 已连接。", "HelloLynk is connected. ")}${reopen}`);
  }
  const receiving = value.configured?.nativeService?.errorCode, page = value.configured?.pageService?.errorCode;
  if (receiving) lines.push(say(`自动收信没有设置好（${receiving}）。`, `Automatic receiving is not set up (${receiving}).`));
  if (page) lines.push(say(`HelloLynk 页面入口没有设置好（${page}）。`, `The HelloLynk page entry is not set up (${page}).`));
  const handover = {
    pending: say("这台电脑上的 HelloLynk 还在运行旧版本。请关闭所有使用 HelloLynk 的客户端，再重新打开。",
      "HelloLynk on this computer still runs an earlier version. Close every client that uses HelloLynk, then open them again."),
    unconfirmed: say("无法确认这台电脑上的 HelloLynk 运行的版本。请关闭所有使用 HelloLynk 的客户端，再重新打开。",
      "Which version HelloLynk on this computer runs could not be checked. Close every client that uses HelloLynk, then open them again."),
  }[value.hostHandover?.status];
  if (handover) lines.push(handover);
  return `${lines.join("\n")}\n`;
}

// The code stays on the first line for support; the second says what happened and what to do.
function failureText(failure) {
  const name = CLIENT_NAMES[metadata.client];
  const byState = {
    existing_profile_preserved: say("这台电脑已有连接资料，没有改动。运行 doctor 检查。",
      "This computer already has connection data; nothing was changed. Run doctor to check it."),
    local_configuration_outcome_uncertain: say(`${name} 的设置可能只改了一部分。再运行一次这条命令。`,
      `${name}'s settings may be only partly changed. Run this command again.`),
    device_connect_outcome_uncertain: say("不确定是否已连接。用同样的参数再运行一次。",
      "Whether it connected is unknown. Run the same command again."),
    device_registration_committed_roll_forward_required: say("账号已连接，客户端设置还没写完。用同样的参数再运行一次。",
      "The account is connected, but the client settings are not finished. Run the same command again."),
    binding_outcome_uncertain: say("不确定是否已连接。先运行 doctor，再运行 setup。",
      "Whether it connected is unknown. Run doctor, then setup."),
    protected_binding_update_outcome_uncertain: say("不确定更新是否完成。先运行 doctor，再运行 setup。",
      "Whether the update finished is unknown. Run doctor, then setup."),
    binding_committed_roll_forward_required: say("账号已连接，客户端设置还没写完。运行 setup 完成。",
      "The account is connected, but the client settings are not finished. Run setup to finish."),
  }[failure.recoveryState];
  return `${failure.error}\n${byState || failureReason(failure.error, name)}\n`;
}

function failureReason(code, name) {
  if (code === "hellolynk_node_22_16_required") return say("需要 Node.js 22.16 或更高版本。", "Node.js 22.16 or later is required.");
  if (code === "hellolynk_npm_windows_only") return say("只支持 Windows。", "Windows only.");
  if (code === "hellolynk_npm_platform_unsupported") return say("此安装包适用于 Apple 芯片的 Mac。", "This package requires an Apple silicon Mac.");
  if (code === "hellolynk_npm_codex_mac_node_required") return say("请将 ChatGPT 安装到「应用程序」，打开 Codex 后再试。",
    "Install ChatGPT in Applications, open Codex, and try again.");
  if (code === "hellolynk_npm_connect_id_invalid") {
    return say("灵信号不对。请从官网复制从 hellolynk: 开始的完整灵信号。",
      "This HelloLynk ID is not valid. Copy the complete ID, starting with hellolynk:, from the website.");
  }
  if (/_(?:command|arguments)_invalid$|^hellolynk_npm_binding_key_stdin_flag_required$/.test(code)) {
    return say("命令或参数不对。运行 --help 查看用法。", "The command or its arguments are not valid. Run --help to see usage.");
  }
  if (/^hellolynk_(?:npm|native)_(?:pack|release|stable_release|package)_invalid$/.test(code)) {
    return say("安装包不完整或被改动过。请重新下载。", "The package is incomplete or was changed. Download it again.");
  }
  if (code === "hellolynk_npm_existing_host_activation_required") {
    return say(`这台电脑还没有连接账号。先运行 init，再在 ${name} 里连接。`, `This computer is not connected yet. Run init, then connect in ${name}.`);
  }
  if (code === "hellolynk_npm_openclaw_config_missing") {
    return say("没有找到 OpenClaw 的配置文件。先打开一次 OpenClaw，再运行这条命令。",
      "OpenClaw's configuration file was not found. Open OpenClaw once, then run this command again.");
  }
  if (/^hellolynk_npm_codex_(?:cli_required|loader_invalid|native_invalid)$/.test(code)) {
    return say("找不到可用的 Codex。安装或打开一次 Codex 后再试。", "No usable Codex was found. Install or open Codex once, then try again.");
  }
  if (/_changed_since_preflight$|^workbench_account_changed$/.test(code)) {
    return say("运行期间设置被改动了。再运行一次这条命令。", "Settings changed while this ran. Run this command again.");
  }
  if (code === "hellolynk_npm_uninstall_config_conflict") {
    return say(`${name} 里有一项 HelloLynk 设置不是安装器写入的，没有删除任何东西。删掉这项设置后再运行一次。`,
      `A HelloLynk setting in ${name} was not written by the installer; nothing was removed. Remove that setting, then run this command again.`);
  }
  if (code === "hellolynk_npm_uninstall_skill_conflict") {
    return say("HelloLynk 技能文件被改动过，没有删除任何东西。还原或删掉这个技能后再运行一次。",
      "The HelloLynk skill files were changed; nothing was removed. Restore or delete the skill, then run this command again.");
  }
  return say("没有完成。处理方法见 README.md。", "This did not complete. See README.md.");
}
