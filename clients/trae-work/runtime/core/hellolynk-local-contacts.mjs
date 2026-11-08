import crypto from "node:crypto";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import { defaultHelloLynkClientRoot } from "./hellolynk-client-profile.mjs";
import { assertLocalDataProtectionAccess } from "./hellolynk-local-data-protection.mjs";
import runtimeSafety from "./hellolynk-runtime-safety.cjs";

const {
  HELLOLYNK_CONTACTS_CONTRACT: CONTACTS_CONTRACT,
  classifyHelloLynkStableId,
  isHelloLynkStableIdReservedText,
} = runtimeSafety;
const SCHEMA_VERSION = 4;
const READABLE_SCHEMA_VERSIONS = new Set([2, 3, SCHEMA_VERSION]);
export const HELLOLYNK_LOCAL_CONTACTS_CONTRACT = CONTACTS_CONTRACT;
export const HELLOLYNK_LOCAL_CONTACTS_SCHEMA_VERSION = SCHEMA_VERSION;
const MAX_CONTACTS = 500;
const MAX_RELATIONSHIP_SYNC_RECORDS = 2000;
const MAX_AUTHORIZED_DELEGATES_PER_CONTACT = 32;
const MAX_INSTANCES_PER_CONTACT = 32;
const INSTANCE_CLIENT_TYPES = new Set(["codex", "openclaw", "trae-work", "workbuddy", "cursor", "dsh", "claude-code"]);
const MAX_STORE_BYTES = 1024 * 1024;
const MAX_PROTECTED_STORE_BYTES = MAX_STORE_BYTES * 2;
const LOCK_ATTEMPTS = 100;
const LOCK_WAIT_MS = 20;
const LOCK_STALE_MS = 5_000;
const PROFILE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/;
const CONTACT_ID_RE = /^contact_[a-f0-9-]{36}$/;
const DELEGATE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,198}$/;
const SAFETY_CODE_RE = /^[A-F0-9]{4}(?:-[A-F0-9]{4}){11}$/;
const SAFETY_CODE_VERIFICATION_STATES = Object.freeze({
  unavailable: "unavailable",
  verificationRequired: "verification-required",
  locallyVerified: "locally-verified",
});
const UNSAFE_DISPLAY_RE = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const mutationQueues = new Map();
const NO_STORE_WRITE = Symbol("hellolynk-local-contacts-no-store-write");

export class HelloLynkLocalContactsError extends Error {
  constructor(code, options = {}) {
    super(code, options.cause ? { cause: options.cause } : undefined);
    this.name = "HelloLynkLocalContactsError";
    this.code = code;
  }
}

export function normalizeContactHelloLynkId(value, options = {}) {
  const hellolynkId = String(value || "").trim();
  const identity = classifyHelloLynkStableId(hellolynkId);
  if (!identity) {
    throw new HelloLynkLocalContactsError("contact_hellolynk_id_invalid");
  }
  return hellolynkId;
}

export function normalizeContactDisplayName(value) {
  const displayName = String(value || "").normalize("NFKC").trim().replace(/\s+/gu, " ");
  if (
    !displayName ||
    [...displayName].length > 80 ||
    UNSAFE_DISPLAY_RE.test(displayName) ||
    isHelloLynkStableIdReservedText(displayName)
  ) {
    throw new HelloLynkLocalContactsError("contact_display_name_invalid");
  }
  return displayName;
}

export function contactDisplayNameKey(value) {
  return normalizeContactDisplayName(value).toLocaleLowerCase("und");
}

function normalizeContactSafetyCode(value) {
  if (value == null || String(value).trim() === "") return null;
  const safetyCode = String(value).trim().toUpperCase().replace(/[\s:]+/gu, "-");
  if (!SAFETY_CODE_RE.test(safetyCode)) throw new HelloLynkLocalContactsError("contact_safety_code_invalid");
  return safetyCode;
}

export function resolveLocalContactsPath(options = {}) {
  const profileId = normalizeProfileId(options.profileId);
  const root = path.resolve(options.root || defaultHelloLynkClientRoot());
  return path.join(root, "contacts", `${profileId}.json`);
}

export function createLocalContactStore(options = {}) {
  const profileId = normalizeProfileId(options.profileId);
  const storePath = path.resolve(options.storePath || resolveLocalContactsPath({
    profileId,
    root: options.root,
  }));
  const now = typeof options.now === "function" ? options.now : () => new Date();
  const protection = normalizeContactDataProtection(options.dataProtector, profileId);

  async function snapshot() {
    const store = await readStore(storePath, profileId, protection);
    return publicSnapshot(store, storePath);
  }

  async function save(input = {}) {
    const hellolynkId = normalizeContactHelloLynkId(input.hellolynkId);
    const stableIdentity = classifyHelloLynkStableId(hellolynkId);
    const displayName = normalizeContactDisplayName(input.displayName);
    if (Object.hasOwn(input, "safetyCode")) throw new HelloLynkLocalContactsError("contact_safety_code_invalid");
    const requestedContactId = input.contactId == null ? null : normalizeContactId(input.contactId);
    return mutateStore(storePath, profileId, async (store) => {
      const displayKey = contactDisplayNameKey(displayName);
      const byRequestedId = requestedContactId
        ? store.contacts.find((contact) => contact.contactId === requestedContactId)
        : null;
      if (requestedContactId && !byRequestedId) throw new HelloLynkLocalContactsError("contact_not_found");
      const byHelloLynkId = store.contacts.find((contact) => contact.hellolynkId === hellolynkId);
      const byStableAlias = store.contacts.find((contact) => (
        classifyHelloLynkStableId(contact.hellolynkId)?.aliasKey === stableIdentity.aliasKey
      ));
      if (byStableAlias && byStableAlias.hellolynkId !== hellolynkId) {
        throw new HelloLynkLocalContactsError("contact_hellolynk_id_alias_conflict");
      }
      if (byHelloLynkId && byRequestedId && byHelloLynkId.contactId !== byRequestedId.contactId) {
        throw new HelloLynkLocalContactsError("contact_hellolynk_id_conflict");
      }
      const target = byRequestedId || byHelloLynkId || null;
      const conflictingName = store.contacts.find((contact) => (
        contactDisplayNameKey(contact.displayName) === displayKey && contact.contactId !== target?.contactId
      ));
      if (conflictingName) throw new HelloLynkLocalContactsError("contact_display_name_conflict");
      const timestamp = normalizeTimestamp(now());
      if (target) {
        const hellolynkIdChanged = target.hellolynkId !== hellolynkId;
        if (hellolynkIdChanged) {
          rememberDeletedContact(store, target.hellolynkId);
          target.autonomousSendDelegateIds = [];
          target.continuousReadDelegateIds = [];
          target.principalId = null;
          target.instances = [];
        }
        target.hellolynkId = hellolynkId;
        target.displayName = displayName;
        target.updatedAt = timestamp;
        clearPendingContactDeletion(store, hellolynkId);
        return publicContact(target);
      }
      if (store.contacts.length >= MAX_CONTACTS) throw new HelloLynkLocalContactsError("contact_capacity_exceeded");
      const contact = {
        contactId: `contact_${crypto.randomUUID()}`,
        hellolynkId,
        displayName,
        principalId: null,
        instances: [],
        safetyCode: null,
        safetyCodeVerificationState: SAFETY_CODE_VERIFICATION_STATES.unavailable,
        autonomousSendDelegateIds: [],
        continuousReadDelegateIds: [],
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      store.contacts.push(contact);
      clearPendingContactDeletion(store, hellolynkId);
      return publicContact(contact);
    }, protection);
  }

  async function rename(contactId, input = {}) {
    const acceptedContactId = normalizeContactId(contactId);
    assertExactObjectFields(input, ["displayName", "expectedDisplayName", "expectedHelloLynkId"]);
    const displayName = normalizeContactDisplayName(input.displayName);
    const expectedDisplayName = normalizeContactDisplayName(input.expectedDisplayName);
    const expectedHelloLynkId = normalizeContactHelloLynkId(input.expectedHelloLynkId);
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      // Compare only the identity and note being edited, under the same write
      // lock. New messages or permission updates are not competing note edits.
      if (contact.hellolynkId !== expectedHelloLynkId || contact.displayName !== expectedDisplayName) {
        throw new HelloLynkLocalContactsError("contact_name_conflict");
      }
      if (store.contacts.some((item) => item.contactId !== acceptedContactId
        && contactDisplayNameKey(item.displayName) === contactDisplayNameKey(displayName))) {
        throw new HelloLynkLocalContactsError("contact_display_name_conflict");
      }
      if (contact.displayName === displayName) return noStoreWrite(publicContact(contact));
      contact.displayName = displayName;
      contact.updatedAt = normalizeTimestamp(now());
      return publicContact(contact);
    }, protection);
  }

  async function remove(contactId) {
    const acceptedId = normalizeContactId(contactId);
    return mutateStore(storePath, profileId, async (store) => {
      const index = store.contacts.findIndex((contact) => contact.contactId === acceptedId);
      if (index < 0) return noStoreWrite(false);
      rememberDeletedContact(store, store.contacts[index].hellolynkId);
      store.contacts.splice(index, 1);
      return true;
    }, protection);
  }

  async function synchronizeRelationships(input = {}) {
    const { owner, relationships } = normalizeRelationshipSynchronization(input);
    return mutateStore(storePath, profileId, async (store) => {
      const sync = store.relationshipSync;
      if (sync.owner && (sync.owner.principalId !== owner.principalId
        || sync.owner.hellolynkId !== owner.hellolynkId)) {
        throw new HelloLynkLocalContactsError("contact_relationship_owner_mismatch");
      }
      if (sync.owner == null) {
        const identity = classifyHelloLynkStableId(owner.hellolynkId);
        sync.pendingDeletedHelloLynkIds = sync.pendingDeletedHelloLynkIds.filter((peerId) => {
          const peer = classifyHelloLynkStableId(peerId);
          return peer.region === identity.region && peer.aliasKey !== identity.aliasKey;
        });
      }
      for (const relationship of relationships) {
        const known = sync.generations.find((item) => item.relationshipId === relationship.relationshipId);
        if (known && known.hellolynkId !== relationship.otherPrincipal.hellolynkId) {
          throw new HelloLynkLocalContactsError("contact_relationship_identity_conflict");
        }
      }
      let changed = sync.owner == null;
      sync.owner = owner;
      let addedCount = 0;
      let capacityReached = false;
      if (serializedStoreBytes(store) > MAX_STORE_BYTES) {
        return noStoreWrite({ addedCount: 0, capacityReached: true });
      }
      for (const relationship of relationships) {
        const peer = relationship.otherPrincipal.hellolynkId;
        const known = sync.generations.find((item) => item.relationshipId === relationship.relationshipId);
        const pending = sync.pendingDeletedHelloLynkIds.includes(peer);
        const contactExists = store.contacts.some((contact) => contact.hellolynkId === peer);
        const suppressed = known?.suppressed === true || pending || relationship.status === "ended";
        const addContact = relationship.status === "active" && !suppressed && !contactExists;
        if ((addContact && store.contacts.length >= MAX_CONTACTS)
          || (!known && sync.generations.length + sync.pendingDeletedHelloLynkIds.length
            - Number(pending) >= MAX_RELATIONSHIP_SYNC_RECORDS)) {
          capacityReached = true;
          continue;
        }
        const previousGenerations = sync.generations;
        const previousPending = sync.pendingDeletedHelloLynkIds;
        let relationshipChanged = false;
        if (!known || known.suppressed !== suppressed) {
          sync.generations = sync.generations.filter((item) => item !== known).concat({
            relationshipId: relationship.relationshipId, hellolynkId: peer, suppressed,
          });
          relationshipChanged = true;
        }
        if (pending) {
          clearPendingContactDeletion(store, peer);
          relationshipChanged = true;
        }
        if (addContact) {
          const timestamp = normalizeTimestamp(now());
          store.contacts.push({
            contactId: `contact_${crypto.randomUUID()}`,
            hellolynkId: peer,
            displayName: automaticContactDisplayName(relationship.otherPrincipal.displayName, peer, store.contacts),
            principalId: null,
            instances: [],
            safetyCode: null,
            safetyCodeVerificationState: SAFETY_CODE_VERIFICATION_STATES.unavailable,
            autonomousSendDelegateIds: [],
            continuousReadDelegateIds: [],
            createdAt: timestamp,
            updatedAt: timestamp,
          });
          relationshipChanged = true;
        }
        if (!relationshipChanged) continue;
        if (serializedStoreBytes(store) > MAX_STORE_BYTES) {
          sync.generations = previousGenerations;
          sync.pendingDeletedHelloLynkIds = previousPending;
          if (addContact) store.contacts.pop();
          capacityReached = true;
          continue;
        }
        changed = true;
        if (addContact) addedCount += 1;
      }
      const result = { addedCount, capacityReached };
      return changed ? result : noStoreWrite(result);
    }, protection);
  }

  // Only the Host may supply the account-bound instance directory result.
  // The stable delegate ID controls identity and routing; displayName is this
  // local contact's label for that instance.
  async function upsertInstance(contactId, input = {}) {
    const acceptedContactId = normalizeContactId(contactId);
    assertExactObjectFields(input, ["principalId", "delegateId", "clientType", "displayName"]);
    const principalId = normalizeDelegateId(input.principalId);
    const delegateId = normalizeDelegateId(input.delegateId);
    const clientType = normalizeInstanceClientType(input.clientType);
    const displayName = normalizeContactDisplayName(input.displayName);
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      if (contact.principalId != null && contact.principalId !== principalId) {
        throw new HelloLynkLocalContactsError("contact_instance_principal_conflict");
      }
      const timestamp = normalizeTimestamp(now());
      const instance = contact.instances.find((item) => item.delegateId === delegateId);
      if (instance) {
        if (instance.clientType !== clientType) throw new HelloLynkLocalContactsError("contact_instance_client_conflict");
        instance.displayName = displayName;
        instance.updatedAt = timestamp;
      } else {
        if (contact.instances.length >= MAX_INSTANCES_PER_CONTACT) {
          throw new HelloLynkLocalContactsError("contact_instance_capacity_exceeded");
        }
        contact.instances.push({ delegateId, clientType, displayName,
          autonomousSendDelegateIds: [], continuousReadDelegateIds: [], createdAt: timestamp, updatedAt: timestamp });
      }
      contact.principalId = principalId;
      contact.updatedAt = timestamp;
      return publicContact(contact);
    }, protection);
  }

  async function renameInstance(contactId, input = {}) {
    const acceptedContactId = normalizeContactId(contactId);
    assertExactObjectFields(input, ["delegateId", "displayName", "expectedDisplayName", "expectedHelloLynkId", "expectedPrincipalId"]);
    const delegateId = normalizeDelegateId(input.delegateId);
    const displayName = normalizeContactDisplayName(input.displayName);
    const expectedDisplayName = normalizeContactDisplayName(input.expectedDisplayName);
    const expectedHelloLynkId = normalizeContactHelloLynkId(input.expectedHelloLynkId);
    const expectedPrincipalId = normalizeDelegateId(input.expectedPrincipalId);
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      if (contact.hellolynkId !== expectedHelloLynkId || contact.principalId !== expectedPrincipalId) {
        throw new HelloLynkLocalContactsError("contact_identity_mismatch");
      }
      // Require the same already saved instance under the write lock. A stale
      // editor must never recreate a deleted entry or overwrite a newer note.
      const instance = requireContactInstance(contact, delegateId);
      if (instance.displayName !== expectedDisplayName) {
        throw new HelloLynkLocalContactsError("contact_instance_name_conflict");
      }
      const timestamp = normalizeTimestamp(now());
      instance.displayName = displayName;
      instance.updatedAt = timestamp;
      contact.updatedAt = timestamp;
      return publicContact(contact);
    }, protection);
  }

  async function removeInstance(contactId, peerDelegateId) {
    const acceptedContactId = normalizeContactId(contactId);
    const acceptedPeerDelegateId = normalizeDelegateId(peerDelegateId);
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      const index = contact.instances.findIndex((item) => item.delegateId === acceptedPeerDelegateId);
      if (index < 0) return noStoreWrite(false);
      contact.instances.splice(index, 1);
      contact.updatedAt = normalizeTimestamp(now());
      return true;
    }, protection);
  }

  async function resolveInstance(contactId, peerDelegateId) {
    const acceptedContactId = normalizeContactId(contactId);
    const acceptedPeerDelegateId = normalizeDelegateId(peerDelegateId);
    const store = await readStore(storePath, profileId, protection);
    const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
    if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
    const instance = requireContactInstance(contact, acceptedPeerDelegateId);
    return resolvedInstance(contact, instance);
  }

  async function resolve(value) {
    const raw = String(value || "").trim();
    if (!raw || raw.length > 200 || /[\r\n\u0000-\u001F\u007F]/u.test(raw)) {
      throw new HelloLynkLocalContactsError("contact_reference_invalid");
    }
    const directIdentity = classifyHelloLynkStableId(raw);
    if (directIdentity) return {
      hellolynkId: raw,
      displayName: raw,
      source: "hellolynk_id",
    };
    const wanted = contactDisplayNameKey(raw);
    const store = await readStore(storePath, profileId, protection);
    const matches = store.contacts.filter((contact) => contactDisplayNameKey(contact.displayName) === wanted);
    if (matches.length !== 1) {
      throw new HelloLynkLocalContactsError(matches.length ? "contact_reference_ambiguous" : "contact_not_found");
    }
    return {
      hellolynkId: matches[0].hellolynkId,
      displayName: matches[0].displayName,
      contactId: matches[0].contactId,
      source: "local_contact",
    };
  }

  async function setAutonomousSendAuthorization(contactId, delegateId, enabled, peerDelegateId = null) {
    const acceptedContactId = normalizeContactId(contactId);
    const acceptedDelegateId = normalizeDelegateId(delegateId);
    const acceptedPeerDelegateId = peerDelegateId == null ? null : normalizeDelegateId(peerDelegateId);
    if (typeof enabled !== "boolean") throw new HelloLynkLocalContactsError("contact_authorization_enabled_invalid");
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      const delegates = new Set(contact.autonomousSendDelegateIds);
      const instance = acceptedPeerDelegateId == null ? null : requireContactInstance(contact, acceptedPeerDelegateId);
      if (enabled) {
        if (!delegates.has(acceptedDelegateId)
          && delegates.size >= MAX_AUTHORIZED_DELEGATES_PER_CONTACT) {
          throw new HelloLynkLocalContactsError("contact_authorization_capacity_exceeded");
        }
        delegates.add(acceptedDelegateId);
      } else if (!instance) {
        delegates.delete(acceptedDelegateId);
      }
      if (instance) {
        const instanceDelegates = new Set(instance.autonomousSendDelegateIds);
        if (enabled) {
          if (!instanceDelegates.has(acceptedDelegateId)
            && instanceDelegates.size >= MAX_AUTHORIZED_DELEGATES_PER_CONTACT) {
            throw new HelloLynkLocalContactsError("contact_authorization_capacity_exceeded");
          }
          instanceDelegates.add(acceptedDelegateId);
        } else instanceDelegates.delete(acceptedDelegateId);
        instance.autonomousSendDelegateIds = [...instanceDelegates].sort();
        instance.updatedAt = normalizeTimestamp(now());
      } else if (!enabled) {
        for (const child of contact.instances) {
          child.autonomousSendDelegateIds = child.autonomousSendDelegateIds.filter((id) => id !== acceptedDelegateId);
        }
      }
      contact.autonomousSendDelegateIds = [...delegates].sort();
      contact.updatedAt = normalizeTimestamp(now());
      return projectContactForDelegate(contact, acceptedDelegateId);
    }, protection);
  }

  async function getAiReadAuthorization(localDelegateId) {
    normalizeDelegateId(localDelegateId);
    // Reading the owner's data is intrinsic; persisted legacy read grants do
    // not constrain it. Send grants remain separate and revocable.
    return Object.freeze({ contactRequests: true });
  }

  async function listForDelegate(delegateId) {
    const acceptedDelegateId = normalizeDelegateId(delegateId);
    const store = await readStore(storePath, profileId, protection);
    return store.contacts
      .slice()
      .sort((left, right) => left.displayName.localeCompare(right.displayName, "zh-CN"))
      .map((contact) => projectContactForDelegate(contact, acceptedDelegateId));
  }

  async function listAuthorizedForDelegate(delegateId) {
    return listAuthorizedRoutesForDelegate(delegateId);
  }

  async function listAuthorizedRoutesForDelegate(delegateId) {
    const acceptedDelegateId = normalizeDelegateId(delegateId);
    const store = await readStore(storePath, profileId, protection);
    return store.contacts
      .filter((contact) => contact.autonomousSendDelegateIds.includes(acceptedDelegateId))
      .flatMap((contact) => contact.instances
        .filter((instance) => instance.autonomousSendDelegateIds.includes(acceptedDelegateId))
        .map((instance) => ({
        contactId: contact.contactId,
        hellolynkId: contact.hellolynkId,
        principalId: contact.principalId,
        displayName: contact.displayName,
        recipientDelegateId: instance.delegateId,
        instanceDisplayName: instance.displayName,
        clientType: instance.clientType,
      })));
  }

  async function listReadableRoutesForDelegate(localDelegateId) {
    normalizeDelegateId(localDelegateId);
    const store = await readStore(storePath, profileId, protection);
    return store.contacts
      .flatMap((contact) => contact.instances
        .map((instance) => ({
          contactId: contact.contactId,
          hellolynkId: contact.hellolynkId,
          principalId: contact.principalId,
          displayName: contact.displayName,
          recipientDelegateId: instance.delegateId,
          instanceDisplayName: instance.displayName,
          clientType: instance.clientType,
        })));
  }

  async function resolveAuthorizedInbound(hellolynkId, delegateId, peerDelegateId = null) {
    const acceptedHelloLynkId = normalizeContactHelloLynkId(hellolynkId);
    normalizeDelegateId(delegateId);
    const store = await readStore(storePath, profileId, protection);
    const contact = store.contacts.find((item) => item.hellolynkId === acceptedHelloLynkId);
    if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
    const instance = peerDelegateId == null ? null : requireContactInstance(contact, normalizeDelegateId(peerDelegateId));
    return {
      contactId: contact.contactId,
      displayName: contact.displayName,
      authorization: "contact_delegate_allowlist",
      ...(instance ? { ...resolvedInstance(contact, instance), senderDelegateId: instance.delegateId } : {}),
    };
  }

  async function resolveAuthorizedSend(contactId, delegateId, peerDelegateId = null) {
    const acceptedContactId = normalizeContactId(contactId);
    const acceptedDelegateId = normalizeDelegateId(delegateId);
    const store = await readStore(storePath, profileId, protection);
    const contact = store.contacts.find((item) => item.contactId === acceptedContactId);
    if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
    if (!contact.autonomousSendDelegateIds.includes(acceptedDelegateId)) {
      throw new HelloLynkLocalContactsError("contact_autonomous_send_not_authorized");
    }
    const instance = peerDelegateId == null ? null : requireAuthorizedContactInstance(contact,
      normalizeDelegateId(peerDelegateId), acceptedDelegateId, "contact_autonomous_send_not_authorized");
    return {
      contactId: contact.contactId,
      hellolynkId: contact.hellolynkId,
      displayName: contact.displayName,
      authorization: "contact_delegate_allowlist",
      ...(instance ? resolvedInstance(contact, instance) : {}),
    };
  }

  async function resolveAuthorizedReply(hellolynkId, delegateId, peerDelegateId) {
    const acceptedHelloLynkId = normalizeContactHelloLynkId(hellolynkId);
    const acceptedDelegateId = normalizeDelegateId(delegateId);
    const acceptedPeerDelegateId = normalizeDelegateId(peerDelegateId);
    // Admission linearizes at these checks under the contact mutation lock.
    // The send grant comes from one snapshot. Release the lock before any network
    // work: a later revocation cannot cancel a send already admitted here.
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.hellolynkId === acceptedHelloLynkId);
      if (!contact) throw new HelloLynkLocalContactsError("contact_not_found");
      if (!contact.autonomousSendDelegateIds.includes(acceptedDelegateId)) {
        throw new HelloLynkLocalContactsError("contact_autonomous_send_not_authorized");
      }
      const instance = requireAuthorizedContactInstance(contact, acceptedPeerDelegateId,
        acceptedDelegateId, "contact_autonomous_send_not_authorized");
      return noStoreWrite({ ...resolvedInstance(contact, instance), authorization: "contact_delegate_allowlist" });
    }, protection);
  }

  async function revokeAutonomousMessagingByHelloLynkId(hellolynkId) {
    const acceptedHelloLynkId = normalizeContactHelloLynkId(hellolynkId);
    return mutateStore(storePath, profileId, async (store) => {
      const contact = store.contacts.find((item) => item.hellolynkId === acceptedHelloLynkId);
      if (!contact) return noStoreWrite(
        Object.freeze({ contactFound: false, revokedDelegateCount: 0 }),
      );
      const revokedDelegateCount = new Set([
        ...contact.autonomousSendDelegateIds,
        ...contact.continuousReadDelegateIds,
        ...contact.instances.flatMap((instance) => [
          ...instance.autonomousSendDelegateIds,
          ...instance.continuousReadDelegateIds,
        ]),
      ]).size;
      if (revokedDelegateCount === 0) return noStoreWrite(
        Object.freeze({ contactFound: true, revokedDelegateCount: 0 }),
      );
      contact.autonomousSendDelegateIds = [];
      contact.continuousReadDelegateIds = [];
      for (const instance of contact.instances) {
        instance.autonomousSendDelegateIds = [];
        instance.continuousReadDelegateIds = [];
        if (instance.continuousReadAfterSeq) instance.continuousReadAfterSeq = [];
      }
      contact.updatedAt = normalizeTimestamp(now());
      return Object.freeze({ contactFound: true, revokedDelegateCount });
    }, protection);
  }

  return Object.freeze({
    contractId: CONTACTS_CONTRACT,
    path: storePath,
    profileId,
    snapshot,
    list: async () => (await snapshot()).contacts,
    listForDelegate,
    listAuthorizedForDelegate,
    listAuthorizedRoutesForDelegate,
    listReadableRoutesForDelegate,
    resolveAuthorizedInbound,
    resolveAuthorizedSend,
    resolveAuthorizedReply,
    revokeAutonomousMessagingByHelloLynkId,
    setAutonomousSendAuthorization,
    getAiReadAuthorization,
    upsertInstance,
    renameInstance,
    removeInstance,
    resolveInstance,
    save,
    rename,
    synchronizeRelationships,
    delete: remove,
    resolve,
  });
}

function emptyStore(profileId) {
  return {
    schemaVersion: SCHEMA_VERSION,
    contractId: CONTACTS_CONTRACT,
    profileId,
    contacts: [],
    contactRequestReadDelegateIds: [],
    relationshipSync: { owner: null, generations: [], pendingDeletedHelloLynkIds: [] },
  };
}

function publicSnapshot(store, storePath) {
  const contacts = store.contacts
    .slice()
    .sort((left, right) => left.displayName.localeCompare(right.displayName, "zh-CN"))
    .map((contact) => publicContact(contact));
  return {
    schemaVersion: SCHEMA_VERSION,
    contractId: CONTACTS_CONTRACT,
    profileId: store.profileId,
    contacts,
    count: contacts.length,
    storage: "local_file",
    storePath,
  };
}

function normalizeContactDataProtection(protector, profileId) {
  if (protector == null) return null;
  if (["sealJson", "openJson"].some((method) => typeof protector?.[method] !== "function")) {
    throw new HelloLynkLocalContactsError("contact_data_protector_invalid");
  }
  return Object.freeze({
    protector,
    context: Object.freeze({
      profileId,
      assetKind: "contacts",
      logicalPath: `contacts/${profileId}.json`,
    }),
  });
}

async function readStore(storePath, profileId, protection = null) {
  await assertContactStoreAccess(storePath, protection);
  await assertSafeStoreDirectories(storePath, { create: false });
  const physicalMaximum = protection ? MAX_PROTECTED_STORE_BYTES : MAX_STORE_BYTES;
  let metadata;
  let handle;
  try {
    metadata = await lstat(storePath);
  } catch (error) {
    if (error?.code === "ENOENT") return emptyStore(profileId);
    throw new HelloLynkLocalContactsError("contact_store_read_failed", { cause: error });
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > physicalMaximum) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  let parsed;
  try {
    handle = await open(storePath, "r");
    const openedMetadata = await handle.stat();
    const windowsUnreportedDevice = process.platform === "win32"
      && (metadata.dev === 0 || openedMetadata.dev === 0);
    if (!openedMetadata.isFile() || openedMetadata.size > physicalMaximum
      || (windowsUnreportedDevice && metadata.ino !== openedMetadata.ino)
      || (Number.isSafeInteger(metadata.dev) && Number.isSafeInteger(metadata.ino)
        && Number.isSafeInteger(openedMetadata.dev) && Number.isSafeInteger(openedMetadata.ino)
        && (metadata.ino !== openedMetadata.ino
          || (metadata.dev !== openedMetadata.dev
            && !windowsUnreportedDevice)))) {
      throw new HelloLynkLocalContactsError("contact_store_invalid");
    }
    const stored = JSON.parse(await handle.readFile("utf8"));
    parsed = protection
      ? await protection.protector.openJson(stored, protection.context)
      : stored;
    if (serializedStoreBytes(parsed) > MAX_STORE_BYTES) {
      throw new HelloLynkLocalContactsError("contact_store_invalid");
    }
  } catch (error) {
    throw new HelloLynkLocalContactsError("contact_store_invalid", { cause: error });
  } finally {
    await handle?.close().catch(() => {});
  }
  try {
    return assertHelloLynkLocalContactStore(parsed, profileId);
  } catch (error) {
    throw new HelloLynkLocalContactsError("contact_store_invalid", { cause: error });
  }
}

export function assertHelloLynkLocalContactStore(input, expectedProfileId) {
  const profileId = normalizeProfileId(expectedProfileId);
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  assertExactObjectFields(
    input,
    ["schemaVersion", "contractId", "profileId", "contacts",
      ...(input.schemaVersion >= 3 ? ["contactRequestReadDelegateIds"] : []),
      ...(input.schemaVersion === SCHEMA_VERSION ? ["relationshipSync"] : [])],
  );
  if (!READABLE_SCHEMA_VERSIONS.has(input.schemaVersion) || input.contractId !== CONTACTS_CONTRACT
    || input.profileId !== profileId || !Array.isArray(input.contacts)
    || input.contacts.length > MAX_CONTACTS) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  const ids = new Set();
  const stableAliases = new Set();
  const names = new Set();
  const contacts = input.contacts.map((contact) => {
    assertExactObjectFields(contact, [
      "contactId",
      "hellolynkId",
      "displayName",
      ...(Object.hasOwn(contact, "principalId") ? ["principalId"] : []),
      ...(Object.hasOwn(contact, "instances") ? ["instances"] : []),
      "safetyCode",
      ...(Object.hasOwn(contact, "safetyCodeVerificationState")
        ? ["safetyCodeVerificationState"]
        : []),
      "autonomousSendDelegateIds",
      ...(input.schemaVersion >= 3 ? ["continuousReadDelegateIds"] : []),
      "createdAt",
      "updatedAt",
    ]);
    const normalized = normalizeStoredContact(contact, input.schemaVersion);
    const nameKey = contactDisplayNameKey(normalized.displayName);
    const stableAlias = classifyHelloLynkStableId(normalized.hellolynkId)?.aliasKey;
    if (ids.has(normalized.contactId) || stableAliases.has(stableAlias) || names.has(nameKey)) {
      throw new HelloLynkLocalContactsError("contact_store_invalid");
    }
    ids.add(normalized.contactId);
    stableAliases.add(stableAlias);
    names.add(nameKey);
    return normalized;
  });
  return {
    ...emptyStore(profileId),
    contacts,
    contactRequestReadDelegateIds: normalizeAuthorizedDelegateIds(input.contactRequestReadDelegateIds ?? []),
    relationshipSync: structuredClone(runtimeSafety.normalizeHelloLynkRelationshipSync(
      input.schemaVersion === SCHEMA_VERSION ? input.relationshipSync
        : { owner: null, generations: [], pendingDeletedHelloLynkIds: [] })),
  };
}

function clearPendingContactDeletion(store, hellolynkId) {
  store.relationshipSync.pendingDeletedHelloLynkIds = store.relationshipSync.pendingDeletedHelloLynkIds
    .filter((peer) => peer !== hellolynkId);
}

function rememberDeletedContact(store, hellolynkId) {
  const sync = store.relationshipSync;
  // Older manual records may include peers that this owner can never import.
  // Deleting those remains local and does not need an ineligible sync marker.
  if (sync.owner) {
    const peer = classifyHelloLynkStableId(hellolynkId);
    const owner = classifyHelloLynkStableId(sync.owner.hellolynkId);
    if (peer.region !== owner.region || peer.aliasKey === owner.aliasKey) return;
  }
  const generations = sync.generations.filter((item) => item.hellolynkId === hellolynkId);
  if (generations.length) {
    for (const item of generations) item.suppressed = true;
  } else if (!sync.pendingDeletedHelloLynkIds.includes(hellolynkId)) {
    if (sync.generations.length + sync.pendingDeletedHelloLynkIds.length >= MAX_RELATIONSHIP_SYNC_RECORDS) {
      throw new HelloLynkLocalContactsError("contact_relationship_sync_capacity_exceeded");
    }
    sync.pendingDeletedHelloLynkIds.push(hellolynkId);
  }
}

function assertRelationshipPeer(hellolynkId, owner) {
  const peer = classifyHelloLynkStableId(hellolynkId);
  const identity = classifyHelloLynkStableId(owner.hellolynkId);
  if (!peer || peer.region !== identity?.region || peer.aliasKey === identity.aliasKey) {
    throw new HelloLynkLocalContactsError("contact_relationship_peer_invalid");
  }
}

function normalizeRelationshipSynchronization(input) {
  assertExactObjectFields(input, ["principalId", "hellolynkId", "relationships"]);
  const owner = {
    principalId: normalizeDelegateId(input.principalId),
    hellolynkId: normalizeContactHelloLynkId(input.hellolynkId),
  };
  if (!Array.isArray(input.relationships)) throw new HelloLynkLocalContactsError("contact_relationships_invalid");
  const ids = new Set();
  const peers = new Set();
  const relationships = input.relationships.map((relationship) => {
    assertExactObjectFields(relationship, [
      "relationshipId", "otherPrincipal", "status", "createdAt", "updatedAt", "endedAt",
    ]);
    const other = relationship.otherPrincipal;
    assertExactObjectFields(other, ["displayName", "hellolynkId",
      ...(other && Object.hasOwn(other, "hellolynkIdPurpose") ? ["hellolynkIdPurpose"] : [])]);
    if ((Object.hasOwn(other, "hellolynkIdPurpose")
      && other.hellolynkIdPurpose !== "human_identity_verification_only")
      || typeof other.displayName !== "string"
      || typeof relationship.relationshipId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,240}$/.test(relationship.relationshipId)
      || !["active", "ended"].includes(relationship.status)) {
      throw new HelloLynkLocalContactsError("contact_relationships_invalid");
    }
    const peer = normalizeContactHelloLynkId(other.hellolynkId);
    assertRelationshipPeer(peer, owner);
    if (ids.has(relationship.relationshipId) || peers.has(peer)) {
      throw new HelloLynkLocalContactsError("contact_relationships_invalid");
    }
    ids.add(relationship.relationshipId);
    peers.add(peer);
    for (const field of ["createdAt", "updatedAt", "endedAt"]) {
      if (field === "endedAt" && relationship[field] === null) continue;
      if (typeof relationship[field] !== "string" || !Number.isFinite(Date.parse(relationship[field]))) {
        throw new HelloLynkLocalContactsError("contact_relationships_invalid");
      }
    }
    if ((relationship.status === "active") !== (relationship.endedAt === null)) {
      throw new HelloLynkLocalContactsError("contact_relationships_invalid");
    }
    return { ...relationship, otherPrincipal: { displayName: other.displayName, hellolynkId: peer } };
  });
  relationships.sort((left, right) => left.otherPrincipal.hellolynkId.localeCompare(right.otherPrincipal.hellolynkId, "en"));
  return { owner, relationships };
}

function automaticContactDisplayName(value, hellolynkId, contacts) {
  let base;
  try { base = normalizeContactDisplayName(value); } catch { base = "联系人"; }
  const names = new Set(contacts.map((contact) => contactDisplayNameKey(contact.displayName)));
  if (!names.has(contactDisplayNameKey(base))) return base;
  const digest = crypto.createHash("sha256").update(hellolynkId).digest("hex");
  for (let attempt = 0; attempt <= MAX_CONTACTS; attempt += 1) {
    const suffix = ` (${digest.slice(0, 8)}${attempt ? `-${attempt}` : ""})`;
    const name = `${[...base].slice(0, 80 - suffix.length).join("")}${suffix}`;
    if (!names.has(contactDisplayNameKey(name))) return name;
  }
  throw new HelloLynkLocalContactsError("contact_display_name_conflict");
}

function assertExactObjectFields(value, fields, code = "contact_store_invalid") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HelloLynkLocalContactsError(code);
  }
  const observed = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (observed.length !== expected.length
    || observed.some((field, index) => field !== expected[index])) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
}

function normalizeStoredContact(contact, schemaVersion) {
  if (!contact || typeof contact !== "object" || Array.isArray(contact)) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  const safetyCode = normalizeContactSafetyCode(contact.safetyCode);
  const principalId = contact.principalId == null ? null : normalizeDelegateId(contact.principalId);
  const instances = normalizeContactInstances(contact.instances ?? [], schemaVersion);
  if (instances.length && principalId == null) throw new HelloLynkLocalContactsError("contact_store_invalid");
  return {
    contactId: normalizeContactId(contact.contactId),
    hellolynkId: normalizeContactHelloLynkId(contact.hellolynkId),
    displayName: normalizeContactDisplayName(contact.displayName),
    principalId,
    instances,
    safetyCode,
    safetyCodeVerificationState: normalizeSafetyCodeVerificationState(
      contact.safetyCodeVerificationState,
      safetyCode,
      Object.hasOwn(contact, "safetyCodeVerificationState"),
    ),
    autonomousSendDelegateIds: normalizeAuthorizedDelegateIds(contact.autonomousSendDelegateIds),
    continuousReadDelegateIds: normalizeAuthorizedDelegateIds(contact.continuousReadDelegateIds ?? []),
    createdAt: normalizeTimestamp(contact.createdAt),
    updatedAt: normalizeTimestamp(contact.updatedAt),
  };
}

function publicContact(contact) {
  return {
    contactId: contact.contactId,
    hellolynkId: contact.hellolynkId,
    displayName: contact.displayName,
    principalId: contact.principalId,
    instances: contact.instances.map((instance) => publicInstance(instance)),
    createdAt: contact.createdAt,
    updatedAt: contact.updatedAt,
  };
}

function projectContactForDelegate(contact, delegateId) {
  return {
    ...publicContact(contact),
    autonomousSendAuthorized: contact.autonomousSendDelegateIds.includes(delegateId),
    continuousReadAuthorized: true,
    instances: contact.instances.map((instance) => ({
      ...publicInstance(instance),
      autonomousSendAuthorized: contact.autonomousSendDelegateIds.includes(delegateId)
        && instance.autonomousSendDelegateIds.includes(delegateId),
      continuousReadAuthorized: true,
    })),
  };
}

function normalizeInstanceClientType(value) {
  if (!INSTANCE_CLIENT_TYPES.has(value)) throw new HelloLynkLocalContactsError("contact_instance_client_type_invalid");
  return value;
}

function normalizeContactInstances(value, schemaVersion) {
  if (!Array.isArray(value) || value.length > MAX_INSTANCES_PER_CONTACT) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  const ids = new Set();
  return value.map((instance) => {
    assertExactObjectFields(instance, ["delegateId", "clientType", "displayName", "createdAt", "updatedAt", "autonomousSendDelegateIds",
      ...(schemaVersion >= 3 ? ["continuousReadDelegateIds"] : []),
      ...(Object.hasOwn(instance, "continuousReadAfterSeq") ? ["continuousReadAfterSeq"] : [])]);
    const delegateId = normalizeDelegateId(instance.delegateId);
    if (ids.has(delegateId)) throw new HelloLynkLocalContactsError("contact_store_invalid");
    ids.add(delegateId);
    return {
      delegateId,
      clientType: normalizeInstanceClientType(instance.clientType),
      displayName: normalizeContactDisplayName(instance.displayName),
      createdAt: normalizeTimestamp(instance.createdAt),
      updatedAt: normalizeTimestamp(instance.updatedAt),
      autonomousSendDelegateIds: normalizeAuthorizedDelegateIds(instance.autonomousSendDelegateIds),
      continuousReadDelegateIds: normalizeAuthorizedDelegateIds(instance.continuousReadDelegateIds ?? []),
      ...(Object.hasOwn(instance, "continuousReadAfterSeq") ? {
        continuousReadAfterSeq: normalizeReadBoundaries(instance.continuousReadAfterSeq, instance.continuousReadDelegateIds),
      } : {}),
    };
  });
}

function normalizeReadBoundaries(value, authorizedIds) {
  if (!Array.isArray(value) || value.length > MAX_AUTHORIZED_DELEGATES_PER_CONTACT) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  const seen = new Set();
  return value.map((entry) => {
    assertExactObjectFields(entry, ["delegateId", "afterSeq"]);
    const delegateId = normalizeDelegateId(entry.delegateId);
    if (entry.delegateId !== delegateId || seen.has(delegateId) || !authorizedIds?.includes(delegateId)
      || (entry.afterSeq !== null && (!Number.isSafeInteger(entry.afterSeq) || entry.afterSeq < 0))) {
      throw new HelloLynkLocalContactsError("contact_store_invalid");
    }
    seen.add(delegateId);
    return { delegateId, afterSeq: entry.afterSeq };
  });
}

function publicInstance(instance) {
  return {
    delegateId: instance.delegateId,
    clientType: instance.clientType,
    displayName: instance.displayName,
    createdAt: instance.createdAt,
    updatedAt: instance.updatedAt,
  };
}

function requireContactInstance(contact, peerDelegateId) {
  const instance = contact.instances.find((item) => item.delegateId === peerDelegateId);
  if (!instance || contact.principalId == null) throw new HelloLynkLocalContactsError("contact_instance_not_found");
  return instance;
}

function requireAuthorizedContactInstance(contact, peerDelegateId, localDelegateId, errorCode,
  authorizationField = "autonomousSendDelegateIds") {
  const instance = requireContactInstance(contact, peerDelegateId);
  if (!instance[authorizationField].includes(localDelegateId)) {
    throw new HelloLynkLocalContactsError(errorCode);
  }
  return instance;
}

function resolvedInstance(contact, instance) {
  return {
    contactId: contact.contactId,
    hellolynkId: contact.hellolynkId,
    principalId: contact.principalId,
    displayName: contact.displayName,
    recipientDelegateId: instance.delegateId,
    instance: publicInstance(instance),
  };
}

function normalizeAuthorizedDelegateIds(value) {
  if (!Array.isArray(value) || value.length > MAX_AUTHORIZED_DELEGATES_PER_CONTACT) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  const normalized = value.map(normalizeDelegateId);
  if (new Set(normalized).size !== normalized.length) throw new HelloLynkLocalContactsError("contact_store_invalid");
  return normalized.sort();
}

function normalizeDelegateId(value) {
  const delegateId = String(value || "").trim();
  if (!DELEGATE_ID_RE.test(delegateId)) throw new HelloLynkLocalContactsError("contact_delegate_id_invalid");
  return delegateId;
}

async function mutateStore(storePath, profileId, callback, protection = null) {
  const previous = mutationQueues.get(storePath) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => current);
  mutationQueues.set(storePath, tail);
  await previous;
  try {
    return await withFileLock(storePath, async () => {
      const store = await readStore(storePath, profileId, protection);
      const result = await callback(store);
      if (result?.[NO_STORE_WRITE] === true) return result.value;
      await atomicWriteStore(storePath, store, protection);
      return result;
    });
  } finally {
    release();
    if (mutationQueues.get(storePath) === tail) mutationQueues.delete(storePath);
  }
}

function initialSafetyCodeVerificationState(safetyCode) {
  return safetyCode
    ? SAFETY_CODE_VERIFICATION_STATES.verificationRequired
    : SAFETY_CODE_VERIFICATION_STATES.unavailable;
}

function normalizeSafetyCodeVerificationState(value, safetyCode, explicitlyStored) {
  const state = explicitlyStored ? String(value || "") : initialSafetyCodeVerificationState(safetyCode);
  if (!Object.values(SAFETY_CODE_VERIFICATION_STATES).includes(state)) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  if ((safetyCode == null) !== (state === SAFETY_CODE_VERIFICATION_STATES.unavailable)) {
    throw new HelloLynkLocalContactsError("contact_store_invalid");
  }
  return state;
}

function noStoreWrite(value) {
  return { [NO_STORE_WRITE]: true, value };
}

async function withFileLock(storePath, callback) {
  const lockPath = `${storePath}.lock`;
  await assertSafeStoreDirectories(storePath, { create: true });
  let handle = null;
  let token = "";
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      handle = await open(lockPath, "wx", 0o600);
      token = crypto.randomBytes(24).toString("hex");
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, token, createdAt: Date.now() })}\n`, "utf8");
      await handle.sync();
      break;
    } catch (error) {
      await handle?.close().catch(() => {});
      handle = null;
      if (error?.code !== "EEXIST") throw error;
      await recoverDeadLock(lockPath);
      await delay(LOCK_WAIT_MS);
    }
  }
  if (!handle) throw new HelloLynkLocalContactsError("contact_store_busy");
  try {
    return await callback();
  } finally {
    await handle.close().catch(() => {});
    try {
      const current = JSON.parse(await readFile(lockPath, "utf8"));
      if (current?.token === token) await rm(lockPath);
    } catch {}
  }
}

async function recoverDeadLock(lockPath) {
  let metadata;
  try {
    metadata = await lstat(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile() || Date.now() - metadata.mtimeMs < LOCK_STALE_MS) return false;
  let record;
  try {
    record = JSON.parse(await readFile(lockPath, "utf8"));
  } catch {
    return false;
  }
  const pid = Number(record?.pid);
  if (!Number.isSafeInteger(pid) || pid <= 0 || processAlive(pid)) return false;
  try {
    await rm(lockPath);
    return true;
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM"].includes(error?.code)) return false;
    throw error;
  }
}

async function atomicWriteStore(storePath, store, protection = null) {
  await assertContactStoreAccess(storePath, protection);
  await assertSafeStoreDirectories(storePath, { create: true });
  if (serializedStoreBytes(store) > MAX_STORE_BYTES) {
    throw new HelloLynkLocalContactsError("contact_store_too_large");
  }
  const stored = protection
    ? await protection.protector.sealJson(store, protection.context)
    : store;
  const body = `${JSON.stringify(stored, null, 2)}\n`;
  if (Buffer.byteLength(body, "utf8") > (protection ? MAX_PROTECTED_STORE_BYTES : MAX_STORE_BYTES)) {
    throw new HelloLynkLocalContactsError("contact_store_too_large");
  }
  const temporary = `${storePath}.${crypto.randomUUID()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await assertContactStoreAccess(storePath, protection);
    let lastError;
    for (const wait of [0, 25, 75, 200]) {
      if (wait) await delay(wait);
      try {
        await rename(temporary, storePath);
        return;
      } catch (error) {
        lastError = error;
        if (!["EACCES", "EPERM", "EBUSY"].includes(error?.code)) throw error;
      }
    }
    throw lastError;
  } catch (error) {
    await rm(temporary, { force: true });
    throw new HelloLynkLocalContactsError("contact_store_write_failed", { cause: error });
  }
}

async function assertContactStoreAccess(storePath, protection) {
  const contactsDirectory = path.dirname(path.resolve(storePath));
  const dataRoot = path.basename(contactsDirectory) === "contacts"
    ? path.dirname(contactsDirectory)
    : contactsDirectory;
  try {
    await assertLocalDataProtectionAccess(dataRoot, protection != null);
  } catch (error) {
    if (error instanceof HelloLynkLocalContactsError) throw error;
    throw new HelloLynkLocalContactsError(error?.code || "contact_store_access_invalid", { cause: error });
  }
}

function serializedStoreBytes(store) {
  return Buffer.byteLength(`${JSON.stringify(store, null, 2)}\n`, "utf8");
}

async function assertSafeStoreDirectories(storePath, options = {}) {
  const contactsDir = path.dirname(storePath);
  const rootDir = path.dirname(contactsDir);
  const create = options.create === true;
  await assertSafeDirectory(rootDir, { create, recursive: true });
  await assertSafeDirectory(contactsDir, { create, recursive: false });
}

async function assertSafeDirectory(directoryPath, options = {}) {
  let metadata;
  try {
    metadata = await lstat(directoryPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw new HelloLynkLocalContactsError("contact_store_directory_invalid", { cause: error });
    }
    if (!options.create) return false;
    try {
      await mkdir(directoryPath, { recursive: options.recursive === true });
      metadata = await lstat(directoryPath);
    } catch (createError) {
      throw new HelloLynkLocalContactsError("contact_store_directory_invalid", { cause: createError });
    }
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new HelloLynkLocalContactsError("contact_store_directory_invalid");
  }
  return true;
}

function normalizeProfileId(value) {
  const profileId = String(value || "").trim();
  if (!PROFILE_ID_RE.test(profileId)) throw new HelloLynkLocalContactsError("contact_profile_id_invalid");
  return profileId;
}

function normalizeContactId(value) {
  const contactId = String(value || "").trim();
  if (!CONTACT_ID_RE.test(contactId)) throw new HelloLynkLocalContactsError("contact_id_invalid");
  return contactId;
}

function normalizeTimestamp(value) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.valueOf())) throw new HelloLynkLocalContactsError("contact_timestamp_invalid");
  return parsed.toISOString();
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
