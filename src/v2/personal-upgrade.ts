import { resolve } from "node:path";
import { BASE_PRODUCT_PROFILE } from "./profile-contract.js";

export interface PersonalDeploymentIdentity {
  productProfile: typeof BASE_PRODUCT_PROFILE;
  publicOrigin: string;
  oauthClientId: string;
  oauthResource: string;
  ownerInstanceId: string;
  connectorName: string;
  connectorInstallationEpoch: number;
}

export interface PersonalExistingDeploymentIdentity
  extends Omit<PersonalDeploymentIdentity, "productProfile"> {
  productProfile: typeof BASE_PRODUCT_PROFILE | "BASE_SINGLE_OWNER";
}

export interface PersonalRuntimeCandidate extends PersonalDeploymentIdentity {
  runtimePath: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
}

export interface PersonalStoreChange {
  id: string;
  path: string;
  kind: "sqlite" | "file" | "directory";
  changed: boolean;
  dependsOn?: readonly string[];
}

export interface PersonalUpgradeInput {
  existing: PersonalExistingDeploymentIdentity & { runtimePath: string };
  candidate: PersonalRuntimeCandidate;
  stores: readonly PersonalStoreChange[];
  currentRuntimePointer: string;
}

export interface PersonalUpgradePlan {
  productProfile: typeof BASE_PRODUCT_PROFILE;
  identityAction: "PRESERVE_EXISTING_BINDING";
  existingRuntimePath: string;
  candidateRuntimePath: string;
  currentRuntimePointer: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  migrationRequired: boolean;
  backupSet: readonly PersonalStoreChange[];
  phases: readonly [
    "PREPARE_IMMUTABLE_RUNTIME",
    "START_ISOLATED_CANDIDATE",
    "VERIFY_CANDIDATE",
    "ATOMIC_CURRENT_POINTER_SWITCH",
    "RESTART_PRODUCTION",
    "VERIFY_PRODUCTION",
    "REMOVE_CANDIDATE",
  ];
  rollback: {
    runtimePointer: string;
    restoreStores: readonly string[];
  };
}

const UPGRADE_PHASES = Object.freeze([
  "PREPARE_IMMUTABLE_RUNTIME",
  "START_ISOLATED_CANDIDATE",
  "VERIFY_CANDIDATE",
  "ATOMIC_CURRENT_POINTER_SWITCH",
  "RESTART_PRODUCTION",
  "VERIFY_PRODUCTION",
  "REMOVE_CANDIDATE",
] as const);

export function createPersonalUpgradePlan(input: PersonalUpgradeInput): PersonalUpgradePlan {
  assertIdentity(input.existing, "existing", true);
  assertIdentity(input.candidate, "candidate");
  assertPreservedBinding(input.existing, input.candidate);
  const existingRuntimePath = absolutePath(input.existing.runtimePath, "existing.runtimePath");
  const candidateRuntimePath = absolutePath(input.candidate.runtimePath, "candidate.runtimePath");
  if (existingRuntimePath === candidateRuntimePath) {
    throw new Error("Candidate runtime must differ from the current runtime.");
  }
  const currentRuntimePointer = absolutePath(input.currentRuntimePointer, "currentRuntimePointer");
  const stores = validatedStores(input.stores);
  const backupIds = dependencyClosure(stores);
  const backupSet = [...backupIds]
    .map((id) => stores.get(id)!)
    .sort((left, right) => left.id.localeCompare(right.id));
  return Object.freeze({
    productProfile: BASE_PRODUCT_PROFILE,
    identityAction: "PRESERVE_EXISTING_BINDING",
    existingRuntimePath,
    candidateRuntimePath,
    currentRuntimePointer,
    sourceRevision: requiredText(input.candidate.sourceRevision, "candidate.sourceRevision"),
    runtimeRevision: requiredText(input.candidate.runtimeRevision, "candidate.runtimeRevision"),
    buildDigest: sha256Identity(input.candidate.buildDigest, "candidate.buildDigest"),
    migrationRequired: backupSet.length > 0,
    backupSet: Object.freeze(backupSet),
    phases: UPGRADE_PHASES,
    rollback: Object.freeze({
      runtimePointer: existingRuntimePath,
      restoreStores: Object.freeze(backupSet.map((store) => store.id)),
    }),
  });
}

export function assertPersonalProductionReadback(
  expected: PersonalRuntimeCandidate,
  observed: PersonalDeploymentIdentity & {
    runtimePath: string;
    productionInstances: number;
    candidateInstances: number;
  },
): void {
  assertIdentity(observed, "observed");
  assertPreservedIdentity(expected, observed);
  if (resolve(observed.runtimePath) !== resolve(expected.runtimePath)) {
    throw new Error("Production runtime pointer does not resolve to the candidate runtime.");
  }
  if (observed.productionInstances !== 1 || observed.candidateInstances !== 0) {
    throw new Error("Canonical personal state requires one production runtime and zero candidates.");
  }
}

function validatedStores(input: readonly PersonalStoreChange[]): Map<string, PersonalStoreChange> {
  const stores = new Map<string, PersonalStoreChange>();
  const paths = new Set<string>();
  for (const store of input) {
    const id = requiredText(store.id, "store.id");
    if (!/^[a-z][a-z0-9-]{0,63}$/u.test(id) || stores.has(id)) {
      throw new Error(`Store id is invalid or duplicated: ${id}`);
    }
    const path = absolutePath(store.path, `store ${id} path`);
    if (paths.has(path)) throw new Error(`Store path is duplicated: ${path}`);
    paths.add(path);
    stores.set(id, Object.freeze({ ...store, id, path, dependsOn: Object.freeze([...(store.dependsOn ?? [])]) }));
  }
  for (const store of stores.values()) {
    for (const dependency of store.dependsOn ?? []) {
      if (!stores.has(dependency)) throw new Error(`Unknown dependency ${dependency} for store ${store.id}.`);
    }
  }
  return stores;
}

function dependencyClosure(stores: ReadonlyMap<string, PersonalStoreChange>): Set<string> {
  const selected = new Set([...stores.values()].filter((store) => store.changed).map((store) => store.id));
  const visit = (id: string, visiting: Set<string>): void => {
    if (visiting.has(id)) throw new Error(`Store dependency cycle includes ${id}.`);
    const next = new Set(visiting).add(id);
    for (const dependency of stores.get(id)?.dependsOn ?? []) {
      selected.add(dependency);
      visit(dependency, next);
    }
  };
  for (const id of [...selected]) visit(id, new Set());
  return selected;
}

function assertPreservedIdentity(
  expected: PersonalDeploymentIdentity,
  observed: PersonalDeploymentIdentity,
): void {
  for (const field of [
    "productProfile",
    "publicOrigin",
    "oauthClientId",
    "oauthResource",
    "ownerInstanceId",
    "connectorName",
    "connectorInstallationEpoch",
  ] as const) {
    if (expected[field] !== observed[field]) {
      throw new Error(`Runtime-only upgrade cannot change ${field}.`);
    }
  }
}

function assertPreservedBinding(
  expected: PersonalExistingDeploymentIdentity,
  observed: PersonalDeploymentIdentity,
): void {
  for (const field of [
    "publicOrigin",
    "oauthClientId",
    "oauthResource",
    "ownerInstanceId",
    "connectorName",
    "connectorInstallationEpoch",
  ] as const) {
    if (expected[field] !== observed[field]) {
      throw new Error(`Runtime-only upgrade cannot change ${field}.`);
    }
  }
}

function assertIdentity(
  value: PersonalDeploymentIdentity | PersonalExistingDeploymentIdentity,
  label: string,
  allowLegacyProfile = false,
): void {
  if (value.productProfile !== BASE_PRODUCT_PROFILE
      && !(allowLegacyProfile && value.productProfile === "BASE_SINGLE_OWNER")) {
    throw new Error(`${label}.productProfile must be ${BASE_PRODUCT_PROFILE}${allowLegacyProfile ? " or the legacy base profile" : ""}.`);
  }
  const origin = new URL(value.publicOrigin);
  if (origin.origin !== value.publicOrigin || origin.protocol !== "https:") {
    throw new Error(`${label}.publicOrigin must be one canonical HTTPS origin.`);
  }
  const resource = new URL(value.oauthResource);
  if (resource.protocol !== "https:") throw new Error(`${label}.oauthResource must be HTTPS.`);
  for (const field of ["oauthClientId", "ownerInstanceId", "connectorName"] as const) {
    requiredText(value[field], `${label}.${field}`);
  }
  if (!Number.isSafeInteger(value.connectorInstallationEpoch) || value.connectorInstallationEpoch < 1) {
    throw new Error(`${label}.connectorInstallationEpoch must be a positive integer.`);
  }
}

function absolutePath(value: string, label: string): string {
  const text = requiredText(value, label);
  if (!text.startsWith("/")) throw new Error(`${label} must be absolute.`);
  return resolve(text);
}

function requiredText(value: string, label: string): string {
  const text = value?.trim();
  if (!text || /[\0\r\n]/u.test(text)) throw new Error(`${label} is required and must be single-line.`);
  return text;
}

function sha256Identity(value: string, label: string): string {
  const text = requiredText(value, label);
  if (!/^sha256:[a-f0-9]{64}$/u.test(text)) throw new Error(`${label} must be a SHA-256 identity.`);
  return text;
}
