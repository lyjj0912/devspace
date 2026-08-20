import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeRuntimeContractIdentities,
  generatedRuntimeContractIdentitySource,
} from "../src/v2/contract-generation.ts";
import { generatedContractFiles, prettyGeneratedJson } from "../src/v2/generated-contracts.ts";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generatedFiles = generatedContractFiles();
const identities = computeRuntimeContractIdentities({
  authorityPolicySource: readFileSync(resolve(root, "src/v2/authority-policy.ts"), "utf8"),
  authorityPrincipalSource: readFileSync(resolve(root, "src/v2/authority-principal.ts"), "utf8"),
  authorityCoreSource: readFileSync(resolve(root, "src/v2/authority.ts"), "utf8"),
  serverCanonicalizationSource: readFileSync(resolve(root, "src/v2/server.ts"), "utf8"),
  connectorAuthorityDescriptorSource: readFileSync(resolve(root, "src/oauth-store.ts"), "utf8"),
  connectorActivationEvidenceSource: readFileSync(
    resolve(root, "src/v2/connector-activation-evidence.ts"),
    "utf8",
  ),
  connectorActivationFinalizerSource: readFileSync(
    resolve(root, "src/v2/connector-activation-finalizer.ts"),
    "utf8",
  ),
  connectorStagingActivationContractSource: readFileSync(
    resolve(root, "src/v2/connector-staging-activation-contract.ts"),
    "utf8",
  ),
  connectorRouteIdentitySource: readFileSync(
    resolve(root, "src/v2/connector-route-identity.ts"),
    "utf8",
  ),
  resourceUriSource: readFileSync(resolve(root, "src/v2/resource-uri.ts"), "utf8"),
  unifiedConfigSource: readFileSync(resolve(root, "src/v2/unified-config.ts"), "utf8"),
  unifiedConfigSchema: generatedFiles["config/config.schema.json"],
});
writeFileSync(
  resolve(root, "src/v2/runtime-contract-identity.ts"),
  generatedRuntimeContractIdentitySource(identities),
  { encoding: "utf8", mode: 0o644 },
);
for (const [relative, value] of Object.entries(generatedFiles)) {
  const destination = resolve(root, relative);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, prettyGeneratedJson(value), { encoding: "utf8", mode: 0o644 });
}
