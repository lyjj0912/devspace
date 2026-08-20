import assert from "node:assert/strict";
import test from "node:test";
import {
  formatResourceUri,
  parseResourceUri,
  ResourceUriError,
  type VersionedResourceReference,
} from "./resource-uri.js";

test("all canonical resource references issue and round-trip only devspace v1 URIs", () => {
  const references: VersionedResourceReference[] = [
    { kind: "process-output", processId: "proc 1" },
    { kind: "context-diff", diffId: "diff/one" },
    { kind: "mcp-resource", routeId: "route one", opaque: "fixture://state/a" },
    { kind: "mcp-result", resultId: "result one" },
    { kind: "artifact", artifactId: "123e4567-e89b-12d3-a456-426614174000" },
  ];

  for (const reference of references) {
    const uri = formatResourceUri(reference);
    assert.match(uri, /^devspace:\/\/v1\//u);
    assert.deepEqual(parseResourceUri(uri), { version: 1, legacy: false, ...reference });
  }
});

test("base profile never issues GUI capture URIs but retains bounded legacy reads", () => {
  assert.throws(
    () => parseResourceUri("devspace://v1/gui/session/capture/generation"),
    hasReason("RESOURCE_URI_UNSUPPORTED"),
  );
  assert.deepEqual(
    parseResourceUri("devspace://gui/session/capture/generation", { allowLegacyRead: true }),
    {
      version: 0,
      legacy: true,
      kind: "gui-capture",
      sessionId: "session",
      generation: "generation",
    },
  );
});

test("legacy resource formats are accepted only by the explicit read-only parser", () => {
  const legacy = "devspace://artifact/123e4567-e89b-12d3-a456-426614174000";
  assert.throws(() => parseResourceUri(legacy), hasReason("RESOURCE_URI_LEGACY"));
  assert.deepEqual(parseResourceUri(legacy, { allowLegacyRead: true }), {
    version: 0,
    legacy: true,
    kind: "artifact",
    artifactId: "123e4567-e89b-12d3-a456-426614174000",
  });

  assert.deepEqual(
    parseResourceUri("devspace://process/proc_1/output/12/50", { allowLegacyRead: true }),
    {
      version: 0,
      legacy: true,
      kind: "process-output",
      processId: "proc_1",
      offset: 12,
      limit: 50,
    },
  );
});

test("canonical parsing rejects unknown versions, query data, and malformed segments", () => {
  for (const uri of [
    "devspace://v2/artifact/123e4567-e89b-12d3-a456-426614174000",
    "devspace://v1/artifact/123e4567-e89b-12d3-a456-426614174000?token=secret",
    "devspace://v1/process/proc/output/extra",
    "https://v1/artifact/id",
  ]) {
    assert.throws(() => parseResourceUri(uri), (error: unknown) => error instanceof ResourceUriError);
  }
});

function hasReason(reason: string) {
  return (error: unknown) => error instanceof ResourceUriError && error.reason === reason;
}
