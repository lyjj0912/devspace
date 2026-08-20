export type VersionedResourceReference =
  | { kind: "process-output"; processId: string }
  | { kind: "context-diff"; diffId: string }
  | { kind: "mcp-resource"; routeId: string; opaque: string }
  | { kind: "mcp-result"; resultId: string }
  | { kind: "artifact"; artifactId: string };

type LegacyResourceReference =
  | VersionedResourceReference
  | { kind: "gui-capture"; sessionId: string; generation: string };

export type ParsedResourceReference =
  | ({ version: 1; legacy: false } & VersionedResourceReference)
  | ({ version: 0; legacy: true; offset?: number; limit?: number } & LegacyResourceReference);

export type ResourceUriFailureReason =
  | "RESOURCE_URI_INVALID"
  | "RESOURCE_URI_LEGACY"
  | "RESOURCE_URI_UNSUPPORTED";

export class ResourceUriError extends Error {
  readonly code = "RESOURCE_URI_ERROR";

  constructor(
    readonly reason: ResourceUriFailureReason,
    message: string,
  ) {
    super(message);
    this.name = "ResourceUriError";
  }
}

/** Issues only the canonical, versioned URI grammar. */
export function formatResourceUri(reference: VersionedResourceReference): string {
  switch (reference.kind) {
    case "process-output":
      return `devspace://v1/process/${component(reference.processId, "processId")}/output`;
    case "context-diff":
      return `devspace://v1/context-diff/${component(reference.diffId, "diffId")}`;
    case "mcp-resource":
      return `devspace://v1/mcp/${component(reference.routeId, "routeId")}/resource/${component(reference.opaque, "opaque")}`;
    case "mcp-result":
      return `devspace://v1/mcp-result/${component(reference.resultId, "resultId")}`;
    case "artifact":
      return `devspace://v1/artifact/${component(reference.artifactId, "artifactId")}`;
  }
}

export function parseResourceUri(
  resourceUri: string,
  options: { allowLegacyRead?: boolean } = {},
): ParsedResourceReference {
  const parsed = safeUrl(resourceUri);
  if (parsed.protocol !== "devspace:" || parsed.username || parsed.password || parsed.port || parsed.search || parsed.hash) {
    throw invalidUri();
  }
  if (parsed.hostname === "v1") return parseV1(resourceUri, parsed);
  if (!options.allowLegacyRead) {
    throw new ResourceUriError(
      "RESOURCE_URI_LEGACY",
      "Unversioned resource URIs are accepted only by the explicit legacy read-only parser.",
    );
  }
  return parseLegacy(parsed);
}

function parseV1(original: string, parsed: URL): ParsedResourceReference {
  const segments = pathSegments(parsed);
  let reference: VersionedResourceReference;
  if (segments.length === 3 && segments[0] === "process" && segments[2] === "output") {
    reference = { kind: "process-output", processId: decoded(segments[1]!) };
  } else if (segments.length === 2 && segments[0] === "context-diff") {
    reference = { kind: "context-diff", diffId: decoded(segments[1]!) };
  } else if (segments.length === 4 && segments[0] === "mcp" && segments[2] === "resource") {
    reference = { kind: "mcp-resource", routeId: decoded(segments[1]!), opaque: decoded(segments[3]!) };
  } else if (segments.length === 2 && segments[0] === "mcp-result") {
    reference = { kind: "mcp-result", resultId: decoded(segments[1]!) };
  } else if (segments.length === 2 && segments[0] === "artifact") {
    reference = { kind: "artifact", artifactId: decoded(segments[1]!) };
  } else {
    throw new ResourceUriError("RESOURCE_URI_UNSUPPORTED", "Resource URI kind or shape is unsupported.");
  }
  if (formatResourceUri(reference) !== original) throw invalidUri();
  return { version: 1, legacy: false, ...reference };
}

function parseLegacy(parsed: URL): ParsedResourceReference {
  const segments = pathSegments(parsed);
  switch (parsed.hostname) {
    case "artifact":
      if (segments.length === 1) {
        return { version: 0, legacy: true, kind: "artifact", artifactId: decoded(segments[0]!) };
      }
      break;
    case "process":
      if (segments.length === 4 && segments[1] === "output") {
        return {
          version: 0,
          legacy: true,
          kind: "process-output",
          processId: decoded(segments[0]!),
          offset: nonnegativeInteger(segments[2]!),
          limit: nonnegativeInteger(segments[3]!),
        };
      }
      break;
    case "context-diff":
      if (segments.length === 1 || segments.length === 3) {
        return {
          version: 0,
          legacy: true,
          kind: "context-diff",
          diffId: decoded(segments[0]!),
          ...(segments.length === 3
            ? { offset: nonnegativeInteger(segments[1]!), limit: nonnegativeInteger(segments[2]!) }
            : {}),
        };
      }
      break;
    case "mcp-result":
      if (segments.length === 1) {
        return { version: 0, legacy: true, kind: "mcp-result", resultId: decoded(segments[0]!) };
      }
      break;
    case "mcp":
      if (segments.length === 5 && segments[1] === "result") {
        return {
          version: 0,
          legacy: true,
          kind: "mcp-result",
          resultId: decoded(segments[2]!),
          offset: nonnegativeInteger(segments[3]!),
          limit: nonnegativeInteger(segments[4]!),
        };
      }
      if (segments.length === 3 && segments[1] === "resource") {
        return {
          version: 0,
          legacy: true,
          kind: "mcp-resource",
          routeId: decoded(segments[0]!),
          opaque: decoded(segments[2]!),
        };
      }
      break;
    case "gui":
      if (segments.length === 3 && segments[1] === "capture") {
        return {
          version: 0,
          legacy: true,
          kind: "gui-capture",
          sessionId: decoded(segments[0]!),
          generation: decoded(segments[2]!),
        };
      }
      break;
  }
  throw new ResourceUriError("RESOURCE_URI_UNSUPPORTED", "Legacy resource URI kind or shape is unsupported.");
}

function safeUrl(value: string): URL {
  if (typeof value !== "string" || value.length === 0 || value.length > 16_384) throw invalidUri();
  try {
    return new URL(value);
  } catch {
    throw invalidUri();
  }
}

function pathSegments(parsed: URL): string[] {
  if (!parsed.pathname.startsWith("/") || parsed.pathname.endsWith("/")) throw invalidUri();
  const segments = parsed.pathname.slice(1).split("/");
  if (segments.some((segment) => segment.length === 0)) throw invalidUri();
  return segments;
}

function component(value: string, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4_096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ResourceUriError("RESOURCE_URI_INVALID", `${field} is not a valid resource URI component.`);
  }
  return encodeURIComponent(value);
}

function decoded(value: string): string {
  try {
    const result = decodeURIComponent(value);
    component(result, "component");
    return result;
  } catch (error) {
    if (error instanceof ResourceUriError) throw error;
    throw invalidUri();
  }
}

function nonnegativeInteger(value: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) throw invalidUri();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw invalidUri();
  return parsed;
}

function invalidUri(): ResourceUriError {
  return new ResourceUriError("RESOURCE_URI_INVALID", "Resource URI is invalid or non-canonical.");
}
