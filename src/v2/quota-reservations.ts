import { UniversalBrokerError } from "./errors.js";

type QuotaVector = Readonly<Record<string, number>>;

export interface QuotaReservation {
  readonly request: QuotaVector;
  readonly settled: boolean;
  commit(apply: () => void): void;
  release(): void;
}

/**
 * Reserves capacity synchronously before an asynchronous provider or creation
 * path starts. Committed usage remains owned by the caller; this primitive only
 * tracks in-flight reservations so concurrent callers cannot oversubscribe it.
 */
export class SynchronousQuotaReservations {
  private readonly limits: Readonly<Record<string, number>>;
  private readonly reserved: Record<string, number>;

  constructor(
    private readonly resource: string,
    limits: QuotaVector,
  ) {
    if (!resource.trim()) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Quota resource name is required.");
    }
    this.limits = Object.freeze(validateVector(limits, "quota limit"));
    this.reserved = Object.fromEntries(Object.keys(this.limits).map((key) => [key, 0]));
  }

  reserve(usage: QuotaVector, request: QuotaVector): QuotaReservation {
    const normalizedUsage = validateMatchingVector(usage, this.limits, "quota usage");
    const normalizedRequest = validateMatchingVector(request, this.limits, "quota request");
    for (const dimension of Object.keys(this.limits)) {
      const maximum = this.limits[dimension]!;
      const used = normalizedUsage[dimension]!;
      const held = this.reserved[dimension]!;
      const requested = normalizedRequest[dimension]!;
      if (used + held + requested > maximum) {
        throw new UniversalBrokerError(
          "RESOURCE_QUOTA_EXCEEDED",
          `${this.resource} ${dimension} quota exceeded.`,
          {
            evidence: {
              resource: this.resource,
              dimension,
              used,
              reserved: held,
              requested,
              maximum,
            },
          },
        );
      }
    }
    for (const dimension of Object.keys(this.limits)) {
      this.reserved[dimension] = this.reserved[dimension]! + normalizedRequest[dimension]!;
    }
    return this.createReservation(Object.freeze(normalizedRequest));
  }

  pending(): Readonly<Record<string, number>> {
    return Object.freeze({ ...this.reserved });
  }

  private createReservation(request: QuotaVector): QuotaReservation {
    let settled = false;
    const settle = (): void => {
      if (settled) return;
      settled = true;
      for (const dimension of Object.keys(this.limits)) {
        this.reserved[dimension] = this.reserved[dimension]! - request[dimension]!;
      }
    };
    return {
      request,
      get settled() { return settled; },
      commit: (apply: () => void): void => {
        if (settled) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            `${this.resource} quota reservation is already settled.`,
          );
        }
        try {
          apply();
        } finally {
          settle();
        }
      },
      release: settle,
    };
  }
}

function validateMatchingVector(
  vector: QuotaVector,
  limits: QuotaVector,
  label: string,
): Record<string, number> {
  const normalized = validateVector(vector, label);
  const actual = Object.keys(normalized).sort();
  const expected = Object.keys(limits).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${label} dimensions must exactly match configured limits.`,
      { evidence: { expected, actual } },
    );
  }
  return normalized;
}

function validateVector(vector: QuotaVector, label: string): Record<string, number> {
  const entries = Object.entries(vector);
  if (entries.length === 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${label} cannot be empty.`);
  }
  const normalized: Record<string, number> = {};
  for (const [dimension, value] of entries) {
    if (!/^[a-z][a-zA-Z0-9]*$/.test(dimension)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid quota dimension: ${dimension}`);
    }
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `${label} ${dimension} must be a non-negative safe integer.`,
      );
    }
    normalized[dimension] = value;
  }
  return normalized;
}
