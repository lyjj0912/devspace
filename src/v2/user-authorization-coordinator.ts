import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { RuntimeIdentity } from "./contracts.js";
import type { CapabilityCallContext } from "./capability-call-context.js";
import type { NormalizedExecutionElevation } from "./elevation.js";
import { UniversalBrokerError } from "./errors.js";
import {
  createUserAuthorizationDescriptor,
  type UserAuthorizationDescriptor,
  type UserAuthorizationProvider,
  type UserAuthorizationProviderRequest,
  type UserAuthorizationReceipt,
  verifyUserAuthorizationReceipt,
} from "./user-authorization.js";
import {
  type PreparedUserAuthorizationOperation,
  type UserAuthorizationOperation,
  UserAuthorizationStore,
} from "./user-authorization-store.js";

export interface UserAuthorizationCoordinatorInput {
  authorizationOperationId: string;
  callContext: CapabilityCallContext;
  target: {
    id: string;
    generation: string;
    transport: "local" | "ssh";
    platform: string;
  };
  runtimeIdentity: RuntimeIdentity;
  command: string;
  cwd: string;
  mode: "auto" | "foreground" | "background";
  tty: boolean;
  envProfile?: string;
  environment?: Record<string, string>;
  elevation: NormalizedExecutionElevation & { mode: "prompt" };
  issuedAt?: string;
  nonce?: string;
}

export interface UserAuthorizationLaunchResult {
  process: ChildProcessWithoutNullStreams;
  descriptor: UserAuthorizationDescriptor;
  receipt: UserAuthorizationReceipt;
  reused: boolean;
}

export class UserAuthorizationCoordinator {
  constructor(
    private readonly store: UserAuthorizationStore,
    private readonly provider: UserAuthorizationProvider,
  ) {}

  async close(): Promise<void> {
    await this.provider.close?.();
    this.store.checkpoint();
    this.store.close();
  }

  async authorizeAndLaunch(
    input: UserAuthorizationCoordinatorInput,
  ): Promise<UserAuthorizationLaunchResult> {
    const capability = await this.provider.capability({
      targetId: input.target.id,
      targetGeneration: input.target.generation,
      platform: input.target.platform,
    });
    if (!capability.available) {
      throw new UniversalBrokerError(
        "ELEVATION_UNAVAILABLE",
        capability.reason ?? `User authorization provider ${capability.providerId} is unavailable.`,
        {
          evidence: {
            targetId: input.target.id,
            providerId: capability.providerId,
            providerGeneration: capability.providerGeneration,
            providerDispatchCount: 0,
          },
        },
      );
    }
    const descriptor = createUserAuthorizationDescriptor(input);
    const prepared = this.store.prepare(descriptor);
    return this.continuePrepared(prepared, descriptor, input);
  }

  private async continuePrepared(
    prepared: PreparedUserAuthorizationOperation,
    receivedDescriptor: UserAuthorizationDescriptor,
    input: UserAuthorizationCoordinatorInput,
  ): Promise<UserAuthorizationLaunchResult> {
    const operation = prepared.operation;
    if (prepared.reused) {
      if (operation.state === "PENDING") {
        throw new UniversalBrokerError(
          "RESOURCE_BUSY",
          "A user authorization prompt for this explicit request is already pending.",
          {
            evidence: {
              authorizationOperationId: operation.operationId,
              actionDigest: operation.actionDigest,
              providerDispatchCount: 0,
            },
          },
        );
      }
      if (operation.state === "APPROVED" && operation.receiptConsumedAt !== undefined) {
        throw resultUnknown(operation);
      }
      if (operation.state !== "APPROVED" || !operation.receipt) {
        throw decisionError(operation);
      }
      return this.consumeAndLaunch(
        operation.descriptor,
        operation.receipt,
        input,
        true,
      );
    }

    let decision;
    try {
      decision = await this.provider.authorize({
        descriptor: receivedDescriptor,
        command: input.command,
        cwd: input.cwd,
        ...(input.environment ? { environment: { ...input.environment } } : {}),
        elevation: input.elevation,
      });
    } catch (error) {
      this.store.markDecisionUnknown({
        operationId: receivedDescriptor.authorizationOperationId,
        descriptorDigest: receivedDescriptor.descriptorDigest,
      });
      throw new UniversalBrokerError(
        "ELEVATION_RESULT_UNKNOWN",
        "The user authorization provider did not return a decision.",
        {
          evidence: {
            authorizationOperationId: receivedDescriptor.authorizationOperationId,
            actionDigest: receivedDescriptor.actionDigest,
            providerDispatchCount: 0,
            errorType: error instanceof Error ? error.name : typeof error,
          },
        },
      );
    }
    verifyUserAuthorizationReceipt(decision.receipt);
    const recorded = this.store.recordDecision(decision.receipt);
    if (recorded.state !== "APPROVED" || !recorded.receipt) {
      throw decisionError(recorded);
    }
    return this.consumeAndLaunch(
      recorded.descriptor,
      recorded.receipt,
      input,
      false,
    );
  }

  private async consumeAndLaunch(
    descriptor: UserAuthorizationDescriptor,
    receipt: UserAuthorizationReceipt,
    input: UserAuthorizationCoordinatorInput,
    reused: boolean,
  ): Promise<UserAuthorizationLaunchResult> {
    this.store.consumeApprovedReceipt({
      operationId: descriptor.authorizationOperationId,
      descriptorDigest: descriptor.descriptorDigest,
      receiptDigest: receipt.receiptDigest,
    });
    try {
      const process = await this.provider.launch({
        descriptor,
        receipt,
        command: input.command,
        cwd: input.cwd,
        ...(input.environment ? { environment: { ...input.environment } } : {}),
        elevation: input.elevation,
      });
      return { process, descriptor, receipt, reused };
    } catch (error) {
      this.store.markResultUnknown({
        operationId: descriptor.authorizationOperationId,
        descriptorDigest: descriptor.descriptorDigest,
        receiptDigest: receipt.receiptDigest,
      });
      throw new UniversalBrokerError(
        "ELEVATION_RESULT_UNKNOWN",
        "The approved authorization client failed while launching the exact operation; it was not retried.",
        {
          evidence: {
            authorizationOperationId: descriptor.authorizationOperationId,
            actionDigest: descriptor.actionDigest,
            receiptDigest: receipt.receiptDigest,
            providerDispatchCount: 1,
            errorType: error instanceof Error ? error.name : typeof error,
          },
        },
      );
    }
  }
}

function decisionError(operation: UserAuthorizationOperation): UniversalBrokerError {
  const evidence = authorizationEvidence(operation);
  switch (operation.state) {
    case "DENIED":
      return new UniversalBrokerError("ELEVATION_DENIED", "The user denied administrator authorization.", { evidence });
    case "CANCELED":
      return new UniversalBrokerError("ELEVATION_CANCELED", "The user canceled administrator authorization.", { evidence });
    case "TIMED_OUT":
    case "EXPIRED":
      return new UniversalBrokerError("ELEVATION_TIMED_OUT", "Administrator authorization expired or timed out.", { evidence });
    case "RESULT_UNKNOWN":
      return resultUnknown(operation);
    default:
      return new UniversalBrokerError(
        "ELEVATION_RESULT_UNKNOWN",
        `Unexpected authorization state: ${operation.state}.`,
        { evidence },
      );
  }
}

function resultUnknown(operation: UserAuthorizationOperation): UniversalBrokerError {
  return new UniversalBrokerError(
    "ELEVATION_RESULT_UNKNOWN",
    "The authorized operation may already have been dispatched; read back its result before retrying.",
    { evidence: authorizationEvidence(operation) },
  );
}

function authorizationEvidence(operation: UserAuthorizationOperation): Record<string, unknown> {
  return {
    authorizationOperationId: operation.operationId,
    actionDigest: operation.actionDigest,
    descriptorDigest: operation.descriptorDigest,
    ...(operation.receipt
      ? {
        receiptDigest: operation.receipt.receiptDigest,
        providerId: operation.receipt.providerId,
        providerGeneration: operation.receipt.providerGeneration,
      }
      : {}),
    providerDispatchCount: 0,
  };
}
