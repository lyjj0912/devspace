import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { promisify } from "node:util";
import type { ServerConfig } from "../config.js";
import { inspectUniversalBrokerBudgets } from "./budgets.js";
import { loadUniversalBrokerNextConfig } from "./config.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import { createRuntimeIdentity } from "./runtime-identity.js";
import { TargetRegistry } from "./targets.js";

const execFileAsync = promisify(execFile);

export async function collectUniversalBrokerDoctor(
  baseConfig: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, unknown>> {
  const config = loadUniversalBrokerNextConfig(baseConfig, env);
  const targets = new TargetRegistry({
    configPath: config.targetConfigPath,
  });
  const routes = new UniversalMcpRouteRegistry(config.mcpRouteConfigPath);
  const envProfiles = new UniversalEnvProfileRegistry({ configPath: config.envProfileConfigPath });
  const [targetSnapshot, routeSnapshot, environmentProfiles, budgets, sourceCommit] = await Promise.all([
    targets.inspect(),
    routes.inspect(),
    envProfiles.list(),
    inspectUniversalBrokerBudgets(),
    gitCommit(),
  ]);
  const observations = await mapWithConcurrency(targetSnapshot.targets, 4, async (target) => {
    try {
      return await targets.probe(target.id);
    } catch (error) {
      const observedAt = new Date().toISOString();
      return {
        targetId: target.id,
        status: "UNKNOWN" as const,
        observedAt,
        expiresAt: observedAt,
        platform: target.platform,
        capabilities: {
          fs: false,
          exec: false,
          pty: false,
          sftp: false,
          rsync: false,
          git: false,
          gui: false,
          mcp: false,
          durableProcess: false,
        },
        reason: errorMessage(error),
        evidence: {
          transport: target.transport,
          ...(target.sshHost ? { sshHost: target.sshHost } : {}),
        },
      };
    }
  });
  const [targetFile, routeFile, envProfileFile] = await Promise.all([
    safePathMetadata(config.targetConfigPath),
    safePathMetadata(config.mcpRouteConfigPath),
    safePathMetadata(config.envProfileConfigPath),
  ]);
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: sourceCommit ?? config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  return {
    generatedAt: new Date().toISOString(),
    sourceCommit,
    runtimeIdentity,
    platform: { platform: process.platform, architecture: process.arch, node: process.version },
    endpoint: {
      deploymentMode: config.deploymentMode,
      local: `http://${config.host}:${config.port}${config.endpointPath}`,
      public: config.publicMcpUrl,
      health: `http://${config.host}:${config.port}${config.healthPath}`,
      managementHealth: `http://${config.managementHost}:${config.managementPort}/healthz`,
      readiness: `http://${config.managementHost}:${config.managementPort}${config.readyPath}`,
      metrics: `http://${config.managementHost}:${config.managementPort}${config.metricsPath}`,
      stateDir: config.stateDir,
      oauthStateReused: config.oauthStateDir === config.serverConfig.stateDir,
      granularScopesOnly: true,
    },
    contracts: budgets,
    selfManagement: {
      stateDir: config.selfManagementDir,
      pm2ProcessName: config.selfRestartPm2ProcessName,
      expectedScript: config.selfRestartExpectedScript,
      restartDelayMs: config.selfRestartDelayMs,
      restartTimeoutMs: config.selfRestartTimeoutMs,
      transactionModel: "detached-worker-with-post-reconnect-readback",
    },
    registries: {
      targets: {
        path: config.targetConfigPath,
        metadata: targetFile,
        generation: targetSnapshot.generation,
        count: targetSnapshot.targets.length,
      },
      mcpRoutes: {
        path: config.mcpRouteConfigPath,
        metadata: routeFile,
        generation: routeSnapshot.generation,
        count: routeSnapshot.routes.length,
        routes: routeSnapshot.routes.map((route) => ({
          id: route.id,
          transport: route.transport,
          target: route.target,
          envProfile: route.envProfile,
        })),
      },
      environmentProfiles: {
        path: config.envProfileConfigPath,
        metadata: envProfileFile,
        count: environmentProfiles.length,
        profiles: environmentProfiles,
      },
    },
    targets: observations,
    targetProbeStats: targets.stats(),
    quotas: {
      httpMcpSessions: config.maximumMcpSessions,
      httpMcpIdleTtlMs: config.mcpSessionIdleTimeoutMs,
      contexts: config.contextMaximumEntries,
      worktrees: config.contextMaximumWorktrees,
      worktreeBytes: config.contextMaximumWorktreeBytes,
      contextDiffEntries: config.contextDiffMaximumEntries,
      contextDiffCharacters: config.contextDiffMaximumCharacters,
      contextIdleTtlMs: config.contextIdleTtlMs,
      contextDiffTtlMs: config.contextDiffTtlMs,
      processes: config.maxRunningProcesses,
      processRecords: config.maximumProcessRecords,
      processesPerTarget: config.maxRunningProcessesPerTarget,
      processOutputBytes: config.processOutputMaxBytes,
      completedProcessTtlMs: config.completedProcessTtlMs,
      restartTimeoutMs: config.selfRestartTimeoutMs,
      downstreamMcpSessions: config.downstreamMcpMaximumSessions,
      downstreamMcpIdleTtlMs: config.downstreamMcpSessionIdleTtlMs,
      mcpResultEntries: config.mcpResultMaximumEntries,
      mcpResultCharacters: config.mcpResultMaximumCharacters,
      mcpResultTtlMs: config.mcpResultTtlMs,
      artifactEntries: config.artifactMaximumEntries,
      artifactTotalBytes: config.artifactMaximumTotalBytes,
      artifactFileBytes: config.artifactMaximumFileBytes,
      artifactTtlMs: config.artifactTtlMs,
      guiSessions: config.guiMaximumSessions,
      guiSessionTtlMs: config.guiSessionTtlMs,
    },
  };
}

async function mapWithConcurrency<T, R>(
  values: readonly T[],
  maximumConcurrency: number,
  mapper: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const output = new Array<R>(values.length);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(Math.max(maximumConcurrency, 1), values.length) },
    async () => {
      while (nextIndex < values.length) {
        const index = nextIndex;
        nextIndex += 1;
        output[index] = await mapper(values[index]!, index);
      }
    },
  );
  await Promise.all(workers);
  return output;
}

async function safePathMetadata(path: string): Promise<Record<string, unknown>> {
  try {
    const metadata = await lstat(path);
    return {
      exists: true,
      type: metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : metadata.isSocket() ? "socket" : "other",
      mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
      uid: metadata.uid,
      gid: metadata.gid,
      size: metadata.size,
      modifiedAt: metadata.mtime.toISOString(),
    };
  } catch (error) {
    return { exists: false, error: errorMessage(error) };
  }
}

async function gitCommit(): Promise<string | undefined> {
  try {
    return (await execFileAsync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    })).stdout.trim();
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
