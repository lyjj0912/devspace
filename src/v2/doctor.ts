import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { promisify } from "node:util";
import type { ServerConfig } from "../config.js";
import { inspectUniversalBrokerBudgets } from "./budgets.js";
import { loadUniversalBrokerNextConfig } from "./config.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
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
  const observations = [];
  for (const target of targetSnapshot.targets) {
    try {
      observations.push(await targets.probe(target.id));
    } catch (error) {
      observations.push({
        targetId: target.id,
        status: "UNKNOWN",
        reason: errorMessage(error),
      });
    }
  }
  const [targetFile, routeFile, envProfileFile] = await Promise.all([
    safePathMetadata(config.targetConfigPath),
    safePathMetadata(config.mcpRouteConfigPath),
    safePathMetadata(config.envProfileConfigPath),
  ]);
  return {
    generatedAt: new Date().toISOString(),
    sourceCommit,
    platform: { platform: process.platform, architecture: process.arch, node: process.version },
    endpoint: {
      deploymentMode: config.deploymentMode,
      local: `http://${config.host}:${config.port}${config.endpointPath}`,
      public: config.publicMcpUrl,
      health: `http://${config.host}:${config.port}${config.healthPath}`,
      metrics: `http://${config.host}:${config.port}${config.metricsPath}`,
      stateDir: config.stateDir,
      oauthStateReused: config.oauthStateDir === config.serverConfig.stateDir,
      legacyScopeCompatibility: config.legacyScopeCompatibility,
    },
    contracts: budgets,
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
      processesPerTarget: config.maxRunningProcessesPerTarget,
      processOutputBytes: config.processOutputMaxBytes,
      completedProcessTtlMs: config.completedProcessTtlMs,
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
