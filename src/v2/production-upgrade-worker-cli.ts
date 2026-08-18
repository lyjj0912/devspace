import { readFile } from "node:fs/promises";
import {
  runProductionUpgradeWorker,
  schedulePm2WorkerCleanup,
  type ProductionUpgradeRequest,
} from "./production-upgrade-worker.js";

const requestPath = process.argv[2];
if (!requestPath) {
  console.error("Production upgrade worker requires a request path.");
  process.exitCode = 2;
} else {
  let fallbackCleanup:
    | { pm2Executable: string; workerName: string; auditDirectory: string }
    | undefined;
  try {
    if (process.env.DEVSPACE_UPGRADE_SCHEDULER === "pm2") {
      const workerName = process.env.DEVSPACE_UPGRADE_PM2_WORKER_NAME;
      if (!workerName) throw new Error("PM2 fallback worker name is missing.");
      const request = JSON.parse(await readFile(requestPath, "utf8")) as ProductionUpgradeRequest;
      fallbackCleanup = {
        pm2Executable: request.pm2Executable,
        workerName,
        auditDirectory: request.auditDirectory,
      };
    }
    await runProductionUpgradeWorker(requestPath);
  } catch (error) {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  } finally {
    if (fallbackCleanup) {
      try {
        schedulePm2WorkerCleanup(
          fallbackCleanup.pm2Executable,
          fallbackCleanup.workerName,
          fallbackCleanup.auditDirectory,
        );
      } catch (error) {
        console.error(error instanceof Error ? error.stack ?? error.message : String(error));
        process.exitCode = 1;
      }
    }
  }
}
