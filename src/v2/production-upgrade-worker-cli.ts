import { runProductionUpgradeWorker } from "./production-upgrade-worker.js";

const requestPath = process.argv[2];
if (!requestPath) {
  console.error("Production upgrade worker requires a request path.");
  process.exitCode = 2;
} else {
  try {
    await runProductionUpgradeWorker(requestPath);
  } catch (error) {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  }
}
